use std::collections::{BTreeMap, BTreeSet};

use socialname_domain::{
    Assertion as DomainAssertion, AssertionQuality as DomainAssertionQuality, CollectionProfile,
    DerivationPolicy, EvidenceClass as DomainEvidenceClass, Observation as DomainObservation,
    ObservationId as DomainObservationId, ProducerKind, ProducerReputation, SiteId as DomainSiteId,
    TargetKey, Verdict, derive_assertion, derive_regional_assertions,
};
use socialname_protocol::{
    Assertion as ProtocolAssertion, AssertionOutcome, AssertionQuality, EvidenceClass, Freshness,
    FreshnessState, ObservationId, RegionClass, RegionalAssertion, ResultSource, SiteId, Target,
    Username,
};
use sqlx::{FromRow, Postgres, Transaction};
use uuid::Uuid;

use crate::delivery::enqueue_confirmed_transition;
use crate::job::JobError;

const ASSERTION_DERIVATION_VERSION: &str = "assertion/v1";
const TRANSITION_DERIVATION_VERSION: &str = "transition/v1";
const FOLLOW_UP_DELAY_MS: i64 = 5 * 60 * 1_000;

pub(crate) struct DerivationKey<'a> {
    pub tenant_id: Uuid,
    pub normalized_username: &'a str,
    pub site_id: &'a str,
    pub rule_version_id: Uuid,
    pub rule_hash: &'a str,
}

pub(crate) struct WatchInterpretationKey<'a> {
    pub tenant_id: Uuid,
    pub watch_target_id: Uuid,
    pub rule_version_id: Uuid,
    pub region_class: &'a str,
}

#[derive(Clone, Copy)]
pub(crate) enum MeasurementOutcome {
    Healthy { observation_id: Uuid },
    Degraded { observation_id: Uuid },
    Unavailable { probe_job_id: Uuid },
}

impl MeasurementOutcome {
    const fn state(self) -> &'static str {
        match self {
            Self::Healthy { .. } => "healthy",
            Self::Degraded { .. } => "degraded",
            Self::Unavailable { .. } => "unavailable",
        }
    }

    const fn observation_id(self) -> Option<Uuid> {
        match self {
            Self::Healthy { observation_id } | Self::Degraded { observation_id } => {
                Some(observation_id)
            }
            Self::Unavailable { .. } => None,
        }
    }

    const fn probe_job_id(self) -> Option<Uuid> {
        match self {
            Self::Unavailable { probe_job_id } => Some(probe_job_id),
            Self::Healthy { .. } | Self::Degraded { .. } => None,
        }
    }
}

pub(crate) struct DerivedAssertion {
    id: Uuid,
    assertion: DomainAssertion,
    regional_assertions: BTreeMap<String, DerivedRegionalAssertion>,
    evidence: Vec<AssertionEvidence>,
    sources: Vec<ResultSource>,
}

struct DerivedRegionalAssertion {
    assertion: DomainAssertion,
    sources: Vec<ResultSource>,
}

impl DerivedAssertion {
    pub(crate) const fn id(&self) -> Uuid {
        self.id
    }

    pub(crate) fn is_conflicted(&self) -> bool {
        self.assertion.quality == DomainAssertionQuality::Conflicted
    }

    pub(crate) fn protocol_assertion(
        &self,
        evaluated_at_unix_ms: i64,
        maximum_age_ms: i64,
    ) -> Result<ProtocolAssertion, JobError> {
        let freshness = Freshness::new(
            self.assertion.observed_at_unix_ms,
            self.assertion.expires_at_unix_ms,
            evaluated_at_unix_ms,
            maximum_age_ms,
        )
        .map_err(|_| JobError::InvalidProtocol)?;
        let quality = if freshness.state == FreshnessState::Current {
            protocol_assertion_quality(self.assertion.quality)
        } else {
            AssertionQuality::Stale
        };
        let outcome = match self.assertion.verdict {
            Verdict::Found => AssertionOutcome::Found,
            Verdict::NotFound => AssertionOutcome::NotFound,
            Verdict::Inconclusive => AssertionOutcome::Inconclusive {
                reason: socialname_protocol::UncertaintyReason::ConflictingEvidence,
            },
            Verdict::InvalidUsername => return Err(JobError::StorageInvariant),
        };
        let supporting_observation_ids = self
            .assertion
            .supporting_observation_ids
            .iter()
            .map(|id| {
                ObservationId::new(id.as_str().to_owned()).map_err(|_| JobError::InvalidProtocol)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let conflicting_observation_ids = self
            .assertion
            .conflicting_observation_ids
            .iter()
            .map(|id| {
                ObservationId::new(id.as_str().to_owned()).map_err(|_| JobError::InvalidProtocol)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let regions = self
            .assertion
            .regions
            .iter()
            .map(|region| RegionClass::new(region.clone()).map_err(|_| JobError::InvalidProtocol))
            .collect::<Result<Vec<_>, _>>()?;
        let regional_assertions = self
            .regional_assertions
            .iter()
            .map(|(region, derived)| {
                protocol_regional_assertion(region, derived, evaluated_at_unix_ms, maximum_age_ms)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ProtocolAssertion {
            target: Target {
                username: Username::new(self.assertion.target.normalized_username.clone())
                    .map_err(|_| JobError::InvalidProtocol)?,
                site_id: SiteId::new(self.assertion.target.site_id.as_str().to_owned())
                    .map_err(|_| JobError::InvalidProtocol)?,
            },
            outcome,
            quality,
            evidence_class: protocol_evidence_class(self.assertion.evidence_class),
            freshness,
            sources: self.sources.clone(),
            regions,
            support_group_count: u32::try_from(self.assertion.support_group_count)
                .map_err(|_| JobError::StorageInvariant)?,
            managed_support: self.assertion.managed_support,
            supporting_observation_ids,
            conflicting_observation_ids,
            regional_assertions: Some(regional_assertions),
            derivation_version: self.assertion.derivation_version.to_owned(),
        })
    }
}

#[derive(Clone)]
struct AssertionEvidence {
    observation_id: Uuid,
    evidence_class: DomainEvidenceClass,
    observed_at_unix_ms: i64,
    region_class: String,
    managed: bool,
}

#[derive(FromRow)]
struct EligibleObservationRow {
    id: Uuid,
    normalized_username: String,
    site_id: String,
    verdict: String,
    evidence_class: String,
    observed_at_unix_ms: i64,
    expires_at_unix_ms: i64,
    region_class: String,
    producer_kind: String,
    visibility: String,
    source: String,
    rule_hash: String,
    evidence_digest: String,
}

#[derive(FromRow)]
struct CurrentAssertionRow {
    id: Uuid,
    outcome_kind: String,
    verdict: Option<String>,
    uncertainty_reason: Option<String>,
    quality: String,
    evidence_class: String,
    observed_at_unix_ms: i64,
    expires_at_unix_ms: i64,
    derivation_version: String,
}

#[derive(FromRow)]
struct CurrentRegionalAssertionRow {
    id: Uuid,
    region_class: String,
    outcome_kind: String,
    verdict: Option<String>,
    uncertainty_reason: Option<String>,
    quality: String,
    evidence_class: String,
    observed_at_unix_ms: i64,
    expires_at_unix_ms: i64,
    support_group_count: i32,
    managed_support: bool,
}

#[derive(FromRow)]
struct LockedAccountBaseline {
    account_state: Option<String>,
    account_assertion_id: Option<Uuid>,
    account_state_since_unix_ms: Option<i64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AccountConfirmation {
    Confirmed(&'static str),
    Pending(&'static str),
    Suppressed(&'static str),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum VerificationPriority {
    Routine,
    AccountConfirmation,
    RegionalConflict,
}

impl VerificationPriority {
    pub(crate) const fn value(self) -> i16 {
        match self {
            Self::Routine => 0,
            Self::AccountConfirmation => 50,
            Self::RegionalConflict => 100,
        }
    }

    const fn from_persisted_state(regional_conflict: bool, account_candidate: bool) -> Self {
        if regional_conflict {
            Self::RegionalConflict
        } else if account_candidate {
            Self::AccountConfirmation
        } else {
            Self::Routine
        }
    }
}

pub(crate) async fn load_verification_priority(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    watch_target_id: Uuid,
    normalized_username: &str,
    site_id: &str,
) -> Result<VerificationPriority, JobError> {
    let (regional_conflict, account_candidate): (bool, bool) = sqlx::query_as(
        "SELECT \
            EXISTS (\
                SELECT 1 FROM assertions \
                WHERE tenant_id = $1 \
                  AND normalized_username = $3 AND site_id = $4 \
                  AND is_current AND withdrawn_at IS NULL \
                  AND quality = 'conflicted'\
            ), \
            EXISTS (\
                SELECT 1 FROM transitions \
                WHERE tenant_id = $1 AND watch_target_id = $2 \
                  AND transition_class = 'account_state' \
                  AND (\
                      confirmation_status = 'pending' \
                      OR (\
                          confirmation_status = 'suppressed' \
                          AND suppression_reason = 'shared_only_absence'\
                      )\
                  )\
            )",
    )
    .bind(tenant_id)
    .bind(watch_target_id)
    .bind(normalized_username)
    .bind(site_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| JobError::StorageInvariant)?;
    Ok(VerificationPriority::from_persisted_state(
        regional_conflict,
        account_candidate,
    ))
}

pub(crate) async fn elevate_probe_job_priority(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    probe_job_id: Uuid,
    priority: VerificationPriority,
) -> Result<(), JobError> {
    if priority == VerificationPriority::Routine {
        return Ok(());
    }
    sqlx::query(
        "UPDATE probe_jobs \
         SET priority = $3, updated_at = clock_timestamp() \
         WHERE tenant_id = $1 AND id = $2 \
           AND state IN ('queued', 'retry_wait') \
           AND priority < $3",
    )
    .bind(tenant_id)
    .bind(probe_job_id)
    .bind(priority.value())
    .execute(&mut **transaction)
    .await
    .map_err(|_| JobError::StorageInvariant)?;
    Ok(())
}

async fn elevate_watch_probe_priorities(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    watch_target_id: Uuid,
    priority: VerificationPriority,
) -> Result<(), JobError> {
    if priority == VerificationPriority::Routine {
        return Ok(());
    }
    sqlx::query(
        "UPDATE probe_jobs AS job \
         SET priority = $3, updated_at = clock_timestamp() \
         WHERE job.tenant_id = $1 \
           AND job.state IN ('queued', 'retry_wait') \
           AND job.priority < $3 \
           AND EXISTS (\
               SELECT 1 FROM probe_job_consumers AS consumer \
               WHERE consumer.tenant_id = job.tenant_id \
                 AND consumer.probe_job_id = job.id \
                 AND consumer.watch_target_id = $2\
           )",
    )
    .bind(tenant_id)
    .bind(watch_target_id)
    .bind(priority.value())
    .execute(&mut **transaction)
    .await
    .map_err(|_| JobError::StorageInvariant)?;
    Ok(())
}

pub(crate) async fn lock_derivation_target(
    transaction: &mut Transaction<'_, Postgres>,
    key: &DerivationKey<'_>,
) -> Result<(), JobError> {
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended(\
            $1::text || ':' || octet_length($2)::text || ':' || $2 \
                || ':' || octet_length($3)::text || ':' || $3, \
            0\
         ))",
    )
    .bind(key.tenant_id)
    .bind(key.normalized_username)
    .bind(key.site_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| JobError::DatabaseUnavailable)?;
    Ok(())
}

pub(crate) async fn recompute_assertion(
    transaction: &mut Transaction<'_, Postgres>,
    key: &DerivationKey<'_>,
    now_unix_ms: i64,
) -> Result<Option<DerivedAssertion>, JobError> {
    let rows: Vec<EligibleObservationRow> = sqlx::query_as(
        "SELECT observation.id, observation.normalized_username, \
                observation.site_id, observation.verdict, \
                observation.evidence_class, \
                (extract(epoch FROM observation.observed_at) * 1000)::bigint \
                    AS observed_at_unix_ms, \
                (extract(epoch FROM observation.expires_at) * 1000)::bigint \
                    AS expires_at_unix_ms, \
                observation.region_class, observation.producer_kind, \
                observation.visibility, observation.source, \
                $6::text AS rule_hash, \
                encode(observation.evidence_digest, 'hex') AS evidence_digest \
         FROM observations AS observation \
         JOIN consent_grants AS consent \
           ON consent.tenant_id = observation.tenant_id \
          AND consent.id = observation.consent_grant_id \
         WHERE observation.tenant_id = $1 \
           AND observation.normalized_username = $2 \
           AND observation.site_id = $3 \
           AND observation.rule_version_id = $4 \
           AND observation.outcome_kind = 'definitive' \
           AND observation.verdict IN ('found', 'not_found') \
           AND observation.evidence_class IN (\
               'e3_explicit_endpoint', 'e4_structured_identity'\
           ) \
           AND observation.rule_health_green \
           AND observation.observed_at <= \
               to_timestamp($5::double precision / 1000.0) \
           AND observation.expires_at > \
               to_timestamp($5::double precision / 1000.0) \
           AND consent.subject_kind = 'account' \
           AND consent.granted_at <= \
               to_timestamp($5::double precision / 1000.0) \
           AND consent.withdrawn_at IS NULL \
           AND (\
               consent.expires_at IS NULL \
               OR consent.expires_at > \
                   to_timestamp($5::double precision / 1000.0)\
           ) \
           AND (\
               (observation.visibility IN ('private', 'managed') \
                AND consent.purpose = 'private_history') \
               OR (observation.visibility = 'shared' \
                   AND consent.purpose = 'shared_observation')\
           ) \
         ORDER BY observation.observed_at, observation.id",
    )
    .bind(key.tenant_id)
    .bind(key.normalized_username)
    .bind(key.site_id)
    .bind(key.rule_version_id)
    .bind(now_unix_ms)
    .bind(key.rule_hash)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| JobError::StorageInvariant)?;
    if rows.is_empty() {
        return Ok(None);
    }

    let domain_observations = rows
        .iter()
        .map(domain_observation)
        .collect::<Result<Vec<_>, _>>()?;
    let assertion = derive_assertion(
        &domain_observations,
        now_unix_ms,
        DerivationPolicy::default(),
    )
    .map_err(|_| JobError::StorageInvariant)?;
    if assertion.derivation_version != ASSERTION_DERIVATION_VERSION {
        return Err(JobError::StorageInvariant);
    }
    let regional_assertions = derive_regional_assertions(
        &domain_observations,
        now_unix_ms,
        DerivationPolicy::default(),
    )
    .map_err(|_| JobError::StorageInvariant)?
    .into_iter()
    .map(|(region, assertion)| {
        if assertion.derivation_version != ASSERTION_DERIVATION_VERSION
            || assertion.regions.len() != 1
            || !assertion.regions.contains(&region)
        {
            return Err(JobError::StorageInvariant);
        }
        let sources = assertion_sources(rows.iter().filter(|row| row.region_class == region))?;
        Ok((region, DerivedRegionalAssertion { assertion, sources }))
    })
    .collect::<Result<BTreeMap<_, _>, JobError>>()?;
    let evidence = rows
        .iter()
        .map(assertion_evidence)
        .collect::<Result<Vec<_>, _>>()?;
    let sources = assertion_sources(&rows)?;
    let expected_support = expected_support(&assertion)?;

    let current: Option<CurrentAssertionRow> = sqlx::query_as(
        "SELECT assertion.id, assertion.outcome_kind, assertion.verdict, \
                assertion.uncertainty_reason, assertion.quality, \
                assertion.evidence_class, \
                (extract(epoch FROM assertion.observed_at) * 1000)::bigint \
                    AS observed_at_unix_ms, \
                (extract(epoch FROM assertion.expires_at) * 1000)::bigint \
                    AS expires_at_unix_ms, \
                assertion.derivation_version \
         FROM assertions AS assertion \
         WHERE assertion.tenant_id = $1 \
           AND assertion.normalized_username = $2 \
           AND assertion.site_id = $3 \
           AND assertion.is_current \
           AND assertion.withdrawn_at IS NULL \
         FOR UPDATE",
    )
    .bind(key.tenant_id)
    .bind(key.normalized_username)
    .bind(key.site_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| JobError::StorageInvariant)?;

    if let Some(current) = current.as_ref() {
        let current_support: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT observation_id, support_role \
             FROM assertion_support \
             WHERE tenant_id = $1 AND assertion_id = $2 \
             ORDER BY observation_id, support_role",
        )
        .bind(key.tenant_id)
        .bind(current.id)
        .fetch_all(&mut **transaction)
        .await
        .map_err(|_| JobError::StorageInvariant)?;
        if assertion_matches(current, &assertion)
            && current_support == expected_support
            && regional_assertions_match(
                transaction,
                key.tenant_id,
                current.id,
                &regional_assertions,
            )
            .await?
        {
            return Ok(Some(DerivedAssertion {
                id: current.id,
                assertion,
                regional_assertions,
                evidence,
                sources,
            }));
        }
    }

    if let Some(current) = current {
        let affected = sqlx::query(
            "UPDATE assertions \
             SET is_current = false \
             WHERE tenant_id = $1 AND id = $2 \
               AND is_current AND withdrawn_at IS NULL",
        )
        .bind(key.tenant_id)
        .bind(current.id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| JobError::StorageInvariant)?
        .rows_affected();
        if affected != 1 {
            return Err(JobError::StorageInvariant);
        }
    }

    let assertion_id = Uuid::new_v4();
    let (outcome_kind, verdict, uncertainty_reason) = assertion_outcome(&assertion)?;
    sqlx::query(
        "INSERT INTO assertions (\
            id, tenant_id, normalized_username, site_id, outcome_kind, \
            verdict, uncertainty_reason, quality, evidence_class, observed_at, \
            expires_at, derivation_version, is_current, created_at\
         ) VALUES (\
            $1, $2, $3, $4, $5, $6, $7, $8, $9, \
            to_timestamp($10::double precision / 1000.0), \
            to_timestamp($11::double precision / 1000.0), $12, true, \
            clock_timestamp()\
         )",
    )
    .bind(assertion_id)
    .bind(key.tenant_id)
    .bind(key.normalized_username)
    .bind(key.site_id)
    .bind(outcome_kind)
    .bind(verdict)
    .bind(uncertainty_reason)
    .bind(assertion_quality_name(assertion.quality))
    .bind(evidence_class_name(assertion.evidence_class))
    .bind(assertion.observed_at_unix_ms)
    .bind(assertion.expires_at_unix_ms)
    .bind(assertion.derivation_version)
    .execute(&mut **transaction)
    .await
    .map_err(|_| JobError::StorageInvariant)?;

    for (observation_id, support_role) in &expected_support {
        sqlx::query(
            "INSERT INTO assertion_support (\
                tenant_id, assertion_id, observation_id, support_role, created_at\
             ) VALUES ($1, $2, $3, $4, clock_timestamp())",
        )
        .bind(key.tenant_id)
        .bind(assertion_id)
        .bind(observation_id)
        .bind(support_role)
        .execute(&mut **transaction)
        .await
        .map_err(|_| JobError::StorageInvariant)?;
        insert_lineage(
            transaction,
            key.tenant_id,
            "observation",
            *observation_id,
            "assertion",
            assertion_id,
            support_role,
        )
        .await?;
    }
    persist_regional_assertions(
        transaction,
        key.tenant_id,
        assertion_id,
        &regional_assertions,
    )
    .await?;

    Ok(Some(DerivedAssertion {
        id: assertion_id,
        assertion,
        regional_assertions,
        evidence,
        sources,
    }))
}

async fn regional_assertions_match(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    assertion_id: Uuid,
    expected: &BTreeMap<String, DerivedRegionalAssertion>,
) -> Result<bool, JobError> {
    let current: Vec<CurrentRegionalAssertionRow> = sqlx::query_as(
        "SELECT regional.id, regional.region_class, regional.outcome_kind, \
                regional.verdict, regional.uncertainty_reason, \
                regional.quality, regional.evidence_class, \
                (extract(epoch FROM regional.observed_at) * 1000)::bigint \
                    AS observed_at_unix_ms, \
                (extract(epoch FROM regional.expires_at) * 1000)::bigint \
                    AS expires_at_unix_ms, \
                regional.support_group_count, regional.managed_support \
         FROM regional_assertions AS regional \
         WHERE regional.tenant_id = $1 AND regional.assertion_id = $2 \
         ORDER BY regional.region_class",
    )
    .bind(tenant_id)
    .bind(assertion_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| JobError::StorageInvariant)?;
    if current.len() != expected.len() {
        return Ok(false);
    }

    for regional in current {
        let Some(expected) = expected.get(&regional.region_class) else {
            return Ok(false);
        };
        if !regional_assertion_matches(&regional, &expected.assertion)? {
            return Ok(false);
        }
        let current_support: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT observation_id, support_role \
             FROM regional_assertion_support \
             WHERE tenant_id = $1 AND regional_assertion_id = $2 \
             ORDER BY observation_id, support_role",
        )
        .bind(tenant_id)
        .bind(regional.id)
        .fetch_all(&mut **transaction)
        .await
        .map_err(|_| JobError::StorageInvariant)?;
        if current_support != expected_support(&expected.assertion)? {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn persist_regional_assertions(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    assertion_id: Uuid,
    regional_assertions: &BTreeMap<String, DerivedRegionalAssertion>,
) -> Result<(), JobError> {
    if regional_assertions.is_empty() || regional_assertions.len() > 16 {
        return Err(JobError::StorageInvariant);
    }
    for (region, derived) in regional_assertions {
        let assertion = &derived.assertion;
        if assertion.regions.len() != 1 || !assertion.regions.contains(region) {
            return Err(JobError::StorageInvariant);
        }
        let regional_assertion_id = Uuid::new_v4();
        let (outcome_kind, verdict, uncertainty_reason) = assertion_outcome(assertion)?;
        let support_group_count =
            i32::try_from(assertion.support_group_count).map_err(|_| JobError::StorageInvariant)?;
        sqlx::query(
            "INSERT INTO regional_assertions (\
                id, tenant_id, assertion_id, region_class, outcome_kind, \
                verdict, uncertainty_reason, quality, evidence_class, \
                observed_at, expires_at, support_group_count, managed_support, \
                created_at\
             ) VALUES (\
                $1, $2, $3, $4, $5, $6, $7, $8, $9, \
                to_timestamp($10::double precision / 1000.0), \
                to_timestamp($11::double precision / 1000.0), $12, $13, \
                clock_timestamp()\
             )",
        )
        .bind(regional_assertion_id)
        .bind(tenant_id)
        .bind(assertion_id)
        .bind(region)
        .bind(outcome_kind)
        .bind(verdict)
        .bind(uncertainty_reason)
        .bind(assertion_quality_name(assertion.quality))
        .bind(evidence_class_name(assertion.evidence_class))
        .bind(assertion.observed_at_unix_ms)
        .bind(assertion.expires_at_unix_ms)
        .bind(support_group_count)
        .bind(assertion.managed_support)
        .execute(&mut **transaction)
        .await
        .map_err(|_| JobError::StorageInvariant)?;

        for (observation_id, support_role) in expected_support(assertion)? {
            sqlx::query(
                "INSERT INTO regional_assertion_support (\
                    tenant_id, regional_assertion_id, observation_id, \
                    support_role, created_at\
                 ) VALUES ($1, $2, $3, $4, clock_timestamp())",
            )
            .bind(tenant_id)
            .bind(regional_assertion_id)
            .bind(observation_id)
            .bind(&support_role)
            .execute(&mut **transaction)
            .await
            .map_err(|_| JobError::StorageInvariant)?;
            insert_lineage(
                transaction,
                tenant_id,
                "observation",
                observation_id,
                "regional_assertion",
                regional_assertion_id,
                &support_role,
            )
            .await?;
        }
        insert_lineage(
            transaction,
            tenant_id,
            "regional_assertion",
            regional_assertion_id,
            "assertion",
            assertion_id,
            "regional_projection",
        )
        .await?;
    }
    Ok(())
}

pub(crate) async fn apply_watch_interpretation(
    transaction: &mut Transaction<'_, Postgres>,
    key: &WatchInterpretationKey<'_>,
    derived: Option<&DerivedAssertion>,
    measurement: MeasurementOutcome,
    detected_at_unix_ms: i64,
) -> Result<(), JobError> {
    record_measurement_transition(
        transaction,
        key.tenant_id,
        key.watch_target_id,
        key.rule_version_id,
        key.region_class,
        measurement,
        detected_at_unix_ms,
    )
    .await?;

    let baseline: LockedAccountBaseline = sqlx::query_as(
        "SELECT account_state, account_assertion_id, \
                CASE WHEN account_state_since IS NULL THEN NULL \
                     ELSE (extract(epoch FROM account_state_since) * 1000)::bigint \
                END AS account_state_since_unix_ms \
         FROM watch_targets \
         WHERE tenant_id = $1 AND id = $2 \
         FOR UPDATE",
    )
    .bind(key.tenant_id)
    .bind(key.watch_target_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| JobError::StorageInvariant)?;
    validate_baseline(&baseline)?;

    let Some(derived) = derived else {
        return Ok(());
    };
    match derived.assertion.verdict {
        Verdict::Inconclusive => {
            suppress_open_account_candidates(
                transaction,
                key.tenant_id,
                key.watch_target_id,
                derived,
            )
            .await?;
            elevate_watch_probe_priorities(
                transaction,
                key.tenant_id,
                key.watch_target_id,
                VerificationPriority::RegionalConflict,
            )
            .await?;
            return Ok(());
        }
        Verdict::Found | Verdict::NotFound => {}
        Verdict::InvalidUsername => return Err(JobError::StorageInvariant),
    }
    if !matches!(
        derived.assertion.quality,
        DomainAssertionQuality::Verified | DomainAssertionQuality::Corroborated
    ) {
        return Ok(());
    }
    let next_state = verdict_name(derived.assertion.verdict)?;

    let Some(current_state) = baseline.account_state.as_deref() else {
        let affected = sqlx::query(
            "UPDATE watch_targets \
             SET account_state = $3, account_assertion_id = $4, \
                 account_state_since = \
                     to_timestamp($5::double precision / 1000.0) \
             WHERE tenant_id = $1 AND id = $2 \
               AND account_state IS NULL \
               AND account_assertion_id IS NULL \
               AND account_state_since IS NULL",
        )
        .bind(key.tenant_id)
        .bind(key.watch_target_id)
        .bind(next_state)
        .bind(derived.id)
        .bind(derived.assertion.observed_at_unix_ms)
        .execute(&mut **transaction)
        .await
        .map_err(|_| JobError::StorageInvariant)?
        .rows_affected();
        if affected != 1 {
            return Err(JobError::StorageInvariant);
        }
        insert_lineage(
            transaction,
            key.tenant_id,
            "assertion",
            derived.id,
            "watch_target",
            key.watch_target_id,
            "account_baseline",
        )
        .await?;
        return Ok(());
    };

    if current_state == next_state {
        sqlx::query(
            "UPDATE watch_targets \
             SET account_assertion_id = $3 \
             WHERE tenant_id = $1 AND id = $2 AND account_state = $4",
        )
        .bind(key.tenant_id)
        .bind(key.watch_target_id)
        .bind(derived.id)
        .bind(current_state)
        .execute(&mut **transaction)
        .await
        .map_err(|_| JobError::StorageInvariant)?;
        insert_lineage(
            transaction,
            key.tenant_id,
            "assertion",
            derived.id,
            "watch_target",
            key.watch_target_id,
            "account_baseline_refresh",
        )
        .await?;
        suppress_open_account_candidates(transaction, key.tenant_id, key.watch_target_id, derived)
            .await?;
        return Ok(());
    }

    let state_since = baseline
        .account_state_since_unix_ms
        .ok_or(JobError::StorageInvariant)?;
    let confirmation = account_confirmation(derived, state_since)?;
    let transition_id = upsert_account_candidate(
        transaction,
        key.tenant_id,
        key.watch_target_id,
        current_state,
        next_state,
        confirmation,
        detected_at_unix_ms,
    )
    .await?;
    attach_transition_basis(
        transaction,
        key.tenant_id,
        transition_id,
        derived.supporting_evidence(),
    )
    .await?;
    insert_lineage(
        transaction,
        key.tenant_id,
        "assertion",
        derived.id,
        "transition",
        transition_id,
        "account_state_candidate",
    )
    .await?;

    if matches!(
        confirmation,
        AccountConfirmation::Pending(_) | AccountConfirmation::Suppressed("shared_only_absence")
    ) {
        elevate_watch_probe_priorities(
            transaction,
            key.tenant_id,
            key.watch_target_id,
            VerificationPriority::AccountConfirmation,
        )
        .await?;
    }

    if let AccountConfirmation::Confirmed(confirmation_basis) = confirmation {
        let affected = sqlx::query(
            "UPDATE watch_targets \
             SET account_state = $3, account_assertion_id = $4, \
                 account_state_since = \
                     to_timestamp($5::double precision / 1000.0) \
             WHERE tenant_id = $1 AND id = $2 AND account_state = $6",
        )
        .bind(key.tenant_id)
        .bind(key.watch_target_id)
        .bind(next_state)
        .bind(derived.id)
        .bind(derived.assertion.observed_at_unix_ms)
        .bind(current_state)
        .execute(&mut **transaction)
        .await
        .map_err(|_| JobError::StorageInvariant)?
        .rows_affected();
        if affected != 1 {
            return Err(JobError::StorageInvariant);
        }
        enqueue_confirmed_transition(
            transaction,
            key.tenant_id,
            key.watch_target_id,
            transition_id,
            confirmation_basis,
        )
        .await?;
    }
    Ok(())
}

impl DerivedAssertion {
    fn supporting_evidence(&self) -> Vec<&AssertionEvidence> {
        let supporting = self
            .assertion
            .supporting_observation_ids
            .iter()
            .map(DomainObservationId::as_str)
            .collect::<BTreeSet<_>>();
        self.evidence
            .iter()
            .filter(|item| supporting.contains(item.observation_id.to_string().as_str()))
            .collect()
    }

    fn conflicting_evidence(&self) -> Vec<&AssertionEvidence> {
        let conflicting = self
            .assertion
            .conflicting_observation_ids
            .iter()
            .map(DomainObservationId::as_str)
            .collect::<BTreeSet<_>>();
        self.evidence
            .iter()
            .filter(|item| conflicting.contains(item.observation_id.to_string().as_str()))
            .collect()
    }
}

async fn record_measurement_transition(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    watch_target_id: Uuid,
    rule_version_id: Uuid,
    region_class: &str,
    measurement: MeasurementOutcome,
    detected_at_unix_ms: i64,
) -> Result<(), JobError> {
    let current_state: Option<String> = sqlx::query_scalar(
        "SELECT to_state \
         FROM transitions \
         WHERE tenant_id = $1 AND watch_target_id = $2 \
           AND transition_class = 'measurement_health' \
           AND rule_version_id = $3 AND region_class = $4 \
         ORDER BY created_at DESC, id DESC \
         LIMIT 1 \
         FOR UPDATE",
    )
    .bind(tenant_id)
    .bind(watch_target_id)
    .bind(rule_version_id)
    .bind(region_class)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| JobError::StorageInvariant)?;
    let current_state = current_state.as_deref().unwrap_or("healthy");
    let next_state = measurement.state();
    if current_state == next_state {
        return Ok(());
    }

    let transition_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO transitions (\
            id, tenant_id, watch_target_id, transition_class, from_state, \
            to_state, region_class, rule_version_id, confirmation_status, \
            confirmation_basis, derivation_version, detected_at, created_at\
         ) VALUES (\
            $1, $2, $3, 'measurement_health', $4, $5, $6, $7, \
            'confirmed', 'measurement_health_evidence', $8, \
            to_timestamp($9::double precision / 1000.0), clock_timestamp()\
         )",
    )
    .bind(transition_id)
    .bind(tenant_id)
    .bind(watch_target_id)
    .bind(current_state)
    .bind(next_state)
    .bind(region_class)
    .bind(rule_version_id)
    .bind(TRANSITION_DERIVATION_VERSION)
    .bind(detected_at_unix_ms)
    .execute(&mut **transaction)
    .await
    .map_err(|_| JobError::StorageInvariant)?;
    if let Some(observation_id) = measurement.observation_id() {
        attach_transition_basis_ids(
            transaction,
            tenant_id,
            transition_id,
            std::iter::once(observation_id),
        )
        .await?;
        insert_lineage(
            transaction,
            tenant_id,
            "observation",
            observation_id,
            "transition",
            transition_id,
            "measurement_health",
        )
        .await?;
    }
    if let Some(probe_job_id) = measurement.probe_job_id() {
        insert_lineage(
            transaction,
            tenant_id,
            "probe_job",
            probe_job_id,
            "transition",
            transition_id,
            "measurement_unavailable",
        )
        .await?;
    }
    enqueue_confirmed_transition(
        transaction,
        tenant_id,
        watch_target_id,
        transition_id,
        "measurement_health_evidence",
    )
    .await?;
    Ok(())
}

async fn suppress_open_account_candidates(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    watch_target_id: Uuid,
    derived: &DerivedAssertion,
) -> Result<(), JobError> {
    let transition_ids: Vec<Uuid> = sqlx::query_scalar(
        "UPDATE transitions \
         SET confirmation_status = 'suppressed', confirmation_basis = NULL, \
             pending_reason = NULL, suppression_reason = 'conflicting_evidence' \
         WHERE tenant_id = $1 AND watch_target_id = $2 \
           AND transition_class = 'account_state' \
           AND confirmation_status = 'pending' \
         RETURNING id",
    )
    .bind(tenant_id)
    .bind(watch_target_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| JobError::StorageInvariant)?;
    let basis = if derived.assertion.verdict == Verdict::Inconclusive {
        derived.conflicting_evidence()
    } else {
        derived.supporting_evidence()
    };
    for transition_id in transition_ids {
        attach_transition_basis(transaction, tenant_id, transition_id, basis.clone()).await?;
        insert_lineage(
            transaction,
            tenant_id,
            "assertion",
            derived.id,
            "transition",
            transition_id,
            "candidate_suppression",
        )
        .await?;
    }
    Ok(())
}

fn account_confirmation(
    derived: &DerivedAssertion,
    state_since_unix_ms: i64,
) -> Result<AccountConfirmation, JobError> {
    let evidence = derived
        .supporting_evidence()
        .into_iter()
        .filter(|item| item.observed_at_unix_ms >= state_since_unix_ms)
        .collect::<Vec<_>>();
    let managed = evidence
        .iter()
        .copied()
        .filter(|item| item.managed)
        .collect::<Vec<_>>();
    match derived.assertion.verdict {
        Verdict::Found => {
            if managed
                .iter()
                .any(|item| item.evidence_class == DomainEvidenceClass::E4StructuredIdentity)
            {
                return Ok(AccountConfirmation::Confirmed("managed_e4"));
            }
            if observations_are_separated(&managed, 1) {
                return Ok(AccountConfirmation::Confirmed("managed_e3_follow_up"));
            }
            if managed.is_empty() {
                Ok(AccountConfirmation::Pending(
                    "managed_verification_required",
                ))
            } else {
                Ok(AccountConfirmation::Pending(
                    "second_managed_observation_required",
                ))
            }
        }
        Verdict::NotFound => {
            if managed.is_empty() {
                return Ok(AccountConfirmation::Suppressed("shared_only_absence"));
            }
            let regions = managed
                .iter()
                .map(|item| item.region_class.as_str())
                .collect::<BTreeSet<_>>();
            if regions.len() >= 2 {
                return Ok(AccountConfirmation::Confirmed(
                    "two_managed_independent_regions",
                ));
            }
            if observations_are_separated(&managed, FOLLOW_UP_DELAY_MS) {
                return Ok(AccountConfirmation::Confirmed(
                    "two_managed_separated_in_time",
                ));
            }
            Ok(AccountConfirmation::Pending(
                "second_managed_observation_required",
            ))
        }
        Verdict::InvalidUsername | Verdict::Inconclusive => Err(JobError::StorageInvariant),
    }
}

fn observations_are_separated(evidence: &[&AssertionEvidence], minimum_span_ms: i64) -> bool {
    if evidence.len() < 2 {
        return false;
    }
    let first = evidence
        .iter()
        .map(|item| item.observed_at_unix_ms)
        .min()
        .unwrap_or(i64::MAX);
    let last = evidence
        .iter()
        .map(|item| item.observed_at_unix_ms)
        .max()
        .unwrap_or(i64::MIN);
    last.saturating_sub(first) >= minimum_span_ms
}

async fn upsert_account_candidate(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    watch_target_id: Uuid,
    from_state: &str,
    to_state: &str,
    confirmation: AccountConfirmation,
    detected_at_unix_ms: i64,
) -> Result<Uuid, JobError> {
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id \
         FROM transitions \
         WHERE tenant_id = $1 AND watch_target_id = $2 \
           AND transition_class = 'account_state' \
           AND from_state = $3 AND to_state = $4 \
           AND confirmation_status IN ('pending', 'suppressed') \
         ORDER BY created_at DESC, id DESC \
         LIMIT 1 \
         FOR UPDATE",
    )
    .bind(tenant_id)
    .bind(watch_target_id)
    .bind(from_state)
    .bind(to_state)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| JobError::StorageInvariant)?;
    let (status, basis, pending, suppression) = confirmation_values(confirmation);
    if let Some(transition_id) = existing {
        sqlx::query(
            "UPDATE transitions \
             SET confirmation_status = $3, confirmation_basis = $4, \
                 pending_reason = $5, suppression_reason = $6 \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(transition_id)
        .bind(status)
        .bind(basis)
        .bind(pending)
        .bind(suppression)
        .execute(&mut **transaction)
        .await
        .map_err(|_| JobError::StorageInvariant)?;
        return Ok(transition_id);
    }

    let transition_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO transitions (\
            id, tenant_id, watch_target_id, transition_class, from_state, \
            to_state, confirmation_status, confirmation_basis, pending_reason, \
            suppression_reason, derivation_version, detected_at, created_at\
         ) VALUES (\
            $1, $2, $3, 'account_state', $4, $5, $6, $7, $8, $9, $10, \
            to_timestamp($11::double precision / 1000.0), clock_timestamp()\
         )",
    )
    .bind(transition_id)
    .bind(tenant_id)
    .bind(watch_target_id)
    .bind(from_state)
    .bind(to_state)
    .bind(status)
    .bind(basis)
    .bind(pending)
    .bind(suppression)
    .bind(TRANSITION_DERIVATION_VERSION)
    .bind(detected_at_unix_ms)
    .execute(&mut **transaction)
    .await
    .map_err(|_| JobError::StorageInvariant)?;
    Ok(transition_id)
}

const fn confirmation_values(
    confirmation: AccountConfirmation,
) -> (
    &'static str,
    Option<&'static str>,
    Option<&'static str>,
    Option<&'static str>,
) {
    match confirmation {
        AccountConfirmation::Confirmed(basis) => ("confirmed", Some(basis), None, None),
        AccountConfirmation::Pending(reason) => ("pending", None, Some(reason), None),
        AccountConfirmation::Suppressed(reason) => ("suppressed", None, None, Some(reason)),
    }
}

async fn attach_transition_basis(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    transition_id: Uuid,
    evidence: Vec<&AssertionEvidence>,
) -> Result<(), JobError> {
    attach_transition_basis_ids(
        transaction,
        tenant_id,
        transition_id,
        evidence.into_iter().map(|item| item.observation_id),
    )
    .await
}

async fn attach_transition_basis_ids(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    transition_id: Uuid,
    observation_ids: impl IntoIterator<Item = Uuid>,
) -> Result<(), JobError> {
    for observation_id in observation_ids {
        sqlx::query(
            "INSERT INTO transition_basis (\
                tenant_id, transition_id, observation_id, created_at\
             ) VALUES ($1, $2, $3, clock_timestamp()) \
             ON CONFLICT (tenant_id, transition_id, observation_id) DO NOTHING",
        )
        .bind(tenant_id)
        .bind(transition_id)
        .bind(observation_id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| JobError::StorageInvariant)?;
    }
    Ok(())
}

fn validate_baseline(baseline: &LockedAccountBaseline) -> Result<(), JobError> {
    let populated = baseline.account_state.is_some()
        && baseline.account_assertion_id.is_some()
        && baseline.account_state_since_unix_ms.is_some();
    let empty = baseline.account_state.is_none()
        && baseline.account_assertion_id.is_none()
        && baseline.account_state_since_unix_ms.is_none();
    if populated || empty {
        Ok(())
    } else {
        Err(JobError::StorageInvariant)
    }
}

fn domain_observation(row: &EligibleObservationRow) -> Result<DomainObservation, JobError> {
    let producer_kind = match row.producer_kind.as_str() {
        "managed_worker" => ProducerKind::ManagedWorker,
        "shared_cli" => ProducerKind::SharedCli,
        _ => return Err(JobError::StorageInvariant),
    };
    let managed = producer_kind == ProducerKind::ManagedWorker;
    let collection_profile = if managed {
        CollectionProfile::Managed
    } else {
        match row.visibility.as_str() {
            "shared" => CollectionProfile::SharedObservation,
            "private" | "managed" => CollectionProfile::PrivateHistory,
            _ => return Err(JobError::StorageInvariant),
        }
    };
    let group = if managed {
        format!("managed:{}", row.region_class)
    } else {
        format!("untrusted:{}", row.id)
    };
    Ok(DomainObservation {
        id: DomainObservationId::new(row.id.to_string()),
        target: TargetKey {
            site_id: DomainSiteId::new(row.site_id.clone()),
            normalized_username: row.normalized_username.clone(),
        },
        verdict: parse_verdict(&row.verdict)?,
        inconclusive_reason: None,
        evidence_class: parse_evidence_class(&row.evidence_class)?,
        observed_at_unix_ms: row.observed_at_unix_ms,
        expires_at_unix_ms: row.expires_at_unix_ms,
        region: row.region_class.clone(),
        network_group: group.clone(),
        independence_group: group,
        producer_kind,
        producer_reputation: if managed {
            ProducerReputation::Trusted
        } else {
            ProducerReputation::New
        },
        collection_profile,
        rule_hash: row.rule_hash.clone(),
        rule_health_green: true,
        evidence_digest: row.evidence_digest.clone(),
    })
}

fn assertion_evidence(row: &EligibleObservationRow) -> Result<AssertionEvidence, JobError> {
    Ok(AssertionEvidence {
        observation_id: row.id,
        evidence_class: parse_evidence_class(&row.evidence_class)?,
        observed_at_unix_ms: row.observed_at_unix_ms,
        region_class: row.region_class.clone(),
        managed: row.producer_kind == "managed_worker",
    })
}

fn assertion_sources<'a>(
    rows: impl IntoIterator<Item = &'a EligibleObservationRow>,
) -> Result<Vec<ResultSource>, JobError> {
    let mut has_private = false;
    let mut has_shared = false;
    let mut has_managed = false;
    for row in rows {
        match row.source.as_str() {
            "private_cloud" => has_private = true,
            "shared_assertion" => has_shared = true,
            "managed_probe" => has_managed = true,
            _ => return Err(JobError::StorageInvariant),
        }
    }
    let mut sources = Vec::new();
    if has_private {
        sources.push(ResultSource::PrivateCloud);
    }
    if has_shared {
        sources.push(ResultSource::SharedAssertion);
    }
    if has_managed {
        sources.push(ResultSource::ManagedProbe);
    }
    if sources.is_empty() {
        Err(JobError::StorageInvariant)
    } else {
        Ok(sources)
    }
}

fn protocol_regional_assertion(
    region: &str,
    derived: &DerivedRegionalAssertion,
    evaluated_at_unix_ms: i64,
    maximum_age_ms: i64,
) -> Result<RegionalAssertion, JobError> {
    let assertion = &derived.assertion;
    if assertion.regions.len() != 1 || !assertion.regions.contains(region) {
        return Err(JobError::StorageInvariant);
    }
    let freshness = Freshness::new(
        assertion.observed_at_unix_ms,
        assertion.expires_at_unix_ms,
        evaluated_at_unix_ms,
        maximum_age_ms,
    )
    .map_err(|_| JobError::InvalidProtocol)?;
    let quality = if freshness.state == FreshnessState::Current {
        protocol_assertion_quality(assertion.quality)
    } else {
        AssertionQuality::Stale
    };
    let outcome = match assertion.verdict {
        Verdict::Found => AssertionOutcome::Found,
        Verdict::NotFound => AssertionOutcome::NotFound,
        Verdict::Inconclusive => AssertionOutcome::Inconclusive {
            reason: socialname_protocol::UncertaintyReason::ConflictingEvidence,
        },
        Verdict::InvalidUsername => return Err(JobError::StorageInvariant),
    };
    let supporting_observation_ids = assertion
        .supporting_observation_ids
        .iter()
        .map(|id| ObservationId::new(id.as_str().to_owned()).map_err(|_| JobError::InvalidProtocol))
        .collect::<Result<Vec<_>, _>>()?;
    let conflicting_observation_ids = assertion
        .conflicting_observation_ids
        .iter()
        .map(|id| ObservationId::new(id.as_str().to_owned()).map_err(|_| JobError::InvalidProtocol))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(RegionalAssertion {
        region_class: RegionClass::new(region.to_owned()).map_err(|_| JobError::InvalidProtocol)?,
        outcome,
        quality,
        evidence_class: protocol_evidence_class(assertion.evidence_class),
        freshness,
        sources: derived.sources.clone(),
        support_group_count: u32::try_from(assertion.support_group_count)
            .map_err(|_| JobError::StorageInvariant)?,
        managed_support: assertion.managed_support,
        supporting_observation_ids,
        conflicting_observation_ids,
    })
}

fn expected_support(assertion: &DomainAssertion) -> Result<Vec<(Uuid, String)>, JobError> {
    let mut support = assertion
        .supporting_observation_ids
        .iter()
        .map(|id| {
            Ok((
                Uuid::parse_str(id.as_str()).map_err(|_| JobError::StorageInvariant)?,
                "supporting".to_owned(),
            ))
        })
        .collect::<Result<Vec<_>, JobError>>()?;
    support.extend(
        assertion
            .conflicting_observation_ids
            .iter()
            .map(|id| {
                Ok((
                    Uuid::parse_str(id.as_str()).map_err(|_| JobError::StorageInvariant)?,
                    "conflicting".to_owned(),
                ))
            })
            .collect::<Result<Vec<_>, JobError>>()?,
    );
    support.sort();
    Ok(support)
}

fn assertion_matches(current: &CurrentAssertionRow, assertion: &DomainAssertion) -> bool {
    let Ok((outcome_kind, verdict, uncertainty_reason)) = assertion_outcome(assertion) else {
        return false;
    };
    current.outcome_kind == outcome_kind
        && current.verdict.as_deref() == verdict
        && current.uncertainty_reason.as_deref() == uncertainty_reason
        && current.quality == assertion_quality_name(assertion.quality)
        && current.evidence_class == evidence_class_name(assertion.evidence_class)
        && current.observed_at_unix_ms == assertion.observed_at_unix_ms
        && current.expires_at_unix_ms == assertion.expires_at_unix_ms
        && current.derivation_version == assertion.derivation_version
}

fn regional_assertion_matches(
    current: &CurrentRegionalAssertionRow,
    assertion: &DomainAssertion,
) -> Result<bool, JobError> {
    let (outcome_kind, verdict, uncertainty_reason) = assertion_outcome(assertion)?;
    let support_group_count =
        i32::try_from(assertion.support_group_count).map_err(|_| JobError::StorageInvariant)?;
    Ok(current.outcome_kind == outcome_kind
        && current.verdict.as_deref() == verdict
        && current.uncertainty_reason.as_deref() == uncertainty_reason
        && current.quality == assertion_quality_name(assertion.quality)
        && current.evidence_class == evidence_class_name(assertion.evidence_class)
        && current.observed_at_unix_ms == assertion.observed_at_unix_ms
        && current.expires_at_unix_ms == assertion.expires_at_unix_ms
        && current.support_group_count == support_group_count
        && current.managed_support == assertion.managed_support)
}

fn assertion_outcome(
    assertion: &DomainAssertion,
) -> Result<(&'static str, Option<&'static str>, Option<&'static str>), JobError> {
    match assertion.verdict {
        Verdict::Found => Ok(("definitive", Some("found"), None)),
        Verdict::NotFound => Ok(("definitive", Some("not_found"), None)),
        Verdict::Inconclusive if assertion.quality == DomainAssertionQuality::Conflicted => {
            Ok(("inconclusive", None, Some("conflicting_evidence")))
        }
        Verdict::InvalidUsername | Verdict::Inconclusive => Err(JobError::StorageInvariant),
    }
}

const fn assertion_quality_name(quality: DomainAssertionQuality) -> &'static str {
    match quality {
        DomainAssertionQuality::Verified => "verified",
        DomainAssertionQuality::Corroborated => "corroborated",
        DomainAssertionQuality::SingleVantage => "single_vantage",
        DomainAssertionQuality::Stale => "stale",
        DomainAssertionQuality::Conflicted => "conflicted",
        DomainAssertionQuality::Untrusted => "untrusted",
    }
}

const fn protocol_assertion_quality(quality: DomainAssertionQuality) -> AssertionQuality {
    match quality {
        DomainAssertionQuality::Verified => AssertionQuality::Verified,
        DomainAssertionQuality::Corroborated => AssertionQuality::Corroborated,
        DomainAssertionQuality::SingleVantage => AssertionQuality::SingleVantage,
        DomainAssertionQuality::Stale => AssertionQuality::Stale,
        DomainAssertionQuality::Conflicted => AssertionQuality::Conflicted,
        DomainAssertionQuality::Untrusted => AssertionQuality::Untrusted,
    }
}

fn parse_verdict(value: &str) -> Result<Verdict, JobError> {
    match value {
        "found" => Ok(Verdict::Found),
        "not_found" => Ok(Verdict::NotFound),
        _ => Err(JobError::StorageInvariant),
    }
}

const fn verdict_name(verdict: Verdict) -> Result<&'static str, JobError> {
    match verdict {
        Verdict::Found => Ok("found"),
        Verdict::NotFound => Ok("not_found"),
        Verdict::InvalidUsername | Verdict::Inconclusive => Err(JobError::StorageInvariant),
    }
}

fn parse_evidence_class(value: &str) -> Result<DomainEvidenceClass, JobError> {
    match value {
        "e0_no_account_evidence" => Ok(DomainEvidenceClass::E0NoAccountEvidence),
        "e1_weak_signal" => Ok(DomainEvidenceClass::E1WeakSignal),
        "e2_differential_template" => Ok(DomainEvidenceClass::E2DifferentialTemplate),
        "e3_explicit_endpoint" => Ok(DomainEvidenceClass::E3ExplicitEndpoint),
        "e4_structured_identity" => Ok(DomainEvidenceClass::E4StructuredIdentity),
        _ => Err(JobError::StorageInvariant),
    }
}

const fn evidence_class_name(value: DomainEvidenceClass) -> &'static str {
    match value {
        DomainEvidenceClass::E0NoAccountEvidence => "e0_no_account_evidence",
        DomainEvidenceClass::E1WeakSignal => "e1_weak_signal",
        DomainEvidenceClass::E2DifferentialTemplate => "e2_differential_template",
        DomainEvidenceClass::E3ExplicitEndpoint => "e3_explicit_endpoint",
        DomainEvidenceClass::E4StructuredIdentity => "e4_structured_identity",
    }
}

const fn protocol_evidence_class(value: DomainEvidenceClass) -> EvidenceClass {
    match value {
        DomainEvidenceClass::E0NoAccountEvidence => EvidenceClass::E0NoAccountEvidence,
        DomainEvidenceClass::E1WeakSignal => EvidenceClass::E1WeakSignal,
        DomainEvidenceClass::E2DifferentialTemplate => EvidenceClass::E2DifferentialTemplate,
        DomainEvidenceClass::E3ExplicitEndpoint => EvidenceClass::E3ExplicitEndpoint,
        DomainEvidenceClass::E4StructuredIdentity => EvidenceClass::E4StructuredIdentity,
    }
}

async fn insert_lineage(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    parent_kind: &str,
    parent_id: Uuid,
    child_kind: &str,
    child_id: Uuid,
    purpose: &str,
) -> Result<(), JobError> {
    sqlx::query(
        "INSERT INTO data_lineage_edges (\
            id, tenant_id, parent_kind, parent_id, child_kind, child_id, \
            purpose, created_at\
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, clock_timestamp()) \
         ON CONFLICT (tenant_id, parent_kind, parent_id, child_kind, child_id, purpose) \
         DO NOTHING",
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(parent_kind)
    .bind(parent_id)
    .bind(child_kind)
    .bind(child_id)
    .bind(purpose)
    .execute(&mut **transaction)
    .await
    .map_err(|_| JobError::StorageInvariant)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use socialname_protocol::Validate;

    fn evidence(
        value: u128,
        class: DomainEvidenceClass,
        observed_at_unix_ms: i64,
        region: &str,
        managed: bool,
    ) -> AssertionEvidence {
        AssertionEvidence {
            observation_id: Uuid::from_u128(value),
            evidence_class: class,
            observed_at_unix_ms,
            region_class: region.to_owned(),
            managed,
        }
    }

    fn derived(verdict: Verdict, evidence: Vec<AssertionEvidence>) -> DerivedAssertion {
        let supporting_observation_ids = evidence
            .iter()
            .map(|item| DomainObservationId::new(item.observation_id.to_string()))
            .collect();
        let assertion = DomainAssertion {
            target: TargetKey {
                site_id: DomainSiteId::new("example"),
                normalized_username: "fixture".to_owned(),
            },
            verdict,
            quality: DomainAssertionQuality::Verified,
            evidence_class: DomainEvidenceClass::E4StructuredIdentity,
            observed_at_unix_ms: 10_000,
            expires_at_unix_ms: 20_000,
            regions: evidence
                .iter()
                .map(|item| item.region_class.clone())
                .collect(),
            support_group_count: evidence.len(),
            managed_support: evidence.iter().any(|item| item.managed),
            supporting_observation_ids,
            conflicting_observation_ids: Vec::new(),
            derivation_version: ASSERTION_DERIVATION_VERSION,
        };
        let regional_assertions = assertion
            .regions
            .iter()
            .map(|region| {
                let supporting_observation_ids = evidence
                    .iter()
                    .filter(|item| &item.region_class == region)
                    .map(|item| DomainObservationId::new(item.observation_id.to_string()))
                    .collect::<Vec<_>>();
                (
                    region.clone(),
                    DerivedRegionalAssertion {
                        assertion: DomainAssertion {
                            target: assertion.target.clone(),
                            verdict,
                            quality: DomainAssertionQuality::Verified,
                            evidence_class: DomainEvidenceClass::E4StructuredIdentity,
                            observed_at_unix_ms: 10_000,
                            expires_at_unix_ms: 20_000,
                            regions: [region.clone()].into_iter().collect(),
                            support_group_count: supporting_observation_ids.len(),
                            managed_support: true,
                            supporting_observation_ids,
                            conflicting_observation_ids: Vec::new(),
                            derivation_version: ASSERTION_DERIVATION_VERSION,
                        },
                        sources: vec![ResultSource::ManagedProbe],
                    },
                )
            })
            .collect();
        DerivedAssertion {
            id: Uuid::from_u128(100),
            assertion,
            regional_assertions,
            evidence,
            sources: vec![ResultSource::ManagedProbe],
        }
    }

    #[test]
    fn protocol_assertion_exposes_each_regional_projection() {
        let derived = derived(
            Verdict::Found,
            vec![
                evidence(
                    1,
                    DomainEvidenceClass::E4StructuredIdentity,
                    10_000,
                    "jp",
                    true,
                ),
                evidence(
                    2,
                    DomainEvidenceClass::E4StructuredIdentity,
                    10_000,
                    "us",
                    true,
                ),
            ],
        );

        let protocol = derived.protocol_assertion(11_000, 5_000).unwrap();

        assert!(protocol.validate().is_ok());
        let regional = protocol.regional_assertions.unwrap();
        assert_eq!(regional.len(), 2);
        assert_eq!(regional[0].region_class.as_str(), "jp");
        assert_eq!(regional[1].region_class.as_str(), "us");
    }

    #[test]
    fn verification_priority_prefers_conflicts_then_account_confirmation() {
        let routine = VerificationPriority::from_persisted_state(false, false);
        let account = VerificationPriority::from_persisted_state(false, true);
        let conflict = VerificationPriority::from_persisted_state(true, true);

        assert_eq!(routine.value(), 0);
        assert_eq!(account.value(), 50);
        assert_eq!(conflict.value(), 100);
        assert!(routine < account);
        assert!(account < conflict);
    }

    #[test]
    fn appearance_confirmation_requires_e4_or_an_e3_follow_up() {
        let single_e3 = derived(
            Verdict::Found,
            vec![evidence(
                1,
                DomainEvidenceClass::E3ExplicitEndpoint,
                2_000,
                "jp",
                true,
            )],
        );
        assert_eq!(
            account_confirmation(&single_e3, 1_000).unwrap(),
            AccountConfirmation::Pending("second_managed_observation_required")
        );

        let followed_up = derived(
            Verdict::Found,
            vec![
                evidence(
                    1,
                    DomainEvidenceClass::E3ExplicitEndpoint,
                    2_000,
                    "jp",
                    true,
                ),
                evidence(
                    2,
                    DomainEvidenceClass::E3ExplicitEndpoint,
                    2_001,
                    "jp",
                    true,
                ),
            ],
        );
        assert_eq!(
            account_confirmation(&followed_up, 1_000).unwrap(),
            AccountConfirmation::Confirmed("managed_e3_follow_up")
        );

        let e4 = derived(
            Verdict::Found,
            vec![evidence(
                3,
                DomainEvidenceClass::E4StructuredIdentity,
                2_000,
                "jp",
                true,
            )],
        );
        assert_eq!(
            account_confirmation(&e4, 1_000).unwrap(),
            AccountConfirmation::Confirmed("managed_e4")
        );
    }

    #[test]
    fn disappearance_confirmation_requires_two_managed_checks() {
        let independent_regions = derived(
            Verdict::NotFound,
            vec![
                evidence(
                    1,
                    DomainEvidenceClass::E3ExplicitEndpoint,
                    2_000,
                    "jp",
                    true,
                ),
                evidence(
                    2,
                    DomainEvidenceClass::E3ExplicitEndpoint,
                    2_000,
                    "us",
                    true,
                ),
            ],
        );
        assert_eq!(
            account_confirmation(&independent_regions, 1_000).unwrap(),
            AccountConfirmation::Confirmed("two_managed_independent_regions")
        );

        let separated = derived(
            Verdict::NotFound,
            vec![
                evidence(
                    3,
                    DomainEvidenceClass::E3ExplicitEndpoint,
                    2_000,
                    "jp",
                    true,
                ),
                evidence(
                    4,
                    DomainEvidenceClass::E3ExplicitEndpoint,
                    2_000 + FOLLOW_UP_DELAY_MS,
                    "jp",
                    true,
                ),
            ],
        );
        assert_eq!(
            account_confirmation(&separated, 1_000).unwrap(),
            AccountConfirmation::Confirmed("two_managed_separated_in_time")
        );
    }

    #[test]
    fn shared_only_absence_stays_suppressed() {
        let shared = derived(
            Verdict::NotFound,
            vec![
                evidence(
                    1,
                    DomainEvidenceClass::E4StructuredIdentity,
                    2_000,
                    "jp",
                    false,
                ),
                evidence(
                    2,
                    DomainEvidenceClass::E4StructuredIdentity,
                    3_000,
                    "us",
                    false,
                ),
            ],
        );
        assert_eq!(
            account_confirmation(&shared, 1_000).unwrap(),
            AccountConfirmation::Suppressed("shared_only_absence")
        );
    }
}
