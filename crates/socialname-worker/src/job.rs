use std::{env, fmt, time::Duration};

use sha2::{Digest, Sha256};
use socialname_domain::{EvidenceClass as DomainEvidenceClass, InconclusiveReason, Verdict};
use socialname_engine::SearchResult;
use socialname_protocol::{
    DefinitiveResult, DefinitiveVerdict, EventId, EvidenceCapsuleId, EvidenceCapsuleProfile,
    EvidenceCapsuleResource, EvidenceCapsuleSchema, EvidenceClass, EvidenceDigest,
    EvidenceMatcherTrace, EvidenceNetworkClass, EvidenceOutcome, EvidenceProbe, EvidenceProvenance,
    EvidenceTransportOutcome, EvidenceVantage, Freshness, HttpsUrl, ObservationId,
    OperationalFailure, OperationalFailureKind, ProtocolVersion, RegionClass, ResultSource,
    RuleHash, RuleHealthStatus, SearchEvent, SearchEventData, SearchId, SearchProgress,
    SearchTerminalState, SiteId, Target, UncertainResult, UncertaintyReason, Username, Validate,
};
use socialname_rule_schema::TransportOutcome;
use sqlx::{FromRow, PgPool, Postgres, Transaction, postgres::PgPoolOptions};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::derivation::{
    DerivationKey, MeasurementOutcome, WatchInterpretationKey, apply_watch_interpretation,
    elevate_probe_job_priority, load_verification_priority, lock_derivation_target,
    recompute_assertion,
};
use crate::{ManagedRule, WorkerError};

pub const WORKER_DATABASE_URL_ENV: &str = "SOCIALNAME_WORKER_DATABASE_URL";

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);
const MAXIMUM_CONNECTIONS: u32 = 4;
const SESSION_LIMITS: [&str; 3] = [
    "SET statement_timeout = '10s'",
    "SET lock_timeout = '5s'",
    "SET idle_in_transaction_session_timeout = '15s'",
];
const MINIMUM_LEASE_MS: u64 = 5_000;
const MAXIMUM_LEASE_MS: u64 = 300_000;
const MAXIMUM_ATTEMPTS: u32 = 10;
const INITIAL_RETRY_DELAY_MS: i64 = 5_000;
const MAXIMUM_RETRY_DELAY_MS: i64 = 5 * 60 * 1_000;
const DAY_MS: i64 = 24 * 60 * 60 * 1_000;
const PRIVATE_INTERACTIVE_RETENTION_DAYS: i64 = 90;
const SHARED_CAPSULE_RETENTION_DAYS: i64 = 400;
const MINIMUM_RETENTION_DAYS: i64 = 30;
const MAXIMUM_RETENTION_DAYS: i64 = 730;
const MAXIMUM_RETENTION_BATCH: u32 = 1_000;

#[derive(Clone)]
pub struct JobStore {
    pool: PgPool,
}

impl fmt::Debug for JobStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JobStore([REDACTED DATABASE])")
    }
}

impl JobStore {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn connect_from_env() -> Result<Self, JobError> {
        Ok(Self::new(connect_worker_pool_from_env().await?))
    }

    pub async fn close(&self) {
        self.pool.close().await;
    }

    pub async fn enforce_evidence_retention(
        &self,
        batch_limit: u32,
    ) -> Result<EvidenceRetentionOutcome, JobError> {
        if !(1..=MAXIMUM_RETENTION_BATCH).contains(&batch_limit) {
            return Err(JobError::InvalidConfiguration);
        }
        let (research_excerpts_purged, structured_capsules_purged, expired_receipts_deleted): (
            i32,
            i32,
            i32,
        ) = sqlx::query_as(
            "SELECT research_excerpts_purged, structured_capsules_purged, \
                        expired_receipts_deleted \
                 FROM socialname_worker_enforce_evidence_retention($1)",
        )
        .bind(i32::try_from(batch_limit).map_err(|_| JobError::InvalidConfiguration)?)
        .fetch_one(&self.pool)
        .await
        .map_err(|_| JobError::DatabaseUnavailable)?;
        Ok(EvidenceRetentionOutcome {
            research_excerpts_purged: u32::try_from(research_excerpts_purged)
                .map_err(|_| JobError::StorageInvariant)?,
            structured_capsules_purged: u32::try_from(structured_capsules_purged)
                .map_err(|_| JobError::StorageInvariant)?,
            expired_receipts_deleted: u32::try_from(expired_receipts_deleted)
                .map_err(|_| JobError::StorageInvariant)?,
        })
    }

    pub async fn bind_rule(&self, rule: &ManagedRule) -> Result<RuleBinding, JobError> {
        let rule_hash = decode_digest(rule.rule_hash())?;
        let pack_hash = decode_digest(rule.rule_pack_hash())?;
        let metadata_id = decode_digest(rule.metadata_id())?;
        let promotion_id = decode_digest(rule.promotion_id())?;
        let metadata_sequence =
            i64::try_from(rule.metadata_sequence()).map_err(|_| JobError::RuleUnavailable)?;
        let promotion_sequence =
            i64::try_from(rule.promotion_sequence()).map_err(|_| JobError::RuleUnavailable)?;
        let rule_version_id: Option<Uuid> = sqlx::query_scalar(
            "SELECT socialname_worker_resolve_rule($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(rule.site_id())
        .bind(rule_hash)
        .bind(pack_hash)
        .bind(rule.region_class())
        .bind(metadata_id)
        .bind(metadata_sequence)
        .bind(promotion_id)
        .bind(promotion_sequence)
        .fetch_one(&self.pool)
        .await
        .map_err(|_| JobError::DatabaseUnavailable)?;
        let rule_version_id = rule_version_id.ok_or(JobError::RuleUnavailable)?;
        Ok(RuleBinding {
            rule_version_id,
            site_id: rule.site_id().to_owned(),
            rule_hash: rule.rule_hash().to_owned(),
            rule_pack_hash: rule.rule_pack_hash().to_owned(),
            engine_hash: rule.engine_hash().to_owned(),
            region_class: rule.region_class().to_owned(),
            metadata_id: rule.metadata_id().to_owned(),
            metadata_sequence: rule.metadata_sequence(),
            promotion_id: rule.promotion_id().to_owned(),
            promotion_sequence: rule.promotion_sequence(),
        })
    }

    pub async fn plan_one_watch(
        &self,
        binding: &RuleBinding,
    ) -> Result<WatchPlanOutcome, JobError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| JobError::DatabaseUnavailable)?;
        let locked: Option<LockedWatchId> = sqlx::query_as(
            "SELECT tenant_id, watch_id \
             FROM socialname_worker_lock_due_watch($1, $2)",
        )
        .bind(binding.rule_version_id)
        .bind(&binding.region_class)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| JobError::DatabaseUnavailable)?;
        let Some(locked) = locked else {
            transaction
                .commit()
                .await
                .map_err(|_| JobError::DatabaseUnavailable)?;
            return Ok(WatchPlanOutcome::Idle);
        };
        set_tenant(&mut transaction, locked.tenant_id).await?;
        let watch: WatchPlan = sqlx::query_as(
            "SELECT revision, interval_seconds, jitter_percent, \
                    maximum_probes_per_run, maximum_bytes_per_run, region_classes, \
                    (EXTRACT(EPOCH FROM next_run_at) * 1000)::bigint \
                        AS scheduled_for_unix_ms \
             FROM watches \
             WHERE tenant_id = $1 AND id = $2 \
               AND state = 'active' AND next_run_at <= clock_timestamp() \
             FOR UPDATE",
        )
        .bind(locked.tenant_id)
        .bind(locked.watch_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| JobError::StorageInvariant)?;
        let watch_target_ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM watch_targets \
             WHERE tenant_id = $1 AND watch_id = $2 AND retired_at IS NULL \
             ORDER BY ordinal, id",
        )
        .bind(locked.tenant_id)
        .bind(locked.watch_id)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| JobError::StorageInvariant)?;
        let planned_count = watch_target_ids
            .len()
            .checked_mul(watch.region_classes.len())
            .ok_or(JobError::StorageInvariant)?;
        if planned_count == 0
            || planned_count
                > usize::try_from(watch.maximum_probes_per_run)
                    .map_err(|_| JobError::StorageInvariant)?
        {
            return Err(JobError::StorageInvariant);
        }
        let planned_count_i32 =
            i32::try_from(planned_count).map_err(|_| JobError::StorageInvariant)?;
        let now_unix_ms = database_now_ms(&mut transaction).await?;
        let next_run_at_unix_ms = now_unix_ms
            .checked_add(watch_schedule_delay_ms(
                locked.watch_id,
                watch.revision,
                watch.scheduled_for_unix_ms,
                watch.interval_seconds,
                watch.jitter_percent,
            )?)
            .ok_or(JobError::StorageInvariant)?;
        let run_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO watch_runs (\
                id, tenant_id, watch_id, watch_revision, scheduled_for, state, \
                maximum_probes, maximum_bytes, reserved_probes, reserved_bytes, \
                created_at\
             ) VALUES (\
                $1, $2, $3, $4, to_timestamp($5::double precision / 1000.0), \
                'planned', $6, $7, $8, 0, clock_timestamp()\
             )",
        )
        .bind(run_id)
        .bind(locked.tenant_id)
        .bind(locked.watch_id)
        .bind(watch.revision)
        .bind(watch.scheduled_for_unix_ms)
        .bind(watch.maximum_probes_per_run)
        .bind(watch.maximum_bytes_per_run)
        .bind(planned_count_i32)
        .execute(&mut *transaction)
        .await
        .map_err(|_| JobError::StorageInvariant)?;
        insert_lineage(
            &mut transaction,
            locked.tenant_id,
            "watch",
            locked.watch_id,
            "watch_run",
            run_id,
            "scheduled_run",
        )
        .await?;
        for watch_target_id in watch_target_ids {
            for region_class in &watch.region_classes {
                let run_target_id = Uuid::new_v4();
                sqlx::query(
                    "INSERT INTO watch_run_targets (\
                        id, tenant_id, watch_run_id, watch_target_id, region_class, \
                        state, created_at\
                     ) VALUES ($1, $2, $3, $4, $5, 'pending', clock_timestamp())",
                )
                .bind(run_target_id)
                .bind(locked.tenant_id)
                .bind(run_id)
                .bind(watch_target_id)
                .bind(region_class)
                .execute(&mut *transaction)
                .await
                .map_err(|_| JobError::StorageInvariant)?;
                insert_lineage(
                    &mut transaction,
                    locked.tenant_id,
                    "watch_run",
                    run_id,
                    "watch_run_target",
                    run_target_id,
                    "scheduled_target",
                )
                .await?;
            }
        }
        let advanced = sqlx::query(
            "UPDATE watches \
             SET next_run_at = to_timestamp($4::double precision / 1000.0), \
                 updated_at = clock_timestamp() \
             WHERE tenant_id = $1 AND id = $2 AND revision = $3 \
               AND state = 'active'",
        )
        .bind(locked.tenant_id)
        .bind(locked.watch_id)
        .bind(watch.revision)
        .bind(next_run_at_unix_ms)
        .execute(&mut *transaction)
        .await
        .map_err(|_| JobError::StorageInvariant)?
        .rows_affected();
        if advanced != 1 {
            return Err(JobError::StorageInvariant);
        }
        transaction
            .commit()
            .await
            .map_err(|_| JobError::DatabaseUnavailable)?;
        Ok(WatchPlanOutcome::Planned {
            run_id,
            target_count: u32::try_from(planned_count).map_err(|_| JobError::StorageInvariant)?,
        })
    }

    pub async fn expand_one_watch(
        &self,
        binding: &RuleBinding,
        rule: &ManagedRule,
    ) -> Result<ExpandOutcome, JobError> {
        binding.matches_rule(rule)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| JobError::DatabaseUnavailable)?;
        let locked: Option<LockedWatchTargetId> = sqlx::query_as(
            "SELECT tenant_id, watch_run_target_id \
             FROM socialname_worker_lock_next_watch_target($1, $2)",
        )
        .bind(binding.rule_version_id)
        .bind(&binding.region_class)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| JobError::DatabaseUnavailable)?;
        let Some(locked) = locked else {
            transaction
                .commit()
                .await
                .map_err(|_| JobError::DatabaseUnavailable)?;
            return Ok(ExpandOutcome::Idle);
        };
        set_tenant(&mut transaction, locked.tenant_id).await?;
        let target: WatchExpansionTarget = sqlx::query_as(
            "SELECT run_target.watch_run_id, run_target.watch_target_id, \
                    target.requested_username, target.site_id, \
                    watch.consent_grant_id, watch.maximum_age_ms \
             FROM watch_run_targets AS run_target \
             JOIN watch_runs AS run \
               ON run.tenant_id = run_target.tenant_id \
              AND run.id = run_target.watch_run_id \
             JOIN watches AS watch \
               ON watch.tenant_id = run.tenant_id \
              AND watch.id = run.watch_id \
             JOIN watch_targets AS target \
               ON target.tenant_id = run_target.tenant_id \
              AND target.id = run_target.watch_target_id \
             WHERE run_target.tenant_id = $1 AND run_target.id = $2 \
               AND run_target.state = 'pending' \
             FOR UPDATE OF run_target, run, watch, target",
        )
        .bind(locked.tenant_id)
        .bind(locked.watch_run_target_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| JobError::StorageInvariant)?;
        if target.site_id != binding.site_id {
            return Err(JobError::StorageInvariant);
        }
        let Some(normalized_username) = rule.normalize_username(&target.requested_username) else {
            finalize_watch_target_without_observation(
                &mut transaction,
                locked.tenant_id,
                locked.watch_run_target_id,
                target.watch_run_id,
                "failed",
            )
            .await?;
            transaction
                .commit()
                .await
                .map_err(|_| JobError::DatabaseUnavailable)?;
            return Ok(ExpandOutcome::InvalidTargetCompleted);
        };
        sqlx::query(
            "UPDATE watch_targets SET normalized_username = $3 \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(locked.tenant_id)
        .bind(target.watch_target_id)
        .bind(&normalized_username)
        .execute(&mut *transaction)
        .await
        .map_err(|_| JobError::StorageInvariant)?;
        let fresh_observation: Option<FreshObservation> = sqlx::query_as(
            "SELECT id, outcome_kind FROM observations \
             WHERE tenant_id = $1 \
               AND normalized_username = $2 \
               AND site_id = $3 \
               AND rule_version_id = $4 \
               AND region_class = $5 \
               AND consent_grant_id = $6 \
               AND visibility = 'private' \
               AND source = 'managed_probe' \
               AND producer_kind = 'managed_worker' \
               AND rule_health_green \
               AND expires_at > clock_timestamp() \
               AND observed_at >= clock_timestamp() \
                   - ($7::bigint::text || ' milliseconds')::interval \
             ORDER BY observed_at DESC, id \
             LIMIT 1",
        )
        .bind(locked.tenant_id)
        .bind(&normalized_username)
        .bind(&binding.site_id)
        .bind(binding.rule_version_id)
        .bind(&binding.region_class)
        .bind(target.consent_grant_id)
        .bind(target.maximum_age_ms)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| JobError::StorageInvariant)?;
        if let Some(fresh_observation) = fresh_observation {
            let observation_id = fresh_observation.id;
            let affected = sqlx::query(
                "UPDATE watch_run_targets \
                 SET state = 'satisfied', observation_id = $3, \
                     completed_at = clock_timestamp() \
                 WHERE tenant_id = $1 AND id = $2 AND state = 'pending'",
            )
            .bind(locked.tenant_id)
            .bind(locked.watch_run_target_id)
            .bind(observation_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| JobError::StorageInvariant)?
            .rows_affected();
            if affected != 1 {
                return Err(JobError::StorageInvariant);
            }
            insert_lineage(
                &mut transaction,
                locked.tenant_id,
                "observation",
                observation_id,
                "watch_run_target",
                locked.watch_run_target_id,
                "freshness_reuse",
            )
            .await?;
            let evaluated_at_unix_ms = database_now_ms(&mut transaction).await?;
            let derivation_key = DerivationKey {
                tenant_id: locked.tenant_id,
                normalized_username: &normalized_username,
                site_id: &binding.site_id,
                rule_version_id: binding.rule_version_id,
                rule_hash: &binding.rule_hash,
            };
            lock_derivation_target(&mut transaction, &derivation_key).await?;
            let derived =
                recompute_assertion(&mut transaction, &derivation_key, evaluated_at_unix_ms)
                    .await?;
            let measurement = match fresh_observation.outcome_kind.as_str() {
                "definitive" if derived.as_ref().is_some_and(|value| value.is_conflicted()) => {
                    MeasurementOutcome::Degraded { observation_id }
                }
                "definitive" => MeasurementOutcome::Healthy { observation_id },
                "uncertain" => MeasurementOutcome::Degraded { observation_id },
                _ => return Err(JobError::StorageInvariant),
            };
            apply_watch_interpretation(
                &mut transaction,
                &WatchInterpretationKey {
                    tenant_id: locked.tenant_id,
                    watch_target_id: target.watch_target_id,
                    rule_version_id: binding.rule_version_id,
                    region_class: &binding.region_class,
                },
                derived.as_ref(),
                measurement,
                evaluated_at_unix_ms,
            )
            .await?;
            finish_watch_run(&mut transaction, locked.tenant_id, target.watch_run_id).await?;
            transaction
                .commit()
                .await
                .map_err(|_| JobError::DatabaseUnavailable)?;
            return Ok(ExpandOutcome::FreshObservationCompleted);
        }

        let reserved_bytes = i64::try_from(rule.maximum_inspected_bytes_per_search())
            .map_err(|_| JobError::StorageInvariant)?;
        if reserved_bytes <= 0 {
            return Err(JobError::StorageInvariant);
        }
        let reserved: Option<i64> = sqlx::query_scalar(
            "UPDATE watch_runs \
             SET reserved_bytes = reserved_bytes + $3 \
             WHERE tenant_id = $1 AND id = $2 \
               AND state IN ('planned', 'running') \
               AND reserved_bytes + $3 <= maximum_bytes \
             RETURNING reserved_bytes",
        )
        .bind(locked.tenant_id)
        .bind(target.watch_run_id)
        .bind(reserved_bytes)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| JobError::StorageInvariant)?;
        if reserved.is_none() {
            finalize_watch_target_without_observation(
                &mut transaction,
                locked.tenant_id,
                locked.watch_run_target_id,
                target.watch_run_id,
                "failed",
            )
            .await?;
            transaction
                .commit()
                .await
                .map_err(|_| JobError::DatabaseUnavailable)?;
            return Ok(ExpandOutcome::BudgetExceededCompleted);
        }

        let work_key_hash = work_key_hash(
            locked.tenant_id,
            &normalized_username,
            binding,
            target.consent_grant_id,
            "private",
        );
        let verification_priority = load_verification_priority(
            &mut transaction,
            locked.tenant_id,
            target.watch_target_id,
            &normalized_username,
            &binding.site_id,
        )
        .await?;
        let proposed_job_id = Uuid::new_v4();
        let inserted_job_id: Option<Uuid> = sqlx::query_scalar(
            "INSERT INTO probe_jobs (\
                id, tenant_id, normalized_username, site_id, rule_version_id, \
                region_class, work_key_hash, consent_grant_id, visibility, state, \
                priority, available_at, created_at, updated_at\
             ) VALUES (\
                $1, $2, $3, $4, $5, $6, $7, $8, 'private', 'queued', \
                $9, clock_timestamp(), clock_timestamp(), clock_timestamp()\
             ) \
             ON CONFLICT (\
                tenant_id, normalized_username, site_id, rule_version_id, \
                region_class, consent_grant_id, visibility\
             ) WHERE state IN ('queued', 'leased', 'retry_wait') \
             DO NOTHING \
             RETURNING id",
        )
        .bind(proposed_job_id)
        .bind(locked.tenant_id)
        .bind(&normalized_username)
        .bind(&binding.site_id)
        .bind(binding.rule_version_id)
        .bind(&binding.region_class)
        .bind(work_key_hash.as_slice())
        .bind(target.consent_grant_id)
        .bind(verification_priority.value())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| JobError::StorageInvariant)?;
        let job_was_inserted = inserted_job_id.is_some();
        let job_id = if let Some(job_id) = inserted_job_id {
            job_id
        } else {
            sqlx::query_scalar(
                "SELECT id FROM probe_jobs \
                 WHERE tenant_id = $1 \
                   AND normalized_username = $2 \
                   AND site_id = $3 \
                   AND rule_version_id = $4 \
                   AND region_class = $5 \
                   AND consent_grant_id = $6 \
                   AND visibility = 'private' \
                   AND state IN ('queued', 'leased', 'retry_wait') \
                 FOR UPDATE",
            )
            .bind(locked.tenant_id)
            .bind(&normalized_username)
            .bind(&binding.site_id)
            .bind(binding.rule_version_id)
            .bind(&binding.region_class)
            .bind(target.consent_grant_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| JobError::StorageInvariant)?
        };
        elevate_probe_job_priority(
            &mut transaction,
            locked.tenant_id,
            job_id,
            verification_priority,
        )
        .await?;
        let linked: Option<Uuid> = sqlx::query_scalar(
            "INSERT INTO probe_job_consumers (\
                id, tenant_id, probe_job_id, watch_target_id, \
                watch_run_target_id, created_at\
             ) VALUES ($1, $2, $3, $4, $5, clock_timestamp()) \
             ON CONFLICT (tenant_id, watch_run_target_id) \
             WHERE watch_run_target_id IS NOT NULL \
             DO NOTHING \
             RETURNING id",
        )
        .bind(Uuid::new_v4())
        .bind(locked.tenant_id)
        .bind(job_id)
        .bind(target.watch_target_id)
        .bind(locked.watch_run_target_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| JobError::StorageInvariant)?;
        if linked.is_none() {
            return Err(JobError::StorageInvariant);
        }
        let affected = sqlx::query(
            "UPDATE watch_run_targets \
             SET state = 'queued', probe_job_id = $3, reserved_bytes = $4 \
             WHERE tenant_id = $1 AND id = $2 AND state = 'pending'",
        )
        .bind(locked.tenant_id)
        .bind(locked.watch_run_target_id)
        .bind(job_id)
        .bind(reserved_bytes)
        .execute(&mut *transaction)
        .await
        .map_err(|_| JobError::StorageInvariant)?
        .rows_affected();
        if affected != 1 {
            return Err(JobError::StorageInvariant);
        }
        sqlx::query(
            "UPDATE watch_runs SET state = 'running' \
             WHERE tenant_id = $1 AND id = $2 AND state = 'planned'",
        )
        .bind(locked.tenant_id)
        .bind(target.watch_run_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| JobError::StorageInvariant)?;
        insert_lineage(
            &mut transaction,
            locked.tenant_id,
            "watch_run_target",
            locked.watch_run_target_id,
            "probe_job",
            job_id,
            "managed_probe_request",
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| JobError::DatabaseUnavailable)?;
        if job_was_inserted {
            Ok(ExpandOutcome::Enqueued { job_id })
        } else {
            Ok(ExpandOutcome::Coalesced { job_id })
        }
    }

    pub async fn expand_one(
        &self,
        binding: &RuleBinding,
        rule: &ManagedRule,
    ) -> Result<ExpandOutcome, JobError> {
        binding.matches_rule(rule)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| JobError::DatabaseUnavailable)?;
        let locked: Option<LockedTargetId> = sqlx::query_as(
            "SELECT tenant_id, search_target_id \
             FROM socialname_worker_lock_next_target($1, $2)",
        )
        .bind(binding.rule_version_id)
        .bind(&binding.region_class)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| JobError::DatabaseUnavailable)?;
        let Some(locked) = locked else {
            transaction
                .commit()
                .await
                .map_err(|_| JobError::DatabaseUnavailable)?;
            return Ok(ExpandOutcome::Idle);
        };
        set_tenant(&mut transaction, locked.tenant_id).await?;
        let target: ExpansionTarget = sqlx::query_as(
            "SELECT target.search_id, target.requested_username, target.site_id, \
                    search.consent_grant_id, search.sync_policy, search.maximum_age_ms \
             FROM search_targets AS target \
             JOIN searches AS search \
               ON search.tenant_id = target.tenant_id \
              AND search.id = target.search_id \
             WHERE target.tenant_id = $1 AND target.id = $2 \
             FOR UPDATE OF target, search",
        )
        .bind(locked.tenant_id)
        .bind(locked.search_target_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| JobError::StorageInvariant)?;
        if target.site_id != binding.site_id {
            return Err(JobError::StorageInvariant);
        }
        let Some(normalized_username) = rule.normalize_username(&target.requested_username) else {
            finalize_invalid_target(
                &mut transaction,
                locked.tenant_id,
                locked.search_target_id,
                &target,
                binding,
            )
            .await?;
            transaction
                .commit()
                .await
                .map_err(|_| JobError::DatabaseUnavailable)?;
            return Ok(ExpandOutcome::InvalidTargetCompleted);
        };
        let visibility = visibility_for_sync(&target.sync_policy)?;
        let consent_grant_id = target.consent_grant_id.ok_or(JobError::StorageInvariant)?;
        let work_key_hash = work_key_hash(
            locked.tenant_id,
            &normalized_username,
            binding,
            consent_grant_id,
            visibility,
        );
        let proposed_job_id = Uuid::new_v4();
        let inserted_job_id: Option<Uuid> = sqlx::query_scalar(
            "INSERT INTO probe_jobs (\
                id, tenant_id, normalized_username, site_id, rule_version_id, \
                region_class, work_key_hash, consent_grant_id, visibility, state, \
                available_at, created_at, updated_at\
             ) VALUES (\
                $1, $2, $3, $4, $5, $6, $7, $8, $9, 'queued', \
                clock_timestamp(), clock_timestamp(), clock_timestamp()\
             ) \
             ON CONFLICT (\
                tenant_id, normalized_username, site_id, rule_version_id, \
                region_class, consent_grant_id, visibility\
             ) WHERE state IN ('queued', 'leased', 'retry_wait') \
             DO NOTHING \
             RETURNING id",
        )
        .bind(proposed_job_id)
        .bind(locked.tenant_id)
        .bind(&normalized_username)
        .bind(&binding.site_id)
        .bind(binding.rule_version_id)
        .bind(&binding.region_class)
        .bind(work_key_hash.as_slice())
        .bind(consent_grant_id)
        .bind(visibility)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| JobError::StorageInvariant)?;
        let job_was_inserted = inserted_job_id.is_some();
        let job_id = if let Some(job_id) = inserted_job_id {
            job_id
        } else {
            sqlx::query_scalar(
                "SELECT id FROM probe_jobs \
                 WHERE tenant_id = $1 \
                   AND normalized_username = $2 \
                   AND site_id = $3 \
                   AND rule_version_id = $4 \
                   AND region_class = $5 \
                   AND consent_grant_id = $6 \
                   AND visibility = $7 \
                   AND state IN ('queued', 'leased', 'retry_wait') \
                 FOR UPDATE",
            )
            .bind(locked.tenant_id)
            .bind(&normalized_username)
            .bind(&binding.site_id)
            .bind(binding.rule_version_id)
            .bind(&binding.region_class)
            .bind(consent_grant_id)
            .bind(visibility)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| JobError::StorageInvariant)?
        };

        let consumer_id = Uuid::new_v4();
        let linked: Option<Uuid> = sqlx::query_scalar(
            "INSERT INTO probe_job_consumers (\
                id, tenant_id, probe_job_id, search_target_id, created_at\
             ) VALUES ($1, $2, $3, $4, clock_timestamp()) \
             ON CONFLICT (tenant_id, search_target_id) \
             WHERE search_target_id IS NOT NULL \
             DO NOTHING \
             RETURNING id",
        )
        .bind(consumer_id)
        .bind(locked.tenant_id)
        .bind(job_id)
        .bind(locked.search_target_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| JobError::StorageInvariant)?;
        if linked.is_none() {
            let existing_job: Uuid = sqlx::query_scalar(
                "SELECT probe_job_id FROM probe_job_consumers \
                 WHERE tenant_id = $1 AND search_target_id = $2",
            )
            .bind(locked.tenant_id)
            .bind(locked.search_target_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| JobError::StorageInvariant)?;
            if existing_job != job_id {
                return Err(JobError::StorageInvariant);
            }
        }

        insert_lineage(
            &mut transaction,
            locked.tenant_id,
            "search_target",
            locked.search_target_id,
            "probe_job",
            job_id,
            "managed_probe_request",
        )
        .await?;
        sqlx::query(
            "UPDATE search_targets \
             SET normalized_username = $3, state = 'running', completed_at = NULL \
             WHERE tenant_id = $1 AND id = $2 AND state = 'pending'",
        )
        .bind(locked.tenant_id)
        .bind(locked.search_target_id)
        .bind(&normalized_username)
        .execute(&mut *transaction)
        .await
        .map_err(|_| JobError::StorageInvariant)?;
        sqlx::query(
            "UPDATE searches \
             SET state = 'running', updated_at = clock_timestamp() \
             WHERE tenant_id = $1 AND id = $2 AND state = 'accepted'",
        )
        .bind(locked.tenant_id)
        .bind(target.search_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| JobError::StorageInvariant)?;
        transaction
            .commit()
            .await
            .map_err(|_| JobError::DatabaseUnavailable)?;
        if job_was_inserted {
            Ok(ExpandOutcome::Enqueued { job_id })
        } else {
            Ok(ExpandOutcome::Coalesced { job_id })
        }
    }

    pub async fn claim(
        &self,
        binding: &RuleBinding,
        lease_owner: &str,
        lease_duration: Duration,
    ) -> Result<Option<JobClaim>, JobError> {
        if !valid_label(lease_owner) {
            return Err(JobError::InvalidConfiguration);
        }
        let lease_ms = u64::try_from(lease_duration.as_millis())
            .map_err(|_| JobError::InvalidConfiguration)?;
        if !(MINIMUM_LEASE_MS..=MAXIMUM_LEASE_MS).contains(&lease_ms) {
            return Err(JobError::InvalidConfiguration);
        }
        let lease_ms = i32::try_from(lease_ms).map_err(|_| JobError::InvalidConfiguration)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| JobError::DatabaseUnavailable)?;
        let claimed: Option<ClaimedJobId> = sqlx::query_as(
            "SELECT tenant_id, probe_job_id, attempt_count \
             FROM socialname_worker_claim_job($1, $2, $3, $4)",
        )
        .bind(binding.rule_version_id)
        .bind(&binding.region_class)
        .bind(lease_owner)
        .bind(lease_ms)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| JobError::DatabaseUnavailable)?;
        let Some(claimed) = claimed else {
            transaction
                .commit()
                .await
                .map_err(|_| JobError::DatabaseUnavailable)?;
            return Ok(None);
        };
        set_tenant(&mut transaction, claimed.tenant_id).await?;
        let row: ClaimedJobRow = sqlx::query_as(
            "SELECT normalized_username, site_id, rule_version_id, region_class, \
                    consent_grant_id, visibility \
             FROM probe_jobs \
             WHERE tenant_id = $1 AND id = $2 AND state = 'leased' \
             FOR UPDATE",
        )
        .bind(claimed.tenant_id)
        .bind(claimed.probe_job_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| JobError::StorageInvariant)?;
        if row.rule_version_id != binding.rule_version_id
            || row.site_id != binding.site_id
            || row.region_class != binding.region_class
        {
            return Err(JobError::StorageInvariant);
        }
        let consent_grant_id = row.consent_grant_id.ok_or(JobError::StorageInvariant)?;
        let visibility = row.visibility.ok_or(JobError::StorageInvariant)?;
        let attempt_count =
            u32::try_from(claimed.attempt_count).map_err(|_| JobError::StorageInvariant)?;
        transaction
            .commit()
            .await
            .map_err(|_| JobError::DatabaseUnavailable)?;
        Ok(Some(JobClaim {
            tenant_id: claimed.tenant_id,
            job_id: claimed.probe_job_id,
            normalized_username: row.normalized_username,
            site_id: row.site_id,
            rule_version_id: row.rule_version_id,
            rule_hash: binding.rule_hash.clone(),
            rule_pack_hash: binding.rule_pack_hash.clone(),
            engine_hash: binding.engine_hash.clone(),
            region_class: row.region_class,
            metadata_id: binding.metadata_id.clone(),
            promotion_id: binding.promotion_id.clone(),
            consent_grant_id,
            visibility,
            attempt_count,
            lease_owner: lease_owner.to_owned(),
        }))
    }

    pub async fn record_result(
        &self,
        claim: &JobClaim,
        result: &SearchResult,
        maximum_attempts: u32,
    ) -> Result<JobDisposition, JobError> {
        validate_maximum_attempts(maximum_attempts)?;
        claim.validate_result(result)?;
        match classify_result(result)? {
            ManagedResult::Observation(outcome) => {
                self.record_observation(claim, result, outcome).await
            }
            ManagedResult::Failure { kind, retryable } => {
                self.record_failure(claim, kind, retryable, maximum_attempts)
                    .await
            }
        }
    }

    pub async fn execute_claim(
        &self,
        claim: &JobClaim,
        rule: &ManagedRule,
        executed_at_unix_ms: i64,
        shutdown: &CancellationToken,
    ) -> Result<SearchResult, JobExecutionError> {
        claim
            .matches_rule(rule)
            .map_err(JobExecutionError::Worker)?;
        if !self
            .claim_is_authorized(claim)
            .await
            .map_err(|_| JobExecutionError::AuthorizationUnavailable)?
        {
            return Err(JobExecutionError::Cancelled);
        }
        tokio::select! {
            biased;
            () = shutdown.cancelled() => Err(JobExecutionError::Cancelled),
            authorization = self.wait_until_unauthorized(claim) => {
                match authorization {
                    Ok(()) => Err(JobExecutionError::Cancelled),
                    Err(_) => Err(JobExecutionError::AuthorizationUnavailable),
                }
            }
            result = rule.execute(
                &claim.normalized_username,
                executed_at_unix_ms,
                shutdown,
            ) => result.map_err(JobExecutionError::Worker),
        }
    }

    pub async fn record_rule_unavailable(
        &self,
        claim: &JobClaim,
        maximum_attempts: u32,
    ) -> Result<JobDisposition, JobError> {
        validate_maximum_attempts(maximum_attempts)?;
        self.record_failure(
            claim,
            OperationalFailureKind::RuleUnavailable,
            true,
            maximum_attempts,
        )
        .await
    }

    pub async fn record_capacity_unavailable(
        &self,
        claim: &JobClaim,
        maximum_attempts: u32,
    ) -> Result<JobDisposition, JobError> {
        validate_maximum_attempts(maximum_attempts)?;
        self.record_failure(
            claim,
            OperationalFailureKind::CapacityUnavailable,
            true,
            maximum_attempts,
        )
        .await
    }

    async fn record_observation(
        &self,
        claim: &JobClaim,
        result: &SearchResult,
        outcome: RecordedOutcome,
    ) -> Result<JobDisposition, JobError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| JobError::DatabaseUnavailable)?;
        set_tenant(&mut transaction, claim.tenant_id).await?;
        match lock_claim(&mut transaction, claim).await? {
            ClaimState::Final => {
                transaction
                    .commit()
                    .await
                    .map_err(|_| JobError::DatabaseUnavailable)?;
                return Ok(JobDisposition::AlreadyFinal);
            }
            ClaimState::Active => {}
        }
        ensure_rule_available(&mut transaction, claim).await?;
        if !lock_active_consent(&mut transaction, claim).await? {
            cancel_orphaned_claim(&mut transaction, claim).await?;
            transaction
                .commit()
                .await
                .map_err(|_| JobError::DatabaseUnavailable)?;
            return Ok(JobDisposition::Cancelled);
        }
        prune_dead_watch_consumers(&mut transaction, claim).await?;
        let search_consumers = load_live_search_consumers(&mut transaction, claim).await?;
        let watch_consumers = load_live_watch_consumers(&mut transaction, claim).await?;
        if search_consumers.is_empty() && watch_consumers.is_empty() {
            cancel_orphaned_claim(&mut transaction, claim).await?;
            transaction
                .commit()
                .await
                .map_err(|_| JobError::DatabaseUnavailable)?;
            return Ok(JobDisposition::Cancelled);
        }
        let observed_at_unix_ms = database_now_ms(&mut transaction).await?;
        let derivation_key = DerivationKey {
            tenant_id: claim.tenant_id,
            normalized_username: &claim.normalized_username,
            site_id: &claim.site_id,
            rule_version_id: claim.rule_version_id,
            rule_hash: &claim.rule_hash,
        };
        lock_derivation_target(&mut transaction, &derivation_key).await?;
        let expires_at_unix_ms = observed_at_unix_ms
            .checked_add(outcome.ttl_ms())
            .ok_or(JobError::StorageInvariant)?;
        let observation_id = Uuid::new_v4();
        let (capsule_profile, capsule_retention_days) = evidence_retention_policy(
            &claim.visibility,
            !search_consumers.is_empty(),
            &watch_consumers,
        )?;
        let capsule_retained_until_unix_ms = observed_at_unix_ms
            .checked_add(
                capsule_retention_days
                    .checked_mul(DAY_MS)
                    .ok_or(JobError::StorageInvariant)?,
            )
            .ok_or(JobError::StorageInvariant)?;
        let capsule_id = Uuid::new_v4();
        let capsule = build_evidence_capsule(
            claim,
            result,
            outcome,
            capsule_id,
            observation_id,
            capsule_profile,
            observed_at_unix_ms,
            capsule_retained_until_unix_ms,
        )?;
        let capsule_payload =
            serde_json::to_value(&capsule).map_err(|_| JobError::InvalidProtocol)?;
        let capsule_bytes = serde_json::to_vec(&capsule).map_err(|_| JobError::InvalidProtocol)?;
        let capsule_digest = Sha256::digest(&capsule_bytes);
        let evidence_digest = decode_digest(&result.classification.evidence_digest)?;
        let (outcome_kind, verdict, uncertainty_reason) = outcome.database_values();
        sqlx::query(
            "INSERT INTO observations (\
                id, tenant_id, probe_job_id, consent_grant_id, normalized_username, \
                site_id, rule_version_id, outcome_kind, verdict, uncertainty_reason, \
                evidence_class, evidence_digest, source, producer_kind, visibility, \
                region_class, rule_health_green, observed_at, expires_at, created_at\
             ) VALUES (\
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, \
                'managed_probe', 'managed_worker', $13, $14, true, \
                to_timestamp($15::double precision / 1000.0), \
                to_timestamp($16::double precision / 1000.0), clock_timestamp()\
             )",
        )
        .bind(observation_id)
        .bind(claim.tenant_id)
        .bind(claim.job_id)
        .bind(claim.consent_grant_id)
        .bind(&claim.normalized_username)
        .bind(&claim.site_id)
        .bind(claim.rule_version_id)
        .bind(outcome_kind)
        .bind(verdict)
        .bind(uncertainty_reason)
        .bind(evidence_class_name(result.classification.evidence_class))
        .bind(evidence_digest.as_slice())
        .bind(&claim.visibility)
        .bind(&claim.region_class)
        .bind(observed_at_unix_ms)
        .bind(expires_at_unix_ms)
        .execute(&mut *transaction)
        .await
        .map_err(|_| JobError::StorageInvariant)?;
        sqlx::query(
            "INSERT INTO evidence_capsules (\
                id, tenant_id, observation_id, collection_profile, \
                structured_payload, structured_payload_digest, \
                structured_payload_bytes, collected_at, \
                structured_retained_until, created_at\
             ) VALUES (\
                $1, $2, $3, $4, $5, $6, $7, \
                to_timestamp($8::double precision / 1000.0), \
                to_timestamp($9::double precision / 1000.0), clock_timestamp()\
             )",
        )
        .bind(capsule_id)
        .bind(claim.tenant_id)
        .bind(observation_id)
        .bind(evidence_capsule_profile_name(capsule_profile))
        .bind(capsule_payload)
        .bind(capsule_digest.as_slice())
        .bind(i32::try_from(capsule_bytes.len()).map_err(|_| JobError::StorageInvariant)?)
        .bind(observed_at_unix_ms)
        .bind(capsule_retained_until_unix_ms)
        .execute(&mut *transaction)
        .await
        .map_err(|_| JobError::StorageInvariant)?;
        transition_job_to_final(&mut transaction, claim, "succeeded", None).await?;
        insert_lineage(
            &mut transaction,
            claim.tenant_id,
            "probe_job",
            claim.job_id,
            "observation",
            observation_id,
            "managed_measurement",
        )
        .await?;
        insert_lineage(
            &mut transaction,
            claim.tenant_id,
            "observation",
            observation_id,
            "evidence_capsule",
            capsule_id,
            "bounded_evidence",
        )
        .await?;
        let derived =
            recompute_assertion(&mut transaction, &derivation_key, observed_at_unix_ms).await?;

        for consumer in search_consumers {
            let event = result_event(
                result,
                outcome,
                observation_id,
                claim,
                &consumer,
                observed_at_unix_ms,
                expires_at_unix_ms,
            )?;
            insert_search_result(
                &mut transaction,
                claim.tenant_id,
                &consumer,
                &event,
                "completed",
            )
            .await?;
            insert_lineage(
                &mut transaction,
                claim.tenant_id,
                "observation",
                observation_id,
                "search_event",
                event_uuid(&event)?,
                "search_result",
            )
            .await?;
            if let Some(derived) = derived.as_ref() {
                let assertion =
                    derived.protocol_assertion(observed_at_unix_ms, consumer.maximum_age_ms)?;
                let mut assertion_event = new_search_event(
                    consumer.search_id,
                    observed_at_unix_ms,
                    SearchEventData::AssertionUpdated { assertion },
                )?;
                assertion_event.sequence =
                    next_sequence(&mut transaction, claim.tenant_id, consumer.search_id).await?;
                insert_event(
                    &mut transaction,
                    claim.tenant_id,
                    consumer.search_id,
                    None,
                    &assertion_event,
                )
                .await?;
                insert_lineage(
                    &mut transaction,
                    claim.tenant_id,
                    "assertion",
                    derived.id(),
                    "search_event",
                    event_uuid(&assertion_event)?,
                    "assertion_update",
                )
                .await?;
            }
            finish_search_if_complete(&mut transaction, claim.tenant_id, consumer.search_id)
                .await?;
        }
        for consumer in watch_consumers {
            complete_watch_consumer(&mut transaction, claim.tenant_id, &consumer, observation_id)
                .await?;
            apply_watch_interpretation(
                &mut transaction,
                &WatchInterpretationKey {
                    tenant_id: claim.tenant_id,
                    watch_target_id: consumer.watch_target_id,
                    rule_version_id: claim.rule_version_id,
                    region_class: &claim.region_class,
                },
                derived.as_ref(),
                outcome.measurement_outcome(
                    observation_id,
                    derived.as_ref().is_some_and(|value| value.is_conflicted()),
                ),
                observed_at_unix_ms,
            )
            .await?;
            insert_lineage(
                &mut transaction,
                claim.tenant_id,
                "observation",
                observation_id,
                "watch_run_target",
                consumer.watch_run_target_id,
                "watch_result",
            )
            .await?;
            finish_watch_run(&mut transaction, claim.tenant_id, consumer.watch_run_id).await?;
        }
        transaction
            .commit()
            .await
            .map_err(|_| JobError::DatabaseUnavailable)?;
        Ok(JobDisposition::Succeeded)
    }

    async fn record_failure(
        &self,
        claim: &JobClaim,
        kind: OperationalFailureKind,
        retryable: bool,
        maximum_attempts: u32,
    ) -> Result<JobDisposition, JobError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| JobError::DatabaseUnavailable)?;
        set_tenant(&mut transaction, claim.tenant_id).await?;
        match lock_claim(&mut transaction, claim).await? {
            ClaimState::Final => {
                transaction
                    .commit()
                    .await
                    .map_err(|_| JobError::DatabaseUnavailable)?;
                return Ok(JobDisposition::AlreadyFinal);
            }
            ClaimState::Active => {}
        }
        ensure_rule_available(&mut transaction, claim).await?;
        if !lock_active_consent(&mut transaction, claim).await? {
            cancel_orphaned_claim(&mut transaction, claim).await?;
            transaction
                .commit()
                .await
                .map_err(|_| JobError::DatabaseUnavailable)?;
            return Ok(JobDisposition::Cancelled);
        }
        prune_dead_watch_consumers(&mut transaction, claim).await?;
        let search_consumers = load_live_search_consumers(&mut transaction, claim).await?;
        let watch_consumers = load_live_watch_consumers(&mut transaction, claim).await?;
        if search_consumers.is_empty() && watch_consumers.is_empty() {
            cancel_orphaned_claim(&mut transaction, claim).await?;
            transaction
                .commit()
                .await
                .map_err(|_| JobError::DatabaseUnavailable)?;
            return Ok(JobDisposition::Cancelled);
        }
        if retryable && claim.attempt_count < maximum_attempts {
            let retry_delay_ms = retry_delay_ms(claim.attempt_count);
            sqlx::query(
                "UPDATE probe_jobs \
                 SET state = 'retry_wait', available_at = clock_timestamp() \
                         + ($4::bigint::text || ' milliseconds')::interval, \
                     lease_owner = NULL, lease_expires_at = NULL, \
                     last_error_code = $5, updated_at = clock_timestamp() \
                 WHERE tenant_id = $1 AND id = $2 \
                   AND state = 'leased' AND attempt_count = $3",
            )
            .bind(claim.tenant_id)
            .bind(claim.job_id)
            .bind(i32::try_from(claim.attempt_count).map_err(|_| JobError::StorageInvariant)?)
            .bind(retry_delay_ms)
            .bind(failure_kind_name(kind))
            .execute(&mut *transaction)
            .await
            .map_err(|_| JobError::StorageInvariant)?;
            transaction
                .commit()
                .await
                .map_err(|_| JobError::DatabaseUnavailable)?;
            return Ok(JobDisposition::RetryScheduled);
        }

        transition_job_to_final(
            &mut transaction,
            claim,
            "failed",
            Some(failure_kind_name(kind)),
        )
        .await?;
        let occurred_at_unix_ms = database_now_ms(&mut transaction).await?;
        for consumer in search_consumers {
            let event =
                operational_failure_event(claim, &consumer, kind, false, occurred_at_unix_ms)?;
            insert_search_result(
                &mut transaction,
                claim.tenant_id,
                &consumer,
                &event,
                "failed",
            )
            .await?;
            insert_lineage(
                &mut transaction,
                claim.tenant_id,
                "probe_job",
                claim.job_id,
                "search_event",
                event_uuid(&event)?,
                "operational_failure",
            )
            .await?;
            finish_search_if_complete(&mut transaction, claim.tenant_id, consumer.search_id)
                .await?;
        }
        for consumer in watch_consumers {
            fail_watch_consumer(&mut transaction, claim.tenant_id, &consumer).await?;
            apply_watch_interpretation(
                &mut transaction,
                &WatchInterpretationKey {
                    tenant_id: claim.tenant_id,
                    watch_target_id: consumer.watch_target_id,
                    rule_version_id: claim.rule_version_id,
                    region_class: &claim.region_class,
                },
                None,
                MeasurementOutcome::Unavailable {
                    probe_job_id: claim.job_id,
                },
                occurred_at_unix_ms,
            )
            .await?;
            insert_lineage(
                &mut transaction,
                claim.tenant_id,
                "probe_job",
                claim.job_id,
                "watch_run_target",
                consumer.watch_run_target_id,
                "operational_failure",
            )
            .await?;
            finish_watch_run(&mut transaction, claim.tenant_id, consumer.watch_run_id).await?;
        }
        transaction
            .commit()
            .await
            .map_err(|_| JobError::DatabaseUnavailable)?;
        Ok(JobDisposition::Failed)
    }

    async fn claim_is_authorized(&self, claim: &JobClaim) -> Result<bool, JobError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| JobError::DatabaseUnavailable)?;
        set_tenant(&mut transaction, claim.tenant_id).await?;
        if !rule_is_available(&mut transaction, claim).await? {
            transaction
                .commit()
                .await
                .map_err(|_| JobError::DatabaseUnavailable)?;
            return Ok(false);
        }
        let authorized: bool = sqlx::query_scalar(
            "SELECT EXISTS (\
                SELECT 1 \
                FROM probe_jobs AS job \
                JOIN consent_grants AS consent \
                  ON consent.tenant_id = job.tenant_id \
                 AND consent.id = job.consent_grant_id \
                WHERE job.tenant_id = $1 AND job.id = $2 \
                  AND job.state = 'leased' \
                  AND job.attempt_count = $3 \
                  AND job.lease_owner = $4 \
                  AND job.lease_expires_at > clock_timestamp() \
                  AND consent.subject_kind = 'account' \
                  AND consent.granted_at <= clock_timestamp() \
                  AND consent.withdrawn_at IS NULL \
                  AND (\
                      consent.expires_at IS NULL \
                      OR consent.expires_at > clock_timestamp()\
                  ) \
                  AND (\
                      (job.visibility = 'private' \
                       AND consent.purpose = 'private_history') \
                      OR \
                      (job.visibility = 'shared' \
                       AND consent.purpose = 'shared_observation')\
                  ) \
                  AND (\
                      EXISTS (\
                          SELECT 1 \
                          FROM probe_job_consumers AS consumer \
                          JOIN search_targets AS target \
                            ON target.tenant_id = consumer.tenant_id \
                           AND target.id = consumer.search_target_id \
                          JOIN searches AS search \
                            ON search.tenant_id = target.tenant_id \
                           AND search.id = target.search_id \
                          WHERE consumer.tenant_id = job.tenant_id \
                            AND consumer.probe_job_id = job.id \
                            AND target.state IN ('pending', 'running') \
                            AND search.state IN ('accepted', 'running')\
                      ) \
                      OR EXISTS (\
                          SELECT 1 \
                          FROM probe_job_consumers AS consumer \
                          JOIN watch_run_targets AS run_target \
                            ON run_target.tenant_id = consumer.tenant_id \
                           AND run_target.id = consumer.watch_run_target_id \
                          JOIN watch_runs AS run \
                            ON run.tenant_id = run_target.tenant_id \
                           AND run.id = run_target.watch_run_id \
                          JOIN watches AS watch \
                            ON watch.tenant_id = run.tenant_id \
                           AND watch.id = run.watch_id \
                          WHERE consumer.tenant_id = job.tenant_id \
                            AND consumer.probe_job_id = job.id \
                            AND run_target.state = 'queued' \
                            AND run_target.probe_job_id = job.id \
                            AND run.state IN ('planned', 'running') \
                            AND watch.state = 'active' \
                            AND watch.revision = run.watch_revision \
                            AND watch.consent_grant_id = job.consent_grant_id \
                            AND job.visibility = 'private' \
                            AND EXISTS (\
                                SELECT 1 \
                                FROM watch_notification_endpoints AS link \
                                JOIN notification_endpoints AS endpoint \
                                  ON endpoint.tenant_id = link.tenant_id \
                                 AND endpoint.id = link.endpoint_id \
                                WHERE link.tenant_id = watch.tenant_id \
                                  AND link.watch_id = watch.id \
                                  AND endpoint.state = 'active'\
                            )\
                      )\
                  )\
             )",
        )
        .bind(claim.tenant_id)
        .bind(claim.job_id)
        .bind(i32::try_from(claim.attempt_count).map_err(|_| JobError::StorageInvariant)?)
        .bind(&claim.lease_owner)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| JobError::DatabaseUnavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| JobError::DatabaseUnavailable)?;
        Ok(authorized)
    }

    async fn wait_until_unauthorized(&self, claim: &JobClaim) -> Result<(), JobError> {
        let mut interval = tokio::time::interval(Duration::from_millis(250));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            if !self.claim_is_authorized(claim).await? {
                return Ok(());
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleBinding {
    rule_version_id: Uuid,
    site_id: String,
    rule_hash: String,
    rule_pack_hash: String,
    engine_hash: String,
    region_class: String,
    metadata_id: String,
    metadata_sequence: u64,
    promotion_id: String,
    promotion_sequence: u64,
}

impl RuleBinding {
    #[must_use]
    pub const fn rule_version_id(&self) -> Uuid {
        self.rule_version_id
    }

    #[must_use]
    pub fn site_id(&self) -> &str {
        &self.site_id
    }

    #[must_use]
    pub fn region_class(&self) -> &str {
        &self.region_class
    }

    fn matches_rule(&self, rule: &ManagedRule) -> Result<(), JobError> {
        if self.site_id == rule.site_id()
            && self.rule_hash == rule.rule_hash()
            && self.rule_pack_hash == rule.rule_pack_hash()
            && self.engine_hash == rule.engine_hash()
            && self.region_class == rule.region_class()
            && self.metadata_id == rule.metadata_id()
            && self.metadata_sequence == rule.metadata_sequence()
            && self.promotion_id == rule.promotion_id()
            && self.promotion_sequence == rule.promotion_sequence()
        {
            Ok(())
        } else {
            Err(JobError::RuleUnavailable)
        }
    }
}

#[derive(Clone)]
pub struct JobClaim {
    tenant_id: Uuid,
    job_id: Uuid,
    normalized_username: String,
    site_id: String,
    rule_version_id: Uuid,
    rule_hash: String,
    rule_pack_hash: String,
    engine_hash: String,
    region_class: String,
    metadata_id: String,
    promotion_id: String,
    consent_grant_id: Uuid,
    visibility: String,
    attempt_count: u32,
    lease_owner: String,
}

impl JobClaim {
    #[must_use]
    pub const fn job_id(&self) -> Uuid {
        self.job_id
    }

    #[must_use]
    pub const fn attempt_count(&self) -> u32 {
        self.attempt_count
    }

    fn matches_rule(&self, rule: &ManagedRule) -> Result<(), WorkerError> {
        if self.site_id != rule.site_id()
            || self.rule_hash != rule.rule_hash()
            || self.rule_pack_hash != rule.rule_pack_hash()
            || self.engine_hash != rule.engine_hash()
            || self.region_class != rule.region_class()
            || self.metadata_id != rule.metadata_id()
            || self.promotion_id != rule.promotion_id()
        {
            return Err(WorkerError::RulePackMismatch);
        }
        Ok(())
    }

    fn validate_result(&self, result: &SearchResult) -> Result<(), JobError> {
        if result.site_id == self.site_id
            && result.username == self.normalized_username
            && result.rule_hash == self.rule_hash
        {
            Ok(())
        } else {
            Err(JobError::ResultMismatch)
        }
    }
}

impl fmt::Debug for JobClaim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JobClaim")
            .field("job_id", &self.job_id)
            .field("site_id", &self.site_id)
            .field("region_class", &self.region_class)
            .field("attempt_count", &self.attempt_count)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpandOutcome {
    Idle,
    Enqueued { job_id: Uuid },
    Coalesced { job_id: Uuid },
    InvalidTargetCompleted,
    FreshObservationCompleted,
    BudgetExceededCompleted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatchPlanOutcome {
    Idle,
    Planned { run_id: Uuid, target_count: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvidenceRetentionOutcome {
    pub research_excerpts_purged: u32,
    pub structured_capsules_purged: u32,
    pub expired_receipts_deleted: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobDisposition {
    Succeeded,
    RetryScheduled,
    Failed,
    Cancelled,
    AlreadyFinal,
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum JobError {
    #[error("managed worker database configuration is invalid")]
    DatabaseConfiguration,
    #[error("managed worker database is unavailable")]
    DatabaseUnavailable,
    #[error("managed worker configuration is invalid")]
    InvalidConfiguration,
    #[error("signed managed rule is unavailable in the registry")]
    RuleUnavailable,
    #[error("managed job storage invariant failed")]
    StorageInvariant,
    #[error("managed job lease is stale")]
    StaleLease,
    #[error("managed result does not match its leased job")]
    ResultMismatch,
    #[error("managed result violates the public protocol")]
    InvalidProtocol,
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum JobExecutionError {
    #[error("managed job execution was cancelled")]
    Cancelled,
    #[error("managed job authorization could not be rechecked")]
    AuthorizationUnavailable,
    #[error(transparent)]
    Worker(WorkerError),
}

#[derive(FromRow)]
struct LockedTargetId {
    tenant_id: Uuid,
    search_target_id: Uuid,
}

#[derive(FromRow)]
struct LockedWatchId {
    tenant_id: Uuid,
    watch_id: Uuid,
}

#[derive(FromRow)]
struct LockedWatchTargetId {
    tenant_id: Uuid,
    watch_run_target_id: Uuid,
}

#[derive(FromRow)]
struct WatchPlan {
    revision: i64,
    interval_seconds: i32,
    jitter_percent: i16,
    maximum_probes_per_run: i32,
    maximum_bytes_per_run: i64,
    region_classes: Vec<String>,
    scheduled_for_unix_ms: i64,
}

#[derive(FromRow)]
struct WatchExpansionTarget {
    watch_run_id: Uuid,
    watch_target_id: Uuid,
    requested_username: String,
    site_id: String,
    consent_grant_id: Uuid,
    maximum_age_ms: i64,
}

#[derive(FromRow)]
struct FreshObservation {
    id: Uuid,
    outcome_kind: String,
}

#[derive(FromRow)]
struct ExpansionTarget {
    search_id: Uuid,
    requested_username: String,
    site_id: String,
    consent_grant_id: Option<Uuid>,
    sync_policy: String,
    #[allow(dead_code)]
    maximum_age_ms: i64,
}

#[derive(FromRow)]
struct ClaimedJobId {
    tenant_id: Uuid,
    probe_job_id: Uuid,
    attempt_count: i32,
}

#[derive(FromRow)]
struct ClaimedJobRow {
    normalized_username: String,
    site_id: String,
    rule_version_id: Uuid,
    region_class: String,
    consent_grant_id: Option<Uuid>,
    visibility: Option<String>,
}

#[derive(FromRow)]
struct LockedClaimRow {
    state: String,
    attempt_count: i32,
    lease_owner: Option<String>,
    lease_is_current: bool,
}

#[derive(FromRow)]
struct LiveSearchConsumer {
    search_target_id: Uuid,
    search_id: Uuid,
    maximum_age_ms: i64,
}

#[derive(FromRow)]
struct LiveWatchConsumer {
    watch_run_target_id: Uuid,
    watch_run_id: Uuid,
    watch_target_id: Uuid,
    retention_days: i16,
}

#[derive(Clone, Copy)]
enum ManagedResult {
    Observation(RecordedOutcome),
    Failure {
        kind: OperationalFailureKind,
        retryable: bool,
    },
}

#[derive(Clone, Copy)]
pub(crate) enum RecordedOutcome {
    Definitive(DefinitiveVerdict),
    Uncertain(UncertaintyReason),
}

impl RecordedOutcome {
    const fn database_values(self) -> (&'static str, Option<&'static str>, Option<&'static str>) {
        match self {
            Self::Definitive(DefinitiveVerdict::Found) => ("definitive", Some("found"), None),
            Self::Definitive(DefinitiveVerdict::NotFound) => {
                ("definitive", Some("not_found"), None)
            }
            Self::Uncertain(UncertaintyReason::SiteChanged) => {
                ("uncertain", None, Some("site_changed"))
            }
            Self::Uncertain(UncertaintyReason::NoRuleMatched) => {
                ("uncertain", None, Some("no_rule_matched"))
            }
            Self::Uncertain(UncertaintyReason::ConflictingEvidence) => {
                ("uncertain", None, Some("conflicting_evidence"))
            }
            Self::Uncertain(UncertaintyReason::ClassificationAmbiguous) => {
                ("uncertain", None, Some("classification_ambiguous"))
            }
        }
    }

    const fn ttl_ms(self) -> i64 {
        match self {
            Self::Definitive(DefinitiveVerdict::Found) => 24 * 60 * 60 * 1_000,
            Self::Definitive(DefinitiveVerdict::NotFound) => 15 * 60 * 1_000,
            Self::Uncertain(_) => 5 * 60 * 1_000,
        }
    }

    const fn measurement_outcome(
        self,
        observation_id: Uuid,
        assertion_is_conflicted: bool,
    ) -> MeasurementOutcome {
        match self {
            Self::Definitive(_) if assertion_is_conflicted => {
                MeasurementOutcome::Degraded { observation_id }
            }
            Self::Definitive(_) => MeasurementOutcome::Healthy { observation_id },
            Self::Uncertain(_) => MeasurementOutcome::Degraded { observation_id },
        }
    }
}

#[derive(Clone, Copy)]
enum ClaimState {
    Active,
    Final,
}

pub(crate) async fn connect_worker_pool_from_env() -> Result<PgPool, JobError> {
    let database_url =
        env::var(WORKER_DATABASE_URL_ENV).map_err(|_| JobError::DatabaseConfiguration)?;
    if database_url.is_empty() {
        return Err(JobError::DatabaseConfiguration);
    }
    tokio::time::timeout(
        CONNECT_TIMEOUT,
        PgPoolOptions::new()
            .max_connections(MAXIMUM_CONNECTIONS)
            .acquire_timeout(ACQUIRE_TIMEOUT)
            .after_connect(|connection, _metadata| {
                Box::pin(async move {
                    for statement in SESSION_LIMITS {
                        sqlx::query(statement).execute(&mut *connection).await?;
                    }
                    Ok(())
                })
            })
            .connect(&database_url),
    )
    .await
    .map_err(|_| JobError::DatabaseUnavailable)?
    .map_err(|_| JobError::DatabaseUnavailable)
}

pub(crate) async fn set_tenant(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
) -> Result<(), JobError> {
    sqlx::query("SELECT set_config('socialname.tenant_id', $1, true)")
        .bind(tenant_id.to_string())
        .execute(&mut **transaction)
        .await
        .map_err(|_| JobError::DatabaseUnavailable)?;
    Ok(())
}

pub(crate) async fn database_now_ms(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<i64, JobError> {
    sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
        .fetch_one(&mut **transaction)
        .await
        .map_err(|_| JobError::DatabaseUnavailable)
}

fn visibility_for_sync(sync_policy: &str) -> Result<&'static str, JobError> {
    match sync_policy {
        "private" => Ok("private"),
        "shared" => Ok("shared"),
        _ => Err(JobError::StorageInvariant),
    }
}

fn work_key_hash(
    tenant_id: Uuid,
    normalized_username: &str,
    binding: &RuleBinding,
    consent_grant_id: Uuid,
    visibility: &str,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for component in [
        tenant_id.as_bytes().as_slice(),
        normalized_username.as_bytes(),
        binding.site_id.as_bytes(),
        binding.rule_version_id.as_bytes().as_slice(),
        binding.region_class.as_bytes(),
        consent_grant_id.as_bytes().as_slice(),
        visibility.as_bytes(),
    ] {
        hasher.update(
            u64::try_from(component.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        hasher.update(component);
    }
    hasher.finalize().into()
}

fn watch_schedule_delay_ms(
    watch_id: Uuid,
    revision: i64,
    scheduled_for_unix_ms: i64,
    interval_seconds: i32,
    jitter_percent: i16,
) -> Result<i64, JobError> {
    if revision <= 0
        || interval_seconds <= 0
        || !(0..=20).contains(&jitter_percent)
        || scheduled_for_unix_ms <= 0
    {
        return Err(JobError::StorageInvariant);
    }
    let interval_ms = i64::from(interval_seconds)
        .checked_mul(1_000)
        .ok_or(JobError::StorageInvariant)?;
    let jitter_window = interval_ms
        .checked_mul(i64::from(jitter_percent))
        .and_then(|value| value.checked_div(100))
        .ok_or(JobError::StorageInvariant)?;
    if jitter_window == 0 {
        return Ok(interval_ms);
    }
    let mut hasher = Sha256::new();
    hasher.update(watch_id.as_bytes());
    hasher.update(revision.to_be_bytes());
    hasher.update(scheduled_for_unix_ms.to_be_bytes());
    let digest = hasher.finalize();
    let sample = u64::from_be_bytes(
        digest[..8]
            .try_into()
            .map_err(|_| JobError::StorageInvariant)?,
    );
    let span = u64::try_from(
        jitter_window
            .checked_mul(2)
            .and_then(|value| value.checked_add(1))
            .ok_or(JobError::StorageInvariant)?,
    )
    .map_err(|_| JobError::StorageInvariant)?;
    let offset =
        i64::try_from(sample % span).map_err(|_| JobError::StorageInvariant)? - jitter_window;
    interval_ms
        .checked_add(offset)
        .ok_or(JobError::StorageInvariant)
}

fn decode_digest(value: &str) -> Result<Vec<u8>, JobError> {
    let bytes = hex::decode(value).map_err(|_| JobError::InvalidProtocol)?;
    if bytes.len() == 32 {
        Ok(bytes)
    } else {
        Err(JobError::InvalidProtocol)
    }
}

fn valid_label(value: &str) -> bool {
    value.len() <= 64
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || (index > 0 && byte == b'-')
        })
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn validate_maximum_attempts(maximum_attempts: u32) -> Result<(), JobError> {
    if (1..=MAXIMUM_ATTEMPTS).contains(&maximum_attempts) {
        Ok(())
    } else {
        Err(JobError::InvalidConfiguration)
    }
}

fn retry_delay_ms(attempt_count: u32) -> i64 {
    let exponent = attempt_count.saturating_sub(1).min(16);
    INITIAL_RETRY_DELAY_MS
        .saturating_mul(1_i64.checked_shl(exponent).unwrap_or(i64::MAX))
        .min(MAXIMUM_RETRY_DELAY_MS)
}

async fn lock_claim(
    transaction: &mut Transaction<'_, Postgres>,
    claim: &JobClaim,
) -> Result<ClaimState, JobError> {
    let row: LockedClaimRow = sqlx::query_as(
        "SELECT state, attempt_count, lease_owner, \
                COALESCE(lease_expires_at > clock_timestamp(), false) \
                    AS lease_is_current \
         FROM probe_jobs \
         WHERE tenant_id = $1 AND id = $2 \
         FOR UPDATE",
    )
    .bind(claim.tenant_id)
    .bind(claim.job_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| JobError::StorageInvariant)?;
    if matches!(row.state.as_str(), "succeeded" | "failed" | "cancelled") {
        return Ok(ClaimState::Final);
    }
    let attempt_count = u32::try_from(row.attempt_count).map_err(|_| JobError::StorageInvariant)?;
    if row.state != "leased"
        || attempt_count != claim.attempt_count
        || row.lease_owner.as_deref() != Some(claim.lease_owner.as_str())
        || !row.lease_is_current
    {
        return Err(JobError::StaleLease);
    }
    Ok(ClaimState::Active)
}

async fn load_live_search_consumers(
    transaction: &mut Transaction<'_, Postgres>,
    claim: &JobClaim,
) -> Result<Vec<LiveSearchConsumer>, JobError> {
    sqlx::query_as(
        "SELECT target.id AS search_target_id, target.search_id, \
                search.maximum_age_ms \
         FROM probe_job_consumers AS consumer \
         JOIN search_targets AS target \
           ON target.tenant_id = consumer.tenant_id \
          AND target.id = consumer.search_target_id \
         JOIN searches AS search \
           ON search.tenant_id = target.tenant_id \
          AND search.id = target.search_id \
         WHERE consumer.tenant_id = $1 AND consumer.probe_job_id = $2 \
           AND target.state IN ('pending', 'running') \
           AND search.state IN ('accepted', 'running') \
           AND search.consent_grant_id = $3 \
           AND search.sync_policy = $4 \
         ORDER BY search.id, target.id \
         FOR UPDATE OF search, target",
    )
    .bind(claim.tenant_id)
    .bind(claim.job_id)
    .bind(claim.consent_grant_id)
    .bind(&claim.visibility)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| JobError::StorageInvariant)
}

async fn load_live_watch_consumers(
    transaction: &mut Transaction<'_, Postgres>,
    claim: &JobClaim,
) -> Result<Vec<LiveWatchConsumer>, JobError> {
    sqlx::query_as(
        "SELECT run_target.id AS watch_run_target_id, \
                run_target.watch_run_id, run_target.watch_target_id, \
                watch.retention_days \
         FROM probe_job_consumers AS consumer \
         JOIN watch_run_targets AS run_target \
           ON run_target.tenant_id = consumer.tenant_id \
          AND run_target.id = consumer.watch_run_target_id \
         JOIN watch_runs AS run \
           ON run.tenant_id = run_target.tenant_id \
          AND run.id = run_target.watch_run_id \
         JOIN watches AS watch \
           ON watch.tenant_id = run.tenant_id \
          AND watch.id = run.watch_id \
         JOIN watch_targets AS target \
           ON target.tenant_id = run_target.tenant_id \
          AND target.id = run_target.watch_target_id \
         WHERE consumer.tenant_id = $1 AND consumer.probe_job_id = $2 \
           AND run_target.state = 'queued' \
           AND run_target.probe_job_id = $2 \
           AND run.state IN ('planned', 'running') \
           AND watch.state = 'active' \
           AND watch.revision = run.watch_revision \
           AND watch.consent_grant_id = $3 \
           AND $4 = 'private' \
           AND EXISTS (\
               SELECT 1 \
               FROM watch_notification_endpoints AS link \
               JOIN notification_endpoints AS endpoint \
                 ON endpoint.tenant_id = link.tenant_id \
                AND endpoint.id = link.endpoint_id \
               WHERE link.tenant_id = watch.tenant_id \
                 AND link.watch_id = watch.id \
                 AND endpoint.state = 'active'\
         ) \
         ORDER BY run.id, run_target.id \
         FOR UPDATE OF run_target, run, watch, target",
    )
    .bind(claim.tenant_id)
    .bind(claim.job_id)
    .bind(claim.consent_grant_id)
    .bind(&claim.visibility)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| JobError::StorageInvariant)
}

async fn lock_active_consent(
    transaction: &mut Transaction<'_, Postgres>,
    claim: &JobClaim,
) -> Result<bool, JobError> {
    sqlx::query_scalar("SELECT socialname_worker_lock_claim_consent($1, $2, $3)")
        .bind(claim.job_id)
        .bind(i32::try_from(claim.attempt_count).map_err(|_| JobError::StorageInvariant)?)
        .bind(&claim.lease_owner)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|_| JobError::DatabaseUnavailable)
}

async fn ensure_rule_available(
    transaction: &mut Transaction<'_, Postgres>,
    claim: &JobClaim,
) -> Result<(), JobError> {
    if rule_is_available(transaction, claim).await? {
        Ok(())
    } else {
        Err(JobError::RuleUnavailable)
    }
}

async fn rule_is_available(
    transaction: &mut Transaction<'_, Postgres>,
    claim: &JobClaim,
) -> Result<bool, JobError> {
    sqlx::query_scalar("SELECT socialname_worker_rule_version_available($1, $2)")
        .bind(claim.rule_version_id)
        .bind(&claim.region_class)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|_| JobError::DatabaseUnavailable)
}

async fn cancel_orphaned_claim(
    transaction: &mut Transaction<'_, Postgres>,
    claim: &JobClaim,
) -> Result<(), JobError> {
    prune_dead_watch_consumers(transaction, claim).await?;
    transition_job_to_final(transaction, claim, "cancelled", Some("consumer_cancelled")).await
}

async fn prune_dead_watch_consumers(
    transaction: &mut Transaction<'_, Postgres>,
    claim: &JobClaim,
) -> Result<(), JobError> {
    let dead_consumers: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT run_target.id, run_target.watch_run_id \
         FROM probe_job_consumers AS consumer \
         JOIN watch_run_targets AS run_target \
           ON run_target.tenant_id = consumer.tenant_id \
          AND run_target.id = consumer.watch_run_target_id \
         JOIN watch_runs AS run \
           ON run.tenant_id = run_target.tenant_id \
          AND run.id = run_target.watch_run_id \
         JOIN watches AS watch \
           ON watch.tenant_id = run.tenant_id \
          AND watch.id = run.watch_id \
         WHERE consumer.tenant_id = $1 AND consumer.probe_job_id = $2 \
           AND run_target.state = 'queued' \
           AND NOT (\
               run.state IN ('planned', 'running') \
               AND watch.state = 'active' \
               AND watch.revision = run.watch_revision \
               AND watch.consent_grant_id = $3 \
               AND $4 = 'private' \
               AND EXISTS (\
                   SELECT 1 \
                   FROM watch_notification_endpoints AS link \
                   JOIN notification_endpoints AS endpoint \
                     ON endpoint.tenant_id = link.tenant_id \
                    AND endpoint.id = link.endpoint_id \
                   WHERE link.tenant_id = watch.tenant_id \
                     AND link.watch_id = watch.id \
                     AND endpoint.state = 'active'\
               )\
           ) \
         ORDER BY run.id, run_target.id \
         FOR UPDATE OF run, run_target, watch",
    )
    .bind(claim.tenant_id)
    .bind(claim.job_id)
    .bind(claim.consent_grant_id)
    .bind(&claim.visibility)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| JobError::StorageInvariant)?;
    for (run_target_id, run_id) in dead_consumers {
        sqlx::query(
            "UPDATE watch_run_targets \
             SET state = 'cancelled', completed_at = clock_timestamp() \
             WHERE tenant_id = $1 AND id = $2 AND state = 'queued'",
        )
        .bind(claim.tenant_id)
        .bind(run_target_id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| JobError::StorageInvariant)?;
        finish_watch_run(transaction, claim.tenant_id, run_id).await?;
    }
    Ok(())
}

async fn finalize_watch_target_without_observation(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    watch_run_target_id: Uuid,
    watch_run_id: Uuid,
    state: &str,
) -> Result<(), JobError> {
    if !matches!(state, "failed" | "cancelled") {
        return Err(JobError::StorageInvariant);
    }
    let affected = sqlx::query(
        "UPDATE watch_run_targets \
         SET state = $3, completed_at = clock_timestamp() \
         WHERE tenant_id = $1 AND id = $2 AND state = 'pending'",
    )
    .bind(tenant_id)
    .bind(watch_run_target_id)
    .bind(state)
    .execute(&mut **transaction)
    .await
    .map_err(|_| JobError::StorageInvariant)?
    .rows_affected();
    if affected != 1 {
        return Err(JobError::StorageInvariant);
    }
    finish_watch_run(transaction, tenant_id, watch_run_id).await
}

async fn complete_watch_consumer(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    consumer: &LiveWatchConsumer,
    observation_id: Uuid,
) -> Result<(), JobError> {
    let affected = sqlx::query(
        "UPDATE watch_run_targets \
         SET state = 'completed', observation_id = $3, \
             completed_at = clock_timestamp() \
         WHERE tenant_id = $1 AND id = $2 AND state = 'queued'",
    )
    .bind(tenant_id)
    .bind(consumer.watch_run_target_id)
    .bind(observation_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| JobError::StorageInvariant)?
    .rows_affected();
    if affected == 1 {
        Ok(())
    } else {
        Err(JobError::StorageInvariant)
    }
}

async fn fail_watch_consumer(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    consumer: &LiveWatchConsumer,
) -> Result<(), JobError> {
    let affected = sqlx::query(
        "UPDATE watch_run_targets \
         SET state = 'failed', completed_at = clock_timestamp() \
         WHERE tenant_id = $1 AND id = $2 AND state = 'queued'",
    )
    .bind(tenant_id)
    .bind(consumer.watch_run_target_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| JobError::StorageInvariant)?
    .rows_affected();
    if affected == 1 {
        Ok(())
    } else {
        Err(JobError::StorageInvariant)
    }
}

async fn finish_watch_run(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    watch_run_id: Uuid,
) -> Result<(), JobError> {
    sqlx::query(
        "UPDATE watch_runs AS run \
         SET state = CASE \
                 WHEN EXISTS (\
                     SELECT 1 FROM watch_run_targets AS target \
                     WHERE target.tenant_id = run.tenant_id \
                       AND target.watch_run_id = run.id \
                       AND target.state = 'failed'\
                 ) THEN 'failed' \
                 WHEN EXISTS (\
                     SELECT 1 FROM watch_run_targets AS target \
                     WHERE target.tenant_id = run.tenant_id \
                       AND target.watch_run_id = run.id \
                       AND target.state = 'cancelled'\
                 ) THEN 'cancelled' \
                 ELSE 'completed' \
             END, \
             completed_at = clock_timestamp() \
         WHERE run.tenant_id = $1 AND run.id = $2 \
           AND run.state IN ('planned', 'running') \
           AND NOT EXISTS (\
               SELECT 1 FROM watch_run_targets AS target \
               WHERE target.tenant_id = run.tenant_id \
                 AND target.watch_run_id = run.id \
                 AND target.state IN ('pending', 'queued')\
           )",
    )
    .bind(tenant_id)
    .bind(watch_run_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| JobError::StorageInvariant)?;
    Ok(())
}

async fn transition_job_to_final(
    transaction: &mut Transaction<'_, Postgres>,
    claim: &JobClaim,
    state: &str,
    error_code: Option<&str>,
) -> Result<(), JobError> {
    let affected = sqlx::query(
        "UPDATE probe_jobs \
         SET state = $4, lease_owner = NULL, lease_expires_at = NULL, \
             last_error_code = $5, updated_at = clock_timestamp(), \
             completed_at = clock_timestamp() \
         WHERE tenant_id = $1 AND id = $2 \
           AND state = 'leased' AND attempt_count = $3",
    )
    .bind(claim.tenant_id)
    .bind(claim.job_id)
    .bind(i32::try_from(claim.attempt_count).map_err(|_| JobError::StorageInvariant)?)
    .bind(state)
    .bind(error_code)
    .execute(&mut **transaction)
    .await
    .map_err(|_| JobError::StorageInvariant)?
    .rows_affected();
    if affected == 1 {
        Ok(())
    } else {
        Err(JobError::StaleLease)
    }
}

async fn finalize_invalid_target(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    search_target_id: Uuid,
    target: &ExpansionTarget,
    binding: &RuleBinding,
) -> Result<(), JobError> {
    let occurred_at_unix_ms = database_now_ms(transaction).await?;
    let sequence = next_sequence(transaction, tenant_id, target.search_id).await?;
    let event_id = Uuid::new_v4();
    let event = SearchEvent {
        schema: ProtocolVersion::ApiV1,
        event_id: EventId::new(event_id.to_string()).map_err(|_| JobError::InvalidProtocol)?,
        search_id: SearchId::new(target.search_id.to_string())
            .map_err(|_| JobError::InvalidProtocol)?,
        sequence,
        emitted_at_unix_ms: occurred_at_unix_ms,
        data: SearchEventData::OperationalFailure {
            failure: OperationalFailure {
                target: Target {
                    username: Username::new(target.requested_username.clone())
                        .map_err(|_| JobError::InvalidProtocol)?,
                    site_id: SiteId::new(target.site_id.clone())
                        .map_err(|_| JobError::InvalidProtocol)?,
                },
                kind: OperationalFailureKind::InvalidTarget,
                source: ResultSource::ManagedProbe,
                occurred_at_unix_ms,
                retryable: false,
                region_class: Some(
                    RegionClass::new(binding.region_class.clone())
                        .map_err(|_| JobError::InvalidProtocol)?,
                ),
                rule_hash: Some(
                    RuleHash::new(binding.rule_hash.clone())
                        .map_err(|_| JobError::InvalidProtocol)?,
                ),
            },
        },
    };
    insert_event(
        transaction,
        tenant_id,
        target.search_id,
        Some(search_target_id),
        &event,
    )
    .await?;
    sqlx::query(
        "UPDATE search_targets \
         SET state = 'failed', completed_at = clock_timestamp() \
         WHERE tenant_id = $1 AND id = $2 AND state = 'pending'",
    )
    .bind(tenant_id)
    .bind(search_target_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| JobError::StorageInvariant)?;
    sqlx::query(
        "UPDATE searches SET state = 'running', updated_at = clock_timestamp() \
         WHERE tenant_id = $1 AND id = $2 AND state = 'accepted'",
    )
    .bind(tenant_id)
    .bind(target.search_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| JobError::StorageInvariant)?;
    insert_lineage(
        transaction,
        tenant_id,
        "search_target",
        search_target_id,
        "search_event",
        event_id,
        "invalid_target",
    )
    .await?;
    finish_search_if_complete(transaction, tenant_id, target.search_id).await
}

fn classify_result(result: &SearchResult) -> Result<ManagedResult, JobError> {
    match result.classification.verdict {
        Verdict::Found => Ok(ManagedResult::Observation(RecordedOutcome::Definitive(
            DefinitiveVerdict::Found,
        ))),
        Verdict::NotFound => Ok(ManagedResult::Observation(RecordedOutcome::Definitive(
            DefinitiveVerdict::NotFound,
        ))),
        Verdict::InvalidUsername => Ok(ManagedResult::Failure {
            kind: OperationalFailureKind::InvalidTarget,
            retryable: false,
        }),
        Verdict::Inconclusive => match result.classification.inconclusive_reason {
            Some(InconclusiveReason::SiteChanged) => Ok(ManagedResult::Observation(
                RecordedOutcome::Uncertain(UncertaintyReason::SiteChanged),
            )),
            Some(InconclusiveReason::NoRuleMatched) => Ok(ManagedResult::Observation(
                RecordedOutcome::Uncertain(UncertaintyReason::NoRuleMatched),
            )),
            Some(InconclusiveReason::ConflictingEvidence) => Ok(ManagedResult::Observation(
                RecordedOutcome::Uncertain(UncertaintyReason::ConflictingEvidence),
            )),
            None => Ok(ManagedResult::Observation(RecordedOutcome::Uncertain(
                UncertaintyReason::ClassificationAmbiguous,
            ))),
            Some(reason) => {
                let (kind, retryable) = operational_reason(reason)?;
                Ok(ManagedResult::Failure { kind, retryable })
            }
        },
    }
}

fn operational_reason(
    reason: InconclusiveReason,
) -> Result<(OperationalFailureKind, bool), JobError> {
    match reason {
        InconclusiveReason::Blocked => Ok((OperationalFailureKind::Blocked, true)),
        InconclusiveReason::RateLimited => Ok((OperationalFailureKind::RateLimited, true)),
        InconclusiveReason::Timeout => Ok((OperationalFailureKind::Timeout, true)),
        InconclusiveReason::Dns => Ok((OperationalFailureKind::Dns, true)),
        InconclusiveReason::Connect => Ok((OperationalFailureKind::Connect, true)),
        InconclusiveReason::Tls => Ok((OperationalFailureKind::Tls, true)),
        InconclusiveReason::RedirectRejected => {
            Ok((OperationalFailureKind::RedirectRejected, false))
        }
        InconclusiveReason::ResponseTooLarge => {
            Ok((OperationalFailureKind::ResponseTooLarge, false))
        }
        InconclusiveReason::Decode => Ok((OperationalFailureKind::Decode, false)),
        InconclusiveReason::SiteChanged
        | InconclusiveReason::NoRuleMatched
        | InconclusiveReason::ConflictingEvidence => Err(JobError::StorageInvariant),
    }
}

fn evidence_retention_policy(
    visibility: &str,
    has_search_consumer: bool,
    watch_consumers: &[LiveWatchConsumer],
) -> Result<(EvidenceCapsuleProfile, i64), JobError> {
    match visibility {
        "private" => {
            let mut retention_days =
                has_search_consumer.then_some(PRIVATE_INTERACTIVE_RETENTION_DAYS);
            for consumer in watch_consumers {
                let watch_retention = i64::from(consumer.retention_days);
                if !(MINIMUM_RETENTION_DAYS..=MAXIMUM_RETENTION_DAYS).contains(&watch_retention) {
                    return Err(JobError::StorageInvariant);
                }
                retention_days = Some(
                    retention_days.map_or(watch_retention, |current| current.max(watch_retention)),
                );
            }
            Ok((
                EvidenceCapsuleProfile::PrivateHistory,
                retention_days.ok_or(JobError::StorageInvariant)?,
            ))
        }
        "shared" if has_search_consumer && watch_consumers.is_empty() => Ok((
            EvidenceCapsuleProfile::SharedObservation,
            SHARED_CAPSULE_RETENTION_DAYS,
        )),
        _ => Err(JobError::StorageInvariant),
    }
}

#[allow(clippy::too_many_arguments)]
fn build_evidence_capsule(
    claim: &JobClaim,
    result: &SearchResult,
    outcome: RecordedOutcome,
    capsule_id: Uuid,
    observation_id: Uuid,
    profile: EvidenceCapsuleProfile,
    collected_at_unix_ms: i64,
    structured_retained_until_unix_ms: i64,
) -> Result<EvidenceCapsuleResource, JobError> {
    let target = Target {
        username: Username::new(result.username.clone()).map_err(|_| JobError::InvalidProtocol)?,
        site_id: SiteId::new(result.site_id.clone()).map_err(|_| JobError::InvalidProtocol)?,
    };
    let outcome = match outcome {
        RecordedOutcome::Definitive(verdict) => EvidenceOutcome::Definitive { verdict },
        RecordedOutcome::Uncertain(reason) => EvidenceOutcome::Uncertain { reason },
    };
    let probes = result
        .probes
        .iter()
        .map(|probe| {
            Ok(EvidenceProbe {
                probe_id: probe.probe_id.clone(),
                transport: evidence_transport_outcome(probe.transport),
                status: probe.status,
                final_url: probe
                    .final_url
                    .as_ref()
                    .map(|value| HttpsUrl::new(value.clone()))
                    .transpose()
                    .map_err(|_| JobError::InvalidProtocol)?,
                content_type: probe
                    .content_type
                    .as_deref()
                    .and_then(|value| sanitized_bounded_text(value, 256, None)),
                body_bytes: u64::try_from(probe.body_bytes)
                    .map_err(|_| JobError::InvalidProtocol)?,
                body_truncated: probe.body_truncated,
                latency_bucket_ms: latency_bucket_ms(probe.elapsed_ms),
            })
        })
        .collect::<Result<Vec<_>, JobError>>()?;
    let matcher_trace = result
        .classification
        .matcher_trace
        .iter()
        .map(|trace| EvidenceMatcherTrace {
            path: sanitized_bounded_text(&trace.path, 512, Some("matcher"))
                .expect("fallback produces a nonempty bounded matcher path"),
            matched: trace.matched,
            detail: sanitized_bounded_text(&trace.detail, 256, Some("detail"))
                .expect("fallback produces nonempty bounded matcher detail"),
        })
        .collect();
    let capsule = EvidenceCapsuleResource {
        schema: ProtocolVersion::ApiV1,
        capsule_schema: EvidenceCapsuleSchema::V1,
        evidence_capsule_id: EvidenceCapsuleId::new(capsule_id.to_string())
            .map_err(|_| JobError::InvalidProtocol)?,
        observation_id: ObservationId::new(observation_id.to_string())
            .map_err(|_| JobError::InvalidProtocol)?,
        profile,
        target,
        outcome,
        provenance: EvidenceProvenance {
            rule_hash: RuleHash::new(claim.rule_hash.clone())
                .map_err(|_| JobError::InvalidProtocol)?,
            rule_pack_hash: claim.rule_pack_hash.clone(),
            engine_hash: claim.engine_hash.clone(),
            rule_pack_metadata_id: claim.metadata_id.clone(),
            rule_promotion_id: claim.promotion_id.clone(),
        },
        vantage: EvidenceVantage {
            region_class: RegionClass::new(claim.region_class.clone())
                .map_err(|_| JobError::InvalidProtocol)?,
            network_class: EvidenceNetworkClass::Managed,
        },
        evidence_class: protocol_evidence_class(result.classification.evidence_class),
        evidence_digest: EvidenceDigest::new(result.classification.evidence_digest.clone())
            .map_err(|_| JobError::InvalidProtocol)?,
        profile_url: result
            .profile_url
            .as_ref()
            .map(|value| HttpsUrl::new(value.clone()))
            .transpose()
            .map_err(|_| JobError::InvalidProtocol)?,
        probes,
        matcher_trace,
        collected_at_unix_ms,
        structured_retained_until_unix_ms,
        research_extension: None,
        research_retained_until_unix_ms: None,
    };
    capsule.validate().map_err(|_| JobError::InvalidProtocol)?;
    Ok(capsule)
}

fn sanitized_bounded_text(
    value: &str,
    maximum_bytes: usize,
    fallback: Option<&str>,
) -> Option<String> {
    let mut output = String::with_capacity(value.len().min(maximum_bytes));
    for character in value.chars().filter(|character| !character.is_control()) {
        if output.len() + character.len_utf8() > maximum_bytes {
            break;
        }
        output.push(character);
    }
    if output.is_empty() {
        fallback.map(str::to_owned)
    } else {
        Some(output)
    }
}

fn latency_bucket_ms(elapsed_ms: u64) -> u32 {
    const BUCKETS: [u32; 15] = [
        0, 10, 25, 50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000, 30_000, 60_000, 90_000, 120_000,
    ];
    BUCKETS
        .into_iter()
        .find(|bucket| elapsed_ms <= u64::from(*bucket))
        .unwrap_or(120_000)
}

const fn evidence_transport_outcome(value: TransportOutcome) -> EvidenceTransportOutcome {
    match value {
        TransportOutcome::Completed => EvidenceTransportOutcome::Completed,
        TransportOutcome::Blocked => EvidenceTransportOutcome::Blocked,
        TransportOutcome::RateLimited => EvidenceTransportOutcome::RateLimited,
        TransportOutcome::Timeout => EvidenceTransportOutcome::Timeout,
        TransportOutcome::Dns => EvidenceTransportOutcome::Dns,
        TransportOutcome::Connect => EvidenceTransportOutcome::Connect,
        TransportOutcome::Tls => EvidenceTransportOutcome::Tls,
        TransportOutcome::RedirectRejected => EvidenceTransportOutcome::RedirectRejected,
        TransportOutcome::ResponseTooLarge => EvidenceTransportOutcome::ResponseTooLarge,
        TransportOutcome::Decode => EvidenceTransportOutcome::Decode,
    }
}

const fn evidence_capsule_profile_name(value: EvidenceCapsuleProfile) -> &'static str {
    match value {
        EvidenceCapsuleProfile::PrivateHistory => "private_history",
        EvidenceCapsuleProfile::SharedObservation => "shared_observation",
        EvidenceCapsuleProfile::SharedResearch => "shared_research",
    }
}

fn result_event(
    result: &SearchResult,
    outcome: RecordedOutcome,
    observation_id: Uuid,
    claim: &JobClaim,
    consumer: &LiveSearchConsumer,
    observed_at_unix_ms: i64,
    expires_at_unix_ms: i64,
) -> Result<SearchEvent, JobError> {
    let target = Target {
        username: Username::new(result.username.clone()).map_err(|_| JobError::InvalidProtocol)?,
        site_id: SiteId::new(result.site_id.clone()).map_err(|_| JobError::InvalidProtocol)?,
    };
    let freshness = Freshness::new(
        observed_at_unix_ms,
        expires_at_unix_ms,
        observed_at_unix_ms,
        consumer.maximum_age_ms,
    )
    .map_err(|_| JobError::InvalidProtocol)?;
    let observation_id =
        ObservationId::new(observation_id.to_string()).map_err(|_| JobError::InvalidProtocol)?;
    let evidence_class = protocol_evidence_class(result.classification.evidence_class);
    let evidence_digest = EvidenceDigest::new(result.classification.evidence_digest.clone())
        .map_err(|_| JobError::InvalidProtocol)?;
    let region_class =
        RegionClass::new(claim.region_class.clone()).map_err(|_| JobError::InvalidProtocol)?;
    let rule_hash =
        RuleHash::new(claim.rule_hash.clone()).map_err(|_| JobError::InvalidProtocol)?;
    let data = match outcome {
        RecordedOutcome::Definitive(verdict) => SearchEventData::DefinitiveResult {
            result: DefinitiveResult {
                observation_id,
                target,
                verdict,
                source: ResultSource::ManagedProbe,
                freshness,
                evidence_class,
                evidence_digest,
                region_class,
                rule_hash,
                rule_health: RuleHealthStatus::Healthy,
                profile_url: result
                    .profile_url
                    .as_ref()
                    .map(|url| HttpsUrl::new(url.clone()))
                    .transpose()
                    .map_err(|_| JobError::InvalidProtocol)?,
            },
        },
        RecordedOutcome::Uncertain(reason) => SearchEventData::UncertainResult {
            result: UncertainResult {
                observation_id,
                target,
                reason,
                source: ResultSource::ManagedProbe,
                freshness,
                evidence_class,
                evidence_digest,
                region_class,
                rule_hash,
                rule_health: RuleHealthStatus::Healthy,
            },
        },
    };
    new_search_event(consumer.search_id, observed_at_unix_ms, data)
}

fn operational_failure_event(
    claim: &JobClaim,
    consumer: &LiveSearchConsumer,
    kind: OperationalFailureKind,
    retryable: bool,
    occurred_at_unix_ms: i64,
) -> Result<SearchEvent, JobError> {
    new_search_event(
        consumer.search_id,
        occurred_at_unix_ms,
        SearchEventData::OperationalFailure {
            failure: OperationalFailure {
                target: Target {
                    username: Username::new(claim.normalized_username.clone())
                        .map_err(|_| JobError::InvalidProtocol)?,
                    site_id: SiteId::new(claim.site_id.clone())
                        .map_err(|_| JobError::InvalidProtocol)?,
                },
                kind,
                source: ResultSource::ManagedProbe,
                occurred_at_unix_ms,
                retryable,
                region_class: Some(
                    RegionClass::new(claim.region_class.clone())
                        .map_err(|_| JobError::InvalidProtocol)?,
                ),
                rule_hash: Some(
                    RuleHash::new(claim.rule_hash.clone())
                        .map_err(|_| JobError::InvalidProtocol)?,
                ),
            },
        },
    )
}

fn new_search_event(
    search_id: Uuid,
    emitted_at_unix_ms: i64,
    data: SearchEventData,
) -> Result<SearchEvent, JobError> {
    Ok(SearchEvent {
        schema: ProtocolVersion::ApiV1,
        event_id: EventId::new(Uuid::new_v4().to_string())
            .map_err(|_| JobError::InvalidProtocol)?,
        search_id: SearchId::new(search_id.to_string()).map_err(|_| JobError::InvalidProtocol)?,
        sequence: 1,
        emitted_at_unix_ms,
        data,
    })
}

async fn insert_search_result(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    consumer: &LiveSearchConsumer,
    event: &SearchEvent,
    target_state: &str,
) -> Result<(), JobError> {
    let mut event = event.clone();
    event.sequence = next_sequence(transaction, tenant_id, consumer.search_id).await?;
    insert_event(
        transaction,
        tenant_id,
        consumer.search_id,
        Some(consumer.search_target_id),
        &event,
    )
    .await?;
    let affected = sqlx::query(
        "UPDATE search_targets \
         SET state = $4, completed_at = clock_timestamp() \
         WHERE tenant_id = $1 AND id = $2 AND search_id = $3 \
           AND state IN ('pending', 'running')",
    )
    .bind(tenant_id)
    .bind(consumer.search_target_id)
    .bind(consumer.search_id)
    .bind(target_state)
    .execute(&mut **transaction)
    .await
    .map_err(|_| JobError::StorageInvariant)?
    .rows_affected();
    if affected != 1 {
        return Err(JobError::StorageInvariant);
    }
    sqlx::query(
        "UPDATE searches SET updated_at = clock_timestamp() \
         WHERE tenant_id = $1 AND id = $2 AND state IN ('accepted', 'running')",
    )
    .bind(tenant_id)
    .bind(consumer.search_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| JobError::StorageInvariant)?;
    Ok(())
}

async fn finish_search_if_complete(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    search_id: Uuid,
) -> Result<(), JobError> {
    let state: String = sqlx::query_scalar(
        "SELECT state FROM searches \
         WHERE tenant_id = $1 AND id = $2 \
         FOR UPDATE",
    )
    .bind(tenant_id)
    .bind(search_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| JobError::StorageInvariant)?;
    if !matches!(state.as_str(), "accepted" | "running") {
        return Ok(());
    }
    let incomplete: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM search_targets \
         WHERE tenant_id = $1 AND search_id = $2 \
           AND state IN ('pending', 'running')",
    )
    .bind(tenant_id)
    .bind(search_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| JobError::StorageInvariant)?;
    if incomplete != 0 {
        return Ok(());
    }
    let counts: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT \
            (SELECT count(*) FROM search_targets \
             WHERE tenant_id = $1 AND search_id = $2), \
            count(*) FILTER (WHERE event_type = 'definitive_result'), \
            count(*) FILTER (WHERE event_type = 'uncertain_result'), \
            count(*) FILTER (WHERE event_type = 'operational_failure') \
         FROM search_events WHERE tenant_id = $1 AND search_id = $2",
    )
    .bind(tenant_id)
    .bind(search_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| JobError::StorageInvariant)?;
    let total_targets = u32::try_from(counts.0).map_err(|_| JobError::StorageInvariant)?;
    let definitive_results = u32::try_from(counts.1).map_err(|_| JobError::StorageInvariant)?;
    let uncertain_results = u32::try_from(counts.2).map_err(|_| JobError::StorageInvariant)?;
    let operational_failures = u32::try_from(counts.3).map_err(|_| JobError::StorageInvariant)?;
    let completed_targets = definitive_results
        .checked_add(uncertain_results)
        .and_then(|count| count.checked_add(operational_failures))
        .ok_or(JobError::StorageInvariant)?;
    let progress = SearchProgress {
        total_targets,
        completed_targets,
        definitive_results,
        uncertain_results,
        operational_failures,
    };
    progress
        .validate()
        .map_err(|_| JobError::StorageInvariant)?;
    if completed_targets != total_targets {
        return Err(JobError::StorageInvariant);
    }
    let emitted_at_unix_ms = database_now_ms(transaction).await?;
    let mut event = new_search_event(
        search_id,
        emitted_at_unix_ms,
        SearchEventData::Finished {
            state: SearchTerminalState::Completed,
            progress,
        },
    )?;
    event.sequence = next_sequence(transaction, tenant_id, search_id).await?;
    insert_event(transaction, tenant_id, search_id, None, &event).await?;
    sqlx::query(
        "UPDATE searches \
         SET state = 'completed', updated_at = clock_timestamp(), \
             completed_at = clock_timestamp() \
         WHERE tenant_id = $1 AND id = $2 AND state IN ('accepted', 'running')",
    )
    .bind(tenant_id)
    .bind(search_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| JobError::StorageInvariant)?;
    Ok(())
}

async fn next_sequence(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    search_id: Uuid,
) -> Result<u64, JobError> {
    let sequence: i64 = sqlx::query_scalar(
        "SELECT COALESCE(max(sequence), 0) + 1 \
         FROM search_events WHERE tenant_id = $1 AND search_id = $2",
    )
    .bind(tenant_id)
    .bind(search_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| JobError::StorageInvariant)?;
    u64::try_from(sequence).map_err(|_| JobError::StorageInvariant)
}

async fn insert_event(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    search_id: Uuid,
    search_target_id: Option<Uuid>,
    event: &SearchEvent,
) -> Result<(), JobError> {
    event.validate().map_err(|_| JobError::InvalidProtocol)?;
    let event_id = event_uuid(event)?;
    let event_type = event_type(&event.data);
    let payload = serde_json::to_string(event).map_err(|_| JobError::InvalidProtocol)?;
    sqlx::query(
        "INSERT INTO search_events (\
            id, tenant_id, search_id, search_target_id, sequence, event_type, \
            payload, emitted_at, created_at\
         ) VALUES (\
            $1, $2, $3, $4, $5, $6, $7::jsonb, \
            to_timestamp($8::double precision / 1000.0), clock_timestamp()\
         )",
    )
    .bind(event_id)
    .bind(tenant_id)
    .bind(search_id)
    .bind(search_target_id)
    .bind(i64::try_from(event.sequence).map_err(|_| JobError::InvalidProtocol)?)
    .bind(event_type)
    .bind(payload)
    .bind(event.emitted_at_unix_ms)
    .execute(&mut **transaction)
    .await
    .map_err(|_| JobError::StorageInvariant)?;
    Ok(())
}

fn event_uuid(event: &SearchEvent) -> Result<Uuid, JobError> {
    Uuid::parse_str(event.event_id.as_str()).map_err(|_| JobError::InvalidProtocol)
}

const fn event_type(data: &SearchEventData) -> &'static str {
    match data {
        SearchEventData::Started { .. } => "started",
        SearchEventData::DefinitiveResult { .. } => "definitive_result",
        SearchEventData::UncertainResult { .. } => "uncertain_result",
        SearchEventData::OperationalFailure { .. } => "operational_failure",
        SearchEventData::AssertionUpdated { .. } => "assertion_updated",
        SearchEventData::Finished { .. } => "finished",
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

const fn failure_kind_name(kind: OperationalFailureKind) -> &'static str {
    match kind {
        OperationalFailureKind::InvalidTarget => "invalid_target",
        OperationalFailureKind::Blocked => "blocked",
        OperationalFailureKind::RateLimited => "rate_limited",
        OperationalFailureKind::Timeout => "timeout",
        OperationalFailureKind::Dns => "dns",
        OperationalFailureKind::Connect => "connect",
        OperationalFailureKind::Tls => "tls",
        OperationalFailureKind::RedirectRejected => "redirect_rejected",
        OperationalFailureKind::ResponseTooLarge => "response_too_large",
        OperationalFailureKind::Decode => "decode",
        OperationalFailureKind::RuleUnavailable => "rule_unavailable",
        OperationalFailureKind::CapacityUnavailable => "capacity_unavailable",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> RuleBinding {
        RuleBinding {
            rule_version_id: Uuid::from_u128(2),
            site_id: "managed-test".to_owned(),
            rule_hash: "11".repeat(32),
            rule_pack_hash: "22".repeat(32),
            engine_hash: "55".repeat(32),
            region_class: "jp".to_owned(),
            metadata_id: "33".repeat(32),
            metadata_sequence: 1,
            promotion_id: "44".repeat(32),
            promotion_sequence: 1,
        }
    }

    #[test]
    fn work_scope_hash_is_framed_and_consent_isolated() {
        let binding = binding();
        let tenant = Uuid::from_u128(1);
        let first = work_key_hash(tenant, "target", &binding, Uuid::from_u128(3), "private");
        assert_eq!(
            first,
            work_key_hash(tenant, "target", &binding, Uuid::from_u128(3), "private")
        );
        assert_ne!(
            first,
            work_key_hash(tenant, "target", &binding, Uuid::from_u128(4), "private")
        );
        assert_ne!(
            first,
            work_key_hash(tenant, "target", &binding, Uuid::from_u128(3), "shared")
        );
    }

    #[test]
    fn retry_backoff_is_bounded_and_worker_labels_are_closed() {
        assert_eq!(retry_delay_ms(1), 5_000);
        assert_eq!(retry_delay_ms(2), 10_000);
        assert_eq!(retry_delay_ms(10), 300_000);
        assert_eq!(retry_delay_ms(u32::MAX), 300_000);
        assert!(valid_label("worker-jp-1"));
        assert!(!valid_label(""));
        assert!(!valid_label("-worker"));
        assert!(!valid_label("worker-"));
        assert!(!valid_label("Worker"));
    }

    #[test]
    fn evidence_retention_is_consumer_specific_and_bounded() {
        let watch = LiveWatchConsumer {
            watch_run_target_id: Uuid::from_u128(10),
            watch_run_id: Uuid::from_u128(11),
            watch_target_id: Uuid::from_u128(12),
            retention_days: 30,
        };
        assert_eq!(
            evidence_retention_policy("private", true, &[]).unwrap(),
            (
                EvidenceCapsuleProfile::PrivateHistory,
                PRIVATE_INTERACTIVE_RETENTION_DAYS,
            )
        );
        assert_eq!(
            evidence_retention_policy("private", false, std::slice::from_ref(&watch)).unwrap(),
            (EvidenceCapsuleProfile::PrivateHistory, 30)
        );
        assert_eq!(
            evidence_retention_policy("private", true, std::slice::from_ref(&watch)).unwrap(),
            (
                EvidenceCapsuleProfile::PrivateHistory,
                PRIVATE_INTERACTIVE_RETENTION_DAYS,
            )
        );
        assert_eq!(
            evidence_retention_policy("shared", true, &[]).unwrap(),
            (
                EvidenceCapsuleProfile::SharedObservation,
                SHARED_CAPSULE_RETENTION_DAYS,
            )
        );
        assert!(evidence_retention_policy("shared", true, &[watch]).is_err());
        assert!(evidence_retention_policy("private", false, &[]).is_err());
    }

    #[test]
    fn evidence_transport_metrics_are_coarsened_and_sanitized() {
        assert_eq!(latency_bucket_ms(0), 0);
        assert_eq!(latency_bucket_ms(1), 10);
        assert_eq!(latency_bucket_ms(26), 50);
        assert_eq!(latency_bucket_ms(u64::MAX), 120_000);
        assert_eq!(
            sanitized_bounded_text("application/json\r\nsecret", 16, None),
            Some("application/json".to_owned())
        );
        assert_eq!(
            sanitized_bounded_text("\r\n", 16, Some("redacted")),
            Some("redacted".to_owned())
        );
    }

    #[test]
    fn watch_jitter_is_deterministic_and_bounded_per_scheduled_run() {
        let watch_id = Uuid::from_u128(7);
        let delay = watch_schedule_delay_ms(watch_id, 3, 1_000_000, 300, 20).unwrap();
        assert_eq!(
            delay,
            watch_schedule_delay_ms(watch_id, 3, 1_000_000, 300, 20).unwrap()
        );
        assert!((240_000..=360_000).contains(&delay));
        assert_eq!(
            watch_schedule_delay_ms(watch_id, 3, 1_000_000, 300, 0).unwrap(),
            300_000
        );
        assert!(watch_schedule_delay_ms(watch_id, 0, 1_000_000, 300, 20).is_err());
    }

    #[test]
    fn claim_debug_omits_target_and_consent_scope() {
        let private_target = "private-target-that-must-not-appear";
        let claim = JobClaim {
            tenant_id: Uuid::from_u128(1),
            job_id: Uuid::from_u128(2),
            normalized_username: private_target.to_owned(),
            site_id: "managed-test".to_owned(),
            rule_version_id: Uuid::from_u128(3),
            rule_hash: "11".repeat(32),
            rule_pack_hash: "22".repeat(32),
            engine_hash: "55".repeat(32),
            region_class: "jp".to_owned(),
            metadata_id: "33".repeat(32),
            promotion_id: "44".repeat(32),
            consent_grant_id: Uuid::from_u128(4),
            visibility: "private".to_owned(),
            attempt_count: 1,
            lease_owner: "worker-jp-1".to_owned(),
        };
        let debug = format!("{claim:?}");
        assert!(!debug.contains(private_target));
        assert!(!debug.contains(&claim.consent_grant_id.to_string()));
        assert!(!debug.contains(&claim.tenant_id.to_string()));
    }
}
