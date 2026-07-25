use socialname_domain::{
    CollectionProfile, EvidenceClass, InconclusiveReason, Observation, ObservationId, ProducerKind,
    ProducerReputation, SiteId, TargetKey, Verdict,
};

use crate::{CacheError, LocalCache};

const OBSERVATION_SELECT: &str = "
    SELECT
        o.observation_id,
        o.site_id,
        o.normalized_username,
        o.verdict,
        o.inconclusive_reason,
        o.evidence_class,
        o.observed_at_unix_ms,
        o.expires_at_unix_ms,
        o.region_class,
        o.network_group,
        o.independence_group,
        o.producer_kind,
        o.producer_reputation,
        o.collection_profile,
        o.rule_hash,
        o.rule_health_green,
        o.evidence_digest,
        m.cached_at_unix_ms,
        m.last_accessed_at_unix_ms,
        m.access_count
    FROM local_observations AS o
    LEFT JOIN observation_cache_metadata AS m
        ON m.observation_id = o.observation_id
    WHERE o.observation_id = ?
";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheMetadata {
    pub cached_at_unix_ms: i64,
    pub last_accessed_at_unix_ms: i64,
    pub access_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachedObservation {
    pub observation: Observation,
    pub metadata: CacheMetadata,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreOutcome {
    Inserted,
    AlreadyPresent,
}

#[derive(Debug, sqlx::FromRow)]
struct StoredObservationRow {
    observation_id: String,
    site_id: String,
    normalized_username: String,
    verdict: String,
    inconclusive_reason: Option<String>,
    evidence_class: String,
    observed_at_unix_ms: i64,
    expires_at_unix_ms: i64,
    region_class: String,
    network_group: String,
    independence_group: String,
    producer_kind: String,
    producer_reputation: String,
    collection_profile: String,
    rule_hash: String,
    rule_health_green: bool,
    evidence_digest: String,
    cached_at_unix_ms: Option<i64>,
    last_accessed_at_unix_ms: Option<i64>,
    access_count: Option<i64>,
}

impl LocalCache {
    pub async fn store_observation(
        &self,
        observation: &Observation,
        cached_at_unix_ms: i64,
    ) -> Result<StoreOutcome, CacheError> {
        validate_observation(observation, cached_at_unix_ms)?;

        let mut transaction = self.pool.begin().await?;
        let inserted = sqlx::query(
            "INSERT INTO local_observations (
                observation_id, site_id, normalized_username, verdict,
                inconclusive_reason, evidence_class, observed_at_unix_ms,
                expires_at_unix_ms, region_class, network_group,
                independence_group, producer_kind, producer_reputation,
                collection_profile, rule_hash, rule_health_green,
                evidence_digest, inserted_at_unix_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(observation_id) DO NOTHING",
        )
        .bind(observation.id.as_str())
        .bind(observation.target.site_id.as_str())
        .bind(&observation.target.normalized_username)
        .bind(verdict_name(observation.verdict))
        .bind(
            observation
                .inconclusive_reason
                .map(inconclusive_reason_name),
        )
        .bind(evidence_class_name(observation.evidence_class))
        .bind(observation.observed_at_unix_ms)
        .bind(observation.expires_at_unix_ms)
        .bind(&observation.region)
        .bind(&observation.network_group)
        .bind(&observation.independence_group)
        .bind(producer_kind_name(observation.producer_kind))
        .bind(producer_reputation_name(observation.producer_reputation))
        .bind(collection_profile_name(observation.collection_profile))
        .bind(&observation.rule_hash)
        .bind(observation.rule_health_green)
        .bind(&observation.evidence_digest)
        .bind(cached_at_unix_ms)
        .execute(&mut *transaction)
        .await?
        .rows_affected();

        if inserted == 0 {
            let existing = sqlx::query_as::<_, StoredObservationRow>(OBSERVATION_SELECT)
                .bind(observation.id.as_str())
                .fetch_optional(&mut *transaction)
                .await?
                .ok_or(CacheError::InvalidStoredObservation {
                    field: "observation_cache_metadata",
                })?
                .into_cached()?;
            if existing.observation == *observation {
                transaction.commit().await?;
                return Ok(StoreOutcome::AlreadyPresent);
            }
            transaction.rollback().await?;
            return Err(CacheError::ObservationConflict);
        }

        sqlx::query(
            "INSERT INTO observation_cache_metadata (
                observation_id, cached_at_unix_ms, last_accessed_at_unix_ms,
                access_count
            ) VALUES (?, ?, ?, 0)",
        )
        .bind(observation.id.as_str())
        .bind(cached_at_unix_ms)
        .bind(cached_at_unix_ms)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(StoreOutcome::Inserted)
    }

    pub async fn get_observation(
        &self,
        observation_id: &ObservationId,
    ) -> Result<Option<CachedObservation>, CacheError> {
        sqlx::query_as::<_, StoredObservationRow>(OBSERVATION_SELECT)
            .bind(observation_id.as_str())
            .fetch_optional(&self.pool)
            .await?
            .map(StoredObservationRow::into_cached)
            .transpose()
    }
}

impl StoredObservationRow {
    fn into_cached(self) -> Result<CachedObservation, CacheError> {
        let cached_at_unix_ms =
            self.cached_at_unix_ms
                .ok_or(CacheError::InvalidStoredObservation {
                    field: "observation_cache_metadata",
                })?;
        let last_accessed_at_unix_ms =
            self.last_accessed_at_unix_ms
                .ok_or(CacheError::InvalidStoredObservation {
                    field: "observation_cache_metadata",
                })?;
        let access_count = u64::try_from(self.access_count.ok_or(
            CacheError::InvalidStoredObservation {
                field: "observation_cache_metadata",
            },
        )?)
        .map_err(|_| CacheError::InvalidStoredObservation {
            field: "access_count",
        })?;
        Ok(CachedObservation {
            observation: Observation {
                id: ObservationId::new(self.observation_id),
                target: TargetKey {
                    site_id: SiteId::new(self.site_id),
                    normalized_username: self.normalized_username,
                },
                verdict: parse_verdict(&self.verdict)?,
                inconclusive_reason: self
                    .inconclusive_reason
                    .as_deref()
                    .map(parse_inconclusive_reason)
                    .transpose()?,
                evidence_class: parse_evidence_class(&self.evidence_class)?,
                observed_at_unix_ms: self.observed_at_unix_ms,
                expires_at_unix_ms: self.expires_at_unix_ms,
                region: self.region_class,
                network_group: self.network_group,
                independence_group: self.independence_group,
                producer_kind: parse_producer_kind(&self.producer_kind)?,
                producer_reputation: parse_producer_reputation(&self.producer_reputation)?,
                collection_profile: parse_collection_profile(&self.collection_profile)?,
                rule_hash: self.rule_hash,
                rule_health_green: self.rule_health_green,
                evidence_digest: self.evidence_digest,
            },
            metadata: CacheMetadata {
                cached_at_unix_ms,
                last_accessed_at_unix_ms,
                access_count,
            },
        })
    }
}

fn validate_observation(
    observation: &Observation,
    cached_at_unix_ms: i64,
) -> Result<(), CacheError> {
    validate_length(observation.id.as_str(), 1, 128, "observation_id")?;
    validate_length(observation.target.site_id.as_str(), 1, 64, "site_id")?;
    validate_length(
        &observation.target.normalized_username,
        1,
        1_024,
        "normalized_username",
    )?;
    validate_length(&observation.region, 1, 64, "region")?;
    validate_length(&observation.network_group, 1, 128, "network_group")?;
    validate_length(
        &observation.independence_group,
        1,
        128,
        "independence_group",
    )?;
    validate_digest(&observation.rule_hash, "rule_hash")?;
    validate_digest(&observation.evidence_digest, "evidence_digest")?;
    if observation.expires_at_unix_ms <= observation.observed_at_unix_ms {
        return Err(CacheError::InvalidObservation {
            field: "expires_at_unix_ms",
        });
    }
    if cached_at_unix_ms < observation.observed_at_unix_ms {
        return Err(CacheError::InvalidObservation {
            field: "cached_at_unix_ms",
        });
    }
    let reason_is_valid = match observation.verdict {
        Verdict::Inconclusive => observation.inconclusive_reason.is_some(),
        Verdict::Found | Verdict::NotFound | Verdict::InvalidUsername => {
            observation.inconclusive_reason.is_none()
        }
    };
    if !reason_is_valid {
        return Err(CacheError::InvalidObservation {
            field: "inconclusive_reason",
        });
    }
    Ok(())
}

fn validate_length(
    value: &str,
    minimum: usize,
    maximum: usize,
    field: &'static str,
) -> Result<(), CacheError> {
    let length = value.chars().count();
    if !(minimum..=maximum).contains(&length) {
        return Err(CacheError::InvalidObservation { field });
    }
    Ok(())
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), CacheError> {
    if value.len() != 64
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(CacheError::InvalidObservation { field });
    }
    Ok(())
}

const fn verdict_name(value: Verdict) -> &'static str {
    match value {
        Verdict::Found => "found",
        Verdict::NotFound => "not_found",
        Verdict::InvalidUsername => "invalid_username",
        Verdict::Inconclusive => "inconclusive",
    }
}

fn parse_verdict(value: &str) -> Result<Verdict, CacheError> {
    match value {
        "found" => Ok(Verdict::Found),
        "not_found" => Ok(Verdict::NotFound),
        "invalid_username" => Ok(Verdict::InvalidUsername),
        "inconclusive" => Ok(Verdict::Inconclusive),
        _ => Err(CacheError::InvalidStoredObservation { field: "verdict" }),
    }
}

const fn inconclusive_reason_name(value: InconclusiveReason) -> &'static str {
    match value {
        InconclusiveReason::Blocked => "blocked",
        InconclusiveReason::RateLimited => "rate_limited",
        InconclusiveReason::Timeout => "timeout",
        InconclusiveReason::Dns => "dns",
        InconclusiveReason::Connect => "connect",
        InconclusiveReason::Tls => "tls",
        InconclusiveReason::RedirectRejected => "redirect_rejected",
        InconclusiveReason::ResponseTooLarge => "response_too_large",
        InconclusiveReason::Decode => "decode",
        InconclusiveReason::SiteChanged => "site_changed",
        InconclusiveReason::NoRuleMatched => "no_rule_matched",
        InconclusiveReason::ConflictingEvidence => "conflicting_evidence",
    }
}

fn parse_inconclusive_reason(value: &str) -> Result<InconclusiveReason, CacheError> {
    match value {
        "blocked" => Ok(InconclusiveReason::Blocked),
        "rate_limited" => Ok(InconclusiveReason::RateLimited),
        "timeout" => Ok(InconclusiveReason::Timeout),
        "dns" => Ok(InconclusiveReason::Dns),
        "connect" => Ok(InconclusiveReason::Connect),
        "tls" => Ok(InconclusiveReason::Tls),
        "redirect_rejected" => Ok(InconclusiveReason::RedirectRejected),
        "response_too_large" => Ok(InconclusiveReason::ResponseTooLarge),
        "decode" => Ok(InconclusiveReason::Decode),
        "site_changed" => Ok(InconclusiveReason::SiteChanged),
        "no_rule_matched" => Ok(InconclusiveReason::NoRuleMatched),
        "conflicting_evidence" => Ok(InconclusiveReason::ConflictingEvidence),
        _ => Err(CacheError::InvalidStoredObservation {
            field: "inconclusive_reason",
        }),
    }
}

const fn evidence_class_name(value: EvidenceClass) -> &'static str {
    match value {
        EvidenceClass::E0NoAccountEvidence => "e0_no_account_evidence",
        EvidenceClass::E1WeakSignal => "e1_weak_signal",
        EvidenceClass::E2DifferentialTemplate => "e2_differential_template",
        EvidenceClass::E3ExplicitEndpoint => "e3_explicit_endpoint",
        EvidenceClass::E4StructuredIdentity => "e4_structured_identity",
    }
}

fn parse_evidence_class(value: &str) -> Result<EvidenceClass, CacheError> {
    match value {
        "e0_no_account_evidence" => Ok(EvidenceClass::E0NoAccountEvidence),
        "e1_weak_signal" => Ok(EvidenceClass::E1WeakSignal),
        "e2_differential_template" => Ok(EvidenceClass::E2DifferentialTemplate),
        "e3_explicit_endpoint" => Ok(EvidenceClass::E3ExplicitEndpoint),
        "e4_structured_identity" => Ok(EvidenceClass::E4StructuredIdentity),
        _ => Err(CacheError::InvalidStoredObservation {
            field: "evidence_class",
        }),
    }
}

const fn producer_kind_name(value: ProducerKind) -> &'static str {
    match value {
        ProducerKind::LocalCli => "local_cli",
        ProducerKind::SharedCli => "shared_cli",
        ProducerKind::ManagedWorker => "managed_worker",
        ProducerKind::CanaryWorker => "canary_worker",
    }
}

fn parse_producer_kind(value: &str) -> Result<ProducerKind, CacheError> {
    match value {
        "local_cli" => Ok(ProducerKind::LocalCli),
        "shared_cli" => Ok(ProducerKind::SharedCli),
        "managed_worker" => Ok(ProducerKind::ManagedWorker),
        "canary_worker" => Ok(ProducerKind::CanaryWorker),
        _ => Err(CacheError::InvalidStoredObservation {
            field: "producer_kind",
        }),
    }
}

const fn producer_reputation_name(value: ProducerReputation) -> &'static str {
    match value {
        ProducerReputation::New => "new",
        ProducerReputation::Calibrated => "calibrated",
        ProducerReputation::Trusted => "trusted",
        ProducerReputation::Suspended => "suspended",
    }
}

fn parse_producer_reputation(value: &str) -> Result<ProducerReputation, CacheError> {
    match value {
        "new" => Ok(ProducerReputation::New),
        "calibrated" => Ok(ProducerReputation::Calibrated),
        "trusted" => Ok(ProducerReputation::Trusted),
        "suspended" => Ok(ProducerReputation::Suspended),
        _ => Err(CacheError::InvalidStoredObservation {
            field: "producer_reputation",
        }),
    }
}

const fn collection_profile_name(value: CollectionProfile) -> &'static str {
    match value {
        CollectionProfile::LocalOnly => "local_only",
        CollectionProfile::PrivateHistory => "private_history",
        CollectionProfile::SharedObservation => "shared_observation",
        CollectionProfile::SharedResearch => "shared_research",
        CollectionProfile::Managed => "managed",
    }
}

fn parse_collection_profile(value: &str) -> Result<CollectionProfile, CacheError> {
    match value {
        "local_only" => Ok(CollectionProfile::LocalOnly),
        "private_history" => Ok(CollectionProfile::PrivateHistory),
        "shared_observation" => Ok(CollectionProfile::SharedObservation),
        "shared_research" => Ok(CollectionProfile::SharedResearch),
        "managed" => Ok(CollectionProfile::Managed),
        _ => Err(CacheError::InvalidStoredObservation {
            field: "collection_profile",
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(id: &str, verdict: Verdict) -> Observation {
        Observation {
            id: ObservationId::new(id),
            target: TargetKey {
                site_id: SiteId::new("example"),
                normalized_username: "private-target".to_owned(),
            },
            verdict,
            inconclusive_reason: (verdict == Verdict::Inconclusive)
                .then_some(InconclusiveReason::RateLimited),
            evidence_class: EvidenceClass::E4StructuredIdentity,
            observed_at_unix_ms: 1_000,
            expires_at_unix_ms: 2_000,
            region: "local".to_owned(),
            network_group: "local-network".to_owned(),
            independence_group: "local-installation".to_owned(),
            producer_kind: ProducerKind::LocalCli,
            producer_reputation: ProducerReputation::New,
            collection_profile: CollectionProfile::LocalOnly,
            rule_hash: "1".repeat(64),
            rule_health_green: true,
            evidence_digest: "2".repeat(64),
        }
    }

    #[tokio::test]
    async fn persists_and_reads_complete_observation_and_metadata() {
        let cache = LocalCache::open_in_memory().await.unwrap();
        let expected = observation("observation-round-trip", Verdict::Inconclusive);

        assert_eq!(
            cache.store_observation(&expected, 1_001).await.unwrap(),
            StoreOutcome::Inserted
        );
        let stored = cache.get_observation(&expected.id).await.unwrap().unwrap();
        assert_eq!(stored.observation, expected);
        assert_eq!(
            stored.metadata,
            CacheMetadata {
                cached_at_unix_ms: 1_001,
                last_accessed_at_unix_ms: 1_001,
                access_count: 0,
            }
        );
        assert!(
            cache
                .get_observation(&ObservationId::new("missing"))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn exact_replay_is_idempotent_but_changed_content_conflicts() {
        let cache = LocalCache::open_in_memory().await.unwrap();
        let expected = observation("observation-idempotent", Verdict::Found);
        assert_eq!(
            cache.store_observation(&expected, 1_001).await.unwrap(),
            StoreOutcome::Inserted
        );
        assert_eq!(
            cache.store_observation(&expected, 1_500).await.unwrap(),
            StoreOutcome::AlreadyPresent
        );

        let mut conflicting = expected.clone();
        conflicting.evidence_digest = "3".repeat(64);
        assert!(matches!(
            cache
                .store_observation(&conflicting, 1_500)
                .await
                .unwrap_err(),
            CacheError::ObservationConflict
        ));

        let stored = cache.get_observation(&expected.id).await.unwrap().unwrap();
        assert_eq!(stored.observation, expected);
        assert_eq!(stored.metadata.cached_at_unix_ms, 1_001);
    }

    #[tokio::test]
    async fn invalid_observation_is_rejected_without_a_partial_row() {
        let cache = LocalCache::open_in_memory().await.unwrap();
        let mut invalid = observation("observation-invalid", Verdict::Inconclusive);
        invalid.inconclusive_reason = None;

        assert!(matches!(
            cache.store_observation(&invalid, 1_001).await.unwrap_err(),
            CacheError::InvalidObservation {
                field: "inconclusive_reason"
            }
        ));
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM local_observations")
            .fetch_one(&cache.pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn metadata_failure_rolls_back_the_observation_insert() {
        let cache = LocalCache::open_in_memory().await.unwrap();
        sqlx::query("DROP TABLE observation_cache_metadata")
            .execute(&cache.pool)
            .await
            .unwrap();
        let expected = observation("observation-rollback", Verdict::NotFound);

        assert!(matches!(
            cache.store_observation(&expected, 1_001).await.unwrap_err(),
            CacheError::Database(_)
        ));
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM local_observations")
            .fetch_one(&cache.pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn missing_metadata_is_not_reported_as_a_cache_miss() {
        let cache = LocalCache::open_in_memory().await.unwrap();
        let expected = observation("observation-orphan", Verdict::Found);
        cache.store_observation(&expected, 1_001).await.unwrap();
        sqlx::query("DELETE FROM observation_cache_metadata WHERE observation_id = ?")
            .bind(expected.id.as_str())
            .execute(&cache.pool)
            .await
            .unwrap();

        assert!(matches!(
            cache.get_observation(&expected.id).await.unwrap_err(),
            CacheError::InvalidStoredObservation {
                field: "observation_cache_metadata"
            }
        ));
    }
}
