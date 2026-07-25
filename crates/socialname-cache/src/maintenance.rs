use crate::{CacheError, LocalCache};

const TOTALS_QUERY: &str = "
    SELECT
        COUNT(*) AS observation_count,
        COALESCE(SUM(
            length(CAST(o.observation_id AS BLOB))
            + length(CAST(o.site_id AS BLOB))
            + length(CAST(o.normalized_username AS BLOB))
            + length(CAST(o.verdict AS BLOB))
            + length(CAST(COALESCE(o.inconclusive_reason, '') AS BLOB))
            + length(CAST(o.evidence_class AS BLOB))
            + length(CAST(o.region_class AS BLOB))
            + length(CAST(o.network_group AS BLOB))
            + length(CAST(o.independence_group AS BLOB))
            + length(CAST(o.producer_kind AS BLOB))
            + length(CAST(o.producer_reputation AS BLOB))
            + length(CAST(o.collection_profile AS BLOB))
            + length(CAST(o.rule_hash AS BLOB))
            + length(CAST(o.evidence_digest AS BLOB))
            + 56
        ), 0) AS payload_bytes
    FROM local_observations AS o
    INNER JOIN observation_cache_metadata AS m
        ON m.observation_id = o.observation_id
";

const CAPACITY_DELETE: &str = "
    WITH ordered AS (
        SELECT
            o.observation_id,
            ROW_NUMBER() OVER (
                ORDER BY
                    m.last_accessed_at_unix_ms ASC,
                    o.observed_at_unix_ms ASC,
                    o.observation_id ASC
            ) AS row_number,
            COALESCE(SUM(
                length(CAST(o.observation_id AS BLOB))
                + length(CAST(o.site_id AS BLOB))
                + length(CAST(o.normalized_username AS BLOB))
                + length(CAST(o.verdict AS BLOB))
                + length(CAST(COALESCE(o.inconclusive_reason, '') AS BLOB))
                + length(CAST(o.evidence_class AS BLOB))
                + length(CAST(o.region_class AS BLOB))
                + length(CAST(o.network_group AS BLOB))
                + length(CAST(o.independence_group AS BLOB))
                + length(CAST(o.producer_kind AS BLOB))
                + length(CAST(o.producer_reputation AS BLOB))
                + length(CAST(o.collection_profile AS BLOB))
                + length(CAST(o.rule_hash AS BLOB))
                + length(CAST(o.evidence_digest AS BLOB))
                + 56
            ) OVER (
                ORDER BY
                    m.last_accessed_at_unix_ms ASC,
                    o.observed_at_unix_ms ASC,
                    o.observation_id ASC
                ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING
            ), 0) AS payload_bytes_before
        FROM local_observations AS o
        INNER JOIN observation_cache_metadata AS m
            ON m.observation_id = o.observation_id
    )
    DELETE FROM local_observations
    WHERE observation_id IN (
        SELECT observation_id
        FROM ordered
        WHERE row_number <= ? OR payload_bytes_before < ?
    )
";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheMaintenancePolicy {
    pub now_unix_ms: i64,
    pub maximum_observations: u64,
    pub maximum_payload_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheMaintenanceReport {
    pub observations_before: u64,
    pub payload_bytes_before: u64,
    pub expired_observations_deleted: u64,
    pub capacity_observations_deleted: u64,
    pub observations_after: u64,
    pub payload_bytes_after: u64,
}

#[derive(Debug, sqlx::FromRow)]
struct CacheTotals {
    observation_count: i64,
    payload_bytes: i64,
}

impl LocalCache {
    pub async fn maintain(
        &self,
        policy: CacheMaintenancePolicy,
    ) -> Result<CacheMaintenanceReport, CacheError> {
        let maximum_observations =
            validate_limit(policy.maximum_observations, "maximum_observations")?;
        let maximum_payload_bytes =
            validate_limit(policy.maximum_payload_bytes, "maximum_payload_bytes")?;
        self.check_integrity().await?;

        let mut transaction = self.pool.begin().await?;
        let before = totals(&mut transaction).await?;
        let expired_observations_deleted =
            sqlx::query("DELETE FROM local_observations WHERE expires_at_unix_ms <= ?")
                .bind(policy.now_unix_ms)
                .execute(&mut *transaction)
                .await?
                .rows_affected();
        let after_expiry = totals(&mut transaction).await?;
        let observations_to_delete = (after_expiry.observation_count - maximum_observations).max(0);
        let payload_bytes_to_delete = (after_expiry.payload_bytes - maximum_payload_bytes).max(0);
        let capacity_observations_deleted =
            if observations_to_delete > 0 || payload_bytes_to_delete > 0 {
                sqlx::query(CAPACITY_DELETE)
                    .bind(observations_to_delete)
                    .bind(payload_bytes_to_delete)
                    .execute(&mut *transaction)
                    .await?
                    .rows_affected()
            } else {
                0
            };
        let after = totals(&mut transaction).await?;
        if after.observation_count > maximum_observations
            || after.payload_bytes > maximum_payload_bytes
        {
            transaction.rollback().await?;
            return Err(CacheError::MaintenanceLimitNotReached);
        }
        transaction.commit().await?;

        Ok(CacheMaintenanceReport {
            observations_before: nonnegative(before.observation_count, "observation_count")?,
            payload_bytes_before: nonnegative(before.payload_bytes, "payload_bytes")?,
            expired_observations_deleted,
            capacity_observations_deleted,
            observations_after: nonnegative(after.observation_count, "observation_count")?,
            payload_bytes_after: nonnegative(after.payload_bytes, "payload_bytes")?,
        })
    }
}

async fn totals(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> Result<CacheTotals, CacheError> {
    sqlx::query_as::<_, CacheTotals>(TOTALS_QUERY)
        .fetch_one(&mut **transaction)
        .await
        .map_err(CacheError::Database)
}

fn validate_limit(value: u64, field: &'static str) -> Result<i64, CacheError> {
    if value == 0 {
        return Err(CacheError::InvalidMaintenancePolicy { field });
    }
    i64::try_from(value).map_err(|_| CacheError::InvalidMaintenancePolicy { field })
}

fn nonnegative(value: i64, field: &'static str) -> Result<u64, CacheError> {
    u64::try_from(value).map_err(|_| CacheError::InvalidStoredObservation { field })
}

#[cfg(test)]
mod tests {
    use socialname_domain::{
        CollectionProfile, EvidenceClass, Observation, ObservationId, ProducerKind,
        ProducerReputation, SiteId, TargetKey, Verdict,
    };

    use super::*;
    use crate::{CacheEligibilityQuery, CacheVerdictPolicy};

    fn observation(id: &str, observed_at: i64, expires_at: i64) -> Observation {
        Observation {
            id: ObservationId::new(id),
            target: TargetKey {
                site_id: SiteId::new("example"),
                normalized_username: "private-target".to_owned(),
            },
            verdict: Verdict::Found,
            inconclusive_reason: None,
            evidence_class: EvidenceClass::E4StructuredIdentity,
            observed_at_unix_ms: observed_at,
            expires_at_unix_ms: expires_at,
            region: "local".to_owned(),
            network_group: "local-network".to_owned(),
            independence_group: format!("installation-{id}"),
            producer_kind: ProducerKind::LocalCli,
            producer_reputation: ProducerReputation::New,
            collection_profile: CollectionProfile::LocalOnly,
            rule_hash: "1".repeat(64),
            rule_health_green: true,
            evidence_digest: "2".repeat(64),
        }
    }

    fn roomy_policy(now_unix_ms: i64) -> CacheMaintenancePolicy {
        CacheMaintenancePolicy {
            now_unix_ms,
            maximum_observations: 1_000,
            maximum_payload_bytes: 1_000_000,
        }
    }

    #[tokio::test]
    async fn expired_observations_are_deleted_before_capacity_pruning() {
        let cache = LocalCache::open_in_memory().await.unwrap();
        let expired = observation("expired", 1_000, 1_100);
        let current = observation("current", 1_050, 2_000);
        cache.store_observation(&expired, 1_051).await.unwrap();
        cache.store_observation(&current, 1_051).await.unwrap();

        let report = cache.maintain(roomy_policy(1_100)).await.unwrap();
        assert_eq!(report.observations_before, 2);
        assert_eq!(report.expired_observations_deleted, 1);
        assert_eq!(report.capacity_observations_deleted, 0);
        assert_eq!(report.observations_after, 1);
        assert!(cache.get_observation(&expired.id).await.unwrap().is_none());
        assert!(cache.get_observation(&current.id).await.unwrap().is_some());
        let metadata_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM observation_cache_metadata")
                .fetch_one(&cache.pool)
                .await
                .unwrap();
        assert_eq!(metadata_count, 1);
    }

    #[tokio::test]
    async fn count_limit_prunes_least_recently_used_observation() {
        let cache = LocalCache::open_in_memory().await.unwrap();
        let first = observation("first", 1_000, 3_000);
        let second = observation("second", 1_100, 3_000);
        let third = observation("third", 1_200, 3_000);
        for item in [&first, &second, &third] {
            cache.store_observation(item, 1_201).await.unwrap();
        }
        cache
            .eligible_observations(&CacheEligibilityQuery {
                target: first.target.clone(),
                region_class: "local".to_owned(),
                rule_hash: "1".repeat(64),
                current_rule_health: socialname_domain::RuleHealth::Healthy,
                now_unix_ms: 1_300,
                maximum_age_ms: 500,
                verdict_policy: CacheVerdictPolicy::Exact(Verdict::Found),
            })
            .await
            .unwrap();
        // Give only the newest row a later access time so the oldest untouched
        // row is deterministic under the LRU/observation-time ordering.
        sqlx::query(
            "UPDATE observation_cache_metadata
             SET last_accessed_at_unix_ms = 1_201, access_count = 0
             WHERE observation_id IN ('first', 'second')",
        )
        .execute(&cache.pool)
        .await
        .unwrap();

        let report = cache
            .maintain(CacheMaintenancePolicy {
                maximum_observations: 2,
                ..roomy_policy(1_400)
            })
            .await
            .unwrap();
        assert_eq!(report.capacity_observations_deleted, 1);
        assert!(cache.get_observation(&first.id).await.unwrap().is_none());
        assert!(cache.get_observation(&second.id).await.unwrap().is_some());
        assert!(cache.get_observation(&third.id).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn payload_limit_is_hard_and_reported() {
        let cache = LocalCache::open_in_memory().await.unwrap();
        for index in 0..3 {
            cache
                .store_observation(
                    &observation(&format!("payload-{index}"), 1_000 + index, 3_000),
                    1_100,
                )
                .await
                .unwrap();
        }
        let report = cache
            .maintain(CacheMaintenancePolicy {
                now_unix_ms: 1_200,
                maximum_observations: 100,
                maximum_payload_bytes: 1,
            })
            .await
            .unwrap();
        assert!(report.payload_bytes_before > 1);
        assert_eq!(report.capacity_observations_deleted, 3);
        assert_eq!(report.observations_after, 0);
        assert_eq!(report.payload_bytes_after, 0);
    }

    #[tokio::test]
    async fn zero_or_unrepresentable_limits_are_rejected_without_deletion() {
        let cache = LocalCache::open_in_memory().await.unwrap();
        let expected = observation("preserved", 1_000, 3_000);
        cache.store_observation(&expected, 1_001).await.unwrap();
        for policy in [
            CacheMaintenancePolicy {
                maximum_observations: 0,
                ..roomy_policy(1_100)
            },
            CacheMaintenancePolicy {
                maximum_payload_bytes: u64::MAX,
                ..roomy_policy(1_100)
            },
        ] {
            assert!(matches!(
                cache.maintain(policy).await.unwrap_err(),
                CacheError::InvalidMaintenancePolicy { .. }
            ));
        }
        assert!(cache.get_observation(&expected.id).await.unwrap().is_some());
    }
}
