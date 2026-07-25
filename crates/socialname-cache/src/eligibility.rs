use socialname_domain::{RuleHealth, TargetKey, Verdict};

use crate::{CacheError, CachedObservation, LocalCache, observation_store::StoredObservationRow};

pub const MAX_ELIGIBLE_OBSERVATIONS: usize = 256;

const ELIGIBLE_OBSERVATIONS_SELECT: &str = "
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
    WHERE o.normalized_username = ?
      AND o.site_id = ?
      AND o.region_class = ?
      AND o.rule_hash = ?
      AND o.rule_health_green = TRUE
      AND o.observed_at_unix_ms <= ?
      AND o.observed_at_unix_ms >= ?
      AND o.expires_at_unix_ms > ?
      AND (
          (o.verdict = 'found' AND ?)
          OR (o.verdict = 'not_found' AND ?)
          OR (o.verdict = 'invalid_username' AND ?)
          OR (o.verdict = 'inconclusive' AND ?)
      )
    ORDER BY o.observed_at_unix_ms DESC, o.observation_id ASC
    LIMIT ?
";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheVerdictPolicy {
    Exact(Verdict),
    Definitive,
    AnyObservation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheEligibilityQuery {
    pub target: TargetKey,
    pub region_class: String,
    pub rule_hash: String,
    pub current_rule_health: RuleHealth,
    pub now_unix_ms: i64,
    pub maximum_age_ms: i64,
    pub verdict_policy: CacheVerdictPolicy,
}

impl LocalCache {
    pub async fn eligible_observations(
        &self,
        query: &CacheEligibilityQuery,
    ) -> Result<Vec<CachedObservation>, CacheError> {
        validate_query(query)?;
        if !query.current_rule_health.allows_definitive_assertions() {
            return Ok(Vec::new());
        }
        let minimum_observed_at_unix_ms = query
            .now_unix_ms
            .checked_sub(query.maximum_age_ms)
            .ok_or(CacheError::InvalidEligibilityQuery {
                field: "maximum_age_ms",
            })?;
        let (allow_found, allow_not_found, allow_invalid, allow_inconclusive) =
            query.verdict_policy.flags();

        let mut transaction = self.pool.begin().await?;
        let rows = sqlx::query_as::<_, StoredObservationRow>(ELIGIBLE_OBSERVATIONS_SELECT)
            .bind(&query.target.normalized_username)
            .bind(query.target.site_id.as_str())
            .bind(&query.region_class)
            .bind(&query.rule_hash)
            .bind(query.now_unix_ms)
            .bind(minimum_observed_at_unix_ms)
            .bind(query.now_unix_ms)
            .bind(allow_found)
            .bind(allow_not_found)
            .bind(allow_invalid)
            .bind(allow_inconclusive)
            .bind(i64::try_from(MAX_ELIGIBLE_OBSERVATIONS + 1).expect("bounded constant"))
            .fetch_all(&mut *transaction)
            .await?;

        if rows.len() > MAX_ELIGIBLE_OBSERVATIONS {
            transaction.rollback().await?;
            return Err(CacheError::TooManyEligibleObservations {
                maximum: MAX_ELIGIBLE_OBSERVATIONS,
            });
        }

        let mut observations = rows
            .into_iter()
            .map(StoredObservationRow::into_cached)
            .collect::<Result<Vec<_>, _>>()?;
        for cached in &observations {
            if cached.metadata.access_count >= i64::MAX as u64 {
                return Err(CacheError::AccessCountOverflow);
            }
        }
        for cached in &mut observations {
            let updated = sqlx::query(
                "UPDATE observation_cache_metadata
                 SET last_accessed_at_unix_ms = MAX(last_accessed_at_unix_ms, ?),
                     access_count = access_count + 1
                 WHERE observation_id = ? AND access_count < ?",
            )
            .bind(query.now_unix_ms)
            .bind(cached.observation.id.as_str())
            .bind(i64::MAX)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
            if updated != 1 {
                return Err(CacheError::InvalidStoredObservation {
                    field: "observation_cache_metadata",
                });
            }
            cached.metadata.last_accessed_at_unix_ms = cached
                .metadata
                .last_accessed_at_unix_ms
                .max(query.now_unix_ms);
            cached.metadata.access_count += 1;
        }
        transaction.commit().await?;
        Ok(observations)
    }
}

impl CacheVerdictPolicy {
    const fn flags(self) -> (bool, bool, bool, bool) {
        match self {
            Self::Exact(Verdict::Found) => (true, false, false, false),
            Self::Exact(Verdict::NotFound) => (false, true, false, false),
            Self::Exact(Verdict::InvalidUsername) => (false, false, true, false),
            Self::Exact(Verdict::Inconclusive) => (false, false, false, true),
            Self::Definitive => (true, true, false, false),
            Self::AnyObservation => (true, true, true, true),
        }
    }
}

fn validate_query(query: &CacheEligibilityQuery) -> Result<(), CacheError> {
    validate_length(
        &query.target.normalized_username,
        1,
        1_024,
        "normalized_username",
    )?;
    validate_length(query.target.site_id.as_str(), 1, 64, "site_id")?;
    validate_length(&query.region_class, 1, 64, "region_class")?;
    if query.maximum_age_ms <= 0 {
        return Err(CacheError::InvalidEligibilityQuery {
            field: "maximum_age_ms",
        });
    }
    if query.rule_hash.len() != 64
        || !query
            .rule_hash
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(CacheError::InvalidEligibilityQuery { field: "rule_hash" });
    }
    Ok(())
}

fn validate_length(
    value: &str,
    minimum: usize,
    maximum: usize,
    field: &'static str,
) -> Result<(), CacheError> {
    if !(minimum..=maximum).contains(&value.chars().count()) {
        return Err(CacheError::InvalidEligibilityQuery { field });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use socialname_domain::{
        CollectionProfile, EvidenceClass, InconclusiveReason, Observation, ObservationId,
        ProducerKind, ProducerReputation, SiteId,
    };

    use super::*;
    use crate::{CacheMetadata, StoreOutcome};

    fn observation(id: &str, verdict: Verdict, observed_at: i64, expires_at: i64) -> Observation {
        Observation {
            id: ObservationId::new(id),
            target: TargetKey {
                site_id: SiteId::new("example"),
                normalized_username: "private-target".to_owned(),
            },
            verdict,
            inconclusive_reason: (verdict == Verdict::Inconclusive)
                .then_some(InconclusiveReason::Timeout),
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

    fn query(policy: CacheVerdictPolicy, now: i64, maximum_age: i64) -> CacheEligibilityQuery {
        CacheEligibilityQuery {
            target: TargetKey {
                site_id: SiteId::new("example"),
                normalized_username: "private-target".to_owned(),
            },
            region_class: "local".to_owned(),
            rule_hash: "1".repeat(64),
            current_rule_health: RuleHealth::Healthy,
            now_unix_ms: now,
            maximum_age_ms: maximum_age,
            verdict_policy: policy,
        }
    }

    #[tokio::test]
    async fn exact_key_hit_returns_all_matching_observations_and_records_access() {
        let cache = LocalCache::open_in_memory().await.unwrap();
        let older = observation("observation-found", Verdict::Found, 1_000, 3_000);
        let newer = observation("observation-not-found", Verdict::NotFound, 1_100, 3_000);
        assert_eq!(
            cache.store_observation(&older, 1_101).await.unwrap(),
            StoreOutcome::Inserted
        );
        cache.store_observation(&newer, 1_101).await.unwrap();

        let eligible = cache
            .eligible_observations(&query(CacheVerdictPolicy::Definitive, 1_200, 500))
            .await
            .unwrap();
        assert_eq!(eligible.len(), 2);
        assert_eq!(eligible[0].observation, newer);
        assert_eq!(eligible[1].observation, older);
        for cached in eligible {
            assert_eq!(
                cached.metadata,
                CacheMetadata {
                    cached_at_unix_ms: 1_101,
                    last_accessed_at_unix_ms: 1_200,
                    access_count: 1,
                }
            );
        }
    }

    #[tokio::test]
    async fn key_or_rule_change_is_a_miss_without_touching_metadata() {
        let cache = LocalCache::open_in_memory().await.unwrap();
        let expected = observation("observation-keyed", Verdict::Found, 1_000, 3_000);
        cache.store_observation(&expected, 1_001).await.unwrap();

        let mut mismatches = Vec::new();
        let mut wrong_username = query(CacheVerdictPolicy::Definitive, 1_100, 500);
        wrong_username.target.normalized_username = "another-target".to_owned();
        mismatches.push(wrong_username);
        let mut wrong_site = query(CacheVerdictPolicy::Definitive, 1_100, 500);
        wrong_site.target.site_id = SiteId::new("another-site");
        mismatches.push(wrong_site);
        let mut wrong_region = query(CacheVerdictPolicy::Definitive, 1_100, 500);
        wrong_region.region_class = "another-region".to_owned();
        mismatches.push(wrong_region);
        let mut wrong_rule = query(CacheVerdictPolicy::Definitive, 1_100, 500);
        wrong_rule.rule_hash = "3".repeat(64);
        mismatches.push(wrong_rule);

        for mismatch in mismatches {
            assert!(
                cache
                    .eligible_observations(&mismatch)
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
        let stored = cache.get_observation(&expected.id).await.unwrap().unwrap();
        assert_eq!(stored.metadata.access_count, 0);
        assert_eq!(stored.metadata.last_accessed_at_unix_ms, 1_001);
    }

    #[tokio::test]
    async fn verdict_policy_and_rule_health_are_explicit() {
        let cache = LocalCache::open_in_memory().await.unwrap();
        let found = observation("observation-found", Verdict::Found, 1_000, 3_000);
        let not_found = observation("observation-not-found", Verdict::NotFound, 1_000, 3_000);
        let inconclusive = observation(
            "observation-inconclusive",
            Verdict::Inconclusive,
            1_000,
            3_000,
        );
        let mut unhealthy = observation("observation-unhealthy", Verdict::Found, 1_000, 3_000);
        unhealthy.rule_health_green = false;
        for item in [&found, &not_found, &inconclusive, &unhealthy] {
            cache.store_observation(item, 1_001).await.unwrap();
        }

        let found_only = cache
            .eligible_observations(&query(
                CacheVerdictPolicy::Exact(Verdict::Found),
                1_100,
                500,
            ))
            .await
            .unwrap();
        assert_eq!(found_only.len(), 1);
        assert_eq!(found_only[0].observation.id, found.id);

        let definitive = cache
            .eligible_observations(&query(CacheVerdictPolicy::Definitive, 1_100, 500))
            .await
            .unwrap();
        assert_eq!(definitive.len(), 2);
        assert!(
            definitive
                .iter()
                .any(|cached| cached.observation.id == not_found.id)
        );

        let any = cache
            .eligible_observations(&query(CacheVerdictPolicy::AnyObservation, 1_100, 500))
            .await
            .unwrap();
        assert_eq!(any.len(), 3);
        assert!(
            any.iter()
                .any(|cached| cached.observation.id == inconclusive.id)
        );
        assert!(
            any.iter()
                .all(|cached| cached.observation.id != unhealthy.id)
        );

        let mut quarantined = query(CacheVerdictPolicy::AnyObservation, 1_100, 500);
        quarantined.current_rule_health = RuleHealth::Quarantined;
        assert!(
            cache
                .eligible_observations(&quarantined)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn expiry_maximum_age_and_negative_ttl_are_all_enforced() {
        let cache = LocalCache::open_in_memory().await.unwrap();
        let found = observation("observation-long-found", Verdict::Found, 1_000, 3_000);
        let negative = observation(
            "observation-short-negative",
            Verdict::NotFound,
            1_000,
            1_150,
        );
        cache.store_observation(&found, 1_001).await.unwrap();
        cache.store_observation(&negative, 1_001).await.unwrap();

        let expired_negative = cache
            .eligible_observations(&query(
                CacheVerdictPolicy::Exact(Verdict::NotFound),
                1_150,
                500,
            ))
            .await
            .unwrap();
        assert!(expired_negative.is_empty());

        let age_boundary = cache
            .eligible_observations(&query(
                CacheVerdictPolicy::Exact(Verdict::Found),
                1_500,
                500,
            ))
            .await
            .unwrap();
        assert_eq!(age_boundary.len(), 1);
        let too_old = cache
            .eligible_observations(&query(
                CacheVerdictPolicy::Exact(Verdict::Found),
                1_501,
                500,
            ))
            .await
            .unwrap();
        assert!(too_old.is_empty());
    }

    #[tokio::test]
    async fn invalid_query_cannot_fall_back_to_a_broader_lookup() {
        let cache = LocalCache::open_in_memory().await.unwrap();
        let invalid = query(CacheVerdictPolicy::Definitive, 1_100, 0);
        assert!(matches!(
            cache.eligible_observations(&invalid).await.unwrap_err(),
            CacheError::InvalidEligibilityQuery {
                field: "maximum_age_ms"
            }
        ));
    }

    #[tokio::test]
    async fn oversized_eligible_set_fails_instead_of_hiding_conflicts() {
        let cache = LocalCache::open_in_memory().await.unwrap();
        for index in 0..=MAX_ELIGIBLE_OBSERVATIONS {
            let verdict = if index % 2 == 0 {
                Verdict::Found
            } else {
                Verdict::NotFound
            };
            let item = observation(
                &format!("observation-bounded-{index:03}"),
                verdict,
                1_000,
                3_000,
            );
            cache.store_observation(&item, 1_001).await.unwrap();
        }

        assert!(matches!(
            cache
                .eligible_observations(&query(CacheVerdictPolicy::Definitive, 1_100, 500))
                .await
                .unwrap_err(),
            CacheError::TooManyEligibleObservations {
                maximum: MAX_ELIGIBLE_OBSERVATIONS
            }
        ));
        let untouched = cache
            .get_observation(&ObservationId::new("observation-bounded-000"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(untouched.metadata.access_count, 0);
    }
}
