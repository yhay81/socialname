use anyhow::{Result, bail};
use chrono::Utc;
use serde::Serialize;
use sha2::{Digest, Sha256};
pub use socialname_app_core::{
    RefreshState, SearchPolicy, SearchRuleHealth, SearchSource, SearchStatus, SyncPolicy,
};
use socialname_cache::{CacheEligibilityQuery, CacheMetadata, CacheVerdictPolicy, LocalCache};
use socialname_domain::{
    CollectionProfile, Observation, ObservationId, ProducerKind, ProducerReputation, RuleHealth,
    SiteId, TargetKey, Verdict,
};
use socialname_engine::{SearchEngine, SearchResult};
use socialname_rule_compiler::{CompiledSiteRule, render_url_template};

const FOUND_TTL_MS: i64 = 24 * 60 * 60 * 1_000;
const NOT_FOUND_TTL_MS: i64 = 15 * 60 * 1_000;
const INCONCLUSIVE_TTL_MS: i64 = 5 * 60 * 1_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CacheMetadataOutput {
    pub cached_at_unix_ms: i64,
    pub last_accessed_at_unix_ms: i64,
    pub access_count: u64,
}

impl From<CacheMetadata> for CacheMetadataOutput {
    fn from(value: CacheMetadata) -> Self {
        Self {
            cached_at_unix_ms: value.cached_at_unix_ms,
            last_accessed_at_unix_ms: value.last_accessed_at_unix_ms,
            access_count: value.access_count,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SearchObservationOutput {
    pub observation: Observation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_metadata: Option<CacheMetadataOutput>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SearchCommandOutput {
    pub source: SearchSource,
    pub sync: SyncPolicy,
    pub status: SearchStatus,
    pub refresh_state: RefreshState,
    pub site_id: String,
    pub username: String,
    pub profile_url: Option<String>,
    pub rule_hash: String,
    pub rule_promoted: bool,
    pub rule_health: Option<RuleHealth>,
    pub rule_health_expires_at_unix_ms: Option<i64>,
    pub observations: Vec<SearchObservationOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub live_result: Option<SearchResult>,
}

impl SearchCommandOutput {
    pub fn human(&self) -> String {
        let health = self
            .rule_health
            .map(|value| match value {
                RuleHealth::Healthy => "healthy",
                RuleHealth::Degraded => "degraded",
                RuleHealth::Quarantined => "quarantined",
                RuleHealth::Recovering => "recovering",
            })
            .unwrap_or("unavailable");
        let mut lines = vec![format!(
            "{}\tstatus={}\tsource={}\tsync={}\trefresh={}\tpromoted={}\thealth={health}\trule={}",
            self.site_id,
            self.status,
            self.source,
            self.sync,
            self.refresh_state,
            self.rule_promoted,
            self.rule_hash
        )];
        for cached in &self.observations {
            lines.push(format!(
                "observation\t{:?}\t{:?}\tobserved={}\texpires={}\tregion={}",
                cached.observation.verdict,
                cached.observation.evidence_class,
                cached.observation.observed_at_unix_ms,
                cached.observation.expires_at_unix_ms,
                cached.observation.region
            ));
        }
        if let Some(profile_url) = &self.profile_url {
            lines.push(format!("profile\t{profile_url}"));
        }
        lines.join("\n")
    }
}

pub async fn execute_search<F>(
    rule: &CompiledSiteRule,
    username: &str,
    policy: SearchPolicy,
    health: Option<SearchRuleHealth>,
    cache: Option<&LocalCache>,
    engine_factory: F,
) -> Result<SearchCommandOutput>
where
    F: FnOnce() -> Result<SearchEngine>,
{
    execute_search_at(
        rule,
        username,
        policy,
        health,
        cache,
        Utc::now().timestamp_millis(),
        engine_factory,
    )
    .await
}

async fn execute_search_at<F>(
    rule: &CompiledSiteRule,
    username: &str,
    policy: SearchPolicy,
    health: Option<SearchRuleHealth>,
    cache: Option<&LocalCache>,
    now_unix_ms: i64,
    engine_factory: F,
) -> Result<SearchCommandOutput>
where
    F: FnOnce() -> Result<SearchEngine>,
{
    match policy.source {
        SearchSource::Cache => {
            execute_cache_search(rule, username, policy, health, cache, now_unix_ms).await
        }
        SearchSource::Local => {
            let engine = engine_factory()?;
            let search = engine.search(rule, username);
            tokio::pin!(search);
            let result = tokio::select! {
                result = &mut search => result,
                signal = tokio::signal::ctrl_c() => {
                    signal?;
                    bail!("local search cancelled");
                }
            };
            local_output(rule, policy, health, cache, now_unix_ms, result).await
        }
    }
}

async fn execute_cache_search(
    rule: &CompiledSiteRule,
    username: &str,
    policy: SearchPolicy,
    health: Option<SearchRuleHealth>,
    cache: Option<&LocalCache>,
    now_unix_ms: i64,
) -> Result<SearchCommandOutput> {
    let Some(normalized_username) = rule.normalize_username(username) else {
        return Ok(base_output(
            rule,
            username.to_owned(),
            &policy,
            health,
            SearchStatus::InvalidUsername,
            RefreshState::NotRequested,
        ));
    };
    if !rule.source.metadata.enabled {
        return Ok(base_output(
            rule,
            normalized_username,
            &policy,
            health,
            SearchStatus::RuleNotPromoted,
            RefreshState::NotRequested,
        ));
    }
    let Some(health) = health else {
        return Ok(base_output(
            rule,
            normalized_username,
            &policy,
            None,
            SearchStatus::RuleHealthUnavailable,
            RefreshState::NotRequested,
        ));
    };
    if health.state != RuleHealth::Healthy {
        return Ok(base_output(
            rule,
            normalized_username,
            &policy,
            Some(health),
            SearchStatus::RuleNotHealthy,
            RefreshState::NotRequested,
        ));
    }
    if health
        .evidence_expires_at_unix_ms
        .is_none_or(|expires_at| expires_at <= now_unix_ms)
    {
        return Ok(base_output(
            rule,
            normalized_username,
            &policy,
            Some(health),
            SearchStatus::RuleHealthStale,
            RefreshState::NotRequested,
        ));
    }
    let Some(cache) = cache else {
        return Ok(base_output(
            rule,
            normalized_username,
            &policy,
            Some(health),
            SearchStatus::CacheMiss,
            RefreshState::NotRequested,
        ));
    };

    let cached = cache
        .eligible_observations(&CacheEligibilityQuery {
            target: TargetKey {
                site_id: SiteId::new(rule.source.id.clone()),
                normalized_username: normalized_username.clone(),
            },
            region_class: policy.region_class.clone(),
            rule_hash: rule.rule_hash.clone(),
            current_rule_health: health.state,
            now_unix_ms,
            maximum_age_ms: policy.maximum_age_ms,
            verdict_policy: CacheVerdictPolicy::Definitive,
        })
        .await?;
    let mut output = base_output(
        rule,
        normalized_username.clone(),
        &policy,
        Some(health),
        if cached.is_empty() {
            SearchStatus::CacheMiss
        } else {
            SearchStatus::Complete
        },
        RefreshState::NotRequested,
    );
    output.profile_url = render_url_template(&rule.source.profile_url, &normalized_username)
        .ok()
        .map(|url| url.to_string());
    output.observations = cached
        .into_iter()
        .map(|cached| SearchObservationOutput {
            observation: cached.observation,
            cache_metadata: Some(cached.metadata.into()),
        })
        .collect();
    Ok(output)
}

async fn local_output(
    rule: &CompiledSiteRule,
    policy: SearchPolicy,
    health: Option<SearchRuleHealth>,
    cache: Option<&LocalCache>,
    now_unix_ms: i64,
    result: SearchResult,
) -> Result<SearchCommandOutput> {
    let status = if result.classification.verdict == Verdict::InvalidUsername {
        SearchStatus::InvalidUsername
    } else {
        SearchStatus::Complete
    };
    let mut output = base_output(
        rule,
        result.username.clone(),
        &policy,
        health,
        status,
        RefreshState::Completed,
    );
    output.profile_url = result.profile_url.clone();
    if let Some(observation) = observation_from_result(
        &result,
        &policy.region_class,
        now_unix_ms,
        rule.source.metadata.enabled
            && health.is_some_and(|health| health.is_fresh_healthy_at(now_unix_ms)),
    )? {
        let cache_metadata = if let Some(cache) = cache {
            cache.store_observation(&observation, now_unix_ms).await?;
            cache
                .get_observation(&observation.id)
                .await?
                .map(|cached| cached.metadata.into())
        } else {
            None
        };
        output.observations.push(SearchObservationOutput {
            observation,
            cache_metadata,
        });
    }
    output.live_result = Some(result);
    Ok(output)
}

fn base_output(
    rule: &CompiledSiteRule,
    username: String,
    policy: &SearchPolicy,
    health: Option<SearchRuleHealth>,
    status: SearchStatus,
    refresh_state: RefreshState,
) -> SearchCommandOutput {
    SearchCommandOutput {
        source: policy.source,
        sync: policy.sync,
        status,
        refresh_state,
        site_id: rule.source.id.clone(),
        username,
        profile_url: None,
        rule_hash: rule.rule_hash.clone(),
        rule_promoted: rule.source.metadata.enabled,
        rule_health: health.map(|health| health.state),
        rule_health_expires_at_unix_ms: health
            .and_then(|health| health.evidence_expires_at_unix_ms),
        observations: Vec::new(),
        live_result: None,
    }
}

fn observation_from_result(
    result: &SearchResult,
    region_class: &str,
    observed_at_unix_ms: i64,
    rule_health_green: bool,
) -> Result<Option<Observation>> {
    let ttl_ms = match result.classification.verdict {
        Verdict::Found => FOUND_TTL_MS,
        Verdict::NotFound => NOT_FOUND_TTL_MS,
        Verdict::Inconclusive => INCONCLUSIVE_TTL_MS,
        Verdict::InvalidUsername => return Ok(None),
    };
    let expires_at_unix_ms = observed_at_unix_ms
        .checked_add(ttl_ms)
        .ok_or_else(|| anyhow::anyhow!("local observation expiry overflow"))?;
    let id = local_observation_id(result, region_class, observed_at_unix_ms);
    Ok(Some(Observation {
        id: ObservationId::new(id),
        target: TargetKey {
            site_id: SiteId::new(result.site_id.clone()),
            normalized_username: result.username.clone(),
        },
        verdict: result.classification.verdict,
        inconclusive_reason: result.classification.inconclusive_reason,
        evidence_class: result.classification.evidence_class,
        observed_at_unix_ms,
        expires_at_unix_ms,
        region: region_class.to_owned(),
        network_group: "local-network".to_owned(),
        independence_group: "local-installation".to_owned(),
        producer_kind: ProducerKind::LocalCli,
        producer_reputation: ProducerReputation::New,
        collection_profile: CollectionProfile::LocalOnly,
        rule_hash: result.rule_hash.clone(),
        rule_health_green,
        evidence_digest: result.classification.evidence_digest.clone(),
    }))
}

fn local_observation_id(
    result: &SearchResult,
    region_class: &str,
    observed_at_unix_ms: i64,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"socialname.local-observation/v1\0");
    for value in [
        result.site_id.as_bytes(),
        result.username.as_bytes(),
        result.rule_hash.as_bytes(),
        region_class.as_bytes(),
        result.classification.evidence_digest.as_bytes(),
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }
    digest.update(observed_at_unix_ms.to_be_bytes());
    format!("local-{}", hex::encode(digest.finalize()))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    use socialname_domain::{EvidenceClass, InconclusiveReason};
    use socialname_rule_compiler::RuleCompiler;

    use super::*;

    static NEXT_CACHE_ID: AtomicU64 = AtomicU64::new(1);

    struct TempCache {
        path: PathBuf,
    }

    impl TempCache {
        fn new() -> Self {
            let id = NEXT_CACHE_ID.fetch_add(1, Ordering::Relaxed);
            Self {
                path: std::env::temp_dir().join(format!(
                    "socialname-cli-cache-{}-{id}.sqlite3",
                    std::process::id()
                )),
            }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempCache {
        fn drop(&mut self) {
            for suffix in ["", "-wal", "-shm", "-journal"] {
                let mut path = self.path.as_os_str().to_owned();
                path.push(suffix);
                let _ = fs::remove_file(PathBuf::from(path));
            }
        }
    }

    fn rule() -> CompiledSiteRule {
        let mut rule = RuleCompiler::new()
            .compile_yaml(
                include_str!("../../../rules/sites/github.yaml"),
                Some("github"),
            )
            .unwrap();
        rule.source.metadata.enabled = true;
        rule
    }

    fn policy(source: SearchSource) -> SearchPolicy {
        SearchPolicy {
            source,
            sync: SyncPolicy::Never,
            region_class: "local".to_owned(),
            maximum_age_ms: 10_000,
        }
    }

    fn health() -> SearchRuleHealth {
        SearchRuleHealth {
            state: RuleHealth::Healthy,
            evidence_expires_at_unix_ms: Some(10_000),
        }
    }

    fn cached_observation(rule: &CompiledSiteRule) -> Observation {
        Observation {
            id: ObservationId::new("cached-observation"),
            target: TargetKey {
                site_id: SiteId::new(rule.source.id.clone()),
                normalized_username: "octocat".to_owned(),
            },
            verdict: Verdict::Found,
            inconclusive_reason: None,
            evidence_class: EvidenceClass::E4StructuredIdentity,
            observed_at_unix_ms: 1_000,
            expires_at_unix_ms: 5_000,
            region: "local".to_owned(),
            network_group: "local-network".to_owned(),
            independence_group: "local-installation".to_owned(),
            producer_kind: ProducerKind::LocalCli,
            producer_reputation: ProducerReputation::New,
            collection_profile: CollectionProfile::LocalOnly,
            rule_hash: rule.rule_hash.clone(),
            rule_health_green: true,
            evidence_digest: "2".repeat(64),
        }
    }

    #[tokio::test]
    async fn cache_source_returns_eligible_data_without_constructing_an_engine() {
        let rule = rule();
        let temp = TempCache::new();
        let cache = LocalCache::open(temp.path()).await.unwrap();
        cache
            .store_observation(&cached_observation(&rule), 1_001)
            .await
            .unwrap();

        let output = execute_search_at(
            &rule,
            "OctoCat",
            policy(SearchSource::Cache),
            Some(health()),
            Some(&cache),
            1_500,
            || panic!("cache source must not construct a network engine"),
        )
        .await
        .unwrap();
        assert_eq!(output.source, SearchSource::Cache);
        assert_eq!(output.sync, SyncPolicy::Never);
        assert_eq!(output.status, SearchStatus::Complete);
        assert_eq!(output.refresh_state, RefreshState::NotRequested);
        assert_eq!(output.observations.len(), 1);
        assert!(output.live_result.is_none());
    }

    #[tokio::test]
    async fn cache_miss_and_unhealthy_rule_do_not_construct_an_engine() {
        let rule = rule();
        let miss = execute_search_at(
            &rule,
            "octocat",
            policy(SearchSource::Cache),
            Some(health()),
            None,
            1_500,
            || panic!("cache miss must not construct a network engine"),
        )
        .await
        .unwrap();
        assert_eq!(miss.status, SearchStatus::CacheMiss);

        let unhealthy = execute_search_at(
            &rule,
            "octocat",
            policy(SearchSource::Cache),
            Some(SearchRuleHealth {
                state: RuleHealth::Quarantined,
                evidence_expires_at_unix_ms: Some(10_000),
            }),
            None,
            1_500,
            || panic!("unhealthy cache lookup must not construct a network engine"),
        )
        .await
        .unwrap();
        assert_eq!(unhealthy.status, SearchStatus::RuleNotHealthy);

        let mut discovery = rule.clone();
        discovery.source.metadata.enabled = false;
        let not_promoted = execute_search_at(
            &discovery,
            "octocat",
            policy(SearchSource::Cache),
            Some(health()),
            None,
            1_500,
            || panic!("discovery rule must not construct a network engine"),
        )
        .await
        .unwrap();
        assert_eq!(not_promoted.status, SearchStatus::RuleNotPromoted);
    }

    #[test]
    fn observation_ttls_are_verdict_specific_and_invalid_input_is_not_stored() {
        let rule = rule();
        let mut result = SearchResult {
            site_id: rule.source.id.clone(),
            username: "octocat".to_owned(),
            profile_url: None,
            rule_hash: rule.rule_hash,
            classification: socialname_engine::Classification {
                verdict: Verdict::Found,
                inconclusive_reason: None,
                evidence_class: EvidenceClass::E4StructuredIdentity,
                matcher_trace: Vec::new(),
                evidence_digest: "2".repeat(64),
            },
            probes: Vec::new(),
        };
        let found = observation_from_result(&result, "local", 1_000, true)
            .unwrap()
            .unwrap();
        assert_eq!(found.expires_at_unix_ms, 1_000 + FOUND_TTL_MS);

        result.classification.verdict = Verdict::NotFound;
        let not_found = observation_from_result(&result, "local", 1_000, true)
            .unwrap()
            .unwrap();
        assert_eq!(not_found.expires_at_unix_ms, 1_000 + NOT_FOUND_TTL_MS);

        result.classification.verdict = Verdict::Inconclusive;
        result.classification.inconclusive_reason = Some(InconclusiveReason::Timeout);
        let inconclusive = observation_from_result(&result, "local", 1_000, false)
            .unwrap()
            .unwrap();
        assert_eq!(inconclusive.expires_at_unix_ms, 1_000 + INCONCLUSIVE_TTL_MS);
        assert!(!inconclusive.rule_health_green);

        result.classification.verdict = Verdict::InvalidUsername;
        result.classification.inconclusive_reason = None;
        assert!(
            observation_from_result(&result, "local", 1_000, false)
                .unwrap()
                .is_none()
        );
    }
}
