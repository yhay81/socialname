use anyhow::{Result, bail};
use chrono::Utc;
use serde::Serialize;
use socialname_app_core::{
    LocalObservationProducer, ManagedSearchAccess, ManagedSearchRun, local_observation_from_result,
    run_managed_search,
};
pub use socialname_app_core::{
    RefreshState, ResultSource, SearchPolicy, SearchRuleHealth, SearchSource, SearchStatus,
    SyncPolicy,
};
use socialname_cache::{CacheEligibilityQuery, CacheMetadata, CacheVerdictPolicy, LocalCache};
use socialname_domain::{Observation, RuleHealth, SiteId, TargetKey, Verdict};
use socialname_engine::{SearchEngine, SearchResult};
use socialname_protocol::{SearchEvent, SearchProgress, SearchTerminalState};
use socialname_rule_compiler::{CompiledSiteRule, render_url_template};

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
    pub result_source: ResultSource,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cached_phase: Option<Box<SearchCommandOutput>>,
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
        let mut lines = self
            .cached_phase
            .as_deref()
            .map(|cached| {
                let mut phase = vec!["phase\tcache".to_owned()];
                phase.extend(cached.human().lines().map(str::to_owned));
                phase.push("phase\trefresh".to_owned());
                phase
            })
            .unwrap_or_default();
        lines.push(format!(
            "{}\tstatus={}\trequested_source={}\tresult_source={}\tsync={}\trefresh={}\tpromoted={}\thealth={health}\trule={}",
            self.site_id,
            self.status,
            self.source,
            self.result_source,
            self.sync,
            self.refresh_state,
            self.rule_promoted,
            self.rule_hash
        ));
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ManagedSearchCommandOutput {
    pub source: SearchSource,
    pub sync: SyncPolicy,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cached_phase: Option<SearchCommandOutput>,
    pub search_id: String,
    pub terminal_state: SearchTerminalState,
    pub progress: SearchProgress,
    pub events: Vec<SearchEvent>,
}

impl ManagedSearchCommandOutput {
    pub fn human(&self) -> String {
        let mut lines = vec![format!(
            "managed-search\tsource={}\tsync={}",
            self.source, self.sync
        )];
        if let Some(cached) = &self.cached_phase {
            lines.push("phase\tlocal-cache".to_owned());
            lines.extend(cached.human().lines().map(str::to_owned));
            lines.push("phase\tmanaged-service".to_owned());
        }
        for event in &self.events {
            lines.push(match &event.data {
                socialname_protocol::SearchEventData::Started { total_targets } => {
                    format!("event\tstarted\ttotal={total_targets}")
                }
                socialname_protocol::SearchEventData::DefinitiveResult { result } => format!(
                    "event\tdefinitive_result\tsite={}\tverdict={:?}\tsource={:?}",
                    result.target.site_id, result.verdict, result.source
                ),
                socialname_protocol::SearchEventData::UncertainResult { result } => format!(
                    "event\tuncertain_result\tsite={}\treason={:?}\tsource={:?}",
                    result.target.site_id, result.reason, result.source
                ),
                socialname_protocol::SearchEventData::OperationalFailure { failure } => format!(
                    "event\toperational_failure\tsite={}\tkind={:?}\tretryable={}",
                    failure.target.site_id, failure.kind, failure.retryable
                ),
                socialname_protocol::SearchEventData::AssertionUpdated { .. } => {
                    "event\tassertion_updated".to_owned()
                }
                socialname_protocol::SearchEventData::Finished { state, progress } => format!(
                    "event\tfinished\tstate={state:?}\tcompleted={}/{}",
                    progress.completed_targets, progress.total_targets
                ),
            });
        }
        lines.push(format!(
            "managed-search\tid={}\tstate={:?}",
            self.search_id, self.terminal_state
        ));
        lines.join("\n")
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn execute_managed_search(
    rule: &CompiledSiteRule,
    username: &str,
    policy: SearchPolicy,
    health: Option<SearchRuleHealth>,
    cache: Option<&LocalCache>,
    access: ManagedSearchAccess,
) -> Result<ManagedSearchCommandOutput> {
    policy.validate_relation()?;
    if !policy.uses_managed_service() {
        bail!("managed execution requires a remote-assisted policy");
    }
    let cached_phase = if policy.source == SearchSource::Hybrid {
        let mut cached = execute_cache_search(
            rule,
            username,
            policy.clone(),
            health,
            cache,
            Utc::now().timestamp_millis(),
        )
        .await?;
        cached.refresh_state = RefreshState::Pending;
        Some(cached)
    } else {
        None
    };
    let cancellation = tokio_util::sync::CancellationToken::new();
    let events = std::sync::Mutex::new(Vec::new());
    let outcome = {
        let run = run_managed_search(
            ManagedSearchRun {
                username: username.trim().to_owned(),
                site_ids: vec![rule.source.id.clone()],
                source: policy.source,
                sync: policy.sync,
                maximum_age_ms: policy.maximum_age_ms,
                region_class: policy.region_class.clone(),
                access,
            },
            cancellation.clone(),
            |event| {
                events
                    .lock()
                    .expect("managed event lock poisoned")
                    .push(event);
            },
        );
        tokio::pin!(run);
        tokio::select! {
            outcome = &mut run => outcome?,
            signal = tokio::signal::ctrl_c() => {
                signal?;
                cancellation.cancel();
                run.await?
            }
        }
    };
    Ok(ManagedSearchCommandOutput {
        source: policy.source,
        sync: policy.sync,
        cached_phase,
        search_id: outcome.search_id.as_str().to_owned(),
        terminal_state: outcome.terminal_state,
        progress: outcome.progress,
        events: events.into_inner().expect("managed event lock poisoned"),
    })
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
        SearchSource::Remote => bail!("remote search requires managed API access"),
        SearchSource::Hybrid => {
            let mut cached =
                execute_cache_search(rule, username, policy.clone(), health, cache, now_unix_ms)
                    .await?;
            cached.refresh_state = RefreshState::Pending;
            let engine = engine_factory()?;
            let search = engine.search(rule, username);
            tokio::pin!(search);
            let result = tokio::select! {
                result = &mut search => result,
                signal = tokio::signal::ctrl_c() => {
                    signal?;
                    bail!("local refresh cancelled");
                }
            };
            let mut output = local_output(rule, policy, health, cache, now_unix_ms, result).await?;
            let mut observations = std::mem::take(&mut cached.observations);
            observations.append(&mut output.observations);
            output.observations = observations;
            output.cached_phase = Some(Box::new(cached));
            Ok(output)
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
        result_source: if policy.source == SearchSource::Cache
            || policy.source == SearchSource::Hybrid && refresh_state != RefreshState::Completed
        {
            ResultSource::Cache
        } else {
            ResultSource::Local
        },
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
        cached_phase: None,
    }
}

fn observation_from_result(
    result: &SearchResult,
    region_class: &str,
    observed_at_unix_ms: i64,
    rule_health_green: bool,
) -> Result<Option<Observation>> {
    local_observation_from_result(
        result,
        region_class,
        observed_at_unix_ms,
        rule_health_green,
        LocalObservationProducer::Cli,
    )
    .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    use socialname_domain::{
        CollectionProfile, EvidenceClass, InconclusiveReason, ObservationId, ProducerKind,
        ProducerReputation,
    };
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
        assert_eq!(found.expires_at_unix_ms, 86_401_000);

        result.classification.verdict = Verdict::NotFound;
        let not_found = observation_from_result(&result, "local", 1_000, true)
            .unwrap()
            .unwrap();
        assert_eq!(not_found.expires_at_unix_ms, 901_000);

        result.classification.verdict = Verdict::Inconclusive;
        result.classification.inconclusive_reason = Some(InconclusiveReason::Timeout);
        let inconclusive = observation_from_result(&result, "local", 1_000, false)
            .unwrap()
            .unwrap();
        assert_eq!(inconclusive.expires_at_unix_ms, 301_000);
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
