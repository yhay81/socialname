#![forbid(unsafe_code)]

mod local_observation;
mod source_policy;

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use futures_util::{StreamExt, stream};
use serde::{Deserialize, Serialize};
use socialname_cache::{CacheEligibilityQuery, CacheMetadata, CacheVerdictPolicy, LocalCache};
use socialname_domain::{
    EvidenceClass, InconclusiveReason, Observation, RuleHealth, RuleHealthPolicy, RuleHealthRecord,
    SiteId, TargetKey, Verdict,
};
use socialname_engine::{MatcherTrace, ProbeSummary, SearchEngine, SearchResult};
use socialname_rule_compiler::{CompiledSiteRule, RuleCompiler, render_url_template};
use socialname_rule_schema::AccountNamespace;
use tokio_util::sync::CancellationToken;

pub use local_observation::local_observation_from_result;
pub use source_policy::{
    DEFAULT_MAXIMUM_AGE_MS, DEFAULT_REGION_CLASS, RefreshState, SearchPolicy, SearchRuleHealth,
    SearchSource, SearchStatus, SyncPolicy,
};

const MAX_SELECTED_SITES: usize = 64;
const MAX_USERNAME_BYTES: usize = 256;
const MAX_CONCURRENT_PROBES: usize = 8;
const MAX_REGION_CLASS_CHARS: usize = 64;

const EMBEDDED_RULES: [(&str, &str); 10] = [
    ("bluesky", include_str!("../../../rules/sites/bluesky.yaml")),
    (
        "docker-hub",
        include_str!("../../../rules/sites/docker-hub.yaml"),
    ),
    ("github", include_str!("../../../rules/sites/github.yaml")),
    ("gitlab", include_str!("../../../rules/sites/gitlab.yaml")),
    (
        "mastodon-social",
        include_str!("../../../rules/sites/mastodon-social.yaml"),
    ),
    ("npm", include_str!("../../../rules/sites/npm.yaml")),
    ("reddit", include_str!("../../../rules/sites/reddit.yaml")),
    ("steam", include_str!("../../../rules/sites/steam.yaml")),
    ("x", include_str!("../../../rules/sites/x.yaml")),
    ("youtube", include_str!("../../../rules/sites/youtube.yaml")),
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteSummary {
    pub id: String,
    pub name: String,
    pub homepage: String,
    pub namespace: AccountNamespace,
    pub enabled: bool,
    pub tags: Vec<String>,
    pub notes: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SearchRequest {
    pub username: String,
    pub site_ids: Vec<String>,
    #[serde(default)]
    pub allow_discovery: bool,
    #[serde(default)]
    pub policy: SearchPolicy,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchCompletion {
    pub total: usize,
    pub completed: usize,
    pub found: usize,
    pub not_found: usize,
    pub inconclusive: usize,
    pub invalid_username: usize,
    pub cache_hits: usize,
    pub cache_misses: usize,
    pub unavailable: usize,
    pub cancelled: bool,
}

impl SearchCompletion {
    fn new(total: usize) -> Self {
        Self {
            total,
            completed: 0,
            found: 0,
            not_found: 0,
            inconclusive: 0,
            invalid_username: 0,
            cache_hits: 0,
            cache_misses: 0,
            unavailable: 0,
            cancelled: false,
        }
    }

    fn record(&mut self, result: &SearchResultView) {
        self.completed += 1;
        if let Some(live_result) = &result.live_result {
            match live_result.verdict {
                Verdict::Found => self.found += 1,
                Verdict::NotFound => self.not_found += 1,
                Verdict::Inconclusive => self.inconclusive += 1,
                Verdict::InvalidUsername => self.invalid_username += 1,
            }
        } else {
            match result.status {
                SearchStatus::Complete => self.cache_hits += 1,
                SearchStatus::CacheMiss => self.cache_misses += 1,
                SearchStatus::InvalidUsername => self.invalid_username += 1,
                SearchStatus::RuleNotPromoted
                | SearchStatus::RuleHealthUnavailable
                | SearchStatus::RuleNotHealthy
                | SearchStatus::RuleHealthStale => self.unavailable += 1,
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "event",
    content = "data"
)]
pub enum SearchEvent {
    Started { total: usize },
    Result { result: SearchResultView },
    Finished { summary: SearchCompletion },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchResultView {
    pub site_id: String,
    pub site_name: String,
    pub username: String,
    pub source: SearchSource,
    pub sync: SyncPolicy,
    pub status: SearchStatus,
    pub refresh_state: RefreshState,
    pub profile_url: Option<String>,
    pub rule_hash: String,
    pub rule_promoted: bool,
    pub rule_health: Option<RuleHealth>,
    pub rule_health_expires_at_unix_ms: Option<i64>,
    pub observations: Vec<SearchObservationView>,
    pub live_result: Option<LiveSearchResultView>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchObservationView {
    pub observation_id: String,
    pub verdict: Verdict,
    pub inconclusive_reason: Option<InconclusiveReason>,
    pub evidence_class: EvidenceClass,
    pub evidence_digest: String,
    pub observed_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub region_class: String,
    pub rule_hash: String,
    pub rule_health_green: bool,
    pub cached_at_unix_ms: Option<i64>,
    pub last_accessed_at_unix_ms: Option<i64>,
    pub access_count: Option<u64>,
}

impl SearchObservationView {
    fn from_observation(observation: Observation, metadata: Option<CacheMetadata>) -> Self {
        Self {
            observation_id: observation.id.as_str().to_owned(),
            verdict: observation.verdict,
            inconclusive_reason: observation.inconclusive_reason,
            evidence_class: observation.evidence_class,
            evidence_digest: observation.evidence_digest,
            observed_at_unix_ms: observation.observed_at_unix_ms,
            expires_at_unix_ms: observation.expires_at_unix_ms,
            region_class: observation.region,
            rule_hash: observation.rule_hash,
            rule_health_green: observation.rule_health_green,
            cached_at_unix_ms: metadata.as_ref().map(|metadata| metadata.cached_at_unix_ms),
            last_accessed_at_unix_ms: metadata
                .as_ref()
                .map(|metadata| metadata.last_accessed_at_unix_ms),
            access_count: metadata.map(|metadata| metadata.access_count),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveSearchResultView {
    pub verdict: Verdict,
    pub inconclusive_reason: Option<InconclusiveReason>,
    pub evidence_class: EvidenceClass,
    pub evidence_digest: String,
    pub matcher_trace: Vec<MatcherTraceView>,
    pub probes: Vec<ProbeSummaryView>,
}

impl LiveSearchResultView {
    fn from_engine(result: SearchResult) -> Self {
        Self {
            verdict: result.classification.verdict,
            inconclusive_reason: result.classification.inconclusive_reason,
            evidence_class: result.classification.evidence_class,
            evidence_digest: result.classification.evidence_digest,
            matcher_trace: result
                .classification
                .matcher_trace
                .into_iter()
                .map(MatcherTraceView::from)
                .collect(),
            probes: result
                .probes
                .into_iter()
                .map(ProbeSummaryView::from)
                .collect(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MatcherTraceView {
    pub path: String,
    pub matched: bool,
    pub detail: String,
}

impl From<MatcherTrace> for MatcherTraceView {
    fn from(value: MatcherTrace) -> Self {
        Self {
            path: value.path,
            matched: value.matched,
            detail: value.detail,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeSummaryView {
    pub probe_id: String,
    pub transport: socialname_rule_schema::TransportOutcome,
    pub status: Option<u16>,
    pub final_url: Option<String>,
    pub content_type: Option<String>,
    pub body_bytes: usize,
    pub body_truncated: bool,
    pub elapsed_ms: u64,
}

impl From<ProbeSummary> for ProbeSummaryView {
    fn from(value: ProbeSummary) -> Self {
        Self {
            probe_id: value.probe_id,
            transport: value.transport,
            status: value.status,
            final_url: value.final_url,
            content_type: value.content_type,
            body_bytes: value.body_bytes,
            body_truncated: value.body_truncated,
            elapsed_ms: value.elapsed_ms,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct RuleHealthLookupKey {
    site_id: String,
    rule_hash: String,
    region_class: String,
}

#[derive(Clone, Debug)]
pub struct AppCore {
    rules: Arc<Vec<Arc<CompiledSiteRule>>>,
    engine: SearchEngine,
    rule_pack_hash: String,
    cache: Option<LocalCache>,
    rule_health: Arc<BTreeMap<RuleHealthLookupKey, SearchRuleHealth>>,
}

impl AppCore {
    pub fn from_embedded_rules() -> Result<Self, AppCoreError> {
        let compiler = RuleCompiler::new();
        let compiled_rules = EMBEDDED_RULES
            .iter()
            .map(|(site_id, source)| {
                compiler
                    .compile_yaml(source, Some(site_id))
                    .map_err(format_compile_errors)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let rule_pack_hash = compiler
            .compile_pack(&compiled_rules)
            .map_err(format_compile_errors)?
            .content_hash;
        let rules = compiled_rules.into_iter().map(Arc::new).collect();
        let engine =
            SearchEngine::new().map_err(|error| AppCoreError::Engine(error.to_string()))?;
        Ok(Self {
            rules: Arc::new(rules),
            engine,
            rule_pack_hash,
            cache: None,
            rule_health: Arc::new(BTreeMap::new()),
        })
    }

    #[must_use]
    pub fn with_local_cache(mut self, cache: LocalCache) -> Self {
        self.cache = Some(cache);
        self
    }

    pub fn with_rule_health_records(
        mut self,
        records: impl IntoIterator<Item = RuleHealthRecord>,
    ) -> Result<Self, AppCoreError> {
        let mut rule_health = BTreeMap::new();
        for record in records {
            record
                .validate(RuleHealthPolicy::default())
                .map_err(|error| AppCoreError::RuleHealth(error.to_string()))?;
            let site_id = record.key.site_id.as_str().to_owned();
            let known_rule = self
                .rules
                .iter()
                .any(|rule| rule.source.id == site_id && rule.rule_hash == record.key.rule_hash);
            if !known_rule {
                return Err(AppCoreError::RuleHealthKey {
                    site_id,
                    region_class: record.key.region,
                });
            }
            let key = RuleHealthLookupKey {
                site_id,
                rule_hash: record.key.rule_hash,
                region_class: record.key.region,
            };
            let value = SearchRuleHealth {
                state: record.state,
                evidence_expires_at_unix_ms: record.last_evidence_expires_at_unix_ms,
            };
            if rule_health.insert(key, value).is_some() {
                return Err(AppCoreError::DuplicateRuleHealth);
            }
        }
        self.rule_health = Arc::new(rule_health);
        Ok(self)
    }

    #[must_use]
    pub fn rule_pack_hash(&self) -> &str {
        &self.rule_pack_hash
    }

    #[must_use]
    pub fn sites(&self) -> Vec<SiteSummary> {
        let mut sites: Vec<_> = self
            .rules
            .iter()
            .map(|rule| SiteSummary {
                id: rule.source.id.clone(),
                name: rule.source.name.clone(),
                homepage: rule.source.homepage.clone(),
                namespace: rule.source.namespace,
                enabled: rule.source.metadata.enabled,
                tags: rule.source.metadata.tags.clone(),
                notes: rule.source.metadata.notes.clone(),
            })
            .collect();
        sites.sort_by(|left, right| left.name.cmp(&right.name));
        sites
    }

    pub async fn run_search<F>(
        &self,
        request: SearchRequest,
        cancellation: CancellationToken,
        on_event: F,
    ) -> Result<SearchCompletion, AppCoreError>
    where
        F: Fn(SearchEvent) + Send + Sync,
    {
        self.run_search_at(request, cancellation, current_unix_ms()?, on_event)
            .await
    }

    async fn run_search_at<F>(
        &self,
        request: SearchRequest,
        cancellation: CancellationToken,
        now_unix_ms: i64,
        on_event: F,
    ) -> Result<SearchCompletion, AppCoreError>
    where
        F: Fn(SearchEvent) + Send + Sync,
    {
        let username = request.username.trim().to_owned();
        let selected = self.select_rules(&request)?;
        let mut summary = SearchCompletion::new(selected.len());
        on_event(SearchEvent::Started {
            total: selected.len(),
        });

        let policy = request.policy;
        let mut pending = stream::iter(selected.into_iter().map(|rule| {
            let cancellation = cancellation.clone();
            let username = username.clone();
            let policy = policy.clone();
            async move {
                tokio::select! {
                    biased;
                    () = cancellation.cancelled() => Ok(None),
                    result = self.execute_rule(&rule, &username, &policy, now_unix_ms) => {
                        result.map(Some)
                    },
                }
            }
        }))
        .buffer_unordered(MAX_CONCURRENT_PROBES);

        while let Some(result) = pending.next().await {
            if let Some(result) = result? {
                summary.record(&result);
                on_event(SearchEvent::Result { result });
            }
        }
        summary.cancelled = cancellation.is_cancelled();
        on_event(SearchEvent::Finished {
            summary: summary.clone(),
        });
        Ok(summary)
    }

    async fn execute_rule(
        &self,
        rule: &CompiledSiteRule,
        username: &str,
        policy: &SearchPolicy,
        now_unix_ms: i64,
    ) -> Result<SearchResultView, AppCoreError> {
        match policy.source {
            SearchSource::Local => {
                self.execute_local_rule(rule, username, policy, now_unix_ms)
                    .await
            }
            SearchSource::Cache => {
                self.execute_cache_rule(rule, username, policy, now_unix_ms)
                    .await
            }
        }
    }

    async fn execute_local_rule(
        &self,
        rule: &CompiledSiteRule,
        username: &str,
        policy: &SearchPolicy,
        now_unix_ms: i64,
    ) -> Result<SearchResultView, AppCoreError> {
        let result = self.engine.search(rule, username).await;
        let health = self.rule_health_for(rule, &policy.region_class);
        let status = if result.classification.verdict == Verdict::InvalidUsername {
            SearchStatus::InvalidUsername
        } else {
            SearchStatus::Complete
        };
        let mut output = self.base_result(
            rule,
            result.username.clone(),
            policy,
            health,
            status,
            RefreshState::Completed,
        );
        output.profile_url.clone_from(&result.profile_url);
        if let Some(observation) = local_observation_from_result(
            &result,
            &policy.region_class,
            now_unix_ms,
            rule.source.metadata.enabled
                && health.is_some_and(|health| health.is_fresh_healthy_at(now_unix_ms)),
        )? {
            let metadata = if let Some(cache) = &self.cache {
                cache
                    .store_observation(&observation, now_unix_ms)
                    .await
                    .map_err(cache_error)?;
                cache
                    .get_observation(&observation.id)
                    .await
                    .map_err(cache_error)?
                    .map(|cached| cached.metadata)
            } else {
                None
            };
            output
                .observations
                .push(SearchObservationView::from_observation(
                    observation,
                    metadata,
                ));
        }
        output.live_result = Some(LiveSearchResultView::from_engine(result));
        Ok(output)
    }

    async fn execute_cache_rule(
        &self,
        rule: &CompiledSiteRule,
        username: &str,
        policy: &SearchPolicy,
        now_unix_ms: i64,
    ) -> Result<SearchResultView, AppCoreError> {
        let Some(normalized_username) = rule.normalize_username(username) else {
            return Ok(self.base_result(
                rule,
                username.to_owned(),
                policy,
                None,
                SearchStatus::InvalidUsername,
                RefreshState::NotRequested,
            ));
        };
        if !rule.source.metadata.enabled {
            return Ok(self.base_result(
                rule,
                normalized_username,
                policy,
                self.rule_health_for(rule, &policy.region_class),
                SearchStatus::RuleNotPromoted,
                RefreshState::NotRequested,
            ));
        }
        let Some(health) = self.rule_health_for(rule, &policy.region_class) else {
            return Ok(self.base_result(
                rule,
                normalized_username,
                policy,
                None,
                SearchStatus::RuleHealthUnavailable,
                RefreshState::NotRequested,
            ));
        };
        if health.state != RuleHealth::Healthy {
            return Ok(self.base_result(
                rule,
                normalized_username,
                policy,
                Some(health),
                SearchStatus::RuleNotHealthy,
                RefreshState::NotRequested,
            ));
        }
        if !health.is_fresh_healthy_at(now_unix_ms) {
            return Ok(self.base_result(
                rule,
                normalized_username,
                policy,
                Some(health),
                SearchStatus::RuleHealthStale,
                RefreshState::NotRequested,
            ));
        }
        let cache = self.cache.as_ref().ok_or(AppCoreError::CacheUnavailable)?;
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
            .await
            .map_err(cache_error)?;
        let mut output = self.base_result(
            rule,
            normalized_username.clone(),
            policy,
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
            .map(|cached| {
                SearchObservationView::from_observation(cached.observation, Some(cached.metadata))
            })
            .collect();
        Ok(output)
    }

    fn base_result(
        &self,
        rule: &CompiledSiteRule,
        username: String,
        policy: &SearchPolicy,
        health: Option<SearchRuleHealth>,
        status: SearchStatus,
        refresh_state: RefreshState,
    ) -> SearchResultView {
        SearchResultView {
            site_id: rule.source.id.clone(),
            site_name: rule.source.name.clone(),
            username,
            source: policy.source,
            sync: policy.sync,
            status,
            refresh_state,
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

    fn rule_health_for(
        &self,
        rule: &CompiledSiteRule,
        region_class: &str,
    ) -> Option<SearchRuleHealth> {
        self.rule_health
            .get(&RuleHealthLookupKey {
                site_id: rule.source.id.clone(),
                rule_hash: rule.rule_hash.clone(),
                region_class: region_class.to_owned(),
            })
            .copied()
    }

    fn select_rules(
        &self,
        request: &SearchRequest,
    ) -> Result<Vec<Arc<CompiledSiteRule>>, AppCoreError> {
        let username = request.username.trim();
        if username.is_empty() {
            return Err(AppCoreError::EmptyUsername);
        }
        if username.len() > MAX_USERNAME_BYTES {
            return Err(AppCoreError::UsernameTooLong {
                maximum: MAX_USERNAME_BYTES,
            });
        }
        if request.site_ids.is_empty() {
            return Err(AppCoreError::NoSitesSelected);
        }
        if request.site_ids.len() > MAX_SELECTED_SITES {
            return Err(AppCoreError::TooManySites {
                maximum: MAX_SELECTED_SITES,
            });
        }
        let region_length = request.policy.region_class.chars().count();
        if !(1..=MAX_REGION_CLASS_CHARS).contains(&region_length) {
            return Err(AppCoreError::InvalidRegionClass {
                maximum: MAX_REGION_CLASS_CHARS,
            });
        }
        if request.policy.maximum_age_ms <= 0 {
            return Err(AppCoreError::InvalidMaximumAge);
        }

        let mut seen = BTreeSet::new();
        let mut selected = Vec::new();
        for site_id in &request.site_ids {
            if !seen.insert(site_id.as_str()) {
                continue;
            }
            let rule = self
                .rules
                .iter()
                .find(|rule| rule.source.id == *site_id)
                .ok_or_else(|| AppCoreError::UnknownSite(site_id.clone()))?;
            if request.policy.source == SearchSource::Local
                && !rule.source.metadata.enabled
                && !request.allow_discovery
            {
                return Err(AppCoreError::DiscoveryRule(site_id.clone()));
            }
            selected.push(Arc::clone(rule));
        }
        Ok(selected)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AppCoreError {
    #[error("embedded Site Rule v1 pack is invalid: {0}")]
    RulePack(String),
    #[error("failed to initialize the local HTTP engine: {0}")]
    Engine(String),
    #[error("username must not be empty")]
    EmptyUsername,
    #[error("username exceeds the {maximum}-byte application limit")]
    UsernameTooLong { maximum: usize },
    #[error("select at least one site")]
    NoSitesSelected,
    #[error("a search may select at most {maximum} sites")]
    TooManySites { maximum: usize },
    #[error("unknown site {0:?}")]
    UnknownSite(String),
    #[error("site {0:?} is discovery-only; explicitly enable research mode")]
    DiscoveryRule(String),
    #[error("region class must contain between 1 and {maximum} characters")]
    InvalidRegionClass { maximum: usize },
    #[error("maximum cache age must be greater than zero")]
    InvalidMaximumAge,
    #[error("local cache is unavailable")]
    CacheUnavailable,
    #[error("local cache operation failed: {0}")]
    Cache(String),
    #[error("rule-health record is invalid: {0}")]
    RuleHealth(String),
    #[error("rule-health record does not match site {site_id:?} in region {region_class:?}")]
    RuleHealthKey {
        site_id: String,
        region_class: String,
    },
    #[error("duplicate rule-health record")]
    DuplicateRuleHealth,
    #[error("system time is before the Unix epoch or exceeds the supported range")]
    Clock,
    #[error(
        "local observation expiry overflowed for observation time {observed_at_unix_ms} and TTL {ttl_ms}"
    )]
    ObservationExpiry {
        observed_at_unix_ms: i64,
        ttl_ms: i64,
    },
}

fn current_unix_ms() -> Result<i64, AppCoreError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AppCoreError::Clock)?;
    i64::try_from(duration.as_millis()).map_err(|_| AppCoreError::Clock)
}

fn cache_error(error: socialname_cache::CacheError) -> AppCoreError {
    AppCoreError::Cache(error.to_string())
}

fn format_compile_errors(errors: socialname_rule_compiler::CompileErrors) -> AppCoreError {
    AppCoreError::RulePack(
        errors
            .0
            .into_iter()
            .map(|error| error.to_string())
            .collect::<Vec<_>>()
            .join("; "),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_pack_contains_the_representative_set() {
        let core = AppCore::from_embedded_rules().unwrap();
        assert_eq!(core.sites().len(), 10);
        assert_eq!(core.rule_pack_hash().len(), 64);
    }

    #[test]
    fn discovery_rules_require_an_explicit_request() {
        let core = AppCore::from_embedded_rules().unwrap();
        let request = SearchRequest {
            username: "octocat".to_owned(),
            site_ids: vec!["github".to_owned()],
            allow_discovery: false,
            policy: SearchPolicy::default(),
        };
        assert!(matches!(
            core.select_rules(&request),
            Err(AppCoreError::DiscoveryRule(site)) if site == "github"
        ));
    }

    #[test]
    fn duplicate_sites_are_coalesced_before_execution() {
        let core = AppCore::from_embedded_rules().unwrap();
        let request = SearchRequest {
            username: "octocat".to_owned(),
            site_ids: vec!["github".to_owned(), "github".to_owned()],
            allow_discovery: true,
            policy: SearchPolicy::default(),
        };
        assert_eq!(core.select_rules(&request).unwrap().len(), 1);
    }

    #[test]
    fn streaming_event_contract_is_stable() {
        let started = serde_json::to_value(SearchEvent::Started { total: 10 }).unwrap();
        assert_eq!(
            started,
            serde_json::json!({
                "event": "started",
                "data": { "total": 10 }
            })
        );

        let finished = serde_json::to_value(SearchEvent::Finished {
            summary: SearchCompletion {
                total: 2,
                completed: 2,
                found: 1,
                not_found: 0,
                inconclusive: 1,
                invalid_username: 0,
                cache_hits: 0,
                cache_misses: 0,
                unavailable: 0,
                cancelled: false,
            },
        })
        .unwrap();
        assert_eq!(finished["event"], "finished");
        assert_eq!(finished["data"]["summary"]["notFound"], 0);
        assert_eq!(finished["data"]["summary"]["invalidUsername"], 0);
    }

    #[tokio::test]
    async fn cache_source_reports_discovery_rules_without_probing() {
        let core = AppCore::from_embedded_rules().unwrap();
        let events = std::sync::Mutex::new(Vec::new());
        let summary = core
            .run_search_at(
                SearchRequest {
                    username: "octocat".to_owned(),
                    site_ids: vec!["github".to_owned()],
                    allow_discovery: false,
                    policy: SearchPolicy {
                        source: SearchSource::Cache,
                        ..SearchPolicy::default()
                    },
                },
                CancellationToken::new(),
                1_500,
                |event| events.lock().unwrap().push(event),
            )
            .await
            .unwrap();

        assert_eq!(summary.completed, 1);
        assert_eq!(summary.unavailable, 1);
        let events = events.into_inner().unwrap();
        let SearchEvent::Result { result } = &events[1] else {
            panic!("expected a result event");
        };
        assert_eq!(result.source, SearchSource::Cache);
        assert_eq!(result.status, SearchStatus::RuleNotPromoted);
        assert_eq!(result.refresh_state, RefreshState::NotRequested);
        assert!(result.live_result.is_none());
        assert!(result.observations.is_empty());
    }

    #[tokio::test]
    async fn cache_source_returns_the_full_eligible_observation_set_as_cached() {
        let mut core = AppCore::from_embedded_rules().unwrap();
        let mut rule = (**core
            .rules
            .iter()
            .find(|rule| rule.source.id == "github")
            .unwrap())
        .clone();
        rule.source.metadata.enabled = true;
        let rule = Arc::new(rule);
        let cache = LocalCache::open_in_memory().await.unwrap();
        for (id, verdict, observed_at) in [
            ("cached-found", Verdict::Found, 1_000),
            ("cached-absent", Verdict::NotFound, 1_100),
        ] {
            cache
                .store_observation(
                    &Observation {
                        id: socialname_domain::ObservationId::new(id),
                        target: TargetKey {
                            site_id: SiteId::new("github"),
                            normalized_username: "octocat".to_owned(),
                        },
                        verdict,
                        inconclusive_reason: None,
                        evidence_class: EvidenceClass::E4StructuredIdentity,
                        observed_at_unix_ms: observed_at,
                        expires_at_unix_ms: 10_000,
                        region: "local".to_owned(),
                        network_group: "local-network".to_owned(),
                        independence_group: id.to_owned(),
                        producer_kind: socialname_domain::ProducerKind::LocalCli,
                        producer_reputation: socialname_domain::ProducerReputation::New,
                        collection_profile: socialname_domain::CollectionProfile::LocalOnly,
                        rule_hash: rule.rule_hash.clone(),
                        rule_health_green: true,
                        evidence_digest: "2".repeat(64),
                    },
                    observed_at,
                )
                .await
                .unwrap();
        }
        core.rules = Arc::new(vec![Arc::clone(&rule)]);
        core.cache = Some(cache);
        core.rule_health = Arc::new(BTreeMap::from([(
            RuleHealthLookupKey {
                site_id: "github".to_owned(),
                rule_hash: rule.rule_hash.clone(),
                region_class: "local".to_owned(),
            },
            SearchRuleHealth {
                state: RuleHealth::Healthy,
                evidence_expires_at_unix_ms: Some(10_000),
            },
        )]));

        let events = std::sync::Mutex::new(Vec::new());
        let summary = core
            .run_search_at(
                SearchRequest {
                    username: "octocat".to_owned(),
                    site_ids: vec!["github".to_owned()],
                    allow_discovery: false,
                    policy: SearchPolicy {
                        source: SearchSource::Cache,
                        ..SearchPolicy::default()
                    },
                },
                CancellationToken::new(),
                1_500,
                |event| events.lock().unwrap().push(event),
            )
            .await
            .unwrap();

        assert_eq!(summary.cache_hits, 1);
        let events = events.into_inner().unwrap();
        let SearchEvent::Result { result } = &events[1] else {
            panic!("expected a result event");
        };
        assert_eq!(result.status, SearchStatus::Complete);
        assert_eq!(result.observations.len(), 2);
        assert!(result.live_result.is_none());
        assert!(
            result
                .observations
                .iter()
                .all(|observation| observation.cached_at_unix_ms.is_some())
        );
    }
}
