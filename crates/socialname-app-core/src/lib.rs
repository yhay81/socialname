#![forbid(unsafe_code)]

mod local_observation;
mod managed_search;
mod source_policy;

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use futures_util::{StreamExt, future::BoxFuture, stream};
use serde::{Deserialize, Serialize};
use socialname_cache::{CacheEligibilityQuery, CacheMetadata, CacheVerdictPolicy, LocalCache};
use socialname_domain::{
    EvidenceClass, InconclusiveReason, Observation, RuleHealth, RuleHealthPolicy, RuleHealthRecord,
    SiteId, TargetKey, Verdict,
};
use socialname_engine::{MatcherTrace, ProbeSummary, SearchEngine, SearchResult};
use socialname_protocol::{
    DefinitiveResult as ManagedDefinitiveResult, DefinitiveVerdict,
    OperationalFailure as ManagedOperationalFailure, ResultSource as ProtocolResultSource,
    RuleHealthStatus, SearchEventData as ManagedSearchEventData,
    SearchTerminalState as ManagedSearchTerminalState, UncertainResult as ManagedUncertainResult,
    UncertaintyReason,
};
use socialname_rule_compiler::{CompiledSiteRule, RuleCompiler, render_url_template};
use socialname_rule_schema::AccountNamespace;
use tokio_util::sync::CancellationToken;

pub use local_observation::{LocalObservationProducer, local_observation_from_result};
pub use managed_search::{
    ManagedSearchAccess, ManagedSearchClientError, ManagedSearchOutcome, ManagedSearchRun,
    run_managed_search,
};
pub use source_policy::{
    DEFAULT_MAXIMUM_AGE_MS, DEFAULT_REGION_CLASS, RefreshState, ResultSource, SearchPolicy,
    SearchPolicyRelationError, SearchRuleHealth, SearchSource, SearchStatus, SyncPolicy,
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
    #[serde(default)]
    pub managed_access: Option<ManagedSearchAccess>,
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
        } else if result.operational_failure.is_some()
            || result.status == SearchStatus::OperationalFailure
        {
            self.unavailable += 1;
        } else if result.source == ResultSource::Cache {
            match result.status {
                SearchStatus::Complete => self.cache_hits += 1,
                SearchStatus::OperationalFailure => self.unavailable += 1,
                SearchStatus::CacheMiss => self.cache_misses += 1,
                SearchStatus::CacheUnavailable => self.unavailable += 1,
                SearchStatus::InvalidUsername => self.invalid_username += 1,
                SearchStatus::RuleNotPromoted
                | SearchStatus::RuleHealthUnavailable
                | SearchStatus::RuleNotHealthy
                | SearchStatus::RuleHealthStale => self.unavailable += 1,
            }
        } else if let Some(observation) = result.observations.last() {
            match observation.verdict {
                Verdict::Found => self.found += 1,
                Verdict::NotFound => self.not_found += 1,
                Verdict::Inconclusive => self.inconclusive += 1,
                Verdict::InvalidUsername => self.invalid_username += 1,
            }
        } else {
            self.unavailable += 1;
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
    Result { result: Box<SearchResultView> },
    Finished { summary: SearchCompletion },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchResultView {
    pub site_id: String,
    pub site_name: String,
    pub username: String,
    pub source: ResultSource,
    pub requested_source: SearchSource,
    pub sync: SyncPolicy,
    pub status: SearchStatus,
    pub refresh_state: RefreshState,
    pub profile_url: Option<String>,
    pub rule_hash: String,
    pub rule_promoted: bool,
    pub rule_health: Option<SearchResultRuleHealth>,
    pub rule_health_expires_at_unix_ms: Option<i64>,
    pub observations: Vec<SearchObservationView>,
    pub live_result: Option<LiveSearchResultView>,
    pub operational_failure: Option<ManagedOperationalFailureView>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchResultRuleHealth {
    Healthy,
    Degraded,
    Quarantined,
    Recovering,
    Unavailable,
    Stale,
}

impl From<RuleHealth> for SearchResultRuleHealth {
    fn from(value: RuleHealth) -> Self {
        match value {
            RuleHealth::Healthy => Self::Healthy,
            RuleHealth::Degraded => Self::Degraded,
            RuleHealth::Quarantined => Self::Quarantined,
            RuleHealth::Recovering => Self::Recovering,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchInconclusiveReason {
    Blocked,
    RateLimited,
    Timeout,
    Dns,
    Connect,
    Tls,
    RedirectRejected,
    ResponseTooLarge,
    Decode,
    SiteChanged,
    NoRuleMatched,
    ConflictingEvidence,
    ClassificationAmbiguous,
}

impl From<InconclusiveReason> for SearchInconclusiveReason {
    fn from(value: InconclusiveReason) -> Self {
        match value {
            InconclusiveReason::Blocked => Self::Blocked,
            InconclusiveReason::RateLimited => Self::RateLimited,
            InconclusiveReason::Timeout => Self::Timeout,
            InconclusiveReason::Dns => Self::Dns,
            InconclusiveReason::Connect => Self::Connect,
            InconclusiveReason::Tls => Self::Tls,
            InconclusiveReason::RedirectRejected => Self::RedirectRejected,
            InconclusiveReason::ResponseTooLarge => Self::ResponseTooLarge,
            InconclusiveReason::Decode => Self::Decode,
            InconclusiveReason::SiteChanged => Self::SiteChanged,
            InconclusiveReason::NoRuleMatched => Self::NoRuleMatched,
            InconclusiveReason::ConflictingEvidence => Self::ConflictingEvidence,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagedOperationalFailureView {
    pub kind: socialname_protocol::OperationalFailureKind,
    pub occurred_at_unix_ms: i64,
    pub retryable: bool,
    pub region_class: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchObservationView {
    pub observation_id: String,
    pub source: ResultSource,
    pub verdict: Verdict,
    pub inconclusive_reason: Option<SearchInconclusiveReason>,
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
    fn from_observation(
        observation: Observation,
        source: ResultSource,
        metadata: Option<CacheMetadata>,
    ) -> Self {
        Self {
            observation_id: observation.id.as_str().to_owned(),
            source,
            verdict: observation.verdict,
            inconclusive_reason: observation.inconclusive_reason.map(Into::into),
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

trait LocalSearchExecutor: std::fmt::Debug + Send + Sync {
    fn search<'a>(
        &'a self,
        rule: &'a CompiledSiteRule,
        username: &'a str,
    ) -> BoxFuture<'a, SearchResult>;
}

impl LocalSearchExecutor for SearchEngine {
    fn search<'a>(
        &'a self,
        rule: &'a CompiledSiteRule,
        username: &'a str,
    ) -> BoxFuture<'a, SearchResult> {
        Box::pin(SearchEngine::search(self, rule, username))
    }
}

#[derive(Clone, Debug)]
pub struct AppCore {
    rules: Arc<Vec<Arc<CompiledSiteRule>>>,
    local_executor: Arc<dyn LocalSearchExecutor>,
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
            local_executor: Arc::new(engine),
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
        let on_event = Arc::new(on_event);
        on_event(SearchEvent::Started {
            total: selected.len(),
        });

        if request.policy.uses_managed_service() {
            return self
                .run_managed_search_at(
                    request,
                    selected,
                    cancellation,
                    now_unix_ms,
                    summary,
                    on_event,
                )
                .await;
        }

        let policy = request.policy;
        let mut pending = stream::iter(selected.into_iter().map(|rule| {
            let cancellation = cancellation.clone();
            let username = username.clone();
            let policy = policy.clone();
            let on_event = Arc::clone(&on_event);
            async move {
                tokio::select! {
                    biased;
                    () = cancellation.cancelled() => Ok(None),
                    result = self.execute_rule(
                        &rule,
                        &username,
                        &policy,
                        now_unix_ms,
                        &cancellation,
                        |result| {
                            on_event(SearchEvent::Result {
                                result: Box::new(result),
                            });
                        },
                    ) => result,
                }
            }
        }))
        .buffer_unordered(MAX_CONCURRENT_PROBES);

        while let Some(result) = pending.next().await {
            if let Some(result) = result? {
                summary.record(&result);
                on_event(SearchEvent::Result {
                    result: Box::new(result),
                });
            }
        }
        summary.cancelled = cancellation.is_cancelled();
        on_event(SearchEvent::Finished {
            summary: summary.clone(),
        });
        Ok(summary)
    }

    async fn run_managed_search_at<F>(
        &self,
        mut request: SearchRequest,
        selected: Vec<Arc<CompiledSiteRule>>,
        cancellation: CancellationToken,
        now_unix_ms: i64,
        summary: SearchCompletion,
        on_event: Arc<F>,
    ) -> Result<SearchCompletion, AppCoreError>
    where
        F: Fn(SearchEvent) + Send + Sync,
    {
        let access = request
            .managed_access
            .take()
            .ok_or(AppCoreError::MissingManagedAccess)?;
        let mut cached_by_site = BTreeMap::new();
        let mut cached_results = BTreeMap::new();
        if request.policy.source == SearchSource::Hybrid {
            for rule in &selected {
                if cancellation.is_cancelled() {
                    let mut summary = summary;
                    summary.cancelled = true;
                    on_event(SearchEvent::Finished {
                        summary: summary.clone(),
                    });
                    return Ok(summary);
                }
                let mut cached = self
                    .execute_cache_rule(rule, request.username.trim(), &request.policy, now_unix_ms)
                    .await?;
                cached.refresh_state = RefreshState::Pending;
                cached_by_site.insert(rule.source.id.clone(), cached.observations.clone());
                cached_results.insert(rule.source.id.clone(), cached.clone());
                on_event(SearchEvent::Result {
                    result: Box::new(cached),
                });
            }
        }

        let rules = selected
            .iter()
            .map(|rule| (rule.source.id.clone(), Arc::clone(rule)))
            .collect::<BTreeMap<_, _>>();
        let expected_username = request.username.trim().to_owned();
        let policy = request.policy.clone();
        let summary = Arc::new(std::sync::Mutex::new(summary));
        let completed = Arc::new(std::sync::Mutex::new(BTreeSet::new()));
        let callback_error = Arc::new(std::sync::Mutex::new(None));
        let callback_summary = Arc::clone(&summary);
        let callback_completed = Arc::clone(&completed);
        let callback_error_slot = Arc::clone(&callback_error);
        let callback_on_event = Arc::clone(&on_event);
        let callback_cached_by_site = cached_by_site.clone();

        let outcome = run_managed_search(
            ManagedSearchRun {
                username: expected_username.clone(),
                site_ids: selected.iter().map(|rule| rule.source.id.clone()).collect(),
                source: policy.source,
                sync: policy.sync,
                maximum_age_ms: policy.maximum_age_ms,
                region_class: policy.region_class.clone(),
                access,
            },
            cancellation,
            move |managed_event| {
                let converted = match managed_event.data {
                    ManagedSearchEventData::DefinitiveResult { result } => {
                        Self::managed_definitive_result(
                            &rules,
                            &callback_cached_by_site,
                            &expected_username,
                            &policy,
                            result,
                        )
                    }
                    ManagedSearchEventData::UncertainResult { result } => {
                        Self::managed_uncertain_result(
                            &rules,
                            &callback_cached_by_site,
                            &expected_username,
                            &policy,
                            result,
                        )
                    }
                    ManagedSearchEventData::OperationalFailure { failure } => {
                        Self::managed_operational_failure(
                            &rules,
                            &callback_cached_by_site,
                            &expected_username,
                            &policy,
                            failure,
                        )
                    }
                    ManagedSearchEventData::Started { .. }
                    | ManagedSearchEventData::AssertionUpdated { .. }
                    | ManagedSearchEventData::Finished { .. } => return,
                };
                let result = match converted {
                    Ok(result) => result,
                    Err(error) => {
                        if let Ok(mut slot) = callback_error_slot.lock() {
                            *slot = Some(error);
                        }
                        return;
                    }
                };
                let unique = callback_completed
                    .lock()
                    .map(|mut completed| completed.insert(result.site_id.clone()))
                    .unwrap_or(false);
                if !unique {
                    if let Ok(mut slot) = callback_error_slot.lock() {
                        *slot = Some(AppCoreError::DuplicateManagedTarget);
                    }
                    return;
                }
                if let Ok(mut summary) = callback_summary.lock() {
                    summary.record(&result);
                }
                callback_on_event(SearchEvent::Result {
                    result: Box::new(result),
                });
            },
        )
        .await;
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                for mut cached in cached_results.into_values() {
                    cached.refresh_state = RefreshState::Failed;
                    on_event(SearchEvent::Result {
                        result: Box::new(cached),
                    });
                }
                return Err(error.into());
            }
        };

        if let Some(error) = callback_error
            .lock()
            .map_err(|_| AppCoreError::ManagedTarget)?
            .take()
        {
            return Err(error);
        }
        let completed_count = completed
            .lock()
            .map_err(|_| AppCoreError::ManagedTarget)?
            .len();
        if completed_count
            != usize::try_from(outcome.progress.completed_targets)
                .map_err(|_| AppCoreError::ManagedTarget)?
        {
            return Err(AppCoreError::ManagedTarget);
        }
        let mut summary = Arc::try_unwrap(summary)
            .map_err(|_| AppCoreError::ManagedTarget)?
            .into_inner()
            .map_err(|_| AppCoreError::ManagedTarget)?;
        summary.cancelled = outcome.terminal_state == ManagedSearchTerminalState::Cancelled;
        if outcome.terminal_state == ManagedSearchTerminalState::Failed {
            summary.unavailable = summary
                .unavailable
                .saturating_add(summary.total.saturating_sub(summary.completed));
        }
        on_event(SearchEvent::Finished {
            summary: summary.clone(),
        });
        Ok(summary)
    }

    fn managed_definitive_result(
        rules: &BTreeMap<String, Arc<CompiledSiteRule>>,
        cached_by_site: &BTreeMap<String, Vec<SearchObservationView>>,
        expected_username: &str,
        policy: &SearchPolicy,
        result: ManagedDefinitiveResult,
    ) -> Result<SearchResultView, AppCoreError> {
        let rule = managed_rule(rules, expected_username, &result.target)?;
        let source = managed_result_source(result.source);
        let mut observations = cached_by_site
            .get(result.target.site_id.as_str())
            .cloned()
            .unwrap_or_default();
        observations.push(SearchObservationView {
            observation_id: result.observation_id.as_str().to_owned(),
            source,
            verdict: match result.verdict {
                DefinitiveVerdict::Found => Verdict::Found,
                DefinitiveVerdict::NotFound => Verdict::NotFound,
            },
            inconclusive_reason: None,
            evidence_class: managed_evidence_class(result.evidence_class),
            evidence_digest: result.evidence_digest.as_str().to_owned(),
            observed_at_unix_ms: result.freshness.observed_at_unix_ms,
            expires_at_unix_ms: result.freshness.expires_at_unix_ms,
            region_class: result.region_class.as_str().to_owned(),
            rule_hash: result.rule_hash.as_str().to_owned(),
            rule_health_green: result.rule_health == RuleHealthStatus::Healthy,
            cached_at_unix_ms: None,
            last_accessed_at_unix_ms: None,
            access_count: None,
        });
        Ok(SearchResultView {
            site_id: rule.source.id.clone(),
            site_name: rule.source.name.clone(),
            username: result.target.username.as_str().to_owned(),
            source,
            requested_source: policy.source,
            sync: policy.sync,
            status: SearchStatus::Complete,
            refresh_state: managed_refresh_state(policy),
            profile_url: result.profile_url.map(|url| url.as_str().to_owned()),
            rule_hash: result.rule_hash.as_str().to_owned(),
            rule_promoted: true,
            rule_health: Some(managed_rule_health(result.rule_health)),
            rule_health_expires_at_unix_ms: None,
            observations,
            live_result: None,
            operational_failure: None,
        })
    }

    fn managed_uncertain_result(
        rules: &BTreeMap<String, Arc<CompiledSiteRule>>,
        cached_by_site: &BTreeMap<String, Vec<SearchObservationView>>,
        expected_username: &str,
        policy: &SearchPolicy,
        result: ManagedUncertainResult,
    ) -> Result<SearchResultView, AppCoreError> {
        let rule = managed_rule(rules, expected_username, &result.target)?;
        let source = managed_result_source(result.source);
        let mut observations = cached_by_site
            .get(result.target.site_id.as_str())
            .cloned()
            .unwrap_or_default();
        observations.push(SearchObservationView {
            observation_id: result.observation_id.as_str().to_owned(),
            source,
            verdict: Verdict::Inconclusive,
            inconclusive_reason: Some(managed_uncertainty_reason(result.reason)),
            evidence_class: managed_evidence_class(result.evidence_class),
            evidence_digest: result.evidence_digest.as_str().to_owned(),
            observed_at_unix_ms: result.freshness.observed_at_unix_ms,
            expires_at_unix_ms: result.freshness.expires_at_unix_ms,
            region_class: result.region_class.as_str().to_owned(),
            rule_hash: result.rule_hash.as_str().to_owned(),
            rule_health_green: result.rule_health == RuleHealthStatus::Healthy,
            cached_at_unix_ms: None,
            last_accessed_at_unix_ms: None,
            access_count: None,
        });
        Ok(SearchResultView {
            site_id: rule.source.id.clone(),
            site_name: rule.source.name.clone(),
            username: result.target.username.as_str().to_owned(),
            source,
            requested_source: policy.source,
            sync: policy.sync,
            status: SearchStatus::Complete,
            refresh_state: managed_refresh_state(policy),
            profile_url: None,
            rule_hash: result.rule_hash.as_str().to_owned(),
            rule_promoted: true,
            rule_health: Some(managed_rule_health(result.rule_health)),
            rule_health_expires_at_unix_ms: None,
            observations,
            live_result: None,
            operational_failure: None,
        })
    }

    fn managed_operational_failure(
        rules: &BTreeMap<String, Arc<CompiledSiteRule>>,
        cached_by_site: &BTreeMap<String, Vec<SearchObservationView>>,
        expected_username: &str,
        policy: &SearchPolicy,
        failure: ManagedOperationalFailure,
    ) -> Result<SearchResultView, AppCoreError> {
        let rule = managed_rule(rules, expected_username, &failure.target)?;
        Ok(SearchResultView {
            site_id: rule.source.id.clone(),
            site_name: rule.source.name.clone(),
            username: failure.target.username.as_str().to_owned(),
            source: managed_result_source(failure.source),
            requested_source: policy.source,
            sync: policy.sync,
            status: SearchStatus::OperationalFailure,
            refresh_state: managed_refresh_state(policy),
            profile_url: None,
            rule_hash: failure
                .rule_hash
                .map_or_else(|| rule.rule_hash.clone(), |hash| hash.as_str().to_owned()),
            rule_promoted: true,
            rule_health: None,
            rule_health_expires_at_unix_ms: None,
            observations: cached_by_site
                .get(failure.target.site_id.as_str())
                .cloned()
                .unwrap_or_default(),
            live_result: None,
            operational_failure: Some(ManagedOperationalFailureView {
                kind: failure.kind,
                occurred_at_unix_ms: failure.occurred_at_unix_ms,
                retryable: failure.retryable,
                region_class: failure
                    .region_class
                    .map(|region| region.as_str().to_owned()),
            }),
        })
    }

    async fn execute_rule<F>(
        &self,
        rule: &CompiledSiteRule,
        username: &str,
        policy: &SearchPolicy,
        now_unix_ms: i64,
        cancellation: &CancellationToken,
        on_intermediate: F,
    ) -> Result<Option<SearchResultView>, AppCoreError>
    where
        F: Fn(SearchResultView) + Send + Sync,
    {
        match policy.source {
            SearchSource::Local => self
                .execute_local_rule(rule, username, policy, now_unix_ms)
                .await
                .map(Some),
            SearchSource::Cache => self
                .execute_cache_rule(rule, username, policy, now_unix_ms)
                .await
                .map(Some),
            SearchSource::Remote => Err(AppCoreError::InvalidPolicy(
                "remote execution requires managed access".to_owned(),
            )),
            SearchSource::Hybrid => {
                let mut cached = self
                    .execute_cache_rule(rule, username, policy, now_unix_ms)
                    .await?;
                cached.refresh_state = RefreshState::Pending;
                let cached_observations = cached.observations.clone();
                on_intermediate(cached);
                if cancellation.is_cancelled() {
                    return Ok(None);
                }

                let mut local = self
                    .execute_local_rule(rule, username, policy, now_unix_ms)
                    .await?;
                let mut observations = cached_observations;
                observations.append(&mut local.observations);
                local.observations = observations;
                Ok(Some(local))
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
        let result = self.local_executor.search(rule, username).await;
        let health = self.rule_health_for(rule, &policy.region_class);
        let status = if result.classification.verdict == Verdict::InvalidUsername {
            SearchStatus::InvalidUsername
        } else {
            SearchStatus::Complete
        };
        let mut output = Self::base_result(
            rule,
            result.username.clone(),
            policy,
            ResultSource::Local,
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
            LocalObservationProducer::Desktop,
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
                    ResultSource::Local,
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
            return Ok(Self::base_result(
                rule,
                username.to_owned(),
                policy,
                ResultSource::Cache,
                None,
                SearchStatus::InvalidUsername,
                RefreshState::NotRequested,
            ));
        };
        if !rule.source.metadata.enabled {
            return Ok(Self::base_result(
                rule,
                normalized_username,
                policy,
                ResultSource::Cache,
                self.rule_health_for(rule, &policy.region_class),
                SearchStatus::RuleNotPromoted,
                RefreshState::NotRequested,
            ));
        }
        let Some(health) = self.rule_health_for(rule, &policy.region_class) else {
            return Ok(Self::base_result(
                rule,
                normalized_username,
                policy,
                ResultSource::Cache,
                None,
                SearchStatus::RuleHealthUnavailable,
                RefreshState::NotRequested,
            ));
        };
        if health.state != RuleHealth::Healthy {
            return Ok(Self::base_result(
                rule,
                normalized_username,
                policy,
                ResultSource::Cache,
                Some(health),
                SearchStatus::RuleNotHealthy,
                RefreshState::NotRequested,
            ));
        }
        if !health.is_fresh_healthy_at(now_unix_ms) {
            return Ok(Self::base_result(
                rule,
                normalized_username,
                policy,
                ResultSource::Cache,
                Some(health),
                SearchStatus::RuleHealthStale,
                RefreshState::NotRequested,
            ));
        }
        let Some(cache) = self.cache.as_ref() else {
            return Ok(Self::base_result(
                rule,
                normalized_username,
                policy,
                ResultSource::Cache,
                Some(health),
                SearchStatus::CacheUnavailable,
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
            .await
            .map_err(cache_error)?;
        let mut output = Self::base_result(
            rule,
            normalized_username.clone(),
            policy,
            ResultSource::Cache,
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
                SearchObservationView::from_observation(
                    cached.observation,
                    ResultSource::Cache,
                    Some(cached.metadata),
                )
            })
            .collect();
        Ok(output)
    }

    fn base_result(
        rule: &CompiledSiteRule,
        username: String,
        policy: &SearchPolicy,
        source: ResultSource,
        health: Option<SearchRuleHealth>,
        status: SearchStatus,
        refresh_state: RefreshState,
    ) -> SearchResultView {
        SearchResultView {
            site_id: rule.source.id.clone(),
            site_name: rule.source.name.clone(),
            username,
            source,
            requested_source: policy.source,
            sync: policy.sync,
            status,
            refresh_state,
            profile_url: None,
            rule_hash: rule.rule_hash.clone(),
            rule_promoted: rule.source.metadata.enabled,
            rule_health: health.map(|health| health.state.into()),
            rule_health_expires_at_unix_ms: health
                .and_then(|health| health.evidence_expires_at_unix_ms),
            observations: Vec::new(),
            live_result: None,
            operational_failure: None,
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
        request
            .policy
            .validate_relation()
            .map_err(|error| AppCoreError::InvalidPolicy(error.to_string()))?;
        if request.policy.uses_managed_service() && request.managed_access.is_none() {
            return Err(AppCoreError::MissingManagedAccess);
        }
        if !request.policy.uses_managed_service() && request.managed_access.is_some() {
            return Err(AppCoreError::UnexpectedManagedAccess);
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
            let performs_local_probe = request.policy.source == SearchSource::Local
                || request.policy.source == SearchSource::Hybrid
                    && request.policy.sync == SyncPolicy::Never;
            if performs_local_probe && !rule.source.metadata.enabled && !request.allow_discovery {
                return Err(AppCoreError::DiscoveryRule(site_id.clone()));
            }
            selected.push(Arc::clone(rule));
        }
        Ok(selected)
    }
}

fn managed_rule<'a>(
    rules: &'a BTreeMap<String, Arc<CompiledSiteRule>>,
    expected_username: &str,
    target: &socialname_protocol::Target,
) -> Result<&'a CompiledSiteRule, AppCoreError> {
    let rule = rules
        .get(target.site_id.as_str())
        .map(AsRef::as_ref)
        .ok_or(AppCoreError::ManagedTarget)?;
    let username_matches = target.username.as_str() == expected_username
        || rule
            .normalize_username(expected_username)
            .as_deref()
            .is_some_and(|normalized| normalized == target.username.as_str());
    if username_matches {
        Ok(rule)
    } else {
        Err(AppCoreError::ManagedTarget)
    }
}

const fn managed_result_source(source: ProtocolResultSource) -> ResultSource {
    match source {
        ProtocolResultSource::LocalCache => ResultSource::Cache,
        ProtocolResultSource::LocalProbe => ResultSource::Local,
        ProtocolResultSource::PrivateCloud => ResultSource::PrivateCloud,
        ProtocolResultSource::SharedAssertion => ResultSource::SharedAssertion,
        ProtocolResultSource::ManagedProbe => ResultSource::ManagedProbe,
    }
}

const fn managed_rule_health(health: RuleHealthStatus) -> SearchResultRuleHealth {
    match health {
        RuleHealthStatus::Healthy => SearchResultRuleHealth::Healthy,
        RuleHealthStatus::Degraded => SearchResultRuleHealth::Degraded,
        RuleHealthStatus::Quarantined => SearchResultRuleHealth::Quarantined,
        RuleHealthStatus::Recovering => SearchResultRuleHealth::Recovering,
        RuleHealthStatus::Unavailable => SearchResultRuleHealth::Unavailable,
        RuleHealthStatus::Stale => SearchResultRuleHealth::Stale,
    }
}

const fn managed_evidence_class(evidence: socialname_protocol::EvidenceClass) -> EvidenceClass {
    match evidence {
        socialname_protocol::EvidenceClass::E0NoAccountEvidence => {
            EvidenceClass::E0NoAccountEvidence
        }
        socialname_protocol::EvidenceClass::E1WeakSignal => EvidenceClass::E1WeakSignal,
        socialname_protocol::EvidenceClass::E2DifferentialTemplate => {
            EvidenceClass::E2DifferentialTemplate
        }
        socialname_protocol::EvidenceClass::E3ExplicitEndpoint => EvidenceClass::E3ExplicitEndpoint,
        socialname_protocol::EvidenceClass::E4StructuredIdentity => {
            EvidenceClass::E4StructuredIdentity
        }
    }
}

const fn managed_uncertainty_reason(reason: UncertaintyReason) -> SearchInconclusiveReason {
    match reason {
        UncertaintyReason::SiteChanged => SearchInconclusiveReason::SiteChanged,
        UncertaintyReason::NoRuleMatched => SearchInconclusiveReason::NoRuleMatched,
        UncertaintyReason::ConflictingEvidence => SearchInconclusiveReason::ConflictingEvidence,
        UncertaintyReason::ClassificationAmbiguous => {
            SearchInconclusiveReason::ClassificationAmbiguous
        }
    }
}

const fn managed_refresh_state(policy: &SearchPolicy) -> RefreshState {
    if matches!(policy.source, SearchSource::Hybrid) {
        RefreshState::Completed
    } else {
        RefreshState::NotRequested
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
    #[error("invalid source/sync policy: {0}")]
    InvalidPolicy(String),
    #[error("managed API access is required for this source/sync policy")]
    MissingManagedAccess,
    #[error("managed API access must not be supplied for a device-only policy")]
    UnexpectedManagedAccess,
    #[error("managed search failed: {0}")]
    ManagedSearch(#[from] ManagedSearchClientError),
    #[error("managed search returned an event outside the requested target set")]
    ManagedTarget,
    #[error("managed search returned more than one terminal result for a target")]
    DuplicateManagedTarget,
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[derive(Debug, Default)]
    struct FoundExecutor {
        calls: AtomicUsize,
    }

    impl LocalSearchExecutor for FoundExecutor {
        fn search<'a>(
            &'a self,
            rule: &'a CompiledSiteRule,
            username: &'a str,
        ) -> BoxFuture<'a, SearchResult> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let result = SearchResult {
                site_id: rule.source.id.clone(),
                username: username.to_owned(),
                profile_url: Some(format!("https://example.test/{username}")),
                rule_hash: rule.rule_hash.clone(),
                classification: socialname_engine::Classification {
                    verdict: Verdict::Found,
                    inconclusive_reason: None,
                    evidence_class: EvidenceClass::E4StructuredIdentity,
                    matcher_trace: Vec::new(),
                    evidence_digest: "3".repeat(64),
                },
                probes: Vec::new(),
            };
            Box::pin(async move { result })
        }
    }

    #[derive(Debug, Default)]
    struct NeverExecutor {
        calls: AtomicUsize,
    }

    impl LocalSearchExecutor for NeverExecutor {
        fn search<'a>(
            &'a self,
            _rule: &'a CompiledSiteRule,
            _username: &'a str,
        ) -> BoxFuture<'a, SearchResult> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Box::pin(std::future::pending())
        }
    }

    async fn cache_ready_core() -> AppCore {
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
        core
    }

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
            managed_access: None,
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
            managed_access: None,
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

    #[test]
    fn managed_result_mapping_preserves_origin_health_and_policy() {
        let core = AppCore::from_embedded_rules().unwrap();
        let rule = core
            .rules
            .iter()
            .find(|rule| rule.source.id == "github")
            .unwrap()
            .clone();
        let rules = BTreeMap::from([("github".to_owned(), rule)]);
        let result = ManagedDefinitiveResult {
            observation_id: socialname_protocol::ObservationId::new("observation_1").unwrap(),
            target: socialname_protocol::Target {
                username: socialname_protocol::Username::new("octocat").unwrap(),
                site_id: socialname_protocol::SiteId::new("github").unwrap(),
            },
            verdict: DefinitiveVerdict::Found,
            source: ProtocolResultSource::ManagedProbe,
            freshness: socialname_protocol::Freshness::new(1_000, 10_000, 2_000, 86_400_000)
                .unwrap(),
            evidence_class: socialname_protocol::EvidenceClass::E4StructuredIdentity,
            evidence_digest: socialname_protocol::EvidenceDigest::new("a".repeat(64)).unwrap(),
            region_class: socialname_protocol::RegionClass::new("jp").unwrap(),
            rule_hash: socialname_protocol::RuleHash::new("b".repeat(64)).unwrap(),
            rule_health: RuleHealthStatus::Healthy,
            profile_url: Some(
                socialname_protocol::HttpsUrl::new("https://github.com/octocat").unwrap(),
            ),
        };
        let policy = SearchPolicy {
            source: SearchSource::Remote,
            sync: SyncPolicy::Private,
            region_class: "jp".to_owned(),
            maximum_age_ms: 86_400_000,
        };
        let mapped = AppCore::managed_definitive_result(
            &rules,
            &BTreeMap::new(),
            "octocat",
            &policy,
            result,
        )
        .unwrap();

        assert_eq!(mapped.source, ResultSource::ManagedProbe);
        assert_eq!(mapped.requested_source, SearchSource::Remote);
        assert_eq!(mapped.sync, SyncPolicy::Private);
        assert_eq!(mapped.rule_health, Some(SearchResultRuleHealth::Healthy));
        assert_eq!(mapped.observations.len(), 1);
        assert_eq!(mapped.observations[0].source, ResultSource::ManagedProbe);
        assert!(mapped.operational_failure.is_none());

        let mut failed_with_prior_evidence = mapped;
        failed_with_prior_evidence.status = SearchStatus::OperationalFailure;
        failed_with_prior_evidence.operational_failure = Some(ManagedOperationalFailureView {
            kind: socialname_protocol::OperationalFailureKind::CapacityUnavailable,
            occurred_at_unix_ms: 2_100,
            retryable: true,
            region_class: Some("jp".to_owned()),
        });
        let mut summary = SearchCompletion::new(1);
        summary.record(&failed_with_prior_evidence);
        assert_eq!(summary.unavailable, 1);
        assert_eq!(summary.found, 0);
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
                    managed_access: None,
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
        assert_eq!(result.source, ResultSource::Cache);
        assert_eq!(result.status, SearchStatus::RuleNotPromoted);
        assert_eq!(result.refresh_state, RefreshState::NotRequested);
        assert!(result.live_result.is_none());
        assert!(result.observations.is_empty());
    }

    #[tokio::test]
    async fn cache_source_returns_the_full_eligible_observation_set_as_cached() {
        let core = cache_ready_core().await;

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
                    managed_access: None,
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
        assert!(result.observations.iter().all(|observation| {
            observation.source == ResultSource::Cache && observation.cached_at_unix_ms.is_some()
        }));
    }

    #[tokio::test]
    async fn hybrid_streams_cached_observations_before_the_local_refresh() {
        let mut core = cache_ready_core().await;
        let executor = Arc::new(FoundExecutor::default());
        core.local_executor = executor.clone();
        let events = std::sync::Mutex::new(Vec::new());

        let summary = core
            .run_search_at(
                SearchRequest {
                    username: "octocat".to_owned(),
                    site_ids: vec!["github".to_owned()],
                    allow_discovery: false,
                    policy: SearchPolicy {
                        source: SearchSource::Hybrid,
                        ..SearchPolicy::default()
                    },
                    managed_access: None,
                },
                CancellationToken::new(),
                1_500,
                |event| events.lock().unwrap().push(event),
            )
            .await
            .unwrap();

        assert_eq!(executor.calls.load(Ordering::Relaxed), 1);
        assert_eq!(summary.completed, 1);
        assert_eq!(summary.found, 1);
        let events = events.into_inner().unwrap();
        assert_eq!(events.len(), 4);
        let SearchEvent::Result { result: cached } = &events[1] else {
            panic!("expected cached intermediate result");
        };
        assert_eq!(cached.source, ResultSource::Cache);
        assert_eq!(cached.requested_source, SearchSource::Hybrid);
        assert_eq!(cached.refresh_state, RefreshState::Pending);
        assert_eq!(cached.observations.len(), 2);
        assert!(cached.live_result.is_none());

        let SearchEvent::Result { result: refreshed } = &events[2] else {
            panic!("expected local refresh result");
        };
        assert_eq!(refreshed.source, ResultSource::Local);
        assert_eq!(refreshed.requested_source, SearchSource::Hybrid);
        assert_eq!(refreshed.refresh_state, RefreshState::Completed);
        assert_eq!(refreshed.observations.len(), 3);
        assert_eq!(
            refreshed
                .observations
                .iter()
                .filter(|observation| observation.source == ResultSource::Cache)
                .count(),
            2
        );
        assert_eq!(
            refreshed
                .observations
                .iter()
                .filter(|observation| observation.source == ResultSource::Local)
                .count(),
            1
        );
        assert!(refreshed.live_result.is_some());
    }

    #[tokio::test]
    async fn cancellation_after_cached_phase_retains_cache_without_a_local_result() {
        let mut core = cache_ready_core().await;
        let executor = Arc::new(NeverExecutor::default());
        core.local_executor = executor.clone();
        let cancellation = CancellationToken::new();
        let cancel_on_cache = cancellation.clone();
        let events = std::sync::Mutex::new(Vec::new());

        let summary = core
            .run_search_at(
                SearchRequest {
                    username: "octocat".to_owned(),
                    site_ids: vec!["github".to_owned()],
                    allow_discovery: false,
                    policy: SearchPolicy {
                        source: SearchSource::Hybrid,
                        ..SearchPolicy::default()
                    },
                    managed_access: None,
                },
                cancellation,
                1_500,
                |event| {
                    if matches!(
                        &event,
                        SearchEvent::Result { result }
                            if result.source == ResultSource::Cache
                                && result.refresh_state == RefreshState::Pending
                    ) {
                        cancel_on_cache.cancel();
                    }
                    events.lock().unwrap().push(event);
                },
            )
            .await
            .unwrap();

        assert!(summary.cancelled);
        assert_eq!(summary.completed, 0);
        assert_eq!(executor.calls.load(Ordering::Relaxed), 0);
        let events = events.into_inner().unwrap();
        assert_eq!(events.len(), 3);
        assert!(matches!(
            &events[1],
            SearchEvent::Result { result }
                if result.source == ResultSource::Cache
                    && result.refresh_state == RefreshState::Pending
        ));
        assert!(matches!(&events[2], SearchEvent::Finished { .. }));
    }

    #[tokio::test]
    async fn managed_failure_marks_the_emitted_cache_phase_failed() {
        let core = cache_ready_core().await;
        let events = std::sync::Mutex::new(Vec::new());
        let result = core
            .run_search_at(
                SearchRequest {
                    username: "octocat".to_owned(),
                    site_ids: vec!["github".to_owned()],
                    allow_discovery: false,
                    policy: SearchPolicy {
                        source: SearchSource::Hybrid,
                        sync: SyncPolicy::Private,
                        ..SearchPolicy::default()
                    },
                    managed_access: Some(ManagedSearchAccess {
                        api_url: "http://api.example.test".to_owned(),
                        api_key: "test-key".to_owned(),
                        consent_grant_id: "grant_1".to_owned(),
                    }),
                },
                CancellationToken::new(),
                1_500,
                |event| events.lock().unwrap().push(event),
            )
            .await;

        assert!(matches!(
            result,
            Err(AppCoreError::ManagedSearch(
                ManagedSearchClientError::InvalidApiUrl
            ))
        ));
        let events = events.into_inner().unwrap();
        assert_eq!(events.len(), 3);
        assert!(matches!(
            &events[1],
            SearchEvent::Result { result }
                if result.refresh_state == RefreshState::Pending
        ));
        assert!(matches!(
            &events[2],
            SearchEvent::Result { result }
                if result.refresh_state == RefreshState::Failed
        ));
    }
}
