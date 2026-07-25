#![forbid(unsafe_code)]

mod source_policy;

use std::{collections::BTreeSet, sync::Arc};

use futures_util::{StreamExt, stream};
use serde::{Deserialize, Serialize};
use socialname_domain::{EvidenceClass, InconclusiveReason, Verdict};
use socialname_engine::{MatcherTrace, ProbeSummary, SearchEngine, SearchResult};
use socialname_rule_compiler::{CompiledSiteRule, RuleCompiler};
use socialname_rule_schema::AccountNamespace;
use tokio_util::sync::CancellationToken;

pub use source_policy::{
    DEFAULT_MAXIMUM_AGE_MS, DEFAULT_REGION_CLASS, RefreshState, SearchPolicy, SearchRuleHealth,
    SearchSource, SearchStatus, SyncPolicy,
};

const MAX_SELECTED_SITES: usize = 64;
const MAX_USERNAME_BYTES: usize = 256;
const MAX_CONCURRENT_PROBES: usize = 8;

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
            cancelled: false,
        }
    }

    fn record(&mut self, verdict: Verdict) {
        self.completed += 1;
        match verdict {
            Verdict::Found => self.found += 1,
            Verdict::NotFound => self.not_found += 1,
            Verdict::Inconclusive => self.inconclusive += 1,
            Verdict::InvalidUsername => self.invalid_username += 1,
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
    pub source: String,
    pub profile_url: Option<String>,
    pub rule_hash: String,
    pub verdict: Verdict,
    pub inconclusive_reason: Option<InconclusiveReason>,
    pub evidence_class: EvidenceClass,
    pub evidence_digest: String,
    pub matcher_trace: Vec<MatcherTraceView>,
    pub probes: Vec<ProbeSummaryView>,
}

impl SearchResultView {
    fn from_engine(site_name: String, result: SearchResult) -> Self {
        Self {
            site_id: result.site_id,
            site_name,
            username: result.username,
            source: "local_probe".to_owned(),
            profile_url: result.profile_url,
            rule_hash: result.rule_hash,
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

#[derive(Clone, Debug)]
pub struct AppCore {
    rules: Arc<Vec<Arc<CompiledSiteRule>>>,
    engine: SearchEngine,
    rule_pack_hash: String,
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
        })
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
        let username = request.username.trim().to_owned();
        let selected = self.select_rules(&request)?;
        let mut summary = SearchCompletion::new(selected.len());
        on_event(SearchEvent::Started {
            total: selected.len(),
        });

        let engine = &self.engine;
        let mut pending = stream::iter(selected.into_iter().map(|rule| {
            let cancellation = cancellation.clone();
            let username = username.clone();
            async move {
                tokio::select! {
                    biased;
                    () = cancellation.cancelled() => None,
                    result = engine.search(&rule, &username) => {
                        Some(SearchResultView::from_engine(rule.source.name.clone(), result))
                    }
                }
            }
        }))
        .buffer_unordered(MAX_CONCURRENT_PROBES);

        while let Some(result) = pending.next().await {
            if let Some(result) = result {
                summary.record(result.verdict);
                on_event(SearchEvent::Result { result });
            }
        }
        summary.cancelled = cancellation.is_cancelled();
        on_event(SearchEvent::Finished {
            summary: summary.clone(),
        });
        Ok(summary)
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
            if !rule.source.metadata.enabled && !request.allow_discovery {
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
                cancelled: false,
            },
        })
        .unwrap();
        assert_eq!(finished["event"], "finished");
        assert_eq!(finished["data"]["summary"]["notFound"], 0);
        assert_eq!(finished["data"]["summary"]["invalidUsername"], 0);
    }
}
