use std::{
    collections::BTreeSet,
    future::Future,
    pin::Pin,
    time::{Duration, Instant},
};

use futures_util::{StreamExt, stream};
use rand::{Rng, RngExt};
use serde::Serialize;
use socialname_domain::{EvidenceClass, InconclusiveReason, Verdict};
use socialname_engine::{ProbeSummary, SearchEngine, SearchResult};
use socialname_rule_compiler::CompiledSiteRule;
use socialname_rule_schema::{ProbePlanSource, TransportOutcome};
use tokio_util::sync::CancellationToken;

use crate::{CompiledCanaryManifest, NegativeAlphabet};

const MAX_CONCURRENCY: usize = 32;
const MAX_REQUESTS: usize = 1_024;
const MAX_ELAPSED_MS: u64 = 15 * 60 * 1_000;
const MAX_RESPONSE_BYTES: usize = 256 * 1_024 * 1_024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DeclaredVantage {
    pub region: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct CanaryRunBudget {
    pub max_requests: usize,
    pub max_concurrency: usize,
    pub max_elapsed_ms: u64,
    pub max_response_bytes: usize,
}

impl Default for CanaryRunBudget {
    fn default() -> Self {
        Self {
            max_requests: 64,
            max_concurrency: 4,
            max_elapsed_ms: 2 * 60 * 1_000,
            max_response_bytes: 16 * 1_024 * 1_024,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CanaryCaseExpectation {
    Found,
    NotFound,
}

impl CanaryCaseExpectation {
    const fn verdict(self) -> Verdict {
        match self {
            Self::Found => Verdict::Found,
            Self::NotFound => Verdict::NotFound,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CanaryProbeSummary {
    pub probe_id: String,
    pub transport: TransportOutcome,
    pub status: Option<u16>,
    pub content_type: Option<String>,
    pub body_bytes: usize,
    pub body_truncated: bool,
    pub elapsed_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CanaryCaseOutcome {
    pub case_id: String,
    pub expectation: CanaryCaseExpectation,
    pub verdict: Verdict,
    pub matched_expectation: bool,
    pub inconclusive_reason: Option<InconclusiveReason>,
    pub evidence_class: EvidenceClass,
    pub evidence_digest: String,
    pub probes: Vec<CanaryProbeSummary>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CanaryRunCompletion {
    Complete,
    Cancelled,
    TimeBudgetExceeded,
    RequestBudgetExceeded,
    ResponseByteBudgetExceeded,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CanaryRun {
    pub site_id: String,
    pub manifest_hash: String,
    pub rule_hash: String,
    pub vantage: DeclaredVantage,
    pub completion: CanaryRunCompletion,
    pub planned_requests: usize,
    pub completed_requests: usize,
    pub completed_response_bytes: usize,
    pub elapsed_ms: u64,
    pub outcomes: Vec<CanaryCaseOutcome>,
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum CanaryRunError {
    #[error("failed to initialize the production search engine: {0}")]
    EngineInitialization(String),
    #[error("declared vantage region is invalid")]
    InvalidVantage,
    #[error("canary run budget is invalid")]
    InvalidBudget,
    #[error("manifest site does not match the selected rule")]
    SiteMismatch,
    #[error("manifest was not validated against the selected rule hash")]
    RuleHashMismatch,
    #[error("planned request count {planned} exceeds budget {maximum}")]
    PlannedRequestsExceedBudget { planned: usize, maximum: usize },
    #[error("planned inspected bytes {planned} exceed budget {maximum}")]
    PlannedResponseBytesExceedBudget { planned: usize, maximum: usize },
    #[error(
        "negative canary generation exhausted its bounded attempts after producing {generated} of {required} controls"
    )]
    NegativeGenerationExhausted { generated: usize, required: usize },
}

pub trait CanaryProbe: Send + Sync {
    fn search<'a>(
        &'a self,
        rule: &'a CompiledSiteRule,
        username: &'a str,
    ) -> Pin<Box<dyn Future<Output = SearchResult> + Send + 'a>>;
}

impl CanaryProbe for SearchEngine {
    fn search<'a>(
        &'a self,
        rule: &'a CompiledSiteRule,
        username: &'a str,
    ) -> Pin<Box<dyn Future<Output = SearchResult> + Send + 'a>> {
        Box::pin(async move { SearchEngine::search(self, rule, username).await })
    }
}

#[derive(Clone, Debug)]
pub struct CanaryRunner<P> {
    probe: P,
}

impl<P> CanaryRunner<P> {
    #[must_use]
    pub const fn new(probe: P) -> Self {
        Self { probe }
    }
}

impl CanaryRunner<SearchEngine> {
    pub fn production() -> Result<Self, CanaryRunError> {
        SearchEngine::new()
            .map(Self::new)
            .map_err(|error| CanaryRunError::EngineInitialization(error.to_string()))
    }
}

impl<P: CanaryProbe> CanaryRunner<P> {
    pub async fn run(
        &self,
        rule: &CompiledSiteRule,
        manifest: &CompiledCanaryManifest,
        vantage: DeclaredVantage,
        budget: CanaryRunBudget,
        cancellation: &CancellationToken,
    ) -> Result<CanaryRun, CanaryRunError> {
        validate_run_inputs(rule, manifest, &vantage, budget)?;
        let cases = {
            let mut rng = rand::rng();
            build_cases(rule, manifest, &mut rng)?
        };
        self.run_cases(rule, manifest, vantage, budget, cancellation, cases)
            .await
    }

    #[cfg(test)]
    async fn run_with_rng<R: Rng + ?Sized>(
        &self,
        rule: &CompiledSiteRule,
        manifest: &CompiledCanaryManifest,
        vantage: DeclaredVantage,
        budget: CanaryRunBudget,
        cancellation: &CancellationToken,
        rng: &mut R,
    ) -> Result<CanaryRun, CanaryRunError> {
        validate_run_inputs(rule, manifest, &vantage, budget)?;
        let cases = build_cases(rule, manifest, rng)?;
        self.run_cases(rule, manifest, vantage, budget, cancellation, cases)
            .await
    }

    async fn run_cases(
        &self,
        rule: &CompiledSiteRule,
        manifest: &CompiledCanaryManifest,
        vantage: DeclaredVantage,
        budget: CanaryRunBudget,
        cancellation: &CancellationToken,
        cases: Vec<CanaryCase>,
    ) -> Result<CanaryRun, CanaryRunError> {
        let requests_per_case = maximum_requests_per_search(rule);
        let planned_requests = cases
            .len()
            .checked_mul(requests_per_case)
            .ok_or(CanaryRunError::InvalidBudget)?;
        if planned_requests > budget.max_requests {
            return Err(CanaryRunError::PlannedRequestsExceedBudget {
                planned: planned_requests,
                maximum: budget.max_requests,
            });
        }

        let response_bytes_per_case = maximum_inspected_bytes_per_search(rule);
        let planned_response_bytes = cases
            .len()
            .checked_mul(response_bytes_per_case)
            .ok_or(CanaryRunError::InvalidBudget)?;
        if planned_response_bytes > budget.max_response_bytes {
            return Err(CanaryRunError::PlannedResponseBytesExceedBudget {
                planned: planned_response_bytes,
                maximum: budget.max_response_bytes,
            });
        }

        let start = Instant::now();
        let searches = stream::iter(cases.into_iter().enumerate())
            .map(|(index, case)| async move {
                let result = self.probe.search(rule, &case.username).await;
                completed_case(index, case, result)
            })
            .buffer_unordered(budget.max_concurrency);
        tokio::pin!(searches);
        let deadline = tokio::time::sleep(Duration::from_millis(budget.max_elapsed_ms));
        tokio::pin!(deadline);

        let mut completion = CanaryRunCompletion::Complete;
        let mut completed_requests = 0_usize;
        let mut completed_response_bytes = 0_usize;
        let mut indexed_outcomes = Vec::new();

        loop {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => {
                    completion = CanaryRunCompletion::Cancelled;
                    break;
                }
                _ = &mut deadline => {
                    completion = CanaryRunCompletion::TimeBudgetExceeded;
                    break;
                }
                next = searches.next() => {
                    let Some(completed) = next else {
                        break;
                    };
                    completed_requests = completed_requests.saturating_add(completed.requests);
                    completed_response_bytes =
                        completed_response_bytes.saturating_add(completed.response_bytes);
                    indexed_outcomes.push((completed.index, completed.outcome));
                    if completed_requests > budget.max_requests {
                        completion = CanaryRunCompletion::RequestBudgetExceeded;
                        break;
                    }
                    if completed_response_bytes > budget.max_response_bytes {
                        completion = CanaryRunCompletion::ResponseByteBudgetExceeded;
                        break;
                    }
                }
            }
        }

        indexed_outcomes.sort_by_key(|(index, _)| *index);
        Ok(CanaryRun {
            site_id: rule.source.id.clone(),
            manifest_hash: manifest.manifest_hash.clone(),
            rule_hash: rule.rule_hash.clone(),
            vantage,
            completion,
            planned_requests,
            completed_requests,
            completed_response_bytes,
            elapsed_ms: duration_ms(start.elapsed()),
            outcomes: indexed_outcomes
                .into_iter()
                .map(|(_, outcome)| outcome)
                .collect(),
        })
    }
}

#[derive(Clone, Debug)]
struct CanaryCase {
    id: String,
    username: String,
    expectation: CanaryCaseExpectation,
}

#[derive(Clone, Debug)]
struct CompletedCase {
    index: usize,
    outcome: CanaryCaseOutcome,
    requests: usize,
    response_bytes: usize,
}

fn build_cases<R: Rng + ?Sized>(
    rule: &CompiledSiteRule,
    manifest: &CompiledCanaryManifest,
    rng: &mut R,
) -> Result<Vec<CanaryCase>, CanaryRunError> {
    let mut cases: Vec<_> = manifest
        .source
        .positive
        .iter()
        .map(|positive| CanaryCase {
            id: positive.id.clone(),
            username: positive.username.clone(),
            expectation: CanaryCaseExpectation::Found,
        })
        .collect();
    let mut used_usernames: BTreeSet<_> = cases.iter().map(|case| case.username.clone()).collect();
    let generator = &manifest.source.negative.generator;
    let alphabet = match generator.alphabet {
        NegativeAlphabet::LowercaseAlnum => b"abcdefghijklmnopqrstuvwxyz0123456789".as_slice(),
        NegativeAlphabet::Lowercase => b"abcdefghijklmnopqrstuvwxyz".as_slice(),
    };

    for index in 0..generator.count {
        let mut accepted = None;
        for _ in 0..generator.attempts_per_candidate {
            let random: String = (0..generator.random_length)
                .map(|_| {
                    let index = rng.random_range(0..alphabet.len());
                    char::from(alphabet[index])
                })
                .collect();
            let candidate = format!("{random}{}", generator.suffix);
            if rule.normalize_username(&candidate).as_deref() == Some(candidate.as_str())
                && used_usernames.insert(candidate.clone())
            {
                accepted = Some(candidate);
                break;
            }
        }
        let Some(username) = accepted else {
            return Err(CanaryRunError::NegativeGenerationExhausted {
                generated: index,
                required: generator.count,
            });
        };
        cases.push(CanaryCase {
            id: format!("generated-negative-{:03}", index + 1),
            username,
            expectation: CanaryCaseExpectation::NotFound,
        });
    }
    Ok(cases)
}

fn validate_run_inputs(
    rule: &CompiledSiteRule,
    manifest: &CompiledCanaryManifest,
    vantage: &DeclaredVantage,
    budget: CanaryRunBudget,
) -> Result<(), CanaryRunError> {
    if manifest.source.site_id != rule.source.id {
        return Err(CanaryRunError::SiteMismatch);
    }
    if manifest.validated_rule_hash != rule.rule_hash {
        return Err(CanaryRunError::RuleHashMismatch);
    }
    if !valid_region(&vantage.region) {
        return Err(CanaryRunError::InvalidVantage);
    }
    if budget.max_requests == 0
        || budget.max_requests > MAX_REQUESTS
        || budget.max_concurrency == 0
        || budget.max_concurrency > MAX_CONCURRENCY
        || budget.max_elapsed_ms == 0
        || budget.max_elapsed_ms > MAX_ELAPSED_MS
        || budget.max_response_bytes == 0
        || budget.max_response_bytes > MAX_RESPONSE_BYTES
    {
        return Err(CanaryRunError::InvalidBudget);
    }
    Ok(())
}

fn valid_region(value: &str) -> bool {
    let mut characters = value.chars();
    matches!(characters.next(), Some('a'..='z' | '0'..='9'))
        && value.len() <= 64
        && characters.all(|character| matches!(character, 'a'..='z' | '0'..='9' | '-'))
}

fn maximum_requests_per_search(rule: &CompiledSiteRule) -> usize {
    match &rule.source.plan {
        ProbePlanSource::Single { .. } => 1,
        ProbePlanSource::Fallback { .. } => 2,
        ProbePlanSource::ParallelAll { probes } => probes.len(),
    }
}

fn maximum_inspected_bytes_per_search(rule: &CompiledSiteRule) -> usize {
    let probe_limit = |probe_id: &str| {
        rule.probe_index
            .get(probe_id)
            .and_then(|index| rule.source.probes.get(*index))
            .map_or(0, |probe| probe.http.limits.inspected_bytes)
    };
    match &rule.source.plan {
        ProbePlanSource::Single { probe } => probe_limit(probe),
        ProbePlanSource::Fallback {
            primary, fallback, ..
        } => probe_limit(primary).saturating_add(probe_limit(fallback)),
        ProbePlanSource::ParallelAll { probes } => probes
            .iter()
            .map(|probe| probe_limit(probe))
            .fold(0_usize, usize::saturating_add),
    }
}

fn completed_case(index: usize, case: CanaryCase, result: SearchResult) -> CompletedCase {
    let requests = result.probes.len();
    let response_bytes = result
        .probes
        .iter()
        .map(|probe| probe.body_bytes)
        .fold(0_usize, usize::saturating_add);
    let probes = result
        .probes
        .into_iter()
        .map(sanitize_probe_summary)
        .collect();
    CompletedCase {
        index,
        outcome: CanaryCaseOutcome {
            case_id: case.id,
            expectation: case.expectation,
            verdict: result.classification.verdict,
            matched_expectation: result.classification.verdict == case.expectation.verdict(),
            inconclusive_reason: result.classification.inconclusive_reason,
            evidence_class: result.classification.evidence_class,
            evidence_digest: result.classification.evidence_digest,
            probes,
        },
        requests,
        response_bytes,
    }
}

fn sanitize_probe_summary(probe: ProbeSummary) -> CanaryProbeSummary {
    CanaryProbeSummary {
        probe_id: probe.probe_id,
        transport: probe.transport,
        status: probe.status,
        content_type: probe.content_type,
        body_bytes: probe.body_bytes,
        body_truncated: probe.body_truncated,
        elapsed_ms: probe.elapsed_ms,
    }
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use chrono::{TimeZone, Utc};
    use rand::{SeedableRng, rngs::StdRng};
    use socialname_engine::Classification;
    use socialname_rule_compiler::RuleCompiler;

    use crate::CanaryManifestCompiler;

    use super::*;

    const VALID_RULE: &str = r#"
schema: socialname.dev/site/v1
id: example
name: Example
homepage: https://example.test/
profile_url: https://example.test/u/{username:path}
namespace: person
username:
  pattern: '^[a-z][a-z0-9]{2,31}$'
  case_sensitive: false
  normalization: lowercase
probes:
  - id: profile
    http:
      method: GET
      url: https://example.test/u/{username:path}
      allowed_hosts: [example.test]
      expected_body: json
      limits:
        inspected_bytes: 1024
plan:
  type: single
  probe: profile
classification:
  found:
    status:
      probe: profile
      in: [200]
  not_found:
    status:
      probe: profile
      in: [404]
metadata:
  enabled: false
"#;

    const VALID_MANIFEST: &str = r#"
schema: socialname.dev/canary-manifest/v1
site_id: example
issued_at: 2026-07-25T00:00:00Z
expires_at: 2026-08-01T00:00:00Z
positive:
  - id: platform
    username: alpha
    kind: platform_official
    reviewed_at: 2026-07-24T00:00:00Z
    evidence_url: https://example.test/u/alpha
  - id: project
    username: bravo
    kind: project_controlled
    reviewed_at: 2026-07-24T00:00:00Z
    evidence_url: https://example.test/u/bravo
  - id: stable-one
    username: charlie
    kind: long_lived_public
    reviewed_at: 2026-07-24T00:00:00Z
    evidence_url: https://example.test/u/charlie
  - id: stable-two
    username: delta
    kind: long_lived_public
    reviewed_at: 2026-07-24T00:00:00Z
    evidence_url: https://example.test/u/delta
  - id: stable-three
    username: echo
    kind: long_lived_public
    reviewed_at: 2026-07-24T00:00:00Z
    evidence_url: https://example.test/u/echo
negative:
  generator:
    alphabet: lowercase_alnum
    random_length: 20
    count: 5
    attempts_per_candidate: 3
"#;

    #[derive(Clone, Debug)]
    struct FakeProbe {
        calls: Arc<AtomicUsize>,
        delay: Duration,
        body_bytes: usize,
    }

    impl FakeProbe {
        fn immediate() -> Self {
            Self {
                calls: Arc::new(AtomicUsize::new(0)),
                delay: Duration::ZERO,
                body_bytes: 10,
            }
        }
    }

    impl CanaryProbe for FakeProbe {
        fn search<'a>(
            &'a self,
            rule: &'a CompiledSiteRule,
            username: &'a str,
        ) -> Pin<Box<dyn Future<Output = SearchResult> + Send + 'a>> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                if !self.delay.is_zero() {
                    tokio::time::sleep(self.delay).await;
                }
                let verdict = if username.len() < 10 {
                    Verdict::Found
                } else {
                    Verdict::NotFound
                };
                SearchResult {
                    site_id: rule.source.id.clone(),
                    username: username.to_owned(),
                    profile_url: Some(format!("https://example.test/u/{username}")),
                    rule_hash: rule.rule_hash.clone(),
                    classification: Classification {
                        verdict,
                        inconclusive_reason: None,
                        evidence_class: EvidenceClass::E4StructuredIdentity,
                        matcher_trace: Vec::new(),
                        evidence_digest: format!("digest-{}", username.len()),
                    },
                    probes: vec![ProbeSummary {
                        probe_id: "profile".to_owned(),
                        transport: TransportOutcome::Completed,
                        status: Some(if verdict == Verdict::Found { 200 } else { 404 }),
                        final_url: Some(format!("https://example.test/u/{username}")),
                        content_type: Some("application/json".to_owned()),
                        body_bytes: self.body_bytes,
                        body_truncated: false,
                        elapsed_ms: 1,
                    }],
                }
            })
        }
    }

    fn validation_time() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 25, 12, 0, 0)
            .single()
            .expect("test timestamp is valid")
    }

    fn rule_and_manifest() -> (CompiledSiteRule, CompiledCanaryManifest) {
        let rule = RuleCompiler::new()
            .compile_yaml(VALID_RULE, Some("example"))
            .expect("test rule compiles");
        let manifest = CanaryManifestCompiler::new()
            .compile_yaml_at(VALID_MANIFEST, &rule, Some("example"), validation_time())
            .expect("test manifest compiles");
        (rule, manifest)
    }

    fn vantage() -> DeclaredVantage {
        DeclaredVantage {
            region: "test-region-1".to_owned(),
        }
    }

    #[tokio::test]
    async fn runs_positive_and_generated_negative_cases_with_bounded_probe_data() {
        let (rule, manifest) = rule_and_manifest();
        let probe = FakeProbe::immediate();
        let calls = Arc::clone(&probe.calls);
        let runner = CanaryRunner::new(probe);
        let mut rng = StdRng::seed_from_u64(7);

        let run = runner
            .run_with_rng(
                &rule,
                &manifest,
                vantage(),
                CanaryRunBudget::default(),
                &CancellationToken::new(),
                &mut rng,
            )
            .await
            .unwrap();

        assert_eq!(run.completion, CanaryRunCompletion::Complete);
        assert_eq!(run.planned_requests, 10);
        assert_eq!(run.completed_requests, 10);
        assert_eq!(run.completed_response_bytes, 100);
        assert_eq!(run.outcomes.len(), 10);
        assert!(
            run.outcomes
                .iter()
                .all(|outcome| outcome.matched_expectation)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 10);
        assert!(
            run.outcomes
                .iter()
                .flat_map(|outcome| &outcome.probes)
                .all(|probe| probe.content_type.as_deref() == Some("application/json"))
        );
    }

    #[tokio::test]
    async fn rejects_request_budget_before_network_work() {
        let (rule, manifest) = rule_and_manifest();
        let probe = FakeProbe::immediate();
        let calls = Arc::clone(&probe.calls);
        let runner = CanaryRunner::new(probe);
        let mut rng = StdRng::seed_from_u64(7);
        let budget = CanaryRunBudget {
            max_requests: 9,
            ..CanaryRunBudget::default()
        };

        let error = runner
            .run_with_rng(
                &rule,
                &manifest,
                vantage(),
                budget,
                &CancellationToken::new(),
                &mut rng,
            )
            .await
            .unwrap_err();

        assert_eq!(
            error,
            CanaryRunError::PlannedRequestsExceedBudget {
                planned: 10,
                maximum: 9
            }
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn rejects_inspected_byte_budget_before_network_work() {
        let (rule, manifest) = rule_and_manifest();
        let probe = FakeProbe::immediate();
        let calls = Arc::clone(&probe.calls);
        let runner = CanaryRunner::new(probe);
        let mut rng = StdRng::seed_from_u64(7);
        let budget = CanaryRunBudget {
            max_response_bytes: 10 * 1_024 - 1,
            ..CanaryRunBudget::default()
        };

        let error = runner
            .run_with_rng(
                &rule,
                &manifest,
                vantage(),
                budget,
                &CancellationToken::new(),
                &mut rng,
            )
            .await
            .unwrap_err();

        assert_eq!(
            error,
            CanaryRunError::PlannedResponseBytesExceedBudget {
                planned: 10 * 1_024,
                maximum: 10 * 1_024 - 1
            }
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn cancellation_returns_a_partial_run_without_starting_more_work() {
        let (rule, manifest) = rule_and_manifest();
        let probe = FakeProbe::immediate();
        let calls = Arc::clone(&probe.calls);
        let runner = CanaryRunner::new(probe);
        let mut rng = StdRng::seed_from_u64(7);
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        let run = runner
            .run_with_rng(
                &rule,
                &manifest,
                vantage(),
                CanaryRunBudget::default(),
                &cancellation,
                &mut rng,
            )
            .await
            .unwrap();

        assert_eq!(run.completion, CanaryRunCompletion::Cancelled);
        assert!(run.outcomes.is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn time_budget_returns_a_partial_run_and_drops_pending_probes() {
        let (rule, manifest) = rule_and_manifest();
        let probe = FakeProbe {
            calls: Arc::new(AtomicUsize::new(0)),
            delay: Duration::from_millis(50),
            body_bytes: 10,
        };
        let runner = CanaryRunner::new(probe);
        let mut rng = StdRng::seed_from_u64(7);
        let budget = CanaryRunBudget {
            max_elapsed_ms: 1,
            max_concurrency: 1,
            ..CanaryRunBudget::default()
        };

        let run = runner
            .run_with_rng(
                &rule,
                &manifest,
                vantage(),
                budget,
                &CancellationToken::new(),
                &mut rng,
            )
            .await
            .unwrap();

        assert_eq!(run.completion, CanaryRunCompletion::TimeBudgetExceeded);
        assert!(run.outcomes.is_empty());
    }

    #[tokio::test]
    async fn refuses_a_rule_hash_other_than_the_one_validated() {
        let (rule, mut manifest) = rule_and_manifest();
        manifest.validated_rule_hash = "different-rule".to_owned();
        let runner = CanaryRunner::new(FakeProbe::immediate());
        let mut rng = StdRng::seed_from_u64(7);

        let error = runner
            .run_with_rng(
                &rule,
                &manifest,
                vantage(),
                CanaryRunBudget::default(),
                &CancellationToken::new(),
                &mut rng,
            )
            .await
            .unwrap_err();

        assert_eq!(error, CanaryRunError::RuleHashMismatch);
    }
}
