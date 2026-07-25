use std::{
    collections::{BTreeSet, HashSet},
    time::{Duration, Instant},
};

use chrono::{DateTime, Utc};
use futures_util::{StreamExt, stream};
use rand::{Rng, RngExt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use socialname_domain::{InconclusiveReason, Verdict};
use socialname_rule_compiler::CompiledSiteRule;
use tokio_util::sync::CancellationToken;

use crate::{
    CANARY_REPORT_V1, CanaryCaseExpectation, CanaryRatio, CanaryReportBuilder,
    CanaryReportEnvelope, CanaryReportError, CanaryReportPolicy, CanaryReportValidator, CanaryRun,
    CanaryRunBudget, CanaryRunCompletion, CanaryRunError, CanaryRunner, CompiledCanaryManifest,
    DeclaredVantage, NegativeAlphabet, ValidatedCanaryReport,
    runner::{
        CanaryCase, CanaryProbe, completed_case, maximum_inspected_bytes_per_search,
        maximum_requests_per_search, validate_run_inputs,
    },
};

pub const CANARY_SHADOW_V1: &str = "socialname.dev/canary-shadow/v1";

const MAX_SHADOW_JSON_BYTES: usize = 2 * 1_024 * 1_024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanaryShadowDisposition {
    Accepted,
    Rejected,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CanaryShadowIssue {
    CandidateBecameInconclusive {
        case_id: String,
        last_known_good: Verdict,
        reason: Option<InconclusiveReason>,
    },
    CandidateVerdictRegression {
        case_id: String,
        expected: CanaryCaseExpectation,
        candidate: Verdict,
        last_known_good: Verdict,
    },
    PrecisionRegression {
        candidate: CanaryRatio,
        last_known_good: CanaryRatio,
    },
    CoverageRegression {
        candidate: CanaryRatio,
        last_known_good: CanaryRatio,
    },
    ConflictRegression {
        candidate: u32,
        last_known_good: u32,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryShadowSummary {
    pub total_cases: u32,
    pub verdict_agreements: u32,
    pub candidate_improvements: u32,
    pub candidate_regressions: u32,
    pub candidate_precision: CanaryRatio,
    pub last_known_good_precision: CanaryRatio,
    pub candidate_conclusive_coverage: CanaryRatio,
    pub last_known_good_conclusive_coverage: CanaryRatio,
    pub candidate_conflicts: u32,
    pub last_known_good_conflicts: u32,
    pub disposition: CanaryShadowDisposition,
    pub issues: Vec<CanaryShadowIssue>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryShadowComparisonV1 {
    pub schema: String,
    pub candidate: CanaryReportEnvelope,
    pub last_known_good: CanaryReportEnvelope,
    pub summary: CanaryShadowSummary,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryShadowEnvelope {
    pub comparison_id: String,
    pub comparison: CanaryShadowComparisonV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedCanaryShadow {
    envelope: CanaryShadowEnvelope,
    candidate: ValidatedCanaryReport,
    last_known_good: ValidatedCanaryReport,
}

impl ValidatedCanaryShadow {
    #[must_use]
    pub const fn envelope(&self) -> &CanaryShadowEnvelope {
        &self.envelope
    }

    #[must_use]
    pub const fn candidate(&self) -> &ValidatedCanaryReport {
        &self.candidate
    }

    #[must_use]
    pub const fn last_known_good(&self) -> &ValidatedCanaryReport {
        &self.last_known_good
    }

    #[must_use]
    pub fn into_envelope(self) -> CanaryShadowEnvelope {
        self.envelope
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanaryShadowPolicy {
    pub site_id: String,
    pub manifest_hash: String,
    pub candidate_rule_hash: String,
    pub last_known_good_rule_hash: String,
    pub engine_hash: String,
    pub allowed_regions: BTreeSet<String>,
    pub max_planned_requests_per_rule: u32,
    pub max_completed_response_bytes_per_rule: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryShadowRun {
    pub completion: CanaryRunCompletion,
    pub candidate: CanaryRun,
    pub last_known_good: CanaryRun,
    pub planned_requests: usize,
    pub completed_requests: usize,
    pub completed_response_bytes: usize,
    pub elapsed_ms: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct CanaryShadowPair<'a> {
    pub candidate_rule: &'a CompiledSiteRule,
    pub candidate_manifest: &'a CompiledCanaryManifest,
    pub last_known_good_rule: &'a CompiledSiteRule,
    pub last_known_good_manifest: &'a CompiledCanaryManifest,
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum CanaryShadowError {
    #[error(transparent)]
    Run(#[from] CanaryRunError),
    #[error(transparent)]
    Report(#[from] CanaryReportError),
    #[error("candidate and last-known-good rule hashes must differ")]
    IdenticalRuleHashes,
    #[error("candidate and last-known-good manifests are not the same source")]
    ManifestMismatch,
    #[error("shadow run is incomplete")]
    IncompleteRun,
    #[error("shadow report JSON exceeds {maximum} bytes")]
    ReportTooLarge { maximum: usize },
    #[error("malformed shadow report JSON: {0}")]
    MalformedJson(String),
    #[error("shadow report schema is unsupported")]
    UnsupportedSchema,
    #[error("shadow comparison ID is not the canonical content SHA-256")]
    ContentHashMismatch,
    #[error("shadow comparison ID has already been accepted")]
    DuplicateComparison,
    #[error("shadow policy is invalid")]
    InvalidPolicy,
    #[error("shadow report is incompatible with its policy")]
    PolicyIncompatible,
    #[error("candidate and last-known-good reports are not a paired run")]
    UnpairedReports,
    #[error("shadow comparison summary does not match its paired reports")]
    SummaryMismatch,
    #[error("shadow metric calculation overflowed")]
    MetricOverflow,
    #[error("failed to serialize canonical shadow content: {0}")]
    CanonicalSerialization(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ShadowRole {
    Candidate,
    LastKnownGood,
}

#[derive(Clone, Debug)]
struct ShadowTask {
    role: ShadowRole,
    index: usize,
    case: CanaryCase,
}

#[derive(Clone, Debug)]
struct CompletedShadowTask {
    role: ShadowRole,
    completed: crate::runner::CompletedCase,
}

impl<P: CanaryProbe> CanaryRunner<P> {
    pub async fn run_shadow(
        &self,
        pair: CanaryShadowPair<'_>,
        vantage: DeclaredVantage,
        budget: CanaryRunBudget,
        cancellation: &CancellationToken,
    ) -> Result<CanaryShadowRun, CanaryShadowError> {
        validate_shadow_inputs(pair, &vantage, budget)?;
        let cases = {
            let mut rng = rand::rng();
            build_shadow_cases(
                pair.candidate_rule,
                pair.last_known_good_rule,
                pair.candidate_manifest,
                &mut rng,
            )?
        };
        self.run_shadow_cases(pair, vantage, budget, cancellation, cases)
            .await
    }

    #[cfg(test)]
    async fn run_shadow_with_rng<R: Rng + ?Sized>(
        &self,
        pair: CanaryShadowPair<'_>,
        vantage: DeclaredVantage,
        budget: CanaryRunBudget,
        cancellation: &CancellationToken,
        rng: &mut R,
    ) -> Result<CanaryShadowRun, CanaryShadowError> {
        validate_shadow_inputs(pair, &vantage, budget)?;
        let cases = build_shadow_cases(
            pair.candidate_rule,
            pair.last_known_good_rule,
            pair.candidate_manifest,
            rng,
        )?;
        self.run_shadow_cases(pair, vantage, budget, cancellation, cases)
            .await
    }

    async fn run_shadow_cases(
        &self,
        pair: CanaryShadowPair<'_>,
        vantage: DeclaredVantage,
        budget: CanaryRunBudget,
        cancellation: &CancellationToken,
        cases: Vec<CanaryCase>,
    ) -> Result<CanaryShadowRun, CanaryShadowError> {
        let candidate_planned_requests = checked_plan(
            cases.len(),
            maximum_requests_per_search(pair.candidate_rule),
        )?;
        let last_known_good_planned_requests = checked_plan(
            cases.len(),
            maximum_requests_per_search(pair.last_known_good_rule),
        )?;
        let planned_requests = candidate_planned_requests
            .checked_add(last_known_good_planned_requests)
            .ok_or(CanaryRunError::InvalidBudget)?;
        if planned_requests > budget.max_requests {
            return Err(CanaryRunError::PlannedRequestsExceedBudget {
                planned: planned_requests,
                maximum: budget.max_requests,
            }
            .into());
        }

        let candidate_planned_bytes = checked_plan(
            cases.len(),
            maximum_inspected_bytes_per_search(pair.candidate_rule),
        )?;
        let last_known_good_planned_bytes = checked_plan(
            cases.len(),
            maximum_inspected_bytes_per_search(pair.last_known_good_rule),
        )?;
        let planned_bytes = candidate_planned_bytes
            .checked_add(last_known_good_planned_bytes)
            .ok_or(CanaryRunError::InvalidBudget)?;
        if planned_bytes > budget.max_response_bytes {
            return Err(CanaryRunError::PlannedResponseBytesExceedBudget {
                planned: planned_bytes,
                maximum: budget.max_response_bytes,
            }
            .into());
        }

        let tasks: Vec<_> = cases
            .into_iter()
            .enumerate()
            .flat_map(|(index, case)| {
                [
                    ShadowTask {
                        role: ShadowRole::Candidate,
                        index,
                        case: case.clone(),
                    },
                    ShadowTask {
                        role: ShadowRole::LastKnownGood,
                        index,
                        case,
                    },
                ]
            })
            .collect();
        let started_at = Utc::now();
        let start = Instant::now();
        let searches = stream::iter(tasks).map(|task| async move {
            let rule = match task.role {
                ShadowRole::Candidate => pair.candidate_rule,
                ShadowRole::LastKnownGood => pair.last_known_good_rule,
            };
            let result = self.probe().search(rule, &task.case.username).await;
            CompletedShadowTask {
                role: task.role,
                completed: completed_case(task.index, task.case, result),
            }
        });
        let searches = searches.buffer_unordered(budget.max_concurrency);
        tokio::pin!(searches);
        let deadline = tokio::time::sleep(Duration::from_millis(budget.max_elapsed_ms));
        tokio::pin!(deadline);

        let mut completion = CanaryRunCompletion::Complete;
        let mut completed_requests = 0_usize;
        let mut completed_response_bytes = 0_usize;
        let mut candidate_completed_requests = 0_usize;
        let mut candidate_completed_bytes = 0_usize;
        let mut last_known_good_completed_requests = 0_usize;
        let mut last_known_good_completed_bytes = 0_usize;
        let mut candidate_outcomes = Vec::new();
        let mut last_known_good_outcomes = Vec::new();

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
                    let Some(task) = next else {
                        break;
                    };
                    completed_requests =
                        completed_requests.saturating_add(task.completed.requests);
                    completed_response_bytes =
                        completed_response_bytes.saturating_add(task.completed.response_bytes);
                    match task.role {
                        ShadowRole::Candidate => {
                            candidate_completed_requests = candidate_completed_requests
                                .saturating_add(task.completed.requests);
                            candidate_completed_bytes = candidate_completed_bytes
                                .saturating_add(task.completed.response_bytes);
                            candidate_outcomes
                                .push((task.completed.index, task.completed.outcome));
                        }
                        ShadowRole::LastKnownGood => {
                            last_known_good_completed_requests = last_known_good_completed_requests
                                .saturating_add(task.completed.requests);
                            last_known_good_completed_bytes = last_known_good_completed_bytes
                                .saturating_add(task.completed.response_bytes);
                            last_known_good_outcomes
                                .push((task.completed.index, task.completed.outcome));
                        }
                    }
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

        candidate_outcomes.sort_by_key(|(index, _)| *index);
        last_known_good_outcomes.sort_by_key(|(index, _)| *index);
        let finished_at = Utc::now();
        let elapsed_ms = duration_ms(start.elapsed());
        let candidate = CanaryRun {
            site_id: pair.candidate_rule.source.id.clone(),
            manifest_hash: pair.candidate_manifest.manifest_hash.clone(),
            rule_hash: pair.candidate_rule.rule_hash.clone(),
            engine_hash: self.engine_hash().to_owned(),
            vantage: vantage.clone(),
            started_at,
            finished_at,
            completion,
            planned_requests: candidate_planned_requests,
            completed_requests: candidate_completed_requests,
            completed_response_bytes: candidate_completed_bytes,
            elapsed_ms,
            outcomes: candidate_outcomes
                .into_iter()
                .map(|(_, outcome)| outcome)
                .collect(),
        };
        let last_known_good = CanaryRun {
            site_id: pair.last_known_good_rule.source.id.clone(),
            manifest_hash: pair.last_known_good_manifest.manifest_hash.clone(),
            rule_hash: pair.last_known_good_rule.rule_hash.clone(),
            engine_hash: self.engine_hash().to_owned(),
            vantage,
            started_at,
            finished_at,
            completion,
            planned_requests: last_known_good_planned_requests,
            completed_requests: last_known_good_completed_requests,
            completed_response_bytes: last_known_good_completed_bytes,
            elapsed_ms,
            outcomes: last_known_good_outcomes
                .into_iter()
                .map(|(_, outcome)| outcome)
                .collect(),
        };
        Ok(CanaryShadowRun {
            completion,
            candidate,
            last_known_good,
            planned_requests,
            completed_requests,
            completed_response_bytes,
            elapsed_ms,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct CanaryShadowBuilder;

impl CanaryShadowBuilder {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    pub fn build(
        &self,
        candidate_manifest: &CompiledCanaryManifest,
        last_known_good_manifest: &CompiledCanaryManifest,
        run: &CanaryShadowRun,
    ) -> Result<CanaryShadowEnvelope, CanaryShadowError> {
        if run.completion != CanaryRunCompletion::Complete {
            return Err(CanaryShadowError::IncompleteRun);
        }
        validate_manifest_pair(candidate_manifest, last_known_good_manifest)?;
        let candidate = CanaryReportBuilder::new().build(candidate_manifest, &run.candidate)?;
        let last_known_good =
            CanaryReportBuilder::new().build(last_known_good_manifest, &run.last_known_good)?;
        validate_report_pair(&candidate, &last_known_good)?;
        let summary = derive_shadow_summary(&candidate, &last_known_good)?;
        seal_shadow(CanaryShadowComparisonV1 {
            schema: CANARY_SHADOW_V1.to_owned(),
            candidate,
            last_known_good,
            summary,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct CanaryShadowValidator;

impl CanaryShadowValidator {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    pub fn parse_and_validate_json_at(
        &self,
        source: &str,
        policy: &CanaryShadowPolicy,
        seen_comparison_ids: &BTreeSet<String>,
        validation_time: DateTime<Utc>,
    ) -> Result<ValidatedCanaryShadow, CanaryShadowError> {
        if source.len() > MAX_SHADOW_JSON_BYTES {
            return Err(CanaryShadowError::ReportTooLarge {
                maximum: MAX_SHADOW_JSON_BYTES,
            });
        }
        let envelope: CanaryShadowEnvelope = serde_json::from_str(source)
            .map_err(|error| CanaryShadowError::MalformedJson(error.to_string()))?;
        self.validate_at(&envelope, policy, seen_comparison_ids, validation_time)
    }

    pub fn validate_at(
        &self,
        envelope: &CanaryShadowEnvelope,
        policy: &CanaryShadowPolicy,
        seen_comparison_ids: &BTreeSet<String>,
        validation_time: DateTime<Utc>,
    ) -> Result<ValidatedCanaryShadow, CanaryShadowError> {
        validate_shadow_policy(policy)?;
        if envelope.comparison.schema != CANARY_SHADOW_V1 {
            return Err(CanaryShadowError::UnsupportedSchema);
        }
        if !valid_sha256(&envelope.comparison_id)
            || canonical_shadow_id(&envelope.comparison)? != envelope.comparison_id
        {
            return Err(CanaryShadowError::ContentHashMismatch);
        }
        if seen_comparison_ids.contains(&envelope.comparison_id) {
            return Err(CanaryShadowError::DuplicateComparison);
        }

        let report_policy = CanaryReportPolicy {
            site_id: policy.site_id.clone(),
            manifest_hash: policy.manifest_hash.clone(),
            allowed_rule_hashes: BTreeSet::from([
                policy.candidate_rule_hash.clone(),
                policy.last_known_good_rule_hash.clone(),
            ]),
            allowed_engine_hashes: BTreeSet::from([policy.engine_hash.clone()]),
            allowed_regions: policy.allowed_regions.clone(),
            max_planned_requests: policy.max_planned_requests_per_rule,
            max_completed_response_bytes: policy.max_completed_response_bytes_per_rule,
        };
        let validator = CanaryReportValidator::new();
        let candidate = validator.validate_at(
            &envelope.comparison.candidate,
            &report_policy,
            &BTreeSet::new(),
            validation_time,
        )?;
        let last_known_good = validator.validate_at(
            &envelope.comparison.last_known_good,
            &report_policy,
            &BTreeSet::from([candidate.envelope().report_id.clone()]),
            validation_time,
        )?;
        if candidate.envelope().report.rule_hash != policy.candidate_rule_hash
            || last_known_good.envelope().report.rule_hash != policy.last_known_good_rule_hash
        {
            return Err(CanaryShadowError::PolicyIncompatible);
        }
        validate_report_pair(candidate.envelope(), last_known_good.envelope())?;
        if derive_shadow_summary(candidate.envelope(), last_known_good.envelope())?
            != envelope.comparison.summary
        {
            return Err(CanaryShadowError::SummaryMismatch);
        }
        Ok(ValidatedCanaryShadow {
            envelope: envelope.clone(),
            candidate,
            last_known_good,
        })
    }
}

fn validate_shadow_inputs(
    pair: CanaryShadowPair<'_>,
    vantage: &DeclaredVantage,
    budget: CanaryRunBudget,
) -> Result<(), CanaryShadowError> {
    validate_run_inputs(
        pair.candidate_rule,
        pair.candidate_manifest,
        vantage,
        budget,
    )?;
    validate_run_inputs(
        pair.last_known_good_rule,
        pair.last_known_good_manifest,
        vantage,
        budget,
    )?;
    validate_manifest_pair(pair.candidate_manifest, pair.last_known_good_manifest)?;
    if pair.candidate_rule.rule_hash == pair.last_known_good_rule.rule_hash {
        return Err(CanaryShadowError::IdenticalRuleHashes);
    }
    Ok(())
}

fn validate_manifest_pair(
    candidate: &CompiledCanaryManifest,
    last_known_good: &CompiledCanaryManifest,
) -> Result<(), CanaryShadowError> {
    if candidate.source != last_known_good.source
        || candidate.manifest_hash != last_known_good.manifest_hash
        || candidate.canonical_json != last_known_good.canonical_json
    {
        return Err(CanaryShadowError::ManifestMismatch);
    }
    Ok(())
}

fn build_shadow_cases<R: Rng + ?Sized>(
    candidate_rule: &CompiledSiteRule,
    last_known_good_rule: &CompiledSiteRule,
    manifest: &CompiledCanaryManifest,
    rng: &mut R,
) -> Result<Vec<CanaryCase>, CanaryShadowError> {
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
    let mut used_usernames: HashSet<_> = cases.iter().map(|case| case.username.clone()).collect();
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
            if candidate_rule.normalize_username(&candidate).as_deref() == Some(candidate.as_str())
                && last_known_good_rule
                    .normalize_username(&candidate)
                    .as_deref()
                    == Some(candidate.as_str())
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
            }
            .into());
        };
        cases.push(CanaryCase {
            id: format!("generated-negative-{:03}", index + 1),
            username,
            expectation: CanaryCaseExpectation::NotFound,
        });
    }
    Ok(cases)
}

fn validate_report_pair(
    candidate: &CanaryReportEnvelope,
    last_known_good: &CanaryReportEnvelope,
) -> Result<(), CanaryShadowError> {
    let candidate_report = &candidate.report;
    let last_known_good_report = &last_known_good.report;
    if candidate_report.schema != CANARY_REPORT_V1
        || last_known_good_report.schema != CANARY_REPORT_V1
        || candidate_report.site_id != last_known_good_report.site_id
        || candidate_report.manifest_hash != last_known_good_report.manifest_hash
        || candidate_report.rule_hash == last_known_good_report.rule_hash
        || candidate_report.engine_hash != last_known_good_report.engine_hash
        || candidate_report.vantage != last_known_good_report.vantage
        || candidate_report.started_at != last_known_good_report.started_at
        || candidate_report.finished_at != last_known_good_report.finished_at
        || candidate_report.expires_at != last_known_good_report.expires_at
        || candidate_report.completion != CanaryRunCompletion::Complete
        || last_known_good_report.completion != CanaryRunCompletion::Complete
        || candidate_report.cases.len() != last_known_good_report.cases.len()
        || candidate_report
            .cases
            .iter()
            .zip(&last_known_good_report.cases)
            .any(|(candidate_case, last_known_good_case)| {
                candidate_case.case_id != last_known_good_case.case_id
                    || candidate_case.expectation != last_known_good_case.expectation
            })
    {
        return Err(CanaryShadowError::UnpairedReports);
    }
    Ok(())
}

fn derive_shadow_summary(
    candidate: &CanaryReportEnvelope,
    last_known_good: &CanaryReportEnvelope,
) -> Result<CanaryShadowSummary, CanaryShadowError> {
    validate_report_pair(candidate, last_known_good)?;
    let candidate_report = &candidate.report;
    let last_known_good_report = &last_known_good.report;
    let total_cases = u32::try_from(candidate_report.cases.len())
        .map_err(|_| CanaryShadowError::MetricOverflow)?;
    let mut verdict_agreements = 0_u32;
    let mut candidate_improvements = 0_u32;
    let mut candidate_regressions = 0_u32;
    let mut issues = Vec::new();

    for (candidate_case, last_known_good_case) in candidate_report
        .cases
        .iter()
        .zip(&last_known_good_report.cases)
    {
        if candidate_case.verdict == last_known_good_case.verdict {
            verdict_agreements = verdict_agreements
                .checked_add(1)
                .ok_or(CanaryShadowError::MetricOverflow)?;
        }
        if !last_known_good_case.matched_expectation && candidate_case.matched_expectation {
            candidate_improvements = candidate_improvements
                .checked_add(1)
                .ok_or(CanaryShadowError::MetricOverflow)?;
        }

        let mut case_regressed = false;
        if last_known_good_case.matched_expectation && !candidate_case.matched_expectation {
            case_regressed = true;
            if candidate_case.verdict == Verdict::Inconclusive {
                issues.push(CanaryShadowIssue::CandidateBecameInconclusive {
                    case_id: candidate_case.case_id.clone(),
                    last_known_good: last_known_good_case.verdict,
                    reason: candidate_case.inconclusive_reason,
                });
            } else {
                issues.push(CanaryShadowIssue::CandidateVerdictRegression {
                    case_id: candidate_case.case_id.clone(),
                    expected: candidate_case.expectation,
                    candidate: candidate_case.verdict,
                    last_known_good: last_known_good_case.verdict,
                });
            }
        }
        if candidate_case.inconclusive_reason == Some(InconclusiveReason::ConflictingEvidence)
            && last_known_good_case.inconclusive_reason
                != Some(InconclusiveReason::ConflictingEvidence)
        {
            case_regressed = true;
        }
        if case_regressed {
            candidate_regressions = candidate_regressions
                .checked_add(1)
                .ok_or(CanaryShadowError::MetricOverflow)?;
        }
    }

    let candidate_precision = candidate_report.summary.precision;
    let last_known_good_precision = last_known_good_report.summary.precision;
    if ratio_less(candidate_precision, last_known_good_precision) {
        issues.push(CanaryShadowIssue::PrecisionRegression {
            candidate: candidate_precision,
            last_known_good: last_known_good_precision,
        });
    }
    let candidate_conclusive_coverage = candidate_report.summary.conclusive_coverage;
    let last_known_good_conclusive_coverage = last_known_good_report.summary.conclusive_coverage;
    if ratio_less(
        candidate_conclusive_coverage,
        last_known_good_conclusive_coverage,
    ) {
        issues.push(CanaryShadowIssue::CoverageRegression {
            candidate: candidate_conclusive_coverage,
            last_known_good: last_known_good_conclusive_coverage,
        });
    }
    let candidate_conflicts = candidate_report.summary.conflicts;
    let last_known_good_conflicts = last_known_good_report.summary.conflicts;
    if candidate_conflicts > last_known_good_conflicts {
        issues.push(CanaryShadowIssue::ConflictRegression {
            candidate: candidate_conflicts,
            last_known_good: last_known_good_conflicts,
        });
    }
    let disposition = if issues.is_empty() {
        CanaryShadowDisposition::Accepted
    } else {
        CanaryShadowDisposition::Rejected
    };

    Ok(CanaryShadowSummary {
        total_cases,
        verdict_agreements,
        candidate_improvements,
        candidate_regressions,
        candidate_precision,
        last_known_good_precision,
        candidate_conclusive_coverage,
        last_known_good_conclusive_coverage,
        candidate_conflicts,
        last_known_good_conflicts,
        disposition,
        issues,
    })
}

fn ratio_less(left: CanaryRatio, right: CanaryRatio) -> bool {
    if left.denominator == 0 {
        return right.denominator != 0;
    }
    if right.denominator == 0 {
        return false;
    }
    u64::from(left.numerator) * u64::from(right.denominator)
        < u64::from(right.numerator) * u64::from(left.denominator)
}

fn validate_shadow_policy(policy: &CanaryShadowPolicy) -> Result<(), CanaryShadowError> {
    if !valid_label(&policy.site_id)
        || !valid_sha256(&policy.manifest_hash)
        || !valid_sha256(&policy.candidate_rule_hash)
        || !valid_sha256(&policy.last_known_good_rule_hash)
        || policy.candidate_rule_hash == policy.last_known_good_rule_hash
        || !valid_sha256(&policy.engine_hash)
        || policy.allowed_regions.is_empty()
        || !policy
            .allowed_regions
            .iter()
            .all(|region| valid_label(region))
        || policy.max_planned_requests_per_rule == 0
        || policy.max_planned_requests_per_rule > 1_024
        || policy.max_completed_response_bytes_per_rule == 0
        || policy.max_completed_response_bytes_per_rule > 256 * 1_024 * 1_024
    {
        return Err(CanaryShadowError::InvalidPolicy);
    }
    Ok(())
}

fn seal_shadow(
    comparison: CanaryShadowComparisonV1,
) -> Result<CanaryShadowEnvelope, CanaryShadowError> {
    let comparison_id = canonical_shadow_id(&comparison)?;
    Ok(CanaryShadowEnvelope {
        comparison_id,
        comparison,
    })
}

fn canonical_shadow_id(comparison: &CanaryShadowComparisonV1) -> Result<String, CanaryShadowError> {
    serde_json::to_vec(comparison)
        .map(|bytes| hex::encode(Sha256::digest(bytes)))
        .map_err(|error| CanaryShadowError::CanonicalSerialization(error.to_string()))
}

fn checked_plan(cases: usize, per_case: usize) -> Result<usize, CanaryRunError> {
    cases
        .checked_mul(per_case)
        .ok_or(CanaryRunError::InvalidBudget)
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn valid_label(value: &str) -> bool {
    let mut characters = value.chars();
    matches!(characters.next(), Some('a'..='z' | '0'..='9'))
        && value.len() <= 64
        && characters.all(|character| matches!(character, 'a'..='z' | '0'..='9' | '-'))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        future::Future,
        pin::Pin,
        sync::{Arc, Mutex},
    };

    use chrono::TimeZone;
    use rand::{SeedableRng, rngs::StdRng};
    use socialname_domain::EvidenceClass;
    use socialname_engine::{Classification, ProbeSummary, SearchResult};
    use socialname_rule_compiler::RuleCompiler;
    use socialname_rule_schema::TransportOutcome;

    use crate::CanaryManifestCompiler;

    use super::*;

    const ENGINE_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const EVIDENCE_DIGEST: &str =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const RULE_TEMPLATE: &str = r#"
schema: socialname.dev/site/v1
id: example
name: __NAME__
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
    const MANIFEST: &str = r#"
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

    #[derive(Clone, Copy, Debug)]
    enum Behavior {
        Stable,
        CandidateInconclusive,
        CandidateWrong,
        CandidateImproves,
        CandidateConflict,
    }

    #[derive(Clone, Debug)]
    struct FakeProbe {
        behavior: Behavior,
        calls: Arc<Mutex<Vec<(String, String)>>>,
    }

    impl FakeProbe {
        fn new(behavior: Behavior) -> Self {
            Self {
                behavior,
                calls: Arc::new(Mutex::new(Vec::new())),
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
                self.calls
                    .lock()
                    .expect("call log lock is available")
                    .push((rule.rule_hash.clone(), username.to_owned()));
                let is_candidate = rule.source.name == "Candidate";
                let expected = if username.len() < 10 {
                    Verdict::Found
                } else {
                    Verdict::NotFound
                };
                let (verdict, inconclusive_reason) = match self.behavior {
                    Behavior::CandidateInconclusive if is_candidate && username == "alpha" => {
                        (Verdict::Inconclusive, Some(InconclusiveReason::Blocked))
                    }
                    Behavior::CandidateWrong if is_candidate && username == "alpha" => {
                        (Verdict::NotFound, None)
                    }
                    Behavior::CandidateImproves if !is_candidate && username == "alpha" => {
                        (Verdict::Inconclusive, Some(InconclusiveReason::Blocked))
                    }
                    Behavior::CandidateConflict if is_candidate && username == "alpha" => (
                        Verdict::Inconclusive,
                        Some(InconclusiveReason::ConflictingEvidence),
                    ),
                    _ => (expected, None),
                };
                SearchResult {
                    site_id: rule.source.id.clone(),
                    username: username.to_owned(),
                    profile_url: None,
                    rule_hash: rule.rule_hash.clone(),
                    classification: Classification {
                        verdict,
                        inconclusive_reason,
                        evidence_class: if verdict == Verdict::Inconclusive {
                            EvidenceClass::E0NoAccountEvidence
                        } else {
                            EvidenceClass::E4StructuredIdentity
                        },
                        matcher_trace: Vec::new(),
                        evidence_digest: EVIDENCE_DIGEST.to_owned(),
                    },
                    probes: vec![ProbeSummary {
                        probe_id: "profile".to_owned(),
                        transport: if verdict == Verdict::Inconclusive {
                            TransportOutcome::Blocked
                        } else {
                            TransportOutcome::Completed
                        },
                        status: match verdict {
                            Verdict::Found => Some(200),
                            Verdict::NotFound => Some(404),
                            _ => None,
                        },
                        final_url: None,
                        content_type: Some("application/json".to_owned()),
                        body_bytes: 100,
                        body_truncated: false,
                        elapsed_ms: 10,
                    }],
                }
            })
        }
    }

    fn validation_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 25, 12, 0, 0)
            .single()
            .expect("test timestamp is valid")
    }

    fn rules_and_manifests() -> (
        CompiledSiteRule,
        CompiledCanaryManifest,
        CompiledSiteRule,
        CompiledCanaryManifest,
    ) {
        let compiler = RuleCompiler::new();
        let candidate = compiler
            .compile_yaml(&RULE_TEMPLATE.replace("__NAME__", "Candidate"), None)
            .expect("candidate rule compiles");
        let last_known_good = compiler
            .compile_yaml(&RULE_TEMPLATE.replace("__NAME__", "Last Known Good"), None)
            .expect("last-known-good rule compiles");
        let manifest_compiler = CanaryManifestCompiler::new();
        let candidate_manifest = manifest_compiler
            .compile_yaml_at(MANIFEST, &candidate, None, validation_time())
            .expect("candidate manifest compiles");
        let last_known_good_manifest = manifest_compiler
            .compile_yaml_at(MANIFEST, &last_known_good, None, validation_time())
            .expect("last-known-good manifest compiles");
        (
            candidate,
            candidate_manifest,
            last_known_good,
            last_known_good_manifest,
        )
    }

    fn policy(envelope: &CanaryShadowEnvelope) -> CanaryShadowPolicy {
        CanaryShadowPolicy {
            site_id: envelope.comparison.candidate.report.site_id.clone(),
            manifest_hash: envelope.comparison.candidate.report.manifest_hash.clone(),
            candidate_rule_hash: envelope.comparison.candidate.report.rule_hash.clone(),
            last_known_good_rule_hash: envelope.comparison.last_known_good.report.rule_hash.clone(),
            engine_hash: ENGINE_HASH.to_owned(),
            allowed_regions: BTreeSet::from(["region-a".to_owned()]),
            max_planned_requests_per_rule: 64,
            max_completed_response_bytes_per_rule: 16 * 1_024 * 1_024,
        }
    }

    async fn build_shadow(
        behavior: Behavior,
    ) -> (
        FakeProbe,
        CanaryShadowEnvelope,
        CompiledCanaryManifest,
        CompiledCanaryManifest,
    ) {
        let (candidate, candidate_manifest, last_known_good, last_known_good_manifest) =
            rules_and_manifests();
        let probe = FakeProbe::new(behavior);
        let runner = CanaryRunner::new(probe.clone(), ENGINE_HASH).expect("runner initializes");
        let mut rng = StdRng::seed_from_u64(7);
        let run = runner
            .run_shadow_with_rng(
                CanaryShadowPair {
                    candidate_rule: &candidate,
                    candidate_manifest: &candidate_manifest,
                    last_known_good_rule: &last_known_good,
                    last_known_good_manifest: &last_known_good_manifest,
                },
                DeclaredVantage {
                    region: "region-a".to_owned(),
                },
                CanaryRunBudget::default(),
                &CancellationToken::new(),
                &mut rng,
            )
            .await
            .expect("shadow run completes");
        let envelope = CanaryShadowBuilder::new()
            .build(&candidate_manifest, &last_known_good_manifest, &run)
            .expect("shadow report builds");
        (
            probe,
            envelope,
            candidate_manifest,
            last_known_good_manifest,
        )
    }

    #[tokio::test]
    async fn paired_run_uses_the_same_private_targets_and_validates() {
        let (probe, envelope, _, _) = build_shadow(Behavior::Stable).await;
        assert_eq!(
            envelope.comparison.summary.disposition,
            CanaryShadowDisposition::Accepted
        );
        assert_eq!(envelope.comparison.summary.verdict_agreements, 10);

        let mut calls_by_rule: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (rule_hash, username) in probe
            .calls
            .lock()
            .expect("call log lock is available")
            .iter()
        {
            calls_by_rule
                .entry(rule_hash.clone())
                .or_default()
                .push(username.clone());
        }
        assert_eq!(calls_by_rule.len(), 2);
        let mut target_sets: Vec<_> = calls_by_rule.into_values().collect();
        target_sets.iter_mut().for_each(|targets| targets.sort());
        assert_eq!(target_sets[0], target_sets[1]);

        let serialized = serde_json::to_string(&envelope).expect("shadow serializes");
        for username in &target_sets[0] {
            assert!(!serialized.contains(username));
        }
        CanaryShadowValidator::new()
            .validate_at(&envelope, &policy(&envelope), &BTreeSet::new(), Utc::now())
            .expect("shadow validates");
    }

    #[tokio::test]
    async fn accepts_a_candidate_that_reduces_inconclusive_results() {
        let (_, envelope, _, _) = build_shadow(Behavior::CandidateImproves).await;
        assert_eq!(
            envelope.comparison.summary.disposition,
            CanaryShadowDisposition::Accepted
        );
        assert_eq!(envelope.comparison.summary.candidate_improvements, 1);
        assert_eq!(envelope.comparison.summary.candidate_regressions, 0);
    }

    #[tokio::test]
    async fn rejects_candidate_coverage_precision_and_conflict_regressions() {
        let (_, inconclusive, _, _) = build_shadow(Behavior::CandidateInconclusive).await;
        assert_eq!(
            inconclusive.comparison.summary.disposition,
            CanaryShadowDisposition::Rejected
        );
        assert!(inconclusive.comparison.summary.issues.iter().any(|issue| {
            matches!(issue, CanaryShadowIssue::CandidateBecameInconclusive { case_id, .. } if case_id == "platform")
        }));
        assert!(
            inconclusive
                .comparison
                .summary
                .issues
                .iter()
                .any(|issue| matches!(issue, CanaryShadowIssue::CoverageRegression { .. }))
        );

        let (_, wrong, _, _) = build_shadow(Behavior::CandidateWrong).await;
        assert!(wrong.comparison.summary.issues.iter().any(|issue| {
            matches!(issue, CanaryShadowIssue::CandidateVerdictRegression { case_id, .. } if case_id == "platform")
        }));
        assert!(
            wrong
                .comparison
                .summary
                .issues
                .iter()
                .any(|issue| matches!(issue, CanaryShadowIssue::PrecisionRegression { .. }))
        );

        let (_, conflict, _, _) = build_shadow(Behavior::CandidateConflict).await;
        assert!(
            conflict
                .comparison
                .summary
                .issues
                .iter()
                .any(|issue| matches!(
                    issue,
                    CanaryShadowIssue::ConflictRegression {
                        candidate: 1,
                        last_known_good: 0
                    }
                ))
        );
    }

    #[tokio::test]
    async fn combined_budget_is_rejected_before_any_probe() {
        let (candidate, candidate_manifest, last_known_good, last_known_good_manifest) =
            rules_and_manifests();
        let probe = FakeProbe::new(Behavior::Stable);
        let runner = CanaryRunner::new(probe.clone(), ENGINE_HASH).expect("runner initializes");
        let mut rng = StdRng::seed_from_u64(7);
        let error = runner
            .run_shadow_with_rng(
                CanaryShadowPair {
                    candidate_rule: &candidate,
                    candidate_manifest: &candidate_manifest,
                    last_known_good_rule: &last_known_good,
                    last_known_good_manifest: &last_known_good_manifest,
                },
                DeclaredVantage {
                    region: "region-a".to_owned(),
                },
                CanaryRunBudget {
                    max_requests: 19,
                    ..CanaryRunBudget::default()
                },
                &CancellationToken::new(),
                &mut rng,
            )
            .await
            .unwrap_err();

        assert_eq!(
            error,
            CanaryShadowError::Run(CanaryRunError::PlannedRequestsExceedBudget {
                planned: 20,
                maximum: 19,
            })
        );
        assert!(
            probe
                .calls
                .lock()
                .expect("call log lock is available")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn cancellation_stays_partial_and_cannot_be_sealed() {
        let (candidate, candidate_manifest, last_known_good, last_known_good_manifest) =
            rules_and_manifests();
        let runner =
            CanaryRunner::new(FakeProbe::new(Behavior::Stable), ENGINE_HASH).expect("runner");
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let mut rng = StdRng::seed_from_u64(7);
        let run = runner
            .run_shadow_with_rng(
                CanaryShadowPair {
                    candidate_rule: &candidate,
                    candidate_manifest: &candidate_manifest,
                    last_known_good_rule: &last_known_good,
                    last_known_good_manifest: &last_known_good_manifest,
                },
                DeclaredVantage {
                    region: "region-a".to_owned(),
                },
                CanaryRunBudget::default(),
                &cancellation,
                &mut rng,
            )
            .await
            .expect("partial run returns");

        assert_eq!(run.completion, CanaryRunCompletion::Cancelled);
        assert_eq!(
            CanaryShadowBuilder::new()
                .build(&candidate_manifest, &last_known_good_manifest, &run)
                .unwrap_err(),
            CanaryShadowError::IncompleteRun
        );
    }

    #[tokio::test]
    async fn rejects_resealed_summary_tampering_and_duplicates() {
        let (_, mut envelope, _, _) = build_shadow(Behavior::Stable).await;
        let original_id = envelope.comparison_id.clone();
        envelope.comparison.summary.verdict_agreements = 0;
        envelope = seal_shadow(envelope.comparison).expect("tampered content reseals");
        let validator = CanaryShadowValidator::new();
        assert_eq!(
            validator
                .validate_at(&envelope, &policy(&envelope), &BTreeSet::new(), Utc::now())
                .unwrap_err(),
            CanaryShadowError::SummaryMismatch
        );

        let (_, original, _, _) = build_shadow(Behavior::Stable).await;
        assert_eq!(
            validator
                .validate_at(
                    &original,
                    &policy(&original),
                    &BTreeSet::from([original.comparison_id.clone()]),
                    Utc::now(),
                )
                .unwrap_err(),
            CanaryShadowError::DuplicateComparison
        );
        assert_ne!(original_id, envelope.comparison_id);
    }
}
