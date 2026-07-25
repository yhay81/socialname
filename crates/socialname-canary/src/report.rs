use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use socialname_domain::{InconclusiveReason, Verdict};
use socialname_rule_schema::TransportOutcome;

use crate::{
    CanaryCaseExpectation, CanaryCaseOutcome, CanaryRun, CanaryRunCompletion,
    CompiledCanaryManifest, DeclaredVantage,
};

pub const CANARY_REPORT_V1: &str = "socialname.dev/canary-report/v1";

const REPORT_VALIDITY_HOURS: i64 = 48;
const MAX_CLOCK_SKEW_MINUTES: i64 = 5;
const MAX_RUN_MINUTES: i64 = 15;
const MAX_REPORT_BYTES: usize = 1_024 * 1_024;
const MIN_CASES_PER_EXPECTATION: usize = 5;
const MAX_CASES_PER_EXPECTATION: usize = 32;
const MAX_CASES: usize = 64;
const MAX_PROBES_PER_CASE: usize = 16;
const MAX_PROBE_BODY_BYTES: usize = 8 * 1_024 * 1_024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryReportEnvelope {
    pub report_id: String,
    pub report: CanaryReportV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedCanaryReport {
    envelope: CanaryReportEnvelope,
}

impl ValidatedCanaryReport {
    #[must_use]
    pub const fn envelope(&self) -> &CanaryReportEnvelope {
        &self.envelope
    }

    #[must_use]
    pub fn into_envelope(self) -> CanaryReportEnvelope {
        self.envelope
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryReportV1 {
    pub schema: String,
    pub site_id: String,
    pub manifest_hash: String,
    pub rule_hash: String,
    pub engine_hash: String,
    pub vantage: DeclaredVantage,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub completion: CanaryRunCompletion,
    pub summary: CanaryReportSummary,
    pub cases: Vec<CanaryCaseOutcome>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryReportSummary {
    pub total_cases: u32,
    pub positive_cases: u32,
    pub negative_cases: u32,
    pub conclusive_cases: u32,
    pub matched_conclusive_cases: u32,
    pub conflicts: u32,
    pub precision: CanaryRatio,
    pub conclusive_coverage: CanaryRatio,
    pub planned_requests: u32,
    pub completed_requests: u32,
    pub completed_response_bytes: u64,
    pub latency_ms: Option<CanaryLatencySummary>,
    pub response_classes: BTreeMap<String, u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryRatio {
    pub numerator: u32,
    pub denominator: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryLatencySummary {
    pub samples: u32,
    pub min: u64,
    pub p50: u64,
    pub p95: u64,
    pub max: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanaryReportPolicy {
    pub site_id: String,
    pub manifest_hash: String,
    pub allowed_rule_hashes: BTreeSet<String>,
    pub allowed_engine_hashes: BTreeSet<String>,
    pub allowed_regions: BTreeSet<String>,
    pub max_planned_requests: u32,
    pub max_completed_response_bytes: u64,
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum CanaryReportError {
    #[error("only a complete canary run can produce an acceptance report")]
    IncompleteRun,
    #[error("run does not match the compiled canary manifest")]
    ManifestMismatch,
    #[error("run timestamps are invalid")]
    InvalidRunTimestamps,
    #[error("run hashes are invalid")]
    InvalidRunHashes,
    #[error("run budget counters are invalid")]
    InvalidRunBudgets,
    #[error("the canary manifest expired before the run completed")]
    ManifestExpired,
    #[error("report JSON exceeds {maximum} bytes")]
    ReportTooLarge { maximum: usize },
    #[error("malformed report JSON: {0}")]
    MalformedJson(String),
    #[error("report schema is unsupported")]
    UnsupportedSchema,
    #[error("report ID is not the canonical content SHA-256")]
    ContentHashMismatch,
    #[error("report ID has already been accepted")]
    DuplicateReport,
    #[error("report has expired")]
    Expired,
    #[error("report timestamps are invalid")]
    InvalidTimestamps,
    #[error("report was produced too far in the future")]
    ProducedInFuture,
    #[error("report policy is invalid")]
    InvalidPolicy,
    #[error("report is incompatible with policy field {0}")]
    PolicyIncompatible(&'static str),
    #[error("report cases are malformed")]
    MalformedCases,
    #[error("report summary does not match its cases")]
    SummaryMismatch,
    #[error("failed to serialize canonical report content: {0}")]
    CanonicalSerialization(String),
}

#[derive(Clone, Debug, Default)]
pub struct CanaryReportBuilder;

impl CanaryReportBuilder {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    pub fn build(
        &self,
        manifest: &CompiledCanaryManifest,
        run: &CanaryRun,
    ) -> Result<CanaryReportEnvelope, CanaryReportError> {
        if run.completion != CanaryRunCompletion::Complete {
            return Err(CanaryReportError::IncompleteRun);
        }
        if run.site_id != manifest.source.site_id
            || run.manifest_hash != manifest.manifest_hash
            || run.rule_hash != manifest.validated_rule_hash
        {
            return Err(CanaryReportError::ManifestMismatch);
        }
        if !valid_sha256(&run.manifest_hash)
            || !valid_sha256(&run.rule_hash)
            || !valid_sha256(&run.engine_hash)
        {
            return Err(CanaryReportError::InvalidRunHashes);
        }
        if run.planned_requests == 0
            || run.planned_requests > 1_024
            || run.completed_requests > run.planned_requests
            || run.completed_response_bytes > 256 * 1_024 * 1_024
        {
            return Err(CanaryReportError::InvalidRunBudgets);
        }
        if run.started_at > run.finished_at
            || run.finished_at - run.started_at > TimeDelta::minutes(MAX_RUN_MINUTES)
        {
            return Err(CanaryReportError::InvalidRunTimestamps);
        }
        if manifest.source.expires_at <= run.finished_at {
            return Err(CanaryReportError::ManifestExpired);
        }
        validate_cases(&run.outcomes)?;

        let expires_at = std::cmp::min(
            run.finished_at + TimeDelta::hours(REPORT_VALIDITY_HOURS),
            manifest.source.expires_at,
        );
        let report = CanaryReportV1 {
            schema: CANARY_REPORT_V1.to_owned(),
            site_id: run.site_id.clone(),
            manifest_hash: run.manifest_hash.clone(),
            rule_hash: run.rule_hash.clone(),
            engine_hash: run.engine_hash.clone(),
            vantage: run.vantage.clone(),
            started_at: run.started_at,
            finished_at: run.finished_at,
            expires_at,
            completion: run.completion,
            summary: derive_summary(run)?,
            cases: run.outcomes.clone(),
        };
        seal(report)
    }
}

#[derive(Clone, Debug, Default)]
pub struct CanaryReportValidator;

impl CanaryReportValidator {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    pub fn parse_and_validate_json_at(
        &self,
        source: &str,
        policy: &CanaryReportPolicy,
        seen_report_ids: &BTreeSet<String>,
        validation_time: DateTime<Utc>,
    ) -> Result<ValidatedCanaryReport, CanaryReportError> {
        if source.len() > MAX_REPORT_BYTES {
            return Err(CanaryReportError::ReportTooLarge {
                maximum: MAX_REPORT_BYTES,
            });
        }
        let envelope: CanaryReportEnvelope = serde_json::from_str(source)
            .map_err(|error| CanaryReportError::MalformedJson(error.to_string()))?;
        self.validate_at(&envelope, policy, seen_report_ids, validation_time)
    }

    pub fn validate_at(
        &self,
        envelope: &CanaryReportEnvelope,
        policy: &CanaryReportPolicy,
        seen_report_ids: &BTreeSet<String>,
        validation_time: DateTime<Utc>,
    ) -> Result<ValidatedCanaryReport, CanaryReportError> {
        validate_policy(policy)?;
        if envelope.report.schema != CANARY_REPORT_V1 {
            return Err(CanaryReportError::UnsupportedSchema);
        }
        if !valid_sha256(&envelope.report_id)
            || canonical_report_id(&envelope.report)? != envelope.report_id
        {
            return Err(CanaryReportError::ContentHashMismatch);
        }
        if seen_report_ids.contains(&envelope.report_id) {
            return Err(CanaryReportError::DuplicateReport);
        }

        validate_policy_compatibility(&envelope.report, policy)?;
        validate_timestamps(&envelope.report, validation_time)?;
        validate_cases(&envelope.report.cases)?;
        if derive_summary_from_report(&envelope.report)? != envelope.report.summary {
            return Err(CanaryReportError::SummaryMismatch);
        }
        Ok(ValidatedCanaryReport {
            envelope: envelope.clone(),
        })
    }
}

fn seal(report: CanaryReportV1) -> Result<CanaryReportEnvelope, CanaryReportError> {
    let report_id = canonical_report_id(&report)?;
    Ok(CanaryReportEnvelope { report_id, report })
}

fn canonical_report_id(report: &CanaryReportV1) -> Result<String, CanaryReportError> {
    serde_json::to_vec(report)
        .map(|bytes| hex::encode(Sha256::digest(bytes)))
        .map_err(|error| CanaryReportError::CanonicalSerialization(error.to_string()))
}

fn validate_policy(policy: &CanaryReportPolicy) -> Result<(), CanaryReportError> {
    if !valid_case_id(&policy.site_id)
        || !valid_sha256(&policy.manifest_hash)
        || policy.allowed_rule_hashes.is_empty()
        || policy.allowed_engine_hashes.is_empty()
        || policy.allowed_regions.is_empty()
        || policy.max_planned_requests == 0
        || policy.max_planned_requests > 1_024
        || policy.max_completed_response_bytes == 0
        || policy.max_completed_response_bytes > 256 * 1_024 * 1_024
        || !policy
            .allowed_rule_hashes
            .iter()
            .all(|hash| valid_sha256(hash))
        || !policy
            .allowed_engine_hashes
            .iter()
            .all(|hash| valid_sha256(hash))
        || !policy
            .allowed_regions
            .iter()
            .all(|region| valid_region(region))
    {
        return Err(CanaryReportError::InvalidPolicy);
    }
    Ok(())
}

fn validate_policy_compatibility(
    report: &CanaryReportV1,
    policy: &CanaryReportPolicy,
) -> Result<(), CanaryReportError> {
    if report.site_id != policy.site_id {
        return Err(CanaryReportError::PolicyIncompatible("site_id"));
    }
    if report.manifest_hash != policy.manifest_hash {
        return Err(CanaryReportError::PolicyIncompatible("manifest_hash"));
    }
    if !policy.allowed_rule_hashes.contains(&report.rule_hash) {
        return Err(CanaryReportError::PolicyIncompatible("rule_hash"));
    }
    if !policy.allowed_engine_hashes.contains(&report.engine_hash) {
        return Err(CanaryReportError::PolicyIncompatible("engine_hash"));
    }
    if !policy.allowed_regions.contains(&report.vantage.region) {
        return Err(CanaryReportError::PolicyIncompatible("region"));
    }
    if report.completion != CanaryRunCompletion::Complete {
        return Err(CanaryReportError::PolicyIncompatible("completion"));
    }
    if report.summary.planned_requests > policy.max_planned_requests
        || report.summary.completed_requests > report.summary.planned_requests
    {
        return Err(CanaryReportError::PolicyIncompatible("request_budget"));
    }
    if report.summary.completed_response_bytes > policy.max_completed_response_bytes {
        return Err(CanaryReportError::PolicyIncompatible(
            "response_byte_budget",
        ));
    }
    Ok(())
}

fn validate_timestamps(
    report: &CanaryReportV1,
    validation_time: DateTime<Utc>,
) -> Result<(), CanaryReportError> {
    if report.started_at > report.finished_at
        || report.expires_at <= report.finished_at
        || report.expires_at > report.finished_at + TimeDelta::hours(REPORT_VALIDITY_HOURS)
        || report.finished_at - report.started_at > TimeDelta::minutes(MAX_RUN_MINUTES)
    {
        return Err(CanaryReportError::InvalidTimestamps);
    }
    if report.finished_at > validation_time + TimeDelta::minutes(MAX_CLOCK_SKEW_MINUTES) {
        return Err(CanaryReportError::ProducedInFuture);
    }
    if report.expires_at <= validation_time {
        return Err(CanaryReportError::Expired);
    }
    Ok(())
}

fn validate_cases(cases: &[CanaryCaseOutcome]) -> Result<(), CanaryReportError> {
    if cases.len() > MAX_CASES {
        return Err(CanaryReportError::MalformedCases);
    }
    let positive = cases
        .iter()
        .filter(|case| case.expectation == CanaryCaseExpectation::Found)
        .count();
    let negative = cases.len().saturating_sub(positive);
    if !(MIN_CASES_PER_EXPECTATION..=MAX_CASES_PER_EXPECTATION).contains(&positive)
        || !(MIN_CASES_PER_EXPECTATION..=MAX_CASES_PER_EXPECTATION).contains(&negative)
    {
        return Err(CanaryReportError::MalformedCases);
    }

    let mut case_ids = BTreeSet::new();
    for case in cases {
        if !valid_case_id(&case.case_id)
            || !case_ids.insert(case.case_id.clone())
            || (case.case_id.starts_with("generated-negative-")
                != (case.expectation == CanaryCaseExpectation::NotFound))
            || case.verdict == Verdict::InvalidUsername
            || case.matched_expectation != (case.verdict == case.expectation.verdict())
            || !valid_sha256(&case.evidence_digest)
            || case.probes.is_empty()
            || case.probes.len() > MAX_PROBES_PER_CASE
        {
            return Err(CanaryReportError::MalformedCases);
        }
        match (case.verdict, case.inconclusive_reason) {
            (Verdict::Found | Verdict::NotFound, None) | (Verdict::Inconclusive, Some(_)) => {}
            _ => return Err(CanaryReportError::MalformedCases),
        }
        for probe in &case.probes {
            if !valid_case_id(&probe.probe_id)
                || probe.body_bytes > MAX_PROBE_BODY_BYTES
                || probe.elapsed_ms
                    > u64::try_from(MAX_RUN_MINUTES * 60 * 1_000).unwrap_or(u64::MAX)
                || probe
                    .content_type
                    .as_deref()
                    .is_some_and(|content_type| !valid_content_type_class(content_type))
            {
                return Err(CanaryReportError::MalformedCases);
            }
        }
    }
    Ok(())
}

fn derive_summary(run: &CanaryRun) -> Result<CanaryReportSummary, CanaryReportError> {
    let summary = derive_summary_parts(
        &run.outcomes,
        run.planned_requests,
        run.completed_requests,
        run.completed_response_bytes,
    )?;
    if summary.completed_requests as usize
        != run
            .outcomes
            .iter()
            .map(|outcome| outcome.probes.len())
            .sum::<usize>()
        || summary.completed_response_bytes as usize
            != run
                .outcomes
                .iter()
                .flat_map(|outcome| &outcome.probes)
                .map(|probe| probe.body_bytes)
                .fold(0_usize, usize::saturating_add)
    {
        return Err(CanaryReportError::SummaryMismatch);
    }
    Ok(summary)
}

fn derive_summary_from_report(
    report: &CanaryReportV1,
) -> Result<CanaryReportSummary, CanaryReportError> {
    derive_summary_parts(
        &report.cases,
        usize::try_from(report.summary.planned_requests)
            .map_err(|_| CanaryReportError::SummaryMismatch)?,
        report.cases.iter().map(|case| case.probes.len()).sum(),
        report
            .cases
            .iter()
            .flat_map(|case| &case.probes)
            .map(|probe| probe.body_bytes)
            .fold(0_usize, usize::saturating_add),
    )
}

pub(crate) fn derive_summary_parts(
    cases: &[CanaryCaseOutcome],
    planned_requests: usize,
    completed_requests: usize,
    completed_response_bytes: usize,
) -> Result<CanaryReportSummary, CanaryReportError> {
    let total_cases = u32::try_from(cases.len()).map_err(|_| CanaryReportError::SummaryMismatch)?;
    let positive_cases = u32::try_from(
        cases
            .iter()
            .filter(|case| case.expectation == CanaryCaseExpectation::Found)
            .count(),
    )
    .map_err(|_| CanaryReportError::SummaryMismatch)?;
    let negative_cases = total_cases.saturating_sub(positive_cases);
    let conclusive_cases = u32::try_from(
        cases
            .iter()
            .filter(|case| matches!(case.verdict, Verdict::Found | Verdict::NotFound))
            .count(),
    )
    .map_err(|_| CanaryReportError::SummaryMismatch)?;
    let matched_conclusive_cases = u32::try_from(
        cases
            .iter()
            .filter(|case| {
                case.matched_expectation
                    && matches!(case.verdict, Verdict::Found | Verdict::NotFound)
            })
            .count(),
    )
    .map_err(|_| CanaryReportError::SummaryMismatch)?;
    let conflicts = u32::try_from(
        cases
            .iter()
            .filter(|case| {
                case.inconclusive_reason == Some(InconclusiveReason::ConflictingEvidence)
            })
            .count(),
    )
    .map_err(|_| CanaryReportError::SummaryMismatch)?;
    let latencies: Vec<_> = cases
        .iter()
        .flat_map(|case| &case.probes)
        .map(|probe| probe.elapsed_ms)
        .collect();
    let mut response_classes = BTreeMap::new();
    for probe in cases.iter().flat_map(|case| &case.probes) {
        *response_classes
            .entry(response_class(probe.transport, probe.status))
            .or_insert(0) += 1;
    }

    Ok(CanaryReportSummary {
        total_cases,
        positive_cases,
        negative_cases,
        conclusive_cases,
        matched_conclusive_cases,
        conflicts,
        precision: CanaryRatio {
            numerator: matched_conclusive_cases,
            denominator: conclusive_cases,
        },
        conclusive_coverage: CanaryRatio {
            numerator: conclusive_cases,
            denominator: total_cases,
        },
        planned_requests: u32::try_from(planned_requests)
            .map_err(|_| CanaryReportError::SummaryMismatch)?,
        completed_requests: u32::try_from(completed_requests)
            .map_err(|_| CanaryReportError::SummaryMismatch)?,
        completed_response_bytes: u64::try_from(completed_response_bytes)
            .map_err(|_| CanaryReportError::SummaryMismatch)?,
        latency_ms: latency_summary(latencies)?,
        response_classes,
    })
}

fn latency_summary(
    mut samples: Vec<u64>,
) -> Result<Option<CanaryLatencySummary>, CanaryReportError> {
    if samples.is_empty() {
        return Ok(None);
    }
    samples.sort_unstable();
    let count = samples.len();
    Ok(Some(CanaryLatencySummary {
        samples: u32::try_from(count).map_err(|_| CanaryReportError::SummaryMismatch)?,
        min: samples[0],
        p50: samples[percentile_index(count, 50)],
        p95: samples[percentile_index(count, 95)],
        max: samples[count - 1],
    }))
}

fn percentile_index(sample_count: usize, percentile: usize) -> usize {
    sample_count
        .saturating_mul(percentile)
        .saturating_add(99)
        .checked_div(100)
        .unwrap_or(1)
        .saturating_sub(1)
        .min(sample_count.saturating_sub(1))
}

fn response_class(transport: TransportOutcome, status: Option<u16>) -> String {
    if transport != TransportOutcome::Completed {
        return format!("transport:{}", transport_label(transport));
    }
    match status {
        Some(200..=299) => "http:2xx".to_owned(),
        Some(300..=399) => "http:3xx".to_owned(),
        Some(400..=499) => "http:4xx".to_owned(),
        Some(500..=599) => "http:5xx".to_owned(),
        Some(_) => "http:other".to_owned(),
        None => "http:none".to_owned(),
    }
}

const fn transport_label(transport: TransportOutcome) -> &'static str {
    match transport {
        TransportOutcome::Completed => "completed",
        TransportOutcome::Blocked => "blocked",
        TransportOutcome::RateLimited => "rate_limited",
        TransportOutcome::Timeout => "timeout",
        TransportOutcome::Dns => "dns",
        TransportOutcome::Connect => "connect",
        TransportOutcome::Tls => "tls",
        TransportOutcome::RedirectRejected => "redirect_rejected",
        TransportOutcome::ResponseTooLarge => "response_too_large",
        TransportOutcome::Decode => "decode",
    }
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_region(value: &str) -> bool {
    let mut characters = value.chars();
    matches!(characters.next(), Some('a'..='z' | '0'..='9'))
        && value.len() <= 64
        && characters.all(|character| matches!(character, 'a'..='z' | '0'..='9' | '-'))
}

fn valid_case_id(value: &str) -> bool {
    let mut characters = value.chars();
    matches!(characters.next(), Some('a'..='z'))
        && value.len() <= 64
        && characters.all(|character| matches!(character, 'a'..='z' | '0'..='9' | '-'))
}

fn valid_content_type_class(value: &str) -> bool {
    matches!(
        value,
        "application/json"
            | "application/problem+json"
            | "application/jrd+json"
            | "text/html"
            | "text/plain"
            | "application/octet-stream"
            | "other"
    )
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use crate::{
        CANARY_MANIFEST_V1, CanaryManifestSource, NegativeAlphabet, NegativeCanaryGeneratorSource,
        NegativeCanarySource,
    };

    use super::*;

    const MANIFEST_HASH: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const RULE_HASH: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const ENGINE_HASH: &str = "3333333333333333333333333333333333333333333333333333333333333333";
    const EVIDENCE_DIGEST: &str =
        "4444444444444444444444444444444444444444444444444444444444444444";

    fn timestamp(hour: u32, minute: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 25, hour, minute, 0)
            .single()
            .expect("test timestamp is valid")
    }

    fn manifest() -> CompiledCanaryManifest {
        CompiledCanaryManifest {
            source: CanaryManifestSource {
                schema: CANARY_MANIFEST_V1.to_owned(),
                site_id: "example".to_owned(),
                issued_at: timestamp(0, 0),
                expires_at: Utc
                    .with_ymd_and_hms(2026, 7, 27, 0, 0, 0)
                    .single()
                    .expect("test timestamp is valid"),
                positive: Vec::new(),
                negative: NegativeCanarySource {
                    generator: NegativeCanaryGeneratorSource {
                        alphabet: NegativeAlphabet::LowercaseAlnum,
                        random_length: 20,
                        suffix: String::new(),
                        count: 5,
                        attempts_per_candidate: 3,
                    },
                },
            },
            validated_rule_hash: RULE_HASH.to_owned(),
            manifest_hash: MANIFEST_HASH.to_owned(),
            canonical_json: Vec::new(),
        }
    }

    fn run() -> CanaryRun {
        let cases = (0..10)
            .map(|index| {
                let positive = index < 5;
                let expectation = if positive {
                    CanaryCaseExpectation::Found
                } else {
                    CanaryCaseExpectation::NotFound
                };
                let verdict = expectation.verdict();
                CanaryCaseOutcome {
                    case_id: if positive {
                        format!("positive-{:03}", index + 1)
                    } else {
                        format!("generated-negative-{:03}", index - 4)
                    },
                    expectation,
                    verdict,
                    matched_expectation: true,
                    inconclusive_reason: None,
                    evidence_class: socialname_domain::EvidenceClass::E4StructuredIdentity,
                    evidence_digest: EVIDENCE_DIGEST.to_owned(),
                    probes: vec![crate::CanaryProbeSummary {
                        probe_id: "profile".to_owned(),
                        transport: TransportOutcome::Completed,
                        status: Some(if positive { 200 } else { 404 }),
                        content_type: Some("application/json".to_owned()),
                        body_bytes: 100,
                        body_truncated: false,
                        elapsed_ms: u64::try_from(index + 1).expect("test index fits u64"),
                    }],
                }
            })
            .collect();
        CanaryRun {
            site_id: "example".to_owned(),
            manifest_hash: MANIFEST_HASH.to_owned(),
            rule_hash: RULE_HASH.to_owned(),
            engine_hash: ENGINE_HASH.to_owned(),
            vantage: DeclaredVantage {
                region: "test-region-1".to_owned(),
            },
            started_at: timestamp(1, 0),
            finished_at: timestamp(1, 1),
            completion: CanaryRunCompletion::Complete,
            planned_requests: 10,
            completed_requests: 10,
            completed_response_bytes: 1_000,
            elapsed_ms: 60_000,
            outcomes: cases,
        }
    }

    fn report() -> CanaryReportEnvelope {
        CanaryReportBuilder::new()
            .build(&manifest(), &run())
            .expect("test report builds")
    }

    fn policy(report: &CanaryReportEnvelope) -> CanaryReportPolicy {
        CanaryReportPolicy {
            site_id: report.report.site_id.clone(),
            manifest_hash: report.report.manifest_hash.clone(),
            allowed_rule_hashes: BTreeSet::from([report.report.rule_hash.clone()]),
            allowed_engine_hashes: BTreeSet::from([report.report.engine_hash.clone()]),
            allowed_regions: BTreeSet::from([report.report.vantage.region.clone()]),
            max_planned_requests: 64,
            max_completed_response_bytes: 16 * 1_024 * 1_024,
        }
    }

    #[test]
    fn builds_versioned_metrics_without_target_or_body_fields() {
        let report = report();

        assert_eq!(report.report.schema, CANARY_REPORT_V1);
        assert_eq!(
            report.report.summary.precision,
            CanaryRatio {
                numerator: 10,
                denominator: 10
            }
        );
        assert_eq!(
            report.report.summary.conclusive_coverage,
            CanaryRatio {
                numerator: 10,
                denominator: 10
            }
        );
        assert_eq!(
            report.report.summary.latency_ms,
            Some(CanaryLatencySummary {
                samples: 10,
                min: 1,
                p50: 5,
                p95: 10,
                max: 10,
            })
        );
        assert_eq!(report.report.summary.response_classes["http:2xx"], 5);
        assert_eq!(report.report.summary.response_classes["http:4xx"], 5);

        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("username"));
        assert!(!json.contains("profile_url"));
        assert!(!json.contains("final_url"));
        assert!(!json.contains("\"body\""));
        assert!(!json.contains("matcher_trace"));
    }

    #[test]
    fn recomputes_conflicts_coverage_and_transport_classes() {
        let mut run = run();
        run.outcomes[0].verdict = Verdict::Inconclusive;
        run.outcomes[0].matched_expectation = false;
        run.outcomes[0].inconclusive_reason = Some(InconclusiveReason::ConflictingEvidence);
        run.outcomes[0].probes[0].transport = TransportOutcome::Blocked;
        let report = CanaryReportBuilder::new()
            .build(&manifest(), &run)
            .expect("conflicted report remains structurally valid");

        assert_eq!(report.report.summary.conflicts, 1);
        assert_eq!(
            report.report.summary.precision,
            CanaryRatio {
                numerator: 9,
                denominator: 9
            }
        );
        assert_eq!(
            report.report.summary.conclusive_coverage,
            CanaryRatio {
                numerator: 9,
                denominator: 10
            }
        );
        assert_eq!(
            report.report.summary.response_classes["transport:blocked"],
            1
        );
    }

    #[test]
    fn validates_canonical_report() {
        let report = report();
        CanaryReportValidator::new()
            .validate_at(&report, &policy(&report), &BTreeSet::new(), timestamp(1, 2))
            .unwrap();
    }

    #[test]
    fn rejects_duplicate_report_id() {
        let report = report();
        let error = CanaryReportValidator::new()
            .validate_at(
                &report,
                &policy(&report),
                &BTreeSet::from([report.report_id.clone()]),
                timestamp(1, 2),
            )
            .unwrap_err();

        assert_eq!(error, CanaryReportError::DuplicateReport);
    }

    #[test]
    fn rejects_expired_report() {
        let report = report();
        let after_expiry = Utc
            .with_ymd_and_hms(2026, 7, 27, 1, 0, 0)
            .single()
            .expect("test timestamp is valid");
        let error = CanaryReportValidator::new()
            .validate_at(&report, &policy(&report), &BTreeSet::new(), after_expiry)
            .unwrap_err();

        assert_eq!(error, CanaryReportError::Expired);
    }

    #[test]
    fn rejects_content_tampering() {
        let mut report = report();
        report.report.summary.total_cases = 9;
        let error = CanaryReportValidator::new()
            .validate_at(&report, &policy(&report), &BTreeSet::new(), timestamp(1, 2))
            .unwrap_err();

        assert_eq!(error, CanaryReportError::ContentHashMismatch);
    }

    #[test]
    fn rejects_resealed_summary_mismatch() {
        let original = report();
        let mut content = original.report;
        content.summary.total_cases = 9;
        let resealed = seal(content).unwrap();
        let error = CanaryReportValidator::new()
            .validate_at(
                &resealed,
                &policy(&resealed),
                &BTreeSet::new(),
                timestamp(1, 2),
            )
            .unwrap_err();

        assert_eq!(error, CanaryReportError::SummaryMismatch);
    }

    #[test]
    fn rejects_policy_incompatible_region() {
        let report = report();
        let mut policy = policy(&report);
        policy.allowed_regions = BTreeSet::from(["other-region".to_owned()]);
        let error = CanaryReportValidator::new()
            .validate_at(&report, &policy, &BTreeSet::new(), timestamp(1, 2))
            .unwrap_err();

        assert_eq!(error, CanaryReportError::PolicyIncompatible("region"));
    }

    #[test]
    fn rejects_malformed_json_and_unknown_fields() {
        let report = report();
        let source = serde_json::to_string(&report)
            .unwrap()
            .replace("\"report_id\":", "\"unknown\":true,\"report_id\":");
        let error = CanaryReportValidator::new()
            .parse_and_validate_json_at(
                &source,
                &policy(&report),
                &BTreeSet::new(),
                timestamp(1, 2),
            )
            .unwrap_err();

        assert!(matches!(error, CanaryReportError::MalformedJson(_)));
    }

    #[test]
    fn refuses_partial_run_report() {
        let mut run = run();
        run.completion = CanaryRunCompletion::Cancelled;
        let error = CanaryReportBuilder::new()
            .build(&manifest(), &run)
            .unwrap_err();

        assert_eq!(error, CanaryReportError::IncompleteRun);
    }
}
