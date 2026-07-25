use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    CanaryCaseOutcome, CanaryReportSummary, ValidatedCanaryReport, report::derive_summary_parts,
};

pub const CANARY_AGGREGATE_V1: &str = "socialname.dev/canary-aggregate/v1";

const ACCEPTANCE_WINDOW_HOURS: i64 = 24;
const MIN_REQUIRED_REGIONS: usize = 3;
const MAX_REQUIRED_REGIONS: usize = 32;
const MIN_RUNS_PER_REGION: u32 = 3;
const MAX_RUNS_PER_REGION: u32 = 32;
const MAX_REPORTS: usize = 1_024;
const REQUIRED_COVERAGE_NUMERATOR: u64 = 95;
const REQUIRED_COVERAGE_DENOMINATOR: u64 = 100;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanaryAggregationPolicy {
    pub site_id: String,
    pub manifest_hash: String,
    pub rule_hash: String,
    pub engine_hash: String,
    pub required_regions: BTreeSet<String>,
    pub window_start: DateTime<Utc>,
    pub window_end: DateTime<Utc>,
    pub minimum_runs_per_region: u32,
    pub maximum_p95_latency_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanaryAcceptanceDisposition {
    Accepted,
    Rejected,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CanaryAcceptanceIssue {
    MissingRegion {
        region: String,
    },
    InsufficientRuns {
        region: String,
        actual: u32,
        required: u32,
    },
    IntervalTooShort {
        region: String,
        actual_ms: i64,
        required_ms: i64,
    },
    PrecisionBelowThreshold {
        region: String,
        matched: u32,
        conclusive: u32,
    },
    CoverageBelowThreshold {
        region: String,
        conclusive: u32,
        total: u32,
    },
    ConflictingEvidence {
        region: String,
        cases: u32,
    },
    LatencyExceeded {
        region: String,
        p95_ms: Option<u64>,
        maximum_ms: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryRegionAggregate {
    pub reports: u32,
    pub first_finished_at: DateTime<Utc>,
    pub last_finished_at: DateTime<Utc>,
    pub summary: CanaryReportSummary,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryAcceptanceAggregate {
    pub schema: String,
    pub site_id: String,
    pub manifest_hash: String,
    pub rule_hash: String,
    pub engine_hash: String,
    pub window_start: DateTime<Utc>,
    pub window_end: DateTime<Utc>,
    pub aggregated_at: DateTime<Utc>,
    pub disposition: CanaryAcceptanceDisposition,
    pub regions: BTreeMap<String, CanaryRegionAggregate>,
    pub overall: CanaryReportSummary,
    pub report_ids: Vec<String>,
    pub issues: Vec<CanaryAcceptanceIssue>,
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum CanaryAggregationError {
    #[error("aggregation policy is invalid")]
    InvalidPolicy,
    #[error("aggregation requires at least one validated report")]
    EmptyInput,
    #[error("aggregation input exceeds the report limit")]
    TooManyReports,
    #[error("validated report ID is duplicated")]
    DuplicateReport,
    #[error("validated report is incompatible with the aggregation policy")]
    IncompatibleReport,
    #[error("validated report falls outside the aggregation window")]
    ReportOutsideWindow,
    #[error("validated report expired before aggregation")]
    ExpiredReport,
    #[error("report metrics overflowed aggregation bounds")]
    MetricOverflow,
    #[error("validated report summary could not be recomputed")]
    InvalidReportSummary,
}

#[derive(Clone, Debug, Default)]
pub struct CanaryReportAggregator;

impl CanaryReportAggregator {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    pub fn aggregate_at(
        &self,
        reports: &[ValidatedCanaryReport],
        policy: &CanaryAggregationPolicy,
        aggregation_time: DateTime<Utc>,
    ) -> Result<CanaryAcceptanceAggregate, CanaryAggregationError> {
        validate_policy(policy, aggregation_time)?;
        if reports.is_empty() {
            return Err(CanaryAggregationError::EmptyInput);
        }
        if reports.len() > MAX_REPORTS {
            return Err(CanaryAggregationError::TooManyReports);
        }

        let mut seen_ids = BTreeSet::new();
        let mut grouped: BTreeMap<String, Vec<&ValidatedCanaryReport>> = BTreeMap::new();
        for validated in reports {
            let envelope = validated.envelope();
            let report = &envelope.report;
            if !seen_ids.insert(envelope.report_id.clone()) {
                return Err(CanaryAggregationError::DuplicateReport);
            }
            if report.site_id != policy.site_id
                || report.manifest_hash != policy.manifest_hash
                || report.rule_hash != policy.rule_hash
                || report.engine_hash != policy.engine_hash
                || !policy.required_regions.contains(&report.vantage.region)
            {
                return Err(CanaryAggregationError::IncompatibleReport);
            }
            if report.finished_at < policy.window_start || report.finished_at > policy.window_end {
                return Err(CanaryAggregationError::ReportOutsideWindow);
            }
            if report.expires_at <= aggregation_time {
                return Err(CanaryAggregationError::ExpiredReport);
            }
            grouped
                .entry(report.vantage.region.clone())
                .or_default()
                .push(validated);
        }

        let mut issues = Vec::new();
        let mut regions = BTreeMap::new();
        for region in &policy.required_regions {
            let Some(region_reports) = grouped.get_mut(region) else {
                issues.push(CanaryAcceptanceIssue::MissingRegion {
                    region: region.clone(),
                });
                continue;
            };
            region_reports.sort_by(|left, right| {
                left.envelope()
                    .report
                    .finished_at
                    .cmp(&right.envelope().report.finished_at)
                    .then_with(|| left.envelope().report_id.cmp(&right.envelope().report_id))
            });
            let aggregate = aggregate_region(region_reports)?;
            evaluate_region(region, &aggregate, policy, &mut issues);
            regions.insert(region.clone(), aggregate);
        }

        let mut ordered_reports: Vec<_> = reports.iter().collect();
        ordered_reports.sort_by(|left, right| {
            left.envelope()
                .report
                .finished_at
                .cmp(&right.envelope().report.finished_at)
                .then_with(|| left.envelope().report_id.cmp(&right.envelope().report_id))
        });
        let overall = aggregate_reports(&ordered_reports)?;
        let report_ids = ordered_reports
            .iter()
            .map(|report| report.envelope().report_id.clone())
            .collect();
        let disposition = if issues.is_empty() {
            CanaryAcceptanceDisposition::Accepted
        } else {
            CanaryAcceptanceDisposition::Rejected
        };

        Ok(CanaryAcceptanceAggregate {
            schema: CANARY_AGGREGATE_V1.to_owned(),
            site_id: policy.site_id.clone(),
            manifest_hash: policy.manifest_hash.clone(),
            rule_hash: policy.rule_hash.clone(),
            engine_hash: policy.engine_hash.clone(),
            window_start: policy.window_start,
            window_end: policy.window_end,
            aggregated_at: aggregation_time,
            disposition,
            regions,
            overall,
            report_ids,
            issues,
        })
    }
}

fn validate_policy(
    policy: &CanaryAggregationPolicy,
    aggregation_time: DateTime<Utc>,
) -> Result<(), CanaryAggregationError> {
    if !valid_region(&policy.site_id)
        || !valid_sha256(&policy.manifest_hash)
        || !valid_sha256(&policy.rule_hash)
        || !valid_sha256(&policy.engine_hash)
        || !(MIN_REQUIRED_REGIONS..=MAX_REQUIRED_REGIONS).contains(&policy.required_regions.len())
        || !policy
            .required_regions
            .iter()
            .all(|region| valid_region(region))
        || policy.window_end - policy.window_start != TimeDelta::hours(ACCEPTANCE_WINDOW_HOURS)
        || aggregation_time < policy.window_end
        || !(MIN_RUNS_PER_REGION..=MAX_RUNS_PER_REGION).contains(&policy.minimum_runs_per_region)
        || policy.maximum_p95_latency_ms == 0
        || policy.maximum_p95_latency_ms > 15 * 60 * 1_000
    {
        return Err(CanaryAggregationError::InvalidPolicy);
    }
    Ok(())
}

fn aggregate_region(
    reports: &[&ValidatedCanaryReport],
) -> Result<CanaryRegionAggregate, CanaryAggregationError> {
    let first_finished_at = reports
        .first()
        .ok_or(CanaryAggregationError::EmptyInput)?
        .envelope()
        .report
        .finished_at;
    let last_finished_at = reports
        .last()
        .ok_or(CanaryAggregationError::EmptyInput)?
        .envelope()
        .report
        .finished_at;
    Ok(CanaryRegionAggregate {
        reports: u32::try_from(reports.len())
            .map_err(|_| CanaryAggregationError::MetricOverflow)?,
        first_finished_at,
        last_finished_at,
        summary: aggregate_reports(reports)?,
    })
}

fn aggregate_reports(
    reports: &[&ValidatedCanaryReport],
) -> Result<CanaryReportSummary, CanaryAggregationError> {
    let cases: Vec<CanaryCaseOutcome> = reports
        .iter()
        .flat_map(|validated| validated.envelope().report.cases.iter().cloned())
        .collect();
    let planned_requests = checked_sum_usize(
        reports
            .iter()
            .map(|validated| validated.envelope().report.summary.planned_requests),
    )?;
    let completed_requests = cases.iter().map(|case| case.probes.len()).sum();
    let completed_response_bytes = cases
        .iter()
        .flat_map(|case| &case.probes)
        .map(|probe| probe.body_bytes)
        .try_fold(0_usize, |total, bytes| total.checked_add(bytes))
        .ok_or(CanaryAggregationError::MetricOverflow)?;
    derive_summary_parts(
        &cases,
        planned_requests,
        completed_requests,
        completed_response_bytes,
    )
    .map_err(|_| CanaryAggregationError::InvalidReportSummary)
}

fn checked_sum_usize(values: impl Iterator<Item = u32>) -> Result<usize, CanaryAggregationError> {
    values
        .map(|value| usize::try_from(value).map_err(|_| CanaryAggregationError::MetricOverflow))
        .try_fold(0_usize, |total, value| {
            total
                .checked_add(value?)
                .ok_or(CanaryAggregationError::MetricOverflow)
        })
}

fn evaluate_region(
    region: &str,
    aggregate: &CanaryRegionAggregate,
    policy: &CanaryAggregationPolicy,
    issues: &mut Vec<CanaryAcceptanceIssue>,
) {
    if aggregate.reports < policy.minimum_runs_per_region {
        issues.push(CanaryAcceptanceIssue::InsufficientRuns {
            region: region.to_owned(),
            actual: aggregate.reports,
            required: policy.minimum_runs_per_region,
        });
    }
    let actual_span = aggregate.last_finished_at - aggregate.first_finished_at;
    let required_span = TimeDelta::hours(ACCEPTANCE_WINDOW_HOURS);
    if actual_span < required_span {
        issues.push(CanaryAcceptanceIssue::IntervalTooShort {
            region: region.to_owned(),
            actual_ms: actual_span.num_milliseconds(),
            required_ms: required_span.num_milliseconds(),
        });
    }
    let precision = aggregate.summary.precision;
    if precision.denominator == 0 || precision.numerator != precision.denominator {
        issues.push(CanaryAcceptanceIssue::PrecisionBelowThreshold {
            region: region.to_owned(),
            matched: precision.numerator,
            conclusive: precision.denominator,
        });
    }
    let coverage = aggregate.summary.conclusive_coverage;
    if u64::from(coverage.numerator) * REQUIRED_COVERAGE_DENOMINATOR
        < u64::from(coverage.denominator) * REQUIRED_COVERAGE_NUMERATOR
    {
        issues.push(CanaryAcceptanceIssue::CoverageBelowThreshold {
            region: region.to_owned(),
            conclusive: coverage.numerator,
            total: coverage.denominator,
        });
    }
    if aggregate.summary.conflicts > 0 {
        issues.push(CanaryAcceptanceIssue::ConflictingEvidence {
            region: region.to_owned(),
            cases: aggregate.summary.conflicts,
        });
    }
    let p95 = aggregate.summary.latency_ms.map(|latency| latency.p95);
    if p95.is_none_or(|latency| latency > policy.maximum_p95_latency_ms) {
        issues.push(CanaryAcceptanceIssue::LatencyExceeded {
            region: region.to_owned(),
            p95_ms: p95,
            maximum_ms: policy.maximum_p95_latency_ms,
        });
    }
}

fn valid_region(value: &str) -> bool {
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
    use chrono::TimeZone;
    use socialname_domain::{EvidenceClass, InconclusiveReason, Verdict};
    use socialname_rule_schema::TransportOutcome;

    use crate::{
        CANARY_MANIFEST_V1, CanaryCaseExpectation, CanaryCaseOutcome, CanaryManifestSource,
        CanaryProbeSummary, CanaryReportBuilder, CanaryReportPolicy, CanaryReportValidator,
        CanaryRun, CanaryRunCompletion, CompiledCanaryManifest, DeclaredVantage, NegativeAlphabet,
        NegativeCanaryGeneratorSource, NegativeCanarySource,
    };

    use super::*;

    const MANIFEST_HASH: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const RULE_HASH: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const ENGINE_HASH: &str = "3333333333333333333333333333333333333333333333333333333333333333";
    const EVIDENCE_DIGEST: &str =
        "4444444444444444444444444444444444444444444444444444444444444444";
    const REGIONS: [&str; 3] = ["region-a", "region-b", "region-c"];

    #[derive(Clone, Copy)]
    enum Quality {
        Healthy,
        Unhealthy,
    }

    fn timestamp(day: u32, hour: u32, minute: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, day, hour, minute, 0)
            .single()
            .expect("test timestamp is valid")
    }

    fn manifest() -> CompiledCanaryManifest {
        CompiledCanaryManifest {
            source: CanaryManifestSource {
                schema: CANARY_MANIFEST_V1.to_owned(),
                site_id: "example".to_owned(),
                issued_at: timestamp(24, 0, 0),
                expires_at: timestamp(29, 0, 0),
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

    fn cases(quality: Quality) -> Vec<CanaryCaseOutcome> {
        (0..10)
            .map(|index| {
                let positive = index < 5;
                let expectation = if positive {
                    CanaryCaseExpectation::Found
                } else {
                    CanaryCaseExpectation::NotFound
                };
                let (verdict, reason, matched, transport) = match quality {
                    Quality::Healthy => (
                        expectation.verdict(),
                        None,
                        true,
                        TransportOutcome::Completed,
                    ),
                    Quality::Unhealthy if index == 9 => {
                        (Verdict::Found, None, false, TransportOutcome::Completed)
                    }
                    Quality::Unhealthy if index == 0 => (
                        Verdict::Inconclusive,
                        Some(InconclusiveReason::ConflictingEvidence),
                        false,
                        TransportOutcome::Blocked,
                    ),
                    Quality::Unhealthy => (
                        Verdict::Inconclusive,
                        Some(InconclusiveReason::Blocked),
                        false,
                        TransportOutcome::Blocked,
                    ),
                };
                CanaryCaseOutcome {
                    case_id: if positive {
                        format!("positive-{:03}", index + 1)
                    } else {
                        format!("generated-negative-{:03}", index - 4)
                    },
                    expectation,
                    verdict,
                    matched_expectation: matched,
                    inconclusive_reason: reason,
                    evidence_class: if matches!(verdict, Verdict::Found | Verdict::NotFound) {
                        EvidenceClass::E4StructuredIdentity
                    } else {
                        EvidenceClass::E0NoAccountEvidence
                    },
                    evidence_digest: EVIDENCE_DIGEST.to_owned(),
                    probes: vec![CanaryProbeSummary {
                        probe_id: "profile".to_owned(),
                        transport,
                        status: Some(if positive { 200 } else { 404 }),
                        content_type: Some("application/json".to_owned()),
                        body_bytes: 100,
                        body_truncated: false,
                        elapsed_ms: if matches!(quality, Quality::Healthy) {
                            100
                        } else {
                            10_000
                        },
                    }],
                }
            })
            .collect()
    }

    fn validated_report(
        region: &str,
        finished_at: DateTime<Utc>,
        quality: Quality,
    ) -> ValidatedCanaryReport {
        let run = CanaryRun {
            site_id: "example".to_owned(),
            manifest_hash: MANIFEST_HASH.to_owned(),
            rule_hash: RULE_HASH.to_owned(),
            engine_hash: ENGINE_HASH.to_owned(),
            vantage: DeclaredVantage {
                region: region.to_owned(),
            },
            started_at: finished_at - TimeDelta::minutes(1),
            finished_at,
            completion: CanaryRunCompletion::Complete,
            planned_requests: 10,
            completed_requests: 10,
            completed_response_bytes: 1_000,
            elapsed_ms: 60_000,
            outcomes: cases(quality),
        };
        let envelope = CanaryReportBuilder::new()
            .build(&manifest(), &run)
            .expect("test report builds");
        let policy = CanaryReportPolicy {
            site_id: "example".to_owned(),
            manifest_hash: MANIFEST_HASH.to_owned(),
            allowed_rule_hashes: BTreeSet::from([RULE_HASH.to_owned()]),
            allowed_engine_hashes: BTreeSet::from([ENGINE_HASH.to_owned()]),
            allowed_regions: BTreeSet::from([region.to_owned()]),
            max_planned_requests: 64,
            max_completed_response_bytes: 16 * 1_024 * 1_024,
        };
        CanaryReportValidator::new()
            .validate_at(
                &envelope,
                &policy,
                &BTreeSet::new(),
                finished_at + TimeDelta::minutes(1),
            )
            .expect("test report validates")
    }

    fn policy() -> CanaryAggregationPolicy {
        CanaryAggregationPolicy {
            site_id: "example".to_owned(),
            manifest_hash: MANIFEST_HASH.to_owned(),
            rule_hash: RULE_HASH.to_owned(),
            engine_hash: ENGINE_HASH.to_owned(),
            required_regions: REGIONS.into_iter().map(str::to_owned).collect(),
            window_start: timestamp(25, 0, 0),
            window_end: timestamp(26, 0, 0),
            minimum_runs_per_region: 3,
            maximum_p95_latency_ms: 6_000,
        }
    }

    fn healthy_reports() -> Vec<ValidatedCanaryReport> {
        REGIONS
            .into_iter()
            .flat_map(|region| {
                [
                    timestamp(25, 0, 0),
                    timestamp(25, 12, 0),
                    timestamp(26, 0, 0),
                ]
                .into_iter()
                .map(move |finished_at| validated_report(region, finished_at, Quality::Healthy))
            })
            .collect()
    }

    #[test]
    fn accepts_three_regions_with_three_precise_runs_spanning_24_hours() {
        let aggregate = CanaryReportAggregator::new()
            .aggregate_at(&healthy_reports(), &policy(), timestamp(26, 0, 1))
            .unwrap();

        assert_eq!(aggregate.disposition, CanaryAcceptanceDisposition::Accepted);
        assert!(aggregate.issues.is_empty());
        assert_eq!(aggregate.regions.len(), 3);
        assert_eq!(aggregate.report_ids.len(), 9);
        assert_eq!(aggregate.overall.total_cases, 90);
        assert!(aggregate.regions.values().all(|region| region.reports == 3
            && region.summary.precision.numerator == 30
            && region.summary.precision.denominator == 30
            && region.summary.conclusive_coverage.numerator == 30
            && region.summary.conclusive_coverage.denominator == 30));
    }

    #[test]
    fn reports_missing_runs_and_short_region_intervals_without_hiding_them() {
        let reports = vec![
            validated_report("region-a", timestamp(25, 0, 0), Quality::Healthy),
            validated_report("region-a", timestamp(25, 1, 0), Quality::Healthy),
            validated_report("region-a", timestamp(25, 2, 0), Quality::Healthy),
            validated_report("region-b", timestamp(25, 0, 0), Quality::Healthy),
            validated_report("region-b", timestamp(26, 0, 0), Quality::Healthy),
        ];
        let aggregate = CanaryReportAggregator::new()
            .aggregate_at(&reports, &policy(), timestamp(26, 0, 1))
            .unwrap();

        assert_eq!(aggregate.disposition, CanaryAcceptanceDisposition::Rejected);
        assert!(aggregate.issues.iter().any(|issue| matches!(
            issue,
            CanaryAcceptanceIssue::IntervalTooShort { region, .. } if region == "region-a"
        )));
        assert!(aggregate.issues.iter().any(|issue| matches!(
            issue,
            CanaryAcceptanceIssue::InsufficientRuns { region, actual: 2, required: 3 }
                if region == "region-b"
        )));
        assert!(aggregate.issues.iter().any(|issue| matches!(
            issue,
            CanaryAcceptanceIssue::MissingRegion { region } if region == "region-c"
        )));
    }

    #[test]
    fn rejects_region_with_low_precision_coverage_conflicts_and_high_latency() {
        let mut reports = healthy_reports();
        reports[1] = validated_report("region-a", timestamp(25, 12, 0), Quality::Unhealthy);
        let aggregate = CanaryReportAggregator::new()
            .aggregate_at(&reports, &policy(), timestamp(26, 0, 1))
            .unwrap();

        assert_eq!(aggregate.disposition, CanaryAcceptanceDisposition::Rejected);
        assert!(aggregate.issues.iter().any(|issue| matches!(
            issue,
            CanaryAcceptanceIssue::PrecisionBelowThreshold { region, .. }
                if region == "region-a"
        )));
        assert!(aggregate.issues.iter().any(|issue| matches!(
            issue,
            CanaryAcceptanceIssue::CoverageBelowThreshold { region, .. }
                if region == "region-a"
        )));
        assert!(aggregate.issues.iter().any(|issue| matches!(
            issue,
            CanaryAcceptanceIssue::ConflictingEvidence { region, .. }
                if region == "region-a"
        )));
        assert!(aggregate.issues.iter().any(|issue| matches!(
            issue,
            CanaryAcceptanceIssue::LatencyExceeded { region, .. }
                if region == "region-a"
        )));
    }

    #[test]
    fn rejects_duplicate_report_input() {
        let mut reports = healthy_reports();
        reports.push(reports[0].clone());
        let error = CanaryReportAggregator::new()
            .aggregate_at(&reports, &policy(), timestamp(26, 0, 1))
            .unwrap_err();

        assert_eq!(error, CanaryAggregationError::DuplicateReport);
    }
}
