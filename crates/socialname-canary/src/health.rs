use chrono::TimeDelta;
use sha2::{Digest, Sha256};
use socialname_domain::{
    InconclusiveReason, RuleClassificationFailure, RuleHealthEvent, RuleHealthKey,
    RuleHealthSignal, RuleOperationalFailure, SiteId,
};

use crate::{
    CANARY_AGGREGATE_V1, CanaryAcceptanceAggregate, CanaryAcceptanceIssue, CanaryShadowIssue,
    EvaluatedCanaryAggregate, ValidatedCanaryShadow,
};

const HEALTH_EVIDENCE_VALIDITY_HOURS: i64 = 24;

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum CanaryHealthError {
    #[error("canary aggregate is malformed")]
    InvalidAggregate,
    #[error("canary aggregate and shadow evidence are incompatible")]
    IncompatibleEvidence,
    #[error("shadow evidence falls outside the aggregate measurement window")]
    ShadowOutsideWindow,
    #[error("canary health evidence has no remaining validity")]
    ExpiredEvidence,
    #[error("failed to serialize canary health evidence: {0}")]
    CanonicalSerialization(String),
}

#[derive(Clone, Debug, Default)]
pub struct CanaryHealthAssessor;

impl CanaryHealthAssessor {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    pub fn assess_region(
        &self,
        evaluated_aggregate: &EvaluatedCanaryAggregate,
        shadow: &ValidatedCanaryShadow,
        region: &str,
        sequence: u64,
    ) -> Result<RuleHealthEvent, CanaryHealthError> {
        let aggregate = evaluated_aggregate.aggregate();
        validate_inputs(aggregate, shadow, region)?;
        let aggregate_evidence_id = aggregate_evidence_id(aggregate)?;
        let shadow_envelope = shadow.envelope();
        let shadow_comparison = &shadow_envelope.comparison;
        let shadow_report = &shadow_comparison.candidate.report;
        let observed_at = std::cmp::max(aggregate.aggregated_at, shadow_report.finished_at);
        let aggregate_policy_expiry =
            aggregate.aggregated_at + TimeDelta::hours(HEALTH_EVIDENCE_VALIDITY_HOURS);
        let expires_at = std::cmp::min(
            std::cmp::min(aggregate_policy_expiry, aggregate.expires_at),
            shadow_report.expires_at,
        );
        if expires_at <= observed_at {
            return Err(CanaryHealthError::ExpiredEvidence);
        }

        let aggregate_issues: Vec<_> = aggregate
            .issues
            .iter()
            .filter(|issue| issue.region() == region)
            .collect();
        let shadow_issues = &shadow_comparison.summary.issues;
        let signal = if let Some(failure) = classification_failure(&aggregate_issues, shadow_issues)
        {
            RuleHealthSignal::ClassificationFailure {
                evidence_id: combined_failure_id(
                    &aggregate_evidence_id,
                    &shadow_envelope.comparison_id,
                ),
                failure,
            }
        } else if let Some(failure) = operational_failure(&aggregate_issues, shadow_issues) {
            RuleHealthSignal::OperationalFailure {
                evidence_id: combined_failure_id(
                    &aggregate_evidence_id,
                    &shadow_envelope.comparison_id,
                ),
                failure,
            }
        } else {
            RuleHealthSignal::AcceptancePassed {
                aggregate_evidence_id,
                shadow_evidence_id: shadow_envelope.comparison_id.clone(),
            }
        };

        Ok(RuleHealthEvent {
            key: RuleHealthKey {
                site_id: SiteId::new(aggregate.site_id.clone()),
                rule_hash: aggregate.rule_hash.clone(),
                region: region.to_owned(),
            },
            sequence,
            manifest_hash: aggregate.manifest_hash.clone(),
            engine_hash: aggregate.engine_hash.clone(),
            observed_at_unix_ms: observed_at.timestamp_millis(),
            expires_at_unix_ms: expires_at.timestamp_millis(),
            signal,
        })
    }
}

fn validate_inputs(
    aggregate: &CanaryAcceptanceAggregate,
    shadow: &ValidatedCanaryShadow,
    region: &str,
) -> Result<(), CanaryHealthError> {
    let shadow_comparison = &shadow.envelope().comparison;
    let shadow_report = &shadow_comparison.candidate.report;
    if aggregate.schema != CANARY_AGGREGATE_V1
        || aggregate.report_ids.is_empty()
        || aggregate.window_end - aggregate.window_start != TimeDelta::hours(24)
        || aggregate.aggregated_at < aggregate.window_end
        || aggregate.expires_at <= aggregate.aggregated_at
        || (!aggregate.regions.contains_key(region)
            && !aggregate
                .issues
                .iter()
                .any(|issue| issue.region() == region))
    {
        return Err(CanaryHealthError::InvalidAggregate);
    }
    if aggregate.site_id != shadow_report.site_id
        || aggregate.manifest_hash != shadow_report.manifest_hash
        || aggregate.rule_hash != shadow_report.rule_hash
        || aggregate.engine_hash != shadow_report.engine_hash
        || shadow_report.vantage.region != region
    {
        return Err(CanaryHealthError::IncompatibleEvidence);
    }
    if shadow_report.finished_at < aggregate.window_start
        || shadow_report.finished_at > aggregate.window_end
    {
        return Err(CanaryHealthError::ShadowOutsideWindow);
    }
    Ok(())
}

fn classification_failure(
    aggregate_issues: &[&CanaryAcceptanceIssue],
    shadow_issues: &[CanaryShadowIssue],
) -> Option<RuleClassificationFailure> {
    if aggregate_issues
        .iter()
        .any(|issue| matches!(issue, CanaryAcceptanceIssue::ConflictingEvidence { .. }))
        || shadow_issues
            .iter()
            .any(|issue| matches!(issue, CanaryShadowIssue::ConflictRegression { .. }))
    {
        return Some(RuleClassificationFailure::ConflictingEvidence);
    }
    if shadow_issues
        .iter()
        .any(|issue| matches!(issue, CanaryShadowIssue::CandidateVerdictRegression { .. }))
    {
        return Some(RuleClassificationFailure::VerdictRegression);
    }
    if aggregate_issues
        .iter()
        .any(|issue| matches!(issue, CanaryAcceptanceIssue::PrecisionBelowThreshold { .. }))
        || shadow_issues
            .iter()
            .any(|issue| matches!(issue, CanaryShadowIssue::PrecisionRegression { .. }))
    {
        return Some(RuleClassificationFailure::PrecisionRegression);
    }
    None
}

fn operational_failure(
    aggregate_issues: &[&CanaryAcceptanceIssue],
    shadow_issues: &[CanaryShadowIssue],
) -> Option<RuleOperationalFailure> {
    for issue in aggregate_issues {
        let failure = match issue {
            CanaryAcceptanceIssue::MissingRegion { .. } => RuleOperationalFailure::MissingRegion,
            CanaryAcceptanceIssue::InsufficientRuns { .. } => {
                RuleOperationalFailure::InsufficientRuns
            }
            CanaryAcceptanceIssue::IntervalTooShort { .. } => {
                RuleOperationalFailure::ShortMeasurementWindow
            }
            CanaryAcceptanceIssue::CoverageBelowThreshold { .. } => {
                RuleOperationalFailure::InsufficientCoverage
            }
            CanaryAcceptanceIssue::LatencyExceeded { .. } => {
                RuleOperationalFailure::ExcessiveLatency
            }
            CanaryAcceptanceIssue::PrecisionBelowThreshold { .. }
            | CanaryAcceptanceIssue::ConflictingEvidence { .. } => continue,
        };
        return Some(failure);
    }
    for issue in shadow_issues {
        match issue {
            CanaryShadowIssue::CandidateBecameInconclusive { reason, .. } => {
                return Some(map_inconclusive_reason(*reason));
            }
            CanaryShadowIssue::CoverageRegression { .. } => {
                return Some(RuleOperationalFailure::InsufficientCoverage);
            }
            CanaryShadowIssue::CandidateVerdictRegression { .. }
            | CanaryShadowIssue::PrecisionRegression { .. }
            | CanaryShadowIssue::ConflictRegression { .. } => {}
        }
    }
    None
}

fn map_inconclusive_reason(reason: Option<InconclusiveReason>) -> RuleOperationalFailure {
    match reason {
        Some(InconclusiveReason::RateLimited) => RuleOperationalFailure::RateLimited,
        Some(InconclusiveReason::Timeout) => RuleOperationalFailure::Timeout,
        Some(InconclusiveReason::Blocked) => RuleOperationalFailure::Blocked,
        Some(
            InconclusiveReason::Dns
            | InconclusiveReason::Connect
            | InconclusiveReason::Tls
            | InconclusiveReason::RedirectRejected
            | InconclusiveReason::ResponseTooLarge
            | InconclusiveReason::Decode
            | InconclusiveReason::SiteChanged
            | InconclusiveReason::NoRuleMatched
            | InconclusiveReason::ConflictingEvidence,
        )
        | None => RuleOperationalFailure::InsufficientCoverage,
    }
}

fn combined_failure_id(aggregate_id: &str, shadow_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"socialname.dev/rule-health-evidence/v1\0");
    hasher.update(aggregate_id.as_bytes());
    hasher.update([0]);
    hasher.update(shadow_id.as_bytes());
    hex::encode(hasher.finalize())
}

fn aggregate_evidence_id(
    aggregate: &CanaryAcceptanceAggregate,
) -> Result<String, CanaryHealthError> {
    let mut evidence = aggregate.clone();
    evidence.aggregated_at = evidence.window_end;
    serde_json::to_vec(&evidence)
        .map(|bytes| hex::encode(Sha256::digest(bytes)))
        .map_err(|error| CanaryHealthError::CanonicalSerialization(error.to_string()))
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use chrono::{DateTime, TimeZone, Utc};
    use socialname_domain::{
        EvidenceClass, RuleHealth, RuleHealthPolicy, RuleHealthRecord, Verdict,
    };
    use socialname_rule_schema::TransportOutcome;

    use crate::{
        CANARY_MANIFEST_V1, CanaryAcceptanceDisposition, CanaryCaseExpectation, CanaryCaseOutcome,
        CanaryManifestSource, CanaryProbeSummary, CanaryRegionAggregate, CanaryRun,
        CanaryRunCompletion, CanaryShadowBuilder, CanaryShadowPolicy, CanaryShadowRun,
        CanaryShadowValidator, CompiledCanaryManifest, DeclaredVantage, NegativeAlphabet,
        NegativeCanaryGeneratorSource, NegativeCanarySource,
    };

    use super::*;

    const MANIFEST_HASH: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const CANDIDATE_HASH: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const LAST_KNOWN_GOOD_HASH: &str =
        "3333333333333333333333333333333333333333333333333333333333333333";
    const ENGINE_HASH: &str = "4444444444444444444444444444444444444444444444444444444444444444";
    const EVIDENCE_DIGEST: &str =
        "5555555555555555555555555555555555555555555555555555555555555555";
    const REPORT_ID: &str = "6666666666666666666666666666666666666666666666666666666666666666";

    fn timestamp(day: u32, hour: u32, minute: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, day, hour, minute, 0)
            .single()
            .expect("test timestamp is valid")
    }

    fn manifest(rule_hash: &str) -> CompiledCanaryManifest {
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
            validated_rule_hash: rule_hash.to_owned(),
            manifest_hash: MANIFEST_HASH.to_owned(),
            canonical_json: b"same-manifest".to_vec(),
        }
    }

    fn cases(candidate_wrong: bool) -> Vec<CanaryCaseOutcome> {
        (0..10)
            .map(|index| {
                let positive = index < 5;
                let expectation = if positive {
                    CanaryCaseExpectation::Found
                } else {
                    CanaryCaseExpectation::NotFound
                };
                let verdict = if candidate_wrong && index == 0 {
                    Verdict::NotFound
                } else {
                    expectation.verdict()
                };
                CanaryCaseOutcome {
                    case_id: if positive {
                        format!("positive-{:03}", index + 1)
                    } else {
                        format!("generated-negative-{:03}", index - 4)
                    },
                    expectation,
                    verdict,
                    matched_expectation: verdict == expectation.verdict(),
                    inconclusive_reason: None,
                    evidence_class: EvidenceClass::E4StructuredIdentity,
                    evidence_digest: EVIDENCE_DIGEST.to_owned(),
                    probes: vec![CanaryProbeSummary {
                        probe_id: "profile".to_owned(),
                        transport: TransportOutcome::Completed,
                        status: Some(if verdict == Verdict::Found { 200 } else { 404 }),
                        content_type: Some("application/json".to_owned()),
                        body_bytes: 100,
                        body_truncated: false,
                        elapsed_ms: 100,
                    }],
                }
            })
            .collect()
    }

    fn run(rule_hash: &str, candidate_wrong: bool) -> CanaryRun {
        CanaryRun {
            site_id: "example".to_owned(),
            manifest_hash: MANIFEST_HASH.to_owned(),
            rule_hash: rule_hash.to_owned(),
            engine_hash: ENGINE_HASH.to_owned(),
            vantage: DeclaredVantage {
                region: "region-a".to_owned(),
            },
            started_at: timestamp(25, 11, 59),
            finished_at: timestamp(25, 12, 0),
            completion: CanaryRunCompletion::Complete,
            planned_requests: 10,
            completed_requests: 10,
            completed_response_bytes: 1_000,
            elapsed_ms: 60_000,
            outcomes: cases(candidate_wrong),
        }
    }

    fn validated_shadow(candidate_wrong: bool) -> ValidatedCanaryShadow {
        let candidate_manifest = manifest(CANDIDATE_HASH);
        let last_known_good_manifest = manifest(LAST_KNOWN_GOOD_HASH);
        let run = CanaryShadowRun {
            completion: CanaryRunCompletion::Complete,
            candidate: run(CANDIDATE_HASH, candidate_wrong),
            last_known_good: run(LAST_KNOWN_GOOD_HASH, false),
            planned_requests: 20,
            completed_requests: 20,
            completed_response_bytes: 2_000,
            elapsed_ms: 60_000,
        };
        let envelope = CanaryShadowBuilder::new()
            .build(&candidate_manifest, &last_known_good_manifest, &run)
            .expect("shadow builds");
        CanaryShadowValidator::new()
            .validate_at(
                &envelope,
                &CanaryShadowPolicy {
                    site_id: "example".to_owned(),
                    manifest_hash: MANIFEST_HASH.to_owned(),
                    candidate_rule_hash: CANDIDATE_HASH.to_owned(),
                    last_known_good_rule_hash: LAST_KNOWN_GOOD_HASH.to_owned(),
                    engine_hash: ENGINE_HASH.to_owned(),
                    allowed_regions: BTreeSet::from(["region-a".to_owned()]),
                    max_planned_requests_per_rule: 64,
                    max_completed_response_bytes_per_rule: 16 * 1_024 * 1_024,
                },
                &BTreeSet::new(),
                timestamp(25, 12, 1),
            )
            .expect("shadow validates")
    }

    fn aggregate(
        shadow: &ValidatedCanaryShadow,
        issues: Vec<CanaryAcceptanceIssue>,
    ) -> EvaluatedCanaryAggregate {
        let summary = shadow.candidate().envelope().report.summary.clone();
        EvaluatedCanaryAggregate::from_test(CanaryAcceptanceAggregate {
            schema: CANARY_AGGREGATE_V1.to_owned(),
            site_id: "example".to_owned(),
            manifest_hash: MANIFEST_HASH.to_owned(),
            rule_hash: CANDIDATE_HASH.to_owned(),
            engine_hash: ENGINE_HASH.to_owned(),
            window_start: timestamp(25, 0, 0),
            window_end: timestamp(26, 0, 0),
            aggregated_at: timestamp(26, 0, 1),
            expires_at: timestamp(27, 0, 0),
            disposition: if issues.is_empty() {
                CanaryAcceptanceDisposition::Accepted
            } else {
                CanaryAcceptanceDisposition::Rejected
            },
            regions: BTreeMap::from([(
                "region-a".to_owned(),
                CanaryRegionAggregate {
                    reports: 3,
                    first_finished_at: timestamp(25, 0, 0),
                    last_finished_at: timestamp(26, 0, 0),
                    summary: summary.clone(),
                },
            )]),
            overall: summary,
            report_ids: vec![REPORT_ID.to_owned()],
            issues,
        })
    }

    fn healthy_record(event: &RuleHealthEvent) -> RuleHealthRecord {
        RuleHealthRecord {
            key: event.key.clone(),
            state: RuleHealth::Healthy,
            sequence: event.sequence - 1,
            entered_at_unix_ms: event.observed_at_unix_ms - 2,
            updated_at_unix_ms: event.observed_at_unix_ms - 1,
            consecutive_recovery_passes: 0,
            consecutive_operational_failures: 0,
            last_manifest_hash: Some(MANIFEST_HASH.to_owned()),
            last_engine_hash: Some(ENGINE_HASH.to_owned()),
            last_evidence_expires_at_unix_ms: Some(event.expires_at_unix_ms),
            last_evidence_ids: vec!["7".repeat(64)],
        }
    }

    #[test]
    fn accepted_pair_creates_fresh_region_scoped_recovery_evidence() {
        let shadow = validated_shadow(false);
        let aggregate = aggregate(
            &shadow,
            vec![CanaryAcceptanceIssue::MissingRegion {
                region: "region-b".to_owned(),
            }],
        );
        let event = CanaryHealthAssessor::new()
            .assess_region(&aggregate, &shadow, "region-a", 1)
            .unwrap();

        assert!(matches!(
            event.signal,
            RuleHealthSignal::AcceptancePassed { .. }
        ));
        assert_eq!(event.key.region, "region-a");
        let initial =
            RuleHealthRecord::quarantined(event.key.clone(), event.observed_at_unix_ms - 1)
                .unwrap();
        let (recovering, transition) = initial
            .apply_at(
                &event,
                RuleHealthPolicy::default(),
                event.observed_at_unix_ms + 1,
            )
            .unwrap();
        assert_eq!(recovering.state, RuleHealth::Recovering);
        assert!(!transition.allows_account_state_notification());
    }

    #[test]
    fn regional_coverage_failure_degrades_without_account_notification() {
        let shadow = validated_shadow(false);
        let aggregate = aggregate(
            &shadow,
            vec![CanaryAcceptanceIssue::CoverageBelowThreshold {
                region: "region-a".to_owned(),
                conclusive: 9,
                total: 10,
            }],
        );
        let event = CanaryHealthAssessor::new()
            .assess_region(&aggregate, &shadow, "region-a", 3)
            .unwrap();
        assert!(matches!(
            event.signal,
            RuleHealthSignal::OperationalFailure {
                failure: RuleOperationalFailure::InsufficientCoverage,
                ..
            }
        ));

        let (degraded, transition) = healthy_record(&event)
            .apply_at(
                &event,
                RuleHealthPolicy::default(),
                event.observed_at_unix_ms + 1,
            )
            .unwrap();
        assert_eq!(degraded.state, RuleHealth::Degraded);
        assert!(!transition.allows_account_state_notification());
    }

    #[test]
    fn precision_and_shadow_verdict_regressions_quarantine_immediately() {
        let stable_shadow = validated_shadow(false);
        let precision_aggregate = aggregate(
            &stable_shadow,
            vec![CanaryAcceptanceIssue::PrecisionBelowThreshold {
                region: "region-a".to_owned(),
                matched: 9,
                conclusive: 10,
            }],
        );
        let event = CanaryHealthAssessor::new()
            .assess_region(&precision_aggregate, &stable_shadow, "region-a", 3)
            .unwrap();
        assert!(matches!(
            event.signal,
            RuleHealthSignal::ClassificationFailure {
                failure: RuleClassificationFailure::PrecisionRegression,
                ..
            }
        ));
        let (quarantined, _) = healthy_record(&event)
            .apply_at(
                &event,
                RuleHealthPolicy::default(),
                event.observed_at_unix_ms + 1,
            )
            .unwrap();
        assert_eq!(quarantined.state, RuleHealth::Quarantined);

        let regressed_shadow = validated_shadow(true);
        let clean_aggregate = aggregate(&regressed_shadow, Vec::new());
        let shadow_event = CanaryHealthAssessor::new()
            .assess_region(&clean_aggregate, &regressed_shadow, "region-a", 1)
            .unwrap();
        assert!(matches!(
            shadow_event.signal,
            RuleHealthSignal::ClassificationFailure {
                failure: RuleClassificationFailure::VerdictRegression,
                ..
            }
        ));
    }

    #[test]
    fn incompatible_or_out_of_window_shadow_evidence_is_rejected() {
        let shadow = validated_shadow(false);
        let mut incompatible_value = aggregate(&shadow, Vec::new()).into_aggregate();
        incompatible_value.engine_hash = "7".repeat(64);
        let incompatible = EvaluatedCanaryAggregate::from_test(incompatible_value);
        assert_eq!(
            CanaryHealthAssessor::new()
                .assess_region(&incompatible, &shadow, "region-a", 1)
                .unwrap_err(),
            CanaryHealthError::IncompatibleEvidence
        );

        let mut outside_value = aggregate(&shadow, Vec::new()).into_aggregate();
        outside_value.window_start = timestamp(26, 0, 0);
        outside_value.window_end = timestamp(27, 0, 0);
        outside_value.aggregated_at = timestamp(27, 0, 1);
        outside_value.expires_at = timestamp(28, 0, 0);
        let outside = EvaluatedCanaryAggregate::from_test(outside_value);
        assert_eq!(
            CanaryHealthAssessor::new()
                .assess_region(&outside, &shadow, "region-a", 1)
                .unwrap_err(),
            CanaryHealthError::ShadowOutsideWindow
        );
    }

    #[test]
    fn reprocessing_time_cannot_manufacture_distinct_aggregate_evidence() {
        let shadow = validated_shadow(false);
        let first = aggregate(&shadow, Vec::new());
        let mut reprocessed_value = first.aggregate().clone();
        reprocessed_value.aggregated_at = timestamp(26, 0, 2);
        let reprocessed = EvaluatedCanaryAggregate::from_test(reprocessed_value);

        let first_event = CanaryHealthAssessor::new()
            .assess_region(&first, &shadow, "region-a", 1)
            .unwrap();
        let second_event = CanaryHealthAssessor::new()
            .assess_region(&reprocessed, &shadow, "region-a", 2)
            .unwrap();
        let RuleHealthSignal::AcceptancePassed {
            aggregate_evidence_id: first_id,
            ..
        } = first_event.signal
        else {
            panic!("first assessment should pass");
        };
        let RuleHealthSignal::AcceptancePassed {
            aggregate_evidence_id: second_id,
            ..
        } = second_event.signal
        else {
            panic!("second assessment should pass");
        };
        assert_eq!(first_id, second_id);
    }
}
