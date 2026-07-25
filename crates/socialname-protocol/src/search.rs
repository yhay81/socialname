use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    ConsentGrantId, DefinitiveVerdict, EventId, EvidenceClass, EvidenceDigest, Freshness, HttpsUrl,
    ObservationId, ProtocolVersion, RegionClass, ResultSource, RuleHash, RuleHealthStatus,
    SearchId, SearchMode, SyncPolicy, Target, TargetSelection, Validate, ValidationCode,
    ValidationErrors,
    common::{
        finish, validate_maximum_age, validate_nonempty_ids, validate_regions,
        validate_sync_consent, validate_timestamp,
    },
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchCreateRequest {
    pub schema: ProtocolVersion,
    pub targets: TargetSelection,
    pub mode: SearchMode,
    pub sync: SyncPolicy,
    pub consent_grant_id: Option<ConsentGrantId>,
    pub maximum_age_ms: i64,
    pub region_classes: Vec<RegionClass>,
}

impl Validate for SearchCreateRequest {
    fn validate(&self) -> Result<(), ValidationErrors> {
        collect_validations([
            self.targets.validate(),
            validate_sync_consent(self.sync, &self.consent_grant_id),
            validate_maximum_age(self.maximum_age_ms),
            validate_regions(&self.region_classes),
        ])
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SearchState {
    Accepted,
    Running,
    Completed,
    Cancelled,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SearchTerminalState {
    Completed,
    Cancelled,
    Failed,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchProgress {
    pub total_targets: u32,
    pub completed_targets: u32,
    pub definitive_results: u32,
    pub uncertain_results: u32,
    pub operational_failures: u32,
}

impl Validate for SearchProgress {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let classified = self
            .definitive_results
            .saturating_add(self.uncertain_results)
            .saturating_add(self.operational_failures);
        if self.total_targets == 0
            || self.completed_targets > self.total_targets
            || classified != self.completed_targets
        {
            Err(ValidationErrors::new(
                "progress",
                ValidationCode::InvalidRelation,
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchResource {
    pub schema: ProtocolVersion,
    pub search_id: SearchId,
    pub state: SearchState,
    pub request: SearchCreateRequest,
    pub progress: SearchProgress,
    pub created_at_unix_ms: i64,
    pub updated_at_unix_ms: i64,
}

impl Validate for SearchResource {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut validations = vec![
            self.request.validate(),
            self.progress.validate(),
            validate_timestamp("created_at_unix_ms", self.created_at_unix_ms),
            validate_timestamp("updated_at_unix_ms", self.updated_at_unix_ms),
        ];
        if self.updated_at_unix_ms < self.created_at_unix_ms {
            validations.push(Err(ValidationErrors::new(
                "updated_at_unix_ms",
                ValidationCode::InvalidRelation,
            )));
        }
        let expected_targets = self
            .request
            .targets
            .usernames
            .len()
            .saturating_mul(self.request.targets.site_ids.len());
        if usize::try_from(self.progress.total_targets).ok() != Some(expected_targets) {
            validations.push(Err(ValidationErrors::new(
                "progress.total_targets",
                ValidationCode::InvalidRelation,
            )));
        }
        let state_progress_valid = match self.state {
            SearchState::Accepted => self.progress.completed_targets == 0,
            SearchState::Running => self.progress.completed_targets < self.progress.total_targets,
            SearchState::Completed => {
                self.progress.completed_targets == self.progress.total_targets
            }
            SearchState::Cancelled | SearchState::Failed => true,
        };
        if !state_progress_valid {
            validations.push(Err(ValidationErrors::new(
                "state",
                ValidationCode::InvalidRelation,
            )));
        }
        collect_validations(validations)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DefinitiveResult {
    pub observation_id: ObservationId,
    pub target: Target,
    pub verdict: DefinitiveVerdict,
    pub source: ResultSource,
    pub freshness: Freshness,
    pub evidence_class: EvidenceClass,
    pub evidence_digest: EvidenceDigest,
    pub region_class: RegionClass,
    pub rule_hash: RuleHash,
    pub rule_health: RuleHealthStatus,
    pub profile_url: Option<HttpsUrl>,
}

impl Validate for DefinitiveResult {
    fn validate(&self) -> Result<(), ValidationErrors> {
        self.freshness.validate()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UncertaintyReason {
    SiteChanged,
    NoRuleMatched,
    ConflictingEvidence,
    ClassificationAmbiguous,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UncertainResult {
    pub observation_id: ObservationId,
    pub target: Target,
    pub reason: UncertaintyReason,
    pub source: ResultSource,
    pub freshness: Freshness,
    pub evidence_class: EvidenceClass,
    pub evidence_digest: EvidenceDigest,
    pub region_class: RegionClass,
    pub rule_hash: RuleHash,
    pub rule_health: RuleHealthStatus,
}

impl Validate for UncertainResult {
    fn validate(&self) -> Result<(), ValidationErrors> {
        self.freshness.validate()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OperationalFailureKind {
    Blocked,
    RateLimited,
    Timeout,
    Dns,
    Connect,
    Tls,
    RedirectRejected,
    ResponseTooLarge,
    Decode,
    RuleUnavailable,
    CapacityUnavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperationalFailure {
    pub target: Target,
    pub kind: OperationalFailureKind,
    pub source: ResultSource,
    pub occurred_at_unix_ms: i64,
    pub retryable: bool,
    pub region_class: Option<RegionClass>,
    pub rule_hash: Option<RuleHash>,
}

impl Validate for OperationalFailure {
    fn validate(&self) -> Result<(), ValidationErrors> {
        if !matches!(
            self.source,
            ResultSource::LocalProbe | ResultSource::ManagedProbe
        ) {
            return Err(ValidationErrors::new(
                "source",
                ValidationCode::InvalidRelation,
            ));
        }
        validate_timestamp("occurred_at_unix_ms", self.occurred_at_unix_ms)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AssertionOutcome {
    Found,
    NotFound,
    Inconclusive { reason: UncertaintyReason },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AssertionQuality {
    Verified,
    Corroborated,
    SingleVantage,
    Stale,
    Conflicted,
    Untrusted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Assertion {
    pub target: Target,
    pub outcome: AssertionOutcome,
    pub quality: AssertionQuality,
    pub evidence_class: EvidenceClass,
    pub freshness: Freshness,
    pub sources: Vec<ResultSource>,
    pub regions: Vec<RegionClass>,
    pub support_group_count: u32,
    pub managed_support: bool,
    pub supporting_observation_ids: Vec<ObservationId>,
    pub conflicting_observation_ids: Vec<ObservationId>,
    pub derivation_version: String,
}

impl Validate for Assertion {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut validations = vec![
            self.freshness.validate(),
            validate_nonempty_ids("sources", &self.sources, 8),
            validate_nonempty_ids("regions", &self.regions, 16),
        ];

        if self.derivation_version.is_empty()
            || self.derivation_version.len() > 64
            || self.derivation_version.chars().any(char::is_control)
        {
            validations.push(Err(ValidationErrors::new(
                "derivation_version",
                ValidationCode::InvalidFormat,
            )));
        }

        let freshness_quality_valid = match self.freshness.state {
            crate::FreshnessState::Current => self.quality != AssertionQuality::Stale,
            crate::FreshnessState::Stale | crate::FreshnessState::Expired => {
                self.quality == AssertionQuality::Stale
            }
        };
        if !freshness_quality_valid {
            validations.push(Err(ValidationErrors::new(
                "assertion.freshness",
                ValidationCode::InvalidRelation,
            )));
        }

        let support_ids = self
            .supporting_observation_ids
            .iter()
            .collect::<BTreeSet<_>>();
        let conflicting_ids = self
            .conflicting_observation_ids
            .iter()
            .collect::<BTreeSet<_>>();
        if support_ids.len() != self.supporting_observation_ids.len()
            || conflicting_ids.len() != self.conflicting_observation_ids.len()
            || !support_ids.is_disjoint(&conflicting_ids)
            || support_ids.len().saturating_add(conflicting_ids.len()) > 256
        {
            validations.push(Err(ValidationErrors::new(
                "observation_ids",
                ValidationCode::Duplicate,
            )));
        }

        match (&self.outcome, self.quality) {
            (
                AssertionOutcome::Inconclusive {
                    reason: UncertaintyReason::ConflictingEvidence,
                },
                AssertionQuality::Conflicted,
            ) if self.supporting_observation_ids.is_empty()
                && !self.conflicting_observation_ids.is_empty()
                && self.support_group_count == 0 => {}
            (AssertionOutcome::Found | AssertionOutcome::NotFound, quality)
                if quality != AssertionQuality::Conflicted
                    && !self.supporting_observation_ids.is_empty()
                    && self.conflicting_observation_ids.is_empty()
                    && self.support_group_count > 0 => {}
            _ => validations.push(Err(ValidationErrors::new(
                "assertion",
                ValidationCode::InvalidRelation,
            ))),
        }

        let managed_quality_valid = match self.quality {
            AssertionQuality::Verified => self.managed_support,
            AssertionQuality::Corroborated
            | AssertionQuality::SingleVantage
            | AssertionQuality::Untrusted => !self.managed_support,
            AssertionQuality::Stale | AssertionQuality::Conflicted => true,
        };
        if !managed_quality_valid {
            validations.push(Err(ValidationErrors::new(
                "assertion.managed_support",
                ValidationCode::InvalidRelation,
            )));
        }

        collect_validations(validations)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SearchEventData {
    Started {
        total_targets: u32,
    },
    DefinitiveResult {
        result: DefinitiveResult,
    },
    UncertainResult {
        result: UncertainResult,
    },
    OperationalFailure {
        failure: OperationalFailure,
    },
    AssertionUpdated {
        assertion: Assertion,
    },
    Finished {
        state: SearchTerminalState,
        progress: SearchProgress,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchEvent {
    pub schema: ProtocolVersion,
    pub event_id: EventId,
    pub search_id: SearchId,
    pub sequence: u64,
    pub emitted_at_unix_ms: i64,
    pub data: SearchEventData,
}

impl Validate for SearchEvent {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut validations = vec![validate_timestamp(
            "emitted_at_unix_ms",
            self.emitted_at_unix_ms,
        )];
        if self.sequence == 0 {
            validations.push(Err(ValidationErrors::new(
                "sequence",
                ValidationCode::OutOfRange,
            )));
        }
        validations.push(match &self.data {
            SearchEventData::Started { total_targets } => {
                if *total_targets == 0 {
                    Err(ValidationErrors::new(
                        "total_targets",
                        ValidationCode::OutOfRange,
                    ))
                } else {
                    Ok(())
                }
            }
            SearchEventData::DefinitiveResult { result } => result.validate(),
            SearchEventData::UncertainResult { result } => result.validate(),
            SearchEventData::OperationalFailure { failure } => failure.validate(),
            SearchEventData::AssertionUpdated { assertion } => assertion.validate(),
            SearchEventData::Finished { state, progress } => {
                let mut result = progress.validate();
                if *state == SearchTerminalState::Completed
                    && progress.completed_targets != progress.total_targets
                {
                    result = Err(ValidationErrors::new(
                        "progress",
                        ValidationCode::InvalidRelation,
                    ));
                }
                result
            }
        });
        collect_validations(validations)
    }
}

fn collect_validations(
    validations: impl IntoIterator<Item = Result<(), ValidationErrors>>,
) -> Result<(), ValidationErrors> {
    let mut issues = Vec::new();
    for result in validations {
        if let Err(errors) = result {
            issues.extend(errors.into_issues());
        }
    }
    finish(issues)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FreshnessState, SiteId};

    fn request() -> SearchCreateRequest {
        SearchCreateRequest {
            schema: ProtocolVersion::ApiV1,
            targets: TargetSelection {
                usernames: vec![crate::Username::new("alice").unwrap()],
                site_ids: vec![SiteId::new("github").unwrap()],
            },
            mode: SearchMode::Remote,
            sync: SyncPolicy::Never,
            consent_grant_id: None,
            maximum_age_ms: 60_000,
            region_classes: vec![RegionClass::new("jp").unwrap()],
        }
    }

    #[test]
    fn synchronization_requires_a_purpose_specific_grant() {
        let mut request = request();
        request.sync = SyncPolicy::Shared;
        assert!(request.validate().is_err());

        request.consent_grant_id = Some(ConsentGrantId::new("grant_01").unwrap());
        assert!(request.validate().is_ok());

        request.sync = SyncPolicy::Never;
        assert!(request.validate().is_err());
    }

    #[test]
    fn completed_progress_must_account_for_every_target() {
        let event = SearchEvent {
            schema: ProtocolVersion::ApiV1,
            event_id: EventId::new("event_01").unwrap(),
            search_id: SearchId::new("search_01").unwrap(),
            sequence: 2,
            emitted_at_unix_ms: 2_000,
            data: SearchEventData::Finished {
                state: SearchTerminalState::Completed,
                progress: SearchProgress {
                    total_targets: 2,
                    completed_targets: 1,
                    definitive_results: 1,
                    uncertain_results: 0,
                    operational_failures: 0,
                },
            },
        };
        assert!(event.validate().is_err());
    }

    #[test]
    fn resource_progress_matches_the_requested_cartesian_target_set() {
        let request = request();
        let mut resource = SearchResource {
            schema: ProtocolVersion::ApiV1,
            search_id: SearchId::new("search_01").unwrap(),
            state: SearchState::Accepted,
            request,
            progress: SearchProgress {
                total_targets: 2,
                completed_targets: 0,
                definitive_results: 0,
                uncertain_results: 0,
                operational_failures: 0,
            },
            created_at_unix_ms: 1_000,
            updated_at_unix_ms: 1_000,
        };
        assert!(resource.validate().is_err());
        resource.progress.total_targets = 1;
        assert!(resource.validate().is_ok());
    }

    #[test]
    fn operational_failure_is_not_a_verdict_or_uncertainty() {
        let failure = SearchEventData::OperationalFailure {
            failure: OperationalFailure {
                target: Target {
                    username: crate::Username::new("alice").unwrap(),
                    site_id: SiteId::new("github").unwrap(),
                },
                kind: OperationalFailureKind::Timeout,
                source: ResultSource::ManagedProbe,
                occurred_at_unix_ms: 2_000,
                retryable: true,
                region_class: Some(RegionClass::new("jp").unwrap()),
                rule_hash: None,
            },
        };
        let json = serde_json::to_value(failure).unwrap();
        assert_eq!(json["type"], "operational_failure");
        assert!(json.get("verdict").is_none());
        assert!(json.get("reason").is_none());
    }

    #[test]
    fn freshness_state_is_checked_inside_results() {
        let mut freshness = Freshness::new(1_000, 10_000, 2_000, 5_000).unwrap();
        freshness.state = FreshnessState::Expired;
        let result = DefinitiveResult {
            observation_id: ObservationId::new("observation_01").unwrap(),
            target: Target {
                username: crate::Username::new("alice").unwrap(),
                site_id: SiteId::new("github").unwrap(),
            },
            verdict: DefinitiveVerdict::Found,
            source: ResultSource::ManagedProbe,
            freshness,
            evidence_class: EvidenceClass::E4StructuredIdentity,
            evidence_digest: EvidenceDigest::new("a".repeat(64)).unwrap(),
            region_class: RegionClass::new("jp").unwrap(),
            rule_hash: RuleHash::new("b".repeat(64)).unwrap(),
            rule_health: RuleHealthStatus::Healthy,
            profile_url: None,
        };
        assert!(result.validate().is_err());
    }
}
