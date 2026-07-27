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

pub const MAX_SEARCH_HISTORY_PAGE_ITEMS: usize = 50;
pub const MAX_SEARCH_EXPORT_PAGE_EVENTS: usize = 50;
pub const MAX_SEARCH_EXPORT_EVENTS: usize = 1_026;
pub const SEARCH_EXPORT_V1: &str = "socialname.dev/search-export/v1";

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
pub struct SearchHistoryPage {
    pub schema: ProtocolVersion,
    pub searches: Vec<SearchResource>,
    pub next_cursor: Option<SearchId>,
}

impl Validate for SearchHistoryPage {
    fn validate(&self) -> Result<(), ValidationErrors> {
        if self.searches.len() > MAX_SEARCH_HISTORY_PAGE_ITEMS {
            return Err(ValidationErrors::new(
                "searches",
                ValidationCode::TooManyItems,
            ));
        }
        let mut ids = BTreeSet::new();
        for search in &self.searches {
            search.validate()?;
            if !ids.insert(search.search_id.as_str()) {
                return Err(ValidationErrors::new("searches", ValidationCode::Duplicate));
            }
        }
        if self.next_cursor.as_ref() != self.searches.last().map(|search| &search.search_id)
            && self.next_cursor.is_some()
        {
            return Err(ValidationErrors::new(
                "next_cursor",
                ValidationCode::InvalidRelation,
            ));
        }
        Ok(())
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
    InvalidTarget,
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
pub struct RegionalAssertion {
    pub region_class: RegionClass,
    pub outcome: AssertionOutcome,
    pub quality: AssertionQuality,
    pub evidence_class: EvidenceClass,
    pub freshness: Freshness,
    pub sources: Vec<ResultSource>,
    pub support_group_count: u32,
    pub managed_support: bool,
    pub supporting_observation_ids: Vec<ObservationId>,
    pub conflicting_observation_ids: Vec<ObservationId>,
}

impl Validate for RegionalAssertion {
    fn validate(&self) -> Result<(), ValidationErrors> {
        validate_assertion_projection(
            &self.outcome,
            self.quality,
            &self.freshness,
            &self.sources,
            self.support_group_count,
            self.managed_support,
            &self.supporting_observation_ids,
            &self.conflicting_observation_ids,
        )
    }
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regional_assertions: Option<Vec<RegionalAssertion>>,
    pub derivation_version: String,
}

impl Validate for Assertion {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut validations = vec![
            validate_nonempty_ids("regions", &self.regions, 16),
            validate_assertion_projection(
                &self.outcome,
                self.quality,
                &self.freshness,
                &self.sources,
                self.support_group_count,
                self.managed_support,
                &self.supporting_observation_ids,
                &self.conflicting_observation_ids,
            ),
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

        if let Some(regional_assertions) = &self.regional_assertions {
            if regional_assertions.is_empty() || regional_assertions.len() > 16 {
                validations.push(Err(ValidationErrors::new(
                    "regional_assertions",
                    ValidationCode::OutOfRange,
                )));
            }
            let global_regions = self.regions.iter().collect::<BTreeSet<_>>();
            let regional_regions = regional_assertions
                .iter()
                .map(|regional| &regional.region_class)
                .collect::<BTreeSet<_>>();
            if regional_regions.len() != regional_assertions.len()
                || regional_regions != global_regions
            {
                validations.push(Err(ValidationErrors::new(
                    "regional_assertions.region_class",
                    ValidationCode::InvalidRelation,
                )));
            }

            let global_sources = self.sources.iter().copied().collect::<BTreeSet<_>>();
            let global_observation_ids = self
                .supporting_observation_ids
                .iter()
                .chain(&self.conflicting_observation_ids)
                .collect::<BTreeSet<_>>();
            for regional in regional_assertions {
                validations.push(regional.validate());
                if !regional
                    .sources
                    .iter()
                    .all(|source| global_sources.contains(source))
                    || !regional
                        .supporting_observation_ids
                        .iter()
                        .chain(&regional.conflicting_observation_ids)
                        .all(|id| global_observation_ids.contains(id))
                {
                    validations.push(Err(ValidationErrors::new(
                        "regional_assertions",
                        ValidationCode::InvalidRelation,
                    )));
                }
            }
        }

        collect_validations(validations)
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_assertion_projection(
    outcome: &AssertionOutcome,
    quality: AssertionQuality,
    freshness: &Freshness,
    sources: &[ResultSource],
    support_group_count: u32,
    managed_support: bool,
    supporting_observation_ids: &[ObservationId],
    conflicting_observation_ids: &[ObservationId],
) -> Result<(), ValidationErrors> {
    let mut validations = vec![
        freshness.validate(),
        validate_nonempty_ids("sources", sources, 8),
    ];
    let freshness_quality_valid = match freshness.state {
        crate::FreshnessState::Current => quality != AssertionQuality::Stale,
        crate::FreshnessState::Stale | crate::FreshnessState::Expired => {
            quality == AssertionQuality::Stale
        }
    };
    if !freshness_quality_valid {
        validations.push(Err(ValidationErrors::new(
            "assertion.freshness",
            ValidationCode::InvalidRelation,
        )));
    }

    let support_ids = supporting_observation_ids.iter().collect::<BTreeSet<_>>();
    let conflicting_ids = conflicting_observation_ids.iter().collect::<BTreeSet<_>>();
    if support_ids.len() != supporting_observation_ids.len()
        || conflicting_ids.len() != conflicting_observation_ids.len()
        || !support_ids.is_disjoint(&conflicting_ids)
        || support_ids.len().saturating_add(conflicting_ids.len()) > 256
    {
        validations.push(Err(ValidationErrors::new(
            "observation_ids",
            ValidationCode::Duplicate,
        )));
    }

    match (outcome, quality) {
        (
            AssertionOutcome::Inconclusive {
                reason: UncertaintyReason::ConflictingEvidence,
            },
            AssertionQuality::Conflicted,
        ) if supporting_observation_ids.is_empty()
            && !conflicting_observation_ids.is_empty()
            && support_group_count == 0 => {}
        (AssertionOutcome::Found | AssertionOutcome::NotFound, quality)
            if quality != AssertionQuality::Conflicted
                && !supporting_observation_ids.is_empty()
                && conflicting_observation_ids.is_empty()
                && support_group_count > 0 => {}
        _ => validations.push(Err(ValidationErrors::new(
            "assertion",
            ValidationCode::InvalidRelation,
        ))),
    }

    let managed_quality_valid = match quality {
        AssertionQuality::Verified => managed_support,
        AssertionQuality::Corroborated
        | AssertionQuality::SingleVantage
        | AssertionQuality::Untrusted => !managed_support,
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum SearchExportSchema {
    #[default]
    #[serde(rename = "socialname.dev/search-export/v1")]
    V1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchExportPage {
    pub schema: ProtocolVersion,
    pub export_schema: SearchExportSchema,
    pub search: SearchResource,
    pub events: Vec<SearchEvent>,
    pub total_events: u32,
    pub complete: bool,
    pub next_cursor: Option<EventId>,
}

impl Validate for SearchExportPage {
    fn validate(&self) -> Result<(), ValidationErrors> {
        self.search.validate()?;
        if !matches!(
            self.search.state,
            SearchState::Completed | SearchState::Cancelled | SearchState::Failed
        ) {
            return Err(ValidationErrors::new(
                "search.state",
                ValidationCode::InvalidRelation,
            ));
        }
        let total_events = usize::try_from(self.total_events)
            .map_err(|_| ValidationErrors::new("total_events", ValidationCode::OutOfRange))?;
        if !(2..=MAX_SEARCH_EXPORT_EVENTS).contains(&total_events) {
            return Err(ValidationErrors::new(
                "total_events",
                ValidationCode::OutOfRange,
            ));
        }
        if self.events.len() > MAX_SEARCH_EXPORT_PAGE_EVENTS || self.events.len() > total_events {
            return Err(ValidationErrors::new(
                "events",
                ValidationCode::TooManyItems,
            ));
        }
        if self.complete != self.next_cursor.is_none() {
            return Err(ValidationErrors::new(
                "complete",
                ValidationCode::InvalidRelation,
            ));
        }
        if self.next_cursor.as_ref() != self.events.last().map(|event| &event.event_id)
            && self.next_cursor.is_some()
        {
            return Err(ValidationErrors::new(
                "next_cursor",
                ValidationCode::InvalidRelation,
            ));
        }

        let mut event_ids = BTreeSet::new();
        let mut previous_sequence = None;
        for event in &self.events {
            event.validate()?;
            if event.search_id != self.search.search_id
                || event.sequence > u64::from(self.total_events)
                || previous_sequence.is_some_and(|previous| event.sequence <= previous)
            {
                return Err(ValidationErrors::new(
                    "events",
                    ValidationCode::InvalidRelation,
                ));
            }
            if !event_ids.insert(event.event_id.as_str()) {
                return Err(ValidationErrors::new("events", ValidationCode::Duplicate));
            }
            previous_sequence = Some(event.sequence);
        }

        if self.complete && !self.events.is_empty() {
            let final_event = self.events.last().expect("nonempty checked");
            let expected_terminal = match self.search.state {
                SearchState::Completed => SearchTerminalState::Completed,
                SearchState::Cancelled => SearchTerminalState::Cancelled,
                SearchState::Failed => SearchTerminalState::Failed,
                SearchState::Accepted | SearchState::Running => unreachable!("terminal checked"),
            };
            if final_event.sequence != u64::from(self.total_events)
                || !matches!(
                    &final_event.data,
                    SearchEventData::Finished { state, .. } if *state == expected_terminal
                )
            {
                return Err(ValidationErrors::new(
                    "events",
                    ValidationCode::InvalidRelation,
                ));
            }
        }
        Ok(())
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

    fn regional_assertion_fixture() -> Assertion {
        let freshness = Freshness::new(1_000, 10_000, 2_000, 5_000).unwrap();
        let observation_id = ObservationId::new("observation_01").unwrap();
        let region_class = RegionClass::new("jp").unwrap();
        Assertion {
            target: Target {
                username: crate::Username::new("alice").unwrap(),
                site_id: SiteId::new("github").unwrap(),
            },
            outcome: AssertionOutcome::Found,
            quality: AssertionQuality::Verified,
            evidence_class: EvidenceClass::E4StructuredIdentity,
            freshness: freshness.clone(),
            sources: vec![ResultSource::ManagedProbe],
            regions: vec![region_class.clone()],
            support_group_count: 1,
            managed_support: true,
            supporting_observation_ids: vec![observation_id.clone()],
            conflicting_observation_ids: Vec::new(),
            regional_assertions: Some(vec![RegionalAssertion {
                region_class,
                outcome: AssertionOutcome::Found,
                quality: AssertionQuality::Verified,
                evidence_class: EvidenceClass::E4StructuredIdentity,
                freshness,
                sources: vec![ResultSource::ManagedProbe],
                support_group_count: 1,
                managed_support: true,
                supporting_observation_ids: vec![observation_id],
                conflicting_observation_ids: Vec::new(),
            }]),
            derivation_version: "assertion/v1".to_owned(),
        }
    }

    fn completed_search() -> SearchResource {
        SearchResource {
            schema: ProtocolVersion::ApiV1,
            search_id: SearchId::new("search_01").unwrap(),
            state: SearchState::Completed,
            request: request(),
            progress: SearchProgress {
                total_targets: 1,
                completed_targets: 1,
                definitive_results: 0,
                uncertain_results: 0,
                operational_failures: 1,
            },
            created_at_unix_ms: 1_000,
            updated_at_unix_ms: 2_000,
        }
    }

    fn export_events() -> Vec<SearchEvent> {
        vec![
            SearchEvent {
                schema: ProtocolVersion::ApiV1,
                event_id: EventId::new("event_01").unwrap(),
                search_id: SearchId::new("search_01").unwrap(),
                sequence: 1,
                emitted_at_unix_ms: 1_000,
                data: SearchEventData::Started { total_targets: 1 },
            },
            SearchEvent {
                schema: ProtocolVersion::ApiV1,
                event_id: EventId::new("event_02").unwrap(),
                search_id: SearchId::new("search_01").unwrap(),
                sequence: 2,
                emitted_at_unix_ms: 1_500,
                data: SearchEventData::OperationalFailure {
                    failure: OperationalFailure {
                        target: Target {
                            username: crate::Username::new("alice").unwrap(),
                            site_id: SiteId::new("github").unwrap(),
                        },
                        kind: OperationalFailureKind::Timeout,
                        source: ResultSource::ManagedProbe,
                        occurred_at_unix_ms: 1_500,
                        retryable: true,
                        region_class: Some(RegionClass::new("jp").unwrap()),
                        rule_hash: None,
                    },
                },
            },
            SearchEvent {
                schema: ProtocolVersion::ApiV1,
                event_id: EventId::new("event_03").unwrap(),
                search_id: SearchId::new("search_01").unwrap(),
                sequence: 3,
                emitted_at_unix_ms: 2_000,
                data: SearchEventData::Finished {
                    state: SearchTerminalState::Completed,
                    progress: completed_search().progress,
                },
            },
        ]
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

    #[test]
    fn regional_assertion_projection_is_validated_against_the_global_assertion() {
        let mut assertion = regional_assertion_fixture();
        assert!(assertion.validate().is_ok());

        assertion.regional_assertions.as_mut().unwrap()[0].region_class =
            RegionClass::new("us").unwrap();
        assert!(assertion.validate().is_err());

        let mut assertion = regional_assertion_fixture();
        assertion.regional_assertions.as_mut().unwrap()[0].supporting_observation_ids =
            vec![ObservationId::new("observation_02").unwrap()];
        assert!(assertion.validate().is_err());
    }

    #[test]
    fn regional_assertions_have_an_explicit_wire_shape() {
        let json = serde_json::to_value(regional_assertion_fixture()).unwrap();

        assert_eq!(json["regional_assertions"][0]["region_class"], "jp");
        assert_eq!(json["regional_assertions"][0]["outcome"]["kind"], "found");
        assert_eq!(json["regional_assertions"][0]["quality"], "verified");
        assert_eq!(
            json["regional_assertions"][0]["sources"][0],
            "managed_probe"
        );
    }

    #[test]
    fn historical_assertions_without_regional_projection_remain_compatible() {
        let mut json = serde_json::to_value(regional_assertion_fixture()).unwrap();
        json.as_object_mut().unwrap().remove("regional_assertions");

        let decoded: Assertion = serde_json::from_value(json).unwrap();

        assert!(decoded.regional_assertions.is_none());
        assert!(decoded.validate().is_ok());
        assert!(
            serde_json::to_value(decoded)
                .unwrap()
                .get("regional_assertions")
                .is_none()
        );
    }

    #[test]
    fn history_cursor_is_bound_to_the_last_search() {
        let search = completed_search();
        let page = SearchHistoryPage {
            schema: ProtocolVersion::ApiV1,
            searches: vec![search.clone()],
            next_cursor: Some(search.search_id.clone()),
        };
        assert!(page.validate().is_ok());

        let mut invalid = page;
        invalid.next_cursor = Some(SearchId::new("search_02").unwrap());
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn export_pages_bind_terminal_state_order_and_resumption() {
        let events = export_events();
        let first = SearchExportPage {
            schema: ProtocolVersion::ApiV1,
            export_schema: SearchExportSchema::V1,
            search: completed_search(),
            events: events[..2].to_vec(),
            total_events: 3,
            complete: false,
            next_cursor: Some(events[1].event_id.clone()),
        };
        assert!(first.validate().is_ok());

        let final_page = SearchExportPage {
            events: events[2..].to_vec(),
            complete: true,
            next_cursor: None,
            ..first.clone()
        };
        assert!(final_page.validate().is_ok());

        let mut wrong_terminal = final_page;
        wrong_terminal.events[0].data = SearchEventData::Finished {
            state: SearchTerminalState::Failed,
            progress: completed_search().progress,
        };
        assert!(wrong_terminal.validate().is_err());
    }
}
