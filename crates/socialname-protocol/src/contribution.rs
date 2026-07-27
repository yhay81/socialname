use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    ContributionId, EvidenceClass, EvidenceDigest, EvidenceMatcherTrace, EvidenceOutcome,
    EvidenceProbe, InstallationId, ProtocolVersion, RegionClass, RuleHash, Target, Validate,
    ValidationCode, ValidationErrors,
};

pub const SHARED_CONTRIBUTION_V1: &str = "socialname.dev/shared-contribution/v1";
pub const MAX_CONTRIBUTION_PAGE_ITEMS: usize = 50;
pub const MAX_CONTRIBUTION_PROBES: usize = 8;
pub const MAX_CONTRIBUTION_MATCHER_TRACES: usize = 32;
pub const MAX_CONTRIBUTION_BYTES: usize = 32 * 1_024;

const MAX_PROBE_ID_BYTES: usize = 64;
const MAX_CONTENT_TYPE_BYTES: usize = 256;
const MAX_MATCHER_PATH_BYTES: usize = 512;
const MAX_MATCHER_DETAIL_BYTES: usize = 1_024;
const MAX_BODY_BYTES: u64 = 8 * 1_024 * 1_024;
const MAX_LATENCY_BUCKET_MS: u32 = 120_000;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum SharedContributionSchema {
    #[default]
    #[serde(rename = "socialname.dev/shared-contribution/v1")]
    V1,
}

/// The client-declared coarse network class of the contributing vantage.
///
/// The claim provides diversity context and is recorded as claimed; it is not
/// treated as verified infrastructure truth.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ContributionNetworkClass {
    Datacenter,
    Residential,
    Anonymizer,
    Unknown,
}

impl ContributionNetworkClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Datacenter => "datacenter",
            Self::Residential => "residential",
            Self::Anonymizer => "anonymizer",
            Self::Unknown => "unknown",
        }
    }
}

/// Whether an accepted contribution may influence the current shared state or
/// is retained as history only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ContributionInfluenceScope {
    Current,
    HistoryOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ContributionHistoryReason {
    StaleUpload,
    RuleHealthNotGreen,
}

/// The contributor's current reputation tier for the submitted site family.
///
/// Tiers are closed calibration states, never a synthetic confidence
/// percentage. A suspended installation cannot submit new contributions, but
/// an already-accepted resource keeps reporting the current tier honestly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ContributorReputationTier {
    New,
    Calibrated,
    Trusted,
    Suspended,
}

impl ContributorReputationTier {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Calibrated => "calibrated",
            Self::Trusted => "trusted",
            Self::Suspended => "suspended",
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedContributionSubmitRequest {
    pub schema: ProtocolVersion,
    pub installation_id: InstallationId,
    pub consent_grant_id: crate::ConsentGrantId,
    pub sequence_number: u64,
    pub target: Target,
    pub rule_hash: RuleHash,
    pub engine_hash: String,
    pub observed_at_unix_ms: i64,
    pub region_class: RegionClass,
    pub network_class: ContributionNetworkClass,
    pub outcome: EvidenceOutcome,
    pub evidence_class: EvidenceClass,
    pub evidence_digest: EvidenceDigest,
    pub probes: Vec<EvidenceProbe>,
    pub matcher_trace: Vec<EvidenceMatcherTrace>,
}

impl std::fmt::Debug for SharedContributionSubmitRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SharedContributionSubmitRequest")
            .field("schema", &self.schema)
            .field("installation_id", &"[REDACTED]")
            .field("consent_grant_id", &self.consent_grant_id)
            .field("sequence_number", &self.sequence_number)
            .field("target", &self.target)
            .field("rule_hash", &self.rule_hash)
            .field("engine_hash", &self.engine_hash)
            .field("observed_at_unix_ms", &self.observed_at_unix_ms)
            .field("region_class", &self.region_class)
            .field("network_class", &self.network_class)
            .field("evidence_class", &self.evidence_class)
            .finish_non_exhaustive()
    }
}

impl Validate for SharedContributionSubmitRequest {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = Vec::new();
        if self.sequence_number == 0 {
            errors.push(("sequence_number", ValidationCode::OutOfRange));
        }
        if !valid_sha256_hex(&self.engine_hash) {
            errors.push(("engine_hash", ValidationCode::InvalidFormat));
        }
        if self.observed_at_unix_ms <= 0 {
            errors.push(("observed_at_unix_ms", ValidationCode::OutOfRange));
        }
        validate_evidence_relation(
            &mut errors,
            &self.outcome,
            self.evidence_class,
            self.probes.len(),
        );
        validate_probes(&mut errors, &self.probes);
        validate_matcher_trace(&mut errors, &self.matcher_trace);
        if errors.is_empty()
            && serde_json::to_vec(self).is_ok_and(|bytes| bytes.len() <= MAX_CONTRIBUTION_BYTES)
        {
            Ok(())
        } else {
            if errors.is_empty() {
                errors.push(("contribution", ValidationCode::TooManyItems));
            }
            Err(collect(errors))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedContributionResource {
    pub schema: ProtocolVersion,
    pub contribution_schema: SharedContributionSchema,
    pub contribution_id: ContributionId,
    pub target: Target,
    pub rule_hash: RuleHash,
    pub region_class: RegionClass,
    pub network_class: ContributionNetworkClass,
    pub outcome: EvidenceOutcome,
    pub evidence_class: EvidenceClass,
    pub evidence_digest: EvidenceDigest,
    pub sequence_number: u64,
    pub influence_scope: ContributionInfluenceScope,
    pub history_reason: Option<ContributionHistoryReason>,
    pub reputation_tier: ContributorReputationTier,
    pub observed_at_unix_ms: i64,
    pub received_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
}

impl Validate for SharedContributionResource {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = Vec::new();
        if self.sequence_number == 0 {
            errors.push(("sequence_number", ValidationCode::OutOfRange));
        }
        let scope_valid = match self.influence_scope {
            ContributionInfluenceScope::Current => self.history_reason.is_none(),
            ContributionInfluenceScope::HistoryOnly => self.history_reason.is_some(),
        };
        if !scope_valid {
            errors.push(("history_reason", ValidationCode::InvalidRelation));
        }
        if self.observed_at_unix_ms <= 0
            || self.received_at_unix_ms <= 0
            || self.expires_at_unix_ms <= self.observed_at_unix_ms
        {
            errors.push(("timestamps", ValidationCode::InvalidRelation));
        }
        validate_evidence_relation(&mut errors, &self.outcome, self.evidence_class, 1);
        if errors.is_empty() {
            Ok(())
        } else {
            Err(collect(errors))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedContributionPage {
    pub schema: ProtocolVersion,
    pub contributions: Vec<SharedContributionResource>,
    pub next_cursor: Option<ContributionId>,
}

impl Validate for SharedContributionPage {
    fn validate(&self) -> Result<(), ValidationErrors> {
        if self.contributions.len() > MAX_CONTRIBUTION_PAGE_ITEMS {
            return Err(ValidationErrors::new(
                "contributions",
                ValidationCode::TooManyItems,
            ));
        }
        if self.next_cursor.is_some()
            && self.next_cursor.as_ref()
                != self
                    .contributions
                    .last()
                    .map(|contribution| &contribution.contribution_id)
        {
            return Err(ValidationErrors::new(
                "next_cursor",
                ValidationCode::InvalidRelation,
            ));
        }
        for contribution in &self.contributions {
            contribution.validate()?;
        }
        Ok(())
    }
}

fn validate_evidence_relation(
    errors: &mut Vec<(&'static str, ValidationCode)>,
    outcome: &EvidenceOutcome,
    evidence_class: EvidenceClass,
    probe_count: usize,
) {
    match outcome {
        EvidenceOutcome::Definitive { .. } => {
            let strong_enough = matches!(
                evidence_class,
                EvidenceClass::E2DifferentialTemplate
                    | EvidenceClass::E3ExplicitEndpoint
                    | EvidenceClass::E4StructuredIdentity
            );
            if !strong_enough || probe_count == 0 {
                errors.push(("outcome", ValidationCode::InvalidRelation));
            }
        }
        EvidenceOutcome::Uncertain { .. } => {}
    }
}

fn validate_probes(errors: &mut Vec<(&'static str, ValidationCode)>, probes: &[EvidenceProbe]) {
    if probes.len() > MAX_CONTRIBUTION_PROBES {
        errors.push(("probes", ValidationCode::TooManyItems));
    }
    for probe in probes {
        if !valid_label(&probe.probe_id, MAX_PROBE_ID_BYTES) {
            errors.push(("probes.probe_id", ValidationCode::InvalidFormat));
            break;
        }
        if probe
            .content_type
            .as_ref()
            .is_some_and(|value| !valid_text(value, MAX_CONTENT_TYPE_BYTES))
        {
            errors.push(("probes.content_type", ValidationCode::InvalidFormat));
            break;
        }
        if probe.body_bytes > MAX_BODY_BYTES || probe.latency_bucket_ms > MAX_LATENCY_BUCKET_MS {
            errors.push(("probes", ValidationCode::OutOfRange));
            break;
        }
    }
}

fn validate_matcher_trace(
    errors: &mut Vec<(&'static str, ValidationCode)>,
    matcher_trace: &[EvidenceMatcherTrace],
) {
    if matcher_trace.len() > MAX_CONTRIBUTION_MATCHER_TRACES {
        errors.push(("matcher_trace", ValidationCode::TooManyItems));
    }
    for trace in matcher_trace {
        if !valid_text(&trace.path, MAX_MATCHER_PATH_BYTES)
            || !valid_text(&trace.detail, MAX_MATCHER_DETAIL_BYTES)
        {
            errors.push(("matcher_trace", ValidationCode::InvalidFormat));
            break;
        }
    }
}

fn collect(errors: Vec<(&'static str, ValidationCode)>) -> ValidationErrors {
    let (field, code) = errors[0];
    let mut validation = ValidationErrors::new(field, code);
    for (field, code) in errors.into_iter().skip(1) {
        validation.push(field, code);
    }
    validation
}

fn valid_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_label(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_text(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ConsentGrantId, DefinitiveVerdict, EvidenceTransportOutcome, HttpsUrl, SiteId,
        UncertaintyReason, Username,
    };

    fn submit_request() -> SharedContributionSubmitRequest {
        SharedContributionSubmitRequest {
            schema: ProtocolVersion::ApiV1,
            installation_id: InstallationId::new("11111111-1111-4111-8111-111111111111").unwrap(),
            consent_grant_id: ConsentGrantId::new("00000000-0000-0000-0000-0000000000c1").unwrap(),
            sequence_number: 7,
            target: Target {
                username: Username::new("private-target").unwrap(),
                site_id: SiteId::new("github").unwrap(),
            },
            rule_hash: RuleHash::new("1".repeat(64)).unwrap(),
            engine_hash: "2".repeat(64),
            observed_at_unix_ms: 1_000,
            region_class: RegionClass::new("jp").unwrap(),
            network_class: ContributionNetworkClass::Residential,
            outcome: EvidenceOutcome::Definitive {
                verdict: DefinitiveVerdict::Found,
            },
            evidence_class: EvidenceClass::E4StructuredIdentity,
            evidence_digest: EvidenceDigest::new("3".repeat(64)).unwrap(),
            probes: vec![EvidenceProbe {
                probe_id: "api".to_owned(),
                transport: EvidenceTransportOutcome::Completed,
                status: Some(200),
                final_url: Some(HttpsUrl::new("https://example.test/u/private-target").unwrap()),
                content_type: Some("application/json".to_owned()),
                body_bytes: 128,
                body_truncated: false,
                latency_bucket_ms: 100,
            }],
            matcher_trace: vec![EvidenceMatcherTrace {
                path: "found.all[0]".to_owned(),
                matched: true,
                detail: "status Some(200)".to_owned(),
            }],
        }
    }

    fn resource() -> SharedContributionResource {
        let request = submit_request();
        SharedContributionResource {
            schema: ProtocolVersion::ApiV1,
            contribution_schema: SharedContributionSchema::V1,
            contribution_id: ContributionId::new("contribution_01").unwrap(),
            target: request.target,
            rule_hash: request.rule_hash,
            region_class: request.region_class,
            network_class: request.network_class,
            outcome: request.outcome,
            evidence_class: request.evidence_class,
            evidence_digest: request.evidence_digest,
            sequence_number: request.sequence_number,
            influence_scope: ContributionInfluenceScope::HistoryOnly,
            history_reason: Some(ContributionHistoryReason::RuleHealthNotGreen),
            reputation_tier: ContributorReputationTier::New,
            observed_at_unix_ms: 1_000,
            received_at_unix_ms: 2_000,
            expires_at_unix_ms: 1_000 + 24 * 60 * 60 * 1_000,
        }
    }

    #[test]
    fn submit_request_is_bounded_and_redacts_sensitive_identifiers() {
        let request = submit_request();
        assert!(request.validate().is_ok());
        let debug = format!("{request:?}");
        assert!(!debug.contains("11111111-1111-4111-8111-111111111111"));
        assert!(!debug.contains("private-target"));
    }

    #[test]
    fn definitive_verdicts_require_strong_evidence_and_probes() {
        let mut request = submit_request();
        request.evidence_class = EvidenceClass::E1WeakSignal;
        assert!(request.validate().is_err());

        request.evidence_class = EvidenceClass::E4StructuredIdentity;
        request.probes.clear();
        assert!(request.validate().is_err());

        request.outcome = EvidenceOutcome::Uncertain {
            reason: UncertaintyReason::SiteChanged,
        };
        request.evidence_class = EvidenceClass::E0NoAccountEvidence;
        assert!(request.validate().is_ok());
    }

    #[test]
    fn zero_sequence_and_malformed_engine_hash_are_rejected() {
        let mut request = submit_request();
        request.sequence_number = 0;
        request.engine_hash = "UPPERCASE".to_owned();
        let errors = request.validate().unwrap_err();
        assert_eq!(errors.issues().len(), 2);
    }

    #[test]
    fn resource_binds_history_reason_to_the_influence_scope() {
        let mut resource = resource();
        assert!(resource.validate().is_ok());

        resource.history_reason = None;
        assert!(resource.validate().is_err());

        resource.influence_scope = ContributionInfluenceScope::Current;
        assert!(resource.validate().is_ok());

        resource.expires_at_unix_ms = resource.observed_at_unix_ms;
        assert!(resource.validate().is_err());
    }

    #[test]
    fn page_cursor_must_name_the_last_returned_contribution() {
        let mut page = SharedContributionPage {
            schema: ProtocolVersion::ApiV1,
            contributions: vec![resource()],
            next_cursor: Some(ContributionId::new("contribution_01").unwrap()),
        };
        assert!(page.validate().is_ok());
        page.next_cursor = Some(ContributionId::new("contribution_02").unwrap());
        assert!(page.validate().is_err());
    }

    #[test]
    fn unknown_fields_have_no_wire_slot() {
        let mut json = serde_json::to_value(submit_request()).unwrap();
        json.as_object_mut()
            .unwrap()
            .insert("raw_http_body".to_owned(), serde_json::json!("forbidden"));
        assert!(serde_json::from_value::<SharedContributionSubmitRequest>(json).is_err());
    }
}
