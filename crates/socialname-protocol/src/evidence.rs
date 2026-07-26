use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    DefinitiveVerdict, EvidenceCapsuleId, EvidenceClass, EvidenceDigest, HttpsUrl, ObservationId,
    ProtocolVersion, RegionClass, RuleHash, Target, UncertaintyReason, Validate, ValidationCode,
    ValidationErrors,
};

pub const EVIDENCE_CAPSULE_V1: &str = "socialname.dev/evidence-capsule/v1";
pub const MAX_EVIDENCE_PROBES: usize = 32;
pub const MAX_EVIDENCE_MATCHER_TRACES: usize = 128;
pub const MAX_EVIDENCE_CAPSULE_BYTES: usize = 64 * 1_024;

const DAY_MS: i64 = 24 * 60 * 60 * 1_000;
const MAX_PRIVATE_RETENTION_DAYS: i64 = 730;
const SHARED_RETENTION_DAYS: i64 = 400;
const MAX_RESEARCH_RETENTION_DAYS: i64 = 30;
const MAX_RESEARCH_EXCERPT_BYTES: usize = 2 * 1_024;
const MAX_PROBE_ID_BYTES: usize = 64;
const MAX_CONTENT_TYPE_BYTES: usize = 256;
const MAX_MATCHER_PATH_BYTES: usize = 512;
const MAX_MATCHER_DETAIL_BYTES: usize = 1_024;
const MAX_BODY_BYTES: u64 = 8 * 1_024 * 1_024;
const MAX_LATENCY_BUCKET_MS: u32 = 120_000;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum EvidenceCapsuleSchema {
    #[default]
    #[serde(rename = "socialname.dev/evidence-capsule/v1")]
    V1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCapsuleProfile {
    PrivateHistory,
    SharedObservation,
    SharedResearch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceTransportOutcome {
    Completed,
    Blocked,
    RateLimited,
    Timeout,
    Dns,
    Connect,
    Tls,
    RedirectRejected,
    ResponseTooLarge,
    Decode,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvidenceOutcome {
    Definitive { verdict: DefinitiveVerdict },
    Uncertain { reason: UncertaintyReason },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceProvenance {
    pub rule_hash: RuleHash,
    pub rule_pack_hash: String,
    pub engine_hash: String,
    pub rule_pack_metadata_id: String,
    pub rule_promotion_id: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceNetworkClass {
    Managed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceVantage {
    pub region_class: RegionClass,
    pub network_class: EvidenceNetworkClass,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceProbe {
    pub probe_id: String,
    pub transport: EvidenceTransportOutcome,
    pub status: Option<u16>,
    pub final_url: Option<HttpsUrl>,
    pub content_type: Option<String>,
    pub body_bytes: u64,
    pub body_truncated: bool,
    pub latency_bucket_ms: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceMatcherTrace {
    pub path: String,
    pub matched: bool,
    pub detail: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceResearchExtension {
    pub sanitized_excerpt: String,
}

impl std::fmt::Debug for EvidenceResearchExtension {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("EvidenceResearchExtension([REDACTED])")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceCapsuleResource {
    pub schema: ProtocolVersion,
    pub capsule_schema: EvidenceCapsuleSchema,
    pub evidence_capsule_id: EvidenceCapsuleId,
    pub observation_id: ObservationId,
    pub profile: EvidenceCapsuleProfile,
    pub target: Target,
    pub outcome: EvidenceOutcome,
    pub provenance: EvidenceProvenance,
    pub vantage: EvidenceVantage,
    pub evidence_class: EvidenceClass,
    pub evidence_digest: EvidenceDigest,
    pub profile_url: Option<HttpsUrl>,
    pub probes: Vec<EvidenceProbe>,
    pub matcher_trace: Vec<EvidenceMatcherTrace>,
    pub collected_at_unix_ms: i64,
    pub structured_retained_until_unix_ms: i64,
    pub research_extension: Option<EvidenceResearchExtension>,
    pub research_retained_until_unix_ms: Option<i64>,
}

impl Validate for EvidenceCapsuleResource {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = Vec::new();
        validate_hash(
            &mut errors,
            "provenance.rule_pack_hash",
            &self.provenance.rule_pack_hash,
        );
        validate_hash(
            &mut errors,
            "provenance.engine_hash",
            &self.provenance.engine_hash,
        );
        validate_hash(
            &mut errors,
            "provenance.rule_pack_metadata_id",
            &self.provenance.rule_pack_metadata_id,
        );
        validate_hash(
            &mut errors,
            "provenance.rule_promotion_id",
            &self.provenance.rule_promotion_id,
        );

        if self.probes.len() > MAX_EVIDENCE_PROBES {
            errors.push(("probes", ValidationCode::TooManyItems));
        }
        for probe in &self.probes {
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
            if probe.body_bytes > MAX_BODY_BYTES || probe.latency_bucket_ms > MAX_LATENCY_BUCKET_MS
            {
                errors.push(("probes", ValidationCode::OutOfRange));
                break;
            }
        }

        if self.matcher_trace.len() > MAX_EVIDENCE_MATCHER_TRACES {
            errors.push(("matcher_trace", ValidationCode::TooManyItems));
        }
        for trace in &self.matcher_trace {
            if !valid_text(&trace.path, MAX_MATCHER_PATH_BYTES)
                || !valid_text(&trace.detail, MAX_MATCHER_DETAIL_BYTES)
            {
                errors.push(("matcher_trace", ValidationCode::InvalidFormat));
                break;
            }
        }

        let maximum_structured_retention_days = match self.profile {
            EvidenceCapsuleProfile::PrivateHistory => MAX_PRIVATE_RETENTION_DAYS,
            EvidenceCapsuleProfile::SharedObservation | EvidenceCapsuleProfile::SharedResearch => {
                SHARED_RETENTION_DAYS
            }
        };
        let structured_maximum = self
            .collected_at_unix_ms
            .checked_add(maximum_structured_retention_days * DAY_MS);
        let shared_deadline_must_be_exact = matches!(
            self.profile,
            EvidenceCapsuleProfile::SharedObservation | EvidenceCapsuleProfile::SharedResearch
        );
        if self.collected_at_unix_ms < 0
            || self.structured_retained_until_unix_ms <= self.collected_at_unix_ms
            || structured_maximum.is_none_or(|maximum| {
                if shared_deadline_must_be_exact {
                    self.structured_retained_until_unix_ms != maximum
                } else {
                    self.structured_retained_until_unix_ms > maximum
                }
            })
        {
            errors.push((
                "structured_retained_until_unix_ms",
                ValidationCode::InvalidRelation,
            ));
        }

        match (
            &self.research_extension,
            self.research_retained_until_unix_ms,
        ) {
            (None, None) => {}
            (Some(extension), Some(deadline))
                if self.profile == EvidenceCapsuleProfile::SharedResearch
                    && valid_text(&extension.sanitized_excerpt, MAX_RESEARCH_EXCERPT_BYTES)
                    && deadline > self.collected_at_unix_ms
                    && self
                        .collected_at_unix_ms
                        .checked_add(MAX_RESEARCH_RETENTION_DAYS * DAY_MS)
                        .is_some_and(|maximum| deadline <= maximum)
                    && deadline <= self.structured_retained_until_unix_ms => {}
            _ => errors.push(("research_extension", ValidationCode::InvalidRelation)),
        }

        if errors.is_empty()
            && serde_json::to_vec(self).is_ok_and(|bytes| bytes.len() <= MAX_EVIDENCE_CAPSULE_BYTES)
        {
            Ok(())
        } else {
            if errors.is_empty() {
                errors.push(("evidence_capsule", ValidationCode::TooManyItems));
            }
            let (field, code) = errors[0];
            let mut validation = ValidationErrors::new(field, code);
            for (field, code) in errors.into_iter().skip(1) {
                validation.push(field, code);
            }
            Err(validation)
        }
    }
}

fn validate_hash<'a>(errors: &mut Vec<(&'a str, ValidationCode)>, field: &'a str, value: &str) {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        errors.push((field, ValidationCode::InvalidFormat));
    }
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
    use crate::{SiteId, Username};

    const DAY_MS: i64 = 24 * 60 * 60 * 1_000;

    fn resource() -> EvidenceCapsuleResource {
        EvidenceCapsuleResource {
            schema: ProtocolVersion::ApiV1,
            capsule_schema: EvidenceCapsuleSchema::V1,
            evidence_capsule_id: EvidenceCapsuleId::new("capsule_01").unwrap(),
            observation_id: ObservationId::new("observation_01").unwrap(),
            profile: EvidenceCapsuleProfile::SharedObservation,
            target: Target {
                username: Username::new("private-target").unwrap(),
                site_id: SiteId::new("github").unwrap(),
            },
            outcome: EvidenceOutcome::Definitive {
                verdict: DefinitiveVerdict::Found,
            },
            provenance: EvidenceProvenance {
                rule_hash: RuleHash::new("1".repeat(64)).unwrap(),
                rule_pack_hash: "2".repeat(64),
                engine_hash: "3".repeat(64),
                rule_pack_metadata_id: "4".repeat(64),
                rule_promotion_id: "5".repeat(64),
            },
            vantage: EvidenceVantage {
                region_class: RegionClass::new("jp").unwrap(),
                network_class: EvidenceNetworkClass::Managed,
            },
            evidence_class: EvidenceClass::E4StructuredIdentity,
            evidence_digest: EvidenceDigest::new("6".repeat(64)).unwrap(),
            profile_url: Some(HttpsUrl::new("https://example.test/u/private-target").unwrap()),
            probes: vec![EvidenceProbe {
                probe_id: "api".to_owned(),
                transport: EvidenceTransportOutcome::Completed,
                status: Some(200),
                final_url: Some(HttpsUrl::new("https://example.test/api/private-target").unwrap()),
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
            collected_at_unix_ms: 1_000,
            structured_retained_until_unix_ms: 1_000 + 400 * DAY_MS,
            research_extension: None,
            research_retained_until_unix_ms: None,
        }
    }

    #[test]
    fn shared_capsule_is_bounded_and_has_exact_retention() {
        let mut capsule = resource();
        assert!(capsule.validate().is_ok());

        capsule.structured_retained_until_unix_ms -= 1;
        assert!(capsule.validate().is_err());
        capsule.structured_retained_until_unix_ms += 1;

        capsule.probes = (0..=MAX_EVIDENCE_PROBES)
            .map(|index| EvidenceProbe {
                probe_id: format!("probe_{index}"),
                ..capsule.probes[0].clone()
            })
            .collect();
        assert!(capsule.validate().is_err());
    }

    #[test]
    fn research_excerpt_is_redacted_and_cannot_outlive_thirty_days() {
        let mut capsule = resource();
        capsule.profile = EvidenceCapsuleProfile::SharedResearch;
        capsule.research_extension = Some(EvidenceResearchExtension {
            sanitized_excerpt: "sensitive public excerpt".to_owned(),
        });
        capsule.research_retained_until_unix_ms = Some(1_000 + 30 * DAY_MS);
        assert!(capsule.validate().is_ok());
        assert!(!format!("{capsule:?}").contains("sensitive public excerpt"));

        capsule.research_retained_until_unix_ms = Some(1_000 + 30 * DAY_MS + 1);
        assert!(capsule.validate().is_err());
    }

    #[test]
    fn unknown_or_forbidden_content_has_no_wire_slot() {
        let mut json = serde_json::to_value(resource()).unwrap();
        json.as_object_mut()
            .unwrap()
            .insert("raw_http_body".to_owned(), serde_json::json!("forbidden"));
        assert!(serde_json::from_value::<EvidenceCapsuleResource>(json).is_err());
    }
}
