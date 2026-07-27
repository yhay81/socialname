use std::{collections::BTreeSet, fmt, hash::Hash};

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, de};

pub const API_V1_SCHEMA: &str = "socialname.dev/api/v1";

const MAX_USERNAME_BYTES: usize = 256;
const MAX_SELECTION_USERNAMES: usize = 100;
const MAX_SELECTION_SITES: usize = 64;
const MAX_TARGET_PAIRS: usize = 512;
const MAX_REGION_CLASSES: usize = 8;
const MAXIMUM_AGE_MS: i64 = 30 * 24 * 60 * 60 * 1_000;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum ProtocolVersion {
    #[default]
    #[serde(rename = "socialname.dev/api/v1")]
    ApiV1,
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ValidationCode {
    Empty,
    TooManyItems,
    Duplicate,
    InvalidFormat,
    OutOfRange,
    InvalidRelation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ValidationIssue {
    pub field: String,
    pub code: ValidationCode,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationErrors {
    issues: Vec<ValidationIssue>,
}

impl ValidationErrors {
    #[must_use]
    pub fn new(field: impl Into<String>, code: ValidationCode) -> Self {
        Self {
            issues: vec![ValidationIssue {
                field: field.into(),
                code,
            }],
        }
    }

    pub fn push(&mut self, field: impl Into<String>, code: ValidationCode) {
        self.issues.push(ValidationIssue {
            field: field.into(),
            code,
        });
    }

    pub fn extend(&mut self, other: Self) {
        self.issues.extend(other.issues);
    }

    #[must_use]
    pub fn issues(&self) -> &[ValidationIssue] {
        &self.issues
    }

    #[must_use]
    pub fn into_issues(self) -> Vec<ValidationIssue> {
        self.issues
    }
}

impl fmt::Display for ValidationErrors {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} protocol validation issue(s)",
            self.issues.len()
        )
    }
}

impl std::error::Error for ValidationErrors {}

pub trait Validate {
    fn validate(&self) -> Result<(), ValidationErrors>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentifierError {
    field: &'static str,
    reason: &'static str,
}

impl IdentifierError {
    const fn new(field: &'static str, reason: &'static str) -> Self {
        Self { field, reason }
    }
}

impl fmt::Display for IdentifierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} is invalid: {} (the supplied value is omitted)",
            self.field, self.reason
        )
    }
}

impl std::error::Error for IdentifierError {}

fn deserialize_validated<'de, D, T>(
    deserializer: D,
    constructor: impl FnOnce(String) -> Result<T, IdentifierError>,
) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
{
    constructor(String::deserialize(deserializer)?).map_err(de::Error::custom)
}

fn validate_opaque_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

macro_rules! opaque_id {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
                let value = value.into();
                if validate_opaque_id(&value) {
                    Ok(Self(value))
                } else {
                    Err(IdentifierError::new(
                        $field,
                        "expected 1-128 ASCII letters, digits, hyphens, or underscores",
                    ))
                }
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                deserialize_validated(deserializer, Self::new)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

opaque_id!(SearchId, "search_id");
opaque_id!(WatchId, "watch_id");
opaque_id!(ObservationId, "observation_id");
opaque_id!(TransitionId, "transition_id");
opaque_id!(NotificationEndpointId, "notification_endpoint_id");
opaque_id!(NotificationDeliveryId, "notification_delivery_id");
opaque_id!(NotificationLogicalKey, "notification_logical_key");
opaque_id!(DeliveryErrorCode, "delivery_error_code");
opaque_id!(EventId, "event_id");
opaque_id!(RequestId, "request_id");
opaque_id!(ConsentGrantId, "consent_grant_id");
opaque_id!(ConsentSubjectId, "consent_subject_id");
opaque_id!(EvidenceCapsuleId, "evidence_capsule_id");
opaque_id!(DeletionRequestId, "deletion_request_id");
opaque_id!(WorkspaceId, "workspace_id");
opaque_id!(ApiKeyId, "api_key_id");
opaque_id!(MembershipId, "membership_id");
opaque_id!(TransitionReviewId, "review_id");
opaque_id!(AuditEventId, "audit_event_id");
opaque_id!(AuditResourceId, "audit_resource_id");

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct InstallationId(String);

impl InstallationId {
    pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
        let value = value.into();
        if valid_uuid_v4(&value) {
            Ok(Self(value))
        } else {
            Err(IdentifierError::new(
                "installation_id",
                "expected a canonical lowercase UUID v4",
            ))
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn valid_uuid_v4(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            14 => byte == b'4',
            19 => matches!(byte, b'8' | b'9' | b'a' | b'b'),
            _ => byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase(),
        })
}

impl<'de> Deserialize<'de> for InstallationId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_validated(deserializer, Self::new)
    }
}

impl fmt::Debug for InstallationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InstallationId([REDACTED])")
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
        let value = value.into();
        if validate_opaque_id(&value) {
            Ok(Self(value))
        } else {
            Err(IdentifierError::new(
                "idempotency_key",
                "expected 1-128 ASCII letters, digits, hyphens, or underscores",
            ))
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for IdempotencyKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_validated(deserializer, Self::new)
    }
}

impl fmt::Debug for IdempotencyKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IdempotencyKey([REDACTED])")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct SiteId(String);

impl SiteId {
    pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && !value.starts_with('-')
            && !value.ends_with('-');
        if valid {
            Ok(Self(value))
        } else {
            Err(IdentifierError::new(
                "site_id",
                "expected 1-64 lowercase ASCII letters, digits, or internal hyphens",
            ))
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for SiteId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_validated(deserializer, Self::new)
    }
}

impl fmt::Display for SiteId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct Username(String);

impl Username {
    pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= MAX_USERNAME_BYTES
            && !value.chars().any(char::is_control);
        if valid {
            Ok(Self(value))
        } else {
            Err(IdentifierError::new(
                "username",
                "expected 1-256 UTF-8 bytes without control characters",
            ))
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Username {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_validated(deserializer, Self::new)
    }
}

impl fmt::Debug for Username {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Username([REDACTED])")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct RegionClass(String);

impl RegionClass {
    pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
        if valid {
            Ok(Self(value))
        } else {
            Err(IdentifierError::new(
                "region_class",
                "expected 1-64 ASCII letters, digits, hyphens, or underscores",
            ))
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for RegionClass {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_validated(deserializer, Self::new)
    }
}

macro_rules! sha256_digest {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
                let value = value.into();
                if value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                {
                    Ok(Self(value))
                } else {
                    Err(IdentifierError::new(
                        $field,
                        "expected exactly 64 lowercase hexadecimal characters",
                    ))
                }
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                deserialize_validated(deserializer, Self::new)
            }
        }
    };
}

sha256_digest!(RuleHash, "rule_hash");
sha256_digest!(EvidenceDigest, "evidence_digest");

#[derive(Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct HttpsUrl(String);

impl HttpsUrl {
    pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
        let value = value.into();
        let parsed = url::Url::parse(&value).ok();
        let valid = value.len() <= 2_048
            && !value.chars().any(char::is_control)
            && parsed.as_ref().is_some_and(|url| {
                url.scheme() == "https"
                    && url.host_str().is_some()
                    && url.username().is_empty()
                    && url.password().is_none()
            });
        if valid {
            Ok(Self(value))
        } else {
            Err(IdentifierError::new(
                "https_url",
                "expected a bounded HTTPS URL with a host and no credentials",
            ))
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for HttpsUrl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_validated(deserializer, Self::new)
    }
}

impl fmt::Debug for HttpsUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HttpsUrl([REDACTED])")
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct EmailAddress(String);

impl EmailAddress {
    pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
        let value = value.into();
        let mut parts = value.split('@');
        let local = parts.next().unwrap_or_default();
        let domain = parts.next().unwrap_or_default();
        let valid = value.len() <= 320
            && !local.is_empty()
            && !domain.is_empty()
            && parts.next().is_none()
            && domain.contains('.')
            && !value
                .chars()
                .any(|character| character.is_control() || character.is_ascii_whitespace());
        if valid {
            Ok(Self(value))
        } else {
            Err(IdentifierError::new(
                "email_address",
                "expected a bounded address with one at-sign and a dotted domain",
            ))
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for EmailAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_validated(deserializer, Self::new)
    }
}

impl fmt::Debug for EmailAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EmailAddress([REDACTED])")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub username: Username,
    pub site_id: SiteId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TargetSelection {
    pub usernames: Vec<Username>,
    pub site_ids: Vec<SiteId>,
}

impl Validate for TargetSelection {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = Vec::new();
        validate_collection(
            &mut errors,
            "usernames",
            &self.usernames,
            MAX_SELECTION_USERNAMES,
        );
        validate_collection(&mut errors, "site_ids", &self.site_ids, MAX_SELECTION_SITES);
        if self.usernames.len().saturating_mul(self.site_ids.len()) > MAX_TARGET_PAIRS {
            errors.push(ValidationIssue {
                field: "targets".to_owned(),
                code: ValidationCode::TooManyItems,
            });
        }
        finish(errors)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SearchMode {
    Local,
    Cache,
    Remote,
    Hybrid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SyncPolicy {
    Never,
    Private,
    Shared,
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ResultSource {
    LocalCache,
    LocalProbe,
    PrivateCloud,
    SharedAssertion,
    ManagedProbe,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DefinitiveVerdict {
    Found,
    NotFound,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClass {
    E0NoAccountEvidence,
    E1WeakSignal,
    E2DifferentialTemplate,
    E3ExplicitEndpoint,
    E4StructuredIdentity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RuleHealthStatus {
    Healthy,
    Degraded,
    Quarantined,
    Recovering,
    Unavailable,
    Stale,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessState {
    Current,
    Stale,
    Expired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Freshness {
    pub observed_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub evaluated_at_unix_ms: i64,
    pub maximum_age_ms: i64,
    pub state: FreshnessState,
}

impl Freshness {
    pub fn new(
        observed_at_unix_ms: i64,
        expires_at_unix_ms: i64,
        evaluated_at_unix_ms: i64,
        maximum_age_ms: i64,
    ) -> Result<Self, ValidationErrors> {
        let state = classify_freshness(
            observed_at_unix_ms,
            expires_at_unix_ms,
            evaluated_at_unix_ms,
            maximum_age_ms,
        )?;
        Ok(Self {
            observed_at_unix_ms,
            expires_at_unix_ms,
            evaluated_at_unix_ms,
            maximum_age_ms,
            state,
        })
    }
}

impl Validate for Freshness {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let expected = classify_freshness(
            self.observed_at_unix_ms,
            self.expires_at_unix_ms,
            self.evaluated_at_unix_ms,
            self.maximum_age_ms,
        )?;
        if expected == self.state {
            Ok(())
        } else {
            Err(ValidationErrors::new(
                "freshness.state",
                ValidationCode::InvalidRelation,
            ))
        }
    }
}

fn classify_freshness(
    observed_at_unix_ms: i64,
    expires_at_unix_ms: i64,
    evaluated_at_unix_ms: i64,
    maximum_age_ms: i64,
) -> Result<FreshnessState, ValidationErrors> {
    let mut errors = Vec::new();
    if observed_at_unix_ms < 0
        || expires_at_unix_ms < 0
        || evaluated_at_unix_ms < 0
        || maximum_age_ms <= 0
        || maximum_age_ms > MAXIMUM_AGE_MS
    {
        errors.push(ValidationIssue {
            field: "freshness".to_owned(),
            code: ValidationCode::OutOfRange,
        });
    }
    if expires_at_unix_ms <= observed_at_unix_ms || observed_at_unix_ms > evaluated_at_unix_ms {
        errors.push(ValidationIssue {
            field: "freshness".to_owned(),
            code: ValidationCode::InvalidRelation,
        });
    }
    finish(errors)?;

    if expires_at_unix_ms <= evaluated_at_unix_ms {
        Ok(FreshnessState::Expired)
    } else if evaluated_at_unix_ms - observed_at_unix_ms > maximum_age_ms {
        Ok(FreshnessState::Stale)
    } else {
        Ok(FreshnessState::Current)
    }
}

pub(crate) fn validate_sync_consent(
    sync: SyncPolicy,
    consent_grant_id: &Option<ConsentGrantId>,
) -> Result<(), ValidationErrors> {
    match (sync, consent_grant_id.is_some()) {
        (SyncPolicy::Never, false) | (SyncPolicy::Private | SyncPolicy::Shared, true) => Ok(()),
        _ => Err(ValidationErrors::new(
            "consent_grant_id",
            ValidationCode::InvalidRelation,
        )),
    }
}

pub(crate) fn validate_regions(regions: &[RegionClass]) -> Result<(), ValidationErrors> {
    let mut errors = Vec::new();
    validate_collection(&mut errors, "region_classes", regions, MAX_REGION_CLASSES);
    finish(errors)
}

pub(crate) fn validate_maximum_age(maximum_age_ms: i64) -> Result<(), ValidationErrors> {
    if (1..=MAXIMUM_AGE_MS).contains(&maximum_age_ms) {
        Ok(())
    } else {
        Err(ValidationErrors::new(
            "maximum_age_ms",
            ValidationCode::OutOfRange,
        ))
    }
}

pub(crate) fn validate_timestamp(
    field: &'static str,
    timestamp_unix_ms: i64,
) -> Result<(), ValidationErrors> {
    if timestamp_unix_ms >= 0 {
        Ok(())
    } else {
        Err(ValidationErrors::new(field, ValidationCode::OutOfRange))
    }
}

pub(crate) fn validate_nonempty_ids<T>(
    field: &'static str,
    values: &[T],
    maximum: usize,
) -> Result<(), ValidationErrors>
where
    T: Ord,
{
    let mut errors = Vec::new();
    validate_collection(&mut errors, field, values, maximum);
    finish(errors)
}

fn validate_collection<T>(
    errors: &mut Vec<ValidationIssue>,
    field: &'static str,
    values: &[T],
    maximum: usize,
) where
    T: Ord,
{
    if values.is_empty() {
        errors.push(ValidationIssue {
            field: field.to_owned(),
            code: ValidationCode::Empty,
        });
    } else if values.len() > maximum {
        errors.push(ValidationIssue {
            field: field.to_owned(),
            code: ValidationCode::TooManyItems,
        });
    }
    if values.iter().collect::<BTreeSet<_>>().len() != values.len() {
        errors.push(ValidationIssue {
            field: field.to_owned(),
            code: ValidationCode::Duplicate,
        });
    }
}

pub(crate) fn finish(errors: Vec<ValidationIssue>) -> Result<(), ValidationErrors> {
    if errors.is_empty() {
        Ok(())
    } else {
        Err(ValidationErrors { issues: errors })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_values_are_redacted_from_debug_and_parse_errors() {
        let username = Username::new("alice-secret").unwrap();
        let target = Target {
            username,
            site_id: SiteId::new("github").unwrap(),
        };
        assert!(!format!("{target:?}").contains("alice-secret"));
        let idempotency_key = IdempotencyKey::new("private-replay-key").unwrap();
        assert!(!format!("{idempotency_key:?}").contains("private-replay-key"));

        let error = serde_json::from_str::<Username>("\"\\u0000secret\"")
            .unwrap_err()
            .to_string();
        assert!(!error.contains("secret"));
    }

    #[test]
    fn freshness_is_derived_and_cannot_be_relabelled() {
        let current = Freshness::new(1_000, 10_000, 2_000, 5_000).unwrap();
        assert_eq!(current.state, FreshnessState::Current);
        let stale = Freshness::new(1_000, 10_000, 8_000, 5_000).unwrap();
        assert_eq!(stale.state, FreshnessState::Stale);
        let expired = Freshness::new(1_000, 10_000, 10_000, 10_000).unwrap();
        assert_eq!(expired.state, FreshnessState::Expired);

        let mut relabelled = current;
        relabelled.state = FreshnessState::Expired;
        assert!(relabelled.validate().is_err());
    }

    #[test]
    fn target_selection_is_bounded_and_deduplicated() {
        let duplicate = Username::new("alice").unwrap();
        let selection = TargetSelection {
            usernames: vec![duplicate.clone(), duplicate],
            site_ids: vec![SiteId::new("github").unwrap()],
        };
        let errors = selection.validate().unwrap_err();
        assert_eq!(errors.issues()[0].code, ValidationCode::Duplicate);

        let oversized = TargetSelection {
            usernames: (0..9)
                .map(|index| Username::new(format!("alice-{index}")).unwrap())
                .collect(),
            site_ids: (0..64)
                .map(|index| SiteId::new(format!("site-{index}")).unwrap())
                .collect(),
        };
        assert!(oversized.validate().is_err());
    }
}
