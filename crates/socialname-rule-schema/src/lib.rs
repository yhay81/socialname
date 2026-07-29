#![forbid(unsafe_code)]

use std::{collections::BTreeMap, net::IpAddr};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const SITE_RULE_V1: &str = "socialname.dev/site/v1";

const MAXIMUM_HOST_BYTES: usize = 253;
const MAXIMUM_LABEL_BYTES: usize = 63;

/// Whether an `allowed_hosts` entry is well formed.
///
/// An entry is either a literal hostname or a single-level wildcard such as
/// `*.example.com`, which exists so a rule whose URL template renders the
/// username into a subdomain can declare the hosts it may reach. A wildcard
/// must name a concrete parent of at least two labels, so an entry can never
/// widen the allowlist to a whole public suffix.
#[must_use]
pub fn valid_allowed_host(entry: &str) -> bool {
    let entry = entry.trim().to_ascii_lowercase();
    let (wildcard, host) = match entry.strip_prefix("*.") {
        Some(parent) => (true, parent),
        None => (false, entry.as_str()),
    };
    if host.is_empty()
        || host.len() > MAXIMUM_HOST_BYTES
        || host == "localhost"
        || host.ends_with(".localhost")
        || host.parse::<IpAddr>().is_ok()
    {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if wildcard && labels.len() < 2 {
        return false;
    }
    labels.iter().all(|label| valid_host_label(label))
}

/// Whether a concrete host is permitted by one `allowed_hosts` entry.
///
/// A wildcard matches exactly one additional DNS label and never the parent
/// itself, which keeps a subdomain rule's reach identical to what its own URL
/// template is able to render.
#[must_use]
pub fn host_matches_allowed(host: &str, allowed: &str) -> bool {
    let host = host.trim().to_ascii_lowercase();
    let allowed = allowed.trim().to_ascii_lowercase();
    match allowed.strip_prefix("*.") {
        None => host == allowed,
        Some(parent) => host
            .strip_suffix(parent)
            .and_then(|label| label.strip_suffix('.'))
            .is_some_and(valid_host_label),
    }
}

fn valid_host_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= MAXIMUM_LABEL_BYTES
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SiteRuleSource {
    pub schema: String,
    pub id: String,
    pub name: String,
    pub homepage: String,
    pub profile_url: String,
    pub namespace: AccountNamespace,
    pub username: UsernamePolicy,
    pub probes: Vec<ProbeSource>,
    pub plan: ProbePlanSource,
    pub classification: ClassificationSource,
    #[serde(default)]
    pub metadata: SiteMetadata,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AccountNamespace {
    Person,
    Organization,
    PersonOrOrganization,
    DeveloperAccount,
    FederatedAccount,
    Channel,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UsernamePolicy {
    pub pattern: String,
    #[serde(default)]
    pub case_sensitive: bool,
    #[serde(default)]
    pub normalization: UsernameNormalization,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UsernameNormalization {
    #[default]
    Preserve,
    Lowercase,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProbeSource {
    pub id: String,
    pub http: HttpProbeSource,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HttpProbeSource {
    pub method: HttpMethod,
    pub url: String,
    #[serde(default)]
    pub redirects: RedirectPolicySource,
    #[serde(default)]
    pub timeout: TimeoutPolicy,
    pub allowed_hosts: Vec<String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: Option<RequestBodySource>,
    #[serde(default)]
    pub expected_body: BodyPolicy,
    #[serde(default)]
    pub limits: ResponseLimits,
    #[serde(default)]
    pub transport_profile: TransportProfile,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum HttpMethod {
    #[serde(rename = "GET")]
    Get,
    #[serde(rename = "HEAD")]
    Head,
    #[serde(rename = "POST")]
    Post,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RedirectMode {
    None,
    SameSite,
    #[default]
    Follow,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RedirectPolicySource {
    #[serde(default)]
    pub mode: RedirectMode,
    #[serde(default = "default_max_hops")]
    pub max_hops: u8,
}

impl Default for RedirectPolicySource {
    fn default() -> Self {
        Self {
            mode: RedirectMode::Follow,
            max_hops: default_max_hops(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TimeoutPolicy {
    #[serde(default = "default_dns_ms")]
    pub dns_ms: u64,
    #[serde(default = "default_connect_ms")]
    pub connect_ms: u64,
    #[serde(default = "default_first_byte_ms")]
    pub first_byte_ms: u64,
    #[serde(default = "default_total_ms")]
    pub total_ms: u64,
}

impl Default for TimeoutPolicy {
    fn default() -> Self {
        Self {
            dns_ms: default_dns_ms(),
            connect_ms: default_connect_ms(),
            first_byte_ms: default_first_byte_ms(),
            total_ms: default_total_ms(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResponseLimits {
    #[serde(default = "default_header_bytes")]
    pub header_bytes: usize,
    #[serde(default = "default_compressed_bytes")]
    pub compressed_bytes: usize,
    #[serde(default = "default_decompressed_bytes")]
    pub decompressed_bytes: usize,
    #[serde(default = "default_inspected_bytes")]
    pub inspected_bytes: usize,
}

impl Default for ResponseLimits {
    fn default() -> Self {
        Self {
            header_bytes: default_header_bytes(),
            compressed_bytes: default_compressed_bytes(),
            decompressed_bytes: default_decompressed_bytes(),
            inspected_bytes: default_inspected_bytes(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BodyPolicy {
    None,
    Json,
    #[default]
    BoundedText,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TransportProfile {
    Minimal,
    #[default]
    BrowserLike,
    ApiJson,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RequestBodySource {
    Json { value: Value },
    Form { fields: BTreeMap<String, String> },
    Text { value: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProbePlanSource {
    Single {
        probe: String,
    },
    Fallback {
        primary: String,
        fallback: String,
        on: FallbackReason,
    },
    ParallelAll {
        probes: Vec<String>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FallbackReason {
    MethodNotAllowed,
    NoRuleMatched,
    TransportFailure,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClassificationSource {
    #[serde(default)]
    pub blocked: Option<ConditionSource>,
    pub found: ConditionSource,
    pub not_found: ConditionSource,
    #[serde(default)]
    pub otherwise: OtherwiseVerdict,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OtherwiseVerdict {
    #[default]
    Inconclusive,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged, deny_unknown_fields)]
pub enum ConditionSource {
    All { all: Vec<ConditionSource> },
    Any { any: Vec<ConditionSource> },
    Not { not: Box<ConditionSource> },
    Status { status: StatusCondition },
    FinalUrl { final_url: FinalUrlCondition },
    Header { header: HeaderCondition },
    Body { body: BodyCondition },
    Json { json: JsonCondition },
    BodyLength { body_length: BodyLengthCondition },
    Transport { transport: TransportCondition },
}

impl ConditionSource {
    pub fn visit_probe_ids(&self, visitor: &mut impl FnMut(&str)) {
        match self {
            Self::All { all: conditions } | Self::Any { any: conditions } => {
                for condition in conditions {
                    condition.visit_probe_ids(visitor);
                }
            }
            Self::Not { not: condition } => condition.visit_probe_ids(visitor),
            Self::Status { status: condition } => visitor(&condition.probe),
            Self::FinalUrl {
                final_url: condition,
            } => visitor(&condition.probe),
            Self::Header { header: condition } => visitor(&condition.probe),
            Self::Body { body: condition } => visitor(&condition.probe),
            Self::Json { json: condition } => visitor(&condition.probe),
            Self::BodyLength {
                body_length: condition,
            } => visitor(&condition.probe),
            Self::Transport {
                transport: condition,
            } => visitor(&condition.probe),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StatusCondition {
    pub probe: String,
    #[serde(rename = "in")]
    pub statuses: Vec<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FinalUrlCondition {
    pub probe: String,
    pub op: StringMatchOp,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HeaderCondition {
    pub probe: String,
    pub name: String,
    pub op: StringMatchOp,
    pub value: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StringMatchOp {
    Equals,
    EqualsTemplate,
    Contains,
    ContainsTemplate,
    Prefix,
    Regex,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BodyCondition {
    pub probe: String,
    pub op: BodyMatchOp,
    pub value: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BodyMatchOp {
    Contains,
    ContainsTemplate,
    NotContains,
    Regex,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JsonCondition {
    pub probe: String,
    #[serde(default)]
    pub pointer: String,
    pub op: JsonMatchOp,
    #[serde(default)]
    pub value: Option<Value>,
    #[serde(default)]
    pub template: Option<String>,
    #[serde(default)]
    pub length: Option<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum JsonMatchOp {
    Exists,
    Absent,
    Equals,
    EqualsTemplate,
    ArrayLength,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BodyLengthCondition {
    pub probe: String,
    #[serde(default)]
    pub min: Option<usize>,
    #[serde(default)]
    pub max: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TransportCondition {
    pub probe: String,
    #[serde(rename = "in")]
    pub outcomes: Vec<TransportOutcome>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TransportOutcome {
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

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SiteMetadata {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub enabled_regions: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub adult: bool,
    #[serde(default)]
    pub notes: String,
}

const fn default_max_hops() -> u8 {
    3
}

const fn default_dns_ms() -> u64 {
    1_500
}

const fn default_connect_ms() -> u64 {
    2_000
}

const fn default_first_byte_ms() -> u64 {
    4_000
}

const fn default_total_ms() -> u64 {
    6_000
}

const fn default_header_bytes() -> usize {
    32 * 1_024
}

const fn default_compressed_bytes() -> usize {
    2 * 1_024 * 1_024
}

const fn default_decompressed_bytes() -> usize {
    4 * 1_024 * 1_024
}

const fn default_inspected_bytes() -> usize {
    256 * 1_024
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_entries_require_a_concrete_parent() {
        for valid in ["example.com", "*.example.com", "*.co.uk.example.com"] {
            assert!(valid_allowed_host(valid), "{valid} should be accepted");
        }
        for invalid in [
            "",
            "*.com",
            "*",
            "*.",
            "localhost",
            "*.localhost",
            "127.0.0.1",
            "*.127.0.0.1",
            "exa mple.com",
            "-example.com",
            "example-.com",
        ] {
            assert!(!valid_allowed_host(invalid), "{invalid} should be rejected");
        }
    }

    #[test]
    fn a_wildcard_matches_exactly_one_label_and_never_the_parent() {
        assert!(host_matches_allowed("alice.example.com", "*.example.com"));
        assert!(host_matches_allowed("ALICE.EXAMPLE.COM", "*.example.com"));
        for host in [
            // The parent itself is a different host and must be listed
            // separately to be reachable.
            "example.com",
            // Nested labels would let one rendered name reach a host the
            // template could never produce.
            "a.b.example.com",
            // A suffix that merely ends with the parent text is a different
            // registrable domain.
            "notexample.com",
            "evil-example.com",
            ".example.com",
        ] {
            assert!(
                !host_matches_allowed(host, "*.example.com"),
                "{host} must not match *.example.com"
            );
        }
    }

    #[test]
    fn literal_entries_match_exactly() {
        assert!(host_matches_allowed("example.com", "example.com"));
        assert!(host_matches_allowed("Example.COM", "example.com"));
        assert!(!host_matches_allowed("alice.example.com", "example.com"));
    }
}
