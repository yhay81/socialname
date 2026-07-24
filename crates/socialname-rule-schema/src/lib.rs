#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const SITE_RULE_V1: &str = "socialname.dev/site/v1";

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
    pub canary: CanaryPolicy,
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CanaryPolicy {
    pub found: Vec<String>,
    pub not_found: NegativeCanaryPolicy,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NegativeCanaryPolicy {
    pub generator: NegativeGenerator,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NegativeGenerator {
    pub alphabet: NegativeAlphabet,
    pub length: usize,
    #[serde(default = "default_negative_attempts")]
    pub attempts: usize,
    #[serde(default)]
    pub suffix: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NegativeAlphabet {
    LowercaseAlnum,
    Lowercase,
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

const fn default_negative_attempts() -> usize {
    3
}
