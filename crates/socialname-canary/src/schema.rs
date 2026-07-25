use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const CANARY_MANIFEST_V1: &str = "socialname.dev/canary-manifest/v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CanaryManifestSource {
    pub schema: String,
    pub site_id: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub positive: Vec<PositiveCanarySource>,
    pub negative: NegativeCanarySource,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PositiveCanarySource {
    pub id: String,
    pub username: String,
    pub kind: PositiveCanaryKind,
    pub reviewed_at: DateTime<Utc>,
    pub evidence_url: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PositiveCanaryKind {
    PlatformOfficial,
    ProjectControlled,
    LongLivedPublic,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NegativeCanarySource {
    pub generator: NegativeCanaryGeneratorSource,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NegativeCanaryGeneratorSource {
    pub alphabet: NegativeAlphabet,
    pub random_length: usize,
    #[serde(default)]
    pub suffix: String,
    pub count: usize,
    pub attempts_per_candidate: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NegativeAlphabet {
    LowercaseAlnum,
    Lowercase,
}
