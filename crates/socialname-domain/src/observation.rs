use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SiteId(String);

impl SiteId {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SiteId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ObservationId(String);

impl ObservationId {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TargetKey {
    pub site_id: SiteId,
    pub normalized_username: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Found,
    NotFound,
    InvalidUsername,
    Inconclusive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InconclusiveReason {
    Blocked,
    RateLimited,
    Timeout,
    Dns,
    Connect,
    Tls,
    RedirectRejected,
    ResponseTooLarge,
    Decode,
    SiteChanged,
    NoRuleMatched,
    ConflictingEvidence,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClass {
    #[default]
    E0NoAccountEvidence,
    E1WeakSignal,
    E2DifferentialTemplate,
    E3ExplicitEndpoint,
    E4StructuredIdentity,
}

impl EvidenceClass {
    #[must_use]
    pub const fn is_strong(self) -> bool {
        matches!(self, Self::E3ExplicitEndpoint | Self::E4StructuredIdentity)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProducerKind {
    LocalCli,
    SharedCli,
    ManagedWorker,
    CanaryWorker,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProducerReputation {
    New,
    Calibrated,
    Trusted,
    Suspended,
}

impl ProducerReputation {
    #[must_use]
    pub const fn quorum_eligible(self) -> bool {
        matches!(self, Self::Calibrated | Self::Trusted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectionProfile {
    LocalOnly,
    PrivateHistory,
    SharedObservation,
    SharedResearch,
    Managed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    pub id: ObservationId,
    pub target: TargetKey,
    pub verdict: Verdict,
    pub inconclusive_reason: Option<InconclusiveReason>,
    pub evidence_class: EvidenceClass,
    pub observed_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub region: String,
    pub network_group: String,
    pub independence_group: String,
    pub producer_kind: ProducerKind,
    pub producer_reputation: ProducerReputation,
    pub collection_profile: CollectionProfile,
    pub rule_hash: String,
    pub rule_health_green: bool,
    pub evidence_digest: String,
}

impl Observation {
    #[must_use]
    pub const fn is_managed(&self) -> bool {
        matches!(self.producer_kind, ProducerKind::ManagedWorker)
    }

    #[must_use]
    pub const fn is_current_at(&self, now_unix_ms: i64) -> bool {
        self.observed_at_unix_ms <= now_unix_ms && self.expires_at_unix_ms > now_unix_ms
    }

    #[must_use]
    pub const fn is_assertion_eligible(&self, now_unix_ms: i64) -> bool {
        self.is_current_at(now_unix_ms)
            && self.rule_health_green
            && self.evidence_class.is_strong()
            && !matches!(self.producer_reputation, ProducerReputation::Suspended)
            && matches!(self.verdict, Verdict::Found | Verdict::NotFound)
    }
}
