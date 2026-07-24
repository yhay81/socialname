use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use socialname_domain::{EvidenceClass, InconclusiveReason, Verdict};
use socialname_rule_schema::TransportOutcome;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeResponse {
    pub probe_id: String,
    pub transport: TransportOutcome,
    pub status: Option<u16>,
    pub final_url: Option<String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub body_bytes: usize,
    #[serde(default)]
    pub body_truncated: bool,
    #[serde(default)]
    pub elapsed_ms: u64,
}

impl ProbeResponse {
    #[must_use]
    pub fn summary(&self) -> ProbeSummary {
        ProbeSummary {
            probe_id: self.probe_id.clone(),
            transport: self.transport,
            status: self.status,
            final_url: self.final_url.clone(),
            content_type: self.headers.get("content-type").cloned(),
            body_bytes: self.body_bytes,
            body_truncated: self.body_truncated,
            elapsed_ms: self.elapsed_ms,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeSummary {
    pub probe_id: String,
    pub transport: TransportOutcome,
    pub status: Option<u16>,
    pub final_url: Option<String>,
    pub content_type: Option<String>,
    pub body_bytes: usize,
    pub body_truncated: bool,
    pub elapsed_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatcherTrace {
    pub path: String,
    pub matched: bool,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Classification {
    pub verdict: Verdict,
    pub inconclusive_reason: Option<InconclusiveReason>,
    pub evidence_class: EvidenceClass,
    pub matcher_trace: Vec<MatcherTrace>,
    pub evidence_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchResult {
    pub site_id: String,
    pub username: String,
    pub profile_url: Option<String>,
    pub rule_hash: String,
    pub classification: Classification,
    pub probes: Vec<ProbeSummary>,
}
