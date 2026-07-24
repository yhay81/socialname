#![forbid(unsafe_code)]

mod assertion;
mod observation;

pub use assertion::{Assertion, AssertionQuality, DerivationPolicy, RuleHealth, derive_assertion};
pub use observation::{
    CollectionProfile, EvidenceClass, InconclusiveReason, Observation, ObservationId, ProducerKind,
    ProducerReputation, SiteId, TargetKey, Verdict,
};
