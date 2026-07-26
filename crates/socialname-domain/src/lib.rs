#![forbid(unsafe_code)]

mod assertion;
mod observation;
mod rule_health;

pub use assertion::{
    Assertion, AssertionQuality, DerivationPolicy, derive_assertion, derive_regional_assertions,
};
pub use observation::{
    CollectionProfile, EvidenceClass, InconclusiveReason, Observation, ObservationId, ProducerKind,
    ProducerReputation, SiteId, TargetKey, Verdict,
};
pub use rule_health::{
    RuleClassificationFailure, RuleHealth, RuleHealthError, RuleHealthEvent, RuleHealthKey,
    RuleHealthPolicy, RuleHealthRecord, RuleHealthSignal, RuleHealthTransition,
    RuleOperationalFailure,
};
