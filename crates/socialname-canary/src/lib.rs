#![forbid(unsafe_code)]

mod aggregate;
mod compiler;
mod error;
mod health;
mod promotion;
mod report;
mod rule_pack_metadata;
mod runner;
mod schema;
mod shadow;
#[cfg(test)]
mod workflow_contract;

pub use aggregate::{
    CANARY_AGGREGATE_V1, CanaryAcceptanceAggregate, CanaryAcceptanceDisposition,
    CanaryAcceptanceIssue, CanaryAggregationError, CanaryAggregationPolicy, CanaryRegionAggregate,
    CanaryReportAggregator, EvaluatedCanaryAggregate,
};
pub use compiler::{
    CanaryManifestCompiler, CompiledCanaryManifest, generator_probe_is_usable,
    minimum_random_length, negative_generator_probe, plan_negative_generator,
};
pub use error::{CanaryManifestError, CanaryManifestErrors};
pub use health::{CanaryHealthAssessor, CanaryHealthError};
pub use promotion::{
    ActivatedPromotion, ED25519_ALGORITHM, PROMOTION_V1, PromotionActivationRegistry,
    PromotionBuildRequest, PromotionBuilder, PromotionEnvelope, PromotionError,
    PromotionRegionEvidence, PromotionSigningKey, PromotionTrustPolicy, PromotionV1,
    PromotionVerifier, ValidatedPromotion,
};
pub use report::{
    CANARY_REPORT_V1, CanaryLatencySummary, CanaryRatio, CanaryReportBuilder, CanaryReportEnvelope,
    CanaryReportError, CanaryReportPolicy, CanaryReportSummary, CanaryReportV1,
    CanaryReportValidator, ValidatedCanaryReport,
};
pub use rule_pack_metadata::{
    ActivatedRulePackMetadata, MAX_RULE_PACK_METADATA_VALIDITY_MS, RULE_PACK_METADATA_V1,
    RULE_PACK_TRUST_V1, RulePackMetadataBuildRequest, RulePackMetadataBuilder,
    RulePackMetadataEnvelope, RulePackMetadataError, RulePackMetadataSigningKey,
    RulePackMetadataV1, RulePackMetadataVerifier, RulePackPromotionBinding,
    RulePackRolloutRegistry, RulePackRolloutStage, RulePackTrustV1, ValidatedRulePackMetadata,
};
pub use runner::{
    CanaryCaseExpectation, CanaryCaseOutcome, CanaryProbe, CanaryProbeSummary, CanaryRun,
    CanaryRunBudget, CanaryRunCompletion, CanaryRunError, CanaryRunner, DeclaredVantage,
};
pub use schema::{
    CANARY_MANIFEST_V1, CanaryManifestSource, NegativeAlphabet, NegativeCanaryGeneratorSource,
    NegativeCanarySource, PositiveCanaryKind, PositiveCanarySource,
};
pub use shadow::{
    CANARY_SHADOW_V1, CanaryShadowBuilder, CanaryShadowComparisonV1, CanaryShadowDisposition,
    CanaryShadowEnvelope, CanaryShadowError, CanaryShadowIssue, CanaryShadowPair,
    CanaryShadowPolicy, CanaryShadowRun, CanaryShadowSummary, CanaryShadowValidator,
    ValidatedCanaryShadow,
};
