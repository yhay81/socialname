#![forbid(unsafe_code)]

mod aggregate;
mod compiler;
mod error;
mod health;
mod promotion;
mod report;
mod runner;
mod schema;
mod shadow;

pub use aggregate::{
    CANARY_AGGREGATE_V1, CanaryAcceptanceAggregate, CanaryAcceptanceDisposition,
    CanaryAcceptanceIssue, CanaryAggregationError, CanaryAggregationPolicy, CanaryRegionAggregate,
    CanaryReportAggregator, EvaluatedCanaryAggregate,
};
pub use compiler::{CanaryManifestCompiler, CompiledCanaryManifest};
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
