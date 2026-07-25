#![forbid(unsafe_code)]

mod compiler;
mod error;
mod report;
mod runner;
mod schema;

pub use compiler::{CanaryManifestCompiler, CompiledCanaryManifest};
pub use error::{CanaryManifestError, CanaryManifestErrors};
pub use report::{
    CANARY_REPORT_V1, CanaryLatencySummary, CanaryRatio, CanaryReportBuilder, CanaryReportEnvelope,
    CanaryReportError, CanaryReportPolicy, CanaryReportSummary, CanaryReportV1,
    CanaryReportValidator,
};
pub use runner::{
    CanaryCaseExpectation, CanaryCaseOutcome, CanaryProbe, CanaryProbeSummary, CanaryRun,
    CanaryRunBudget, CanaryRunCompletion, CanaryRunError, CanaryRunner, DeclaredVantage,
};
pub use schema::{
    CANARY_MANIFEST_V1, CanaryManifestSource, NegativeAlphabet, NegativeCanaryGeneratorSource,
    NegativeCanarySource, PositiveCanaryKind, PositiveCanarySource,
};
