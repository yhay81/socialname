#![forbid(unsafe_code)]

mod compiler;
mod error;
mod runner;
mod schema;

pub use compiler::{CanaryManifestCompiler, CompiledCanaryManifest};
pub use error::{CanaryManifestError, CanaryManifestErrors};
pub use runner::{
    CanaryCaseExpectation, CanaryCaseOutcome, CanaryProbe, CanaryProbeSummary, CanaryRun,
    CanaryRunBudget, CanaryRunCompletion, CanaryRunError, CanaryRunner, DeclaredVantage,
};
pub use schema::{
    CANARY_MANIFEST_V1, CanaryManifestSource, NegativeAlphabet, NegativeCanaryGeneratorSource,
    NegativeCanarySource, PositiveCanaryKind, PositiveCanarySource,
};
