#![forbid(unsafe_code)]

mod compiler;
mod error;
mod schema;

pub use compiler::{CanaryManifestCompiler, CompiledCanaryManifest};
pub use error::{CanaryManifestError, CanaryManifestErrors};
pub use schema::{
    CANARY_MANIFEST_V1, CanaryManifestSource, NegativeAlphabet, NegativeCanaryGeneratorSource,
    NegativeCanarySource, PositiveCanaryKind, PositiveCanarySource,
};
