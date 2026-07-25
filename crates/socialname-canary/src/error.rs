use std::path::PathBuf;

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum CanaryManifestError {
    #[error("canary manifest source exceeds {maximum} bytes")]
    SourceTooLarge { maximum: usize },
    #[error("line {line} exceeds {maximum} bytes")]
    LineTooLarge { line: usize, maximum: usize },
    #[error("line {line} uses a tab; indentation must use spaces")]
    TabIndentation { line: usize },
    #[error("line {line} exceeds the maximum nesting depth")]
    NestingTooDeep { line: usize },
    #[error("YAML anchors, aliases, tags, and merge keys are forbidden (line {line})")]
    ForbiddenYamlFeature { line: usize },
    #[error("invalid YAML: {0}")]
    InvalidYaml(String),
    #[error("schema must be socialname.dev/canary-manifest/v1, got {0}")]
    UnsupportedSchema(String),
    #[error("manifest site {manifest:?} does not match rule site {rule:?}")]
    SiteMismatch { manifest: String, rule: String },
    #[error("manifest site {actual:?} does not match filename {expected:?}")]
    FilenameMismatch { expected: String, actual: String },
    #[error("manifest references unknown site {0:?}")]
    UnknownSite(String),
    #[error("manifest for site {0:?} is duplicated")]
    DuplicateManifest(String),
    #[error("manifest issued_at must not be after the validation time")]
    IssuedInFuture,
    #[error("manifest expires_at must be after issued_at")]
    InvalidValidityWindow,
    #[error("canary manifest has expired")]
    Expired,
    #[error("manifest must contain between 5 and 32 positive canaries")]
    InvalidPositiveCount,
    #[error("invalid positive canary ID {0:?}")]
    InvalidPositiveId(String),
    #[error("duplicate positive canary ID {0:?}")]
    DuplicatePositiveId(String),
    #[error("positive canary username {0:?} does not satisfy the site username policy")]
    InvalidPositiveUsername(String),
    #[error("positive canary username {actual:?} is not normalized; expected {expected:?}")]
    NonCanonicalPositiveUsername { actual: String, expected: String },
    #[error("duplicate positive canary username {0:?}")]
    DuplicatePositiveUsername(String),
    #[error("positive canary {0:?} has an invalid review timestamp")]
    InvalidReviewTime(String),
    #[error("positive canary {id:?} has an invalid HTTPS evidence URL {url:?}")]
    InvalidEvidenceUrl { id: String, url: String },
    #[error("negative canary generator is invalid or incompatible with the site policy")]
    InvalidNegativeGenerator,
    #[error("failed to read canary manifest {path}: {message}")]
    ReadManifest { path: PathBuf, message: String },
    #[error("failed to serialize canonical canary manifest: {0}")]
    CanonicalSerialization(String),
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
#[error(
    "canary manifest validation failed with {count} error(s)",
    count = .0.len()
)]
pub struct CanaryManifestErrors(pub Vec<CanaryManifestError>);

impl CanaryManifestErrors {
    #[must_use]
    pub fn new(error: CanaryManifestError) -> Self {
        Self(vec![error])
    }
}
