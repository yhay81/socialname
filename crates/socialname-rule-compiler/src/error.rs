use std::path::PathBuf;

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum CompileError {
    #[error("rule source exceeds {maximum} bytes")]
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
    #[error("schema must be socialname.dev/site/v1, got {0}")]
    UnsupportedSchema(String),
    #[error("invalid site ID {0:?}")]
    InvalidSiteId(String),
    #[error("site ID {actual:?} does not match filename {expected:?}")]
    FilenameMismatch { expected: String, actual: String },
    #[error("invalid username regular expression: {0}")]
    InvalidUsernameRegex(String),
    #[error("invalid matcher regular expression {pattern:?}: {message}")]
    InvalidMatcherRegex { pattern: String, message: String },
    #[error("duplicate probe ID {0:?}")]
    DuplicateProbe(String),
    #[error("unknown probe ID {0:?}")]
    UnknownProbe(String),
    #[error("probe plan must contain at least one probe")]
    EmptyProbePlan,
    #[error("condition {0} must contain at least one child")]
    EmptyCondition(&'static str),
    #[error("condition tree exceeds 16 levels or 128 nodes")]
    ConditionTooComplex,
    #[error("invalid HTTP status {0}")]
    InvalidStatus(u16),
    #[error("invalid URL template: {0}")]
    InvalidUrlTemplate(String),
    #[error("URL host {host:?} is not listed in allowed_hosts")]
    HostNotAllowed { host: String },
    #[error("invalid allowed host {0:?}")]
    InvalidAllowedHost(String),
    #[error("HTTP is forbidden for v1 rule URL {0:?}")]
    InsecureUrl(String),
    #[error("unsafe or unsupported request header {0:?}")]
    UnsafeRequestHeader(String),
    #[error("request body is only valid for POST")]
    BodyOnNonPost,
    #[error("POST must declare a typed request body")]
    MissingPostBody,
    #[error("redirect max_hops must be between 0 and 10")]
    InvalidRedirectHops,
    #[error("timeout values must be non-zero and total_ms must cover connect/first-byte")]
    InvalidTimeout,
    #[error("response byte limits are invalid or exceed hard safety limits")]
    InvalidResponseLimits,
    #[error("invalid JSON Pointer {0:?}")]
    InvalidJsonPointer(String),
    #[error("JSON matcher fields do not match operation")]
    InvalidJsonMatcher,
    #[error("body length matcher must provide min or max and min must not exceed max")]
    InvalidBodyLength,
    #[error("invalid classification template {0:?}")]
    InvalidIdentityTemplate(String),
    #[error("failed to read rule {path}: {message}")]
    ReadRule { path: PathBuf, message: String },
    #[error("rule directory {0} contains no .yaml files")]
    EmptyRuleDirectory(PathBuf),
    #[error("failed to serialize canonical rule: {0}")]
    CanonicalSerialization(String),
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
#[error("site rule compilation failed with {count} error(s)", count = .0.len())]
pub struct CompileErrors(pub Vec<CompileError>);

impl CompileErrors {
    #[must_use]
    pub fn new(error: CompileError) -> Self {
        Self(vec![error])
    }

    pub fn push(&mut self, error: CompileError) {
        self.0.push(error);
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
