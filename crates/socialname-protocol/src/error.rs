use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    ProtocolVersion, RequestId, Validate, ValidationCode, ValidationErrors, ValidationIssue,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApiErrorCode {
    InvalidRequest,
    Unauthenticated,
    Forbidden,
    NotFound,
    Conflict,
    IdempotencyConflict,
    RateLimited,
    QuotaExceeded,
    Unavailable,
    Internal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FieldViolation {
    pub field: String,
    pub code: ValidationCode,
}

impl From<ValidationIssue> for FieldViolation {
    fn from(issue: ValidationIssue) -> Self {
        Self {
            field: issue.field,
            code: issue.code,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApiError {
    pub code: ApiErrorCode,
    pub retryable: bool,
    pub retry_after_ms: Option<u64>,
    pub violations: Vec<FieldViolation>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApiErrorResponse {
    pub schema: ProtocolVersion,
    pub request_id: RequestId,
    pub error: ApiError,
}

impl ApiErrorResponse {
    #[must_use]
    pub fn invalid_request(request_id: RequestId, errors: ValidationErrors) -> Self {
        Self {
            schema: ProtocolVersion::ApiV1,
            request_id,
            error: ApiError {
                code: ApiErrorCode::InvalidRequest,
                retryable: false,
                retry_after_ms: None,
                violations: errors
                    .into_issues()
                    .into_iter()
                    .map(FieldViolation::from)
                    .collect(),
            },
        }
    }
}

impl Validate for ApiErrorResponse {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let fields_valid = self.error.violations.len() <= 32
            && self.error.violations.iter().all(|violation| {
                !violation.field.is_empty()
                    && violation.field.len() <= 128
                    && violation.field.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'[' | b']')
                    })
            });
        let unique_fields = self
            .error
            .violations
            .iter()
            .map(|violation| (&violation.field, violation.code))
            .collect::<BTreeSet<_>>()
            .len()
            == self.error.violations.len();
        if !fields_valid || !unique_fields {
            return Err(ValidationErrors::new(
                "error.violations",
                ValidationCode::InvalidFormat,
            ));
        }
        let violation_relation_valid = match self.error.code {
            ApiErrorCode::InvalidRequest => !self.error.violations.is_empty(),
            _ => self.error.violations.is_empty(),
        };
        if !violation_relation_valid {
            return Err(ValidationErrors::new(
                "error.violations",
                ValidationCode::InvalidRelation,
            ));
        }

        let retry_valid = match self.error.code {
            ApiErrorCode::InvalidRequest
            | ApiErrorCode::Unauthenticated
            | ApiErrorCode::Forbidden
            | ApiErrorCode::NotFound
            | ApiErrorCode::Conflict
            | ApiErrorCode::IdempotencyConflict => {
                !self.error.retryable && self.error.retry_after_ms.is_none()
            }
            ApiErrorCode::RateLimited | ApiErrorCode::QuotaExceeded => {
                self.error.retryable && self.error.retry_after_ms.is_some_and(|delay| delay > 0)
            }
            ApiErrorCode::Unavailable => {
                self.error.retryable && self.error.retry_after_ms.is_none_or(|delay| delay > 0)
            }
            ApiErrorCode::Internal => !self.error.retryable && self.error.retry_after_ms.is_none(),
        };
        if retry_valid {
            Ok(())
        } else {
            Err(ValidationErrors::new(
                "error.retry",
                ValidationCode::InvalidRelation,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_request_errors_never_echo_supplied_values() {
        let errors = ValidationErrors::new("targets.usernames", ValidationCode::InvalidFormat);
        let response =
            ApiErrorResponse::invalid_request(RequestId::new("request_01").unwrap(), errors);
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("targets.usernames"));
        assert!(!json.contains("alice-secret"));
        assert!(response.validate().is_ok());
    }

    #[test]
    fn retry_metadata_is_tied_to_predictable_error_codes() {
        let response = ApiErrorResponse {
            schema: ProtocolVersion::ApiV1,
            request_id: RequestId::new("request_01").unwrap(),
            error: ApiError {
                code: ApiErrorCode::RateLimited,
                retryable: true,
                retry_after_ms: None,
                violations: Vec::new(),
            },
        };
        assert!(response.validate().is_err());
    }

    #[test]
    fn unknown_error_fields_are_rejected() {
        let json = r#"{
            "schema":"socialname.dev/api/v1",
            "request_id":"request_01",
            "error":{
                "code":"internal",
                "retryable":false,
                "retry_after_ms":null,
                "violations":[],
                "debug_body":"secret"
            }
        }"#;
        assert!(serde_json::from_str::<ApiErrorResponse>(json).is_err());
    }
}
