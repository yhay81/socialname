use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{ApiKeyId, ProtocolVersion, Validate, ValidationCode, ValidationErrors, WorkspaceId};

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
pub enum ApiKeyScope {
    #[serde(rename = "workspace:read")]
    WorkspaceRead,
    #[serde(rename = "search:read")]
    SearchRead,
    #[serde(rename = "search:write")]
    SearchWrite,
    #[serde(rename = "watch:read")]
    WatchRead,
    #[serde(rename = "watch:write")]
    WatchWrite,
    #[serde(rename = "notification:read")]
    NotificationRead,
    #[serde(rename = "notification:write")]
    NotificationWrite,
    #[serde(rename = "data:export")]
    DataExport,
    #[serde(rename = "data:delete")]
    DataDelete,
    #[serde(rename = "consent:read")]
    ConsentRead,
    #[serde(rename = "consent:write")]
    ConsentWrite,
    #[serde(rename = "contribution:read")]
    ContributionRead,
    #[serde(rename = "contribution:write")]
    ContributionWrite,
    #[serde(rename = "evidence:read")]
    EvidenceRead,
    #[serde(rename = "operations:read")]
    OperationsRead,
    #[serde(rename = "usage:read")]
    UsageRead,
}

impl ApiKeyScope {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WorkspaceRead => "workspace:read",
            Self::SearchRead => "search:read",
            Self::SearchWrite => "search:write",
            Self::WatchRead => "watch:read",
            Self::WatchWrite => "watch:write",
            Self::NotificationRead => "notification:read",
            Self::NotificationWrite => "notification:write",
            Self::DataExport => "data:export",
            Self::DataDelete => "data:delete",
            Self::ConsentRead => "consent:read",
            Self::ConsentWrite => "consent:write",
            Self::ContributionRead => "contribution:read",
            Self::ContributionWrite => "contribution:write",
            Self::EvidenceRead => "evidence:read",
            Self::OperationsRead => "operations:read",
            Self::UsageRead => "usage:read",
        }
    }

    pub fn parse(value: &str) -> Result<Self, ValidationErrors> {
        match value {
            "workspace:read" => Ok(Self::WorkspaceRead),
            "search:read" => Ok(Self::SearchRead),
            "search:write" => Ok(Self::SearchWrite),
            "watch:read" => Ok(Self::WatchRead),
            "watch:write" => Ok(Self::WatchWrite),
            "notification:read" => Ok(Self::NotificationRead),
            "notification:write" => Ok(Self::NotificationWrite),
            "data:export" => Ok(Self::DataExport),
            "data:delete" => Ok(Self::DataDelete),
            "consent:read" => Ok(Self::ConsentRead),
            "consent:write" => Ok(Self::ConsentWrite),
            "contribution:read" => Ok(Self::ContributionRead),
            "contribution:write" => Ok(Self::ContributionWrite),
            "evidence:read" => Ok(Self::EvidenceRead),
            "operations:read" => Ok(Self::OperationsRead),
            "usage:read" => Ok(Self::UsageRead),
            _ => Err(ValidationErrors::new(
                "scopes",
                ValidationCode::InvalidFormat,
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceState {
    Active,
    Suspended,
    Deleting,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApiKeyState {
    Active,
    Revoked,
    Expired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedApiKeyResource {
    pub api_key_id: ApiKeyId,
    pub key_prefix: String,
    pub scopes: Vec<ApiKeyScope>,
    pub state: ApiKeyState,
    pub expires_at_unix_ms: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceResource {
    pub schema: ProtocolVersion,
    pub workspace_id: WorkspaceId,
    pub slug: String,
    pub display_name: String,
    pub state: WorkspaceState,
    pub authenticated_api_key: AuthenticatedApiKeyResource,
}

impl Validate for WorkspaceResource {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = Vec::new();
        if !valid_slug(&self.slug) {
            errors.push(("slug", ValidationCode::InvalidFormat));
        }
        if self.display_name.is_empty()
            || self.display_name.len() > 200
            || self.display_name.chars().any(char::is_control)
        {
            errors.push(("display_name", ValidationCode::InvalidFormat));
        }
        let key = &self.authenticated_api_key;
        if key.key_prefix.len() != 16
            || !key
                .key_prefix
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            errors.push((
                "authenticated_api_key.key_prefix",
                ValidationCode::InvalidFormat,
            ));
        }
        if key.scopes.is_empty() || key.scopes.len() > 16 {
            errors.push(("authenticated_api_key.scopes", ValidationCode::OutOfRange));
        } else if key.scopes.iter().collect::<BTreeSet<_>>().len() != key.scopes.len() {
            errors.push(("authenticated_api_key.scopes", ValidationCode::Duplicate));
        }
        if key
            .expires_at_unix_ms
            .is_some_and(|timestamp| timestamp <= 0)
        {
            errors.push((
                "authenticated_api_key.expires_at_unix_ms",
                ValidationCode::OutOfRange,
            ));
        }

        if let Some((field, code)) = errors.first().copied() {
            let mut validation_errors = ValidationErrors::new(field, code);
            for (field, code) in errors.into_iter().skip(1) {
                validation_errors.push(field, code);
            }
            Err(validation_errors)
        } else {
            Ok(())
        }
    }
}

fn valid_slug(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !value.contains("--")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resource() -> WorkspaceResource {
        WorkspaceResource {
            schema: ProtocolVersion::ApiV1,
            workspace_id: WorkspaceId::new("workspace_01").unwrap(),
            slug: "example-workspace".to_owned(),
            display_name: "Example workspace".to_owned(),
            state: WorkspaceState::Active,
            authenticated_api_key: AuthenticatedApiKeyResource {
                api_key_id: ApiKeyId::new("api_key_01").unwrap(),
                key_prefix: "0123456789abcdef".to_owned(),
                scopes: vec![ApiKeyScope::WorkspaceRead],
                state: ApiKeyState::Active,
                expires_at_unix_ms: None,
            },
        }
    }

    #[test]
    fn workspace_resource_is_bounded_and_contains_no_secret_field() {
        let resource = resource();
        assert!(resource.validate().is_ok());
        let json = serde_json::to_value(resource).unwrap();
        assert_eq!(json["schema"], crate::API_V1_SCHEMA);
        assert_eq!(json["authenticated_api_key"]["scopes"][0], "workspace:read");
        assert!(json["authenticated_api_key"].get("secret").is_none());
        assert!(json["authenticated_api_key"].get("secret_hash").is_none());
    }

    #[test]
    fn workspace_resource_rejects_duplicate_scopes_and_invalid_prefixes() {
        let mut resource = resource();
        resource.authenticated_api_key.key_prefix = "PUBLIC-PREFIX".to_owned();
        resource
            .authenticated_api_key
            .scopes
            .push(ApiKeyScope::WorkspaceRead);
        let errors = resource.validate().unwrap_err();
        assert_eq!(errors.issues().len(), 2);
    }

    #[test]
    fn api_key_scope_parser_is_closed_and_omits_rejected_values() {
        assert_eq!(
            ApiKeyScope::parse("evidence:read").unwrap(),
            ApiKeyScope::EvidenceRead
        );
        assert_eq!(
            ApiKeyScope::parse("operations:read").unwrap(),
            ApiKeyScope::OperationsRead
        );
        let error = ApiKeyScope::parse("secret-scope").unwrap_err();
        assert!(!error.to_string().contains("secret-scope"));
    }
}
