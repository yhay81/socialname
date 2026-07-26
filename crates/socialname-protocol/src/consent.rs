use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    ConsentGrantId, ConsentSubjectId, InstallationId, ProtocolVersion, Validate, ValidationCode,
    ValidationErrors,
};

pub const MAX_CONSENT_PAGE_ITEMS: usize = 50;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConsentSubjectKind {
    Account,
    Installation,
}

impl ConsentSubjectKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Account => "account",
            Self::Installation => "installation",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConsentPurpose {
    PrivateHistory,
    SharedObservation,
    SharedResearch,
}

impl ConsentPurpose {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PrivateHistory => "private_history",
            Self::SharedObservation => "shared_observation",
            Self::SharedResearch => "shared_research",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum ConsentCollectionProfileVersion {
    #[serde(rename = "profile-v1")]
    V1,
}

impl ConsentCollectionProfileVersion {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V1 => "profile-v1",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum ConsentNoticeVersion {
    #[serde(rename = "notice-v1")]
    V1,
}

impl ConsentNoticeVersion {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V1 => "notice-v1",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConsentSource {
    Cli,
    Web,
    Api,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConsentGrantState {
    Active,
    Expired,
    Withdrawn,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsentGrantCreateRequest {
    pub schema: ProtocolVersion,
    pub subject_kind: ConsentSubjectKind,
    pub installation_id: Option<InstallationId>,
    pub purpose: ConsentPurpose,
    pub collection_profile_version: ConsentCollectionProfileVersion,
    pub notice_version: ConsentNoticeVersion,
    pub expires_at_unix_ms: Option<i64>,
}

impl std::fmt::Debug for ConsentGrantCreateRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConsentGrantCreateRequest")
            .field("schema", &self.schema)
            .field("subject_kind", &self.subject_kind)
            .field(
                "installation_id",
                &self.installation_id.as_ref().map(|_| "[REDACTED]"),
            )
            .field("purpose", &self.purpose)
            .field(
                "collection_profile_version",
                &self.collection_profile_version,
            )
            .field("notice_version", &self.notice_version)
            .field("expires_at_unix_ms", &self.expires_at_unix_ms)
            .finish()
    }
}

impl Validate for ConsentGrantCreateRequest {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let subject_valid = matches!(
            (self.subject_kind, self.installation_id.as_ref()),
            (ConsentSubjectKind::Account, None) | (ConsentSubjectKind::Installation, Some(_))
        );
        if !subject_valid {
            return Err(ValidationErrors::new(
                "installation_id",
                ValidationCode::InvalidRelation,
            ));
        }
        if self.expires_at_unix_ms.is_some_and(|value| value <= 0) {
            return Err(ValidationErrors::new(
                "expires_at_unix_ms",
                ValidationCode::OutOfRange,
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsentGrantResource {
    pub schema: ProtocolVersion,
    pub consent_grant_id: ConsentGrantId,
    pub subject_kind: ConsentSubjectKind,
    pub subject_id: ConsentSubjectId,
    pub purpose: ConsentPurpose,
    pub collection_profile_version: ConsentCollectionProfileVersion,
    pub notice_version: ConsentNoticeVersion,
    pub source: ConsentSource,
    pub state: ConsentGrantState,
    pub granted_at_unix_ms: i64,
    pub expires_at_unix_ms: Option<i64>,
    pub withdrawn_at_unix_ms: Option<i64>,
}

impl Validate for ConsentGrantResource {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let timestamps_valid = self.granted_at_unix_ms > 0
            && self
                .expires_at_unix_ms
                .is_none_or(|value| value > self.granted_at_unix_ms)
            && self
                .withdrawn_at_unix_ms
                .is_none_or(|value| value >= self.granted_at_unix_ms);
        if !timestamps_valid {
            return Err(ValidationErrors::new(
                "timestamps",
                ValidationCode::InvalidRelation,
            ));
        }
        let state_valid = match self.state {
            ConsentGrantState::Active => self.withdrawn_at_unix_ms.is_none(),
            ConsentGrantState::Expired => {
                self.withdrawn_at_unix_ms.is_none() && self.expires_at_unix_ms.is_some()
            }
            ConsentGrantState::Withdrawn => self.withdrawn_at_unix_ms.is_some(),
        };
        if !state_valid {
            return Err(ValidationErrors::new(
                "state",
                ValidationCode::InvalidRelation,
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsentGrantListPage {
    pub schema: ProtocolVersion,
    pub consent_grants: Vec<ConsentGrantResource>,
    pub next_cursor: Option<ConsentGrantId>,
}

impl Validate for ConsentGrantListPage {
    fn validate(&self) -> Result<(), ValidationErrors> {
        if self.consent_grants.len() > MAX_CONSENT_PAGE_ITEMS {
            return Err(ValidationErrors::new(
                "consent_grants",
                ValidationCode::TooManyItems,
            ));
        }
        if self.next_cursor.as_ref()
            != self
                .consent_grants
                .last()
                .map(|grant| &grant.consent_grant_id)
            && self.next_cursor.is_some()
        {
            return Err(ValidationErrors::new(
                "next_cursor",
                ValidationCode::InvalidRelation,
            ));
        }
        for grant in &self.consent_grants {
            grant.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsentWithdrawalRequest {
    pub schema: ProtocolVersion,
}

impl Validate for ConsentWithdrawalRequest {
    fn validate(&self) -> Result<(), ValidationErrors> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_request() -> ConsentGrantCreateRequest {
        ConsentGrantCreateRequest {
            schema: ProtocolVersion::ApiV1,
            subject_kind: ConsentSubjectKind::Installation,
            installation_id: Some(
                InstallationId::new("11111111-1111-4111-8111-111111111111").unwrap(),
            ),
            purpose: ConsentPurpose::SharedObservation,
            collection_profile_version: ConsentCollectionProfileVersion::V1,
            notice_version: ConsentNoticeVersion::V1,
            expires_at_unix_ms: None,
        }
    }

    #[test]
    fn create_request_binds_installation_identifier_to_subject_kind() {
        assert!(create_request().validate().is_ok());
        let mut account = create_request();
        account.subject_kind = ConsentSubjectKind::Account;
        assert_eq!(
            account.validate().unwrap_err().issues()[0].field,
            "installation_id"
        );
    }

    #[test]
    fn installation_identifier_is_redacted_from_debug_output() {
        let request = create_request();
        assert!(InstallationId::new("low-entropy-installation").is_err());
        assert!(!format!("{request:?}").contains("11111111-1111-4111-8111-111111111111"));
        assert!(
            !format!("{:?}", request.installation_id.unwrap())
                .contains("11111111-1111-4111-8111-111111111111")
        );
    }

    #[test]
    fn list_cursor_must_name_the_last_returned_grant() {
        let grant = ConsentGrantResource {
            schema: ProtocolVersion::ApiV1,
            consent_grant_id: ConsentGrantId::new("grant-1").unwrap(),
            subject_kind: ConsentSubjectKind::Account,
            subject_id: ConsentSubjectId::new("subject-1").unwrap(),
            purpose: ConsentPurpose::PrivateHistory,
            collection_profile_version: ConsentCollectionProfileVersion::V1,
            notice_version: ConsentNoticeVersion::V1,
            source: ConsentSource::Api,
            state: ConsentGrantState::Active,
            granted_at_unix_ms: 1,
            expires_at_unix_ms: None,
            withdrawn_at_unix_ms: None,
        };
        let mut page = ConsentGrantListPage {
            schema: ProtocolVersion::ApiV1,
            consent_grants: vec![grant],
            next_cursor: Some(ConsentGrantId::new("grant-1").unwrap()),
        };
        assert!(page.validate().is_ok());
        page.next_cursor = Some(ConsentGrantId::new("grant-2").unwrap());
        assert!(page.validate().is_err());
    }
}
