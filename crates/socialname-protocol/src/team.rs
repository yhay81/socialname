use std::{collections::HashSet, fmt};

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, de};

use crate::{
    ApiKeyId, ApiKeyScope, AuditEventId, AuditResourceId, MembershipId, ProtocolVersion,
    Transition, TransitionReviewId, Validate, ValidationCode, ValidationErrors, WorkspaceId,
    common::validate_timestamp,
};

pub const MAX_TEAM_PAGE_ITEMS: usize = 50;
pub const MINIMUM_WATCH_RETENTION_DAYS: u16 = 30;
pub const MAXIMUM_WATCH_RETENTION_DAYS: u16 = 730;

#[derive(Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct OrganizationSubjectReference(String);

impl OrganizationSubjectReference {
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationErrors> {
        let value = value.into();
        if bounded_text(&value, 200) {
            Ok(Self(value))
        } else {
            Err(ValidationErrors::new(
                "subject_reference",
                ValidationCode::InvalidFormat,
            ))
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for OrganizationSubjectReference {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

impl fmt::Debug for OrganizationSubjectReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OrganizationSubjectReference([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OrganizationRole {
    Owner,
    Administrator,
    Member,
    Viewer,
}

impl OrganizationRole {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Administrator => "administrator",
            Self::Member => "member",
            Self::Viewer => "viewer",
        }
    }

    pub fn parse(value: &str) -> Result<Self, ValidationErrors> {
        match value {
            "owner" => Ok(Self::Owner),
            "administrator" => Ok(Self::Administrator),
            "member" => Ok(Self::Member),
            "viewer" => Ok(Self::Viewer),
            _ => Err(ValidationErrors::new("role", ValidationCode::InvalidFormat)),
        }
    }

    #[must_use]
    pub const fn permits_scope(self, scope: ApiKeyScope) -> bool {
        match self {
            Self::Owner | Self::Administrator => true,
            Self::Member => true,
            Self::Viewer => matches!(
                scope,
                ApiKeyScope::WorkspaceRead
                    | ApiKeyScope::SearchRead
                    | ApiKeyScope::WatchRead
                    | ApiKeyScope::ConsentRead
                    | ApiKeyScope::ContributionRead
                    | ApiKeyScope::EvidenceRead
                    | ApiKeyScope::NotificationRead
                    | ApiKeyScope::OperationsRead
                    | ApiKeyScope::UsageRead
                    | ApiKeyScope::DataExport
            ),
        }
    }

    #[must_use]
    pub const fn can_manage_members(self) -> bool {
        matches!(self, Self::Owner | Self::Administrator)
    }

    #[must_use]
    pub const fn can_handle_reviews(self) -> bool {
        !matches!(self, Self::Viewer)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OrganizationMemberState {
    Active,
    Suspended,
    Removed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrganizationMemberResource {
    pub schema: ProtocolVersion,
    pub organization_id: WorkspaceId,
    pub membership_id: MembershipId,
    pub display_name: String,
    pub role: OrganizationRole,
    pub state: OrganizationMemberState,
    pub revision: u64,
    pub created_at_unix_ms: i64,
    pub updated_at_unix_ms: i64,
}

impl Validate for OrganizationMemberResource {
    fn validate(&self) -> Result<(), ValidationErrors> {
        if !bounded_text(&self.display_name, 100) {
            return Err(ValidationErrors::new(
                "display_name",
                ValidationCode::InvalidFormat,
            ));
        }
        if self.revision == 0 {
            return Err(ValidationErrors::new(
                "revision",
                ValidationCode::OutOfRange,
            ));
        }
        validate_timestamp("created_at_unix_ms", self.created_at_unix_ms)?;
        validate_timestamp("updated_at_unix_ms", self.updated_at_unix_ms)?;
        if self.updated_at_unix_ms < self.created_at_unix_ms {
            return Err(ValidationErrors::new(
                "updated_at_unix_ms",
                ValidationCode::InvalidRelation,
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrganizationResource {
    pub schema: ProtocolVersion,
    pub organization_id: WorkspaceId,
    pub slug: String,
    pub display_name: String,
    pub state: crate::WorkspaceState,
    pub authenticated_member: OrganizationMemberResource,
}

impl Validate for OrganizationResource {
    fn validate(&self) -> Result<(), ValidationErrors> {
        if self.slug.is_empty()
            || self.slug.len() > 63
            || self.slug.starts_with('-')
            || self.slug.ends_with('-')
            || self.slug.contains("--")
            || !self
                .slug
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(ValidationErrors::new("slug", ValidationCode::InvalidFormat));
        }
        if !bounded_text(&self.display_name, 200) {
            return Err(ValidationErrors::new(
                "display_name",
                ValidationCode::InvalidFormat,
            ));
        }
        self.authenticated_member.validate()?;
        if self.authenticated_member.organization_id != self.organization_id {
            return Err(ValidationErrors::new(
                "authenticated_member.organization_id",
                ValidationCode::InvalidRelation,
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrganizationMemberCreateRequest {
    pub schema: ProtocolVersion,
    pub subject_reference: OrganizationSubjectReference,
    pub display_name: String,
    pub role: OrganizationRole,
}

impl Validate for OrganizationMemberCreateRequest {
    fn validate(&self) -> Result<(), ValidationErrors> {
        if bounded_text(&self.display_name, 100) {
            Ok(())
        } else {
            Err(ValidationErrors::new(
                "display_name",
                ValidationCode::InvalidFormat,
            ))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OrganizationMemberAction {
    ChangeRole { role: OrganizationRole },
    Suspend,
    Reactivate,
    Remove,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrganizationMemberPatchRequest {
    pub schema: ProtocolVersion,
    pub expected_revision: u64,
    pub action: OrganizationMemberAction,
}

impl Validate for OrganizationMemberPatchRequest {
    fn validate(&self) -> Result<(), ValidationErrors> {
        if self.expected_revision == 0 {
            Err(ValidationErrors::new(
                "expected_revision",
                ValidationCode::OutOfRange,
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrganizationMemberPage {
    pub schema: ProtocolVersion,
    pub members: Vec<OrganizationMemberResource>,
    pub next_cursor: Option<MembershipId>,
}

impl Validate for OrganizationMemberPage {
    fn validate(&self) -> Result<(), ValidationErrors> {
        validate_page(
            "members",
            &self.members,
            self.next_cursor.as_ref(),
            |member| {
                member.validate()?;
                Ok(member.membership_id.as_str())
            },
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OrganizationAuditActor {
    System,
    Membership { membership_id: MembershipId },
    ApiKey { api_key_id: ApiKeyId },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrganizationAuditEventResource {
    pub schema: ProtocolVersion,
    pub audit_event_id: AuditEventId,
    pub actor: OrganizationAuditActor,
    pub action: String,
    pub resource_kind: String,
    pub resource_id: Option<AuditResourceId>,
    pub occurred_at_unix_ms: i64,
}

impl Validate for OrganizationAuditEventResource {
    fn validate(&self) -> Result<(), ValidationErrors> {
        if !bounded_text(&self.action, 100) {
            return Err(ValidationErrors::new(
                "action",
                ValidationCode::InvalidFormat,
            ));
        }
        if !bounded_text(&self.resource_kind, 64) {
            return Err(ValidationErrors::new(
                "resource_kind",
                ValidationCode::InvalidFormat,
            ));
        }
        validate_timestamp("occurred_at_unix_ms", self.occurred_at_unix_ms)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrganizationAuditEventPage {
    pub schema: ProtocolVersion,
    pub events: Vec<OrganizationAuditEventResource>,
    pub next_cursor: Option<AuditEventId>,
}

impl Validate for OrganizationAuditEventPage {
    fn validate(&self) -> Result<(), ValidationErrors> {
        validate_page("events", &self.events, self.next_cursor.as_ref(), |event| {
            event.validate()?;
            Ok(event.audit_event_id.as_str())
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrganizationRetentionPolicyResource {
    pub schema: ProtocolVersion,
    pub organization_id: WorkspaceId,
    pub revision: u64,
    pub minimum_watch_retention_days: u16,
    pub maximum_watch_retention_days: u16,
    pub updated_at_unix_ms: i64,
}

impl Validate for OrganizationRetentionPolicyResource {
    fn validate(&self) -> Result<(), ValidationErrors> {
        validate_retention_policy(
            self.revision,
            self.minimum_watch_retention_days,
            self.maximum_watch_retention_days,
        )?;
        validate_timestamp("updated_at_unix_ms", self.updated_at_unix_ms)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrganizationRetentionPolicyPatchRequest {
    pub schema: ProtocolVersion,
    pub expected_revision: u64,
    pub minimum_watch_retention_days: u16,
    pub maximum_watch_retention_days: u16,
}

impl Validate for OrganizationRetentionPolicyPatchRequest {
    fn validate(&self) -> Result<(), ValidationErrors> {
        validate_retention_policy(
            self.expected_revision,
            self.minimum_watch_retention_days,
            self.maximum_watch_retention_days,
        )
    }
}

fn validate_retention_policy(
    revision: u64,
    minimum_days: u16,
    maximum_days: u16,
) -> Result<(), ValidationErrors> {
    if revision == 0 {
        return Err(ValidationErrors::new(
            "revision",
            ValidationCode::OutOfRange,
        ));
    }
    if !(MINIMUM_WATCH_RETENTION_DAYS..=MAXIMUM_WATCH_RETENTION_DAYS).contains(&minimum_days)
        || !(minimum_days..=MAXIMUM_WATCH_RETENTION_DAYS).contains(&maximum_days)
    {
        return Err(ValidationErrors::new(
            "watch_retention_days",
            ValidationCode::OutOfRange,
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TransitionReviewState {
    Open,
    Acknowledged,
    Resolved,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TransitionReviewResolution {
    ActionTaken,
    NoActionRequired,
    MeasurementFollowUp,
    ExternallyEscalated,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TransitionReviewResource {
    pub schema: ProtocolVersion,
    pub review_id: TransitionReviewId,
    pub transition: Transition,
    pub state: TransitionReviewState,
    pub revision: u64,
    pub assigned_membership_id: Option<MembershipId>,
    pub acknowledged_by_membership_id: Option<MembershipId>,
    pub acknowledged_at_unix_ms: Option<i64>,
    pub resolved_by_membership_id: Option<MembershipId>,
    pub resolved_at_unix_ms: Option<i64>,
    pub resolution: Option<TransitionReviewResolution>,
    pub created_at_unix_ms: i64,
    pub updated_at_unix_ms: i64,
}

impl Validate for TransitionReviewResource {
    fn validate(&self) -> Result<(), ValidationErrors> {
        self.transition.validate()?;
        if !matches!(
            self.transition.change,
            crate::TransitionChange::AccountState { .. }
        ) || !matches!(
            self.transition.confirmation,
            crate::TransitionConfirmation::Confirmed { .. }
        ) {
            return Err(ValidationErrors::new(
                "transition",
                ValidationCode::InvalidRelation,
            ));
        }
        if self.revision == 0 {
            return Err(ValidationErrors::new(
                "revision",
                ValidationCode::OutOfRange,
            ));
        }
        validate_timestamp("created_at_unix_ms", self.created_at_unix_ms)?;
        validate_timestamp("updated_at_unix_ms", self.updated_at_unix_ms)?;
        if self.updated_at_unix_ms < self.created_at_unix_ms {
            return Err(ValidationErrors::new(
                "updated_at_unix_ms",
                ValidationCode::InvalidRelation,
            ));
        }
        for (field, timestamp) in [
            ("acknowledged_at_unix_ms", self.acknowledged_at_unix_ms),
            ("resolved_at_unix_ms", self.resolved_at_unix_ms),
        ] {
            if let Some(timestamp) = timestamp {
                validate_timestamp(field, timestamp)?;
            }
        }
        let valid = match self.state {
            TransitionReviewState::Open => {
                self.acknowledged_by_membership_id.is_none()
                    && self.acknowledged_at_unix_ms.is_none()
                    && self.resolved_by_membership_id.is_none()
                    && self.resolved_at_unix_ms.is_none()
                    && self.resolution.is_none()
            }
            TransitionReviewState::Acknowledged => {
                self.assigned_membership_id.is_some()
                    && self.acknowledged_by_membership_id == self.assigned_membership_id
                    && self.acknowledged_at_unix_ms.is_some()
                    && self.resolved_by_membership_id.is_none()
                    && self.resolved_at_unix_ms.is_none()
                    && self.resolution.is_none()
            }
            TransitionReviewState::Resolved => {
                self.assigned_membership_id.is_some()
                    && self.acknowledged_by_membership_id == self.assigned_membership_id
                    && self.resolved_by_membership_id == self.assigned_membership_id
                    && self.acknowledged_at_unix_ms.is_some()
                    && self.resolved_at_unix_ms.is_some()
                    && self.resolution.is_some()
            }
        };
        if !valid
            || self
                .acknowledged_at_unix_ms
                .is_some_and(|timestamp| timestamp < self.created_at_unix_ms)
            || self.resolved_at_unix_ms.is_some_and(|timestamp| {
                self.acknowledged_at_unix_ms
                    .is_none_or(|acknowledged| timestamp < acknowledged)
            })
        {
            return Err(ValidationErrors::new(
                "state",
                ValidationCode::InvalidRelation,
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TransitionReviewAction {
    Assign {
        membership_id: MembershipId,
    },
    Acknowledge,
    Resolve {
        resolution: TransitionReviewResolution,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TransitionReviewPatchRequest {
    pub schema: ProtocolVersion,
    pub expected_revision: u64,
    pub action: TransitionReviewAction,
}

impl Validate for TransitionReviewPatchRequest {
    fn validate(&self) -> Result<(), ValidationErrors> {
        if self.expected_revision == 0 {
            Err(ValidationErrors::new(
                "expected_revision",
                ValidationCode::OutOfRange,
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TransitionReviewPage {
    pub schema: ProtocolVersion,
    pub reviews: Vec<TransitionReviewResource>,
    pub next_cursor: Option<TransitionReviewId>,
}

impl Validate for TransitionReviewPage {
    fn validate(&self) -> Result<(), ValidationErrors> {
        validate_page(
            "reviews",
            &self.reviews,
            self.next_cursor.as_ref(),
            |review| {
                review.validate()?;
                Ok(review.review_id.as_str())
            },
        )
    }
}

fn validate_page<'a, T, C>(
    field: &str,
    items: &'a [T],
    next_cursor: Option<&C>,
    mut validate_and_id: impl FnMut(&'a T) -> Result<&'a str, ValidationErrors>,
) -> Result<(), ValidationErrors>
where
    C: AsRef<str>,
{
    if items.len() > MAX_TEAM_PAGE_ITEMS {
        return Err(ValidationErrors::new(field, ValidationCode::TooManyItems));
    }
    let mut ids = HashSet::with_capacity(items.len());
    let mut last_id = None;
    for item in items {
        let id = validate_and_id(item)?;
        if !ids.insert(id) {
            return Err(ValidationErrors::new(field, ValidationCode::Duplicate));
        }
        last_id = Some(id);
    }
    if next_cursor.map(AsRef::as_ref) != last_id && next_cursor.is_some() {
        return Err(ValidationErrors::new(
            "next_cursor",
            ValidationCode::InvalidRelation,
        ));
    }
    Ok(())
}

fn bounded_text(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= maximum_bytes && !value.chars().any(char::is_control)
}

impl AsRef<str> for MembershipId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<str> for AuditEventId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<str> for TransitionReviewId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AccountState, ConfirmationBasis, ObservationId, SiteId, Target, TransitionChange,
        TransitionConfirmation, TransitionId, Username, WatchId,
    };

    fn member(id: &str) -> OrganizationMemberResource {
        OrganizationMemberResource {
            schema: ProtocolVersion::ApiV1,
            organization_id: WorkspaceId::new("organization_01").unwrap(),
            membership_id: MembershipId::new(id).unwrap(),
            display_name: "Reviewer".to_owned(),
            role: OrganizationRole::Member,
            state: OrganizationMemberState::Active,
            revision: 1,
            created_at_unix_ms: 1_000,
            updated_at_unix_ms: 1_000,
        }
    }

    fn confirmed_transition() -> Transition {
        Transition {
            schema: ProtocolVersion::ApiV1,
            transition_id: TransitionId::new("transition_01").unwrap(),
            watch_id: WatchId::new("watch_01").unwrap(),
            target: Target {
                username: Username::new("alice").unwrap(),
                site_id: SiteId::new("github").unwrap(),
            },
            change: TransitionChange::AccountState {
                from: AccountState::NotFound,
                to: AccountState::Found,
            },
            confirmation: TransitionConfirmation::Confirmed {
                basis: ConfirmationBasis::ManagedE4,
            },
            supporting_observation_ids: vec![ObservationId::new("observation_01").unwrap()],
            detected_at_unix_ms: 2_000,
        }
    }

    #[test]
    fn subject_reference_is_redacted_and_member_page_is_bounded() {
        let subject = OrganizationSubjectReference::new("identity-provider|alice").unwrap();
        assert!(!format!("{subject:?}").contains("alice"));
        let page = OrganizationMemberPage {
            schema: ProtocolVersion::ApiV1,
            members: vec![member("membership_01")],
            next_cursor: Some(MembershipId::new("membership_01").unwrap()),
        };
        assert!(page.validate().is_ok());
    }

    #[test]
    fn retention_policy_requires_an_ordered_hard_bounded_range() {
        let valid = OrganizationRetentionPolicyPatchRequest {
            schema: ProtocolVersion::ApiV1,
            expected_revision: 1,
            minimum_watch_retention_days: 90,
            maximum_watch_retention_days: 400,
        };
        assert!(valid.validate().is_ok());
        let mut invalid = valid;
        invalid.maximum_watch_retention_days = 30;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn review_acknowledgement_is_assignment_bound() {
        let assigned = MembershipId::new("membership_01").unwrap();
        let review = TransitionReviewResource {
            schema: ProtocolVersion::ApiV1,
            review_id: TransitionReviewId::new("review_01").unwrap(),
            transition: confirmed_transition(),
            state: TransitionReviewState::Acknowledged,
            revision: 3,
            assigned_membership_id: Some(assigned.clone()),
            acknowledged_by_membership_id: Some(assigned),
            acknowledged_at_unix_ms: Some(3_000),
            resolved_by_membership_id: None,
            resolved_at_unix_ms: None,
            resolution: None,
            created_at_unix_ms: 2_000,
            updated_at_unix_ms: 3_000,
        };
        assert!(review.validate().is_ok());
        let mut invalid = review;
        invalid.acknowledged_by_membership_id = Some(MembershipId::new("membership_02").unwrap());
        assert!(invalid.validate().is_err());
    }
}
