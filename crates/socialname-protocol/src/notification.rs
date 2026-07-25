use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    ConfirmationBasis, DeliveryErrorCode, EmailAddress, HttpsUrl, NotificationDeliveryId,
    NotificationEndpointId, NotificationLogicalKey, ProtocolVersion, Transition, TransitionChange,
    TransitionConfirmation, TransitionId, Validate, ValidationCode, ValidationErrors,
    common::validate_timestamp,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NotificationChannel {
    Email,
    Webhook,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "channel", rename_all = "snake_case", deny_unknown_fields)]
pub enum NotificationDestination {
    Email { address: EmailAddress },
    Webhook { url: HttpsUrl },
}

impl NotificationDestination {
    const fn channel(&self) -> NotificationChannel {
        match self {
            Self::Email { .. } => NotificationChannel::Email,
            Self::Webhook { .. } => NotificationChannel::Webhook,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NotificationEndpointCreateRequest {
    pub schema: ProtocolVersion,
    pub destination: NotificationDestination,
}

impl Validate for NotificationEndpointCreateRequest {
    fn validate(&self) -> Result<(), ValidationErrors> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NotificationEndpointState {
    PendingVerification,
    Active,
    Disabled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NotificationEndpointResource {
    pub schema: ProtocolVersion,
    pub endpoint_id: NotificationEndpointId,
    pub channel: NotificationChannel,
    pub state: NotificationEndpointState,
    pub created_at_unix_ms: i64,
    pub verified_at_unix_ms: Option<i64>,
}

impl NotificationEndpointResource {
    pub fn pending(
        endpoint_id: NotificationEndpointId,
        request: &NotificationEndpointCreateRequest,
        created_at_unix_ms: i64,
    ) -> Result<Self, ValidationErrors> {
        validate_timestamp("created_at_unix_ms", created_at_unix_ms)?;
        Ok(Self {
            schema: ProtocolVersion::ApiV1,
            endpoint_id,
            channel: request.destination.channel(),
            state: NotificationEndpointState::PendingVerification,
            created_at_unix_ms,
            verified_at_unix_ms: None,
        })
    }
}

impl Validate for NotificationEndpointResource {
    fn validate(&self) -> Result<(), ValidationErrors> {
        validate_timestamp("created_at_unix_ms", self.created_at_unix_ms)?;
        match (self.state, self.verified_at_unix_ms) {
            (NotificationEndpointState::PendingVerification, None) => Ok(()),
            (
                NotificationEndpointState::Active | NotificationEndpointState::Disabled,
                Some(verified_at),
            ) if verified_at >= self.created_at_unix_ms => Ok(()),
            _ => Err(ValidationErrors::new(
                "verified_at_unix_ms",
                ValidationCode::InvalidRelation,
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NotificationKind {
    AccountState,
    MeasurementHealth,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NotificationDeliveryState {
    Queued,
    Delivering,
    RetryScheduled,
    Delivered,
    PermanentlyFailed,
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NotificationDelivery {
    pub schema: ProtocolVersion,
    pub delivery_id: NotificationDeliveryId,
    pub transition_id: TransitionId,
    pub endpoint_id: NotificationEndpointId,
    pub logical_notification_key: NotificationLogicalKey,
    pub kind: NotificationKind,
    pub channel: NotificationChannel,
    pub confirmation_basis: ConfirmationBasis,
    pub state: NotificationDeliveryState,
    pub attempt_count: u32,
    pub created_at_unix_ms: i64,
    pub next_attempt_at_unix_ms: Option<i64>,
    pub delivered_at_unix_ms: Option<i64>,
    pub last_error_code: Option<DeliveryErrorCode>,
}

impl NotificationDelivery {
    pub fn queued_for_transition(
        delivery_id: NotificationDeliveryId,
        transition: &Transition,
        endpoint_id: NotificationEndpointId,
        logical_notification_key: NotificationLogicalKey,
        channel: NotificationChannel,
        created_at_unix_ms: i64,
    ) -> Result<Self, ValidationErrors> {
        transition.validate()?;
        let TransitionConfirmation::Confirmed { basis } = transition.confirmation else {
            return Err(ValidationErrors::new(
                "transition.confirmation",
                ValidationCode::InvalidRelation,
            ));
        };
        let kind = match transition.change {
            TransitionChange::AccountState { .. } => NotificationKind::AccountState,
            TransitionChange::MeasurementHealth { .. } => NotificationKind::MeasurementHealth,
        };
        let delivery = Self {
            schema: ProtocolVersion::ApiV1,
            delivery_id,
            transition_id: transition.transition_id.clone(),
            endpoint_id,
            logical_notification_key,
            kind,
            channel,
            confirmation_basis: basis,
            state: NotificationDeliveryState::Queued,
            attempt_count: 0,
            created_at_unix_ms,
            next_attempt_at_unix_ms: None,
            delivered_at_unix_ms: None,
            last_error_code: None,
        };
        delivery.validate()?;
        Ok(delivery)
    }
}

impl Validate for NotificationDelivery {
    fn validate(&self) -> Result<(), ValidationErrors> {
        validate_timestamp("created_at_unix_ms", self.created_at_unix_ms)?;
        validate_kind_basis(self.kind, self.confirmation_basis)?;

        let timestamps_valid = self
            .next_attempt_at_unix_ms
            .into_iter()
            .chain(self.delivered_at_unix_ms)
            .all(|timestamp| timestamp >= self.created_at_unix_ms);
        if !timestamps_valid {
            return Err(ValidationErrors::new(
                "delivery_timestamps",
                ValidationCode::InvalidRelation,
            ));
        }

        let state_valid = match self.state {
            NotificationDeliveryState::Queued | NotificationDeliveryState::Delivering => {
                self.next_attempt_at_unix_ms.is_none()
                    && self.delivered_at_unix_ms.is_none()
                    && self.last_error_code.is_none()
            }
            NotificationDeliveryState::RetryScheduled => {
                self.attempt_count > 0
                    && self.next_attempt_at_unix_ms.is_some()
                    && self.delivered_at_unix_ms.is_none()
                    && self.last_error_code.is_some()
            }
            NotificationDeliveryState::Delivered => {
                self.attempt_count > 0
                    && self.next_attempt_at_unix_ms.is_none()
                    && self.delivered_at_unix_ms.is_some()
                    && self.last_error_code.is_none()
            }
            NotificationDeliveryState::PermanentlyFailed => {
                self.attempt_count > 0
                    && self.next_attempt_at_unix_ms.is_none()
                    && self.delivered_at_unix_ms.is_none()
                    && self.last_error_code.is_some()
            }
            NotificationDeliveryState::Cancelled => {
                self.next_attempt_at_unix_ms.is_none() && self.delivered_at_unix_ms.is_none()
            }
        };
        if state_valid {
            Ok(())
        } else {
            Err(ValidationErrors::new(
                "delivery_state",
                ValidationCode::InvalidRelation,
            ))
        }
    }
}

fn validate_kind_basis(
    kind: NotificationKind,
    basis: ConfirmationBasis,
) -> Result<(), ValidationErrors> {
    let valid = match kind {
        NotificationKind::AccountState => {
            !matches!(basis, ConfirmationBasis::MeasurementHealthEvidence)
        }
        NotificationKind::MeasurementHealth => {
            basis == ConfirmationBasis::MeasurementHealthEvidence
        }
    };
    if valid {
        Ok(())
    } else {
        Err(ValidationErrors::new(
            "confirmation_basis",
            ValidationCode::InvalidRelation,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AccountState, ObservationId, SiteId, SuppressionReason, Target, Username, WatchId,
    };

    fn transition(confirmation: TransitionConfirmation) -> Transition {
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
            confirmation,
            supporting_observation_ids: vec![ObservationId::new("observation_01").unwrap()],
            detected_at_unix_ms: 1_000,
        }
    }

    #[test]
    fn endpoint_destination_is_write_only_and_redacted_from_debug() {
        let request = NotificationEndpointCreateRequest {
            schema: ProtocolVersion::ApiV1,
            destination: NotificationDestination::Email {
                address: EmailAddress::new("private@example.com").unwrap(),
            },
        };
        assert!(!format!("{request:?}").contains("private@example.com"));

        let endpoint = NotificationEndpointResource::pending(
            NotificationEndpointId::new("endpoint_01").unwrap(),
            &request,
            1_000,
        )
        .unwrap();
        let json = serde_json::to_value(endpoint).unwrap();
        assert!(json.get("destination").is_none());
        assert_eq!(json["channel"], "email");
    }

    #[test]
    fn pending_or_suppressed_transition_cannot_create_a_delivery() {
        for confirmation in [
            TransitionConfirmation::Pending {
                reason: crate::PendingConfirmationReason::ManagedVerificationRequired,
            },
            TransitionConfirmation::Suppressed {
                reason: SuppressionReason::ConflictingEvidence,
            },
        ] {
            let result = NotificationDelivery::queued_for_transition(
                NotificationDeliveryId::new("delivery_01").unwrap(),
                &transition(confirmation),
                NotificationEndpointId::new("endpoint_01").unwrap(),
                NotificationLogicalKey::new("logical_01").unwrap(),
                NotificationChannel::Webhook,
                2_000,
            );
            assert!(result.is_err());
        }
    }

    #[test]
    fn confirmed_transition_creates_one_typed_queued_delivery() {
        let delivery = NotificationDelivery::queued_for_transition(
            NotificationDeliveryId::new("delivery_01").unwrap(),
            &transition(TransitionConfirmation::Confirmed {
                basis: ConfirmationBasis::ManagedE4,
            }),
            NotificationEndpointId::new("endpoint_01").unwrap(),
            NotificationLogicalKey::new("logical_01").unwrap(),
            NotificationChannel::Email,
            2_000,
        )
        .unwrap();
        assert_eq!(delivery.kind, NotificationKind::AccountState);
        assert_eq!(delivery.state, NotificationDeliveryState::Queued);
        assert_eq!(delivery.attempt_count, 0);
    }

    #[test]
    fn delivery_state_requires_consistent_attempt_metadata() {
        let mut delivery = NotificationDelivery::queued_for_transition(
            NotificationDeliveryId::new("delivery_01").unwrap(),
            &transition(TransitionConfirmation::Confirmed {
                basis: ConfirmationBasis::ManagedE4,
            }),
            NotificationEndpointId::new("endpoint_01").unwrap(),
            NotificationLogicalKey::new("logical_01").unwrap(),
            NotificationChannel::Email,
            2_000,
        )
        .unwrap();
        delivery.state = NotificationDeliveryState::Delivered;
        assert!(delivery.validate().is_err());

        delivery.attempt_count = 1;
        delivery.delivered_at_unix_ms = Some(3_000);
        assert!(delivery.validate().is_ok());
    }
}
