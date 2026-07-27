use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    DeliveryErrorCode, NotificationDeliveryId, NotificationDeliveryState, NotificationEndpointId,
    ProtocolVersion, SearchId, SearchState, Validate, ValidationCode, ValidationErrors,
    common::validate_timestamp,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchCompletionWebhookCreateRequest {
    pub schema: ProtocolVersion,
    pub endpoint_id: NotificationEndpointId,
}

impl Validate for SearchCompletionWebhookCreateRequest {
    fn validate(&self) -> Result<(), ValidationErrors> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SearchCompletionWebhookSubscriptionState {
    Active,
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SearchCompletionOutcome {
    Completed,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchCompletionDeliveryStatus {
    pub delivery_id: NotificationDeliveryId,
    pub state: NotificationDeliveryState,
    pub attempt_count: u32,
    pub queued_at_unix_ms: i64,
    pub next_attempt_at_unix_ms: Option<i64>,
    pub delivered_at_unix_ms: Option<i64>,
    pub last_error_code: Option<DeliveryErrorCode>,
}

impl SearchCompletionDeliveryStatus {
    fn validate(&self, subscription_created_at_unix_ms: i64) -> Result<(), ValidationErrors> {
        validate_timestamp("delivery.queued_at_unix_ms", self.queued_at_unix_ms)?;
        if self.queued_at_unix_ms < subscription_created_at_unix_ms
            || self
                .next_attempt_at_unix_ms
                .into_iter()
                .chain(self.delivered_at_unix_ms)
                .any(|timestamp| timestamp < self.queued_at_unix_ms)
        {
            return Err(ValidationErrors::new(
                "delivery.timestamps",
                ValidationCode::InvalidRelation,
            ));
        }
        let valid = match self.state {
            NotificationDeliveryState::Queued => {
                self.attempt_count == 0
                    && self.next_attempt_at_unix_ms.is_none()
                    && self.delivered_at_unix_ms.is_none()
                    && self.last_error_code.is_none()
            }
            NotificationDeliveryState::Delivering => {
                self.attempt_count > 0
                    && self.next_attempt_at_unix_ms.is_none()
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
        if valid {
            Ok(())
        } else {
            Err(ValidationErrors::new(
                "delivery.state",
                ValidationCode::InvalidRelation,
            ))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchCompletionWebhookResource {
    pub schema: ProtocolVersion,
    pub search_id: SearchId,
    pub endpoint_id: NotificationEndpointId,
    pub search_state: SearchState,
    pub subscription_state: SearchCompletionWebhookSubscriptionState,
    pub created_at_unix_ms: i64,
    pub cancelled_at_unix_ms: Option<i64>,
    pub delivery: Option<SearchCompletionDeliveryStatus>,
}

impl Validate for SearchCompletionWebhookResource {
    fn validate(&self) -> Result<(), ValidationErrors> {
        validate_timestamp("created_at_unix_ms", self.created_at_unix_ms)?;
        if self
            .cancelled_at_unix_ms
            .is_some_and(|timestamp| timestamp < self.created_at_unix_ms)
            || (self.subscription_state == SearchCompletionWebhookSubscriptionState::Active)
                != self.cancelled_at_unix_ms.is_none()
        {
            return Err(ValidationErrors::new(
                "subscription_state",
                ValidationCode::InvalidRelation,
            ));
        }
        if matches!(
            self.search_state,
            SearchState::Accepted | SearchState::Running | SearchState::Cancelled
        ) && self.delivery.is_some()
        {
            return Err(ValidationErrors::new(
                "delivery",
                ValidationCode::InvalidRelation,
            ));
        }
        if matches!(
            self.search_state,
            SearchState::Completed | SearchState::Failed
        ) && self.subscription_state == SearchCompletionWebhookSubscriptionState::Active
            && self.delivery.is_none()
        {
            return Err(ValidationErrors::new(
                "delivery",
                ValidationCode::InvalidRelation,
            ));
        }
        if let Some(delivery) = &self.delivery {
            delivery.validate(self.created_at_unix_ms)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchCompletionWebhook {
    pub schema: ProtocolVersion,
    pub delivery_id: NotificationDeliveryId,
    pub search_id: SearchId,
    pub outcome: SearchCompletionOutcome,
    pub completed_at_unix_ms: i64,
}

impl SearchCompletionWebhook {
    pub fn new(
        delivery_id: NotificationDeliveryId,
        search_id: SearchId,
        outcome: SearchCompletionOutcome,
        completed_at_unix_ms: i64,
    ) -> Result<Self, ValidationErrors> {
        let notification = Self {
            schema: ProtocolVersion::ApiV1,
            delivery_id,
            search_id,
            outcome,
            completed_at_unix_ms,
        };
        notification.validate()?;
        Ok(notification)
    }
}

impl Validate for SearchCompletionWebhook {
    fn validate(&self) -> Result<(), ValidationErrors> {
        validate_timestamp("completed_at_unix_ms", self.completed_at_unix_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resource() -> SearchCompletionWebhookResource {
        SearchCompletionWebhookResource {
            schema: ProtocolVersion::ApiV1,
            search_id: SearchId::new("00000000-0000-0000-0000-000000000001").unwrap(),
            endpoint_id: NotificationEndpointId::new("00000000-0000-0000-0000-000000000002")
                .unwrap(),
            search_state: SearchState::Completed,
            subscription_state: SearchCompletionWebhookSubscriptionState::Active,
            created_at_unix_ms: 1_000,
            cancelled_at_unix_ms: None,
            delivery: Some(SearchCompletionDeliveryStatus {
                delivery_id: NotificationDeliveryId::new("00000000-0000-0000-0000-000000000003")
                    .unwrap(),
                state: NotificationDeliveryState::Queued,
                attempt_count: 0,
                queued_at_unix_ms: 2_000,
                next_attempt_at_unix_ms: None,
                delivered_at_unix_ms: None,
                last_error_code: None,
            }),
        }
    }

    #[test]
    fn completion_resource_keeps_waiting_and_delivery_states_distinct() {
        let resource = resource();
        assert!(resource.validate().is_ok());
        let mut waiting = resource;
        waiting.search_state = SearchState::Running;
        waiting.delivery = None;
        assert!(waiting.validate().is_ok());
    }

    #[test]
    fn completion_resource_rejects_missing_terminal_delivery_and_bad_retry_state() {
        let mut missing_delivery = resource();
        missing_delivery.delivery = None;
        assert!(missing_delivery.validate().is_err());

        let mut invalid_retry = resource();
        let delivery = invalid_retry.delivery.as_mut().unwrap();
        delivery.state = NotificationDeliveryState::RetryScheduled;
        delivery.attempt_count = 1;
        assert!(invalid_retry.validate().is_err());
    }

    #[test]
    fn completion_payload_is_target_free_and_timestamped() {
        let payload = SearchCompletionWebhook::new(
            NotificationDeliveryId::new("00000000-0000-0000-0000-000000000003").unwrap(),
            SearchId::new("00000000-0000-0000-0000-000000000001").unwrap(),
            SearchCompletionOutcome::Failed,
            2_000,
        )
        .unwrap();
        let serialized = serde_json::to_string(&payload).unwrap();
        assert!(!serialized.contains("username"));
        assert!(!serialized.contains("site"));
        assert!(!serialized.contains("result"));
    }
}
