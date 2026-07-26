use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    ConsentGrantId, DeletionRequestId, ProtocolVersion, Validate, ValidationCode, ValidationErrors,
};

pub const MAXIMUM_DELETION_MATCH_COUNT: u32 = 1_000_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContributorDeletionCreateRequest {
    pub schema: ProtocolVersion,
    pub consent_grant_id: ConsentGrantId,
}

impl Validate for ContributorDeletionCreateRequest {
    fn validate(&self) -> Result<(), ValidationErrors> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeletionScope {
    Contributor,
    Target,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeletionRequestState {
    Hidden,
    WithdrawingSupport,
    Deleting,
    Rebuilding,
    Completed,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeletionStoreKind {
    Primary,
    Derived,
    Backup,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeletionStoreState {
    Pending,
    Running,
    RetryWait,
    Completed,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeletionStoreReceipt {
    pub store: DeletionStoreKind,
    pub state: DeletionStoreState,
    pub deadline_at_unix_ms: i64,
    pub completed_at_unix_ms: Option<i64>,
}

impl Validate for DeletionStoreReceipt {
    fn validate(&self) -> Result<(), ValidationErrors> {
        if self.deadline_at_unix_ms < 0 {
            return Err(ValidationErrors::new(
                "deadline_at_unix_ms",
                ValidationCode::OutOfRange,
            ));
        }
        if (self.state == DeletionStoreState::Completed) != self.completed_at_unix_ms.is_some()
            || self
                .completed_at_unix_ms
                .is_some_and(|completed| completed < 0)
        {
            return Err(ValidationErrors::new(
                "completed_at_unix_ms",
                ValidationCode::InvalidRelation,
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeletionReceiptState {
    Pending,
    Completed,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeletionReceiptResource {
    pub schema: ProtocolVersion,
    pub deletion_request_id: DeletionRequestId,
    pub state: DeletionReceiptState,
    pub evaluated_at_unix_ms: i64,
    pub stores: Vec<DeletionStoreReceipt>,
    pub primary_completed_at_unix_ms: Option<i64>,
    pub backup_expiry_by_unix_ms: i64,
    pub remaining_backup_expiry_ms: i64,
    pub completed_at_unix_ms: Option<i64>,
}

impl Validate for DeletionReceiptResource {
    fn validate(&self) -> Result<(), ValidationErrors> {
        if self.evaluated_at_unix_ms < 0
            || self.backup_expiry_by_unix_ms < 0
            || self.remaining_backup_expiry_ms
                != self
                    .backup_expiry_by_unix_ms
                    .saturating_sub(self.evaluated_at_unix_ms)
                    .max(0)
        {
            return Err(ValidationErrors::new(
                "remaining_backup_expiry_ms",
                ValidationCode::InvalidRelation,
            ));
        }
        if self.stores.len() != 3 {
            return Err(ValidationErrors::new(
                "stores",
                ValidationCode::InvalidRelation,
            ));
        }
        let mut seen = [false; 3];
        for store in &self.stores {
            store.validate()?;
            let index = match store.store {
                DeletionStoreKind::Primary => 0,
                DeletionStoreKind::Derived => 1,
                DeletionStoreKind::Backup => 2,
            };
            if seen[index] {
                return Err(ValidationErrors::new("stores", ValidationCode::Duplicate));
            }
            seen[index] = true;
        }
        let primary = self
            .stores
            .iter()
            .find(|store| store.store == DeletionStoreKind::Primary)
            .ok_or_else(|| ValidationErrors::new("stores", ValidationCode::InvalidRelation))?;
        if self.primary_completed_at_unix_ms != primary.completed_at_unix_ms {
            return Err(ValidationErrors::new(
                "primary_completed_at_unix_ms",
                ValidationCode::InvalidRelation,
            ));
        }
        let all_complete = self
            .stores
            .iter()
            .all(|store| store.state == DeletionStoreState::Completed);
        let state_valid = match self.state {
            DeletionReceiptState::Pending => !all_complete && self.completed_at_unix_ms.is_none(),
            DeletionReceiptState::Completed => {
                all_complete
                    && self.completed_at_unix_ms.is_some()
                    && self.remaining_backup_expiry_ms == 0
            }
            DeletionReceiptState::Failed => {
                self.stores
                    .iter()
                    .any(|store| store.state == DeletionStoreState::Failed)
                    && self.completed_at_unix_ms.is_none()
            }
        };
        if !state_valid {
            return Err(ValidationErrors::new(
                "state",
                ValidationCode::InvalidRelation,
            ));
        }
        if self
            .completed_at_unix_ms
            .is_some_and(|completed| completed > self.evaluated_at_unix_ms)
        {
            return Err(ValidationErrors::new(
                "completed_at_unix_ms",
                ValidationCode::InvalidRelation,
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeletionRequestResource {
    pub schema: ProtocolVersion,
    pub deletion_request_id: DeletionRequestId,
    pub scope: DeletionScope,
    pub state: DeletionRequestState,
    pub requested_at_unix_ms: i64,
    pub hide_by_unix_ms: i64,
    pub support_withdrawal_by_unix_ms: i64,
    pub primary_delete_by_unix_ms: i64,
    pub derived_rebuild_by_unix_ms: i64,
    pub backup_expiry_by_unix_ms: i64,
    pub matched_observations: u32,
    pub hidden_resources: u32,
    pub support_withdrawn_at_unix_ms: Option<i64>,
    pub primary_completed_at_unix_ms: Option<i64>,
    pub completed_at_unix_ms: Option<i64>,
}

impl Validate for DeletionRequestResource {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = Vec::new();
        if self.requested_at_unix_ms < 0
            || self.hide_by_unix_ms < self.requested_at_unix_ms
            || self.support_withdrawal_by_unix_ms < self.hide_by_unix_ms
            || self.primary_delete_by_unix_ms < self.support_withdrawal_by_unix_ms
            || self.derived_rebuild_by_unix_ms < self.primary_delete_by_unix_ms
            || self.backup_expiry_by_unix_ms < self.derived_rebuild_by_unix_ms
        {
            errors.push(("deadlines", ValidationCode::InvalidRelation));
        }
        if self.matched_observations > MAXIMUM_DELETION_MATCH_COUNT
            || self.hidden_resources > MAXIMUM_DELETION_MATCH_COUNT
            || self.hidden_resources < self.matched_observations
        {
            errors.push(("hidden_resources", ValidationCode::OutOfRange));
        }
        let support_done = self.support_withdrawn_at_unix_ms;
        let primary_done = self.primary_completed_at_unix_ms;
        let completed = self.completed_at_unix_ms;
        if support_done.is_some_and(|value| value < self.requested_at_unix_ms)
            || primary_done
                .is_some_and(|value| value < support_done.unwrap_or(self.requested_at_unix_ms))
            || completed
                .is_some_and(|value| value < primary_done.unwrap_or(self.requested_at_unix_ms))
        {
            errors.push(("completion_times", ValidationCode::InvalidRelation));
        }
        let state_valid = match self.state {
            DeletionRequestState::Hidden => {
                support_done.is_none() && primary_done.is_none() && completed.is_none()
            }
            DeletionRequestState::WithdrawingSupport | DeletionRequestState::Deleting => {
                primary_done.is_none() && completed.is_none()
            }
            DeletionRequestState::Rebuilding => {
                support_done.is_some() && primary_done.is_some() && completed.is_none()
            }
            DeletionRequestState::Completed => {
                support_done.is_some() && primary_done.is_some() && completed.is_some()
            }
            DeletionRequestState::Failed => completed.is_none(),
        };
        if !state_valid {
            errors.push(("state", ValidationCode::InvalidRelation));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            let (field, code) = errors[0];
            let mut validation = ValidationErrors::new(field, code);
            for (field, code) in errors.into_iter().skip(1) {
                validation.push(field, code);
            }
            Err(validation)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resource() -> DeletionRequestResource {
        DeletionRequestResource {
            schema: ProtocolVersion::ApiV1,
            deletion_request_id: DeletionRequestId::new("deletion_01").unwrap(),
            scope: DeletionScope::Contributor,
            state: DeletionRequestState::Hidden,
            requested_at_unix_ms: 1_000,
            hide_by_unix_ms: 301_000,
            support_withdrawal_by_unix_ms: 3_601_000,
            primary_delete_by_unix_ms: 86_401_000,
            derived_rebuild_by_unix_ms: 604_801_000,
            backup_expiry_by_unix_ms: 3_024_001_000,
            matched_observations: 2,
            hidden_resources: 4,
            support_withdrawn_at_unix_ms: None,
            primary_completed_at_unix_ms: None,
            completed_at_unix_ms: None,
        }
    }

    #[test]
    fn deletion_deadlines_and_progress_are_relational() {
        let mut request = resource();
        assert!(request.validate().is_ok());
        request.hide_by_unix_ms = 999;
        assert!(request.validate().is_err());
        request.hide_by_unix_ms = 301_000;
        request.state = DeletionRequestState::Rebuilding;
        assert!(request.validate().is_err());
        request.support_withdrawn_at_unix_ms = Some(2_000);
        request.primary_completed_at_unix_ms = Some(3_000);
        assert!(request.validate().is_ok());
    }

    #[test]
    fn deletion_wire_shape_rejects_selectors_and_unknown_fields() {
        let mut value = serde_json::to_value(resource()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("selector".to_owned(), serde_json::json!("private-target"));
        assert!(serde_json::from_value::<DeletionRequestResource>(value).is_err());
    }

    #[test]
    fn receipt_tracks_all_stores_and_remaining_backup_time() {
        let mut receipt = DeletionReceiptResource {
            schema: ProtocolVersion::ApiV1,
            deletion_request_id: DeletionRequestId::new("deletion_01").unwrap(),
            state: DeletionReceiptState::Pending,
            evaluated_at_unix_ms: 2_000,
            stores: vec![
                DeletionStoreReceipt {
                    store: DeletionStoreKind::Primary,
                    state: DeletionStoreState::Completed,
                    deadline_at_unix_ms: 1_000,
                    completed_at_unix_ms: Some(1_500),
                },
                DeletionStoreReceipt {
                    store: DeletionStoreKind::Derived,
                    state: DeletionStoreState::Completed,
                    deadline_at_unix_ms: 3_000,
                    completed_at_unix_ms: Some(1_500),
                },
                DeletionStoreReceipt {
                    store: DeletionStoreKind::Backup,
                    state: DeletionStoreState::Pending,
                    deadline_at_unix_ms: 5_000,
                    completed_at_unix_ms: None,
                },
            ],
            primary_completed_at_unix_ms: Some(1_500),
            backup_expiry_by_unix_ms: 5_000,
            remaining_backup_expiry_ms: 3_000,
            completed_at_unix_ms: None,
        };
        assert!(receipt.validate().is_ok());
        receipt.stores[2].state = DeletionStoreState::Completed;
        receipt.stores[2].completed_at_unix_ms = Some(5_000);
        receipt.state = DeletionReceiptState::Completed;
        receipt.evaluated_at_unix_ms = 5_000;
        receipt.remaining_backup_expiry_ms = 0;
        receipt.completed_at_unix_ms = Some(5_000);
        assert!(receipt.validate().is_ok());
    }
}
