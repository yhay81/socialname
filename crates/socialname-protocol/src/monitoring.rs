use std::collections::HashSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    NotificationDelivery, ProtocolVersion, Transition, TransitionId, Validate, ValidationCode,
    ValidationErrors, WatchId, WatchResource,
};

pub const MAX_MONITORING_PAGE_ITEMS: usize = 50;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WatchListPage {
    pub schema: ProtocolVersion,
    pub watches: Vec<WatchResource>,
    pub next_cursor: Option<WatchId>,
}

impl Validate for WatchListPage {
    fn validate(&self) -> Result<(), ValidationErrors> {
        if self.watches.len() > MAX_MONITORING_PAGE_ITEMS {
            return Err(ValidationErrors::new(
                "watches",
                ValidationCode::TooManyItems,
            ));
        }
        let mut ids = HashSet::with_capacity(self.watches.len());
        for watch in &self.watches {
            watch.validate()?;
            if !ids.insert(watch.watch_id.as_str()) {
                return Err(ValidationErrors::new("watches", ValidationCode::Duplicate));
            }
        }
        if self.next_cursor.as_ref() != self.watches.last().map(|watch| &watch.watch_id)
            && self.next_cursor.is_some()
        {
            return Err(ValidationErrors::new(
                "next_cursor",
                ValidationCode::InvalidRelation,
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WatchTransitionEntry {
    pub transition: Transition,
    pub deliveries: Vec<NotificationDelivery>,
}

impl Validate for WatchTransitionEntry {
    fn validate(&self) -> Result<(), ValidationErrors> {
        self.transition.validate()?;
        if self.deliveries.len() > 16 {
            return Err(ValidationErrors::new(
                "deliveries",
                ValidationCode::TooManyItems,
            ));
        }
        let mut ids = HashSet::with_capacity(self.deliveries.len());
        for delivery in &self.deliveries {
            delivery.validate()?;
            if delivery.transition_id != self.transition.transition_id
                || !self.transition.confirmation.permits_delivery()
            {
                return Err(ValidationErrors::new(
                    "deliveries",
                    ValidationCode::InvalidRelation,
                ));
            }
            if !ids.insert(delivery.delivery_id.as_str()) {
                return Err(ValidationErrors::new(
                    "deliveries",
                    ValidationCode::Duplicate,
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WatchTransitionPage {
    pub schema: ProtocolVersion,
    pub watch_id: WatchId,
    pub entries: Vec<WatchTransitionEntry>,
    pub next_cursor: Option<TransitionId>,
}

impl Validate for WatchTransitionPage {
    fn validate(&self) -> Result<(), ValidationErrors> {
        if self.entries.len() > MAX_MONITORING_PAGE_ITEMS {
            return Err(ValidationErrors::new(
                "entries",
                ValidationCode::TooManyItems,
            ));
        }
        let mut ids = HashSet::with_capacity(self.entries.len());
        for entry in &self.entries {
            entry.validate()?;
            if entry.transition.watch_id != self.watch_id {
                return Err(ValidationErrors::new(
                    "entries",
                    ValidationCode::InvalidRelation,
                ));
            }
            if !ids.insert(entry.transition.transition_id.as_str()) {
                return Err(ValidationErrors::new("entries", ValidationCode::Duplicate));
            }
        }
        if self.next_cursor.as_ref()
            != self
                .entries
                .last()
                .map(|entry| &entry.transition.transition_id)
            && self.next_cursor.is_some()
        {
            return Err(ValidationErrors::new(
                "next_cursor",
                ValidationCode::InvalidRelation,
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AccountState, ConfirmationBasis, ConsentGrantId, NotificationEndpointId, ObservationId,
        ProbeBudget, RegionClass, SiteId, Target, TargetSelection, TransitionChange,
        TransitionConfirmation, Username, WatchCreateRequest, WatchSchedule, WatchState,
    };

    fn watch(id: &str) -> WatchResource {
        WatchResource {
            schema: ProtocolVersion::ApiV1,
            watch_id: WatchId::new(id).unwrap(),
            state: WatchState::Active,
            revision: 1,
            configuration: WatchCreateRequest {
                schema: ProtocolVersion::ApiV1,
                targets: TargetSelection {
                    usernames: vec![Username::new("alice").unwrap()],
                    site_ids: vec![SiteId::new("github").unwrap()],
                },
                region_classes: vec![RegionClass::new("jp").unwrap()],
                maximum_age_ms: 60_000,
                schedule: WatchSchedule {
                    interval_seconds: 300,
                    jitter_percent: 0,
                },
                probe_budget: ProbeBudget {
                    maximum_probes_per_run: 1,
                    maximum_bytes_per_run: 1_024,
                },
                notification_endpoint_ids: vec![
                    NotificationEndpointId::new("endpoint_01").unwrap(),
                ],
                private_history_consent_grant_id: ConsentGrantId::new("grant_01").unwrap(),
                retention_days: 30,
            },
            created_at_unix_ms: 1_000,
            updated_at_unix_ms: 1_000,
            next_run_at_unix_ms: Some(301_000),
        }
    }

    fn transition(id: &str, watch_id: &str) -> Transition {
        Transition {
            schema: ProtocolVersion::ApiV1,
            transition_id: TransitionId::new(id).unwrap(),
            watch_id: WatchId::new(watch_id).unwrap(),
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
    fn page_cursor_must_match_the_last_returned_resource() {
        let page = WatchListPage {
            schema: ProtocolVersion::ApiV1,
            watches: vec![watch("watch_01")],
            next_cursor: Some(WatchId::new("watch_01").unwrap()),
        };
        assert!(page.validate().is_ok());

        let mut invalid = page;
        invalid.next_cursor = Some(WatchId::new("watch_02").unwrap());
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn transition_page_binds_watch_and_delivery_relations() {
        let page = WatchTransitionPage {
            schema: ProtocolVersion::ApiV1,
            watch_id: WatchId::new("watch_01").unwrap(),
            entries: vec![WatchTransitionEntry {
                transition: transition("transition_01", "watch_01"),
                deliveries: Vec::new(),
            }],
            next_cursor: Some(TransitionId::new("transition_01").unwrap()),
        };
        assert!(page.validate().is_ok());

        let mut invalid = page;
        invalid.entries[0].transition.watch_id = WatchId::new("watch_02").unwrap();
        assert!(invalid.validate().is_err());
    }
}
