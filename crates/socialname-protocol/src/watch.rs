use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    ConsentGrantId, NotificationEndpointId, ProtocolVersion, RegionClass, TargetSelection,
    Validate, ValidationCode, ValidationErrors, WatchId,
    common::{
        finish, validate_maximum_age, validate_nonempty_ids, validate_regions, validate_timestamp,
    },
};

const MIN_INTERVAL_SECONDS: u32 = 5 * 60;
const MAX_INTERVAL_SECONDS: u32 = 31 * 24 * 60 * 60;
const MAX_PROBES_PER_RUN: u32 = 256;
const MAX_BYTES_PER_RUN: u64 = 64 * 1_024 * 1_024;
const MIN_RETENTION_DAYS: u16 = 30;
const MAX_RETENTION_DAYS: u16 = 730;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WatchSchedule {
    pub interval_seconds: u32,
    pub jitter_percent: u8,
}

impl Validate for WatchSchedule {
    fn validate(&self) -> Result<(), ValidationErrors> {
        if (MIN_INTERVAL_SECONDS..=MAX_INTERVAL_SECONDS).contains(&self.interval_seconds)
            && self.jitter_percent <= 20
        {
            Ok(())
        } else {
            Err(ValidationErrors::new(
                "schedule",
                ValidationCode::OutOfRange,
            ))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProbeBudget {
    pub maximum_probes_per_run: u32,
    pub maximum_bytes_per_run: u64,
}

impl Validate for ProbeBudget {
    fn validate(&self) -> Result<(), ValidationErrors> {
        if (1..=MAX_PROBES_PER_RUN).contains(&self.maximum_probes_per_run)
            && (1_024..=MAX_BYTES_PER_RUN).contains(&self.maximum_bytes_per_run)
        {
            Ok(())
        } else {
            Err(ValidationErrors::new(
                "probe_budget",
                ValidationCode::OutOfRange,
            ))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WatchCreateRequest {
    pub schema: ProtocolVersion,
    pub targets: TargetSelection,
    pub region_classes: Vec<RegionClass>,
    pub maximum_age_ms: i64,
    pub schedule: WatchSchedule,
    pub probe_budget: ProbeBudget,
    pub notification_endpoint_ids: Vec<NotificationEndpointId>,
    pub private_history_consent_grant_id: ConsentGrantId,
    pub retention_days: u16,
}

impl Validate for WatchCreateRequest {
    fn validate(&self) -> Result<(), ValidationErrors> {
        collect_validations([
            self.targets.validate(),
            validate_regions(&self.region_classes),
            validate_maximum_age(self.maximum_age_ms),
            self.schedule.validate(),
            self.probe_budget.validate(),
            validate_nonempty_ids(
                "notification_endpoint_ids",
                &self.notification_endpoint_ids,
                16,
            ),
            validate_retention(self.retention_days),
        ])
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WatchState {
    Active,
    Paused,
    Deleting,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WatchStateUpdate {
    Active,
    Paused,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WatchPatchRequest {
    pub schema: ProtocolVersion,
    pub expected_revision: u64,
    pub state: Option<WatchStateUpdate>,
    pub maximum_age_ms: Option<i64>,
    pub schedule: Option<WatchSchedule>,
    pub probe_budget: Option<ProbeBudget>,
    pub notification_endpoint_ids: Option<Vec<NotificationEndpointId>>,
    pub retention_days: Option<u16>,
}

impl Validate for WatchPatchRequest {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut validations = Vec::new();
        if self.expected_revision == 0 {
            validations.push(Err(ValidationErrors::new(
                "expected_revision",
                ValidationCode::OutOfRange,
            )));
        }
        if self.state.is_none()
            && self.maximum_age_ms.is_none()
            && self.schedule.is_none()
            && self.probe_budget.is_none()
            && self.notification_endpoint_ids.is_none()
            && self.retention_days.is_none()
        {
            validations.push(Err(ValidationErrors::new("patch", ValidationCode::Empty)));
        }
        if let Some(maximum_age_ms) = self.maximum_age_ms {
            validations.push(validate_maximum_age(maximum_age_ms));
        }
        if let Some(schedule) = &self.schedule {
            validations.push(schedule.validate());
        }
        if let Some(probe_budget) = &self.probe_budget {
            validations.push(probe_budget.validate());
        }
        if let Some(endpoint_ids) = &self.notification_endpoint_ids {
            validations.push(validate_nonempty_ids(
                "notification_endpoint_ids",
                endpoint_ids,
                16,
            ));
        }
        if let Some(retention_days) = self.retention_days {
            validations.push(validate_retention(retention_days));
        }
        collect_validations(validations)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WatchResource {
    pub schema: ProtocolVersion,
    pub watch_id: WatchId,
    pub state: WatchState,
    pub revision: u64,
    pub configuration: WatchCreateRequest,
    pub created_at_unix_ms: i64,
    pub updated_at_unix_ms: i64,
    pub next_run_at_unix_ms: Option<i64>,
}

impl Validate for WatchResource {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut validations = vec![
            self.configuration.validate(),
            validate_timestamp("created_at_unix_ms", self.created_at_unix_ms),
            validate_timestamp("updated_at_unix_ms", self.updated_at_unix_ms),
        ];
        if self.revision == 0 {
            validations.push(Err(ValidationErrors::new(
                "revision",
                ValidationCode::OutOfRange,
            )));
        }
        if self.updated_at_unix_ms < self.created_at_unix_ms {
            validations.push(Err(ValidationErrors::new(
                "updated_at_unix_ms",
                ValidationCode::InvalidRelation,
            )));
        }
        match (self.state, self.next_run_at_unix_ms) {
            (WatchState::Active, Some(next_run_at)) => {
                validations.push(validate_timestamp("next_run_at_unix_ms", next_run_at));
                if next_run_at <= self.updated_at_unix_ms {
                    validations.push(Err(ValidationErrors::new(
                        "next_run_at_unix_ms",
                        ValidationCode::InvalidRelation,
                    )));
                }
            }
            (WatchState::Paused | WatchState::Deleting, None) => {}
            _ => validations.push(Err(ValidationErrors::new(
                "next_run_at_unix_ms",
                ValidationCode::InvalidRelation,
            ))),
        }
        collect_validations(validations)
    }
}

fn validate_retention(retention_days: u16) -> Result<(), ValidationErrors> {
    if (MIN_RETENTION_DAYS..=MAX_RETENTION_DAYS).contains(&retention_days) {
        Ok(())
    } else {
        Err(ValidationErrors::new(
            "retention_days",
            ValidationCode::OutOfRange,
        ))
    }
}

fn collect_validations(
    validations: impl IntoIterator<Item = Result<(), ValidationErrors>>,
) -> Result<(), ValidationErrors> {
    let mut issues = Vec::new();
    for result in validations {
        if let Err(errors) = result {
            issues.extend(errors.into_issues());
        }
    }
    finish(issues)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NotificationEndpointId, SiteId, Username};

    fn create_request() -> WatchCreateRequest {
        WatchCreateRequest {
            schema: ProtocolVersion::ApiV1,
            targets: TargetSelection {
                usernames: vec![Username::new("alice").unwrap()],
                site_ids: vec![SiteId::new("github").unwrap()],
            },
            region_classes: vec![RegionClass::new("jp").unwrap()],
            maximum_age_ms: 3_600_000,
            schedule: WatchSchedule {
                interval_seconds: 3_600,
                jitter_percent: 10,
            },
            probe_budget: ProbeBudget {
                maximum_probes_per_run: 10,
                maximum_bytes_per_run: 1_048_576,
            },
            notification_endpoint_ids: vec![NotificationEndpointId::new("endpoint_01").unwrap()],
            private_history_consent_grant_id: ConsentGrantId::new("grant_01").unwrap(),
            retention_days: 400,
        }
    }

    #[test]
    fn watch_schedule_budget_and_retention_are_bounded() {
        let mut request = create_request();
        assert!(request.validate().is_ok());

        request.schedule.interval_seconds = 1;
        request.probe_budget.maximum_probes_per_run = u32::MAX;
        request.retention_days = u16::MAX;
        assert!(request.validate().is_err());
    }

    #[test]
    fn empty_patch_and_empty_endpoint_replacement_are_rejected() {
        let mut patch = WatchPatchRequest {
            schema: ProtocolVersion::ApiV1,
            expected_revision: 1,
            state: None,
            maximum_age_ms: None,
            schedule: None,
            probe_budget: None,
            notification_endpoint_ids: None,
            retention_days: None,
        };
        assert!(patch.validate().is_err());

        patch.notification_endpoint_ids = Some(Vec::new());
        assert!(patch.validate().is_err());
    }

    #[test]
    fn active_and_paused_watches_have_distinct_next_run_contracts() {
        let mut resource = WatchResource {
            schema: ProtocolVersion::ApiV1,
            watch_id: WatchId::new("watch_01").unwrap(),
            state: WatchState::Active,
            revision: 1,
            configuration: create_request(),
            created_at_unix_ms: 1_000,
            updated_at_unix_ms: 2_000,
            next_run_at_unix_ms: Some(3_000),
        };
        assert!(resource.validate().is_ok());

        resource.state = WatchState::Paused;
        assert!(resource.validate().is_err());
        resource.next_run_at_unix_ms = None;
        assert!(resource.validate().is_ok());
    }
}
