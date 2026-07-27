use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{ProtocolVersion, Validate, ValidationCode, ValidationErrors};

pub const WATCH_RUN_SUCCESS_TARGET_BASIS_POINTS: u16 = 9_900;
pub const DELIVERY_SUCCESS_TARGET_BASIS_POINTS: u16 = 9_900;
pub const TRANSITION_TO_DELIVERY_P95_TARGET_MS: u64 = 300_000;
pub const DELETION_MAX_OVERDUE_MILESTONES: u64 = 0;

const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum OperationalReportWindow {
    #[serde(rename = "24h")]
    Last24Hours,
    #[serde(rename = "7d")]
    Last7Days,
    #[serde(rename = "30d")]
    Last30Days,
}

impl OperationalReportWindow {
    #[must_use]
    pub const fn duration_ms(self) -> i64 {
        match self {
            Self::Last24Hours => 24 * 60 * 60 * 1_000,
            Self::Last7Days => 7 * 24 * 60 * 60 * 1_000,
            Self::Last30Days => 30 * 24 * 60 * 60 * 1_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SloStatus {
    NoData,
    Meeting,
    Breached,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RatioSlo {
    pub status: SloStatus,
    pub good_events: u64,
    pub total_events: u64,
    pub target_basis_points: u16,
}

impl RatioSlo {
    #[must_use]
    pub fn from_counts(good_events: u64, total_events: u64, target_basis_points: u16) -> Self {
        let status = if total_events == 0 {
            SloStatus::NoData
        } else if u128::from(good_events) * 10_000
            >= u128::from(total_events) * u128::from(target_basis_points)
        {
            SloStatus::Meeting
        } else {
            SloStatus::Breached
        };
        Self {
            status,
            good_events,
            total_events,
            target_basis_points,
        }
    }

    fn validate_for(&self, expected_target: u16) -> Result<(), ValidationErrors> {
        if self.good_events > MAX_SAFE_JSON_INTEGER
            || self.total_events > MAX_SAFE_JSON_INTEGER
            || self.good_events > self.total_events
            || self.target_basis_points != expected_target
        {
            return Err(ValidationErrors::new(
                "objectives",
                ValidationCode::InvalidRelation,
            ));
        }
        let expected = Self::from_counts(
            self.good_events,
            self.total_events,
            self.target_basis_points,
        )
        .status;
        if self.status != expected {
            return Err(ValidationErrors::new(
                "objectives",
                ValidationCode::InvalidRelation,
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LatencySlo {
    pub status: SloStatus,
    pub samples: u64,
    pub p95_ms: Option<u64>,
    pub target_ms: u64,
}

impl LatencySlo {
    #[must_use]
    pub fn from_samples(samples: u64, p95_ms: Option<u64>, target_ms: u64) -> Self {
        let status = match p95_ms {
            None => SloStatus::NoData,
            Some(p95_ms) if p95_ms <= target_ms => SloStatus::Meeting,
            Some(_) => SloStatus::Breached,
        };
        Self {
            status,
            samples,
            p95_ms,
            target_ms,
        }
    }

    fn validate_for(&self, expected_target: u64) -> Result<(), ValidationErrors> {
        if self.samples > MAX_SAFE_JSON_INTEGER
            || self
                .p95_ms
                .is_some_and(|value| value > MAX_SAFE_JSON_INTEGER)
            || self.target_ms != expected_target
            || (self.samples == 0) != self.p95_ms.is_none()
        {
            return Err(ValidationErrors::new(
                "objectives",
                ValidationCode::InvalidRelation,
            ));
        }
        let expected = Self::from_samples(self.samples, self.p95_ms, self.target_ms).status;
        if self.status != expected {
            return Err(ValidationErrors::new(
                "objectives",
                ValidationCode::InvalidRelation,
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeletionOverdueMilestones {
    pub hide: u64,
    pub support_withdrawal: u64,
    pub primary_delete: u64,
    pub derived_rebuild: u64,
    pub backup_expiry: u64,
}

impl DeletionOverdueMilestones {
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.hide
            .saturating_add(self.support_withdrawal)
            .saturating_add(self.primary_delete)
            .saturating_add(self.derived_rebuild)
            .saturating_add(self.backup_expiry)
    }

    fn validate(&self) -> Result<(), ValidationErrors> {
        if [
            self.hide,
            self.support_withdrawal,
            self.primary_delete,
            self.derived_rebuild,
            self.backup_expiry,
        ]
        .into_iter()
        .any(|value| value > MAX_SAFE_JSON_INTEGER)
        {
            return Err(ValidationErrors::new(
                "objectives.deletion_deadline_health.overdue",
                ValidationCode::OutOfRange,
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeletionDeadlineSlo {
    pub status: SloStatus,
    pub open_requests: u64,
    pub failed_requests: u64,
    pub overdue: DeletionOverdueMilestones,
    pub target_max_overdue_milestones: u64,
}

impl DeletionDeadlineSlo {
    #[must_use]
    pub fn from_counts(
        open_requests: u64,
        failed_requests: u64,
        overdue: DeletionOverdueMilestones,
    ) -> Self {
        let status = if open_requests == 0 {
            SloStatus::NoData
        } else if failed_requests == 0 && overdue.total() == 0 {
            SloStatus::Meeting
        } else {
            SloStatus::Breached
        };
        Self {
            status,
            open_requests,
            failed_requests,
            overdue,
            target_max_overdue_milestones: DELETION_MAX_OVERDUE_MILESTONES,
        }
    }

    fn validate(&self) -> Result<(), ValidationErrors> {
        self.overdue.validate()?;
        if self.open_requests > MAX_SAFE_JSON_INTEGER
            || self.failed_requests > self.open_requests
            || self.target_max_overdue_milestones != DELETION_MAX_OVERDUE_MILESTONES
            || (self.open_requests == 0 && (self.failed_requests != 0 || self.overdue.total() != 0))
        {
            return Err(ValidationErrors::new(
                "objectives.deletion_deadline_health",
                ValidationCode::InvalidRelation,
            ));
        }
        let expected = Self::from_counts(
            self.open_requests,
            self.failed_requests,
            self.overdue.clone(),
        )
        .status;
        if self.status != expected {
            return Err(ValidationErrors::new(
                "objectives.deletion_deadline_health",
                ValidationCode::InvalidRelation,
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChannelSlo<T> {
    pub email: T,
    pub webhook: T,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperationalObjectives {
    pub watch_run_success: RatioSlo,
    pub delivery_success: ChannelSlo<RatioSlo>,
    pub transition_to_delivery_latency: ChannelSlo<LatencySlo>,
    pub deletion_deadline_health: DeletionDeadlineSlo,
}

impl OperationalObjectives {
    fn validate(&self) -> Result<(), ValidationErrors> {
        self.watch_run_success
            .validate_for(WATCH_RUN_SUCCESS_TARGET_BASIS_POINTS)?;
        self.delivery_success
            .email
            .validate_for(DELIVERY_SUCCESS_TARGET_BASIS_POINTS)?;
        self.delivery_success
            .webhook
            .validate_for(DELIVERY_SUCCESS_TARGET_BASIS_POINTS)?;
        self.transition_to_delivery_latency
            .email
            .validate_for(TRANSITION_TO_DELIVERY_P95_TARGET_MS)?;
        self.transition_to_delivery_latency
            .webhook
            .validate_for(TRANSITION_TO_DELIVERY_P95_TARGET_MS)?;
        self.deletion_deadline_health.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperationalBacklog {
    pub active_watches: u64,
    pub paused_watches: u64,
    pub deleting_watches: u64,
    pub planned_watch_runs: u64,
    pub running_watch_runs: u64,
    pub queued_probe_jobs: u64,
    pub leased_probe_jobs: u64,
    pub retry_wait_probe_jobs: u64,
    pub oldest_pending_probe_job_age_ms: Option<u64>,
    pub queued_email_deliveries: u64,
    pub delivering_email_deliveries: u64,
    pub retry_scheduled_email_deliveries: u64,
    pub queued_webhook_deliveries: u64,
    pub delivering_webhook_deliveries: u64,
    pub retry_scheduled_webhook_deliveries: u64,
    pub oldest_pending_delivery_age_ms: Option<u64>,
}

impl OperationalBacklog {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let counts = [
            self.active_watches,
            self.paused_watches,
            self.deleting_watches,
            self.planned_watch_runs,
            self.running_watch_runs,
            self.queued_probe_jobs,
            self.leased_probe_jobs,
            self.retry_wait_probe_jobs,
            self.queued_email_deliveries,
            self.delivering_email_deliveries,
            self.retry_scheduled_email_deliveries,
            self.queued_webhook_deliveries,
            self.delivering_webhook_deliveries,
            self.retry_scheduled_webhook_deliveries,
        ];
        if counts
            .into_iter()
            .any(|value| value > MAX_SAFE_JSON_INTEGER)
            || self
                .oldest_pending_probe_job_age_ms
                .is_some_and(|value| value > MAX_SAFE_JSON_INTEGER)
            || self
                .oldest_pending_delivery_age_ms
                .is_some_and(|value| value > MAX_SAFE_JSON_INTEGER)
        {
            return Err(ValidationErrors::new("backlog", ValidationCode::OutOfRange));
        }
        let has_probe_backlog =
            self.queued_probe_jobs + self.leased_probe_jobs + self.retry_wait_probe_jobs > 0;
        let has_delivery_backlog = self.queued_email_deliveries
            + self.delivering_email_deliveries
            + self.retry_scheduled_email_deliveries
            + self.queued_webhook_deliveries
            + self.delivering_webhook_deliveries
            + self.retry_scheduled_webhook_deliveries
            > 0;
        if has_probe_backlog != self.oldest_pending_probe_job_age_ms.is_some()
            || has_delivery_backlog != self.oldest_pending_delivery_age_ms.is_some()
        {
            return Err(ValidationErrors::new(
                "backlog",
                ValidationCode::InvalidRelation,
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperationalReportResource {
    pub schema: ProtocolVersion,
    pub window: OperationalReportWindow,
    pub generated_at_unix_ms: i64,
    pub window_started_at_unix_ms: i64,
    pub backlog: OperationalBacklog,
    pub objectives: OperationalObjectives,
}

impl Validate for OperationalReportResource {
    fn validate(&self) -> Result<(), ValidationErrors> {
        if self.window_started_at_unix_ms <= 0
            || self.generated_at_unix_ms <= self.window_started_at_unix_ms
            || self.generated_at_unix_ms - self.window_started_at_unix_ms
                != self.window.duration_ms()
        {
            return Err(ValidationErrors::new(
                "window_started_at_unix_ms",
                ValidationCode::InvalidRelation,
            ));
        }
        self.backlog.validate()?;
        self.objectives.validate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> OperationalReportResource {
        OperationalReportResource {
            schema: ProtocolVersion::ApiV1,
            window: OperationalReportWindow::Last24Hours,
            generated_at_unix_ms: 100_000_000,
            window_started_at_unix_ms: 13_600_000,
            backlog: OperationalBacklog {
                active_watches: 2,
                paused_watches: 1,
                deleting_watches: 0,
                planned_watch_runs: 1,
                running_watch_runs: 0,
                queued_probe_jobs: 1,
                leased_probe_jobs: 0,
                retry_wait_probe_jobs: 0,
                oldest_pending_probe_job_age_ms: Some(1_000),
                queued_email_deliveries: 0,
                delivering_email_deliveries: 0,
                retry_scheduled_email_deliveries: 0,
                queued_webhook_deliveries: 0,
                delivering_webhook_deliveries: 0,
                retry_scheduled_webhook_deliveries: 0,
                oldest_pending_delivery_age_ms: None,
            },
            objectives: OperationalObjectives {
                watch_run_success: RatioSlo::from_counts(
                    99,
                    100,
                    WATCH_RUN_SUCCESS_TARGET_BASIS_POINTS,
                ),
                delivery_success: ChannelSlo {
                    email: RatioSlo::from_counts(1, 1, DELIVERY_SUCCESS_TARGET_BASIS_POINTS),
                    webhook: RatioSlo::from_counts(0, 0, DELIVERY_SUCCESS_TARGET_BASIS_POINTS),
                },
                transition_to_delivery_latency: ChannelSlo {
                    email: LatencySlo::from_samples(
                        1,
                        Some(250_000),
                        TRANSITION_TO_DELIVERY_P95_TARGET_MS,
                    ),
                    webhook: LatencySlo::from_samples(
                        0,
                        None,
                        TRANSITION_TO_DELIVERY_P95_TARGET_MS,
                    ),
                },
                deletion_deadline_health: DeletionDeadlineSlo::from_counts(
                    0,
                    0,
                    DeletionOverdueMilestones::default(),
                ),
            },
        }
    }

    #[test]
    fn report_keeps_no_data_distinct_from_success() {
        let report = report();
        assert!(report.validate().is_ok());
        assert_eq!(
            report.objectives.delivery_success.webhook.status,
            SloStatus::NoData
        );
        assert_eq!(
            report
                .objectives
                .transition_to_delivery_latency
                .webhook
                .status,
            SloStatus::NoData
        );
    }

    #[test]
    fn report_rejects_relabelled_status_and_inconsistent_backlog_age() {
        let mut relabelled = report();
        relabelled.objectives.watch_run_success.status = SloStatus::Breached;
        assert!(relabelled.validate().is_err());

        let mut missing_age = report();
        missing_age.backlog.oldest_pending_probe_job_age_ms = None;
        assert!(missing_age.validate().is_err());
    }

    #[test]
    fn deletion_health_breaches_on_failure_or_overdue_milestone() {
        let overdue = DeletionDeadlineSlo::from_counts(
            1,
            0,
            DeletionOverdueMilestones {
                primary_delete: 1,
                ..DeletionOverdueMilestones::default()
            },
        );
        assert_eq!(overdue.status, SloStatus::Breached);
        assert!(overdue.validate().is_ok());
    }
}
