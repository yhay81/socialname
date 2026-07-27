use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{LatencySlo, ProtocolVersion, RatioSlo, Validate, ValidationCode, ValidationErrors};

pub const DEVELOPER_SEARCH_SUCCESS_TARGET_BASIS_POINTS: u16 = 9_900;
pub const DEVELOPER_FIRST_RESULT_P95_TARGET_MS: u64 = 30_000;
pub const DEVELOPER_TERMINAL_P95_TARGET_MS: u64 = 300_000;

const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;
const UTC_DAY_MS: i64 = 24 * 60 * 60 * 1_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum DeveloperReportWindow {
    #[serde(rename = "24h")]
    Last24Hours,
    #[serde(rename = "7d")]
    Last7Days,
    #[serde(rename = "30d")]
    Last30Days,
}

impl DeveloperReportWindow {
    #[must_use]
    pub const fn duration_ms(self) -> i64 {
        match self {
            Self::Last24Hours => UTC_DAY_MS,
            Self::Last7Days => 7 * UTC_DAY_MS,
            Self::Last30Days => 30 * UTC_DAY_MS,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeveloperQuotaCounter {
    pub limit: u64,
    pub used: u64,
    pub remaining: u64,
}

impl DeveloperQuotaCounter {
    fn validate(&self) -> Result<(), ValidationErrors> {
        if self.limit == 0
            || self.limit > MAX_SAFE_JSON_INTEGER
            || self.used > self.limit
            || self.remaining != self.limit - self.used
        {
            Err(ValidationErrors::new(
                "quota",
                ValidationCode::InvalidRelation,
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeveloperQuotaSnapshot {
    pub period_started_at_unix_ms: i64,
    pub resets_at_unix_ms: i64,
    pub tenant: DeveloperQuotaCounter,
    pub api_key: DeveloperQuotaCounter,
}

impl DeveloperQuotaSnapshot {
    fn validate(&self, generated_at_unix_ms: i64) -> Result<(), ValidationErrors> {
        if self.period_started_at_unix_ms <= 0
            || self.resets_at_unix_ms - self.period_started_at_unix_ms != UTC_DAY_MS
            || generated_at_unix_ms < self.period_started_at_unix_ms
            || generated_at_unix_ms >= self.resets_at_unix_ms
        {
            return Err(ValidationErrors::new(
                "quota.period",
                ValidationCode::InvalidRelation,
            ));
        }
        self.tenant.validate()?;
        self.api_key.validate()?;
        if self.api_key.limit > self.tenant.limit {
            return Err(ValidationErrors::new(
                "quota.api_key.limit",
                ValidationCode::InvalidRelation,
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeveloperUsageSummary {
    pub admitted_searches: u64,
    pub admitted_target_pairs: u64,
}

impl DeveloperUsageSummary {
    fn validate(&self) -> Result<(), ValidationErrors> {
        if self.admitted_searches > MAX_SAFE_JSON_INTEGER
            || self.admitted_target_pairs > MAX_SAFE_JSON_INTEGER
            || self.admitted_searches > self.admitted_target_pairs
        {
            Err(ValidationErrors::new(
                "usage",
                ValidationCode::InvalidRelation,
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeveloperSearchBacklog {
    pub accepted_searches: u64,
    pub running_searches: u64,
    pub active_searches_without_result: u64,
    pub oldest_active_search_age_ms: Option<u64>,
}

impl DeveloperSearchBacklog {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let active_searches = self
            .accepted_searches
            .checked_add(self.running_searches)
            .ok_or_else(|| ValidationErrors::new("backlog", ValidationCode::InvalidRelation))?;
        if active_searches > MAX_SAFE_JSON_INTEGER
            || self.active_searches_without_result > active_searches
            || self
                .oldest_active_search_age_ms
                .is_some_and(|value| value > MAX_SAFE_JSON_INTEGER)
            || (active_searches == 0) != self.oldest_active_search_age_ms.is_none()
        {
            Err(ValidationErrors::new(
                "backlog",
                ValidationCode::InvalidRelation,
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeveloperServiceObjectives {
    pub terminal_search_success: RatioSlo,
    pub first_result_latency: LatencySlo,
    pub terminal_latency: LatencySlo,
}

impl DeveloperServiceObjectives {
    fn validate(&self) -> Result<(), ValidationErrors> {
        self.terminal_search_success
            .validate_for(DEVELOPER_SEARCH_SUCCESS_TARGET_BASIS_POINTS)?;
        self.first_result_latency
            .validate_for(DEVELOPER_FIRST_RESULT_P95_TARGET_MS)?;
        self.terminal_latency
            .validate_for(DEVELOPER_TERMINAL_P95_TARGET_MS)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeveloperReportResource {
    pub schema: ProtocolVersion,
    pub window: DeveloperReportWindow,
    pub generated_at_unix_ms: i64,
    pub window_started_at_unix_ms: i64,
    pub quota: DeveloperQuotaSnapshot,
    pub usage: DeveloperUsageSummary,
    pub backlog: DeveloperSearchBacklog,
    pub objectives: DeveloperServiceObjectives,
}

impl Validate for DeveloperReportResource {
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
        self.quota.validate(self.generated_at_unix_ms)?;
        self.usage.validate()?;
        self.backlog.validate()?;
        self.objectives.validate()
    }
}

#[cfg(test)]
mod tests {
    use crate::SloStatus;

    use super::*;

    fn report() -> DeveloperReportResource {
        DeveloperReportResource {
            schema: ProtocolVersion::ApiV1,
            window: DeveloperReportWindow::Last24Hours,
            generated_at_unix_ms: 172_800_001,
            window_started_at_unix_ms: 86_400_001,
            quota: DeveloperQuotaSnapshot {
                period_started_at_unix_ms: 172_800_000,
                resets_at_unix_ms: 259_200_000,
                tenant: DeveloperQuotaCounter {
                    limit: 10_000,
                    used: 250,
                    remaining: 9_750,
                },
                api_key: DeveloperQuotaCounter {
                    limit: 2_000,
                    used: 100,
                    remaining: 1_900,
                },
            },
            usage: DeveloperUsageSummary {
                admitted_searches: 2,
                admitted_target_pairs: 100,
            },
            backlog: DeveloperSearchBacklog {
                accepted_searches: 1,
                running_searches: 0,
                active_searches_without_result: 1,
                oldest_active_search_age_ms: Some(1_000),
            },
            objectives: DeveloperServiceObjectives {
                terminal_search_success: RatioSlo::from_counts(
                    99,
                    100,
                    DEVELOPER_SEARCH_SUCCESS_TARGET_BASIS_POINTS,
                ),
                first_result_latency: LatencySlo::from_samples(
                    2,
                    Some(15_000),
                    DEVELOPER_FIRST_RESULT_P95_TARGET_MS,
                ),
                terminal_latency: LatencySlo::from_samples(
                    0,
                    None,
                    DEVELOPER_TERMINAL_P95_TARGET_MS,
                ),
            },
        }
    }

    #[test]
    fn developer_report_keeps_quota_usage_backlog_and_no_data_distinct() {
        let report = report();
        assert!(report.validate().is_ok());
        assert_eq!(report.objectives.terminal_latency.status, SloStatus::NoData);
    }

    #[test]
    fn developer_report_rejects_relabelled_or_impossible_arithmetic() {
        let mut report = report();
        report.quota.api_key.remaining += 1;
        report.objectives.terminal_search_success.status = SloStatus::Breached;
        assert!(report.validate().is_err());
    }

    #[test]
    fn developer_report_rejects_hidden_active_backlog_or_changed_targets() {
        let mut report = report();
        report.backlog.oldest_active_search_age_ms = None;
        report.objectives.first_result_latency.target_ms += 1;
        assert!(report.validate().is_err());
    }
}
