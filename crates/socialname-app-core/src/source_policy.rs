use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use socialname_domain::RuleHealth;

pub const DEFAULT_MAXIMUM_AGE_MS: i64 = 24 * 60 * 60 * 1_000;
pub const DEFAULT_REGION_CLASS: &str = "local";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchSource {
    #[default]
    Local,
    Cache,
    Hybrid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultSource {
    Local,
    Cache,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncPolicy {
    #[default]
    Never,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SearchPolicy {
    pub source: SearchSource,
    pub sync: SyncPolicy,
    pub region_class: String,
    pub maximum_age_ms: i64,
}

impl Default for SearchPolicy {
    fn default() -> Self {
        Self {
            source: SearchSource::Local,
            sync: SyncPolicy::Never,
            region_class: DEFAULT_REGION_CLASS.to_owned(),
            maximum_age_ms: DEFAULT_MAXIMUM_AGE_MS,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SearchRuleHealth {
    pub state: RuleHealth,
    pub evidence_expires_at_unix_ms: Option<i64>,
}

impl SearchRuleHealth {
    #[must_use]
    pub fn is_fresh_healthy_at(self, now_unix_ms: i64) -> bool {
        self.state == RuleHealth::Healthy
            && self
                .evidence_expires_at_unix_ms
                .is_some_and(|expires_at| expires_at > now_unix_ms)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchStatus {
    Complete,
    CacheMiss,
    CacheUnavailable,
    InvalidUsername,
    RuleNotPromoted,
    RuleHealthUnavailable,
    RuleNotHealthy,
    RuleHealthStale,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RefreshState {
    Completed,
    NotRequested,
    Pending,
}

impl fmt::Display for SearchSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Local => "local",
            Self::Cache => "cache",
            Self::Hybrid => "hybrid",
        })
    }
}

impl FromStr for SearchSource {
    type Err = ParseSearchPolicyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "local" => Ok(Self::Local),
            "cache" => Ok(Self::Cache),
            "hybrid" => Ok(Self::Hybrid),
            _ => Err(ParseSearchPolicyError {
                field: "source",
                value: value.to_owned(),
            }),
        }
    }
}

impl fmt::Display for SyncPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("never")
    }
}

impl FromStr for SyncPolicy {
    type Err = ParseSearchPolicyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "never" => Ok(Self::Never),
            _ => Err(ParseSearchPolicyError {
                field: "sync",
                value: value.to_owned(),
            }),
        }
    }
}

impl fmt::Display for SearchStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Complete => "complete",
            Self::CacheMiss => "cache_miss",
            Self::CacheUnavailable => "cache_unavailable",
            Self::InvalidUsername => "invalid_username",
            Self::RuleNotPromoted => "rule_not_promoted",
            Self::RuleHealthUnavailable => "rule_health_unavailable",
            Self::RuleNotHealthy => "rule_not_healthy",
            Self::RuleHealthStale => "rule_health_stale",
        })
    }
}

impl fmt::Display for RefreshState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Completed => "completed",
            Self::NotRequested => "not_requested",
            Self::Pending => "pending",
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("unsupported {field} value {value:?}")]
pub struct ParseSearchPolicyError {
    field: &'static str,
    value: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_local_and_never_synchronized() {
        assert_eq!(
            SearchPolicy::default(),
            SearchPolicy {
                source: SearchSource::Local,
                sync: SyncPolicy::Never,
                region_class: "local".to_owned(),
                maximum_age_ms: 86_400_000,
            }
        );
    }

    #[test]
    fn source_and_sync_parsers_are_closed() {
        assert_eq!("local".parse(), Ok(SearchSource::Local));
        assert_eq!("cache".parse(), Ok(SearchSource::Cache));
        assert_eq!("hybrid".parse(), Ok(SearchSource::Hybrid));
        assert!("cloud".parse::<SearchSource>().is_err());
        assert_eq!("never".parse(), Ok(SyncPolicy::Never));
        assert!("private".parse::<SyncPolicy>().is_err());
    }

    #[test]
    fn policy_json_uses_the_shared_ipc_shape() {
        let policy = serde_json::to_value(SearchPolicy::default()).unwrap();
        assert_eq!(
            policy,
            serde_json::json!({
                "source": "local",
                "sync": "never",
                "regionClass": "local",
                "maximumAgeMs": 86_400_000
            })
        );
    }
}
