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
    Remote,
    Hybrid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultSource {
    #[serde(rename = "local_probe")]
    Local,
    #[serde(rename = "local_cache")]
    Cache,
    PrivateCloud,
    SharedAssertion,
    ManagedProbe,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncPolicy {
    #[default]
    Never,
    Private,
    Shared,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SearchPolicy {
    pub source: SearchSource,
    pub sync: SyncPolicy,
    pub region_class: String,
    pub maximum_age_ms: i64,
}

impl SearchPolicy {
    pub fn validate_relation(&self) -> Result<(), SearchPolicyRelationError> {
        let valid = match self.source {
            SearchSource::Local | SearchSource::Cache => self.sync == SyncPolicy::Never,
            SearchSource::Remote => matches!(self.sync, SyncPolicy::Private | SyncPolicy::Shared),
            SearchSource::Hybrid => true,
        };
        if valid {
            Ok(())
        } else {
            Err(SearchPolicyRelationError {
                requested_source: self.source,
                sync: self.sync,
            })
        }
    }

    #[must_use]
    pub const fn uses_managed_service(&self) -> bool {
        matches!(self.source, SearchSource::Remote)
            || matches!(self.source, SearchSource::Hybrid)
                && !matches!(self.sync, SyncPolicy::Never)
    }
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
    OperationalFailure,
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
    Failed,
    NotRequested,
    Pending,
}

impl fmt::Display for SearchSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Local => "local",
            Self::Cache => "cache",
            Self::Remote => "remote",
            Self::Hybrid => "hybrid",
        })
    }
}

impl fmt::Display for ResultSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Local => "local_probe",
            Self::Cache => "local_cache",
            Self::PrivateCloud => "private_cloud",
            Self::SharedAssertion => "shared_assertion",
            Self::ManagedProbe => "managed_probe",
        })
    }
}

impl FromStr for SearchSource {
    type Err = ParseSearchPolicyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "local" => Ok(Self::Local),
            "cache" => Ok(Self::Cache),
            "remote" => Ok(Self::Remote),
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
        formatter.write_str(match self {
            Self::Never => "never",
            Self::Private => "private",
            Self::Shared => "shared",
        })
    }
}

impl FromStr for SyncPolicy {
    type Err = ParseSearchPolicyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "never" => Ok(Self::Never),
            "private" => Ok(Self::Private),
            "shared" => Ok(Self::Shared),
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
            Self::OperationalFailure => "operational_failure",
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
            Self::Failed => "failed",
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

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("source={requested_source} cannot be combined with sync={sync}")]
pub struct SearchPolicyRelationError {
    requested_source: SearchSource,
    sync: SyncPolicy,
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
        assert_eq!("remote".parse(), Ok(SearchSource::Remote));
        assert_eq!("hybrid".parse(), Ok(SearchSource::Hybrid));
        assert!("cloud".parse::<SearchSource>().is_err());
        assert_eq!("never".parse(), Ok(SyncPolicy::Never));
        assert_eq!("private".parse(), Ok(SyncPolicy::Private));
        assert_eq!("shared".parse(), Ok(SyncPolicy::Shared));
        assert!("public".parse::<SyncPolicy>().is_err());
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
        assert_eq!(
            serde_json::to_value(ResultSource::Local).unwrap(),
            serde_json::json!("local_probe")
        );
        assert_eq!(
            serde_json::to_value(ResultSource::Cache).unwrap(),
            serde_json::json!("local_cache")
        );
    }

    #[test]
    fn source_and_sync_relation_is_closed_without_implying_sync() {
        for (source, sync, valid, managed) in [
            (SearchSource::Local, SyncPolicy::Never, true, false),
            (SearchSource::Local, SyncPolicy::Private, false, false),
            (SearchSource::Cache, SyncPolicy::Shared, false, false),
            (SearchSource::Remote, SyncPolicy::Never, false, true),
            (SearchSource::Remote, SyncPolicy::Private, true, true),
            (SearchSource::Hybrid, SyncPolicy::Never, true, false),
            (SearchSource::Hybrid, SyncPolicy::Shared, true, true),
        ] {
            let policy = SearchPolicy {
                source,
                sync,
                ..SearchPolicy::default()
            };
            assert_eq!(policy.validate_relation().is_ok(), valid);
            assert_eq!(policy.uses_managed_service(), managed);
        }
    }
}
