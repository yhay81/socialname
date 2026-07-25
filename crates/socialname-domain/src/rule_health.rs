use serde::{Deserialize, Serialize};

use crate::SiteId;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleHealth {
    Healthy,
    Degraded,
    Quarantined,
    Recovering,
}

impl RuleHealth {
    #[must_use]
    pub const fn allows_definitive_assertions(self) -> bool {
        matches!(self, Self::Healthy)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleHealthKey {
    pub site_id: SiteId,
    pub rule_hash: String,
    pub region: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleOperationalFailure {
    Blocked,
    RateLimited,
    Timeout,
    ExcessiveLatency,
    InsufficientCoverage,
    MissingRegion,
    InsufficientRuns,
    ShortMeasurementWindow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleClassificationFailure {
    PrecisionRegression,
    ConflictingEvidence,
    VerdictRegression,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuleHealthSignal {
    AcceptancePassed {
        aggregate_evidence_id: String,
        shadow_evidence_id: String,
    },
    OperationalFailure {
        evidence_id: String,
        failure: RuleOperationalFailure,
    },
    ClassificationFailure {
        evidence_id: String,
        failure: RuleClassificationFailure,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleHealthEvent {
    pub key: RuleHealthKey,
    pub sequence: u64,
    pub manifest_hash: String,
    pub engine_hash: String,
    pub observed_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub signal: RuleHealthSignal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuleHealthPolicy {
    pub recovery_passes_required: u32,
    pub operational_failures_to_quarantine: u32,
}

impl Default for RuleHealthPolicy {
    fn default() -> Self {
        Self {
            recovery_passes_required: 2,
            operational_failures_to_quarantine: 2,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleHealthRecord {
    pub key: RuleHealthKey,
    pub state: RuleHealth,
    pub sequence: u64,
    pub entered_at_unix_ms: i64,
    pub updated_at_unix_ms: i64,
    pub consecutive_recovery_passes: u32,
    pub consecutive_operational_failures: u32,
    pub last_manifest_hash: Option<String>,
    pub last_engine_hash: Option<String>,
    pub last_evidence_expires_at_unix_ms: Option<i64>,
    pub last_evidence_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleHealthTransition {
    pub key: RuleHealthKey,
    pub sequence: u64,
    pub from: RuleHealth,
    pub to: RuleHealth,
    pub changed: bool,
    pub manifest_hash: String,
    pub engine_hash: String,
    pub observed_at_unix_ms: i64,
    pub evidence_expires_at_unix_ms: i64,
    pub evidence_ids: Vec<String>,
}

impl RuleHealthTransition {
    #[must_use]
    pub const fn allows_account_state_notification(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum RuleHealthError {
    #[error("rule-health key is invalid")]
    InvalidKey,
    #[error("rule-health policy is invalid")]
    InvalidPolicy,
    #[error("rule-health event key does not match the record")]
    KeyMismatch,
    #[error("rule-health event sequence is not the next sequence")]
    InvalidSequence,
    #[error("rule-health evidence is stale, expired, or out of order")]
    InvalidEvidenceTime,
    #[error("rule-health evidence identity is invalid")]
    InvalidEvidenceId,
    #[error("persisted rule-health record is invalid")]
    InvalidRecord,
    #[error("rule-health counter overflowed")]
    CounterOverflow,
}

impl RuleHealthRecord {
    pub fn quarantined(
        key: RuleHealthKey,
        initialized_at_unix_ms: i64,
    ) -> Result<Self, RuleHealthError> {
        validate_key(&key)?;
        Ok(Self {
            key,
            state: RuleHealth::Quarantined,
            sequence: 0,
            entered_at_unix_ms: initialized_at_unix_ms,
            updated_at_unix_ms: initialized_at_unix_ms,
            consecutive_recovery_passes: 0,
            consecutive_operational_failures: 0,
            last_manifest_hash: None,
            last_engine_hash: None,
            last_evidence_expires_at_unix_ms: None,
            last_evidence_ids: Vec::new(),
        })
    }

    pub fn apply_at(
        &self,
        event: &RuleHealthEvent,
        policy: RuleHealthPolicy,
        applied_at_unix_ms: i64,
    ) -> Result<(Self, RuleHealthTransition), RuleHealthError> {
        validate_policy(policy)?;
        self.validate(policy)?;
        validate_key(&event.key)?;
        if event.key != self.key {
            return Err(RuleHealthError::KeyMismatch);
        }
        if event.sequence
            != self
                .sequence
                .checked_add(1)
                .ok_or(RuleHealthError::InvalidSequence)?
        {
            return Err(RuleHealthError::InvalidSequence);
        }
        if !valid_sha256(&event.manifest_hash) || !valid_sha256(&event.engine_hash) {
            return Err(RuleHealthError::InvalidEvidenceId);
        }
        if event.observed_at_unix_ms < self.updated_at_unix_ms
            || event.observed_at_unix_ms > applied_at_unix_ms
            || event.expires_at_unix_ms <= applied_at_unix_ms
            || event.expires_at_unix_ms <= event.observed_at_unix_ms
        {
            return Err(RuleHealthError::InvalidEvidenceTime);
        }
        let evidence_ids = validate_signal(&event.signal)?;
        if evidence_ids
            .iter()
            .any(|id| self.last_evidence_ids.contains(id))
        {
            return Err(RuleHealthError::InvalidEvidenceId);
        }

        let from = self.state;
        let mut next = self.clone();
        next.sequence = event.sequence;
        next.updated_at_unix_ms = event.observed_at_unix_ms;
        next.last_manifest_hash = Some(event.manifest_hash.clone());
        next.last_engine_hash = Some(event.engine_hash.clone());
        next.last_evidence_expires_at_unix_ms = Some(event.expires_at_unix_ms);
        next.last_evidence_ids.clone_from(&evidence_ids);

        match event.signal {
            RuleHealthSignal::AcceptancePassed { .. } => {
                next.consecutive_operational_failures = 0;
                match self.state {
                    RuleHealth::Healthy => {
                        next.consecutive_recovery_passes = 0;
                    }
                    RuleHealth::Degraded | RuleHealth::Quarantined => {
                        next.state = RuleHealth::Recovering;
                        next.consecutive_recovery_passes = 1;
                    }
                    RuleHealth::Recovering => {
                        next.consecutive_recovery_passes = self
                            .consecutive_recovery_passes
                            .checked_add(1)
                            .ok_or(RuleHealthError::CounterOverflow)?;
                        if next.consecutive_recovery_passes >= policy.recovery_passes_required {
                            next.state = RuleHealth::Healthy;
                            next.consecutive_recovery_passes = 0;
                        }
                    }
                }
            }
            RuleHealthSignal::OperationalFailure { .. } => {
                next.consecutive_recovery_passes = 0;
                match self.state {
                    RuleHealth::Healthy => {
                        next.state = RuleHealth::Degraded;
                        next.consecutive_operational_failures = 1;
                    }
                    RuleHealth::Degraded => {
                        next.consecutive_operational_failures = self
                            .consecutive_operational_failures
                            .checked_add(1)
                            .ok_or(RuleHealthError::CounterOverflow)?;
                        if next.consecutive_operational_failures
                            >= policy.operational_failures_to_quarantine
                        {
                            next.state = RuleHealth::Quarantined;
                            next.consecutive_operational_failures = 0;
                        }
                    }
                    RuleHealth::Recovering => {
                        next.state = RuleHealth::Quarantined;
                        next.consecutive_operational_failures = 0;
                    }
                    RuleHealth::Quarantined => {
                        next.consecutive_operational_failures = 0;
                    }
                }
            }
            RuleHealthSignal::ClassificationFailure { .. } => {
                next.state = RuleHealth::Quarantined;
                next.consecutive_recovery_passes = 0;
                next.consecutive_operational_failures = 0;
            }
        }

        let changed = from != next.state;
        if changed {
            next.entered_at_unix_ms = event.observed_at_unix_ms;
        }
        let transition = RuleHealthTransition {
            key: next.key.clone(),
            sequence: next.sequence,
            from,
            to: next.state,
            changed,
            manifest_hash: event.manifest_hash.clone(),
            engine_hash: event.engine_hash.clone(),
            observed_at_unix_ms: event.observed_at_unix_ms,
            evidence_expires_at_unix_ms: event.expires_at_unix_ms,
            evidence_ids,
        };
        Ok((next, transition))
    }

    pub fn validate(&self, policy: RuleHealthPolicy) -> Result<(), RuleHealthError> {
        validate_policy(policy)?;
        validate_key(&self.key)?;
        let valid_initial_shape = self.last_evidence_ids.is_empty()
            && self.last_manifest_hash.is_none()
            && self.last_engine_hash.is_none()
            && self.last_evidence_expires_at_unix_ms.is_none()
            && self.state == RuleHealth::Quarantined
            && self.entered_at_unix_ms == self.updated_at_unix_ms;
        let evidence_count_valid = if self.sequence == 0 {
            true
        } else {
            match self.state {
                RuleHealth::Healthy | RuleHealth::Recovering => self.last_evidence_ids.len() == 2,
                RuleHealth::Degraded | RuleHealth::Quarantined => self.last_evidence_ids.len() == 1,
            }
        };
        if self.entered_at_unix_ms > self.updated_at_unix_ms
            || (self.sequence == 0 && !valid_initial_shape)
            || (self.sequence > 0 && self.last_evidence_ids.is_empty())
            || !evidence_count_valid
            || (self.sequence > 0
                && (self
                    .last_manifest_hash
                    .as_deref()
                    .is_none_or(|hash| !valid_sha256(hash))
                    || self
                        .last_engine_hash
                        .as_deref()
                        .is_none_or(|hash| !valid_sha256(hash))
                    || self
                        .last_evidence_expires_at_unix_ms
                        .is_none_or(|expires_at| expires_at <= self.updated_at_unix_ms)))
            || self.last_evidence_ids.len() > 2
            || (self.last_evidence_ids.len() == 2
                && self.last_evidence_ids[0] == self.last_evidence_ids[1])
            || !self.last_evidence_ids.iter().all(|id| valid_sha256(id))
        {
            return Err(RuleHealthError::InvalidRecord);
        }
        let counters_valid = match self.state {
            RuleHealth::Healthy | RuleHealth::Quarantined => {
                self.consecutive_recovery_passes == 0 && self.consecutive_operational_failures == 0
            }
            RuleHealth::Degraded => {
                self.consecutive_recovery_passes == 0
                    && (1..policy.operational_failures_to_quarantine)
                        .contains(&self.consecutive_operational_failures)
            }
            RuleHealth::Recovering => {
                self.consecutive_operational_failures == 0
                    && (1..policy.recovery_passes_required)
                        .contains(&self.consecutive_recovery_passes)
            }
        };
        if !counters_valid {
            return Err(RuleHealthError::InvalidRecord);
        }
        Ok(())
    }
}

fn validate_key(key: &RuleHealthKey) -> Result<(), RuleHealthError> {
    if !valid_label(key.site_id.as_str())
        || !valid_sha256(&key.rule_hash)
        || !valid_label(&key.region)
    {
        return Err(RuleHealthError::InvalidKey);
    }
    Ok(())
}

fn validate_policy(policy: RuleHealthPolicy) -> Result<(), RuleHealthError> {
    if !(2..=32).contains(&policy.recovery_passes_required)
        || !(2..=32).contains(&policy.operational_failures_to_quarantine)
    {
        return Err(RuleHealthError::InvalidPolicy);
    }
    Ok(())
}

fn validate_signal(signal: &RuleHealthSignal) -> Result<Vec<String>, RuleHealthError> {
    let evidence_ids = match signal {
        RuleHealthSignal::AcceptancePassed {
            aggregate_evidence_id,
            shadow_evidence_id,
        } => {
            if aggregate_evidence_id == shadow_evidence_id {
                return Err(RuleHealthError::InvalidEvidenceId);
            }
            vec![aggregate_evidence_id.clone(), shadow_evidence_id.clone()]
        }
        RuleHealthSignal::OperationalFailure { evidence_id, .. }
        | RuleHealthSignal::ClassificationFailure { evidence_id, .. } => {
            vec![evidence_id.clone()]
        }
    };
    if !evidence_ids.iter().all(|id| valid_sha256(id)) {
        return Err(RuleHealthError::InvalidEvidenceId);
    }
    Ok(evidence_ids)
}

fn valid_label(value: &str) -> bool {
    let mut characters = value.chars();
    matches!(characters.next(), Some('a'..='z' | '0'..='9'))
        && value.len() <= 64
        && characters.all(|character| matches!(character, 'a'..='z' | '0'..='9' | '-'))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULE_HASH: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const MANIFEST_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ENGINE_HASH: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const FAILURE_ID: &str = "4444444444444444444444444444444444444444444444444444444444444444";

    fn key(region: &str) -> RuleHealthKey {
        RuleHealthKey {
            site_id: SiteId::new("example"),
            rule_hash: RULE_HASH.to_owned(),
            region: region.to_owned(),
        }
    }

    fn event(
        key: RuleHealthKey,
        sequence: u64,
        at: i64,
        signal: RuleHealthSignal,
    ) -> RuleHealthEvent {
        RuleHealthEvent {
            key,
            sequence,
            manifest_hash: MANIFEST_HASH.to_owned(),
            engine_hash: ENGINE_HASH.to_owned(),
            observed_at_unix_ms: at,
            expires_at_unix_ms: at + 60_000,
            signal,
        }
    }

    fn pass(key: RuleHealthKey, sequence: u64, at: i64) -> RuleHealthEvent {
        event(
            key,
            sequence,
            at,
            RuleHealthSignal::AcceptancePassed {
                aggregate_evidence_id: format!("{:064x}", 0x2000_u64 + sequence),
                shadow_evidence_id: format!("{:064x}", 0x3000_u64 + sequence),
            },
        )
    }

    fn operational_failure(key: RuleHealthKey, sequence: u64, at: i64) -> RuleHealthEvent {
        event(
            key,
            sequence,
            at,
            RuleHealthSignal::OperationalFailure {
                evidence_id: format!("{:064x}", 0x4000_u64 + sequence),
                failure: RuleOperationalFailure::Blocked,
            },
        )
    }

    #[test]
    fn quarantined_rule_requires_two_fresh_passes_to_become_healthy() {
        let record = RuleHealthRecord::quarantined(key("region-a"), 1_000).unwrap();
        let (recovering, first) = record
            .apply_at(
                &pass(key("region-a"), 1, 2_000),
                RuleHealthPolicy::default(),
                2_001,
            )
            .unwrap();
        assert_eq!(recovering.state, RuleHealth::Recovering);
        assert_eq!(recovering.consecutive_recovery_passes, 1);
        assert_eq!(first.from, RuleHealth::Quarantined);
        assert_eq!(first.to, RuleHealth::Recovering);

        let (healthy, second) = recovering
            .apply_at(
                &pass(key("region-a"), 2, 3_000),
                RuleHealthPolicy::default(),
                3_001,
            )
            .unwrap();
        assert_eq!(healthy.state, RuleHealth::Healthy);
        assert_eq!(healthy.consecutive_recovery_passes, 0);
        assert_eq!(healthy.last_manifest_hash.as_deref(), Some(MANIFEST_HASH));
        assert_eq!(healthy.last_engine_hash.as_deref(), Some(ENGINE_HASH));
        assert_eq!(healthy.last_evidence_expires_at_unix_ms, Some(63_000));
        assert_eq!(second.to, RuleHealth::Healthy);
        assert_eq!(second.evidence_expires_at_unix_ms, 63_000);
    }

    #[test]
    fn repeated_operational_failure_degrades_then_quarantines() {
        let initial = RuleHealthRecord::quarantined(key("region-a"), 1_000).unwrap();
        let (recovering, _) = initial
            .apply_at(
                &pass(key("region-a"), 1, 2_000),
                RuleHealthPolicy::default(),
                2_001,
            )
            .unwrap();
        let (healthy, _) = recovering
            .apply_at(
                &pass(key("region-a"), 2, 3_000),
                RuleHealthPolicy::default(),
                3_001,
            )
            .unwrap();
        let (degraded, first_failure) = healthy
            .apply_at(
                &operational_failure(key("region-a"), 3, 4_000),
                RuleHealthPolicy::default(),
                4_001,
            )
            .unwrap();
        assert_eq!(degraded.state, RuleHealth::Degraded);
        assert_eq!(first_failure.to, RuleHealth::Degraded);

        let (quarantined, second_failure) = degraded
            .apply_at(
                &operational_failure(key("region-a"), 4, 5_000),
                RuleHealthPolicy::default(),
                5_001,
            )
            .unwrap();
        assert_eq!(quarantined.state, RuleHealth::Quarantined);
        assert_eq!(second_failure.to, RuleHealth::Quarantined);
    }

    #[test]
    fn classification_failure_quarantines_immediately() {
        let initial = RuleHealthRecord::quarantined(key("region-a"), 1_000).unwrap();
        let (recovering, _) = initial
            .apply_at(
                &pass(key("region-a"), 1, 2_000),
                RuleHealthPolicy::default(),
                2_001,
            )
            .unwrap();
        let (healthy, _) = recovering
            .apply_at(
                &pass(key("region-a"), 2, 3_000),
                RuleHealthPolicy::default(),
                3_001,
            )
            .unwrap();
        let failure = event(
            key("region-a"),
            3,
            4_000,
            RuleHealthSignal::ClassificationFailure {
                evidence_id: FAILURE_ID.to_owned(),
                failure: RuleClassificationFailure::VerdictRegression,
            },
        );
        let (quarantined, transition) = healthy
            .apply_at(&failure, RuleHealthPolicy::default(), 4_001)
            .unwrap();

        assert_eq!(quarantined.state, RuleHealth::Quarantined);
        assert_eq!(transition.from, RuleHealth::Healthy);
        assert_eq!(transition.to, RuleHealth::Quarantined);
    }

    #[test]
    fn recovery_failure_returns_to_quarantine() {
        let initial = RuleHealthRecord::quarantined(key("region-a"), 1_000).unwrap();
        let (recovering, _) = initial
            .apply_at(
                &pass(key("region-a"), 1, 2_000),
                RuleHealthPolicy::default(),
                2_001,
            )
            .unwrap();
        let (quarantined, _) = recovering
            .apply_at(
                &operational_failure(key("region-a"), 2, 3_000),
                RuleHealthPolicy::default(),
                3_001,
            )
            .unwrap();

        assert_eq!(quarantined.state, RuleHealth::Quarantined);
        assert_eq!(quarantined.consecutive_recovery_passes, 0);
    }

    #[test]
    fn rejects_replays_stale_evidence_and_cross_region_updates() {
        let initial = RuleHealthRecord::quarantined(key("region-a"), 1_000).unwrap();
        let (recovering, _) = initial
            .apply_at(
                &pass(key("region-a"), 1, 2_000),
                RuleHealthPolicy::default(),
                2_001,
            )
            .unwrap();

        assert_eq!(
            recovering
                .apply_at(
                    &pass(key("region-a"), 1, 3_000),
                    RuleHealthPolicy::default(),
                    3_001
                )
                .unwrap_err(),
            RuleHealthError::InvalidSequence
        );
        assert_eq!(
            recovering
                .apply_at(
                    &pass(key("region-a"), 2, 1_500),
                    RuleHealthPolicy::default(),
                    3_001
                )
                .unwrap_err(),
            RuleHealthError::InvalidEvidenceTime
        );
        assert_eq!(
            recovering
                .apply_at(
                    &pass(key("region-b"), 2, 3_000),
                    RuleHealthPolicy::default(),
                    3_001
                )
                .unwrap_err(),
            RuleHealthError::KeyMismatch
        );
    }

    #[test]
    fn only_healthy_state_allows_definitive_assertions_and_never_account_notifications() {
        assert!(RuleHealth::Healthy.allows_definitive_assertions());
        assert!(!RuleHealth::Degraded.allows_definitive_assertions());
        assert!(!RuleHealth::Quarantined.allows_definitive_assertions());
        assert!(!RuleHealth::Recovering.allows_definitive_assertions());

        let initial = RuleHealthRecord::quarantined(key("region-a"), 1_000).unwrap();
        let (_, transition) = initial
            .apply_at(
                &pass(key("region-a"), 1, 2_000),
                RuleHealthPolicy::default(),
                2_001,
            )
            .unwrap();
        assert!(!transition.allows_account_state_notification());
    }

    #[test]
    fn rejects_an_invalid_persisted_record_before_applying_evidence() {
        let invalid = RuleHealthRecord {
            key: key("region-a"),
            state: RuleHealth::Healthy,
            sequence: 0,
            entered_at_unix_ms: 1_000,
            updated_at_unix_ms: 1_000,
            consecutive_recovery_passes: 1,
            consecutive_operational_failures: 0,
            last_manifest_hash: None,
            last_engine_hash: None,
            last_evidence_expires_at_unix_ms: None,
            last_evidence_ids: Vec::new(),
        };
        assert_eq!(
            invalid.validate(RuleHealthPolicy::default()).unwrap_err(),
            RuleHealthError::InvalidRecord
        );
        assert_eq!(
            invalid
                .apply_at(
                    &pass(key("region-a"), 1, 2_000),
                    RuleHealthPolicy::default(),
                    2_001,
                )
                .unwrap_err(),
            RuleHealthError::InvalidRecord
        );

        let initial = RuleHealthRecord::quarantined(key("region-a"), 1_000).unwrap();
        let (mut invalid_expiry, _) = initial
            .apply_at(
                &pass(key("region-a"), 1, 2_000),
                RuleHealthPolicy::default(),
                2_001,
            )
            .unwrap();
        invalid_expiry.last_evidence_expires_at_unix_ms = Some(invalid_expiry.updated_at_unix_ms);
        assert_eq!(
            invalid_expiry
                .validate(RuleHealthPolicy::default())
                .unwrap_err(),
            RuleHealthError::InvalidRecord
        );

        let initial = RuleHealthRecord::quarantined(key("region-a"), 1_000).unwrap();
        let (mut fabricated_healthy, _) = initial
            .apply_at(
                &pass(key("region-a"), 1, 2_000),
                RuleHealthPolicy::default(),
                2_001,
            )
            .unwrap();
        fabricated_healthy.state = RuleHealth::Healthy;
        fabricated_healthy.consecutive_recovery_passes = 0;
        fabricated_healthy.last_evidence_ids.truncate(1);
        assert_eq!(
            fabricated_healthy
                .validate(RuleHealthPolicy::default())
                .unwrap_err(),
            RuleHealthError::InvalidRecord
        );
    }
}
