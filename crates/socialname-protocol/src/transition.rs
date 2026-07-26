use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    ObservationId, ProtocolVersion, RegionClass, RuleHash, Target, TransitionId, Validate,
    ValidationCode, ValidationErrors, WatchId,
    common::{validate_nonempty_ids, validate_timestamp},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AccountState {
    Found,
    NotFound,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MeasurementState {
    Healthy,
    Degraded,
    Quarantined,
    Recovering,
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "class", rename_all = "snake_case", deny_unknown_fields)]
pub enum TransitionChange {
    AccountState {
        from: AccountState,
        to: AccountState,
    },
    MeasurementHealth {
        region_class: RegionClass,
        rule_hash: RuleHash,
        from: MeasurementState,
        to: MeasurementState,
    },
}

impl TransitionChange {
    fn validate(&self) -> Result<(), ValidationErrors> {
        match self {
            Self::AccountState { from, to } if from == to => Err(ValidationErrors::new(
                "change",
                ValidationCode::InvalidRelation,
            )),
            Self::MeasurementHealth { from, to, .. } if from == to => Err(ValidationErrors::new(
                "change",
                ValidationCode::InvalidRelation,
            )),
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmationBasis {
    ManagedE4,
    ManagedE3FollowUp,
    TwoManagedIndependentRegions,
    TwoManagedSeparatedInTime,
    CorroboratedSharedCandidateOptIn,
    MeasurementHealthEvidence,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PendingConfirmationReason {
    ManagedVerificationRequired,
    SecondManagedObservationRequired,
    RegionalConflict,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SuppressionReason {
    SharedOnlyAbsence,
    ConflictingEvidence,
    WatchPaused,
    SupportingEvidenceDeleted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum TransitionConfirmation {
    Pending { reason: PendingConfirmationReason },
    Confirmed { basis: ConfirmationBasis },
    Suppressed { reason: SuppressionReason },
}

impl TransitionConfirmation {
    #[must_use]
    pub const fn permits_delivery(&self) -> bool {
        matches!(self, Self::Confirmed { .. })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Transition {
    pub schema: ProtocolVersion,
    pub transition_id: TransitionId,
    pub watch_id: WatchId,
    pub target: Target,
    pub change: TransitionChange,
    pub confirmation: TransitionConfirmation,
    pub supporting_observation_ids: Vec<ObservationId>,
    pub detected_at_unix_ms: i64,
}

impl Validate for Transition {
    fn validate(&self) -> Result<(), ValidationErrors> {
        self.change.validate()?;
        if matches!(self.change, TransitionChange::AccountState { .. })
            || !self.supporting_observation_ids.is_empty()
        {
            validate_nonempty_ids(
                "supporting_observation_ids",
                &self.supporting_observation_ids,
                32,
            )?;
        }
        validate_timestamp("detected_at_unix_ms", self.detected_at_unix_ms)?;
        validate_confirmation(&self.change, &self.confirmation)
    }
}

fn validate_confirmation(
    change: &TransitionChange,
    confirmation: &TransitionConfirmation,
) -> Result<(), ValidationErrors> {
    let valid = matches!(
        (change, confirmation),
        (
            TransitionChange::AccountState {
                to: AccountState::Found,
                ..
            },
            TransitionConfirmation::Confirmed {
                basis: ConfirmationBasis::ManagedE4
                    | ConfirmationBasis::ManagedE3FollowUp
                    | ConfirmationBasis::CorroboratedSharedCandidateOptIn,
            },
        ) | (
            TransitionChange::AccountState {
                to: AccountState::NotFound,
                ..
            },
            TransitionConfirmation::Confirmed {
                basis: ConfirmationBasis::TwoManagedIndependentRegions
                    | ConfirmationBasis::TwoManagedSeparatedInTime,
            },
        ) | (
            TransitionChange::MeasurementHealth { .. },
            TransitionConfirmation::Confirmed {
                basis: ConfirmationBasis::MeasurementHealthEvidence,
            },
        ) | (
            TransitionChange::AccountState { .. },
            TransitionConfirmation::Pending { .. }
        ) | (
            TransitionChange::AccountState {
                to: AccountState::NotFound,
                ..
            },
            TransitionConfirmation::Suppressed {
                reason: SuppressionReason::SharedOnlyAbsence,
            },
        ) | (
            TransitionChange::AccountState { .. },
            TransitionConfirmation::Suppressed {
                reason: SuppressionReason::ConflictingEvidence
                    | SuppressionReason::WatchPaused
                    | SuppressionReason::SupportingEvidenceDeleted,
            },
        ) | (
            TransitionChange::MeasurementHealth { .. },
            TransitionConfirmation::Suppressed {
                reason: SuppressionReason::WatchPaused
                    | SuppressionReason::SupportingEvidenceDeleted,
            },
        )
    );

    if valid {
        Ok(())
    } else {
        Err(ValidationErrors::new(
            "confirmation",
            ValidationCode::InvalidRelation,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SiteId, Username};

    fn transition(change: TransitionChange, confirmation: TransitionConfirmation) -> Transition {
        Transition {
            schema: ProtocolVersion::ApiV1,
            transition_id: TransitionId::new("transition_01").unwrap(),
            watch_id: WatchId::new("watch_01").unwrap(),
            target: Target {
                username: Username::new("alice").unwrap(),
                site_id: SiteId::new("github").unwrap(),
            },
            change,
            confirmation,
            supporting_observation_ids: vec![ObservationId::new("observation_01").unwrap()],
            detected_at_unix_ms: 2_000,
        }
    }

    #[test]
    fn shared_only_absence_is_structurally_non_deliverable() {
        let transition = transition(
            TransitionChange::AccountState {
                from: AccountState::Found,
                to: AccountState::NotFound,
            },
            TransitionConfirmation::Suppressed {
                reason: SuppressionReason::SharedOnlyAbsence,
            },
        );
        assert!(transition.validate().is_ok());
        assert!(!transition.confirmation.permits_delivery());
    }

    #[test]
    fn disappearance_rejects_appearance_confirmation_basis() {
        let transition = transition(
            TransitionChange::AccountState {
                from: AccountState::Found,
                to: AccountState::NotFound,
            },
            TransitionConfirmation::Confirmed {
                basis: ConfirmationBasis::ManagedE4,
            },
        );
        assert!(transition.validate().is_err());
    }

    #[test]
    fn measurement_degradation_is_not_an_account_state() {
        let transition = transition(
            TransitionChange::MeasurementHealth {
                region_class: RegionClass::new("jp").unwrap(),
                rule_hash: RuleHash::new("a".repeat(64)).unwrap(),
                from: MeasurementState::Healthy,
                to: MeasurementState::Degraded,
            },
            TransitionConfirmation::Confirmed {
                basis: ConfirmationBasis::MeasurementHealthEvidence,
            },
        );
        assert!(transition.validate().is_ok());
        let json = serde_json::to_value(transition).unwrap();
        assert_eq!(json["change"]["class"], "measurement_health");
        assert!(json["change"].get("from").is_some());
        assert!(json["change"].get("account_state").is_none());
    }

    #[test]
    fn operational_measurement_failure_does_not_require_an_observation() {
        let mut transition = transition(
            TransitionChange::MeasurementHealth {
                region_class: RegionClass::new("jp").unwrap(),
                rule_hash: RuleHash::new("a".repeat(64)).unwrap(),
                from: MeasurementState::Healthy,
                to: MeasurementState::Unavailable,
            },
            TransitionConfirmation::Confirmed {
                basis: ConfirmationBasis::MeasurementHealthEvidence,
            },
        );
        transition.supporting_observation_ids.clear();

        assert!(transition.validate().is_ok());
    }
}
