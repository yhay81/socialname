use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    ProtocolVersion, Validate, ValidationCode, ValidationErrors, common::validate_timestamp,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PlanCode {
    Community,
    Developer,
    Monitor,
    Evaluation,
}

impl PlanCode {
    #[must_use]
    pub const fn capabilities(self) -> &'static [PlanCapability] {
        match self {
            Self::Community => &[],
            Self::Developer => &[PlanCapability::ManagedSearch],
            Self::Monitor | Self::Evaluation => {
                &[PlanCapability::ManagedSearch, PlanCapability::Monitoring]
            }
        }
    }
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PlanCapability {
    ManagedSearch,
    Monitoring,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PlanEntitlementState {
    Pending,
    Active,
    Suspended,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PlanEntitlementResource {
    pub schema: ProtocolVersion,
    pub plan: PlanCode,
    pub state: PlanEntitlementState,
    pub capabilities: Vec<PlanCapability>,
    pub revision: u64,
    pub effective_at_unix_ms: i64,
    pub access_until_unix_ms: Option<i64>,
    pub updated_at_unix_ms: i64,
    pub evaluated_at_unix_ms: i64,
}

impl Validate for PlanEntitlementResource {
    fn validate(&self) -> Result<(), ValidationErrors> {
        for (field, timestamp) in [
            ("effective_at_unix_ms", self.effective_at_unix_ms),
            ("updated_at_unix_ms", self.updated_at_unix_ms),
            ("evaluated_at_unix_ms", self.evaluated_at_unix_ms),
        ] {
            validate_timestamp(field, timestamp)?;
        }
        if let Some(access_until_unix_ms) = self.access_until_unix_ms {
            validate_timestamp("access_until_unix_ms", access_until_unix_ms)?;
            if access_until_unix_ms <= self.effective_at_unix_ms {
                return Err(ValidationErrors::new(
                    "access_until_unix_ms",
                    ValidationCode::InvalidRelation,
                ));
            }
        }
        if self.revision == 0 {
            return Err(ValidationErrors::new(
                "revision",
                ValidationCode::OutOfRange,
            ));
        }
        if self.updated_at_unix_ms > self.evaluated_at_unix_ms {
            return Err(ValidationErrors::new(
                "updated_at_unix_ms",
                ValidationCode::InvalidRelation,
            ));
        }

        let state_relation_valid = match self.state {
            PlanEntitlementState::Pending => self.evaluated_at_unix_ms < self.effective_at_unix_ms,
            PlanEntitlementState::Active => {
                self.evaluated_at_unix_ms >= self.effective_at_unix_ms
                    && self
                        .access_until_unix_ms
                        .is_none_or(|deadline| deadline > self.evaluated_at_unix_ms)
            }
            PlanEntitlementState::Suspended => {
                self.evaluated_at_unix_ms >= self.effective_at_unix_ms
                    && self
                        .access_until_unix_ms
                        .is_none_or(|deadline| deadline <= self.evaluated_at_unix_ms)
            }
        };
        if !state_relation_valid {
            return Err(ValidationErrors::new(
                "state",
                ValidationCode::InvalidRelation,
            ));
        }
        let expected_capabilities = if self.state == PlanEntitlementState::Active {
            self.plan.capabilities()
        } else {
            &[]
        };
        if self.capabilities.as_slice() != expected_capabilities {
            return Err(ValidationErrors::new(
                "capabilities",
                ValidationCode::InvalidRelation,
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resource() -> PlanEntitlementResource {
        PlanEntitlementResource {
            schema: ProtocolVersion::ApiV1,
            plan: PlanCode::Monitor,
            state: PlanEntitlementState::Active,
            capabilities: PlanCode::Monitor.capabilities().to_vec(),
            revision: 2,
            effective_at_unix_ms: 1_000,
            access_until_unix_ms: Some(10_000),
            updated_at_unix_ms: 1_000,
            evaluated_at_unix_ms: 2_000,
        }
    }

    #[test]
    fn active_capabilities_are_derived_from_the_closed_plan() {
        let mut entitlement = resource();
        assert!(entitlement.validate().is_ok());
        entitlement.capabilities = vec![PlanCapability::Monitoring];
        assert!(entitlement.validate().is_err());
    }

    #[test]
    fn pending_and_expired_access_cannot_claim_active_capabilities() {
        let mut pending = resource();
        pending.state = PlanEntitlementState::Pending;
        pending.capabilities.clear();
        pending.effective_at_unix_ms = 3_000;
        assert!(pending.validate().is_ok());

        let mut expired = resource();
        expired.state = PlanEntitlementState::Suspended;
        expired.capabilities.clear();
        expired.evaluated_at_unix_ms = 10_000;
        assert!(expired.validate().is_ok());
    }

    #[test]
    fn grace_deadline_must_follow_effective_time() {
        let mut entitlement = resource();
        entitlement.access_until_unix_ms = Some(entitlement.effective_at_unix_ms);
        assert!(entitlement.validate().is_err());
    }
}
