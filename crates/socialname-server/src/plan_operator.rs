use std::env;

use serde::Serialize;
use sha2::{Digest, Sha256};
use socialname_protocol::{PlanCode, PlanEntitlementResource};
use sqlx::{PgPool, Postgres, Transaction};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    database::{DATABASE_URL_ENV, DatabaseError, connect_database, database_url_from_env},
    plan::{PlanLoadError, plan_code, plan_code_value, select_plan_entitlement},
};

pub const PLAN_CODE_ENV: &str = "SOCIALNAME_PLAN_CODE";
pub const PLAN_ACCESS_STATE_ENV: &str = "SOCIALNAME_PLAN_ACCESS_STATE";
pub const PLAN_EXPECTED_REVISION_ENV: &str = "SOCIALNAME_PLAN_EXPECTED_REVISION";
pub const PLAN_EFFECTIVE_AT_ENV: &str = "SOCIALNAME_PLAN_EFFECTIVE_AT_UNIX_MS";
pub const PLAN_ACCESS_UNTIL_ENV: &str = "SOCIALNAME_PLAN_ACCESS_UNTIL_UNIX_MS";
pub const BILLING_EVENT_ID_ENV: &str = "SOCIALNAME_BILLING_EVENT_ID";
pub const PLAN_WORKSPACE_ID_ENV: &str = "SOCIALNAME_WORKSPACE_ID";

const HASH_DOMAIN: &[u8] = b"socialname.plan-entitlement-reconciliation/v1\0";
const MAXIMUM_EVENT_ID_BYTES: usize = 200;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconciledAccessState {
    Active,
    Suspended,
}

#[derive(Clone)]
pub struct PlanReconciliation {
    pub workspace_id: Uuid,
    pub expected_revision: u64,
    pub plan: PlanCode,
    pub access_state: ReconciledAccessState,
    pub effective_at_unix_ms: i64,
    pub access_until_unix_ms: Option<i64>,
    source_event_id: String,
}

impl PlanReconciliation {
    pub fn new(
        workspace_id: Uuid,
        expected_revision: u64,
        plan: PlanCode,
        access_state: ReconciledAccessState,
        effective_at_unix_ms: i64,
        access_until_unix_ms: Option<i64>,
        source_event_id: impl Into<String>,
    ) -> Result<Self, PlanOperatorError> {
        let source_event_id = source_event_id.into();
        let valid_event_id = !source_event_id.is_empty()
            && source_event_id.len() <= MAXIMUM_EVENT_ID_BYTES
            && source_event_id
                .bytes()
                .all(|byte| matches!(byte, 0x21..=0x7e));
        let valid_access = expected_revision > 0
            && effective_at_unix_ms > 0
            && match access_state {
                ReconciledAccessState::Active => {
                    access_until_unix_ms.is_none_or(|deadline| deadline > effective_at_unix_ms)
                }
                ReconciledAccessState::Suspended => access_until_unix_ms.is_none(),
            };
        if !valid_event_id || !valid_access {
            return Err(PlanOperatorError::InvalidConfiguration);
        }
        Ok(Self {
            workspace_id,
            expected_revision,
            plan,
            access_state,
            effective_at_unix_ms,
            access_until_unix_ms,
            source_event_id,
        })
    }

    fn from_env() -> Result<Self, PlanOperatorError> {
        let workspace_id = Uuid::parse_str(&required_env(PLAN_WORKSPACE_ID_ENV)?)
            .map_err(|_| PlanOperatorError::InvalidConfiguration)?;
        let expected_revision = required_env(PLAN_EXPECTED_REVISION_ENV)?
            .parse()
            .map_err(|_| PlanOperatorError::InvalidConfiguration)?;
        let plan = plan_code(&required_env(PLAN_CODE_ENV)?)
            .map_err(|_| PlanOperatorError::InvalidConfiguration)?;
        let access_state = match required_env(PLAN_ACCESS_STATE_ENV)?.as_str() {
            "active" => ReconciledAccessState::Active,
            "suspended" => ReconciledAccessState::Suspended,
            _ => return Err(PlanOperatorError::InvalidConfiguration),
        };
        let effective_at_unix_ms = required_env(PLAN_EFFECTIVE_AT_ENV)?
            .parse()
            .map_err(|_| PlanOperatorError::InvalidConfiguration)?;
        let access_until_unix_ms = optional_env(PLAN_ACCESS_UNTIL_ENV)?
            .map(|value| {
                value
                    .parse()
                    .map_err(|_| PlanOperatorError::InvalidConfiguration)
            })
            .transpose()?;
        Self::new(
            workspace_id,
            expected_revision,
            plan,
            access_state,
            effective_at_unix_ms,
            access_until_unix_ms,
            required_env(BILLING_EVENT_ID_ENV)?,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PlanReconciliationOutput {
    pub entitlement: PlanEntitlementResource,
    pub replayed: bool,
}

pub async fn reconcile_plan_entitlement_from_env()
-> Result<PlanReconciliationOutput, PlanOperatorError> {
    let database_url = database_url_from_env(DATABASE_URL_ENV)?;
    let request = PlanReconciliation::from_env()?;
    let pool = connect_database(&database_url, 1).await?;
    let result = reconcile_plan_entitlement(&pool, request).await;
    pool.close().await;
    result
}

pub async fn reconcile_plan_entitlement(
    pool: &PgPool,
    request: PlanReconciliation,
) -> Result<PlanReconciliationOutput, PlanOperatorError> {
    let source_event_hash = Sha256::digest(request.source_event_id.as_bytes());
    let request_hash = reconciliation_hash(&request);
    let mut transaction = begin_tenant_transaction(pool, request.workspace_id).await?;
    let existing_request_hash: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT request_hash FROM plan_entitlement_events \
         WHERE tenant_id = $1 AND source_event_hash = $2",
    )
    .bind(request.workspace_id)
    .bind(&source_event_hash[..])
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| PlanOperatorError::DatabaseOperationFailed)?;
    if let Some(existing_request_hash) = existing_request_hash {
        if existing_request_hash.as_slice() != request_hash.as_slice() {
            return Err(PlanOperatorError::EventConflict);
        }
        let entitlement = select_plan_entitlement(&mut transaction, request.workspace_id)
            .await
            .map_err(map_plan_load)?;
        transaction
            .commit()
            .await
            .map_err(|_| PlanOperatorError::DatabaseOperationFailed)?;
        return Ok(PlanReconciliationOutput {
            entitlement,
            replayed: true,
        });
    }

    let current_revision: Option<i64> = sqlx::query_scalar(
        "SELECT revision FROM tenant_plan_entitlements \
         WHERE tenant_id = $1 FOR UPDATE",
    )
    .bind(request.workspace_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| PlanOperatorError::DatabaseOperationFailed)?;
    let Some(current_revision) = current_revision else {
        return Err(PlanOperatorError::NotFound);
    };
    if u64::try_from(current_revision).ok() != Some(request.expected_revision) {
        return Err(PlanOperatorError::RevisionConflict);
    }
    let next_revision = current_revision
        .checked_add(1)
        .ok_or(PlanOperatorError::DatabaseOperationFailed)?;
    let access_state = access_state_value(request.access_state);
    let updated_at_unix_ms: i64 = sqlx::query_scalar(
        "UPDATE tenant_plan_entitlements SET \
            plan_code = $2, access_state = $3, revision = $4, \
            source_kind = 'billing', source_event_hash = $5, request_hash = $6, \
            effective_at = to_timestamp($7::double precision / 1000.0), \
            access_until = CASE \
                WHEN $8::bigint IS NULL THEN NULL \
                ELSE to_timestamp($8::double precision / 1000.0) \
            END, updated_at = clock_timestamp() \
         WHERE tenant_id = $1 \
         RETURNING (EXTRACT(EPOCH FROM updated_at) * 1000)::bigint",
    )
    .bind(request.workspace_id)
    .bind(plan_code_value(request.plan))
    .bind(access_state)
    .bind(next_revision)
    .bind(&source_event_hash[..])
    .bind(&request_hash[..])
    .bind(request.effective_at_unix_ms)
    .bind(request.access_until_unix_ms)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| PlanOperatorError::DatabaseOperationFailed)?;
    sqlx::query(
        "INSERT INTO plan_entitlement_events (\
            id, tenant_id, revision, plan_code, access_state, source_kind, \
            source_event_hash, request_hash, effective_at, access_until, occurred_at\
         ) VALUES (\
            $1, $2, $3, $4, $5, 'billing', $6, $7, \
            to_timestamp($8::double precision / 1000.0), \
            CASE WHEN $9::bigint IS NULL THEN NULL \
                 ELSE to_timestamp($9::double precision / 1000.0) END, \
            to_timestamp($10::double precision / 1000.0)\
         )",
    )
    .bind(Uuid::new_v4())
    .bind(request.workspace_id)
    .bind(next_revision)
    .bind(plan_code_value(request.plan))
    .bind(access_state)
    .bind(&source_event_hash[..])
    .bind(&request_hash[..])
    .bind(request.effective_at_unix_ms)
    .bind(request.access_until_unix_ms)
    .bind(updated_at_unix_ms)
    .execute(&mut *transaction)
    .await
    .map_err(|_| PlanOperatorError::DatabaseOperationFailed)?;
    sqlx::query(
        "INSERT INTO audit_events (\
            id, tenant_id, action, resource_kind, resource_id, occurred_at, details\
         ) VALUES (\
            $1, $2, 'plan_entitlement.reconciled', 'workspace', $2, \
            to_timestamp($3::double precision / 1000.0), \
            jsonb_build_object(\
                'plan_code', $4::text, \
                'access_state', $5::text, \
                'revision', $6::bigint\
            )\
         )",
    )
    .bind(Uuid::new_v4())
    .bind(request.workspace_id)
    .bind(updated_at_unix_ms)
    .bind(plan_code_value(request.plan))
    .bind(access_state)
    .bind(next_revision)
    .execute(&mut *transaction)
    .await
    .map_err(|_| PlanOperatorError::DatabaseOperationFailed)?;
    let entitlement = select_plan_entitlement(&mut transaction, request.workspace_id)
        .await
        .map_err(map_plan_load)?;
    transaction
        .commit()
        .await
        .map_err(|_| PlanOperatorError::DatabaseOperationFailed)?;
    Ok(PlanReconciliationOutput {
        entitlement,
        replayed: false,
    })
}

fn reconciliation_hash(request: &PlanReconciliation) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(HASH_DOMAIN);
    hasher.update(request.workspace_id.as_bytes());
    hasher.update(request.expected_revision.to_be_bytes());
    hasher.update([plan_code_discriminator(request.plan)]);
    hasher.update([access_state_discriminator(request.access_state)]);
    hasher.update(request.effective_at_unix_ms.to_be_bytes());
    hasher.update(
        request
            .access_until_unix_ms
            .unwrap_or_default()
            .to_be_bytes(),
    );
    hasher.finalize().into()
}

const fn plan_code_discriminator(value: PlanCode) -> u8 {
    match value {
        PlanCode::Community => 1,
        PlanCode::Developer => 2,
        PlanCode::Monitor => 3,
        PlanCode::Evaluation => 4,
    }
}

const fn access_state_discriminator(value: ReconciledAccessState) -> u8 {
    match value {
        ReconciledAccessState::Active => 1,
        ReconciledAccessState::Suspended => 2,
    }
}

const fn access_state_value(value: ReconciledAccessState) -> &'static str {
    match value {
        ReconciledAccessState::Active => "active",
        ReconciledAccessState::Suspended => "suspended",
    }
}

async fn begin_tenant_transaction(
    pool: &PgPool,
    tenant_id: Uuid,
) -> Result<Transaction<'_, Postgres>, PlanOperatorError> {
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| PlanOperatorError::DatabaseOperationFailed)?;
    sqlx::query("SELECT set_config('socialname.tenant_id', $1, true)")
        .bind(tenant_id.to_string())
        .execute(&mut *transaction)
        .await
        .map_err(|_| PlanOperatorError::DatabaseOperationFailed)?;
    Ok(transaction)
}

fn required_env(variable: &'static str) -> Result<String, PlanOperatorError> {
    optional_env(variable)?.ok_or(PlanOperatorError::MissingConfiguration(variable))
}

fn optional_env(variable: &'static str) -> Result<Option<String>, PlanOperatorError> {
    match env::var(variable) {
        Ok(value) if value.is_empty() => Ok(None),
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(PlanOperatorError::InvalidConfiguration),
    }
}

fn map_plan_load(_: PlanLoadError) -> PlanOperatorError {
    PlanOperatorError::DatabaseOperationFailed
}

#[derive(Debug, Error)]
pub enum PlanOperatorError {
    #[error(transparent)]
    Database(#[from] DatabaseError),
    #[error("{0} is required")]
    MissingConfiguration(&'static str),
    #[error("plan reconciliation configuration is invalid; supplied values are omitted")]
    InvalidConfiguration,
    #[error("workspace or plan entitlement was not found")]
    NotFound,
    #[error("plan entitlement revision has changed")]
    RevisionConflict,
    #[error("billing event was reused with different entitlement content")]
    EventConflict,
    #[error("plan entitlement database operation failed")]
    DatabaseOperationFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_validation_is_closed_and_redacts_event_values() {
        let invalid = match PlanReconciliation::new(
            Uuid::nil(),
            1,
            PlanCode::Developer,
            ReconciledAccessState::Active,
            1_000,
            None,
            "private\nbilling-event",
        ) {
            Ok(_) => panic!("control character should fail validation"),
            Err(error) => error,
        };
        assert!(!invalid.to_string().contains("private"));
        assert!(!format!("{invalid:?}").contains("private"));

        assert!(
            PlanReconciliation::new(
                Uuid::nil(),
                1,
                PlanCode::Monitor,
                ReconciledAccessState::Suspended,
                1_000,
                Some(2_000),
                "billing-event-1",
            )
            .is_err()
        );
    }

    #[test]
    fn request_hash_binds_every_effective_field() {
        let request = PlanReconciliation::new(
            Uuid::nil(),
            1,
            PlanCode::Developer,
            ReconciledAccessState::Active,
            1_000,
            Some(2_000),
            "billing-event-1",
        )
        .unwrap();
        let mut changed = request.clone();
        changed.plan = PlanCode::Monitor;
        assert_ne!(reconciliation_hash(&request), reconciliation_hash(&changed));
    }
}
