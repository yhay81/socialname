use axum::{
    Extension, Json,
    extract::State,
    response::{IntoResponse, Response},
};
use socialname_protocol::{
    ApiErrorCode, ApiKeyScope, PlanCapability, PlanCode, PlanEntitlementResource,
    PlanEntitlementState, ProtocolVersion, RequestId, Validate,
};
use sqlx::{PgPool, Postgres, Transaction};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    ServerState,
    auth::{self, AuthenticatedPrincipal, AuthenticationError},
    standard_api_error, unauthenticated_response,
};

pub(crate) async fn get_plan_entitlement(
    State(state): State<ServerState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
) -> Response {
    match load_plan_entitlement(&state.database, &principal).await {
        Ok(resource) => Json(resource).into_response(),
        Err(error) => error_response(request_id, error),
    }
}

pub(crate) async fn require_plan_capability(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    capability: PlanCapability,
) -> Result<(), PlanCapabilityError> {
    let enabled: bool = sqlx::query_scalar("SELECT socialname_has_plan_capability($1, $2)")
        .bind(tenant_id)
        .bind(capability_value(capability))
        .fetch_one(&mut **transaction)
        .await
        .map_err(|_| PlanCapabilityError::Unavailable)?;
    if enabled {
        Ok(())
    } else {
        Err(PlanCapabilityError::Required)
    }
}

async fn load_plan_entitlement(
    pool: &PgPool,
    principal: &AuthenticatedPrincipal,
) -> Result<PlanEntitlementResource, PlanLoadError> {
    let mut transaction =
        auth::begin_authorized_transaction(pool, principal, ApiKeyScope::WorkspaceRead).await?;
    let resource = select_plan_entitlement(&mut transaction, principal.workspace_id).await?;
    transaction
        .commit()
        .await
        .map_err(|_| PlanLoadError::Unavailable)?;
    Ok(resource)
}

pub(crate) async fn select_plan_entitlement(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
) -> Result<PlanEntitlementResource, PlanLoadError> {
    let row: Option<StoredPlanEntitlement> = sqlx::query_as(
        r#"
        WITH evaluated AS MATERIALIZED (
            SELECT statement_timestamp() AS evaluated_at
        )
        SELECT
            entitlement.plan_code,
            CASE
                WHEN evaluated.evaluated_at < entitlement.effective_at
                    THEN 'pending'
                WHEN entitlement.access_state = 'suspended'
                    OR entitlement.access_until <= evaluated.evaluated_at
                    THEN 'suspended'
                ELSE 'active'
            END AS effective_state,
            entitlement.revision,
            (EXTRACT(EPOCH FROM entitlement.effective_at) * 1000)::bigint
                AS effective_at_unix_ms,
            (EXTRACT(EPOCH FROM entitlement.access_until) * 1000)::bigint
                AS access_until_unix_ms,
            (EXTRACT(EPOCH FROM entitlement.updated_at) * 1000)::bigint
                AS updated_at_unix_ms,
            (EXTRACT(EPOCH FROM evaluated.evaluated_at) * 1000)::bigint
                AS evaluated_at_unix_ms
        FROM tenant_plan_entitlements AS entitlement
        CROSS JOIN evaluated
        WHERE entitlement.tenant_id = $1
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| PlanLoadError::Unavailable)?;
    let row = row.ok_or(PlanLoadError::Unavailable)?;
    plan_entitlement_resource(row).map_err(|_| PlanLoadError::Unavailable)
}

pub(crate) fn plan_entitlement_resource(
    row: StoredPlanEntitlement,
) -> Result<PlanEntitlementResource, PlanValueError> {
    let plan = plan_code(&row.plan_code)?;
    let state = entitlement_state(&row.effective_state)?;
    let capabilities = if state == PlanEntitlementState::Active {
        plan.capabilities().to_vec()
    } else {
        Vec::new()
    };
    let resource = PlanEntitlementResource {
        schema: ProtocolVersion::ApiV1,
        plan,
        state,
        capabilities,
        revision: u64::try_from(row.revision).map_err(|_| PlanValueError)?,
        effective_at_unix_ms: row.effective_at_unix_ms,
        access_until_unix_ms: row.access_until_unix_ms,
        updated_at_unix_ms: row.updated_at_unix_ms,
        evaluated_at_unix_ms: row.evaluated_at_unix_ms,
    };
    resource.validate().map_err(|_| PlanValueError)?;
    Ok(resource)
}

pub(crate) fn plan_code(value: &str) -> Result<PlanCode, PlanValueError> {
    match value {
        "community" => Ok(PlanCode::Community),
        "developer" => Ok(PlanCode::Developer),
        "monitor" => Ok(PlanCode::Monitor),
        "evaluation" => Ok(PlanCode::Evaluation),
        _ => Err(PlanValueError),
    }
}

pub(crate) const fn plan_code_value(value: PlanCode) -> &'static str {
    match value {
        PlanCode::Community => "community",
        PlanCode::Developer => "developer",
        PlanCode::Monitor => "monitor",
        PlanCode::Evaluation => "evaluation",
    }
}

pub(crate) const fn capability_value(value: PlanCapability) -> &'static str {
    match value {
        PlanCapability::ManagedSearch => "managed_search",
        PlanCapability::Monitoring => "monitoring",
    }
}

fn entitlement_state(value: &str) -> Result<PlanEntitlementState, PlanValueError> {
    match value {
        "pending" => Ok(PlanEntitlementState::Pending),
        "active" => Ok(PlanEntitlementState::Active),
        "suspended" => Ok(PlanEntitlementState::Suspended),
        _ => Err(PlanValueError),
    }
}

fn error_response(request_id: RequestId, error: PlanLoadError) -> Response {
    match error {
        PlanLoadError::Authentication(AuthenticationError::Forbidden) => crate::api_error_response(
            axum::http::StatusCode::FORBIDDEN,
            request_id,
            standard_api_error(ApiErrorCode::Forbidden, false),
        ),
        PlanLoadError::Authentication(AuthenticationError::InvalidCredential) => {
            unauthenticated_response(request_id)
        }
        PlanLoadError::Authentication(AuthenticationError::Unavailable)
        | PlanLoadError::Unavailable => crate::api_error_response(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            request_id,
            standard_api_error(ApiErrorCode::Unavailable, true),
        ),
    }
}

#[derive(sqlx::FromRow)]
pub(crate) struct StoredPlanEntitlement {
    pub(crate) plan_code: String,
    pub(crate) effective_state: String,
    pub(crate) revision: i64,
    pub(crate) effective_at_unix_ms: i64,
    pub(crate) access_until_unix_ms: Option<i64>,
    pub(crate) updated_at_unix_ms: i64,
    pub(crate) evaluated_at_unix_ms: i64,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("stored plan entitlement is invalid")]
pub(crate) struct PlanValueError;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub(crate) enum PlanCapabilityError {
    #[error("the current plan does not grant this operation")]
    Required,
    #[error("plan entitlement storage is unavailable")]
    Unavailable,
}

#[derive(Debug, Error)]
pub(crate) enum PlanLoadError {
    #[error(transparent)]
    Authentication(#[from] AuthenticationError),
    #[error("plan entitlement storage is unavailable")]
    Unavailable,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_values_and_capabilities_are_closed() {
        assert_eq!(plan_code("community").unwrap(), PlanCode::Community);
        assert_eq!(plan_code_value(PlanCode::Evaluation), "evaluation");
        assert!(plan_code("private-target").is_err());
        assert_eq!(
            capability_value(PlanCapability::ManagedSearch),
            "managed_search"
        );
    }
}
