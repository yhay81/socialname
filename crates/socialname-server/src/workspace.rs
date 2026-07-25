use socialname_protocol::{
    ApiKeyId, ApiKeyState, AuthenticatedApiKeyResource, ProtocolVersion, Validate, WorkspaceId,
    WorkspaceResource, WorkspaceState,
};
use sqlx::PgPool;
use thiserror::Error;

use crate::auth::AuthenticatedPrincipal;

pub(crate) async fn load_workspace(
    pool: &PgPool,
    principal: &AuthenticatedPrincipal,
) -> Result<WorkspaceResource, WorkspaceLoadError> {
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| WorkspaceLoadError::Unavailable)?;
    sqlx::query("SELECT set_config('socialname.tenant_id', $1, true)")
        .bind(principal.workspace_id.to_string())
        .execute(&mut *transaction)
        .await
        .map_err(|_| WorkspaceLoadError::Unavailable)?;
    let workspace: Option<(String, String, String)> = sqlx::query_as(
        "SELECT tenant.id::text, tenant.slug, tenant.display_name \
         FROM tenants AS tenant \
         JOIN api_keys AS key ON key.tenant_id = tenant.id \
         WHERE tenant.id = $1 AND tenant.state = 'active' \
           AND key.id = $2 AND key.state = 'active' \
           AND 'workspace:read' = ANY(key.scopes) \
           AND (key.expires_at IS NULL OR key.expires_at > clock_timestamp())",
    )
    .bind(principal.workspace_id)
    .bind(principal.api_key_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| WorkspaceLoadError::Unavailable)?;
    transaction
        .commit()
        .await
        .map_err(|_| WorkspaceLoadError::Unavailable)?;
    let Some((workspace_id, slug, display_name)) = workspace else {
        return Err(WorkspaceLoadError::Unauthenticated);
    };
    let resource = WorkspaceResource {
        schema: ProtocolVersion::ApiV1,
        workspace_id: WorkspaceId::new(workspace_id)
            .map_err(|_| WorkspaceLoadError::Unavailable)?,
        slug,
        display_name,
        state: WorkspaceState::Active,
        authenticated_api_key: AuthenticatedApiKeyResource {
            api_key_id: ApiKeyId::new(principal.api_key_id.to_string())
                .map_err(|_| WorkspaceLoadError::Unavailable)?,
            key_prefix: principal.key_prefix.clone(),
            scopes: principal.scopes.clone(),
            state: ApiKeyState::Active,
            expires_at_unix_ms: principal.expires_at_unix_ms,
        },
    };
    resource
        .validate()
        .map_err(|_| WorkspaceLoadError::Unavailable)?;
    Ok(resource)
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub(crate) enum WorkspaceLoadError {
    #[error("workspace credential is no longer active")]
    Unauthenticated,
    #[error("workspace storage is unavailable")]
    Unavailable,
}
