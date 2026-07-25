use socialname_protocol::{
    ApiKeyId, ApiKeyState, AuthenticatedApiKeyResource, ProtocolVersion, Validate, WorkspaceId,
    WorkspaceResource, WorkspaceState,
};
use sqlx::PgPool;
use thiserror::Error;

use crate::auth::{self, AuthenticatedPrincipal, AuthenticationError};

pub(crate) async fn load_workspace(
    pool: &PgPool,
    principal: &AuthenticatedPrincipal,
) -> Result<WorkspaceResource, WorkspaceLoadError> {
    let mut transaction = auth::begin_authorized_transaction(
        pool,
        principal,
        socialname_protocol::ApiKeyScope::WorkspaceRead,
    )
    .await
    .map_err(WorkspaceLoadError::from_authentication)?;
    let workspace: Option<(String, String, String)> = sqlx::query_as(
        "SELECT tenant.id::text, tenant.slug, tenant.display_name \
         FROM tenants AS tenant \
         WHERE tenant.id = $1 AND tenant.state = 'active'",
    )
    .bind(principal.workspace_id)
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
    #[error("workspace credential no longer grants this operation")]
    Forbidden,
    #[error("workspace storage is unavailable")]
    Unavailable,
}

impl WorkspaceLoadError {
    fn from_authentication(error: AuthenticationError) -> Self {
        match error {
            AuthenticationError::InvalidCredential => Self::Unauthenticated,
            AuthenticationError::Forbidden => Self::Forbidden,
            AuthenticationError::Unavailable => Self::Unavailable,
        }
    }
}
