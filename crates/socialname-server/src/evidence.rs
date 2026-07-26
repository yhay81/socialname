use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use socialname_protocol::{
    ApiErrorCode, ApiKeyScope, EvidenceCapsuleResource, EvidenceResearchExtension, RequestId,
    Validate, ValidationCode, ValidationErrors,
};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::{
    ServerState,
    auth::{self, AuthenticatedPrincipal, AuthenticationError},
    standard_api_error, unauthenticated_response,
};

pub(crate) async fn get_evidence_capsule(
    State(state): State<ServerState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Path(observation_id): Path<String>,
) -> Response {
    let observation_id = match Uuid::parse_str(&observation_id) {
        Ok(observation_id) => observation_id,
        Err(_) => {
            return error_response(
                request_id,
                EvidenceError::InvalidRequest("observation_id", ValidationCode::InvalidFormat),
            );
        }
    };
    match load_evidence_capsule(&state.database, &principal, observation_id).await {
        Ok(resource) => Json(resource).into_response(),
        Err(error) => error_response(request_id, error),
    }
}

async fn load_evidence_capsule(
    pool: &PgPool,
    principal: &AuthenticatedPrincipal,
    observation_id: Uuid,
) -> Result<EvidenceCapsuleResource, EvidenceError> {
    let mut transaction =
        auth::begin_authorized_transaction(pool, principal, ApiKeyScope::EvidenceRead).await?;
    let stored: Option<StoredEvidenceCapsule> = sqlx::query_as(
        "SELECT capsule.structured_payload, \
                CASE \
                    WHEN capsule.research_retained_until > clock_timestamp() \
                    THEN capsule.research_excerpt \
                END AS research_excerpt, \
                CASE \
                    WHEN capsule.research_retained_until > clock_timestamp() \
                    THEN (EXTRACT(EPOCH FROM capsule.research_retained_until) * 1000)::bigint \
                END AS research_retained_until_unix_ms \
         FROM evidence_capsules AS capsule \
         WHERE capsule.tenant_id = $1 \
           AND capsule.observation_id = $2 \
           AND capsule.structured_payload IS NOT NULL \
           AND capsule.structured_retained_until > clock_timestamp() \
           AND NOT EXISTS (\
               SELECT 1 FROM deletion_resource_matches AS matched \
               WHERE matched.tenant_id = capsule.tenant_id \
                 AND matched.resource_id IN (capsule.id, capsule.observation_id) \
                 AND matched.resource_kind IN ('evidence_capsule', 'observation')\
           )",
    )
    .bind(principal.workspace_id)
    .bind(observation_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| EvidenceError::Unavailable)?;
    let Some(stored) = stored else {
        transaction
            .commit()
            .await
            .map_err(|_| EvidenceError::Unavailable)?;
        return Err(EvidenceError::NotFound);
    };
    let mut resource: EvidenceCapsuleResource = serde_json::from_value(stored.structured_payload)
        .map_err(|_| EvidenceError::Unavailable)?;
    match (
        stored.research_excerpt,
        stored.research_retained_until_unix_ms,
    ) {
        (Some(sanitized_excerpt), Some(deadline)) => {
            resource.research_extension = Some(EvidenceResearchExtension { sanitized_excerpt });
            resource.research_retained_until_unix_ms = Some(deadline);
        }
        (None, None) => {}
        _ => return Err(EvidenceError::Unavailable),
    }
    resource
        .validate()
        .map_err(|_| EvidenceError::Unavailable)?;
    transaction
        .commit()
        .await
        .map_err(|_| EvidenceError::Unavailable)?;
    Ok(resource)
}

fn error_response(request_id: RequestId, error: EvidenceError) -> Response {
    match error {
        EvidenceError::InvalidRequest(field, code) => (
            StatusCode::BAD_REQUEST,
            Json(socialname_protocol::ApiErrorResponse::invalid_request(
                request_id,
                ValidationErrors::new(field, code),
            )),
        )
            .into_response(),
        EvidenceError::NotFound => crate::api_error_response(
            StatusCode::NOT_FOUND,
            request_id,
            standard_api_error(ApiErrorCode::NotFound, false),
        ),
        EvidenceError::Authentication(AuthenticationError::Forbidden) => crate::api_error_response(
            StatusCode::FORBIDDEN,
            request_id,
            standard_api_error(ApiErrorCode::Forbidden, false),
        ),
        EvidenceError::Authentication(AuthenticationError::InvalidCredential) => {
            unauthenticated_response(request_id)
        }
        EvidenceError::Authentication(AuthenticationError::Unavailable)
        | EvidenceError::Unavailable => crate::api_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            request_id,
            standard_api_error(ApiErrorCode::Unavailable, true),
        ),
    }
}

#[derive(FromRow)]
struct StoredEvidenceCapsule {
    structured_payload: serde_json::Value,
    research_excerpt: Option<String>,
    research_retained_until_unix_ms: Option<i64>,
}

#[derive(Debug, thiserror::Error)]
enum EvidenceError {
    #[error("evidence request is invalid")]
    InvalidRequest(&'static str, ValidationCode),
    #[error("evidence capsule was not found")]
    NotFound,
    #[error(transparent)]
    Authentication(#[from] AuthenticationError),
    #[error("evidence storage is unavailable")]
    Unavailable,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_observation_identifier_is_not_echoed() {
        let private = "private-observation-identifier";
        let error = Uuid::parse_str(private)
            .map_err(|_| {
                EvidenceError::InvalidRequest("observation_id", ValidationCode::InvalidFormat)
            })
            .unwrap_err();
        assert!(!error.to_string().contains(private));
    }
}
