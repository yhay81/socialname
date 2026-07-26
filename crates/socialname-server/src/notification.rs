use axum::{
    Json,
    extract::{Extension, Path, State, rejection::JsonRejection},
    http::{HeaderValue, StatusCode, header::LOCATION},
    response::{IntoResponse, Response},
};
use socialname_protocol::{
    ApiErrorCode, ApiKeyScope, NotificationAcknowledgementCreateRequest,
    NotificationAcknowledgementResource, NotificationDeliveryId, ProtocolVersion, RequestId,
    Validate, ValidationCode, ValidationErrors,
};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    ServerState,
    auth::{self, AuthenticatedPrincipal, AuthenticationError},
    standard_api_error, unauthenticated_response,
};

pub(crate) async fn acknowledge_delivery(
    State(state): State<ServerState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Path(delivery_id): Path<String>,
    payload: Result<Json<NotificationAcknowledgementCreateRequest>, JsonRejection>,
) -> Response {
    let delivery_id = match parse_delivery_id(&delivery_id) {
        Ok(value) => value,
        Err(error) => return error_response(request_id, error),
    };
    let request = match parse_json(payload) {
        Ok(request) => request,
        Err((status, errors)) => {
            return invalid_request_response(status, request_id, errors);
        }
    };
    if let Err(errors) = request.validate() {
        return invalid_request_response(StatusCode::BAD_REQUEST, request_id, errors);
    }

    match persist_acknowledgement(&state.database, &principal, delivery_id).await {
        Ok(AcknowledgementOutcome { resource, replayed }) => {
            let location = format!(
                "/v1/notification-deliveries/{}/acknowledgement",
                resource.delivery_id.as_str()
            );
            let mut response = (
                if replayed {
                    StatusCode::OK
                } else {
                    StatusCode::CREATED
                },
                Json(resource),
            )
                .into_response();
            if let Ok(location) = HeaderValue::from_str(&location) {
                response.headers_mut().insert(LOCATION, location);
            }
            response
        }
        Err(error) => error_response(request_id, error),
    }
}

pub(crate) async fn get_delivery_acknowledgement(
    State(state): State<ServerState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Path(delivery_id): Path<String>,
) -> Response {
    let delivery_id = match parse_delivery_id(&delivery_id) {
        Ok(value) => value,
        Err(error) => return error_response(request_id, error),
    };
    match load_acknowledgement(&state.database, &principal, delivery_id).await {
        Ok(resource) => Json(resource).into_response(),
        Err(error) => error_response(request_id, error),
    }
}

fn parse_json<T>(
    payload: Result<Json<T>, JsonRejection>,
) -> Result<T, (StatusCode, ValidationErrors)> {
    payload.map(|Json(value)| value).map_err(|rejection| {
        let too_large = rejection.status() == StatusCode::PAYLOAD_TOO_LARGE;
        (
            if too_large {
                StatusCode::PAYLOAD_TOO_LARGE
            } else {
                StatusCode::BAD_REQUEST
            },
            ValidationErrors::new(
                "body",
                if too_large {
                    ValidationCode::TooManyItems
                } else {
                    ValidationCode::InvalidFormat
                },
            ),
        )
    })
}

fn parse_delivery_id(value: &str) -> Result<Uuid, NotificationError> {
    Uuid::parse_str(value).map_err(|_| {
        NotificationError::InvalidRequest("delivery_id", ValidationCode::InvalidFormat)
    })
}

struct AcknowledgementOutcome {
    resource: NotificationAcknowledgementResource,
    replayed: bool,
}

async fn persist_acknowledgement(
    pool: &PgPool,
    principal: &AuthenticatedPrincipal,
    delivery_id: Uuid,
) -> Result<AcknowledgementOutcome, NotificationError> {
    let mut transaction =
        auth::begin_authorized_transaction(pool, principal, ApiKeyScope::NotificationWrite).await?;
    let delivery_state: Option<String> = sqlx::query_scalar(
        "SELECT delivery.state \
         FROM notification_deliveries AS delivery \
         WHERE delivery.tenant_id = $1 AND delivery.id = $2 \
           AND NOT EXISTS (\
               SELECT 1 FROM deletion_resource_matches AS matched \
               WHERE matched.tenant_id = delivery.tenant_id \
                 AND matched.resource_kind = 'notification_delivery' \
                 AND matched.resource_id = delivery.id\
           ) \
         FOR UPDATE",
    )
    .bind(principal.workspace_id)
    .bind(delivery_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| NotificationError::Unavailable)?;
    let Some(delivery_state) = delivery_state else {
        return Err(NotificationError::NotFound);
    };
    if delivery_state != "delivered" {
        return Err(NotificationError::Conflict);
    }

    let inserted_at_unix_ms: Option<i64> = sqlx::query_scalar(
        "INSERT INTO notification_acknowledgements (\
            delivery_id, tenant_id, acknowledged_by_membership_id, \
            acknowledged_by_api_key_id, acknowledged_at\
         ) VALUES ($1, $2, $3, $4, clock_timestamp()) \
         ON CONFLICT (delivery_id) DO NOTHING \
         RETURNING (EXTRACT(EPOCH FROM acknowledged_at) * 1000)::bigint",
    )
    .bind(delivery_id)
    .bind(principal.workspace_id)
    .bind(principal.membership_id)
    .bind(principal.api_key_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| NotificationError::Unavailable)?;
    let replayed = inserted_at_unix_ms.is_none();
    let acknowledged_at_unix_ms = match inserted_at_unix_ms {
        Some(value) => {
            sqlx::query(
                "INSERT INTO audit_events (\
                    id, tenant_id, actor_api_key_id, action, resource_kind, \
                    resource_id, occurred_at, details\
                 ) \
                 SELECT $1, tenant_id, acknowledged_by_api_key_id, \
                        'notification.delivery.acknowledged', \
                        'notification_delivery', delivery_id, \
                        acknowledged_at, '{}'::jsonb \
                 FROM notification_acknowledgements \
                 WHERE tenant_id = $2 AND delivery_id = $3",
            )
            .bind(Uuid::new_v4())
            .bind(principal.workspace_id)
            .bind(delivery_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| NotificationError::Unavailable)?;
            value
        }
        None => select_acknowledged_at(&mut transaction, principal.workspace_id, delivery_id)
            .await?
            .ok_or(NotificationError::Unavailable)?,
    };
    let resource = acknowledgement_resource(delivery_id, acknowledged_at_unix_ms)?;
    transaction
        .commit()
        .await
        .map_err(|_| NotificationError::Unavailable)?;
    Ok(AcknowledgementOutcome { resource, replayed })
}

async fn load_acknowledgement(
    pool: &PgPool,
    principal: &AuthenticatedPrincipal,
    delivery_id: Uuid,
) -> Result<NotificationAcknowledgementResource, NotificationError> {
    let mut transaction =
        auth::begin_authorized_transaction(pool, principal, ApiKeyScope::NotificationRead).await?;
    let acknowledged_at_unix_ms =
        select_acknowledged_at(&mut transaction, principal.workspace_id, delivery_id)
            .await?
            .ok_or(NotificationError::NotFound)?;
    let resource = acknowledgement_resource(delivery_id, acknowledged_at_unix_ms)?;
    transaction
        .commit()
        .await
        .map_err(|_| NotificationError::Unavailable)?;
    Ok(resource)
}

async fn select_acknowledged_at(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    delivery_id: Uuid,
) -> Result<Option<i64>, NotificationError> {
    sqlx::query_scalar(
        "SELECT (EXTRACT(EPOCH FROM acknowledgement.acknowledged_at) * 1000)::bigint \
         FROM notification_acknowledgements AS acknowledgement \
         JOIN notification_deliveries AS delivery \
           ON delivery.tenant_id = acknowledgement.tenant_id \
          AND delivery.id = acknowledgement.delivery_id \
         WHERE acknowledgement.tenant_id = $1 \
           AND acknowledgement.delivery_id = $2 \
           AND NOT EXISTS (\
               SELECT 1 FROM deletion_resource_matches AS matched \
               WHERE matched.tenant_id = delivery.tenant_id \
                 AND matched.resource_kind = 'notification_delivery' \
                 AND matched.resource_id = delivery.id\
           )",
    )
    .bind(tenant_id)
    .bind(delivery_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| NotificationError::Unavailable)
}

fn acknowledgement_resource(
    delivery_id: Uuid,
    acknowledged_at_unix_ms: i64,
) -> Result<NotificationAcknowledgementResource, NotificationError> {
    let resource = NotificationAcknowledgementResource {
        schema: ProtocolVersion::ApiV1,
        delivery_id: NotificationDeliveryId::new(delivery_id.to_string())
            .map_err(|_| NotificationError::Unavailable)?,
        acknowledged_at_unix_ms,
    };
    resource
        .validate()
        .map_err(|_| NotificationError::Unavailable)?;
    Ok(resource)
}

fn invalid_request_response(
    status: StatusCode,
    request_id: RequestId,
    errors: ValidationErrors,
) -> Response {
    (
        status,
        Json(socialname_protocol::ApiErrorResponse::invalid_request(
            request_id, errors,
        )),
    )
        .into_response()
}

fn error_response(request_id: RequestId, error: NotificationError) -> Response {
    match error {
        NotificationError::InvalidRequest(field, code) => invalid_request_response(
            StatusCode::BAD_REQUEST,
            request_id,
            ValidationErrors::new(field, code),
        ),
        NotificationError::NotFound => crate::api_error_response(
            StatusCode::NOT_FOUND,
            request_id,
            standard_api_error(ApiErrorCode::NotFound, false),
        ),
        NotificationError::Conflict => crate::api_error_response(
            StatusCode::CONFLICT,
            request_id,
            standard_api_error(ApiErrorCode::Conflict, false),
        ),
        NotificationError::Authentication(AuthenticationError::Forbidden) => {
            crate::api_error_response(
                StatusCode::FORBIDDEN,
                request_id,
                standard_api_error(ApiErrorCode::Forbidden, false),
            )
        }
        NotificationError::Authentication(AuthenticationError::InvalidCredential) => {
            unauthenticated_response(request_id)
        }
        NotificationError::Authentication(AuthenticationError::Unavailable)
        | NotificationError::Unavailable => crate::api_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            request_id,
            standard_api_error(ApiErrorCode::Unavailable, true),
        ),
    }
}

#[derive(Debug, thiserror::Error)]
enum NotificationError {
    #[error("notification request is invalid")]
    InvalidRequest(&'static str, ValidationCode),
    #[error("notification delivery was not found")]
    NotFound,
    #[error("notification delivery is not acknowledgement eligible")]
    Conflict,
    #[error(transparent)]
    Authentication(#[from] AuthenticationError),
    #[error("notification storage is unavailable")]
    Unavailable,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejected_delivery_id_is_not_echoed() {
        let private = "private-delivery-id";
        let error = parse_delivery_id(private).unwrap_err();
        assert!(!error.to_string().contains(private));
    }
}
