use axum::{
    Json,
    extract::{Extension, Path, State, rejection::JsonRejection},
    http::{HeaderValue, StatusCode, header::LOCATION},
    response::{IntoResponse, Response},
};
use socialname_protocol::{
    ApiErrorCode, ApiKeyScope, DeliveryErrorCode, NotificationDeliveryId,
    NotificationDeliveryState, NotificationEndpointId, PlanCapability, ProtocolVersion, RequestId,
    SearchCompletionDeliveryStatus, SearchCompletionWebhookCreateRequest,
    SearchCompletionWebhookResource, SearchCompletionWebhookSubscriptionState, SearchId,
    SearchState, Validate, ValidationCode, ValidationErrors,
};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    ServerState,
    auth::{self, AuthenticatedPrincipal, AuthenticationError},
    plan::{self, PlanCapabilityError},
    standard_api_error, unauthenticated_response,
};

pub(crate) async fn create_search_completion_webhook(
    State(state): State<ServerState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Path(search_id): Path<String>,
    payload: Result<Json<SearchCompletionWebhookCreateRequest>, JsonRejection>,
) -> Response {
    let search_id = match parse_uuid(&search_id, "search_id") {
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
    let endpoint_id = match parse_uuid(request.endpoint_id.as_str(), "endpoint_id") {
        Ok(value) => value,
        Err(error) => return error_response(request_id, error),
    };

    match persist_binding(&state.database, &principal, search_id, endpoint_id).await {
        Ok(BindingOutcome { resource, replayed }) => {
            let location = format!(
                "/v1/searches/{}/completion-webhook",
                resource.search_id.as_str()
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

pub(crate) async fn get_search_completion_webhook(
    State(state): State<ServerState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Path(search_id): Path<String>,
) -> Response {
    let search_id = match parse_uuid(&search_id, "search_id") {
        Ok(value) => value,
        Err(error) => return error_response(request_id, error),
    };
    match load_binding(&state.database, &principal, search_id).await {
        Ok(resource) => Json(resource).into_response(),
        Err(error) => error_response(request_id, error),
    }
}

pub(crate) async fn cancel_search_completion_webhook(
    State(state): State<ServerState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Path(search_id): Path<String>,
) -> Response {
    let search_id = match parse_uuid(&search_id, "search_id") {
        Ok(value) => value,
        Err(error) => return error_response(request_id, error),
    };
    match cancel_binding(&state.database, &principal, search_id).await {
        Ok(resource) => Json(resource).into_response(),
        Err(error) => error_response(request_id, error),
    }
}

struct BindingOutcome {
    resource: SearchCompletionWebhookResource,
    replayed: bool,
}

async fn persist_binding(
    pool: &PgPool,
    principal: &AuthenticatedPrincipal,
    search_id: Uuid,
    endpoint_id: Uuid,
) -> Result<BindingOutcome, SearchWebhookError> {
    let mut transaction =
        auth::begin_authorized_transaction(pool, principal, ApiKeyScope::SearchWrite).await?;
    let search_state: Option<String> = sqlx::query_scalar(
        "SELECT search.state \
         FROM searches AS search \
         WHERE search.tenant_id = $1 AND search.id = $2 \
           AND NOT EXISTS (\
               SELECT 1 FROM deletion_resource_matches AS matched \
               WHERE matched.tenant_id = search.tenant_id \
                 AND matched.resource_kind = 'search' \
                 AND matched.resource_id = search.id\
           ) \
         FOR UPDATE OF search",
    )
    .bind(principal.workspace_id)
    .bind(search_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| SearchWebhookError::Unavailable)?;
    let Some(search_state) = search_state else {
        return Err(SearchWebhookError::NotFound);
    };
    if search_state == "cancelled" {
        return Err(SearchWebhookError::Conflict);
    }

    let endpoint_available: Option<bool> = sqlx::query_scalar(
        "SELECT true FROM notification_endpoints AS endpoint \
         WHERE endpoint.tenant_id = $1 AND endpoint.id = $2 \
           AND endpoint.channel = 'webhook' AND endpoint.state = 'active'",
    )
    .bind(principal.workspace_id)
    .bind(endpoint_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| SearchWebhookError::Unavailable)?;
    if endpoint_available != Some(true) {
        return Err(SearchWebhookError::NotFound);
    }

    let inserted: Option<i64> = sqlx::query_scalar(
        "INSERT INTO search_completion_webhooks (\
            search_id, tenant_id, endpoint_id, created_by_api_key_id, \
            state, created_at\
         ) VALUES ($1, $2, $3, $4, 'active', clock_timestamp()) \
         ON CONFLICT (search_id) DO NOTHING \
         RETURNING (EXTRACT(EPOCH FROM created_at) * 1000)::bigint",
    )
    .bind(search_id)
    .bind(principal.workspace_id)
    .bind(endpoint_id)
    .bind(principal.api_key_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| SearchWebhookError::Unavailable)?;
    let replayed = inserted.is_none();
    if replayed {
        let existing_endpoint_id: Option<Uuid> = sqlx::query_scalar(
            "SELECT endpoint_id FROM search_completion_webhooks \
             WHERE tenant_id = $1 AND search_id = $2",
        )
        .bind(principal.workspace_id)
        .bind(search_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| SearchWebhookError::Unavailable)?;
        if existing_endpoint_id != Some(endpoint_id) {
            return Err(SearchWebhookError::Conflict);
        }
    } else {
        plan::require_plan_capability(
            &mut transaction,
            principal.workspace_id,
            PlanCapability::ManagedSearch,
        )
        .await
        .map_err(|error| match error {
            PlanCapabilityError::Required => SearchWebhookError::EntitlementRequired,
            PlanCapabilityError::Unavailable => SearchWebhookError::Unavailable,
        })?;
        sqlx::query(
            "INSERT INTO audit_events (\
                id, tenant_id, actor_api_key_id, action, resource_kind, \
                resource_id, occurred_at, details\
             ) VALUES (\
                $1, $2, $3, 'search_completion.webhook.created', \
                'search_completion_webhook', $4, clock_timestamp(), \
                '{}'::jsonb\
             )",
        )
        .bind(Uuid::new_v4())
        .bind(principal.workspace_id)
        .bind(principal.api_key_id)
        .bind(search_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| SearchWebhookError::Unavailable)?;
    }

    let resource = select_binding(&mut transaction, principal.workspace_id, search_id).await?;
    transaction
        .commit()
        .await
        .map_err(|_| SearchWebhookError::Unavailable)?;
    Ok(BindingOutcome { resource, replayed })
}

async fn load_binding(
    pool: &PgPool,
    principal: &AuthenticatedPrincipal,
    search_id: Uuid,
) -> Result<SearchCompletionWebhookResource, SearchWebhookError> {
    let mut transaction =
        auth::begin_authorized_transaction(pool, principal, ApiKeyScope::SearchRead).await?;
    let resource = select_binding(&mut transaction, principal.workspace_id, search_id).await?;
    transaction
        .commit()
        .await
        .map_err(|_| SearchWebhookError::Unavailable)?;
    Ok(resource)
}

async fn cancel_binding(
    pool: &PgPool,
    principal: &AuthenticatedPrincipal,
    search_id: Uuid,
) -> Result<SearchCompletionWebhookResource, SearchWebhookError> {
    let mut transaction =
        auth::begin_authorized_transaction(pool, principal, ApiKeyScope::SearchWrite).await?;
    let binding_state: Option<String> = sqlx::query_scalar(
        "SELECT binding.state \
         FROM search_completion_webhooks AS binding \
         JOIN searches AS search \
           ON search.tenant_id = binding.tenant_id \
          AND search.id = binding.search_id \
         WHERE binding.tenant_id = $1 AND binding.search_id = $2 \
           AND NOT EXISTS (\
               SELECT 1 FROM deletion_resource_matches AS matched \
               WHERE matched.tenant_id = search.tenant_id \
                 AND matched.resource_kind = 'search' \
                 AND matched.resource_id = search.id\
           ) \
         FOR UPDATE OF binding",
    )
    .bind(principal.workspace_id)
    .bind(search_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| SearchWebhookError::Unavailable)?;
    let Some(binding_state) = binding_state else {
        return Err(SearchWebhookError::NotFound);
    };
    if binding_state == "active" {
        sqlx::query(
            "UPDATE notification_deliveries \
             SET state = 'cancelled', next_attempt_at = NULL, \
                 delivered_at = NULL, last_error_code = NULL, \
                 lease_owner = NULL, lease_started_at = NULL, \
                 lease_expires_at = NULL \
             WHERE tenant_id = $1 AND search_id = $2 \
               AND delivery_kind = 'search_completion' \
               AND state IN ('queued', 'delivering', 'retry_scheduled')",
        )
        .bind(principal.workspace_id)
        .bind(search_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| SearchWebhookError::Unavailable)?;
        sqlx::query(
            "UPDATE search_completion_webhooks \
             SET state = 'cancelled', cancelled_at = clock_timestamp() \
             WHERE tenant_id = $1 AND search_id = $2 AND state = 'active'",
        )
        .bind(principal.workspace_id)
        .bind(search_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| SearchWebhookError::Unavailable)?;
        sqlx::query(
            "INSERT INTO audit_events (\
                id, tenant_id, actor_api_key_id, action, resource_kind, \
                resource_id, occurred_at, details\
             ) VALUES (\
                $1, $2, $3, 'search_completion.webhook.cancelled', \
                'search_completion_webhook', $4, clock_timestamp(), \
                '{}'::jsonb\
             )",
        )
        .bind(Uuid::new_v4())
        .bind(principal.workspace_id)
        .bind(principal.api_key_id)
        .bind(search_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| SearchWebhookError::Unavailable)?;
    }
    let resource = select_binding(&mut transaction, principal.workspace_id, search_id).await?;
    transaction
        .commit()
        .await
        .map_err(|_| SearchWebhookError::Unavailable)?;
    Ok(resource)
}

async fn select_binding(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    search_id: Uuid,
) -> Result<SearchCompletionWebhookResource, SearchWebhookError> {
    let row: Option<StoredBinding> = sqlx::query_as(
        "SELECT \
            binding.endpoint_id, search.state AS search_state, \
            binding.state AS subscription_state, \
            (EXTRACT(EPOCH FROM binding.created_at) * 1000)::bigint \
                AS created_at_unix_ms, \
            (EXTRACT(EPOCH FROM binding.cancelled_at) * 1000)::bigint \
                AS cancelled_at_unix_ms, \
            delivery.id AS delivery_id, delivery.state AS delivery_state, \
            delivery.attempt_count, \
            (EXTRACT(EPOCH FROM delivery.created_at) * 1000)::bigint \
                AS queued_at_unix_ms, \
            (EXTRACT(EPOCH FROM delivery.next_attempt_at) * 1000)::bigint \
                AS next_attempt_at_unix_ms, \
            (EXTRACT(EPOCH FROM delivery.delivered_at) * 1000)::bigint \
                AS delivered_at_unix_ms, \
            delivery.last_error_code \
         FROM search_completion_webhooks AS binding \
         JOIN searches AS search \
           ON search.tenant_id = binding.tenant_id \
          AND search.id = binding.search_id \
         LEFT JOIN notification_deliveries AS delivery \
           ON delivery.tenant_id = binding.tenant_id \
          AND delivery.search_id = binding.search_id \
          AND delivery.endpoint_id = binding.endpoint_id \
          AND delivery.delivery_kind = 'search_completion' \
         WHERE binding.tenant_id = $1 AND binding.search_id = $2 \
           AND NOT EXISTS (\
               SELECT 1 FROM deletion_resource_matches AS matched \
               WHERE matched.tenant_id = search.tenant_id \
                 AND matched.resource_kind = 'search' \
                 AND matched.resource_id = search.id\
           )",
    )
    .bind(tenant_id)
    .bind(search_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| SearchWebhookError::Unavailable)?;
    let row = row.ok_or(SearchWebhookError::NotFound)?;
    binding_resource(search_id, row)
}

fn binding_resource(
    search_id: Uuid,
    row: StoredBinding,
) -> Result<SearchCompletionWebhookResource, SearchWebhookError> {
    let delivery = match row.delivery_id {
        Some(delivery_id) => Some(SearchCompletionDeliveryStatus {
            delivery_id: NotificationDeliveryId::new(delivery_id.to_string())
                .map_err(|_| SearchWebhookError::Unavailable)?,
            state: delivery_state(
                row.delivery_state
                    .as_deref()
                    .ok_or(SearchWebhookError::Unavailable)?,
            )?,
            attempt_count: u32::try_from(row.attempt_count.ok_or(SearchWebhookError::Unavailable)?)
                .map_err(|_| SearchWebhookError::Unavailable)?,
            queued_at_unix_ms: row
                .queued_at_unix_ms
                .ok_or(SearchWebhookError::Unavailable)?,
            next_attempt_at_unix_ms: row.next_attempt_at_unix_ms,
            delivered_at_unix_ms: row.delivered_at_unix_ms,
            last_error_code: row
                .last_error_code
                .map(DeliveryErrorCode::new)
                .transpose()
                .map_err(|_| SearchWebhookError::Unavailable)?,
        }),
        None => None,
    };
    let resource = SearchCompletionWebhookResource {
        schema: ProtocolVersion::ApiV1,
        search_id: SearchId::new(search_id.to_string())
            .map_err(|_| SearchWebhookError::Unavailable)?,
        endpoint_id: NotificationEndpointId::new(row.endpoint_id.to_string())
            .map_err(|_| SearchWebhookError::Unavailable)?,
        search_state: search_state(&row.search_state)?,
        subscription_state: subscription_state(&row.subscription_state)?,
        created_at_unix_ms: row.created_at_unix_ms,
        cancelled_at_unix_ms: row.cancelled_at_unix_ms,
        delivery,
    };
    resource
        .validate()
        .map_err(|_| SearchWebhookError::Unavailable)?;
    Ok(resource)
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

fn parse_uuid(value: &str, field: &'static str) -> Result<Uuid, SearchWebhookError> {
    Uuid::parse_str(value)
        .map_err(|_| SearchWebhookError::InvalidRequest(field, ValidationCode::InvalidFormat))
}

fn search_state(value: &str) -> Result<SearchState, SearchWebhookError> {
    match value {
        "accepted" => Ok(SearchState::Accepted),
        "running" => Ok(SearchState::Running),
        "completed" => Ok(SearchState::Completed),
        "cancelled" => Ok(SearchState::Cancelled),
        "failed" => Ok(SearchState::Failed),
        _ => Err(SearchWebhookError::Unavailable),
    }
}

fn subscription_state(
    value: &str,
) -> Result<SearchCompletionWebhookSubscriptionState, SearchWebhookError> {
    match value {
        "active" => Ok(SearchCompletionWebhookSubscriptionState::Active),
        "cancelled" => Ok(SearchCompletionWebhookSubscriptionState::Cancelled),
        _ => Err(SearchWebhookError::Unavailable),
    }
}

fn delivery_state(value: &str) -> Result<NotificationDeliveryState, SearchWebhookError> {
    match value {
        "queued" => Ok(NotificationDeliveryState::Queued),
        "delivering" => Ok(NotificationDeliveryState::Delivering),
        "retry_scheduled" => Ok(NotificationDeliveryState::RetryScheduled),
        "delivered" => Ok(NotificationDeliveryState::Delivered),
        "permanently_failed" => Ok(NotificationDeliveryState::PermanentlyFailed),
        "cancelled" => Ok(NotificationDeliveryState::Cancelled),
        _ => Err(SearchWebhookError::Unavailable),
    }
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

fn error_response(request_id: RequestId, error: SearchWebhookError) -> Response {
    match error {
        SearchWebhookError::InvalidRequest(field, code) => invalid_request_response(
            StatusCode::BAD_REQUEST,
            request_id,
            ValidationErrors::new(field, code),
        ),
        SearchWebhookError::NotFound => crate::api_error_response(
            StatusCode::NOT_FOUND,
            request_id,
            standard_api_error(ApiErrorCode::NotFound, false),
        ),
        SearchWebhookError::Conflict => crate::api_error_response(
            StatusCode::CONFLICT,
            request_id,
            standard_api_error(ApiErrorCode::Conflict, false),
        ),
        SearchWebhookError::EntitlementRequired
        | SearchWebhookError::Authentication(AuthenticationError::Forbidden) => {
            crate::api_error_response(
                StatusCode::FORBIDDEN,
                request_id,
                standard_api_error(ApiErrorCode::Forbidden, false),
            )
        }
        SearchWebhookError::Authentication(AuthenticationError::InvalidCredential) => {
            unauthenticated_response(request_id)
        }
        SearchWebhookError::Authentication(AuthenticationError::Unavailable)
        | SearchWebhookError::Unavailable => crate::api_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            request_id,
            standard_api_error(ApiErrorCode::Unavailable, true),
        ),
    }
}

#[derive(FromRow)]
struct StoredBinding {
    endpoint_id: Uuid,
    search_state: String,
    subscription_state: String,
    created_at_unix_ms: i64,
    cancelled_at_unix_ms: Option<i64>,
    delivery_id: Option<Uuid>,
    delivery_state: Option<String>,
    attempt_count: Option<i32>,
    queued_at_unix_ms: Option<i64>,
    next_attempt_at_unix_ms: Option<i64>,
    delivered_at_unix_ms: Option<i64>,
    last_error_code: Option<String>,
}

#[derive(Debug, thiserror::Error)]
enum SearchWebhookError {
    #[error("search-completion webhook request is invalid")]
    InvalidRequest(&'static str, ValidationCode),
    #[error("search-completion webhook was not found")]
    NotFound,
    #[error("search-completion webhook conflicts with current state")]
    Conflict,
    #[error("the current plan does not grant managed search")]
    EntitlementRequired,
    #[error(transparent)]
    Authentication(#[from] AuthenticationError),
    #[error("search-completion webhook storage is unavailable")]
    Unavailable,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_fail_without_reflecting_private_values() {
        let private = "private-search-webhook";
        let error = parse_uuid(private, "search_id").unwrap_err();
        assert!(!error.to_string().contains(private));
    }
}
