#![forbid(unsafe_code)]

mod api_key;
mod auth;
mod config;
mod consent;
mod database;
mod deletion;
mod deletion_operator;
mod developer;
mod evidence;
mod monitoring;
mod notification;
mod operations;
mod plan;
mod plan_operator;
mod rule_registry_operator;
mod search;
mod search_webhook;
mod target_deletion_operator;
mod team;
mod watch;
mod workspace;
mod workspace_operator;

use std::{
    future::Future,
    io,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use axum::{
    Extension, Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Request, State},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_LENGTH, WWW_AUTHENTICATE},
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Serialize;
use socialname_protocol::{
    ApiError, ApiErrorCode, ApiErrorResponse, ApiKeyScope, ProtocolVersion, RequestId, Validate,
    ValidationCode, ValidationErrors,
};
use sqlx::PgPool;
use tokio::sync::Semaphore;
use tower::{ServiceBuilder, limit::ConcurrencyLimitLayer};
use tracing::Instrument;

pub use config::{
    BIND_ENV, ConfigError, EXPECTED_RESTORE_LEDGER_ID_ENV, MAXIMUM_BODY_BYTES_ENV,
    MAXIMUM_IN_FLIGHT_ENV, REQUEST_TIMEOUT_ENV, SUPPRESSION_HMAC_KEY_ENV, ServerConfig,
    SuppressionHmacKey,
};
pub use database::{
    DATABASE_URL_ENV, DatabaseError, MIGRATOR, RUNTIME_DATABASE_URL_ENV,
    connect_runtime_database_from_env, migrate_database, migrate_database_from_env,
};
pub use deletion_operator::{
    BackupExpiryVerificationInput, BackupExpiryVerificationOutput, DeletionOperatorError,
    RestoreLedgerArtifact, RestoreLedgerEntry, RestoreLedgerPayload, RestoreLedgerReplayOutput,
    export_restore_ledger, export_restore_ledger_from_env, replay_restore_ledger,
    replay_restore_ledger_from_env, verify_backup_expiry, verify_backup_expiry_from_env,
};
pub use plan_operator::{
    BILLING_EVENT_ID_ENV, PLAN_ACCESS_STATE_ENV, PLAN_ACCESS_UNTIL_ENV, PLAN_CODE_ENV,
    PLAN_EFFECTIVE_AT_ENV, PLAN_EXPECTED_REVISION_ENV, PLAN_WORKSPACE_ID_ENV, PlanOperatorError,
    PlanReconciliation, PlanReconciliationOutput, ReconciledAccessState,
    reconcile_plan_entitlement, reconcile_plan_entitlement_from_env,
};
pub use rule_registry_operator::{
    AppliedRulePack, AppliedRulePackOutput, INITIAL_RULE_TRUST_FILE_ENV, INITIAL_RULE_TRUST_ID_ENV,
    InitialRulePackTrust, RULE_METADATA_FILE_ENV, RULES_DIRECTORY_ENV, RuleRegistryError,
    apply_rule_pack_metadata, apply_rule_pack_metadata_from_env,
};
pub use target_deletion_operator::{
    TargetDeletionOperatorError, TargetDeletionSelector, VerifiedTargetDeletionInput,
    VerifiedTargetDeletionOutput, request_target_deletion_from_env,
    request_verified_target_deletion,
};
pub use workspace_operator::{
    API_KEY_DAILY_TARGET_LIMIT_ENV, API_KEY_EXPIRES_AT_ENV, API_KEY_ID_ENV, API_KEY_SCOPES_ENV,
    DAILY_TARGET_LIMIT_ENV, DeveloperQuotaPolicyOutput, IssuedApiKey, MEMBERSHIP_ID_ENV,
    MEMBERSHIP_SUBJECT_ENV, WORKSPACE_DISPLAY_NAME_ENV, WORKSPACE_ID_ENV, WORKSPACE_SLUG_ENV,
    WorkspaceOperatorError, bootstrap_workspace_from_env, issue_api_key_from_env,
    revoke_api_key_from_env, set_developer_quota_from_env,
};

const X_REQUEST_ID: &str = "x-request-id";
const X_CONTENT_TYPE_OPTIONS: &str = "x-content-type-options";

#[derive(Clone)]
struct ServerState {
    config: ServerConfig,
    database: PgPool,
    request_sequence: Arc<AtomicU64>,
    sse_connections: Arc<Semaphore>,
}

impl ServerState {
    fn new(config: ServerConfig, database: PgPool) -> Self {
        let maximum_sse_connections = config.maximum_in_flight();
        Self {
            config,
            database,
            request_sequence: Arc::new(AtomicU64::new(1)),
            sse_connections: Arc::new(Semaphore::new(maximum_sse_connections)),
        }
    }

    fn next_request_id(&self) -> RequestId {
        let sequence = self.request_sequence.fetch_add(1, Ordering::Relaxed);
        RequestId::new(format!("request_{}_{}", std::process::id(), sequence))
            .expect("generated request IDs satisfy the closed protocol format")
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum HealthStatus {
    Live,
    Ready,
    NotReady,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    schema: ProtocolVersion,
    service: &'static str,
    version: &'static str,
    status: HealthStatus,
}

#[derive(Clone)]
struct ProtectedRouteState {
    server: ServerState,
    required_scope: ApiKeyScope,
}

fn server_required_scope(operation_id: &str) -> ApiKeyScope {
    match operation_id {
        "getWorkspace"
        | "getPlanEntitlement"
        | "getOrganization"
        | "listOrganizationMembers"
        | "createOrganizationMember"
        | "updateOrganizationMember"
        | "getOrganizationRetentionPolicy"
        | "updateOrganizationRetentionPolicy" => ApiKeyScope::WorkspaceRead,
        "createSearch"
        | "cancelSearch"
        | "createSearchCompletionWebhook"
        | "cancelSearchCompletionWebhook" => ApiKeyScope::SearchWrite,
        "listSearches" | "getSearch" | "streamSearchEvents" | "getSearchCompletionWebhook" => {
            ApiKeyScope::SearchRead
        }
        "exportSearch" => ApiKeyScope::DataExport,
        "createWatch" | "updateWatch" | "deleteWatch" => ApiKeyScope::WatchWrite,
        "listWatches" | "getWatch" | "listWatchTransitions" | "listTransitionReviews" => {
            ApiKeyScope::WatchRead
        }
        "updateTransitionReview" => ApiKeyScope::WatchWrite,
        "createConsentGrant" | "withdrawConsentGrant" => ApiKeyScope::ConsentWrite,
        "listConsentGrants" | "getConsentGrant" => ApiKeyScope::ConsentRead,
        "getEvidenceCapsule" => ApiKeyScope::EvidenceRead,
        "createContributorDeletion" | "getDeletionRequest" | "getDeletionReceipt" => {
            ApiKeyScope::DataDelete
        }
        "createNotificationAcknowledgement" => ApiKeyScope::NotificationWrite,
        "getNotificationAcknowledgement" => ApiKeyScope::NotificationRead,
        "getOperationalReport" | "listOrganizationAuditEvents" => ApiKeyScope::OperationsRead,
        "getDeveloperReport" => ApiKeyScope::UsageRead,
        _ => panic!("server route must name one published operation"),
    }
}

pub fn build_router(config: ServerConfig, database: PgPool) -> Router {
    let state = ServerState::new(config, database);
    let workspace_routes = Router::new()
        .route("/v1/workspace", get(workspace_resource))
        .route("/v1/workspace/plan", get(plan::get_plan_entitlement))
        .route_layer(middleware::from_fn_with_state(
            ProtectedRouteState {
                server: state.clone(),
                required_scope: server_required_scope("getWorkspace"),
            },
            authenticate_request,
        ));
    let organization_routes = Router::new()
        .route("/v1/organization", get(team::get_organization))
        .route(
            "/v1/organization/members",
            get(team::list_organization_members).post(team::create_organization_member),
        )
        .route(
            "/v1/organization/members/{membership_id}",
            axum::routing::patch(team::patch_organization_member),
        )
        .route(
            "/v1/organization/retention-policy",
            get(team::get_organization_retention_policy)
                .patch(team::patch_organization_retention_policy),
        )
        .route_layer(middleware::from_fn_with_state(
            ProtectedRouteState {
                server: state.clone(),
                required_scope: server_required_scope("getOrganization"),
            },
            authenticate_request,
        ));
    let organization_audit_routes = Router::new()
        .route(
            "/v1/organization/audit-events",
            get(team::list_organization_audit_events),
        )
        .route_layer(middleware::from_fn_with_state(
            ProtectedRouteState {
                server: state.clone(),
                required_scope: server_required_scope("listOrganizationAuditEvents"),
            },
            authenticate_request,
        ));
    let review_read_routes = Router::new()
        .route("/v1/reviews", get(team::list_transition_reviews))
        .route_layer(middleware::from_fn_with_state(
            ProtectedRouteState {
                server: state.clone(),
                required_scope: server_required_scope("listTransitionReviews"),
            },
            authenticate_request,
        ));
    let review_write_routes = Router::new()
        .route(
            "/v1/reviews/{review_id}",
            axum::routing::patch(team::patch_transition_review),
        )
        .route_layer(middleware::from_fn_with_state(
            ProtectedRouteState {
                server: state.clone(),
                required_scope: server_required_scope("updateTransitionReview"),
            },
            authenticate_request,
        ));
    let search_create_routes = Router::new()
        .route("/v1/searches", axum::routing::post(search::create_search))
        .route_layer(middleware::from_fn_with_state(
            ProtectedRouteState {
                server: state.clone(),
                required_scope: server_required_scope("createSearch"),
            },
            authenticate_request,
        ));
    let search_read_routes = Router::new()
        .route("/v1/searches", get(search::list_searches))
        .route("/v1/searches/{search_id}", get(search::get_search))
        .route(
            "/v1/searches/{search_id}/events",
            get(search::search_events),
        )
        .route_layer(middleware::from_fn_with_state(
            ProtectedRouteState {
                server: state.clone(),
                required_scope: server_required_scope("getSearch"),
            },
            authenticate_request,
        ));
    let search_export_routes = Router::new()
        .route(
            "/v1/searches/{search_id}/export",
            get(search::export_search),
        )
        .route_layer(middleware::from_fn_with_state(
            ProtectedRouteState {
                server: state.clone(),
                required_scope: server_required_scope("exportSearch"),
            },
            authenticate_request,
        ));
    let search_cancel_routes = Router::new()
        .route(
            "/v1/searches/{search_id}",
            axum::routing::delete(search::cancel_search),
        )
        .route_layer(middleware::from_fn_with_state(
            ProtectedRouteState {
                server: state.clone(),
                required_scope: server_required_scope("cancelSearch"),
            },
            authenticate_request,
        ));
    let search_webhook_write_routes = Router::new()
        .route(
            "/v1/searches/{search_id}/completion-webhook",
            axum::routing::post(search_webhook::create_search_completion_webhook)
                .delete(search_webhook::cancel_search_completion_webhook),
        )
        .route_layer(middleware::from_fn_with_state(
            ProtectedRouteState {
                server: state.clone(),
                required_scope: server_required_scope("createSearchCompletionWebhook"),
            },
            authenticate_request,
        ));
    let search_webhook_read_routes = Router::new()
        .route(
            "/v1/searches/{search_id}/completion-webhook",
            get(search_webhook::get_search_completion_webhook),
        )
        .route_layer(middleware::from_fn_with_state(
            ProtectedRouteState {
                server: state.clone(),
                required_scope: server_required_scope("getSearchCompletionWebhook"),
            },
            authenticate_request,
        ));
    let watch_write_routes = Router::new()
        .route("/v1/watches", axum::routing::post(watch::create_watch))
        .route(
            "/v1/watches/{watch_id}",
            axum::routing::patch(watch::patch_watch).delete(watch::delete_watch),
        )
        .route_layer(middleware::from_fn_with_state(
            ProtectedRouteState {
                server: state.clone(),
                required_scope: server_required_scope("createWatch"),
            },
            authenticate_request,
        ));
    let watch_read_routes = Router::new()
        .route("/v1/watches", get(monitoring::list_watches))
        .route("/v1/watches/{watch_id}", get(watch::get_watch))
        .route(
            "/v1/watches/{watch_id}/transitions",
            get(monitoring::list_watch_transitions),
        )
        .route_layer(middleware::from_fn_with_state(
            ProtectedRouteState {
                server: state.clone(),
                required_scope: server_required_scope("listWatches"),
            },
            authenticate_request,
        ));
    let consent_write_routes = Router::new()
        .route(
            "/v1/consent-grants",
            axum::routing::post(consent::create_consent_grant),
        )
        .route(
            "/v1/consent-grants/{consent_grant_id}/withdrawals",
            axum::routing::post(consent::withdraw_consent_grant),
        )
        .route_layer(middleware::from_fn_with_state(
            ProtectedRouteState {
                server: state.clone(),
                required_scope: server_required_scope("createConsentGrant"),
            },
            authenticate_request,
        ));
    let consent_read_routes = Router::new()
        .route("/v1/consent-grants", get(consent::list_consent_grants))
        .route(
            "/v1/consent-grants/{consent_grant_id}",
            get(consent::get_consent_grant),
        )
        .route_layer(middleware::from_fn_with_state(
            ProtectedRouteState {
                server: state.clone(),
                required_scope: server_required_scope("listConsentGrants"),
            },
            authenticate_request,
        ));
    let evidence_read_routes = Router::new()
        .route(
            "/v1/observations/{observation_id}/evidence-capsule",
            get(evidence::get_evidence_capsule),
        )
        .route_layer(middleware::from_fn_with_state(
            ProtectedRouteState {
                server: state.clone(),
                required_scope: server_required_scope("getEvidenceCapsule"),
            },
            authenticate_request,
        ));
    let deletion_routes = Router::new()
        .route(
            "/v1/deletion-requests/contributor",
            axum::routing::post(deletion::create_contributor_deletion),
        )
        .route(
            "/v1/deletion-requests/{deletion_request_id}",
            get(deletion::get_deletion_request),
        )
        .route(
            "/v1/deletion-requests/{deletion_request_id}/receipt",
            get(deletion::get_deletion_receipt),
        )
        .route_layer(middleware::from_fn_with_state(
            ProtectedRouteState {
                server: state.clone(),
                required_scope: server_required_scope("createContributorDeletion"),
            },
            authenticate_request,
        ));
    let notification_write_routes = Router::new()
        .route(
            "/v1/notification-deliveries/{delivery_id}/acknowledgement",
            axum::routing::post(notification::acknowledge_delivery),
        )
        .route_layer(middleware::from_fn_with_state(
            ProtectedRouteState {
                server: state.clone(),
                required_scope: server_required_scope("createNotificationAcknowledgement"),
            },
            authenticate_request,
        ));
    let notification_read_routes = Router::new()
        .route(
            "/v1/notification-deliveries/{delivery_id}/acknowledgement",
            get(notification::get_delivery_acknowledgement),
        )
        .route_layer(middleware::from_fn_with_state(
            ProtectedRouteState {
                server: state.clone(),
                required_scope: server_required_scope("getNotificationAcknowledgement"),
            },
            authenticate_request,
        ));
    let operations_routes = Router::new()
        .route("/v1/operations/report", get(operations::operational_report))
        .route_layer(middleware::from_fn_with_state(
            ProtectedRouteState {
                server: state.clone(),
                required_scope: server_required_scope("getOperationalReport"),
            },
            authenticate_request,
        ));
    let developer_routes = Router::new()
        .route("/v1/developer/report", get(developer::developer_report))
        .route_layer(middleware::from_fn_with_state(
            ProtectedRouteState {
                server: state.clone(),
                required_scope: server_required_scope("getDeveloperReport"),
            },
            authenticate_request,
        ));
    let routes = Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .merge(workspace_routes)
        .merge(organization_routes)
        .merge(organization_audit_routes)
        .merge(review_read_routes)
        .merge(review_write_routes)
        .merge(search_create_routes)
        .merge(search_read_routes)
        .merge(search_export_routes)
        .merge(search_cancel_routes)
        .merge(search_webhook_write_routes)
        .merge(search_webhook_read_routes)
        .merge(watch_write_routes)
        .merge(watch_read_routes)
        .merge(consent_write_routes)
        .merge(consent_read_routes)
        .merge(evidence_read_routes)
        .merge(deletion_routes)
        .merge(notification_write_routes)
        .merge(notification_read_routes)
        .merge(operations_routes)
        .merge(developer_routes)
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .with_state(state.clone());
    apply_runtime_layers(routes, state)
}

fn apply_runtime_layers(routes: Router, state: ServerState) -> Router {
    let config = state.config.clone();
    routes.layer(
        ServiceBuilder::new()
            .layer(middleware::from_fn_with_state(state, request_guard))
            .layer(ConcurrencyLimitLayer::new(config.maximum_in_flight()))
            .layer(DefaultBodyLimit::max(config.maximum_body_bytes())),
    )
}

pub async fn serve<F>(
    listener: tokio::net::TcpListener,
    config: ServerConfig,
    database: PgPool,
    shutdown: F,
) -> io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    axum::serve(listener, build_router(config, database))
        .with_graceful_shutdown(shutdown)
        .await
}

async fn live() -> Json<HealthResponse> {
    Json(HealthResponse {
        schema: ProtocolVersion::ApiV1,
        service: "socialname-server",
        version: env!("CARGO_PKG_VERSION"),
        status: HealthStatus::Live,
    })
}

async fn ready(State(state): State<ServerState>) -> Response {
    let database_timeout = (state.config.request_timeout() / 2).min(Duration::from_secs(1));
    let available = if let Some(restore_run_id) = state.config.expected_restore_ledger_id() {
        tokio::time::timeout(
            database_timeout,
            sqlx::query_scalar::<_, bool>("SELECT socialname_restore_ledger_ready($1)")
                .bind(restore_run_id)
                .fetch_one(&state.database),
        )
        .await
        .is_ok_and(|result| matches!(result, Ok(true)))
    } else {
        tokio::time::timeout(
            database_timeout,
            sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(&state.database),
        )
        .await
        .is_ok_and(|result| matches!(result, Ok(1)))
    };
    let status = if available {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let health_status = if available {
        HealthStatus::Ready
    } else {
        HealthStatus::NotReady
    };
    (
        status,
        Json(HealthResponse {
            schema: ProtocolVersion::ApiV1,
            service: "socialname-server",
            version: env!("CARGO_PKG_VERSION"),
            status: health_status,
        }),
    )
        .into_response()
}

async fn workspace_resource(
    State(state): State<ServerState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<auth::AuthenticatedPrincipal>,
) -> Response {
    match workspace::load_workspace(&state.database, &principal).await {
        Ok(resource) => Json(resource).into_response(),
        Err(workspace::WorkspaceLoadError::Unauthenticated) => unauthenticated_response(request_id),
        Err(workspace::WorkspaceLoadError::Forbidden) => api_error_response(
            StatusCode::FORBIDDEN,
            request_id,
            standard_api_error(ApiErrorCode::Forbidden, false),
        ),
        Err(workspace::WorkspaceLoadError::Unavailable) => api_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            request_id,
            standard_api_error(ApiErrorCode::Unavailable, true),
        ),
    }
}

async fn authenticate_request(
    State(state): State<ProtectedRouteState>,
    mut request: Request,
    next: Next,
) -> Response {
    let request_id = request
        .extensions()
        .get::<RequestId>()
        .cloned()
        .unwrap_or_else(|| state.server.next_request_id());
    match auth::authenticate(
        &state.server.database,
        request.headers(),
        state.required_scope,
    )
    .await
    {
        Ok(principal) => {
            request.headers_mut().remove(AUTHORIZATION);
            request.extensions_mut().insert(principal);
            next.run(request).await
        }
        Err(auth::AuthenticationError::InvalidCredential) => unauthenticated_response(request_id),
        Err(auth::AuthenticationError::Forbidden) => api_error_response(
            StatusCode::FORBIDDEN,
            request_id,
            standard_api_error(ApiErrorCode::Forbidden, false),
        ),
        Err(auth::AuthenticationError::Unavailable) => api_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            request_id,
            standard_api_error(ApiErrorCode::Unavailable, true),
        ),
    }
}

fn unauthenticated_response(request_id: RequestId) -> Response {
    let mut response = api_error_response(
        StatusCode::UNAUTHORIZED,
        request_id,
        standard_api_error(ApiErrorCode::Unauthenticated, false),
    );
    response
        .headers_mut()
        .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

fn standard_api_error(code: ApiErrorCode, retryable: bool) -> ApiError {
    ApiError {
        code,
        retryable,
        retry_after_ms: None,
        violations: Vec::new(),
    }
}

async fn not_found(Extension(request_id): Extension<RequestId>) -> Response {
    api_error_response(
        StatusCode::NOT_FOUND,
        request_id,
        ApiError {
            code: ApiErrorCode::NotFound,
            retryable: false,
            retry_after_ms: None,
            violations: Vec::new(),
        },
    )
}

async fn method_not_allowed(Extension(request_id): Extension<RequestId>) -> Response {
    invalid_request_response(
        StatusCode::METHOD_NOT_ALLOWED,
        request_id,
        "method",
        ValidationCode::InvalidRelation,
    )
}

async fn request_guard(
    State(state): State<ServerState>,
    mut request: Request,
    next: Next,
) -> Response {
    let request_id =
        incoming_request_id(request.headers()).unwrap_or_else(|| state.next_request_id());
    request.extensions_mut().insert(request_id.clone());
    let method = request.method().clone();
    let span = tracing::info_span!(
        "http_request",
        request_id = %request_id,
        method = %method,
    );
    let started = Instant::now();
    let response = async {
        match content_length(request.headers()) {
            Ok(Some(length)) if length > state.config.maximum_body_bytes() as u64 => {
                invalid_request_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    request_id.clone(),
                    "body",
                    ValidationCode::TooManyItems,
                )
            }
            Err(()) => invalid_request_response(
                StatusCode::BAD_REQUEST,
                request_id.clone(),
                "content_length",
                ValidationCode::InvalidFormat,
            ),
            Ok(_) => match tokio::time::timeout(state.config.request_timeout(), next.run(request))
                .await
            {
                Ok(response) => response,
                Err(_) => api_error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    request_id.clone(),
                    ApiError {
                        code: ApiErrorCode::Unavailable,
                        retryable: true,
                        retry_after_ms: None,
                        violations: Vec::new(),
                    },
                ),
            },
        }
    }
    .instrument(span)
    .await;
    let status = response.status();
    let response = finalize_response(response, &request_id);
    tracing::info!(
        request_id = %request_id,
        method = %method,
        status = status.as_u16(),
        elapsed_ms = started.elapsed().as_millis(),
        "request completed"
    );
    response
}

fn incoming_request_id(headers: &HeaderMap) -> Option<RequestId> {
    headers
        .get(X_REQUEST_ID)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| RequestId::new(value.to_owned()).ok())
}

fn content_length(headers: &HeaderMap) -> Result<Option<u64>, ()> {
    headers
        .get(CONTENT_LENGTH)
        .map(|value| value.to_str().map_err(|_| ())?.parse().map_err(|_| ()))
        .transpose()
}

fn invalid_request_response(
    status: StatusCode,
    request_id: RequestId,
    field: &'static str,
    code: ValidationCode,
) -> Response {
    let response =
        ApiErrorResponse::invalid_request(request_id, ValidationErrors::new(field, code));
    debug_assert!(response.validate().is_ok());
    (status, Json(response)).into_response()
}

fn api_error_response(status: StatusCode, request_id: RequestId, error: ApiError) -> Response {
    let response = ApiErrorResponse {
        schema: ProtocolVersion::ApiV1,
        request_id,
        error,
    };
    debug_assert!(response.validate().is_ok());
    (status, Json(response)).into_response()
}

fn finalize_response(mut response: Response<Body>, request_id: &RequestId) -> Response<Body> {
    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(request_id.as_str()) {
        headers.insert(X_REQUEST_ID, value);
    }
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    response
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, time::Duration};

    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
        routing::get,
    };
    use socialname_protocol::{
        API_V1_SCHEMA, ApiErrorResponse, Validate, published_api_v1_operations,
    };
    use sqlx::{PgPool, postgres::PgPoolOptions};
    use tower::ServiceExt;

    use super::*;

    fn test_config(timeout: Duration) -> ServerConfig {
        ServerConfig::new(
            "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            timeout,
            4_096,
            8,
        )
        .unwrap()
        .with_suppression_hmac_key(SuppressionHmacKey::from_hex(&"11".repeat(32)).unwrap())
    }

    fn test_database() -> PgPool {
        PgPoolOptions::new()
            .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
            .expect("static test database URL is valid")
    }

    async fn json_body(response: Response) -> serde_json::Value {
        let bytes = to_bytes(response.into_body(), 64 * 1_024).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn health_is_versioned_hardened_and_request_identified() {
        let response = build_router(test_config(Duration::from_secs(1)), test_database())
            .oneshot(
                Request::builder()
                    .uri("/health/live")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[X_CONTENT_TYPE_OPTIONS], "nosniff");
        let request_id = response.headers()[X_REQUEST_ID].to_str().unwrap();
        assert!(RequestId::new(request_id.to_owned()).is_ok());
        let body = json_body(response).await;
        assert_eq!(body["schema"], API_V1_SCHEMA);
        assert_eq!(body["service"], "socialname-server");
        assert_eq!(body["status"], "live");
    }

    #[tokio::test]
    async fn unknown_routes_and_methods_return_closed_protocol_errors() {
        for (method, uri, expected_status, expected_code) in [
            (
                "GET",
                "/v1/unimplemented",
                StatusCode::NOT_FOUND,
                "not_found",
            ),
            (
                "GET",
                "/v1/searches",
                StatusCode::UNAUTHORIZED,
                "unauthenticated",
            ),
            (
                "POST",
                "/health/live",
                StatusCode::METHOD_NOT_ALLOWED,
                "invalid_request",
            ),
        ] {
            let response = build_router(test_config(Duration::from_secs(1)), test_database())
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(uri)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected_status);
            let response: ApiErrorResponse =
                serde_json::from_value(json_body(response).await).unwrap();
            assert_eq!(
                serde_json::to_value(response.error.code).unwrap(),
                expected_code
            );
            assert!(response.validate().is_ok());
        }
    }

    #[tokio::test]
    async fn every_published_api_operation_is_registered_by_the_router() {
        let router = build_router(test_config(Duration::from_secs(1)), test_database());
        for operation in published_api_v1_operations() {
            assert_eq!(
                operation.required_scope,
                server_required_scope(operation.operation_id),
                "{} has a published scope different from the router",
                operation.operation_id
            );
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method(operation.method.as_str())
                        .uri(concrete_contract_path(operation.path))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "{} {} is not registered behind authentication",
                operation.method.as_str(),
                operation.path
            );
        }
    }

    #[tokio::test]
    async fn oversized_or_invalid_content_length_is_typed_before_routing() {
        for (content_length, expected_status) in [
            ("4097", StatusCode::PAYLOAD_TOO_LARGE),
            ("invalid", StatusCode::BAD_REQUEST),
        ] {
            let response = build_router(test_config(Duration::from_secs(1)), test_database())
                .oneshot(
                    Request::builder()
                        .uri("/health/live")
                        .header(CONTENT_LENGTH, content_length)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected_status);
            let error: ApiErrorResponse =
                serde_json::from_value(json_body(response).await).unwrap();
            assert_eq!(error.error.code, ApiErrorCode::InvalidRequest);
            assert!(error.validate().is_ok());
        }
    }

    #[tokio::test]
    async fn invalid_inbound_request_id_is_not_reflected() {
        let response = build_router(test_config(Duration::from_secs(1)), test_database())
            .oneshot(
                Request::builder()
                    .uri("/missing")
                    .header(X_REQUEST_ID, "invalid:request:id")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(
            response.headers()[X_REQUEST_ID],
            HeaderValue::from_static("invalid:request:id")
        );
        let body = json_body(response).await.to_string();
        assert!(!body.contains("invalid:request:id"));
        assert!(!body.contains("/missing"));
    }

    #[tokio::test]
    async fn deadline_returns_a_typed_unavailable_error() {
        let routes = Router::new()
            .route(
                "/slow",
                get(|| async {
                    tokio::time::sleep(Duration::from_millis(150)).await;
                    StatusCode::NO_CONTENT
                }),
            )
            .fallback(not_found)
            .method_not_allowed_fallback(method_not_allowed);
        let config = test_config(Duration::from_millis(100));
        let state = ServerState::new(config, test_database());
        let response = apply_runtime_layers(routes, state)
            .oneshot(Request::builder().uri("/slow").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let error: ApiErrorResponse = serde_json::from_value(json_body(response).await).unwrap();
        assert_eq!(error.error.code, ApiErrorCode::Unavailable);
        assert!(error.error.retryable);
        assert!(error.validate().is_ok());
    }

    #[tokio::test]
    async fn server_honors_graceful_shutdown_without_external_dependencies() {
        let config = test_config(Duration::from_secs(1));
        let listener = tokio::net::TcpListener::bind(config.bind_address())
            .await
            .unwrap();
        tokio::time::timeout(
            Duration::from_secs(1),
            serve(listener, config, test_database(), async {}),
        )
        .await
        .unwrap()
        .unwrap();
    }

    fn concrete_contract_path(template: &str) -> String {
        template
            .split('/')
            .map(|segment| {
                if segment.starts_with('{') && segment.ends_with('}') {
                    "00000000-0000-0000-0000-000000000001"
                } else {
                    segment
                }
            })
            .collect::<Vec<_>>()
            .join("/")
    }
}
