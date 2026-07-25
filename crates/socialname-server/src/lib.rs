#![forbid(unsafe_code)]

mod config;
mod database;

use std::{
    future::Future,
    io,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

use axum::{
    Extension, Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Request, State},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{CACHE_CONTROL, CONTENT_LENGTH},
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Serialize;
use socialname_protocol::{
    ApiError, ApiErrorCode, ApiErrorResponse, ProtocolVersion, RequestId, Validate, ValidationCode,
    ValidationErrors,
};
use tower::{ServiceBuilder, limit::ConcurrencyLimitLayer};
use tracing::Instrument;

pub use config::{
    BIND_ENV, ConfigError, MAXIMUM_BODY_BYTES_ENV, MAXIMUM_IN_FLIGHT_ENV, REQUEST_TIMEOUT_ENV,
    ServerConfig,
};
pub use database::{
    DATABASE_URL_ENV, DatabaseError, MIGRATOR, migrate_database, migrate_database_from_env,
};

const X_REQUEST_ID: &str = "x-request-id";
const X_CONTENT_TYPE_OPTIONS: &str = "x-content-type-options";

#[derive(Clone)]
struct ServerState {
    config: ServerConfig,
    request_sequence: Arc<AtomicU64>,
}

impl ServerState {
    fn new(config: ServerConfig) -> Self {
        Self {
            config,
            request_sequence: Arc::new(AtomicU64::new(1)),
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
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    schema: ProtocolVersion,
    service: &'static str,
    version: &'static str,
    status: HealthStatus,
}

pub fn build_router(config: ServerConfig) -> Router {
    let routes = Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed);
    apply_runtime_layers(routes, config)
}

fn apply_runtime_layers(routes: Router, config: ServerConfig) -> Router {
    let state = ServerState::new(config.clone());
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
    shutdown: F,
) -> io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    axum::serve(listener, build_router(config))
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

async fn ready() -> Json<HealthResponse> {
    Json(HealthResponse {
        schema: ProtocolVersion::ApiV1,
        service: "socialname-server",
        version: env!("CARGO_PKG_VERSION"),
        status: HealthStatus::Ready,
    })
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
    use socialname_protocol::{API_V1_SCHEMA, ApiErrorResponse, Validate};
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
    }

    async fn json_body(response: Response) -> serde_json::Value {
        let bytes = to_bytes(response.into_body(), 64 * 1_024).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn health_is_versioned_hardened_and_request_identified() {
        let response = build_router(test_config(Duration::from_secs(1)))
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
            ("GET", "/v1/searches", StatusCode::NOT_FOUND, "not_found"),
            (
                "POST",
                "/health/live",
                StatusCode::METHOD_NOT_ALLOWED,
                "invalid_request",
            ),
        ] {
            let response = build_router(test_config(Duration::from_secs(1)))
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
    async fn oversized_or_invalid_content_length_is_typed_before_routing() {
        for (content_length, expected_status) in [
            ("4097", StatusCode::PAYLOAD_TOO_LARGE),
            ("invalid", StatusCode::BAD_REQUEST),
        ] {
            let response = build_router(test_config(Duration::from_secs(1)))
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
        let response = build_router(test_config(Duration::from_secs(1)))
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
        let response = apply_runtime_layers(routes, test_config(Duration::from_millis(100)))
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
        tokio::time::timeout(Duration::from_secs(1), serve(listener, config, async {}))
            .await
            .unwrap()
            .unwrap();
    }
}
