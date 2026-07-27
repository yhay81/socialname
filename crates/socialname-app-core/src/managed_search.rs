use std::{fmt, net::IpAddr, time::Duration};

use futures_util::StreamExt;
use reqwest::{Client, Response, StatusCode, header};
use serde::Deserialize;
use socialname_protocol::{
    ApiErrorCode, ApiErrorResponse, ConsentGrantId, ProtocolVersion, RegionClass,
    SearchCreateRequest, SearchEvent, SearchEventData, SearchId, SearchMode, SearchProgress,
    SearchResource, SearchTerminalState, SiteId, SyncPolicy as ProtocolSyncPolicy, TargetSelection,
    Username, Validate,
};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use url::Url;
use uuid::Uuid;

use crate::{SearchSource, SyncPolicy};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(35);
const RUN_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_JSON_BODY_BYTES: usize = 256 * 1024;
const MAX_SSE_BUFFER_BYTES: usize = 256 * 1024;
const MAX_STREAM_RECONNECTS: usize = 8;
const MAX_CREATE_ATTEMPTS: usize = 2;

#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManagedSearchAccess {
    pub api_url: String,
    pub api_key: String,
    pub consent_grant_id: String,
}

impl fmt::Debug for ManagedSearchAccess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedSearchAccess")
            .field("api_url", &self.api_url)
            .field("api_key", &"[REDACTED]")
            .field("consent_grant_id", &self.consent_grant_id)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagedSearchRun {
    pub username: String,
    pub site_ids: Vec<String>,
    pub source: SearchSource,
    pub sync: SyncPolicy,
    pub maximum_age_ms: i64,
    pub region_class: String,
    pub access: ManagedSearchAccess,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagedSearchOutcome {
    pub search_id: SearchId,
    pub terminal_state: SearchTerminalState,
    pub progress: SearchProgress,
}

#[derive(Debug, thiserror::Error)]
pub enum ManagedSearchClientError {
    #[error("managed search requires source=remote or source=hybrid")]
    InvalidSource,
    #[error("managed search requires sync=private or sync=shared")]
    InvalidSync,
    #[error("managed API URL must be HTTPS, or HTTP on localhost/loopback")]
    InvalidApiUrl,
    #[error("managed API key must contain 1-4096 printable ASCII characters without spaces")]
    InvalidApiKey,
    #[error("managed search request is invalid: {0}")]
    InvalidRequest(String),
    #[error("managed API transport failed")]
    Transport,
    #[error("managed API returned HTTP {status}")]
    HttpStatus { status: u16 },
    #[error("managed API rejected the request with {code:?}")]
    Api {
        code: ApiErrorCode,
        retryable: bool,
        retry_after_ms: Option<u64>,
    },
    #[error("managed API returned an oversized response")]
    ResponseTooLarge,
    #[error("managed API returned an invalid response")]
    InvalidResponse,
    #[error("managed search event stream exceeded its reconnect limit")]
    ReconnectLimit,
    #[error("managed search did not finish within the client deadline")]
    Deadline,
    #[error("managed search cancellation could not be confirmed")]
    CancellationUnconfirmed,
}

pub async fn run_managed_search<F>(
    run: ManagedSearchRun,
    cancellation: CancellationToken,
    on_event: F,
) -> Result<ManagedSearchOutcome, ManagedSearchClientError>
where
    F: Fn(SearchEvent) + Send + Sync,
{
    let deadline = Instant::now() + RUN_TIMEOUT;
    let prepared = PreparedRun::new(run)?;
    let client = Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("socialname-app-core/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|_| ManagedSearchClientError::Transport)?;
    let resource = tokio::time::timeout_at(deadline, create_search(&client, &prepared))
        .await
        .map_err(|_| ManagedSearchClientError::Deadline)??;

    if cancellation.is_cancelled() {
        return cancel_search(&client, &prepared, &resource.search_id).await;
    }

    let mut cursor = EventCursor::default();
    for _ in 0..MAX_STREAM_RECONNECTS {
        if Instant::now() >= deadline {
            return Err(ManagedSearchClientError::Deadline);
        }
        let stream_result = tokio::time::timeout_at(
            deadline,
            consume_event_stream(
                &client,
                &prepared,
                &resource.search_id,
                &mut cursor,
                &cancellation,
                &on_event,
            ),
        )
        .await
        .map_err(|_| ManagedSearchClientError::Deadline)?;
        match stream_result {
            Ok(StreamEnd::Finished(outcome)) => return Ok(outcome),
            Ok(StreamEnd::Reconnect) => {}
            Ok(StreamEnd::Cancelled) => {
                return cancel_search(&client, &prepared, &resource.search_id).await;
            }
            Err(error) => return Err(error),
        }
    }
    Err(ManagedSearchClientError::ReconnectLimit)
}

struct PreparedRun {
    base_url: Url,
    api_key: String,
    request: SearchCreateRequest,
    idempotency_key: String,
}

impl PreparedRun {
    fn new(run: ManagedSearchRun) -> Result<Self, ManagedSearchClientError> {
        let mode = match run.source {
            SearchSource::Remote => SearchMode::Remote,
            SearchSource::Hybrid => SearchMode::Hybrid,
            SearchSource::Local | SearchSource::Cache => {
                return Err(ManagedSearchClientError::InvalidSource);
            }
        };
        let sync = match run.sync {
            SyncPolicy::Private => ProtocolSyncPolicy::Private,
            SyncPolicy::Shared => ProtocolSyncPolicy::Shared,
            SyncPolicy::Never => return Err(ManagedSearchClientError::InvalidSync),
        };
        let base_url = validate_api_url(&run.access.api_url)?;
        if run.access.api_key.is_empty()
            || run.access.api_key.len() > 4096
            || !run
                .access
                .api_key
                .bytes()
                .all(|byte| byte.is_ascii_graphic())
        {
            return Err(ManagedSearchClientError::InvalidApiKey);
        }
        let username = Username::new(run.username)
            .map_err(|error| ManagedSearchClientError::InvalidRequest(error.to_string()))?;
        let site_ids = run
            .site_ids
            .into_iter()
            .map(SiteId::new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| ManagedSearchClientError::InvalidRequest(error.to_string()))?;
        let consent_grant_id = ConsentGrantId::new(run.access.consent_grant_id)
            .map_err(|error| ManagedSearchClientError::InvalidRequest(error.to_string()))?;
        let region_class = RegionClass::new(run.region_class)
            .map_err(|error| ManagedSearchClientError::InvalidRequest(error.to_string()))?;
        let request = SearchCreateRequest {
            schema: ProtocolVersion::ApiV1,
            targets: TargetSelection {
                usernames: vec![username],
                site_ids,
            },
            mode,
            sync,
            consent_grant_id: Some(consent_grant_id),
            maximum_age_ms: run.maximum_age_ms,
            region_classes: vec![region_class],
        };
        request
            .validate()
            .map_err(|error| ManagedSearchClientError::InvalidRequest(error.to_string()))?;
        Ok(Self {
            base_url,
            api_key: run.access.api_key,
            request,
            idempotency_key: Uuid::new_v4().to_string(),
        })
    }

    fn endpoint(&self, relative: &str) -> Result<Url, ManagedSearchClientError> {
        self.base_url
            .join(relative)
            .map_err(|_| ManagedSearchClientError::InvalidApiUrl)
    }
}

fn validate_api_url(value: &str) -> Result<Url, ManagedSearchClientError> {
    let mut url = Url::parse(value).map_err(|_| ManagedSearchClientError::InvalidApiUrl)?;
    if url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
    {
        return Err(ManagedSearchClientError::InvalidApiUrl);
    }
    let secure = url.scheme() == "https";
    let loopback_http = url.scheme() == "http"
        && url.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        });
    if !secure && !loopback_http {
        return Err(ManagedSearchClientError::InvalidApiUrl);
    }
    if !url.path().ends_with('/') {
        let mut path = url.path().to_owned();
        path.push('/');
        url.set_path(&path);
    }
    Ok(url)
}

async fn create_search(
    client: &Client,
    run: &PreparedRun,
) -> Result<SearchResource, ManagedSearchClientError> {
    for attempt in 0..MAX_CREATE_ATTEMPTS {
        let response = client
            .post(run.endpoint("v1/searches")?)
            .bearer_auth(&run.api_key)
            .header("idempotency-key", &run.idempotency_key)
            .json(&run.request)
            .send()
            .await;
        match response {
            Ok(response) if matches!(response.status(), StatusCode::CREATED | StatusCode::OK) => {
                return parse_json_response(response, &[StatusCode::CREATED, StatusCode::OK]).await;
            }
            Ok(response) => {
                let error = parse_error_response(response).await;
                let retryable = matches!(
                    error,
                    ManagedSearchClientError::Api {
                        retryable: true,
                        ..
                    } | ManagedSearchClientError::HttpStatus { status: 500..=599 }
                );
                if !retryable || attempt + 1 == MAX_CREATE_ATTEMPTS {
                    return Err(error);
                }
            }
            Err(_) if attempt + 1 == MAX_CREATE_ATTEMPTS => {
                return Err(ManagedSearchClientError::Transport);
            }
            Err(_) => {}
        }
    }
    Err(ManagedSearchClientError::Transport)
}

async fn cancel_search(
    client: &Client,
    run: &PreparedRun,
    search_id: &SearchId,
) -> Result<ManagedSearchOutcome, ManagedSearchClientError> {
    let response = client
        .delete(run.endpoint(&format!("v1/searches/{}", search_id.as_str()))?)
        .bearer_auth(&run.api_key)
        .send()
        .await
        .map_err(|_| ManagedSearchClientError::CancellationUnconfirmed)?;
    let resource: SearchResource = parse_json_response(response, &[StatusCode::OK])
        .await
        .map_err(|_| ManagedSearchClientError::CancellationUnconfirmed)?;
    if resource.search_id != *search_id {
        return Err(ManagedSearchClientError::CancellationUnconfirmed);
    }
    let terminal_state = match resource.state {
        socialname_protocol::SearchState::Completed => SearchTerminalState::Completed,
        socialname_protocol::SearchState::Cancelled => SearchTerminalState::Cancelled,
        socialname_protocol::SearchState::Failed => SearchTerminalState::Failed,
        socialname_protocol::SearchState::Accepted | socialname_protocol::SearchState::Running => {
            return Err(ManagedSearchClientError::CancellationUnconfirmed);
        }
    };
    Ok(ManagedSearchOutcome {
        search_id: resource.search_id,
        terminal_state,
        progress: resource.progress,
    })
}

enum StreamEnd {
    Finished(ManagedSearchOutcome),
    Reconnect,
    Cancelled,
}

#[derive(Default)]
struct EventCursor {
    event_id: Option<String>,
    sequence: u64,
    started: bool,
}

async fn consume_event_stream<F>(
    client: &Client,
    run: &PreparedRun,
    search_id: &SearchId,
    cursor: &mut EventCursor,
    cancellation: &CancellationToken,
    on_event: &F,
) -> Result<StreamEnd, ManagedSearchClientError>
where
    F: Fn(SearchEvent) + Send + Sync,
{
    let mut request = client
        .get(run.endpoint(&format!("v1/searches/{}/events", search_id.as_str()))?)
        .bearer_auth(&run.api_key)
        .header(header::ACCEPT, "text/event-stream");
    if let Some(last_event_id) = cursor.event_id.as_deref() {
        request = request.header("last-event-id", last_event_id);
    }
    let response = request
        .send()
        .await
        .map_err(|_| ManagedSearchClientError::Transport)?;
    if !response.status().is_success() {
        return Err(parse_error_response(response).await);
    }
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if !content_type.starts_with("text/event-stream") {
        return Err(ManagedSearchClientError::InvalidResponse);
    }

    let mut decoder = SseDecoder::default();
    let mut stream = response.bytes_stream();
    loop {
        let next = tokio::select! {
            biased;
            () = cancellation.cancelled() => return Ok(StreamEnd::Cancelled),
            next = stream.next() => next,
        };
        let Some(chunk) = next else {
            decoder.finish()?;
            return Ok(StreamEnd::Reconnect);
        };
        let chunk = chunk.map_err(|_| ManagedSearchClientError::Transport)?;
        for message in decoder.push(&chunk)? {
            match message.event.as_deref() {
                Some("search_event") => {
                    let event: SearchEvent = serde_json::from_str(&message.data)
                        .map_err(|_| ManagedSearchClientError::InvalidResponse)?;
                    event
                        .validate()
                        .map_err(|_| ManagedSearchClientError::InvalidResponse)?;
                    if event.search_id != *search_id
                        || event.event_id.as_str() != message.id.as_deref().unwrap_or_default()
                        || event.sequence != cursor.sequence.saturating_add(1)
                    {
                        return Err(ManagedSearchClientError::InvalidResponse);
                    }
                    match &event.data {
                        SearchEventData::Started { .. } if !cursor.started => {
                            cursor.started = true;
                        }
                        SearchEventData::Started { .. } => {
                            return Err(ManagedSearchClientError::InvalidResponse);
                        }
                        _ if !cursor.started => {
                            return Err(ManagedSearchClientError::InvalidResponse);
                        }
                        _ => {}
                    }
                    cursor.sequence = event.sequence;
                    cursor.event_id = message.id;
                    let terminal = match &event.data {
                        SearchEventData::Finished { state, progress } => {
                            Some((*state, progress.clone()))
                        }
                        _ => None,
                    };
                    on_event(event);
                    if let Some((terminal_state, progress)) = terminal {
                        return Ok(StreamEnd::Finished(ManagedSearchOutcome {
                            search_id: search_id.clone(),
                            terminal_state,
                            progress,
                        }));
                    }
                }
                Some("stream_error") => {
                    let error: ApiErrorResponse = serde_json::from_str(&message.data)
                        .map_err(|_| ManagedSearchClientError::InvalidResponse)?;
                    error
                        .validate()
                        .map_err(|_| ManagedSearchClientError::InvalidResponse)?;
                    return Err(api_error(error));
                }
                _ if message.data.is_empty() => {}
                _ => return Err(ManagedSearchClientError::InvalidResponse),
            }
        }
    }
}

async fn parse_json_response<T>(
    response: Response,
    accepted: &[StatusCode],
) -> Result<T, ManagedSearchClientError>
where
    T: for<'de> Deserialize<'de> + Validate,
{
    if !accepted.contains(&response.status()) {
        return Err(parse_error_response(response).await);
    }
    let bytes = bounded_body(response).await?;
    let value: T =
        serde_json::from_slice(&bytes).map_err(|_| ManagedSearchClientError::InvalidResponse)?;
    value
        .validate()
        .map_err(|_| ManagedSearchClientError::InvalidResponse)?;
    Ok(value)
}

async fn parse_error_response(response: Response) -> ManagedSearchClientError {
    let status = response.status().as_u16();
    match bounded_body(response).await {
        Ok(bytes) => match serde_json::from_slice::<ApiErrorResponse>(&bytes) {
            Ok(error) if error.validate().is_ok() => api_error(error),
            _ => ManagedSearchClientError::HttpStatus { status },
        },
        Err(error) => error,
    }
}

fn api_error(response: ApiErrorResponse) -> ManagedSearchClientError {
    ManagedSearchClientError::Api {
        code: response.error.code,
        retryable: response.error.retryable,
        retry_after_ms: response.error.retry_after_ms,
    }
}

async fn bounded_body(response: Response) -> Result<Vec<u8>, ManagedSearchClientError> {
    if response
        .content_length()
        .is_some_and(|size| usize::try_from(size).map_or(true, |size| size > MAX_JSON_BODY_BYTES))
    {
        return Err(ManagedSearchClientError::ResponseTooLarge);
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| ManagedSearchClientError::Transport)?;
        if body
            .len()
            .checked_add(chunk.len())
            .is_none_or(|length| length > MAX_JSON_BODY_BYTES)
        {
            return Err(ManagedSearchClientError::ResponseTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[derive(Default)]
struct SseDecoder {
    buffer: Vec<u8>,
}

impl SseDecoder {
    fn push(&mut self, chunk: &[u8]) -> Result<Vec<SseMessage>, ManagedSearchClientError> {
        self.buffer.extend_from_slice(chunk);
        if self.buffer.len() > MAX_SSE_BUFFER_BYTES {
            return Err(ManagedSearchClientError::ResponseTooLarge);
        }
        let mut messages = Vec::new();
        while let Some((position, delimiter_length)) = find_event_delimiter(&self.buffer) {
            let block = self.buffer[..position].to_vec();
            self.buffer.drain(..position + delimiter_length);
            if let Some(message) = parse_sse_block(&block)? {
                messages.push(message);
            }
        }
        Ok(messages)
    }

    fn finish(&self) -> Result<(), ManagedSearchClientError> {
        if self.buffer.iter().all(u8::is_ascii_whitespace) {
            Ok(())
        } else {
            Err(ManagedSearchClientError::InvalidResponse)
        }
    }
}

struct SseMessage {
    event: Option<String>,
    id: Option<String>,
    data: String,
}

fn find_event_delimiter(buffer: &[u8]) -> Option<(usize, usize)> {
    let lf = buffer.windows(2).position(|window| window == b"\n\n");
    let crlf = buffer.windows(4).position(|window| window == b"\r\n\r\n");
    match (lf, crlf) {
        (Some(left), Some(right)) if left <= right => Some((left, 2)),
        (Some(_), Some(right)) => Some((right, 4)),
        (Some(position), None) => Some((position, 2)),
        (None, Some(position)) => Some((position, 4)),
        (None, None) => None,
    }
}

fn parse_sse_block(block: &[u8]) -> Result<Option<SseMessage>, ManagedSearchClientError> {
    let block =
        std::str::from_utf8(block).map_err(|_| ManagedSearchClientError::InvalidResponse)?;
    let mut event = None;
    let mut id = None;
    let mut data = Vec::new();
    for raw_line in block.lines() {
        let line = raw_line.trim_end_matches('\r');
        if line.starts_with(':') || line.is_empty() {
            continue;
        }
        let (field, value) = line.split_once(':').map_or((line, ""), |(field, value)| {
            (field, value.strip_prefix(' ').unwrap_or(value))
        });
        match field {
            "event" => event = Some(value.to_owned()),
            "id" if !value.contains('\0') => id = Some(value.to_owned()),
            "data" => data.push(value),
            _ => {}
        }
    }
    if event.is_none() && id.is_none() && data.is_empty() {
        return Ok(None);
    }
    Ok(Some(SseMessage {
        event,
        id,
        data: data.join("\n"),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Json, Router,
        extract::Path,
        http::{HeaderMap, StatusCode},
        response::IntoResponse,
        routing::{delete, get, post},
    };
    use serde_json::{Value, json};
    use socialname_protocol::API_V1_SCHEMA;

    #[test]
    fn access_debug_redacts_the_api_key() {
        let access = ManagedSearchAccess {
            api_url: "https://api.example.test".to_owned(),
            api_key: "secret-value".to_owned(),
            consent_grant_id: "grant_1".to_owned(),
        };
        let rendered = format!("{access:?}");
        assert!(!rendered.contains("secret-value"));
        assert!(rendered.contains("[REDACTED]"));
    }

    #[test]
    fn api_url_requires_https_except_for_loopback_development() {
        assert!(validate_api_url("https://api.example.test/root").is_ok());
        assert!(validate_api_url("http://localhost:8080").is_ok());
        assert!(validate_api_url("http://127.0.0.1:8080").is_ok());
        assert!(validate_api_url("http://api.example.test").is_err());
        assert!(validate_api_url("https://user@example.test").is_err());
    }

    #[test]
    fn decoder_handles_chunked_crlf_and_multiple_events() {
        let mut decoder = SseDecoder::default();
        assert!(
            decoder
                .push(b"event: search_event\r\nid: event_1\r\nda")
                .unwrap()
                .is_empty()
        );
        let messages = decoder
            .push(b"ta: {\"schema\":\"socialname.dev/api/v1\"}\r\n\r\nevent: ping\n\n")
            .unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].event.as_deref(), Some("search_event"));
        assert_eq!(messages[0].id.as_deref(), Some("event_1"));
        assert!(messages[0].data.contains(API_V1_SCHEMA));
        assert_eq!(messages[1].event.as_deref(), Some("ping"));
        decoder.finish().unwrap();
    }

    #[tokio::test]
    async fn client_posts_authenticated_request_and_consumes_terminal_sse() {
        async fn create(headers: HeaderMap, Json(request): Json<Value>) -> impl IntoResponse {
            assert_eq!(
                headers
                    .get(header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok()),
                Some("Bearer test-api-key")
            );
            assert!(
                headers
                    .get("idempotency-key")
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|value| Uuid::parse_str(value).is_ok())
            );
            (
                StatusCode::CREATED,
                Json(json!({
                    "schema": API_V1_SCHEMA,
                    "search_id": "search_1",
                    "state": "accepted",
                    "request": request,
                    "progress": {
                        "total_targets": 1,
                        "completed_targets": 0,
                        "definitive_results": 0,
                        "uncertain_results": 0,
                        "operational_failures": 0
                    },
                    "created_at_unix_ms": 1_000,
                    "updated_at_unix_ms": 1_000
                })),
            )
        }

        async fn events(Path(search_id): Path<String>, headers: HeaderMap) -> impl IntoResponse {
            assert_eq!(search_id, "search_1");
            assert_eq!(
                headers
                    .get(header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok()),
                Some("Bearer test-api-key")
            );
            let event_values = [
                json!({
                    "schema": API_V1_SCHEMA,
                    "event_id": "event_1",
                    "search_id": "search_1",
                    "sequence": 1,
                    "emitted_at_unix_ms": 1_000,
                    "data": {"type": "started", "total_targets": 1}
                }),
                json!({
                    "schema": API_V1_SCHEMA,
                    "event_id": "event_2",
                    "search_id": "search_1",
                    "sequence": 2,
                    "emitted_at_unix_ms": 2_000,
                    "data": {
                        "type": "definitive_result",
                        "result": {
                            "observation_id": "observation_1",
                            "target": {"username": "octocat", "site_id": "github"},
                            "verdict": "found",
                            "source": "managed_probe",
                            "freshness": {
                                "observed_at_unix_ms": 1_500,
                                "expires_at_unix_ms": 100_000,
                                "evaluated_at_unix_ms": 2_000,
                                "maximum_age_ms": 86_400_000,
                                "state": "current"
                            },
                            "evidence_class": "e4_structured_identity",
                            "evidence_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                            "region_class": "local",
                            "rule_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                            "rule_health": "healthy",
                            "profile_url": "https://github.com/octocat"
                        }
                    }
                }),
                json!({
                    "schema": API_V1_SCHEMA,
                    "event_id": "event_3",
                    "search_id": "search_1",
                    "sequence": 3,
                    "emitted_at_unix_ms": 2_100,
                    "data": {
                        "type": "finished",
                        "state": "completed",
                        "progress": {
                            "total_targets": 1,
                            "completed_targets": 1,
                            "definitive_results": 1,
                            "uncertain_results": 0,
                            "operational_failures": 0
                        }
                    }
                }),
            ];
            let body = event_values
                .iter()
                .enumerate()
                .map(|(index, event)| {
                    format!(
                        "id: event_{}\nevent: search_event\ndata: {}\n\n",
                        index + 1,
                        serde_json::to_string(event).unwrap()
                    )
                })
                .collect::<String>();
            ([(header::CONTENT_TYPE, "text/event-stream")], body)
        }

        let app = Router::new()
            .route("/v1/searches", post(create))
            .route("/v1/searches/{search_id}/events", get(events));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let received = std::sync::Mutex::new(Vec::new());
        let outcome = run_managed_search(
            ManagedSearchRun {
                username: "octocat".to_owned(),
                site_ids: vec!["github".to_owned()],
                source: SearchSource::Remote,
                sync: SyncPolicy::Private,
                maximum_age_ms: 86_400_000,
                region_class: "local".to_owned(),
                access: ManagedSearchAccess {
                    api_url: format!("http://{address}"),
                    api_key: "test-api-key".to_owned(),
                    consent_grant_id: "grant_1".to_owned(),
                },
            },
            CancellationToken::new(),
            |event| received.lock().unwrap().push(event),
        )
        .await
        .unwrap();
        server.abort();

        assert_eq!(outcome.search_id.as_str(), "search_1");
        assert_eq!(outcome.terminal_state, SearchTerminalState::Completed);
        assert_eq!(outcome.progress.completed_targets, 1);
        assert_eq!(received.into_inner().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn cancellation_requires_a_valid_terminal_resource() {
        async fn cancel(Path(search_id): Path<String>) -> impl IntoResponse {
            assert_eq!(search_id, "search_1");
            Json(json!({
                "schema": API_V1_SCHEMA,
                "search_id": "search_1",
                "state": "cancelled",
                "request": {
                    "schema": API_V1_SCHEMA,
                    "targets": {
                        "usernames": ["octocat"],
                        "site_ids": ["github"]
                    },
                    "mode": "remote",
                    "sync": "private",
                    "consent_grant_id": "grant_1",
                    "maximum_age_ms": 86_400_000,
                    "region_classes": ["local"]
                },
                "progress": {
                    "total_targets": 1,
                    "completed_targets": 0,
                    "definitive_results": 0,
                    "uncertain_results": 0,
                    "operational_failures": 0
                },
                "created_at_unix_ms": 1_000,
                "updated_at_unix_ms": 2_000
            }))
        }

        let app = Router::new().route("/v1/searches/{search_id}", delete(cancel));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let prepared = PreparedRun::new(ManagedSearchRun {
            username: "octocat".to_owned(),
            site_ids: vec!["github".to_owned()],
            source: SearchSource::Remote,
            sync: SyncPolicy::Private,
            maximum_age_ms: 86_400_000,
            region_class: "local".to_owned(),
            access: ManagedSearchAccess {
                api_url: format!("http://{address}"),
                api_key: "test-api-key".to_owned(),
                consent_grant_id: "grant_1".to_owned(),
            },
        })
        .unwrap();
        let client = Client::new();
        let outcome = cancel_search(&client, &prepared, &SearchId::new("search_1").unwrap())
            .await
            .unwrap();
        server.abort();

        assert_eq!(outcome.terminal_state, SearchTerminalState::Cancelled);
        assert_eq!(outcome.progress.completed_targets, 0);
    }
}
