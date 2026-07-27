use std::{
    collections::HashSet,
    convert::Infallible,
    time::{Duration, Instant},
};

use async_stream::stream;
use axum::{
    Json,
    extract::{
        Extension, Path, Query, State,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{HeaderMap, HeaderValue, StatusCode, header::LOCATION},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use socialname_protocol::{
    API_V1_SCHEMA, ApiError, ApiErrorCode, ApiErrorResponse, ApiKeyScope, ConsentGrantId, EventId,
    IdempotencyKey, MAX_SEARCH_EXPORT_EVENTS, MAX_SEARCH_EXPORT_PAGE_EVENTS,
    MAX_SEARCH_HISTORY_PAGE_ITEMS, PlanCapability, ProtocolVersion, RegionClass, RequestId,
    SearchCreateRequest, SearchEvent, SearchEventData, SearchExportPage, SearchExportSchema,
    SearchHistoryPage, SearchId, SearchMode, SearchProgress, SearchResource, SearchState,
    SearchTerminalState, SiteId, SyncPolicy, Username, Validate, ValidationCode, ValidationErrors,
};
use sqlx::{PgPool, Postgres, QueryBuilder, Transaction};
use tokio::sync::OwnedSemaphorePermit;
use uuid::Uuid;

use crate::{
    ServerState,
    auth::{self, AuthenticatedPrincipal, AuthenticationError},
    plan::{self, PlanCapabilityError},
    standard_api_error, unauthenticated_response,
};

const IDEMPOTENCY_KEY: &str = "idempotency-key";
const LAST_EVENT_ID: &str = "last-event-id";
const SEARCH_EVENT_NAME: &str = "search_event";
const STREAM_ERROR_EVENT_NAME: &str = "stream_error";
const EVENT_BATCH_SIZE: i64 = 128;
const EVENT_POLL_INTERVAL: Duration = Duration::from_millis(250);
const EVENT_STREAM_WINDOW: Duration = Duration::from_secs(30);
const EVENT_RETRY_DELAY: Duration = Duration::from_secs(1);
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);
const DEFAULT_HISTORY_PAGE_ITEMS: usize = 20;
const DEFAULT_EXPORT_PAGE_EVENTS: usize = 20;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SearchPageQuery {
    limit: Option<u16>,
    after: Option<String>,
}

#[derive(Clone, Copy)]
struct PageRequest {
    limit: usize,
    after: Option<Uuid>,
}

pub(crate) async fn create_search(
    State(state): State<ServerState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    headers: HeaderMap,
    payload: Result<Json<SearchCreateRequest>, JsonRejection>,
) -> Response {
    let idempotency_key = match parse_idempotency_key(&headers) {
        Ok(key) => key,
        Err(error) => return error_response(request_id, error),
    };
    let Json(request) = match payload {
        Ok(payload) => payload,
        Err(rejection) => {
            return invalid_request_response_with_status(
                if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
                    StatusCode::PAYLOAD_TOO_LARGE
                } else {
                    StatusCode::BAD_REQUEST
                },
                request_id,
                ValidationErrors::new(
                    "body",
                    if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
                        ValidationCode::TooManyItems
                    } else {
                        ValidationCode::InvalidFormat
                    },
                ),
            );
        }
    };
    if let Err(errors) = validate_managed_search_request(&request) {
        return invalid_request_response(request_id, errors);
    }

    match persist_search(&state.database, &principal, &idempotency_key, &request).await {
        Ok(CreateSearchOutcome { resource, replayed }) => {
            let location = format!("/v1/searches/{}", resource.search_id.as_str());
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

pub(crate) async fn get_search(
    State(state): State<ServerState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Path(search_id): Path<String>,
) -> Response {
    let search_id = match parse_search_id(&search_id) {
        Ok(search_id) => search_id,
        Err(error) => return error_response(request_id, error),
    };
    match load_search(
        &state.database,
        &principal,
        search_id,
        ApiKeyScope::SearchRead,
    )
    .await
    {
        Ok(resource) => Json(resource).into_response(),
        Err(error) => error_response(request_id, error),
    }
}

pub(crate) async fn list_searches(
    State(state): State<ServerState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    query: Result<Query<SearchPageQuery>, QueryRejection>,
) -> Response {
    let page = match parse_page_query(
        query,
        DEFAULT_HISTORY_PAGE_ITEMS,
        MAX_SEARCH_HISTORY_PAGE_ITEMS,
    ) {
        Ok(page) => page,
        Err(error) => return error_response(request_id, error),
    };
    match load_search_history_page(&state.database, &principal, page).await {
        Ok(resource) => Json(resource).into_response(),
        Err(error) => error_response(request_id, error),
    }
}

pub(crate) async fn export_search(
    State(state): State<ServerState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Path(search_id): Path<String>,
    query: Result<Query<SearchPageQuery>, QueryRejection>,
) -> Response {
    let search_id = match parse_search_id(&search_id) {
        Ok(search_id) => search_id,
        Err(error) => return error_response(request_id, error),
    };
    let page = match parse_page_query(
        query,
        DEFAULT_EXPORT_PAGE_EVENTS,
        MAX_SEARCH_EXPORT_PAGE_EVENTS,
    ) {
        Ok(page) => page,
        Err(error) => return error_response(request_id, error),
    };
    match load_search_export_page(&state.database, &principal, search_id, page).await {
        Ok(resource) => Json(resource).into_response(),
        Err(error) => error_response(request_id, error),
    }
}

pub(crate) async fn cancel_search(
    State(state): State<ServerState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Path(search_id): Path<String>,
) -> Response {
    let search_id = match parse_search_id(&search_id) {
        Ok(search_id) => search_id,
        Err(error) => return error_response(request_id, error),
    };
    match cancel_persisted_search(&state.database, &principal, search_id).await {
        Ok(resource) => Json(resource).into_response(),
        Err(error) => error_response(request_id, error),
    }
}

pub(crate) async fn search_events(
    State(state): State<ServerState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Path(search_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let search_id = match parse_search_id(&search_id) {
        Ok(search_id) => search_id,
        Err(error) => return error_response(request_id, error),
    };
    let after_event_id = match parse_last_event_id(&headers) {
        Ok(event_id) => event_id,
        Err(error) => return error_response(request_id, error),
    };
    let permit = match state.sse_connections.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return crate::api_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                request_id,
                standard_api_error(ApiErrorCode::Unavailable, true),
            );
        }
    };
    let after_sequence =
        match resolve_event_cursor(&state.database, &principal, search_id, after_event_id).await {
            Ok(sequence) => sequence,
            Err(error) => return error_response(request_id, error),
        };

    let stream = persisted_event_stream(
        state.database,
        principal,
        search_id,
        after_sequence,
        request_id,
        permit,
    );
    Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(KEEP_ALIVE_INTERVAL)
                .text("keep-alive"),
        )
        .into_response()
}

fn validate_managed_search_request(request: &SearchCreateRequest) -> Result<(), ValidationErrors> {
    request.validate()?;
    if !matches!(request.mode, SearchMode::Remote | SearchMode::Hybrid) {
        return Err(ValidationErrors::new(
            "mode",
            ValidationCode::InvalidRelation,
        ));
    }
    if request.sync == SyncPolicy::Never {
        return Err(ValidationErrors::new(
            "sync",
            ValidationCode::InvalidRelation,
        ));
    }
    Ok(())
}

fn parse_idempotency_key(headers: &HeaderMap) -> Result<IdempotencyKey, SearchError> {
    let mut values = headers.get_all(IDEMPOTENCY_KEY).iter();
    let value = values.next().ok_or(SearchError::InvalidRequest(
        "idempotency_key",
        ValidationCode::InvalidFormat,
    ))?;
    if values.next().is_some() {
        return Err(SearchError::InvalidRequest(
            "idempotency_key",
            ValidationCode::Duplicate,
        ));
    }
    let value = value.to_str().map_err(|_| {
        SearchError::InvalidRequest("idempotency_key", ValidationCode::InvalidFormat)
    })?;
    IdempotencyKey::new(value.to_owned())
        .map_err(|_| SearchError::InvalidRequest("idempotency_key", ValidationCode::InvalidFormat))
}

fn parse_last_event_id(headers: &HeaderMap) -> Result<Option<Uuid>, SearchError> {
    let mut values = headers.get_all(LAST_EVENT_ID).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(SearchError::InvalidRequest(
            "last_event_id",
            ValidationCode::Duplicate,
        ));
    }
    let value = value
        .to_str()
        .map_err(|_| SearchError::InvalidRequest("last_event_id", ValidationCode::InvalidFormat))?;
    Uuid::parse_str(value)
        .map(Some)
        .map_err(|_| SearchError::InvalidRequest("last_event_id", ValidationCode::InvalidFormat))
}

fn parse_search_id(value: &str) -> Result<Uuid, SearchError> {
    Uuid::parse_str(value)
        .map_err(|_| SearchError::InvalidRequest("search_id", ValidationCode::InvalidFormat))
}

fn parse_page_query(
    query: Result<Query<SearchPageQuery>, QueryRejection>,
    default_limit: usize,
    maximum_limit: usize,
) -> Result<PageRequest, SearchError> {
    let Query(query) =
        query.map_err(|_| SearchError::InvalidRequest("query", ValidationCode::InvalidFormat))?;
    let limit = usize::from(
        query
            .limit
            .unwrap_or(u16::try_from(default_limit).map_err(|_| SearchError::Unavailable)?),
    );
    if !(1..=maximum_limit).contains(&limit) {
        return Err(SearchError::InvalidRequest(
            "limit",
            ValidationCode::OutOfRange,
        ));
    }
    let after = query
        .after
        .map(|value| {
            Uuid::parse_str(&value)
                .map_err(|_| SearchError::InvalidRequest("after", ValidationCode::InvalidFormat))
        })
        .transpose()?;
    Ok(PageRequest { limit, after })
}

struct CreateSearchOutcome {
    resource: SearchResource,
    replayed: bool,
}

async fn persist_search(
    pool: &PgPool,
    principal: &AuthenticatedPrincipal,
    idempotency_key: &IdempotencyKey,
    request: &SearchCreateRequest,
) -> Result<CreateSearchOutcome, SearchError> {
    let consent_grant_id = request
        .consent_grant_id
        .as_ref()
        .and_then(|id| Uuid::parse_str(id.as_str()).ok())
        .ok_or(SearchError::InvalidRequest(
            "consent_grant_id",
            ValidationCode::InvalidFormat,
        ))?;
    let mut transaction =
        auth::begin_authorized_transaction(pool, principal, ApiKeyScope::SearchWrite).await?;
    verify_known_sites(&mut transaction, request).await?;
    verify_consent(&mut transaction, principal, consent_grant_id, request.sync).await?;

    let idempotency_hash = Sha256::digest(idempotency_key.as_str().as_bytes());
    let search_id = Uuid::new_v4();
    let mode = search_mode_value(request.mode);
    let sync = sync_policy_value(request.sync);
    let inserted: Option<(Uuid, i64)> = sqlx::query_as(
        "INSERT INTO searches (\
            id, tenant_id, requested_by_api_key_id, idempotency_key_hash, \
            mode, sync_policy, consent_grant_id, maximum_age_ms, region_classes, \
            state, created_at, updated_at\
         ) VALUES (\
            $1, $2, $3, $4, $5, $6, $7, $8, $9, 'accepted', \
            clock_timestamp(), clock_timestamp()\
         ) \
         ON CONFLICT (tenant_id, idempotency_key_hash) DO NOTHING \
         RETURNING id, (EXTRACT(EPOCH FROM created_at) * 1000)::bigint",
    )
    .bind(search_id)
    .bind(principal.workspace_id)
    .bind(principal.api_key_id)
    .bind(&idempotency_hash[..])
    .bind(mode)
    .bind(sync)
    .bind(consent_grant_id)
    .bind(request.maximum_age_ms)
    .bind(
        request
            .region_classes
            .iter()
            .map(|region| region.as_str().to_owned())
            .collect::<Vec<_>>(),
    )
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| SearchError::Unavailable)?;

    let (search_id, replayed) = if let Some((search_id, created_at_unix_ms)) = inserted {
        insert_search_targets(&mut transaction, principal.workspace_id, search_id, request).await?;
        plan::require_plan_capability(
            &mut transaction,
            principal.workspace_id,
            PlanCapability::ManagedSearch,
        )
        .await
        .map_err(|error| match error {
            PlanCapabilityError::Required => SearchError::EntitlementRequired,
            PlanCapabilityError::Unavailable => SearchError::Unavailable,
        })?;
        admit_developer_usage(
            &mut transaction,
            principal.workspace_id,
            principal.api_key_id,
            search_id,
            target_count(request)?,
        )
        .await?;
        insert_started_event(
            &mut transaction,
            principal.workspace_id,
            search_id,
            created_at_unix_ms,
            target_count(request)?,
        )
        .await?;
        (search_id, false)
    } else {
        let existing_id: Uuid = sqlx::query_scalar(
            "SELECT id FROM searches \
             WHERE tenant_id = $1 AND idempotency_key_hash = $2",
        )
        .bind(principal.workspace_id)
        .bind(&idempotency_hash[..])
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| SearchError::Unavailable)?;
        (existing_id, true)
    };

    let resource =
        load_search_resource(&mut transaction, principal.workspace_id, search_id).await?;
    if replayed && resource.request != *request {
        return Err(SearchError::IdempotencyConflict);
    }
    transaction
        .commit()
        .await
        .map_err(|_| SearchError::Unavailable)?;
    Ok(CreateSearchOutcome { resource, replayed })
}

async fn admit_developer_usage(
    transaction: &mut Transaction<'_, Postgres>,
    workspace_id: Uuid,
    api_key_id: Uuid,
    search_id: Uuid,
    quantity: u32,
) -> Result<(), SearchError> {
    let limits: Option<(i32, i32)> = sqlx::query_as(
        "SELECT daily_target_limit, api_key_daily_target_limit \
         FROM socialname_lock_developer_quota($1)",
    )
    .bind(workspace_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| SearchError::Unavailable)?;
    let Some((tenant_limit, api_key_limit)) = limits else {
        return Err(SearchError::Unavailable);
    };

    // This statement intentionally follows the policy lock. Under PostgreSQL's
    // READ COMMITTED isolation it receives a fresh snapshot after any preceding
    // quota admission for the tenant has committed.
    let (tenant_used, api_key_used, retry_after_ms): (i64, i64, i64) = sqlx::query_as(
        r#"
        WITH bounds AS MATERIALIZED (
            SELECT
                statement_timestamp() AS generated_at,
                date_trunc('day', statement_timestamp() AT TIME ZONE 'UTC')
                    AT TIME ZONE 'UTC' AS period_started_at
        )
        SELECT
            COALESCE((
                SELECT sum(usage.quantity)
                FROM developer_usage_records AS usage
                CROSS JOIN bounds
                WHERE usage.tenant_id = $1
                  AND usage.occurred_at >= bounds.period_started_at
                  AND usage.occurred_at < bounds.generated_at
                  AND usage.retained_until > bounds.generated_at
            ), 0)::bigint AS tenant_used,
            COALESCE((
                SELECT sum(usage.quantity)
                FROM developer_usage_records AS usage
                CROSS JOIN bounds
                WHERE usage.tenant_id = $1
                  AND usage.api_key_id = $2
                  AND usage.occurred_at >= bounds.period_started_at
                  AND usage.occurred_at < bounds.generated_at
                  AND usage.retained_until > bounds.generated_at
            ), 0)::bigint AS api_key_used,
            (
                EXTRACT(EPOCH FROM (
                    bounds.period_started_at + interval '1 day'
                    - bounds.generated_at
                )) * 1000
            )::bigint AS retry_after_ms
        FROM bounds
        "#,
    )
    .bind(workspace_id)
    .bind(api_key_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| SearchError::Unavailable)?;
    let quantity = i64::from(quantity);
    if tenant_used
        .checked_add(quantity)
        .is_none_or(|used| used > i64::from(tenant_limit))
        || api_key_used
            .checked_add(quantity)
            .is_none_or(|used| used > i64::from(api_key_limit))
    {
        return Err(SearchError::QuotaExceeded(
            u64::try_from(retry_after_ms.max(1)).map_err(|_| SearchError::Unavailable)?,
        ));
    }

    sqlx::query(
        "INSERT INTO developer_usage_records (\
            id, tenant_id, api_key_id, search_id, meter, quantity, \
            occurred_at, retained_until\
         ) \
         SELECT \
            $1, search.tenant_id, $2, search.id, \
            'search_target_admitted', $3, search.created_at, \
            search.created_at + interval '400 days' \
         FROM searches AS search \
         WHERE search.tenant_id = $4 AND search.id = $5",
    )
    .bind(Uuid::new_v4())
    .bind(api_key_id)
    .bind(i32::try_from(quantity).map_err(|_| SearchError::Unavailable)?)
    .bind(workspace_id)
    .bind(search_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| SearchError::Unavailable)?;
    Ok(())
}

async fn verify_known_sites(
    transaction: &mut Transaction<'_, Postgres>,
    request: &SearchCreateRequest,
) -> Result<(), SearchError> {
    let site_ids = request
        .targets
        .site_ids
        .iter()
        .map(|site_id| site_id.as_str().to_owned())
        .collect::<Vec<_>>();
    let known_count: i64 = sqlx::query_scalar("SELECT count(*) FROM sites WHERE id = ANY($1)")
        .bind(&site_ids)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|_| SearchError::Unavailable)?;
    if usize::try_from(known_count).ok() == Some(site_ids.len()) {
        Ok(())
    } else {
        Err(SearchError::InvalidRequest(
            "targets.site_ids",
            ValidationCode::InvalidRelation,
        ))
    }
}

async fn verify_consent(
    transaction: &mut Transaction<'_, Postgres>,
    principal: &AuthenticatedPrincipal,
    consent_grant_id: Uuid,
    sync: SyncPolicy,
) -> Result<(), SearchError> {
    let purpose = match sync {
        SyncPolicy::Private => "private_history",
        SyncPolicy::Shared => "shared_observation",
        SyncPolicy::Never => {
            return Err(SearchError::InvalidRequest(
                "sync",
                ValidationCode::InvalidRelation,
            ));
        }
    };
    let authorized: bool = sqlx::query_scalar(
        "SELECT EXISTS (\
            SELECT 1 \
            FROM consent_grants AS consent \
            JOIN api_keys AS key \
              ON key.tenant_id = consent.tenant_id \
             AND key.created_by_membership_id = consent.membership_id \
            WHERE consent.tenant_id = $1 AND consent.id = $2 \
              AND key.id = $3 AND consent.subject_kind = 'account' \
              AND consent.purpose = $4 AND consent.withdrawn_at IS NULL \
              AND consent.collection_profile_version = 'profile-v1' \
              AND consent.notice_version = 'notice-v1' \
              AND consent.granted_at <= clock_timestamp() \
              AND (consent.expires_at IS NULL OR consent.expires_at > clock_timestamp())\
         )",
    )
    .bind(principal.workspace_id)
    .bind(consent_grant_id)
    .bind(principal.api_key_id)
    .bind(purpose)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| SearchError::Unavailable)?;
    if authorized {
        Ok(())
    } else {
        Err(SearchError::ConsentForbidden)
    }
}

async fn insert_search_targets(
    transaction: &mut Transaction<'_, Postgres>,
    workspace_id: Uuid,
    search_id: Uuid,
    request: &SearchCreateRequest,
) -> Result<(), SearchError> {
    let mut targets = Vec::with_capacity(
        request
            .targets
            .usernames
            .len()
            .saturating_mul(request.targets.site_ids.len()),
    );
    for username in &request.targets.usernames {
        for site_id in &request.targets.site_ids {
            let ordinal = i32::try_from(targets.len()).map_err(|_| SearchError::Unavailable)?;
            targets.push((
                Uuid::new_v4(),
                username.as_str().to_owned(),
                site_id.as_str().to_owned(),
                ordinal,
            ));
        }
    }

    let mut query = QueryBuilder::<Postgres>::new(
        "INSERT INTO search_targets (\
            id, tenant_id, search_id, requested_username, site_id, ordinal, created_at\
         ) ",
    );
    query.push_values(targets, |mut row, (id, username, site_id, ordinal)| {
        row.push_bind(id)
            .push_bind(workspace_id)
            .push_bind(search_id)
            .push_bind(username)
            .push_bind(site_id)
            .push_bind(ordinal)
            .push("clock_timestamp()");
    });
    query
        .build()
        .execute(&mut **transaction)
        .await
        .map_err(|_| SearchError::Unavailable)?;
    Ok(())
}

async fn insert_started_event(
    transaction: &mut Transaction<'_, Postgres>,
    workspace_id: Uuid,
    search_id: Uuid,
    emitted_at_unix_ms: i64,
    total_targets: u32,
) -> Result<(), SearchError> {
    let event_id = Uuid::new_v4();
    let event = SearchEvent {
        schema: ProtocolVersion::ApiV1,
        event_id: EventId::new(event_id.to_string()).map_err(|_| SearchError::Unavailable)?,
        search_id: SearchId::new(search_id.to_string()).map_err(|_| SearchError::Unavailable)?,
        sequence: 1,
        emitted_at_unix_ms,
        data: SearchEventData::Started { total_targets },
    };
    insert_event(
        transaction,
        workspace_id,
        search_id,
        None,
        event_id,
        "started",
        &event,
    )
    .await
}

async fn insert_event(
    transaction: &mut Transaction<'_, Postgres>,
    workspace_id: Uuid,
    search_id: Uuid,
    search_target_id: Option<Uuid>,
    event_id: Uuid,
    event_type: &'static str,
    event: &SearchEvent,
) -> Result<(), SearchError> {
    event.validate().map_err(|_| SearchError::Unavailable)?;
    let payload = serde_json::to_string(event).map_err(|_| SearchError::Unavailable)?;
    let sequence = i64::try_from(event.sequence).map_err(|_| SearchError::Unavailable)?;
    sqlx::query(
        "INSERT INTO search_events (\
            id, tenant_id, search_id, search_target_id, sequence, event_type, \
            payload, emitted_at, created_at\
         ) VALUES (\
            $1, $2, $3, $4, $5, $6, $7::jsonb, \
            to_timestamp($8::double precision / 1000.0), clock_timestamp()\
         )",
    )
    .bind(event_id)
    .bind(workspace_id)
    .bind(search_id)
    .bind(search_target_id)
    .bind(sequence)
    .bind(event_type)
    .bind(payload)
    .bind(event.emitted_at_unix_ms)
    .execute(&mut **transaction)
    .await
    .map_err(|_| SearchError::Unavailable)?;
    Ok(())
}

async fn load_search_history_page(
    pool: &PgPool,
    principal: &AuthenticatedPrincipal,
    page: PageRequest,
) -> Result<SearchHistoryPage, SearchError> {
    let mut transaction =
        auth::begin_authorized_transaction(pool, principal, ApiKeyScope::SearchRead).await?;
    ensure_visible_search_cursor(&mut transaction, principal.workspace_id, page.after).await?;
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT search.id \
         FROM searches AS search \
         WHERE search.tenant_id = $1 \
           AND NOT EXISTS (\
               SELECT 1 \
               FROM search_targets AS target \
               JOIN deletion_resource_matches AS matched \
                 ON matched.tenant_id = target.tenant_id \
                AND matched.resource_kind = 'search_target' \
                AND matched.resource_id = target.id \
               WHERE target.tenant_id = search.tenant_id \
                 AND target.search_id = search.id\
           ) \
           AND NOT EXISTS (\
               SELECT 1 \
               FROM search_events AS event \
               JOIN deletion_resource_matches AS matched \
                 ON matched.tenant_id = event.tenant_id \
                AND matched.resource_kind = 'search_event' \
                AND matched.resource_id = event.id \
               WHERE event.tenant_id = search.tenant_id \
                 AND event.search_id = search.id\
           ) \
           AND (\
               $2::uuid IS NULL \
               OR EXISTS (\
                   SELECT 1 FROM searches AS cursor \
                   WHERE cursor.tenant_id = search.tenant_id AND cursor.id = $2 \
                     AND (search.created_at, search.id) < (cursor.created_at, cursor.id)\
               )\
           ) \
         ORDER BY search.created_at DESC, search.id DESC \
         LIMIT $3",
    )
    .bind(principal.workspace_id)
    .bind(page.after)
    .bind(i64::try_from(page.limit + 1).map_err(|_| SearchError::Unavailable)?)
    .fetch_all(&mut *transaction)
    .await
    .map_err(|_| SearchError::Unavailable)?;
    let has_more = ids.len() > page.limit;
    let mut searches = Vec::with_capacity(page.limit.min(ids.len()));
    for id in ids.into_iter().take(page.limit) {
        searches.push(load_search_resource(&mut transaction, principal.workspace_id, id).await?);
    }
    let next_cursor = has_more
        .then(|| searches.last())
        .flatten()
        .map(|search| search.search_id.clone());
    let resource = SearchHistoryPage {
        schema: ProtocolVersion::ApiV1,
        searches,
        next_cursor,
    };
    resource.validate().map_err(|_| SearchError::Unavailable)?;
    transaction
        .commit()
        .await
        .map_err(|_| SearchError::Unavailable)?;
    Ok(resource)
}

async fn ensure_visible_search_cursor(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    cursor: Option<Uuid>,
) -> Result<(), SearchError> {
    let Some(cursor) = cursor else {
        return Ok(());
    };
    if search_is_visible(transaction, tenant_id, cursor).await? {
        Ok(())
    } else {
        Err(SearchError::InvalidRequest(
            "after",
            ValidationCode::InvalidRelation,
        ))
    }
}

async fn load_search_export_page(
    pool: &PgPool,
    principal: &AuthenticatedPrincipal,
    search_id: Uuid,
    page: PageRequest,
) -> Result<SearchExportPage, SearchError> {
    let mut transaction =
        auth::begin_authorized_transaction(pool, principal, ApiKeyScope::DataExport).await?;
    if !search_is_visible(&mut transaction, principal.workspace_id, search_id).await? {
        return Err(SearchError::NotFound);
    }
    let search = load_search_resource(&mut transaction, principal.workspace_id, search_id).await?;
    if !matches!(
        search.state,
        SearchState::Completed | SearchState::Cancelled | SearchState::Failed
    ) {
        return Err(SearchError::ExportNotTerminal);
    }
    let after_sequence = if let Some(after) = page.after {
        sqlx::query_scalar(
            "SELECT sequence \
             FROM search_events \
             WHERE tenant_id = $1 AND search_id = $2 AND id = $3",
        )
        .bind(principal.workspace_id)
        .bind(search_id)
        .bind(after)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| SearchError::Unavailable)?
        .ok_or(SearchError::InvalidRequest(
            "after",
            ValidationCode::InvalidRelation,
        ))?
    } else {
        0_i64
    };
    let total_events: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM search_events \
         WHERE tenant_id = $1 AND search_id = $2",
    )
    .bind(principal.workspace_id)
    .bind(search_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| SearchError::Unavailable)?;
    if !(2..=i64::try_from(MAX_SEARCH_EXPORT_EVENTS).unwrap_or(i64::MAX)).contains(&total_events) {
        return Err(SearchError::Unavailable);
    }
    let rows: Vec<(i64, String)> = sqlx::query_as(
        "SELECT sequence, payload::text \
         FROM search_events \
         WHERE tenant_id = $1 AND search_id = $2 AND sequence > $3 \
         ORDER BY sequence \
         LIMIT $4",
    )
    .bind(principal.workspace_id)
    .bind(search_id)
    .bind(after_sequence)
    .bind(i64::try_from(page.limit + 1).map_err(|_| SearchError::Unavailable)?)
    .fetch_all(&mut *transaction)
    .await
    .map_err(|_| SearchError::Unavailable)?;
    transaction
        .commit()
        .await
        .map_err(|_| SearchError::Unavailable)?;

    let has_more = rows.len() > page.limit;
    let mut events = Vec::with_capacity(page.limit.min(rows.len()));
    for (sequence, payload) in rows.into_iter().take(page.limit) {
        let event: SearchEvent =
            serde_json::from_str(&payload).map_err(|_| SearchError::Unavailable)?;
        event.validate().map_err(|_| SearchError::Unavailable)?;
        if i64::try_from(event.sequence).ok() != Some(sequence) {
            return Err(SearchError::Unavailable);
        }
        events.push(event);
    }
    let next_cursor = has_more
        .then(|| events.last())
        .flatten()
        .map(|event| event.event_id.clone());
    let resource = SearchExportPage {
        schema: ProtocolVersion::ApiV1,
        export_schema: SearchExportSchema::V1,
        search,
        events,
        total_events: u32::try_from(total_events).map_err(|_| SearchError::Unavailable)?,
        complete: !has_more,
        next_cursor,
    };
    resource.validate().map_err(|_| SearchError::Unavailable)?;
    Ok(resource)
}

async fn search_is_visible(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    search_id: Uuid,
) -> Result<bool, SearchError> {
    sqlx::query_scalar(
        "SELECT EXISTS (\
            SELECT 1 FROM searches AS search \
            WHERE search.tenant_id = $1 AND search.id = $2 \
              AND NOT EXISTS (\
                  SELECT 1 \
                  FROM search_targets AS target \
                  JOIN deletion_resource_matches AS matched \
                    ON matched.tenant_id = target.tenant_id \
                   AND matched.resource_kind = 'search_target' \
                   AND matched.resource_id = target.id \
                  WHERE target.tenant_id = search.tenant_id \
                    AND target.search_id = search.id\
              ) \
              AND NOT EXISTS (\
                  SELECT 1 \
                  FROM search_events AS event \
                  JOIN deletion_resource_matches AS matched \
                    ON matched.tenant_id = event.tenant_id \
                   AND matched.resource_kind = 'search_event' \
                   AND matched.resource_id = event.id \
                  WHERE event.tenant_id = search.tenant_id \
                    AND event.search_id = search.id\
              )\
         )",
    )
    .bind(tenant_id)
    .bind(search_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| SearchError::Unavailable)
}

async fn load_search(
    pool: &PgPool,
    principal: &AuthenticatedPrincipal,
    search_id: Uuid,
    required_scope: ApiKeyScope,
) -> Result<SearchResource, SearchError> {
    let mut transaction =
        auth::begin_authorized_transaction(pool, principal, required_scope).await?;
    let resource =
        load_search_resource(&mut transaction, principal.workspace_id, search_id).await?;
    transaction
        .commit()
        .await
        .map_err(|_| SearchError::Unavailable)?;
    Ok(resource)
}

async fn load_search_resource(
    transaction: &mut Transaction<'_, Postgres>,
    workspace_id: Uuid,
    search_id: Uuid,
) -> Result<SearchResource, SearchError> {
    load_search_resource_with_terminal_check(transaction, workspace_id, search_id, true).await
}

async fn load_search_resource_with_terminal_check(
    transaction: &mut Transaction<'_, Postgres>,
    workspace_id: Uuid,
    search_id: Uuid,
    require_terminal_event: bool,
) -> Result<SearchResource, SearchError> {
    let row: Option<PersistedSearch> = sqlx::query_as(
        "SELECT mode, sync_policy, consent_grant_id, maximum_age_ms, \
                region_classes, state, \
                (EXTRACT(EPOCH FROM created_at) * 1000)::bigint \
                    AS created_at_unix_ms, \
                (EXTRACT(EPOCH FROM updated_at) * 1000)::bigint \
                    AS updated_at_unix_ms \
         FROM searches WHERE tenant_id = $1 AND id = $2",
    )
    .bind(workspace_id)
    .bind(search_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| SearchError::Unavailable)?;
    let Some(PersistedSearch {
        mode,
        sync_policy,
        consent_grant_id,
        maximum_age_ms,
        region_classes,
        state,
        created_at_unix_ms,
        updated_at_unix_ms,
    }) = row
    else {
        return Err(SearchError::NotFound);
    };

    let target_rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT requested_username, site_id \
         FROM search_targets \
         WHERE tenant_id = $1 AND search_id = $2 \
         ORDER BY ordinal",
    )
    .bind(workspace_id)
    .bind(search_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| SearchError::Unavailable)?;
    if target_rows.is_empty() {
        return Err(SearchError::Unavailable);
    }
    let mut seen_usernames = HashSet::new();
    let mut seen_sites = HashSet::new();
    let mut usernames = Vec::new();
    let mut site_ids = Vec::new();
    for (username, site_id) in &target_rows {
        if seen_usernames.insert(username.clone()) {
            usernames.push(Username::new(username.clone()).map_err(|_| SearchError::Unavailable)?);
        }
        if seen_sites.insert(site_id.clone()) {
            site_ids.push(SiteId::new(site_id.clone()).map_err(|_| SearchError::Unavailable)?);
        }
    }

    let counts: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT \
            count(*) FILTER (WHERE event_type = 'definitive_result'), \
            count(*) FILTER (WHERE event_type = 'uncertain_result'), \
            count(*) FILTER (WHERE event_type = 'operational_failure'), \
            count(*) FILTER (WHERE event_type = 'finished') \
         FROM search_events AS event \
         WHERE event.tenant_id = $1 AND event.search_id = $2 \
           AND NOT EXISTS (\
               SELECT 1 FROM deletion_resource_matches AS matched \
               WHERE matched.tenant_id = event.tenant_id \
                 AND matched.resource_kind = 'search_event' \
                 AND matched.resource_id = event.id\
           )",
    )
    .bind(workspace_id)
    .bind(search_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| SearchError::Unavailable)?;
    let definitive_results = count_to_u32(counts.0)?;
    let uncertain_results = count_to_u32(counts.1)?;
    let operational_failures = count_to_u32(counts.2)?;
    let completed_targets = definitive_results
        .checked_add(uncertain_results)
        .and_then(|count| count.checked_add(operational_failures))
        .ok_or(SearchError::Unavailable)?;
    let search_state = parse_search_state(&state)?;
    if require_terminal_event {
        let terminal = matches!(
            search_state,
            SearchState::Completed | SearchState::Cancelled | SearchState::Failed
        );
        if terminal != (counts.3 == 1) {
            return Err(SearchError::Unavailable);
        }
    }

    let request = SearchCreateRequest {
        schema: ProtocolVersion::ApiV1,
        targets: socialname_protocol::TargetSelection {
            usernames,
            site_ids,
        },
        mode: parse_search_mode(&mode)?,
        sync: parse_sync_policy(&sync_policy)?,
        consent_grant_id: consent_grant_id
            .map(|id| ConsentGrantId::new(id.to_string()))
            .transpose()
            .map_err(|_| SearchError::Unavailable)?,
        maximum_age_ms,
        region_classes: region_classes
            .into_iter()
            .map(RegionClass::new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| SearchError::Unavailable)?,
    };
    let resource = SearchResource {
        schema: ProtocolVersion::ApiV1,
        search_id: SearchId::new(search_id.to_string()).map_err(|_| SearchError::Unavailable)?,
        state: search_state,
        request,
        progress: SearchProgress {
            total_targets: count_to_u32(
                i64::try_from(target_rows.len()).map_err(|_| SearchError::Unavailable)?,
            )?,
            completed_targets,
            definitive_results,
            uncertain_results,
            operational_failures,
        },
        created_at_unix_ms,
        updated_at_unix_ms,
    };
    resource.validate().map_err(|_| SearchError::Unavailable)?;
    Ok(resource)
}

#[derive(sqlx::FromRow)]
struct PersistedSearch {
    mode: String,
    sync_policy: String,
    consent_grant_id: Option<Uuid>,
    maximum_age_ms: i64,
    region_classes: Vec<String>,
    state: String,
    created_at_unix_ms: i64,
    updated_at_unix_ms: i64,
}

async fn cancel_persisted_search(
    pool: &PgPool,
    principal: &AuthenticatedPrincipal,
    search_id: Uuid,
) -> Result<SearchResource, SearchError> {
    let mut transaction =
        auth::begin_authorized_transaction(pool, principal, ApiKeyScope::SearchWrite).await?;
    let state: Option<String> = sqlx::query_scalar(
        "SELECT state FROM searches \
         WHERE tenant_id = $1 AND id = $2 \
         FOR UPDATE",
    )
    .bind(principal.workspace_id)
    .bind(search_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| SearchError::Unavailable)?;
    let Some(state) = state else {
        return Err(SearchError::NotFound);
    };
    if matches!(state.as_str(), "accepted" | "running") {
        let emitted_at_unix_ms: i64 = sqlx::query_scalar(
            "UPDATE searches \
             SET state = 'cancelled', updated_at = clock_timestamp(), \
                 completed_at = clock_timestamp() \
             WHERE tenant_id = $1 AND id = $2 \
             RETURNING (EXTRACT(EPOCH FROM updated_at) * 1000)::bigint",
        )
        .bind(principal.workspace_id)
        .bind(search_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| SearchError::Unavailable)?;
        sqlx::query(
            "UPDATE search_targets \
             SET state = 'cancelled', completed_at = clock_timestamp() \
             WHERE tenant_id = $1 AND search_id = $2 \
               AND state IN ('pending', 'running')",
        )
        .bind(principal.workspace_id)
        .bind(search_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| SearchError::Unavailable)?;

        let resource = load_search_resource_with_terminal_check(
            &mut transaction,
            principal.workspace_id,
            search_id,
            false,
        )
        .await?;
        let sequence: i64 = sqlx::query_scalar(
            "SELECT COALESCE(max(sequence), 0) + 1 \
             FROM search_events WHERE tenant_id = $1 AND search_id = $2",
        )
        .bind(principal.workspace_id)
        .bind(search_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| SearchError::Unavailable)?;
        let event_id = Uuid::new_v4();
        let event = SearchEvent {
            schema: ProtocolVersion::ApiV1,
            event_id: EventId::new(event_id.to_string()).map_err(|_| SearchError::Unavailable)?,
            search_id: SearchId::new(search_id.to_string())
                .map_err(|_| SearchError::Unavailable)?,
            sequence: u64::try_from(sequence).map_err(|_| SearchError::Unavailable)?,
            emitted_at_unix_ms,
            data: SearchEventData::Finished {
                state: SearchTerminalState::Cancelled,
                progress: resource.progress.clone(),
            },
        };
        insert_event(
            &mut transaction,
            principal.workspace_id,
            search_id,
            None,
            event_id,
            "finished",
            &event,
        )
        .await?;
    }

    let resource =
        load_search_resource(&mut transaction, principal.workspace_id, search_id).await?;
    transaction
        .commit()
        .await
        .map_err(|_| SearchError::Unavailable)?;
    Ok(resource)
}

async fn resolve_event_cursor(
    pool: &PgPool,
    principal: &AuthenticatedPrincipal,
    search_id: Uuid,
    after_event_id: Option<Uuid>,
) -> Result<i64, SearchError> {
    let mut transaction =
        auth::begin_authorized_transaction(pool, principal, ApiKeyScope::SearchRead).await?;
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (\
            SELECT 1 FROM searches WHERE tenant_id = $1 AND id = $2\
         )",
    )
    .bind(principal.workspace_id)
    .bind(search_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| SearchError::Unavailable)?;
    if !exists {
        return Err(SearchError::NotFound);
    }
    let sequence = if let Some(event_id) = after_event_id {
        sqlx::query_scalar(
            "SELECT event.sequence FROM search_events AS event \
             WHERE event.tenant_id = $1 AND event.search_id = $2 AND event.id = $3 \
               AND NOT EXISTS (\
                   SELECT 1 FROM deletion_resource_matches AS matched \
                   WHERE matched.tenant_id = event.tenant_id \
                     AND matched.resource_kind = 'search_event' \
                     AND matched.resource_id = event.id\
               )",
        )
        .bind(principal.workspace_id)
        .bind(search_id)
        .bind(event_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| SearchError::Unavailable)?
        .ok_or(SearchError::InvalidRequest(
            "last_event_id",
            ValidationCode::InvalidRelation,
        ))?
    } else {
        0
    };
    transaction
        .commit()
        .await
        .map_err(|_| SearchError::Unavailable)?;
    Ok(sequence)
}

fn persisted_event_stream(
    pool: PgPool,
    principal: AuthenticatedPrincipal,
    search_id: Uuid,
    mut after_sequence: i64,
    request_id: RequestId,
    permit: OwnedSemaphorePermit,
) -> impl futures_util::Stream<Item = Result<Event, Infallible>> {
    stream! {
        let _permit = permit;
        let deadline = Instant::now() + EVENT_STREAM_WINDOW;
        loop {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return;
            };
            let batch = match tokio::time::timeout(
                remaining,
                fetch_event_batch(&pool, &principal, search_id, after_sequence),
            )
            .await
            {
                Ok(batch) => batch,
                Err(_) => return,
            };
            match batch {
                Ok(batch) => {
                    for persisted in batch.events {
                        after_sequence = persisted.sequence;
                        match persisted.into_sse_event() {
                            Ok(event) => yield Ok(event),
                            Err(error) => {
                                yield Ok(stream_error_event(&request_id, error));
                                return;
                            }
                        }
                    }
                    if batch
                        .terminal_sequence
                        .is_some_and(|sequence| after_sequence >= sequence)
                    {
                        return;
                    }
                }
                Err(error) => {
                    yield Ok(stream_error_event(&request_id, error));
                    return;
                }
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return;
            };
            tokio::time::sleep(EVENT_POLL_INTERVAL.min(remaining)).await;
        }
    }
}

struct EventBatch {
    events: Vec<PersistedEvent>,
    terminal_sequence: Option<i64>,
}

struct PersistedEvent {
    sequence: i64,
    event: SearchEvent,
}

impl PersistedEvent {
    fn into_sse_event(self) -> Result<Event, SearchError> {
        let payload = serde_json::to_string(&self.event).map_err(|_| SearchError::Unavailable)?;
        Ok(Event::default()
            .id(self.event.event_id.as_str())
            .event(SEARCH_EVENT_NAME)
            .retry(EVENT_RETRY_DELAY)
            .data(payload))
    }
}

async fn fetch_event_batch(
    pool: &PgPool,
    principal: &AuthenticatedPrincipal,
    search_id: Uuid,
    after_sequence: i64,
) -> Result<EventBatch, SearchError> {
    let mut transaction =
        auth::begin_authorized_transaction(pool, principal, ApiKeyScope::SearchRead).await?;
    let state: Option<(String, Option<i64>)> = sqlx::query_as(
        "SELECT search.state, (\
            SELECT event.sequence \
            FROM search_events AS event \
            WHERE event.tenant_id = search.tenant_id \
              AND event.search_id = search.id \
              AND event.event_type = 'finished' \
              AND NOT EXISTS (\
                  SELECT 1 FROM deletion_resource_matches AS matched \
                  WHERE matched.tenant_id = event.tenant_id \
                    AND matched.resource_kind = 'search_event' \
                    AND matched.resource_id = event.id\
              )\
         ) \
         FROM searches AS search \
         WHERE search.tenant_id = $1 AND search.id = $2",
    )
    .bind(principal.workspace_id)
    .bind(search_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| SearchError::Unavailable)?;
    let Some((state, terminal_sequence)) = state else {
        return Err(SearchError::NotFound);
    };
    let terminal = matches!(state.as_str(), "completed" | "cancelled" | "failed");
    if terminal != terminal_sequence.is_some() {
        return Err(SearchError::Unavailable);
    }
    let rows: Vec<(i64, String)> = sqlx::query_as(
        "SELECT event.sequence, event.payload::text \
         FROM search_events AS event \
         WHERE event.tenant_id = $1 AND event.search_id = $2 AND event.sequence > $3 \
           AND NOT EXISTS (\
               SELECT 1 FROM deletion_resource_matches AS matched \
               WHERE matched.tenant_id = event.tenant_id \
                 AND matched.resource_kind = 'search_event' \
                 AND matched.resource_id = event.id\
           ) \
         ORDER BY event.sequence \
         LIMIT $4",
    )
    .bind(principal.workspace_id)
    .bind(search_id)
    .bind(after_sequence)
    .bind(EVENT_BATCH_SIZE)
    .fetch_all(&mut *transaction)
    .await
    .map_err(|_| SearchError::Unavailable)?;
    transaction
        .commit()
        .await
        .map_err(|_| SearchError::Unavailable)?;

    let mut events = Vec::with_capacity(rows.len());
    for (sequence, payload) in rows {
        let event: SearchEvent =
            serde_json::from_str(&payload).map_err(|_| SearchError::Unavailable)?;
        event.validate().map_err(|_| SearchError::Unavailable)?;
        if i64::try_from(event.sequence).ok() != Some(sequence) {
            return Err(SearchError::Unavailable);
        }
        events.push(PersistedEvent { sequence, event });
    }
    Ok(EventBatch {
        events,
        terminal_sequence,
    })
}

fn stream_error_event(request_id: &RequestId, error: SearchError) -> Event {
    let response = match error {
        SearchError::InvalidRequest(field, code) => ApiErrorResponse::invalid_request(
            request_id.clone(),
            ValidationErrors::new(field, code),
        ),
        other => {
            let (code, retryable, retry_after_ms) = match other {
                SearchError::Authentication(AuthenticationError::InvalidCredential) => {
                    (ApiErrorCode::Unauthenticated, false, None)
                }
                SearchError::Authentication(AuthenticationError::Forbidden)
                | SearchError::ConsentForbidden
                | SearchError::EntitlementRequired => (ApiErrorCode::Forbidden, false, None),
                SearchError::NotFound => (ApiErrorCode::NotFound, false, None),
                SearchError::IdempotencyConflict => {
                    (ApiErrorCode::IdempotencyConflict, false, None)
                }
                SearchError::ExportNotTerminal => (ApiErrorCode::Conflict, false, None),
                SearchError::QuotaExceeded(delay) => {
                    (ApiErrorCode::QuotaExceeded, true, Some(delay))
                }
                SearchError::Authentication(AuthenticationError::Unavailable)
                | SearchError::Unavailable => (ApiErrorCode::Unavailable, true, None),
                SearchError::InvalidRequest(_, _) => unreachable!(),
            };
            ApiErrorResponse {
                schema: ProtocolVersion::ApiV1,
                request_id: request_id.clone(),
                error: ApiError {
                    code,
                    retryable,
                    retry_after_ms,
                    violations: Vec::new(),
                },
            }
        }
    };
    debug_assert!(response.validate().is_ok());
    let payload = serde_json::to_string(&response).unwrap_or_else(|_| {
        format!(
            "{{\"schema\":\"{API_V1_SCHEMA}\",\"request_id\":\"stream_error\",\
             \"error\":{{\"code\":\"internal\",\"retryable\":false,\
             \"retry_after_ms\":null,\"violations\":[]}}}}"
        )
    });
    Event::default()
        .event(STREAM_ERROR_EVENT_NAME)
        .data(payload)
}

fn error_response(request_id: RequestId, error: SearchError) -> Response {
    match error {
        SearchError::InvalidRequest(field, code) => {
            invalid_request_response(request_id, ValidationErrors::new(field, code))
        }
        SearchError::ConsentForbidden
        | SearchError::EntitlementRequired
        | SearchError::Authentication(AuthenticationError::Forbidden) => crate::api_error_response(
            StatusCode::FORBIDDEN,
            request_id,
            standard_api_error(ApiErrorCode::Forbidden, false),
        ),
        SearchError::NotFound => crate::api_error_response(
            StatusCode::NOT_FOUND,
            request_id,
            standard_api_error(ApiErrorCode::NotFound, false),
        ),
        SearchError::IdempotencyConflict => crate::api_error_response(
            StatusCode::CONFLICT,
            request_id,
            standard_api_error(ApiErrorCode::IdempotencyConflict, false),
        ),
        SearchError::ExportNotTerminal => crate::api_error_response(
            StatusCode::CONFLICT,
            request_id,
            standard_api_error(ApiErrorCode::Conflict, false),
        ),
        SearchError::QuotaExceeded(retry_after_ms) => crate::api_error_response(
            StatusCode::TOO_MANY_REQUESTS,
            request_id,
            ApiError {
                code: ApiErrorCode::QuotaExceeded,
                retryable: true,
                retry_after_ms: Some(retry_after_ms),
                violations: Vec::new(),
            },
        ),
        SearchError::Authentication(AuthenticationError::InvalidCredential) => {
            unauthenticated_response(request_id)
        }
        SearchError::Authentication(AuthenticationError::Unavailable)
        | SearchError::Unavailable => crate::api_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            request_id,
            standard_api_error(ApiErrorCode::Unavailable, true),
        ),
    }
}

fn invalid_request_response(request_id: RequestId, errors: ValidationErrors) -> Response {
    invalid_request_response_with_status(StatusCode::BAD_REQUEST, request_id, errors)
}

fn invalid_request_response_with_status(
    status: StatusCode,
    request_id: RequestId,
    errors: ValidationErrors,
) -> Response {
    let response = ApiErrorResponse::invalid_request(request_id, errors);
    debug_assert!(response.validate().is_ok());
    (status, Json(response)).into_response()
}

fn target_count(request: &SearchCreateRequest) -> Result<u32, SearchError> {
    u32::try_from(
        request
            .targets
            .usernames
            .len()
            .checked_mul(request.targets.site_ids.len())
            .ok_or(SearchError::Unavailable)?,
    )
    .map_err(|_| SearchError::Unavailable)
}

fn count_to_u32(value: i64) -> Result<u32, SearchError> {
    u32::try_from(value).map_err(|_| SearchError::Unavailable)
}

const fn search_mode_value(mode: SearchMode) -> &'static str {
    match mode {
        SearchMode::Local => "local",
        SearchMode::Cache => "cache",
        SearchMode::Remote => "remote",
        SearchMode::Hybrid => "hybrid",
    }
}

const fn sync_policy_value(sync: SyncPolicy) -> &'static str {
    match sync {
        SyncPolicy::Never => "never",
        SyncPolicy::Private => "private",
        SyncPolicy::Shared => "shared",
    }
}

fn parse_search_mode(value: &str) -> Result<SearchMode, SearchError> {
    match value {
        "local" => Ok(SearchMode::Local),
        "cache" => Ok(SearchMode::Cache),
        "remote" => Ok(SearchMode::Remote),
        "hybrid" => Ok(SearchMode::Hybrid),
        _ => Err(SearchError::Unavailable),
    }
}

fn parse_sync_policy(value: &str) -> Result<SyncPolicy, SearchError> {
    match value {
        "never" => Ok(SyncPolicy::Never),
        "private" => Ok(SyncPolicy::Private),
        "shared" => Ok(SyncPolicy::Shared),
        _ => Err(SearchError::Unavailable),
    }
}

fn parse_search_state(value: &str) -> Result<SearchState, SearchError> {
    match value {
        "accepted" => Ok(SearchState::Accepted),
        "running" => Ok(SearchState::Running),
        "completed" => Ok(SearchState::Completed),
        "cancelled" => Ok(SearchState::Cancelled),
        "failed" => Ok(SearchState::Failed),
        _ => Err(SearchError::Unavailable),
    }
}

#[derive(Debug, thiserror::Error)]
enum SearchError {
    #[error("search request is invalid")]
    InvalidRequest(&'static str, ValidationCode),
    #[error("search consent is not authorized")]
    ConsentForbidden,
    #[error("the current plan does not grant managed search")]
    EntitlementRequired,
    #[error("search was not found")]
    NotFound,
    #[error("idempotency key was reused with a different request")]
    IdempotencyConflict,
    #[error("search export requires a terminal search")]
    ExportNotTerminal,
    #[error("developer target quota is exhausted")]
    QuotaExceeded(u64),
    #[error(transparent)]
    Authentication(#[from] AuthenticationError),
    #[error("search storage is unavailable")]
    Unavailable,
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;
    use socialname_protocol::{TargetSelection, WorkspaceId};

    use super::*;

    fn request() -> SearchCreateRequest {
        SearchCreateRequest {
            schema: ProtocolVersion::ApiV1,
            targets: TargetSelection {
                usernames: vec![Username::new("private-target").unwrap()],
                site_ids: vec![SiteId::new("github").unwrap()],
            },
            mode: SearchMode::Remote,
            sync: SyncPolicy::Private,
            consent_grant_id: Some(ConsentGrantId::new(Uuid::nil().to_string()).unwrap()),
            maximum_age_ms: 60_000,
            region_classes: vec![RegionClass::new("jp").unwrap()],
        }
    }

    #[test]
    fn managed_request_requires_remote_sync_and_consent() {
        assert!(validate_managed_search_request(&request()).is_ok());

        let mut local = request();
        local.mode = SearchMode::Local;
        assert!(validate_managed_search_request(&local).is_err());

        let mut never = request();
        never.sync = SyncPolicy::Never;
        never.consent_grant_id = None;
        assert!(validate_managed_search_request(&never).is_err());
    }

    #[test]
    fn idempotency_and_resume_headers_are_strict_and_redacted() {
        let mut headers = HeaderMap::new();
        headers.insert(
            IDEMPOTENCY_KEY,
            HeaderValue::from_static("private-replay-key"),
        );
        let key = parse_idempotency_key(&headers).unwrap();
        assert_eq!(key.as_str(), "private-replay-key");
        assert!(!format!("{key:?}").contains("private-replay-key"));

        headers.append(
            IDEMPOTENCY_KEY,
            HeaderValue::from_static("private-replay-key"),
        );
        assert!(parse_idempotency_key(&headers).is_err());

        let mut resume = HeaderMap::new();
        resume.insert(LAST_EVENT_ID, HeaderValue::from_static("not-a-uuid"));
        assert!(parse_last_event_id(&resume).is_err());
    }

    #[test]
    fn stream_errors_never_include_search_or_workspace_values() {
        let request_id = RequestId::new("request_01").unwrap();
        let event = stream_error_event(&request_id, SearchError::Unavailable);
        let rendered = format!("{event:?}");
        assert!(!rendered.contains("private-target"));
        assert!(!rendered.contains(WorkspaceId::new("workspace_01").unwrap().as_str()));
    }
}
