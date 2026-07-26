use std::collections::HashSet;

use axum::{
    Json,
    extract::{Extension, Path, State, rejection::JsonRejection},
    http::{HeaderValue, StatusCode, header::LOCATION},
    response::{IntoResponse, Response},
};
use sha2::{Digest, Sha256};
use socialname_protocol::{
    ApiErrorCode, ApiKeyScope, ConsentGrantId, NotificationEndpointId, ProbeBudget,
    ProtocolVersion, RegionClass, RequestId, SiteId, TargetSelection, Username, Validate,
    ValidationCode, ValidationErrors, WatchCreateRequest, WatchId, WatchPatchRequest,
    WatchResource, WatchSchedule, WatchState, WatchStateUpdate,
};
use sqlx::{FromRow, PgPool, Postgres, QueryBuilder, Transaction};
use uuid::Uuid;

use crate::{
    ServerState,
    auth::{self, AuthenticatedPrincipal, AuthenticationError},
    standard_api_error, unauthenticated_response,
};

pub(crate) async fn create_watch(
    State(state): State<ServerState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    payload: Result<Json<WatchCreateRequest>, JsonRejection>,
) -> Response {
    let request = match parse_json(payload) {
        Ok(request) => request,
        Err((status, errors)) => {
            return invalid_request_response_with_status(status, request_id, errors);
        }
    };
    if let Err(errors) = request.validate() {
        return invalid_request_response(request_id, errors);
    }
    match persist_watch(&state.database, &principal, &request).await {
        Ok(resource) => {
            let location = format!("/v1/watches/{}", resource.watch_id.as_str());
            let mut response = (StatusCode::CREATED, Json(resource)).into_response();
            if let Ok(location) = HeaderValue::from_str(&location) {
                response.headers_mut().insert(LOCATION, location);
            }
            response
        }
        Err(error) => error_response(request_id, error),
    }
}

pub(crate) async fn get_watch(
    State(state): State<ServerState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Path(watch_id): Path<String>,
) -> Response {
    let watch_id = match parse_watch_id(&watch_id) {
        Ok(watch_id) => watch_id,
        Err(error) => return error_response(request_id, error),
    };
    match load_watch(
        &state.database,
        &principal,
        watch_id,
        ApiKeyScope::WatchRead,
    )
    .await
    {
        Ok(resource) => Json(resource).into_response(),
        Err(error) => error_response(request_id, error),
    }
}

pub(crate) async fn patch_watch(
    State(state): State<ServerState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Path(watch_id): Path<String>,
    payload: Result<Json<WatchPatchRequest>, JsonRejection>,
) -> Response {
    let watch_id = match parse_watch_id(&watch_id) {
        Ok(watch_id) => watch_id,
        Err(error) => return error_response(request_id, error),
    };
    let patch = match parse_json(payload) {
        Ok(patch) => patch,
        Err((status, errors)) => {
            return invalid_request_response_with_status(status, request_id, errors);
        }
    };
    if let Err(errors) = patch.validate() {
        return invalid_request_response(request_id, errors);
    }
    match apply_watch_patch(&state.database, &principal, watch_id, &patch).await {
        Ok(resource) => Json(resource).into_response(),
        Err(error) => error_response(request_id, error),
    }
}

pub(crate) async fn delete_watch(
    State(state): State<ServerState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Path(watch_id): Path<String>,
) -> Response {
    let watch_id = match parse_watch_id(&watch_id) {
        Ok(watch_id) => watch_id,
        Err(error) => return error_response(request_id, error),
    };
    match mark_watch_deleting(&state.database, &principal, watch_id).await {
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

fn parse_watch_id(value: &str) -> Result<Uuid, WatchError> {
    Uuid::parse_str(value)
        .map_err(|_| WatchError::InvalidRequest("watch_id", ValidationCode::InvalidFormat))
}

async fn persist_watch(
    pool: &PgPool,
    principal: &AuthenticatedPrincipal,
    request: &WatchCreateRequest,
) -> Result<WatchResource, WatchError> {
    let consent_grant_id = parse_uuid(
        request.private_history_consent_grant_id.as_str(),
        "private_history_consent_grant_id",
    )?;
    let endpoint_ids = parse_endpoint_ids(&request.notification_endpoint_ids)?;
    let mut transaction =
        auth::begin_authorized_transaction(pool, principal, ApiKeyScope::WatchWrite).await?;
    verify_watch_consent(&mut transaction, principal, consent_grant_id).await?;
    verify_known_sites(&mut transaction, request).await?;
    verify_active_endpoints(&mut transaction, principal.workspace_id, &endpoint_ids).await?;
    let membership_id: Uuid = sqlx::query_scalar(
        "SELECT created_by_membership_id FROM api_keys \
         WHERE tenant_id = $1 AND id = $2",
    )
    .bind(principal.workspace_id)
    .bind(principal.api_key_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| WatchError::Unavailable)?;
    let now_unix_ms = database_now_ms(&mut transaction).await?;
    let watch_id = Uuid::new_v4();
    let revision = 1_u64;
    let next_run_at_unix_ms = now_unix_ms
        .checked_add(schedule_delay_ms(watch_id, revision, &request.schedule)?)
        .ok_or(WatchError::Unavailable)?;
    sqlx::query(
        "INSERT INTO watches (\
            id, tenant_id, created_by_membership_id, consent_grant_id, state, \
            revision, maximum_age_ms, interval_seconds, jitter_percent, \
            maximum_probes_per_run, maximum_bytes_per_run, retention_days, \
            region_classes, next_run_at, created_at, updated_at\
         ) VALUES (\
            $1, $2, $3, $4, 'active', $5, $6, $7, $8, $9, $10, $11, $12, \
            to_timestamp($13::double precision / 1000.0), \
            to_timestamp($14::double precision / 1000.0), \
            to_timestamp($14::double precision / 1000.0)\
         )",
    )
    .bind(watch_id)
    .bind(principal.workspace_id)
    .bind(membership_id)
    .bind(consent_grant_id)
    .bind(i64::try_from(revision).map_err(|_| WatchError::Unavailable)?)
    .bind(request.maximum_age_ms)
    .bind(i32::try_from(request.schedule.interval_seconds).map_err(|_| WatchError::Unavailable)?)
    .bind(i16::from(request.schedule.jitter_percent))
    .bind(
        i32::try_from(request.probe_budget.maximum_probes_per_run)
            .map_err(|_| WatchError::Unavailable)?,
    )
    .bind(
        i64::try_from(request.probe_budget.maximum_bytes_per_run)
            .map_err(|_| WatchError::Unavailable)?,
    )
    .bind(i16::try_from(request.retention_days).map_err(|_| WatchError::Unavailable)?)
    .bind(
        request
            .region_classes
            .iter()
            .map(|region| region.as_str().to_owned())
            .collect::<Vec<_>>(),
    )
    .bind(next_run_at_unix_ms)
    .bind(now_unix_ms)
    .execute(&mut *transaction)
    .await
    .map_err(|_| WatchError::Unavailable)?;
    insert_watch_targets(&mut transaction, principal.workspace_id, watch_id, request).await?;
    replace_watch_endpoints(
        &mut transaction,
        principal.workspace_id,
        watch_id,
        &endpoint_ids,
    )
    .await?;
    let resource = load_watch_resource(&mut transaction, principal.workspace_id, watch_id).await?;
    transaction
        .commit()
        .await
        .map_err(|_| WatchError::Unavailable)?;
    Ok(resource)
}

async fn load_watch(
    pool: &PgPool,
    principal: &AuthenticatedPrincipal,
    watch_id: Uuid,
    scope: ApiKeyScope,
) -> Result<WatchResource, WatchError> {
    let mut transaction = auth::begin_authorized_transaction(pool, principal, scope).await?;
    let resource = load_watch_resource(&mut transaction, principal.workspace_id, watch_id).await?;
    transaction
        .commit()
        .await
        .map_err(|_| WatchError::Unavailable)?;
    Ok(resource)
}

async fn apply_watch_patch(
    pool: &PgPool,
    principal: &AuthenticatedPrincipal,
    watch_id: Uuid,
    patch: &WatchPatchRequest,
) -> Result<WatchResource, WatchError> {
    let mut transaction =
        auth::begin_authorized_transaction(pool, principal, ApiKeyScope::WatchWrite).await?;
    let stored_revision: Option<i64> = sqlx::query_scalar(
        "SELECT revision FROM watches \
         WHERE tenant_id = $1 AND id = $2 \
         FOR UPDATE",
    )
    .bind(principal.workspace_id)
    .bind(watch_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| WatchError::Unavailable)?;
    let Some(stored_revision) = stored_revision else {
        return Err(WatchError::NotFound);
    };
    if u64::try_from(stored_revision).ok() != Some(patch.expected_revision) {
        return Err(WatchError::Conflict);
    }
    let mut resource =
        load_watch_resource(&mut transaction, principal.workspace_id, watch_id).await?;
    if resource.state == WatchState::Deleting {
        return Err(WatchError::Conflict);
    }
    verify_watch_consent(
        &mut transaction,
        principal,
        parse_uuid(
            resource
                .configuration
                .private_history_consent_grant_id
                .as_str(),
            "private_history_consent_grant_id",
        )?,
    )
    .await?;
    if let Some(state) = patch.state {
        resource.state = match state {
            WatchStateUpdate::Active => WatchState::Active,
            WatchStateUpdate::Paused => WatchState::Paused,
        };
    }
    if let Some(maximum_age_ms) = patch.maximum_age_ms {
        resource.configuration.maximum_age_ms = maximum_age_ms;
    }
    if let Some(schedule) = &patch.schedule {
        resource.configuration.schedule = schedule.clone();
    }
    if let Some(probe_budget) = &patch.probe_budget {
        resource.configuration.probe_budget = probe_budget.clone();
    }
    if let Some(retention_days) = patch.retention_days {
        resource.configuration.retention_days = retention_days;
    }
    let replacement_endpoint_ids = patch
        .notification_endpoint_ids
        .as_ref()
        .map(|ids| parse_endpoint_ids(ids))
        .transpose()?;
    if let Some(endpoint_ids) = &replacement_endpoint_ids {
        verify_active_endpoints(&mut transaction, principal.workspace_id, endpoint_ids).await?;
        resource.configuration.notification_endpoint_ids =
            patch.notification_endpoint_ids.clone().unwrap_or_default();
    }
    resource
        .configuration
        .validate()
        .map_err(WatchError::Validation)?;
    let new_revision = patch
        .expected_revision
        .checked_add(1)
        .ok_or(WatchError::Unavailable)?;
    let now_unix_ms = database_now_ms(&mut transaction).await?;
    let next_run_at_unix_ms = match resource.state {
        WatchState::Active => Some(
            now_unix_ms
                .checked_add(schedule_delay_ms(
                    watch_id,
                    new_revision,
                    &resource.configuration.schedule,
                )?)
                .ok_or(WatchError::Unavailable)?,
        ),
        WatchState::Paused | WatchState::Deleting => None,
    };
    sqlx::query(
        "UPDATE watches SET \
            state = $3, revision = $4, maximum_age_ms = $5, \
            interval_seconds = $6, jitter_percent = $7, \
            maximum_probes_per_run = $8, maximum_bytes_per_run = $9, \
            retention_days = $10, next_run_at = CASE \
                WHEN $11::bigint IS NULL THEN NULL \
                ELSE to_timestamp($11::double precision / 1000.0) \
            END, updated_at = to_timestamp($12::double precision / 1000.0) \
         WHERE tenant_id = $1 AND id = $2 AND revision = $13",
    )
    .bind(principal.workspace_id)
    .bind(watch_id)
    .bind(watch_state_value(resource.state))
    .bind(i64::try_from(new_revision).map_err(|_| WatchError::Unavailable)?)
    .bind(resource.configuration.maximum_age_ms)
    .bind(
        i32::try_from(resource.configuration.schedule.interval_seconds)
            .map_err(|_| WatchError::Unavailable)?,
    )
    .bind(i16::from(resource.configuration.schedule.jitter_percent))
    .bind(
        i32::try_from(resource.configuration.probe_budget.maximum_probes_per_run)
            .map_err(|_| WatchError::Unavailable)?,
    )
    .bind(
        i64::try_from(resource.configuration.probe_budget.maximum_bytes_per_run)
            .map_err(|_| WatchError::Unavailable)?,
    )
    .bind(
        i16::try_from(resource.configuration.retention_days)
            .map_err(|_| WatchError::Unavailable)?,
    )
    .bind(next_run_at_unix_ms)
    .bind(now_unix_ms)
    .bind(stored_revision)
    .execute(&mut *transaction)
    .await
    .map_err(|_| WatchError::Unavailable)?;
    if let Some(endpoint_ids) = replacement_endpoint_ids {
        replace_watch_endpoints(
            &mut transaction,
            principal.workspace_id,
            watch_id,
            &endpoint_ids,
        )
        .await?;
    }
    cancel_stale_runs(
        &mut transaction,
        principal.workspace_id,
        watch_id,
        new_revision,
    )
    .await?;
    let resource = load_watch_resource(&mut transaction, principal.workspace_id, watch_id).await?;
    transaction
        .commit()
        .await
        .map_err(|_| WatchError::Unavailable)?;
    Ok(resource)
}

async fn mark_watch_deleting(
    pool: &PgPool,
    principal: &AuthenticatedPrincipal,
    watch_id: Uuid,
) -> Result<WatchResource, WatchError> {
    let mut transaction =
        auth::begin_authorized_transaction(pool, principal, ApiKeyScope::WatchWrite).await?;
    let row: Option<(String, i64)> = sqlx::query_as(
        "SELECT state, revision FROM watches \
         WHERE tenant_id = $1 AND id = $2 \
         FOR UPDATE",
    )
    .bind(principal.workspace_id)
    .bind(watch_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| WatchError::Unavailable)?;
    let Some((state, revision)) = row else {
        return Err(WatchError::NotFound);
    };
    if state != "deleting" {
        let next_revision = revision.checked_add(1).ok_or(WatchError::Unavailable)?;
        sqlx::query(
            "UPDATE watches SET state = 'deleting', revision = $3, \
                    next_run_at = NULL, updated_at = clock_timestamp() \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(principal.workspace_id)
        .bind(watch_id)
        .bind(next_revision)
        .execute(&mut *transaction)
        .await
        .map_err(|_| WatchError::Unavailable)?;
        sqlx::query(
            "UPDATE watch_targets SET retired_at = clock_timestamp() \
             WHERE tenant_id = $1 AND watch_id = $2 AND retired_at IS NULL",
        )
        .bind(principal.workspace_id)
        .bind(watch_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| WatchError::Unavailable)?;
        cancel_stale_runs(
            &mut transaction,
            principal.workspace_id,
            watch_id,
            u64::try_from(next_revision).map_err(|_| WatchError::Unavailable)?,
        )
        .await?;
    }
    let resource = load_watch_resource(&mut transaction, principal.workspace_id, watch_id).await?;
    transaction
        .commit()
        .await
        .map_err(|_| WatchError::Unavailable)?;
    Ok(resource)
}

async fn cancel_stale_runs(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    watch_id: Uuid,
    current_revision: u64,
) -> Result<(), WatchError> {
    let revision = i64::try_from(current_revision).map_err(|_| WatchError::Unavailable)?;
    sqlx::query(
        "UPDATE watch_run_targets AS target \
         SET state = 'cancelled', completed_at = clock_timestamp() \
         FROM watch_runs AS run \
         WHERE run.tenant_id = target.tenant_id \
           AND run.id = target.watch_run_id \
           AND run.tenant_id = $1 AND run.watch_id = $2 \
           AND run.watch_revision <> $3 \
           AND target.state IN ('pending', 'queued')",
    )
    .bind(tenant_id)
    .bind(watch_id)
    .bind(revision)
    .execute(&mut **transaction)
    .await
    .map_err(|_| WatchError::Unavailable)?;
    sqlx::query(
        "UPDATE watch_runs \
         SET state = 'cancelled', completed_at = clock_timestamp() \
         WHERE tenant_id = $1 AND watch_id = $2 \
           AND watch_revision <> $3 \
           AND state IN ('planned', 'running')",
    )
    .bind(tenant_id)
    .bind(watch_id)
    .bind(revision)
    .execute(&mut **transaction)
    .await
    .map_err(|_| WatchError::Unavailable)?;
    Ok(())
}

async fn verify_watch_consent(
    transaction: &mut Transaction<'_, Postgres>,
    principal: &AuthenticatedPrincipal,
    consent_grant_id: Uuid,
) -> Result<(), WatchError> {
    let authorized: bool = sqlx::query_scalar(
        "SELECT EXISTS (\
            SELECT 1 \
            FROM consent_grants AS consent \
            JOIN api_keys AS key \
              ON key.tenant_id = consent.tenant_id \
             AND key.created_by_membership_id = consent.membership_id \
            WHERE consent.tenant_id = $1 AND consent.id = $2 \
              AND key.id = $3 AND consent.subject_kind = 'account' \
              AND consent.purpose = 'private_history' \
              AND consent.collection_profile_version = 'profile-v1' \
              AND consent.notice_version = 'notice-v1' \
              AND consent.withdrawn_at IS NULL \
              AND consent.granted_at <= clock_timestamp() \
              AND (consent.expires_at IS NULL OR consent.expires_at > clock_timestamp())\
         )",
    )
    .bind(principal.workspace_id)
    .bind(consent_grant_id)
    .bind(principal.api_key_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| WatchError::Unavailable)?;
    if authorized {
        Ok(())
    } else {
        Err(WatchError::ConsentForbidden)
    }
}

async fn verify_known_sites(
    transaction: &mut Transaction<'_, Postgres>,
    request: &WatchCreateRequest,
) -> Result<(), WatchError> {
    let site_ids = request
        .targets
        .site_ids
        .iter()
        .map(|site| site.as_str().to_owned())
        .collect::<Vec<_>>();
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM sites WHERE id = ANY($1)")
        .bind(&site_ids)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|_| WatchError::Unavailable)?;
    if usize::try_from(count).ok() == Some(site_ids.len()) {
        Ok(())
    } else {
        Err(WatchError::InvalidRequest(
            "targets.site_ids",
            ValidationCode::InvalidRelation,
        ))
    }
}

async fn verify_active_endpoints(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    endpoint_ids: &[Uuid],
) -> Result<(), WatchError> {
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM notification_endpoints \
         WHERE tenant_id = $1 AND id = ANY($2) AND state = 'active'",
    )
    .bind(tenant_id)
    .bind(endpoint_ids)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| WatchError::Unavailable)?;
    if usize::try_from(count).ok() == Some(endpoint_ids.len()) {
        Ok(())
    } else {
        Err(WatchError::InvalidRequest(
            "notification_endpoint_ids",
            ValidationCode::InvalidRelation,
        ))
    }
}

async fn insert_watch_targets(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    watch_id: Uuid,
    request: &WatchCreateRequest,
) -> Result<(), WatchError> {
    let mut targets = Vec::new();
    for username in &request.targets.usernames {
        for site_id in &request.targets.site_ids {
            targets.push((
                Uuid::new_v4(),
                username.as_str().to_owned(),
                site_id.as_str().to_owned(),
                i32::try_from(targets.len()).map_err(|_| WatchError::Unavailable)?,
            ));
        }
    }
    let mut query = QueryBuilder::<Postgres>::new(
        "INSERT INTO watch_targets (\
            id, tenant_id, watch_id, requested_username, normalized_username, \
            site_id, ordinal, created_at\
         ) ",
    );
    query.push_values(targets, |mut row, (id, username, site_id, ordinal)| {
        row.push_bind(id)
            .push_bind(tenant_id)
            .push_bind(watch_id)
            .push_bind(username)
            .push("NULL")
            .push_bind(site_id)
            .push_bind(ordinal)
            .push("clock_timestamp()");
    });
    query
        .build()
        .execute(&mut **transaction)
        .await
        .map_err(|_| WatchError::Unavailable)?;
    Ok(())
}

async fn replace_watch_endpoints(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    watch_id: Uuid,
    endpoint_ids: &[Uuid],
) -> Result<(), WatchError> {
    sqlx::query(
        "DELETE FROM watch_notification_endpoints \
         WHERE tenant_id = $1 AND watch_id = $2",
    )
    .bind(tenant_id)
    .bind(watch_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| WatchError::Unavailable)?;
    let mut query = QueryBuilder::<Postgres>::new(
        "INSERT INTO watch_notification_endpoints (\
            tenant_id, watch_id, endpoint_id, ordinal, created_at\
         ) ",
    );
    query.push_values(
        endpoint_ids.iter().enumerate(),
        |mut row, (ordinal, endpoint_id)| {
            row.push_bind(tenant_id)
                .push_bind(watch_id)
                .push_bind(*endpoint_id)
                .push_bind(i32::try_from(ordinal).unwrap_or(i32::MAX))
                .push("clock_timestamp()");
        },
    );
    query
        .build()
        .execute(&mut **transaction)
        .await
        .map_err(|_| WatchError::Unavailable)?;
    Ok(())
}

pub(crate) async fn load_watch_resource(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    watch_id: Uuid,
) -> Result<WatchResource, WatchError> {
    let row: Option<StoredWatch> = sqlx::query_as(
        "SELECT id, state, revision, consent_grant_id, maximum_age_ms, \
                interval_seconds, jitter_percent, maximum_probes_per_run, \
                maximum_bytes_per_run, retention_days, region_classes, \
                (EXTRACT(EPOCH FROM created_at) * 1000)::bigint AS created_at_unix_ms, \
                (EXTRACT(EPOCH FROM updated_at) * 1000)::bigint AS updated_at_unix_ms, \
                (EXTRACT(EPOCH FROM next_run_at) * 1000)::bigint AS next_run_at_unix_ms \
         FROM watches WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id)
    .bind(watch_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| WatchError::Unavailable)?;
    let Some(row) = row else {
        return Err(WatchError::NotFound);
    };
    let target_rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT requested_username, site_id FROM watch_targets \
         WHERE tenant_id = $1 AND watch_id = $2 \
         ORDER BY ordinal",
    )
    .bind(tenant_id)
    .bind(watch_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| WatchError::Unavailable)?;
    let endpoint_rows: Vec<Uuid> = sqlx::query_scalar(
        "SELECT endpoint_id FROM watch_notification_endpoints \
         WHERE tenant_id = $1 AND watch_id = $2 \
         ORDER BY ordinal",
    )
    .bind(tenant_id)
    .bind(watch_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| WatchError::Unavailable)?;
    build_watch_resource(row, target_rows, endpoint_rows)
}

fn build_watch_resource(
    row: StoredWatch,
    target_rows: Vec<(String, String)>,
    endpoint_ids: Vec<Uuid>,
) -> Result<WatchResource, WatchError> {
    let mut usernames = Vec::new();
    let mut username_seen = HashSet::new();
    let mut sites = Vec::new();
    let mut site_seen = HashSet::new();
    for (username, site) in target_rows {
        if username_seen.insert(username.clone()) {
            usernames.push(Username::new(username).map_err(|_| WatchError::Unavailable)?);
        }
        if site_seen.insert(site.clone()) {
            sites.push(SiteId::new(site).map_err(|_| WatchError::Unavailable)?);
        }
    }
    let resource = WatchResource {
        schema: ProtocolVersion::ApiV1,
        watch_id: WatchId::new(row.id.to_string()).map_err(|_| WatchError::Unavailable)?,
        state: parse_watch_state(&row.state)?,
        revision: u64::try_from(row.revision).map_err(|_| WatchError::Unavailable)?,
        configuration: WatchCreateRequest {
            schema: ProtocolVersion::ApiV1,
            targets: TargetSelection {
                usernames,
                site_ids: sites,
            },
            region_classes: row
                .region_classes
                .into_iter()
                .map(RegionClass::new)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| WatchError::Unavailable)?,
            maximum_age_ms: row.maximum_age_ms,
            schedule: WatchSchedule {
                interval_seconds: u32::try_from(row.interval_seconds)
                    .map_err(|_| WatchError::Unavailable)?,
                jitter_percent: u8::try_from(row.jitter_percent)
                    .map_err(|_| WatchError::Unavailable)?,
            },
            probe_budget: ProbeBudget {
                maximum_probes_per_run: u32::try_from(row.maximum_probes_per_run)
                    .map_err(|_| WatchError::Unavailable)?,
                maximum_bytes_per_run: u64::try_from(row.maximum_bytes_per_run)
                    .map_err(|_| WatchError::Unavailable)?,
            },
            notification_endpoint_ids: endpoint_ids
                .into_iter()
                .map(|id| {
                    NotificationEndpointId::new(id.to_string()).map_err(|_| WatchError::Unavailable)
                })
                .collect::<Result<Vec<_>, _>>()?,
            private_history_consent_grant_id: ConsentGrantId::new(row.consent_grant_id.to_string())
                .map_err(|_| WatchError::Unavailable)?,
            retention_days: u16::try_from(row.retention_days)
                .map_err(|_| WatchError::Unavailable)?,
        },
        created_at_unix_ms: row.created_at_unix_ms,
        updated_at_unix_ms: row.updated_at_unix_ms,
        next_run_at_unix_ms: row.next_run_at_unix_ms,
    };
    resource.validate().map_err(|_| WatchError::Unavailable)?;
    Ok(resource)
}

fn parse_endpoint_ids(ids: &[NotificationEndpointId]) -> Result<Vec<Uuid>, WatchError> {
    ids.iter()
        .map(|id| parse_uuid(id.as_str(), "notification_endpoint_ids"))
        .collect()
}

fn parse_uuid(value: &str, field: &'static str) -> Result<Uuid, WatchError> {
    Uuid::parse_str(value)
        .map_err(|_| WatchError::InvalidRequest(field, ValidationCode::InvalidFormat))
}

async fn database_now_ms(transaction: &mut Transaction<'_, Postgres>) -> Result<i64, WatchError> {
    sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
        .fetch_one(&mut **transaction)
        .await
        .map_err(|_| WatchError::Unavailable)
}

fn schedule_delay_ms(
    watch_id: Uuid,
    revision: u64,
    schedule: &WatchSchedule,
) -> Result<i64, WatchError> {
    let base = i64::from(schedule.interval_seconds)
        .checked_mul(1_000)
        .ok_or(WatchError::Unavailable)?;
    let span = base
        .checked_mul(i64::from(schedule.jitter_percent))
        .and_then(|value| value.checked_div(100))
        .ok_or(WatchError::Unavailable)?;
    if span == 0 {
        return Ok(base);
    }
    let mut hasher = Sha256::new();
    hasher.update(watch_id.as_bytes());
    hasher.update(revision.to_be_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let sample = u64::from_be_bytes(
        digest[..8]
            .try_into()
            .map_err(|_| WatchError::Unavailable)?,
    );
    let width = u64::try_from(
        span.checked_mul(2)
            .and_then(|value| value.checked_add(1))
            .ok_or(WatchError::Unavailable)?,
    )
    .map_err(|_| WatchError::Unavailable)?;
    let offset = i64::try_from(sample % width).map_err(|_| WatchError::Unavailable)? - span;
    base.checked_add(offset).ok_or(WatchError::Unavailable)
}

const fn watch_state_value(state: WatchState) -> &'static str {
    match state {
        WatchState::Active => "active",
        WatchState::Paused => "paused",
        WatchState::Deleting => "deleting",
    }
}

fn parse_watch_state(value: &str) -> Result<WatchState, WatchError> {
    match value {
        "active" => Ok(WatchState::Active),
        "paused" => Ok(WatchState::Paused),
        "deleting" => Ok(WatchState::Deleting),
        _ => Err(WatchError::Unavailable),
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
    (
        status,
        Json(socialname_protocol::ApiErrorResponse::invalid_request(
            request_id, errors,
        )),
    )
        .into_response()
}

fn error_response(request_id: RequestId, error: WatchError) -> Response {
    match error {
        WatchError::InvalidRequest(field, code) => {
            invalid_request_response(request_id, ValidationErrors::new(field, code))
        }
        WatchError::Validation(errors) => invalid_request_response(request_id, errors),
        WatchError::ConsentForbidden
        | WatchError::Authentication(AuthenticationError::Forbidden) => crate::api_error_response(
            StatusCode::FORBIDDEN,
            request_id,
            standard_api_error(ApiErrorCode::Forbidden, false),
        ),
        WatchError::NotFound => crate::api_error_response(
            StatusCode::NOT_FOUND,
            request_id,
            standard_api_error(ApiErrorCode::NotFound, false),
        ),
        WatchError::Conflict => crate::api_error_response(
            StatusCode::CONFLICT,
            request_id,
            standard_api_error(ApiErrorCode::Conflict, false),
        ),
        WatchError::Authentication(AuthenticationError::InvalidCredential) => {
            unauthenticated_response(request_id)
        }
        WatchError::Authentication(AuthenticationError::Unavailable) | WatchError::Unavailable => {
            crate::api_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                request_id,
                standard_api_error(ApiErrorCode::Unavailable, true),
            )
        }
    }
}

#[derive(FromRow)]
struct StoredWatch {
    id: Uuid,
    state: String,
    revision: i64,
    consent_grant_id: Uuid,
    maximum_age_ms: i64,
    interval_seconds: i32,
    jitter_percent: i16,
    maximum_probes_per_run: i32,
    maximum_bytes_per_run: i64,
    retention_days: i16,
    region_classes: Vec<String>,
    created_at_unix_ms: i64,
    updated_at_unix_ms: i64,
    next_run_at_unix_ms: Option<i64>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum WatchError {
    #[error("watch request is invalid")]
    InvalidRequest(&'static str, ValidationCode),
    #[error("watch validation failed")]
    Validation(ValidationErrors),
    #[error("watch consent is not authorized")]
    ConsentForbidden,
    #[error("watch was not found")]
    NotFound,
    #[error("watch revision conflicts")]
    Conflict,
    #[error(transparent)]
    Authentication(#[from] AuthenticationError),
    #[error("watch storage is unavailable")]
    Unavailable,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_jitter_stays_inside_the_declared_window() {
        let schedule = WatchSchedule {
            interval_seconds: 300,
            jitter_percent: 20,
        };
        let delay = schedule_delay_ms(Uuid::from_u128(1), 1, &schedule).unwrap();
        assert!((240_000..=360_000).contains(&delay));
        assert_eq!(
            delay,
            schedule_delay_ms(Uuid::from_u128(1), 1, &schedule).unwrap()
        );
        assert_ne!(
            delay,
            schedule_delay_ms(Uuid::from_u128(1), 2, &schedule).unwrap()
        );
    }

    #[test]
    fn identifiers_fail_without_reflecting_values() {
        let private = "private-watch-value";
        let error = parse_watch_id(private).unwrap_err();
        assert!(!error.to_string().contains(private));
        assert!(!format!("{error:?}").contains(private));
    }
}
