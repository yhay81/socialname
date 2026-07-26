use axum::{
    Json,
    extract::{Extension, Path, State, rejection::JsonRejection},
    http::{HeaderValue, StatusCode, header::LOCATION},
    response::{IntoResponse, Response},
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use socialname_protocol::{
    ApiErrorCode, ApiKeyScope, ContributorDeletionCreateRequest, DeletionReceiptResource,
    DeletionReceiptState, DeletionRequestId, DeletionRequestResource, DeletionRequestState,
    DeletionScope, DeletionStoreKind, DeletionStoreReceipt, DeletionStoreState, RequestId,
    Validate, ValidationCode, ValidationErrors,
};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    ServerState,
    auth::{self, AuthenticatedPrincipal, AuthenticationError},
    standard_api_error, unauthenticated_response,
};

type HmacSha256 = Hmac<Sha256>;

pub(crate) async fn create_contributor_deletion(
    State(state): State<ServerState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    payload: Result<Json<ContributorDeletionCreateRequest>, JsonRejection>,
) -> Response {
    let request = match parse_json(payload) {
        Ok(request) => request,
        Err((status, errors)) => {
            return (
                status,
                Json(socialname_protocol::ApiErrorResponse::invalid_request(
                    request_id, errors,
                )),
            )
                .into_response();
        }
    };
    if let Err(errors) = request.validate() {
        return (
            StatusCode::BAD_REQUEST,
            Json(socialname_protocol::ApiErrorResponse::invalid_request(
                request_id, errors,
            )),
        )
            .into_response();
    }
    let consent_grant_id = match Uuid::parse_str(request.consent_grant_id.as_str()) {
        Ok(value) => value,
        Err(_) => {
            return error_response(
                request_id,
                DeletionError::InvalidRequest("consent_grant_id", ValidationCode::InvalidFormat),
            );
        }
    };
    let Some(key) = state.config.suppression_hmac_key() else {
        return error_response(request_id, DeletionError::Unavailable);
    };
    match persist_contributor_deletion(&state.database, &principal, consent_grant_id, key.expose())
        .await
    {
        Ok((resource, created)) => {
            let location = format!(
                "/v1/deletion-requests/{}",
                resource.deletion_request_id.as_str()
            );
            let mut response = (
                if created {
                    StatusCode::CREATED
                } else {
                    StatusCode::OK
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

pub(crate) async fn get_deletion_request(
    State(state): State<ServerState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Path(deletion_request_id): Path<String>,
) -> Response {
    let deletion_request_id = match Uuid::parse_str(&deletion_request_id) {
        Ok(value) => value,
        Err(_) => {
            return error_response(
                request_id,
                DeletionError::InvalidRequest("deletion_request_id", ValidationCode::InvalidFormat),
            );
        }
    };
    match load_deletion_request(&state.database, &principal, deletion_request_id).await {
        Ok(resource) => Json(resource).into_response(),
        Err(error) => error_response(request_id, error),
    }
}

pub(crate) async fn get_deletion_receipt(
    State(state): State<ServerState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Path(deletion_request_id): Path<String>,
) -> Response {
    let deletion_request_id = match Uuid::parse_str(&deletion_request_id) {
        Ok(value) => value,
        Err(_) => {
            return error_response(
                request_id,
                DeletionError::InvalidRequest("deletion_request_id", ValidationCode::InvalidFormat),
            );
        }
    };
    match load_deletion_receipt(&state.database, &principal, deletion_request_id).await {
        Ok(resource) => Json(resource).into_response(),
        Err(error) => error_response(request_id, error),
    }
}

fn parse_json(
    payload: Result<Json<ContributorDeletionCreateRequest>, JsonRejection>,
) -> Result<ContributorDeletionCreateRequest, (StatusCode, ValidationErrors)> {
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

async fn persist_contributor_deletion(
    pool: &PgPool,
    principal: &AuthenticatedPrincipal,
    consent_grant_id: Uuid,
    suppression_key: &[u8; 32],
) -> Result<(DeletionRequestResource, bool), DeletionError> {
    let mut transaction =
        auth::begin_authorized_transaction(pool, principal, ApiKeyScope::DataDelete).await?;
    let owned: Option<OwnedConsentSubject> = sqlx::query_as(
        "SELECT consent.subject_kind, \
                COALESCE(consent.membership_id, consent.client_id) AS subject_id, \
                consent.purpose \
         FROM consent_grants AS consent \
         WHERE consent.tenant_id = $1 AND consent.id = $2 \
           AND (\
             (consent.subject_kind = 'account' AND consent.membership_id = $3) \
             OR (consent.subject_kind = 'installation' AND EXISTS (\
                 SELECT 1 FROM consent_events AS event \
                 WHERE event.tenant_id = consent.tenant_id \
                   AND event.consent_grant_id = consent.id \
                   AND event.event_kind = 'granted' \
                   AND event.actor_membership_id = $3\
             ))\
           ) \
         FOR UPDATE",
    )
    .bind(principal.workspace_id)
    .bind(consent_grant_id)
    .bind(principal.membership_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| DeletionError::Unavailable)?;
    let Some(subject) = owned else {
        return Err(DeletionError::NotFound);
    };
    let selector_token = contributor_suppression_token(
        suppression_key,
        principal.workspace_id,
        &subject.subject_kind,
        subject.subject_id,
        &subject.purpose,
    )
    .ok_or(DeletionError::Unavailable)?;
    let key_fingerprint =
        suppression_key_fingerprint(suppression_key).ok_or(DeletionError::Unavailable)?;
    let incompatible_key_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (\
            SELECT 1 FROM suppression_tokens \
            WHERE tenant_id = $1 \
              AND purpose = 'contributor_reingestion' \
              AND expires_at > clock_timestamp() \
              AND key_fingerprint IS DISTINCT FROM $2\
         )",
    )
    .bind(principal.workspace_id)
    .bind(key_fingerprint.as_slice())
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| DeletionError::Unavailable)?;
    if incompatible_key_exists {
        return Err(DeletionError::Unavailable);
    }
    sqlx::query(
        "SELECT pg_advisory_xact_lock(\
            hashtextextended($1::text || ':' || encode($2::bytea, 'hex'), 0)\
         )",
    )
    .bind(principal.workspace_id.to_string())
    .bind(selector_token.as_slice())
    .execute(&mut *transaction)
    .await
    .map_err(|_| DeletionError::Unavailable)?;
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM deletion_requests \
         WHERE tenant_id = $1 AND request_origin = 'contributor_api' \
           AND selector_token = $2 \
         ORDER BY requested_at DESC, id DESC LIMIT 1",
    )
    .bind(principal.workspace_id)
    .bind(selector_token.as_slice())
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| DeletionError::Unavailable)?;
    if let Some(existing) = existing {
        let resource = load_owned_resource(&mut transaction, principal, existing)
            .await?
            .ok_or(DeletionError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| DeletionError::Unavailable)?;
        return Ok((resource, false));
    }

    let matched_observations: i64 = sqlx::query_scalar(
        "SELECT count(*) \
         FROM observations AS observation \
         JOIN consent_grants AS consent \
           ON consent.tenant_id = observation.tenant_id \
          AND consent.id = observation.consent_grant_id \
         WHERE observation.tenant_id = $1 \
           AND consent.subject_kind = $2 \
           AND COALESCE(consent.membership_id, consent.client_id) = $3 \
           AND consent.purpose = $4",
    )
    .bind(principal.workspace_id)
    .bind(&subject.subject_kind)
    .bind(subject.subject_id)
    .bind(&subject.purpose)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| DeletionError::Unavailable)?;
    if matched_observations > i64::from(socialname_protocol::MAXIMUM_DELETION_MATCH_COUNT) {
        return Err(DeletionError::Conflict);
    }

    let deletion_request_id = Uuid::new_v4();
    sqlx::query(
        "WITH moment AS (SELECT clock_timestamp() AS now) \
         INSERT INTO deletion_requests (\
            id, tenant_id, requested_by_membership_id, scope_kind, \
            selector_token, state, requested_at, hide_by, support_withdrawal_by, \
            primary_delete_by, derived_rebuild_by, backup_expiry_by, \
            request_origin, consent_grant_id\
         ) \
         SELECT $1, $2, $3, 'contributor', $4, 'hidden', now, \
                now + interval '5 minutes', \
                now + interval '1 hour', \
                now + interval '24 hours', \
                now + interval '7 days', \
                now + interval '35 days', \
                'contributor_api', $5 \
         FROM moment",
    )
    .bind(deletion_request_id)
    .bind(principal.workspace_id)
    .bind(principal.membership_id)
    .bind(selector_token.as_slice())
    .bind(consent_grant_id)
    .execute(&mut *transaction)
    .await
    .map_err(|_| DeletionError::Unavailable)?;

    let grant_ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM consent_grants \
         WHERE tenant_id = $1 AND subject_kind = $2 \
           AND COALESCE(membership_id, client_id) = $3 \
           AND purpose = $4 AND withdrawn_at IS NULL \
         ORDER BY id FOR UPDATE",
    )
    .bind(principal.workspace_id)
    .bind(&subject.subject_kind)
    .bind(subject.subject_id)
    .bind(&subject.purpose)
    .fetch_all(&mut *transaction)
    .await
    .map_err(|_| DeletionError::Unavailable)?;
    for grant_id in grant_ids {
        sqlx::query(
            "UPDATE consent_grants SET withdrawn_at = clock_timestamp() \
             WHERE tenant_id = $1 AND id = $2 AND withdrawn_at IS NULL",
        )
        .bind(principal.workspace_id)
        .bind(grant_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| DeletionError::Unavailable)?;
        sqlx::query(
            "INSERT INTO consent_events (\
                id, tenant_id, consent_grant_id, event_kind, \
                actor_membership_id, occurred_at, details\
             ) \
             SELECT $1, tenant_id, id, 'withdrawn', $2, withdrawn_at, \
                    jsonb_build_object('deletion_request_id', $3::text) \
             FROM consent_grants WHERE tenant_id = $4 AND id = $5",
        )
        .bind(Uuid::new_v4())
        .bind(principal.membership_id)
        .bind(deletion_request_id)
        .bind(principal.workspace_id)
        .bind(grant_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| DeletionError::Unavailable)?;
    }

    materialize_contributor_lineage(
        &mut transaction,
        principal.workspace_id,
        deletion_request_id,
        &subject,
    )
    .await?;
    sqlx::query("SELECT socialname_redact_deletion_job_targets($1, $2)")
        .bind(principal.workspace_id)
        .bind(deletion_request_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| DeletionError::Unavailable)?;
    sqlx::query(
        "UPDATE notification_deliveries AS delivery \
         SET state = 'cancelled', next_attempt_at = NULL, delivered_at = NULL, \
             last_error_code = NULL, lease_owner = NULL, \
             lease_started_at = NULL, lease_expires_at = NULL \
         WHERE delivery.tenant_id = $1 \
           AND delivery.state IN ('queued', 'delivering', 'retry_scheduled') \
           AND EXISTS (\
               SELECT 1 FROM deletion_resource_matches AS matched \
               WHERE matched.tenant_id = delivery.tenant_id \
                 AND matched.deletion_request_id = $2 \
                 AND matched.resource_kind = 'notification_delivery' \
                 AND matched.resource_id = delivery.id\
           )",
    )
    .bind(principal.workspace_id)
    .bind(deletion_request_id)
    .execute(&mut *transaction)
    .await
    .map_err(|_| DeletionError::Unavailable)?;
    sqlx::query(
        "INSERT INTO suppression_tokens (\
            id, tenant_id, purpose, token_hmac, key_fingerprint, \
            created_at, expires_at\
         ) VALUES (\
            $1, $2, 'contributor_reingestion', $3, $4, clock_timestamp(), \
            clock_timestamp() + interval '3 years'\
         ) ON CONFLICT (tenant_id, purpose, token_hmac) DO NOTHING",
    )
    .bind(Uuid::new_v4())
    .bind(principal.workspace_id)
    .bind(selector_token.as_slice())
    .bind(key_fingerprint.as_slice())
    .execute(&mut *transaction)
    .await
    .map_err(|_| DeletionError::Unavailable)?;
    for store_kind in ["primary", "analytics", "backup"] {
        sqlx::query(
            "INSERT INTO deletion_tasks (\
                id, tenant_id, deletion_request_id, store_kind, state, \
                deadline_at, available_at\
             ) VALUES (\
                $1, $2, $3, $4, 'pending', \
                (SELECT CASE $4 \
                    WHEN 'primary' THEN primary_delete_by \
                    WHEN 'analytics' THEN derived_rebuild_by \
                    WHEN 'backup' THEN backup_expiry_by \
                 END FROM deletion_requests \
                 WHERE tenant_id = $2 AND id = $3), \
                clock_timestamp()\
             )",
        )
        .bind(Uuid::new_v4())
        .bind(principal.workspace_id)
        .bind(deletion_request_id)
        .bind(store_kind)
        .execute(&mut *transaction)
        .await
        .map_err(|_| DeletionError::Unavailable)?;
    }
    sqlx::query(
        "INSERT INTO audit_events (\
            id, tenant_id, actor_membership_id, action, resource_kind, \
            resource_id, occurred_at, details\
         ) VALUES (\
            $1, $2, $3, 'deletion.contributor.hidden', 'deletion_request', \
            $4, clock_timestamp(), \
            jsonb_build_object('scope', 'contributor')\
         )",
    )
    .bind(Uuid::new_v4())
    .bind(principal.workspace_id)
    .bind(principal.membership_id)
    .bind(deletion_request_id)
    .execute(&mut *transaction)
    .await
    .map_err(|_| DeletionError::Unavailable)?;

    let resource = load_owned_resource(&mut transaction, principal, deletion_request_id)
        .await?
        .ok_or(DeletionError::Unavailable)?;
    transaction
        .commit()
        .await
        .map_err(|_| DeletionError::Unavailable)?;
    Ok((resource, true))
}

async fn materialize_contributor_lineage(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    deletion_request_id: Uuid,
    subject: &OwnedConsentSubject,
) -> Result<(), DeletionError> {
    sqlx::query(
        "WITH RECURSIVE selected_observations AS (\
            SELECT observation.id, observation.probe_job_id \
            FROM observations AS observation \
            JOIN consent_grants AS consent \
              ON consent.tenant_id = observation.tenant_id \
             AND consent.id = observation.consent_grant_id \
            WHERE observation.tenant_id = $1 \
              AND consent.subject_kind = $3 \
              AND COALESCE(consent.membership_id, consent.client_id) = $4 \
              AND consent.purpose = $5 \
         ), matched(resource_kind, resource_id) AS (\
            SELECT 'observation'::text, selected.id \
            FROM selected_observations AS selected \
            UNION \
            SELECT 'probe_job'::text, selected.probe_job_id \
            FROM selected_observations AS selected \
            UNION \
            SELECT 'search_target'::text, consumer.search_target_id \
            FROM selected_observations AS selected \
            JOIN probe_job_consumers AS consumer \
              ON consumer.tenant_id = $1 \
             AND consumer.probe_job_id = selected.probe_job_id \
            WHERE consumer.search_target_id IS NOT NULL \
            UNION \
            SELECT lineage.child_kind, lineage.child_id \
            FROM data_lineage_edges AS lineage \
            JOIN matched AS parent \
              ON parent.resource_kind = lineage.parent_kind \
             AND parent.resource_id = lineage.parent_id \
            WHERE lineage.tenant_id = $1\
         ) \
         INSERT INTO deletion_resource_matches (\
            tenant_id, deletion_request_id, resource_kind, resource_id, hidden_at\
         ) \
         SELECT $1, $2, resource_kind, resource_id, clock_timestamp() \
         FROM matched \
         WHERE resource_kind IN (\
            'observation', 'evidence_capsule', 'assertion', \
            'regional_assertion', 'search_event', 'watch_run_target', \
            'transition', 'notification_delivery', 'probe_job', 'search_target'\
         ) \
         ON CONFLICT DO NOTHING",
    )
    .bind(tenant_id)
    .bind(deletion_request_id)
    .bind(&subject.subject_kind)
    .bind(subject.subject_id)
    .bind(&subject.purpose)
    .execute(&mut **transaction)
    .await
    .map_err(|_| DeletionError::Unavailable)?;
    Ok(())
}

pub(crate) async fn redact_matched_job_targets(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    deletion_request_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE search_targets AS target \
         SET requested_username = 'deleted-target-' || replace(target.id::text, '-', ''), \
             normalized_username = 'deleted-target-' || replace(target.id::text, '-', ''), \
             state = CASE \
                 WHEN target.state IN ('pending', 'running') THEN 'cancelled' \
                 ELSE target.state \
             END, \
             completed_at = CASE \
                 WHEN target.state IN ('pending', 'running') \
                 THEN clock_timestamp() ELSE target.completed_at \
             END \
         WHERE target.tenant_id = $1 AND EXISTS (\
             SELECT 1 FROM deletion_resource_matches AS matched \
             WHERE matched.tenant_id = target.tenant_id \
               AND matched.deletion_request_id = $2 \
               AND matched.resource_kind = 'search_target' \
               AND matched.resource_id = target.id\
         )",
    )
    .bind(tenant_id)
    .bind(deletion_request_id)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "UPDATE probe_jobs AS job \
         SET normalized_username = 'deleted-target-' || replace(job.id::text, '-', ''), \
             work_key_hash = decode(\
                 md5(job.id::text || ':' || $2::uuid::text) \
                 || md5(job.id::text || ':' || $2::uuid::text || ':redacted'), \
                 'hex'\
             ), \
             state = CASE \
                 WHEN job.state IN ('queued', 'leased', 'retry_wait') THEN 'cancelled' \
                 ELSE job.state \
             END, \
             lease_owner = NULL, lease_expires_at = NULL, \
             last_error_code = NULL, \
             updated_at = clock_timestamp(), \
             completed_at = CASE \
                 WHEN job.state IN ('queued', 'leased', 'retry_wait') \
                 THEN clock_timestamp() ELSE job.completed_at \
             END \
         WHERE job.tenant_id = $1 AND EXISTS (\
             SELECT 1 FROM deletion_resource_matches AS matched \
             WHERE matched.tenant_id = job.tenant_id \
               AND matched.deletion_request_id = $2 \
               AND matched.resource_kind = 'probe_job' \
               AND matched.resource_id = job.id\
         )",
    )
    .bind(tenant_id)
    .bind(deletion_request_id)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn load_deletion_request(
    pool: &PgPool,
    principal: &AuthenticatedPrincipal,
    deletion_request_id: Uuid,
) -> Result<DeletionRequestResource, DeletionError> {
    let mut transaction =
        auth::begin_authorized_transaction(pool, principal, ApiKeyScope::DataDelete).await?;
    let resource = load_owned_resource(&mut transaction, principal, deletion_request_id)
        .await?
        .ok_or(DeletionError::NotFound)?;
    transaction
        .commit()
        .await
        .map_err(|_| DeletionError::Unavailable)?;
    Ok(resource)
}

async fn load_deletion_receipt(
    pool: &PgPool,
    principal: &AuthenticatedPrincipal,
    deletion_request_id: Uuid,
) -> Result<DeletionReceiptResource, DeletionError> {
    let mut transaction =
        auth::begin_authorized_transaction(pool, principal, ApiKeyScope::DataDelete).await?;
    let request: Option<StoredReceiptRequest> = sqlx::query_as(
        "SELECT request.id, request.state, \
                (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::bigint \
                    AS evaluated_at_unix_ms, \
                (EXTRACT(EPOCH FROM request.backup_expiry_by) * 1000)::bigint \
                    AS backup_expiry_by_unix_ms, \
                (EXTRACT(EPOCH FROM request.primary_completed_at) * 1000)::bigint \
                    AS primary_completed_at_unix_ms, \
                (EXTRACT(EPOCH FROM request.completed_at) * 1000)::bigint \
                    AS completed_at_unix_ms, \
                EXISTS (\
                    SELECT 1 FROM deletion_receipts AS receipt \
                    WHERE receipt.tenant_id = request.tenant_id \
                      AND receipt.deletion_request_id = request.id\
                ) AS receipt_exists \
         FROM deletion_requests AS request \
         WHERE request.tenant_id = $1 AND request.id = $2 \
           AND request.requested_by_membership_id = $3 \
           AND request.request_origin = 'contributor_api'",
    )
    .bind(principal.workspace_id)
    .bind(deletion_request_id)
    .bind(principal.membership_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| DeletionError::Unavailable)?;
    let request = request.ok_or(DeletionError::NotFound)?;
    let tasks: Vec<StoredReceiptTask> = sqlx::query_as(
        "SELECT store_kind, state, \
                (EXTRACT(EPOCH FROM deadline_at) * 1000)::bigint \
                    AS deadline_at_unix_ms, \
                (EXTRACT(EPOCH FROM completed_at) * 1000)::bigint \
                    AS completed_at_unix_ms \
         FROM deletion_tasks \
         WHERE tenant_id = $1 AND deletion_request_id = $2 \
           AND store_kind IN ('primary', 'analytics', 'backup') \
         ORDER BY CASE store_kind \
            WHEN 'primary' THEN 1 WHEN 'analytics' THEN 2 ELSE 3 END",
    )
    .bind(principal.workspace_id)
    .bind(deletion_request_id)
    .fetch_all(&mut *transaction)
    .await
    .map_err(|_| DeletionError::Unavailable)?;
    transaction
        .commit()
        .await
        .map_err(|_| DeletionError::Unavailable)?;

    if tasks.len() != 3 || (request.state == "completed" && !request.receipt_exists) {
        return Err(DeletionError::Unavailable);
    }
    let stores: Vec<DeletionStoreReceipt> = tasks
        .into_iter()
        .map(TryInto::try_into)
        .collect::<Result<_, _>>()?;
    let state = if request.state == "completed" {
        DeletionReceiptState::Completed
    } else if stores
        .iter()
        .any(|store| store.state == DeletionStoreState::Failed)
    {
        DeletionReceiptState::Failed
    } else {
        DeletionReceiptState::Pending
    };
    let resource = DeletionReceiptResource {
        schema: socialname_protocol::ProtocolVersion::ApiV1,
        deletion_request_id: DeletionRequestId::new(request.id.to_string())
            .map_err(|_| DeletionError::Unavailable)?,
        state,
        evaluated_at_unix_ms: request.evaluated_at_unix_ms,
        stores,
        primary_completed_at_unix_ms: request.primary_completed_at_unix_ms,
        backup_expiry_by_unix_ms: request.backup_expiry_by_unix_ms,
        remaining_backup_expiry_ms: request
            .backup_expiry_by_unix_ms
            .saturating_sub(request.evaluated_at_unix_ms)
            .max(0),
        completed_at_unix_ms: request.completed_at_unix_ms,
    };
    resource
        .validate()
        .map_err(|_| DeletionError::Unavailable)?;
    Ok(resource)
}

async fn load_owned_resource(
    transaction: &mut Transaction<'_, Postgres>,
    principal: &AuthenticatedPrincipal,
    deletion_request_id: Uuid,
) -> Result<Option<DeletionRequestResource>, DeletionError> {
    let stored: Option<StoredDeletionRequest> = sqlx::query_as(
        "SELECT request.id, request.scope_kind, request.state, \
                (EXTRACT(EPOCH FROM request.requested_at) * 1000)::bigint \
                    AS requested_at_unix_ms, \
                (EXTRACT(EPOCH FROM request.hide_by) * 1000)::bigint \
                    AS hide_by_unix_ms, \
                (EXTRACT(EPOCH FROM request.support_withdrawal_by) * 1000)::bigint \
                    AS support_withdrawal_by_unix_ms, \
                (EXTRACT(EPOCH FROM request.primary_delete_by) * 1000)::bigint \
                    AS primary_delete_by_unix_ms, \
                (EXTRACT(EPOCH FROM request.derived_rebuild_by) * 1000)::bigint \
                    AS derived_rebuild_by_unix_ms, \
                (EXTRACT(EPOCH FROM request.backup_expiry_by) * 1000)::bigint \
                    AS backup_expiry_by_unix_ms, \
                (SELECT count(*) FROM deletion_resource_matches AS matched \
                 WHERE matched.tenant_id = request.tenant_id \
                   AND matched.deletion_request_id = request.id \
                   AND matched.resource_kind = 'observation')::bigint \
                    AS matched_observations, \
                (SELECT count(*) FROM deletion_resource_matches AS matched \
                 WHERE matched.tenant_id = request.tenant_id \
                   AND matched.deletion_request_id = request.id)::bigint \
                    AS hidden_resources, \
                (EXTRACT(EPOCH FROM request.support_withdrawn_at) * 1000)::bigint \
                    AS support_withdrawn_at_unix_ms, \
                (EXTRACT(EPOCH FROM request.primary_completed_at) * 1000)::bigint \
                    AS primary_completed_at_unix_ms, \
                (EXTRACT(EPOCH FROM request.completed_at) * 1000)::bigint \
                    AS completed_at_unix_ms \
         FROM deletion_requests AS request \
         WHERE request.tenant_id = $1 AND request.id = $2 \
           AND request.requested_by_membership_id = $3 \
           AND request.request_origin = 'contributor_api'",
    )
    .bind(principal.workspace_id)
    .bind(deletion_request_id)
    .bind(principal.membership_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| DeletionError::Unavailable)?;
    stored.map(TryInto::try_into).transpose()
}

pub(crate) fn contributor_suppression_token(
    key: &[u8; 32],
    tenant_id: Uuid,
    subject_kind: &str,
    subject_id: Uuid,
    purpose: &str,
) -> Option<[u8; 32]> {
    let Ok(mut hmac) = HmacSha256::new_from_slice(key) else {
        return None;
    };
    for field in [
        b"socialname:suppression:v1".as_slice(),
        b"contributor",
        tenant_id.as_bytes(),
        subject_kind.as_bytes(),
        subject_id.as_bytes(),
        purpose.as_bytes(),
    ] {
        let Ok(field_length) = u64::try_from(field.len()) else {
            return None;
        };
        hmac.update(&field_length.to_be_bytes());
        hmac.update(field);
    }
    Some(hmac.finalize().into_bytes().into())
}

pub(crate) fn target_suppression_token(
    key: &[u8; 32],
    tenant_id: Uuid,
    site_id: &str,
    normalized_username: &str,
) -> Option<[u8; 32]> {
    let Ok(mut hmac) = HmacSha256::new_from_slice(key) else {
        return None;
    };
    for field in [
        b"socialname:suppression:v1".as_slice(),
        b"target",
        tenant_id.as_bytes(),
        site_id.as_bytes(),
        normalized_username.as_bytes(),
    ] {
        let Ok(field_length) = u64::try_from(field.len()) else {
            return None;
        };
        hmac.update(&field_length.to_be_bytes());
        hmac.update(field);
    }
    Some(hmac.finalize().into_bytes().into())
}

pub(crate) fn suppression_key_fingerprint(key: &[u8; 32]) -> Option<[u8; 32]> {
    let mut hmac = HmacSha256::new_from_slice(key).ok()?;
    let domain = b"socialname:suppression-key-fingerprint:v1";
    hmac.update(&u64::try_from(domain.len()).ok()?.to_be_bytes());
    hmac.update(domain);
    Some(hmac.finalize().into_bytes().into())
}

fn error_response(request_id: RequestId, error: DeletionError) -> Response {
    match error {
        DeletionError::InvalidRequest(field, code) => (
            StatusCode::BAD_REQUEST,
            Json(socialname_protocol::ApiErrorResponse::invalid_request(
                request_id,
                ValidationErrors::new(field, code),
            )),
        )
            .into_response(),
        DeletionError::NotFound => crate::api_error_response(
            StatusCode::NOT_FOUND,
            request_id,
            standard_api_error(ApiErrorCode::NotFound, false),
        ),
        DeletionError::Conflict => crate::api_error_response(
            StatusCode::CONFLICT,
            request_id,
            standard_api_error(ApiErrorCode::Conflict, false),
        ),
        DeletionError::Authentication(AuthenticationError::Forbidden) => crate::api_error_response(
            StatusCode::FORBIDDEN,
            request_id,
            standard_api_error(ApiErrorCode::Forbidden, false),
        ),
        DeletionError::Authentication(AuthenticationError::InvalidCredential) => {
            unauthenticated_response(request_id)
        }
        DeletionError::Authentication(AuthenticationError::Unavailable)
        | DeletionError::Unavailable => crate::api_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            request_id,
            standard_api_error(ApiErrorCode::Unavailable, true),
        ),
    }
}

#[derive(FromRow)]
struct OwnedConsentSubject {
    subject_kind: String,
    subject_id: Uuid,
    purpose: String,
}

#[derive(FromRow)]
struct StoredDeletionRequest {
    id: Uuid,
    scope_kind: String,
    state: String,
    requested_at_unix_ms: i64,
    hide_by_unix_ms: i64,
    support_withdrawal_by_unix_ms: i64,
    primary_delete_by_unix_ms: i64,
    derived_rebuild_by_unix_ms: i64,
    backup_expiry_by_unix_ms: i64,
    matched_observations: i64,
    hidden_resources: i64,
    support_withdrawn_at_unix_ms: Option<i64>,
    primary_completed_at_unix_ms: Option<i64>,
    completed_at_unix_ms: Option<i64>,
}

#[derive(FromRow)]
struct StoredReceiptRequest {
    id: Uuid,
    state: String,
    evaluated_at_unix_ms: i64,
    backup_expiry_by_unix_ms: i64,
    primary_completed_at_unix_ms: Option<i64>,
    completed_at_unix_ms: Option<i64>,
    receipt_exists: bool,
}

#[derive(FromRow)]
struct StoredReceiptTask {
    store_kind: String,
    state: String,
    deadline_at_unix_ms: i64,
    completed_at_unix_ms: Option<i64>,
}

impl TryFrom<StoredReceiptTask> for DeletionStoreReceipt {
    type Error = DeletionError;

    fn try_from(stored: StoredReceiptTask) -> Result<Self, Self::Error> {
        let receipt = Self {
            store: match stored.store_kind.as_str() {
                "primary" => DeletionStoreKind::Primary,
                "analytics" => DeletionStoreKind::Derived,
                "backup" => DeletionStoreKind::Backup,
                _ => return Err(DeletionError::Unavailable),
            },
            state: match stored.state.as_str() {
                "pending" => DeletionStoreState::Pending,
                "running" => DeletionStoreState::Running,
                "retry_wait" => DeletionStoreState::RetryWait,
                "completed" => DeletionStoreState::Completed,
                "failed" => DeletionStoreState::Failed,
                _ => return Err(DeletionError::Unavailable),
            },
            deadline_at_unix_ms: stored.deadline_at_unix_ms,
            completed_at_unix_ms: stored.completed_at_unix_ms,
        };
        receipt.validate().map_err(|_| DeletionError::Unavailable)?;
        Ok(receipt)
    }
}

impl TryFrom<StoredDeletionRequest> for DeletionRequestResource {
    type Error = DeletionError;

    fn try_from(stored: StoredDeletionRequest) -> Result<Self, Self::Error> {
        let resource = Self {
            schema: socialname_protocol::ProtocolVersion::ApiV1,
            deletion_request_id: DeletionRequestId::new(stored.id.to_string())
                .map_err(|_| DeletionError::Unavailable)?,
            scope: match stored.scope_kind.as_str() {
                "contributor" => DeletionScope::Contributor,
                "target" => DeletionScope::Target,
                _ => return Err(DeletionError::Unavailable),
            },
            state: match stored.state.as_str() {
                "hidden" => DeletionRequestState::Hidden,
                "withdrawing_support" => DeletionRequestState::WithdrawingSupport,
                "deleting" => DeletionRequestState::Deleting,
                "rebuilding" => DeletionRequestState::Rebuilding,
                "completed" => DeletionRequestState::Completed,
                "failed" => DeletionRequestState::Failed,
                _ => return Err(DeletionError::Unavailable),
            },
            requested_at_unix_ms: stored.requested_at_unix_ms,
            hide_by_unix_ms: stored.hide_by_unix_ms,
            support_withdrawal_by_unix_ms: stored.support_withdrawal_by_unix_ms,
            primary_delete_by_unix_ms: stored.primary_delete_by_unix_ms,
            derived_rebuild_by_unix_ms: stored.derived_rebuild_by_unix_ms,
            backup_expiry_by_unix_ms: stored.backup_expiry_by_unix_ms,
            matched_observations: u32::try_from(stored.matched_observations)
                .map_err(|_| DeletionError::Unavailable)?,
            hidden_resources: u32::try_from(stored.hidden_resources)
                .map_err(|_| DeletionError::Unavailable)?,
            support_withdrawn_at_unix_ms: stored.support_withdrawn_at_unix_ms,
            primary_completed_at_unix_ms: stored.primary_completed_at_unix_ms,
            completed_at_unix_ms: stored.completed_at_unix_ms,
        };
        resource
            .validate()
            .map_err(|_| DeletionError::Unavailable)?;
        Ok(resource)
    }
}

#[derive(Debug, thiserror::Error)]
enum DeletionError {
    #[error("deletion request is invalid")]
    InvalidRequest(&'static str, ValidationCode),
    #[error("deletion request was not found")]
    NotFound,
    #[error("deletion request conflicts with policy")]
    Conflict,
    #[error(transparent)]
    Authentication(#[from] AuthenticationError),
    #[error("deletion workflow is unavailable")]
    Unavailable,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contributor_selector_is_framed_and_not_plaintext() {
        let token = contributor_suppression_token(
            &[7; 32],
            Uuid::nil(),
            "account",
            Uuid::from_u128(1),
            "shared_observation",
        )
        .unwrap();
        assert_eq!(token.len(), 32);
        assert!(!hex::encode(token).contains("shared_observation"));
    }

    #[test]
    fn target_suppression_token_has_a_cross_process_vector() {
        let token = target_suppression_token(&[7; 32], Uuid::nil(), "github", "alice").unwrap();
        assert_eq!(
            hex::encode(token),
            "6e37c557c2a2a94a5f411838fe1abda09a8f7800423d1583603f3b31c0fbe77f"
        );
        assert_eq!(
            hex::encode(suppression_key_fingerprint(&[7; 32]).unwrap()),
            "82814fa27e037e0e33842b233eec843bb5e70a7273b6eadac9e57f5c7f2a247b"
        );
    }
}
