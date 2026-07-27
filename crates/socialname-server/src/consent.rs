use axum::{
    Json,
    extract::{
        Extension, Path, Query, State,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{HeaderValue, StatusCode, header::LOCATION},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use socialname_protocol::{
    ApiErrorCode, ApiKeyScope, ConsentCollectionProfileVersion, ConsentGrantCreateRequest,
    ConsentGrantId, ConsentGrantListPage, ConsentGrantResource, ConsentGrantState,
    ConsentNoticeVersion, ConsentPurpose, ConsentSource, ConsentSubjectId, ConsentSubjectKind,
    ConsentWithdrawalRequest, MAX_CONSENT_PAGE_ITEMS, ProtocolVersion, RequestId, Validate,
    ValidationCode, ValidationErrors,
};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    ServerState,
    auth::{self, AuthenticatedPrincipal, AuthenticationError},
    standard_api_error, unauthenticated_response,
};

const DEFAULT_PAGE_ITEMS: usize = 20;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConsentPageQuery {
    limit: Option<u16>,
    after: Option<String>,
}

pub(crate) async fn create_consent_grant(
    State(state): State<ServerState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    payload: Result<Json<ConsentGrantCreateRequest>, JsonRejection>,
) -> Response {
    let request = match parse_json(payload) {
        Ok(request) => request,
        Err((status, errors)) => {
            return invalid_request_response(status, request_id, errors);
        }
    };
    if let Err(errors) = request.validate() {
        return invalid_request_response(StatusCode::BAD_REQUEST, request_id, errors);
    }
    let Some(suppression_key) = state.config.suppression_hmac_key() else {
        return error_response(request_id, ConsentError::Unavailable);
    };
    match persist_consent_grant(
        &state.database,
        &principal,
        &request,
        suppression_key.expose(),
    )
    .await
    {
        Ok(CreateConsentOutcome { resource, replayed }) => {
            let location = format!("/v1/consent-grants/{}", resource.consent_grant_id.as_str());
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

pub(crate) async fn list_consent_grants(
    State(state): State<ServerState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    query: Result<Query<ConsentPageQuery>, QueryRejection>,
) -> Response {
    let page = match parse_page_query(query) {
        Ok(page) => page,
        Err(error) => return error_response(request_id, error),
    };
    match load_consent_grant_page(&state.database, &principal, page).await {
        Ok(resource) => Json(resource).into_response(),
        Err(error) => error_response(request_id, error),
    }
}

pub(crate) async fn get_consent_grant(
    State(state): State<ServerState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Path(consent_grant_id): Path<String>,
) -> Response {
    let consent_grant_id = match parse_grant_id(&consent_grant_id) {
        Ok(value) => value,
        Err(error) => return error_response(request_id, error),
    };
    match load_consent_grant(
        &state.database,
        &principal,
        consent_grant_id,
        ApiKeyScope::ConsentRead,
    )
    .await
    {
        Ok(resource) => Json(resource).into_response(),
        Err(error) => error_response(request_id, error),
    }
}

pub(crate) async fn withdraw_consent_grant(
    State(state): State<ServerState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Path(consent_grant_id): Path<String>,
    payload: Result<Json<ConsentWithdrawalRequest>, JsonRejection>,
) -> Response {
    let consent_grant_id = match parse_grant_id(&consent_grant_id) {
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
    match persist_withdrawal(&state.database, &principal, consent_grant_id).await {
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

#[derive(Clone, Copy)]
struct ConsentPageRequest {
    limit: usize,
    after: Option<Uuid>,
}

fn parse_page_query(
    query: Result<Query<ConsentPageQuery>, QueryRejection>,
) -> Result<ConsentPageRequest, ConsentError> {
    let Query(query) =
        query.map_err(|_| ConsentError::InvalidRequest("query", ValidationCode::InvalidFormat))?;
    let limit = usize::from(query.limit.unwrap_or(DEFAULT_PAGE_ITEMS as u16));
    if !(1..=MAX_CONSENT_PAGE_ITEMS).contains(&limit) {
        return Err(ConsentError::InvalidRequest(
            "limit",
            ValidationCode::OutOfRange,
        ));
    }
    let after = query
        .after
        .map(|value| {
            Uuid::parse_str(&value)
                .map_err(|_| ConsentError::InvalidRequest("after", ValidationCode::InvalidFormat))
        })
        .transpose()?;
    Ok(ConsentPageRequest { limit, after })
}

fn parse_grant_id(value: &str) -> Result<Uuid, ConsentError> {
    Uuid::parse_str(value).map_err(|_| {
        ConsentError::InvalidRequest("consent_grant_id", ValidationCode::InvalidFormat)
    })
}

struct CreateConsentOutcome {
    resource: ConsentGrantResource,
    replayed: bool,
}

async fn persist_consent_grant(
    pool: &PgPool,
    principal: &AuthenticatedPrincipal,
    request: &ConsentGrantCreateRequest,
    suppression_key: &[u8; 32],
) -> Result<CreateConsentOutcome, ConsentError> {
    let mut transaction =
        auth::begin_authorized_transaction(pool, principal, ApiKeyScope::ConsentWrite).await?;
    let now_unix_ms: i64 =
        sqlx::query_scalar("SELECT (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| ConsentError::Unavailable)?;
    if request
        .expires_at_unix_ms
        .is_some_and(|expires_at| expires_at <= now_unix_ms)
    {
        return Err(ConsentError::InvalidRequest(
            "expires_at_unix_ms",
            ValidationCode::OutOfRange,
        ));
    }

    let (membership_id, client_id, subject_id) =
        resolve_subject(&mut transaction, principal, request).await?;
    let lock_key = format!(
        "consent-v1:{}:{}:{}",
        request.subject_kind.as_str(),
        subject_id,
        request.purpose.as_str()
    );
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(lock_key)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ConsentError::Unavailable)?;
    let suppression_token = crate::deletion::contributor_suppression_token(
        suppression_key,
        principal.workspace_id,
        request.subject_kind.as_str(),
        subject_id,
        request.purpose.as_str(),
    )
    .ok_or(ConsentError::Unavailable)?;
    let key_fingerprint = crate::deletion::suppression_key_fingerprint(suppression_key)
        .ok_or(ConsentError::Unavailable)?;
    let (incompatible_key_exists, suppressed): (bool, bool) = sqlx::query_as(
        "SELECT \
            EXISTS (\
                SELECT 1 FROM suppression_tokens \
                WHERE tenant_id = $1 \
                  AND purpose = 'contributor_reingestion' \
                  AND expires_at > clock_timestamp() \
                  AND key_fingerprint IS DISTINCT FROM $3\
            ), \
            EXISTS (\
                SELECT 1 FROM suppression_tokens \
                WHERE tenant_id = $1 \
                  AND purpose = 'contributor_reingestion' \
                  AND token_hmac = $2 \
                  AND key_fingerprint = $3 \
                  AND expires_at > clock_timestamp()\
            )",
    )
    .bind(principal.workspace_id)
    .bind(suppression_token.as_slice())
    .bind(key_fingerprint.as_slice())
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| ConsentError::Unavailable)?;
    if incompatible_key_exists {
        return Err(ConsentError::Unavailable);
    }
    if suppressed {
        return Err(ConsentError::Conflict);
    }

    let existing: Option<(Uuid, bool)> = sqlx::query_as(
        "SELECT id, \
                expires_at IS NOT DISTINCT FROM (\
                    CASE WHEN $8::bigint IS NULL THEN NULL \
                         ELSE to_timestamp($8::double precision / 1000.0) END\
                ) AS exact_expiry \
         FROM consent_grants \
         WHERE tenant_id = $1 \
           AND membership_id IS NOT DISTINCT FROM $2 \
           AND client_id IS NOT DISTINCT FROM $3 \
           AND subject_kind = $4 \
           AND purpose = $5 \
           AND collection_profile_version = $6 \
           AND notice_version = $7 \
           AND withdrawn_at IS NULL \
           AND granted_at <= clock_timestamp() \
           AND (expires_at IS NULL OR expires_at > clock_timestamp()) \
         ORDER BY granted_at DESC, id DESC \
         LIMIT 1 \
         FOR UPDATE",
    )
    .bind(principal.workspace_id)
    .bind(membership_id)
    .bind(client_id)
    .bind(request.subject_kind.as_str())
    .bind(request.purpose.as_str())
    .bind(request.collection_profile_version.as_str())
    .bind(request.notice_version.as_str())
    .bind(request.expires_at_unix_ms)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| ConsentError::Unavailable)?;

    let (consent_grant_id, replayed) = if let Some((existing, exact_expiry)) = existing {
        if !exact_expiry {
            return Err(ConsentError::Conflict);
        }
        (existing, true)
    } else {
        let consent_grant_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO consent_grants (\
                id, tenant_id, membership_id, client_id, subject_kind, purpose, \
                collection_profile_version, notice_version, source, granted_at, expires_at\
             ) VALUES (\
                $1, $2, $3, $4, $5, $6, $7, $8, 'api', clock_timestamp(), \
                CASE WHEN $9::bigint IS NULL THEN NULL \
                     ELSE to_timestamp($9::double precision / 1000.0) END\
             )",
        )
        .bind(consent_grant_id)
        .bind(principal.workspace_id)
        .bind(membership_id)
        .bind(client_id)
        .bind(request.subject_kind.as_str())
        .bind(request.purpose.as_str())
        .bind(request.collection_profile_version.as_str())
        .bind(request.notice_version.as_str())
        .bind(request.expires_at_unix_ms)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ConsentError::Unavailable)?;
        sqlx::query(
            "INSERT INTO consent_events (\
                id, tenant_id, consent_grant_id, event_kind, \
                actor_membership_id, occurred_at, details\
             ) \
             SELECT $1, tenant_id, id, 'granted', $2, granted_at, '{}'::jsonb \
             FROM consent_grants \
             WHERE tenant_id = $3 AND id = $4",
        )
        .bind(Uuid::new_v4())
        .bind(principal.membership_id)
        .bind(principal.workspace_id)
        .bind(consent_grant_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ConsentError::Unavailable)?;
        (consent_grant_id, false)
    };

    let resource = load_owned_resource(&mut transaction, principal, consent_grant_id)
        .await?
        .ok_or(ConsentError::Unavailable)?;
    transaction
        .commit()
        .await
        .map_err(|_| ConsentError::Unavailable)?;
    Ok(CreateConsentOutcome { resource, replayed })
}

async fn resolve_subject(
    transaction: &mut Transaction<'_, Postgres>,
    principal: &AuthenticatedPrincipal,
    request: &ConsentGrantCreateRequest,
) -> Result<(Option<Uuid>, Option<Uuid>, Uuid), ConsentError> {
    match request.subject_kind {
        ConsentSubjectKind::Account => {
            Ok((Some(principal.membership_id), None, principal.membership_id))
        }
        ConsentSubjectKind::Installation => {
            let installation_id =
                request
                    .installation_id
                    .as_ref()
                    .ok_or(ConsentError::InvalidRequest(
                        "installation_id",
                        ValidationCode::InvalidRelation,
                    ))?;
            let installation_hash =
                installation_hash(principal.workspace_id, installation_id.as_str().as_bytes());
            let candidate_id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO clients (\
                    id, tenant_id, installation_hash, consent_owner_membership_id, \
                    state, created_at, last_seen_at\
                 ) VALUES ($1, $2, $3, $4, 'active', clock_timestamp(), clock_timestamp()) \
                 ON CONFLICT (tenant_id, installation_hash) DO NOTHING",
            )
            .bind(candidate_id)
            .bind(principal.workspace_id)
            .bind(&installation_hash[..])
            .bind(principal.membership_id)
            .execute(&mut **transaction)
            .await
            .map_err(|_| ConsentError::Unavailable)?;
            let client: Option<(Uuid, String, Option<Uuid>)> = sqlx::query_as(
                "SELECT id, state, consent_owner_membership_id \
                 FROM clients \
                 WHERE tenant_id = $1 AND installation_hash = $2 \
                 FOR UPDATE",
            )
            .bind(principal.workspace_id)
            .bind(&installation_hash[..])
            .fetch_optional(&mut **transaction)
            .await
            .map_err(|_| ConsentError::Unavailable)?;
            let Some((client_id, state, consent_owner_membership_id)) = client else {
                return Err(ConsentError::Unavailable);
            };
            if state != "active" || consent_owner_membership_id != Some(principal.membership_id) {
                return Err(ConsentError::Conflict);
            }
            sqlx::query(
                "UPDATE clients \
                 SET last_seen_at = GREATEST(\
                    created_at, clock_timestamp(), COALESCE(last_seen_at, created_at)\
                 ) \
                 WHERE tenant_id = $1 AND id = $2",
            )
            .bind(principal.workspace_id)
            .bind(client_id)
            .execute(&mut **transaction)
            .await
            .map_err(|_| ConsentError::Unavailable)?;
            Ok((None, Some(client_id), client_id))
        }
    }
}

pub(crate) fn installation_hash(workspace_id: Uuid, installation_id: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"socialname-installation-v1\0");
    hasher.update(workspace_id.as_bytes());
    hasher.update([0]);
    hasher.update(installation_id);
    hasher.finalize().into()
}

async fn load_consent_grant(
    pool: &PgPool,
    principal: &AuthenticatedPrincipal,
    consent_grant_id: Uuid,
    scope: ApiKeyScope,
) -> Result<ConsentGrantResource, ConsentError> {
    let mut transaction = auth::begin_authorized_transaction(pool, principal, scope).await?;
    let resource = load_owned_resource(&mut transaction, principal, consent_grant_id)
        .await?
        .ok_or(ConsentError::NotFound)?;
    transaction
        .commit()
        .await
        .map_err(|_| ConsentError::Unavailable)?;
    Ok(resource)
}

async fn load_consent_grant_page(
    pool: &PgPool,
    principal: &AuthenticatedPrincipal,
    page: ConsentPageRequest,
) -> Result<ConsentGrantListPage, ConsentError> {
    let mut transaction =
        auth::begin_authorized_transaction(pool, principal, ApiKeyScope::ConsentRead).await?;
    if let Some(cursor) = page.after {
        let cursor_owned: bool = sqlx::query_scalar(
            "SELECT EXISTS(\
                SELECT 1 FROM consent_grants AS consent \
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
                  )\
             )",
        )
        .bind(principal.workspace_id)
        .bind(cursor)
        .bind(principal.membership_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ConsentError::Unavailable)?;
        if !cursor_owned {
            return Err(ConsentError::InvalidRequest(
                "after",
                ValidationCode::InvalidRelation,
            ));
        }
    }

    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT consent.id \
         FROM consent_grants AS consent \
         WHERE consent.tenant_id = $1 \
           AND (\
             (consent.subject_kind = 'account' AND consent.membership_id = $2) \
             OR (consent.subject_kind = 'installation' AND EXISTS (\
                 SELECT 1 FROM consent_events AS event \
                 WHERE event.tenant_id = consent.tenant_id \
                   AND event.consent_grant_id = consent.id \
                   AND event.event_kind = 'granted' \
                   AND event.actor_membership_id = $2\
             ))\
           ) \
           AND (\
             $3::uuid IS NULL \
             OR EXISTS (\
                 SELECT 1 FROM consent_grants AS cursor \
                 WHERE cursor.tenant_id = consent.tenant_id AND cursor.id = $3 \
                   AND (consent.granted_at, consent.id) \
                       < (cursor.granted_at, cursor.id)\
             )\
           ) \
         ORDER BY consent.granted_at DESC, consent.id DESC \
         LIMIT $4",
    )
    .bind(principal.workspace_id)
    .bind(principal.membership_id)
    .bind(page.after)
    .bind(i64::try_from(page.limit + 1).map_err(|_| ConsentError::Unavailable)?)
    .fetch_all(&mut *transaction)
    .await
    .map_err(|_| ConsentError::Unavailable)?;
    let has_more = ids.len() > page.limit;
    let mut consent_grants = Vec::with_capacity(page.limit.min(ids.len()));
    for id in ids.into_iter().take(page.limit) {
        consent_grants.push(
            load_owned_resource(&mut transaction, principal, id)
                .await?
                .ok_or(ConsentError::Unavailable)?,
        );
    }
    let next_cursor = has_more
        .then(|| consent_grants.last())
        .flatten()
        .map(|grant| grant.consent_grant_id.clone());
    let page = ConsentGrantListPage {
        schema: ProtocolVersion::ApiV1,
        consent_grants,
        next_cursor,
    };
    page.validate().map_err(|_| ConsentError::Unavailable)?;
    transaction
        .commit()
        .await
        .map_err(|_| ConsentError::Unavailable)?;
    Ok(page)
}

async fn persist_withdrawal(
    pool: &PgPool,
    principal: &AuthenticatedPrincipal,
    consent_grant_id: Uuid,
) -> Result<ConsentGrantResource, ConsentError> {
    let mut transaction =
        auth::begin_authorized_transaction(pool, principal, ApiKeyScope::ConsentWrite).await?;
    let owned: Option<bool> = sqlx::query_scalar(
        "SELECT consent.withdrawn_at IS NOT NULL \
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
    .map_err(|_| ConsentError::Unavailable)?;
    let Some(already_withdrawn) = owned else {
        return Err(ConsentError::NotFound);
    };
    if !already_withdrawn {
        sqlx::query(
            "UPDATE consent_grants \
             SET withdrawn_at = clock_timestamp() \
             WHERE tenant_id = $1 AND id = $2 AND withdrawn_at IS NULL",
        )
        .bind(principal.workspace_id)
        .bind(consent_grant_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ConsentError::Unavailable)?;
        sqlx::query(
            "INSERT INTO consent_events (\
                id, tenant_id, consent_grant_id, event_kind, \
                actor_membership_id, occurred_at, details\
             ) \
             SELECT $1, tenant_id, id, 'withdrawn', $2, withdrawn_at, '{}'::jsonb \
             FROM consent_grants \
             WHERE tenant_id = $3 AND id = $4",
        )
        .bind(Uuid::new_v4())
        .bind(principal.membership_id)
        .bind(principal.workspace_id)
        .bind(consent_grant_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ConsentError::Unavailable)?;
    }
    let resource = load_owned_resource(&mut transaction, principal, consent_grant_id)
        .await?
        .ok_or(ConsentError::Unavailable)?;
    transaction
        .commit()
        .await
        .map_err(|_| ConsentError::Unavailable)?;
    Ok(resource)
}

async fn load_owned_resource(
    transaction: &mut Transaction<'_, Postgres>,
    principal: &AuthenticatedPrincipal,
    consent_grant_id: Uuid,
) -> Result<Option<ConsentGrantResource>, ConsentError> {
    let stored: Option<StoredConsentGrant> = sqlx::query_as(
        "SELECT \
            consent.id, consent.subject_kind, \
            COALESCE(consent.membership_id, consent.client_id) AS subject_id, \
            consent.purpose, consent.collection_profile_version, \
            consent.notice_version, consent.source, \
            CASE \
                WHEN consent.withdrawn_at IS NOT NULL THEN 'withdrawn' \
                WHEN consent.expires_at IS NOT NULL \
                 AND consent.expires_at <= clock_timestamp() THEN 'expired' \
                ELSE 'active' \
            END AS state, \
            (EXTRACT(EPOCH FROM consent.granted_at) * 1000)::bigint \
                AS granted_at_unix_ms, \
            (EXTRACT(EPOCH FROM consent.expires_at) * 1000)::bigint \
                AS expires_at_unix_ms, \
            (EXTRACT(EPOCH FROM consent.withdrawn_at) * 1000)::bigint \
                AS withdrawn_at_unix_ms \
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
           )",
    )
    .bind(principal.workspace_id)
    .bind(consent_grant_id)
    .bind(principal.membership_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| ConsentError::Unavailable)?;
    stored.map(StoredConsentGrant::into_resource).transpose()
}

#[derive(FromRow)]
struct StoredConsentGrant {
    id: Uuid,
    subject_kind: String,
    subject_id: Uuid,
    purpose: String,
    collection_profile_version: String,
    notice_version: String,
    source: String,
    state: String,
    granted_at_unix_ms: i64,
    expires_at_unix_ms: Option<i64>,
    withdrawn_at_unix_ms: Option<i64>,
}

impl StoredConsentGrant {
    fn into_resource(self) -> Result<ConsentGrantResource, ConsentError> {
        let resource = ConsentGrantResource {
            schema: ProtocolVersion::ApiV1,
            consent_grant_id: ConsentGrantId::new(self.id.to_string())
                .map_err(|_| ConsentError::Unavailable)?,
            subject_kind: parse_subject_kind(&self.subject_kind)?,
            subject_id: ConsentSubjectId::new(self.subject_id.to_string())
                .map_err(|_| ConsentError::Unavailable)?,
            purpose: parse_purpose(&self.purpose)?,
            collection_profile_version: match self.collection_profile_version.as_str() {
                "profile-v1" => ConsentCollectionProfileVersion::V1,
                _ => return Err(ConsentError::Unavailable),
            },
            notice_version: match self.notice_version.as_str() {
                "notice-v1" => ConsentNoticeVersion::V1,
                _ => return Err(ConsentError::Unavailable),
            },
            source: match self.source.as_str() {
                "cli" => ConsentSource::Cli,
                "web" => ConsentSource::Web,
                "api" => ConsentSource::Api,
                _ => return Err(ConsentError::Unavailable),
            },
            state: match self.state.as_str() {
                "active" => ConsentGrantState::Active,
                "expired" => ConsentGrantState::Expired,
                "withdrawn" => ConsentGrantState::Withdrawn,
                _ => return Err(ConsentError::Unavailable),
            },
            granted_at_unix_ms: self.granted_at_unix_ms,
            expires_at_unix_ms: self.expires_at_unix_ms,
            withdrawn_at_unix_ms: self.withdrawn_at_unix_ms,
        };
        resource.validate().map_err(|_| ConsentError::Unavailable)?;
        Ok(resource)
    }
}

fn parse_subject_kind(value: &str) -> Result<ConsentSubjectKind, ConsentError> {
    match value {
        "account" => Ok(ConsentSubjectKind::Account),
        "installation" => Ok(ConsentSubjectKind::Installation),
        _ => Err(ConsentError::Unavailable),
    }
}

fn parse_purpose(value: &str) -> Result<ConsentPurpose, ConsentError> {
    match value {
        "private_history" => Ok(ConsentPurpose::PrivateHistory),
        "shared_observation" => Ok(ConsentPurpose::SharedObservation),
        "shared_research" => Ok(ConsentPurpose::SharedResearch),
        _ => Err(ConsentError::Unavailable),
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

fn error_response(request_id: RequestId, error: ConsentError) -> Response {
    match error {
        ConsentError::InvalidRequest(field, code) => invalid_request_response(
            StatusCode::BAD_REQUEST,
            request_id,
            ValidationErrors::new(field, code),
        ),
        ConsentError::NotFound => crate::api_error_response(
            StatusCode::NOT_FOUND,
            request_id,
            standard_api_error(ApiErrorCode::NotFound, false),
        ),
        ConsentError::Conflict => crate::api_error_response(
            StatusCode::CONFLICT,
            request_id,
            standard_api_error(ApiErrorCode::Conflict, false),
        ),
        ConsentError::Authentication(AuthenticationError::Forbidden) => crate::api_error_response(
            StatusCode::FORBIDDEN,
            request_id,
            standard_api_error(ApiErrorCode::Forbidden, false),
        ),
        ConsentError::Authentication(AuthenticationError::InvalidCredential) => {
            unauthenticated_response(request_id)
        }
        ConsentError::Authentication(AuthenticationError::Unavailable)
        | ConsentError::Unavailable => crate::api_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            request_id,
            standard_api_error(ApiErrorCode::Unavailable, true),
        ),
    }
}

#[derive(Debug, thiserror::Error)]
enum ConsentError {
    #[error("consent request is invalid")]
    InvalidRequest(&'static str, ValidationCode),
    #[error("consent grant was not found")]
    NotFound,
    #[error("consent subject is not active")]
    Conflict,
    #[error(transparent)]
    Authentication(#[from] AuthenticationError),
    #[error("consent storage is unavailable")]
    Unavailable,
}

#[cfg(test)]
mod tests {
    use super::*;
    use socialname_protocol::InstallationId;

    #[test]
    fn installation_hash_is_tenant_separated_and_deterministic() {
        let installation = InstallationId::new("11111111-1111-4111-8111-111111111111").unwrap();
        let first = installation_hash(Uuid::from_u128(1), installation.as_str().as_bytes());
        assert_eq!(
            first,
            installation_hash(Uuid::from_u128(1), installation.as_str().as_bytes())
        );
        assert_ne!(
            first,
            installation_hash(Uuid::from_u128(2), installation.as_str().as_bytes())
        );
    }

    #[test]
    fn page_query_is_bounded_and_rejects_private_cursor_text() {
        assert!(matches!(
            parse_page_query(Ok(Query(ConsentPageQuery {
                limit: Some(51),
                after: None,
            }))),
            Err(ConsentError::InvalidRequest(
                "limit",
                ValidationCode::OutOfRange
            ))
        ));
        let private = "private-consent-cursor";
        let error = Uuid::parse_str(private)
            .map_err(|_| ConsentError::InvalidRequest("after", ValidationCode::InvalidFormat))
            .unwrap_err();
        assert!(!error.to_string().contains(private));
    }
}
