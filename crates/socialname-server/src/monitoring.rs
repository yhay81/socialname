use axum::{
    Json,
    extract::{Extension, Path, Query, State, rejection::QueryRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use socialname_protocol::{
    AccountState, ApiErrorCode, ApiKeyScope, ConfirmationBasis, DeliveryErrorCode,
    MAX_MONITORING_PAGE_ITEMS, MeasurementState, NotificationChannel, NotificationDelivery,
    NotificationDeliveryId, NotificationDeliveryState, NotificationEndpointId, NotificationKind,
    NotificationLogicalKey, ObservationId, PendingConfirmationReason, ProtocolVersion, RegionClass,
    RequestId, RuleHash, SiteId, SuppressionReason, Target, Transition, TransitionChange,
    TransitionConfirmation, TransitionId, Username, Validate, ValidationCode, ValidationErrors,
    WatchId, WatchListPage, WatchTransitionEntry, WatchTransitionPage,
};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    ServerState,
    auth::{self, AuthenticatedPrincipal, AuthenticationError},
    standard_api_error, unauthenticated_response,
    watch::{self, WatchError},
};

const DEFAULT_PAGE_ITEMS: usize = 20;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MonitoringPageQuery {
    limit: Option<u16>,
    after: Option<String>,
}

pub(crate) async fn list_watches(
    State(state): State<ServerState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    query: Result<Query<MonitoringPageQuery>, QueryRejection>,
) -> Response {
    let page = match parse_page_query(query) {
        Ok(page) => page,
        Err(error) => return error_response(request_id, error),
    };
    match load_watch_page(&state.database, &principal, page).await {
        Ok(resource) => Json(resource).into_response(),
        Err(error) => error_response(request_id, error),
    }
}

pub(crate) async fn list_watch_transitions(
    State(state): State<ServerState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Path(watch_id): Path<String>,
    query: Result<Query<MonitoringPageQuery>, QueryRejection>,
) -> Response {
    let watch_id = match Uuid::parse_str(&watch_id) {
        Ok(watch_id) => watch_id,
        Err(_) => {
            return error_response(
                request_id,
                MonitoringError::InvalidRequest("watch_id", ValidationCode::InvalidFormat),
            );
        }
    };
    let page = match parse_page_query(query) {
        Ok(page) => page,
        Err(error) => return error_response(request_id, error),
    };
    match load_transition_page(&state.database, &principal, watch_id, page).await {
        Ok(resource) => Json(resource).into_response(),
        Err(error) => error_response(request_id, error),
    }
}

#[derive(Clone, Copy)]
struct PageRequest {
    limit: usize,
    after: Option<Uuid>,
}

fn parse_page_query(
    query: Result<Query<MonitoringPageQuery>, QueryRejection>,
) -> Result<PageRequest, MonitoringError> {
    let Query(query) = query
        .map_err(|_| MonitoringError::InvalidRequest("query", ValidationCode::InvalidFormat))?;
    let limit = usize::from(query.limit.unwrap_or(DEFAULT_PAGE_ITEMS as u16));
    if !(1..=MAX_MONITORING_PAGE_ITEMS).contains(&limit) {
        return Err(MonitoringError::InvalidRequest(
            "limit",
            ValidationCode::OutOfRange,
        ));
    }
    let after = query
        .after
        .map(|value| {
            Uuid::parse_str(&value).map_err(|_| {
                MonitoringError::InvalidRequest("after", ValidationCode::InvalidFormat)
            })
        })
        .transpose()?;
    Ok(PageRequest { limit, after })
}

async fn load_watch_page(
    pool: &PgPool,
    principal: &AuthenticatedPrincipal,
    page: PageRequest,
) -> Result<WatchListPage, MonitoringError> {
    let mut transaction =
        auth::begin_authorized_transaction(pool, principal, ApiKeyScope::WatchRead).await?;
    ensure_watch_cursor(&mut transaction, principal.workspace_id, page.after).await?;
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT watch.id \
         FROM watches AS watch \
         WHERE watch.tenant_id = $1 \
           AND (\
                $2::uuid IS NULL \
                OR EXISTS (\
                    SELECT 1 FROM watches AS cursor \
                    WHERE cursor.tenant_id = $1 AND cursor.id = $2 \
                      AND (watch.created_at, watch.id) \
                          < (cursor.created_at, cursor.id)\
                )\
           ) \
         ORDER BY watch.created_at DESC, watch.id DESC \
         LIMIT $3",
    )
    .bind(principal.workspace_id)
    .bind(page.after)
    .bind(i64::try_from(page.limit + 1).map_err(|_| MonitoringError::Unavailable)?)
    .fetch_all(&mut *transaction)
    .await
    .map_err(|_| MonitoringError::Unavailable)?;
    let has_more = ids.len() > page.limit;
    let mut watches = Vec::with_capacity(page.limit.min(ids.len()));
    for id in ids.into_iter().take(page.limit) {
        watches.push(
            watch::load_watch_resource(&mut transaction, principal.workspace_id, id)
                .await
                .map_err(MonitoringError::from_watch)?,
        );
    }
    let next_cursor = has_more
        .then(|| watches.last())
        .flatten()
        .map(|watch| watch.watch_id.clone());
    let resource = WatchListPage {
        schema: ProtocolVersion::ApiV1,
        watches,
        next_cursor,
    };
    resource
        .validate()
        .map_err(|_| MonitoringError::Unavailable)?;
    transaction
        .commit()
        .await
        .map_err(|_| MonitoringError::Unavailable)?;
    Ok(resource)
}

async fn ensure_watch_cursor(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    cursor: Option<Uuid>,
) -> Result<(), MonitoringError> {
    let Some(cursor) = cursor else {
        return Ok(());
    };
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(\
            SELECT 1 FROM watches WHERE tenant_id = $1 AND id = $2\
         )",
    )
    .bind(tenant_id)
    .bind(cursor)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| MonitoringError::Unavailable)?;
    if exists {
        Ok(())
    } else {
        Err(MonitoringError::InvalidRequest(
            "after",
            ValidationCode::InvalidRelation,
        ))
    }
}

async fn load_transition_page(
    pool: &PgPool,
    principal: &AuthenticatedPrincipal,
    watch_id: Uuid,
    page: PageRequest,
) -> Result<WatchTransitionPage, MonitoringError> {
    let mut transaction =
        auth::begin_authorized_transaction(pool, principal, ApiKeyScope::WatchRead).await?;
    watch::load_watch_resource(&mut transaction, principal.workspace_id, watch_id)
        .await
        .map_err(MonitoringError::from_watch)?;
    ensure_transition_cursor(
        &mut transaction,
        principal.workspace_id,
        watch_id,
        page.after,
    )
    .await?;
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT transition.id \
         FROM transitions AS transition \
         JOIN watch_targets AS target \
           ON target.tenant_id = transition.tenant_id \
          AND target.id = transition.watch_target_id \
         WHERE transition.tenant_id = $1 AND target.watch_id = $2 \
           AND NOT EXISTS (\
               SELECT 1 FROM deletion_resource_matches AS matched \
               WHERE matched.tenant_id = transition.tenant_id \
                 AND matched.resource_kind = 'transition' \
                 AND matched.resource_id = transition.id\
           ) \
           AND (\
                $3::uuid IS NULL \
                OR EXISTS (\
                    SELECT 1 \
                    FROM transitions AS cursor \
                    JOIN watch_targets AS cursor_target \
                      ON cursor_target.tenant_id = cursor.tenant_id \
                     AND cursor_target.id = cursor.watch_target_id \
                    WHERE cursor.tenant_id = $1 AND cursor.id = $3 \
                      AND cursor_target.watch_id = $2 \
                      AND (transition.detected_at, transition.id) \
                          < (cursor.detected_at, cursor.id)\
                )\
           ) \
         ORDER BY transition.detected_at DESC, transition.id DESC \
         LIMIT $4",
    )
    .bind(principal.workspace_id)
    .bind(watch_id)
    .bind(page.after)
    .bind(i64::try_from(page.limit + 1).map_err(|_| MonitoringError::Unavailable)?)
    .fetch_all(&mut *transaction)
    .await
    .map_err(|_| MonitoringError::Unavailable)?;
    let has_more = ids.len() > page.limit;
    let mut entries = Vec::with_capacity(page.limit.min(ids.len()));
    for id in ids.into_iter().take(page.limit) {
        entries.push(
            load_transition_entry(&mut transaction, principal.workspace_id, watch_id, id).await?,
        );
    }
    let next_cursor = has_more
        .then(|| entries.last())
        .flatten()
        .map(|entry| entry.transition.transition_id.clone());
    let resource = WatchTransitionPage {
        schema: ProtocolVersion::ApiV1,
        watch_id: WatchId::new(watch_id.to_string()).map_err(|_| MonitoringError::Unavailable)?,
        entries,
        next_cursor,
    };
    resource
        .validate()
        .map_err(|_| MonitoringError::Unavailable)?;
    transaction
        .commit()
        .await
        .map_err(|_| MonitoringError::Unavailable)?;
    Ok(resource)
}

async fn ensure_transition_cursor(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    watch_id: Uuid,
    cursor: Option<Uuid>,
) -> Result<(), MonitoringError> {
    let Some(cursor) = cursor else {
        return Ok(());
    };
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(\
            SELECT 1 \
            FROM transitions AS transition \
            JOIN watch_targets AS target \
              ON target.tenant_id = transition.tenant_id \
             AND target.id = transition.watch_target_id \
            WHERE transition.tenant_id = $1 AND transition.id = $2 \
              AND target.watch_id = $3 \
              AND NOT EXISTS (\
                  SELECT 1 FROM deletion_resource_matches AS matched \
                  WHERE matched.tenant_id = transition.tenant_id \
                    AND matched.resource_kind = 'transition' \
                    AND matched.resource_id = transition.id\
              )\
         )",
    )
    .bind(tenant_id)
    .bind(cursor)
    .bind(watch_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| MonitoringError::Unavailable)?;
    if exists {
        Ok(())
    } else {
        Err(MonitoringError::InvalidRequest(
            "after",
            ValidationCode::InvalidRelation,
        ))
    }
}

async fn load_transition_entry(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    watch_id: Uuid,
    transition_id: Uuid,
) -> Result<WatchTransitionEntry, MonitoringError> {
    let row: StoredTransition = sqlx::query_as(
        "SELECT transition.id, transition.transition_class, \
                transition.from_state, transition.to_state, \
                transition.region_class, \
                CASE WHEN version.rule_hash IS NULL THEN NULL \
                     ELSE encode(version.rule_hash, 'hex') END AS rule_hash, \
                transition.confirmation_status, transition.confirmation_basis, \
                transition.pending_reason, transition.suppression_reason, \
                (extract(epoch FROM transition.detected_at) * 1000)::bigint \
                    AS detected_at_unix_ms, \
                target.normalized_username, target.site_id \
         FROM transitions AS transition \
         JOIN watch_targets AS target \
           ON target.tenant_id = transition.tenant_id \
          AND target.id = transition.watch_target_id \
         LEFT JOIN rule_versions AS version \
           ON version.id = transition.rule_version_id \
         WHERE transition.tenant_id = $1 AND transition.id = $2 \
           AND target.watch_id = $3 \
           AND NOT EXISTS (\
               SELECT 1 FROM deletion_resource_matches AS matched \
               WHERE matched.tenant_id = transition.tenant_id \
                 AND matched.resource_kind = 'transition' \
                 AND matched.resource_id = transition.id\
           )",
    )
    .bind(tenant_id)
    .bind(transition_id)
    .bind(watch_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| MonitoringError::Unavailable)?;
    let supporting_ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT observation_id \
         FROM transition_basis \
         WHERE tenant_id = $1 AND transition_id = $2 \
           AND NOT EXISTS (\
               SELECT 1 FROM deletion_resource_matches AS matched \
               WHERE matched.tenant_id = transition_basis.tenant_id \
                 AND matched.resource_kind = 'observation' \
                 AND matched.resource_id = transition_basis.observation_id\
           ) \
         ORDER BY observation_id",
    )
    .bind(tenant_id)
    .bind(transition_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| MonitoringError::Unavailable)?;
    let transition = protocol_transition(row, watch_id, supporting_ids)?;
    let delivery_rows: Vec<StoredDelivery> = sqlx::query_as(
        "SELECT delivery.id, delivery.endpoint_id, delivery.transition_id, \
                encode(delivery.logical_notification_key, 'hex') \
                    AS logical_notification_key, \
                endpoint.channel, delivery.confirmation_basis, delivery.state, \
                delivery.attempt_count, \
                (extract(epoch FROM delivery.created_at) * 1000)::bigint \
                    AS created_at_unix_ms, \
                (extract(epoch FROM delivery.next_attempt_at) * 1000)::bigint \
                    AS next_attempt_at_unix_ms, \
                (extract(epoch FROM delivery.delivered_at) * 1000)::bigint \
                    AS delivered_at_unix_ms, \
                delivery.last_error_code \
         FROM notification_deliveries AS delivery \
         JOIN notification_endpoints AS endpoint \
           ON endpoint.tenant_id = delivery.tenant_id \
          AND endpoint.id = delivery.endpoint_id \
         WHERE delivery.tenant_id = $1 AND delivery.transition_id = $2 \
           AND NOT EXISTS (\
               SELECT 1 FROM deletion_resource_matches AS matched \
               WHERE matched.tenant_id = delivery.tenant_id \
                 AND matched.resource_kind = 'notification_delivery' \
                 AND matched.resource_id = delivery.id\
           ) \
         ORDER BY delivery.created_at, delivery.id",
    )
    .bind(tenant_id)
    .bind(transition_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| MonitoringError::Unavailable)?;
    let deliveries = delivery_rows
        .into_iter()
        .map(|row| protocol_delivery(row, &transition.change))
        .collect::<Result<Vec<_>, _>>()?;
    let entry = WatchTransitionEntry {
        transition,
        deliveries,
    };
    entry.validate().map_err(|_| MonitoringError::Unavailable)?;
    Ok(entry)
}

fn protocol_transition(
    row: StoredTransition,
    watch_id: Uuid,
    supporting_ids: Vec<Uuid>,
) -> Result<Transition, MonitoringError> {
    let change = match row.transition_class.as_str() {
        "account_state" => TransitionChange::AccountState {
            from: account_state(&row.from_state)?,
            to: account_state(&row.to_state)?,
        },
        "measurement_health" => TransitionChange::MeasurementHealth {
            region_class: RegionClass::new(row.region_class.ok_or(MonitoringError::Unavailable)?)
                .map_err(|_| MonitoringError::Unavailable)?,
            rule_hash: RuleHash::new(row.rule_hash.ok_or(MonitoringError::Unavailable)?)
                .map_err(|_| MonitoringError::Unavailable)?,
            from: measurement_state(&row.from_state)?,
            to: measurement_state(&row.to_state)?,
        },
        _ => return Err(MonitoringError::Unavailable),
    };
    let confirmation = match row.confirmation_status.as_str() {
        "confirmed" => TransitionConfirmation::Confirmed {
            basis: confirmation_basis(
                row.confirmation_basis
                    .as_deref()
                    .ok_or(MonitoringError::Unavailable)?,
            )?,
        },
        "pending" => TransitionConfirmation::Pending {
            reason: pending_reason(
                row.pending_reason
                    .as_deref()
                    .ok_or(MonitoringError::Unavailable)?,
            )?,
        },
        "suppressed" => TransitionConfirmation::Suppressed {
            reason: suppression_reason(
                row.suppression_reason
                    .as_deref()
                    .ok_or(MonitoringError::Unavailable)?,
            )?,
        },
        _ => return Err(MonitoringError::Unavailable),
    };
    let transition = Transition {
        schema: ProtocolVersion::ApiV1,
        transition_id: TransitionId::new(row.id.to_string())
            .map_err(|_| MonitoringError::Unavailable)?,
        watch_id: WatchId::new(watch_id.to_string()).map_err(|_| MonitoringError::Unavailable)?,
        target: Target {
            username: Username::new(
                row.normalized_username
                    .ok_or(MonitoringError::Unavailable)?,
            )
            .map_err(|_| MonitoringError::Unavailable)?,
            site_id: SiteId::new(row.site_id).map_err(|_| MonitoringError::Unavailable)?,
        },
        change,
        confirmation,
        supporting_observation_ids: supporting_ids
            .into_iter()
            .map(|id| ObservationId::new(id.to_string()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| MonitoringError::Unavailable)?,
        detected_at_unix_ms: row.detected_at_unix_ms,
    };
    transition
        .validate()
        .map_err(|_| MonitoringError::Unavailable)?;
    Ok(transition)
}

fn protocol_delivery(
    row: StoredDelivery,
    change: &TransitionChange,
) -> Result<NotificationDelivery, MonitoringError> {
    let delivery = NotificationDelivery {
        schema: ProtocolVersion::ApiV1,
        delivery_id: NotificationDeliveryId::new(row.id.to_string())
            .map_err(|_| MonitoringError::Unavailable)?,
        transition_id: TransitionId::new(row.transition_id.to_string())
            .map_err(|_| MonitoringError::Unavailable)?,
        endpoint_id: NotificationEndpointId::new(row.endpoint_id.to_string())
            .map_err(|_| MonitoringError::Unavailable)?,
        logical_notification_key: NotificationLogicalKey::new(row.logical_notification_key)
            .map_err(|_| MonitoringError::Unavailable)?,
        kind: match change {
            TransitionChange::AccountState { .. } => NotificationKind::AccountState,
            TransitionChange::MeasurementHealth { .. } => NotificationKind::MeasurementHealth,
        },
        channel: match row.channel.as_str() {
            "email" => NotificationChannel::Email,
            "webhook" => NotificationChannel::Webhook,
            _ => return Err(MonitoringError::Unavailable),
        },
        confirmation_basis: confirmation_basis(&row.confirmation_basis)?,
        state: delivery_state(&row.state)?,
        attempt_count: u32::try_from(row.attempt_count)
            .map_err(|_| MonitoringError::Unavailable)?,
        created_at_unix_ms: row.created_at_unix_ms,
        next_attempt_at_unix_ms: row.next_attempt_at_unix_ms,
        delivered_at_unix_ms: row.delivered_at_unix_ms,
        last_error_code: row
            .last_error_code
            .map(DeliveryErrorCode::new)
            .transpose()
            .map_err(|_| MonitoringError::Unavailable)?,
    };
    delivery
        .validate()
        .map_err(|_| MonitoringError::Unavailable)?;
    Ok(delivery)
}

const fn account_state(value: &str) -> Result<AccountState, MonitoringError> {
    match value.as_bytes() {
        b"found" => Ok(AccountState::Found),
        b"not_found" => Ok(AccountState::NotFound),
        _ => Err(MonitoringError::Unavailable),
    }
}

const fn measurement_state(value: &str) -> Result<MeasurementState, MonitoringError> {
    match value.as_bytes() {
        b"healthy" => Ok(MeasurementState::Healthy),
        b"degraded" => Ok(MeasurementState::Degraded),
        b"quarantined" => Ok(MeasurementState::Quarantined),
        b"recovering" => Ok(MeasurementState::Recovering),
        b"unavailable" => Ok(MeasurementState::Unavailable),
        _ => Err(MonitoringError::Unavailable),
    }
}

const fn confirmation_basis(value: &str) -> Result<ConfirmationBasis, MonitoringError> {
    match value.as_bytes() {
        b"managed_e4" => Ok(ConfirmationBasis::ManagedE4),
        b"managed_e3_follow_up" => Ok(ConfirmationBasis::ManagedE3FollowUp),
        b"two_managed_independent_regions" => Ok(ConfirmationBasis::TwoManagedIndependentRegions),
        b"two_managed_separated_in_time" => Ok(ConfirmationBasis::TwoManagedSeparatedInTime),
        b"corroborated_shared_candidate_opt_in" => {
            Ok(ConfirmationBasis::CorroboratedSharedCandidateOptIn)
        }
        b"measurement_health_evidence" => Ok(ConfirmationBasis::MeasurementHealthEvidence),
        _ => Err(MonitoringError::Unavailable),
    }
}

const fn pending_reason(value: &str) -> Result<PendingConfirmationReason, MonitoringError> {
    match value.as_bytes() {
        b"managed_verification_required" => {
            Ok(PendingConfirmationReason::ManagedVerificationRequired)
        }
        b"second_managed_observation_required" => {
            Ok(PendingConfirmationReason::SecondManagedObservationRequired)
        }
        b"regional_conflict" => Ok(PendingConfirmationReason::RegionalConflict),
        _ => Err(MonitoringError::Unavailable),
    }
}

const fn suppression_reason(value: &str) -> Result<SuppressionReason, MonitoringError> {
    match value.as_bytes() {
        b"shared_only_absence" => Ok(SuppressionReason::SharedOnlyAbsence),
        b"conflicting_evidence" => Ok(SuppressionReason::ConflictingEvidence),
        b"watch_paused" => Ok(SuppressionReason::WatchPaused),
        b"supporting_evidence_deleted" => Ok(SuppressionReason::SupportingEvidenceDeleted),
        _ => Err(MonitoringError::Unavailable),
    }
}

const fn delivery_state(value: &str) -> Result<NotificationDeliveryState, MonitoringError> {
    match value.as_bytes() {
        b"queued" => Ok(NotificationDeliveryState::Queued),
        b"delivering" => Ok(NotificationDeliveryState::Delivering),
        b"retry_scheduled" => Ok(NotificationDeliveryState::RetryScheduled),
        b"delivered" => Ok(NotificationDeliveryState::Delivered),
        b"permanently_failed" => Ok(NotificationDeliveryState::PermanentlyFailed),
        b"cancelled" => Ok(NotificationDeliveryState::Cancelled),
        _ => Err(MonitoringError::Unavailable),
    }
}

fn error_response(request_id: RequestId, error: MonitoringError) -> Response {
    match error {
        MonitoringError::InvalidRequest(field, code) => (
            StatusCode::BAD_REQUEST,
            Json(socialname_protocol::ApiErrorResponse::invalid_request(
                request_id,
                ValidationErrors::new(field, code),
            )),
        )
            .into_response(),
        MonitoringError::NotFound => crate::api_error_response(
            StatusCode::NOT_FOUND,
            request_id,
            standard_api_error(ApiErrorCode::NotFound, false),
        ),
        MonitoringError::Authentication(AuthenticationError::Forbidden) => {
            crate::api_error_response(
                StatusCode::FORBIDDEN,
                request_id,
                standard_api_error(ApiErrorCode::Forbidden, false),
            )
        }
        MonitoringError::Authentication(AuthenticationError::InvalidCredential) => {
            unauthenticated_response(request_id)
        }
        MonitoringError::Authentication(AuthenticationError::Unavailable)
        | MonitoringError::Unavailable => crate::api_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            request_id,
            standard_api_error(ApiErrorCode::Unavailable, true),
        ),
    }
}

#[derive(FromRow)]
struct StoredTransition {
    id: Uuid,
    transition_class: String,
    from_state: String,
    to_state: String,
    region_class: Option<String>,
    rule_hash: Option<String>,
    confirmation_status: String,
    confirmation_basis: Option<String>,
    pending_reason: Option<String>,
    suppression_reason: Option<String>,
    detected_at_unix_ms: i64,
    normalized_username: Option<String>,
    site_id: String,
}

#[derive(FromRow)]
struct StoredDelivery {
    id: Uuid,
    endpoint_id: Uuid,
    transition_id: Uuid,
    logical_notification_key: String,
    channel: String,
    confirmation_basis: String,
    state: String,
    attempt_count: i32,
    created_at_unix_ms: i64,
    next_attempt_at_unix_ms: Option<i64>,
    delivered_at_unix_ms: Option<i64>,
    last_error_code: Option<String>,
}

#[derive(Debug, thiserror::Error)]
enum MonitoringError {
    #[error("monitoring request is invalid")]
    InvalidRequest(&'static str, ValidationCode),
    #[error("monitoring resource was not found")]
    NotFound,
    #[error(transparent)]
    Authentication(#[from] AuthenticationError),
    #[error("monitoring storage is unavailable")]
    Unavailable,
}

impl MonitoringError {
    fn from_watch(error: WatchError) -> Self {
        match error {
            WatchError::NotFound => Self::NotFound,
            WatchError::Authentication(authentication) => Self::Authentication(authentication),
            _ => Self::Unavailable,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_bounds_and_cursor_errors_do_not_echo_values() {
        let private = "private-monitoring-cursor";
        let error = Uuid::parse_str(private)
            .map_err(|_| MonitoringError::InvalidRequest("after", ValidationCode::InvalidFormat))
            .unwrap_err();
        assert!(!error.to_string().contains(private));
        assert!(matches!(
            parse_page_query(Ok(Query(MonitoringPageQuery {
                limit: Some(51),
                after: None,
            }))),
            Err(MonitoringError::InvalidRequest(
                "limit",
                ValidationCode::OutOfRange
            ))
        ));
    }
}
