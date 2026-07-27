use axum::{
    Json,
    extract::{Extension, Query, State, rejection::QueryRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use socialname_protocol::{
    ApiErrorCode, ApiKeyScope, ChannelSlo, DELIVERY_SUCCESS_TARGET_BASIS_POINTS,
    DeletionDeadlineSlo, DeletionOverdueMilestones, LatencySlo, OperationalBacklog,
    OperationalObjectives, OperationalReportResource, OperationalReportWindow, ProtocolVersion,
    RatioSlo, RequestId, TRANSITION_TO_DELIVERY_P95_TARGET_MS, Validate, ValidationCode,
    ValidationErrors, WATCH_RUN_SUCCESS_TARGET_BASIS_POINTS,
};
use sqlx::{FromRow, PgPool};

use crate::{
    ServerState,
    auth::{self, AuthenticatedPrincipal, AuthenticationError},
    standard_api_error, unauthenticated_response,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OperationalReportQuery {
    window: Option<OperationalReportWindow>,
}

pub(crate) async fn operational_report(
    State(state): State<ServerState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    query: Result<Query<OperationalReportQuery>, QueryRejection>,
) -> Response {
    let window = match query {
        Ok(Query(query)) => query.window.unwrap_or(OperationalReportWindow::Last24Hours),
        Err(_) => {
            return error_response(
                request_id,
                OperationsError::InvalidRequest("query", ValidationCode::InvalidFormat),
            );
        }
    };
    match load_operational_report(&state.database, &principal, window).await {
        Ok(resource) => Json(resource).into_response(),
        Err(error) => error_response(request_id, error),
    }
}

async fn load_operational_report(
    pool: &PgPool,
    principal: &AuthenticatedPrincipal,
    window: OperationalReportWindow,
) -> Result<OperationalReportResource, OperationsError> {
    let mut transaction =
        auth::begin_authorized_transaction(pool, principal, ApiKeyScope::OperationsRead).await?;
    let row: StoredOperationalReport = sqlx::query_as(
        r#"
        WITH bounds AS MATERIALIZED (
            SELECT
                statement_timestamp() AS generated_at,
                statement_timestamp()
                    - ($2::bigint * interval '1 millisecond') AS window_started_at
        ),
        watch_counts AS (
            SELECT
                count(*) FILTER (WHERE watch.state = 'active') AS active_watches,
                count(*) FILTER (WHERE watch.state = 'paused') AS paused_watches,
                count(*) FILTER (WHERE watch.state = 'deleting') AS deleting_watches
            FROM watches AS watch
            WHERE watch.tenant_id = $1
        ),
        run_counts AS (
            SELECT
                count(*) FILTER (WHERE run.state = 'planned') AS planned_watch_runs,
                count(*) FILTER (WHERE run.state = 'running') AS running_watch_runs,
                count(*) FILTER (
                    WHERE run.state = 'completed'
                      AND run.created_at >= bounds.window_started_at
                      AND run.created_at < bounds.generated_at
                ) AS successful_watch_runs,
                count(*) FILTER (
                    WHERE run.state = 'failed'
                      AND run.created_at >= bounds.window_started_at
                      AND run.created_at < bounds.generated_at
                ) AS failed_watch_runs
            FROM watch_runs AS run
            CROSS JOIN bounds
            WHERE run.tenant_id = $1
        ),
        probe_counts AS (
            SELECT
                count(*) FILTER (WHERE job.state = 'queued') AS queued_probe_jobs,
                count(*) FILTER (WHERE job.state = 'leased') AS leased_probe_jobs,
                count(*) FILTER (WHERE job.state = 'retry_wait') AS retry_wait_probe_jobs,
                CASE
                    WHEN min(job.created_at) FILTER (
                        WHERE job.state IN ('queued', 'leased', 'retry_wait')
                    ) IS NULL THEN NULL
                    ELSE GREATEST(
                        0,
                        (
                            EXTRACT(EPOCH FROM (
                                bounds.generated_at
                                - min(job.created_at) FILTER (
                                    WHERE job.state IN ('queued', 'leased', 'retry_wait')
                                )
                            )) * 1000
                        )::bigint
                    )
                END AS oldest_pending_probe_job_age_ms
            FROM bounds
            LEFT JOIN probe_jobs AS job ON job.tenant_id = $1
            GROUP BY bounds.generated_at
        ),
        delivery_counts AS (
            SELECT
                count(*) FILTER (
                    WHERE endpoint.channel = 'email' AND delivery.state = 'queued'
                ) AS queued_email_deliveries,
                count(*) FILTER (
                    WHERE endpoint.channel = 'email' AND delivery.state = 'delivering'
                ) AS delivering_email_deliveries,
                count(*) FILTER (
                    WHERE endpoint.channel = 'email'
                      AND delivery.state = 'retry_scheduled'
                ) AS retry_scheduled_email_deliveries,
                count(*) FILTER (
                    WHERE endpoint.channel = 'webhook' AND delivery.state = 'queued'
                ) AS queued_webhook_deliveries,
                count(*) FILTER (
                    WHERE endpoint.channel = 'webhook' AND delivery.state = 'delivering'
                ) AS delivering_webhook_deliveries,
                count(*) FILTER (
                    WHERE endpoint.channel = 'webhook'
                      AND delivery.state = 'retry_scheduled'
                ) AS retry_scheduled_webhook_deliveries,
                CASE
                    WHEN min(delivery.created_at) FILTER (
                        WHERE delivery.state IN ('queued', 'delivering', 'retry_scheduled')
                    ) IS NULL THEN NULL
                    ELSE GREATEST(
                        0,
                        (
                            EXTRACT(EPOCH FROM (
                                bounds.generated_at
                                - min(delivery.created_at) FILTER (
                                    WHERE delivery.state
                                        IN ('queued', 'delivering', 'retry_scheduled')
                                )
                            )) * 1000
                        )::bigint
                    )
                END AS oldest_pending_delivery_age_ms,
                count(*) FILTER (
                    WHERE endpoint.channel = 'email'
                      AND delivery.state = 'delivered'
                      AND delivery.created_at >= bounds.window_started_at
                      AND delivery.created_at < bounds.generated_at
                ) AS successful_email_deliveries,
                count(*) FILTER (
                    WHERE endpoint.channel = 'email'
                      AND delivery.state = 'permanently_failed'
                      AND delivery.created_at >= bounds.window_started_at
                      AND delivery.created_at < bounds.generated_at
                ) AS failed_email_deliveries,
                count(*) FILTER (
                    WHERE endpoint.channel = 'webhook'
                      AND delivery.state = 'delivered'
                      AND delivery.created_at >= bounds.window_started_at
                      AND delivery.created_at < bounds.generated_at
                ) AS successful_webhook_deliveries,
                count(*) FILTER (
                    WHERE endpoint.channel = 'webhook'
                      AND delivery.state = 'permanently_failed'
                      AND delivery.created_at >= bounds.window_started_at
                      AND delivery.created_at < bounds.generated_at
                ) AS failed_webhook_deliveries,
                count(*) FILTER (
                    WHERE endpoint.channel = 'email'
                      AND delivery.state = 'delivered'
                      AND delivery.created_at >= bounds.window_started_at
                      AND delivery.created_at < bounds.generated_at
                ) AS email_latency_samples,
                percentile_disc(0.95) WITHIN GROUP (
                    ORDER BY (
                        EXTRACT(EPOCH FROM (
                            delivery.delivered_at - transition.detected_at
                        )) * 1000
                    )::bigint
                ) FILTER (
                    WHERE endpoint.channel = 'email'
                      AND delivery.state = 'delivered'
                      AND delivery.created_at >= bounds.window_started_at
                      AND delivery.created_at < bounds.generated_at
                ) AS email_latency_p95_ms,
                count(*) FILTER (
                    WHERE endpoint.channel = 'webhook'
                      AND delivery.state = 'delivered'
                      AND delivery.created_at >= bounds.window_started_at
                      AND delivery.created_at < bounds.generated_at
                ) AS webhook_latency_samples,
                percentile_disc(0.95) WITHIN GROUP (
                    ORDER BY (
                        EXTRACT(EPOCH FROM (
                            delivery.delivered_at - transition.detected_at
                        )) * 1000
                    )::bigint
                ) FILTER (
                    WHERE endpoint.channel = 'webhook'
                      AND delivery.state = 'delivered'
                      AND delivery.created_at >= bounds.window_started_at
                      AND delivery.created_at < bounds.generated_at
                ) AS webhook_latency_p95_ms
            FROM bounds
            LEFT JOIN notification_deliveries AS delivery
              ON delivery.tenant_id = $1
            LEFT JOIN notification_endpoints AS endpoint
              ON endpoint.tenant_id = delivery.tenant_id
             AND endpoint.id = delivery.endpoint_id
            LEFT JOIN transitions AS transition
              ON transition.tenant_id = delivery.tenant_id
             AND transition.id = delivery.transition_id
            GROUP BY bounds.generated_at, bounds.window_started_at
        ),
        deletion_counts AS (
            SELECT
                count(*) FILTER (
                    WHERE request.state <> 'completed'
                ) AS open_deletion_requests,
                count(*) FILTER (
                    WHERE request.state = 'failed'
                ) AS failed_deletion_requests,
                count(*) FILTER (
                    WHERE request.state <> 'completed'
                      AND request.hide_by < bounds.generated_at
                      AND request.state = 'accepted'
                ) AS overdue_hide,
                count(*) FILTER (
                    WHERE request.state <> 'completed'
                      AND request.support_withdrawal_by < bounds.generated_at
                      AND request.support_withdrawn_at IS NULL
                ) AS overdue_support_withdrawal,
                count(*) FILTER (
                    WHERE request.state <> 'completed'
                      AND request.primary_delete_by < bounds.generated_at
                      AND request.primary_completed_at IS NULL
                ) AS overdue_primary_delete,
                count(*) FILTER (
                    WHERE request.state <> 'completed'
                      AND request.derived_rebuild_by < bounds.generated_at
                      AND NOT EXISTS (
                          SELECT 1
                          FROM deletion_tasks AS task
                          WHERE task.tenant_id = request.tenant_id
                            AND task.deletion_request_id = request.id
                            AND task.store_kind = 'analytics'
                            AND task.state = 'completed'
                      )
                ) AS overdue_derived_rebuild,
                count(*) FILTER (
                    WHERE request.state <> 'completed'
                      AND request.backup_expiry_by < bounds.generated_at
                ) AS overdue_backup_expiry
            FROM bounds
            LEFT JOIN deletion_requests AS request ON request.tenant_id = $1
            GROUP BY bounds.generated_at
        )
        SELECT
            (EXTRACT(EPOCH FROM bounds.generated_at) * 1000)::bigint
                AS generated_at_unix_ms,
            (EXTRACT(EPOCH FROM bounds.window_started_at) * 1000)::bigint
                AS window_started_at_unix_ms,
            watch_counts.*,
            run_counts.*,
            probe_counts.*,
            delivery_counts.*,
            deletion_counts.*
        FROM bounds
        CROSS JOIN watch_counts
        CROSS JOIN run_counts
        CROSS JOIN probe_counts
        CROSS JOIN delivery_counts
        CROSS JOIN deletion_counts
        "#,
    )
    .bind(principal.workspace_id)
    .bind(window.duration_ms())
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| OperationsError::Unavailable)?;

    let report = protocol_report(window, row)?;
    report
        .validate()
        .map_err(|_| OperationsError::Unavailable)?;
    transaction
        .commit()
        .await
        .map_err(|_| OperationsError::Unavailable)?;
    Ok(report)
}

fn protocol_report(
    window: OperationalReportWindow,
    row: StoredOperationalReport,
) -> Result<OperationalReportResource, OperationsError> {
    let successful_watch_runs = count(row.successful_watch_runs)?;
    let failed_watch_runs = count(row.failed_watch_runs)?;
    let successful_email_deliveries = count(row.successful_email_deliveries)?;
    let failed_email_deliveries = count(row.failed_email_deliveries)?;
    let successful_webhook_deliveries = count(row.successful_webhook_deliveries)?;
    let failed_webhook_deliveries = count(row.failed_webhook_deliveries)?;
    let overdue = DeletionOverdueMilestones {
        hide: count(row.overdue_hide)?,
        support_withdrawal: count(row.overdue_support_withdrawal)?,
        primary_delete: count(row.overdue_primary_delete)?,
        derived_rebuild: count(row.overdue_derived_rebuild)?,
        backup_expiry: count(row.overdue_backup_expiry)?,
    };
    Ok(OperationalReportResource {
        schema: ProtocolVersion::ApiV1,
        window,
        generated_at_unix_ms: row.generated_at_unix_ms,
        window_started_at_unix_ms: row.window_started_at_unix_ms,
        backlog: OperationalBacklog {
            active_watches: count(row.active_watches)?,
            paused_watches: count(row.paused_watches)?,
            deleting_watches: count(row.deleting_watches)?,
            planned_watch_runs: count(row.planned_watch_runs)?,
            running_watch_runs: count(row.running_watch_runs)?,
            queued_probe_jobs: count(row.queued_probe_jobs)?,
            leased_probe_jobs: count(row.leased_probe_jobs)?,
            retry_wait_probe_jobs: count(row.retry_wait_probe_jobs)?,
            oldest_pending_probe_job_age_ms: optional_count(row.oldest_pending_probe_job_age_ms)?,
            queued_email_deliveries: count(row.queued_email_deliveries)?,
            delivering_email_deliveries: count(row.delivering_email_deliveries)?,
            retry_scheduled_email_deliveries: count(row.retry_scheduled_email_deliveries)?,
            queued_webhook_deliveries: count(row.queued_webhook_deliveries)?,
            delivering_webhook_deliveries: count(row.delivering_webhook_deliveries)?,
            retry_scheduled_webhook_deliveries: count(row.retry_scheduled_webhook_deliveries)?,
            oldest_pending_delivery_age_ms: optional_count(row.oldest_pending_delivery_age_ms)?,
        },
        objectives: OperationalObjectives {
            watch_run_success: RatioSlo::from_counts(
                successful_watch_runs,
                successful_watch_runs + failed_watch_runs,
                WATCH_RUN_SUCCESS_TARGET_BASIS_POINTS,
            ),
            delivery_success: ChannelSlo {
                email: RatioSlo::from_counts(
                    successful_email_deliveries,
                    successful_email_deliveries + failed_email_deliveries,
                    DELIVERY_SUCCESS_TARGET_BASIS_POINTS,
                ),
                webhook: RatioSlo::from_counts(
                    successful_webhook_deliveries,
                    successful_webhook_deliveries + failed_webhook_deliveries,
                    DELIVERY_SUCCESS_TARGET_BASIS_POINTS,
                ),
            },
            transition_to_delivery_latency: ChannelSlo {
                email: LatencySlo::from_samples(
                    count(row.email_latency_samples)?,
                    optional_count(row.email_latency_p95_ms)?,
                    TRANSITION_TO_DELIVERY_P95_TARGET_MS,
                ),
                webhook: LatencySlo::from_samples(
                    count(row.webhook_latency_samples)?,
                    optional_count(row.webhook_latency_p95_ms)?,
                    TRANSITION_TO_DELIVERY_P95_TARGET_MS,
                ),
            },
            deletion_deadline_health: DeletionDeadlineSlo::from_counts(
                count(row.open_deletion_requests)?,
                count(row.failed_deletion_requests)?,
                overdue,
            ),
        },
    })
}

fn count(value: i64) -> Result<u64, OperationsError> {
    u64::try_from(value).map_err(|_| OperationsError::Unavailable)
}

fn optional_count(value: Option<i64>) -> Result<Option<u64>, OperationsError> {
    value.map(count).transpose()
}

fn error_response(request_id: RequestId, error: OperationsError) -> Response {
    match error {
        OperationsError::InvalidRequest(field, code) => (
            StatusCode::BAD_REQUEST,
            Json(socialname_protocol::ApiErrorResponse::invalid_request(
                request_id,
                ValidationErrors::new(field, code),
            )),
        )
            .into_response(),
        OperationsError::Authentication(AuthenticationError::Forbidden) => {
            crate::api_error_response(
                StatusCode::FORBIDDEN,
                request_id,
                standard_api_error(ApiErrorCode::Forbidden, false),
            )
        }
        OperationsError::Authentication(AuthenticationError::InvalidCredential) => {
            unauthenticated_response(request_id)
        }
        OperationsError::Authentication(AuthenticationError::Unavailable)
        | OperationsError::Unavailable => crate::api_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            request_id,
            standard_api_error(ApiErrorCode::Unavailable, true),
        ),
    }
}

#[derive(FromRow)]
struct StoredOperationalReport {
    generated_at_unix_ms: i64,
    window_started_at_unix_ms: i64,
    active_watches: i64,
    paused_watches: i64,
    deleting_watches: i64,
    planned_watch_runs: i64,
    running_watch_runs: i64,
    successful_watch_runs: i64,
    failed_watch_runs: i64,
    queued_probe_jobs: i64,
    leased_probe_jobs: i64,
    retry_wait_probe_jobs: i64,
    oldest_pending_probe_job_age_ms: Option<i64>,
    queued_email_deliveries: i64,
    delivering_email_deliveries: i64,
    retry_scheduled_email_deliveries: i64,
    queued_webhook_deliveries: i64,
    delivering_webhook_deliveries: i64,
    retry_scheduled_webhook_deliveries: i64,
    oldest_pending_delivery_age_ms: Option<i64>,
    successful_email_deliveries: i64,
    failed_email_deliveries: i64,
    successful_webhook_deliveries: i64,
    failed_webhook_deliveries: i64,
    email_latency_samples: i64,
    email_latency_p95_ms: Option<i64>,
    webhook_latency_samples: i64,
    webhook_latency_p95_ms: Option<i64>,
    open_deletion_requests: i64,
    failed_deletion_requests: i64,
    overdue_hide: i64,
    overdue_support_withdrawal: i64,
    overdue_primary_delete: i64,
    overdue_derived_rebuild: i64,
    overdue_backup_expiry: i64,
}

#[derive(Debug, thiserror::Error)]
enum OperationsError {
    #[error("operational report request is invalid")]
    InvalidRequest(&'static str, ValidationCode),
    #[error(transparent)]
    Authentication(#[from] AuthenticationError),
    #[error("operational report is unavailable")]
    Unavailable,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_query_error_omits_supplied_value() {
        let private = "private-window";
        let error = OperationsError::InvalidRequest("query", ValidationCode::InvalidFormat);
        assert!(!error.to_string().contains(private));
    }
}
