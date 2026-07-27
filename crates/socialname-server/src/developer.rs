use axum::{
    Json,
    extract::{Extension, Query, State, rejection::QueryRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use socialname_protocol::{
    ApiErrorCode, ApiKeyScope, DEVELOPER_FIRST_RESULT_P95_TARGET_MS,
    DEVELOPER_SEARCH_SUCCESS_TARGET_BASIS_POINTS, DEVELOPER_TERMINAL_P95_TARGET_MS,
    DeveloperQuotaCounter, DeveloperQuotaSnapshot, DeveloperReportResource, DeveloperReportWindow,
    DeveloperSearchBacklog, DeveloperServiceObjectives, DeveloperUsageSummary, LatencySlo,
    ProtocolVersion, RatioSlo, RequestId, Validate, ValidationCode, ValidationErrors,
};
use sqlx::{FromRow, PgPool};

use crate::{
    ServerState,
    auth::{self, AuthenticatedPrincipal, AuthenticationError},
    standard_api_error, unauthenticated_response,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeveloperReportQuery {
    window: Option<DeveloperReportWindow>,
}

pub(crate) async fn developer_report(
    State(state): State<ServerState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    query: Result<Query<DeveloperReportQuery>, QueryRejection>,
) -> Response {
    let window = match query {
        Ok(Query(query)) => query.window.unwrap_or(DeveloperReportWindow::Last24Hours),
        Err(_) => {
            return error_response(
                request_id,
                DeveloperError::InvalidRequest("query", ValidationCode::InvalidFormat),
            );
        }
    };
    match load_developer_report(&state.database, &principal, window).await {
        Ok(resource) => Json(resource).into_response(),
        Err(error) => error_response(request_id, error),
    }
}

async fn load_developer_report(
    pool: &PgPool,
    principal: &AuthenticatedPrincipal,
    window: DeveloperReportWindow,
) -> Result<DeveloperReportResource, DeveloperError> {
    let mut transaction =
        auth::begin_authorized_transaction(pool, principal, ApiKeyScope::UsageRead).await?;
    let row: StoredDeveloperReport = sqlx::query_as(
        r#"
        WITH bounds AS MATERIALIZED (
            SELECT
                statement_timestamp() AS generated_at,
                statement_timestamp()
                    - ($3::bigint * interval '1 millisecond') AS window_started_at,
                date_trunc('day', statement_timestamp() AT TIME ZONE 'UTC')
                    AT TIME ZONE 'UTC' AS quota_started_at
        ),
        quota AS (
            SELECT
                policy.daily_target_limit::bigint AS tenant_limit,
                policy.api_key_daily_target_limit::bigint AS api_key_limit
            FROM developer_quota_policies AS policy
            WHERE policy.tenant_id = $1
        ),
        current_usage AS (
            SELECT
                COALESCE(sum(usage.quantity), 0)::bigint AS tenant_used,
                COALESCE(sum(usage.quantity) FILTER (
                    WHERE usage.api_key_id = $2
                ), 0)::bigint AS api_key_used
            FROM bounds
            LEFT JOIN developer_usage_records AS usage
              ON usage.tenant_id = $1
             AND usage.occurred_at >= bounds.quota_started_at
             AND usage.occurred_at < bounds.generated_at
             AND usage.retained_until > bounds.generated_at
        ),
        window_usage AS (
            SELECT
                count(usage.id)::bigint AS admitted_searches,
                COALESCE(sum(usage.quantity), 0)::bigint AS admitted_target_pairs
            FROM bounds
            LEFT JOIN developer_usage_records AS usage
              ON usage.tenant_id = $1
             AND usage.occurred_at >= bounds.window_started_at
             AND usage.occurred_at < bounds.generated_at
             AND usage.retained_until > bounds.generated_at
        ),
        backlog AS (
            SELECT
                count(*) FILTER (
                    WHERE search.state = 'accepted'
                ) AS accepted_searches,
                count(*) FILTER (
                    WHERE search.state = 'running'
                ) AS running_searches,
                count(*) FILTER (
                    WHERE search.state IN ('accepted', 'running')
                      AND NOT EXISTS (
                          SELECT 1
                          FROM search_events AS event
                          WHERE event.tenant_id = search.tenant_id
                            AND event.search_id = search.id
                            AND event.event_type IN (
                                'definitive_result',
                                'uncertain_result',
                                'operational_failure'
                            )
                      )
                ) AS active_searches_without_result,
                CASE
                    WHEN min(search.created_at) FILTER (
                        WHERE search.state IN ('accepted', 'running')
                    ) IS NULL THEN NULL
                    ELSE GREATEST(
                        0,
                        (
                            EXTRACT(EPOCH FROM (
                                bounds.generated_at
                                - min(search.created_at) FILTER (
                                    WHERE search.state IN ('accepted', 'running')
                                )
                            )) * 1000
                        )::bigint
                    )
                END AS oldest_active_search_age_ms
            FROM bounds
            LEFT JOIN searches AS search ON search.tenant_id = $1
            GROUP BY bounds.generated_at
        ),
        terminal AS (
            SELECT
                count(*) FILTER (
                    WHERE search.state = 'completed'
                      AND search.created_at >= bounds.window_started_at
                      AND search.created_at < bounds.generated_at
                ) AS successful_searches,
                count(*) FILTER (
                    WHERE search.state = 'failed'
                      AND search.created_at >= bounds.window_started_at
                      AND search.created_at < bounds.generated_at
                ) AS failed_searches,
                count(*) FILTER (
                    WHERE search.state IN ('completed', 'failed')
                      AND search.created_at >= bounds.window_started_at
                      AND search.created_at < bounds.generated_at
                ) AS terminal_latency_samples,
                percentile_disc(0.95) WITHIN GROUP (
                    ORDER BY GREATEST(
                        0,
                        (
                            EXTRACT(EPOCH FROM (
                                search.completed_at - search.created_at
                            )) * 1000
                        )::bigint
                    )
                ) FILTER (
                    WHERE search.state IN ('completed', 'failed')
                      AND search.created_at >= bounds.window_started_at
                      AND search.created_at < bounds.generated_at
                ) AS terminal_latency_p95_ms
            FROM bounds
            LEFT JOIN searches AS search ON search.tenant_id = $1
            GROUP BY bounds.generated_at, bounds.window_started_at
        ),
        first_result_per_search AS (
            SELECT
                search.id,
                GREATEST(
                    0,
                    (
                        EXTRACT(EPOCH FROM (
                            min(event.emitted_at) - search.created_at
                        )) * 1000
                    )::bigint
                ) AS first_result_latency_ms
            FROM bounds
            JOIN searches AS search
              ON search.tenant_id = $1
             AND search.created_at >= bounds.window_started_at
             AND search.created_at < bounds.generated_at
            JOIN search_events AS event
              ON event.tenant_id = search.tenant_id
             AND event.search_id = search.id
             AND event.event_type IN (
                'definitive_result',
                'uncertain_result',
                'operational_failure'
             )
            GROUP BY search.id, search.created_at
        ),
        first_result AS (
            SELECT
                count(*)::bigint AS first_result_latency_samples,
                percentile_disc(0.95) WITHIN GROUP (
                    ORDER BY first_result_latency_ms
                )::bigint AS first_result_latency_p95_ms
            FROM first_result_per_search
        )
        SELECT
            (EXTRACT(EPOCH FROM bounds.generated_at) * 1000)::bigint
                AS generated_at_unix_ms,
            (EXTRACT(EPOCH FROM bounds.window_started_at) * 1000)::bigint
                AS window_started_at_unix_ms,
            (EXTRACT(EPOCH FROM bounds.quota_started_at) * 1000)::bigint
                AS quota_started_at_unix_ms,
            (
                EXTRACT(EPOCH FROM (
                    bounds.quota_started_at + interval '1 day'
                )) * 1000
            )::bigint AS quota_resets_at_unix_ms,
            quota.*,
            current_usage.*,
            window_usage.*,
            backlog.*,
            terminal.*,
            first_result.*
        FROM bounds
        CROSS JOIN quota
        CROSS JOIN current_usage
        CROSS JOIN window_usage
        CROSS JOIN backlog
        CROSS JOIN terminal
        CROSS JOIN first_result
        "#,
    )
    .bind(principal.workspace_id)
    .bind(principal.api_key_id)
    .bind(window.duration_ms())
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| DeveloperError::Unavailable)?;

    let report = protocol_report(window, row)?;
    report.validate().map_err(|_| DeveloperError::Unavailable)?;
    transaction
        .commit()
        .await
        .map_err(|_| DeveloperError::Unavailable)?;
    Ok(report)
}

fn protocol_report(
    window: DeveloperReportWindow,
    row: StoredDeveloperReport,
) -> Result<DeveloperReportResource, DeveloperError> {
    let tenant_limit = count(row.tenant_limit)?;
    let tenant_used = count(row.tenant_used)?;
    let api_key_limit = count(row.api_key_limit)?;
    let api_key_used = count(row.api_key_used)?;
    let successful_searches = count(row.successful_searches)?;
    let failed_searches = count(row.failed_searches)?;
    Ok(DeveloperReportResource {
        schema: ProtocolVersion::ApiV1,
        window,
        generated_at_unix_ms: row.generated_at_unix_ms,
        window_started_at_unix_ms: row.window_started_at_unix_ms,
        quota: DeveloperQuotaSnapshot {
            period_started_at_unix_ms: row.quota_started_at_unix_ms,
            resets_at_unix_ms: row.quota_resets_at_unix_ms,
            tenant: quota_counter(tenant_limit, tenant_used)?,
            api_key: quota_counter(api_key_limit, api_key_used)?,
        },
        usage: DeveloperUsageSummary {
            admitted_searches: count(row.admitted_searches)?,
            admitted_target_pairs: count(row.admitted_target_pairs)?,
        },
        backlog: DeveloperSearchBacklog {
            accepted_searches: count(row.accepted_searches)?,
            running_searches: count(row.running_searches)?,
            active_searches_without_result: count(row.active_searches_without_result)?,
            oldest_active_search_age_ms: optional_count(row.oldest_active_search_age_ms)?,
        },
        objectives: DeveloperServiceObjectives {
            terminal_search_success: RatioSlo::from_counts(
                successful_searches,
                successful_searches
                    .checked_add(failed_searches)
                    .ok_or(DeveloperError::Unavailable)?,
                DEVELOPER_SEARCH_SUCCESS_TARGET_BASIS_POINTS,
            ),
            first_result_latency: LatencySlo::from_samples(
                count(row.first_result_latency_samples)?,
                optional_count(row.first_result_latency_p95_ms)?,
                DEVELOPER_FIRST_RESULT_P95_TARGET_MS,
            ),
            terminal_latency: LatencySlo::from_samples(
                count(row.terminal_latency_samples)?,
                optional_count(row.terminal_latency_p95_ms)?,
                DEVELOPER_TERMINAL_P95_TARGET_MS,
            ),
        },
    })
}

fn quota_counter(limit: u64, used: u64) -> Result<DeveloperQuotaCounter, DeveloperError> {
    Ok(DeveloperQuotaCounter {
        limit,
        used,
        remaining: limit.checked_sub(used).ok_or(DeveloperError::Unavailable)?,
    })
}

fn count(value: i64) -> Result<u64, DeveloperError> {
    u64::try_from(value).map_err(|_| DeveloperError::Unavailable)
}

fn optional_count(value: Option<i64>) -> Result<Option<u64>, DeveloperError> {
    value.map(count).transpose()
}

fn error_response(request_id: RequestId, error: DeveloperError) -> Response {
    match error {
        DeveloperError::InvalidRequest(field, code) => (
            StatusCode::BAD_REQUEST,
            Json(socialname_protocol::ApiErrorResponse::invalid_request(
                request_id,
                ValidationErrors::new(field, code),
            )),
        )
            .into_response(),
        DeveloperError::Authentication(AuthenticationError::Forbidden) => {
            crate::api_error_response(
                StatusCode::FORBIDDEN,
                request_id,
                standard_api_error(ApiErrorCode::Forbidden, false),
            )
        }
        DeveloperError::Authentication(AuthenticationError::InvalidCredential) => {
            unauthenticated_response(request_id)
        }
        DeveloperError::Authentication(AuthenticationError::Unavailable)
        | DeveloperError::Unavailable => crate::api_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            request_id,
            standard_api_error(ApiErrorCode::Unavailable, true),
        ),
    }
}

#[derive(FromRow)]
struct StoredDeveloperReport {
    generated_at_unix_ms: i64,
    window_started_at_unix_ms: i64,
    quota_started_at_unix_ms: i64,
    quota_resets_at_unix_ms: i64,
    tenant_limit: i64,
    api_key_limit: i64,
    tenant_used: i64,
    api_key_used: i64,
    admitted_searches: i64,
    admitted_target_pairs: i64,
    accepted_searches: i64,
    running_searches: i64,
    active_searches_without_result: i64,
    oldest_active_search_age_ms: Option<i64>,
    successful_searches: i64,
    failed_searches: i64,
    terminal_latency_samples: i64,
    terminal_latency_p95_ms: Option<i64>,
    first_result_latency_samples: i64,
    first_result_latency_p95_ms: Option<i64>,
}

#[derive(Debug, thiserror::Error)]
enum DeveloperError {
    #[error("developer report request is invalid")]
    InvalidRequest(&'static str, ValidationCode),
    #[error(transparent)]
    Authentication(#[from] AuthenticationError),
    #[error("developer report is unavailable")]
    Unavailable,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_query_error_omits_supplied_value() {
        let private = "private-window";
        let error = DeveloperError::InvalidRequest("query", ValidationCode::InvalidFormat);
        assert!(!error.to_string().contains(private));
    }

    #[test]
    fn quota_counter_rejects_overuse_instead_of_wrapping() {
        assert!(quota_counter(1, 2).is_err());
    }
}
