use axum::{
    Json,
    extract::{
        Extension, Path, Query, State,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{HeaderValue, StatusCode, header::LOCATION},
    response::{IntoResponse, Response},
};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use socialname_protocol::{
    ApiError, ApiErrorCode, ApiKeyScope, ContributionHistoryReason, ContributionId,
    ContributionInfluenceScope, ContributionNetworkClass, ContributorReputationTier, EvidenceClass,
    EvidenceDigest, EvidenceOutcome, MAX_CONTRIBUTION_PAGE_ITEMS, ProtocolVersion, RegionClass,
    RequestId, RuleHash, SharedContributionPage, SharedContributionResource,
    SharedContributionSchema, SharedContributionSubmitRequest, SiteId, Target, Username, Validate,
    ValidationCode, ValidationErrors,
};
use socialname_rule_compiler::{CompiledSiteRule, RuleCompiler};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    ServerState,
    auth::{self, AuthenticatedPrincipal, AuthenticationError},
    standard_api_error, unauthenticated_response,
};

type HmacSha256 = Hmac<Sha256>;

const DEFAULT_PAGE_ITEMS: usize = 20;
/// Initial calibration parameters for the software quota guardrail. They bound
/// accepted contributions per UTC day and are deliberately conservative until
/// live calibration evidence exists.
const TENANT_DAILY_ACCEPT_LIMIT: i32 = 5_000;
const INSTALLATION_DAILY_ACCEPT_LIMIT: i32 = 1_000;
/// A shared upload may influence the current state only when it arrives within
/// fifteen minutes of its observation; up to 24 hours it is history only.
const CURRENT_INFLUENCE_WINDOW_MS: i64 = 15 * 60 * 1_000;
const HISTORY_RETENTION_WINDOW_MS: i64 = 24 * 60 * 60 * 1_000;
const MAX_FUTURE_CLOCK_SKEW_MS: i64 = 5 * 60 * 1_000;
/// Repeated replay violations suspend the installation's site-family
/// reputation; fabricated probe-plan evidence suspends immediately.
const REPLAY_SUSPENSION_THRESHOLD: i64 = 3;
const FOUND_TTL_MS: i64 = 24 * 60 * 60 * 1_000;
const NOT_FOUND_TTL_MS: i64 = 15 * 60 * 1_000;
const UNCERTAIN_TTL_MS: i64 = 5 * 60 * 1_000;
const WEEK_MS: i64 = 7 * 24 * 60 * 60 * 1_000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ContributionPageQuery {
    limit: Option<u16>,
    after: Option<String>,
}

pub(crate) async fn create_shared_contribution(
    State(state): State<ServerState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    payload: Result<Json<SharedContributionSubmitRequest>, JsonRejection>,
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
        return error_response(request_id, ContributionError::Unavailable);
    };
    match persist_contribution(
        &state.database,
        &principal,
        &request,
        suppression_key.expose(),
    )
    .await
    {
        Ok(SubmitOutcome { resource, replayed }) => {
            let location = format!(
                "/v1/shared-contributions/{}",
                resource.contribution_id.as_str()
            );
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

pub(crate) async fn get_shared_contribution(
    State(state): State<ServerState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Path(contribution_id): Path<String>,
) -> Response {
    let contribution_id = match Uuid::parse_str(&contribution_id) {
        Ok(value) => value,
        Err(_) => {
            return error_response(
                request_id,
                ContributionError::InvalidRequest("contribution_id", ValidationCode::InvalidFormat),
            );
        }
    };
    match load_contribution(&state.database, &principal, contribution_id).await {
        Ok(resource) => Json(resource).into_response(),
        Err(error) => error_response(request_id, error),
    }
}

pub(crate) async fn list_shared_contributions(
    State(state): State<ServerState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    query: Result<Query<ContributionPageQuery>, QueryRejection>,
) -> Response {
    let page = match parse_page_query(query) {
        Ok(page) => page,
        Err(error) => return error_response(request_id, error),
    };
    match load_contribution_page(&state.database, &principal, page).await {
        Ok(resource) => Json(resource).into_response(),
        Err(error) => error_response(request_id, error),
    }
}

struct SubmitOutcome {
    resource: SharedContributionResource,
    replayed: bool,
}

async fn persist_contribution(
    pool: &PgPool,
    principal: &AuthenticatedPrincipal,
    request: &SharedContributionSubmitRequest,
    suppression_key: &[u8; 32],
) -> Result<SubmitOutcome, ContributionError> {
    let mut transaction =
        auth::begin_authorized_transaction(pool, principal, ApiKeyScope::ContributionWrite).await?;
    let now_unix_ms: i64 =
        sqlx::query_scalar("SELECT (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| ContributionError::Unavailable)?;

    // Freshness and clock-skew admission windows are target-free and cheap.
    if request.observed_at_unix_ms > now_unix_ms.saturating_add(MAX_FUTURE_CLOCK_SKEW_MS) {
        return Err(ContributionError::InvalidRequest(
            "observed_at_unix_ms",
            ValidationCode::OutOfRange,
        ));
    }
    let upload_age_ms = now_unix_ms.saturating_sub(request.observed_at_unix_ms);
    if upload_age_ms > HISTORY_RETENTION_WINDOW_MS {
        return Err(ContributionError::InvalidRequest(
            "observed_at_unix_ms",
            ValidationCode::OutOfRange,
        ));
    }

    let context = admit_subject_and_rule(&mut transaction, principal, request, now_unix_ms).await?;

    // Replay control: the per-installation sequence lock serializes concurrent
    // submissions, exact replay converges, and regression is a counted
    // violation that persists even though the submission is rejected.
    match check_replay(&mut transaction, principal, request, &context).await? {
        ReplayDecision::Fresh => {}
        ReplayDecision::ExactReplay(existing_id) => {
            let resource = load_owned_resource(&mut transaction, principal, existing_id)
                .await?
                .ok_or(ContributionError::Unavailable)?;
            transaction
                .commit()
                .await
                .map_err(|_| ContributionError::Unavailable)?;
            return Ok(SubmitOutcome {
                resource,
                replayed: true,
            });
        }
        ReplayDecision::Violation => {
            let suspended = record_replay_violation(&mut transaction, principal, &context).await?;
            transaction
                .commit()
                .await
                .map_err(|_| ContributionError::Unavailable)?;
            return Err(if suspended {
                ContributionError::Forbidden
            } else {
                ContributionError::Conflict
            });
        }
    }

    // Anomaly control: submitted probes must agree with the compiled probe
    // plan. Fabricated plan evidence suspends the site-family reputation
    // immediately and the suspension is committed despite the rejection.
    if !probes_agree_with_plan(request, &context.compiled) {
        suspend_reputation(
            &mut transaction,
            principal,
            &context,
            "fabricated_plan_evidence",
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| ContributionError::Unavailable)?;
        return Err(ContributionError::Forbidden);
    }

    // Deletion suppression is fail-closed: an active token from a different
    // key fingerprint refuses ingestion rather than forgetting the erasure.
    let key_fingerprint = crate::deletion::suppression_key_fingerprint(suppression_key)
        .ok_or(ContributionError::Unavailable)?;
    let target_token = crate::deletion::target_suppression_token(
        suppression_key,
        principal.workspace_id,
        request.target.site_id.as_str(),
        &context.normalized_username,
    )
    .ok_or(ContributionError::Unavailable)?;
    let (incompatible_key_exists, suppressed): (bool, bool) = sqlx::query_as(
        "SELECT \
            EXISTS (\
                SELECT 1 FROM suppression_tokens \
                WHERE tenant_id = $1 \
                  AND purpose = 'target_reingestion' \
                  AND expires_at > clock_timestamp() \
                  AND key_fingerprint IS DISTINCT FROM $3\
            ), \
            EXISTS (\
                SELECT 1 FROM suppression_tokens \
                WHERE tenant_id = $1 \
                  AND purpose = 'target_reingestion' \
                  AND token_hmac = $2 \
                  AND key_fingerprint = $3 \
                  AND expires_at > clock_timestamp()\
            )",
    )
    .bind(principal.workspace_id)
    .bind(target_token.as_slice())
    .bind(key_fingerprint.as_slice())
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| ContributionError::Unavailable)?;
    if incompatible_key_exists {
        return Err(ContributionError::Unavailable);
    }
    if suppressed {
        return Err(ContributionError::Conflict);
    }

    // Quota control: both counters increment atomically; exceeding either
    // limit rolls the whole submission back without recording the target.
    enforce_quota(&mut transaction, principal, &context).await?;

    let contribution_id = insert_contribution(
        &mut transaction,
        principal,
        request,
        &context,
        suppression_key,
    )
    .await?;
    record_acceptance_activity(&mut transaction, principal, &context).await?;

    let resource = load_owned_resource(&mut transaction, principal, contribution_id)
        .await?
        .ok_or(ContributionError::Unavailable)?;
    transaction
        .commit()
        .await
        .map_err(|_| ContributionError::Unavailable)?;
    Ok(SubmitOutcome {
        resource,
        replayed: false,
    })
}

struct AdmittedContext {
    now_unix_ms: i64,
    upload_age_ms: i64,
    client_id: Uuid,
    rule_version_id: Uuid,
    normalized_username: String,
    reputation_id: Uuid,
    compiled: CompiledSiteRule,
}

async fn admit_subject_and_rule(
    transaction: &mut Transaction<'_, Postgres>,
    principal: &AuthenticatedPrincipal,
    request: &SharedContributionSubmitRequest,
    now_unix_ms: i64,
) -> Result<AdmittedContext, ContributionError> {
    // The installation must already exist with an active shared-observation
    // grant that covers both the observation time and the submission time.
    let installation_hash = crate::consent::installation_hash(
        principal.workspace_id,
        request.installation_id.as_str().as_bytes(),
    );
    let client_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT client.id \
         FROM clients AS client \
         JOIN consent_grants AS consent \
           ON consent.tenant_id = client.tenant_id \
          AND consent.client_id = client.id \
         WHERE client.tenant_id = $1 \
           AND client.installation_hash = $2 \
           AND client.state = 'active' \
           AND consent.id = $3 \
           AND consent.subject_kind = 'installation' \
           AND consent.purpose = 'shared_observation' \
           AND consent.withdrawn_at IS NULL \
           AND consent.granted_at <= to_timestamp($4::double precision / 1000.0) \
           AND consent.granted_at <= clock_timestamp() \
           AND (consent.expires_at IS NULL OR consent.expires_at > clock_timestamp())",
    )
    .bind(principal.workspace_id)
    .bind(&installation_hash[..])
    .bind(
        Uuid::parse_str(request.consent_grant_id.as_str()).map_err(|_| {
            ContributionError::InvalidRequest("consent_grant_id", ValidationCode::InvalidFormat)
        })?,
    )
    .bind(request.observed_at_unix_ms)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| ContributionError::Unavailable)?;
    let Some(client_id) = client_id else {
        return Err(ContributionError::Conflict);
    };

    // The referenced rule must be a recognized exact (site, rule hash) pair.
    let rule_hash =
        decode_sha256_hex(request.rule_hash.as_str()).ok_or(ContributionError::Unavailable)?;
    let rule_version: Option<(Uuid, serde_json::Value)> = sqlx::query_as(
        "SELECT id, compiled_rule FROM rule_versions \
         WHERE site_id = $1 AND rule_hash = $2",
    )
    .bind(request.target.site_id.as_str())
    .bind(&rule_hash[..])
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| ContributionError::Unavailable)?;
    let Some((rule_version_id, compiled_rule)) = rule_version else {
        return Err(ContributionError::InvalidRequest(
            "rule_hash",
            ValidationCode::InvalidRelation,
        ));
    };
    let source: socialname_rule_schema::SiteRuleSource =
        serde_json::from_value(compiled_rule).map_err(|_| ContributionError::Unavailable)?;
    let compiled = RuleCompiler::new()
        .compile_source(source, None)
        .map_err(|_| ContributionError::Unavailable)?;
    let normalized_username = compiled
        .normalize_username(request.target.username.as_str())
        .filter(|normalized| {
            (1..=256).contains(&normalized.len()) && !normalized.chars().any(char::is_control)
        })
        .ok_or(ContributionError::InvalidRequest(
            "target",
            ValidationCode::InvalidFormat,
        ))?;

    // Reputation control: the site-family record is created quarantine-free
    // as `new`, locked for this submission, and suspension rejects up front.
    let reputation_candidate = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contributor_reputation (\
            id, tenant_id, client_id, site_family, tier, revision, created_at, updated_at\
         ) VALUES ($1, $2, $3, $4, 'new', 1, clock_timestamp(), clock_timestamp()) \
         ON CONFLICT (tenant_id, client_id, site_family) DO NOTHING",
    )
    .bind(reputation_candidate)
    .bind(principal.workspace_id)
    .bind(client_id)
    .bind(request.target.site_id.as_str())
    .execute(&mut **transaction)
    .await
    .map_err(|_| ContributionError::Unavailable)?;
    let (reputation_id, tier): (Uuid, String) = sqlx::query_as(
        "SELECT id, tier FROM contributor_reputation \
         WHERE tenant_id = $1 AND client_id = $2 AND site_family = $3 \
         FOR UPDATE",
    )
    .bind(principal.workspace_id)
    .bind(client_id)
    .bind(request.target.site_id.as_str())
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| ContributionError::Unavailable)?;
    if tier == "suspended" {
        return Err(ContributionError::Forbidden);
    }

    sqlx::query(
        "INSERT INTO contribution_sequences (\
            tenant_id, client_id, high_water, replay_violations, created_at, updated_at\
         ) VALUES ($1, $2, 0, 0, clock_timestamp(), clock_timestamp()) \
         ON CONFLICT (tenant_id, client_id) DO NOTHING",
    )
    .bind(principal.workspace_id)
    .bind(client_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ContributionError::Unavailable)?;

    Ok(AdmittedContext {
        now_unix_ms,
        upload_age_ms: now_unix_ms.saturating_sub(request.observed_at_unix_ms),
        client_id,
        rule_version_id,
        normalized_username,
        reputation_id,
        compiled,
    })
}

enum ReplayDecision {
    Fresh,
    ExactReplay(Uuid),
    Violation,
}

async fn check_replay(
    transaction: &mut Transaction<'_, Postgres>,
    principal: &AuthenticatedPrincipal,
    request: &SharedContributionSubmitRequest,
    context: &AdmittedContext,
) -> Result<ReplayDecision, ContributionError> {
    let high_water: i64 = sqlx::query_scalar(
        "SELECT high_water FROM contribution_sequences \
         WHERE tenant_id = $1 AND client_id = $2 \
         FOR UPDATE",
    )
    .bind(principal.workspace_id)
    .bind(context.client_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| ContributionError::Unavailable)?;
    let sequence_number =
        i64::try_from(request.sequence_number).map_err(|_| ContributionError::Unavailable)?;
    let content_digest = content_digest(request).ok_or(ContributionError::Unavailable)?;
    let existing: Option<(Uuid, Vec<u8>)> = sqlx::query_as(
        "SELECT contribution.id, contribution.content_digest \
         FROM shared_contributions AS contribution \
         WHERE contribution.tenant_id = $1 \
           AND contribution.client_id = $2 \
           AND contribution.sequence_number = $3 \
           AND NOT EXISTS (\
               SELECT 1 FROM deletion_resource_matches AS hidden \
               WHERE hidden.tenant_id = contribution.tenant_id \
                 AND hidden.resource_kind = 'shared_contribution' \
                 AND hidden.resource_id = contribution.id\
           )",
    )
    .bind(principal.workspace_id)
    .bind(context.client_id)
    .bind(sequence_number)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| ContributionError::Unavailable)?;
    match existing {
        Some((existing_id, stored_digest)) if stored_digest == content_digest => {
            Ok(ReplayDecision::ExactReplay(existing_id))
        }
        Some(_) => Ok(ReplayDecision::Violation),
        None if sequence_number <= high_water => Ok(ReplayDecision::Violation),
        None => Ok(ReplayDecision::Fresh),
    }
}

async fn record_replay_violation(
    transaction: &mut Transaction<'_, Postgres>,
    principal: &AuthenticatedPrincipal,
    context: &AdmittedContext,
) -> Result<bool, ContributionError> {
    let violations: i64 = sqlx::query_scalar(
        "UPDATE contribution_sequences \
         SET replay_violations = replay_violations + 1, \
             last_violation_at = clock_timestamp(), \
             updated_at = clock_timestamp() \
         WHERE tenant_id = $1 AND client_id = $2 \
         RETURNING replay_violations",
    )
    .bind(principal.workspace_id)
    .bind(context.client_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| ContributionError::Unavailable)?;
    if violations >= REPLAY_SUSPENSION_THRESHOLD {
        suspend_reputation(transaction, principal, context, "replay_abuse").await?;
        return Ok(true);
    }
    Ok(false)
}

async fn suspend_reputation(
    transaction: &mut Transaction<'_, Postgres>,
    principal: &AuthenticatedPrincipal,
    context: &AdmittedContext,
    reason: &'static str,
) -> Result<(), ContributionError> {
    let suspended = sqlx::query(
        "UPDATE contributor_reputation \
         SET tier = 'suspended', suspended_at = clock_timestamp(), \
             suspension_reason = $3, revision = revision + 1, \
             updated_at = clock_timestamp() \
         WHERE tenant_id = $1 AND id = $2 AND tier <> 'suspended'",
    )
    .bind(principal.workspace_id)
    .bind(context.reputation_id)
    .bind(reason)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ContributionError::Unavailable)?;
    if suspended.rows_affected() == 1 {
        sqlx::query(
            "INSERT INTO audit_events (\
                id, tenant_id, action, resource_kind, resource_id, \
                occurred_at, details\
             ) VALUES (\
                $1, $2, 'contribution.reputation.suspended', \
                'contributor_reputation', $3, clock_timestamp(), \
                jsonb_build_object('reason', $4::text)\
             )",
        )
        .bind(Uuid::new_v4())
        .bind(principal.workspace_id)
        .bind(context.reputation_id)
        .bind(reason)
        .execute(&mut **transaction)
        .await
        .map_err(|_| ContributionError::Unavailable)?;
    }
    Ok(())
}

fn probes_agree_with_plan(
    request: &SharedContributionSubmitRequest,
    compiled: &CompiledSiteRule,
) -> bool {
    request.probes.iter().all(|probe| {
        let Some(index) = compiled.probe_index.get(&probe.probe_id) else {
            return false;
        };
        let Some(plan) = compiled.source.probes.get(*index) else {
            return false;
        };
        let Some(final_url) = probe.final_url.as_ref() else {
            return true;
        };
        let Ok(parsed) = url::Url::parse(final_url.as_str()) else {
            return false;
        };
        let Some(host) = parsed.host_str() else {
            return false;
        };
        plan.http
            .allowed_hosts
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(host))
    })
}

async fn enforce_quota(
    transaction: &mut Transaction<'_, Postgres>,
    principal: &AuthenticatedPrincipal,
    context: &AdmittedContext,
) -> Result<(), ContributionError> {
    for (scope, client_id, limit) in [
        ("tenant", None, TENANT_DAILY_ACCEPT_LIMIT),
        (
            "installation",
            Some(context.client_id),
            INSTALLATION_DAILY_ACCEPT_LIMIT,
        ),
    ] {
        let accepted: i32 = sqlx::query_scalar(
            "INSERT INTO contribution_quota_counters (\
                id, tenant_id, counter_scope, client_id, day, accepted_count\
             ) VALUES (\
                $1, $2, $3, $4, (clock_timestamp() AT TIME ZONE 'UTC')::date, 1\
             ) \
             ON CONFLICT ON CONSTRAINT contribution_quota_counters_unique \
             DO UPDATE SET accepted_count = \
                contribution_quota_counters.accepted_count + 1 \
             RETURNING accepted_count",
        )
        .bind(Uuid::new_v4())
        .bind(principal.workspace_id)
        .bind(scope)
        .bind(client_id)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|_| ContributionError::Unavailable)?;
        if accepted > limit {
            let retry_after_ms: i64 = sqlx::query_scalar(
                "SELECT (EXTRACT(EPOCH FROM (\
                    date_trunc('day', clock_timestamp() AT TIME ZONE 'UTC') \
                    + interval '1 day' \
                    - (clock_timestamp() AT TIME ZONE 'UTC')\
                 )) * 1000)::bigint",
            )
            .fetch_one(&mut **transaction)
            .await
            .map_err(|_| ContributionError::Unavailable)?;
            return Err(ContributionError::QuotaExceeded(
                u64::try_from(retry_after_ms.max(1)).map_err(|_| ContributionError::Unavailable)?,
            ));
        }
    }
    Ok(())
}

async fn insert_contribution(
    transaction: &mut Transaction<'_, Postgres>,
    principal: &AuthenticatedPrincipal,
    request: &SharedContributionSubmitRequest,
    context: &AdmittedContext,
    suppression_key: &[u8; 32],
) -> Result<Uuid, ContributionError> {
    let contribution_id = Uuid::new_v4();
    let (outcome_kind, verdict, uncertainty_reason, expiry_ttl_ms) = match &request.outcome {
        EvidenceOutcome::Definitive { verdict } => {
            let (verdict, ttl) = match verdict {
                socialname_protocol::DefinitiveVerdict::Found => ("found", FOUND_TTL_MS),
                socialname_protocol::DefinitiveVerdict::NotFound => ("not_found", NOT_FOUND_TTL_MS),
            };
            ("definitive", Some(verdict), None, ttl)
        }
        EvidenceOutcome::Uncertain { reason } => {
            let reason = match reason {
                socialname_protocol::UncertaintyReason::SiteChanged => "site_changed",
                socialname_protocol::UncertaintyReason::NoRuleMatched => "no_rule_matched",
                socialname_protocol::UncertaintyReason::ConflictingEvidence => {
                    "conflicting_evidence"
                }
                socialname_protocol::UncertaintyReason::ClassificationAmbiguous => {
                    "classification_ambiguous"
                }
            };
            ("uncertain", None, Some(reason), UNCERTAIN_TTL_MS)
        }
    };
    // Influence eligibility never widens after admission: only a fresh upload
    // for a currently green regional rule can influence the current state.
    let rule_health_green: bool = sqlx::query_scalar(
        "SELECT COALESCE((\
            SELECT health.state = 'healthy' \
             AND health.evidence_expires_at > clock_timestamp() \
            FROM rule_health_records AS health \
            WHERE health.rule_version_id = $1 AND health.region_class = $2 \
            ORDER BY health.recorded_at DESC \
            LIMIT 1\
         ), false)",
    )
    .bind(context.rule_version_id)
    .bind(request.region_class.as_str())
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| ContributionError::Unavailable)?;
    let (influence_scope, history_reason) = if context.upload_age_ms > CURRENT_INFLUENCE_WINDOW_MS {
        ("history_only", Some("stale_upload"))
    } else if !rule_health_green {
        ("history_only", Some("rule_health_not_green"))
    } else {
        ("current", None)
    };
    let network_group = network_group(
        suppression_key,
        request.region_class.as_str(),
        request.network_class.as_str(),
        context.now_unix_ms,
    )
    .ok_or(ContributionError::Unavailable)?;
    let content_digest = content_digest(request).ok_or(ContributionError::Unavailable)?;
    let evidence_digest = decode_sha256_hex(request.evidence_digest.as_str())
        .ok_or(ContributionError::Unavailable)?;
    let engine_hash =
        decode_sha256_hex(&request.engine_hash).ok_or(ContributionError::Unavailable)?;
    sqlx::query(
        "INSERT INTO shared_contributions (\
            id, tenant_id, client_id, consent_grant_id, sequence_number, \
            content_digest, normalized_username, site_id, rule_version_id, \
            engine_hash, outcome_kind, verdict, uncertainty_reason, \
            evidence_class, evidence_digest, region_class, network_class, \
            network_group, influence_scope, history_reason, observed_at, \
            received_at, expires_at, created_at\
         ) VALUES (\
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, \
            $15, $16, $17, $18, $19, $20, \
            to_timestamp($21::double precision / 1000.0), \
            to_timestamp($22::double precision / 1000.0), \
            to_timestamp($23::double precision / 1000.0), \
            to_timestamp($22::double precision / 1000.0)\
         )",
    )
    .bind(contribution_id)
    .bind(principal.workspace_id)
    .bind(context.client_id)
    .bind(
        Uuid::parse_str(request.consent_grant_id.as_str())
            .map_err(|_| ContributionError::Unavailable)?,
    )
    .bind(i64::try_from(request.sequence_number).map_err(|_| ContributionError::Unavailable)?)
    .bind(&content_digest[..])
    .bind(&context.normalized_username)
    .bind(request.target.site_id.as_str())
    .bind(context.rule_version_id)
    .bind(&engine_hash[..])
    .bind(outcome_kind)
    .bind(verdict)
    .bind(uncertainty_reason)
    .bind(evidence_class_label(request.evidence_class))
    .bind(&evidence_digest[..])
    .bind(request.region_class.as_str())
    .bind(request.network_class.as_str())
    .bind(&network_group[..])
    .bind(influence_scope)
    .bind(history_reason)
    .bind(request.observed_at_unix_ms)
    .bind(context.now_unix_ms)
    .bind(
        request
            .observed_at_unix_ms
            .checked_add(expiry_ttl_ms)
            .ok_or(ContributionError::Unavailable)?,
    )
    .execute(&mut **transaction)
    .await
    .map_err(|_| ContributionError::Unavailable)?;

    let high_water_updated = sqlx::query(
        "UPDATE contribution_sequences \
         SET high_water = $3, updated_at = clock_timestamp() \
         WHERE tenant_id = $1 AND client_id = $2 AND high_water < $3",
    )
    .bind(principal.workspace_id)
    .bind(context.client_id)
    .bind(i64::try_from(request.sequence_number).map_err(|_| ContributionError::Unavailable)?)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ContributionError::Unavailable)?;
    if high_water_updated.rows_affected() != 1 {
        return Err(ContributionError::Unavailable);
    }

    sqlx::query(
        "UPDATE clients \
         SET last_seen_at = GREATEST(\
            created_at, clock_timestamp(), COALESCE(last_seen_at, created_at)\
         ) \
         WHERE tenant_id = $1 AND id = $2",
    )
    .bind(principal.workspace_id)
    .bind(context.client_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ContributionError::Unavailable)?;
    Ok(contribution_id)
}

async fn record_acceptance_activity(
    transaction: &mut Transaction<'_, Postgres>,
    principal: &AuthenticatedPrincipal,
    context: &AdmittedContext,
) -> Result<(), ContributionError> {
    sqlx::query(
        "UPDATE contributor_reputation \
         SET active_days = active_days + 1, \
             last_active_day = (clock_timestamp() AT TIME ZONE 'UTC')::date, \
             revision = revision + 1, \
             updated_at = clock_timestamp() \
         WHERE tenant_id = $1 AND id = $2 \
           AND (\
               last_active_day IS NULL \
               OR last_active_day < (clock_timestamp() AT TIME ZONE 'UTC')::date\
           )",
    )
    .bind(principal.workspace_id)
    .bind(context.reputation_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ContributionError::Unavailable)?;
    Ok(())
}

fn content_digest(request: &SharedContributionSubmitRequest) -> Option<[u8; 32]> {
    let bytes = serde_json::to_vec(request).ok()?;
    Some(Sha256::digest(&bytes).into())
}

/// Derives the short-lived coarse independence-group token from the claimed
/// region and network class plus a weekly rotation window. The token is a
/// keyed population bucket, not an identifier, and never stores a client IP.
/// The configured server secret keys the bucket under a distinct domain.
fn network_group(
    key: &[u8; 32],
    region_class: &str,
    network_class: &str,
    now_unix_ms: i64,
) -> Option<[u8; 32]> {
    let week_index = now_unix_ms.checked_div(WEEK_MS)?;
    let mut hmac = HmacSha256::new_from_slice(key).ok()?;
    for field in [
        b"socialname:independence-group:v1".as_slice(),
        region_class.as_bytes(),
        network_class.as_bytes(),
        &week_index.to_be_bytes(),
    ] {
        let field_length = u64::try_from(field.len()).ok()?;
        hmac.update(&field_length.to_be_bytes());
        hmac.update(field);
    }
    Some(hmac.finalize().into_bytes().into())
}

fn evidence_class_label(value: EvidenceClass) -> &'static str {
    match value {
        EvidenceClass::E0NoAccountEvidence => "e0_no_account_evidence",
        EvidenceClass::E1WeakSignal => "e1_weak_signal",
        EvidenceClass::E2DifferentialTemplate => "e2_differential_template",
        EvidenceClass::E3ExplicitEndpoint => "e3_explicit_endpoint",
        EvidenceClass::E4StructuredIdentity => "e4_structured_identity",
    }
}

fn decode_sha256_hex(value: &str) -> Option<[u8; 32]> {
    let mut bytes = [0_u8; 32];
    hex::decode_to_slice(value, &mut bytes).ok()?;
    Some(bytes)
}

async fn load_contribution(
    pool: &PgPool,
    principal: &AuthenticatedPrincipal,
    contribution_id: Uuid,
) -> Result<SharedContributionResource, ContributionError> {
    let mut transaction =
        auth::begin_authorized_transaction(pool, principal, ApiKeyScope::ContributionRead).await?;
    let resource = load_owned_resource(&mut transaction, principal, contribution_id)
        .await?
        .ok_or(ContributionError::NotFound)?;
    transaction
        .commit()
        .await
        .map_err(|_| ContributionError::Unavailable)?;
    Ok(resource)
}

#[derive(Clone, Copy)]
struct ContributionPageRequest {
    limit: usize,
    after: Option<Uuid>,
}

fn parse_page_query(
    query: Result<Query<ContributionPageQuery>, QueryRejection>,
) -> Result<ContributionPageRequest, ContributionError> {
    let Query(query) = query
        .map_err(|_| ContributionError::InvalidRequest("query", ValidationCode::InvalidFormat))?;
    let limit = usize::from(query.limit.unwrap_or(DEFAULT_PAGE_ITEMS as u16));
    if !(1..=MAX_CONTRIBUTION_PAGE_ITEMS).contains(&limit) {
        return Err(ContributionError::InvalidRequest(
            "limit",
            ValidationCode::OutOfRange,
        ));
    }
    let after = query
        .after
        .map(|value| {
            Uuid::parse_str(&value).map_err(|_| {
                ContributionError::InvalidRequest("after", ValidationCode::InvalidFormat)
            })
        })
        .transpose()?;
    Ok(ContributionPageRequest { limit, after })
}

async fn load_contribution_page(
    pool: &PgPool,
    principal: &AuthenticatedPrincipal,
    page: ContributionPageRequest,
) -> Result<SharedContributionPage, ContributionError> {
    let mut transaction =
        auth::begin_authorized_transaction(pool, principal, ApiKeyScope::ContributionRead).await?;
    if let Some(cursor) = page.after {
        let cursor_owned: bool = sqlx::query_scalar(
            "SELECT EXISTS(\
                SELECT 1 FROM shared_contributions \
                WHERE tenant_id = $1 AND id = $2\
             )",
        )
        .bind(principal.workspace_id)
        .bind(cursor)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ContributionError::Unavailable)?;
        if !cursor_owned {
            return Err(ContributionError::InvalidRequest(
                "after",
                ValidationCode::InvalidRelation,
            ));
        }
    }
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT contribution.id \
         FROM shared_contributions AS contribution \
         WHERE contribution.tenant_id = $1 \
           AND NOT EXISTS (\
               SELECT 1 FROM deletion_resource_matches AS hidden \
               WHERE hidden.tenant_id = contribution.tenant_id \
                 AND hidden.resource_kind = 'shared_contribution' \
                 AND hidden.resource_id = contribution.id\
           ) \
           AND (\
             $2::uuid IS NULL \
             OR EXISTS (\
                 SELECT 1 FROM shared_contributions AS cursor \
                 WHERE cursor.tenant_id = contribution.tenant_id \
                   AND cursor.id = $2 \
                   AND (contribution.received_at, contribution.id) \
                       < (cursor.received_at, cursor.id)\
             )\
           ) \
         ORDER BY contribution.received_at DESC, contribution.id DESC \
         LIMIT $3",
    )
    .bind(principal.workspace_id)
    .bind(page.after)
    .bind(i64::try_from(page.limit + 1).map_err(|_| ContributionError::Unavailable)?)
    .fetch_all(&mut *transaction)
    .await
    .map_err(|_| ContributionError::Unavailable)?;
    let has_more = ids.len() > page.limit;
    let mut contributions = Vec::with_capacity(page.limit.min(ids.len()));
    for id in ids.into_iter().take(page.limit) {
        contributions.push(
            load_owned_resource(&mut transaction, principal, id)
                .await?
                .ok_or(ContributionError::Unavailable)?,
        );
    }
    let next_cursor = has_more
        .then(|| contributions.last())
        .flatten()
        .map(|contribution| contribution.contribution_id.clone());
    let page = SharedContributionPage {
        schema: ProtocolVersion::ApiV1,
        contributions,
        next_cursor,
    };
    page.validate()
        .map_err(|_| ContributionError::Unavailable)?;
    transaction
        .commit()
        .await
        .map_err(|_| ContributionError::Unavailable)?;
    Ok(page)
}

async fn load_owned_resource(
    transaction: &mut Transaction<'_, Postgres>,
    principal: &AuthenticatedPrincipal,
    contribution_id: Uuid,
) -> Result<Option<SharedContributionResource>, ContributionError> {
    let stored: Option<StoredContribution> = sqlx::query_as(
        "SELECT \
            contribution.id, contribution.normalized_username, contribution.site_id, \
            encode(rule_version.rule_hash, 'hex') AS rule_hash, \
            contribution.region_class, contribution.network_class, \
            contribution.outcome_kind, contribution.verdict, \
            contribution.uncertainty_reason, contribution.evidence_class, \
            encode(contribution.evidence_digest, 'hex') AS evidence_digest, \
            contribution.sequence_number, contribution.influence_scope, \
            contribution.history_reason, reputation.tier AS reputation_tier, \
            (EXTRACT(EPOCH FROM contribution.observed_at) * 1000)::bigint \
                AS observed_at_unix_ms, \
            (EXTRACT(EPOCH FROM contribution.received_at) * 1000)::bigint \
                AS received_at_unix_ms, \
            (EXTRACT(EPOCH FROM contribution.expires_at) * 1000)::bigint \
                AS expires_at_unix_ms \
         FROM shared_contributions AS contribution \
         JOIN rule_versions AS rule_version \
           ON rule_version.id = contribution.rule_version_id \
         JOIN contributor_reputation AS reputation \
           ON reputation.tenant_id = contribution.tenant_id \
          AND reputation.client_id = contribution.client_id \
          AND reputation.site_family = contribution.site_id \
         WHERE contribution.tenant_id = $1 AND contribution.id = $2 \
           AND NOT EXISTS (\
               SELECT 1 FROM deletion_resource_matches AS hidden \
               WHERE hidden.tenant_id = contribution.tenant_id \
                 AND hidden.resource_kind = 'shared_contribution' \
                 AND hidden.resource_id = contribution.id\
           )",
    )
    .bind(principal.workspace_id)
    .bind(contribution_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| ContributionError::Unavailable)?;
    stored.map(StoredContribution::into_resource).transpose()
}

#[derive(FromRow)]
struct StoredContribution {
    id: Uuid,
    normalized_username: String,
    site_id: String,
    rule_hash: String,
    region_class: String,
    network_class: String,
    outcome_kind: String,
    verdict: Option<String>,
    uncertainty_reason: Option<String>,
    evidence_class: String,
    evidence_digest: String,
    sequence_number: i64,
    influence_scope: String,
    history_reason: Option<String>,
    reputation_tier: String,
    observed_at_unix_ms: i64,
    received_at_unix_ms: i64,
    expires_at_unix_ms: i64,
}

impl StoredContribution {
    fn into_resource(self) -> Result<SharedContributionResource, ContributionError> {
        let outcome = match (
            self.outcome_kind.as_str(),
            self.verdict.as_deref(),
            self.uncertainty_reason.as_deref(),
        ) {
            ("definitive", Some("found"), None) => EvidenceOutcome::Definitive {
                verdict: socialname_protocol::DefinitiveVerdict::Found,
            },
            ("definitive", Some("not_found"), None) => EvidenceOutcome::Definitive {
                verdict: socialname_protocol::DefinitiveVerdict::NotFound,
            },
            ("uncertain", None, Some(reason)) => EvidenceOutcome::Uncertain {
                reason: match reason {
                    "site_changed" => socialname_protocol::UncertaintyReason::SiteChanged,
                    "no_rule_matched" => socialname_protocol::UncertaintyReason::NoRuleMatched,
                    "conflicting_evidence" => {
                        socialname_protocol::UncertaintyReason::ConflictingEvidence
                    }
                    "classification_ambiguous" => {
                        socialname_protocol::UncertaintyReason::ClassificationAmbiguous
                    }
                    _ => return Err(ContributionError::Unavailable),
                },
            },
            _ => return Err(ContributionError::Unavailable),
        };
        let resource = SharedContributionResource {
            schema: ProtocolVersion::ApiV1,
            contribution_schema: SharedContributionSchema::V1,
            contribution_id: ContributionId::new(self.id.to_string())
                .map_err(|_| ContributionError::Unavailable)?,
            target: Target {
                username: Username::new(self.normalized_username)
                    .map_err(|_| ContributionError::Unavailable)?,
                site_id: SiteId::new(self.site_id).map_err(|_| ContributionError::Unavailable)?,
            },
            rule_hash: RuleHash::new(self.rule_hash).map_err(|_| ContributionError::Unavailable)?,
            region_class: RegionClass::new(self.region_class)
                .map_err(|_| ContributionError::Unavailable)?,
            network_class: match self.network_class.as_str() {
                "datacenter" => ContributionNetworkClass::Datacenter,
                "residential" => ContributionNetworkClass::Residential,
                "anonymizer" => ContributionNetworkClass::Anonymizer,
                "unknown" => ContributionNetworkClass::Unknown,
                _ => return Err(ContributionError::Unavailable),
            },
            outcome,
            evidence_class: match self.evidence_class.as_str() {
                "e0_no_account_evidence" => EvidenceClass::E0NoAccountEvidence,
                "e1_weak_signal" => EvidenceClass::E1WeakSignal,
                "e2_differential_template" => EvidenceClass::E2DifferentialTemplate,
                "e3_explicit_endpoint" => EvidenceClass::E3ExplicitEndpoint,
                "e4_structured_identity" => EvidenceClass::E4StructuredIdentity,
                _ => return Err(ContributionError::Unavailable),
            },
            evidence_digest: EvidenceDigest::new(self.evidence_digest)
                .map_err(|_| ContributionError::Unavailable)?,
            sequence_number: u64::try_from(self.sequence_number)
                .map_err(|_| ContributionError::Unavailable)?,
            influence_scope: match self.influence_scope.as_str() {
                "current" => ContributionInfluenceScope::Current,
                "history_only" => ContributionInfluenceScope::HistoryOnly,
                _ => return Err(ContributionError::Unavailable),
            },
            history_reason: match self.history_reason.as_deref() {
                None => None,
                Some("stale_upload") => Some(ContributionHistoryReason::StaleUpload),
                Some("rule_health_not_green") => {
                    Some(ContributionHistoryReason::RuleHealthNotGreen)
                }
                Some(_) => return Err(ContributionError::Unavailable),
            },
            reputation_tier: match self.reputation_tier.as_str() {
                "new" => ContributorReputationTier::New,
                "calibrated" => ContributorReputationTier::Calibrated,
                "trusted" => ContributorReputationTier::Trusted,
                "suspended" => ContributorReputationTier::Suspended,
                _ => return Err(ContributionError::Unavailable),
            },
            observed_at_unix_ms: self.observed_at_unix_ms,
            received_at_unix_ms: self.received_at_unix_ms,
            expires_at_unix_ms: self.expires_at_unix_ms,
        };
        resource
            .validate()
            .map_err(|_| ContributionError::Unavailable)?;
        Ok(resource)
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

fn error_response(request_id: RequestId, error: ContributionError) -> Response {
    match error {
        ContributionError::InvalidRequest(field, code) => invalid_request_response(
            StatusCode::BAD_REQUEST,
            request_id,
            ValidationErrors::new(field, code),
        ),
        ContributionError::NotFound => crate::api_error_response(
            StatusCode::NOT_FOUND,
            request_id,
            standard_api_error(ApiErrorCode::NotFound, false),
        ),
        ContributionError::Conflict => crate::api_error_response(
            StatusCode::CONFLICT,
            request_id,
            standard_api_error(ApiErrorCode::Conflict, false),
        ),
        ContributionError::Forbidden => crate::api_error_response(
            StatusCode::FORBIDDEN,
            request_id,
            standard_api_error(ApiErrorCode::Forbidden, false),
        ),
        ContributionError::QuotaExceeded(retry_after_ms) => crate::api_error_response(
            StatusCode::TOO_MANY_REQUESTS,
            request_id,
            ApiError {
                code: ApiErrorCode::QuotaExceeded,
                retryable: true,
                retry_after_ms: Some(retry_after_ms),
                violations: Vec::new(),
            },
        ),
        ContributionError::Authentication(AuthenticationError::Forbidden) => {
            crate::api_error_response(
                StatusCode::FORBIDDEN,
                request_id,
                standard_api_error(ApiErrorCode::Forbidden, false),
            )
        }
        ContributionError::Authentication(AuthenticationError::InvalidCredential) => {
            unauthenticated_response(request_id)
        }
        ContributionError::Authentication(AuthenticationError::Unavailable)
        | ContributionError::Unavailable => crate::api_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            request_id,
            standard_api_error(ApiErrorCode::Unavailable, true),
        ),
    }
}

#[derive(Debug, thiserror::Error)]
enum ContributionError {
    #[error("contribution request is invalid")]
    InvalidRequest(&'static str, ValidationCode),
    #[error("contribution was not found")]
    NotFound,
    #[error("contribution admission was refused")]
    Conflict,
    #[error("contribution submission is not permitted")]
    Forbidden,
    #[error("contribution quota is exhausted")]
    QuotaExceeded(u64),
    #[error(transparent)]
    Authentication(#[from] AuthenticationError),
    #[error("contribution storage is unavailable")]
    Unavailable,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_group_rotates_weekly_and_separates_populations() {
        let key = [7_u8; 32];
        let first = network_group(&key, "jp", "residential", WEEK_MS).unwrap();
        assert_eq!(
            first,
            network_group(&key, "jp", "residential", WEEK_MS + 1).unwrap()
        );
        assert_ne!(
            first,
            network_group(&key, "jp", "residential", 2 * WEEK_MS).unwrap()
        );
        assert_ne!(
            first,
            network_group(&key, "us", "residential", WEEK_MS).unwrap()
        );
        assert_ne!(
            first,
            network_group(&key, "jp", "datacenter", WEEK_MS).unwrap()
        );
        assert_ne!(
            first,
            network_group(&[8_u8; 32], "jp", "residential", WEEK_MS).unwrap()
        );
    }

    #[test]
    fn page_query_is_bounded_and_rejects_private_cursor_text() {
        assert!(matches!(
            parse_page_query(Ok(Query(ContributionPageQuery {
                limit: Some(51),
                after: None,
            }))),
            Err(ContributionError::InvalidRequest(
                "limit",
                ValidationCode::OutOfRange
            ))
        ));
        let private = "private-contribution-cursor";
        let error = Uuid::parse_str(private)
            .map_err(|_| ContributionError::InvalidRequest("after", ValidationCode::InvalidFormat))
            .unwrap_err();
        assert!(!error.to_string().contains(private));
    }
}
