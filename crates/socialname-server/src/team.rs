use axum::{
    Json,
    extract::{
        Extension, Path, Query, State,
        rejection::{JsonRejection, QueryRejection},
    },
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use socialname_protocol::{
    ApiErrorCode, ApiKeyId, ApiKeyScope, AuditEventId, AuditResourceId, MAX_TEAM_PAGE_ITEMS,
    MembershipId, OrganizationAuditActor, OrganizationAuditEventPage,
    OrganizationAuditEventResource, OrganizationMemberAction, OrganizationMemberCreateRequest,
    OrganizationMemberPage, OrganizationMemberPatchRequest, OrganizationMemberResource,
    OrganizationMemberState, OrganizationResource, OrganizationRetentionPolicyPatchRequest,
    OrganizationRetentionPolicyResource, OrganizationRole, ProtocolVersion, RequestId,
    TransitionReviewAction, TransitionReviewId, TransitionReviewPage, TransitionReviewPatchRequest,
    TransitionReviewResolution, TransitionReviewResource, TransitionReviewState, Validate,
    ValidationCode, ValidationErrors, WorkspaceId, WorkspaceState,
};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    ServerState,
    auth::{self, AuthenticatedPrincipal, AuthenticationError},
    monitoring, standard_api_error, unauthenticated_response,
};

const DEFAULT_PAGE_ITEMS: usize = 20;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TeamPageQuery {
    limit: Option<u16>,
    after: Option<String>,
}

#[derive(Clone, Copy)]
struct PageRequest {
    limit: usize,
    after: Option<Uuid>,
}

pub(crate) async fn get_organization(
    State(state): State<ServerState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
) -> Response {
    match load_organization(&state.database, &principal).await {
        Ok(resource) => Json(resource).into_response(),
        Err(error) => error_response(request_id, error),
    }
}

pub(crate) async fn list_organization_members(
    State(state): State<ServerState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    query: Result<Query<TeamPageQuery>, QueryRejection>,
) -> Response {
    let page = match parse_page_query(query) {
        Ok(page) => page,
        Err(error) => return error_response(request_id, error),
    };
    match load_member_page(&state.database, &principal, page).await {
        Ok(resource) => Json(resource).into_response(),
        Err(error) => error_response(request_id, error),
    }
}

pub(crate) async fn create_organization_member(
    State(state): State<ServerState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    payload: Result<Json<OrganizationMemberCreateRequest>, JsonRejection>,
) -> Response {
    let request = match validated_json(payload) {
        Ok(request) => request,
        Err(error) => return error_response(request_id, error),
    };
    match persist_member(&state.database, &principal, request).await {
        Ok((resource, false)) => (StatusCode::CREATED, Json(resource)).into_response(),
        Ok((resource, true)) => Json(resource).into_response(),
        Err(error) => error_response(request_id, error),
    }
}

pub(crate) async fn patch_organization_member(
    State(state): State<ServerState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Path(membership_id): Path<String>,
    payload: Result<Json<OrganizationMemberPatchRequest>, JsonRejection>,
) -> Response {
    let membership_id = match parse_uuid(&membership_id, "membership_id") {
        Ok(id) => id,
        Err(error) => return error_response(request_id, error),
    };
    let request = match validated_json(payload) {
        Ok(request) => request,
        Err(error) => return error_response(request_id, error),
    };
    match mutate_member(&state.database, &principal, membership_id, request).await {
        Ok(resource) => Json(resource).into_response(),
        Err(error) => error_response(request_id, error),
    }
}

pub(crate) async fn list_organization_audit_events(
    State(state): State<ServerState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    query: Result<Query<TeamPageQuery>, QueryRejection>,
) -> Response {
    let page = match parse_page_query(query) {
        Ok(page) => page,
        Err(error) => return error_response(request_id, error),
    };
    match load_audit_page(&state.database, &principal, page).await {
        Ok(resource) => Json(resource).into_response(),
        Err(error) => error_response(request_id, error),
    }
}

pub(crate) async fn get_organization_retention_policy(
    State(state): State<ServerState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
) -> Response {
    match load_retention_policy(&state.database, &principal).await {
        Ok(resource) => Json(resource).into_response(),
        Err(error) => error_response(request_id, error),
    }
}

pub(crate) async fn patch_organization_retention_policy(
    State(state): State<ServerState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    payload: Result<Json<OrganizationRetentionPolicyPatchRequest>, JsonRejection>,
) -> Response {
    let request = match validated_json(payload) {
        Ok(request) => request,
        Err(error) => return error_response(request_id, error),
    };
    match mutate_retention_policy(&state.database, &principal, request).await {
        Ok(resource) => Json(resource).into_response(),
        Err(error) => error_response(request_id, error),
    }
}

pub(crate) async fn list_transition_reviews(
    State(state): State<ServerState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    query: Result<Query<TeamPageQuery>, QueryRejection>,
) -> Response {
    let page = match parse_page_query(query) {
        Ok(page) => page,
        Err(error) => return error_response(request_id, error),
    };
    match load_review_page(&state.database, &principal, page).await {
        Ok(resource) => Json(resource).into_response(),
        Err(error) => error_response(request_id, error),
    }
}

pub(crate) async fn patch_transition_review(
    State(state): State<ServerState>,
    Extension(request_id): Extension<RequestId>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Path(review_id): Path<String>,
    payload: Result<Json<TransitionReviewPatchRequest>, JsonRejection>,
) -> Response {
    let review_id = match parse_uuid(&review_id, "review_id") {
        Ok(id) => id,
        Err(error) => return error_response(request_id, error),
    };
    let request = match validated_json(payload) {
        Ok(request) => request,
        Err(error) => return error_response(request_id, error),
    };
    match mutate_review(&state.database, &principal, review_id, request).await {
        Ok(resource) => Json(resource).into_response(),
        Err(error) => error_response(request_id, error),
    }
}

fn parse_page_query(
    query: Result<Query<TeamPageQuery>, QueryRejection>,
) -> Result<PageRequest, TeamError> {
    let Query(query) =
        query.map_err(|_| TeamError::InvalidRequest("query", ValidationCode::InvalidFormat))?;
    let limit = usize::from(query.limit.unwrap_or(DEFAULT_PAGE_ITEMS as u16));
    if !(1..=MAX_TEAM_PAGE_ITEMS).contains(&limit) {
        return Err(TeamError::InvalidRequest(
            "limit",
            ValidationCode::OutOfRange,
        ));
    }
    let after = query
        .after
        .map(|value| {
            Uuid::parse_str(&value)
                .map_err(|_| TeamError::InvalidRequest("after", ValidationCode::InvalidFormat))
        })
        .transpose()?;
    Ok(PageRequest { limit, after })
}

fn validated_json<T: Validate>(payload: Result<Json<T>, JsonRejection>) -> Result<T, TeamError> {
    let Json(request) =
        payload.map_err(|_| TeamError::InvalidRequest("body", ValidationCode::InvalidFormat))?;
    request
        .validate()
        .map_err(TeamError::InvalidBody)
        .map(|()| request)
}

async fn load_organization(
    pool: &PgPool,
    principal: &AuthenticatedPrincipal,
) -> Result<OrganizationResource, TeamError> {
    let mut transaction =
        auth::begin_authorized_transaction(pool, principal, ApiKeyScope::WorkspaceRead).await?;
    let row: Option<StoredOrganization> = sqlx::query_as(
        "SELECT tenant.id, tenant.slug, tenant.display_name, tenant.state, \
                membership.id AS membership_id, \
                membership.display_name AS member_display_name, \
                membership.role AS member_role, \
                membership.state AS member_state, membership.revision, \
                (extract(epoch FROM membership.created_at) * 1000)::bigint \
                    AS member_created_at_unix_ms, \
                (extract(epoch FROM membership.updated_at) * 1000)::bigint \
                    AS member_updated_at_unix_ms \
         FROM tenants AS tenant \
         JOIN memberships AS membership \
           ON membership.tenant_id = tenant.id \
          AND membership.id = $2 \
         WHERE tenant.id = $1 AND tenant.state = 'active' \
           AND membership.state = 'active'",
    )
    .bind(principal.workspace_id)
    .bind(principal.membership_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| TeamError::Unavailable)?;
    let resource = organization_resource(row.ok_or(TeamError::NotFound)?)
        .map_err(|_| TeamError::Unavailable)?;
    transaction
        .commit()
        .await
        .map_err(|_| TeamError::Unavailable)?;
    Ok(resource)
}

async fn load_member_page(
    pool: &PgPool,
    principal: &AuthenticatedPrincipal,
    page: PageRequest,
) -> Result<OrganizationMemberPage, TeamError> {
    let mut transaction =
        auth::begin_authorized_transaction(pool, principal, ApiKeyScope::WorkspaceRead).await?;
    ensure_member_cursor(&mut transaction, principal.workspace_id, page.after).await?;
    let rows: Vec<StoredMember> = sqlx::query_as(
        "SELECT membership.id, membership.display_name, membership.role, \
                membership.state, membership.revision, \
                (extract(epoch FROM membership.created_at) * 1000)::bigint \
                    AS created_at_unix_ms, \
                (extract(epoch FROM membership.updated_at) * 1000)::bigint \
                    AS updated_at_unix_ms \
         FROM memberships AS membership \
         WHERE membership.tenant_id = $1 \
           AND (\
                $2::uuid IS NULL \
                OR EXISTS (\
                    SELECT 1 FROM memberships AS cursor \
                    WHERE cursor.tenant_id = $1 AND cursor.id = $2 \
                      AND (membership.created_at, membership.id) \
                          < (cursor.created_at, cursor.id)\
                )\
           ) \
         ORDER BY membership.created_at DESC, membership.id DESC \
         LIMIT $3",
    )
    .bind(principal.workspace_id)
    .bind(page.after)
    .bind(i64::try_from(page.limit + 1).map_err(|_| TeamError::Unavailable)?)
    .fetch_all(&mut *transaction)
    .await
    .map_err(|_| TeamError::Unavailable)?;
    let has_more = rows.len() > page.limit;
    let members = rows
        .into_iter()
        .take(page.limit)
        .map(|row| member_resource(principal.workspace_id, row))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| TeamError::Unavailable)?;
    let next_cursor = has_more
        .then(|| members.last())
        .flatten()
        .map(|member| member.membership_id.clone());
    let resource = OrganizationMemberPage {
        schema: ProtocolVersion::ApiV1,
        members,
        next_cursor,
    };
    resource.validate().map_err(|_| TeamError::Unavailable)?;
    transaction
        .commit()
        .await
        .map_err(|_| TeamError::Unavailable)?;
    Ok(resource)
}

async fn persist_member(
    pool: &PgPool,
    principal: &AuthenticatedPrincipal,
    request: OrganizationMemberCreateRequest,
) -> Result<(OrganizationMemberResource, bool), TeamError> {
    require_member_manager(principal)?;
    if !can_manage_role(principal.role, request.role) {
        return Err(TeamError::Forbidden);
    }
    let mut transaction =
        auth::begin_authorized_transaction(pool, principal, ApiKeyScope::WorkspaceRead).await?;
    lock_tenant(&mut transaction, principal.workspace_id).await?;
    let membership_id = Uuid::new_v4();
    let provisioned: StoredProvisionedMember = sqlx::query_as(
        "SELECT id, display_name, role, state, revision, \
                created_at_unix_ms, updated_at_unix_ms, was_existing \
         FROM socialname_provision_organization_member($1, $2, $3, $4, $5, $6)",
    )
    .bind(principal.workspace_id)
    .bind(principal.membership_id)
    .bind(membership_id)
    .bind(request.subject_reference.as_str())
    .bind(&request.display_name)
    .bind(request.role.as_str())
    .fetch_one(&mut *transaction)
    .await
    .map_err(map_provision_database_error)?;
    if provisioned.was_existing {
        if provisioned.member.state != "active"
            || provisioned.member.display_name != request.display_name
            || provisioned.member.role != request.role.as_str()
        {
            return Err(TeamError::Conflict);
        }
        let resource = member_resource(principal.workspace_id, provisioned.member)
            .map_err(|_| TeamError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| TeamError::Unavailable)?;
        return Ok((resource, true));
    }

    insert_audit(
        &mut transaction,
        principal,
        "organization.member.created",
        "membership",
        membership_id,
    )
    .await?;
    let resource = member_resource(principal.workspace_id, provisioned.member)
        .map_err(|_| TeamError::Unavailable)?;
    transaction
        .commit()
        .await
        .map_err(|_| TeamError::Unavailable)?;
    Ok((resource, false))
}

async fn mutate_member(
    pool: &PgPool,
    principal: &AuthenticatedPrincipal,
    membership_id: Uuid,
    request: OrganizationMemberPatchRequest,
) -> Result<OrganizationMemberResource, TeamError> {
    require_member_manager(principal)?;
    if membership_id == principal.membership_id {
        return Err(TeamError::Conflict);
    }
    let mut transaction =
        auth::begin_authorized_transaction(pool, principal, ApiKeyScope::WorkspaceRead).await?;
    lock_tenant(&mut transaction, principal.workspace_id).await?;
    let current: Option<StoredMember> = sqlx::query_as(
        "SELECT id, display_name, role, state, revision, \
                (extract(epoch FROM created_at) * 1000)::bigint \
                    AS created_at_unix_ms, \
                (extract(epoch FROM updated_at) * 1000)::bigint \
                    AS updated_at_unix_ms \
         FROM memberships \
         WHERE tenant_id = $1 AND id = $2 \
         FOR UPDATE",
    )
    .bind(principal.workspace_id)
    .bind(membership_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| TeamError::Unavailable)?;
    let current = current.ok_or(TeamError::NotFound)?;
    if current.state == "removed"
        || u64::try_from(current.revision).ok() != Some(request.expected_revision)
    {
        return Err(TeamError::Conflict);
    }
    let current_role =
        OrganizationRole::parse(&current.role).map_err(|_| TeamError::Unavailable)?;
    if !can_manage_target(principal.role, current_role) {
        return Err(TeamError::Forbidden);
    }

    let (role, state, action) = match request.action {
        OrganizationMemberAction::ChangeRole { role } => {
            if current.state != "active"
                || role == current_role
                || !can_manage_role(principal.role, role)
            {
                return Err(TeamError::Conflict);
            }
            (
                role.as_str(),
                current.state.as_str(),
                "organization.member.role_changed",
            )
        }
        OrganizationMemberAction::Suspend => {
            if current.state != "active" {
                return Err(TeamError::Conflict);
            }
            (
                current.role.as_str(),
                "suspended",
                "organization.member.suspended",
            )
        }
        OrganizationMemberAction::Reactivate => {
            if current.state != "suspended" {
                return Err(TeamError::Conflict);
            }
            (
                current.role.as_str(),
                "active",
                "organization.member.reactivated",
            )
        }
        OrganizationMemberAction::Remove => {
            if !matches!(current.state.as_str(), "active" | "suspended") {
                return Err(TeamError::Conflict);
            }
            sqlx::query(
                "UPDATE api_keys \
                 SET state = 'revoked', revoked_at = clock_timestamp() \
                 WHERE tenant_id = $1 AND created_by_membership_id = $2 \
                   AND state = 'active'",
            )
            .bind(principal.workspace_id)
            .bind(membership_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| TeamError::Unavailable)?;
            (
                current.role.as_str(),
                "removed",
                "organization.member.removed",
            )
        }
    };

    let row: StoredMember = sqlx::query_as(
        "UPDATE memberships \
         SET role = $3, state = $4, revision = revision + 1, \
             updated_at = clock_timestamp() \
         WHERE tenant_id = $1 AND id = $2 AND revision = $5 \
         RETURNING id, display_name, role, state, revision, \
            (extract(epoch FROM created_at) * 1000)::bigint AS created_at_unix_ms, \
            (extract(epoch FROM updated_at) * 1000)::bigint AS updated_at_unix_ms",
    )
    .bind(principal.workspace_id)
    .bind(membership_id)
    .bind(role)
    .bind(state)
    .bind(current.revision)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(map_database_error)?
    .ok_or(TeamError::Conflict)?;
    insert_audit(
        &mut transaction,
        principal,
        action,
        "membership",
        membership_id,
    )
    .await?;
    let resource =
        member_resource(principal.workspace_id, row).map_err(|_| TeamError::Unavailable)?;
    transaction
        .commit()
        .await
        .map_err(|_| TeamError::Unavailable)?;
    Ok(resource)
}

async fn load_audit_page(
    pool: &PgPool,
    principal: &AuthenticatedPrincipal,
    page: PageRequest,
) -> Result<OrganizationAuditEventPage, TeamError> {
    if !matches!(
        principal.role,
        OrganizationRole::Owner | OrganizationRole::Administrator
    ) {
        return Err(TeamError::Forbidden);
    }
    let mut transaction =
        auth::begin_authorized_transaction(pool, principal, ApiKeyScope::OperationsRead).await?;
    ensure_audit_cursor(&mut transaction, principal.workspace_id, page.after).await?;
    let rows: Vec<StoredAuditEvent> = sqlx::query_as(
        "SELECT event.id, event.actor_membership_id, event.actor_api_key_id, \
                event.action, event.resource_kind, event.resource_id, \
                (extract(epoch FROM event.occurred_at) * 1000)::bigint \
                    AS occurred_at_unix_ms \
         FROM audit_events AS event \
         WHERE event.tenant_id = $1 \
           AND (\
                $2::uuid IS NULL \
                OR EXISTS (\
                    SELECT 1 FROM audit_events AS cursor \
                    WHERE cursor.tenant_id = $1 AND cursor.id = $2 \
                      AND (event.occurred_at, event.id) \
                          < (cursor.occurred_at, cursor.id)\
                )\
           ) \
         ORDER BY event.occurred_at DESC, event.id DESC \
         LIMIT $3",
    )
    .bind(principal.workspace_id)
    .bind(page.after)
    .bind(i64::try_from(page.limit + 1).map_err(|_| TeamError::Unavailable)?)
    .fetch_all(&mut *transaction)
    .await
    .map_err(|_| TeamError::Unavailable)?;
    let has_more = rows.len() > page.limit;
    let events = rows
        .into_iter()
        .take(page.limit)
        .map(audit_resource)
        .collect::<Result<Vec<_>, _>>()?;
    let next_cursor = has_more
        .then(|| events.last())
        .flatten()
        .map(|event| event.audit_event_id.clone());
    let resource = OrganizationAuditEventPage {
        schema: ProtocolVersion::ApiV1,
        events,
        next_cursor,
    };
    resource.validate().map_err(|_| TeamError::Unavailable)?;
    transaction
        .commit()
        .await
        .map_err(|_| TeamError::Unavailable)?;
    Ok(resource)
}

async fn load_retention_policy(
    pool: &PgPool,
    principal: &AuthenticatedPrincipal,
) -> Result<OrganizationRetentionPolicyResource, TeamError> {
    let mut transaction =
        auth::begin_authorized_transaction(pool, principal, ApiKeyScope::WorkspaceRead).await?;
    let resource = select_retention_policy(&mut transaction, principal.workspace_id).await?;
    transaction
        .commit()
        .await
        .map_err(|_| TeamError::Unavailable)?;
    Ok(resource)
}

async fn mutate_retention_policy(
    pool: &PgPool,
    principal: &AuthenticatedPrincipal,
    request: OrganizationRetentionPolicyPatchRequest,
) -> Result<OrganizationRetentionPolicyResource, TeamError> {
    require_member_manager(principal)?;
    let mut transaction =
        auth::begin_authorized_transaction(pool, principal, ApiKeyScope::WorkspaceRead).await?;
    let row: Option<StoredRetentionPolicy> = sqlx::query_as(
        "UPDATE organization_retention_policies \
         SET revision = revision + 1, minimum_watch_retention_days = $2, \
             maximum_watch_retention_days = $3, \
             updated_by_membership_id = $4, updated_at = clock_timestamp() \
         WHERE tenant_id = $1 AND revision = $5 \
         RETURNING tenant_id, revision, minimum_watch_retention_days, \
            maximum_watch_retention_days, \
            (extract(epoch FROM updated_at) * 1000)::bigint AS updated_at_unix_ms",
    )
    .bind(principal.workspace_id)
    .bind(
        i16::try_from(request.minimum_watch_retention_days)
            .map_err(|_| TeamError::InvalidRequest("body", ValidationCode::OutOfRange))?,
    )
    .bind(
        i16::try_from(request.maximum_watch_retention_days)
            .map_err(|_| TeamError::InvalidRequest("body", ValidationCode::OutOfRange))?,
    )
    .bind(principal.membership_id)
    .bind(i64::try_from(request.expected_revision).map_err(|_| TeamError::Conflict)?)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(map_database_error)?;
    let resource = retention_resource(row.ok_or(TeamError::Conflict)?)?;
    insert_audit(
        &mut transaction,
        principal,
        "organization.retention.updated",
        "organization_retention_policy",
        principal.workspace_id,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|_| TeamError::Unavailable)?;
    Ok(resource)
}

async fn select_retention_policy(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
) -> Result<OrganizationRetentionPolicyResource, TeamError> {
    let row: Option<StoredRetentionPolicy> = sqlx::query_as(
        "SELECT tenant_id, revision, minimum_watch_retention_days, \
                maximum_watch_retention_days, \
                (extract(epoch FROM updated_at) * 1000)::bigint AS updated_at_unix_ms \
         FROM organization_retention_policies \
         WHERE tenant_id = $1",
    )
    .bind(tenant_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| TeamError::Unavailable)?;
    retention_resource(row.ok_or(TeamError::Unavailable)?)
}

async fn load_review_page(
    pool: &PgPool,
    principal: &AuthenticatedPrincipal,
    page: PageRequest,
) -> Result<TransitionReviewPage, TeamError> {
    let mut transaction =
        auth::begin_authorized_transaction(pool, principal, ApiKeyScope::WatchRead).await?;
    ensure_review_cursor(&mut transaction, principal.workspace_id, page.after).await?;
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT review.id \
         FROM transition_reviews AS review \
         JOIN transitions AS transition \
           ON transition.tenant_id = review.tenant_id \
          AND transition.id = review.transition_id \
         WHERE review.tenant_id = $1 \
           AND NOT EXISTS (\
                SELECT 1 FROM deletion_resource_matches AS matched \
                WHERE matched.tenant_id = transition.tenant_id \
                  AND matched.resource_kind = 'transition' \
                  AND matched.resource_id = transition.id\
           ) \
           AND (\
                $2::uuid IS NULL \
                OR EXISTS (\
                    SELECT 1 FROM transition_reviews AS cursor \
                    JOIN transitions AS cursor_transition \
                      ON cursor_transition.tenant_id = cursor.tenant_id \
                     AND cursor_transition.id = cursor.transition_id \
                    WHERE cursor.tenant_id = $1 AND cursor.id = $2 \
                      AND NOT EXISTS (\
                          SELECT 1 FROM deletion_resource_matches AS matched \
                          WHERE matched.tenant_id = cursor_transition.tenant_id \
                            AND matched.resource_kind = 'transition' \
                            AND matched.resource_id = cursor_transition.id\
                      ) \
                      AND (review.updated_at, review.id) \
                          < (cursor.updated_at, cursor.id)\
                )\
           ) \
         ORDER BY review.updated_at DESC, review.id DESC \
         LIMIT $3",
    )
    .bind(principal.workspace_id)
    .bind(page.after)
    .bind(i64::try_from(page.limit + 1).map_err(|_| TeamError::Unavailable)?)
    .fetch_all(&mut *transaction)
    .await
    .map_err(|_| TeamError::Unavailable)?;
    let has_more = ids.len() > page.limit;
    let mut reviews = Vec::with_capacity(page.limit.min(ids.len()));
    for id in ids.into_iter().take(page.limit) {
        reviews.push(load_review_resource(&mut transaction, principal.workspace_id, id).await?);
    }
    let next_cursor = has_more
        .then(|| reviews.last())
        .flatten()
        .map(|review| review.review_id.clone());
    let resource = TransitionReviewPage {
        schema: ProtocolVersion::ApiV1,
        reviews,
        next_cursor,
    };
    resource.validate().map_err(|_| TeamError::Unavailable)?;
    transaction
        .commit()
        .await
        .map_err(|_| TeamError::Unavailable)?;
    Ok(resource)
}

async fn mutate_review(
    pool: &PgPool,
    principal: &AuthenticatedPrincipal,
    review_id: Uuid,
    request: TransitionReviewPatchRequest,
) -> Result<TransitionReviewResource, TeamError> {
    if !principal.role.can_handle_reviews() {
        return Err(TeamError::Forbidden);
    }
    let mut transaction =
        auth::begin_authorized_transaction(pool, principal, ApiKeyScope::WatchWrite).await?;
    let current: Option<StoredReviewLock> = sqlx::query_as(
        "SELECT review.state, review.revision, review.assigned_membership_id \
         FROM transition_reviews AS review \
         JOIN transitions AS transition \
           ON transition.tenant_id = review.tenant_id \
          AND transition.id = review.transition_id \
         WHERE review.tenant_id = $1 AND review.id = $2 \
           AND NOT EXISTS (\
                SELECT 1 FROM deletion_resource_matches AS matched \
                WHERE matched.tenant_id = transition.tenant_id \
                  AND matched.resource_kind = 'transition' \
                  AND matched.resource_id = transition.id\
           ) \
         FOR UPDATE OF review",
    )
    .bind(principal.workspace_id)
    .bind(review_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| TeamError::Unavailable)?;
    let current = current.ok_or(TeamError::NotFound)?;
    if u64::try_from(current.revision).ok() != Some(request.expected_revision) {
        return Err(TeamError::Conflict);
    }

    let (event_action, resolution) = match request.action {
        TransitionReviewAction::Assign { membership_id } => {
            if !matches!(
                principal.role,
                OrganizationRole::Owner | OrganizationRole::Administrator
            ) {
                return Err(TeamError::Forbidden);
            }
            if current.state != "open" {
                return Err(TeamError::Conflict);
            }
            let assignee_id =
                Uuid::parse_str(membership_id.as_str()).map_err(|_| TeamError::Unavailable)?;
            let eligible: bool = sqlx::query_scalar(
                "SELECT EXISTS(\
                    SELECT 1 FROM memberships \
                    WHERE tenant_id = $1 AND id = $2 AND state = 'active' \
                      AND role IN ('owner', 'administrator', 'member')\
                 )",
            )
            .bind(principal.workspace_id)
            .bind(assignee_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| TeamError::Unavailable)?;
            if !eligible || current.assigned_membership_id == Some(assignee_id) {
                return Err(TeamError::Conflict);
            }
            sqlx::query(
                "UPDATE transition_reviews \
                 SET assigned_membership_id = $3, revision = revision + 1, \
                     updated_at = clock_timestamp() \
                 WHERE tenant_id = $1 AND id = $2 AND revision = $4",
            )
            .bind(principal.workspace_id)
            .bind(review_id)
            .bind(assignee_id)
            .bind(current.revision)
            .execute(&mut *transaction)
            .await
            .map_err(map_database_error)?;
            ("assigned", None)
        }
        TransitionReviewAction::Acknowledge => {
            if current.state != "open"
                || current.assigned_membership_id != Some(principal.membership_id)
            {
                return Err(TeamError::Conflict);
            }
            sqlx::query(
                "UPDATE transition_reviews \
                 SET state = 'acknowledged', \
                     acknowledged_by_membership_id = $3, \
                     acknowledged_at = clock_timestamp(), \
                     revision = revision + 1, updated_at = clock_timestamp() \
                 WHERE tenant_id = $1 AND id = $2 AND revision = $4",
            )
            .bind(principal.workspace_id)
            .bind(review_id)
            .bind(principal.membership_id)
            .bind(current.revision)
            .execute(&mut *transaction)
            .await
            .map_err(map_database_error)?;
            ("acknowledged", None)
        }
        TransitionReviewAction::Resolve { resolution } => {
            if current.state != "acknowledged"
                || current.assigned_membership_id != Some(principal.membership_id)
            {
                return Err(TeamError::Conflict);
            }
            let resolution_value = review_resolution_value(resolution);
            sqlx::query(
                "UPDATE transition_reviews \
                 SET state = 'resolved', resolved_by_membership_id = $3, \
                     resolved_at = clock_timestamp(), resolution = $4, \
                     revision = revision + 1, updated_at = clock_timestamp() \
                 WHERE tenant_id = $1 AND id = $2 AND revision = $5",
            )
            .bind(principal.workspace_id)
            .bind(review_id)
            .bind(principal.membership_id)
            .bind(resolution_value)
            .bind(current.revision)
            .execute(&mut *transaction)
            .await
            .map_err(map_database_error)?;
            ("resolved", Some(resolution_value))
        }
    };

    let updated: StoredReviewEventProjection = sqlx::query_as(
        "SELECT state, assigned_membership_id \
         FROM transition_reviews \
         WHERE tenant_id = $1 AND id = $2",
    )
    .bind(principal.workspace_id)
    .bind(review_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| TeamError::Unavailable)?;
    sqlx::query(
        "INSERT INTO transition_review_events (\
            id, tenant_id, review_id, actor_membership_id, actor_api_key_id, \
            action, from_state, to_state, assigned_membership_id, resolution, \
            occurred_at\
         ) VALUES (\
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, clock_timestamp()\
         )",
    )
    .bind(Uuid::new_v4())
    .bind(principal.workspace_id)
    .bind(review_id)
    .bind(principal.membership_id)
    .bind(principal.api_key_id)
    .bind(event_action)
    .bind(current.state)
    .bind(updated.state)
    .bind(updated.assigned_membership_id)
    .bind(resolution)
    .execute(&mut *transaction)
    .await
    .map_err(map_database_error)?;
    insert_audit(
        &mut transaction,
        principal,
        match event_action {
            "assigned" => "transition.review.assigned",
            "acknowledged" => "transition.review.acknowledged",
            "resolved" => "transition.review.resolved",
            _ => return Err(TeamError::Unavailable),
        },
        "transition_review",
        review_id,
    )
    .await?;
    let resource =
        load_review_resource(&mut transaction, principal.workspace_id, review_id).await?;
    transaction
        .commit()
        .await
        .map_err(|_| TeamError::Unavailable)?;
    Ok(resource)
}

async fn load_review_resource(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    review_id: Uuid,
) -> Result<TransitionReviewResource, TeamError> {
    let row: Option<StoredReview> = sqlx::query_as(
        "SELECT review.id, review.transition_id, target.watch_id, \
                review.state, review.revision, review.assigned_membership_id, \
                review.acknowledged_by_membership_id, \
                (extract(epoch FROM review.acknowledged_at) * 1000)::bigint \
                    AS acknowledged_at_unix_ms, \
                review.resolved_by_membership_id, \
                (extract(epoch FROM review.resolved_at) * 1000)::bigint \
                    AS resolved_at_unix_ms, \
                review.resolution, \
                (extract(epoch FROM review.created_at) * 1000)::bigint \
                    AS created_at_unix_ms, \
                (extract(epoch FROM review.updated_at) * 1000)::bigint \
                    AS updated_at_unix_ms \
         FROM transition_reviews AS review \
         JOIN transitions AS transition \
           ON transition.tenant_id = review.tenant_id \
          AND transition.id = review.transition_id \
         JOIN watch_targets AS target \
           ON target.tenant_id = transition.tenant_id \
          AND target.id = transition.watch_target_id \
         WHERE review.tenant_id = $1 AND review.id = $2 \
           AND NOT EXISTS (\
                SELECT 1 FROM deletion_resource_matches AS matched \
                WHERE matched.tenant_id = transition.tenant_id \
                  AND matched.resource_kind = 'transition' \
                  AND matched.resource_id = transition.id\
           )",
    )
    .bind(tenant_id)
    .bind(review_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| TeamError::Unavailable)?;
    let row = row.ok_or(TeamError::NotFound)?;
    let transition =
        monitoring::load_transition_entry(transaction, tenant_id, row.watch_id, row.transition_id)
            .await
            .map_err(|_| TeamError::Unavailable)?
            .transition;
    let resource = TransitionReviewResource {
        schema: ProtocolVersion::ApiV1,
        review_id: TransitionReviewId::new(row.id.to_string())
            .map_err(|_| TeamError::Unavailable)?,
        transition,
        state: review_state(&row.state)?,
        revision: u64::try_from(row.revision).map_err(|_| TeamError::Unavailable)?,
        assigned_membership_id: optional_membership_id(row.assigned_membership_id)?,
        acknowledged_by_membership_id: optional_membership_id(row.acknowledged_by_membership_id)?,
        acknowledged_at_unix_ms: row.acknowledged_at_unix_ms,
        resolved_by_membership_id: optional_membership_id(row.resolved_by_membership_id)?,
        resolved_at_unix_ms: row.resolved_at_unix_ms,
        resolution: row
            .resolution
            .as_deref()
            .map(review_resolution)
            .transpose()?,
        created_at_unix_ms: row.created_at_unix_ms,
        updated_at_unix_ms: row.updated_at_unix_ms,
    };
    resource.validate().map_err(|_| TeamError::Unavailable)?;
    Ok(resource)
}

async fn ensure_member_cursor(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    cursor: Option<Uuid>,
) -> Result<(), TeamError> {
    ensure_cursor(
        transaction,
        tenant_id,
        cursor,
        "SELECT EXISTS(SELECT 1 FROM memberships WHERE tenant_id = $1 AND id = $2)",
    )
    .await
}

async fn ensure_audit_cursor(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    cursor: Option<Uuid>,
) -> Result<(), TeamError> {
    ensure_cursor(
        transaction,
        tenant_id,
        cursor,
        "SELECT EXISTS(SELECT 1 FROM audit_events WHERE tenant_id = $1 AND id = $2)",
    )
    .await
}

async fn ensure_review_cursor(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    cursor: Option<Uuid>,
) -> Result<(), TeamError> {
    let Some(cursor) = cursor else {
        return Ok(());
    };
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(\
            SELECT 1 \
            FROM transition_reviews AS review \
            JOIN transitions AS transition \
              ON transition.tenant_id = review.tenant_id \
             AND transition.id = review.transition_id \
            WHERE review.tenant_id = $1 AND review.id = $2 \
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
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| TeamError::Unavailable)?;
    if exists {
        Ok(())
    } else {
        Err(TeamError::InvalidRequest(
            "after",
            ValidationCode::InvalidRelation,
        ))
    }
}

async fn ensure_cursor(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    cursor: Option<Uuid>,
    statement: &'static str,
) -> Result<(), TeamError> {
    let Some(cursor) = cursor else {
        return Ok(());
    };
    let exists: bool = sqlx::query_scalar(statement)
        .bind(tenant_id)
        .bind(cursor)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|_| TeamError::Unavailable)?;
    if exists {
        Ok(())
    } else {
        Err(TeamError::InvalidRequest(
            "after",
            ValidationCode::InvalidRelation,
        ))
    }
}

async fn lock_tenant(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
) -> Result<(), TeamError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))")
        .bind(tenant_id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| TeamError::Unavailable)?;
    let active: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1 AND state = 'active')",
    )
    .bind(tenant_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| TeamError::Unavailable)?;
    if active {
        Ok(())
    } else {
        Err(TeamError::NotFound)
    }
}

async fn insert_audit(
    transaction: &mut Transaction<'_, Postgres>,
    principal: &AuthenticatedPrincipal,
    action: &'static str,
    resource_kind: &'static str,
    resource_id: Uuid,
) -> Result<(), TeamError> {
    sqlx::query(
        "INSERT INTO audit_events (\
            id, tenant_id, actor_api_key_id, action, resource_kind, \
            resource_id, occurred_at, details\
         ) VALUES ($1, $2, $3, $4, $5, $6, clock_timestamp(), '{}'::jsonb)",
    )
    .bind(Uuid::new_v4())
    .bind(principal.workspace_id)
    .bind(principal.api_key_id)
    .bind(action)
    .bind(resource_kind)
    .bind(resource_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| TeamError::Unavailable)?;
    Ok(())
}

fn organization_resource(row: StoredOrganization) -> Result<OrganizationResource, TeamError> {
    let organization_id =
        WorkspaceId::new(row.id.to_string()).map_err(|_| TeamError::Unavailable)?;
    let member = member_resource(
        row.id,
        StoredMember {
            id: row.membership_id,
            display_name: row.member_display_name,
            role: row.member_role,
            state: row.member_state,
            revision: row.revision,
            created_at_unix_ms: row.member_created_at_unix_ms,
            updated_at_unix_ms: row.member_updated_at_unix_ms,
        },
    )
    .map_err(|_| TeamError::Unavailable)?;
    let resource = OrganizationResource {
        schema: ProtocolVersion::ApiV1,
        organization_id,
        slug: row.slug,
        display_name: row.display_name,
        state: match row.state.as_str() {
            "active" => WorkspaceState::Active,
            "suspended" => WorkspaceState::Suspended,
            "deleting" => WorkspaceState::Deleting,
            _ => return Err(TeamError::Unavailable),
        },
        authenticated_member: member,
    };
    resource.validate().map_err(|_| TeamError::Unavailable)?;
    Ok(resource)
}

fn member_resource(
    tenant_id: Uuid,
    row: StoredMember,
) -> Result<OrganizationMemberResource, TeamError> {
    let resource = OrganizationMemberResource {
        schema: ProtocolVersion::ApiV1,
        organization_id: WorkspaceId::new(tenant_id.to_string())
            .map_err(|_| TeamError::Unavailable)?,
        membership_id: MembershipId::new(row.id.to_string()).map_err(|_| TeamError::Unavailable)?,
        display_name: row.display_name,
        role: OrganizationRole::parse(&row.role).map_err(|_| TeamError::Unavailable)?,
        state: member_state(&row.state)?,
        revision: u64::try_from(row.revision).map_err(|_| TeamError::Unavailable)?,
        created_at_unix_ms: row.created_at_unix_ms,
        updated_at_unix_ms: row.updated_at_unix_ms,
    };
    resource.validate().map_err(|_| TeamError::Unavailable)?;
    Ok(resource)
}

fn retention_resource(
    row: StoredRetentionPolicy,
) -> Result<OrganizationRetentionPolicyResource, TeamError> {
    let resource = OrganizationRetentionPolicyResource {
        schema: ProtocolVersion::ApiV1,
        organization_id: WorkspaceId::new(row.tenant_id.to_string())
            .map_err(|_| TeamError::Unavailable)?,
        revision: u64::try_from(row.revision).map_err(|_| TeamError::Unavailable)?,
        minimum_watch_retention_days: u16::try_from(row.minimum_watch_retention_days)
            .map_err(|_| TeamError::Unavailable)?,
        maximum_watch_retention_days: u16::try_from(row.maximum_watch_retention_days)
            .map_err(|_| TeamError::Unavailable)?,
        updated_at_unix_ms: row.updated_at_unix_ms,
    };
    resource.validate().map_err(|_| TeamError::Unavailable)?;
    Ok(resource)
}

fn audit_resource(row: StoredAuditEvent) -> Result<OrganizationAuditEventResource, TeamError> {
    let actor = match (row.actor_membership_id, row.actor_api_key_id) {
        (None, None) => OrganizationAuditActor::System,
        (Some(id), None) => OrganizationAuditActor::Membership {
            membership_id: MembershipId::new(id.to_string()).map_err(|_| TeamError::Unavailable)?,
        },
        (None, Some(id)) => OrganizationAuditActor::ApiKey {
            api_key_id: ApiKeyId::new(id.to_string()).map_err(|_| TeamError::Unavailable)?,
        },
        (Some(_), Some(_)) => return Err(TeamError::Unavailable),
    };
    let resource = OrganizationAuditEventResource {
        schema: ProtocolVersion::ApiV1,
        audit_event_id: AuditEventId::new(row.id.to_string())
            .map_err(|_| TeamError::Unavailable)?,
        actor,
        action: row.action,
        resource_kind: row.resource_kind,
        resource_id: row
            .resource_id
            .map(|id| AuditResourceId::new(id.to_string()))
            .transpose()
            .map_err(|_| TeamError::Unavailable)?,
        occurred_at_unix_ms: row.occurred_at_unix_ms,
    };
    resource.validate().map_err(|_| TeamError::Unavailable)?;
    Ok(resource)
}

const fn member_state(value: &str) -> Result<OrganizationMemberState, TeamError> {
    match value.as_bytes() {
        b"active" => Ok(OrganizationMemberState::Active),
        b"suspended" => Ok(OrganizationMemberState::Suspended),
        b"removed" => Ok(OrganizationMemberState::Removed),
        _ => Err(TeamError::Unavailable),
    }
}

const fn review_state(value: &str) -> Result<TransitionReviewState, TeamError> {
    match value.as_bytes() {
        b"open" => Ok(TransitionReviewState::Open),
        b"acknowledged" => Ok(TransitionReviewState::Acknowledged),
        b"resolved" => Ok(TransitionReviewState::Resolved),
        _ => Err(TeamError::Unavailable),
    }
}

const fn review_resolution(value: &str) -> Result<TransitionReviewResolution, TeamError> {
    match value.as_bytes() {
        b"action_taken" => Ok(TransitionReviewResolution::ActionTaken),
        b"no_action_required" => Ok(TransitionReviewResolution::NoActionRequired),
        b"measurement_follow_up" => Ok(TransitionReviewResolution::MeasurementFollowUp),
        b"externally_escalated" => Ok(TransitionReviewResolution::ExternallyEscalated),
        _ => Err(TeamError::Unavailable),
    }
}

const fn review_resolution_value(value: TransitionReviewResolution) -> &'static str {
    match value {
        TransitionReviewResolution::ActionTaken => "action_taken",
        TransitionReviewResolution::NoActionRequired => "no_action_required",
        TransitionReviewResolution::MeasurementFollowUp => "measurement_follow_up",
        TransitionReviewResolution::ExternallyEscalated => "externally_escalated",
    }
}

fn optional_membership_id(value: Option<Uuid>) -> Result<Option<MembershipId>, TeamError> {
    value
        .map(|id| MembershipId::new(id.to_string()))
        .transpose()
        .map_err(|_| TeamError::Unavailable)
}

fn can_manage_role(actor: OrganizationRole, target: OrganizationRole) -> bool {
    match actor {
        OrganizationRole::Owner => true,
        OrganizationRole::Administrator => {
            matches!(target, OrganizationRole::Member | OrganizationRole::Viewer)
        }
        OrganizationRole::Member | OrganizationRole::Viewer => false,
    }
}

fn can_manage_target(actor: OrganizationRole, target: OrganizationRole) -> bool {
    match actor {
        OrganizationRole::Owner => true,
        OrganizationRole::Administrator => {
            matches!(target, OrganizationRole::Member | OrganizationRole::Viewer)
        }
        OrganizationRole::Member | OrganizationRole::Viewer => false,
    }
}

fn require_member_manager(principal: &AuthenticatedPrincipal) -> Result<(), TeamError> {
    if principal.role.can_manage_members() {
        Ok(())
    } else {
        Err(TeamError::Forbidden)
    }
}

fn parse_uuid(value: &str, field: &'static str) -> Result<Uuid, TeamError> {
    Uuid::parse_str(value)
        .map_err(|_| TeamError::InvalidRequest(field, ValidationCode::InvalidFormat))
}

fn map_database_error(error: sqlx::Error) -> TeamError {
    let conflict = error
        .as_database_error()
        .and_then(|database| database.code())
        .is_some_and(|code| matches!(code.as_ref(), "23503" | "23505" | "23514" | "55000"));
    if conflict {
        TeamError::Conflict
    } else {
        TeamError::Unavailable
    }
}

fn map_provision_database_error(error: sqlx::Error) -> TeamError {
    if error
        .as_database_error()
        .and_then(|database| database.code())
        .is_some_and(|code| code.as_ref() == "42501")
    {
        TeamError::Forbidden
    } else {
        map_database_error(error)
    }
}

fn error_response(request_id: RequestId, error: TeamError) -> Response {
    match error {
        TeamError::InvalidRequest(field, code) => (
            StatusCode::BAD_REQUEST,
            Json(socialname_protocol::ApiErrorResponse::invalid_request(
                request_id,
                ValidationErrors::new(field, code),
            )),
        )
            .into_response(),
        TeamError::InvalidBody(errors) => (
            StatusCode::BAD_REQUEST,
            Json(socialname_protocol::ApiErrorResponse::invalid_request(
                request_id, errors,
            )),
        )
            .into_response(),
        TeamError::NotFound => crate::api_error_response(
            StatusCode::NOT_FOUND,
            request_id,
            standard_api_error(ApiErrorCode::NotFound, false),
        ),
        TeamError::Conflict => crate::api_error_response(
            StatusCode::CONFLICT,
            request_id,
            standard_api_error(ApiErrorCode::Conflict, false),
        ),
        TeamError::Forbidden | TeamError::Authentication(AuthenticationError::Forbidden) => {
            crate::api_error_response(
                StatusCode::FORBIDDEN,
                request_id,
                standard_api_error(ApiErrorCode::Forbidden, false),
            )
        }
        TeamError::Authentication(AuthenticationError::InvalidCredential) => {
            unauthenticated_response(request_id)
        }
        TeamError::Authentication(AuthenticationError::Unavailable) | TeamError::Unavailable => {
            crate::api_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                request_id,
                standard_api_error(ApiErrorCode::Unavailable, true),
            )
        }
    }
}

#[derive(FromRow)]
struct StoredOrganization {
    id: Uuid,
    slug: String,
    display_name: String,
    state: String,
    membership_id: Uuid,
    member_display_name: String,
    member_role: String,
    member_state: String,
    revision: i64,
    member_created_at_unix_ms: i64,
    member_updated_at_unix_ms: i64,
}

#[derive(FromRow)]
struct StoredMember {
    id: Uuid,
    display_name: String,
    role: String,
    state: String,
    revision: i64,
    created_at_unix_ms: i64,
    updated_at_unix_ms: i64,
}

#[derive(FromRow)]
struct StoredProvisionedMember {
    #[sqlx(flatten)]
    member: StoredMember,
    was_existing: bool,
}

#[derive(FromRow)]
struct StoredRetentionPolicy {
    tenant_id: Uuid,
    revision: i64,
    minimum_watch_retention_days: i16,
    maximum_watch_retention_days: i16,
    updated_at_unix_ms: i64,
}

#[derive(FromRow)]
struct StoredAuditEvent {
    id: Uuid,
    actor_membership_id: Option<Uuid>,
    actor_api_key_id: Option<Uuid>,
    action: String,
    resource_kind: String,
    resource_id: Option<Uuid>,
    occurred_at_unix_ms: i64,
}

#[derive(FromRow)]
struct StoredReview {
    id: Uuid,
    transition_id: Uuid,
    watch_id: Uuid,
    state: String,
    revision: i64,
    assigned_membership_id: Option<Uuid>,
    acknowledged_by_membership_id: Option<Uuid>,
    acknowledged_at_unix_ms: Option<i64>,
    resolved_by_membership_id: Option<Uuid>,
    resolved_at_unix_ms: Option<i64>,
    resolution: Option<String>,
    created_at_unix_ms: i64,
    updated_at_unix_ms: i64,
}

#[derive(FromRow)]
struct StoredReviewLock {
    state: String,
    revision: i64,
    assigned_membership_id: Option<Uuid>,
}

#[derive(FromRow)]
struct StoredReviewEventProjection {
    state: String,
    assigned_membership_id: Option<Uuid>,
}

#[derive(Debug, thiserror::Error)]
enum TeamError {
    #[error("team request is invalid")]
    InvalidRequest(&'static str, ValidationCode),
    #[error("team request body is invalid")]
    InvalidBody(ValidationErrors),
    #[error("team resource was not found")]
    NotFound,
    #[error("team resource revision or state conflicts")]
    Conflict,
    #[error("team role does not grant this operation")]
    Forbidden,
    #[error(transparent)]
    Authentication(#[from] AuthenticationError),
    #[error("team storage is unavailable")]
    Unavailable,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manager_matrix_separates_owner_and_administrator_targets() {
        assert!(can_manage_role(
            OrganizationRole::Owner,
            OrganizationRole::Owner
        ));
        assert!(!can_manage_role(
            OrganizationRole::Administrator,
            OrganizationRole::Administrator
        ));
        assert!(can_manage_role(
            OrganizationRole::Administrator,
            OrganizationRole::Member
        ));
        assert!(!can_manage_role(
            OrganizationRole::Member,
            OrganizationRole::Viewer
        ));
    }

    #[test]
    fn database_conflicts_are_not_reflected() {
        let private = "private-member-id";
        let error = parse_uuid(private, "membership_id").unwrap_err();
        assert!(!error.to_string().contains(private));
    }
}
