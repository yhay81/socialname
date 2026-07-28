GRANT USAGE ON SCHEMA public TO {role};
GRANT SELECT ON tenants TO {role};
GRANT SELECT (
    id, tenant_id, display_name, role, state, revision,
    created_at, updated_at
) ON memberships TO {role};
GRANT SELECT ON api_keys TO {role};
GRANT UPDATE (last_used_at, state, revoked_at) ON api_keys
    TO {role};
GRANT SELECT ON
    sites, clients, consent_grants, consent_events,
    searches, search_targets, search_events,
    watches, watch_targets, watch_notification_endpoints,
    search_completion_webhooks,
    notification_endpoints, watch_runs, watch_run_targets,
    transitions, transition_basis, notification_deliveries,
    notification_acknowledgements,
    rule_versions, rule_health_records, evidence_capsules,
    suppression_tokens,
    deletion_requests, deletion_tasks, deletion_receipts,
    deletion_resource_matches, observations,
    data_lineage_edges, probe_jobs, probe_job_consumers,
    developer_quota_policies, developer_usage_records,
    organization_retention_policies, transition_reviews,
    shared_contributions, contribution_sequences,
    contribution_quota_counters, contributor_reputation
    TO {role};
GRANT SELECT (
    id, tenant_id, actor_membership_id, actor_api_key_id,
    action, resource_kind, resource_id, occurred_at
) ON audit_events TO {role};
GRANT SELECT (
    tenant_id, plan_code, access_state, revision,
    effective_at, access_until, updated_at
) ON tenant_plan_entitlements TO {role};
GRANT INSERT ON
    clients, consent_grants, consent_events,
    searches, search_targets, search_events, watches, watch_targets,
    watch_notification_endpoints, search_completion_webhooks,
    deletion_requests, deletion_tasks,
    suppression_tokens, deletion_resource_matches,
    notification_acknowledgements, audit_events,
    developer_usage_records, transition_review_events,
    shared_contributions, contribution_sequences,
    contribution_quota_counters, contributor_reputation
    TO {role};
GRANT UPDATE (
    high_water, replay_violations, last_violation_at, updated_at
) ON contribution_sequences TO {role};
GRANT UPDATE (accepted_count) ON contribution_quota_counters
    TO {role};
GRANT UPDATE (
    tier, revision, active_days, last_active_day, suspended_at,
    suspension_reason, updated_at
) ON contributor_reputation TO {role};
GRANT UPDATE (last_seen_at) ON clients
    TO {role};
GRANT UPDATE (role, state, revision, updated_at) ON memberships
    TO {role};
GRANT UPDATE (
    revision, minimum_watch_retention_days,
    maximum_watch_retention_days, updated_by_membership_id, updated_at
) ON organization_retention_policies
    TO {role};
GRANT UPDATE (
    state, revision, assigned_membership_id,
    acknowledged_by_membership_id, acknowledged_at,
    resolved_by_membership_id, resolved_at, resolution, updated_at
) ON transition_reviews TO {role};
GRANT UPDATE (withdrawn_at) ON consent_grants
    TO {role};
GRANT UPDATE (
    state, next_attempt_at, delivered_at, last_error_code,
    lease_owner, lease_started_at, lease_expires_at
) ON notification_deliveries TO {role};
GRANT UPDATE (state, cancelled_at) ON search_completion_webhooks
    TO {role};
GRANT UPDATE (state, updated_at, completed_at) ON searches
    TO {role};
GRANT UPDATE (state, completed_at) ON search_targets
    TO {role};
GRANT UPDATE (
    state, revision, maximum_age_ms, interval_seconds, jitter_percent,
    maximum_probes_per_run, maximum_bytes_per_run, retention_days,
    next_run_at, updated_at
) ON watches TO {role};
GRANT UPDATE (retired_at) ON watch_targets
    TO {role};
GRANT UPDATE (state, completed_at) ON watch_runs, watch_run_targets
    TO {role};
GRANT DELETE ON watch_notification_endpoints
    TO {role};
GRANT EXECUTE ON FUNCTION socialname_authenticate_api_key(text, bytea)
    TO {role};
GRANT EXECUTE ON FUNCTION socialname_lock_developer_quota(uuid)
    TO {role};
GRANT EXECUTE ON FUNCTION socialname_has_plan_capability(uuid, text)
    TO {role};
GRANT EXECUTE ON FUNCTION socialname_provision_organization_member(
    uuid, uuid, uuid, text, text, text
) TO {role};
GRANT EXECUTE ON FUNCTION
    socialname_redact_deletion_job_targets(uuid, uuid)
    TO {role};
GRANT EXECUTE ON FUNCTION socialname_restore_ledger_ready(uuid)
    TO {role};
