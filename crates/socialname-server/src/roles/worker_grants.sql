GRANT USAGE ON SCHEMA public TO {role};
GRANT SELECT ON
    consent_grants, searches, search_targets, search_events, probe_jobs,
    probe_job_consumers, data_lineage_edges, audit_events,
    rule_versions, watches, watch_targets,
    watch_notification_endpoints, search_completion_webhooks,
    notification_endpoints, watch_runs,
    watch_run_targets, observations, assertions, assertion_support,
    regional_assertions, regional_assertion_support, transitions,
    transition_basis, notification_deliveries,
    notification_delivery_attempts, evidence_capsules,
    evidence_retention_receipts, deletion_requests,
    deletion_resource_matches, deletion_tasks, suppression_tokens,
    shared_contributions, contribution_validations,
    contributor_reputation
    TO {role};
GRANT INSERT ON
    search_events, probe_jobs, probe_job_consumers, observations,
    assertions, assertion_support, regional_assertions,
    regional_assertion_support, transitions, transition_basis,
    notification_deliveries, notification_delivery_attempts,
    audit_events, data_lineage_edges, watch_runs, watch_run_targets,
    evidence_capsules
    TO {role};
GRANT UPDATE (state, updated_at, completed_at) ON searches
    TO {role};
GRANT UPDATE (
    requested_username, normalized_username, state, completed_at
) ON search_targets
    TO {role};
GRANT UPDATE (next_run_at, updated_at) ON watches
    TO {role};
GRANT UPDATE (
    normalized_username, account_state, account_assertion_id,
    account_state_since
) ON watch_targets
    TO {role};
GRANT UPDATE (is_current) ON assertions
    TO {role};
GRANT UPDATE (is_current, withdrawn_at) ON assertions
    TO {role};
GRANT UPDATE (
    confirmation_status, confirmation_basis, pending_reason,
    suppression_reason
) ON transitions TO {role};
GRANT UPDATE (state, reserved_bytes, completed_at) ON watch_runs
    TO {role};
GRANT UPDATE (
    state, probe_job_id, observation_id, observation_deleted_at,
    reserved_bytes, completed_at
) ON watch_run_targets TO {role};
GRANT UPDATE (
    normalized_username, work_key_hash, state, attempt_count,
    available_at, lease_owner, lease_expires_at, last_error_code,
    priority, updated_at, completed_at
) ON probe_jobs TO {role};
GRANT UPDATE (
    state, attempt_count, next_attempt_at, delivered_at,
    last_error_code, lease_owner, lease_started_at, lease_expires_at
) ON notification_deliveries TO {role};
GRANT UPDATE (
    state, support_withdrawn_at, primary_completed_at,
    lease_owner, lease_expires_at, last_error_code
) ON deletion_requests TO {role};
GRANT UPDATE (support_withdrawn_at, primary_deleted_at)
    ON deletion_resource_matches TO {role};
GRANT UPDATE (
    state, attempt_count, completed_at, last_error_code
) ON deletion_tasks TO {role};
GRANT DELETE ON
    assertion_support, regional_assertion_support,
    transition_basis, notification_delivery_attempts,
    notification_deliveries, transitions, regional_assertions,
    assertions, evidence_retention_receipts, evidence_capsules,
    search_events, observations, shared_contributions,
    contribution_validations, data_lineage_edges
    TO {role};
GRANT UPDATE (
    validated_overlaps, agreement_hits, agreement_misses,
    revision, updated_at
) ON contributor_reputation TO {role};
GRANT EXECUTE ON FUNCTION
    socialname_worker_resolve_rule(
        text, bytea, bytea, text, bytea, bigint, bytea, bigint
    ),
    socialname_worker_rule_version_available(uuid, text),
    socialname_worker_lock_next_target(uuid, text),
    socialname_worker_lock_due_watch(uuid, text),
    socialname_worker_lock_next_watch_target(uuid, text),
    socialname_worker_claim_job(uuid, text, text, integer),
    socialname_worker_lock_claim_consent(uuid, integer, text),
    socialname_worker_claim_webhook_delivery(text, integer, integer),
    socialname_worker_claim_email_delivery(text, integer, integer),
    socialname_worker_enforce_evidence_retention(integer),
    socialname_worker_enforce_developer_usage_retention(integer),
    socialname_worker_validate_contributions(integer),
    socialname_worker_derive_shared_assertions(integer),
    socialname_worker_withdraw_shared_support(uuid, uuid),
    socialname_worker_claim_deletion(text, integer)
    TO {role};
