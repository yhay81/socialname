CREATE FUNCTION socialname_current_tenant_id()
RETURNS uuid
LANGUAGE sql
STABLE
AS $$
    SELECT NULLIF(current_setting('socialname.tenant_id', true), '')::uuid
$$;

CREATE FUNCTION socialname_reject_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME USING ERRCODE = '55000';
END
$$;

CREATE TABLE tenants (
    id uuid PRIMARY KEY,
    slug text NOT NULL UNIQUE,
    display_name text NOT NULL,
    state text NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT tenants_slug_format CHECK (
        length(slug) BETWEEN 1 AND 63
        AND slug ~ '^[a-z0-9]+(?:-[a-z0-9]+)*$'
    ),
    CONSTRAINT tenants_display_name_bound CHECK (length(display_name) BETWEEN 1 AND 200),
    CONSTRAINT tenants_state_closed CHECK (state IN ('active', 'suspended', 'deleting')),
    CONSTRAINT tenants_time_order CHECK (updated_at >= created_at)
);

CREATE TABLE memberships (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    subject_id text NOT NULL,
    role text NOT NULL,
    state text NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, subject_id),
    CONSTRAINT memberships_subject_bound CHECK (length(subject_id) BETWEEN 1 AND 200),
    CONSTRAINT memberships_role_closed CHECK (role IN ('owner', 'administrator', 'member', 'viewer')),
    CONSTRAINT memberships_state_closed CHECK (state IN ('active', 'suspended', 'removed')),
    CONSTRAINT memberships_time_order CHECK (updated_at >= created_at)
);

CREATE TABLE api_keys (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    created_by_membership_id uuid NOT NULL,
    key_prefix text NOT NULL,
    secret_hash bytea NOT NULL,
    scopes text[] NOT NULL,
    state text NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL,
    expires_at timestamptz,
    revoked_at timestamptz,
    last_used_at timestamptz,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, key_prefix),
    UNIQUE (secret_hash),
    FOREIGN KEY (tenant_id, created_by_membership_id)
        REFERENCES memberships(tenant_id, id),
    CONSTRAINT api_keys_prefix_bound CHECK (length(key_prefix) BETWEEN 8 AND 32),
    CONSTRAINT api_keys_hash_sha256 CHECK (octet_length(secret_hash) = 32),
    CONSTRAINT api_keys_scopes_nonempty CHECK (
        cardinality(scopes) BETWEEN 1 AND 16
        AND scopes <@ ARRAY[
            'search:read', 'search:write', 'watch:read', 'watch:write',
            'notification:read', 'notification:write', 'data:export', 'data:delete'
        ]::text[]
    ),
    CONSTRAINT api_keys_state_closed CHECK (state IN ('active', 'revoked', 'expired')),
    CONSTRAINT api_keys_expiry_order CHECK (expires_at IS NULL OR expires_at > created_at),
    CONSTRAINT api_keys_revocation_relation CHECK (
        (state = 'revoked' AND revoked_at IS NOT NULL)
        OR (state <> 'revoked' AND revoked_at IS NULL)
    )
);

CREATE TABLE clients (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    installation_hash bytea NOT NULL,
    state text NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL,
    last_seen_at timestamptz,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, installation_hash),
    CONSTRAINT clients_hash_sha256 CHECK (octet_length(installation_hash) = 32),
    CONSTRAINT clients_state_closed CHECK (state IN ('active', 'suspended', 'deleted')),
    CONSTRAINT clients_seen_order CHECK (last_seen_at IS NULL OR last_seen_at >= created_at)
);

CREATE TABLE sites (
    id text PRIMARY KEY,
    display_name text NOT NULL,
    state text NOT NULL DEFAULT 'discovery',
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT sites_id_format CHECK (
        length(id) BETWEEN 1 AND 64
        AND id ~ '^[a-z0-9]+(?:-[a-z0-9]+)*$'
    ),
    CONSTRAINT sites_display_name_bound CHECK (length(display_name) BETWEEN 1 AND 200),
    CONSTRAINT sites_state_closed CHECK (state IN ('discovery', 'promoted', 'quarantined', 'retired')),
    CONSTRAINT sites_time_order CHECK (updated_at >= created_at)
);

CREATE TABLE rule_packs (
    id uuid PRIMARY KEY,
    version text NOT NULL UNIQUE,
    pack_hash bytea NOT NULL UNIQUE,
    previous_pack_hash bytea,
    state text NOT NULL,
    created_at timestamptz NOT NULL,
    published_at timestamptz,
    expires_at timestamptz,
    CONSTRAINT rule_packs_version_bound CHECK (length(version) BETWEEN 1 AND 100),
    CONSTRAINT rule_packs_hash_sha256 CHECK (octet_length(pack_hash) = 32),
    CONSTRAINT rule_packs_previous_hash CHECK (
        previous_pack_hash IS NULL OR octet_length(previous_pack_hash) = 32
    ),
    CONSTRAINT rule_packs_state_closed CHECK (state IN ('staged', 'active', 'retired', 'rejected')),
    CONSTRAINT rule_packs_publication_relation CHECK (
        (state IN ('active', 'retired') AND published_at IS NOT NULL)
        OR (state IN ('staged', 'rejected') AND published_at IS NULL)
    ),
    CONSTRAINT rule_packs_expiry_order CHECK (expires_at IS NULL OR expires_at > created_at)
);

CREATE TABLE rule_versions (
    id uuid PRIMARY KEY,
    rule_pack_id uuid NOT NULL REFERENCES rule_packs(id),
    site_id text NOT NULL REFERENCES sites(id),
    rule_hash bytea NOT NULL,
    compiled_rule jsonb NOT NULL,
    enabled boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL,
    UNIQUE (rule_pack_id, site_id),
    UNIQUE (site_id, rule_hash),
    CONSTRAINT rule_versions_hash_sha256 CHECK (octet_length(rule_hash) = 32),
    CONSTRAINT rule_versions_compiled_object CHECK (
        jsonb_typeof(compiled_rule) = 'object'
        AND octet_length(compiled_rule::text) <= 262144
    )
);

CREATE TABLE rule_health_records (
    id uuid PRIMARY KEY,
    rule_version_id uuid NOT NULL REFERENCES rule_versions(id),
    region_class text NOT NULL,
    state text NOT NULL,
    evidence_id uuid NOT NULL,
    evidence_expires_at timestamptz NOT NULL,
    summary jsonb NOT NULL,
    recorded_at timestamptz NOT NULL,
    UNIQUE (rule_version_id, region_class, recorded_at),
    CONSTRAINT rule_health_region_bound CHECK (length(region_class) BETWEEN 1 AND 64),
    CONSTRAINT rule_health_state_closed CHECK (
        state IN ('healthy', 'degraded', 'quarantined', 'recovering')
    ),
    CONSTRAINT rule_health_summary_object CHECK (
        jsonb_typeof(summary) = 'object' AND octet_length(summary::text) <= 32768
    ),
    CONSTRAINT rule_health_expiry_order CHECK (evidence_expires_at > recorded_at)
);

CREATE TABLE consent_grants (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    membership_id uuid,
    client_id uuid,
    subject_kind text NOT NULL,
    purpose text NOT NULL,
    collection_profile_version text NOT NULL,
    notice_version text NOT NULL,
    source text NOT NULL,
    granted_at timestamptz NOT NULL,
    expires_at timestamptz,
    withdrawn_at timestamptz,
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, membership_id) REFERENCES memberships(tenant_id, id),
    FOREIGN KEY (tenant_id, client_id) REFERENCES clients(tenant_id, id),
    CONSTRAINT consent_subject_relation CHECK (
        (subject_kind = 'account' AND membership_id IS NOT NULL AND client_id IS NULL)
        OR (subject_kind = 'installation' AND membership_id IS NULL AND client_id IS NOT NULL)
    ),
    CONSTRAINT consent_purpose_closed CHECK (
        purpose IN ('private_history', 'shared_observation', 'shared_research')
    ),
    CONSTRAINT consent_source_closed CHECK (source IN ('cli', 'web', 'api')),
    CONSTRAINT consent_versions_bound CHECK (
        length(collection_profile_version) BETWEEN 1 AND 100
        AND length(notice_version) BETWEEN 1 AND 100
    ),
    CONSTRAINT consent_expiry_order CHECK (expires_at IS NULL OR expires_at > granted_at),
    CONSTRAINT consent_withdrawal_order CHECK (withdrawn_at IS NULL OR withdrawn_at >= granted_at)
);

CREATE TABLE consent_events (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    consent_grant_id uuid NOT NULL,
    event_kind text NOT NULL,
    actor_membership_id uuid,
    occurred_at timestamptz NOT NULL,
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, consent_grant_id) REFERENCES consent_grants(tenant_id, id),
    FOREIGN KEY (tenant_id, actor_membership_id) REFERENCES memberships(tenant_id, id),
    CONSTRAINT consent_events_kind_closed CHECK (event_kind IN ('granted', 'withdrawn', 'expired')),
    CONSTRAINT consent_events_details_object CHECK (
        jsonb_typeof(details) = 'object' AND octet_length(details::text) <= 8192
    )
);

CREATE TABLE searches (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    requested_by_membership_id uuid,
    requested_by_api_key_id uuid,
    idempotency_key_hash bytea NOT NULL,
    mode text NOT NULL,
    sync_policy text NOT NULL,
    consent_grant_id uuid,
    maximum_age_ms bigint NOT NULL,
    region_classes text[] NOT NULL,
    state text NOT NULL DEFAULT 'accepted',
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    completed_at timestamptz,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, idempotency_key_hash),
    FOREIGN KEY (tenant_id, requested_by_membership_id) REFERENCES memberships(tenant_id, id),
    FOREIGN KEY (tenant_id, requested_by_api_key_id) REFERENCES api_keys(tenant_id, id),
    FOREIGN KEY (tenant_id, consent_grant_id) REFERENCES consent_grants(tenant_id, id),
    CONSTRAINT searches_actor_relation CHECK (
        (requested_by_membership_id IS NOT NULL)::integer
        + (requested_by_api_key_id IS NOT NULL)::integer = 1
    ),
    CONSTRAINT searches_idempotency_hash CHECK (octet_length(idempotency_key_hash) = 32),
    CONSTRAINT searches_mode_closed CHECK (mode IN ('local', 'cache', 'remote', 'hybrid')),
    CONSTRAINT searches_sync_closed CHECK (sync_policy IN ('never', 'private', 'shared')),
    CONSTRAINT searches_consent_relation CHECK (
        (sync_policy = 'never' AND consent_grant_id IS NULL)
        OR (sync_policy IN ('private', 'shared') AND consent_grant_id IS NOT NULL)
    ),
    CONSTRAINT searches_maximum_age_bound CHECK (maximum_age_ms BETWEEN 1 AND 2592000000),
    CONSTRAINT searches_regions_bound CHECK (cardinality(region_classes) BETWEEN 1 AND 8),
    CONSTRAINT searches_state_closed CHECK (
        state IN ('accepted', 'running', 'completed', 'cancelled', 'failed')
    ),
    CONSTRAINT searches_time_order CHECK (
        updated_at >= created_at
        AND (completed_at IS NULL OR completed_at >= created_at)
    ),
    CONSTRAINT searches_completion_relation CHECK (
        (state IN ('completed', 'cancelled', 'failed') AND completed_at IS NOT NULL)
        OR (state IN ('accepted', 'running') AND completed_at IS NULL)
    )
);

CREATE TABLE search_targets (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    search_id uuid NOT NULL,
    normalized_username text NOT NULL,
    site_id text NOT NULL REFERENCES sites(id),
    ordinal integer NOT NULL,
    state text NOT NULL DEFAULT 'pending',
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, search_id, normalized_username, site_id),
    UNIQUE (tenant_id, search_id, ordinal),
    FOREIGN KEY (tenant_id, search_id) REFERENCES searches(tenant_id, id),
    CONSTRAINT search_targets_username_bound CHECK (
        octet_length(normalized_username) BETWEEN 1 AND 256
        AND normalized_username !~ '[[:cntrl:]]'
    ),
    CONSTRAINT search_targets_ordinal_nonnegative CHECK (ordinal >= 0),
    CONSTRAINT search_targets_state_closed CHECK (
        state IN ('pending', 'running', 'completed', 'cancelled', 'failed')
    ),
    CONSTRAINT search_targets_completion_relation CHECK (
        (state IN ('completed', 'cancelled', 'failed') AND completed_at IS NOT NULL)
        OR (state IN ('pending', 'running') AND completed_at IS NULL)
    )
);

CREATE TABLE watches (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    created_by_membership_id uuid NOT NULL,
    consent_grant_id uuid NOT NULL,
    state text NOT NULL DEFAULT 'active',
    revision bigint NOT NULL DEFAULT 1,
    maximum_age_ms bigint NOT NULL,
    interval_seconds integer NOT NULL,
    jitter_percent smallint NOT NULL,
    maximum_probes_per_run integer NOT NULL,
    maximum_bytes_per_run bigint NOT NULL,
    retention_days smallint NOT NULL,
    region_classes text[] NOT NULL,
    next_run_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, created_by_membership_id) REFERENCES memberships(tenant_id, id),
    FOREIGN KEY (tenant_id, consent_grant_id) REFERENCES consent_grants(tenant_id, id),
    CONSTRAINT watches_state_closed CHECK (state IN ('active', 'paused', 'deleting')),
    CONSTRAINT watches_revision_positive CHECK (revision > 0),
    CONSTRAINT watches_age_bound CHECK (maximum_age_ms BETWEEN 1 AND 2592000000),
    CONSTRAINT watches_interval_bound CHECK (interval_seconds BETWEEN 300 AND 2678400),
    CONSTRAINT watches_jitter_bound CHECK (jitter_percent BETWEEN 0 AND 20),
    CONSTRAINT watches_probe_bound CHECK (maximum_probes_per_run BETWEEN 1 AND 256),
    CONSTRAINT watches_byte_bound CHECK (maximum_bytes_per_run BETWEEN 1024 AND 67108864),
    CONSTRAINT watches_retention_bound CHECK (retention_days BETWEEN 30 AND 730),
    CONSTRAINT watches_regions_bound CHECK (cardinality(region_classes) BETWEEN 1 AND 8),
    CONSTRAINT watches_next_run_relation CHECK (
        (state = 'active' AND next_run_at IS NOT NULL AND next_run_at > updated_at)
        OR (state IN ('paused', 'deleting') AND next_run_at IS NULL)
    ),
    CONSTRAINT watches_time_order CHECK (updated_at >= created_at)
);

CREATE TABLE watch_targets (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    watch_id uuid NOT NULL,
    normalized_username text NOT NULL,
    site_id text NOT NULL REFERENCES sites(id),
    created_at timestamptz NOT NULL,
    retired_at timestamptz,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, watch_id, normalized_username, site_id),
    FOREIGN KEY (tenant_id, watch_id) REFERENCES watches(tenant_id, id),
    CONSTRAINT watch_targets_username_bound CHECK (
        octet_length(normalized_username) BETWEEN 1 AND 256
        AND normalized_username !~ '[[:cntrl:]]'
    ),
    CONSTRAINT watch_targets_retirement_order CHECK (retired_at IS NULL OR retired_at >= created_at)
);

CREATE TABLE probe_jobs (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    normalized_username text NOT NULL,
    site_id text NOT NULL REFERENCES sites(id),
    rule_version_id uuid NOT NULL REFERENCES rule_versions(id),
    region_class text NOT NULL,
    work_key_hash bytea NOT NULL,
    state text NOT NULL DEFAULT 'queued',
    priority smallint NOT NULL DEFAULT 0,
    attempt_count integer NOT NULL DEFAULT 0,
    available_at timestamptz NOT NULL,
    lease_owner text,
    lease_expires_at timestamptz,
    last_error_code text,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    completed_at timestamptz,
    UNIQUE (tenant_id, id),
    CONSTRAINT probe_jobs_username_bound CHECK (octet_length(normalized_username) BETWEEN 1 AND 256),
    CONSTRAINT probe_jobs_region_bound CHECK (length(region_class) BETWEEN 1 AND 64),
    CONSTRAINT probe_jobs_work_hash CHECK (octet_length(work_key_hash) = 32),
    CONSTRAINT probe_jobs_state_closed CHECK (
        state IN ('queued', 'leased', 'succeeded', 'retry_wait', 'failed', 'cancelled')
    ),
    CONSTRAINT probe_jobs_attempt_nonnegative CHECK (attempt_count >= 0),
    CONSTRAINT probe_jobs_lease_relation CHECK (
        (state = 'leased' AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)
        OR (state <> 'leased' AND lease_owner IS NULL AND lease_expires_at IS NULL)
    ),
    CONSTRAINT probe_jobs_completion_relation CHECK (
        (state IN ('succeeded', 'failed', 'cancelled') AND completed_at IS NOT NULL)
        OR (state IN ('queued', 'leased', 'retry_wait') AND completed_at IS NULL)
    ),
    CONSTRAINT probe_jobs_time_order CHECK (
        updated_at >= created_at AND (completed_at IS NULL OR completed_at >= created_at)
    )
);

CREATE UNIQUE INDEX probe_jobs_one_active_work
ON probe_jobs (tenant_id, work_key_hash)
WHERE state IN ('queued', 'leased', 'retry_wait');

CREATE TABLE probe_job_consumers (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    probe_job_id uuid NOT NULL,
    search_target_id uuid,
    watch_target_id uuid,
    created_at timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, probe_job_id) REFERENCES probe_jobs(tenant_id, id),
    FOREIGN KEY (tenant_id, search_target_id) REFERENCES search_targets(tenant_id, id),
    FOREIGN KEY (tenant_id, watch_target_id) REFERENCES watch_targets(tenant_id, id),
    CONSTRAINT probe_consumers_one_owner CHECK (
        (search_target_id IS NOT NULL)::integer + (watch_target_id IS NOT NULL)::integer = 1
    )
);

CREATE UNIQUE INDEX probe_consumers_search_unique
ON probe_job_consumers (tenant_id, probe_job_id, search_target_id)
WHERE search_target_id IS NOT NULL;

CREATE UNIQUE INDEX probe_consumers_watch_unique
ON probe_job_consumers (tenant_id, probe_job_id, watch_target_id)
WHERE watch_target_id IS NOT NULL;

CREATE TABLE observations (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    probe_job_id uuid NOT NULL,
    consent_grant_id uuid NOT NULL,
    normalized_username text NOT NULL,
    site_id text NOT NULL REFERENCES sites(id),
    rule_version_id uuid NOT NULL REFERENCES rule_versions(id),
    outcome_kind text NOT NULL,
    verdict text,
    uncertainty_reason text,
    evidence_class text NOT NULL,
    evidence_digest bytea NOT NULL,
    source text NOT NULL,
    producer_kind text NOT NULL,
    visibility text NOT NULL,
    region_class text NOT NULL,
    rule_health_green boolean NOT NULL,
    observed_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, probe_job_id),
    FOREIGN KEY (tenant_id, probe_job_id) REFERENCES probe_jobs(tenant_id, id),
    FOREIGN KEY (tenant_id, consent_grant_id) REFERENCES consent_grants(tenant_id, id),
    CONSTRAINT observations_username_bound CHECK (octet_length(normalized_username) BETWEEN 1 AND 256),
    CONSTRAINT observations_outcome_closed CHECK (outcome_kind IN ('definitive', 'uncertain')),
    CONSTRAINT observations_outcome_relation CHECK (
        (outcome_kind = 'definitive' AND verdict IN ('found', 'not_found') AND uncertainty_reason IS NULL)
        OR (outcome_kind = 'uncertain' AND verdict IS NULL AND uncertainty_reason IN (
            'site_changed', 'no_rule_matched', 'conflicting_evidence', 'classification_ambiguous'
        ))
    ),
    CONSTRAINT observations_evidence_closed CHECK (
        evidence_class IN (
            'e0_no_account_evidence', 'e1_weak_signal', 'e2_differential_template',
            'e3_explicit_endpoint', 'e4_structured_identity'
        )
    ),
    CONSTRAINT observations_digest_sha256 CHECK (octet_length(evidence_digest) = 32),
    CONSTRAINT observations_source_closed CHECK (
        source IN ('private_cloud', 'shared_assertion', 'managed_probe')
    ),
    CONSTRAINT observations_producer_closed CHECK (
        producer_kind IN ('shared_cli', 'managed_worker')
    ),
    CONSTRAINT observations_visibility_closed CHECK (visibility IN ('private', 'shared', 'managed')),
    CONSTRAINT observations_region_bound CHECK (length(region_class) BETWEEN 1 AND 64),
    CONSTRAINT observations_time_order CHECK (
        observed_at <= created_at AND expires_at > observed_at
    )
);

CREATE TABLE assertions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    normalized_username text NOT NULL,
    site_id text NOT NULL REFERENCES sites(id),
    outcome_kind text NOT NULL,
    verdict text,
    uncertainty_reason text,
    quality text NOT NULL,
    evidence_class text NOT NULL,
    observed_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    derivation_version text NOT NULL,
    is_current boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL,
    withdrawn_at timestamptz,
    UNIQUE (tenant_id, id),
    CONSTRAINT assertions_username_bound CHECK (octet_length(normalized_username) BETWEEN 1 AND 256),
    CONSTRAINT assertions_outcome_relation CHECK (
        (outcome_kind = 'definitive' AND verdict IN ('found', 'not_found') AND uncertainty_reason IS NULL)
        OR (outcome_kind = 'inconclusive' AND verdict IS NULL AND uncertainty_reason = 'conflicting_evidence')
    ),
    CONSTRAINT assertions_quality_closed CHECK (
        quality IN ('verified', 'corroborated', 'single_vantage', 'stale', 'conflicted', 'untrusted')
    ),
    CONSTRAINT assertions_evidence_closed CHECK (
        evidence_class IN (
            'e0_no_account_evidence', 'e1_weak_signal', 'e2_differential_template',
            'e3_explicit_endpoint', 'e4_structured_identity'
        )
    ),
    CONSTRAINT assertions_derivation_bound CHECK (length(derivation_version) BETWEEN 1 AND 64),
    CONSTRAINT assertions_time_order CHECK (
        expires_at > observed_at AND created_at >= observed_at
        AND (withdrawn_at IS NULL OR withdrawn_at >= created_at)
    ),
    CONSTRAINT assertions_current_relation CHECK (
        (is_current AND withdrawn_at IS NULL) OR NOT is_current
    )
);

CREATE UNIQUE INDEX assertions_one_current
ON assertions (tenant_id, normalized_username, site_id)
WHERE is_current AND withdrawn_at IS NULL;

CREATE TABLE assertion_support (
    tenant_id uuid NOT NULL,
    assertion_id uuid NOT NULL,
    observation_id uuid NOT NULL,
    support_role text NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, assertion_id, observation_id),
    FOREIGN KEY (tenant_id, assertion_id) REFERENCES assertions(tenant_id, id),
    FOREIGN KEY (tenant_id, observation_id) REFERENCES observations(tenant_id, id),
    CONSTRAINT assertion_support_role_closed CHECK (support_role IN ('supporting', 'conflicting'))
);

CREATE TABLE transitions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    watch_target_id uuid NOT NULL,
    transition_class text NOT NULL,
    from_state text NOT NULL,
    to_state text NOT NULL,
    region_class text,
    rule_version_id uuid REFERENCES rule_versions(id),
    confirmation_status text NOT NULL,
    confirmation_basis text,
    pending_reason text,
    suppression_reason text,
    derivation_version text NOT NULL,
    detected_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, watch_target_id) REFERENCES watch_targets(tenant_id, id),
    CONSTRAINT transitions_state_changed CHECK (from_state <> to_state),
    CONSTRAINT transitions_class_relation CHECK (
        (transition_class = 'account_state'
            AND from_state IN ('found', 'not_found')
            AND to_state IN ('found', 'not_found')
            AND region_class IS NULL AND rule_version_id IS NULL)
        OR (transition_class = 'measurement_health'
            AND from_state IN ('healthy', 'degraded', 'quarantined', 'recovering', 'unavailable')
            AND to_state IN ('healthy', 'degraded', 'quarantined', 'recovering', 'unavailable')
            AND region_class IS NOT NULL AND rule_version_id IS NOT NULL)
    ),
    CONSTRAINT transitions_confirmation_relation CHECK (
        (confirmation_status = 'confirmed' AND confirmation_basis IS NOT NULL
            AND pending_reason IS NULL AND suppression_reason IS NULL)
        OR (confirmation_status = 'pending' AND confirmation_basis IS NULL
            AND pending_reason IS NOT NULL AND suppression_reason IS NULL)
        OR (confirmation_status = 'suppressed' AND confirmation_basis IS NULL
            AND pending_reason IS NULL AND suppression_reason IS NOT NULL)
    ),
    CONSTRAINT transitions_basis_closed CHECK (
        confirmation_basis IS NULL OR confirmation_basis IN (
            'managed_e4', 'managed_e3_follow_up', 'two_managed_independent_regions',
            'two_managed_separated_in_time', 'corroborated_shared_candidate_opt_in',
            'measurement_health_evidence'
        )
    ),
    CONSTRAINT transitions_pending_closed CHECK (
        pending_reason IS NULL OR pending_reason IN (
            'managed_verification_required', 'second_managed_observation_required', 'regional_conflict'
        )
    ),
    CONSTRAINT transitions_suppression_closed CHECK (
        suppression_reason IS NULL OR suppression_reason IN (
            'shared_only_absence', 'conflicting_evidence', 'watch_paused', 'supporting_evidence_deleted'
        )
    ),
    CONSTRAINT transitions_confirmation_change_relation CHECK (
        (
            transition_class = 'account_state'
            AND (
                (
                    confirmation_status = 'confirmed'
                    AND (
                        (
                            to_state = 'found'
                            AND confirmation_basis IN (
                                'managed_e4', 'managed_e3_follow_up',
                                'corroborated_shared_candidate_opt_in'
                            )
                        )
                        OR (
                            to_state = 'not_found'
                            AND confirmation_basis IN (
                                'two_managed_independent_regions',
                                'two_managed_separated_in_time'
                            )
                        )
                    )
                )
                OR confirmation_status = 'pending'
                OR (
                    confirmation_status = 'suppressed'
                    AND (
                        (to_state = 'not_found' AND suppression_reason = 'shared_only_absence')
                        OR suppression_reason IN (
                            'conflicting_evidence', 'watch_paused',
                            'supporting_evidence_deleted'
                        )
                    )
                )
            )
        )
        OR (
            transition_class = 'measurement_health'
            AND (
                (
                    confirmation_status = 'confirmed'
                    AND confirmation_basis = 'measurement_health_evidence'
                )
                OR (
                    confirmation_status = 'suppressed'
                    AND suppression_reason IN ('watch_paused', 'supporting_evidence_deleted')
                )
            )
        )
    ),
    CONSTRAINT transitions_derivation_bound CHECK (length(derivation_version) BETWEEN 1 AND 64),
    CONSTRAINT transitions_time_order CHECK (created_at >= detected_at)
);

CREATE TABLE transition_basis (
    tenant_id uuid NOT NULL,
    transition_id uuid NOT NULL,
    observation_id uuid NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, transition_id, observation_id),
    FOREIGN KEY (tenant_id, transition_id) REFERENCES transitions(tenant_id, id),
    FOREIGN KEY (tenant_id, observation_id) REFERENCES observations(tenant_id, id)
);

CREATE TABLE notification_endpoints (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    channel text NOT NULL,
    destination_ciphertext bytea NOT NULL,
    destination_hash bytea NOT NULL,
    encryption_key_id text NOT NULL,
    state text NOT NULL DEFAULT 'pending_verification',
    created_at timestamptz NOT NULL,
    verified_at timestamptz,
    disabled_at timestamptz,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, channel, destination_hash),
    CONSTRAINT endpoints_channel_closed CHECK (channel IN ('email', 'webhook')),
    CONSTRAINT endpoints_ciphertext_nonempty CHECK (octet_length(destination_ciphertext) BETWEEN 17 AND 8192),
    CONSTRAINT endpoints_hash_sha256 CHECK (octet_length(destination_hash) = 32),
    CONSTRAINT endpoints_key_bound CHECK (length(encryption_key_id) BETWEEN 1 AND 128),
    CONSTRAINT endpoints_state_closed CHECK (state IN ('pending_verification', 'active', 'disabled')),
    CONSTRAINT endpoints_state_relation CHECK (
        (state = 'pending_verification' AND verified_at IS NULL AND disabled_at IS NULL)
        OR (state = 'active' AND verified_at IS NOT NULL AND disabled_at IS NULL)
        OR (state = 'disabled' AND disabled_at IS NOT NULL)
    )
);

CREATE TABLE notification_deliveries (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    transition_id uuid NOT NULL,
    endpoint_id uuid NOT NULL,
    logical_notification_key bytea NOT NULL,
    confirmation_basis text NOT NULL,
    state text NOT NULL DEFAULT 'queued',
    attempt_count integer NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL,
    next_attempt_at timestamptz,
    delivered_at timestamptz,
    last_error_code text,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, logical_notification_key),
    FOREIGN KEY (tenant_id, transition_id) REFERENCES transitions(tenant_id, id),
    FOREIGN KEY (tenant_id, endpoint_id) REFERENCES notification_endpoints(tenant_id, id),
    CONSTRAINT deliveries_key_sha256 CHECK (octet_length(logical_notification_key) = 32),
    CONSTRAINT deliveries_attempt_nonnegative CHECK (attempt_count >= 0),
    CONSTRAINT deliveries_state_closed CHECK (
        state IN ('queued', 'delivering', 'retry_scheduled', 'delivered', 'permanently_failed', 'cancelled')
    ),
    CONSTRAINT deliveries_state_relation CHECK (
        (state IN ('queued', 'delivering') AND next_attempt_at IS NULL
            AND delivered_at IS NULL AND last_error_code IS NULL)
        OR (state = 'retry_scheduled' AND attempt_count > 0 AND next_attempt_at IS NOT NULL
            AND delivered_at IS NULL AND last_error_code IS NOT NULL)
        OR (state = 'delivered' AND attempt_count > 0 AND next_attempt_at IS NULL
            AND delivered_at IS NOT NULL AND last_error_code IS NULL)
        OR (state = 'permanently_failed' AND attempt_count > 0 AND next_attempt_at IS NULL
            AND delivered_at IS NULL AND last_error_code IS NOT NULL)
        OR (state = 'cancelled' AND next_attempt_at IS NULL AND delivered_at IS NULL)
    )
);

CREATE FUNCTION socialname_validate_delivery()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    transition_status text;
    transition_basis text;
    endpoint_state text;
BEGIN
    SELECT confirmation_status, confirmation_basis
      INTO transition_status, transition_basis
      FROM transitions
     WHERE tenant_id = NEW.tenant_id AND id = NEW.transition_id;

    SELECT state
      INTO endpoint_state
      FROM notification_endpoints
     WHERE tenant_id = NEW.tenant_id AND id = NEW.endpoint_id;

    IF transition_status IS DISTINCT FROM 'confirmed'
       OR transition_basis IS DISTINCT FROM NEW.confirmation_basis THEN
        RAISE EXCEPTION 'notification delivery requires the exact confirmed transition basis'
            USING ERRCODE = '23514';
    END IF;
    IF endpoint_state IS DISTINCT FROM 'active' THEN
        RAISE EXCEPTION 'notification delivery requires an active endpoint'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER notification_deliveries_validate
BEFORE INSERT OR UPDATE ON notification_deliveries
FOR EACH ROW EXECUTE FUNCTION socialname_validate_delivery();

CREATE TABLE audit_events (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    actor_membership_id uuid,
    actor_api_key_id uuid,
    action text NOT NULL,
    resource_kind text NOT NULL,
    resource_id uuid,
    occurred_at timestamptz NOT NULL,
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, actor_membership_id) REFERENCES memberships(tenant_id, id),
    FOREIGN KEY (tenant_id, actor_api_key_id) REFERENCES api_keys(tenant_id, id),
    CONSTRAINT audit_actor_relation CHECK (
        (actor_membership_id IS NOT NULL)::integer + (actor_api_key_id IS NOT NULL)::integer <= 1
    ),
    CONSTRAINT audit_names_bound CHECK (
        length(action) BETWEEN 1 AND 100 AND length(resource_kind) BETWEEN 1 AND 64
    ),
    CONSTRAINT audit_details_object CHECK (
        jsonb_typeof(details) = 'object' AND octet_length(details::text) <= 16384
    )
);

CREATE TABLE data_lineage_edges (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    parent_kind text NOT NULL,
    parent_id uuid NOT NULL,
    child_kind text NOT NULL,
    child_id uuid NOT NULL,
    purpose text NOT NULL,
    created_at timestamptz NOT NULL,
    UNIQUE (tenant_id, parent_kind, parent_id, child_kind, child_id, purpose),
    CONSTRAINT lineage_kinds_bound CHECK (
        length(parent_kind) BETWEEN 1 AND 64 AND length(child_kind) BETWEEN 1 AND 64
        AND length(purpose) BETWEEN 1 AND 100
    ),
    CONSTRAINT lineage_not_self CHECK (parent_kind <> child_kind OR parent_id <> child_id)
);

CREATE TABLE deletion_requests (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    requested_by_membership_id uuid,
    scope_kind text NOT NULL,
    selector_token bytea NOT NULL,
    selector_ciphertext bytea,
    state text NOT NULL DEFAULT 'accepted',
    requested_at timestamptz NOT NULL,
    hide_by timestamptz NOT NULL,
    support_withdrawal_by timestamptz NOT NULL,
    primary_delete_by timestamptz NOT NULL,
    derived_rebuild_by timestamptz NOT NULL,
    backup_expiry_by timestamptz NOT NULL,
    completed_at timestamptz,
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, requested_by_membership_id) REFERENCES memberships(tenant_id, id),
    CONSTRAINT deletion_scope_closed CHECK (scope_kind IN ('tenant', 'contributor', 'target')),
    CONSTRAINT deletion_selector_hash CHECK (octet_length(selector_token) = 32),
    CONSTRAINT deletion_selector_ciphertext_bound CHECK (
        selector_ciphertext IS NULL OR octet_length(selector_ciphertext) BETWEEN 17 AND 8192
    ),
    CONSTRAINT deletion_state_closed CHECK (
        state IN ('accepted', 'hidden', 'withdrawing_support', 'deleting', 'rebuilding', 'completed', 'failed')
    ),
    CONSTRAINT deletion_deadline_order CHECK (
        hide_by >= requested_at
        AND support_withdrawal_by >= hide_by
        AND primary_delete_by >= support_withdrawal_by
        AND derived_rebuild_by >= primary_delete_by
        AND backup_expiry_by >= derived_rebuild_by
        AND (completed_at IS NULL OR completed_at >= requested_at)
    ),
    CONSTRAINT deletion_completion_relation CHECK (
        (state = 'completed' AND completed_at IS NOT NULL)
        OR (state <> 'completed' AND completed_at IS NULL)
    )
);

CREATE TABLE deletion_tasks (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    deletion_request_id uuid NOT NULL,
    store_kind text NOT NULL,
    state text NOT NULL DEFAULT 'pending',
    deadline_at timestamptz NOT NULL,
    attempt_count integer NOT NULL DEFAULT 0,
    available_at timestamptz NOT NULL,
    completed_at timestamptz,
    last_error_code text,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, deletion_request_id, store_kind),
    FOREIGN KEY (tenant_id, deletion_request_id) REFERENCES deletion_requests(tenant_id, id),
    CONSTRAINT deletion_tasks_store_closed CHECK (
        store_kind IN ('primary', 'cache', 'index', 'queue', 'object', 'analytics', 'backup')
    ),
    CONSTRAINT deletion_tasks_state_closed CHECK (
        state IN ('pending', 'running', 'retry_wait', 'completed', 'failed')
    ),
    CONSTRAINT deletion_tasks_attempt_nonnegative CHECK (attempt_count >= 0),
    CONSTRAINT deletion_tasks_completion_relation CHECK (
        (state = 'completed' AND completed_at IS NOT NULL AND last_error_code IS NULL)
        OR (state <> 'completed' AND completed_at IS NULL)
    )
);

CREATE TABLE deletion_receipts (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    deletion_request_id uuid NOT NULL,
    stores jsonb NOT NULL,
    primary_completed_at timestamptz NOT NULL,
    backup_expiry_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, deletion_request_id),
    FOREIGN KEY (tenant_id, deletion_request_id) REFERENCES deletion_requests(tenant_id, id),
    CONSTRAINT deletion_receipts_stores_object CHECK (
        jsonb_typeof(stores) = 'object' AND octet_length(stores::text) <= 32768
    ),
    CONSTRAINT deletion_receipts_time_order CHECK (
        created_at >= primary_completed_at AND backup_expiry_at >= primary_completed_at
    )
);

CREATE TABLE suppression_tokens (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    purpose text NOT NULL,
    token_hmac bytea NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, purpose, token_hmac),
    CONSTRAINT suppression_purpose_closed CHECK (purpose IN ('target_reingestion', 'contributor_reingestion')),
    CONSTRAINT suppression_hmac_sha256 CHECK (octet_length(token_hmac) = 32),
    CONSTRAINT suppression_expiry_order CHECK (expires_at > created_at)
);

CREATE INDEX observations_target_time
ON observations (tenant_id, normalized_username, site_id, observed_at DESC);
CREATE INDEX assertions_target_time
ON assertions (tenant_id, normalized_username, site_id, created_at DESC);
CREATE INDEX watch_targets_due
ON watches (tenant_id, next_run_at) WHERE state = 'active';
CREATE INDEX probe_jobs_claim
ON probe_jobs (available_at, priority DESC, created_at) WHERE state IN ('queued', 'retry_wait');
CREATE INDEX deletion_tasks_due
ON deletion_tasks (deadline_at, available_at) WHERE state IN ('pending', 'retry_wait');
CREATE INDEX lineage_parent
ON data_lineage_edges (tenant_id, parent_kind, parent_id);
CREATE INDEX lineage_child
ON data_lineage_edges (tenant_id, child_kind, child_id);

CREATE TRIGGER observations_append_only
BEFORE UPDATE ON observations
FOR EACH ROW EXECUTE FUNCTION socialname_reject_update();
CREATE TRIGGER consent_events_append_only
BEFORE UPDATE ON consent_events
FOR EACH ROW EXECUTE FUNCTION socialname_reject_update();
CREATE TRIGGER assertion_support_append_only
BEFORE UPDATE ON assertion_support
FOR EACH ROW EXECUTE FUNCTION socialname_reject_update();
CREATE TRIGGER transition_basis_append_only
BEFORE UPDATE ON transition_basis
FOR EACH ROW EXECUTE FUNCTION socialname_reject_update();
CREATE TRIGGER audit_events_append_only
BEFORE UPDATE ON audit_events
FOR EACH ROW EXECUTE FUNCTION socialname_reject_update();
CREATE TRIGGER lineage_edges_append_only
BEFORE UPDATE ON data_lineage_edges
FOR EACH ROW EXECUTE FUNCTION socialname_reject_update();
CREATE TRIGGER deletion_receipts_append_only
BEFORE UPDATE ON deletion_receipts
FOR EACH ROW EXECUTE FUNCTION socialname_reject_update();

DO $$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'memberships', 'api_keys', 'clients', 'consent_grants',
        'consent_events', 'searches', 'search_targets', 'watches', 'watch_targets',
        'probe_jobs', 'probe_job_consumers', 'observations', 'assertions',
        'assertion_support', 'transitions', 'transition_basis',
        'notification_endpoints', 'notification_deliveries', 'audit_events',
        'data_lineage_edges', 'deletion_requests', 'deletion_tasks',
        'deletion_receipts', 'suppression_tokens'
    ]
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %I USING (tenant_id = socialname_current_tenant_id()) WITH CHECK (tenant_id = socialname_current_tenant_id())',
            table_name
        );
    END LOOP;

    ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
    ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
    CREATE POLICY tenant_isolation ON tenants
        USING (id = socialname_current_tenant_id())
        WITH CHECK (id = socialname_current_tenant_id());
END
$$;
