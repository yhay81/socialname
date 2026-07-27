CREATE OR REPLACE FUNCTION socialname_api_key_scopes_valid(candidate text[])
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
AS $$
    SELECT
        cardinality(candidate) BETWEEN 1 AND 16
        AND array_position(candidate, NULL) IS NULL
        AND (
            SELECT count(*) = count(DISTINCT scope)
            FROM unnest(candidate) AS scope
        )
        AND candidate <@ ARRAY[
            'workspace:read',
            'search:read', 'search:write', 'watch:read', 'watch:write',
            'notification:read', 'notification:write',
            'consent:read', 'consent:write',
            'contribution:read', 'contribution:write',
            'evidence:read', 'operations:read', 'usage:read',
            'data:export', 'data:delete'
        ]::text[]
$$;

CREATE TABLE shared_contributions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    client_id uuid NOT NULL,
    consent_grant_id uuid NOT NULL,
    sequence_number bigint NOT NULL,
    content_digest bytea NOT NULL,
    normalized_username text NOT NULL,
    site_id text NOT NULL REFERENCES sites(id),
    rule_version_id uuid NOT NULL REFERENCES rule_versions(id),
    engine_hash bytea NOT NULL,
    outcome_kind text NOT NULL,
    verdict text,
    uncertainty_reason text,
    evidence_class text NOT NULL,
    evidence_digest bytea NOT NULL,
    region_class text NOT NULL,
    network_class text NOT NULL,
    network_group bytea NOT NULL,
    influence_scope text NOT NULL,
    history_reason text,
    observed_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, client_id, sequence_number),
    UNIQUE (tenant_id, client_id, content_digest),
    FOREIGN KEY (tenant_id, client_id) REFERENCES clients(tenant_id, id),
    FOREIGN KEY (tenant_id, consent_grant_id)
        REFERENCES consent_grants(tenant_id, id),
    CONSTRAINT shared_contributions_username_bound CHECK (
        octet_length(normalized_username) BETWEEN 1 AND 256
    ),
    CONSTRAINT shared_contributions_sequence_positive CHECK (
        sequence_number >= 1
    ),
    CONSTRAINT shared_contributions_content_digest_sha256 CHECK (
        octet_length(content_digest) = 32
    ),
    CONSTRAINT shared_contributions_engine_hash_sha256 CHECK (
        octet_length(engine_hash) = 32
    ),
    CONSTRAINT shared_contributions_evidence_digest_sha256 CHECK (
        octet_length(evidence_digest) = 32
    ),
    CONSTRAINT shared_contributions_network_group_hmac CHECK (
        octet_length(network_group) = 32
    ),
    CONSTRAINT shared_contributions_outcome_closed CHECK (
        outcome_kind IN ('definitive', 'uncertain')
    ),
    CONSTRAINT shared_contributions_outcome_relation CHECK (
        (
            outcome_kind = 'definitive'
            AND verdict IN ('found', 'not_found')
            AND uncertainty_reason IS NULL
        )
        OR (
            outcome_kind = 'uncertain'
            AND verdict IS NULL
            AND uncertainty_reason IN (
                'site_changed', 'no_rule_matched', 'conflicting_evidence',
                'classification_ambiguous'
            )
        )
    ),
    CONSTRAINT shared_contributions_evidence_closed CHECK (
        evidence_class IN (
            'e0_no_account_evidence', 'e1_weak_signal',
            'e2_differential_template', 'e3_explicit_endpoint',
            'e4_structured_identity'
        )
    ),
    CONSTRAINT shared_contributions_definitive_evidence_strong CHECK (
        outcome_kind <> 'definitive'
        OR evidence_class IN (
            'e2_differential_template', 'e3_explicit_endpoint',
            'e4_structured_identity'
        )
    ),
    CONSTRAINT shared_contributions_region_bound CHECK (
        length(region_class) BETWEEN 1 AND 64
    ),
    CONSTRAINT shared_contributions_network_closed CHECK (
        network_class IN ('datacenter', 'residential', 'anonymizer', 'unknown')
    ),
    CONSTRAINT shared_contributions_influence_relation CHECK (
        (influence_scope = 'current' AND history_reason IS NULL)
        OR (
            influence_scope = 'history_only'
            AND history_reason IN ('stale_upload', 'rule_health_not_green')
        )
    ),
    CONSTRAINT shared_contributions_time_order CHECK (
        expires_at > observed_at
        AND received_at >= observed_at - interval '5 minutes'
        AND created_at >= received_at
    )
);

CREATE INDEX shared_contributions_target_time
ON shared_contributions (tenant_id, normalized_username, site_id, observed_at DESC);
CREATE INDEX shared_contributions_page
ON shared_contributions (tenant_id, received_at DESC, id DESC);

CREATE TRIGGER shared_contributions_append_only
BEFORE UPDATE ON shared_contributions
FOR EACH ROW EXECUTE FUNCTION socialname_reject_update();

CREATE TABLE contribution_sequences (
    tenant_id uuid NOT NULL,
    client_id uuid NOT NULL,
    high_water bigint NOT NULL DEFAULT 0,
    replay_violations bigint NOT NULL DEFAULT 0,
    last_violation_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, client_id),
    FOREIGN KEY (tenant_id, client_id) REFERENCES clients(tenant_id, id),
    CONSTRAINT contribution_sequences_high_water_nonnegative CHECK (
        high_water >= 0
    ),
    CONSTRAINT contribution_sequences_violations_nonnegative CHECK (
        replay_violations >= 0
    ),
    CONSTRAINT contribution_sequences_time_order CHECK (
        updated_at >= created_at
    )
);

CREATE FUNCTION socialname_guard_contribution_sequence_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.client_id IS DISTINCT FROM OLD.client_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.high_water < OLD.high_water
       OR NEW.replay_violations < OLD.replay_violations
       OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'contribution sequence update is invalid'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER contribution_sequences_guard_update
BEFORE UPDATE ON contribution_sequences
FOR EACH ROW
EXECUTE FUNCTION socialname_guard_contribution_sequence_update();

CREATE TABLE contribution_quota_counters (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    counter_scope text NOT NULL,
    client_id uuid,
    day date NOT NULL,
    accepted_count integer NOT NULL DEFAULT 0,
    UNIQUE (tenant_id, id),
    CONSTRAINT contribution_quota_counters_unique
        UNIQUE NULLS NOT DISTINCT (tenant_id, counter_scope, client_id, day),
    FOREIGN KEY (tenant_id, client_id) REFERENCES clients(tenant_id, id),
    CONSTRAINT contribution_quota_scope_closed CHECK (
        counter_scope IN ('tenant', 'installation')
    ),
    CONSTRAINT contribution_quota_scope_relation CHECK (
        (counter_scope = 'tenant' AND client_id IS NULL)
        OR (counter_scope = 'installation' AND client_id IS NOT NULL)
    ),
    CONSTRAINT contribution_quota_count_nonnegative CHECK (
        accepted_count >= 0
    )
);

CREATE FUNCTION socialname_guard_contribution_quota_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.counter_scope IS DISTINCT FROM OLD.counter_scope
       OR NEW.client_id IS DISTINCT FROM OLD.client_id
       OR NEW.day IS DISTINCT FROM OLD.day
       OR NEW.accepted_count < OLD.accepted_count THEN
        RAISE EXCEPTION 'contribution quota update is invalid'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER contribution_quota_counters_guard_update
BEFORE UPDATE ON contribution_quota_counters
FOR EACH ROW
EXECUTE FUNCTION socialname_guard_contribution_quota_update();

CREATE TABLE contributor_reputation (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    client_id uuid NOT NULL,
    site_family text NOT NULL,
    tier text NOT NULL DEFAULT 'new',
    revision bigint NOT NULL DEFAULT 1,
    validated_overlaps bigint NOT NULL DEFAULT 0,
    agreement_hits bigint NOT NULL DEFAULT 0,
    agreement_misses bigint NOT NULL DEFAULT 0,
    active_days integer NOT NULL DEFAULT 0,
    last_active_day date,
    suspended_at timestamptz,
    suspension_reason text,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, client_id, site_family),
    FOREIGN KEY (tenant_id, client_id) REFERENCES clients(tenant_id, id),
    CONSTRAINT contributor_reputation_site_family_bound CHECK (
        length(site_family) BETWEEN 1 AND 64
        AND site_family ~ '^[a-z0-9]+(?:-[a-z0-9]+)*$'
    ),
    CONSTRAINT contributor_reputation_tier_closed CHECK (
        tier IN ('new', 'calibrated', 'trusted', 'suspended')
    ),
    CONSTRAINT contributor_reputation_revision_positive CHECK (revision >= 1),
    CONSTRAINT contributor_reputation_counters_nonnegative CHECK (
        validated_overlaps >= 0
        AND agreement_hits >= 0
        AND agreement_misses >= 0
        AND active_days >= 0
    ),
    CONSTRAINT contributor_reputation_suspension_relation CHECK (
        (
            tier = 'suspended'
            AND suspended_at IS NOT NULL
            AND suspension_reason IN (
                'replay_abuse', 'fabricated_plan_evidence', 'agreement_collapse'
            )
        )
        OR (
            tier <> 'suspended'
            AND suspended_at IS NULL
            AND suspension_reason IS NULL
        )
    ),
    CONSTRAINT contributor_reputation_time_order CHECK (
        updated_at >= created_at
        AND (suspended_at IS NULL OR suspended_at >= created_at)
    )
);

CREATE FUNCTION socialname_guard_contributor_reputation_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.client_id IS DISTINCT FROM OLD.client_id
       OR NEW.site_family IS DISTINCT FROM OLD.site_family
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.revision IS DISTINCT FROM OLD.revision + 1
       OR NEW.updated_at <= OLD.updated_at
       OR NEW.validated_overlaps < OLD.validated_overlaps
       OR NEW.agreement_hits < OLD.agreement_hits
       OR NEW.agreement_misses < OLD.agreement_misses
       OR NEW.active_days < OLD.active_days
       OR OLD.tier = 'suspended'
       OR NOT (
            NEW.tier = OLD.tier
            OR (OLD.tier = 'new' AND NEW.tier IN ('calibrated', 'suspended'))
            OR (
                OLD.tier = 'calibrated'
                AND NEW.tier IN ('trusted', 'new', 'suspended')
            )
            OR (
                OLD.tier = 'trusted'
                AND NEW.tier IN ('calibrated', 'suspended')
            )
       ) THEN
        RAISE EXCEPTION 'contributor reputation update is invalid'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER contributor_reputation_guard_update
BEFORE UPDATE ON contributor_reputation
FOR EACH ROW
EXECUTE FUNCTION socialname_guard_contributor_reputation_update();

ALTER TABLE deletion_resource_matches
    DROP CONSTRAINT deletion_resource_matches_kind_closed,
    ADD CONSTRAINT deletion_resource_matches_kind_closed CHECK (
        resource_kind IN (
            'observation', 'evidence_capsule', 'assertion',
            'regional_assertion', 'search_event', 'watch_run_target',
            'transition', 'notification_delivery', 'probe_job',
            'search_target', 'shared_contribution'
        )
    );

ALTER TABLE shared_contributions ENABLE ROW LEVEL SECURITY;
ALTER TABLE shared_contributions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON shared_contributions
    USING (tenant_id = socialname_current_tenant_id())
    WITH CHECK (tenant_id = socialname_current_tenant_id());

ALTER TABLE contribution_sequences ENABLE ROW LEVEL SECURITY;
ALTER TABLE contribution_sequences FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON contribution_sequences
    USING (tenant_id = socialname_current_tenant_id())
    WITH CHECK (tenant_id = socialname_current_tenant_id());

ALTER TABLE contribution_quota_counters ENABLE ROW LEVEL SECURITY;
ALTER TABLE contribution_quota_counters FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON contribution_quota_counters
    USING (tenant_id = socialname_current_tenant_id())
    WITH CHECK (tenant_id = socialname_current_tenant_id());

ALTER TABLE contributor_reputation ENABLE ROW LEVEL SECURITY;
ALTER TABLE contributor_reputation FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON contributor_reputation
    USING (tenant_id = socialname_current_tenant_id())
    WITH CHECK (tenant_id = socialname_current_tenant_id());

REVOKE ALL ON shared_contributions, contribution_sequences,
    contribution_quota_counters, contributor_reputation
FROM PUBLIC;
