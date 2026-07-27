CREATE TABLE tenant_plan_entitlements (
    tenant_id uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    plan_code text NOT NULL,
    access_state text NOT NULL,
    revision bigint NOT NULL,
    source_kind text NOT NULL,
    source_event_hash bytea NOT NULL,
    request_hash bytea NOT NULL,
    effective_at timestamptz NOT NULL,
    access_until timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT tenant_plan_code_closed CHECK (
        plan_code IN ('community', 'developer', 'monitor', 'evaluation')
    ),
    CONSTRAINT tenant_plan_access_state_closed CHECK (
        access_state IN ('active', 'suspended')
    ),
    CONSTRAINT tenant_plan_revision_positive CHECK (revision >= 1),
    CONSTRAINT tenant_plan_source_closed CHECK (
        source_kind IN ('bootstrap', 'migration', 'billing')
    ),
    CONSTRAINT tenant_plan_hashes_exact CHECK (
        octet_length(source_event_hash) = 32
        AND octet_length(request_hash) = 32
    ),
    CONSTRAINT tenant_plan_access_window CHECK (
        (access_state = 'active'
            AND (access_until IS NULL OR access_until > effective_at))
        OR (access_state = 'suspended' AND access_until IS NULL)
    ),
    CONSTRAINT tenant_plan_time_order CHECK (updated_at >= created_at)
);

CREATE TABLE plan_entitlement_events (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    revision bigint NOT NULL,
    plan_code text NOT NULL,
    access_state text NOT NULL,
    source_kind text NOT NULL,
    source_event_hash bytea NOT NULL,
    request_hash bytea NOT NULL,
    effective_at timestamptz NOT NULL,
    access_until timestamptz,
    occurred_at timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, revision),
    UNIQUE (tenant_id, source_event_hash),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    CONSTRAINT plan_event_code_closed CHECK (
        plan_code IN ('community', 'developer', 'monitor', 'evaluation')
    ),
    CONSTRAINT plan_event_access_state_closed CHECK (
        access_state IN ('active', 'suspended')
    ),
    CONSTRAINT plan_event_revision_positive CHECK (revision >= 1),
    CONSTRAINT plan_event_source_closed CHECK (
        source_kind IN ('bootstrap', 'migration', 'billing')
    ),
    CONSTRAINT plan_event_hashes_exact CHECK (
        octet_length(source_event_hash) = 32
        AND octet_length(request_hash) = 32
    ),
    CONSTRAINT plan_event_access_window CHECK (
        (access_state = 'active'
            AND (access_until IS NULL OR access_until > effective_at))
        OR (access_state = 'suspended' AND access_until IS NULL)
    )
);

CREATE FUNCTION socialname_insert_initial_plan_entitlement()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    event_hash bytea;
    observed_at timestamptz := clock_timestamp();
BEGIN
    event_hash := sha256(
        convert_to(
            'socialname.plan.bootstrap.v1:' || NEW.id::text,
            'UTF8'
        )
    );
    INSERT INTO tenant_plan_entitlements (
        tenant_id, plan_code, access_state, revision, source_kind,
        source_event_hash, request_hash, effective_at, access_until,
        created_at, updated_at
    ) VALUES (
        NEW.id, 'community', 'active', 1, 'bootstrap',
        event_hash, event_hash, observed_at, NULL, observed_at, observed_at
    );
    INSERT INTO plan_entitlement_events (
        id, tenant_id, revision, plan_code, access_state, source_kind,
        source_event_hash, request_hash, effective_at, access_until, occurred_at
    ) VALUES (
        gen_random_uuid(), NEW.id, 1, 'community', 'active', 'bootstrap',
        event_hash, event_hash, observed_at, NULL, observed_at
    );
    RETURN NEW;
END
$$;

CREATE TRIGGER tenants_initial_plan_entitlement
AFTER INSERT ON tenants
FOR EACH ROW EXECUTE FUNCTION socialname_insert_initial_plan_entitlement();

REVOKE ALL ON FUNCTION socialname_insert_initial_plan_entitlement()
FROM PUBLIC;

WITH existing AS (
    SELECT
        tenant.id,
        clock_timestamp() AS observed_at,
        sha256(
            convert_to(
                'socialname.plan.migration.v1:' || tenant.id::text,
                'UTF8'
            )
        ) AS event_hash
    FROM tenants AS tenant
),
inserted AS (
    INSERT INTO tenant_plan_entitlements (
        tenant_id, plan_code, access_state, revision, source_kind,
        source_event_hash, request_hash, effective_at, access_until,
        created_at, updated_at
    )
    SELECT
        id, 'evaluation', 'active', 1, 'migration',
        event_hash, event_hash, observed_at, NULL, observed_at, observed_at
    FROM existing
    RETURNING
        tenant_id, revision, plan_code, access_state, source_kind,
        source_event_hash, request_hash, effective_at, access_until, created_at
)
INSERT INTO plan_entitlement_events (
    id, tenant_id, revision, plan_code, access_state, source_kind,
    source_event_hash, request_hash, effective_at, access_until, occurred_at
)
SELECT
    gen_random_uuid(), tenant_id, revision, plan_code, access_state, source_kind,
    source_event_hash, request_hash, effective_at, access_until, created_at
FROM inserted;

CREATE FUNCTION socialname_guard_plan_entitlement_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.revision IS DISTINCT FROM OLD.revision + 1 THEN
        RAISE EXCEPTION 'plan entitlement identity or revision is invalid'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER tenant_plan_entitlement_guard_update
BEFORE UPDATE ON tenant_plan_entitlements
FOR EACH ROW EXECUTE FUNCTION socialname_guard_plan_entitlement_update();

CREATE TRIGGER plan_entitlement_events_append_only
BEFORE UPDATE ON plan_entitlement_events
FOR EACH ROW EXECUTE FUNCTION socialname_reject_update();

CREATE FUNCTION socialname_plan_capability_enabled(
    p_plan_code text,
    p_capability text
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
AS $$
    SELECT CASE p_capability
        WHEN 'managed_search' THEN
            p_plan_code IN ('developer', 'monitor', 'evaluation')
        WHEN 'monitoring' THEN
            p_plan_code IN ('monitor', 'evaluation')
        ELSE false
    END
$$;

REVOKE ALL ON FUNCTION socialname_plan_capability_enabled(text, text)
FROM PUBLIC;

CREATE FUNCTION socialname_has_plan_capability(
    p_tenant_id uuid,
    p_capability text
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    selected_plan_code text;
    selected_access_state text;
    selected_effective_at timestamptz;
    selected_access_until timestamptz;
    evaluated_at timestamptz := clock_timestamp();
BEGIN
    IF p_tenant_id IS DISTINCT FROM public.socialname_current_tenant_id()
       OR p_capability NOT IN ('managed_search', 'monitoring') THEN
        RAISE EXCEPTION 'plan entitlement request is invalid'
            USING ERRCODE = '42501';
    END IF;

    SELECT
        entitlement.plan_code,
        entitlement.access_state,
        entitlement.effective_at,
        entitlement.access_until
      INTO
        selected_plan_code,
        selected_access_state,
        selected_effective_at,
        selected_access_until
      FROM public.tenant_plan_entitlements AS entitlement
     WHERE entitlement.tenant_id = p_tenant_id
     FOR SHARE OF entitlement;

    RETURN FOUND
       AND selected_access_state = 'active'
       AND selected_effective_at <= evaluated_at
       AND (
           selected_access_until IS NULL
           OR selected_access_until > evaluated_at
       )
       AND public.socialname_plan_capability_enabled(
           selected_plan_code,
           p_capability
       );
END
$$;

REVOKE ALL ON FUNCTION socialname_has_plan_capability(uuid, text)
FROM PUBLIC;

ALTER TABLE tenant_plan_entitlements ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_plan_entitlements FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant_plan_entitlements
    USING (tenant_id = socialname_current_tenant_id())
    WITH CHECK (tenant_id = socialname_current_tenant_id());

ALTER TABLE plan_entitlement_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE plan_entitlement_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON plan_entitlement_events
    USING (tenant_id = socialname_current_tenant_id())
    WITH CHECK (tenant_id = socialname_current_tenant_id());

CREATE OR REPLACE FUNCTION socialname_worker_lock_due_watch(
    p_rule_version_id uuid,
    p_region_class text
)
RETURNS TABLE (tenant_id uuid, watch_id uuid)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
    IF p_rule_version_id IS NULL
       OR p_region_class IS NULL
       OR p_region_class !~ '^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$'
       OR length(p_region_class) > 64 THEN
        RAISE EXCEPTION 'managed watch scheduler parameters are invalid'
            USING ERRCODE = '22023';
    END IF;

    RETURN QUERY
    SELECT watch.tenant_id, watch.id
    FROM public.watches AS watch
    JOIN public.tenant_plan_entitlements AS entitlement
      ON entitlement.tenant_id = watch.tenant_id
    JOIN public.consent_grants AS consent
      ON consent.tenant_id = watch.tenant_id
     AND consent.id = watch.consent_grant_id
    JOIN public.rule_versions AS version
      ON version.id = p_rule_version_id
    JOIN public.rule_packs AS pack
      ON pack.id = version.rule_pack_id
    JOIN public.sites AS site
      ON site.id = version.site_id
    WHERE watch.state = 'active'
      AND watch.next_run_at <= clock_timestamp()
      AND entitlement.access_state = 'active'
      AND entitlement.effective_at <= clock_timestamp()
      AND (
          entitlement.access_until IS NULL
          OR entitlement.access_until > clock_timestamp()
      )
      AND public.socialname_plan_capability_enabled(
          entitlement.plan_code,
          'monitoring'
      )
      AND p_region_class = ANY(watch.region_classes)
      AND consent.subject_kind = 'account'
      AND consent.purpose = 'private_history'
      AND consent.granted_at <= clock_timestamp()
      AND consent.withdrawn_at IS NULL
      AND (consent.expires_at IS NULL OR consent.expires_at > clock_timestamp())
      AND version.enabled
      AND pack.state = 'active'
      AND pack.published_at IS NOT NULL
      AND (pack.expires_at IS NULL OR pack.expires_at > clock_timestamp())
      AND site.state = 'promoted'
      AND EXISTS (
          SELECT 1
          FROM public.rule_health_records AS health
          WHERE health.id = (
              SELECT latest.id
              FROM public.rule_health_records AS latest
              WHERE latest.rule_version_id = version.id
                AND latest.region_class = p_region_class
              ORDER BY latest.recorded_at DESC
              LIMIT 1
          )
            AND health.state = 'healthy'
            AND health.recorded_at <= clock_timestamp()
            AND health.evidence_expires_at > clock_timestamp()
      )
      AND EXISTS (
          SELECT 1
          FROM public.watch_targets AS target
          WHERE target.tenant_id = watch.tenant_id
            AND target.watch_id = watch.id
            AND target.site_id = version.site_id
            AND target.retired_at IS NULL
      )
      AND EXISTS (
          SELECT 1
          FROM public.watch_notification_endpoints AS link
          JOIN public.notification_endpoints AS endpoint
            ON endpoint.tenant_id = link.tenant_id
           AND endpoint.id = link.endpoint_id
          WHERE link.tenant_id = watch.tenant_id
            AND link.watch_id = watch.id
            AND endpoint.state = 'active'
      )
    ORDER BY watch.next_run_at, watch.id
    LIMIT 1
    FOR UPDATE OF watch SKIP LOCKED;
END
$$;

REVOKE ALL ON FUNCTION socialname_worker_lock_due_watch(uuid, text)
FROM PUBLIC;
