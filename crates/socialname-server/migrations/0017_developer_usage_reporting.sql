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
            'consent:read', 'consent:write', 'evidence:read',
            'operations:read', 'usage:read',
            'data:export', 'data:delete'
        ]::text[]
$$;

CREATE TABLE developer_quota_policies (
    tenant_id uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    daily_target_limit integer NOT NULL,
    api_key_daily_target_limit integer NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT developer_quota_limits_bounded CHECK (
        daily_target_limit BETWEEN 1 AND 1000000
        AND api_key_daily_target_limit BETWEEN 1 AND 1000000
        AND api_key_daily_target_limit <= daily_target_limit
    ),
    CONSTRAINT developer_quota_time_order CHECK (updated_at >= created_at)
);

CREATE FUNCTION socialname_insert_default_developer_quota_policy()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO developer_quota_policies (
        tenant_id, daily_target_limit, api_key_daily_target_limit,
        created_at, updated_at
    ) VALUES (
        NEW.id, 10000, 2000, clock_timestamp(), clock_timestamp()
    );
    RETURN NEW;
END
$$;

CREATE TRIGGER tenants_default_developer_quota
AFTER INSERT ON tenants
FOR EACH ROW EXECUTE FUNCTION socialname_insert_default_developer_quota_policy();

REVOKE ALL ON FUNCTION socialname_insert_default_developer_quota_policy()
FROM PUBLIC;

INSERT INTO developer_quota_policies (
    tenant_id, daily_target_limit, api_key_daily_target_limit,
    created_at, updated_at
)
SELECT id, 10000, 2000, clock_timestamp(), clock_timestamp()
FROM tenants;

CREATE TABLE developer_usage_records (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    api_key_id uuid,
    search_id uuid NOT NULL,
    meter text NOT NULL,
    quantity integer NOT NULL,
    occurred_at timestamptz NOT NULL,
    retained_until timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, search_id, meter),
    FOREIGN KEY (tenant_id, api_key_id) REFERENCES api_keys(tenant_id, id),
    FOREIGN KEY (tenant_id, search_id) REFERENCES searches(tenant_id, id),
    CONSTRAINT developer_usage_meter_closed CHECK (
        meter = 'search_target_admitted'
    ),
    CONSTRAINT developer_usage_quantity_bounded CHECK (
        quantity BETWEEN 1 AND 512
    ),
    CONSTRAINT developer_usage_retention_exact CHECK (
        retained_until = occurred_at + interval '400 days'
    )
);

CREATE INDEX developer_usage_tenant_time
ON developer_usage_records (tenant_id, occurred_at);

CREATE INDEX developer_usage_api_key_time
ON developer_usage_records (tenant_id, api_key_id, occurred_at)
WHERE api_key_id IS NOT NULL;

CREATE FUNCTION socialname_validate_developer_usage_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    selected_api_key_id uuid;
    selected_created_at timestamptz;
    selected_target_count integer;
BEGIN
    SELECT
        search.requested_by_api_key_id,
        search.created_at,
        count(target.id)::integer
      INTO
        selected_api_key_id,
        selected_created_at,
        selected_target_count
      FROM searches AS search
      JOIN search_targets AS target
        ON target.tenant_id = search.tenant_id
       AND target.search_id = search.id
     WHERE search.tenant_id = NEW.tenant_id
       AND search.id = NEW.search_id
     GROUP BY search.requested_by_api_key_id, search.created_at;

    IF NOT FOUND
       OR NEW.meter IS DISTINCT FROM 'search_target_admitted'
       OR NEW.api_key_id IS DISTINCT FROM selected_api_key_id
       OR NEW.quantity IS DISTINCT FROM selected_target_count
       OR NEW.occurred_at IS DISTINCT FROM selected_created_at
       OR NEW.retained_until IS DISTINCT FROM
          selected_created_at + interval '400 days' THEN
        RAISE EXCEPTION 'developer usage record does not match its admitted search'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER developer_usage_validate_insert
BEFORE INSERT ON developer_usage_records
FOR EACH ROW EXECUTE FUNCTION socialname_validate_developer_usage_insert();

CREATE TRIGGER developer_usage_append_only
BEFORE UPDATE ON developer_usage_records
FOR EACH ROW EXECUTE FUNCTION socialname_reject_update();

INSERT INTO developer_usage_records (
    id, tenant_id, api_key_id, search_id, meter, quantity,
    occurred_at, retained_until
)
SELECT
    gen_random_uuid(),
    search.tenant_id,
    search.requested_by_api_key_id,
    search.id,
    'search_target_admitted',
    count(target.id)::integer,
    search.created_at,
    search.created_at + interval '400 days'
FROM searches AS search
JOIN search_targets AS target
  ON target.tenant_id = search.tenant_id
 AND target.search_id = search.id
GROUP BY
    search.tenant_id,
    search.requested_by_api_key_id,
    search.id,
    search.created_at;

WITH utc_period AS (
    SELECT
        date_trunc('day', clock_timestamp() AT TIME ZONE 'UTC')
            AT TIME ZONE 'UTC' AS started_at
),
tenant_usage AS (
    SELECT
        usage.tenant_id,
        sum(usage.quantity)::integer AS quantity
    FROM developer_usage_records AS usage
    CROSS JOIN utc_period
    WHERE usage.occurred_at >= utc_period.started_at
    GROUP BY usage.tenant_id
),
key_totals AS (
    SELECT
        usage.tenant_id,
        usage.api_key_id,
        sum(usage.quantity)::integer AS quantity
    FROM developer_usage_records AS usage
    CROSS JOIN utc_period
    WHERE usage.occurred_at >= utc_period.started_at
      AND usage.api_key_id IS NOT NULL
    GROUP BY usage.tenant_id, usage.api_key_id
),
key_usage AS (
    SELECT
        tenant_id,
        max(quantity)::integer AS quantity
    FROM key_totals
    GROUP BY tenant_id
)
UPDATE developer_quota_policies AS policy
SET
    daily_target_limit = GREATEST(
        policy.daily_target_limit,
        COALESCE(tenant_usage.quantity, 0),
        COALESCE(key_usage.quantity, 0)
    ),
    api_key_daily_target_limit = GREATEST(
        policy.api_key_daily_target_limit,
        COALESCE(key_usage.quantity, 0)
    ),
    updated_at = clock_timestamp()
FROM tenant_usage
FULL JOIN key_usage USING (tenant_id)
WHERE policy.tenant_id = COALESCE(tenant_usage.tenant_id, key_usage.tenant_id);

CREATE FUNCTION socialname_guard_developer_quota_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'developer quota identity is immutable'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER developer_quota_guard_update
BEFORE UPDATE ON developer_quota_policies
FOR EACH ROW EXECUTE FUNCTION socialname_guard_developer_quota_update();

CREATE FUNCTION socialname_lock_developer_quota(p_tenant_id uuid)
RETURNS TABLE (
    daily_target_limit integer,
    api_key_daily_target_limit integer
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
    IF p_tenant_id IS DISTINCT FROM public.socialname_current_tenant_id() THEN
        RAISE EXCEPTION 'developer quota tenant context is invalid'
            USING ERRCODE = '42501';
    END IF;

    RETURN QUERY
    SELECT
        policy.daily_target_limit,
        policy.api_key_daily_target_limit
    FROM public.developer_quota_policies AS policy
    WHERE policy.tenant_id = p_tenant_id
    FOR UPDATE OF policy;
END
$$;

REVOKE ALL ON FUNCTION socialname_lock_developer_quota(uuid)
FROM PUBLIC;

ALTER TABLE developer_quota_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE developer_quota_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON developer_quota_policies
    USING (tenant_id = socialname_current_tenant_id())
    WITH CHECK (tenant_id = socialname_current_tenant_id());

ALTER TABLE developer_usage_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE developer_usage_records FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON developer_usage_records
    USING (tenant_id = socialname_current_tenant_id())
    WITH CHECK (tenant_id = socialname_current_tenant_id());

CREATE FUNCTION socialname_worker_enforce_developer_usage_retention(
    p_batch_limit integer
)
RETURNS integer
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    deleted_count integer;
BEGIN
    IF p_batch_limit IS NULL OR p_batch_limit NOT BETWEEN 1 AND 1000 THEN
        RAISE EXCEPTION 'developer usage retention batch limit is invalid'
            USING ERRCODE = '22023';
    END IF;

    WITH candidates AS (
        SELECT usage.tenant_id, usage.id
        FROM public.developer_usage_records AS usage
        WHERE usage.retained_until <= clock_timestamp()
        ORDER BY usage.retained_until, usage.id
        LIMIT p_batch_limit
        FOR UPDATE SKIP LOCKED
    ),
    deleted AS (
        DELETE FROM public.developer_usage_records AS usage
        USING candidates
        WHERE usage.tenant_id = candidates.tenant_id
          AND usage.id = candidates.id
        RETURNING 1
    )
    SELECT count(*)::integer INTO deleted_count FROM deleted;

    RETURN deleted_count;
END
$$;

REVOKE ALL ON FUNCTION socialname_worker_enforce_developer_usage_retention(integer)
FROM PUBLIC;
