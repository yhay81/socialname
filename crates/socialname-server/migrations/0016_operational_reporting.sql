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
            'notification:read', 'notification:write', 'data:export', 'data:delete',
            'consent:read', 'consent:write', 'evidence:read', 'operations:read'
        ]::text[]
$$;

CREATE INDEX watch_runs_operational_report
ON watch_runs (tenant_id, created_at);

CREATE INDEX notification_deliveries_operational_report
ON notification_deliveries (tenant_id, created_at);
