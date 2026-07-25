CREATE FUNCTION socialname_api_key_scopes_valid(candidate text[])
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
            'notification:read', 'notification:write', 'data:export', 'data:delete'
        ]::text[]
$$;

ALTER TABLE api_keys
    DROP CONSTRAINT api_keys_scopes_nonempty,
    ADD CONSTRAINT api_keys_scopes_valid CHECK (socialname_api_key_scopes_valid(scopes)),
    ADD CONSTRAINT api_keys_last_used_order CHECK (
        last_used_at IS NULL OR last_used_at >= created_at
    );

CREATE TABLE api_key_credentials (
    key_prefix text PRIMARY KEY,
    tenant_id uuid NOT NULL,
    api_key_id uuid NOT NULL UNIQUE,
    secret_hash bytea NOT NULL UNIQUE,
    created_at timestamptz NOT NULL,
    FOREIGN KEY (tenant_id, api_key_id)
        REFERENCES api_keys(tenant_id, id)
        ON DELETE CASCADE,
    CONSTRAINT api_key_credentials_prefix_format CHECK (
        key_prefix ~ '^[0-9a-f]{16}$'
    ),
    CONSTRAINT api_key_credentials_hash_sha256 CHECK (
        octet_length(secret_hash) = 32
    )
);

REVOKE ALL ON api_key_credentials FROM PUBLIC;

ALTER TABLE api_keys NO FORCE ROW LEVEL SECURITY;

INSERT INTO api_key_credentials (
    key_prefix, tenant_id, api_key_id, secret_hash, created_at
)
SELECT key_prefix, tenant_id, id, secret_hash, created_at
FROM api_keys;

ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;

ALTER TABLE api_keys
    DROP CONSTRAINT api_keys_tenant_id_key_prefix_key,
    DROP CONSTRAINT api_keys_secret_hash_key,
    DROP CONSTRAINT api_keys_prefix_bound,
    DROP CONSTRAINT api_keys_hash_sha256,
    DROP COLUMN key_prefix,
    DROP COLUMN secret_hash;

CREATE FUNCTION socialname_authenticate_api_key(
    candidate_prefix text,
    candidate_hash bytea
)
RETURNS TABLE (tenant_id uuid, api_key_id uuid)
LANGUAGE sql
STABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
    SELECT credential.tenant_id, credential.api_key_id
    FROM public.api_key_credentials AS credential
    WHERE credential.key_prefix = candidate_prefix
      AND credential.secret_hash = candidate_hash
$$;

REVOKE ALL ON FUNCTION socialname_authenticate_api_key(text, bytea) FROM PUBLIC;
