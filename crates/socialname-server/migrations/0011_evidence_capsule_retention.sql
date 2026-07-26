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
            'consent:read', 'consent:write', 'evidence:read'
        ]::text[]
$$;

CREATE TABLE evidence_capsules (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    observation_id uuid NOT NULL,
    collection_profile text NOT NULL,
    structured_payload jsonb,
    structured_payload_digest bytea NOT NULL,
    structured_payload_bytes integer NOT NULL,
    collected_at timestamptz NOT NULL,
    structured_retained_until timestamptz NOT NULL,
    structured_purged_at timestamptz,
    research_excerpt text,
    research_excerpt_digest bytea,
    research_retained_until timestamptz,
    research_purged_at timestamptz,
    created_at timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, observation_id),
    FOREIGN KEY (tenant_id, observation_id)
        REFERENCES observations(tenant_id, id),
    CONSTRAINT evidence_capsules_profile_closed CHECK (
        collection_profile IN (
            'private_history', 'shared_observation', 'shared_research'
        )
    ),
    CONSTRAINT evidence_capsules_structured_digest_sha256 CHECK (
        octet_length(structured_payload_digest) = 32
    ),
    CONSTRAINT evidence_capsules_structured_size_bound CHECK (
        structured_payload_bytes BETWEEN 2 AND 65536
    ),
    CONSTRAINT evidence_capsules_structured_state CHECK (
        (
            structured_payload IS NOT NULL
            AND structured_purged_at IS NULL
            AND jsonb_typeof(structured_payload) = 'object'
            AND octet_length(structured_payload::text) <= 65536
            AND structured_payload ?& ARRAY[
                'schema', 'capsule_schema', 'evidence_capsule_id',
                'observation_id', 'profile', 'target', 'outcome',
                'provenance', 'vantage', 'evidence_class',
                'evidence_digest', 'profile_url', 'probes', 'matcher_trace',
                'collected_at_unix_ms', 'structured_retained_until_unix_ms',
                'research_extension', 'research_retained_until_unix_ms'
            ]
            AND structured_payload - ARRAY[
                'schema', 'capsule_schema', 'evidence_capsule_id',
                'observation_id', 'profile', 'target', 'outcome',
                'provenance', 'vantage', 'evidence_class',
                'evidence_digest', 'profile_url', 'probes', 'matcher_trace',
                'collected_at_unix_ms', 'structured_retained_until_unix_ms',
                'research_extension', 'research_retained_until_unix_ms'
            ] = '{}'::jsonb
            AND structured_payload ->> 'schema' = 'socialname.dev/api/v1'
            AND structured_payload ->> 'capsule_schema'
                = 'socialname.dev/evidence-capsule/v1'
            AND structured_payload ->> 'evidence_capsule_id' = id::text
            AND structured_payload ->> 'observation_id' = observation_id::text
            AND structured_payload ->> 'profile' = collection_profile
            AND (structured_payload ->> 'collected_at_unix_ms')::bigint
                = (EXTRACT(EPOCH FROM collected_at) * 1000)::bigint
            AND (
                structured_payload ->> 'structured_retained_until_unix_ms'
            )::bigint = (
                EXTRACT(EPOCH FROM structured_retained_until) * 1000
            )::bigint
            AND structured_payload -> 'research_extension' = 'null'::jsonb
            AND structured_payload -> 'research_retained_until_unix_ms'
                = 'null'::jsonb
        )
        OR (
            structured_payload IS NULL
            AND structured_purged_at IS NOT NULL
        )
    ),
    CONSTRAINT evidence_capsules_structured_retention CHECK (
        structured_retained_until > collected_at
        AND structured_retained_until <= collected_at + interval '730 days'
        AND (
            collection_profile = 'private_history'
            OR structured_retained_until = collected_at + interval '400 days'
        )
        AND (
            structured_purged_at IS NULL
            OR structured_purged_at >= structured_retained_until
        )
    ),
    CONSTRAINT evidence_capsules_research_state CHECK (
        (
            research_excerpt IS NULL
            AND research_excerpt_digest IS NULL
            AND research_retained_until IS NULL
            AND research_purged_at IS NULL
        )
        OR (
            collection_profile = 'shared_research'
            AND research_excerpt IS NOT NULL
            AND octet_length(research_excerpt) BETWEEN 1 AND 2048
            AND octet_length(research_excerpt_digest) = 32
            AND research_retained_until > collected_at
            AND research_retained_until <= collected_at + interval '30 days'
            AND research_retained_until <= structured_retained_until
            AND research_purged_at IS NULL
        )
        OR (
            collection_profile = 'shared_research'
            AND research_excerpt IS NULL
            AND octet_length(research_excerpt_digest) = 32
            AND research_retained_until > collected_at
            AND research_retained_until <= collected_at + interval '30 days'
            AND research_retained_until <= structured_retained_until
            AND research_purged_at >= research_retained_until
        )
    ),
    CONSTRAINT evidence_capsules_time_order CHECK (
        created_at >= collected_at
    )
);

CREATE TABLE evidence_retention_receipts (
    tenant_id uuid NOT NULL,
    evidence_capsule_id uuid NOT NULL,
    action text NOT NULL,
    deadline_at timestamptz NOT NULL,
    completed_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, evidence_capsule_id, action),
    FOREIGN KEY (tenant_id, evidence_capsule_id)
        REFERENCES evidence_capsules(tenant_id, id),
    CONSTRAINT evidence_retention_receipts_action_closed CHECK (
        action IN ('research_excerpt_purged', 'structured_capsule_purged')
    ),
    CONSTRAINT evidence_retention_receipts_time_order CHECK (
        completed_at >= deadline_at
        AND expires_at = completed_at + interval '3 years'
    )
);

CREATE INDEX evidence_capsules_research_due
ON evidence_capsules (research_retained_until, id)
WHERE research_excerpt IS NOT NULL;

CREATE INDEX evidence_capsules_structured_due
ON evidence_capsules (structured_retained_until, id)
WHERE structured_payload IS NOT NULL;

CREATE INDEX evidence_retention_receipts_expiry
ON evidence_retention_receipts (expires_at, evidence_capsule_id);

ALTER TABLE evidence_capsules ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence_capsules FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON evidence_capsules
    USING (tenant_id = socialname_current_tenant_id())
    WITH CHECK (tenant_id = socialname_current_tenant_id());

ALTER TABLE evidence_retention_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence_retention_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON evidence_retention_receipts
    USING (tenant_id = socialname_current_tenant_id())
    WITH CHECK (tenant_id = socialname_current_tenant_id());

REVOKE ALL ON evidence_capsules, evidence_retention_receipts FROM PUBLIC;

CREATE FUNCTION socialname_guard_evidence_capsule_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    structured_purged boolean;
    research_purged boolean;
BEGIN
    IF ROW(
        NEW.id,
        NEW.tenant_id,
        NEW.observation_id,
        NEW.collection_profile,
        NEW.structured_payload_digest,
        NEW.structured_payload_bytes,
        NEW.collected_at,
        NEW.structured_retained_until,
        NEW.research_excerpt_digest,
        NEW.research_retained_until,
        NEW.created_at
    ) IS DISTINCT FROM ROW(
        OLD.id,
        OLD.tenant_id,
        OLD.observation_id,
        OLD.collection_profile,
        OLD.structured_payload_digest,
        OLD.structured_payload_bytes,
        OLD.collected_at,
        OLD.structured_retained_until,
        OLD.research_excerpt_digest,
        OLD.research_retained_until,
        OLD.created_at
    ) THEN
        RAISE EXCEPTION 'evidence capsule identity, digest, and deadlines are immutable'
            USING ERRCODE = '55000';
    END IF;

    structured_purged :=
        OLD.structured_payload IS NOT NULL
        AND NEW.structured_payload IS NULL
        AND OLD.structured_purged_at IS NULL
        AND NEW.structured_purged_at IS NOT NULL
        AND NEW.structured_purged_at >= OLD.structured_retained_until
        AND clock_timestamp() >= OLD.structured_retained_until;
    research_purged :=
        OLD.research_excerpt IS NOT NULL
        AND NEW.research_excerpt IS NULL
        AND OLD.research_purged_at IS NULL
        AND NEW.research_purged_at IS NOT NULL
        AND NEW.research_purged_at >= OLD.research_retained_until
        AND clock_timestamp() >= OLD.research_retained_until;

    IF NEW.structured_payload IS DISTINCT FROM OLD.structured_payload
        OR NEW.structured_purged_at IS DISTINCT FROM OLD.structured_purged_at
    THEN
        IF NOT structured_purged THEN
            RAISE EXCEPTION 'structured evidence can only be purged after its deadline'
                USING ERRCODE = '55000';
        END IF;
    END IF;

    IF NEW.research_excerpt IS DISTINCT FROM OLD.research_excerpt
        OR NEW.research_purged_at IS DISTINCT FROM OLD.research_purged_at
    THEN
        IF NOT research_purged THEN
            RAISE EXCEPTION 'research evidence can only be purged after its deadline'
                USING ERRCODE = '55000';
        END IF;
    END IF;

    IF NOT structured_purged AND NOT research_purged THEN
        RAISE EXCEPTION 'evidence capsule updates require a retention transition'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER evidence_capsules_retention_only
BEFORE UPDATE ON evidence_capsules
FOR EACH ROW EXECUTE FUNCTION socialname_guard_evidence_capsule_update();

CREATE TRIGGER evidence_retention_receipts_append_only
BEFORE UPDATE ON evidence_retention_receipts
FOR EACH ROW EXECUTE FUNCTION socialname_reject_update();

CREATE FUNCTION socialname_worker_enforce_evidence_retention(p_batch_limit integer)
RETURNS TABLE (
    research_excerpts_purged integer,
    structured_capsules_purged integer,
    expired_receipts_deleted integer
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    research_count integer;
    structured_count integer;
    receipt_count integer;
BEGIN
    IF p_batch_limit IS NULL OR p_batch_limit NOT BETWEEN 1 AND 1000 THEN
        RAISE EXCEPTION 'evidence retention batch limit is invalid'
            USING ERRCODE = '22023';
    END IF;

    WITH candidates AS (
        SELECT capsule.tenant_id, capsule.id
        FROM public.evidence_capsules AS capsule
        WHERE capsule.research_excerpt IS NOT NULL
          AND capsule.research_retained_until <= clock_timestamp()
        ORDER BY capsule.research_retained_until, capsule.id
        LIMIT p_batch_limit
        FOR UPDATE SKIP LOCKED
    ),
    purged AS (
        UPDATE public.evidence_capsules AS capsule
        SET research_excerpt = NULL,
            research_purged_at = clock_timestamp()
        FROM candidates
        WHERE capsule.tenant_id = candidates.tenant_id
          AND capsule.id = candidates.id
        RETURNING
            capsule.tenant_id,
            capsule.id,
            capsule.research_retained_until,
            capsule.research_purged_at
    ),
    receipts AS (
        INSERT INTO public.evidence_retention_receipts (
            tenant_id, evidence_capsule_id, action, deadline_at,
            completed_at, expires_at
        )
        SELECT
            tenant_id, id, 'research_excerpt_purged',
            research_retained_until, research_purged_at,
            research_purged_at + interval '3 years'
        FROM purged
        ON CONFLICT (tenant_id, evidence_capsule_id, action) DO NOTHING
        RETURNING 1
    )
    SELECT count(*)::integer INTO research_count FROM purged;

    WITH candidates AS (
        SELECT capsule.tenant_id, capsule.id
        FROM public.evidence_capsules AS capsule
        WHERE capsule.structured_payload IS NOT NULL
          AND capsule.structured_retained_until <= clock_timestamp()
        ORDER BY capsule.structured_retained_until, capsule.id
        LIMIT p_batch_limit
        FOR UPDATE SKIP LOCKED
    ),
    purged AS (
        UPDATE public.evidence_capsules AS capsule
        SET structured_payload = NULL,
            structured_purged_at = clock_timestamp()
        FROM candidates
        WHERE capsule.tenant_id = candidates.tenant_id
          AND capsule.id = candidates.id
        RETURNING
            capsule.tenant_id,
            capsule.id,
            capsule.structured_retained_until,
            capsule.structured_purged_at
    ),
    receipts AS (
        INSERT INTO public.evidence_retention_receipts (
            tenant_id, evidence_capsule_id, action, deadline_at,
            completed_at, expires_at
        )
        SELECT
            tenant_id, id, 'structured_capsule_purged',
            structured_retained_until, structured_purged_at,
            structured_purged_at + interval '3 years'
        FROM purged
        ON CONFLICT (tenant_id, evidence_capsule_id, action) DO NOTHING
        RETURNING 1
    )
    SELECT count(*)::integer INTO structured_count FROM purged;

    WITH candidates AS (
        SELECT receipt.tenant_id, receipt.evidence_capsule_id, receipt.action
        FROM public.evidence_retention_receipts AS receipt
        WHERE receipt.expires_at <= clock_timestamp()
        ORDER BY receipt.expires_at, receipt.evidence_capsule_id, receipt.action
        LIMIT p_batch_limit
        FOR UPDATE SKIP LOCKED
    ),
    deleted AS (
        DELETE FROM public.evidence_retention_receipts AS receipt
        USING candidates
        WHERE receipt.tenant_id = candidates.tenant_id
          AND receipt.evidence_capsule_id = candidates.evidence_capsule_id
          AND receipt.action = candidates.action
        RETURNING 1
    )
    SELECT count(*)::integer INTO receipt_count FROM deleted;

    RETURN QUERY SELECT research_count, structured_count, receipt_count;
END
$$;

REVOKE ALL ON FUNCTION socialname_worker_enforce_evidence_retention(integer)
FROM PUBLIC;
