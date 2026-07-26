ALTER TABLE deletion_requests
    ADD COLUMN request_origin text,
    ADD COLUMN consent_grant_id uuid,
    ADD COLUMN request_group_id uuid,
    ADD COLUMN verification_reference_digest bytea,
    ADD COLUMN support_withdrawn_at timestamptz,
    ADD COLUMN primary_completed_at timestamptz,
    ADD COLUMN processing_attempt integer NOT NULL DEFAULT 0,
    ADD COLUMN lease_owner text,
    ADD COLUMN lease_expires_at timestamptz,
    ADD COLUMN last_error_code text,
    ADD FOREIGN KEY (tenant_id, consent_grant_id)
        REFERENCES consent_grants(tenant_id, id),
    ADD CONSTRAINT deletion_requests_origin_closed CHECK (
        request_origin IS NULL
        OR request_origin IN ('contributor_api', 'verified_target_operator')
    ),
    ADD CONSTRAINT deletion_requests_origin_relation CHECK (
        request_origin IS NULL
        OR (
            request_origin = 'contributor_api'
            AND scope_kind = 'contributor'
            AND consent_grant_id IS NOT NULL
            AND request_group_id IS NULL
            AND verification_reference_digest IS NULL
        )
        OR (
            request_origin = 'verified_target_operator'
            AND scope_kind = 'target'
            AND consent_grant_id IS NULL
            AND request_group_id IS NOT NULL
            AND octet_length(verification_reference_digest) = 32
        )
    ),
    ADD CONSTRAINT deletion_requests_software_deadlines CHECK (
        request_origin IS NULL
        OR (
            hide_by = requested_at + interval '5 minutes'
            AND support_withdrawal_by = requested_at + interval '1 hour'
            AND primary_delete_by = requested_at + interval '24 hours'
            AND derived_rebuild_by = requested_at + interval '7 days'
            AND backup_expiry_by = requested_at + interval '35 days'
        )
    ),
    ADD CONSTRAINT deletion_requests_progress_relation CHECK (
        request_origin IS NULL
        OR (
            (support_withdrawn_at IS NULL OR support_withdrawn_at >= requested_at)
            AND (
                primary_completed_at IS NULL
                OR (
                    support_withdrawn_at IS NOT NULL
                    AND primary_completed_at >= support_withdrawn_at
                )
            )
            AND (
                completed_at IS NULL
                OR (
                    primary_completed_at IS NOT NULL
                    AND completed_at >= primary_completed_at
                )
            )
        )
    ),
    ADD CONSTRAINT deletion_requests_lease_relation CHECK (
        processing_attempt >= 0
        AND (
            (lease_owner IS NULL AND lease_expires_at IS NULL)
            OR (
                length(lease_owner) BETWEEN 1 AND 64
                AND lease_owner ~ '^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$'
                AND lease_expires_at IS NOT NULL
            )
        )
        AND (
            last_error_code IS NULL
            OR last_error_code IN ('storage', 'invariant', 'retry_exhausted')
        )
    );

ALTER TABLE suppression_tokens
    ADD COLUMN key_fingerprint bytea,
    ADD CONSTRAINT suppression_key_fingerprint_sha256 CHECK (
        key_fingerprint IS NULL OR octet_length(key_fingerprint) = 32
    );

ALTER TABLE watch_run_targets
    ADD COLUMN observation_deleted_at timestamptz,
    DROP CONSTRAINT watch_run_targets_state_relation,
    ADD CONSTRAINT watch_run_targets_state_relation CHECK (
        (
            state = 'pending'
            AND probe_job_id IS NULL
            AND observation_id IS NULL
            AND observation_deleted_at IS NULL
            AND completed_at IS NULL
        )
        OR (
            state = 'satisfied'
            AND probe_job_id IS NULL
            AND (
                (observation_id IS NOT NULL AND observation_deleted_at IS NULL)
                OR (observation_id IS NULL AND observation_deleted_at IS NOT NULL)
            )
            AND completed_at IS NOT NULL
        )
        OR (
            state = 'queued'
            AND probe_job_id IS NOT NULL
            AND observation_id IS NULL
            AND observation_deleted_at IS NULL
            AND completed_at IS NULL
        )
        OR (
            state = 'completed'
            AND probe_job_id IS NOT NULL
            AND (
                (observation_id IS NOT NULL AND observation_deleted_at IS NULL)
                OR (observation_id IS NULL AND observation_deleted_at IS NOT NULL)
            )
            AND completed_at IS NOT NULL
        )
        OR (
            state IN ('failed', 'cancelled')
            AND observation_id IS NULL
            AND observation_deleted_at IS NULL
            AND completed_at IS NOT NULL
        )
    ),
    ADD CONSTRAINT watch_run_targets_deletion_time_order CHECK (
        observation_deleted_at IS NULL
        OR observation_deleted_at >= created_at
    );

CREATE TABLE deletion_resource_matches (
    tenant_id uuid NOT NULL,
    deletion_request_id uuid NOT NULL,
    resource_kind text NOT NULL,
    resource_id uuid NOT NULL,
    hidden_at timestamptz NOT NULL,
    support_withdrawn_at timestamptz,
    primary_deleted_at timestamptz,
    PRIMARY KEY (tenant_id, deletion_request_id, resource_kind, resource_id),
    FOREIGN KEY (tenant_id, deletion_request_id)
        REFERENCES deletion_requests(tenant_id, id),
    CONSTRAINT deletion_resource_matches_kind_closed CHECK (
        resource_kind IN (
            'observation', 'evidence_capsule', 'assertion',
            'regional_assertion', 'search_event', 'watch_run_target',
            'transition', 'notification_delivery', 'probe_job', 'search_target'
        )
    ),
    CONSTRAINT deletion_resource_matches_time_order CHECK (
        (support_withdrawn_at IS NULL OR support_withdrawn_at >= hidden_at)
        AND (
            primary_deleted_at IS NULL
            OR (
                support_withdrawn_at IS NOT NULL
                AND primary_deleted_at >= support_withdrawn_at
            )
        )
    )
);

CREATE INDEX deletion_resource_matches_resource
ON deletion_resource_matches (tenant_id, resource_kind, resource_id);

CREATE INDEX deletion_requests_worker_due
ON deletion_requests (support_withdrawal_by, requested_at, id)
WHERE request_origin IS NOT NULL
  AND state IN ('hidden', 'withdrawing_support', 'deleting');

ALTER TABLE deletion_resource_matches ENABLE ROW LEVEL SECURITY;
ALTER TABLE deletion_resource_matches FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON deletion_resource_matches
    USING (tenant_id = socialname_current_tenant_id())
    WITH CHECK (tenant_id = socialname_current_tenant_id());

REVOKE ALL ON deletion_resource_matches FROM PUBLIC;

CREATE FUNCTION socialname_guard_deletion_request_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    old_rank integer;
    new_rank integer;
BEGIN
    IF ROW(
        NEW.id, NEW.tenant_id, NEW.requested_by_membership_id,
        NEW.scope_kind, NEW.selector_token, NEW.selector_ciphertext,
        NEW.requested_at, NEW.hide_by, NEW.support_withdrawal_by,
        NEW.primary_delete_by, NEW.derived_rebuild_by, NEW.backup_expiry_by,
        NEW.request_origin, NEW.consent_grant_id, NEW.request_group_id,
        NEW.verification_reference_digest
    ) IS DISTINCT FROM ROW(
        OLD.id, OLD.tenant_id, OLD.requested_by_membership_id,
        OLD.scope_kind, OLD.selector_token, OLD.selector_ciphertext,
        OLD.requested_at, OLD.hide_by, OLD.support_withdrawal_by,
        OLD.primary_delete_by, OLD.derived_rebuild_by, OLD.backup_expiry_by,
        OLD.request_origin, OLD.consent_grant_id, OLD.request_group_id,
        OLD.verification_reference_digest
    ) THEN
        RAISE EXCEPTION 'deletion request identity and deadlines are immutable'
            USING ERRCODE = '55000';
    END IF;

    old_rank := CASE OLD.state
        WHEN 'accepted' THEN 0
        WHEN 'hidden' THEN 1
        WHEN 'withdrawing_support' THEN 2
        WHEN 'deleting' THEN 3
        WHEN 'rebuilding' THEN 4
        WHEN 'completed' THEN 5
        WHEN 'failed' THEN 6
    END;
    new_rank := CASE NEW.state
        WHEN 'accepted' THEN 0
        WHEN 'hidden' THEN 1
        WHEN 'withdrawing_support' THEN 2
        WHEN 'deleting' THEN 3
        WHEN 'rebuilding' THEN 4
        WHEN 'completed' THEN 5
        WHEN 'failed' THEN 6
    END;
    IF NEW.state <> OLD.state
        AND NOT (
            NEW.state = 'failed'
            OR (OLD.state <> 'failed' AND new_rank = old_rank + 1)
        )
    THEN
        RAISE EXCEPTION 'deletion request state transition is invalid'
            USING ERRCODE = '55000';
    END IF;
    IF OLD.support_withdrawn_at IS NOT NULL
        AND NEW.support_withdrawn_at IS DISTINCT FROM OLD.support_withdrawn_at
    THEN
        RAISE EXCEPTION 'support withdrawal time is immutable'
            USING ERRCODE = '55000';
    END IF;
    IF OLD.primary_completed_at IS NOT NULL
        AND NEW.primary_completed_at IS DISTINCT FROM OLD.primary_completed_at
    THEN
        RAISE EXCEPTION 'primary completion time is immutable'
            USING ERRCODE = '55000';
    END IF;
    IF OLD.completed_at IS NOT NULL
        AND NEW.completed_at IS DISTINCT FROM OLD.completed_at
    THEN
        RAISE EXCEPTION 'deletion completion time is immutable'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER deletion_requests_ordered_progress
BEFORE UPDATE ON deletion_requests
FOR EACH ROW EXECUTE FUNCTION socialname_guard_deletion_request_update();

CREATE FUNCTION socialname_guard_deletion_resource_match_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF ROW(
        NEW.tenant_id, NEW.deletion_request_id,
        NEW.resource_kind, NEW.resource_id, NEW.hidden_at
    ) IS DISTINCT FROM ROW(
        OLD.tenant_id, OLD.deletion_request_id,
        OLD.resource_kind, OLD.resource_id, OLD.hidden_at
    ) THEN
        RAISE EXCEPTION 'deletion resource match identity is immutable'
            USING ERRCODE = '55000';
    END IF;
    IF OLD.support_withdrawn_at IS NOT NULL
        AND NEW.support_withdrawn_at IS DISTINCT FROM OLD.support_withdrawn_at
    THEN
        RAISE EXCEPTION 'resource support withdrawal is immutable'
            USING ERRCODE = '55000';
    END IF;
    IF OLD.primary_deleted_at IS NOT NULL
        AND NEW.primary_deleted_at IS DISTINCT FROM OLD.primary_deleted_at
    THEN
        RAISE EXCEPTION 'resource primary deletion is immutable'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER deletion_resource_matches_ordered_progress
BEFORE UPDATE ON deletion_resource_matches
FOR EACH ROW EXECUTE FUNCTION socialname_guard_deletion_resource_match_update();

CREATE FUNCTION socialname_redact_deletion_job_targets(
    p_tenant_id uuid,
    p_deletion_request_id uuid
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
    IF p_tenant_id IS DISTINCT FROM public.socialname_current_tenant_id()
        OR NOT EXISTS (
            SELECT 1 FROM public.deletion_requests AS request
            WHERE request.tenant_id = p_tenant_id
              AND request.id = p_deletion_request_id
              AND request.request_origin IS NOT NULL
              AND request.state = 'hidden'
        )
    THEN
        RAISE EXCEPTION 'deletion redaction context is invalid'
            USING ERRCODE = '42501';
    END IF;

    UPDATE public.search_targets AS target
       SET requested_username =
                'deleted-target-' || replace(target.id::text, '-', ''),
           normalized_username =
                'deleted-target-' || replace(target.id::text, '-', ''),
           state = CASE
                WHEN target.state IN ('pending', 'running') THEN 'cancelled'
                ELSE target.state
           END,
           completed_at = CASE
                WHEN target.state IN ('pending', 'running')
                THEN clock_timestamp()
                ELSE target.completed_at
           END
     WHERE target.tenant_id = p_tenant_id
       AND EXISTS (
            SELECT 1 FROM public.deletion_resource_matches AS matched
            WHERE matched.tenant_id = target.tenant_id
              AND matched.deletion_request_id = p_deletion_request_id
              AND matched.resource_kind = 'search_target'
              AND matched.resource_id = target.id
       );

    UPDATE public.probe_jobs AS job
       SET normalized_username =
                'deleted-target-' || replace(job.id::text, '-', ''),
           work_key_hash = decode(
                md5(job.id::text || ':' || p_deletion_request_id::text)
                || md5(
                    job.id::text || ':' || p_deletion_request_id::text
                    || ':redacted'
                ),
                'hex'
           ),
           state = CASE
                WHEN job.state IN ('queued', 'leased', 'retry_wait')
                THEN 'cancelled'
                ELSE job.state
           END,
           lease_owner = NULL,
           lease_expires_at = NULL,
           last_error_code = NULL,
           updated_at = clock_timestamp(),
           completed_at = CASE
                WHEN job.state IN ('queued', 'leased', 'retry_wait')
                THEN clock_timestamp()
                ELSE job.completed_at
           END
     WHERE job.tenant_id = p_tenant_id
       AND EXISTS (
            SELECT 1 FROM public.deletion_resource_matches AS matched
            WHERE matched.tenant_id = job.tenant_id
              AND matched.deletion_request_id = p_deletion_request_id
              AND matched.resource_kind = 'probe_job'
              AND matched.resource_id = job.id
       );
END
$$;

REVOKE ALL ON FUNCTION
    socialname_redact_deletion_job_targets(uuid, uuid)
FROM PUBLIC;

CREATE FUNCTION socialname_worker_claim_deletion(
    p_lease_owner text,
    p_lease_seconds integer
)
RETURNS TABLE (
    tenant_id uuid,
    deletion_request_id uuid,
    processing_attempt integer
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
    IF p_lease_owner IS NULL
        OR length(p_lease_owner) NOT BETWEEN 1 AND 64
        OR p_lease_owner !~ '^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$'
        OR p_lease_seconds IS NULL
        OR p_lease_seconds NOT BETWEEN 5 AND 300
    THEN
        RAISE EXCEPTION 'deletion lease configuration is invalid'
            USING ERRCODE = '22023';
    END IF;

    RETURN QUERY
    WITH candidate AS (
        SELECT request.tenant_id, request.id
        FROM public.deletion_requests AS request
        WHERE request.request_origin IS NOT NULL
          AND request.state IN ('hidden', 'withdrawing_support', 'deleting')
          AND (
              request.lease_expires_at IS NULL
              OR request.lease_expires_at <= clock_timestamp()
          )
        ORDER BY request.support_withdrawal_by, request.requested_at, request.id
        LIMIT 1
        FOR UPDATE SKIP LOCKED
    )
    UPDATE public.deletion_requests AS request
    SET state = CASE request.state
            WHEN 'hidden' THEN 'withdrawing_support'
            ELSE request.state
        END,
        processing_attempt = request.processing_attempt + 1,
        lease_owner = p_lease_owner,
        lease_expires_at = clock_timestamp()
            + make_interval(secs => p_lease_seconds),
        last_error_code = NULL
    FROM candidate
    WHERE request.tenant_id = candidate.tenant_id
      AND request.id = candidate.id
    RETURNING
        request.tenant_id,
        request.id,
        request.processing_attempt;
END
$$;

REVOKE ALL ON FUNCTION socialname_worker_claim_deletion(text, integer)
FROM PUBLIC;
