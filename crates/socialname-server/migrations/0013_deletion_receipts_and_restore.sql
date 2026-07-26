ALTER TABLE deletion_requests
    DROP CONSTRAINT deletion_requests_origin_closed,
    DROP CONSTRAINT deletion_requests_origin_relation,
    ADD CONSTRAINT deletion_requests_origin_closed CHECK (
        request_origin IS NULL
        OR request_origin IN (
            'contributor_api', 'verified_target_operator', 'restore_ledger'
        )
    ),
    ADD CONSTRAINT deletion_requests_origin_relation CHECK (
        request_origin IS NULL
        OR (
            request_origin = 'contributor_api'
            AND scope_kind = 'contributor'
            AND requested_by_membership_id IS NOT NULL
            AND consent_grant_id IS NOT NULL
            AND request_group_id IS NULL
            AND verification_reference_digest IS NULL
        )
        OR (
            request_origin = 'verified_target_operator'
            AND scope_kind = 'target'
            AND requested_by_membership_id IS NULL
            AND consent_grant_id IS NULL
            AND request_group_id IS NOT NULL
            AND octet_length(verification_reference_digest) = 32
        )
        OR (
            request_origin = 'restore_ledger'
            AND scope_kind IN ('contributor', 'target')
            AND requested_by_membership_id IS NULL
            AND consent_grant_id IS NULL
            AND request_group_id IS NOT NULL
            AND octet_length(verification_reference_digest) = 32
        )
    );

CREATE TABLE deletion_backup_verifications (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    deletion_request_id uuid NOT NULL,
    verification_reference_digest bytea NOT NULL,
    inventory_evidence_digest bytea NOT NULL,
    oldest_restorable_at timestamptz,
    no_restorable_backups boolean NOT NULL,
    verified_at timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, deletion_request_id),
    FOREIGN KEY (tenant_id, deletion_request_id)
        REFERENCES deletion_requests(tenant_id, id),
    CONSTRAINT deletion_backup_verification_digests CHECK (
        octet_length(verification_reference_digest) = 32
        AND octet_length(inventory_evidence_digest) = 32
    ),
    CONSTRAINT deletion_backup_inventory_relation CHECK (
        no_restorable_backups = (oldest_restorable_at IS NULL)
    )
);

CREATE TABLE deletion_restore_runs (
    id uuid PRIMARY KEY,
    artifact_digest bytea NOT NULL UNIQUE,
    key_fingerprint bytea NOT NULL,
    issued_at timestamptz NOT NULL,
    replayed_at timestamptz NOT NULL,
    verified_at timestamptz NOT NULL,
    entry_count integer NOT NULL,
    matched_observations integer NOT NULL,
    CONSTRAINT deletion_restore_run_digests CHECK (
        octet_length(artifact_digest) = 32
        AND octet_length(key_fingerprint) = 32
    ),
    CONSTRAINT deletion_restore_run_counts CHECK (
        entry_count BETWEEN 0 AND 100000
        AND matched_observations BETWEEN 0 AND 1000000
    ),
    CONSTRAINT deletion_restore_run_time_order CHECK (
        replayed_at >= issued_at AND verified_at >= replayed_at
    )
);

CREATE TABLE deletion_restore_request_links (
    restore_run_id uuid NOT NULL REFERENCES deletion_restore_runs(id),
    tenant_id uuid NOT NULL,
    deletion_request_id uuid NOT NULL,
    PRIMARY KEY (restore_run_id, tenant_id, deletion_request_id),
    FOREIGN KEY (tenant_id, deletion_request_id)
        REFERENCES deletion_requests(tenant_id, id)
);

ALTER TABLE deletion_backup_verifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE deletion_backup_verifications FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON deletion_backup_verifications
    USING (tenant_id = socialname_current_tenant_id())
    WITH CHECK (tenant_id = socialname_current_tenant_id());

REVOKE ALL ON deletion_backup_verifications FROM PUBLIC;
REVOKE ALL ON deletion_restore_runs FROM PUBLIC;
REVOKE ALL ON deletion_restore_request_links FROM PUBLIC;

CREATE TRIGGER deletion_backup_verifications_append_only
BEFORE UPDATE ON deletion_backup_verifications
FOR EACH ROW EXECUTE FUNCTION socialname_reject_update();

CREATE TRIGGER deletion_restore_runs_append_only
BEFORE UPDATE ON deletion_restore_runs
FOR EACH ROW EXECUTE FUNCTION socialname_reject_update();

CREATE TRIGGER deletion_restore_request_links_append_only
BEFORE UPDATE ON deletion_restore_request_links
FOR EACH ROW EXECUTE FUNCTION socialname_reject_update();

CREATE FUNCTION socialname_validate_deletion_backup_verification()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    request_row deletion_requests%ROWTYPE;
    primary_completed timestamptz;
    derived_completed timestamptz;
BEGIN
    SELECT * INTO request_row
    FROM deletion_requests
    WHERE tenant_id = NEW.tenant_id
      AND id = NEW.deletion_request_id
    FOR UPDATE;

    IF request_row.id IS NULL
        OR request_row.state <> 'rebuilding'
        OR NEW.verified_at < request_row.backup_expiry_by
    THEN
        RAISE EXCEPTION 'backup verification is premature'
            USING ERRCODE = '55000';
    END IF;

    SELECT completed_at INTO primary_completed
    FROM deletion_tasks
    WHERE tenant_id = NEW.tenant_id
      AND deletion_request_id = NEW.deletion_request_id
      AND store_kind = 'primary'
      AND state = 'completed';
    SELECT completed_at INTO derived_completed
    FROM deletion_tasks
    WHERE tenant_id = NEW.tenant_id
      AND deletion_request_id = NEW.deletion_request_id
      AND store_kind = 'analytics'
      AND state = 'completed';

    IF primary_completed IS NULL
        OR derived_completed IS NULL
        OR (
            NEW.oldest_restorable_at IS NOT NULL
            AND NEW.oldest_restorable_at <= primary_completed
        )
    THEN
        RAISE EXCEPTION 'backup inventory still reaches deleted primary data'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER deletion_backup_verification_gate
BEFORE INSERT ON deletion_backup_verifications
FOR EACH ROW EXECUTE FUNCTION socialname_validate_deletion_backup_verification();

CREATE FUNCTION socialname_validate_deletion_receipt()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    request_row deletion_requests%ROWTYPE;
    completed_tasks integer;
    expected_stores jsonb;
BEGIN
    SELECT * INTO request_row
    FROM deletion_requests
    WHERE tenant_id = NEW.tenant_id
      AND id = NEW.deletion_request_id
    FOR UPDATE;

    SELECT count(*) INTO completed_tasks
    FROM deletion_tasks
    WHERE tenant_id = NEW.tenant_id
      AND deletion_request_id = NEW.deletion_request_id
      AND store_kind IN ('primary', 'analytics', 'backup')
      AND state = 'completed';
    SELECT jsonb_object_agg(
        CASE store_kind WHEN 'analytics' THEN 'derived' ELSE store_kind END,
        jsonb_build_object(
            'state', state,
            'deadline_at_unix_ms',
                (EXTRACT(EPOCH FROM deadline_at) * 1000)::bigint,
            'completed_at_unix_ms',
                (EXTRACT(EPOCH FROM completed_at) * 1000)::bigint
        )
    ) INTO expected_stores
    FROM deletion_tasks
    WHERE tenant_id = NEW.tenant_id
      AND deletion_request_id = NEW.deletion_request_id
      AND store_kind IN ('primary', 'analytics', 'backup');

    IF request_row.request_origin IS NULL THEN
        RETURN NEW;
    END IF;

    IF request_row.id IS NULL
        OR request_row.state <> 'rebuilding'
        OR completed_tasks <> 3
        OR NEW.stores IS DISTINCT FROM expected_stores
        OR NEW.primary_completed_at IS DISTINCT FROM request_row.primary_completed_at
        OR NEW.backup_expiry_at IS DISTINCT FROM request_row.backup_expiry_by
        OR NEW.created_at < request_row.backup_expiry_by
        OR NOT EXISTS (
            SELECT 1 FROM deletion_backup_verifications AS verification
            WHERE verification.tenant_id = NEW.tenant_id
              AND verification.deletion_request_id = NEW.deletion_request_id
        )
    THEN
        RAISE EXCEPTION 'deletion receipt completion gate is not satisfied'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER deletion_receipt_completion_gate
BEFORE INSERT ON deletion_receipts
FOR EACH ROW EXECUTE FUNCTION socialname_validate_deletion_receipt();

CREATE FUNCTION socialname_restore_ledger_ready(p_restore_run_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM public.deletion_restore_runs AS run
        WHERE run.id = p_restore_run_id
          AND run.verified_at IS NOT NULL
    )
$$;

REVOKE ALL ON FUNCTION socialname_restore_ledger_ready(uuid) FROM PUBLIC;
