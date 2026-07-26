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
            'consent:read', 'consent:write'
        ]::text[]
$$;

ALTER TABLE consent_grants
    ADD CONSTRAINT consent_current_contract_closed CHECK (
        collection_profile_version = 'profile-v1'
        AND notice_version = 'notice-v1'
    );

ALTER TABLE clients
    ADD COLUMN consent_owner_membership_id uuid,
    ADD CONSTRAINT clients_consent_owner_membership_fk
        FOREIGN KEY (tenant_id, consent_owner_membership_id)
        REFERENCES memberships(tenant_id, id);

CREATE INDEX consent_grants_account_page
ON consent_grants (tenant_id, membership_id, granted_at DESC, id DESC)
WHERE subject_kind = 'account';

CREATE INDEX consent_grants_installation_page
ON consent_grants (tenant_id, client_id, granted_at DESC, id DESC)
WHERE subject_kind = 'installation';

CREATE INDEX consent_events_actor_grant
ON consent_events (tenant_id, actor_membership_id, consent_grant_id, occurred_at DESC);

CREATE FUNCTION socialname_guard_consent_grant_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF ROW(
        NEW.id,
        NEW.tenant_id,
        NEW.membership_id,
        NEW.client_id,
        NEW.subject_kind,
        NEW.purpose,
        NEW.collection_profile_version,
        NEW.notice_version,
        NEW.source,
        NEW.granted_at,
        NEW.expires_at
    ) IS DISTINCT FROM ROW(
        OLD.id,
        OLD.tenant_id,
        OLD.membership_id,
        OLD.client_id,
        OLD.subject_kind,
        OLD.purpose,
        OLD.collection_profile_version,
        OLD.notice_version,
        OLD.source,
        OLD.granted_at,
        OLD.expires_at
    ) THEN
        RAISE EXCEPTION 'consent grant identity and contract are immutable'
            USING ERRCODE = '55000';
    END IF;
    IF OLD.withdrawn_at IS NOT NULL
        OR NEW.withdrawn_at IS NULL
        OR NEW.withdrawn_at < OLD.granted_at
    THEN
        RAISE EXCEPTION 'consent withdrawal is a one-way transition'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER consent_grants_withdrawal_only
BEFORE UPDATE ON consent_grants
FOR EACH ROW EXECUTE FUNCTION socialname_guard_consent_grant_update();
