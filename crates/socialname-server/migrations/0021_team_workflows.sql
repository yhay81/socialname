ALTER TABLE memberships
ADD COLUMN display_name text;

UPDATE memberships
SET display_name = CASE
    WHEN role = 'owner' THEN 'Workspace owner'
    ELSE 'Workspace member'
END;

ALTER TABLE memberships
ALTER COLUMN display_name SET NOT NULL,
ALTER COLUMN display_name SET DEFAULT 'Workspace member',
ADD COLUMN revision bigint NOT NULL DEFAULT 1,
ADD CONSTRAINT memberships_display_name_bound CHECK (
    length(display_name) BETWEEN 1 AND 100
    AND display_name !~ '[[:cntrl:]]'
),
ADD CONSTRAINT memberships_revision_positive CHECK (revision >= 1);

CREATE INDEX memberships_created_page
ON memberships (tenant_id, created_at, id);

CREATE TABLE organization_retention_policies (
    tenant_id uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    revision bigint NOT NULL DEFAULT 1,
    minimum_watch_retention_days smallint NOT NULL DEFAULT 30,
    maximum_watch_retention_days smallint NOT NULL DEFAULT 730,
    updated_by_membership_id uuid,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    FOREIGN KEY (tenant_id, updated_by_membership_id)
        REFERENCES memberships(tenant_id, id),
    CONSTRAINT organization_retention_revision_positive CHECK (revision >= 1),
    CONSTRAINT organization_retention_watch_bounds CHECK (
        minimum_watch_retention_days BETWEEN 30 AND 730
        AND maximum_watch_retention_days BETWEEN minimum_watch_retention_days AND 730
    ),
    CONSTRAINT organization_retention_time_order CHECK (updated_at >= created_at)
);

CREATE FUNCTION socialname_insert_initial_organization_retention_policy()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
    INSERT INTO public.organization_retention_policies (
        tenant_id, revision, minimum_watch_retention_days,
        maximum_watch_retention_days, created_at, updated_at
    ) VALUES (
        NEW.id, 1, 30, 730, clock_timestamp(), clock_timestamp()
    );
    RETURN NEW;
END
$$;

CREATE TRIGGER tenants_initial_organization_retention_policy
AFTER INSERT ON tenants
FOR EACH ROW
EXECUTE FUNCTION socialname_insert_initial_organization_retention_policy();

REVOKE ALL ON FUNCTION socialname_insert_initial_organization_retention_policy()
FROM PUBLIC;

INSERT INTO organization_retention_policies (
    tenant_id, revision, minimum_watch_retention_days,
    maximum_watch_retention_days, created_at, updated_at
)
SELECT id, 1, 30, 730, clock_timestamp(), clock_timestamp()
FROM tenants;

CREATE FUNCTION socialname_provision_organization_member(
    p_tenant_id uuid,
    p_actor_membership_id uuid,
    p_membership_id uuid,
    p_subject_id text,
    p_display_name text,
    p_role text
)
RETURNS TABLE (
    id uuid,
    display_name text,
    role text,
    state text,
    revision bigint,
    created_at_unix_ms bigint,
    updated_at_unix_ms bigint,
    was_existing boolean
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    actor_role text;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 0));

    IF p_tenant_id IS DISTINCT FROM public.socialname_current_tenant_id() THEN
        RAISE EXCEPTION 'organization member tenant context is invalid'
            USING ERRCODE = '42501';
    END IF;

    SELECT membership.role
    INTO actor_role
    FROM public.memberships AS membership
    JOIN public.tenants AS tenant
      ON tenant.id = membership.tenant_id
    WHERE membership.tenant_id = p_tenant_id
      AND membership.id = p_actor_membership_id
      AND membership.state = 'active'
      AND membership.role IN ('owner', 'administrator')
      AND tenant.state = 'active';

    IF actor_role IS NULL
       OR (
            actor_role = 'administrator'
            AND p_role NOT IN ('member', 'viewer')
       ) THEN
        RAISE EXCEPTION 'organization member actor is not permitted'
            USING ERRCODE = '42501';
    END IF;

    RETURN QUERY
    SELECT
        membership.id,
        membership.display_name,
        membership.role,
        membership.state,
        membership.revision,
        (extract(epoch FROM membership.created_at) * 1000)::bigint,
        (extract(epoch FROM membership.updated_at) * 1000)::bigint,
        TRUE
    FROM public.memberships AS membership
    WHERE membership.tenant_id = p_tenant_id
      AND membership.subject_id = p_subject_id
    FOR UPDATE OF membership;

    IF FOUND THEN
        RETURN;
    END IF;

    RETURN QUERY
    INSERT INTO public.memberships (
        id, tenant_id, subject_id, display_name, role, state, revision,
        created_at, updated_at
    ) VALUES (
        p_membership_id, p_tenant_id, p_subject_id, p_display_name, p_role,
        'active', 1, clock_timestamp(), clock_timestamp()
    )
    RETURNING
        memberships.id,
        memberships.display_name,
        memberships.role,
        memberships.state,
        memberships.revision,
        (extract(epoch FROM memberships.created_at) * 1000)::bigint,
        (extract(epoch FROM memberships.updated_at) * 1000)::bigint,
        FALSE;
END
$$;

REVOKE ALL ON FUNCTION socialname_provision_organization_member(
    uuid, uuid, uuid, text, text, text
)
FROM PUBLIC;

CREATE TABLE transition_reviews (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    transition_id uuid NOT NULL,
    state text NOT NULL DEFAULT 'open',
    revision bigint NOT NULL DEFAULT 1,
    assigned_membership_id uuid,
    acknowledged_by_membership_id uuid,
    acknowledged_at timestamptz,
    resolved_by_membership_id uuid,
    resolved_at timestamptz,
    resolution text,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, transition_id),
    FOREIGN KEY (tenant_id, transition_id)
        REFERENCES transitions(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, assigned_membership_id)
        REFERENCES memberships(tenant_id, id),
    FOREIGN KEY (tenant_id, acknowledged_by_membership_id)
        REFERENCES memberships(tenant_id, id),
    FOREIGN KEY (tenant_id, resolved_by_membership_id)
        REFERENCES memberships(tenant_id, id),
    CONSTRAINT transition_reviews_state_closed CHECK (
        state IN ('open', 'acknowledged', 'resolved')
    ),
    CONSTRAINT transition_reviews_revision_positive CHECK (revision >= 1),
    CONSTRAINT transition_reviews_resolution_closed CHECK (
        resolution IS NULL
        OR resolution IN (
            'action_taken', 'no_action_required',
            'measurement_follow_up', 'externally_escalated'
        )
    ),
    CONSTRAINT transition_reviews_state_relation CHECK (
        (
            state = 'open'
            AND acknowledged_by_membership_id IS NULL
            AND acknowledged_at IS NULL
            AND resolved_by_membership_id IS NULL
            AND resolved_at IS NULL
            AND resolution IS NULL
        )
        OR (
            state = 'acknowledged'
            AND assigned_membership_id IS NOT NULL
            AND acknowledged_by_membership_id = assigned_membership_id
            AND acknowledged_at IS NOT NULL
            AND resolved_by_membership_id IS NULL
            AND resolved_at IS NULL
            AND resolution IS NULL
        )
        OR (
            state = 'resolved'
            AND assigned_membership_id IS NOT NULL
            AND acknowledged_by_membership_id = assigned_membership_id
            AND acknowledged_at IS NOT NULL
            AND resolved_by_membership_id = assigned_membership_id
            AND resolved_at IS NOT NULL
            AND resolution IS NOT NULL
        )
    ),
    CONSTRAINT transition_reviews_time_order CHECK (
        updated_at >= created_at
        AND (acknowledged_at IS NULL OR acknowledged_at >= created_at)
        AND (
            resolved_at IS NULL
            OR (
                acknowledged_at IS NOT NULL
                AND resolved_at >= acknowledged_at
            )
        )
    )
);

CREATE INDEX transition_reviews_queue_page
ON transition_reviews (tenant_id, updated_at DESC, id DESC);

CREATE TABLE transition_review_events (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    review_id uuid NOT NULL,
    actor_membership_id uuid,
    actor_api_key_id uuid,
    action text NOT NULL,
    from_state text,
    to_state text NOT NULL,
    assigned_membership_id uuid,
    resolution text,
    occurred_at timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, review_id)
        REFERENCES transition_reviews(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, actor_membership_id)
        REFERENCES memberships(tenant_id, id),
    FOREIGN KEY (tenant_id, actor_api_key_id)
        REFERENCES api_keys(tenant_id, id),
    FOREIGN KEY (tenant_id, assigned_membership_id)
        REFERENCES memberships(tenant_id, id),
    CONSTRAINT transition_review_events_action_closed CHECK (
        action IN ('opened', 'assigned', 'acknowledged', 'resolved')
    ),
    CONSTRAINT transition_review_events_state_closed CHECK (
        from_state IS NULL OR from_state IN ('open', 'acknowledged', 'resolved')
    ),
    CONSTRAINT transition_review_events_to_state_closed CHECK (
        to_state IN ('open', 'acknowledged', 'resolved')
    ),
    CONSTRAINT transition_review_events_resolution_closed CHECK (
        resolution IS NULL
        OR resolution IN (
            'action_taken', 'no_action_required',
            'measurement_follow_up', 'externally_escalated'
        )
    ),
    CONSTRAINT transition_review_events_actor_relation CHECK (
        (
            action = 'opened'
            AND actor_membership_id IS NULL
            AND actor_api_key_id IS NULL
            AND from_state IS NULL
            AND to_state = 'open'
            AND resolution IS NULL
        )
        OR (
            action <> 'opened'
            AND actor_membership_id IS NOT NULL
            AND actor_api_key_id IS NOT NULL
            AND from_state IS NOT NULL
        )
    ),
    CONSTRAINT transition_review_events_action_relation CHECK (
        (
            action = 'opened'
            AND to_state = 'open'
            AND assigned_membership_id IS NULL
            AND resolution IS NULL
        )
        OR (
            action = 'assigned'
            AND to_state = 'open'
            AND assigned_membership_id IS NOT NULL
            AND resolution IS NULL
        )
        OR (
            action = 'acknowledged'
            AND from_state = 'open'
            AND to_state = 'acknowledged'
            AND assigned_membership_id IS NOT NULL
            AND resolution IS NULL
        )
        OR (
            action = 'resolved'
            AND from_state = 'acknowledged'
            AND to_state = 'resolved'
            AND assigned_membership_id IS NOT NULL
            AND resolution IS NOT NULL
        )
    )
);

CREATE INDEX transition_review_events_history
ON transition_review_events (tenant_id, review_id, occurred_at, id);

CREATE FUNCTION socialname_guard_organization_retention_policy_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text, 0));

    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.revision IS DISTINCT FROM OLD.revision + 1
       OR NEW.updated_at <= OLD.updated_at
       OR NEW.updated_by_membership_id IS NULL
       OR NOT EXISTS (
            SELECT 1
            FROM memberships AS actor
            WHERE actor.tenant_id = NEW.tenant_id
              AND actor.id = NEW.updated_by_membership_id
              AND actor.state = 'active'
              AND actor.role IN ('owner', 'administrator')
       )
       OR EXISTS (
            SELECT 1
            FROM watches AS watch
            WHERE watch.tenant_id = NEW.tenant_id
              AND watch.state <> 'deleting'
              AND (
                  watch.retention_days < NEW.minimum_watch_retention_days
                  OR watch.retention_days > NEW.maximum_watch_retention_days
              )
       ) THEN
        RAISE EXCEPTION 'organization retention policy update is invalid'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER organization_retention_policy_guard_update
BEFORE UPDATE ON organization_retention_policies
FOR EACH ROW
EXECUTE FUNCTION socialname_guard_organization_retention_policy_update();

CREATE FUNCTION socialname_validate_watch_organization_retention()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    minimum_days smallint;
    maximum_days smallint;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text, 0));

    SELECT
        policy.minimum_watch_retention_days,
        policy.maximum_watch_retention_days
      INTO minimum_days, maximum_days
      FROM organization_retention_policies AS policy
     WHERE policy.tenant_id = NEW.tenant_id;

    IF NOT FOUND
       OR NEW.retention_days < minimum_days
       OR NEW.retention_days > maximum_days THEN
        RAISE EXCEPTION 'watch retention violates the organization policy'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER watches_validate_organization_retention
BEFORE INSERT OR UPDATE OF retention_days ON watches
FOR EACH ROW
EXECUTE FUNCTION socialname_validate_watch_organization_retention();

CREATE FUNCTION socialname_guard_transition_review_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text, 0));

    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.transition_id IS DISTINCT FROM OLD.transition_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.revision IS DISTINCT FROM OLD.revision + 1
       OR NEW.updated_at <= OLD.updated_at
       OR OLD.state = 'resolved'
       OR (OLD.state = 'acknowledged' AND NEW.state <> 'resolved')
       OR (OLD.state = 'open' AND NEW.state NOT IN ('open', 'acknowledged'))
       OR (
            OLD.assigned_membership_id IS DISTINCT FROM NEW.assigned_membership_id
            AND (
                OLD.state <> 'open'
                OR NEW.state <> 'open'
                OR NEW.assigned_membership_id IS NULL
            )
       )
       OR (
            NEW.assigned_membership_id IS NOT NULL
            AND NOT EXISTS (
                SELECT 1
                FROM memberships AS assignee
                WHERE assignee.tenant_id = NEW.tenant_id
                  AND assignee.id = NEW.assigned_membership_id
                  AND assignee.state = 'active'
                  AND assignee.role IN ('owner', 'administrator', 'member')
            )
       ) THEN
        RAISE EXCEPTION 'transition review update is invalid'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER transition_reviews_guard_update
BEFORE UPDATE ON transition_reviews
FOR EACH ROW
EXECUTE FUNCTION socialname_guard_transition_review_update();

CREATE FUNCTION socialname_guard_membership_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text, 0));

    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.subject_id IS DISTINCT FROM OLD.subject_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.revision IS DISTINCT FROM OLD.revision + 1
       OR NEW.updated_at <= OLD.updated_at
       OR (OLD.state = 'removed' AND NEW IS DISTINCT FROM OLD)
       OR (
            OLD.role = 'owner'
            AND OLD.state = 'active'
            AND (NEW.role <> 'owner' OR NEW.state <> 'active')
            AND NOT EXISTS (
                SELECT 1
                FROM memberships AS remaining_owner
                WHERE remaining_owner.tenant_id = NEW.tenant_id
                  AND remaining_owner.id <> NEW.id
                  AND remaining_owner.role = 'owner'
                  AND remaining_owner.state = 'active'
            )
       )
       OR (
            (NEW.state <> 'active' OR NEW.role = 'viewer')
            AND EXISTS (
                SELECT 1
                FROM transition_reviews AS review
                WHERE review.tenant_id = NEW.tenant_id
                  AND review.assigned_membership_id = NEW.id
                  AND review.state <> 'resolved'
            )
       )
       OR (
            NEW.state = 'removed'
            AND EXISTS (
                SELECT 1
                FROM api_keys AS key
                WHERE key.tenant_id = NEW.tenant_id
                  AND key.created_by_membership_id = NEW.id
                  AND key.state = 'active'
            )
       ) THEN
        RAISE EXCEPTION 'membership update is invalid'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER memberships_guard_update
BEFORE UPDATE ON memberships
FOR EACH ROW
EXECUTE FUNCTION socialname_guard_membership_update();

CREATE FUNCTION socialname_create_transition_review()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    inserted_review_id uuid;
    observed_at timestamptz := clock_timestamp();
BEGIN
    IF NEW.transition_class = 'account_state'
       AND NEW.confirmation_status = 'confirmed' THEN
        INSERT INTO public.transition_reviews (
            id, tenant_id, transition_id, state, revision, created_at, updated_at
        ) VALUES (
            gen_random_uuid(), NEW.tenant_id, NEW.id, 'open', 1,
            observed_at, observed_at
        )
        ON CONFLICT (tenant_id, transition_id) DO NOTHING
        RETURNING id INTO inserted_review_id;

        IF inserted_review_id IS NOT NULL THEN
            INSERT INTO public.transition_review_events (
                id, tenant_id, review_id, action, from_state, to_state,
                occurred_at
            ) VALUES (
                gen_random_uuid(), NEW.tenant_id, inserted_review_id,
                'opened', NULL, 'open', observed_at
            );
            INSERT INTO public.audit_events (
                id, tenant_id, action, resource_kind, resource_id,
                occurred_at, details
            ) VALUES (
                gen_random_uuid(), NEW.tenant_id, 'transition.review.opened',
                'transition_review', inserted_review_id, observed_at,
                '{}'::jsonb
            );
        END IF;
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER transitions_create_review
AFTER INSERT OR UPDATE OF confirmation_status ON transitions
FOR EACH ROW
EXECUTE FUNCTION socialname_create_transition_review();

REVOKE ALL ON FUNCTION socialname_create_transition_review()
FROM PUBLIC;

WITH inserted AS (
    INSERT INTO transition_reviews (
        id, tenant_id, transition_id, state, revision, created_at, updated_at
    )
    SELECT
        gen_random_uuid(), transition.tenant_id, transition.id,
        'open', 1, clock_timestamp(), clock_timestamp()
    FROM transitions AS transition
    WHERE transition.transition_class = 'account_state'
      AND transition.confirmation_status = 'confirmed'
    ON CONFLICT (tenant_id, transition_id) DO NOTHING
    RETURNING id, tenant_id, created_at
),
events AS (
    INSERT INTO transition_review_events (
        id, tenant_id, review_id, action, from_state, to_state, occurred_at
    )
    SELECT
        gen_random_uuid(), tenant_id, id, 'opened', NULL, 'open', created_at
    FROM inserted
)
INSERT INTO audit_events (
    id, tenant_id, action, resource_kind, resource_id, occurred_at, details
)
SELECT
    gen_random_uuid(), tenant_id, 'transition.review.opened',
    'transition_review', id, created_at, '{}'::jsonb
FROM inserted;

CREATE TRIGGER transition_review_events_append_only
BEFORE UPDATE ON transition_review_events
FOR EACH ROW
EXECUTE FUNCTION socialname_reject_update();

ALTER TABLE organization_retention_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_retention_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON organization_retention_policies
    USING (tenant_id = socialname_current_tenant_id())
    WITH CHECK (tenant_id = socialname_current_tenant_id());

ALTER TABLE transition_reviews ENABLE ROW LEVEL SECURITY;
ALTER TABLE transition_reviews FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON transition_reviews
    USING (tenant_id = socialname_current_tenant_id())
    WITH CHECK (tenant_id = socialname_current_tenant_id());

ALTER TABLE transition_review_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE transition_review_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON transition_review_events
    USING (tenant_id = socialname_current_tenant_id())
    WITH CHECK (tenant_id = socialname_current_tenant_id());

REVOKE ALL ON organization_retention_policies, transition_reviews,
    transition_review_events
FROM PUBLIC;
