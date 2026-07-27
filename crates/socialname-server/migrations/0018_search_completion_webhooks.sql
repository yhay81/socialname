CREATE TABLE search_completion_webhooks (
    search_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    endpoint_id uuid NOT NULL,
    created_by_api_key_id uuid NOT NULL,
    state text NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL,
    cancelled_at timestamptz,
    UNIQUE (tenant_id, search_id),
    UNIQUE (tenant_id, search_id, endpoint_id),
    FOREIGN KEY (tenant_id, search_id) REFERENCES searches(tenant_id, id),
    FOREIGN KEY (tenant_id, endpoint_id)
        REFERENCES notification_endpoints(tenant_id, id),
    FOREIGN KEY (tenant_id, created_by_api_key_id)
        REFERENCES api_keys(tenant_id, id),
    CONSTRAINT search_completion_webhook_state_closed CHECK (
        state IN ('active', 'cancelled')
    ),
    CONSTRAINT search_completion_webhook_state_relation CHECK (
        (state = 'active' AND cancelled_at IS NULL)
        OR (
            state = 'cancelled'
            AND cancelled_at IS NOT NULL
            AND cancelled_at >= created_at
        )
    )
);

ALTER TABLE notification_deliveries
    ADD COLUMN delivery_kind text NOT NULL DEFAULT 'watch_transition',
    ADD COLUMN search_id uuid,
    ALTER COLUMN transition_id DROP NOT NULL,
    ALTER COLUMN confirmation_basis DROP NOT NULL,
    ADD CONSTRAINT notification_delivery_kind_closed CHECK (
        delivery_kind IN ('watch_transition', 'search_completion')
    ),
    ADD CONSTRAINT notification_delivery_origin_relation CHECK (
        (
            delivery_kind = 'watch_transition'
            AND transition_id IS NOT NULL
            AND search_id IS NULL
            AND confirmation_basis IS NOT NULL
        )
        OR (
            delivery_kind = 'search_completion'
            AND transition_id IS NULL
            AND search_id IS NOT NULL
            AND confirmation_basis IS NULL
        )
    ),
    ADD FOREIGN KEY (tenant_id, search_id) REFERENCES searches(tenant_id, id);

CREATE UNIQUE INDEX notification_deliveries_search_completion
ON notification_deliveries (tenant_id, search_id, endpoint_id)
WHERE delivery_kind = 'search_completion';

CREATE OR REPLACE FUNCTION socialname_validate_delivery()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
    transition_status text;
    transition_basis text;
    search_state text;
    binding_state text;
    endpoint_state text;
BEGIN
    IF TG_OP = 'UPDATE'
       AND (
           NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
           OR NEW.delivery_kind IS DISTINCT FROM OLD.delivery_kind
           OR NEW.transition_id IS DISTINCT FROM OLD.transition_id
           OR NEW.search_id IS DISTINCT FROM OLD.search_id
           OR NEW.endpoint_id IS DISTINCT FROM OLD.endpoint_id
           OR NEW.logical_notification_key
                IS DISTINCT FROM OLD.logical_notification_key
           OR NEW.confirmation_basis IS DISTINCT FROM OLD.confirmation_basis
           OR NEW.created_at IS DISTINCT FROM OLD.created_at
       ) THEN
        RAISE EXCEPTION 'notification delivery identity is immutable'
            USING ERRCODE = '23514';
    END IF;

    SELECT state
      INTO endpoint_state
      FROM public.notification_endpoints
     WHERE tenant_id = NEW.tenant_id AND id = NEW.endpoint_id;

    IF NEW.delivery_kind = 'watch_transition' THEN
        SELECT confirmation_status, confirmation_basis
          INTO transition_status, transition_basis
          FROM public.transitions
         WHERE tenant_id = NEW.tenant_id AND id = NEW.transition_id;

        IF transition_status IS DISTINCT FROM 'confirmed'
           OR transition_basis IS DISTINCT FROM NEW.confirmation_basis THEN
            RAISE EXCEPTION 'notification delivery requires the exact confirmed transition basis'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.delivery_kind = 'search_completion' THEN
        SELECT state
          INTO search_state
          FROM public.searches
         WHERE tenant_id = NEW.tenant_id AND id = NEW.search_id;
        SELECT state
          INTO binding_state
          FROM public.search_completion_webhooks
         WHERE tenant_id = NEW.tenant_id
           AND search_id = NEW.search_id
           AND endpoint_id = NEW.endpoint_id;

        IF search_state NOT IN ('completed', 'failed')
           OR (
                binding_state IS DISTINCT FROM 'active'
                AND NEW.state IS DISTINCT FROM 'cancelled'
           ) THEN
            RAISE EXCEPTION 'search-completion delivery requires an active terminal binding'
                USING ERRCODE = '23514';
        END IF;
    ELSE
        RAISE EXCEPTION 'notification delivery kind is invalid'
            USING ERRCODE = '23514';
    END IF;

    IF endpoint_state IS DISTINCT FROM 'active'
       AND NEW.state IS DISTINCT FROM 'cancelled' THEN
        RAISE EXCEPTION 'notification delivery requires an active endpoint'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION socialname_enqueue_search_completion_delivery(
    p_tenant_id uuid,
    p_search_id uuid
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    inserted_delivery record;
BEGIN
    FOR inserted_delivery IN
        INSERT INTO public.notification_deliveries (
            id, tenant_id, delivery_kind, transition_id, search_id,
            endpoint_id, logical_notification_key, confirmation_basis,
            state, attempt_count, created_at, last_error_code
        )
        SELECT
            gen_random_uuid(),
            binding.tenant_id,
            'search_completion',
            NULL,
            binding.search_id,
            binding.endpoint_id,
            pg_catalog.sha256(
                pg_catalog.convert_to(
                    'search_completion:' || binding.tenant_id::text || ':'
                    || binding.search_id::text || ':' || binding.endpoint_id::text,
                    'UTF8'
                )
            ),
            NULL,
            CASE endpoint.state
                WHEN 'active' THEN 'queued'
                ELSE 'cancelled'
            END,
            0,
            clock_timestamp(),
            CASE endpoint.state
                WHEN 'active' THEN NULL
                ELSE 'endpoint_disabled'
            END
        FROM public.search_completion_webhooks AS binding
        JOIN public.searches AS search
          ON search.tenant_id = binding.tenant_id
         AND search.id = binding.search_id
        JOIN public.notification_endpoints AS endpoint
          ON endpoint.tenant_id = binding.tenant_id
         AND endpoint.id = binding.endpoint_id
        WHERE binding.tenant_id = p_tenant_id
          AND binding.search_id = p_search_id
          AND binding.state = 'active'
          AND search.state IN ('completed', 'failed')
        ON CONFLICT (tenant_id, logical_notification_key) DO NOTHING
        RETURNING id, tenant_id, search_id, state
    LOOP
        INSERT INTO public.data_lineage_edges (
            id, tenant_id, parent_kind, parent_id, child_kind, child_id,
            purpose, created_at
        ) VALUES (
            gen_random_uuid(), inserted_delivery.tenant_id,
            'search', inserted_delivery.search_id,
            'notification_delivery', inserted_delivery.id,
            'search_completion_webhook', clock_timestamp()
        )
        ON CONFLICT DO NOTHING;

        INSERT INTO public.data_lineage_edges (
            id, tenant_id, parent_kind, parent_id, child_kind, child_id,
            purpose, created_at
        )
        SELECT
            gen_random_uuid(), target.tenant_id,
            'search_target', target.id,
            'notification_delivery', inserted_delivery.id,
            'search_completion_webhook', clock_timestamp()
        FROM public.search_targets AS target
        WHERE target.tenant_id = inserted_delivery.tenant_id
          AND target.search_id = inserted_delivery.search_id
        ON CONFLICT DO NOTHING;

        INSERT INTO public.audit_events (
            id, tenant_id, action, resource_kind, resource_id,
            occurred_at, details
        ) VALUES (
            gen_random_uuid(), inserted_delivery.tenant_id,
            CASE inserted_delivery.state
                WHEN 'queued' THEN 'search_completion.delivery.queued'
                ELSE 'search_completion.delivery.cancelled'
            END,
            'notification_delivery', inserted_delivery.id,
            clock_timestamp(),
            jsonb_build_object(
                'channel', 'webhook',
                'kind', 'search_completion',
                'state', inserted_delivery.state
            )
        );
    END LOOP;
END
$$;

REVOKE ALL ON FUNCTION
    socialname_enqueue_search_completion_delivery(uuid, uuid)
FROM PUBLIC;

CREATE FUNCTION socialname_enqueue_search_completion_trigger()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
    IF TG_TABLE_NAME = 'searches' THEN
        PERFORM public.socialname_enqueue_search_completion_delivery(
            NEW.tenant_id,
            NEW.id
        );
    ELSE
        PERFORM public.socialname_enqueue_search_completion_delivery(
            NEW.tenant_id,
            NEW.search_id
        );
    END IF;
    RETURN NEW;
END
$$;

REVOKE ALL ON FUNCTION socialname_enqueue_search_completion_trigger()
FROM PUBLIC;

CREATE TRIGGER searches_enqueue_completion_webhook
AFTER UPDATE OF state ON searches
FOR EACH ROW
WHEN (
    OLD.state IS DISTINCT FROM NEW.state
    AND NEW.state IN ('completed', 'failed')
)
EXECUTE FUNCTION socialname_enqueue_search_completion_trigger();

CREATE TRIGGER search_completion_webhook_enqueue_terminal
AFTER INSERT ON search_completion_webhooks
FOR EACH ROW
WHEN (NEW.state = 'active')
EXECUTE FUNCTION socialname_enqueue_search_completion_trigger();

ALTER TABLE search_completion_webhooks ENABLE ROW LEVEL SECURITY;
ALTER TABLE search_completion_webhooks FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON search_completion_webhooks
    USING (tenant_id = socialname_current_tenant_id())
    WITH CHECK (tenant_id = socialname_current_tenant_id());
