ALTER TABLE notification_deliveries
    ADD COLUMN lease_owner text,
    ADD COLUMN lease_started_at timestamptz,
    ADD COLUMN lease_expires_at timestamptz,
    ADD CONSTRAINT deliveries_error_code_bound CHECK (
        last_error_code IS NULL
        OR last_error_code IN (
            'timeout', 'connection_failed', 'transport_failed',
            'destination_rejected', 'request_rejected',
            'http_retryable', 'http_permanent', 'lease_expired',
            'endpoint_disabled'
        )
    ),
    ADD CONSTRAINT deliveries_lease_relation CHECK (
        (
            state = 'delivering'
            AND attempt_count > 0
            AND lease_owner IS NOT NULL
            AND lease_owner ~ '^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$'
            AND length(lease_owner) <= 64
            AND lease_started_at IS NOT NULL
            AND lease_expires_at IS NOT NULL
            AND lease_expires_at > lease_started_at
        )
        OR (
            state <> 'delivering'
            AND lease_owner IS NULL
            AND lease_started_at IS NULL
            AND lease_expires_at IS NULL
        )
    );

CREATE INDEX notification_deliveries_due
ON notification_deliveries (
    COALESCE(next_attempt_at, lease_expires_at, created_at), created_at, id
)
WHERE state IN ('queued', 'retry_scheduled', 'delivering');

CREATE TABLE notification_delivery_attempts (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    delivery_id uuid NOT NULL,
    attempt_number integer NOT NULL,
    event_kind text NOT NULL,
    worker_id text,
    http_status integer,
    error_code text,
    request_body_sha256 bytea,
    occurred_at timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, delivery_id, attempt_number, event_kind),
    FOREIGN KEY (tenant_id, delivery_id)
        REFERENCES notification_deliveries(tenant_id, id),
    CONSTRAINT delivery_attempt_number_positive CHECK (attempt_number > 0),
    CONSTRAINT delivery_attempt_event_closed CHECK (
        event_kind IN (
            'claimed', 'delivered', 'retry_scheduled',
            'permanently_failed', 'lease_expired', 'cancelled'
        )
    ),
    CONSTRAINT delivery_attempt_worker_bound CHECK (
        worker_id IS NULL
        OR (
            worker_id ~ '^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$'
            AND length(worker_id) <= 64
        )
    ),
    CONSTRAINT delivery_attempt_status_bound CHECK (
        http_status IS NULL OR http_status BETWEEN 100 AND 599
    ),
    CONSTRAINT delivery_attempt_error_closed CHECK (
        error_code IS NULL
        OR error_code IN (
            'timeout', 'connection_failed', 'transport_failed',
            'destination_rejected', 'request_rejected',
            'http_retryable', 'http_permanent', 'lease_expired',
            'endpoint_disabled'
        )
    ),
    CONSTRAINT delivery_attempt_digest_sha256 CHECK (
        request_body_sha256 IS NULL
        OR octet_length(request_body_sha256) = 32
    ),
    CONSTRAINT delivery_attempt_event_relation CHECK (
        (
            event_kind = 'claimed'
            AND worker_id IS NOT NULL
            AND http_status IS NULL
            AND error_code IS NULL
            AND request_body_sha256 IS NULL
        )
        OR (
            event_kind = 'lease_expired'
            AND worker_id IS NOT NULL
            AND http_status IS NULL
            AND error_code = 'lease_expired'
            AND request_body_sha256 IS NULL
        )
        OR (
            event_kind = 'delivered'
            AND worker_id IS NOT NULL
            AND http_status BETWEEN 200 AND 299
            AND error_code IS NULL
            AND octet_length(request_body_sha256) = 32
        )
        OR (
            event_kind IN (
                'retry_scheduled', 'permanently_failed', 'cancelled'
            )
            AND worker_id IS NOT NULL
            AND error_code IS NOT NULL
            AND octet_length(request_body_sha256) = 32
        )
    )
);

CREATE TRIGGER notification_delivery_attempts_append_only
BEFORE UPDATE ON notification_delivery_attempts
FOR EACH ROW EXECUTE FUNCTION socialname_reject_update();

ALTER TABLE notification_delivery_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_delivery_attempts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON notification_delivery_attempts
    USING (tenant_id = socialname_current_tenant_id())
    WITH CHECK (tenant_id = socialname_current_tenant_id());

CREATE OR REPLACE FUNCTION socialname_validate_delivery()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
    transition_status text;
    transition_basis text;
    endpoint_state text;
BEGIN
    IF TG_OP = 'UPDATE'
       AND (
           NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
           OR NEW.transition_id IS DISTINCT FROM OLD.transition_id
           OR NEW.endpoint_id IS DISTINCT FROM OLD.endpoint_id
           OR NEW.logical_notification_key
                IS DISTINCT FROM OLD.logical_notification_key
           OR NEW.confirmation_basis IS DISTINCT FROM OLD.confirmation_basis
           OR NEW.created_at IS DISTINCT FROM OLD.created_at
       ) THEN
        RAISE EXCEPTION 'notification delivery identity is immutable'
            USING ERRCODE = '23514';
    END IF;

    SELECT confirmation_status, confirmation_basis
      INTO transition_status, transition_basis
      FROM public.transitions
     WHERE tenant_id = NEW.tenant_id AND id = NEW.transition_id;

    SELECT state
      INTO endpoint_state
      FROM public.notification_endpoints
     WHERE tenant_id = NEW.tenant_id AND id = NEW.endpoint_id;

    IF transition_status IS DISTINCT FROM 'confirmed'
       OR transition_basis IS DISTINCT FROM NEW.confirmation_basis THEN
        RAISE EXCEPTION 'notification delivery requires the exact confirmed transition basis'
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

CREATE OR REPLACE FUNCTION socialname_worker_claim_webhook_delivery(
    p_worker_id text,
    p_lease_ms integer,
    p_maximum_attempts integer
)
RETURNS TABLE (
    tenant_id uuid,
    notification_delivery_id uuid,
    attempt_count integer
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    selected_tenant_id uuid;
    selected_delivery_id uuid;
    selected_state text;
    selected_attempt_count integer;
    selected_lease_owner text;
    selected_endpoint_state text;
    selected_endpoint_channel text;
    attempt_event_id uuid;
    claimed_at timestamptz;
BEGIN
    IF p_worker_id IS NULL
       OR p_lease_ms IS NULL
       OR p_maximum_attempts IS NULL
       OR p_worker_id !~ '^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$'
       OR length(p_worker_id) > 64
       OR p_lease_ms NOT BETWEEN 1000 AND 30000
       OR p_maximum_attempts NOT BETWEEN 1 AND 10 THEN
        RAISE EXCEPTION 'webhook delivery claim parameters are invalid'
            USING ERRCODE = '22023';
    END IF;

    SELECT delivery.tenant_id, delivery.id, delivery.state,
           delivery.attempt_count, delivery.lease_owner,
           endpoint.state, endpoint.channel
      INTO selected_tenant_id, selected_delivery_id, selected_state,
           selected_attempt_count, selected_lease_owner,
           selected_endpoint_state, selected_endpoint_channel
      FROM public.notification_deliveries AS delivery
      JOIN public.notification_endpoints AS endpoint
        ON endpoint.tenant_id = delivery.tenant_id
       AND endpoint.id = delivery.endpoint_id
     WHERE endpoint.channel = 'webhook'
       AND (
            delivery.state = 'queued'
            OR (
                delivery.state = 'retry_scheduled'
                AND delivery.next_attempt_at <= clock_timestamp()
            )
            OR (
                delivery.state = 'delivering'
                AND delivery.lease_expires_at <= clock_timestamp()
            )
       )
     ORDER BY
        COALESCE(
            delivery.next_attempt_at,
            delivery.lease_expires_at,
            delivery.created_at
        ),
        delivery.created_at,
        delivery.id
     LIMIT 1
     FOR UPDATE OF delivery SKIP LOCKED;

    IF selected_delivery_id IS NULL THEN
        RETURN;
    END IF;

    IF selected_endpoint_state IS DISTINCT FROM 'active'
       OR selected_endpoint_channel IS DISTINCT FROM 'webhook' THEN
        UPDATE public.notification_deliveries AS delivery
           SET state = 'cancelled',
               next_attempt_at = NULL,
               delivered_at = NULL,
               last_error_code = 'endpoint_disabled',
               lease_owner = NULL,
               lease_started_at = NULL,
               lease_expires_at = NULL
         WHERE delivery.tenant_id = selected_tenant_id
           AND delivery.id = selected_delivery_id;
        INSERT INTO public.audit_events (
            id, tenant_id, action, resource_kind, resource_id,
            occurred_at, details
        ) VALUES (
            gen_random_uuid(), selected_tenant_id,
            'notification.delivery.cancelled', 'notification_delivery',
            selected_delivery_id, clock_timestamp(),
            '{"reason":"endpoint_disabled"}'::jsonb
        );
        RETURN;
    END IF;

    IF selected_state = 'delivering' THEN
        attempt_event_id := gen_random_uuid();
        INSERT INTO public.notification_delivery_attempts (
            id, tenant_id, delivery_id, attempt_number, event_kind,
            worker_id, error_code, occurred_at
        ) VALUES (
            attempt_event_id, selected_tenant_id, selected_delivery_id,
            selected_attempt_count, 'lease_expired', selected_lease_owner,
            'lease_expired', clock_timestamp()
        )
        ON CONFLICT DO NOTHING;
        SELECT attempt.id
          INTO attempt_event_id
          FROM public.notification_delivery_attempts AS attempt
         WHERE attempt.tenant_id = selected_tenant_id
           AND attempt.delivery_id = selected_delivery_id
           AND attempt.attempt_number = selected_attempt_count
           AND attempt.event_kind = 'lease_expired';
        INSERT INTO public.data_lineage_edges (
            id, tenant_id, parent_kind, parent_id, child_kind, child_id,
            purpose, created_at
        ) VALUES (
            gen_random_uuid(), selected_tenant_id,
            'notification_delivery', selected_delivery_id,
            'notification_delivery_attempt', attempt_event_id,
            'webhook_attempt', clock_timestamp()
        )
        ON CONFLICT DO NOTHING;

        IF selected_attempt_count >= p_maximum_attempts THEN
            UPDATE public.notification_deliveries AS delivery
               SET state = 'permanently_failed',
                   next_attempt_at = NULL,
                   delivered_at = NULL,
                   last_error_code = 'lease_expired',
                   lease_owner = NULL,
                   lease_started_at = NULL,
                   lease_expires_at = NULL
             WHERE delivery.tenant_id = selected_tenant_id
               AND delivery.id = selected_delivery_id;
            INSERT INTO public.audit_events (
                id, tenant_id, action, resource_kind, resource_id,
                occurred_at, details
            ) VALUES (
                gen_random_uuid(), selected_tenant_id,
                'notification.delivery.permanently_failed',
                'notification_delivery', selected_delivery_id,
                clock_timestamp(),
                '{"reason":"lease_expired"}'::jsonb
            );
            RETURN;
        END IF;
    END IF;

    claimed_at := clock_timestamp();
    selected_attempt_count := selected_attempt_count + 1;
    UPDATE public.notification_deliveries AS delivery
       SET state = 'delivering',
           attempt_count = selected_attempt_count,
           next_attempt_at = NULL,
           delivered_at = NULL,
           last_error_code = NULL,
           lease_owner = p_worker_id,
           lease_started_at = claimed_at,
           lease_expires_at =
               claimed_at + (p_lease_ms::bigint::text || ' milliseconds')::interval
     WHERE delivery.tenant_id = selected_tenant_id
       AND delivery.id = selected_delivery_id;

    attempt_event_id := gen_random_uuid();
    INSERT INTO public.notification_delivery_attempts (
        id, tenant_id, delivery_id, attempt_number, event_kind,
        worker_id, occurred_at
    ) VALUES (
        attempt_event_id, selected_tenant_id, selected_delivery_id,
        selected_attempt_count, 'claimed', p_worker_id, claimed_at
    );
    INSERT INTO public.data_lineage_edges (
        id, tenant_id, parent_kind, parent_id, child_kind, child_id,
        purpose, created_at
    ) VALUES (
        gen_random_uuid(), selected_tenant_id,
        'notification_delivery', selected_delivery_id,
        'notification_delivery_attempt', attempt_event_id,
        'webhook_attempt', claimed_at
    );

    RETURN QUERY
    SELECT selected_tenant_id, selected_delivery_id, selected_attempt_count;
END
$$;

REVOKE ALL ON FUNCTION socialname_worker_claim_webhook_delivery(
    text, integer, integer
) FROM PUBLIC;
