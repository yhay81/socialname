CREATE FUNCTION socialname_reject_notification_endpoint_channel_change()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF NEW.channel IS DISTINCT FROM OLD.channel THEN
        RAISE EXCEPTION 'notification endpoint channel is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER notification_endpoints_channel_immutable
BEFORE UPDATE ON notification_endpoints
FOR EACH ROW EXECUTE FUNCTION socialname_reject_notification_endpoint_channel_change();

CREATE OR REPLACE FUNCTION socialname_worker_claim_email_delivery(
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
        RAISE EXCEPTION 'email delivery claim parameters are invalid'
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
     WHERE endpoint.channel = 'email'
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
       OR selected_endpoint_channel IS DISTINCT FROM 'email' THEN
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
            '{"channel":"email","reason":"endpoint_disabled"}'::jsonb
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
            'email_attempt', clock_timestamp()
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
                '{"channel":"email","reason":"lease_expired"}'::jsonb
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
        'email_attempt', claimed_at
    );

    RETURN QUERY
    SELECT selected_tenant_id, selected_delivery_id, selected_attempt_count;
END
$$;

REVOKE ALL ON FUNCTION socialname_worker_claim_email_delivery(
    text, integer, integer
) FROM PUBLIC;
