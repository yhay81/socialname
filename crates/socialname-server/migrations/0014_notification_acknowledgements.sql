CREATE TABLE notification_acknowledgements (
    delivery_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    acknowledged_by_membership_id uuid NOT NULL,
    acknowledged_by_api_key_id uuid NOT NULL,
    acknowledged_at timestamptz NOT NULL,
    UNIQUE (tenant_id, delivery_id),
    FOREIGN KEY (tenant_id, delivery_id)
        REFERENCES notification_deliveries(tenant_id, id)
        ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, acknowledged_by_membership_id)
        REFERENCES memberships(tenant_id, id),
    FOREIGN KEY (tenant_id, acknowledged_by_api_key_id)
        REFERENCES api_keys(tenant_id, id)
);

CREATE INDEX notification_acknowledgements_recent
ON notification_acknowledgements (tenant_id, acknowledged_at DESC, delivery_id);

CREATE FUNCTION socialname_validate_notification_acknowledgement()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
    delivery_state text;
    delivery_delivered_at timestamptz;
BEGIN
    SELECT state, delivered_at
      INTO delivery_state, delivery_delivered_at
      FROM public.notification_deliveries
     WHERE tenant_id = NEW.tenant_id AND id = NEW.delivery_id;

    IF delivery_state IS DISTINCT FROM 'delivered'
       OR delivery_delivered_at IS NULL
       OR NEW.acknowledged_at < delivery_delivered_at THEN
        RAISE EXCEPTION 'notification acknowledgement requires a delivered notification'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER notification_acknowledgements_validate
BEFORE INSERT ON notification_acknowledgements
FOR EACH ROW EXECUTE FUNCTION socialname_validate_notification_acknowledgement();

CREATE FUNCTION socialname_validate_acknowledged_delivery()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    acknowledged_at timestamptz;
BEGIN
    SELECT acknowledgement.acknowledged_at
      INTO acknowledged_at
      FROM public.notification_acknowledgements AS acknowledgement
     WHERE acknowledgement.tenant_id = NEW.tenant_id
       AND acknowledgement.delivery_id = NEW.id;

    IF acknowledged_at IS NOT NULL
       AND (
           NEW.state IS DISTINCT FROM 'delivered'
           OR NEW.delivered_at IS NULL
           OR acknowledged_at < NEW.delivered_at
       ) THEN
        RAISE EXCEPTION 'acknowledged notification must remain delivered'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER notification_deliveries_preserve_acknowledgement
BEFORE UPDATE ON notification_deliveries
FOR EACH ROW EXECUTE FUNCTION socialname_validate_acknowledged_delivery();

CREATE TRIGGER notification_acknowledgements_append_only
BEFORE UPDATE ON notification_acknowledgements
FOR EACH ROW EXECUTE FUNCTION socialname_reject_update();

ALTER TABLE notification_acknowledgements ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_acknowledgements FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON notification_acknowledgements
    USING (tenant_id = socialname_current_tenant_id())
    WITH CHECK (tenant_id = socialname_current_tenant_id());
