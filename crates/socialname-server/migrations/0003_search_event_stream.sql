ALTER TABLE search_targets
    RENAME COLUMN normalized_username TO requested_username;

ALTER TABLE search_targets
    RENAME CONSTRAINT search_targets_username_bound
    TO search_targets_requested_username_bound;

ALTER TABLE search_targets
    ADD COLUMN normalized_username text,
    ADD CONSTRAINT search_targets_normalized_username_bound CHECK (
        normalized_username IS NULL
        OR (
            octet_length(normalized_username) BETWEEN 1 AND 256
            AND normalized_username !~ '[[:cntrl:]]'
        )
    );

CREATE TABLE search_events (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    search_id uuid NOT NULL,
    search_target_id uuid,
    sequence bigint NOT NULL,
    event_type text NOT NULL,
    payload jsonb NOT NULL,
    emitted_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, search_id, sequence),
    UNIQUE (tenant_id, search_id, search_target_id),
    FOREIGN KEY (tenant_id, search_id)
        REFERENCES searches(tenant_id, id)
        ON DELETE CASCADE,
    CONSTRAINT search_events_sequence_positive CHECK (sequence > 0),
    CONSTRAINT search_events_type_closed CHECK (
        event_type IN (
            'started', 'definitive_result', 'uncertain_result',
            'operational_failure', 'assertion_updated', 'finished'
        )
    ),
    CONSTRAINT search_events_target_relation CHECK (
        (
            event_type IN (
                'definitive_result', 'uncertain_result', 'operational_failure'
            )
            AND search_target_id IS NOT NULL
        )
        OR (
            event_type IN ('started', 'assertion_updated', 'finished')
            AND search_target_id IS NULL
        )
    ),
    CONSTRAINT search_events_payload_bound CHECK (
        jsonb_typeof(payload) = 'object'
        AND octet_length(payload::text) <= 131072
    ),
    CONSTRAINT search_events_payload_identity CHECK (
        payload ->> 'schema' = 'socialname.dev/api/v1'
        AND payload ->> 'event_id' = id::text
        AND payload ->> 'search_id' = search_id::text
        AND payload -> 'sequence' = to_jsonb(sequence)
        AND payload -> 'data' ->> 'type' = event_type
    )
);

ALTER TABLE search_targets
    ADD CONSTRAINT search_targets_tenant_search_id_id_key
        UNIQUE (tenant_id, search_id, id);

ALTER TABLE search_events
    ADD CONSTRAINT search_events_target_fk
        FOREIGN KEY (tenant_id, search_id, search_target_id)
        REFERENCES search_targets(tenant_id, search_id, id);

CREATE UNIQUE INDEX search_events_one_started
ON search_events (tenant_id, search_id)
WHERE event_type = 'started';

CREATE UNIQUE INDEX search_events_one_finished
ON search_events (tenant_id, search_id)
WHERE event_type = 'finished';

CREATE INDEX search_events_replay
ON search_events (tenant_id, search_id, sequence);

ALTER TABLE search_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE search_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON search_events
    USING (tenant_id = socialname_current_tenant_id())
    WITH CHECK (tenant_id = socialname_current_tenant_id());

CREATE TRIGGER search_events_append_only
BEFORE UPDATE ON search_events
FOR EACH ROW EXECUTE FUNCTION socialname_reject_update();
