ALTER TABLE watch_targets
    ADD COLUMN account_state text,
    ADD COLUMN account_assertion_id uuid,
    ADD COLUMN account_state_since timestamptz,
    ADD FOREIGN KEY (tenant_id, account_assertion_id)
        REFERENCES assertions(tenant_id, id),
    ADD CONSTRAINT watch_targets_account_state_closed CHECK (
        account_state IS NULL OR account_state IN ('found', 'not_found')
    ),
    ADD CONSTRAINT watch_targets_account_baseline_relation CHECK (
        (
            account_state IS NULL
            AND account_assertion_id IS NULL
            AND account_state_since IS NULL
        )
        OR (
            account_state IS NOT NULL
            AND account_assertion_id IS NOT NULL
            AND account_state_since IS NOT NULL
        )
    );

CREATE INDEX transitions_account_candidate
ON transitions (tenant_id, watch_target_id, created_at DESC, id DESC)
WHERE transition_class = 'account_state'
  AND confirmation_status IN ('pending', 'suppressed');

CREATE INDEX transitions_measurement_latest
ON transitions (
    tenant_id, watch_target_id, rule_version_id, region_class,
    created_at DESC, id DESC
)
WHERE transition_class = 'measurement_health';
