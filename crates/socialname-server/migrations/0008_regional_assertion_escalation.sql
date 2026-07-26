CREATE TABLE regional_assertions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    assertion_id uuid NOT NULL,
    region_class text NOT NULL,
    outcome_kind text NOT NULL,
    verdict text,
    uncertainty_reason text,
    quality text NOT NULL,
    evidence_class text NOT NULL,
    observed_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    support_group_count integer NOT NULL,
    managed_support boolean NOT NULL,
    created_at timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, assertion_id, region_class),
    FOREIGN KEY (tenant_id, assertion_id)
        REFERENCES assertions(tenant_id, id),
    CONSTRAINT regional_assertions_region_bound CHECK (
        length(region_class) BETWEEN 1 AND 64
    ),
    CONSTRAINT regional_assertions_outcome_relation CHECK (
        (
            outcome_kind = 'definitive'
            AND verdict IN ('found', 'not_found')
            AND uncertainty_reason IS NULL
            AND quality <> 'conflicted'
            AND support_group_count > 0
        )
        OR (
            outcome_kind = 'inconclusive'
            AND verdict IS NULL
            AND uncertainty_reason = 'conflicting_evidence'
            AND quality = 'conflicted'
            AND support_group_count = 0
        )
    ),
    CONSTRAINT regional_assertions_quality_closed CHECK (
        quality IN (
            'verified', 'corroborated', 'single_vantage',
            'stale', 'conflicted', 'untrusted'
        )
    ),
    CONSTRAINT regional_assertions_managed_quality_relation CHECK (
        (quality = 'verified' AND managed_support)
        OR (
            quality IN ('corroborated', 'single_vantage', 'untrusted')
            AND NOT managed_support
        )
        OR quality IN ('stale', 'conflicted')
    ),
    CONSTRAINT regional_assertions_evidence_closed CHECK (
        evidence_class IN (
            'e0_no_account_evidence', 'e1_weak_signal',
            'e2_differential_template', 'e3_explicit_endpoint',
            'e4_structured_identity'
        )
    ),
    CONSTRAINT regional_assertions_support_bound CHECK (
        support_group_count BETWEEN 0 AND 256
    ),
    CONSTRAINT regional_assertions_time_order CHECK (
        expires_at > observed_at AND created_at >= observed_at
    )
);

CREATE TABLE regional_assertion_support (
    tenant_id uuid NOT NULL,
    regional_assertion_id uuid NOT NULL,
    observation_id uuid NOT NULL,
    support_role text NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, regional_assertion_id, observation_id),
    FOREIGN KEY (tenant_id, regional_assertion_id)
        REFERENCES regional_assertions(tenant_id, id),
    FOREIGN KEY (tenant_id, observation_id)
        REFERENCES observations(tenant_id, id),
    CONSTRAINT regional_assertion_support_role_closed CHECK (
        support_role IN ('supporting', 'conflicting')
    )
);

CREATE TRIGGER regional_assertions_append_only
BEFORE UPDATE ON regional_assertions
FOR EACH ROW EXECUTE FUNCTION socialname_reject_update();

CREATE TRIGGER regional_assertion_support_append_only
BEFORE UPDATE ON regional_assertion_support
FOR EACH ROW EXECUTE FUNCTION socialname_reject_update();

ALTER TABLE regional_assertions ENABLE ROW LEVEL SECURITY;
ALTER TABLE regional_assertions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON regional_assertions
    USING (tenant_id = socialname_current_tenant_id())
    WITH CHECK (tenant_id = socialname_current_tenant_id());

ALTER TABLE regional_assertion_support ENABLE ROW LEVEL SECURITY;
ALTER TABLE regional_assertion_support FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON regional_assertion_support
    USING (tenant_id = socialname_current_tenant_id())
    WITH CHECK (tenant_id = socialname_current_tenant_id());

ALTER TABLE probe_jobs
    ADD COLUMN priority_reason text GENERATED ALWAYS AS (
        CASE
            WHEN priority >= 100 THEN 'regional_conflict'
            WHEN priority >= 50 THEN 'account_confirmation'
            ELSE 'routine'
        END
    ) STORED;
