PRAGMA application_id = 1397637453;

CREATE TABLE local_observations (
    observation_id TEXT PRIMARY KEY
        CHECK (length(observation_id) BETWEEN 1 AND 128),
    site_id TEXT NOT NULL
        CHECK (length(site_id) BETWEEN 1 AND 64),
    normalized_username TEXT NOT NULL
        CHECK (length(normalized_username) BETWEEN 1 AND 1024),
    verdict TEXT NOT NULL
        CHECK (verdict IN ('found', 'not_found', 'invalid_username', 'inconclusive')),
    inconclusive_reason TEXT
        CHECK (inconclusive_reason IS NULL OR inconclusive_reason IN (
            'blocked',
            'rate_limited',
            'timeout',
            'dns',
            'connect',
            'tls',
            'redirect_rejected',
            'response_too_large',
            'decode',
            'site_changed',
            'no_rule_matched',
            'conflicting_evidence'
        )),
    evidence_class TEXT NOT NULL
        CHECK (evidence_class IN (
            'e0_no_account_evidence',
            'e1_weak_signal',
            'e2_differential_template',
            'e3_explicit_endpoint',
            'e4_structured_identity'
        )),
    observed_at_unix_ms INTEGER NOT NULL,
    expires_at_unix_ms INTEGER NOT NULL,
    region_class TEXT NOT NULL
        CHECK (length(region_class) BETWEEN 1 AND 64),
    network_group TEXT NOT NULL
        CHECK (length(network_group) BETWEEN 1 AND 128),
    independence_group TEXT NOT NULL
        CHECK (length(independence_group) BETWEEN 1 AND 128),
    producer_kind TEXT NOT NULL
        CHECK (producer_kind IN ('local_cli', 'shared_cli', 'managed_worker', 'canary_worker')),
    producer_reputation TEXT NOT NULL
        CHECK (producer_reputation IN ('new', 'calibrated', 'trusted', 'suspended')),
    collection_profile TEXT NOT NULL
        CHECK (collection_profile IN (
            'local_only',
            'private_history',
            'shared_observation',
            'shared_research',
            'managed'
        )),
    rule_hash TEXT NOT NULL
        CHECK (
            length(rule_hash) = 64
            AND rule_hash NOT GLOB '*[^0-9a-f]*'
        ),
    rule_health_green INTEGER NOT NULL
        CHECK (rule_health_green IN (0, 1)),
    evidence_digest TEXT NOT NULL
        CHECK (
            length(evidence_digest) = 64
            AND evidence_digest NOT GLOB '*[^0-9a-f]*'
        ),
    inserted_at_unix_ms INTEGER NOT NULL,
    CHECK (expires_at_unix_ms > observed_at_unix_ms),
    CHECK (inserted_at_unix_ms >= observed_at_unix_ms),
    CHECK (
        (verdict = 'inconclusive' AND inconclusive_reason IS NOT NULL)
        OR (verdict <> 'inconclusive' AND inconclusive_reason IS NULL)
    )
) STRICT, WITHOUT ROWID;

CREATE TABLE observation_cache_metadata (
    observation_id TEXT PRIMARY KEY
        REFERENCES local_observations(observation_id) ON DELETE CASCADE,
    cached_at_unix_ms INTEGER NOT NULL,
    last_accessed_at_unix_ms INTEGER NOT NULL,
    access_count INTEGER NOT NULL DEFAULT 0
        CHECK (access_count >= 0),
    CHECK (last_accessed_at_unix_ms >= cached_at_unix_ms)
) STRICT, WITHOUT ROWID;

CREATE INDEX local_observations_eligibility
    ON local_observations (
        normalized_username,
        site_id,
        region_class,
        rule_hash,
        observed_at_unix_ms DESC
    );

CREATE INDEX local_observations_expiry
    ON local_observations (expires_at_unix_ms);

CREATE INDEX local_observations_inserted
    ON local_observations (inserted_at_unix_ms);

CREATE TRIGGER local_observations_are_immutable
BEFORE UPDATE ON local_observations
BEGIN
    SELECT RAISE(ABORT, 'local observations are immutable');
END;
