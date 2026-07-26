-- Durable signed rule-pack trust, rollout, replay protection, and rollback state.

ALTER TABLE rule_versions
    DROP CONSTRAINT rule_versions_site_id_rule_hash_key;

CREATE INDEX rule_versions_site_rule_hash
ON rule_versions (site_id, rule_hash);

CREATE TABLE rule_pack_trust_roots (
    generation bigint PRIMARY KEY,
    trust_id bytea NOT NULL UNIQUE,
    threshold integer NOT NULL,
    keys jsonb NOT NULL,
    expires_at timestamptz NOT NULL,
    state text NOT NULL,
    installed_at timestamptz NOT NULL,
    CONSTRAINT rule_pack_trust_generation_positive CHECK (generation > 0),
    CONSTRAINT rule_pack_trust_id_sha256 CHECK (octet_length(trust_id) = 32),
    CONSTRAINT rule_pack_trust_threshold_bound CHECK (threshold BETWEEN 1 AND 16),
    CONSTRAINT rule_pack_trust_keys_object CHECK (
        jsonb_typeof(keys) = 'object'
        AND octet_length(keys::text) <= 32768
    ),
    CONSTRAINT rule_pack_trust_state_closed CHECK (
        state IN ('staged', 'active', 'retired')
    ),
    CONSTRAINT rule_pack_trust_expiry_order CHECK (expires_at > installed_at)
);

CREATE UNIQUE INDEX rule_pack_trust_one_active
ON rule_pack_trust_roots ((state))
WHERE state = 'active';

CREATE TABLE rule_pack_metadata (
    metadata_id bytea PRIMARY KEY,
    sequence bigint NOT NULL UNIQUE,
    release_id bytea NOT NULL,
    rule_pack_id uuid NOT NULL REFERENCES rule_packs(id),
    previous_pack_hash bytea,
    rollout_stage text NOT NULL,
    required_regions text[] NOT NULL,
    eligible_regions text[] NOT NULL,
    eligible_workers text[] NOT NULL,
    trust_generation bigint NOT NULL REFERENCES rule_pack_trust_roots(generation),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    signed_envelope jsonb NOT NULL,
    state text NOT NULL,
    applied_at timestamptz NOT NULL,
    CONSTRAINT rule_pack_metadata_id_sha256 CHECK (octet_length(metadata_id) = 32),
    CONSTRAINT rule_pack_metadata_sequence_positive CHECK (sequence > 0),
    CONSTRAINT rule_pack_metadata_release_sha256 CHECK (octet_length(release_id) = 32),
    CONSTRAINT rule_pack_metadata_previous_sha256 CHECK (
        previous_pack_hash IS NULL OR octet_length(previous_pack_hash) = 32
    ),
    CONSTRAINT rule_pack_metadata_stage_closed CHECK (
        rollout_stage IN ('canary', 'regional', 'general', 'rollback')
    ),
    CONSTRAINT rule_pack_metadata_required_regions_bound CHECK (
        cardinality(required_regions) BETWEEN 1 AND 16
        AND array_position(required_regions, NULL) IS NULL
    ),
    CONSTRAINT rule_pack_metadata_eligible_regions_bound CHECK (
        cardinality(eligible_regions) BETWEEN 1 AND 16
        AND array_position(eligible_regions, NULL) IS NULL
    ),
    CONSTRAINT rule_pack_metadata_eligible_workers_bound CHECK (
        cardinality(eligible_workers) BETWEEN 0 AND 256
        AND array_position(eligible_workers, NULL) IS NULL
    ),
    CONSTRAINT rule_pack_metadata_rollout_shape CHECK (
        (
            rollout_stage = 'canary'
            AND cardinality(eligible_workers) BETWEEN 1 AND 256
        )
        OR (
            rollout_stage IN ('regional', 'general', 'rollback')
            AND cardinality(eligible_workers) = 0
        )
    ),
    CONSTRAINT rule_pack_metadata_envelope_object CHECK (
        jsonb_typeof(signed_envelope) = 'object'
        AND octet_length(signed_envelope::text) <= 2097152
    ),
    CONSTRAINT rule_pack_metadata_state_closed CHECK (
        state IN ('staged', 'active', 'superseded', 'rejected', 'rolled_back')
    ),
    CONSTRAINT rule_pack_metadata_time_order CHECK (
        issued_at <= applied_at
        AND expires_at > applied_at
        AND expires_at <= issued_at + interval '24 hours'
    )
);

CREATE INDEX rule_pack_metadata_pack_sequence
ON rule_pack_metadata (rule_pack_id, sequence DESC);

CREATE TABLE rule_pack_promotions (
    metadata_id bytea NOT NULL REFERENCES rule_pack_metadata(metadata_id),
    site_id text NOT NULL REFERENCES sites(id),
    promotion_id bytea NOT NULL,
    promotion_sequence bigint NOT NULL,
    rule_hash bytea NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (metadata_id, site_id),
    UNIQUE (metadata_id, promotion_id),
    CONSTRAINT rule_pack_promotions_metadata_sha256 CHECK (octet_length(metadata_id) = 32),
    CONSTRAINT rule_pack_promotions_id_sha256 CHECK (octet_length(promotion_id) = 32),
    CONSTRAINT rule_pack_promotions_sequence_positive CHECK (promotion_sequence > 0),
    CONSTRAINT rule_pack_promotions_rule_sha256 CHECK (octet_length(rule_hash) = 32)
);

CREATE TABLE rule_pack_registry (
    singleton boolean PRIMARY KEY DEFAULT true,
    registry_state jsonb NOT NULL,
    highest_sequence bigint NOT NULL,
    current_trust_generation bigint NOT NULL REFERENCES rule_pack_trust_roots(generation),
    active_metadata_id bytea REFERENCES rule_pack_metadata(metadata_id),
    staged_metadata_id bytea REFERENCES rule_pack_metadata(metadata_id),
    last_known_good_metadata_id bytea REFERENCES rule_pack_metadata(metadata_id),
    updated_at timestamptz NOT NULL,
    CONSTRAINT rule_pack_registry_singleton CHECK (singleton),
    CONSTRAINT rule_pack_registry_state_object CHECK (
        jsonb_typeof(registry_state) = 'object'
        AND octet_length(registry_state::text) <= 524288
    ),
    CONSTRAINT rule_pack_registry_sequence_nonnegative CHECK (highest_sequence >= 0),
    CONSTRAINT rule_pack_registry_distinct_current CHECK (
        active_metadata_id IS NULL
        OR staged_metadata_id IS NULL
        OR active_metadata_id <> staged_metadata_id
    )
);

CREATE TABLE rule_site_promotion_high_water (
    site_id text PRIMARY KEY REFERENCES sites(id),
    highest_sequence bigint NOT NULL,
    promotion_id bytea NOT NULL,
    metadata_id bytea NOT NULL REFERENCES rule_pack_metadata(metadata_id),
    updated_at timestamptz NOT NULL,
    CONSTRAINT rule_site_promotion_sequence_positive CHECK (highest_sequence > 0),
    CONSTRAINT rule_site_promotion_id_sha256 CHECK (octet_length(promotion_id) = 32),
    CONSTRAINT rule_site_promotion_metadata_sha256 CHECK (octet_length(metadata_id) = 32)
);

REVOKE ALL ON TABLE
    rule_pack_trust_roots,
    rule_pack_metadata,
    rule_pack_promotions,
    rule_pack_registry,
    rule_site_promotion_high_water
FROM PUBLIC;

DROP FUNCTION socialname_worker_resolve_rule(text, bytea, bytea, text);

CREATE FUNCTION socialname_worker_resolve_rule(
    p_site_id text,
    p_rule_hash bytea,
    p_pack_hash bytea,
    p_region_class text,
    p_metadata_id bytea,
    p_metadata_sequence bigint,
    p_promotion_id bytea,
    p_promotion_sequence bigint
)
RETURNS uuid
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
    SELECT version.id
    FROM public.rule_versions AS version
    JOIN public.rule_packs AS pack
      ON pack.id = version.rule_pack_id
    JOIN public.sites AS site
      ON site.id = version.site_id
    JOIN public.rule_pack_registry AS registry
      ON registry.singleton
    JOIN public.rule_pack_metadata AS metadata
      ON metadata.metadata_id = registry.active_metadata_id
     AND metadata.rule_pack_id = pack.id
    JOIN public.rule_pack_promotions AS promotion
      ON promotion.metadata_id = metadata.metadata_id
     AND promotion.site_id = version.site_id
     AND promotion.rule_hash = version.rule_hash
    WHERE version.site_id = p_site_id
      AND version.rule_hash = p_rule_hash
      AND pack.pack_hash = p_pack_hash
      AND metadata.metadata_id = p_metadata_id
      AND metadata.sequence = p_metadata_sequence
      AND promotion.promotion_id = p_promotion_id
      AND promotion.promotion_sequence = p_promotion_sequence
      AND octet_length(p_rule_hash) = 32
      AND octet_length(p_pack_hash) = 32
      AND octet_length(p_metadata_id) = 32
      AND octet_length(p_promotion_id) = 32
      AND p_metadata_sequence > 0
      AND p_promotion_sequence > 0
      AND p_region_class ~ '^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$'
      AND length(p_region_class) <= 64
      AND version.enabled
      AND pack.state = 'active'
      AND pack.published_at IS NOT NULL
      AND pack.expires_at > clock_timestamp()
      AND metadata.state = 'active'
      AND metadata.rollout_stage IN ('general', 'rollback')
      AND metadata.issued_at <= clock_timestamp()
      AND metadata.expires_at > clock_timestamp()
      AND p_region_class = ANY(metadata.required_regions)
      AND promotion.expires_at > clock_timestamp()
      AND site.state = 'promoted'
      AND EXISTS (
          SELECT 1
          FROM public.rule_health_records AS health
          WHERE health.id = (
              SELECT latest.id
              FROM public.rule_health_records AS latest
              WHERE latest.rule_version_id = version.id
                AND latest.region_class = p_region_class
              ORDER BY latest.recorded_at DESC
              LIMIT 1
          )
            AND health.state = 'healthy'
            AND health.recorded_at <= clock_timestamp()
            AND health.evidence_expires_at > clock_timestamp()
      )
    LIMIT 1
$$;

REVOKE ALL ON FUNCTION socialname_worker_resolve_rule(
    text, bytea, bytea, text, bytea, bigint, bytea, bigint
)
FROM PUBLIC;

CREATE FUNCTION socialname_worker_rule_version_available(
    p_rule_version_id uuid,
    p_region_class text
)
RETURNS boolean
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM public.rule_versions AS version
        JOIN public.rule_packs AS pack
          ON pack.id = version.rule_pack_id
        JOIN public.sites AS site
          ON site.id = version.site_id
        JOIN public.rule_pack_registry AS registry
          ON registry.singleton
        JOIN public.rule_pack_metadata AS metadata
          ON metadata.metadata_id = registry.active_metadata_id
         AND metadata.rule_pack_id = pack.id
        JOIN public.rule_pack_promotions AS promotion
          ON promotion.metadata_id = metadata.metadata_id
         AND promotion.site_id = version.site_id
         AND promotion.rule_hash = version.rule_hash
        WHERE version.id = p_rule_version_id
          AND p_region_class ~ '^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$'
          AND length(p_region_class) <= 64
          AND version.enabled
          AND pack.state = 'active'
          AND pack.published_at IS NOT NULL
          AND pack.expires_at > clock_timestamp()
          AND metadata.state = 'active'
          AND metadata.rollout_stage IN ('general', 'rollback')
          AND metadata.issued_at <= clock_timestamp()
          AND metadata.expires_at > clock_timestamp()
          AND p_region_class = ANY(metadata.required_regions)
          AND promotion.expires_at > clock_timestamp()
          AND site.state = 'promoted'
          AND EXISTS (
              SELECT 1
              FROM public.rule_health_records AS health
              WHERE health.id = (
                  SELECT latest.id
                  FROM public.rule_health_records AS latest
                  WHERE latest.rule_version_id = version.id
                    AND latest.region_class = p_region_class
                  ORDER BY latest.recorded_at DESC
                  LIMIT 1
              )
                AND health.state = 'healthy'
                AND health.recorded_at <= clock_timestamp()
                AND health.evidence_expires_at > clock_timestamp()
          )
    )
$$;

REVOKE ALL ON FUNCTION socialname_worker_rule_version_available(uuid, text)
FROM PUBLIC;
