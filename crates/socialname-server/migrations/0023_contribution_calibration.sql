CREATE TABLE contribution_validations (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    contribution_id uuid NOT NULL,
    observation_id uuid NOT NULL,
    client_id uuid NOT NULL,
    site_family text NOT NULL,
    region_class text NOT NULL,
    agreement boolean NOT NULL,
    contribution_verdict text NOT NULL,
    truth_verdict text NOT NULL,
    validated_at timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, contribution_id),
    FOREIGN KEY (tenant_id, contribution_id)
        REFERENCES shared_contributions(tenant_id, id),
    FOREIGN KEY (tenant_id, observation_id)
        REFERENCES observations(tenant_id, id),
    FOREIGN KEY (tenant_id, client_id) REFERENCES clients(tenant_id, id),
    CONSTRAINT contribution_validations_site_family_bound CHECK (
        length(site_family) BETWEEN 1 AND 64
        AND site_family ~ '^[a-z0-9]+(?:-[a-z0-9]+)*$'
    ),
    CONSTRAINT contribution_validations_region_bound CHECK (
        length(region_class) BETWEEN 1 AND 64
    ),
    CONSTRAINT contribution_validations_verdicts_closed CHECK (
        contribution_verdict IN ('found', 'not_found')
        AND truth_verdict IN ('found', 'not_found')
    ),
    CONSTRAINT contribution_validations_agreement_relation CHECK (
        agreement = (contribution_verdict = truth_verdict)
    )
);

CREATE INDEX contribution_validations_reputation_window
ON contribution_validations (
    tenant_id, client_id, site_family, validated_at DESC
);
CREATE INDEX contribution_validations_observation
ON contribution_validations (tenant_id, observation_id);

CREATE TRIGGER contribution_validations_append_only
BEFORE UPDATE ON contribution_validations
FOR EACH ROW EXECUTE FUNCTION socialname_reject_update();

-- Lineage-backed deletion must be able to recompute the cached reputation
-- aggregates from the remaining validation rows, so the overlap counters are
-- no longer monotonic. Identity, revision fencing, strict update-time order,
-- monotonic activity days, the closed tier matrix, and terminal suspension
-- remain enforced.
CREATE OR REPLACE FUNCTION socialname_guard_contributor_reputation_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.client_id IS DISTINCT FROM OLD.client_id
       OR NEW.site_family IS DISTINCT FROM OLD.site_family
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.revision IS DISTINCT FROM OLD.revision + 1
       OR NEW.updated_at <= OLD.updated_at
       OR NEW.active_days < OLD.active_days
       OR OLD.tier = 'suspended'
       OR NOT (
            NEW.tier = OLD.tier
            OR (OLD.tier = 'new' AND NEW.tier IN ('calibrated', 'suspended'))
            OR (
                OLD.tier = 'calibrated'
                AND NEW.tier IN ('trusted', 'new', 'suspended')
            )
            OR (
                OLD.tier = 'trusted'
                AND NEW.tier IN ('calibrated', 'suspended')
            )
       ) THEN
        RAISE EXCEPTION 'contributor reputation update is invalid'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

-- Validates one bounded batch of unvalidated definitive contributions
-- against managed truth and re-evaluates a bounded set of reputation tiers.
-- Every threshold below is an initial calibration parameter that must be
-- replayed against labeled canary history before production use:
-- a truth observation is the nearest same-tenant, same-rule-version,
-- same-region, definitive, strong (E3/E4), health-green managed observation
-- within fifteen minutes; the tier window is 120 days; ascent requires
-- 20 overlaps / 98% agreement / 7 active days (calibrated) and
-- 100 / 99% / 30 active days / 5 site families (trusted); rolling agreement
-- below 90% over at least ten windowed validations suspends.
CREATE FUNCTION socialname_worker_validate_contributions(p_batch_limit integer)
RETURNS TABLE (
    validated integer,
    agreements integer,
    disagreements integer,
    tier_promotions integer,
    tier_demotions integer,
    suspensions integer
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    inserted_agreements integer := 0;
    inserted_disagreements integer := 0;
    counted_rows integer := 0;
    promotion_count integer := 0;
    demotion_count integer := 0;
    suspension_count integer := 0;
    reputation_row record;
    effective_overlaps bigint;
    effective_hits bigint;
    windowed_families bigint;
    next_tier text;
BEGIN
    IF p_batch_limit IS NULL OR p_batch_limit < 1 OR p_batch_limit > 1000 THEN
        RAISE EXCEPTION 'contribution validation batch limit is invalid'
            USING ERRCODE = '22023';
    END IF;

    WITH candidate AS (
        SELECT
            contribution.tenant_id,
            contribution.id AS contribution_id,
            contribution.client_id,
            contribution.site_id,
            contribution.region_class,
            contribution.verdict AS contribution_verdict,
            truth.id AS observation_id,
            truth.verdict AS truth_verdict
        FROM public.shared_contributions AS contribution
        CROSS JOIN LATERAL (
            SELECT observation.id, observation.verdict
            FROM public.observations AS observation
            WHERE observation.tenant_id = contribution.tenant_id
              AND observation.site_id = contribution.site_id
              AND observation.normalized_username
                  = contribution.normalized_username
              AND observation.rule_version_id = contribution.rule_version_id
              AND observation.region_class = contribution.region_class
              AND observation.outcome_kind = 'definitive'
              AND observation.evidence_class IN (
                  'e3_explicit_endpoint', 'e4_structured_identity'
              )
              AND observation.rule_health_green
              AND observation.observed_at
                  BETWEEN contribution.observed_at - interval '15 minutes'
                      AND contribution.observed_at + interval '15 minutes'
              AND NOT EXISTS (
                  SELECT 1 FROM public.deletion_resource_matches AS hidden
                  WHERE hidden.tenant_id = observation.tenant_id
                    AND hidden.resource_kind = 'observation'
                    AND hidden.resource_id = observation.id
              )
            ORDER BY
                GREATEST(
                    observation.observed_at - contribution.observed_at,
                    contribution.observed_at - observation.observed_at
                ),
                observation.id
            LIMIT 1
        ) AS truth
        WHERE contribution.outcome_kind = 'definitive'
          AND NOT EXISTS (
              SELECT 1 FROM public.contribution_validations AS existing
              WHERE existing.tenant_id = contribution.tenant_id
                AND existing.contribution_id = contribution.id
          )
          AND NOT EXISTS (
              SELECT 1 FROM public.deletion_resource_matches AS hidden
              WHERE hidden.tenant_id = contribution.tenant_id
                AND hidden.resource_kind = 'shared_contribution'
                AND hidden.resource_id = contribution.id
          )
          AND NOT EXISTS (
              SELECT 1 FROM public.contributor_reputation AS reputation
              WHERE reputation.tenant_id = contribution.tenant_id
                AND reputation.client_id = contribution.client_id
                AND reputation.site_family = contribution.site_id
                AND reputation.tier = 'suspended'
          )
        ORDER BY contribution.received_at, contribution.id
        LIMIT p_batch_limit
    ), inserted AS (
        INSERT INTO public.contribution_validations (
            id, tenant_id, contribution_id, observation_id, client_id,
            site_family, region_class, agreement, contribution_verdict,
            truth_verdict, validated_at
        )
        SELECT
            gen_random_uuid(), candidate.tenant_id, candidate.contribution_id,
            candidate.observation_id, candidate.client_id, candidate.site_id,
            candidate.region_class,
            candidate.contribution_verdict = candidate.truth_verdict,
            candidate.contribution_verdict, candidate.truth_verdict,
            clock_timestamp()
        FROM candidate
        ON CONFLICT (tenant_id, contribution_id) DO NOTHING
        RETURNING tenant_id, client_id, site_family, agreement
    ), counted AS (
        UPDATE public.contributor_reputation AS reputation
        SET validated_overlaps = reputation.validated_overlaps + delta.total,
            agreement_hits = reputation.agreement_hits + delta.hits,
            agreement_misses = reputation.agreement_misses + delta.misses,
            revision = reputation.revision + 1,
            updated_at = GREATEST(
                clock_timestamp(),
                reputation.updated_at + interval '1 microsecond'
            )
        FROM (
            SELECT
                inserted.tenant_id, inserted.client_id, inserted.site_family,
                count(*) AS total,
                count(*) FILTER (WHERE inserted.agreement) AS hits,
                count(*) FILTER (WHERE NOT inserted.agreement) AS misses
            FROM inserted
            GROUP BY 1, 2, 3
        ) AS delta
        WHERE reputation.tenant_id = delta.tenant_id
          AND reputation.client_id = delta.client_id
          AND reputation.site_family = delta.site_family
          AND reputation.tier <> 'suspended'
        RETURNING 1
    )
    SELECT
        COALESCE((
            SELECT count(*) FILTER (WHERE inserted.agreement) FROM inserted
        ), 0)::integer,
        COALESCE((
            SELECT count(*) FILTER (WHERE NOT inserted.agreement) FROM inserted
        ), 0)::integer,
        COALESCE((SELECT count(*) FROM counted), 0)::integer
    INTO inserted_agreements, inserted_disagreements, counted_rows;

    FOR reputation_row IN
        SELECT reputation.tenant_id, reputation.id, reputation.client_id,
               reputation.site_family, reputation.tier, reputation.active_days
        FROM public.contributor_reputation AS reputation
        WHERE reputation.tier <> 'suspended'
          AND EXISTS (
              SELECT 1 FROM public.contribution_validations AS validation
              WHERE validation.tenant_id = reputation.tenant_id
                AND validation.client_id = reputation.client_id
                AND validation.site_family = reputation.site_family
          )
        ORDER BY reputation.updated_at
        LIMIT p_batch_limit
        FOR UPDATE SKIP LOCKED
    LOOP
        SELECT count(*),
               count(*) FILTER (WHERE validation.agreement)
        INTO effective_overlaps, effective_hits
        FROM public.contribution_validations AS validation
        WHERE validation.tenant_id = reputation_row.tenant_id
          AND validation.client_id = reputation_row.client_id
          AND validation.site_family = reputation_row.site_family
          AND validation.validated_at > clock_timestamp() - interval '120 days';
        SELECT count(DISTINCT validation.site_family)
        INTO windowed_families
        FROM public.contribution_validations AS validation
        WHERE validation.tenant_id = reputation_row.tenant_id
          AND validation.client_id = reputation_row.client_id
          AND validation.validated_at > clock_timestamp() - interval '120 days';

        IF effective_overlaps >= 10
           AND effective_hits * 100 < effective_overlaps * 90 THEN
            UPDATE public.contributor_reputation
            SET tier = 'suspended',
                suspended_at = clock_timestamp(),
                suspension_reason = 'agreement_collapse',
                revision = revision + 1,
                updated_at = GREATEST(
                    clock_timestamp(), updated_at + interval '1 microsecond'
                )
            WHERE tenant_id = reputation_row.tenant_id
              AND id = reputation_row.id;
            INSERT INTO public.audit_events (
                id, tenant_id, action, resource_kind, resource_id,
                occurred_at, details
            ) VALUES (
                gen_random_uuid(), reputation_row.tenant_id,
                'contribution.reputation.suspended', 'contributor_reputation',
                reputation_row.id, clock_timestamp(),
                jsonb_build_object('reason', 'agreement_collapse')
            );
            suspension_count := suspension_count + 1;
            CONTINUE;
        END IF;

        next_tier := reputation_row.tier;
        IF reputation_row.tier = 'new' THEN
            IF effective_overlaps >= 20
               AND effective_hits * 100 >= effective_overlaps * 98
               AND reputation_row.active_days >= 7 THEN
                next_tier := 'calibrated';
            END IF;
        ELSIF reputation_row.tier = 'calibrated' THEN
            IF effective_overlaps >= 100
               AND effective_hits * 100 >= effective_overlaps * 99
               AND reputation_row.active_days >= 30
               AND windowed_families >= 5 THEN
                next_tier := 'trusted';
            ELSIF effective_overlaps < 20
                  OR effective_hits * 100 < effective_overlaps * 98 THEN
                next_tier := 'new';
            END IF;
        ELSIF reputation_row.tier = 'trusted' THEN
            IF effective_overlaps < 100
               OR effective_hits * 100 < effective_overlaps * 99 THEN
                next_tier := 'calibrated';
            END IF;
        END IF;

        IF next_tier IS DISTINCT FROM reputation_row.tier THEN
            UPDATE public.contributor_reputation
            SET tier = next_tier,
                revision = revision + 1,
                updated_at = GREATEST(
                    clock_timestamp(), updated_at + interval '1 microsecond'
                )
            WHERE tenant_id = reputation_row.tenant_id
              AND id = reputation_row.id;
            INSERT INTO public.audit_events (
                id, tenant_id, action, resource_kind, resource_id,
                occurred_at, details
            ) VALUES (
                gen_random_uuid(), reputation_row.tenant_id,
                'contribution.reputation.tier_changed',
                'contributor_reputation', reputation_row.id,
                clock_timestamp(),
                jsonb_build_object(
                    'from', reputation_row.tier, 'to', next_tier
                )
            );
            IF (reputation_row.tier = 'new' AND next_tier = 'calibrated')
               OR (
                    reputation_row.tier = 'calibrated'
                    AND next_tier = 'trusted'
               ) THEN
                promotion_count := promotion_count + 1;
            ELSE
                demotion_count := demotion_count + 1;
            END IF;
        END IF;
    END LOOP;

    RETURN QUERY SELECT
        inserted_agreements + inserted_disagreements,
        inserted_agreements,
        inserted_disagreements,
        promotion_count,
        demotion_count,
        suspension_count;
END
$$;

REVOKE ALL ON FUNCTION socialname_worker_validate_contributions(integer)
FROM PUBLIC;

ALTER TABLE contribution_validations ENABLE ROW LEVEL SECURITY;
ALTER TABLE contribution_validations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON contribution_validations
    USING (tenant_id = socialname_current_tenant_id())
    WITH CHECK (tenant_id = socialname_current_tenant_id());

REVOKE ALL ON contribution_validations FROM PUBLIC;
