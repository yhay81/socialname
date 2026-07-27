-- Shared quorum assertions are cross-tenant shared-pool knowledge derived
-- from calibrated contributions. The tables carry no tenant column, are
-- forced-RLS with no policy (deny-all), and are reachable only through the
-- narrow SECURITY DEFINER functions below plus schema-owner operations.

CREATE TABLE shared_assertions (
    id uuid PRIMARY KEY,
    site_id text NOT NULL REFERENCES sites(id),
    normalized_username text NOT NULL,
    rule_version_id uuid NOT NULL REFERENCES rule_versions(id),
    quality text NOT NULL,
    outcome text,
    vote_count integer NOT NULL,
    network_group_count integer NOT NULL,
    region_count integer NOT NULL,
    regions text[] NOT NULL,
    first_counted_at timestamptz NOT NULL,
    last_counted_at timestamptz NOT NULL,
    derivation_version text NOT NULL DEFAULT 'shared-assertion-v1',
    derived_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    UNIQUE (site_id, normalized_username),
    CONSTRAINT shared_assertions_username_bound CHECK (
        octet_length(normalized_username) BETWEEN 1 AND 256
    ),
    CONSTRAINT shared_assertions_quality_closed CHECK (
        quality IN ('corroborated', 'conflicted')
    ),
    CONSTRAINT shared_assertions_derivation_closed CHECK (
        derivation_version = 'shared-assertion-v1'
    ),
    CONSTRAINT shared_assertions_counts_nonnegative CHECK (
        vote_count >= 0 AND network_group_count >= 0 AND region_count >= 0
        AND cardinality(regions) = region_count
    ),
    CONSTRAINT shared_assertions_time_order CHECK (
        last_counted_at >= first_counted_at AND expires_at > derived_at
    ),
    CONSTRAINT shared_assertions_quorum_relation CHECK (
        (
            quality = 'corroborated'
            AND outcome = 'found'
            AND vote_count >= 3
            AND network_group_count >= 2
            AND region_count >= 2
        )
        OR (
            quality = 'corroborated'
            AND outcome = 'not_found'
            AND vote_count >= 5
            AND network_group_count >= 3
            AND region_count >= 2
            AND last_counted_at >= first_counted_at + interval '10 minutes'
        )
        OR (
            quality = 'conflicted'
            AND outcome IS NULL
        )
    )
);

CREATE INDEX shared_assertions_expiry
ON shared_assertions (expires_at);

CREATE TABLE shared_assertion_support (
    id uuid PRIMARY KEY,
    shared_assertion_id uuid NOT NULL
        REFERENCES shared_assertions(id) ON DELETE CASCADE,
    tenant_id uuid NOT NULL,
    contribution_id uuid NOT NULL,
    UNIQUE (shared_assertion_id, tenant_id, contribution_id),
    FOREIGN KEY (tenant_id, contribution_id)
        REFERENCES shared_contributions(tenant_id, id)
);

CREATE INDEX shared_assertion_support_contribution
ON shared_assertion_support (tenant_id, contribution_id);

ALTER TABLE probe_jobs DROP COLUMN priority_reason;
ALTER TABLE probe_jobs
    ADD COLUMN priority_reason text GENERATED ALWAYS AS (
        CASE
            WHEN priority >= 100 THEN 'regional_conflict'
            WHEN priority >= 50 THEN 'account_confirmation'
            WHEN priority >= 25 THEN 'shared_quorum'
            ELSE 'routine'
        END
    ) STORED;

-- Derives one bounded batch of shared quorum assertions. Every parameter is
-- an initial calibration value pending labeled-canary replay: eligible votes
-- are unexpired current-influence definitive E3/E4 contributions on the
-- newest contributing rule version whose site-family reputation is
-- calibrated or trusted; independence counts at most one vote per tenant,
-- per installation, and per network group through a deterministic greedy
-- pass; found quorum needs 3 votes / 2 network groups / 2 regions,
-- shared-only absence needs 5 / 3 / 2 plus a ten-minute span; every counted
-- region must currently be healthy; fresh strong shared-visibility managed
-- evidence supersedes (and withdraws) shared derivation; any fresh opposing
-- strong eligible contribution makes the key conflicted. A derived
-- corroborated or conflicted key raises only already-budgeted queued or
-- retry probe jobs of differing watch targets to the shared-quorum priority.
CREATE FUNCTION socialname_worker_derive_shared_assertions(
    p_batch_limit integer
)
RETURNS TABLE (
    scanned_keys integer,
    corroborated integer,
    conflicted integer,
    withdrawn integer,
    escalated_jobs integer
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    scanned integer := 0;
    corroborated_count integer := 0;
    conflicted_count integer := 0;
    withdrawn_count integer := 0;
    escalated_count integer := 0;
    key_row record;
    vote_row record;
    latest_rule uuid;
    managed_supersedes boolean;
    found_votes integer;
    not_found_votes integer;
    counted_outcome text;
    counted_votes integer;
    counted_groups integer;
    counted_regions text[];
    counted_first timestamptz;
    counted_last timestamptz;
    counted_expires timestamptz;
    unhealthy_region boolean;
    assertion_id uuid;
    raised integer;
BEGIN
    IF p_batch_limit IS NULL OR p_batch_limit < 1 OR p_batch_limit > 1000 THEN
        RAISE EXCEPTION 'shared assertion batch limit is invalid'
            USING ERRCODE = '22023';
    END IF;

    DELETE FROM public.shared_assertions
    WHERE expires_at <= clock_timestamp();
    GET DIAGNOSTICS withdrawn_count = ROW_COUNT;

    CREATE TEMPORARY TABLE IF NOT EXISTS shared_quorum_votes (
        tenant_id uuid NOT NULL,
        contribution_id uuid NOT NULL,
        client_id uuid NOT NULL,
        network_group bytea NOT NULL,
        region_class text NOT NULL,
        verdict text NOT NULL,
        evidence_class text NOT NULL,
        observed_at timestamptz NOT NULL,
        expires_at timestamptz NOT NULL,
        counted boolean NOT NULL DEFAULT false
    ) ON COMMIT DROP;

    FOR key_row IN
        SELECT candidate.site_id, candidate.normalized_username
        FROM (
            SELECT contribution.site_id, contribution.normalized_username,
                   max(contribution.received_at) AS last_received
            FROM public.shared_contributions AS contribution
            WHERE contribution.outcome_kind = 'definitive'
              AND contribution.influence_scope = 'current'
              AND contribution.expires_at > clock_timestamp()
            GROUP BY 1, 2
        ) AS candidate
        LEFT JOIN public.shared_assertions AS existing
          ON existing.site_id = candidate.site_id
         AND existing.normalized_username = candidate.normalized_username
        WHERE existing.id IS NULL
           OR existing.derived_at < candidate.last_received
           OR existing.expires_at <= clock_timestamp()
        ORDER BY candidate.last_received, candidate.site_id,
                 candidate.normalized_username
        LIMIT p_batch_limit
    LOOP
        scanned := scanned + 1;
        DELETE FROM shared_quorum_votes;

        -- Fresh strong shared-visibility managed evidence owns this key.
        SELECT EXISTS (
            SELECT 1 FROM public.observations AS observation
            WHERE observation.site_id = key_row.site_id
              AND observation.normalized_username = key_row.normalized_username
              AND observation.visibility = 'shared'
              AND observation.outcome_kind = 'definitive'
              AND observation.evidence_class IN (
                  'e3_explicit_endpoint', 'e4_structured_identity'
              )
              AND observation.expires_at > clock_timestamp()
              AND NOT EXISTS (
                  SELECT 1 FROM public.deletion_resource_matches AS hidden
                  WHERE hidden.tenant_id = observation.tenant_id
                    AND hidden.resource_kind = 'observation'
                    AND hidden.resource_id = observation.id
              )
        ) INTO managed_supersedes;
        IF managed_supersedes THEN
            DELETE FROM public.shared_assertions
            WHERE site_id = key_row.site_id
              AND normalized_username = key_row.normalized_username;
            IF FOUND THEN
                withdrawn_count := withdrawn_count + 1;
            END IF;
            CONTINUE;
        END IF;

        SELECT contribution.rule_version_id
        INTO latest_rule
        FROM public.shared_contributions AS contribution
        JOIN public.rule_versions AS version
          ON version.id = contribution.rule_version_id
        WHERE contribution.site_id = key_row.site_id
          AND contribution.normalized_username = key_row.normalized_username
          AND contribution.outcome_kind = 'definitive'
          AND contribution.influence_scope = 'current'
          AND contribution.expires_at > clock_timestamp()
        ORDER BY version.created_at DESC, version.id DESC
        LIMIT 1;

        INSERT INTO shared_quorum_votes (
            tenant_id, contribution_id, client_id, network_group,
            region_class, verdict, evidence_class, observed_at, expires_at
        )
        SELECT contribution.tenant_id, contribution.id,
               contribution.client_id, contribution.network_group,
               contribution.region_class, contribution.verdict,
               contribution.evidence_class, contribution.observed_at,
               contribution.expires_at
        FROM public.shared_contributions AS contribution
        JOIN public.contributor_reputation AS reputation
          ON reputation.tenant_id = contribution.tenant_id
         AND reputation.client_id = contribution.client_id
         AND reputation.site_family = contribution.site_id
        WHERE contribution.site_id = key_row.site_id
          AND contribution.normalized_username = key_row.normalized_username
          AND contribution.rule_version_id = latest_rule
          AND contribution.outcome_kind = 'definitive'
          AND contribution.evidence_class IN (
              'e3_explicit_endpoint', 'e4_structured_identity'
          )
          AND contribution.influence_scope = 'current'
          AND contribution.expires_at > clock_timestamp()
          AND reputation.tier IN ('calibrated', 'trusted')
          AND NOT EXISTS (
              SELECT 1 FROM public.deletion_resource_matches AS hidden
              WHERE hidden.tenant_id = contribution.tenant_id
                AND hidden.resource_kind = 'shared_contribution'
                AND hidden.resource_id = contribution.id
          );

        SELECT count(*) FILTER (WHERE verdict = 'found'),
               count(*) FILTER (WHERE verdict = 'not_found')
        INTO found_votes, not_found_votes
        FROM shared_quorum_votes;

        IF found_votes > 0 AND not_found_votes > 0 THEN
            -- Fresh opposing strong eligible evidence conflicts the key and
            -- cannot move any account baseline.
            assertion_id := gen_random_uuid();
            DELETE FROM public.shared_assertions
            WHERE site_id = key_row.site_id
              AND normalized_username = key_row.normalized_username;
            INSERT INTO public.shared_assertions (
                id, site_id, normalized_username, rule_version_id, quality,
                outcome, vote_count, network_group_count, region_count,
                regions, first_counted_at, last_counted_at, derived_at,
                expires_at
            )
            SELECT assertion_id, key_row.site_id,
                   key_row.normalized_username, latest_rule, 'conflicted',
                   NULL, 0, 0, 0, '{}'::text[], clock_timestamp(),
                   clock_timestamp(), clock_timestamp(),
                   min(vote.expires_at)
            FROM shared_quorum_votes AS vote;
            INSERT INTO public.shared_assertion_support (
                id, shared_assertion_id, tenant_id, contribution_id
            )
            SELECT gen_random_uuid(), assertion_id, vote.tenant_id,
                   vote.contribution_id
            FROM shared_quorum_votes AS vote;
            conflicted_count := conflicted_count + 1;
            counted_outcome := NULL;
        ELSE
            counted_outcome := CASE
                WHEN found_votes > 0 THEN 'found'
                WHEN not_found_votes > 0 THEN 'not_found'
                ELSE NULL
            END;
        END IF;

        IF counted_outcome IS NOT NULL THEN
            -- Deterministic greedy independence pass: strongest evidence
            -- first, then oldest observation; a vote is counted only when
            -- its tenant, installation, and network group are all unused.
            counted_votes := 0;
            FOR vote_row IN
                SELECT vote.tenant_id, vote.contribution_id, vote.client_id,
                       vote.network_group
                FROM shared_quorum_votes AS vote
                WHERE vote.verdict = counted_outcome
                ORDER BY vote.evidence_class DESC, vote.observed_at,
                         vote.contribution_id
            LOOP
                IF NOT EXISTS (
                    SELECT 1 FROM shared_quorum_votes AS used
                    WHERE used.counted
                      AND (
                          used.tenant_id = vote_row.tenant_id
                          OR used.client_id = vote_row.client_id
                          OR used.network_group = vote_row.network_group
                      )
                ) THEN
                    UPDATE shared_quorum_votes
                    SET counted = true
                    WHERE contribution_id = vote_row.contribution_id
                      AND tenant_id = vote_row.tenant_id;
                    counted_votes := counted_votes + 1;
                END IF;
            END LOOP;

            SELECT count(DISTINCT vote.network_group),
                   array_agg(DISTINCT vote.region_class ORDER BY
                             vote.region_class),
                   min(vote.observed_at), max(vote.observed_at),
                   min(vote.expires_at)
            INTO counted_groups, counted_regions, counted_first,
                 counted_last, counted_expires
            FROM shared_quorum_votes AS vote
            WHERE vote.counted;

            SELECT EXISTS (
                SELECT 1
                FROM unnest(counted_regions) AS region(region_class)
                WHERE NOT EXISTS (
                    SELECT 1 FROM public.rule_health_records AS health
                    WHERE health.id = (
                        SELECT latest.id
                        FROM public.rule_health_records AS latest
                        WHERE latest.rule_version_id = latest_rule
                          AND latest.region_class = region.region_class
                        ORDER BY latest.recorded_at DESC
                        LIMIT 1
                    )
                      AND health.state = 'healthy'
                      AND health.evidence_expires_at > clock_timestamp()
                )
            ) INTO unhealthy_region;

            IF NOT unhealthy_region
               AND (
                   (
                       counted_outcome = 'found'
                       AND counted_votes >= 3
                       AND counted_groups >= 2
                       AND cardinality(counted_regions) >= 2
                   )
                   OR (
                       counted_outcome = 'not_found'
                       AND counted_votes >= 5
                       AND counted_groups >= 3
                       AND cardinality(counted_regions) >= 2
                       AND counted_last
                           >= counted_first + interval '10 minutes'
                   )
               ) THEN
                assertion_id := gen_random_uuid();
                DELETE FROM public.shared_assertions
                WHERE site_id = key_row.site_id
                  AND normalized_username = key_row.normalized_username;
                INSERT INTO public.shared_assertions (
                    id, site_id, normalized_username, rule_version_id,
                    quality, outcome, vote_count, network_group_count,
                    region_count, regions, first_counted_at,
                    last_counted_at, derived_at, expires_at
                ) VALUES (
                    assertion_id, key_row.site_id,
                    key_row.normalized_username, latest_rule,
                    'corroborated', counted_outcome, counted_votes,
                    counted_groups, cardinality(counted_regions),
                    counted_regions, counted_first, counted_last,
                    clock_timestamp(), counted_expires
                );
                INSERT INTO public.shared_assertion_support (
                    id, shared_assertion_id, tenant_id, contribution_id
                )
                SELECT gen_random_uuid(), assertion_id, vote.tenant_id,
                       vote.contribution_id
                FROM shared_quorum_votes AS vote
                WHERE vote.counted;
                corroborated_count := corroborated_count + 1;
            ELSE
                DELETE FROM public.shared_assertions
                WHERE site_id = key_row.site_id
                  AND normalized_username = key_row.normalized_username;
                IF FOUND THEN
                    withdrawn_count := withdrawn_count + 1;
                END IF;
                CONTINUE;
            END IF;
        ELSIF counted_outcome IS NULL AND NOT (
            found_votes > 0 AND not_found_votes > 0
        ) THEN
            DELETE FROM public.shared_assertions
            WHERE site_id = key_row.site_id
              AND normalized_username = key_row.normalized_username;
            IF FOUND THEN
                withdrawn_count := withdrawn_count + 1;
            END IF;
            CONTINUE;
        END IF;

        -- Managed verification escalation: raise only already-budgeted
        -- queued or retry jobs of watch targets whose account state differs
        -- from (or has not established) the shared outcome.
        UPDATE public.probe_jobs AS job
        SET priority = 25, updated_at = clock_timestamp()
        WHERE job.state IN ('queued', 'retry_wait')
          AND job.priority < 25
          AND EXISTS (
              SELECT 1
              FROM public.probe_job_consumers AS consumer
              JOIN public.watch_targets AS target
                ON target.tenant_id = consumer.tenant_id
               AND target.id = consumer.watch_target_id
              WHERE consumer.tenant_id = job.tenant_id
                AND consumer.probe_job_id = job.id
                AND consumer.watch_target_id IS NOT NULL
                AND target.site_id = key_row.site_id
                AND target.normalized_username = key_row.normalized_username
                AND target.retired_at IS NULL
                AND (
                    counted_outcome IS NULL
                    OR target.account_state IS NULL
                    OR target.account_state <> counted_outcome
                )
          );
        GET DIAGNOSTICS raised = ROW_COUNT;
        escalated_count := escalated_count + raised;
    END LOOP;

    DROP TABLE shared_quorum_votes;
    RETURN QUERY SELECT scanned, corroborated_count, conflicted_count,
                        withdrawn_count, escalated_count;
END
$$;

REVOKE ALL ON FUNCTION socialname_worker_derive_shared_assertions(integer)
FROM PUBLIC;

-- Withdraws shared-pool support derived from one deletion request's matched
-- contributions before the fenced worker purges the underlying rows. The
-- affected assertions are withdrawn entirely; remaining eligible evidence
-- re-derives them on the next bounded derivation pass.
CREATE FUNCTION socialname_worker_withdraw_shared_support(
    p_tenant_id uuid,
    p_deletion_request_id uuid
)
RETURNS integer
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    withdrawn integer;
BEGIN
    IF p_tenant_id IS NULL OR p_deletion_request_id IS NULL THEN
        RAISE EXCEPTION 'shared support withdrawal parameters are invalid'
            USING ERRCODE = '22023';
    END IF;
    WITH affected AS (
        SELECT DISTINCT support.shared_assertion_id
        FROM public.shared_assertion_support AS support
        JOIN public.deletion_resource_matches AS matched
          ON matched.tenant_id = support.tenant_id
         AND matched.resource_id = support.contribution_id
        WHERE support.tenant_id = p_tenant_id
          AND matched.deletion_request_id = p_deletion_request_id
          AND matched.resource_kind = 'shared_contribution'
    )
    DELETE FROM public.shared_assertions AS assertion
    USING affected
    WHERE assertion.id = affected.shared_assertion_id;
    GET DIAGNOSTICS withdrawn = ROW_COUNT;
    RETURN withdrawn;
END
$$;

REVOKE ALL ON FUNCTION socialname_worker_withdraw_shared_support(uuid, uuid)
FROM PUBLIC;

ALTER TABLE shared_assertions ENABLE ROW LEVEL SECURITY;
ALTER TABLE shared_assertions FORCE ROW LEVEL SECURITY;
ALTER TABLE shared_assertion_support ENABLE ROW LEVEL SECURITY;
ALTER TABLE shared_assertion_support FORCE ROW LEVEL SECURITY;

REVOKE ALL ON shared_assertions, shared_assertion_support FROM PUBLIC;
