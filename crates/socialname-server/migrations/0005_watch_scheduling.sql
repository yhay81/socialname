ALTER TABLE watch_targets
    ADD COLUMN requested_username text,
    ADD COLUMN ordinal integer;

UPDATE watch_targets AS target
SET requested_username = target.normalized_username;

WITH ordered AS (
    SELECT id,
           row_number() OVER (
               PARTITION BY tenant_id, watch_id
               ORDER BY created_at, id
           ) - 1 AS ordinal
    FROM watch_targets
)
UPDATE watch_targets AS target
SET ordinal = ordered.ordinal
FROM ordered
WHERE ordered.id = target.id;

ALTER TABLE watch_targets
    ALTER COLUMN requested_username SET NOT NULL,
    ALTER COLUMN ordinal SET NOT NULL,
    ALTER COLUMN normalized_username DROP NOT NULL,
    DROP CONSTRAINT watch_targets_username_bound,
    DROP CONSTRAINT watch_targets_tenant_id_watch_id_normalized_username_site_i_key,
    ADD CONSTRAINT watch_targets_requested_username_bound CHECK (
        octet_length(requested_username) BETWEEN 1 AND 256
        AND requested_username !~ '[[:cntrl:]]'
    ),
    ADD CONSTRAINT watch_targets_normalized_username_bound CHECK (
        normalized_username IS NULL
        OR (
            octet_length(normalized_username) BETWEEN 1 AND 256
            AND normalized_username !~ '[[:cntrl:]]'
        )
    ),
    ADD CONSTRAINT watch_targets_ordinal_nonnegative CHECK (ordinal >= 0),
    ADD UNIQUE (tenant_id, watch_id, requested_username, site_id),
    ADD UNIQUE (tenant_id, watch_id, ordinal);

CREATE INDEX watch_targets_normalized
ON watch_targets (tenant_id, normalized_username, site_id)
WHERE normalized_username IS NOT NULL AND retired_at IS NULL;

CREATE TABLE watch_notification_endpoints (
    tenant_id uuid NOT NULL,
    watch_id uuid NOT NULL,
    endpoint_id uuid NOT NULL,
    ordinal integer NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, watch_id, endpoint_id),
    UNIQUE (tenant_id, watch_id, ordinal),
    FOREIGN KEY (tenant_id, watch_id) REFERENCES watches(tenant_id, id),
    FOREIGN KEY (tenant_id, endpoint_id)
        REFERENCES notification_endpoints(tenant_id, id),
    CONSTRAINT watch_endpoints_ordinal_nonnegative CHECK (ordinal >= 0)
);

CREATE TABLE watch_runs (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    watch_id uuid NOT NULL,
    watch_revision bigint NOT NULL,
    scheduled_for timestamptz NOT NULL,
    state text NOT NULL DEFAULT 'planned',
    maximum_probes integer NOT NULL,
    maximum_bytes bigint NOT NULL,
    reserved_probes integer NOT NULL DEFAULT 0,
    reserved_bytes bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, watch_id, scheduled_for),
    FOREIGN KEY (tenant_id, watch_id) REFERENCES watches(tenant_id, id),
    CONSTRAINT watch_runs_revision_positive CHECK (watch_revision > 0),
    CONSTRAINT watch_runs_state_closed CHECK (
        state IN ('planned', 'running', 'completed', 'failed', 'cancelled')
    ),
    CONSTRAINT watch_runs_probe_budget CHECK (
        maximum_probes BETWEEN 1 AND 256
        AND reserved_probes BETWEEN 0 AND maximum_probes
    ),
    CONSTRAINT watch_runs_byte_budget CHECK (
        maximum_bytes BETWEEN 1024 AND 67108864
        AND reserved_bytes BETWEEN 0 AND maximum_bytes
    ),
    CONSTRAINT watch_runs_completion_relation CHECK (
        (
            state IN ('planned', 'running')
            AND completed_at IS NULL
        )
        OR (
            state IN ('completed', 'failed', 'cancelled')
            AND completed_at IS NOT NULL
        )
    ),
    CONSTRAINT watch_runs_time_order CHECK (
        scheduled_for <= created_at
        AND (completed_at IS NULL OR completed_at >= created_at)
    )
);

CREATE TABLE watch_run_targets (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    watch_run_id uuid NOT NULL,
    watch_target_id uuid NOT NULL,
    region_class text NOT NULL,
    state text NOT NULL DEFAULT 'pending',
    probe_job_id uuid,
    observation_id uuid,
    reserved_bytes bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, watch_run_id, watch_target_id, region_class),
    FOREIGN KEY (tenant_id, watch_run_id) REFERENCES watch_runs(tenant_id, id),
    FOREIGN KEY (tenant_id, watch_target_id)
        REFERENCES watch_targets(tenant_id, id),
    FOREIGN KEY (tenant_id, probe_job_id) REFERENCES probe_jobs(tenant_id, id),
    FOREIGN KEY (tenant_id, observation_id) REFERENCES observations(tenant_id, id),
    CONSTRAINT watch_run_targets_region_bound CHECK (
        length(region_class) BETWEEN 1 AND 64
        AND region_class ~ '^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$'
    ),
    CONSTRAINT watch_run_targets_state_closed CHECK (
        state IN ('pending', 'satisfied', 'queued', 'completed', 'failed', 'cancelled')
    ),
    CONSTRAINT watch_run_targets_byte_bound CHECK (
        reserved_bytes BETWEEN 0 AND 67108864
    ),
    CONSTRAINT watch_run_targets_state_relation CHECK (
        (
            state = 'pending'
            AND probe_job_id IS NULL
            AND observation_id IS NULL
            AND completed_at IS NULL
        )
        OR (
            state = 'satisfied'
            AND probe_job_id IS NULL
            AND observation_id IS NOT NULL
            AND completed_at IS NOT NULL
        )
        OR (
            state = 'queued'
            AND probe_job_id IS NOT NULL
            AND observation_id IS NULL
            AND completed_at IS NULL
        )
        OR (
            state = 'completed'
            AND probe_job_id IS NOT NULL
            AND observation_id IS NOT NULL
            AND completed_at IS NOT NULL
        )
        OR (
            state IN ('failed', 'cancelled')
            AND observation_id IS NULL
            AND completed_at IS NOT NULL
        )
    )
);

ALTER TABLE probe_job_consumers
    ADD COLUMN watch_run_target_id uuid,
    DROP CONSTRAINT probe_consumers_one_owner,
    ADD FOREIGN KEY (tenant_id, watch_run_target_id)
        REFERENCES watch_run_targets(tenant_id, id),
    ADD CONSTRAINT probe_consumers_one_owner CHECK (
        (
            search_target_id IS NOT NULL
            AND watch_target_id IS NULL
            AND watch_run_target_id IS NULL
        )
        OR (
            search_target_id IS NULL
            AND watch_target_id IS NOT NULL
            AND watch_run_target_id IS NOT NULL
        )
    );

CREATE UNIQUE INDEX probe_consumers_watch_run_target_unique
ON probe_job_consumers (tenant_id, watch_run_target_id)
WHERE watch_run_target_id IS NOT NULL;

CREATE INDEX watch_runs_active
ON watch_runs (tenant_id, watch_id, scheduled_for)
WHERE state IN ('planned', 'running');

CREATE INDEX watch_run_targets_pending
ON watch_run_targets (region_class, created_at, id)
WHERE state = 'pending';

ALTER TABLE watch_notification_endpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE watch_notification_endpoints FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON watch_notification_endpoints
    USING (tenant_id = socialname_current_tenant_id())
    WITH CHECK (tenant_id = socialname_current_tenant_id());

ALTER TABLE watch_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE watch_runs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON watch_runs
    USING (tenant_id = socialname_current_tenant_id())
    WITH CHECK (tenant_id = socialname_current_tenant_id());

ALTER TABLE watch_run_targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE watch_run_targets FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON watch_run_targets
    USING (tenant_id = socialname_current_tenant_id())
    WITH CHECK (tenant_id = socialname_current_tenant_id());

CREATE FUNCTION socialname_worker_lock_due_watch(
    p_rule_version_id uuid,
    p_region_class text
)
RETURNS TABLE (tenant_id uuid, watch_id uuid)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
    IF p_rule_version_id IS NULL
       OR p_region_class IS NULL
       OR p_region_class !~ '^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$'
       OR length(p_region_class) > 64 THEN
        RAISE EXCEPTION 'managed watch scheduler parameters are invalid'
            USING ERRCODE = '22023';
    END IF;

    RETURN QUERY
    SELECT watch.tenant_id, watch.id
    FROM public.watches AS watch
    JOIN public.consent_grants AS consent
      ON consent.tenant_id = watch.tenant_id
     AND consent.id = watch.consent_grant_id
    JOIN public.rule_versions AS version
      ON version.id = p_rule_version_id
    JOIN public.rule_packs AS pack
      ON pack.id = version.rule_pack_id
    JOIN public.sites AS site
      ON site.id = version.site_id
    WHERE watch.state = 'active'
      AND watch.next_run_at <= clock_timestamp()
      AND p_region_class = ANY(watch.region_classes)
      AND consent.subject_kind = 'account'
      AND consent.purpose = 'private_history'
      AND consent.granted_at <= clock_timestamp()
      AND consent.withdrawn_at IS NULL
      AND (consent.expires_at IS NULL OR consent.expires_at > clock_timestamp())
      AND version.enabled
      AND pack.state = 'active'
      AND pack.published_at IS NOT NULL
      AND (pack.expires_at IS NULL OR pack.expires_at > clock_timestamp())
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
      AND EXISTS (
          SELECT 1
          FROM public.watch_targets AS target
          WHERE target.tenant_id = watch.tenant_id
            AND target.watch_id = watch.id
            AND target.site_id = version.site_id
            AND target.retired_at IS NULL
      )
      AND EXISTS (
          SELECT 1
          FROM public.watch_notification_endpoints AS link
          JOIN public.notification_endpoints AS endpoint
            ON endpoint.tenant_id = link.tenant_id
           AND endpoint.id = link.endpoint_id
          WHERE link.tenant_id = watch.tenant_id
            AND link.watch_id = watch.id
            AND endpoint.state = 'active'
      )
    ORDER BY watch.next_run_at, watch.id
    LIMIT 1
    FOR UPDATE OF watch SKIP LOCKED;
END
$$;

REVOKE ALL ON FUNCTION socialname_worker_lock_due_watch(uuid, text)
FROM PUBLIC;

CREATE FUNCTION socialname_worker_lock_next_watch_target(
    p_rule_version_id uuid,
    p_region_class text
)
RETURNS TABLE (tenant_id uuid, watch_run_target_id uuid)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
    IF p_rule_version_id IS NULL
       OR p_region_class IS NULL
       OR p_region_class !~ '^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$'
       OR length(p_region_class) > 64 THEN
        RAISE EXCEPTION 'managed watch expansion parameters are invalid'
            USING ERRCODE = '22023';
    END IF;

    RETURN QUERY
    SELECT run_target.tenant_id, run_target.id
    FROM public.watch_run_targets AS run_target
    JOIN public.watch_runs AS run
      ON run.tenant_id = run_target.tenant_id
     AND run.id = run_target.watch_run_id
    JOIN public.watches AS watch
      ON watch.tenant_id = run.tenant_id
     AND watch.id = run.watch_id
    JOIN public.watch_targets AS target
      ON target.tenant_id = run_target.tenant_id
     AND target.id = run_target.watch_target_id
    JOIN public.consent_grants AS consent
      ON consent.tenant_id = watch.tenant_id
     AND consent.id = watch.consent_grant_id
    JOIN public.rule_versions AS version
      ON version.id = p_rule_version_id
     AND version.site_id = target.site_id
    JOIN public.rule_packs AS pack
      ON pack.id = version.rule_pack_id
    JOIN public.sites AS site
      ON site.id = version.site_id
    WHERE run_target.state = 'pending'
      AND run_target.region_class = p_region_class
      AND run.state IN ('planned', 'running')
      AND watch.state = 'active'
      AND watch.revision = run.watch_revision
      AND target.retired_at IS NULL
      AND consent.subject_kind = 'account'
      AND consent.purpose = 'private_history'
      AND consent.granted_at <= clock_timestamp()
      AND consent.withdrawn_at IS NULL
      AND (consent.expires_at IS NULL OR consent.expires_at > clock_timestamp())
      AND version.enabled
      AND pack.state = 'active'
      AND pack.published_at IS NOT NULL
      AND (pack.expires_at IS NULL OR pack.expires_at > clock_timestamp())
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
      AND EXISTS (
          SELECT 1
          FROM public.watch_notification_endpoints AS link
          JOIN public.notification_endpoints AS endpoint
            ON endpoint.tenant_id = link.tenant_id
           AND endpoint.id = link.endpoint_id
          WHERE link.tenant_id = watch.tenant_id
            AND link.watch_id = watch.id
            AND endpoint.state = 'active'
      )
      AND NOT EXISTS (
          SELECT 1
          FROM public.probe_job_consumers AS consumer
          WHERE consumer.tenant_id = run_target.tenant_id
            AND consumer.watch_run_target_id = run_target.id
      )
    ORDER BY run.scheduled_for, target.ordinal, run_target.region_class, run_target.id
    LIMIT 1
    FOR UPDATE OF run_target, run, watch, target SKIP LOCKED;
END
$$;

REVOKE ALL ON FUNCTION socialname_worker_lock_next_watch_target(uuid, text)
FROM PUBLIC;

CREATE OR REPLACE FUNCTION socialname_worker_claim_job(
    p_rule_version_id uuid,
    p_region_class text,
    p_lease_owner text,
    p_lease_ms integer
)
RETURNS TABLE (tenant_id uuid, probe_job_id uuid, attempt_count integer)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
    IF p_rule_version_id IS NULL
       OR p_region_class IS NULL
       OR p_lease_owner IS NULL
       OR p_lease_ms IS NULL
       OR p_region_class !~ '^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$'
       OR length(p_region_class) > 64
       OR p_lease_owner !~ '^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$'
       OR length(p_lease_owner) > 64
       OR p_lease_ms NOT BETWEEN 5000 AND 300000 THEN
        RAISE EXCEPTION 'managed worker claim parameters are invalid'
            USING ERRCODE = '22023';
    END IF;

    UPDATE public.watch_run_targets AS run_target
    SET state = 'cancelled',
        completed_at = clock_timestamp()
    FROM public.probe_job_consumers AS consumer,
         public.watch_runs AS run,
         public.watches AS watch,
         public.probe_jobs AS job
    WHERE consumer.tenant_id = run_target.tenant_id
      AND consumer.watch_run_target_id = run_target.id
      AND run.tenant_id = run_target.tenant_id
      AND run.id = run_target.watch_run_id
      AND watch.tenant_id = run.tenant_id
      AND watch.id = run.watch_id
      AND job.tenant_id = consumer.tenant_id
      AND job.id = consumer.probe_job_id
      AND run_target.state = 'queued'
      AND (
          run.state NOT IN ('planned', 'running')
          OR watch.state <> 'active'
          OR watch.revision <> run.watch_revision
          OR NOT EXISTS (
              SELECT 1
              FROM public.consent_grants AS consent
              WHERE consent.tenant_id = watch.tenant_id
                AND consent.id = watch.consent_grant_id
                AND consent.id = job.consent_grant_id
                AND consent.subject_kind = 'account'
                AND consent.purpose = 'private_history'
                AND consent.granted_at <= clock_timestamp()
                AND consent.withdrawn_at IS NULL
                AND (
                    consent.expires_at IS NULL
                    OR consent.expires_at > clock_timestamp()
                )
          )
          OR NOT EXISTS (
              SELECT 1
              FROM public.watch_notification_endpoints AS link
              JOIN public.notification_endpoints AS endpoint
                ON endpoint.tenant_id = link.tenant_id
               AND endpoint.id = link.endpoint_id
              WHERE link.tenant_id = watch.tenant_id
                AND link.watch_id = watch.id
                AND endpoint.state = 'active'
          )
      );

    UPDATE public.watch_runs AS run
    SET state = CASE
            WHEN EXISTS (
                SELECT 1
                FROM public.watch_run_targets AS target
                WHERE target.tenant_id = run.tenant_id
                  AND target.watch_run_id = run.id
                  AND target.state = 'failed'
            ) THEN 'failed'
            WHEN EXISTS (
                SELECT 1
                FROM public.watch_run_targets AS target
                WHERE target.tenant_id = run.tenant_id
                  AND target.watch_run_id = run.id
                  AND target.state = 'cancelled'
            ) THEN 'cancelled'
            ELSE 'completed'
        END,
        completed_at = clock_timestamp()
    WHERE run.state IN ('planned', 'running')
      AND NOT EXISTS (
          SELECT 1
          FROM public.watch_run_targets AS target
          WHERE target.tenant_id = run.tenant_id
            AND target.watch_run_id = run.id
            AND target.state IN ('pending', 'queued')
      );

    UPDATE public.probe_jobs AS orphan
    SET state = 'cancelled',
        lease_owner = NULL,
        lease_expires_at = NULL,
        last_error_code = 'authorization_cancelled',
        updated_at = clock_timestamp(),
        completed_at = clock_timestamp()
    WHERE orphan.rule_version_id = p_rule_version_id
      AND orphan.region_class = p_region_class
      AND orphan.state IN ('queued', 'leased', 'retry_wait')
      AND (
          NOT (
              EXISTS (
                  SELECT 1
                  FROM public.probe_job_consumers AS consumer
                  JOIN public.search_targets AS target
                    ON target.tenant_id = consumer.tenant_id
                   AND target.id = consumer.search_target_id
                  JOIN public.searches AS search
                    ON search.tenant_id = target.tenant_id
                   AND search.id = target.search_id
                  WHERE consumer.tenant_id = orphan.tenant_id
                    AND consumer.probe_job_id = orphan.id
                    AND target.state IN ('pending', 'running')
                    AND search.state IN ('accepted', 'running')
              )
              OR EXISTS (
                  SELECT 1
                  FROM public.probe_job_consumers AS consumer
                  JOIN public.watch_run_targets AS run_target
                    ON run_target.tenant_id = consumer.tenant_id
                   AND run_target.id = consumer.watch_run_target_id
                  JOIN public.watch_runs AS run
                    ON run.tenant_id = run_target.tenant_id
                   AND run.id = run_target.watch_run_id
                  JOIN public.watches AS watch
                    ON watch.tenant_id = run.tenant_id
                   AND watch.id = run.watch_id
                  WHERE consumer.tenant_id = orphan.tenant_id
                    AND consumer.probe_job_id = orphan.id
                    AND run_target.state = 'queued'
                    AND run_target.probe_job_id = orphan.id
                    AND run.state IN ('planned', 'running')
                    AND watch.state = 'active'
                    AND watch.revision = run.watch_revision
                    AND watch.consent_grant_id = orphan.consent_grant_id
                    AND orphan.visibility = 'private'
                    AND EXISTS (
                        SELECT 1
                        FROM public.watch_notification_endpoints AS link
                        JOIN public.notification_endpoints AS endpoint
                          ON endpoint.tenant_id = link.tenant_id
                         AND endpoint.id = link.endpoint_id
                        WHERE link.tenant_id = watch.tenant_id
                          AND link.watch_id = watch.id
                          AND endpoint.state = 'active'
                    )
              )
          )
          OR NOT EXISTS (
              SELECT 1
              FROM public.consent_grants AS consent
              WHERE consent.tenant_id = orphan.tenant_id
                AND consent.id = orphan.consent_grant_id
                AND consent.subject_kind = 'account'
                AND consent.granted_at <= clock_timestamp()
                AND consent.withdrawn_at IS NULL
                AND (
                    consent.expires_at IS NULL
                    OR consent.expires_at > clock_timestamp()
                )
                AND (
                    (orphan.visibility = 'private'
                     AND consent.purpose = 'private_history')
                    OR
                    (orphan.visibility = 'shared'
                     AND consent.purpose = 'shared_observation')
                )
          )
      );

    RETURN QUERY
    WITH candidate AS (
        SELECT job.id
        FROM public.probe_jobs AS job
        JOIN public.rule_versions AS version
          ON version.id = job.rule_version_id
        JOIN public.rule_packs AS pack
          ON pack.id = version.rule_pack_id
        JOIN public.sites AS site
          ON site.id = version.site_id
        JOIN public.consent_grants AS consent
          ON consent.tenant_id = job.tenant_id
         AND consent.id = job.consent_grant_id
        WHERE job.rule_version_id = p_rule_version_id
          AND job.region_class = p_region_class
          AND (
              (
                  job.state IN ('queued', 'retry_wait')
                  AND job.available_at <= clock_timestamp()
              )
              OR (
                  job.state = 'leased'
                  AND job.lease_expires_at <= clock_timestamp()
              )
          )
          AND version.enabled
          AND pack.state = 'active'
          AND pack.published_at IS NOT NULL
          AND (pack.expires_at IS NULL OR pack.expires_at > clock_timestamp())
          AND site.state = 'promoted'
          AND consent.subject_kind = 'account'
          AND consent.granted_at <= clock_timestamp()
          AND consent.withdrawn_at IS NULL
          AND (
              consent.expires_at IS NULL
              OR consent.expires_at > clock_timestamp()
          )
          AND (
              (job.visibility = 'private' AND consent.purpose = 'private_history')
              OR
              (job.visibility = 'shared' AND consent.purpose = 'shared_observation')
          )
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
          AND (
              EXISTS (
                  SELECT 1
                  FROM public.probe_job_consumers AS consumer
                  JOIN public.search_targets AS target
                    ON target.tenant_id = consumer.tenant_id
                   AND target.id = consumer.search_target_id
                  JOIN public.searches AS search
                    ON search.tenant_id = target.tenant_id
                   AND search.id = target.search_id
                  WHERE consumer.tenant_id = job.tenant_id
                    AND consumer.probe_job_id = job.id
                    AND target.state IN ('pending', 'running')
                    AND search.state IN ('accepted', 'running')
              )
              OR EXISTS (
                  SELECT 1
                  FROM public.probe_job_consumers AS consumer
                  JOIN public.watch_run_targets AS run_target
                    ON run_target.tenant_id = consumer.tenant_id
                   AND run_target.id = consumer.watch_run_target_id
                  JOIN public.watch_runs AS run
                    ON run.tenant_id = run_target.tenant_id
                   AND run.id = run_target.watch_run_id
                  JOIN public.watches AS watch
                    ON watch.tenant_id = run.tenant_id
                   AND watch.id = run.watch_id
                  WHERE consumer.tenant_id = job.tenant_id
                    AND consumer.probe_job_id = job.id
                    AND run_target.state = 'queued'
                    AND run_target.probe_job_id = job.id
                    AND run.state IN ('planned', 'running')
                    AND watch.state = 'active'
                    AND watch.revision = run.watch_revision
                    AND watch.consent_grant_id = job.consent_grant_id
                    AND job.visibility = 'private'
                    AND EXISTS (
                        SELECT 1
                        FROM public.watch_notification_endpoints AS link
                        JOIN public.notification_endpoints AS endpoint
                          ON endpoint.tenant_id = link.tenant_id
                         AND endpoint.id = link.endpoint_id
                        WHERE link.tenant_id = watch.tenant_id
                          AND link.watch_id = watch.id
                          AND endpoint.state = 'active'
                    )
              )
          )
        ORDER BY job.priority DESC, job.available_at, job.created_at, job.id
        LIMIT 1
        FOR UPDATE OF job SKIP LOCKED
    )
    UPDATE public.probe_jobs AS job
    SET state = 'leased',
        attempt_count = job.attempt_count + 1,
        lease_owner = p_lease_owner,
        lease_expires_at = clock_timestamp()
            + (p_lease_ms::text || ' milliseconds')::interval,
        updated_at = clock_timestamp(),
        completed_at = NULL
    FROM candidate
    WHERE job.id = candidate.id
    RETURNING job.tenant_id, job.id, job.attempt_count;
END
$$;
