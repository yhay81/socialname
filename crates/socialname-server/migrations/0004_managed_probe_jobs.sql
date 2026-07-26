ALTER TABLE probe_jobs
    ADD COLUMN consent_grant_id uuid,
    ADD COLUMN visibility text;

UPDATE probe_jobs AS job
SET consent_grant_id = observation.consent_grant_id,
    visibility = observation.visibility
FROM observations AS observation
WHERE observation.tenant_id = job.tenant_id
  AND observation.probe_job_id = job.id
  AND job.consent_grant_id IS NULL;

UPDATE probe_jobs AS job
SET consent_grant_id = search.consent_grant_id,
    visibility = CASE search.sync_policy
        WHEN 'private' THEN 'private'
        WHEN 'shared' THEN 'shared'
        ELSE NULL
    END
FROM probe_job_consumers AS consumer
JOIN search_targets AS target
  ON target.tenant_id = consumer.tenant_id
 AND target.id = consumer.search_target_id
JOIN searches AS search
  ON search.tenant_id = target.tenant_id
 AND search.id = target.search_id
WHERE consumer.tenant_id = job.tenant_id
  AND consumer.probe_job_id = job.id
  AND job.consent_grant_id IS NULL
  AND search.consent_grant_id IS NOT NULL
  AND search.sync_policy IN ('private', 'shared');

UPDATE probe_jobs
SET state = 'cancelled',
    lease_owner = NULL,
    lease_expires_at = NULL,
    last_error_code = 'migration_missing_consent',
    updated_at = clock_timestamp(),
    completed_at = clock_timestamp()
WHERE state IN ('queued', 'leased', 'retry_wait')
  AND consent_grant_id IS NULL;

ALTER TABLE probe_jobs
    ADD FOREIGN KEY (tenant_id, consent_grant_id)
        REFERENCES consent_grants(tenant_id, id),
    ADD CONSTRAINT probe_jobs_visibility_closed CHECK (
        visibility IS NULL OR visibility IN ('private', 'shared')
    ),
    ADD CONSTRAINT probe_jobs_consent_relation CHECK (
        (
            consent_grant_id IS NOT NULL
            AND visibility IN ('private', 'shared')
        )
        OR (
            consent_grant_id IS NULL
            AND visibility IS NULL
            AND state IN ('succeeded', 'failed', 'cancelled')
        )
    ),
    ADD CONSTRAINT probe_jobs_attempt_bound CHECK (
        attempt_count BETWEEN 0 AND 1000
    ),
    ADD CONSTRAINT probe_jobs_lease_owner_bound CHECK (
        lease_owner IS NULL
        OR (
            length(lease_owner) BETWEEN 1 AND 64
            AND lease_owner ~ '^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$'
        )
    ),
    ADD CONSTRAINT probe_jobs_error_code_bound CHECK (
        last_error_code IS NULL
        OR (
            length(last_error_code) BETWEEN 1 AND 64
            AND last_error_code ~ '^[a-z0-9]+(?:_[a-z0-9]+)*$'
        )
    );

ALTER TABLE probe_jobs
    DROP CONSTRAINT probe_jobs_lease_relation,
    ADD CONSTRAINT probe_jobs_lease_relation CHECK (
        (
            state = 'leased'
            AND lease_owner IS NOT NULL
            AND lease_expires_at IS NOT NULL
            AND lease_expires_at > updated_at
        )
        OR (
            state <> 'leased'
            AND lease_owner IS NULL
            AND lease_expires_at IS NULL
        )
    );

CREATE UNIQUE INDEX probe_jobs_one_active_scope
ON probe_jobs (
    tenant_id,
    normalized_username,
    site_id,
    rule_version_id,
    region_class,
    consent_grant_id,
    visibility
)
WHERE state IN ('queued', 'leased', 'retry_wait');

CREATE UNIQUE INDEX probe_consumers_search_target_unique
ON probe_job_consumers (tenant_id, search_target_id)
WHERE search_target_id IS NOT NULL;

CREATE INDEX probe_jobs_expired_lease
ON probe_jobs (lease_expires_at, priority DESC, created_at)
WHERE state = 'leased';

CREATE FUNCTION socialname_worker_resolve_rule(
    p_site_id text,
    p_rule_hash bytea,
    p_pack_hash bytea,
    p_region_class text
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
    WHERE version.site_id = p_site_id
      AND version.rule_hash = p_rule_hash
      AND pack.pack_hash = p_pack_hash
      AND octet_length(p_rule_hash) = 32
      AND octet_length(p_pack_hash) = 32
      AND p_region_class ~ '^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$'
      AND length(p_region_class) <= 64
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
    LIMIT 1
$$;

REVOKE ALL ON FUNCTION socialname_worker_resolve_rule(text, bytea, bytea, text)
FROM PUBLIC;

CREATE FUNCTION socialname_worker_lock_next_target(
    p_rule_version_id uuid,
    p_region_class text
)
RETURNS TABLE (tenant_id uuid, search_target_id uuid)
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
        RAISE EXCEPTION 'managed worker region is invalid'
            USING ERRCODE = '22023';
    END IF;

    RETURN QUERY
    SELECT target.tenant_id, target.id
    FROM public.search_targets AS target
    JOIN public.searches AS search
      ON search.tenant_id = target.tenant_id
     AND search.id = target.search_id
    JOIN public.consent_grants AS consent
      ON consent.tenant_id = search.tenant_id
     AND consent.id = search.consent_grant_id
    JOIN public.rule_versions AS version
      ON version.id = p_rule_version_id
     AND version.site_id = target.site_id
    JOIN public.rule_packs AS pack
      ON pack.id = version.rule_pack_id
    JOIN public.sites AS site
      ON site.id = version.site_id
    WHERE target.state = 'pending'
      AND search.state IN ('accepted', 'running')
      AND search.mode IN ('remote', 'hybrid')
      AND search.sync_policy IN ('private', 'shared')
      AND p_region_class = ANY(search.region_classes)
      AND consent.subject_kind = 'account'
      AND consent.granted_at <= clock_timestamp()
      AND consent.withdrawn_at IS NULL
      AND (consent.expires_at IS NULL OR consent.expires_at > clock_timestamp())
      AND (
          (search.sync_policy = 'private' AND consent.purpose = 'private_history')
          OR
          (search.sync_policy = 'shared' AND consent.purpose = 'shared_observation')
      )
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
      AND NOT EXISTS (
          SELECT 1
          FROM public.probe_job_consumers AS consumer
          WHERE consumer.tenant_id = target.tenant_id
            AND consumer.search_target_id = target.id
      )
    ORDER BY search.created_at, target.ordinal, target.id
    LIMIT 1
    FOR UPDATE OF search, target SKIP LOCKED;
END
$$;

REVOKE ALL ON FUNCTION socialname_worker_lock_next_target(uuid, text)
FROM PUBLIC;

CREATE FUNCTION socialname_worker_claim_job(
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
          NOT EXISTS (
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
          AND EXISTS (
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

REVOKE ALL ON FUNCTION socialname_worker_claim_job(uuid, text, text, integer)
FROM PUBLIC;

CREATE FUNCTION socialname_worker_lock_claim_consent(
    p_probe_job_id uuid,
    p_attempt_count integer,
    p_lease_owner text
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    active boolean;
BEGIN
    IF p_probe_job_id IS NULL
       OR p_attempt_count IS NULL
       OR p_attempt_count NOT BETWEEN 1 AND 1000
       OR p_lease_owner IS NULL
       OR p_lease_owner !~ '^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$'
       OR length(p_lease_owner) > 64 THEN
        RAISE EXCEPTION 'managed worker consent-lock parameters are invalid'
            USING ERRCODE = '22023';
    END IF;

    SELECT true
    INTO active
    FROM public.probe_jobs AS job
    JOIN public.consent_grants AS consent
      ON consent.tenant_id = job.tenant_id
     AND consent.id = job.consent_grant_id
    WHERE job.id = p_probe_job_id
      AND job.state = 'leased'
      AND job.attempt_count = p_attempt_count
      AND job.lease_owner = p_lease_owner
      AND job.lease_expires_at > clock_timestamp()
      AND consent.subject_kind = 'account'
      AND consent.granted_at <= clock_timestamp()
      AND consent.withdrawn_at IS NULL
      AND (consent.expires_at IS NULL OR consent.expires_at > clock_timestamp())
      AND (
          (job.visibility = 'private' AND consent.purpose = 'private_history')
          OR
          (job.visibility = 'shared' AND consent.purpose = 'shared_observation')
      )
    FOR KEY SHARE OF consent;

    RETURN COALESCE(active, false);
END
$$;

REVOKE ALL ON FUNCTION socialname_worker_lock_claim_consent(uuid, integer, text)
FROM PUBLIC;
