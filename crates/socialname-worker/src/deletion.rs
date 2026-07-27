use std::{fmt, time::Duration};

use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::{
    derivation::{DerivationKey, recompute_assertion},
    job::{JobError, connect_worker_pool_from_env, set_tenant},
};

const MINIMUM_LEASE_SECONDS: u64 = 5;
const MAXIMUM_LEASE_SECONDS: u64 = 300;

#[derive(Clone)]
pub struct DeletionStore {
    pool: PgPool,
}

impl fmt::Debug for DeletionStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeletionStore([REDACTED DATABASE])")
    }
}

impl DeletionStore {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn connect_from_env() -> Result<Self, DeletionError> {
        Ok(Self::new(connect_worker_pool_from_env().await?))
    }

    pub async fn close(&self) {
        self.pool.close().await;
    }

    pub async fn process_one(
        &self,
        worker_id: &str,
        lease: Duration,
    ) -> Result<DeletionProcessOutcome, DeletionError> {
        validate_worker_id(worker_id)?;
        if lease.subsec_nanos() != 0
            || !(MINIMUM_LEASE_SECONDS..=MAXIMUM_LEASE_SECONDS).contains(&lease.as_secs())
        {
            return Err(DeletionError::InvalidConfiguration);
        }
        let lease_seconds =
            i32::try_from(lease.as_secs()).map_err(|_| DeletionError::InvalidConfiguration)?;
        let claimed: Option<ClaimedDeletion> = sqlx::query_as(
            "SELECT tenant_id, deletion_request_id, processing_attempt \
             FROM socialname_worker_claim_deletion($1, $2)",
        )
        .bind(worker_id)
        .bind(lease_seconds)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| DeletionError::DatabaseUnavailable)?;
        let Some(claimed) = claimed else {
            return Ok(DeletionProcessOutcome::Idle);
        };
        self.process_claim(worker_id, claimed).await
    }

    async fn process_claim(
        &self,
        worker_id: &str,
        claimed: ClaimedDeletion,
    ) -> Result<DeletionProcessOutcome, DeletionError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| DeletionError::DatabaseUnavailable)?;
        set_tenant(&mut transaction, claimed.tenant_id).await?;
        let locked: LockedDeletion = sqlx::query_as(
            "SELECT request.state, request.processing_attempt, request.lease_owner, \
                    request.lease_expires_at > clock_timestamp() AS lease_is_current \
             FROM deletion_requests AS request \
             WHERE request.tenant_id = $1 AND request.id = $2 \
             FOR UPDATE",
        )
        .bind(claimed.tenant_id)
        .bind(claimed.deletion_request_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| DeletionError::StorageInvariant)?;
        if !matches!(locked.state.as_str(), "withdrawing_support" | "deleting")
            || locked.processing_attempt != claimed.processing_attempt
            || locked.lease_owner.as_deref() != Some(worker_id)
            || !locked.lease_is_current
        {
            return Err(DeletionError::StaleLease);
        }

        let derivation_keys: Vec<OwnedDerivationKey> = sqlx::query_as(
            "SELECT DISTINCT observation.normalized_username, \
                    observation.site_id, observation.rule_version_id, \
                    encode(version.rule_hash, 'hex') AS rule_hash \
             FROM deletion_resource_matches AS matched \
             JOIN observations AS observation \
               ON observation.tenant_id = matched.tenant_id \
              AND observation.id = matched.resource_id \
             JOIN rule_versions AS version ON version.id = observation.rule_version_id \
             WHERE matched.tenant_id = $1 \
               AND matched.deletion_request_id = $2 \
               AND matched.resource_kind = 'observation' \
             ORDER BY observation.normalized_username, observation.site_id, \
                      observation.rule_version_id",
        )
        .bind(claimed.tenant_id)
        .bind(claimed.deletion_request_id)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| DeletionError::StorageInvariant)?;

        if locked.state == "withdrawing_support" {
            sqlx::query(
                "UPDATE deletion_requests \
                 SET state = 'deleting', \
                     support_withdrawn_at = COALESCE(\
                         support_withdrawn_at, clock_timestamp()\
                     ) \
                 WHERE tenant_id = $1 AND id = $2",
            )
            .bind(claimed.tenant_id)
            .bind(claimed.deletion_request_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| DeletionError::StorageInvariant)?;
        }
        sqlx::query(
            "UPDATE deletion_resource_matches \
             SET support_withdrawn_at = COALESCE(\
                 support_withdrawn_at, clock_timestamp()\
             ) \
             WHERE tenant_id = $1 AND deletion_request_id = $2",
        )
        .bind(claimed.tenant_id)
        .bind(claimed.deletion_request_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| DeletionError::StorageInvariant)?;

        delete_support_relations(
            &mut transaction,
            claimed.tenant_id,
            claimed.deletion_request_id,
        )
        .await?;
        sqlx::query(
            "UPDATE assertions AS assertion \
             SET is_current = false, withdrawn_at = clock_timestamp() \
             WHERE assertion.tenant_id = $1 \
               AND assertion.is_current AND assertion.withdrawn_at IS NULL \
               AND EXISTS (\
                   SELECT 1 FROM deletion_resource_matches AS matched \
                   WHERE matched.tenant_id = assertion.tenant_id \
                     AND matched.deletion_request_id = $2 \
                     AND matched.resource_kind = 'assertion' \
                     AND matched.resource_id = assertion.id\
               )",
        )
        .bind(claimed.tenant_id)
        .bind(claimed.deletion_request_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| DeletionError::StorageInvariant)?;
        sqlx::query(
            "UPDATE watch_targets AS target \
             SET account_state = NULL, account_assertion_id = NULL, \
                 account_state_since = NULL \
             WHERE target.tenant_id = $1 \
               AND target.account_assertion_id IS NOT NULL \
               AND (\
                   EXISTS (\
                       SELECT 1 FROM deletion_resource_matches AS matched \
                       WHERE matched.tenant_id = target.tenant_id \
                         AND matched.deletion_request_id = $2 \
                         AND matched.resource_kind = 'assertion' \
                         AND matched.resource_id = target.account_assertion_id\
                   ) \
                   OR EXISTS (\
                       SELECT 1 FROM assertions AS assertion \
                       WHERE assertion.tenant_id = target.tenant_id \
                         AND assertion.id = target.account_assertion_id \
                         AND assertion.withdrawn_at IS NOT NULL\
                   )\
               )",
        )
        .bind(claimed.tenant_id)
        .bind(claimed.deletion_request_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| DeletionError::StorageInvariant)?;

        let recomputed_at_unix_ms: i64 =
            sqlx::query_scalar("SELECT (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::bigint")
                .fetch_one(&mut *transaction)
                .await
                .map_err(|_| DeletionError::DatabaseUnavailable)?;
        for key in &derivation_keys {
            recompute_assertion(
                &mut transaction,
                &DerivationKey {
                    tenant_id: claimed.tenant_id,
                    normalized_username: &key.normalized_username,
                    site_id: &key.site_id,
                    rule_version_id: key.rule_version_id,
                    rule_hash: &key.rule_hash,
                },
                recomputed_at_unix_ms,
            )
            .await?;
        }

        delete_primary_resources(
            &mut transaction,
            claimed.tenant_id,
            claimed.deletion_request_id,
        )
        .await?;
        let matched_resources: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM deletion_resource_matches \
             WHERE tenant_id = $1 AND deletion_request_id = $2",
        )
        .bind(claimed.tenant_id)
        .bind(claimed.deletion_request_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| DeletionError::StorageInvariant)?;
        sqlx::query(
            "UPDATE deletion_resource_matches \
             SET primary_deleted_at = COALESCE(\
                 primary_deleted_at, clock_timestamp()\
             ) \
             WHERE tenant_id = $1 AND deletion_request_id = $2",
        )
        .bind(claimed.tenant_id)
        .bind(claimed.deletion_request_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| DeletionError::StorageInvariant)?;
        sqlx::query(
            "UPDATE deletion_tasks \
             SET state = 'completed', attempt_count = attempt_count + 1, \
                 completed_at = clock_timestamp(), last_error_code = NULL \
             WHERE tenant_id = $1 AND deletion_request_id = $2 \
               AND store_kind IN ('primary', 'analytics') \
               AND state <> 'completed'",
        )
        .bind(claimed.tenant_id)
        .bind(claimed.deletion_request_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| DeletionError::StorageInvariant)?;
        sqlx::query(
            "UPDATE deletion_requests \
             SET state = 'rebuilding', primary_completed_at = (\
                    SELECT completed_at FROM deletion_tasks \
                    WHERE tenant_id = $1 AND deletion_request_id = $2 \
                      AND store_kind = 'primary'\
                 ), \
                 lease_owner = NULL, lease_expires_at = NULL, last_error_code = NULL \
             WHERE tenant_id = $1 AND id = $2 AND state = 'deleting'",
        )
        .bind(claimed.tenant_id)
        .bind(claimed.deletion_request_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| DeletionError::StorageInvariant)?;
        sqlx::query(
            "INSERT INTO audit_events (\
                id, tenant_id, action, resource_kind, resource_id, \
                occurred_at, details\
             ) VALUES (\
                $1, $2, 'deletion.primary_and_derived.completed', \
                'deletion_request', $3, \
                clock_timestamp(), jsonb_build_object(\
                    'processing_attempt', $4::integer, \
                    'matched_resources', $5::bigint\
                )\
             )",
        )
        .bind(Uuid::new_v4())
        .bind(claimed.tenant_id)
        .bind(claimed.deletion_request_id)
        .bind(claimed.processing_attempt)
        .bind(matched_resources)
        .execute(&mut *transaction)
        .await
        .map_err(|_| DeletionError::StorageInvariant)?;
        transaction
            .commit()
            .await
            .map_err(|_| DeletionError::DatabaseUnavailable)?;
        Ok(DeletionProcessOutcome::Processed {
            deletion_request_id: claimed.deletion_request_id,
            processing_attempt: u32::try_from(claimed.processing_attempt)
                .map_err(|_| DeletionError::StorageInvariant)?,
            matched_resources: u32::try_from(matched_resources)
                .map_err(|_| DeletionError::StorageInvariant)?,
            recomputed_targets: u32::try_from(derivation_keys.len())
                .map_err(|_| DeletionError::StorageInvariant)?,
        })
    }
}

async fn delete_support_relations(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
    deletion_request_id: Uuid,
) -> Result<(), DeletionError> {
    for statement in [
        "DELETE FROM transition_basis AS basis \
         WHERE basis.tenant_id = $1 AND (\
             EXISTS (\
                 SELECT 1 FROM deletion_resource_matches AS matched \
                 WHERE matched.tenant_id = basis.tenant_id \
                   AND matched.deletion_request_id = $2 \
                   AND matched.resource_kind = 'observation' \
                   AND matched.resource_id = basis.observation_id\
             ) \
             OR EXISTS (\
                 SELECT 1 FROM deletion_resource_matches AS matched \
                 WHERE matched.tenant_id = basis.tenant_id \
                   AND matched.deletion_request_id = $2 \
                   AND matched.resource_kind = 'transition' \
                   AND matched.resource_id = basis.transition_id\
             )\
         )",
        "DELETE FROM regional_assertion_support AS support \
         WHERE support.tenant_id = $1 AND (\
             EXISTS (\
                 SELECT 1 FROM deletion_resource_matches AS matched \
                 WHERE matched.tenant_id = support.tenant_id \
                   AND matched.deletion_request_id = $2 \
                   AND matched.resource_kind = 'observation' \
                   AND matched.resource_id = support.observation_id\
             ) \
             OR EXISTS (\
                 SELECT 1 FROM deletion_resource_matches AS matched \
                 WHERE matched.tenant_id = support.tenant_id \
                   AND matched.deletion_request_id = $2 \
                   AND matched.resource_kind = 'regional_assertion' \
                   AND matched.resource_id = support.regional_assertion_id\
             )\
         )",
        "DELETE FROM assertion_support AS support \
         WHERE support.tenant_id = $1 AND (\
             EXISTS (\
                 SELECT 1 FROM deletion_resource_matches AS matched \
                 WHERE matched.tenant_id = support.tenant_id \
                   AND matched.deletion_request_id = $2 \
                   AND matched.resource_kind = 'observation' \
                   AND matched.resource_id = support.observation_id\
             ) \
             OR EXISTS (\
                 SELECT 1 FROM deletion_resource_matches AS matched \
                 WHERE matched.tenant_id = support.tenant_id \
                   AND matched.deletion_request_id = $2 \
                   AND matched.resource_kind = 'assertion' \
                   AND matched.resource_id = support.assertion_id\
             )\
         )",
    ] {
        sqlx::query(statement)
            .bind(tenant_id)
            .bind(deletion_request_id)
            .execute(&mut **transaction)
            .await
            .map_err(|_| DeletionError::StorageInvariant)?;
    }
    Ok(())
}

async fn delete_primary_resources(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
    deletion_request_id: Uuid,
) -> Result<(), DeletionError> {
    for statement in [
        "DELETE FROM notification_delivery_attempts AS attempt \
         WHERE attempt.tenant_id = $1 AND EXISTS (\
             SELECT 1 FROM deletion_resource_matches AS matched \
             WHERE matched.tenant_id = attempt.tenant_id \
               AND matched.deletion_request_id = $2 \
               AND matched.resource_kind = 'notification_delivery' \
               AND matched.resource_id = attempt.delivery_id\
         )",
        "DELETE FROM notification_deliveries AS delivery \
         WHERE delivery.tenant_id = $1 AND EXISTS (\
             SELECT 1 FROM deletion_resource_matches AS matched \
             WHERE matched.tenant_id = delivery.tenant_id \
               AND matched.deletion_request_id = $2 \
               AND matched.resource_kind = 'notification_delivery' \
               AND matched.resource_id = delivery.id\
         )",
        "DELETE FROM transition_basis AS basis \
         WHERE basis.tenant_id = $1 AND EXISTS (\
             SELECT 1 FROM deletion_resource_matches AS matched \
             WHERE matched.tenant_id = basis.tenant_id \
               AND matched.deletion_request_id = $2 \
               AND matched.resource_kind = 'transition' \
               AND matched.resource_id = basis.transition_id\
         )",
        "DELETE FROM transitions AS transition \
         WHERE transition.tenant_id = $1 AND EXISTS (\
             SELECT 1 FROM deletion_resource_matches AS matched \
             WHERE matched.tenant_id = transition.tenant_id \
               AND matched.deletion_request_id = $2 \
               AND matched.resource_kind = 'transition' \
               AND matched.resource_id = transition.id\
         )",
        "DELETE FROM regional_assertion_support AS support \
         WHERE support.tenant_id = $1 AND EXISTS (\
             SELECT 1 FROM deletion_resource_matches AS matched \
             WHERE matched.tenant_id = support.tenant_id \
               AND matched.deletion_request_id = $2 \
               AND matched.resource_kind = 'regional_assertion' \
               AND matched.resource_id = support.regional_assertion_id\
         )",
        "DELETE FROM regional_assertions AS regional \
         WHERE regional.tenant_id = $1 AND EXISTS (\
             SELECT 1 FROM deletion_resource_matches AS matched \
             WHERE matched.tenant_id = regional.tenant_id \
               AND matched.deletion_request_id = $2 \
               AND matched.resource_kind = 'regional_assertion' \
               AND matched.resource_id = regional.id\
         )",
        "DELETE FROM assertion_support AS support \
         WHERE support.tenant_id = $1 AND EXISTS (\
             SELECT 1 FROM deletion_resource_matches AS matched \
             WHERE matched.tenant_id = support.tenant_id \
               AND matched.deletion_request_id = $2 \
               AND matched.resource_kind = 'assertion' \
               AND matched.resource_id = support.assertion_id\
         )",
        "DELETE FROM assertions AS assertion \
         WHERE assertion.tenant_id = $1 AND EXISTS (\
             SELECT 1 FROM deletion_resource_matches AS matched \
             WHERE matched.tenant_id = assertion.tenant_id \
               AND matched.deletion_request_id = $2 \
               AND matched.resource_kind = 'assertion' \
               AND matched.resource_id = assertion.id\
         )",
        "DELETE FROM evidence_retention_receipts AS receipt \
         WHERE receipt.tenant_id = $1 AND (\
             EXISTS (\
                 SELECT 1 FROM deletion_resource_matches AS matched \
                 WHERE matched.tenant_id = receipt.tenant_id \
                   AND matched.deletion_request_id = $2 \
                   AND matched.resource_kind = 'evidence_capsule' \
                   AND matched.resource_id = receipt.evidence_capsule_id\
             ) \
             OR EXISTS (\
                 SELECT 1 \
                 FROM evidence_capsules AS capsule \
                 JOIN deletion_resource_matches AS matched \
                   ON matched.tenant_id = capsule.tenant_id \
                  AND matched.deletion_request_id = $2 \
                  AND matched.resource_kind = 'observation' \
                  AND matched.resource_id = capsule.observation_id \
                 WHERE capsule.tenant_id = receipt.tenant_id \
                   AND capsule.id = receipt.evidence_capsule_id\
             )\
         )",
        "DELETE FROM evidence_capsules AS capsule \
         WHERE capsule.tenant_id = $1 AND (\
             EXISTS (\
                 SELECT 1 FROM deletion_resource_matches AS matched \
                 WHERE matched.tenant_id = capsule.tenant_id \
                   AND matched.deletion_request_id = $2 \
                   AND matched.resource_kind = 'evidence_capsule' \
                   AND matched.resource_id = capsule.id\
             ) \
             OR EXISTS (\
                 SELECT 1 FROM deletion_resource_matches AS matched \
                 WHERE matched.tenant_id = capsule.tenant_id \
                   AND matched.deletion_request_id = $2 \
                   AND matched.resource_kind = 'observation' \
                   AND matched.resource_id = capsule.observation_id\
             )\
         )",
        "DELETE FROM search_events AS event \
         WHERE event.tenant_id = $1 AND EXISTS (\
             SELECT 1 FROM deletion_resource_matches AS matched \
             WHERE matched.tenant_id = event.tenant_id \
               AND matched.deletion_request_id = $2 \
               AND matched.resource_kind = 'search_event' \
               AND matched.resource_id = event.id\
         )",
        "UPDATE watch_run_targets AS target \
         SET observation_id = NULL, observation_deleted_at = clock_timestamp() \
         WHERE target.tenant_id = $1 AND target.observation_id IS NOT NULL \
           AND EXISTS (\
               SELECT 1 FROM deletion_resource_matches AS matched \
               WHERE matched.tenant_id = target.tenant_id \
                 AND matched.deletion_request_id = $2 \
                 AND matched.resource_kind = 'observation' \
                 AND matched.resource_id = target.observation_id\
           )",
        "DELETE FROM observations AS observation \
         WHERE observation.tenant_id = $1 AND EXISTS (\
             SELECT 1 FROM deletion_resource_matches AS matched \
             WHERE matched.tenant_id = observation.tenant_id \
               AND matched.deletion_request_id = $2 \
               AND matched.resource_kind = 'observation' \
               AND matched.resource_id = observation.id\
         )",
        "DELETE FROM shared_contributions AS contribution \
         WHERE contribution.tenant_id = $1 AND EXISTS (\
             SELECT 1 FROM deletion_resource_matches AS matched \
             WHERE matched.tenant_id = contribution.tenant_id \
               AND matched.deletion_request_id = $2 \
               AND matched.resource_kind = 'shared_contribution' \
               AND matched.resource_id = contribution.id\
         )",
        "DELETE FROM data_lineage_edges AS lineage \
         WHERE lineage.tenant_id = $1 AND (\
             EXISTS (\
                 SELECT 1 FROM deletion_resource_matches AS matched \
                 WHERE matched.tenant_id = lineage.tenant_id \
                   AND matched.deletion_request_id = $2 \
                   AND matched.resource_kind = lineage.parent_kind \
                   AND matched.resource_id = lineage.parent_id\
             ) \
             OR EXISTS (\
                 SELECT 1 FROM deletion_resource_matches AS matched \
                 WHERE matched.tenant_id = lineage.tenant_id \
                   AND matched.deletion_request_id = $2 \
                   AND matched.resource_kind = lineage.child_kind \
                   AND matched.resource_id = lineage.child_id\
             )\
         )",
    ] {
        sqlx::query(statement)
            .bind(tenant_id)
            .bind(deletion_request_id)
            .execute(&mut **transaction)
            .await
            .map_err(|_| DeletionError::StorageInvariant)?;
    }
    Ok(())
}

fn validate_worker_id(worker_id: &str) -> Result<(), DeletionError> {
    let mut characters = worker_id.chars();
    if worker_id.len() > 64
        || !matches!(characters.next(), Some('a'..='z' | '0'..='9'))
        || !characters.all(|character| matches!(character, 'a'..='z' | '0'..='9' | '-'))
        || worker_id.ends_with('-')
    {
        return Err(DeletionError::InvalidConfiguration);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeletionProcessOutcome {
    Idle,
    Processed {
        deletion_request_id: Uuid,
        processing_attempt: u32,
        matched_resources: u32,
        recomputed_targets: u32,
    },
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum DeletionError {
    #[error("deletion worker configuration is invalid")]
    InvalidConfiguration,
    #[error("deletion worker database is unavailable")]
    DatabaseUnavailable,
    #[error("deletion worker storage invariant failed")]
    StorageInvariant,
    #[error("deletion worker lease is stale")]
    StaleLease,
}

impl From<JobError> for DeletionError {
    fn from(error: JobError) -> Self {
        match error {
            JobError::DatabaseConfiguration | JobError::InvalidConfiguration => {
                Self::InvalidConfiguration
            }
            JobError::DatabaseUnavailable => Self::DatabaseUnavailable,
            JobError::StaleLease => Self::StaleLease,
            JobError::RuleUnavailable
            | JobError::StorageInvariant
            | JobError::ResultMismatch
            | JobError::InvalidProtocol => Self::StorageInvariant,
        }
    }
}

#[derive(FromRow)]
struct ClaimedDeletion {
    tenant_id: Uuid,
    deletion_request_id: Uuid,
    processing_attempt: i32,
}

#[derive(FromRow)]
struct LockedDeletion {
    state: String,
    processing_attempt: i32,
    lease_owner: Option<String>,
    lease_is_current: bool,
}

#[derive(FromRow)]
struct OwnedDerivationKey {
    normalized_username: String,
    site_id: String,
    rule_version_id: Uuid,
    rule_hash: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deletion_worker_identity_and_lease_are_bounded() {
        assert!(validate_worker_id("deletion-worker-1").is_ok());
        assert!(validate_worker_id("-bad").is_err());
        assert!(validate_worker_id("bad-").is_err());
        assert!(validate_worker_id("").is_err());
    }
}
