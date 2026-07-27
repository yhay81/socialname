use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    io::{self, Read},
};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    SUPPRESSION_HMAC_KEY_ENV, SuppressionHmacKey,
    database::{DATABASE_URL_ENV, DatabaseError, connect_database, database_url_from_env},
    deletion::{
        contributor_suppression_token, redact_matched_job_targets, suppression_key_fingerprint,
        target_suppression_token,
    },
};

const BACKUP_ACK_ENV: &str = "SOCIALNAME_BACKUP_EXPIRY_VERIFIED";
const RESTORE_ACK_ENV: &str = "SOCIALNAME_RESTORE_LEDGER_REPLAY";
const BACKUP_INPUT_SCHEMA: &str = "socialname.dev/backup-expiry-verification/v1";
const BACKUP_OUTPUT_SCHEMA: &str = "socialname.dev/backup-expiry-verification-result/v1";
const RESTORE_LEDGER_SCHEMA: &str = "socialname.dev/deletion-restore-ledger/v1";
const RESTORE_OUTPUT_SCHEMA: &str = "socialname.dev/deletion-restore-result/v1";
const MAXIMUM_INPUT_BYTES: u64 = 16 * 1_024 * 1_024;
const MAXIMUM_LEDGER_ENTRIES: usize = 100_000;
const MAXIMUM_REPLAY_OBSERVATIONS: usize = 1_000_000;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupExpiryVerificationInput {
    pub schema: String,
    pub tenant_id: Uuid,
    pub deletion_request_id: Uuid,
    pub verification_reference: String,
    pub inventory_evidence_reference: String,
    pub oldest_restorable_at_unix_ms: Option<i64>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct BackupExpiryVerificationOutput {
    pub schema: &'static str,
    pub deletion_request_id: Uuid,
    pub completed_at_unix_ms: i64,
    pub exact_replay: bool,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RestoreLedgerArtifact {
    pub payload: RestoreLedgerPayload,
    pub mac_hex: String,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RestoreLedgerPayload {
    pub schema: String,
    pub ledger_id: Uuid,
    pub issued_at_unix_ms: i64,
    pub key_fingerprint_hex: String,
    pub entries: Vec<RestoreLedgerEntry>,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct RestoreLedgerEntry {
    pub tenant_id: Uuid,
    pub purpose: String,
    pub token_hmac_hex: String,
    pub expires_at_unix_ms: i64,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct RestoreLedgerReplayOutput {
    pub schema: &'static str,
    pub ledger_id: Uuid,
    pub entries: u32,
    pub deletion_requests: u32,
    pub matched_observations: u32,
    pub exact_replay: bool,
}

pub async fn verify_backup_expiry_from_env()
-> Result<BackupExpiryVerificationOutput, DeletionOperatorError> {
    if env::var(BACKUP_ACK_ENV).as_deref() != Ok("true") {
        return Err(DeletionOperatorError::BackupVerificationNotAcknowledged);
    }
    let input: BackupExpiryVerificationInput = read_json(io::stdin().lock())?;
    let database_url = database_url_from_env(DATABASE_URL_ENV)?;
    let pool = connect_database(&database_url, 1).await?;
    let result = verify_backup_expiry(&pool, input).await;
    pool.close().await;
    result
}

pub async fn export_restore_ledger_from_env() -> Result<RestoreLedgerArtifact, DeletionOperatorError>
{
    let database_url = database_url_from_env(DATABASE_URL_ENV)?;
    let key = suppression_key_from_env()?;
    let pool = connect_database(&database_url, 1).await?;
    let result = export_restore_ledger(&pool, key.expose()).await;
    pool.close().await;
    result
}

pub async fn replay_restore_ledger_from_env()
-> Result<RestoreLedgerReplayOutput, DeletionOperatorError> {
    if env::var(RESTORE_ACK_ENV).as_deref() != Ok("true") {
        return Err(DeletionOperatorError::RestoreReplayNotAcknowledged);
    }
    let artifact: RestoreLedgerArtifact = read_json(io::stdin().lock())?;
    let database_url = database_url_from_env(DATABASE_URL_ENV)?;
    let key = suppression_key_from_env()?;
    let pool = connect_database(&database_url, 1).await?;
    let result = replay_restore_ledger(&pool, key.expose(), artifact).await;
    pool.close().await;
    result
}

pub async fn verify_backup_expiry(
    pool: &PgPool,
    input: BackupExpiryVerificationInput,
) -> Result<BackupExpiryVerificationOutput, DeletionOperatorError> {
    validate_reference(&input.schema, BACKUP_INPUT_SCHEMA)?;
    validate_reference_text(&input.verification_reference)?;
    validate_reference_text(&input.inventory_evidence_reference)?;
    if input
        .oldest_restorable_at_unix_ms
        .is_some_and(|value| value < 0)
    {
        return Err(DeletionOperatorError::InvalidInput);
    }
    let verification_digest: [u8; 32] =
        Sha256::digest(input.verification_reference.as_bytes()).into();
    let inventory_digest: [u8; 32] =
        Sha256::digest(input.inventory_evidence_reference.as_bytes()).into();

    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| DeletionOperatorError::DatabaseUnavailable)?;
    let tenant_id = input.tenant_id;
    set_tenant(&mut transaction, tenant_id).await?;

    let request: Option<StoredBackupRequest> = sqlx::query_as(
        "SELECT state, \
                (EXTRACT(EPOCH FROM backup_expiry_by) * 1000)::bigint \
                    AS backup_expiry_by_unix_ms, \
                (EXTRACT(EPOCH FROM primary_completed_at) * 1000)::bigint \
                    AS primary_completed_at_unix_ms, \
                (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::bigint \
                    AS evaluated_at_unix_ms \
         FROM deletion_requests \
         WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
    )
    .bind(tenant_id)
    .bind(input.deletion_request_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| DeletionOperatorError::DatabaseUnavailable)?;
    let request = request.ok_or(DeletionOperatorError::NotFound)?;
    let existing: Option<StoredBackupVerification> = sqlx::query_as(
        "SELECT verification_reference_digest, inventory_evidence_digest, \
                (EXTRACT(EPOCH FROM oldest_restorable_at) * 1000)::bigint \
                    AS oldest_restorable_at_unix_ms, \
                no_restorable_backups, \
                (EXTRACT(EPOCH FROM verified_at) * 1000)::bigint \
                    AS verified_at_unix_ms \
         FROM deletion_backup_verifications \
         WHERE tenant_id = $1 AND deletion_request_id = $2",
    )
    .bind(tenant_id)
    .bind(input.deletion_request_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| DeletionOperatorError::DatabaseUnavailable)?;
    if let Some(existing) = existing {
        if existing.verification_reference_digest != verification_digest
            || existing.inventory_evidence_digest != inventory_digest
            || existing.oldest_restorable_at_unix_ms != input.oldest_restorable_at_unix_ms
            || existing.no_restorable_backups != input.oldest_restorable_at_unix_ms.is_none()
        {
            return Err(DeletionOperatorError::Conflict);
        }
        transaction
            .commit()
            .await
            .map_err(|_| DeletionOperatorError::DatabaseUnavailable)?;
        return Ok(BackupExpiryVerificationOutput {
            schema: BACKUP_OUTPUT_SCHEMA,
            deletion_request_id: input.deletion_request_id,
            completed_at_unix_ms: existing.verified_at_unix_ms,
            exact_replay: true,
        });
    }

    if request.state != "rebuilding"
        || request.primary_completed_at_unix_ms.is_none()
        || request.evaluated_at_unix_ms < request.backup_expiry_by_unix_ms
        || input.oldest_restorable_at_unix_ms.is_some_and(|oldest| {
            oldest <= request.primary_completed_at_unix_ms.unwrap_or(i64::MAX)
        })
    {
        return Err(DeletionOperatorError::VerificationGateNotSatisfied);
    }
    let completed_stores: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM deletion_tasks \
         WHERE tenant_id = $1 AND deletion_request_id = $2 \
           AND store_kind IN ('primary', 'analytics') AND state = 'completed'",
    )
    .bind(tenant_id)
    .bind(input.deletion_request_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| DeletionOperatorError::DatabaseUnavailable)?;
    if completed_stores != 2 {
        return Err(DeletionOperatorError::VerificationGateNotSatisfied);
    }

    sqlx::query(
        "INSERT INTO deletion_backup_verifications (\
            id, tenant_id, deletion_request_id, verification_reference_digest, \
            inventory_evidence_digest, oldest_restorable_at, \
            no_restorable_backups, verified_at\
         ) VALUES (\
            $1, $2, $3, $4, $5, \
            CASE WHEN $6::bigint IS NULL THEN NULL \
                 ELSE to_timestamp($6::double precision / 1000.0) END, \
            $6::bigint IS NULL, \
            to_timestamp($7::double precision / 1000.0)\
         )",
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(input.deletion_request_id)
    .bind(verification_digest.as_slice())
    .bind(inventory_digest.as_slice())
    .bind(input.oldest_restorable_at_unix_ms)
    .bind(request.evaluated_at_unix_ms)
    .execute(&mut *transaction)
    .await
    .map_err(|_| DeletionOperatorError::VerificationGateNotSatisfied)?;
    sqlx::query(
        "UPDATE deletion_tasks \
         SET state = 'completed', attempt_count = attempt_count + 1, \
             completed_at = to_timestamp($3::double precision / 1000.0), \
             last_error_code = NULL \
         WHERE tenant_id = $1 AND deletion_request_id = $2 \
           AND store_kind = 'backup' AND state <> 'completed'",
    )
    .bind(tenant_id)
    .bind(input.deletion_request_id)
    .bind(request.evaluated_at_unix_ms)
    .execute(&mut *transaction)
    .await
    .map_err(|_| DeletionOperatorError::StorageInvariant)?;
    let stores: serde_json::Value = sqlx::query_scalar(
        "SELECT jsonb_object_agg(\
            CASE store_kind WHEN 'analytics' THEN 'derived' ELSE store_kind END, \
            jsonb_build_object(\
                'state', state, \
                'deadline_at_unix_ms', \
                    (EXTRACT(EPOCH FROM deadline_at) * 1000)::bigint, \
                'completed_at_unix_ms', \
                    (EXTRACT(EPOCH FROM completed_at) * 1000)::bigint\
            )\
         ) FROM deletion_tasks \
         WHERE tenant_id = $1 AND deletion_request_id = $2 \
           AND store_kind IN ('primary', 'analytics', 'backup')",
    )
    .bind(tenant_id)
    .bind(input.deletion_request_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| DeletionOperatorError::StorageInvariant)?;
    sqlx::query(
        "INSERT INTO deletion_receipts (\
            id, tenant_id, deletion_request_id, stores, \
            primary_completed_at, backup_expiry_at, created_at\
         ) SELECT $1, tenant_id, id, $2, primary_completed_at, \
                  backup_expiry_by, to_timestamp($3::double precision / 1000.0) \
           FROM deletion_requests WHERE tenant_id = $4 AND id = $5",
    )
    .bind(Uuid::new_v4())
    .bind(stores)
    .bind(request.evaluated_at_unix_ms)
    .bind(tenant_id)
    .bind(input.deletion_request_id)
    .execute(&mut *transaction)
    .await
    .map_err(|_| DeletionOperatorError::StorageInvariant)?;
    sqlx::query(
        "UPDATE deletion_requests \
         SET state = 'completed', \
             completed_at = to_timestamp($3::double precision / 1000.0) \
         WHERE tenant_id = $1 AND id = $2 AND state = 'rebuilding'",
    )
    .bind(tenant_id)
    .bind(input.deletion_request_id)
    .bind(request.evaluated_at_unix_ms)
    .execute(&mut *transaction)
    .await
    .map_err(|_| DeletionOperatorError::StorageInvariant)?;
    sqlx::query(
        "INSERT INTO audit_events (\
            id, tenant_id, action, resource_kind, resource_id, \
            occurred_at, details\
         ) VALUES (\
            $1, $2, 'deletion.backup.verified', 'deletion_request', $3, \
            to_timestamp($4::double precision / 1000.0), \
            jsonb_build_object('inventory', \
                CASE WHEN $5::bigint IS NULL \
                     THEN 'no_restorable_backups' ELSE 'bounded_oldest_snapshot' END\
            )\
         )",
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(input.deletion_request_id)
    .bind(request.evaluated_at_unix_ms)
    .bind(input.oldest_restorable_at_unix_ms)
    .execute(&mut *transaction)
    .await
    .map_err(|_| DeletionOperatorError::StorageInvariant)?;
    transaction
        .commit()
        .await
        .map_err(|_| DeletionOperatorError::DatabaseUnavailable)?;
    Ok(BackupExpiryVerificationOutput {
        schema: BACKUP_OUTPUT_SCHEMA,
        deletion_request_id: input.deletion_request_id,
        completed_at_unix_ms: request.evaluated_at_unix_ms,
        exact_replay: false,
    })
}

pub async fn export_restore_ledger(
    pool: &PgPool,
    suppression_key: &[u8; 32],
) -> Result<RestoreLedgerArtifact, DeletionOperatorError> {
    let key_fingerprint = suppression_key_fingerprint(suppression_key)
        .ok_or(DeletionOperatorError::CryptographicFailure)?;
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| DeletionOperatorError::DatabaseUnavailable)?;
    let issued_at_unix_ms: i64 =
        sqlx::query_scalar("SELECT (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| DeletionOperatorError::DatabaseUnavailable)?;
    let tenant_ids: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM tenants ORDER BY id")
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| DeletionOperatorError::DatabaseUnavailable)?;
    let mut entries = Vec::new();
    for tenant_id in tenant_ids {
        set_tenant(&mut transaction, tenant_id).await?;
        let incompatible_key_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (\
                SELECT 1 FROM suppression_tokens \
                WHERE tenant_id = $1 AND expires_at > clock_timestamp() \
                  AND key_fingerprint IS DISTINCT FROM $2\
             )",
        )
        .bind(tenant_id)
        .bind(key_fingerprint.as_slice())
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| DeletionOperatorError::DatabaseUnavailable)?;
        if incompatible_key_exists {
            return Err(DeletionOperatorError::KeyMismatch);
        }
        let stored: Vec<StoredSuppressionToken> = sqlx::query_as(
            "SELECT purpose, encode(token_hmac, 'hex') AS token_hmac_hex, \
                    (EXTRACT(EPOCH FROM expires_at) * 1000)::bigint \
                        AS expires_at_unix_ms \
             FROM suppression_tokens \
             WHERE tenant_id = $1 AND expires_at > clock_timestamp() \
               AND key_fingerprint = $2 \
             ORDER BY purpose, token_hmac",
        )
        .bind(tenant_id)
        .bind(key_fingerprint.as_slice())
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| DeletionOperatorError::DatabaseUnavailable)?;
        for token in stored {
            entries.push(RestoreLedgerEntry {
                tenant_id,
                purpose: token.purpose,
                token_hmac_hex: token.token_hmac_hex,
                expires_at_unix_ms: token.expires_at_unix_ms,
            });
            if entries.len() > MAXIMUM_LEDGER_ENTRIES {
                return Err(DeletionOperatorError::BoundExceeded);
            }
        }
    }
    transaction
        .commit()
        .await
        .map_err(|_| DeletionOperatorError::DatabaseUnavailable)?;
    let payload = RestoreLedgerPayload {
        schema: RESTORE_LEDGER_SCHEMA.to_owned(),
        ledger_id: Uuid::new_v4(),
        issued_at_unix_ms,
        key_fingerprint_hex: hex::encode(key_fingerprint),
        entries,
    };
    let payload_bytes =
        serde_json::to_vec(&payload).map_err(|_| DeletionOperatorError::InvalidInput)?;
    let mac_hex = hex::encode(authenticate(suppression_key, &payload_bytes)?);
    Ok(RestoreLedgerArtifact { payload, mac_hex })
}

pub async fn replay_restore_ledger(
    pool: &PgPool,
    suppression_key: &[u8; 32],
    artifact: RestoreLedgerArtifact,
) -> Result<RestoreLedgerReplayOutput, DeletionOperatorError> {
    validate_restore_artifact(suppression_key, &artifact)?;
    let payload_bytes =
        serde_json::to_vec(&artifact.payload).map_err(|_| DeletionOperatorError::InvalidInput)?;
    let artifact_digest: [u8; 32] = Sha256::digest(&payload_bytes).into();
    let key_fingerprint = suppression_key_fingerprint(suppression_key)
        .ok_or(DeletionOperatorError::CryptographicFailure)?;
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| DeletionOperatorError::DatabaseUnavailable)?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))")
        .bind(artifact.payload.ledger_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| DeletionOperatorError::DatabaseUnavailable)?;
    let existing: Option<StoredRestoreRun> = sqlx::query_as(
        "SELECT artifact_digest, entry_count, matched_observations, \
                (SELECT count(*) FROM deletion_restore_request_links AS link \
                 WHERE link.restore_run_id = run.id)::bigint AS request_count \
         FROM deletion_restore_runs AS run WHERE id = $1",
    )
    .bind(artifact.payload.ledger_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| DeletionOperatorError::DatabaseUnavailable)?;
    if let Some(existing) = existing {
        if existing.artifact_digest != artifact_digest {
            return Err(DeletionOperatorError::Conflict);
        }
        return replay_output(
            artifact.payload.ledger_id,
            existing.entry_count,
            existing.request_count,
            existing.matched_observations,
            true,
        );
    }
    let replayed_at_unix_ms: i64 =
        sqlx::query_scalar("SELECT (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| DeletionOperatorError::DatabaseUnavailable)?;
    if artifact.payload.issued_at_unix_ms > replayed_at_unix_ms {
        return Err(DeletionOperatorError::InvalidInput);
    }

    let mut by_tenant: BTreeMap<Uuid, Vec<RestoreLedgerEntry>> = BTreeMap::new();
    for entry in artifact.payload.entries.iter().cloned() {
        by_tenant.entry(entry.tenant_id).or_default().push(entry);
    }
    let mut plans = Vec::new();
    let mut scanned_observations = 0usize;
    for (tenant_id, entries) in &by_tenant {
        set_tenant(&mut transaction, *tenant_id).await?;
        let tenant_exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM tenants WHERE id = $1)")
                .bind(tenant_id)
                .fetch_one(&mut *transaction)
                .await
                .map_err(|_| DeletionOperatorError::DatabaseUnavailable)?;
        if !tenant_exists {
            return Err(DeletionOperatorError::InvalidInput);
        }
        let incompatible_key_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (\
                SELECT 1 FROM suppression_tokens \
                WHERE tenant_id = $1 AND expires_at > clock_timestamp() \
                  AND key_fingerprint IS DISTINCT FROM $2\
             )",
        )
        .bind(tenant_id)
        .bind(key_fingerprint.as_slice())
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| DeletionOperatorError::DatabaseUnavailable)?;
        if incompatible_key_exists {
            return Err(DeletionOperatorError::KeyMismatch);
        }
        let contributor_grants: Vec<StoredConsentGrant> = sqlx::query_as(
            "SELECT id, subject_kind, COALESCE(membership_id, client_id) AS subject_id, purpose \
             FROM consent_grants WHERE tenant_id = $1 ORDER BY id",
        )
        .bind(tenant_id)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| DeletionOperatorError::DatabaseUnavailable)?;
        let observations: Vec<StoredReplayObservation> = sqlx::query_as(
            "SELECT id, probe_job_id, consent_grant_id, site_id, normalized_username, visibility \
             FROM observations WHERE tenant_id = $1 ORDER BY id",
        )
        .bind(tenant_id)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| DeletionOperatorError::DatabaseUnavailable)?;
        let contributions: Vec<StoredReplayContribution> = sqlx::query_as(
            "SELECT id, consent_grant_id, site_id, normalized_username \
             FROM shared_contributions WHERE tenant_id = $1 ORDER BY id",
        )
        .bind(tenant_id)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| DeletionOperatorError::DatabaseUnavailable)?;
        scanned_observations = scanned_observations
            .saturating_add(observations.len())
            .saturating_add(contributions.len());
        if scanned_observations > MAXIMUM_REPLAY_OBSERVATIONS {
            return Err(DeletionOperatorError::BoundExceeded);
        }
        for entry in entries {
            if entry.expires_at_unix_ms <= replayed_at_unix_ms {
                continue;
            }
            let token = decode_digest(&entry.token_hmac_hex)?;
            let mut grant_ids = Vec::new();
            let mut observation_ids = Vec::new();
            let mut probe_job_ids = Vec::new();
            let mut contribution_ids = Vec::new();
            match entry.purpose.as_str() {
                "contributor_reingestion" => {
                    for grant in &contributor_grants {
                        let candidate = contributor_suppression_token(
                            suppression_key,
                            *tenant_id,
                            &grant.subject_kind,
                            grant.subject_id,
                            &grant.purpose,
                        )
                        .ok_or(DeletionOperatorError::CryptographicFailure)?;
                        if candidate == token {
                            grant_ids.push(grant.id);
                        }
                    }
                    for observation in &observations {
                        if grant_ids.contains(&observation.consent_grant_id) {
                            observation_ids.push(observation.id);
                            probe_job_ids.push(observation.probe_job_id);
                        }
                    }
                    for contribution in &contributions {
                        if grant_ids.contains(&contribution.consent_grant_id) {
                            contribution_ids.push(contribution.id);
                        }
                    }
                }
                "target_reingestion" => {
                    for observation in &observations {
                        if observation.visibility != "shared" {
                            continue;
                        }
                        let candidate = target_suppression_token(
                            suppression_key,
                            *tenant_id,
                            &observation.site_id,
                            &observation.normalized_username,
                        )
                        .ok_or(DeletionOperatorError::CryptographicFailure)?;
                        if candidate == token {
                            observation_ids.push(observation.id);
                            probe_job_ids.push(observation.probe_job_id);
                        }
                    }
                    for contribution in &contributions {
                        let candidate = target_suppression_token(
                            suppression_key,
                            *tenant_id,
                            &contribution.site_id,
                            &contribution.normalized_username,
                        )
                        .ok_or(DeletionOperatorError::CryptographicFailure)?;
                        if candidate == token {
                            contribution_ids.push(contribution.id);
                        }
                    }
                }
                _ => return Err(DeletionOperatorError::InvalidInput),
            }
            plans.push(ReplayPlan {
                tenant_id: *tenant_id,
                entry: entry.clone(),
                token,
                grant_ids,
                observation_ids,
                probe_job_ids,
                contribution_ids,
            });
        }
    }
    let matched_observations: usize = plans.iter().map(|plan| plan.observation_ids.len()).sum();
    if matched_observations > MAXIMUM_REPLAY_OBSERVATIONS {
        return Err(DeletionOperatorError::BoundExceeded);
    }
    sqlx::query(
        "INSERT INTO deletion_restore_runs (\
            id, artifact_digest, key_fingerprint, issued_at, replayed_at, verified_at, \
            entry_count, matched_observations\
         ) VALUES (\
            $1, $2, $3, to_timestamp($4::double precision / 1000.0), \
            to_timestamp($5::double precision / 1000.0), \
            to_timestamp($5::double precision / 1000.0), $6, $7\
         )",
    )
    .bind(artifact.payload.ledger_id)
    .bind(artifact_digest.as_slice())
    .bind(key_fingerprint.as_slice())
    .bind(artifact.payload.issued_at_unix_ms)
    .bind(replayed_at_unix_ms)
    .bind(
        i32::try_from(artifact.payload.entries.len())
            .map_err(|_| DeletionOperatorError::BoundExceeded)?,
    )
    .bind(i32::try_from(matched_observations).map_err(|_| DeletionOperatorError::BoundExceeded)?)
    .execute(&mut *transaction)
    .await
    .map_err(|_| DeletionOperatorError::StorageInvariant)?;

    let mut request_count = 0usize;
    for plan in plans {
        set_tenant(&mut transaction, plan.tenant_id).await?;
        let imported = sqlx::query(
            "INSERT INTO suppression_tokens (\
                id, tenant_id, purpose, token_hmac, key_fingerprint, \
                created_at, expires_at\
             ) VALUES (\
                $1, $2, $3, $4, $5, \
                to_timestamp($6::double precision / 1000.0), \
                to_timestamp($7::double precision / 1000.0)\
             ) ON CONFLICT (tenant_id, purpose, token_hmac) DO UPDATE \
               SET expires_at = GREATEST(\
                    suppression_tokens.expires_at, EXCLUDED.expires_at\
               ) \
             WHERE suppression_tokens.key_fingerprint \
                   IS NOT DISTINCT FROM EXCLUDED.key_fingerprint",
        )
        .bind(Uuid::new_v4())
        .bind(plan.tenant_id)
        .bind(&plan.entry.purpose)
        .bind(plan.token.as_slice())
        .bind(key_fingerprint.as_slice())
        .bind(replayed_at_unix_ms)
        .bind(plan.entry.expires_at_unix_ms)
        .execute(&mut *transaction)
        .await
        .map_err(|_| DeletionOperatorError::StorageInvariant)?;
        if imported.rows_affected() != 1 {
            return Err(DeletionOperatorError::KeyMismatch);
        }
        if plan.observation_ids.is_empty() && plan.contribution_ids.is_empty() {
            continue;
        }
        let request_id = Uuid::new_v4();
        let scope = if plan.entry.purpose == "contributor_reingestion" {
            "contributor"
        } else {
            "target"
        };
        sqlx::query(
            "WITH moment AS (\
                SELECT to_timestamp($6::double precision / 1000.0) AS now\
             ) INSERT INTO deletion_requests (\
                id, tenant_id, scope_kind, selector_token, state, requested_at, \
                hide_by, support_withdrawal_by, primary_delete_by, \
                derived_rebuild_by, backup_expiry_by, request_origin, \
                request_group_id, verification_reference_digest\
             ) SELECT $1, $2, $3, $4, 'hidden', now, \
                      now + interval '5 minutes', now + interval '1 hour', \
                      now + interval '24 hours', now + interval '7 days', \
                      now + interval '35 days', 'restore_ledger', $5, $7 \
               FROM moment",
        )
        .bind(request_id)
        .bind(plan.tenant_id)
        .bind(scope)
        .bind(plan.token.as_slice())
        .bind(artifact.payload.ledger_id)
        .bind(replayed_at_unix_ms)
        .bind(artifact_digest.as_slice())
        .execute(&mut *transaction)
        .await
        .map_err(|_| DeletionOperatorError::StorageInvariant)?;
        if scope == "contributor" {
            withdraw_restored_grants(
                &mut transaction,
                plan.tenant_id,
                request_id,
                &plan.grant_ids,
                replayed_at_unix_ms,
            )
            .await?;
        }
        materialize_restored_lineage(
            &mut transaction,
            plan.tenant_id,
            request_id,
            &plan.observation_ids,
            &plan.probe_job_ids,
            &plan.contribution_ids,
            replayed_at_unix_ms,
        )
        .await?;
        redact_matched_job_targets(&mut transaction, plan.tenant_id, request_id)
            .await
            .map_err(|_| DeletionOperatorError::StorageInvariant)?;
        cancel_matched_deliveries(&mut transaction, plan.tenant_id, request_id).await?;
        insert_deletion_tasks(&mut transaction, plan.tenant_id, request_id).await?;
        sqlx::query(
            "INSERT INTO deletion_restore_request_links (\
                restore_run_id, tenant_id, deletion_request_id\
             ) VALUES ($1, $2, $3)",
        )
        .bind(artifact.payload.ledger_id)
        .bind(plan.tenant_id)
        .bind(request_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| DeletionOperatorError::StorageInvariant)?;
        request_count += 1;
    }
    transaction
        .commit()
        .await
        .map_err(|_| DeletionOperatorError::DatabaseUnavailable)?;
    replay_output(
        artifact.payload.ledger_id,
        artifact.payload.entries.len(),
        request_count,
        matched_observations,
        false,
    )
}

async fn withdraw_restored_grants(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    deletion_request_id: Uuid,
    grant_ids: &[Uuid],
    replayed_at_unix_ms: i64,
) -> Result<(), DeletionOperatorError> {
    for grant_id in grant_ids {
        let changed: Option<i32> = sqlx::query_scalar(
            "UPDATE consent_grants \
             SET withdrawn_at = to_timestamp($3::double precision / 1000.0) \
             WHERE tenant_id = $1 AND id = $2 AND withdrawn_at IS NULL \
             RETURNING 1",
        )
        .bind(tenant_id)
        .bind(grant_id)
        .bind(replayed_at_unix_ms)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| DeletionOperatorError::StorageInvariant)?;
        if changed.is_some() {
            sqlx::query(
                "INSERT INTO consent_events (\
                    id, tenant_id, consent_grant_id, event_kind, occurred_at, details\
                 ) VALUES (\
                    $1, $2, $3, 'withdrawn', \
                    to_timestamp($4::double precision / 1000.0), \
                    jsonb_build_object('restore_deletion_request_id', $5::text)\
                 )",
            )
            .bind(Uuid::new_v4())
            .bind(tenant_id)
            .bind(grant_id)
            .bind(replayed_at_unix_ms)
            .bind(deletion_request_id)
            .execute(&mut **transaction)
            .await
            .map_err(|_| DeletionOperatorError::StorageInvariant)?;
        }
    }
    Ok(())
}

async fn materialize_restored_lineage(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    deletion_request_id: Uuid,
    observation_ids: &[Uuid],
    probe_job_ids: &[Uuid],
    contribution_ids: &[Uuid],
    replayed_at_unix_ms: i64,
) -> Result<(), DeletionOperatorError> {
    sqlx::query(
        "WITH RECURSIVE matched(resource_kind, resource_id) AS (\
            SELECT 'observation'::text, id FROM unnest($3::uuid[]) AS id \
            UNION \
            SELECT 'probe_job'::text, id FROM unnest($4::uuid[]) AS id \
            UNION \
            SELECT 'shared_contribution'::text, id FROM unnest($6::uuid[]) AS id \
            UNION \
            SELECT 'search_target'::text, consumer.search_target_id \
            FROM probe_job_consumers AS consumer \
            WHERE consumer.tenant_id = $1 \
              AND consumer.probe_job_id = ANY($4::uuid[]) \
              AND consumer.search_target_id IS NOT NULL \
            UNION \
            SELECT lineage.child_kind, lineage.child_id \
            FROM data_lineage_edges AS lineage \
            JOIN matched AS parent \
              ON parent.resource_kind = lineage.parent_kind \
             AND parent.resource_id = lineage.parent_id \
            WHERE lineage.tenant_id = $1\
         ) INSERT INTO deletion_resource_matches (\
            tenant_id, deletion_request_id, resource_kind, resource_id, hidden_at\
         ) SELECT $1, $2, resource_kind, resource_id, \
                  to_timestamp($5::double precision / 1000.0) \
           FROM matched \
           WHERE resource_kind IN (\
                'observation', 'evidence_capsule', 'assertion', \
                'regional_assertion', 'search_event', 'watch_run_target', \
                'transition', 'notification_delivery', 'probe_job', \
                'search_target', 'shared_contribution'\
           ) ON CONFLICT DO NOTHING",
    )
    .bind(tenant_id)
    .bind(deletion_request_id)
    .bind(observation_ids)
    .bind(probe_job_ids)
    .bind(replayed_at_unix_ms)
    .bind(contribution_ids)
    .execute(&mut **transaction)
    .await
    .map_err(|_| DeletionOperatorError::StorageInvariant)?;
    Ok(())
}

async fn cancel_matched_deliveries(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    deletion_request_id: Uuid,
) -> Result<(), DeletionOperatorError> {
    sqlx::query(
        "UPDATE notification_deliveries AS delivery \
         SET state = 'cancelled', next_attempt_at = NULL, delivered_at = NULL, \
             last_error_code = NULL, lease_owner = NULL, \
             lease_started_at = NULL, lease_expires_at = NULL \
         WHERE delivery.tenant_id = $1 \
           AND delivery.state IN ('queued', 'delivering', 'retry_scheduled') \
           AND EXISTS (\
               SELECT 1 FROM deletion_resource_matches AS matched \
               WHERE matched.tenant_id = delivery.tenant_id \
                 AND matched.deletion_request_id = $2 \
                 AND matched.resource_kind = 'notification_delivery' \
                 AND matched.resource_id = delivery.id\
           )",
    )
    .bind(tenant_id)
    .bind(deletion_request_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| DeletionOperatorError::StorageInvariant)?;
    Ok(())
}

async fn insert_deletion_tasks(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    deletion_request_id: Uuid,
) -> Result<(), DeletionOperatorError> {
    for store in ["primary", "analytics", "backup"] {
        sqlx::query(
            "INSERT INTO deletion_tasks (\
                id, tenant_id, deletion_request_id, store_kind, state, \
                deadline_at, available_at\
             ) SELECT $1, $2, $3, $4, 'pending', \
                    CASE $4 WHEN 'primary' THEN primary_delete_by \
                            WHEN 'analytics' THEN derived_rebuild_by \
                            ELSE backup_expiry_by END, \
                    clock_timestamp() \
               FROM deletion_requests WHERE tenant_id = $2 AND id = $3",
        )
        .bind(Uuid::new_v4())
        .bind(tenant_id)
        .bind(deletion_request_id)
        .bind(store)
        .execute(&mut **transaction)
        .await
        .map_err(|_| DeletionOperatorError::StorageInvariant)?;
    }
    Ok(())
}

fn validate_restore_artifact(
    key: &[u8; 32],
    artifact: &RestoreLedgerArtifact,
) -> Result<(), DeletionOperatorError> {
    validate_reference(&artifact.payload.schema, RESTORE_LEDGER_SCHEMA)?;
    if artifact.payload.issued_at_unix_ms < 0
        || artifact.payload.entries.len() > MAXIMUM_LEDGER_ENTRIES
        || artifact.payload.key_fingerprint_hex.len() != 64
        || artifact.mac_hex.len() != 64
    {
        return Err(DeletionOperatorError::InvalidInput);
    }
    let expected_fingerprint =
        suppression_key_fingerprint(key).ok_or(DeletionOperatorError::CryptographicFailure)?;
    if decode_digest(&artifact.payload.key_fingerprint_hex)? != expected_fingerprint {
        return Err(DeletionOperatorError::KeyMismatch);
    }
    let mut unique = BTreeSet::new();
    for entry in &artifact.payload.entries {
        if !matches!(
            entry.purpose.as_str(),
            "contributor_reingestion" | "target_reingestion"
        ) || entry.expires_at_unix_ms < 0
            || decode_digest(&entry.token_hmac_hex).is_err()
            || !unique.insert(entry.clone())
        {
            return Err(DeletionOperatorError::InvalidInput);
        }
    }
    let payload =
        serde_json::to_vec(&artifact.payload).map_err(|_| DeletionOperatorError::InvalidInput)?;
    let supplied = decode_digest(&artifact.mac_hex)?;
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|_| DeletionOperatorError::CryptographicFailure)?;
    mac.update(&payload);
    mac.verify_slice(&supplied)
        .map_err(|_| DeletionOperatorError::AuthenticationFailed)
}

fn authenticate(key: &[u8; 32], bytes: &[u8]) -> Result<[u8; 32], DeletionOperatorError> {
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|_| DeletionOperatorError::CryptographicFailure)?;
    mac.update(bytes);
    Ok(mac.finalize().into_bytes().into())
}

fn decode_digest(value: &str) -> Result<[u8; 32], DeletionOperatorError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(DeletionOperatorError::InvalidInput);
    }
    hex::decode(value)
        .map_err(|_| DeletionOperatorError::InvalidInput)?
        .try_into()
        .map_err(|_| DeletionOperatorError::InvalidInput)
}

fn validate_reference(schema: &str, expected: &str) -> Result<(), DeletionOperatorError> {
    if schema == expected {
        Ok(())
    } else {
        Err(DeletionOperatorError::InvalidInput)
    }
}

fn validate_reference_text(value: &str) -> Result<(), DeletionOperatorError> {
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        Err(DeletionOperatorError::InvalidInput)
    } else {
        Ok(())
    }
}

fn suppression_key_from_env() -> Result<SuppressionHmacKey, DeletionOperatorError> {
    let value = env::var(SUPPRESSION_HMAC_KEY_ENV)
        .map_err(|_| DeletionOperatorError::InvalidConfiguration)?;
    SuppressionHmacKey::from_hex(&value).map_err(|_| DeletionOperatorError::InvalidConfiguration)
}

fn read_json<T: for<'de> Deserialize<'de>>(reader: impl Read) -> Result<T, DeletionOperatorError> {
    let mut bytes = Vec::new();
    reader
        .take(MAXIMUM_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| DeletionOperatorError::InvalidInput)?;
    if bytes.is_empty()
        || u64::try_from(bytes.len()).map_or(true, |length| length > MAXIMUM_INPUT_BYTES)
    {
        return Err(DeletionOperatorError::InvalidInput);
    }
    serde_json::from_slice(&bytes).map_err(|_| DeletionOperatorError::InvalidInput)
}

async fn set_tenant(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
) -> Result<(), DeletionOperatorError> {
    sqlx::query("SELECT set_config('socialname.tenant_id', $1, true)")
        .bind(tenant_id.to_string())
        .execute(&mut **transaction)
        .await
        .map_err(|_| DeletionOperatorError::DatabaseUnavailable)?;
    Ok(())
}

fn replay_output(
    ledger_id: Uuid,
    entries: impl TryInto<u32>,
    requests: impl TryInto<u32>,
    observations: impl TryInto<u32>,
    exact_replay: bool,
) -> Result<RestoreLedgerReplayOutput, DeletionOperatorError> {
    Ok(RestoreLedgerReplayOutput {
        schema: RESTORE_OUTPUT_SCHEMA,
        ledger_id,
        entries: entries
            .try_into()
            .map_err(|_| DeletionOperatorError::BoundExceeded)?,
        deletion_requests: requests
            .try_into()
            .map_err(|_| DeletionOperatorError::BoundExceeded)?,
        matched_observations: observations
            .try_into()
            .map_err(|_| DeletionOperatorError::BoundExceeded)?,
        exact_replay,
    })
}

#[derive(FromRow)]
struct StoredBackupVerification {
    verification_reference_digest: Vec<u8>,
    inventory_evidence_digest: Vec<u8>,
    oldest_restorable_at_unix_ms: Option<i64>,
    no_restorable_backups: bool,
    verified_at_unix_ms: i64,
}

#[derive(FromRow)]
struct StoredBackupRequest {
    state: String,
    backup_expiry_by_unix_ms: i64,
    primary_completed_at_unix_ms: Option<i64>,
    evaluated_at_unix_ms: i64,
}

#[derive(FromRow)]
struct StoredSuppressionToken {
    purpose: String,
    token_hmac_hex: String,
    expires_at_unix_ms: i64,
}

#[derive(FromRow)]
struct StoredConsentGrant {
    id: Uuid,
    subject_kind: String,
    subject_id: Uuid,
    purpose: String,
}

#[derive(FromRow)]
struct StoredReplayObservation {
    id: Uuid,
    probe_job_id: Uuid,
    consent_grant_id: Uuid,
    site_id: String,
    normalized_username: String,
    visibility: String,
}

#[derive(FromRow)]
struct StoredReplayContribution {
    id: Uuid,
    consent_grant_id: Uuid,
    site_id: String,
    normalized_username: String,
}

struct ReplayPlan {
    tenant_id: Uuid,
    entry: RestoreLedgerEntry,
    token: [u8; 32],
    grant_ids: Vec<Uuid>,
    observation_ids: Vec<Uuid>,
    probe_job_ids: Vec<Uuid>,
    contribution_ids: Vec<Uuid>,
}

#[derive(FromRow)]
struct StoredRestoreRun {
    artifact_digest: Vec<u8>,
    entry_count: i32,
    matched_observations: i32,
    request_count: i64,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DeletionOperatorError {
    #[error("backup expiry verification requires an explicit inventory acknowledgement")]
    BackupVerificationNotAcknowledged,
    #[error("restore ledger replay requires an explicit quarantine acknowledgement")]
    RestoreReplayNotAcknowledged,
    #[error("deletion operator configuration is invalid")]
    InvalidConfiguration,
    #[error("deletion operator input is invalid")]
    InvalidInput,
    #[error("deletion operator input exceeds its bound")]
    BoundExceeded,
    #[error("deletion request was not found")]
    NotFound,
    #[error("deletion operator exact replay conflicts with stored evidence")]
    Conflict,
    #[error("backup expiry verification gate is not satisfied")]
    VerificationGateNotSatisfied,
    #[error("restore ledger authentication failed")]
    AuthenticationFailed,
    #[error("restore ledger suppression key does not match")]
    KeyMismatch,
    #[error("deletion operator cryptographic operation failed")]
    CryptographicFailure,
    #[error("deletion operator database is unavailable")]
    DatabaseUnavailable,
    #[error("deletion operator storage invariant failed")]
    StorageInvariant,
    #[error(transparent)]
    Database(#[from] DatabaseError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restore_artifact_authentication_is_exact_and_target_free() {
        let key = [7_u8; 32];
        let payload = RestoreLedgerPayload {
            schema: RESTORE_LEDGER_SCHEMA.to_owned(),
            ledger_id: Uuid::nil(),
            issued_at_unix_ms: 1,
            key_fingerprint_hex: hex::encode(suppression_key_fingerprint(&key).unwrap()),
            entries: vec![RestoreLedgerEntry {
                tenant_id: Uuid::nil(),
                purpose: "target_reingestion".to_owned(),
                token_hmac_hex: "11".repeat(32),
                expires_at_unix_ms: 2,
            }],
        };
        let bytes = serde_json::to_vec(&payload).unwrap();
        let mut artifact = RestoreLedgerArtifact {
            payload,
            mac_hex: hex::encode(authenticate(&key, &bytes).unwrap()),
        };
        assert!(validate_restore_artifact(&key, &artifact).is_ok());
        let json = serde_json::to_string(&artifact).unwrap();
        assert!(!json.contains("username"));
        artifact.payload.entries[0].expires_at_unix_ms = 3;
        assert_eq!(
            validate_restore_artifact(&key, &artifact).unwrap_err(),
            DeletionOperatorError::AuthenticationFailed
        );
    }
}
