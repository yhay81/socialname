use std::{
    env,
    io::{self, Read},
};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    SUPPRESSION_HMAC_KEY_ENV, SuppressionHmacKey,
    database::{DATABASE_URL_ENV, DatabaseError, connect_database, database_url_from_env},
    deletion::{redact_matched_job_targets, suppression_key_fingerprint, target_suppression_token},
};

const VERIFICATION_ACK_ENV: &str = "SOCIALNAME_TARGET_DELETION_VERIFIED";
const INPUT_SCHEMA: &str = "socialname.dev/verified-target-deletion/v1";
const MAXIMUM_INPUT_BYTES: u64 = 32 * 1_024;
const MAXIMUM_SELECTORS: usize = 64;
const MAXIMUM_TENANTS: usize = 10_000;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedTargetDeletionInput {
    pub schema: String,
    pub verification_reference: String,
    pub selectors: Vec<TargetDeletionSelector>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct TargetDeletionSelector {
    pub site_id: String,
    pub normalized_username: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct VerifiedTargetDeletionOutput {
    pub schema: &'static str,
    pub request_group_id: Uuid,
    pub deletion_request_ids: Vec<Uuid>,
    pub matched_observations: u32,
    pub suppressed_tenants: u32,
    pub selectors: u32,
}

pub async fn request_target_deletion_from_env()
-> Result<VerifiedTargetDeletionOutput, TargetDeletionOperatorError> {
    if env::var(VERIFICATION_ACK_ENV).as_deref() != Ok("true") {
        return Err(TargetDeletionOperatorError::VerificationNotAcknowledged);
    }
    let database_url = database_url_from_env(DATABASE_URL_ENV)?;
    let key_text = env::var(SUPPRESSION_HMAC_KEY_ENV)
        .map_err(|_| TargetDeletionOperatorError::InvalidConfiguration)?;
    let key = SuppressionHmacKey::from_hex(&key_text)
        .map_err(|_| TargetDeletionOperatorError::InvalidConfiguration)?;
    let input = read_input(io::stdin().lock())?;
    let pool = connect_database(&database_url, 1).await?;
    let result = request_verified_target_deletion(&pool, key.expose(), input).await;
    pool.close().await;
    result
}

pub async fn request_verified_target_deletion(
    pool: &PgPool,
    suppression_key: &[u8; 32],
    mut input: VerifiedTargetDeletionInput,
) -> Result<VerifiedTargetDeletionOutput, TargetDeletionOperatorError> {
    validate_input(&mut input)?;
    let verification_digest: [u8; 32] =
        Sha256::digest(input.verification_reference.as_bytes()).into();
    let key_fingerprint = suppression_key_fingerprint(suppression_key)
        .ok_or(TargetDeletionOperatorError::CryptographicFailure)?;
    let site_ids: Vec<String> = input
        .selectors
        .iter()
        .map(|selector| selector.site_id.clone())
        .collect();
    let usernames: Vec<String> = input
        .selectors
        .iter()
        .map(|selector| selector.normalized_username.clone())
        .collect();

    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| TargetDeletionOperatorError::DatabaseUnavailable)?;
    let tenant_ids: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM tenants ORDER BY id LIMIT $1")
        .bind(
            i64::try_from(MAXIMUM_TENANTS + 1)
                .map_err(|_| TargetDeletionOperatorError::InvalidConfiguration)?,
        )
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| TargetDeletionOperatorError::DatabaseUnavailable)?;
    if tenant_ids.len() > MAXIMUM_TENANTS {
        return Err(TargetDeletionOperatorError::TooManyMatches);
    }

    let mut tenant_tokens = Vec::with_capacity(tenant_ids.len());
    let mut existing_group_id = None;
    for tenant_id in &tenant_ids {
        let incompatible_key_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (\
                SELECT 1 FROM suppression_tokens \
                WHERE tenant_id = $1 \
                  AND purpose = 'target_reingestion' \
                  AND expires_at > clock_timestamp() \
                  AND key_fingerprint IS DISTINCT FROM $2\
             )",
        )
        .bind(tenant_id)
        .bind(key_fingerprint.as_slice())
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| TargetDeletionOperatorError::DatabaseUnavailable)?;
        if incompatible_key_exists {
            return Err(TargetDeletionOperatorError::InvalidConfiguration);
        }
        let token = request_selector_token(suppression_key, *tenant_id, &input.selectors)?;
        let existing: Option<(Uuid, Uuid)> = sqlx::query_as(
            "SELECT id, request_group_id \
             FROM deletion_requests \
             WHERE tenant_id = $1 \
               AND request_origin = 'verified_target_operator' \
               AND selector_token = $2 \
             ORDER BY requested_at DESC, id DESC LIMIT 1 \
             FOR UPDATE",
        )
        .bind(tenant_id)
        .bind(token.as_slice())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| TargetDeletionOperatorError::DatabaseUnavailable)?;
        if let Some((_, group_id)) = existing {
            if existing_group_id.is_some_and(|known| known != group_id) {
                return Err(TargetDeletionOperatorError::StorageInvariant);
            }
            existing_group_id = Some(group_id);
        }
        tenant_tokens.push((*tenant_id, token, existing));
    }
    let request_group_id = existing_group_id.unwrap_or_else(Uuid::new_v4);
    let mut deletion_request_ids = Vec::new();
    let mut matched_observations = 0_u32;

    for (tenant_id, selector_token, existing) in tenant_tokens {
        for selector in &input.selectors {
            let target_token = target_suppression_token(
                suppression_key,
                tenant_id,
                &selector.site_id,
                &selector.normalized_username,
            )
            .ok_or(TargetDeletionOperatorError::CryptographicFailure)?;
            sqlx::query(
                "INSERT INTO suppression_tokens (\
                    id, tenant_id, purpose, token_hmac, key_fingerprint, \
                    created_at, expires_at\
                 ) VALUES (\
                    $1, $2, 'target_reingestion', $3, $4, clock_timestamp(), \
                    clock_timestamp() + interval '3 years'\
                 ) ON CONFLICT (tenant_id, purpose, token_hmac) DO UPDATE \
                   SET expires_at = GREATEST(\
                       suppression_tokens.expires_at, EXCLUDED.expires_at\
                   ), key_fingerprint = EXCLUDED.key_fingerprint",
            )
            .bind(Uuid::new_v4())
            .bind(tenant_id)
            .bind(target_token.as_slice())
            .bind(key_fingerprint.as_slice())
            .execute(&mut *transaction)
            .await
            .map_err(|_| TargetDeletionOperatorError::DatabaseUnavailable)?;
        }

        if let Some((request_id, group_id)) = existing {
            if group_id != request_group_id {
                return Err(TargetDeletionOperatorError::StorageInvariant);
            }
            let matched: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM deletion_resource_matches \
                 WHERE tenant_id = $1 AND deletion_request_id = $2 \
                   AND resource_kind = 'observation'",
            )
            .bind(tenant_id)
            .bind(request_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| TargetDeletionOperatorError::DatabaseUnavailable)?;
            matched_observations = matched_observations
                .checked_add(
                    u32::try_from(matched)
                        .map_err(|_| TargetDeletionOperatorError::TooManyMatches)?,
                )
                .ok_or(TargetDeletionOperatorError::TooManyMatches)?;
            deletion_request_ids.push(request_id);
            continue;
        }

        let matched: i64 = sqlx::query_scalar(
            "SELECT count(*) \
             FROM observations AS observation \
             WHERE observation.tenant_id = $1 \
               AND observation.visibility = 'shared' \
               AND EXISTS (\
                   SELECT 1 FROM unnest($2::text[], $3::text[]) \
                       AS selector(site_id, normalized_username) \
                   WHERE selector.site_id = observation.site_id \
                     AND selector.normalized_username = observation.normalized_username\
               )",
        )
        .bind(tenant_id)
        .bind(&site_ids)
        .bind(&usernames)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| TargetDeletionOperatorError::DatabaseUnavailable)?;
        let matched =
            u32::try_from(matched).map_err(|_| TargetDeletionOperatorError::TooManyMatches)?;
        if matched > socialname_protocol::MAXIMUM_DELETION_MATCH_COUNT {
            return Err(TargetDeletionOperatorError::TooManyMatches);
        }
        if matched == 0 {
            continue;
        }
        matched_observations = matched_observations
            .checked_add(matched)
            .ok_or(TargetDeletionOperatorError::TooManyMatches)?;
        if matched_observations > socialname_protocol::MAXIMUM_DELETION_MATCH_COUNT {
            return Err(TargetDeletionOperatorError::TooManyMatches);
        }

        let deletion_request_id = {
            let request_id = Uuid::new_v4();
            sqlx::query(
                "WITH moment AS (SELECT clock_timestamp() AS now) \
                 INSERT INTO deletion_requests (\
                    id, tenant_id, scope_kind, selector_token, state, \
                    requested_at, hide_by, support_withdrawal_by, \
                    primary_delete_by, derived_rebuild_by, backup_expiry_by, \
                    request_origin, request_group_id, verification_reference_digest\
                 ) \
                 SELECT $1, $2, 'target', $3, 'hidden', now, \
                        now + interval '5 minutes', \
                        now + interval '1 hour', \
                        now + interval '24 hours', \
                        now + interval '7 days', \
                        now + interval '35 days', \
                        'verified_target_operator', $4, $5 \
                 FROM moment",
            )
            .bind(request_id)
            .bind(tenant_id)
            .bind(selector_token.as_slice())
            .bind(request_group_id)
            .bind(verification_digest.as_slice())
            .execute(&mut *transaction)
            .await
            .map_err(|_| TargetDeletionOperatorError::DatabaseUnavailable)?;
            materialize_target_lineage(
                &mut transaction,
                tenant_id,
                request_id,
                &site_ids,
                &usernames,
            )
            .await?;
            redact_matched_job_targets(&mut transaction, tenant_id, request_id)
                .await
                .map_err(|_| TargetDeletionOperatorError::DatabaseUnavailable)?;
            cancel_matched_deliveries(&mut transaction, tenant_id, request_id).await?;
            insert_tasks(&mut transaction, tenant_id, request_id).await?;
            sqlx::query(
                "INSERT INTO audit_events (\
                    id, tenant_id, action, resource_kind, resource_id, \
                    occurred_at, details\
                 ) VALUES (\
                    $1, $2, 'deletion.target.hidden', 'deletion_request', $3, \
                    clock_timestamp(), jsonb_build_object(\
                        'request_group_id', $4::text, 'scope', 'shared_only'\
                    )\
                 )",
            )
            .bind(Uuid::new_v4())
            .bind(tenant_id)
            .bind(request_id)
            .bind(request_group_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| TargetDeletionOperatorError::DatabaseUnavailable)?;
            request_id
        };
        deletion_request_ids.push(deletion_request_id);
    }

    transaction
        .commit()
        .await
        .map_err(|_| TargetDeletionOperatorError::DatabaseUnavailable)?;
    Ok(VerifiedTargetDeletionOutput {
        schema: "socialname.dev/verified-target-deletion-result/v1",
        request_group_id,
        deletion_request_ids,
        matched_observations,
        suppressed_tenants: u32::try_from(tenant_ids.len())
            .map_err(|_| TargetDeletionOperatorError::TooManyMatches)?,
        selectors: u32::try_from(input.selectors.len())
            .map_err(|_| TargetDeletionOperatorError::InvalidConfiguration)?,
    })
}

async fn materialize_target_lineage(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    deletion_request_id: Uuid,
    site_ids: &[String],
    usernames: &[String],
) -> Result<(), TargetDeletionOperatorError> {
    sqlx::query(
        "WITH RECURSIVE selected_observations AS (\
            SELECT observation.id, observation.probe_job_id \
            FROM observations AS observation \
            WHERE observation.tenant_id = $1 \
              AND observation.visibility = 'shared' \
              AND EXISTS (\
                  SELECT 1 FROM unnest($3::text[], $4::text[]) \
                      AS selector(site_id, normalized_username) \
                  WHERE selector.site_id = observation.site_id \
                    AND selector.normalized_username = observation.normalized_username\
              ) \
         ), matched(resource_kind, resource_id) AS (\
            SELECT 'observation'::text, selected.id \
            FROM selected_observations AS selected \
            UNION \
            SELECT 'probe_job'::text, selected.probe_job_id \
            FROM selected_observations AS selected \
            UNION \
            SELECT 'search_target'::text, consumer.search_target_id \
            FROM selected_observations AS selected \
            JOIN probe_job_consumers AS consumer \
              ON consumer.tenant_id = $1 \
             AND consumer.probe_job_id = selected.probe_job_id \
            WHERE consumer.search_target_id IS NOT NULL \
            UNION \
            SELECT lineage.child_kind, lineage.child_id \
            FROM data_lineage_edges AS lineage \
            JOIN matched AS parent \
              ON parent.resource_kind = lineage.parent_kind \
             AND parent.resource_id = lineage.parent_id \
            WHERE lineage.tenant_id = $1\
         ) \
         INSERT INTO deletion_resource_matches (\
            tenant_id, deletion_request_id, resource_kind, resource_id, hidden_at\
         ) \
         SELECT $1, $2, resource_kind, resource_id, clock_timestamp() \
         FROM matched \
         WHERE resource_kind IN (\
            'observation', 'evidence_capsule', 'assertion', \
            'regional_assertion', 'search_event', 'watch_run_target', \
            'transition', 'notification_delivery', 'probe_job', 'search_target'\
         ) \
         ON CONFLICT DO NOTHING",
    )
    .bind(tenant_id)
    .bind(deletion_request_id)
    .bind(site_ids)
    .bind(usernames)
    .execute(&mut **transaction)
    .await
    .map_err(|_| TargetDeletionOperatorError::DatabaseUnavailable)?;
    Ok(())
}

async fn cancel_matched_deliveries(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    deletion_request_id: Uuid,
) -> Result<(), TargetDeletionOperatorError> {
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
    .map_err(|_| TargetDeletionOperatorError::DatabaseUnavailable)?;
    Ok(())
}

async fn insert_tasks(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    deletion_request_id: Uuid,
) -> Result<(), TargetDeletionOperatorError> {
    for store_kind in ["primary", "analytics", "backup"] {
        sqlx::query(
            "INSERT INTO deletion_tasks (\
                id, tenant_id, deletion_request_id, store_kind, state, \
                deadline_at, available_at\
             ) VALUES (\
                $1, $2, $3, $4, 'pending', \
                (SELECT CASE $4 \
                    WHEN 'primary' THEN primary_delete_by \
                    WHEN 'analytics' THEN derived_rebuild_by \
                    WHEN 'backup' THEN backup_expiry_by \
                 END FROM deletion_requests \
                 WHERE tenant_id = $2 AND id = $3), \
                clock_timestamp()\
             )",
        )
        .bind(Uuid::new_v4())
        .bind(tenant_id)
        .bind(deletion_request_id)
        .bind(store_kind)
        .execute(&mut **transaction)
        .await
        .map_err(|_| TargetDeletionOperatorError::DatabaseUnavailable)?;
    }
    Ok(())
}

fn read_input(
    reader: impl Read,
) -> Result<VerifiedTargetDeletionInput, TargetDeletionOperatorError> {
    let mut bytes = Vec::new();
    reader
        .take(MAXIMUM_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| TargetDeletionOperatorError::InvalidInput)?;
    if bytes.is_empty()
        || u64::try_from(bytes.len()).map_or(true, |length| length > MAXIMUM_INPUT_BYTES)
    {
        return Err(TargetDeletionOperatorError::InvalidInput);
    }
    serde_json::from_slice(&bytes).map_err(|_| TargetDeletionOperatorError::InvalidInput)
}

fn validate_input(
    input: &mut VerifiedTargetDeletionInput,
) -> Result<(), TargetDeletionOperatorError> {
    if input.schema != INPUT_SCHEMA
        || input.verification_reference.is_empty()
        || input.verification_reference.len() > 256
        || input.verification_reference.chars().any(char::is_control)
        || !(1..=MAXIMUM_SELECTORS).contains(&input.selectors.len())
    {
        return Err(TargetDeletionOperatorError::InvalidInput);
    }
    for selector in &input.selectors {
        let mut site_characters = selector.site_id.chars();
        if selector.site_id.len() > 64
            || !matches!(site_characters.next(), Some('a'..='z' | '0'..='9'))
            || !site_characters.all(|character| matches!(character, 'a'..='z' | '0'..='9' | '-'))
            || selector.site_id.ends_with('-')
            || !(1..=256).contains(&selector.normalized_username.len())
            || selector.normalized_username.chars().any(char::is_control)
        {
            return Err(TargetDeletionOperatorError::InvalidInput);
        }
    }
    input.selectors.sort();
    input.selectors.dedup();
    Ok(())
}

fn request_selector_token(
    key: &[u8; 32],
    tenant_id: Uuid,
    selectors: &[TargetDeletionSelector],
) -> Result<[u8; 32], TargetDeletionOperatorError> {
    let mut hmac = HmacSha256::new_from_slice(key)
        .map_err(|_| TargetDeletionOperatorError::CryptographicFailure)?;
    for field in [
        b"socialname:target-deletion-request:v1".as_slice(),
        tenant_id.as_bytes(),
    ] {
        update_framed_hmac(&mut hmac, field)?;
    }
    for selector in selectors {
        update_framed_hmac(&mut hmac, selector.site_id.as_bytes())?;
        update_framed_hmac(&mut hmac, selector.normalized_username.as_bytes())?;
    }
    Ok(hmac.finalize().into_bytes().into())
}

fn update_framed_hmac(
    hmac: &mut HmacSha256,
    field: &[u8],
) -> Result<(), TargetDeletionOperatorError> {
    let length =
        u64::try_from(field.len()).map_err(|_| TargetDeletionOperatorError::InvalidInput)?;
    hmac.update(&length.to_be_bytes());
    hmac.update(field);
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum TargetDeletionOperatorError {
    #[error("target deletion requires an external verification acknowledgement")]
    VerificationNotAcknowledged,
    #[error("target deletion configuration is invalid")]
    InvalidConfiguration,
    #[error("target deletion input is invalid")]
    InvalidInput,
    #[error("target deletion matches exceed the bounded workflow")]
    TooManyMatches,
    #[error("target deletion cryptographic operation failed")]
    CryptographicFailure,
    #[error("target deletion database is unavailable")]
    DatabaseUnavailable,
    #[error("target deletion storage invariant failed")]
    StorageInvariant,
    #[error(transparent)]
    Database(#[from] DatabaseError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_validation_is_canonical_and_private() {
        let mut input = VerifiedTargetDeletionInput {
            schema: INPUT_SCHEMA.to_owned(),
            verification_reference: "opaque-case-1".to_owned(),
            selectors: vec![
                TargetDeletionSelector {
                    site_id: "github".to_owned(),
                    normalized_username: "alice".to_owned(),
                },
                TargetDeletionSelector {
                    site_id: "github".to_owned(),
                    normalized_username: "alice".to_owned(),
                },
            ],
        };
        validate_input(&mut input).unwrap();
        assert_eq!(input.selectors.len(), 1);
        let token = request_selector_token(&[7; 32], Uuid::nil(), &input.selectors).unwrap();
        assert!(!hex::encode(token).contains("alice"));
    }

    #[test]
    fn bounded_reader_rejects_unknown_fields() {
        let input = br#"{"schema":"socialname.dev/verified-target-deletion/v1","verification_reference":"case","selectors":[],"target":"private"}"#;
        assert!(read_input(input.as_slice()).is_err());
    }
}
