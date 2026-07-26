use std::{env, fmt, future::Future, pin::Pin, time::Duration};

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, Generate, KeyInit, Payload},
};
use hmac::{Hmac, Mac};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use socialname_engine::{
    ManagedEmailGatewayClient, ManagedEmailGatewayError,
    ManagedEmailGatewayRequest as EngineEmailGatewayRequest, ManagedWebhookClient,
    ManagedWebhookError, ManagedWebhookRequest as EngineWebhookRequest,
};
use socialname_protocol::{
    AccountState, ConfirmationBasis, EmailAddress, EmailNotification, HttpsUrl, MeasurementState,
    NotificationChannel, NotificationDeliveryId, ObservationId, ProtocolVersion, RegionClass,
    RuleHash, SiteId, Target, Transition, TransitionChange, TransitionConfirmation, TransitionId,
    Username, Validate, WatchId, WebhookNotification,
};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::job::{JobError, connect_worker_pool_from_env, database_now_ms, set_tenant};

pub const ENDPOINT_ENCRYPTION_KEY_ID_ENV: &str = "SOCIALNAME_ENDPOINT_ENCRYPTION_KEY_ID";
pub const ENDPOINT_ENCRYPTION_KEY_HEX_ENV: &str = "SOCIALNAME_ENDPOINT_ENCRYPTION_KEY_HEX";
pub const WEBHOOK_SIGNING_KEY_ID_ENV: &str = "SOCIALNAME_WEBHOOK_SIGNING_KEY_ID";
pub const WEBHOOK_SIGNING_KEY_HEX_ENV: &str = "SOCIALNAME_WEBHOOK_SIGNING_KEY_HEX";
pub const EMAIL_GATEWAY_URL_ENV: &str = "SOCIALNAME_EMAIL_GATEWAY_URL";
pub const EMAIL_GATEWAY_TOKEN_ENV: &str = "SOCIALNAME_EMAIL_GATEWAY_TOKEN";
pub const EMAIL_FROM_ENV: &str = "SOCIALNAME_EMAIL_FROM";

const DESTINATION_ENVELOPE_VERSION: u8 = 1;
const DESTINATION_NONCE_BYTES: usize = 24;
const DESTINATION_TAG_BYTES: usize = 16;
const MINIMUM_LEASE_MS: u64 = 1_000;
const MAXIMUM_LEASE_MS: u64 = 30_000;
const MAXIMUM_ATTEMPTS: u32 = 10;
const INITIAL_RETRY_DELAY_MS: i64 = 5_000;
const MAXIMUM_RETRY_DELAY_MS: i64 = 15 * 60 * 1_000;
const MAXIMUM_WEBHOOK_BODY_BYTES: usize = 32 * 1_024;
const MAXIMUM_EMAIL_BODY_BYTES: usize = 32 * 1_024;

type HmacSha256 = Hmac<Sha256>;

pub struct DeliverySecrets {
    endpoint_encryption_key_id: String,
    endpoint_encryption_key: Zeroizing<[u8; 32]>,
    webhook_signing_key_id: Option<String>,
    webhook_signing_key: Option<Zeroizing<[u8; 32]>>,
}

impl fmt::Debug for DeliverySecrets {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeliverySecrets([REDACTED])")
    }
}

impl DeliverySecrets {
    pub fn from_env() -> Result<Self, DeliveryError> {
        let endpoint_encryption_key_id = required_env(ENDPOINT_ENCRYPTION_KEY_ID_ENV)?;
        let endpoint_encryption_key_hex =
            Zeroizing::new(required_env(ENDPOINT_ENCRYPTION_KEY_HEX_ENV)?);
        let endpoint_encryption_key = parse_secret_key(&endpoint_encryption_key_hex)?;
        let webhook_signing_key_id = required_env(WEBHOOK_SIGNING_KEY_ID_ENV)?;
        let webhook_signing_key_hex = Zeroizing::new(required_env(WEBHOOK_SIGNING_KEY_HEX_ENV)?);
        let webhook_signing_key = parse_secret_key(&webhook_signing_key_hex)?;
        Self::new(
            endpoint_encryption_key_id,
            endpoint_encryption_key,
            webhook_signing_key_id,
            webhook_signing_key,
        )
    }

    pub fn new(
        endpoint_encryption_key_id: impl Into<String>,
        endpoint_encryption_key: [u8; 32],
        webhook_signing_key_id: impl Into<String>,
        webhook_signing_key: [u8; 32],
    ) -> Result<Self, DeliveryError> {
        let endpoint_encryption_key_id = endpoint_encryption_key_id.into();
        let webhook_signing_key_id = webhook_signing_key_id.into();
        let endpoint_encryption_key = Zeroizing::new(endpoint_encryption_key);
        let webhook_signing_key = Zeroizing::new(webhook_signing_key);
        if !valid_key_id(&endpoint_encryption_key_id) || !valid_key_id(&webhook_signing_key_id) {
            return Err(DeliveryError::InvalidConfiguration);
        }
        Ok(Self {
            endpoint_encryption_key_id,
            endpoint_encryption_key,
            webhook_signing_key_id: Some(webhook_signing_key_id),
            webhook_signing_key: Some(webhook_signing_key),
        })
    }

    pub fn from_email_env() -> Result<Self, DeliveryError> {
        let endpoint_encryption_key_id = required_env(ENDPOINT_ENCRYPTION_KEY_ID_ENV)?;
        let endpoint_encryption_key_hex =
            Zeroizing::new(required_env(ENDPOINT_ENCRYPTION_KEY_HEX_ENV)?);
        let endpoint_encryption_key = parse_secret_key(&endpoint_encryption_key_hex)?;
        Self::new_email(endpoint_encryption_key_id, endpoint_encryption_key)
    }

    pub fn new_email(
        endpoint_encryption_key_id: impl Into<String>,
        endpoint_encryption_key: [u8; 32],
    ) -> Result<Self, DeliveryError> {
        let endpoint_encryption_key_id = endpoint_encryption_key_id.into();
        if !valid_key_id(&endpoint_encryption_key_id) {
            return Err(DeliveryError::InvalidConfiguration);
        }
        Ok(Self {
            endpoint_encryption_key_id,
            endpoint_encryption_key: Zeroizing::new(endpoint_encryption_key),
            webhook_signing_key_id: None,
            webhook_signing_key: None,
        })
    }

    pub fn seal_destination(
        &self,
        tenant_id: Uuid,
        endpoint_id: Uuid,
        destination: &str,
    ) -> Result<Vec<u8>, DeliveryError> {
        HttpsUrl::new(destination.to_owned()).map_err(|_| DeliveryError::InvalidDestination)?;
        let nonce = XNonce::generate();
        let cipher = XChaCha20Poly1305::new_from_slice(self.endpoint_encryption_key.as_ref())
            .map_err(|_| DeliveryError::InvalidConfiguration)?;
        let aad = destination_aad(tenant_id, endpoint_id, &self.endpoint_encryption_key_id);
        let encrypted = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: destination.as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|_| DeliveryError::CryptographicFailure)?;
        let mut envelope = Vec::with_capacity(1 + DESTINATION_NONCE_BYTES + encrypted.len());
        envelope.push(DESTINATION_ENVELOPE_VERSION);
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&encrypted);
        if envelope.len() > 8_192 {
            return Err(DeliveryError::InvalidDestination);
        }
        Ok(envelope)
    }

    pub fn seal_email_destination(
        &self,
        tenant_id: Uuid,
        endpoint_id: Uuid,
        destination: &str,
    ) -> Result<Vec<u8>, DeliveryError> {
        EmailAddress::new(destination.to_owned()).map_err(|_| DeliveryError::InvalidDestination)?;
        self.seal_for_domain(
            tenant_id,
            endpoint_id,
            destination,
            b"socialname/email-destination/v1",
        )
    }

    fn open_destination(
        &self,
        tenant_id: Uuid,
        endpoint_id: Uuid,
        encryption_key_id: &str,
        envelope: &[u8],
    ) -> Result<Zeroizing<String>, DeliveryError> {
        if encryption_key_id != self.endpoint_encryption_key_id
            || envelope.len() < 1 + DESTINATION_NONCE_BYTES + DESTINATION_TAG_BYTES
            || envelope.len() > 8_192
            || envelope.first().copied() != Some(DESTINATION_ENVELOPE_VERSION)
        {
            return Err(DeliveryError::CryptographicFailure);
        }
        let nonce = XNonce::try_from(&envelope[1..1 + DESTINATION_NONCE_BYTES])
            .map_err(|_| DeliveryError::CryptographicFailure)?;
        let cipher = XChaCha20Poly1305::new_from_slice(self.endpoint_encryption_key.as_ref())
            .map_err(|_| DeliveryError::InvalidConfiguration)?;
        let aad = destination_aad(tenant_id, endpoint_id, encryption_key_id);
        let plaintext = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &envelope[1 + DESTINATION_NONCE_BYTES..],
                    aad: &aad,
                },
            )
            .map_err(|_| DeliveryError::CryptographicFailure)?;
        let destination = Zeroizing::new(
            String::from_utf8(plaintext).map_err(|_| DeliveryError::CryptographicFailure)?,
        );
        HttpsUrl::new(destination.as_str().to_owned())
            .map_err(|_| DeliveryError::InvalidDestination)?;
        Ok(destination)
    }

    fn open_email_destination(
        &self,
        tenant_id: Uuid,
        endpoint_id: Uuid,
        encryption_key_id: &str,
        envelope: &[u8],
    ) -> Result<Zeroizing<String>, DeliveryError> {
        let destination = self.open_for_domain(
            tenant_id,
            endpoint_id,
            encryption_key_id,
            envelope,
            b"socialname/email-destination/v1",
        )?;
        EmailAddress::new(destination.as_str().to_owned())
            .map_err(|_| DeliveryError::InvalidDestination)?;
        Ok(destination)
    }

    fn seal_for_domain(
        &self,
        tenant_id: Uuid,
        endpoint_id: Uuid,
        destination: &str,
        domain: &[u8],
    ) -> Result<Vec<u8>, DeliveryError> {
        let nonce = XNonce::generate();
        let cipher = XChaCha20Poly1305::new_from_slice(self.endpoint_encryption_key.as_ref())
            .map_err(|_| DeliveryError::InvalidConfiguration)?;
        let aad = destination_aad_for_domain(
            tenant_id,
            endpoint_id,
            &self.endpoint_encryption_key_id,
            domain,
        );
        let encrypted = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: destination.as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|_| DeliveryError::CryptographicFailure)?;
        let mut envelope = Vec::with_capacity(1 + DESTINATION_NONCE_BYTES + encrypted.len());
        envelope.push(DESTINATION_ENVELOPE_VERSION);
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&encrypted);
        if envelope.len() > 8_192 {
            return Err(DeliveryError::InvalidDestination);
        }
        Ok(envelope)
    }

    fn open_for_domain(
        &self,
        tenant_id: Uuid,
        endpoint_id: Uuid,
        encryption_key_id: &str,
        envelope: &[u8],
        domain: &[u8],
    ) -> Result<Zeroizing<String>, DeliveryError> {
        if encryption_key_id != self.endpoint_encryption_key_id
            || envelope.len() < 1 + DESTINATION_NONCE_BYTES + DESTINATION_TAG_BYTES
            || envelope.len() > 8_192
            || envelope.first().copied() != Some(DESTINATION_ENVELOPE_VERSION)
        {
            return Err(DeliveryError::CryptographicFailure);
        }
        let nonce = XNonce::try_from(&envelope[1..1 + DESTINATION_NONCE_BYTES])
            .map_err(|_| DeliveryError::CryptographicFailure)?;
        let cipher = XChaCha20Poly1305::new_from_slice(self.endpoint_encryption_key.as_ref())
            .map_err(|_| DeliveryError::InvalidConfiguration)?;
        let aad = destination_aad_for_domain(tenant_id, endpoint_id, encryption_key_id, domain);
        let plaintext = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &envelope[1 + DESTINATION_NONCE_BYTES..],
                    aad: &aad,
                },
            )
            .map_err(|_| DeliveryError::CryptographicFailure)?;
        Ok(Zeroizing::new(
            String::from_utf8(plaintext).map_err(|_| DeliveryError::CryptographicFailure)?,
        ))
    }

    fn signature(
        &self,
        delivery_id: Uuid,
        timestamp_unix_ms: i64,
        body: &[u8],
    ) -> Result<String, DeliveryError> {
        if timestamp_unix_ms <= 0 {
            return Err(DeliveryError::InvalidConfiguration);
        }
        let signing_key = self
            .webhook_signing_key
            .as_ref()
            .ok_or(DeliveryError::InvalidConfiguration)?;
        let mut mac = HmacSha256::new_from_slice(signing_key.as_ref())
            .map_err(|_| DeliveryError::InvalidConfiguration)?;
        mac.update(timestamp_unix_ms.to_string().as_bytes());
        mac.update(b".");
        mac.update(delivery_id.to_string().as_bytes());
        mac.update(b".");
        mac.update(body);
        Ok(format!("v1={}", hex::encode(mac.finalize().into_bytes())))
    }
}

pub struct EmailGatewayConfig {
    gateway: String,
    bearer_token: Zeroizing<String>,
    from: String,
}

impl fmt::Debug for EmailGatewayConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EmailGatewayConfig([REDACTED])")
    }
}

impl EmailGatewayConfig {
    pub fn from_env() -> Result<Self, DeliveryError> {
        Self::new(
            required_env(EMAIL_GATEWAY_URL_ENV)?,
            required_env(EMAIL_GATEWAY_TOKEN_ENV)?,
            required_env(EMAIL_FROM_ENV)?,
        )
    }

    pub fn new(
        gateway: impl Into<String>,
        bearer_token: impl Into<String>,
        from: impl Into<String>,
    ) -> Result<Self, DeliveryError> {
        let gateway = gateway.into();
        let bearer_token = Zeroizing::new(bearer_token.into());
        let from = from.into();
        HttpsUrl::new(gateway.clone()).map_err(|_| DeliveryError::InvalidConfiguration)?;
        ManagedEmailGatewayClient::validate_gateway(&gateway)
            .map_err(|_| DeliveryError::InvalidConfiguration)?;
        EmailAddress::new(from.clone()).map_err(|_| DeliveryError::InvalidConfiguration)?;
        if !(1..=4_096).contains(&bearer_token.len())
            || !bearer_token.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(DeliveryError::InvalidConfiguration);
        }
        Ok(Self {
            gateway,
            bearer_token,
            from,
        })
    }
}

#[derive(Clone)]
pub struct DeliveryStore {
    pool: PgPool,
}

impl fmt::Debug for DeliveryStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeliveryStore([REDACTED DATABASE])")
    }
}

impl DeliveryStore {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn connect_from_env() -> Result<Self, DeliveryError> {
        connect_worker_pool_from_env()
            .await
            .map(Self::new)
            .map_err(DeliveryError::from_job)
    }

    pub async fn close(&self) {
        self.pool.close().await;
    }

    pub async fn claim(
        &self,
        worker_id: &str,
        lease: Duration,
        maximum_attempts: u32,
    ) -> Result<Option<DeliveryClaim>, DeliveryError> {
        self.claim_for_channel(
            NotificationChannel::Webhook,
            worker_id,
            lease,
            maximum_attempts,
        )
        .await
    }

    pub async fn claim_email(
        &self,
        worker_id: &str,
        lease: Duration,
        maximum_attempts: u32,
    ) -> Result<Option<DeliveryClaim>, DeliveryError> {
        self.claim_for_channel(
            NotificationChannel::Email,
            worker_id,
            lease,
            maximum_attempts,
        )
        .await
    }

    async fn claim_for_channel(
        &self,
        channel: NotificationChannel,
        worker_id: &str,
        lease: Duration,
        maximum_attempts: u32,
    ) -> Result<Option<DeliveryClaim>, DeliveryError> {
        validate_process_limits(worker_id, lease, maximum_attempts)?;
        let lease_ms =
            u64::try_from(lease.as_millis()).map_err(|_| DeliveryError::InvalidConfiguration)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| DeliveryError::DatabaseUnavailable)?;
        let claim_query = match channel {
            NotificationChannel::Webhook => {
                "SELECT tenant_id, notification_delivery_id, attempt_count \
                 FROM socialname_worker_claim_webhook_delivery($1, $2, $3)"
            }
            NotificationChannel::Email => {
                "SELECT tenant_id, notification_delivery_id, attempt_count \
                 FROM socialname_worker_claim_email_delivery($1, $2, $3)"
            }
        };
        let coordinate: Option<ClaimCoordinate> = sqlx::query_as(claim_query)
            .bind(worker_id)
            .bind(i32::try_from(lease_ms).map_err(|_| DeliveryError::InvalidConfiguration)?)
            .bind(i32::try_from(maximum_attempts).map_err(|_| DeliveryError::InvalidConfiguration)?)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| DeliveryError::DatabaseUnavailable)?;
        let Some(coordinate) = coordinate else {
            transaction
                .commit()
                .await
                .map_err(|_| DeliveryError::DatabaseUnavailable)?;
            return Ok(None);
        };
        set_tenant(&mut transaction, coordinate.tenant_id)
            .await
            .map_err(DeliveryError::from_job)?;
        let row: ClaimedDeliveryRow = sqlx::query_as(
            "SELECT delivery.id, delivery.endpoint_id, endpoint.channel AS endpoint_channel, \
                    endpoint.destination_ciphertext, endpoint.encryption_key_id, \
                    transition.id AS transition_id, watch.id AS watch_id, \
                    target.normalized_username, target.site_id, \
                    transition.transition_class, transition.from_state, \
                    transition.to_state, transition.region_class, \
                    CASE WHEN version.rule_hash IS NULL THEN NULL \
                         ELSE encode(version.rule_hash, 'hex') END AS rule_hash, \
                    transition.confirmation_basis, \
                    (extract(epoch FROM transition.detected_at) * 1000)::bigint \
                        AS detected_at_unix_ms \
             FROM notification_deliveries AS delivery \
             JOIN notification_endpoints AS endpoint \
               ON endpoint.tenant_id = delivery.tenant_id \
              AND endpoint.id = delivery.endpoint_id \
             JOIN transitions AS transition \
               ON transition.tenant_id = delivery.tenant_id \
              AND transition.id = delivery.transition_id \
             JOIN watch_targets AS target \
               ON target.tenant_id = transition.tenant_id \
              AND target.id = transition.watch_target_id \
             JOIN watches AS watch \
               ON watch.tenant_id = target.tenant_id \
              AND watch.id = target.watch_id \
             LEFT JOIN rule_versions AS version \
               ON version.id = transition.rule_version_id \
             WHERE delivery.tenant_id = $1 AND delivery.id = $2 \
               AND delivery.state = 'delivering' \
               AND delivery.attempt_count = $3 \
               AND delivery.lease_owner = $4 \
               AND delivery.lease_expires_at > clock_timestamp()",
        )
        .bind(coordinate.tenant_id)
        .bind(coordinate.notification_delivery_id)
        .bind(coordinate.attempt_count)
        .bind(worker_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| DeliveryError::StorageInvariant)?;
        if notification_channel(&row.endpoint_channel)? != channel {
            return Err(DeliveryError::StorageInvariant);
        }
        let supporting_observation_ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT observation_id \
             FROM transition_basis \
             WHERE tenant_id = $1 AND transition_id = $2 \
             ORDER BY observation_id",
        )
        .bind(coordinate.tenant_id)
        .bind(row.transition_id)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| DeliveryError::StorageInvariant)?;
        attach_attempt_lineage(
            &mut transaction,
            coordinate.tenant_id,
            coordinate.notification_delivery_id,
            channel,
        )
        .await?;
        let transition = protocol_transition(&row, supporting_observation_ids)?;
        let delivery_id = NotificationDeliveryId::new(row.id.to_string())
            .map_err(|_| DeliveryError::StorageInvariant)?;
        let body = match channel {
            NotificationChannel::Webhook => serde_json::to_vec(
                &WebhookNotification::for_confirmed_transition(delivery_id, transition)
                    .map_err(|_| DeliveryError::StorageInvariant)?,
            ),
            NotificationChannel::Email => serde_json::to_vec(
                &EmailNotification::for_confirmed_transition(delivery_id, transition)
                    .map_err(|_| DeliveryError::StorageInvariant)?,
            ),
        }
        .map_err(|_| DeliveryError::StorageInvariant)?;
        let maximum_body_bytes = match channel {
            NotificationChannel::Webhook => MAXIMUM_WEBHOOK_BODY_BYTES,
            NotificationChannel::Email => MAXIMUM_EMAIL_BODY_BYTES,
        };
        if !(1..=maximum_body_bytes).contains(&body.len()) {
            return Err(DeliveryError::StorageInvariant);
        }
        transaction
            .commit()
            .await
            .map_err(|_| DeliveryError::DatabaseUnavailable)?;
        Ok(Some(DeliveryClaim {
            tenant_id: coordinate.tenant_id,
            delivery_id: row.id,
            endpoint_id: row.endpoint_id,
            channel,
            attempt_count: u32::try_from(coordinate.attempt_count)
                .map_err(|_| DeliveryError::StorageInvariant)?,
            worker_id: worker_id.to_owned(),
            destination_ciphertext: row.destination_ciphertext,
            encryption_key_id: row.encryption_key_id,
            body,
        }))
    }

    pub async fn record_send_result(
        &self,
        claim: &DeliveryClaim,
        result: Result<u16, WebhookSendError>,
        maximum_attempts: u32,
    ) -> Result<DeliveryProcessOutcome, DeliveryError> {
        if claim.channel != NotificationChannel::Webhook {
            return Err(DeliveryError::StorageInvariant);
        }
        let request_body_sha256: [u8; 32] = Sha256::digest(&claim.body).into();
        self.record(
            claim,
            DeliveryAttemptOutcome::from_send_result(result),
            maximum_attempts,
            request_body_sha256,
        )
        .await
    }

    pub async fn record_email_send_result(
        &self,
        claim: &DeliveryClaim,
        result: Result<u16, EmailSendError>,
        maximum_attempts: u32,
    ) -> Result<DeliveryProcessOutcome, DeliveryError> {
        if claim.channel != NotificationChannel::Email {
            return Err(DeliveryError::StorageInvariant);
        }
        let request_body_sha256: [u8; 32] = Sha256::digest(&claim.body).into();
        self.record(
            claim,
            DeliveryAttemptOutcome::from_email_send_result(result),
            maximum_attempts,
            request_body_sha256,
        )
        .await
    }

    async fn record(
        &self,
        claim: &DeliveryClaim,
        outcome: DeliveryAttemptOutcome,
        maximum_attempts: u32,
        request_body_sha256: [u8; 32],
    ) -> Result<DeliveryProcessOutcome, DeliveryError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| DeliveryError::DatabaseUnavailable)?;
        set_tenant(&mut transaction, claim.tenant_id)
            .await
            .map_err(DeliveryError::from_job)?;
        let locked: LockedDelivery = sqlx::query_as(
            "SELECT delivery.state, delivery.attempt_count, \
                    delivery.lease_owner, \
                    COALESCE(delivery.lease_expires_at > clock_timestamp(), false) \
                        AS lease_is_current, \
                    endpoint.state AS endpoint_state, endpoint.channel AS endpoint_channel \
             FROM notification_deliveries AS delivery \
             JOIN notification_endpoints AS endpoint \
               ON endpoint.tenant_id = delivery.tenant_id \
              AND endpoint.id = delivery.endpoint_id \
             WHERE delivery.tenant_id = $1 AND delivery.id = $2 \
             FOR UPDATE OF delivery",
        )
        .bind(claim.tenant_id)
        .bind(claim.delivery_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| DeliveryError::StorageInvariant)?;
        let attempt_count =
            u32::try_from(locked.attempt_count).map_err(|_| DeliveryError::StorageInvariant)?;
        if locked.state != "delivering"
            || attempt_count != claim.attempt_count
            || locked.lease_owner.as_deref() != Some(claim.worker_id.as_str())
            || !locked.lease_is_current
            || notification_channel(&locked.endpoint_channel)? != claim.channel
        {
            return Err(DeliveryError::StaleLease);
        }
        let completed_at_unix_ms = database_now_ms(&mut transaction)
            .await
            .map_err(DeliveryError::from_job)?;
        let persisted = if locked.endpoint_state != "active" {
            PersistedAttempt {
                state: "cancelled",
                event_kind: "cancelled",
                error_code: Some("endpoint_disabled"),
                http_status: outcome.http_status(),
                next_attempt_at_unix_ms: None,
            }
        } else {
            persisted_outcome(
                outcome,
                claim.attempt_count,
                maximum_attempts,
                completed_at_unix_ms,
            )?
        };
        let affected = sqlx::query(
            "UPDATE notification_deliveries \
             SET state = $3, next_attempt_at = \
                    CASE WHEN $4::bigint IS NULL THEN NULL \
                         ELSE to_timestamp($4::double precision / 1000.0) END, \
                 delivered_at = \
                    CASE WHEN $3 = 'delivered' \
                         THEN to_timestamp($5::double precision / 1000.0) \
                         ELSE NULL END, \
                 last_error_code = $6, \
                 lease_owner = NULL, lease_started_at = NULL, \
                 lease_expires_at = NULL \
             WHERE tenant_id = $1 AND id = $2 \
               AND state = 'delivering' AND attempt_count = $7 \
               AND lease_owner = $8",
        )
        .bind(claim.tenant_id)
        .bind(claim.delivery_id)
        .bind(persisted.state)
        .bind(persisted.next_attempt_at_unix_ms)
        .bind(completed_at_unix_ms)
        .bind(persisted.error_code)
        .bind(i32::try_from(claim.attempt_count).map_err(|_| DeliveryError::StorageInvariant)?)
        .bind(&claim.worker_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| DeliveryError::StorageInvariant)?
        .rows_affected();
        if affected != 1 {
            return Err(DeliveryError::StaleLease);
        }
        let attempt_event_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO notification_delivery_attempts (\
                id, tenant_id, delivery_id, attempt_number, event_kind, \
                worker_id, http_status, error_code, request_body_sha256, \
                occurred_at\
             ) VALUES (\
                $1, $2, $3, $4, $5, $6, $7, $8, $9, \
                to_timestamp($10::double precision / 1000.0)\
             )",
        )
        .bind(attempt_event_id)
        .bind(claim.tenant_id)
        .bind(claim.delivery_id)
        .bind(i32::try_from(claim.attempt_count).map_err(|_| DeliveryError::StorageInvariant)?)
        .bind(persisted.event_kind)
        .bind(&claim.worker_id)
        .bind(persisted.http_status.map(i32::from))
        .bind(persisted.error_code)
        .bind(request_body_sha256.to_vec())
        .bind(completed_at_unix_ms)
        .execute(&mut *transaction)
        .await
        .map_err(|_| DeliveryError::StorageInvariant)?;
        insert_lineage(
            &mut transaction,
            claim.tenant_id,
            "notification_delivery",
            claim.delivery_id,
            "notification_delivery_attempt",
            attempt_event_id,
            attempt_lineage_purpose(claim.channel),
        )
        .await?;
        insert_audit(
            &mut transaction,
            claim.tenant_id,
            match persisted.state {
                "delivered" => "notification.delivery.delivered",
                "retry_scheduled" => "notification.delivery.retry_scheduled",
                "permanently_failed" => "notification.delivery.permanently_failed",
                "cancelled" => "notification.delivery.cancelled",
                _ => return Err(DeliveryError::StorageInvariant),
            },
            claim.delivery_id,
            json!({
                "channel": notification_channel_name(claim.channel),
                "attempt": claim.attempt_count,
                "error_code": persisted.error_code,
                "http_status": persisted.http_status,
            }),
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| DeliveryError::DatabaseUnavailable)?;
        Ok(match persisted.state {
            "delivered" => DeliveryProcessOutcome::Delivered {
                delivery_id: claim.delivery_id,
                attempt_count: claim.attempt_count,
            },
            "retry_scheduled" => DeliveryProcessOutcome::RetryScheduled {
                delivery_id: claim.delivery_id,
                attempt_count: claim.attempt_count,
            },
            "permanently_failed" => DeliveryProcessOutcome::PermanentlyFailed {
                delivery_id: claim.delivery_id,
                attempt_count: claim.attempt_count,
            },
            "cancelled" => DeliveryProcessOutcome::Cancelled {
                delivery_id: claim.delivery_id,
                attempt_count: claim.attempt_count,
            },
            _ => return Err(DeliveryError::StorageInvariant),
        })
    }
}

pub struct DeliveryClaim {
    tenant_id: Uuid,
    delivery_id: Uuid,
    endpoint_id: Uuid,
    channel: NotificationChannel,
    attempt_count: u32,
    worker_id: String,
    destination_ciphertext: Vec<u8>,
    encryption_key_id: String,
    body: Vec<u8>,
}

impl fmt::Debug for DeliveryClaim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeliveryClaim")
            .field("delivery_id", &self.delivery_id)
            .field("attempt_count", &self.attempt_count)
            .field("channel", &self.channel)
            .field("destination", &"[REDACTED]")
            .finish()
    }
}

impl DeliveryClaim {
    #[must_use]
    pub const fn delivery_id(&self) -> Uuid {
        self.delivery_id
    }

    #[must_use]
    pub const fn attempt_count(&self) -> u32 {
        self.attempt_count
    }

    fn prepare(
        &self,
        secrets: &DeliverySecrets,
        timestamp_unix_ms: i64,
    ) -> Result<WebhookRequest, DeliveryError> {
        if self.channel != NotificationChannel::Webhook {
            return Err(DeliveryError::StorageInvariant);
        }
        let destination = secrets.open_destination(
            self.tenant_id,
            self.endpoint_id,
            &self.encryption_key_id,
            &self.destination_ciphertext,
        )?;
        let signature = secrets.signature(self.delivery_id, timestamp_unix_ms, &self.body)?;
        Ok(WebhookRequest {
            destination,
            delivery_id: self.delivery_id.to_string(),
            timestamp_unix_ms,
            signature,
            signing_key_id: secrets
                .webhook_signing_key_id
                .clone()
                .ok_or(DeliveryError::InvalidConfiguration)?,
            attempt_count: self.attempt_count,
            body: self.body.clone(),
        })
    }

    fn prepare_email(
        &self,
        secrets: &DeliverySecrets,
        gateway: &EmailGatewayConfig,
    ) -> Result<EmailRequest, DeliveryError> {
        if self.channel != NotificationChannel::Email {
            return Err(DeliveryError::StorageInvariant);
        }
        let destination = secrets.open_email_destination(
            self.tenant_id,
            self.endpoint_id,
            &self.encryption_key_id,
            &self.destination_ciphertext,
        )?;
        let payload: EmailNotification =
            serde_json::from_slice(&self.body).map_err(|_| DeliveryError::StorageInvariant)?;
        payload
            .validate()
            .map_err(|_| DeliveryError::StorageInvariant)?;
        let (subject, text) = render_email_message(&payload)?;
        let gateway_body = serde_json::to_vec(&EmailGatewayBody {
            schema: "socialname.dev/email-gateway/v1",
            delivery_id: self.delivery_id.to_string(),
            from: gateway.from.clone(),
            to: destination.as_str().to_owned(),
            subject,
            text,
        })
        .map_err(|_| DeliveryError::StorageInvariant)?;
        if !(1..=MAXIMUM_EMAIL_BODY_BYTES).contains(&gateway_body.len()) {
            return Err(DeliveryError::StorageInvariant);
        }
        Ok(EmailRequest {
            gateway: Zeroizing::new(gateway.gateway.clone()),
            bearer_token: gateway.bearer_token.clone(),
            delivery_id: self.delivery_id.to_string(),
            attempt_count: self.attempt_count,
            body: Zeroizing::new(gateway_body),
        })
    }
}

pub struct WebhookRequest {
    destination: Zeroizing<String>,
    delivery_id: String,
    timestamp_unix_ms: i64,
    signature: String,
    signing_key_id: String,
    attempt_count: u32,
    body: Vec<u8>,
}

impl fmt::Debug for WebhookRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebhookRequest")
            .field("delivery_id", &self.delivery_id)
            .field("attempt_count", &self.attempt_count)
            .field("destination", &"[REDACTED]")
            .field("signature", &"[REDACTED]")
            .finish()
    }
}

impl WebhookRequest {
    #[must_use]
    pub fn destination(&self) -> &str {
        self.destination.as_str()
    }

    #[must_use]
    pub fn delivery_id(&self) -> &str {
        &self.delivery_id
    }

    #[must_use]
    pub const fn timestamp_unix_ms(&self) -> i64 {
        self.timestamp_unix_ms
    }

    #[must_use]
    pub fn signature(&self) -> &str {
        &self.signature
    }

    #[must_use]
    pub fn signing_key_id(&self) -> &str {
        &self.signing_key_id
    }

    #[must_use]
    pub const fn attempt_count(&self) -> u32 {
        self.attempt_count
    }

    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

pub trait WebhookTransport: Send + Sync {
    fn send<'a>(
        &'a self,
        request: &'a WebhookRequest,
    ) -> Pin<Box<dyn Future<Output = Result<u16, WebhookSendError>> + Send + 'a>>;
}

#[derive(Clone, Debug)]
pub struct ManagedWebhookTransport {
    client: ManagedWebhookClient,
}

impl ManagedWebhookTransport {
    pub fn new(timeout: Duration) -> Result<Self, DeliveryError> {
        ManagedWebhookClient::new(timeout)
            .map(|client| Self { client })
            .map_err(|_| DeliveryError::InvalidConfiguration)
    }
}

impl WebhookTransport for ManagedWebhookTransport {
    fn send<'a>(
        &'a self,
        request: &'a WebhookRequest,
    ) -> Pin<Box<dyn Future<Output = Result<u16, WebhookSendError>> + Send + 'a>> {
        Box::pin(async move {
            self.client
                .post_signed_json(&EngineWebhookRequest {
                    destination: request.destination(),
                    delivery_id: request.delivery_id(),
                    timestamp_unix_ms: request.timestamp_unix_ms(),
                    signature: request.signature(),
                    signing_key_id: request.signing_key_id(),
                    attempt_count: request.attempt_count(),
                    body: request.body(),
                })
                .await
                .map(|response| response.status)
                .map_err(WebhookSendError::from_engine)
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WebhookSendError {
    Timeout,
    Connection,
    Transport,
    DestinationRejected,
    RequestRejected,
}

impl WebhookSendError {
    const fn from_engine(error: ManagedWebhookError) -> Self {
        match error {
            ManagedWebhookError::Timeout => Self::Timeout,
            ManagedWebhookError::Connection => Self::Connection,
            ManagedWebhookError::DestinationRejected => Self::DestinationRejected,
            ManagedWebhookError::RequestRejected | ManagedWebhookError::InvalidConfiguration => {
                Self::RequestRejected
            }
            ManagedWebhookError::Transport => Self::Transport,
        }
    }
}

#[derive(Serialize)]
struct EmailGatewayBody {
    schema: &'static str,
    delivery_id: String,
    from: String,
    to: String,
    subject: &'static str,
    text: String,
}

pub struct EmailRequest {
    gateway: Zeroizing<String>,
    bearer_token: Zeroizing<String>,
    delivery_id: String,
    attempt_count: u32,
    body: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for EmailRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmailRequest")
            .field("delivery_id", &self.delivery_id)
            .field("attempt_count", &self.attempt_count)
            .field("gateway", &"[REDACTED]")
            .field("bearer_token", &"[REDACTED]")
            .field("body", &"[REDACTED]")
            .finish()
    }
}

impl EmailRequest {
    #[must_use]
    pub fn gateway(&self) -> &str {
        self.gateway.as_str()
    }

    #[must_use]
    pub fn bearer_token(&self) -> &str {
        self.bearer_token.as_str()
    }

    #[must_use]
    pub fn delivery_id(&self) -> &str {
        &self.delivery_id
    }

    #[must_use]
    pub const fn attempt_count(&self) -> u32 {
        self.attempt_count
    }

    #[must_use]
    pub fn body(&self) -> &[u8] {
        self.body.as_slice()
    }
}

pub trait EmailGatewayTransport: Send + Sync {
    fn send<'a>(
        &'a self,
        request: &'a EmailRequest,
    ) -> Pin<Box<dyn Future<Output = Result<u16, EmailSendError>> + Send + 'a>>;
}

#[derive(Clone, Debug)]
pub struct ManagedEmailGatewayTransport {
    client: ManagedEmailGatewayClient,
}

impl ManagedEmailGatewayTransport {
    pub fn new(timeout: Duration) -> Result<Self, DeliveryError> {
        ManagedEmailGatewayClient::new(timeout)
            .map(|client| Self { client })
            .map_err(|_| DeliveryError::InvalidConfiguration)
    }
}

impl EmailGatewayTransport for ManagedEmailGatewayTransport {
    fn send<'a>(
        &'a self,
        request: &'a EmailRequest,
    ) -> Pin<Box<dyn Future<Output = Result<u16, EmailSendError>> + Send + 'a>> {
        Box::pin(async move {
            self.client
                .post_json(&EngineEmailGatewayRequest {
                    gateway: request.gateway(),
                    bearer_token: request.bearer_token(),
                    delivery_id: request.delivery_id(),
                    attempt_count: request.attempt_count(),
                    body: request.body(),
                })
                .await
                .map(|response| response.status)
                .map_err(EmailSendError::from_engine)
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmailSendError {
    Timeout,
    Connection,
    Transport,
    DestinationRejected,
    RequestRejected,
}

impl EmailSendError {
    const fn from_engine(error: ManagedEmailGatewayError) -> Self {
        match error {
            ManagedEmailGatewayError::Timeout => Self::Timeout,
            ManagedEmailGatewayError::Connection => Self::Connection,
            ManagedEmailGatewayError::DestinationRejected => Self::DestinationRejected,
            ManagedEmailGatewayError::RequestRejected
            | ManagedEmailGatewayError::InvalidConfiguration => Self::RequestRejected,
            ManagedEmailGatewayError::Transport => Self::Transport,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryProcessOutcome {
    Idle,
    Delivered {
        delivery_id: Uuid,
        attempt_count: u32,
    },
    RetryScheduled {
        delivery_id: Uuid,
        attempt_count: u32,
    },
    PermanentlyFailed {
        delivery_id: Uuid,
        attempt_count: u32,
    },
    Cancelled {
        delivery_id: Uuid,
        attempt_count: u32,
    },
}

pub struct DeliveryProcessConfig<'a> {
    pub worker_id: &'a str,
    pub lease: Duration,
    pub maximum_attempts: u32,
    pub timestamp_unix_ms: i64,
    pub cancellation: &'a CancellationToken,
}

pub async fn process_one_delivery<T>(
    store: &DeliveryStore,
    secrets: &DeliverySecrets,
    transport: &T,
    config: DeliveryProcessConfig<'_>,
) -> Result<DeliveryProcessOutcome, DeliveryError>
where
    T: WebhookTransport,
{
    let Some(claim) = store
        .claim(config.worker_id, config.lease, config.maximum_attempts)
        .await?
    else {
        return Ok(DeliveryProcessOutcome::Idle);
    };
    let request = claim.prepare(secrets, config.timestamp_unix_ms)?;
    let result = tokio::select! {
        biased;
        () = config.cancellation.cancelled() => return Err(DeliveryError::Cancelled),
        result = transport.send(&request) => result,
    };
    store
        .record_send_result(&claim, result, config.maximum_attempts)
        .await
}

pub async fn process_one_email_delivery<T>(
    store: &DeliveryStore,
    secrets: &DeliverySecrets,
    gateway: &EmailGatewayConfig,
    transport: &T,
    config: DeliveryProcessConfig<'_>,
) -> Result<DeliveryProcessOutcome, DeliveryError>
where
    T: EmailGatewayTransport,
{
    let Some(claim) = store
        .claim_email(config.worker_id, config.lease, config.maximum_attempts)
        .await?
    else {
        return Ok(DeliveryProcessOutcome::Idle);
    };
    let request = claim.prepare_email(secrets, gateway)?;
    let result = tokio::select! {
        biased;
        () = config.cancellation.cancelled() => return Err(DeliveryError::Cancelled),
        result = transport.send(&request) => result,
    };
    store
        .record_email_send_result(&claim, result, config.maximum_attempts)
        .await
}

pub(crate) async fn enqueue_confirmed_transition(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    watch_target_id: Uuid,
    transition_id: Uuid,
    confirmation_basis: &str,
) -> Result<(), JobError> {
    let endpoints: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT endpoint.id, endpoint.channel \
         FROM watch_targets AS target \
         JOIN watch_notification_endpoints AS link \
           ON link.tenant_id = target.tenant_id \
          AND link.watch_id = target.watch_id \
         JOIN notification_endpoints AS endpoint \
           ON endpoint.tenant_id = link.tenant_id \
          AND endpoint.id = link.endpoint_id \
         WHERE target.tenant_id = $1 AND target.id = $2 \
           AND endpoint.state = 'active' \
           AND endpoint.channel IN ('email', 'webhook') \
         ORDER BY link.ordinal, endpoint.id",
    )
    .bind(tenant_id)
    .bind(watch_target_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| JobError::StorageInvariant)?;
    for (endpoint_id, channel_name) in endpoints {
        let channel =
            notification_channel(&channel_name).map_err(|_| JobError::StorageInvariant)?;
        let delivery_id = Uuid::new_v4();
        let logical_key = match channel {
            NotificationChannel::Webhook => {
                logical_notification_key(tenant_id, transition_id, endpoint_id)
            }
            NotificationChannel::Email => {
                email_logical_notification_key(tenant_id, transition_id, endpoint_id)
            }
        };
        let inserted: Option<Uuid> = sqlx::query_scalar(
            "INSERT INTO notification_deliveries (\
                id, tenant_id, transition_id, endpoint_id, \
                logical_notification_key, confirmation_basis, state, \
                attempt_count, created_at\
             ) VALUES (\
                $1, $2, $3, $4, $5, $6, 'queued', 0, clock_timestamp()\
             ) \
             ON CONFLICT (tenant_id, logical_notification_key) DO NOTHING \
             RETURNING id",
        )
        .bind(delivery_id)
        .bind(tenant_id)
        .bind(transition_id)
        .bind(endpoint_id)
        .bind(logical_key.to_vec())
        .bind(confirmation_basis)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| JobError::StorageInvariant)?;
        let Some(delivery_id) = inserted else {
            continue;
        };
        insert_lineage(
            transaction,
            tenant_id,
            "transition",
            transition_id,
            "notification_delivery",
            delivery_id,
            confirmed_lineage_purpose(channel),
        )
        .await
        .map_err(|_| JobError::StorageInvariant)?;
        insert_audit(
            transaction,
            tenant_id,
            "notification.delivery.queued",
            delivery_id,
            json!({"channel":notification_channel_name(channel)}),
        )
        .await
        .map_err(|_| JobError::StorageInvariant)?;
    }
    Ok(())
}

#[derive(FromRow)]
struct ClaimCoordinate {
    tenant_id: Uuid,
    notification_delivery_id: Uuid,
    attempt_count: i32,
}

#[derive(FromRow)]
struct ClaimedDeliveryRow {
    id: Uuid,
    endpoint_id: Uuid,
    endpoint_channel: String,
    destination_ciphertext: Vec<u8>,
    encryption_key_id: String,
    transition_id: Uuid,
    watch_id: Uuid,
    normalized_username: Option<String>,
    site_id: String,
    transition_class: String,
    from_state: String,
    to_state: String,
    region_class: Option<String>,
    rule_hash: Option<String>,
    confirmation_basis: Option<String>,
    detected_at_unix_ms: i64,
}

#[derive(FromRow)]
struct LockedDelivery {
    state: String,
    attempt_count: i32,
    lease_owner: Option<String>,
    lease_is_current: bool,
    endpoint_state: String,
    endpoint_channel: String,
}

#[derive(Clone, Copy)]
enum DeliveryAttemptOutcome {
    Delivered {
        http_status: u16,
    },
    Failed {
        error_code: &'static str,
        http_status: Option<u16>,
        retryable: bool,
    },
}

impl DeliveryAttemptOutcome {
    const fn from_send_result(result: Result<u16, WebhookSendError>) -> Self {
        match result {
            Ok(status @ 200..=299) => Self::Delivered {
                http_status: status,
            },
            Ok(status @ (408 | 425 | 429 | 500..=599)) => Self::Failed {
                error_code: "http_retryable",
                http_status: Some(status),
                retryable: true,
            },
            Ok(status) => Self::Failed {
                error_code: "http_permanent",
                http_status: Some(status),
                retryable: false,
            },
            Err(WebhookSendError::Timeout) => Self::Failed {
                error_code: "timeout",
                http_status: None,
                retryable: true,
            },
            Err(WebhookSendError::Connection) => Self::Failed {
                error_code: "connection_failed",
                http_status: None,
                retryable: true,
            },
            Err(WebhookSendError::Transport) => Self::Failed {
                error_code: "transport_failed",
                http_status: None,
                retryable: true,
            },
            Err(WebhookSendError::DestinationRejected) => Self::Failed {
                error_code: "destination_rejected",
                http_status: None,
                retryable: false,
            },
            Err(WebhookSendError::RequestRejected) => Self::Failed {
                error_code: "request_rejected",
                http_status: None,
                retryable: false,
            },
        }
    }

    const fn from_email_send_result(result: Result<u16, EmailSendError>) -> Self {
        match result {
            Ok(status @ 200..=299) => Self::Delivered {
                http_status: status,
            },
            Ok(status @ (408 | 425 | 429 | 500..=599)) => Self::Failed {
                error_code: "http_retryable",
                http_status: Some(status),
                retryable: true,
            },
            Ok(status) => Self::Failed {
                error_code: "http_permanent",
                http_status: Some(status),
                retryable: false,
            },
            Err(EmailSendError::Timeout) => Self::Failed {
                error_code: "timeout",
                http_status: None,
                retryable: true,
            },
            Err(EmailSendError::Connection) => Self::Failed {
                error_code: "connection_failed",
                http_status: None,
                retryable: true,
            },
            Err(EmailSendError::Transport) => Self::Failed {
                error_code: "transport_failed",
                http_status: None,
                retryable: true,
            },
            Err(EmailSendError::DestinationRejected) => Self::Failed {
                error_code: "destination_rejected",
                http_status: None,
                retryable: false,
            },
            Err(EmailSendError::RequestRejected) => Self::Failed {
                error_code: "request_rejected",
                http_status: None,
                retryable: false,
            },
        }
    }

    const fn http_status(self) -> Option<u16> {
        match self {
            Self::Delivered { http_status } => Some(http_status),
            Self::Failed { http_status, .. } => http_status,
        }
    }
}

struct PersistedAttempt {
    state: &'static str,
    event_kind: &'static str,
    error_code: Option<&'static str>,
    http_status: Option<u16>,
    next_attempt_at_unix_ms: Option<i64>,
}

fn persisted_outcome(
    outcome: DeliveryAttemptOutcome,
    attempt_count: u32,
    maximum_attempts: u32,
    completed_at_unix_ms: i64,
) -> Result<PersistedAttempt, DeliveryError> {
    match outcome {
        DeliveryAttemptOutcome::Delivered { http_status } => Ok(PersistedAttempt {
            state: "delivered",
            event_kind: "delivered",
            error_code: None,
            http_status: Some(http_status),
            next_attempt_at_unix_ms: None,
        }),
        DeliveryAttemptOutcome::Failed {
            error_code,
            http_status,
            retryable,
        } if retryable && attempt_count < maximum_attempts => Ok(PersistedAttempt {
            state: "retry_scheduled",
            event_kind: "retry_scheduled",
            error_code: Some(error_code),
            http_status,
            next_attempt_at_unix_ms: Some(
                completed_at_unix_ms
                    .checked_add(retry_delay_ms(attempt_count))
                    .ok_or(DeliveryError::StorageInvariant)?,
            ),
        }),
        DeliveryAttemptOutcome::Failed {
            error_code,
            http_status,
            ..
        } => Ok(PersistedAttempt {
            state: "permanently_failed",
            event_kind: "permanently_failed",
            error_code: Some(error_code),
            http_status,
            next_attempt_at_unix_ms: None,
        }),
    }
}

fn render_email_message(
    notification: &EmailNotification,
) -> Result<(&'static str, String), DeliveryError> {
    let transition = &notification.transition;
    let target = format!(
        "{} on {}",
        transition.target.username.as_str(),
        transition.target.site_id.as_str()
    );
    let delivery_id = notification.delivery_id.as_str();
    match &transition.change {
        TransitionChange::AccountState { from, to } => Ok((
            "SocialName account state changed",
            format!(
                "SocialName observed a time- and vantage-specific account-state change.\n\n\
                 Target: {target}\n\
                 Change: {} -> {}\n\
                 Observed at (Unix ms): {}\n\
                 Delivery ID: {delivery_id}\n\n\
                 This observation is not timeless truth. A matching public username does not \
                 prove common ownership.",
                account_state_name(*from),
                account_state_name(*to),
                transition.detected_at_unix_ms,
            ),
        )),
        TransitionChange::MeasurementHealth {
            region_class,
            from,
            to,
            ..
        } => Ok((
            "SocialName measurement health changed",
            format!(
                "SocialName observed a time- and vantage-specific measurement-health change.\n\n\
                 Target: {target}\n\
                 Region: {}\n\
                 Change: {} -> {}\n\
                 Observed at (Unix ms): {}\n\
                 Delivery ID: {delivery_id}\n\n\
                 Measurement degradation is not an account-state change.",
                region_class.as_str(),
                measurement_state_name(*from),
                measurement_state_name(*to),
                transition.detected_at_unix_ms,
            ),
        )),
    }
}

const fn account_state_name(value: AccountState) -> &'static str {
    match value {
        AccountState::Found => "found",
        AccountState::NotFound => "not_found",
    }
}

const fn measurement_state_name(value: MeasurementState) -> &'static str {
    match value {
        MeasurementState::Healthy => "healthy",
        MeasurementState::Degraded => "degraded",
        MeasurementState::Quarantined => "quarantined",
        MeasurementState::Recovering => "recovering",
        MeasurementState::Unavailable => "unavailable",
    }
}

fn protocol_transition(
    row: &ClaimedDeliveryRow,
    supporting_observation_ids: Vec<Uuid>,
) -> Result<Transition, DeliveryError> {
    let change = match row.transition_class.as_str() {
        "account_state" => TransitionChange::AccountState {
            from: account_state(&row.from_state)?,
            to: account_state(&row.to_state)?,
        },
        "measurement_health" => TransitionChange::MeasurementHealth {
            region_class: RegionClass::new(
                row.region_class
                    .clone()
                    .ok_or(DeliveryError::StorageInvariant)?,
            )
            .map_err(|_| DeliveryError::StorageInvariant)?,
            rule_hash: RuleHash::new(
                row.rule_hash
                    .clone()
                    .ok_or(DeliveryError::StorageInvariant)?,
            )
            .map_err(|_| DeliveryError::StorageInvariant)?,
            from: measurement_state(&row.from_state)?,
            to: measurement_state(&row.to_state)?,
        },
        _ => return Err(DeliveryError::StorageInvariant),
    };
    let confirmation = TransitionConfirmation::Confirmed {
        basis: confirmation_basis(
            row.confirmation_basis
                .as_deref()
                .ok_or(DeliveryError::StorageInvariant)?,
        )?,
    };
    let transition = Transition {
        schema: ProtocolVersion::ApiV1,
        transition_id: TransitionId::new(row.transition_id.to_string())
            .map_err(|_| DeliveryError::StorageInvariant)?,
        watch_id: WatchId::new(row.watch_id.to_string())
            .map_err(|_| DeliveryError::StorageInvariant)?,
        target: Target {
            username: Username::new(
                row.normalized_username
                    .clone()
                    .ok_or(DeliveryError::StorageInvariant)?,
            )
            .map_err(|_| DeliveryError::StorageInvariant)?,
            site_id: SiteId::new(row.site_id.clone())
                .map_err(|_| DeliveryError::StorageInvariant)?,
        },
        change,
        confirmation,
        supporting_observation_ids: supporting_observation_ids
            .into_iter()
            .map(|id| {
                ObservationId::new(id.to_string()).map_err(|_| DeliveryError::StorageInvariant)
            })
            .collect::<Result<Vec<_>, _>>()?,
        detected_at_unix_ms: row.detected_at_unix_ms,
    };
    transition
        .validate()
        .map_err(|_| DeliveryError::StorageInvariant)?;
    Ok(transition)
}

const fn account_state(value: &str) -> Result<AccountState, DeliveryError> {
    match value.as_bytes() {
        b"found" => Ok(AccountState::Found),
        b"not_found" => Ok(AccountState::NotFound),
        _ => Err(DeliveryError::StorageInvariant),
    }
}

const fn measurement_state(value: &str) -> Result<MeasurementState, DeliveryError> {
    match value.as_bytes() {
        b"healthy" => Ok(MeasurementState::Healthy),
        b"degraded" => Ok(MeasurementState::Degraded),
        b"quarantined" => Ok(MeasurementState::Quarantined),
        b"recovering" => Ok(MeasurementState::Recovering),
        b"unavailable" => Ok(MeasurementState::Unavailable),
        _ => Err(DeliveryError::StorageInvariant),
    }
}

const fn confirmation_basis(value: &str) -> Result<ConfirmationBasis, DeliveryError> {
    match value.as_bytes() {
        b"managed_e4" => Ok(ConfirmationBasis::ManagedE4),
        b"managed_e3_follow_up" => Ok(ConfirmationBasis::ManagedE3FollowUp),
        b"two_managed_independent_regions" => Ok(ConfirmationBasis::TwoManagedIndependentRegions),
        b"two_managed_separated_in_time" => Ok(ConfirmationBasis::TwoManagedSeparatedInTime),
        b"corroborated_shared_candidate_opt_in" => {
            Ok(ConfirmationBasis::CorroboratedSharedCandidateOptIn)
        }
        b"measurement_health_evidence" => Ok(ConfirmationBasis::MeasurementHealthEvidence),
        _ => Err(DeliveryError::StorageInvariant),
    }
}

fn destination_aad(tenant_id: Uuid, endpoint_id: Uuid, encryption_key_id: &str) -> Vec<u8> {
    destination_aad_for_domain(
        tenant_id,
        endpoint_id,
        encryption_key_id,
        b"socialname/webhook-destination/v1",
    )
}

fn destination_aad_for_domain(
    tenant_id: Uuid,
    endpoint_id: Uuid,
    encryption_key_id: &str,
    domain: &[u8],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(domain.len() + 40 + encryption_key_id.len());
    aad.extend_from_slice(domain);
    aad.extend_from_slice(tenant_id.as_bytes());
    aad.extend_from_slice(endpoint_id.as_bytes());
    aad.extend_from_slice(
        &u32::try_from(encryption_key_id.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    aad.extend_from_slice(encryption_key_id.as_bytes());
    aad
}

fn logical_notification_key(tenant_id: Uuid, transition_id: Uuid, endpoint_id: Uuid) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"socialname/logical-webhook/v1");
    hash.update(tenant_id.as_bytes());
    hash.update(transition_id.as_bytes());
    hash.update(endpoint_id.as_bytes());
    hash.finalize().into()
}

fn email_logical_notification_key(
    tenant_id: Uuid,
    transition_id: Uuid,
    endpoint_id: Uuid,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"socialname/logical-email/v1");
    hash.update(tenant_id.as_bytes());
    hash.update(transition_id.as_bytes());
    hash.update(endpoint_id.as_bytes());
    hash.finalize().into()
}

fn notification_channel(value: &str) -> Result<NotificationChannel, DeliveryError> {
    match value {
        "email" => Ok(NotificationChannel::Email),
        "webhook" => Ok(NotificationChannel::Webhook),
        _ => Err(DeliveryError::StorageInvariant),
    }
}

const fn notification_channel_name(channel: NotificationChannel) -> &'static str {
    match channel {
        NotificationChannel::Email => "email",
        NotificationChannel::Webhook => "webhook",
    }
}

const fn attempt_lineage_purpose(channel: NotificationChannel) -> &'static str {
    match channel {
        NotificationChannel::Email => "email_attempt",
        NotificationChannel::Webhook => "webhook_attempt",
    }
}

const fn confirmed_lineage_purpose(channel: NotificationChannel) -> &'static str {
    match channel {
        NotificationChannel::Email => "confirmed_email",
        NotificationChannel::Webhook => "confirmed_webhook",
    }
}

fn required_env(name: &'static str) -> Result<String, DeliveryError> {
    let value = env::var(name).map_err(|_| DeliveryError::InvalidConfiguration)?;
    if value.is_empty() {
        Err(DeliveryError::InvalidConfiguration)
    } else {
        Ok(value)
    }
}

fn parse_secret_key(value: &str) -> Result<[u8; 32], DeliveryError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(DeliveryError::InvalidConfiguration);
    }
    let decoded = hex::decode(value).map_err(|_| DeliveryError::InvalidConfiguration)?;
    decoded
        .try_into()
        .map_err(|_| DeliveryError::InvalidConfiguration)
}

fn valid_key_id(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn validate_process_limits(
    worker_id: &str,
    lease: Duration,
    maximum_attempts: u32,
) -> Result<(), DeliveryError> {
    let lease_ms =
        u64::try_from(lease.as_millis()).map_err(|_| DeliveryError::InvalidConfiguration)?;
    let worker_valid = (1..=64).contains(&worker_id.len())
        && worker_id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && worker_id
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && worker_id
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric);
    if worker_valid
        && (MINIMUM_LEASE_MS..=MAXIMUM_LEASE_MS).contains(&lease_ms)
        && (1..=MAXIMUM_ATTEMPTS).contains(&maximum_attempts)
    {
        Ok(())
    } else {
        Err(DeliveryError::InvalidConfiguration)
    }
}

fn retry_delay_ms(attempt_count: u32) -> i64 {
    let exponent = attempt_count.saturating_sub(1).min(16);
    INITIAL_RETRY_DELAY_MS
        .saturating_mul(1_i64.checked_shl(exponent).unwrap_or(i64::MAX))
        .min(MAXIMUM_RETRY_DELAY_MS)
}

async fn attach_attempt_lineage(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    delivery_id: Uuid,
    channel: NotificationChannel,
) -> Result<(), DeliveryError> {
    let purpose = attempt_lineage_purpose(channel);
    let attempt_ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT attempt.id \
         FROM notification_delivery_attempts AS attempt \
         WHERE attempt.tenant_id = $1 AND attempt.delivery_id = $2 \
           AND NOT EXISTS (\
               SELECT 1 FROM data_lineage_edges AS lineage \
               WHERE lineage.tenant_id = attempt.tenant_id \
                 AND lineage.parent_kind = 'notification_delivery' \
                 AND lineage.parent_id = attempt.delivery_id \
                 AND lineage.child_kind = 'notification_delivery_attempt' \
                 AND lineage.child_id = attempt.id \
                 AND lineage.purpose = $3\
           ) \
         ORDER BY attempt.occurred_at, attempt.id",
    )
    .bind(tenant_id)
    .bind(delivery_id)
    .bind(purpose)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| DeliveryError::StorageInvariant)?;
    for attempt_id in attempt_ids {
        insert_lineage(
            transaction,
            tenant_id,
            "notification_delivery",
            delivery_id,
            "notification_delivery_attempt",
            attempt_id,
            purpose,
        )
        .await?;
    }
    Ok(())
}

async fn insert_audit(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    action: &str,
    resource_id: Uuid,
    details: serde_json::Value,
) -> Result<(), DeliveryError> {
    sqlx::query(
        "INSERT INTO audit_events (\
            id, tenant_id, action, resource_kind, resource_id, \
            occurred_at, details\
         ) VALUES (\
            $1, $2, $3, 'notification_delivery', $4, \
            clock_timestamp(), $5\
         )",
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(action)
    .bind(resource_id)
    .bind(details)
    .execute(&mut **transaction)
    .await
    .map_err(|_| DeliveryError::StorageInvariant)?;
    Ok(())
}

async fn insert_lineage(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    parent_kind: &str,
    parent_id: Uuid,
    child_kind: &str,
    child_id: Uuid,
    purpose: &str,
) -> Result<(), DeliveryError> {
    sqlx::query(
        "INSERT INTO data_lineage_edges (\
            id, tenant_id, parent_kind, parent_id, child_kind, child_id, \
            purpose, created_at\
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, clock_timestamp()) \
         ON CONFLICT (\
            tenant_id, parent_kind, parent_id, child_kind, child_id, purpose\
         ) DO NOTHING",
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(parent_kind)
    .bind(parent_id)
    .bind(child_kind)
    .bind(child_id)
    .bind(purpose)
    .execute(&mut **transaction)
    .await
    .map_err(|_| DeliveryError::StorageInvariant)?;
    Ok(())
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum DeliveryError {
    #[error("notification delivery configuration is invalid")]
    InvalidConfiguration,
    #[error("notification destination is invalid")]
    InvalidDestination,
    #[error("notification delivery cryptographic operation failed")]
    CryptographicFailure,
    #[error("notification delivery database is unavailable")]
    DatabaseUnavailable,
    #[error("notification delivery storage invariant failed")]
    StorageInvariant,
    #[error("notification delivery lease is stale")]
    StaleLease,
    #[error("notification delivery was cancelled")]
    Cancelled,
}

impl DeliveryError {
    const fn from_job(error: JobError) -> Self {
        match error {
            JobError::DatabaseConfiguration | JobError::InvalidConfiguration => {
                Self::InvalidConfiguration
            }
            JobError::DatabaseUnavailable => Self::DatabaseUnavailable,
            _ => Self::StorageInvariant,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secrets() -> DeliverySecrets {
        DeliverySecrets::new("endpoint-key-1", [7; 32], "signing-key-1", [9; 32]).unwrap()
    }

    #[test]
    fn destination_envelope_is_bound_and_debug_output_is_redacted() {
        let secrets = secrets();
        let tenant_id = Uuid::from_u128(1);
        let endpoint_id = Uuid::from_u128(2);
        let destination = "https://hooks.example.test/events";
        let envelope = secrets
            .seal_destination(tenant_id, endpoint_id, destination)
            .unwrap();
        assert!(
            !envelope
                .windows(destination.len())
                .any(|value| value == destination.as_bytes())
        );
        assert_eq!(
            secrets
                .open_destination(tenant_id, endpoint_id, "endpoint-key-1", &envelope,)
                .unwrap()
                .as_str(),
            destination
        );
        assert_eq!(
            secrets.open_destination(Uuid::from_u128(3), endpoint_id, "endpoint-key-1", &envelope,),
            Err(DeliveryError::CryptographicFailure)
        );
        assert!(!format!("{secrets:?}").contains(destination));
    }

    #[test]
    fn email_destination_uses_a_separate_envelope_domain() {
        let secrets = DeliverySecrets::new_email("endpoint-key-1", [7; 32]).unwrap();
        let tenant_id = Uuid::from_u128(1);
        let endpoint_id = Uuid::from_u128(2);
        let destination = "private-alerts@example.test";
        let envelope = secrets
            .seal_email_destination(tenant_id, endpoint_id, destination)
            .unwrap();
        assert_eq!(
            secrets
                .open_email_destination(tenant_id, endpoint_id, "endpoint-key-1", &envelope)
                .unwrap()
                .as_str(),
            destination
        );
        assert_eq!(
            secrets.open_destination(tenant_id, endpoint_id, "endpoint-key-1", &envelope),
            Err(DeliveryError::CryptographicFailure)
        );
        assert!(
            secrets
                .signature(Uuid::from_u128(3), 1_000, b"body")
                .is_err()
        );
    }

    #[test]
    fn email_gateway_configuration_and_request_debug_are_redacted() {
        let token = "private-token-that-must-not-appear";
        let address = "sender@example.test";
        let config =
            EmailGatewayConfig::new("https://email.example.test/v1/send", token, address).unwrap();
        let debug = format!("{config:?}");
        assert!(!debug.contains(token));
        assert!(!debug.contains(address));
        assert!(EmailGatewayConfig::new("https://127.0.0.1/send", token, address).is_err());

        let request = EmailRequest {
            gateway: Zeroizing::new("https://email.example.test/v1/send".to_owned()),
            bearer_token: Zeroizing::new(token.to_owned()),
            delivery_id: "delivery_01".to_owned(),
            attempt_count: 1,
            body: Zeroizing::new(address.as_bytes().to_vec()),
        };
        let debug = format!("{request:?}");
        assert!(!debug.contains(token));
        assert!(!debug.contains(address));
    }

    #[test]
    fn webhook_signature_binds_timestamp_delivery_and_body() {
        let secrets = secrets();
        let delivery_id = Uuid::from_u128(10);
        let body = br#"{"schema":"socialname.dev/api/v1"}"#;
        let first = secrets.signature(delivery_id, 1_000, body).unwrap();
        let replay = secrets.signature(delivery_id, 1_000, body).unwrap();
        let changed = secrets.signature(delivery_id, 1_001, body).unwrap();
        assert_eq!(first, replay);
        assert_ne!(first, changed);
        assert_eq!(first.len(), 67);
    }

    #[test]
    fn retry_and_dead_letter_classification_is_closed() {
        assert!(matches!(
            DeliveryAttemptOutcome::from_send_result(Ok(204)),
            DeliveryAttemptOutcome::Delivered { .. }
        ));
        assert!(matches!(
            DeliveryAttemptOutcome::from_send_result(Ok(429)),
            DeliveryAttemptOutcome::Failed {
                retryable: true,
                ..
            }
        ));
        assert!(matches!(
            DeliveryAttemptOutcome::from_send_result(Ok(404)),
            DeliveryAttemptOutcome::Failed {
                retryable: false,
                ..
            }
        ));
        assert_eq!(retry_delay_ms(1), 5_000);
        assert_eq!(retry_delay_ms(10), MAXIMUM_RETRY_DELAY_MS);
        assert!(matches!(
            DeliveryAttemptOutcome::from_email_send_result(Err(EmailSendError::Timeout)),
            DeliveryAttemptOutcome::Failed {
                retryable: true,
                ..
            }
        ));
        assert!(matches!(
            DeliveryAttemptOutcome::from_email_send_result(Ok(400)),
            DeliveryAttemptOutcome::Failed {
                retryable: false,
                ..
            }
        ));
    }

    #[test]
    fn logical_key_is_endpoint_specific_and_stable() {
        let tenant_id = Uuid::from_u128(1);
        let transition_id = Uuid::from_u128(2);
        let first = logical_notification_key(tenant_id, transition_id, Uuid::from_u128(3));
        let replay = logical_notification_key(tenant_id, transition_id, Uuid::from_u128(3));
        let other = logical_notification_key(tenant_id, transition_id, Uuid::from_u128(4));
        assert_eq!(first, replay);
        assert_ne!(first, other);
        assert_ne!(
            first,
            email_logical_notification_key(tenant_id, transition_id, Uuid::from_u128(3))
        );
    }
}
