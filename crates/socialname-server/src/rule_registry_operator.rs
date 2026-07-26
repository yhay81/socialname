use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Serialize, de::DeserializeOwned};
use socialname_canary::{
    RulePackMetadataEnvelope, RulePackMetadataVerifier, RulePackRolloutRegistry,
    RulePackRolloutStage, RulePackTrustV1,
};
use socialname_rule_compiler::{CompiledRulePack, CompiledSiteRule, RuleCompiler};
use sqlx::{FromRow, PgPool, Postgres, Transaction, postgres::PgPoolOptions};
use uuid::Uuid;

use crate::DATABASE_URL_ENV;

pub const RULE_METADATA_FILE_ENV: &str = "SOCIALNAME_RULE_METADATA_FILE";
pub const RULES_DIRECTORY_ENV: &str = "SOCIALNAME_RULES_DIRECTORY";
pub const INITIAL_RULE_TRUST_FILE_ENV: &str = "SOCIALNAME_INITIAL_RULE_TRUST_FILE";
pub const INITIAL_RULE_TRUST_ID_ENV: &str = "SOCIALNAME_INITIAL_RULE_TRUST_ID";

const MAX_METADATA_BYTES: usize = 2 * 1_024 * 1_024;
const MAX_TRUST_BYTES: usize = 64 * 1_024;
const MAXIMUM_CONNECTIONS: u32 = 1;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy)]
pub struct InitialRulePackTrust<'a> {
    pub trust: &'a RulePackTrustV1,
    pub expected_trust_id: &'a str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppliedRulePack {
    metadata_id: String,
    sequence: u64,
    rollout_stage: RulePackRolloutStage,
    rule_pack_hash: String,
    trust_generation: u64,
    rule_version_ids: BTreeMap<String, Uuid>,
}

impl AppliedRulePack {
    #[must_use]
    pub fn metadata_id(&self) -> &str {
        &self.metadata_id
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn rollout_stage(&self) -> RulePackRolloutStage {
        self.rollout_stage
    }

    #[must_use]
    pub fn rule_pack_hash(&self) -> &str {
        &self.rule_pack_hash
    }

    #[must_use]
    pub const fn trust_generation(&self) -> u64 {
        self.trust_generation
    }

    #[must_use]
    pub fn rule_version_id(&self, site_id: &str) -> Option<Uuid> {
        self.rule_version_ids.get(site_id).copied()
    }
}

pub async fn apply_rule_pack_metadata_from_env() -> Result<AppliedRulePack, RuleRegistryError> {
    let database_url =
        env::var(DATABASE_URL_ENV).map_err(|_| RuleRegistryError::InvalidConfiguration)?;
    let rules_directory = required_path(RULES_DIRECTORY_ENV)?;
    let metadata_file = required_path(RULE_METADATA_FILE_ENV)?;
    let metadata: RulePackMetadataEnvelope = load_bounded_json(&metadata_file, MAX_METADATA_BYTES)?;
    let rules = RuleCompiler::new()
        .load_directory(&rules_directory)
        .map_err(|_| RuleRegistryError::InvalidArtifact)?;
    let initial_trust = optional_initial_trust()?;
    let initial = initial_trust
        .as_ref()
        .map(|(trust, expected)| InitialRulePackTrust {
            trust,
            expected_trust_id: expected,
        });
    let pool = PgPoolOptions::new()
        .max_connections(MAXIMUM_CONNECTIONS)
        .acquire_timeout(ACQUIRE_TIMEOUT)
        .connect_lazy(&database_url)
        .map_err(|_| RuleRegistryError::DatabaseUnavailable)?;
    tokio::time::timeout(CONNECT_TIMEOUT, pool.acquire())
        .await
        .map_err(|_| RuleRegistryError::DatabaseUnavailable)?
        .map_err(|_| RuleRegistryError::DatabaseUnavailable)?;
    let result = apply_rule_pack_metadata(&pool, initial, &metadata, &rules, now_unix_ms()?).await;
    pool.close().await;
    result
}

pub async fn apply_rule_pack_metadata(
    pool: &PgPool,
    initial_trust: Option<InitialRulePackTrust<'_>>,
    envelope: &RulePackMetadataEnvelope,
    rules: &[CompiledSiteRule],
    applied_at_unix_ms: i64,
) -> Result<AppliedRulePack, RuleRegistryError> {
    let compiler = RuleCompiler::new();
    let rule_pack = compiler
        .compile_pack(rules)
        .map_err(|_| RuleRegistryError::InvalidArtifact)?;
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| RuleRegistryError::DatabaseUnavailable)?;
    sqlx::query("LOCK TABLE rule_pack_registry IN EXCLUSIVE MODE")
        .execute(&mut *transaction)
        .await
        .map_err(|_| RuleRegistryError::DatabaseUnavailable)?;
    let persisted: Option<RegistryRow> = sqlx::query_as(
        "SELECT registry_state, highest_sequence, current_trust_generation, \
                active_metadata_id, staged_metadata_id, last_known_good_metadata_id \
         FROM rule_pack_registry WHERE singleton FOR UPDATE",
    )
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| RuleRegistryError::DatabaseUnavailable)?;
    let mut registry = if let Some(persisted) = persisted.as_ref() {
        let registry: RulePackRolloutRegistry =
            serde_json::from_value(persisted.registry_state.clone())
                .map_err(|_| RuleRegistryError::StorageInvariant)?;
        validate_persisted_registry(&registry, persisted)?;
        registry
    } else {
        let initial = initial_trust.ok_or(RuleRegistryError::InitialTrustRequired)?;
        if !valid_sha256(initial.expected_trust_id)
            || initial
                .trust
                .content_id()
                .map_err(|_| RuleRegistryError::InvalidArtifact)?
                != initial.expected_trust_id
        {
            return Err(RuleRegistryError::InvalidInitialTrustPin);
        }
        RulePackRolloutRegistry::new(initial.trust.clone(), applied_at_unix_ms)
            .map_err(|_| RuleRegistryError::InvalidArtifact)?
    };
    validate_persisted_promotion_high_water(&mut transaction, &registry).await?;
    let previous_registry = registry.clone();
    let validated = RulePackMetadataVerifier::new()
        .validate_at(envelope, registry.current_trust(), applied_at_unix_ms)
        .map_err(|_| RuleRegistryError::InvalidArtifact)?;
    registry
        .apply(&validated, &rule_pack, applied_at_unix_ms)
        .map_err(|_| RuleRegistryError::InvalidTransition)?;

    install_sites(&mut transaction, rules).await?;
    install_trust_root(
        &mut transaction,
        previous_registry.current_trust().clone(),
        applied_at_unix_ms,
    )
    .await?;
    install_trust_root(
        &mut transaction,
        validated.metadata().trust.clone(),
        applied_at_unix_ms,
    )
    .await?;
    materialize_trust_root_state(&mut transaction, registry.current_trust().generation).await?;
    let rule_pack_id = install_rule_pack(
        &mut transaction,
        &rule_pack,
        validated.metadata().previous_rule_pack_hash.as_deref(),
        validated.metadata().expires_at_unix_ms,
        applied_at_unix_ms,
    )
    .await?;
    let rule_version_ids =
        install_rule_versions(&mut transaction, rule_pack_id, rules, applied_at_unix_ms).await?;
    install_metadata(&mut transaction, rule_pack_id, envelope, applied_at_unix_ms).await?;
    install_promotions(&mut transaction, envelope).await?;
    apply_materialized_state(
        &mut transaction,
        &previous_registry,
        &registry,
        envelope,
        rule_pack_id,
        &rule_version_ids,
        applied_at_unix_ms,
    )
    .await?;
    persist_registry(&mut transaction, &registry, applied_at_unix_ms).await?;
    persist_promotion_high_water(&mut transaction, &registry, envelope, applied_at_unix_ms).await?;
    transaction
        .commit()
        .await
        .map_err(|_| RuleRegistryError::DatabaseUnavailable)?;
    Ok(AppliedRulePack {
        metadata_id: envelope.metadata_id.clone(),
        sequence: envelope.metadata.sequence,
        rollout_stage: envelope.metadata.rollout_stage,
        rule_pack_hash: envelope.metadata.rule_pack_hash.clone(),
        trust_generation: envelope.metadata.trust.generation,
        rule_version_ids,
    })
}

async fn install_sites(
    transaction: &mut Transaction<'_, Postgres>,
    rules: &[CompiledSiteRule],
) -> Result<(), RuleRegistryError> {
    for rule in rules {
        sqlx::query(
            "INSERT INTO sites (id, display_name, state, created_at, updated_at) \
             VALUES ($1, $2, 'discovery', clock_timestamp(), clock_timestamp()) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&rule.source.id)
        .bind(&rule.source.name)
        .execute(&mut **transaction)
        .await
        .map_err(|_| RuleRegistryError::DatabaseUnavailable)?;
        let display_name: Option<String> =
            sqlx::query_scalar("SELECT display_name FROM sites WHERE id = $1")
                .bind(&rule.source.id)
                .fetch_optional(&mut **transaction)
                .await
                .map_err(|_| RuleRegistryError::DatabaseUnavailable)?;
        if display_name.as_deref() != Some(rule.source.name.as_str()) {
            return Err(RuleRegistryError::StorageInvariant);
        }
    }
    Ok(())
}

async fn install_trust_root(
    transaction: &mut Transaction<'_, Postgres>,
    trust: RulePackTrustV1,
    installed_at_unix_ms: i64,
) -> Result<(), RuleRegistryError> {
    let generation =
        i64::try_from(trust.generation).map_err(|_| RuleRegistryError::InvalidArtifact)?;
    let trust_id = decode_sha256(
        &trust
            .content_id()
            .map_err(|_| RuleRegistryError::InvalidArtifact)?,
    )?;
    let keys = serde_json::to_value(&trust.keys).map_err(|_| RuleRegistryError::InvalidArtifact)?;
    sqlx::query(
        "INSERT INTO rule_pack_trust_roots (\
            generation, trust_id, threshold, keys, expires_at, state, installed_at\
         ) VALUES (\
            $1, $2, $3, $4, to_timestamp($5::double precision / 1000.0), \
            'staged', to_timestamp($6::double precision / 1000.0)\
         ) ON CONFLICT (generation) DO NOTHING",
    )
    .bind(generation)
    .bind(&trust_id)
    .bind(i32::from(trust.threshold))
    .bind(&keys)
    .bind(trust.expires_at_unix_ms)
    .bind(installed_at_unix_ms)
    .execute(&mut **transaction)
    .await
    .map_err(|_| RuleRegistryError::DatabaseUnavailable)?;
    let stored: TrustRootRow = sqlx::query_as(
        "SELECT trust_id, threshold, keys, \
                (EXTRACT(EPOCH FROM expires_at) * 1000)::bigint AS expires_at_unix_ms \
         FROM rule_pack_trust_roots WHERE generation = $1 FOR UPDATE",
    )
    .bind(generation)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| RuleRegistryError::DatabaseUnavailable)?;
    if stored.trust_id != trust_id
        || stored.threshold != i32::from(trust.threshold)
        || stored.keys != keys
        || stored.expires_at_unix_ms != trust.expires_at_unix_ms
    {
        return Err(RuleRegistryError::StorageInvariant);
    }
    Ok(())
}

async fn materialize_trust_root_state(
    transaction: &mut Transaction<'_, Postgres>,
    active_generation: u64,
) -> Result<(), RuleRegistryError> {
    let active_generation =
        i64::try_from(active_generation).map_err(|_| RuleRegistryError::InvalidArtifact)?;
    sqlx::query(
        "UPDATE rule_pack_trust_roots SET state = 'retired' \
         WHERE state = 'active' AND generation <> $1",
    )
    .bind(active_generation)
    .execute(&mut **transaction)
    .await
    .map_err(|_| RuleRegistryError::DatabaseUnavailable)?;
    let affected =
        sqlx::query("UPDATE rule_pack_trust_roots SET state = 'active' WHERE generation = $1")
            .bind(active_generation)
            .execute(&mut **transaction)
            .await
            .map_err(|_| RuleRegistryError::DatabaseUnavailable)?
            .rows_affected();
    if affected != 1 {
        return Err(RuleRegistryError::StorageInvariant);
    }
    Ok(())
}

async fn install_rule_pack(
    transaction: &mut Transaction<'_, Postgres>,
    rule_pack: &CompiledRulePack,
    previous_rule_pack_hash: Option<&str>,
    expires_at_unix_ms: i64,
    created_at_unix_ms: i64,
) -> Result<Uuid, RuleRegistryError> {
    let pack_hash = decode_sha256(&rule_pack.content_hash)?;
    if let Some(existing) =
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM rule_packs WHERE pack_hash = $1 FOR UPDATE")
            .bind(&pack_hash)
            .fetch_optional(&mut **transaction)
            .await
            .map_err(|_| RuleRegistryError::DatabaseUnavailable)?
    {
        return Ok(existing);
    }
    let id = Uuid::new_v4();
    let previous = previous_rule_pack_hash.map(decode_sha256).transpose()?;
    let version = format!(
        "release-{}-{}",
        created_at_unix_ms,
        &rule_pack.content_hash[..12]
    );
    sqlx::query(
        "INSERT INTO rule_packs (\
            id, version, pack_hash, previous_pack_hash, state, created_at, expires_at\
         ) VALUES (\
            $1, $2, $3, $4, 'staged', \
            to_timestamp($5::double precision / 1000.0), \
            to_timestamp($6::double precision / 1000.0)\
         )",
    )
    .bind(id)
    .bind(version)
    .bind(pack_hash)
    .bind(previous)
    .bind(created_at_unix_ms)
    .bind(expires_at_unix_ms)
    .execute(&mut **transaction)
    .await
    .map_err(|_| RuleRegistryError::DatabaseUnavailable)?;
    Ok(id)
}

async fn install_rule_versions(
    transaction: &mut Transaction<'_, Postgres>,
    rule_pack_id: Uuid,
    rules: &[CompiledSiteRule],
    created_at_unix_ms: i64,
) -> Result<BTreeMap<String, Uuid>, RuleRegistryError> {
    let mut result = BTreeMap::new();
    for rule in rules {
        let rule_hash = decode_sha256(&rule.rule_hash)?;
        let compiled_rule =
            serde_json::to_value(&rule.source).map_err(|_| RuleRegistryError::InvalidArtifact)?;
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO rule_versions (\
                id, rule_pack_id, site_id, rule_hash, compiled_rule, enabled, created_at\
             ) VALUES (\
                $1, $2, $3, $4, $5, false, \
                to_timestamp($6::double precision / 1000.0)\
             ) ON CONFLICT (rule_pack_id, site_id) DO NOTHING",
        )
        .bind(id)
        .bind(rule_pack_id)
        .bind(&rule.source.id)
        .bind(&rule_hash)
        .bind(&compiled_rule)
        .bind(created_at_unix_ms)
        .execute(&mut **transaction)
        .await
        .map_err(|_| RuleRegistryError::DatabaseUnavailable)?;
        let stored: RuleVersionRow = sqlx::query_as(
            "SELECT id, rule_hash, compiled_rule FROM rule_versions \
             WHERE rule_pack_id = $1 AND site_id = $2 FOR UPDATE",
        )
        .bind(rule_pack_id)
        .bind(&rule.source.id)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|_| RuleRegistryError::DatabaseUnavailable)?;
        if stored.rule_hash != rule_hash || stored.compiled_rule != compiled_rule {
            return Err(RuleRegistryError::StorageInvariant);
        }
        result.insert(rule.source.id.clone(), stored.id);
    }
    Ok(result)
}

async fn install_metadata(
    transaction: &mut Transaction<'_, Postgres>,
    rule_pack_id: Uuid,
    envelope: &RulePackMetadataEnvelope,
    applied_at_unix_ms: i64,
) -> Result<(), RuleRegistryError> {
    let metadata = &envelope.metadata;
    let metadata_id = decode_sha256(&envelope.metadata_id)?;
    let release_id = decode_sha256(&metadata.release_id)?;
    let previous = metadata
        .previous_rule_pack_hash
        .as_deref()
        .map(decode_sha256)
        .transpose()?;
    let sequence =
        i64::try_from(metadata.sequence).map_err(|_| RuleRegistryError::InvalidArtifact)?;
    let trust_generation =
        i64::try_from(metadata.trust.generation).map_err(|_| RuleRegistryError::InvalidArtifact)?;
    let signed_envelope =
        serde_json::to_value(envelope).map_err(|_| RuleRegistryError::InvalidArtifact)?;
    let state = if matches!(
        metadata.rollout_stage,
        RulePackRolloutStage::Canary | RulePackRolloutStage::Regional
    ) {
        "staged"
    } else {
        "active"
    };
    sqlx::query(
        "INSERT INTO rule_pack_metadata (\
            metadata_id, sequence, release_id, rule_pack_id, previous_pack_hash, \
            rollout_stage, required_regions, eligible_regions, eligible_workers, \
            trust_generation, issued_at, expires_at, signed_envelope, state, applied_at\
         ) VALUES (\
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, \
            to_timestamp($11::double precision / 1000.0), \
            to_timestamp($12::double precision / 1000.0), $13, $14, \
            to_timestamp($15::double precision / 1000.0)\
         )",
    )
    .bind(metadata_id)
    .bind(sequence)
    .bind(release_id)
    .bind(rule_pack_id)
    .bind(previous)
    .bind(rollout_stage_name(metadata.rollout_stage))
    .bind(
        metadata
            .required_regions
            .iter()
            .cloned()
            .collect::<Vec<_>>(),
    )
    .bind(
        metadata
            .eligible_regions
            .iter()
            .cloned()
            .collect::<Vec<_>>(),
    )
    .bind(
        metadata
            .eligible_workers
            .iter()
            .cloned()
            .collect::<Vec<_>>(),
    )
    .bind(trust_generation)
    .bind(metadata.issued_at_unix_ms)
    .bind(metadata.expires_at_unix_ms)
    .bind(signed_envelope)
    .bind(state)
    .bind(applied_at_unix_ms)
    .execute(&mut **transaction)
    .await
    .map_err(|_| RuleRegistryError::DatabaseUnavailable)?;
    Ok(())
}

async fn install_promotions(
    transaction: &mut Transaction<'_, Postgres>,
    envelope: &RulePackMetadataEnvelope,
) -> Result<(), RuleRegistryError> {
    let metadata_id = decode_sha256(&envelope.metadata_id)?;
    for (site_id, promotion) in &envelope.metadata.promotions {
        sqlx::query(
            "INSERT INTO rule_pack_promotions (\
                metadata_id, site_id, promotion_id, promotion_sequence, rule_hash, expires_at\
             ) VALUES (\
                $1, $2, $3, $4, $5, \
                to_timestamp($6::double precision / 1000.0)\
             )",
        )
        .bind(&metadata_id)
        .bind(site_id)
        .bind(decode_sha256(&promotion.promotion_id)?)
        .bind(
            i64::try_from(promotion.promotion.sequence)
                .map_err(|_| RuleRegistryError::InvalidArtifact)?,
        )
        .bind(decode_sha256(&promotion.promotion.rule_hash)?)
        .bind(promotion.promotion.expires_at_unix_ms)
        .execute(&mut **transaction)
        .await
        .map_err(|_| RuleRegistryError::DatabaseUnavailable)?;
    }
    Ok(())
}

async fn apply_materialized_state(
    transaction: &mut Transaction<'_, Postgres>,
    previous: &RulePackRolloutRegistry,
    current: &RulePackRolloutRegistry,
    envelope: &RulePackMetadataEnvelope,
    rule_pack_id: Uuid,
    rule_version_ids: &BTreeMap<String, Uuid>,
    applied_at_unix_ms: i64,
) -> Result<(), RuleRegistryError> {
    let new_metadata_id = decode_sha256(&envelope.metadata_id)?;
    if let Some(previous_staged) = previous.staged()
        && previous_staged.metadata_id != envelope.metadata_id
    {
        let state = if envelope.metadata.rollout_stage == RulePackRolloutStage::Rollback {
            "rejected"
        } else {
            "superseded"
        };
        sqlx::query("UPDATE rule_pack_metadata SET state = $2 WHERE metadata_id = $1")
            .bind(decode_sha256(&previous_staged.metadata_id)?)
            .bind(state)
            .execute(&mut **transaction)
            .await
            .map_err(|_| RuleRegistryError::DatabaseUnavailable)?;
    }
    if let Some(previous_active) = previous.active()
        && current
            .active()
            .is_some_and(|active| active.metadata_id != previous_active.metadata_id)
    {
        let state = if envelope.metadata.rollout_stage == RulePackRolloutStage::Rollback
            && previous_active.rule_pack_hash
                == envelope
                    .metadata
                    .previous_rule_pack_hash
                    .as_deref()
                    .unwrap_or_default()
        {
            "rolled_back"
        } else {
            "superseded"
        };
        sqlx::query("UPDATE rule_pack_metadata SET state = $2 WHERE metadata_id = $1")
            .bind(decode_sha256(&previous_active.metadata_id)?)
            .bind(state)
            .execute(&mut **transaction)
            .await
            .map_err(|_| RuleRegistryError::DatabaseUnavailable)?;
    }
    let new_state = if current
        .staged()
        .is_some_and(|staged| staged.metadata_id == envelope.metadata_id)
    {
        "staged"
    } else {
        "active"
    };
    sqlx::query("UPDATE rule_pack_metadata SET state = $2 WHERE metadata_id = $1")
        .bind(&new_metadata_id)
        .bind(new_state)
        .execute(&mut **transaction)
        .await
        .map_err(|_| RuleRegistryError::DatabaseUnavailable)?;

    if let Some(previous_staged) = previous.staged()
        && current
            .staged()
            .is_none_or(|staged| staged.rule_pack_hash != previous_staged.rule_pack_hash)
    {
        sqlx::query(
            "UPDATE rule_packs SET state = 'rejected' \
             WHERE pack_hash = $1 AND state = 'staged'",
        )
        .bind(decode_sha256(&previous_staged.rule_pack_hash)?)
        .execute(&mut **transaction)
        .await
        .map_err(|_| RuleRegistryError::DatabaseUnavailable)?;
    }
    if let Some(previous_active) = previous.active()
        && current
            .active()
            .is_some_and(|active| active.rule_pack_hash != previous_active.rule_pack_hash)
    {
        sqlx::query(
            "UPDATE rule_packs SET state = 'retired' \
             WHERE pack_hash = $1 AND state = 'active'",
        )
        .bind(decode_sha256(&previous_active.rule_pack_hash)?)
        .execute(&mut **transaction)
        .await
        .map_err(|_| RuleRegistryError::DatabaseUnavailable)?;
    }
    if current
        .staged()
        .is_some_and(|staged| staged.metadata_id == envelope.metadata_id)
    {
        sqlx::query(
            "UPDATE rule_packs \
             SET state = 'staged', published_at = NULL, \
                 expires_at = to_timestamp($2::double precision / 1000.0) \
             WHERE id = $1",
        )
        .bind(rule_pack_id)
        .bind(envelope.metadata.expires_at_unix_ms)
        .execute(&mut **transaction)
        .await
        .map_err(|_| RuleRegistryError::DatabaseUnavailable)?;
        return Ok(());
    }

    sqlx::query(
        "UPDATE rule_packs \
         SET state = 'active', published_at = COALESCE(published_at, \
             to_timestamp($2::double precision / 1000.0)), \
             expires_at = to_timestamp($3::double precision / 1000.0) \
         WHERE id = $1",
    )
    .bind(rule_pack_id)
    .bind(applied_at_unix_ms)
    .bind(envelope.metadata.expires_at_unix_ms)
    .execute(&mut **transaction)
    .await
    .map_err(|_| RuleRegistryError::DatabaseUnavailable)?;
    sqlx::query("UPDATE rule_versions SET enabled = false WHERE enabled")
        .execute(&mut **transaction)
        .await
        .map_err(|_| RuleRegistryError::DatabaseUnavailable)?;
    sqlx::query(
        "UPDATE sites SET state = 'quarantined', updated_at = clock_timestamp() \
         WHERE state = 'promoted'",
    )
    .execute(&mut **transaction)
    .await
    .map_err(|_| RuleRegistryError::DatabaseUnavailable)?;
    for site_id in envelope.metadata.promotions.keys() {
        let rule_version_id = rule_version_ids
            .get(site_id)
            .ok_or(RuleRegistryError::StorageInvariant)?;
        let affected = sqlx::query(
            "UPDATE rule_versions SET enabled = true \
             WHERE id = $1 AND rule_pack_id = $2",
        )
        .bind(rule_version_id)
        .bind(rule_pack_id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| RuleRegistryError::DatabaseUnavailable)?
        .rows_affected();
        if affected != 1 {
            return Err(RuleRegistryError::StorageInvariant);
        }
        sqlx::query(
            "UPDATE sites SET state = 'promoted', updated_at = clock_timestamp() WHERE id = $1",
        )
        .bind(site_id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| RuleRegistryError::DatabaseUnavailable)?;
    }
    Ok(())
}

async fn persist_registry(
    transaction: &mut Transaction<'_, Postgres>,
    registry: &RulePackRolloutRegistry,
    updated_at_unix_ms: i64,
) -> Result<(), RuleRegistryError> {
    let state = serde_json::to_value(registry).map_err(|_| RuleRegistryError::StorageInvariant)?;
    let highest_sequence = i64::try_from(registry.highest_sequence())
        .map_err(|_| RuleRegistryError::InvalidArtifact)?;
    let trust_generation = i64::try_from(registry.current_trust().generation)
        .map_err(|_| RuleRegistryError::InvalidArtifact)?;
    let active = registry
        .active()
        .map(|value| decode_sha256(&value.metadata_id))
        .transpose()?;
    let staged = registry
        .staged()
        .map(|value| decode_sha256(&value.metadata_id))
        .transpose()?;
    let last_known_good = registry
        .last_known_good()
        .map(|value| decode_sha256(&value.metadata_id))
        .transpose()?;
    sqlx::query(
        "INSERT INTO rule_pack_registry (\
            singleton, registry_state, highest_sequence, current_trust_generation, \
            active_metadata_id, staged_metadata_id, last_known_good_metadata_id, updated_at\
         ) VALUES (\
            true, $1, $2, $3, $4, $5, $6, \
            to_timestamp($7::double precision / 1000.0)\
         ) ON CONFLICT (singleton) DO UPDATE SET \
            registry_state = EXCLUDED.registry_state, \
            highest_sequence = EXCLUDED.highest_sequence, \
            current_trust_generation = EXCLUDED.current_trust_generation, \
            active_metadata_id = EXCLUDED.active_metadata_id, \
            staged_metadata_id = EXCLUDED.staged_metadata_id, \
            last_known_good_metadata_id = EXCLUDED.last_known_good_metadata_id, \
            updated_at = EXCLUDED.updated_at",
    )
    .bind(state)
    .bind(highest_sequence)
    .bind(trust_generation)
    .bind(active)
    .bind(staged)
    .bind(last_known_good)
    .bind(updated_at_unix_ms)
    .execute(&mut **transaction)
    .await
    .map_err(|_| RuleRegistryError::DatabaseUnavailable)?;
    Ok(())
}

async fn persist_promotion_high_water(
    transaction: &mut Transaction<'_, Postgres>,
    registry: &RulePackRolloutRegistry,
    envelope: &RulePackMetadataEnvelope,
    updated_at_unix_ms: i64,
) -> Result<(), RuleRegistryError> {
    let metadata_id = decode_sha256(&envelope.metadata_id)?;
    for (site_id, promotion) in &envelope.metadata.promotions {
        let expected = registry
            .promotion_high_water()
            .get(site_id)
            .copied()
            .ok_or(RuleRegistryError::StorageInvariant)?;
        if expected != promotion.promotion.sequence {
            return Err(RuleRegistryError::StorageInvariant);
        }
        let affected = sqlx::query(
            "INSERT INTO rule_site_promotion_high_water (\
                site_id, highest_sequence, promotion_id, metadata_id, updated_at\
             ) VALUES (\
                $1, $2, $3, $4, to_timestamp($5::double precision / 1000.0)\
             ) ON CONFLICT (site_id) DO UPDATE SET \
                highest_sequence = EXCLUDED.highest_sequence, \
                promotion_id = EXCLUDED.promotion_id, \
                metadata_id = EXCLUDED.metadata_id, \
                updated_at = EXCLUDED.updated_at \
             WHERE rule_site_promotion_high_water.highest_sequence \
                   < EXCLUDED.highest_sequence",
        )
        .bind(site_id)
        .bind(i64::try_from(expected).map_err(|_| RuleRegistryError::InvalidArtifact)?)
        .bind(decode_sha256(&promotion.promotion_id)?)
        .bind(&metadata_id)
        .bind(updated_at_unix_ms)
        .execute(&mut **transaction)
        .await
        .map_err(|_| RuleRegistryError::DatabaseUnavailable)?
        .rows_affected();
        if affected != 1 {
            return Err(RuleRegistryError::StorageInvariant);
        }
    }
    Ok(())
}

async fn validate_persisted_promotion_high_water(
    transaction: &mut Transaction<'_, Postgres>,
    registry: &RulePackRolloutRegistry,
) -> Result<(), RuleRegistryError> {
    let stored: Vec<PromotionHighWaterRow> = sqlx::query_as(
        "SELECT site_id, highest_sequence \
         FROM rule_site_promotion_high_water ORDER BY site_id FOR UPDATE",
    )
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| RuleRegistryError::DatabaseUnavailable)?;
    let mut stored_by_site = BTreeMap::new();
    for row in stored {
        let sequence =
            u64::try_from(row.highest_sequence).map_err(|_| RuleRegistryError::StorageInvariant)?;
        if stored_by_site.insert(row.site_id, sequence).is_some() {
            return Err(RuleRegistryError::StorageInvariant);
        }
    }
    if &stored_by_site != registry.promotion_high_water() {
        return Err(RuleRegistryError::StorageInvariant);
    }
    Ok(())
}

fn validate_persisted_registry(
    registry: &RulePackRolloutRegistry,
    persisted: &RegistryRow,
) -> Result<(), RuleRegistryError> {
    let expected_highest = i64::try_from(registry.highest_sequence())
        .map_err(|_| RuleRegistryError::StorageInvariant)?;
    let expected_generation = i64::try_from(registry.current_trust().generation)
        .map_err(|_| RuleRegistryError::StorageInvariant)?;
    if persisted.highest_sequence != expected_highest
        || persisted.current_trust_generation != expected_generation
        || persisted.active_metadata_id
            != registry
                .active()
                .map(|value| decode_sha256(&value.metadata_id))
                .transpose()?
        || persisted.staged_metadata_id
            != registry
                .staged()
                .map(|value| decode_sha256(&value.metadata_id))
                .transpose()?
        || persisted.last_known_good_metadata_id
            != registry
                .last_known_good()
                .map(|value| decode_sha256(&value.metadata_id))
                .transpose()?
    {
        return Err(RuleRegistryError::StorageInvariant);
    }
    Ok(())
}

fn required_path(name: &str) -> Result<PathBuf, RuleRegistryError> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or(RuleRegistryError::InvalidConfiguration)
}

fn optional_initial_trust() -> Result<Option<(RulePackTrustV1, String)>, RuleRegistryError> {
    match (
        env::var_os(INITIAL_RULE_TRUST_FILE_ENV),
        env::var(INITIAL_RULE_TRUST_ID_ENV),
    ) {
        (None, Err(_)) => Ok(None),
        (Some(path), Ok(expected)) if !path.is_empty() && valid_sha256(&expected) => Ok(Some((
            load_bounded_json(Path::new(&path), MAX_TRUST_BYTES)?,
            expected,
        ))),
        _ => Err(RuleRegistryError::InvalidConfiguration),
    }
}

fn load_bounded_json<T: DeserializeOwned>(
    path: &Path,
    maximum_bytes: usize,
) -> Result<T, RuleRegistryError> {
    let bytes = fs::read(path).map_err(|_| RuleRegistryError::InvalidConfiguration)?;
    if bytes.len() > maximum_bytes {
        return Err(RuleRegistryError::InvalidArtifact);
    }
    serde_json::from_slice(&bytes).map_err(|_| RuleRegistryError::InvalidArtifact)
}

fn decode_sha256(value: &str) -> Result<Vec<u8>, RuleRegistryError> {
    if !valid_sha256(value) {
        return Err(RuleRegistryError::InvalidArtifact);
    }
    hex::decode(value).map_err(|_| RuleRegistryError::InvalidArtifact)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

const fn rollout_stage_name(stage: RulePackRolloutStage) -> &'static str {
    match stage {
        RulePackRolloutStage::Canary => "canary",
        RulePackRolloutStage::Regional => "regional",
        RulePackRolloutStage::General => "general",
        RulePackRolloutStage::Rollback => "rollback",
    }
}

fn now_unix_ms() -> Result<i64, RuleRegistryError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RuleRegistryError::ClockUnavailable)?;
    i64::try_from(duration.as_millis()).map_err(|_| RuleRegistryError::ClockUnavailable)
}

#[derive(FromRow)]
struct RegistryRow {
    registry_state: serde_json::Value,
    highest_sequence: i64,
    current_trust_generation: i64,
    active_metadata_id: Option<Vec<u8>>,
    staged_metadata_id: Option<Vec<u8>>,
    last_known_good_metadata_id: Option<Vec<u8>>,
}

#[derive(FromRow)]
struct TrustRootRow {
    trust_id: Vec<u8>,
    threshold: i32,
    keys: serde_json::Value,
    expires_at_unix_ms: i64,
}

#[derive(FromRow)]
struct RuleVersionRow {
    id: Uuid,
    rule_hash: Vec<u8>,
    compiled_rule: serde_json::Value,
}

#[derive(FromRow)]
struct PromotionHighWaterRow {
    site_id: String,
    highest_sequence: i64,
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum RuleRegistryError {
    #[error("rule registry operator configuration is invalid")]
    InvalidConfiguration,
    #[error("rule registry database is unavailable")]
    DatabaseUnavailable,
    #[error("rule registry artifact is invalid")]
    InvalidArtifact,
    #[error("rule registry requires an explicitly pinned initial trust root")]
    InitialTrustRequired,
    #[error("rule registry initial trust pin is invalid")]
    InvalidInitialTrustPin,
    #[error("rule registry transition is invalid")]
    InvalidTransition,
    #[error("rule registry persisted state is invalid")]
    StorageInvariant,
    #[error("rule registry clock is unavailable")]
    ClockUnavailable,
}

#[derive(Serialize)]
pub struct AppliedRulePackOutput<'a> {
    pub schema: &'static str,
    pub metadata_id: &'a str,
    pub sequence: u64,
    pub rollout_stage: &'static str,
    pub rule_pack_hash: &'a str,
    pub trust_generation: u64,
}

impl AppliedRulePack {
    #[must_use]
    pub fn output(&self) -> AppliedRulePackOutput<'_> {
        AppliedRulePackOutput {
            schema: "socialname.dev/rule-pack-apply/v1",
            metadata_id: &self.metadata_id,
            sequence: self.sequence,
            rollout_stage: rollout_stage_name(self.rollout_stage),
            rule_pack_hash: &self.rule_pack_hash,
            trust_generation: self.trust_generation,
        }
    }
}
