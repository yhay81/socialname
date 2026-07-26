use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use socialname_rule_compiler::{CompiledRulePack, RuleCompiler};

use crate::{
    ED25519_ALGORITHM, PromotionEnvelope, PromotionTrustPolicy, PromotionVerifier,
    ValidatedPromotion,
};

pub const RULE_PACK_TRUST_V1: &str = "socialname.dev/rule-pack-trust/v1";
pub const RULE_PACK_METADATA_V1: &str = "socialname.dev/rule-pack-metadata/v1";
pub const MAX_RULE_PACK_METADATA_VALIDITY_MS: i64 = 24 * 60 * 60 * 1_000;

const TRUST_SIGNING_DOMAIN: &[u8] = b"socialname.dev/rule-pack-trust/v1\0";
const METADATA_SIGNING_DOMAIN: &[u8] = b"socialname.dev/rule-pack-metadata/v1\0";
const RELEASE_ID_DOMAIN: &[u8] = b"socialname.dev/rule-pack-release/v1\0";
const MAX_KEYS: usize = 16;
const MAX_PROMOTIONS: usize = 256;
const MAX_REGIONS: usize = 16;
const MAX_WORKERS: usize = 256;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RulePackTrustV1 {
    pub schema: String,
    pub generation: u64,
    pub threshold: u16,
    pub keys: BTreeMap<String, String>,
    pub expires_at_unix_ms: i64,
}

impl RulePackTrustV1 {
    pub fn validate_at(&self, evaluated_at_unix_ms: i64) -> Result<(), RulePackMetadataError> {
        validate_trust(self, evaluated_at_unix_ms)
    }

    pub fn content_id(&self) -> Result<String, RulePackMetadataError> {
        let bytes = trust_signing_bytes(self)?;
        Ok(sha256_hex(&bytes))
    }

    fn verifying_keys(&self) -> Result<BTreeMap<String, VerifyingKey>, RulePackMetadataError> {
        self.keys
            .iter()
            .map(|(key_id, encoded)| {
                let decoded =
                    hex::decode(encoded).map_err(|_| RulePackMetadataError::InvalidTrust)?;
                let bytes: [u8; 32] = decoded
                    .try_into()
                    .map_err(|_| RulePackMetadataError::InvalidTrust)?;
                let key = VerifyingKey::from_bytes(&bytes)
                    .map_err(|_| RulePackMetadataError::InvalidTrust)?;
                Ok((key_id.clone(), key))
            })
            .collect()
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RulePackRolloutStage {
    Canary,
    Regional,
    General,
    Rollback,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RulePackPromotionBinding {
    pub promotion_id: String,
    pub sequence: u64,
    pub rule_hash: String,
    pub expires_at_unix_ms: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RulePackMetadataV1 {
    pub schema: String,
    pub sequence: u64,
    pub release_id: String,
    pub rule_pack_hash: String,
    pub previous_rule_pack_hash: Option<String>,
    pub required_regions: BTreeSet<String>,
    pub rollout_stage: RulePackRolloutStage,
    pub eligible_regions: BTreeSet<String>,
    pub eligible_workers: BTreeSet<String>,
    pub issued_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub trust: RulePackTrustV1,
    pub promotions: BTreeMap<String, PromotionEnvelope>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RulePackMetadataEnvelope {
    pub metadata_id: String,
    pub algorithm: String,
    pub metadata: RulePackMetadataV1,
    pub signatures: BTreeMap<String, String>,
}

#[derive(Clone)]
pub struct RulePackMetadataSigningKey {
    key_id: String,
    signing_key: SigningKey,
}

impl std::fmt::Debug for RulePackMetadataSigningKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RulePackMetadataSigningKey")
            .field("key_id", &self.key_id)
            .field("signing_key", &"[REDACTED]")
            .finish()
    }
}

impl RulePackMetadataSigningKey {
    pub fn from_seed(
        key_id: impl Into<String>,
        seed: [u8; 32],
    ) -> Result<Self, RulePackMetadataError> {
        let key_id = key_id.into();
        if !valid_label(&key_id) {
            return Err(RulePackMetadataError::InvalidKeyId);
        }
        Ok(Self {
            key_id,
            signing_key: SigningKey::from_bytes(&seed),
        })
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    #[must_use]
    pub fn verifying_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }
}

pub struct RulePackMetadataBuildRequest<'a> {
    pub sequence: u64,
    pub rule_pack: &'a CompiledRulePack,
    pub previous_rule_pack_hash: Option<&'a str>,
    pub required_regions: &'a BTreeSet<String>,
    pub rollout_stage: RulePackRolloutStage,
    pub eligible_regions: &'a BTreeSet<String>,
    pub eligible_workers: &'a BTreeSet<String>,
    pub issued_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub trust: RulePackTrustV1,
    pub promotions: &'a [PromotionEnvelope],
}

#[derive(Clone, Debug, Default)]
pub struct RulePackMetadataBuilder;

impl RulePackMetadataBuilder {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    pub fn build(
        &self,
        signing_keys: &[RulePackMetadataSigningKey],
        request: RulePackMetadataBuildRequest<'_>,
    ) -> Result<RulePackMetadataEnvelope, RulePackMetadataError> {
        let promotions = request
            .promotions
            .iter()
            .map(|promotion| (promotion.promotion.site_id.clone(), promotion.to_owned()))
            .collect::<BTreeMap<_, _>>();
        if promotions.len() != request.promotions.len() {
            return Err(RulePackMetadataError::InvalidPromotions);
        }
        let rule_hashes = promotions
            .iter()
            .map(|(site_id, promotion)| (site_id.clone(), promotion.promotion.rule_hash.clone()))
            .collect::<BTreeMap<_, _>>();
        let release_id = release_id(
            &request.rule_pack.content_hash,
            request.previous_rule_pack_hash,
            request.required_regions,
            &rule_hashes,
        )?;
        let metadata = RulePackMetadataV1 {
            schema: RULE_PACK_METADATA_V1.to_owned(),
            sequence: request.sequence,
            release_id,
            rule_pack_hash: request.rule_pack.content_hash.clone(),
            previous_rule_pack_hash: request.previous_rule_pack_hash.map(str::to_owned),
            required_regions: request.required_regions.clone(),
            rollout_stage: request.rollout_stage,
            eligible_regions: request.eligible_regions.clone(),
            eligible_workers: request.eligible_workers.clone(),
            issued_at_unix_ms: request.issued_at_unix_ms,
            expires_at_unix_ms: request.expires_at_unix_ms,
            trust: request.trust,
            promotions,
        };
        validate_metadata_shape(&metadata, request.issued_at_unix_ms)?;
        validate_pack(&metadata, request.rule_pack)?;
        validate_embedded_promotions(&metadata, request.issued_at_unix_ms)?;
        let signing_bytes = metadata_signing_bytes(&metadata)?;
        let metadata_id = sha256_hex(&signing_bytes);
        let signatures = signing_keys
            .iter()
            .map(|key| {
                (
                    key.key_id.clone(),
                    hex::encode(key.signing_key.sign(&signing_bytes).to_bytes()),
                )
            })
            .collect::<BTreeMap<_, _>>();
        if signatures.len() != signing_keys.len() || signatures.is_empty() {
            return Err(RulePackMetadataError::InvalidSignatures);
        }
        Ok(RulePackMetadataEnvelope {
            metadata_id,
            algorithm: ED25519_ALGORITHM.to_owned(),
            metadata,
            signatures,
        })
    }
}

#[derive(Clone, Debug)]
pub struct ValidatedRulePackMetadata {
    envelope: RulePackMetadataEnvelope,
    source_trust_id: String,
    promotions: BTreeMap<String, ValidatedPromotion>,
}

impl ValidatedRulePackMetadata {
    #[must_use]
    pub const fn envelope(&self) -> &RulePackMetadataEnvelope {
        &self.envelope
    }

    #[must_use]
    pub const fn metadata(&self) -> &RulePackMetadataV1 {
        &self.envelope.metadata
    }

    #[must_use]
    pub fn promotion(&self, site_id: &str) -> Option<&ValidatedPromotion> {
        self.promotions.get(site_id)
    }

    #[must_use]
    pub fn source_trust_id(&self) -> &str {
        &self.source_trust_id
    }

    #[must_use]
    pub fn permits_worker(&self, region: &str, worker_id: &str) -> bool {
        let metadata = self.metadata();
        if !metadata.required_regions.contains(region) || !valid_label(worker_id) {
            return false;
        }
        match metadata.rollout_stage {
            RulePackRolloutStage::Canary => {
                metadata.eligible_regions.contains(region)
                    && metadata.eligible_workers.contains(worker_id)
            }
            RulePackRolloutStage::Regional => metadata.eligible_regions.contains(region),
            RulePackRolloutStage::General | RulePackRolloutStage::Rollback => true,
        }
    }

    #[must_use]
    pub const fn permits_customer_work(&self) -> bool {
        matches!(
            self.envelope.metadata.rollout_stage,
            RulePackRolloutStage::General | RulePackRolloutStage::Rollback
        )
    }

    pub fn validate_pack(&self, rule_pack: &CompiledRulePack) -> Result<(), RulePackMetadataError> {
        validate_pack(self.metadata(), rule_pack)
    }
}

#[derive(Clone, Debug, Default)]
pub struct RulePackMetadataVerifier;

impl RulePackMetadataVerifier {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    pub fn validate_json_at(
        &self,
        input: &[u8],
        current_trust: &RulePackTrustV1,
        verified_at_unix_ms: i64,
    ) -> Result<ValidatedRulePackMetadata, RulePackMetadataError> {
        let envelope: RulePackMetadataEnvelope =
            serde_json::from_slice(input).map_err(|_| RulePackMetadataError::MalformedArtifact)?;
        self.validate_at(&envelope, current_trust, verified_at_unix_ms)
    }

    pub fn validate_at(
        &self,
        envelope: &RulePackMetadataEnvelope,
        current_trust: &RulePackTrustV1,
        verified_at_unix_ms: i64,
    ) -> Result<ValidatedRulePackMetadata, RulePackMetadataError> {
        validate_trust(current_trust, verified_at_unix_ms)?;
        validate_metadata_shape(&envelope.metadata, verified_at_unix_ms)?;
        if envelope.algorithm != ED25519_ALGORITHM {
            return Err(RulePackMetadataError::UnsupportedAlgorithm);
        }
        let signing_bytes = metadata_signing_bytes(&envelope.metadata)?;
        if envelope.metadata_id != sha256_hex(&signing_bytes) {
            return Err(RulePackMetadataError::InvalidMetadataId);
        }
        validate_trust_rotation(current_trust, &envelope.metadata.trust)?;
        verify_threshold(&signing_bytes, &envelope.signatures, current_trust)?;
        if envelope.metadata.trust != *current_trust {
            verify_threshold(
                &signing_bytes,
                &envelope.signatures,
                &envelope.metadata.trust,
            )?;
        }
        let allowed_keys = current_trust
            .keys
            .keys()
            .chain(envelope.metadata.trust.keys.keys())
            .collect::<BTreeSet<_>>();
        if envelope.signatures.is_empty()
            || envelope.signatures.len() > MAX_KEYS * 2
            || envelope
                .signatures
                .keys()
                .any(|key_id| !allowed_keys.contains(key_id))
        {
            return Err(RulePackMetadataError::InvalidSignatures);
        }
        let promotions = validate_embedded_promotions(&envelope.metadata, verified_at_unix_ms)?;
        Ok(ValidatedRulePackMetadata {
            envelope: envelope.clone(),
            source_trust_id: current_trust.content_id()?,
            promotions,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActivatedRulePackMetadata {
    pub metadata_id: String,
    pub sequence: u64,
    pub release_id: String,
    pub rule_pack_hash: String,
    pub previous_rule_pack_hash: Option<String>,
    pub rollout_stage: RulePackRolloutStage,
    pub required_regions: BTreeSet<String>,
    pub eligible_regions: BTreeSet<String>,
    pub eligible_workers: BTreeSet<String>,
    pub expires_at_unix_ms: i64,
    pub promotion_bindings: BTreeMap<String, RulePackPromotionBinding>,
}

impl ActivatedRulePackMetadata {
    fn from_validated(validated: &ValidatedRulePackMetadata) -> Self {
        let metadata = validated.metadata();
        let promotion_bindings = metadata
            .promotions
            .iter()
            .map(|(site_id, envelope)| {
                (
                    site_id.clone(),
                    RulePackPromotionBinding {
                        promotion_id: envelope.promotion_id.clone(),
                        sequence: envelope.promotion.sequence,
                        rule_hash: envelope.promotion.rule_hash.clone(),
                        expires_at_unix_ms: envelope.promotion.expires_at_unix_ms,
                    },
                )
            })
            .collect();
        Self {
            metadata_id: validated.envelope.metadata_id.clone(),
            sequence: metadata.sequence,
            release_id: metadata.release_id.clone(),
            rule_pack_hash: metadata.rule_pack_hash.clone(),
            previous_rule_pack_hash: metadata.previous_rule_pack_hash.clone(),
            rollout_stage: metadata.rollout_stage,
            required_regions: metadata.required_regions.clone(),
            eligible_regions: metadata.eligible_regions.clone(),
            eligible_workers: metadata.eligible_workers.clone(),
            expires_at_unix_ms: metadata.expires_at_unix_ms,
            promotion_bindings,
        }
    }

    fn permits_worker(&self, region: &str, worker_id: &str) -> bool {
        if !self.required_regions.contains(region) || !valid_label(worker_id) {
            return false;
        }
        match self.rollout_stage {
            RulePackRolloutStage::Canary => {
                self.eligible_regions.contains(region) && self.eligible_workers.contains(worker_id)
            }
            RulePackRolloutStage::Regional => self.eligible_regions.contains(region),
            RulePackRolloutStage::General | RulePackRolloutStage::Rollback => true,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RulePackRolloutRegistry {
    current_trust: RulePackTrustV1,
    highest_sequence: u64,
    promotion_high_water: BTreeMap<String, u64>,
    active: Option<ActivatedRulePackMetadata>,
    staged: Option<ActivatedRulePackMetadata>,
    last_known_good: Option<ActivatedRulePackMetadata>,
}

impl RulePackRolloutRegistry {
    pub fn new(
        initial_trust: RulePackTrustV1,
        evaluated_at_unix_ms: i64,
    ) -> Result<Self, RulePackMetadataError> {
        initial_trust.validate_at(evaluated_at_unix_ms)?;
        Ok(Self {
            current_trust: initial_trust,
            highest_sequence: 0,
            promotion_high_water: BTreeMap::new(),
            active: None,
            staged: None,
            last_known_good: None,
        })
    }

    pub fn apply(
        &mut self,
        validated: &ValidatedRulePackMetadata,
        rule_pack: &CompiledRulePack,
        applied_at_unix_ms: i64,
    ) -> Result<&ActivatedRulePackMetadata, RulePackMetadataError> {
        if validated.source_trust_id != self.current_trust.content_id()? {
            return Err(RulePackMetadataError::TrustStateMismatch);
        }
        let metadata = validated.metadata();
        if metadata.sequence <= self.highest_sequence {
            return Err(RulePackMetadataError::SequenceReplay);
        }
        if metadata.issued_at_unix_ms > applied_at_unix_ms
            || metadata.expires_at_unix_ms <= applied_at_unix_ms
        {
            return Err(RulePackMetadataError::ExpiredMetadata);
        }
        validated.validate_pack(rule_pack)?;
        for (site_id, promotion) in &metadata.promotions {
            if promotion.promotion.sequence
                <= self
                    .promotion_high_water
                    .get(site_id)
                    .copied()
                    .unwrap_or_default()
            {
                return Err(RulePackMetadataError::PromotionReplay);
            }
        }
        let activated = ActivatedRulePackMetadata::from_validated(validated);
        match metadata.rollout_stage {
            RulePackRolloutStage::Rollback => self.apply_rollback(activated)?,
            RulePackRolloutStage::Canary
            | RulePackRolloutStage::Regional
            | RulePackRolloutStage::General => self.apply_rollout(activated)?,
        }
        self.highest_sequence = metadata.sequence;
        self.current_trust = metadata.trust.clone();
        for (site_id, promotion) in &metadata.promotions {
            self.promotion_high_water
                .insert(site_id.clone(), promotion.promotion.sequence);
        }
        match metadata.rollout_stage {
            RulePackRolloutStage::Canary | RulePackRolloutStage::Regional => self
                .staged
                .as_ref()
                .ok_or(RulePackMetadataError::RegistryInvariant),
            RulePackRolloutStage::General | RulePackRolloutStage::Rollback => self
                .active
                .as_ref()
                .ok_or(RulePackMetadataError::RegistryInvariant),
        }
    }

    fn apply_rollout(
        &mut self,
        candidate: ActivatedRulePackMetadata,
    ) -> Result<(), RulePackMetadataError> {
        if let Some(staged) = self.staged.as_ref() {
            if staged.release_id != candidate.release_id
                || staged.rule_pack_hash != candidate.rule_pack_hash
                || staged.previous_rule_pack_hash != candidate.previous_rule_pack_hash
                || staged.required_regions != candidate.required_regions
                || staged
                    .promotion_bindings
                    .keys()
                    .ne(candidate.promotion_bindings.keys())
                || staged.promotion_bindings.iter().any(|(site_id, prior)| {
                    candidate
                        .promotion_bindings
                        .get(site_id)
                        .is_none_or(|next| next.rule_hash != prior.rule_hash)
                })
            {
                return Err(RulePackMetadataError::RolloutMismatch);
            }
            validate_rollout_progression(staged, &candidate)?;
            if candidate.rollout_stage == RulePackRolloutStage::General {
                self.last_known_good = self.active.take();
                self.active = Some(candidate);
                self.staged = None;
            } else {
                self.staged = Some(candidate);
            }
            return Ok(());
        }

        if let Some(active) = self.active.as_ref() {
            if candidate.rule_pack_hash == active.rule_pack_hash {
                if candidate.rollout_stage != RulePackRolloutStage::General
                    || candidate.release_id != active.release_id
                    || candidate.previous_rule_pack_hash != active.previous_rule_pack_hash
                    || candidate
                        .promotion_bindings
                        .keys()
                        .ne(active.promotion_bindings.keys())
                {
                    return Err(RulePackMetadataError::RolloutMismatch);
                }
                self.active = Some(candidate);
                return Ok(());
            }
            if candidate.previous_rule_pack_hash.as_deref() != Some(active.rule_pack_hash.as_str())
                || candidate.rollout_stage != RulePackRolloutStage::Canary
            {
                return Err(RulePackMetadataError::RolloutMismatch);
            }
        } else if candidate.previous_rule_pack_hash.is_some()
            || candidate.rollout_stage != RulePackRolloutStage::Canary
        {
            return Err(RulePackMetadataError::RolloutMismatch);
        }
        self.staged = Some(candidate);
        Ok(())
    }

    fn apply_rollback(
        &mut self,
        candidate: ActivatedRulePackMetadata,
    ) -> Result<(), RulePackMetadataError> {
        let failed_hash = candidate
            .previous_rule_pack_hash
            .as_deref()
            .ok_or(RulePackMetadataError::RollbackMismatch)?;
        if let Some(staged) = self.staged.as_ref() {
            let active = self
                .active
                .as_ref()
                .ok_or(RulePackMetadataError::RollbackMismatch)?;
            if staged.rule_pack_hash != failed_hash
                || active.rule_pack_hash != candidate.rule_pack_hash
            {
                return Err(RulePackMetadataError::RollbackMismatch);
            }
            self.active = Some(candidate);
            self.staged = None;
            return Ok(());
        }
        if let (Some(active), Some(last_known_good)) =
            (self.active.as_ref(), self.last_known_good.as_ref())
        {
            if active.rule_pack_hash != failed_hash
                || last_known_good.rule_pack_hash != candidate.rule_pack_hash
            {
                return Err(RulePackMetadataError::RollbackMismatch);
            }
            self.active = Some(candidate);
            self.staged = None;
            self.last_known_good = None;
            return Ok(());
        }
        if self.active.as_ref().is_some_and(|active| {
            active.rollout_stage == RulePackRolloutStage::Rollback
                && active.release_id == candidate.release_id
                && active.rule_pack_hash == candidate.rule_pack_hash
                && active.previous_rule_pack_hash == candidate.previous_rule_pack_hash
        }) {
            self.active = Some(candidate);
            return Ok(());
        }
        Err(RulePackMetadataError::RollbackMismatch)
    }

    pub fn select_at(
        &self,
        region: &str,
        worker_id: &str,
        selected_at_unix_ms: i64,
    ) -> Result<&ActivatedRulePackMetadata, RulePackMetadataError> {
        if let Some(staged) = self.staged.as_ref()
            && staged.expires_at_unix_ms > selected_at_unix_ms
            && staged.permits_worker(region, worker_id)
        {
            return Ok(staged);
        }
        let active = self
            .active
            .as_ref()
            .ok_or(RulePackMetadataError::NoEligibleRulePack)?;
        if active.expires_at_unix_ms <= selected_at_unix_ms
            || !active.permits_worker(region, worker_id)
        {
            return Err(RulePackMetadataError::NoEligibleRulePack);
        }
        Ok(active)
    }

    #[must_use]
    pub const fn current_trust(&self) -> &RulePackTrustV1 {
        &self.current_trust
    }

    #[must_use]
    pub const fn highest_sequence(&self) -> u64 {
        self.highest_sequence
    }

    #[must_use]
    pub const fn promotion_high_water(&self) -> &BTreeMap<String, u64> {
        &self.promotion_high_water
    }

    #[must_use]
    pub const fn active(&self) -> Option<&ActivatedRulePackMetadata> {
        self.active.as_ref()
    }

    #[must_use]
    pub const fn staged(&self) -> Option<&ActivatedRulePackMetadata> {
        self.staged.as_ref()
    }

    #[must_use]
    pub const fn last_known_good(&self) -> Option<&ActivatedRulePackMetadata> {
        self.last_known_good.as_ref()
    }
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum RulePackMetadataError {
    #[error("rule-pack trust metadata is invalid or expired")]
    InvalidTrust,
    #[error("rule-pack signing key id is invalid")]
    InvalidKeyId,
    #[error("rule-pack metadata artifact is malformed")]
    MalformedArtifact,
    #[error("rule-pack metadata signing algorithm is unsupported")]
    UnsupportedAlgorithm,
    #[error("rule-pack metadata identity is invalid")]
    InvalidMetadataId,
    #[error("rule-pack metadata signatures are invalid")]
    InvalidSignatures,
    #[error("rule-pack trust rotation is invalid")]
    InvalidTrustRotation,
    #[error("rule-pack metadata payload is invalid")]
    InvalidMetadata,
    #[error("rule-pack metadata has expired or is not yet valid")]
    ExpiredMetadata,
    #[error("rule-pack metadata validity exceeds the maximum")]
    ExcessiveValidity,
    #[error("rule-pack rollout policy is invalid")]
    InvalidRollout,
    #[error("rule-pack embedded promotions are invalid")]
    InvalidPromotions,
    #[error("rule-pack bytes do not match signed metadata")]
    RulePackMismatch,
    #[error("rule-pack metadata sequence was already seen")]
    SequenceReplay,
    #[error("rule-pack promotion sequence was already seen")]
    PromotionReplay,
    #[error("rule-pack rollout does not extend the staged or active release")]
    RolloutMismatch,
    #[error("rule-pack rollback does not restore the retained release")]
    RollbackMismatch,
    #[error("rule-pack metadata was verified from a different trust state")]
    TrustStateMismatch,
    #[error("no unexpired rule pack is eligible for this worker")]
    NoEligibleRulePack,
    #[error("rule-pack registry state is invalid")]
    RegistryInvariant,
    #[error("rule-pack canonical serialization failed")]
    CanonicalSerialization,
}

fn validate_trust(
    trust: &RulePackTrustV1,
    evaluated_at_unix_ms: i64,
) -> Result<(), RulePackMetadataError> {
    if trust.schema != RULE_PACK_TRUST_V1
        || trust.generation == 0
        || trust.keys.is_empty()
        || trust.keys.len() > MAX_KEYS
        || trust.threshold == 0
        || usize::from(trust.threshold) > trust.keys.len()
        || trust.expires_at_unix_ms <= evaluated_at_unix_ms
        || trust
            .keys
            .iter()
            .any(|(key_id, encoded)| !valid_label(key_id) || !valid_sha256(encoded))
    {
        return Err(RulePackMetadataError::InvalidTrust);
    }
    trust.verifying_keys()?;
    Ok(())
}

fn validate_trust_rotation(
    current: &RulePackTrustV1,
    candidate: &RulePackTrustV1,
) -> Result<(), RulePackMetadataError> {
    if candidate == current {
        return Ok(());
    }
    if candidate.generation != current.generation.saturating_add(1)
        || candidate.expires_at_unix_ms < current.expires_at_unix_ms
        || candidate.keys == current.keys
    {
        return Err(RulePackMetadataError::InvalidTrustRotation);
    }
    Ok(())
}

fn verify_threshold(
    signing_bytes: &[u8],
    signatures: &BTreeMap<String, String>,
    trust: &RulePackTrustV1,
) -> Result<(), RulePackMetadataError> {
    let keys = trust.verifying_keys()?;
    let valid_count = signatures
        .iter()
        .filter_map(|(key_id, encoded)| {
            let key = keys.get(key_id)?;
            let decoded = hex::decode(encoded).ok()?;
            let signature = Signature::from_slice(&decoded).ok()?;
            key.verify_strict(signing_bytes, &signature).ok()?;
            Some(())
        })
        .count();
    if valid_count < usize::from(trust.threshold) {
        return Err(RulePackMetadataError::InvalidSignatures);
    }
    Ok(())
}

fn validate_metadata_shape(
    metadata: &RulePackMetadataV1,
    evaluated_at_unix_ms: i64,
) -> Result<(), RulePackMetadataError> {
    if metadata.schema != RULE_PACK_METADATA_V1
        || metadata.sequence == 0
        || !valid_sha256(&metadata.release_id)
        || !valid_sha256(&metadata.rule_pack_hash)
        || metadata
            .previous_rule_pack_hash
            .as_deref()
            .is_some_and(|hash| !valid_sha256(hash) || hash == metadata.rule_pack_hash)
    {
        return Err(RulePackMetadataError::InvalidMetadata);
    }
    if metadata.issued_at_unix_ms > evaluated_at_unix_ms
        || metadata.expires_at_unix_ms <= evaluated_at_unix_ms
        || metadata.expires_at_unix_ms <= metadata.issued_at_unix_ms
    {
        return Err(RulePackMetadataError::ExpiredMetadata);
    }
    if metadata.expires_at_unix_ms - metadata.issued_at_unix_ms > MAX_RULE_PACK_METADATA_VALIDITY_MS
    {
        return Err(RulePackMetadataError::ExcessiveValidity);
    }
    validate_trust(&metadata.trust, evaluated_at_unix_ms)?;
    if metadata.trust.expires_at_unix_ms < metadata.expires_at_unix_ms {
        return Err(RulePackMetadataError::InvalidTrust);
    }
    if !valid_regions(&metadata.required_regions)
        || metadata
            .eligible_regions
            .iter()
            .any(|region| !metadata.required_regions.contains(region))
        || metadata.eligible_workers.len() > MAX_WORKERS
        || metadata
            .eligible_workers
            .iter()
            .any(|worker| !valid_label(worker))
    {
        return Err(RulePackMetadataError::InvalidRollout);
    }
    match metadata.rollout_stage {
        RulePackRolloutStage::Canary => {
            if metadata.eligible_regions.is_empty() || metadata.eligible_workers.is_empty() {
                return Err(RulePackMetadataError::InvalidRollout);
            }
        }
        RulePackRolloutStage::Regional => {
            if metadata.eligible_regions.is_empty()
                || metadata.eligible_regions == metadata.required_regions
                || !metadata.eligible_workers.is_empty()
            {
                return Err(RulePackMetadataError::InvalidRollout);
            }
        }
        RulePackRolloutStage::General | RulePackRolloutStage::Rollback => {
            if metadata.eligible_regions != metadata.required_regions
                || !metadata.eligible_workers.is_empty()
            {
                return Err(RulePackMetadataError::InvalidRollout);
            }
        }
    }
    if metadata.rollout_stage == RulePackRolloutStage::Rollback
        && metadata.previous_rule_pack_hash.is_none()
    {
        return Err(RulePackMetadataError::InvalidRollout);
    }
    let rule_hashes = metadata
        .promotions
        .iter()
        .map(|(site_id, promotion)| (site_id.clone(), promotion.promotion.rule_hash.clone()))
        .collect::<BTreeMap<_, _>>();
    if metadata.release_id
        != release_id(
            &metadata.rule_pack_hash,
            metadata.previous_rule_pack_hash.as_deref(),
            &metadata.required_regions,
            &rule_hashes,
        )?
    {
        return Err(RulePackMetadataError::InvalidMetadata);
    }
    Ok(())
}

fn validate_embedded_promotions(
    metadata: &RulePackMetadataV1,
    verified_at_unix_ms: i64,
) -> Result<BTreeMap<String, ValidatedPromotion>, RulePackMetadataError> {
    if metadata.promotions.is_empty() || metadata.promotions.len() > MAX_PROMOTIONS {
        return Err(RulePackMetadataError::InvalidPromotions);
    }
    let trusted_keys = metadata
        .trust
        .keys
        .iter()
        .map(|(key_id, encoded)| {
            let decoded = hex::decode(encoded).map_err(|_| RulePackMetadataError::InvalidTrust)?;
            let bytes = decoded
                .try_into()
                .map_err(|_| RulePackMetadataError::InvalidTrust)?;
            Ok((key_id.clone(), bytes))
        })
        .collect::<Result<BTreeMap<String, [u8; 32]>, RulePackMetadataError>>()?;
    metadata
        .promotions
        .iter()
        .map(|(site_id, envelope)| {
            let promotion = &envelope.promotion;
            if !valid_label(site_id)
                || promotion.site_id != *site_id
                || promotion.rule_pack_hash != metadata.rule_pack_hash
                || promotion.previous_rule_pack_hash != metadata.previous_rule_pack_hash
                || promotion
                    .regions
                    .keys()
                    .ne(metadata.required_regions.iter())
                || promotion.expires_at_unix_ms < metadata.expires_at_unix_ms
            {
                return Err(RulePackMetadataError::InvalidPromotions);
            }
            let validated = PromotionVerifier::new()
                .validate_at(
                    envelope,
                    &PromotionTrustPolicy {
                        trusted_keys: trusted_keys.clone(),
                        expected_site_id: site_id.clone(),
                        expected_rule_hash: promotion.rule_hash.clone(),
                        expected_rule_pack_hash: metadata.rule_pack_hash.clone(),
                        expected_previous_rule_pack_hash: metadata.previous_rule_pack_hash.clone(),
                        expected_manifest_hash: promotion.manifest_hash.clone(),
                        expected_engine_hash: promotion.engine_hash.clone(),
                        required_regions: metadata.required_regions.clone(),
                        minimum_sequence_exclusive: 0,
                    },
                    verified_at_unix_ms,
                )
                .map_err(|_| RulePackMetadataError::InvalidPromotions)?;
            Ok((site_id.clone(), validated))
        })
        .collect()
}

fn validate_pack(
    metadata: &RulePackMetadataV1,
    rule_pack: &CompiledRulePack,
) -> Result<(), RulePackMetadataError> {
    let compiler = RuleCompiler::new();
    let compiled = rule_pack
        .rules
        .iter()
        .map(|source| {
            compiler
                .compile_source(source.clone(), Some(&source.id))
                .map_err(|_| RulePackMetadataError::RulePackMismatch)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let rebuilt = compiler
        .compile_pack(&compiled)
        .map_err(|_| RulePackMetadataError::RulePackMismatch)?;
    if rebuilt.content_hash != metadata.rule_pack_hash
        || rebuilt.content_hash != rule_pack.content_hash
        || metadata.promotions.iter().any(|(site_id, promotion)| {
            compiled.iter().all(|candidate| {
                candidate.source.id != *site_id
                    || candidate.rule_hash != promotion.promotion.rule_hash
            })
        })
    {
        return Err(RulePackMetadataError::RulePackMismatch);
    }
    Ok(())
}

fn validate_rollout_progression(
    current: &ActivatedRulePackMetadata,
    next: &ActivatedRulePackMetadata,
) -> Result<(), RulePackMetadataError> {
    match (current.rollout_stage, next.rollout_stage) {
        (RulePackRolloutStage::Canary, RulePackRolloutStage::Canary) => {
            if !current.eligible_regions.is_subset(&next.eligible_regions)
                || !current.eligible_workers.is_subset(&next.eligible_workers)
            {
                return Err(RulePackMetadataError::RolloutMismatch);
            }
        }
        (RulePackRolloutStage::Canary, RulePackRolloutStage::Regional)
        | (RulePackRolloutStage::Canary, RulePackRolloutStage::General)
        | (RulePackRolloutStage::Regional, RulePackRolloutStage::General) => {}
        (RulePackRolloutStage::Regional, RulePackRolloutStage::Regional) => {
            if !current.eligible_regions.is_subset(&next.eligible_regions) {
                return Err(RulePackMetadataError::RolloutMismatch);
            }
        }
        _ => return Err(RulePackMetadataError::RolloutMismatch),
    }
    Ok(())
}

fn release_id(
    rule_pack_hash: &str,
    previous_rule_pack_hash: Option<&str>,
    required_regions: &BTreeSet<String>,
    rule_hashes: &BTreeMap<String, String>,
) -> Result<String, RulePackMetadataError> {
    #[derive(Serialize)]
    struct ReleaseIdentity<'a> {
        rule_pack_hash: &'a str,
        previous_rule_pack_hash: Option<&'a str>,
        required_regions: &'a BTreeSet<String>,
        rule_hashes: &'a BTreeMap<String, String>,
    }
    let canonical = serde_json::to_vec(&ReleaseIdentity {
        rule_pack_hash,
        previous_rule_pack_hash,
        required_regions,
        rule_hashes,
    })
    .map_err(|_| RulePackMetadataError::CanonicalSerialization)?;
    Ok(domain_hash(RELEASE_ID_DOMAIN, &canonical))
}

fn trust_signing_bytes(trust: &RulePackTrustV1) -> Result<Vec<u8>, RulePackMetadataError> {
    let canonical =
        serde_json::to_vec(trust).map_err(|_| RulePackMetadataError::CanonicalSerialization)?;
    Ok(domain_bytes(TRUST_SIGNING_DOMAIN, &canonical))
}

fn metadata_signing_bytes(metadata: &RulePackMetadataV1) -> Result<Vec<u8>, RulePackMetadataError> {
    let canonical =
        serde_json::to_vec(metadata).map_err(|_| RulePackMetadataError::CanonicalSerialization)?;
    Ok(domain_bytes(METADATA_SIGNING_DOMAIN, &canonical))
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> String {
    sha256_hex(&domain_bytes(domain, bytes))
}

fn domain_bytes(domain: &[u8], bytes: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(domain.len() + bytes.len());
    output.extend_from_slice(domain);
    output.extend_from_slice(bytes);
    output
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn valid_regions(regions: &BTreeSet<String>) -> bool {
    !regions.is_empty()
        && regions.len() <= MAX_REGIONS
        && regions.iter().all(|region| valid_label(region))
}

fn valid_label(value: &str) -> bool {
    let mut characters = value.chars();
    matches!(characters.next(), Some('a'..='z' | '0'..='9'))
        && value.len() <= 64
        && characters.all(|character| matches!(character, 'a'..='z' | '0'..='9' | '-'))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use socialname_domain::{RuleHealth, RuleHealthKey, RuleHealthRecord, SiteId};
    use socialname_rule_compiler::CompiledSiteRule;

    use crate::{PromotionBuildRequest, PromotionBuilder, PromotionSigningKey};

    use super::*;

    const MANIFEST_HASH: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const ENGINE_HASH: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const START: i64 = 1_000_000;
    const TRUST_EXPIRY: i64 = START + 30 * 24 * 60 * 60 * 1_000;

    fn candidate(note: &str) -> CompiledSiteRule {
        let mut source = RuleCompiler::new()
            .compile_yaml(
                include_str!("../../../rules/sites/github.yaml"),
                Some("github"),
            )
            .unwrap()
            .source;
        source.metadata.notes = note.to_owned();
        RuleCompiler::new()
            .compile_source(source, Some("github"))
            .unwrap()
    }

    fn pack(candidate: &CompiledSiteRule) -> CompiledRulePack {
        RuleCompiler::new()
            .compile_pack(std::slice::from_ref(candidate))
            .unwrap()
    }

    fn regions() -> BTreeSet<String> {
        BTreeSet::from(["region-a".to_owned(), "region-b".to_owned()])
    }

    fn health(
        candidate: &CompiledSiteRule,
        region: &str,
        sequence: u64,
        issued_at: i64,
        expires_at: i64,
    ) -> RuleHealthRecord {
        let marker = if region == "region-a" { 0x1000 } else { 0x2000 };
        RuleHealthRecord {
            key: RuleHealthKey {
                site_id: SiteId::new("github"),
                rule_hash: candidate.rule_hash.clone(),
                region: region.to_owned(),
            },
            state: RuleHealth::Healthy,
            sequence,
            entered_at_unix_ms: issued_at - 2_000,
            updated_at_unix_ms: issued_at - 1_000,
            consecutive_recovery_passes: 0,
            consecutive_operational_failures: 0,
            last_manifest_hash: Some(MANIFEST_HASH.to_owned()),
            last_engine_hash: Some(ENGINE_HASH.to_owned()),
            last_evidence_expires_at_unix_ms: Some(expires_at + 1_000),
            last_evidence_ids: vec![
                format!("{:064x}", 0x100_u64 + sequence),
                format!("{:064x}", marker + sequence),
            ],
        }
    }

    fn promotion(
        key: &PromotionSigningKey,
        candidate: &CompiledSiteRule,
        pack: &CompiledRulePack,
        previous: Option<&str>,
        sequence: u64,
        issued_at: i64,
        expires_at: i64,
    ) -> PromotionEnvelope {
        let health = vec![
            health(candidate, "region-a", sequence * 2, issued_at, expires_at),
            health(
                candidate,
                "region-b",
                sequence * 2 + 1,
                issued_at,
                expires_at,
            ),
        ];
        PromotionBuilder::new()
            .build(
                key,
                PromotionBuildRequest {
                    sequence,
                    candidate,
                    rule_pack: pack,
                    previous_rule_pack_hash: previous,
                    health_records: &health,
                    required_regions: &regions(),
                    issued_at_unix_ms: issued_at,
                    expires_at_unix_ms: expires_at,
                },
            )
            .unwrap()
    }

    fn trust(
        generation: u64,
        threshold: u16,
        keys: &[&RulePackMetadataSigningKey],
    ) -> RulePackTrustV1 {
        RulePackTrustV1 {
            schema: RULE_PACK_TRUST_V1.to_owned(),
            generation,
            threshold,
            keys: keys
                .iter()
                .map(|key| (key.key_id().to_owned(), key.verifying_key_hex()))
                .collect(),
            expires_at_unix_ms: TRUST_EXPIRY,
        }
    }

    struct MetadataRequest<'a> {
        sequence: u64,
        pack: &'a CompiledRulePack,
        previous: Option<&'a str>,
        promotion: PromotionEnvelope,
        stage: RulePackRolloutStage,
        trust: RulePackTrustV1,
        issued_at: i64,
    }

    fn metadata(
        signing_keys: &[RulePackMetadataSigningKey],
        request: MetadataRequest<'_>,
    ) -> RulePackMetadataEnvelope {
        let eligible_regions = match request.stage {
            RulePackRolloutStage::Canary | RulePackRolloutStage::Regional => {
                BTreeSet::from(["region-a".to_owned()])
            }
            RulePackRolloutStage::General | RulePackRolloutStage::Rollback => regions(),
        };
        let eligible_workers = if request.stage == RulePackRolloutStage::Canary {
            BTreeSet::from(["worker-a".to_owned()])
        } else {
            BTreeSet::new()
        };
        RulePackMetadataBuilder::new()
            .build(
                signing_keys,
                RulePackMetadataBuildRequest {
                    sequence: request.sequence,
                    rule_pack: request.pack,
                    previous_rule_pack_hash: request.previous,
                    required_regions: &regions(),
                    rollout_stage: request.stage,
                    eligible_regions: &eligible_regions,
                    eligible_workers: &eligible_workers,
                    issued_at_unix_ms: request.issued_at,
                    expires_at_unix_ms: request.issued_at + 60_000,
                    trust: request.trust,
                    promotions: &[request.promotion],
                },
            )
            .unwrap()
    }

    fn validate(
        envelope: &RulePackMetadataEnvelope,
        current_trust: &RulePackTrustV1,
        verified_at: i64,
    ) -> ValidatedRulePackMetadata {
        RulePackMetadataVerifier::new()
            .validate_at(envelope, current_trust, verified_at)
            .unwrap()
    }

    #[test]
    fn rollout_selects_only_eligible_workers_then_activates_and_rolls_back() {
        let metadata_key = RulePackMetadataSigningKey::from_seed("release-old", [7; 32]).unwrap();
        let promotion_key = PromotionSigningKey::from_seed("release-old", [7; 32]).unwrap();
        let initial_trust = trust(1, 1, &[&metadata_key]);
        let first_candidate = candidate("first");
        let first_pack = pack(&first_candidate);
        let mut registry = RulePackRolloutRegistry::new(initial_trust.clone(), START).unwrap();

        let canary = metadata(
            std::slice::from_ref(&metadata_key),
            MetadataRequest {
                sequence: 1,
                pack: &first_pack,
                previous: None,
                promotion: promotion(
                    &promotion_key,
                    &first_candidate,
                    &first_pack,
                    None,
                    1,
                    START,
                    START + 61_000,
                ),
                stage: RulePackRolloutStage::Canary,
                trust: initial_trust.clone(),
                issued_at: START,
            },
        );
        let canary = validate(&canary, &initial_trust, START + 1);
        registry.apply(&canary, &first_pack, START + 1).unwrap();
        assert_eq!(
            registry
                .select_at("region-a", "worker-a", START + 2)
                .unwrap()
                .rule_pack_hash,
            first_pack.content_hash
        );
        assert_eq!(
            registry
                .select_at("region-a", "worker-b", START + 2)
                .unwrap_err(),
            RulePackMetadataError::NoEligibleRulePack
        );

        let regional = metadata(
            std::slice::from_ref(&metadata_key),
            MetadataRequest {
                sequence: 2,
                pack: &first_pack,
                previous: None,
                promotion: promotion(
                    &promotion_key,
                    &first_candidate,
                    &first_pack,
                    None,
                    2,
                    START + 1_000,
                    START + 62_000,
                ),
                stage: RulePackRolloutStage::Regional,
                trust: initial_trust.clone(),
                issued_at: START + 1_000,
            },
        );
        let regional = validate(&regional, &initial_trust, START + 1_001);
        registry
            .apply(&regional, &first_pack, START + 1_001)
            .unwrap();
        assert_eq!(
            registry
                .select_at("region-a", "worker-b", START + 1_002)
                .unwrap()
                .rule_pack_hash,
            first_pack.content_hash
        );

        let general = metadata(
            std::slice::from_ref(&metadata_key),
            MetadataRequest {
                sequence: 3,
                pack: &first_pack,
                previous: None,
                promotion: promotion(
                    &promotion_key,
                    &first_candidate,
                    &first_pack,
                    None,
                    3,
                    START + 2_000,
                    START + 63_000,
                ),
                stage: RulePackRolloutStage::General,
                trust: initial_trust.clone(),
                issued_at: START + 2_000,
            },
        );
        let general = validate(&general, &initial_trust, START + 2_001);
        registry
            .apply(&general, &first_pack, START + 2_001)
            .unwrap();
        assert!(registry.staged().is_none());
        assert_eq!(
            registry
                .select_at("region-b", "worker-b", START + 2_002)
                .unwrap()
                .rule_pack_hash,
            first_pack.content_hash
        );

        let second_candidate = candidate("second");
        let second_pack = pack(&second_candidate);
        let second_canary = metadata(
            std::slice::from_ref(&metadata_key),
            MetadataRequest {
                sequence: 4,
                pack: &second_pack,
                previous: Some(&first_pack.content_hash),
                promotion: promotion(
                    &promotion_key,
                    &second_candidate,
                    &second_pack,
                    Some(&first_pack.content_hash),
                    4,
                    START + 3_000,
                    START + 64_000,
                ),
                stage: RulePackRolloutStage::Canary,
                trust: initial_trust.clone(),
                issued_at: START + 3_000,
            },
        );
        let second_canary = validate(&second_canary, &initial_trust, START + 3_001);
        registry
            .apply(&second_canary, &second_pack, START + 3_001)
            .unwrap();
        assert_eq!(
            registry
                .select_at("region-a", "worker-a", START + 3_002)
                .unwrap()
                .rule_pack_hash,
            second_pack.content_hash
        );
        assert_eq!(
            registry
                .select_at("region-b", "worker-b", START + 3_002)
                .unwrap()
                .rule_pack_hash,
            first_pack.content_hash
        );

        let second_general = metadata(
            std::slice::from_ref(&metadata_key),
            MetadataRequest {
                sequence: 5,
                pack: &second_pack,
                previous: Some(&first_pack.content_hash),
                promotion: promotion(
                    &promotion_key,
                    &second_candidate,
                    &second_pack,
                    Some(&first_pack.content_hash),
                    5,
                    START + 4_000,
                    START + 65_000,
                ),
                stage: RulePackRolloutStage::General,
                trust: initial_trust.clone(),
                issued_at: START + 4_000,
            },
        );
        let second_general = validate(&second_general, &initial_trust, START + 4_001);
        registry
            .apply(&second_general, &second_pack, START + 4_001)
            .unwrap();
        assert_eq!(
            registry.last_known_good().unwrap().rule_pack_hash,
            first_pack.content_hash
        );

        let rollback = metadata(
            std::slice::from_ref(&metadata_key),
            MetadataRequest {
                sequence: 6,
                pack: &first_pack,
                previous: Some(&second_pack.content_hash),
                promotion: promotion(
                    &promotion_key,
                    &first_candidate,
                    &first_pack,
                    Some(&second_pack.content_hash),
                    6,
                    START + 5_000,
                    START + 66_000,
                ),
                stage: RulePackRolloutStage::Rollback,
                trust: initial_trust,
                issued_at: START + 5_000,
            },
        );
        let rollback = validate(&rollback, registry.current_trust(), START + 5_001);
        registry
            .apply(&rollback, &first_pack, START + 5_001)
            .unwrap();
        assert_eq!(registry.highest_sequence(), 6);
        assert_eq!(registry.promotion_high_water().get("github"), Some(&6));
        assert_eq!(
            registry.active().unwrap().rule_pack_hash,
            first_pack.content_hash
        );
        assert!(registry.last_known_good().is_none());
        assert_eq!(
            registry
                .apply(&second_general, &second_pack, START + 5_002)
                .unwrap_err(),
            RulePackMetadataError::SequenceReplay
        );
        assert_eq!(
            registry
                .select_at("region-a", "worker-a", START + 66_000)
                .unwrap_err(),
            RulePackMetadataError::NoEligibleRulePack
        );
    }

    #[test]
    fn rotation_requires_old_and_new_thresholds_before_old_key_can_be_removed() {
        let old = RulePackMetadataSigningKey::from_seed("release-old", [7; 32]).unwrap();
        let new = RulePackMetadataSigningKey::from_seed("release-new", [8; 32]).unwrap();
        let promotion_old = PromotionSigningKey::from_seed("release-old", [7; 32]).unwrap();
        let initial_trust = trust(1, 1, &[&old]);
        let overlapping = trust(2, 2, &[&old, &new]);
        let candidate = candidate("rotation");
        let pack = pack(&candidate);
        let first_promotion = promotion(
            &promotion_old,
            &candidate,
            &pack,
            None,
            1,
            START,
            START + 61_000,
        );
        let missing_new = metadata(
            std::slice::from_ref(&old),
            MetadataRequest {
                sequence: 1,
                pack: &pack,
                previous: None,
                promotion: first_promotion.clone(),
                stage: RulePackRolloutStage::Canary,
                trust: overlapping.clone(),
                issued_at: START,
            },
        );
        assert_eq!(
            RulePackMetadataVerifier::new()
                .validate_at(&missing_new, &initial_trust, START + 1)
                .unwrap_err(),
            RulePackMetadataError::InvalidSignatures
        );

        let dual_signed = metadata(
            &[old.clone(), new.clone()],
            MetadataRequest {
                sequence: 1,
                pack: &pack,
                previous: None,
                promotion: first_promotion,
                stage: RulePackRolloutStage::Canary,
                trust: overlapping.clone(),
                issued_at: START,
            },
        );
        let validated = validate(&dual_signed, &initial_trust, START + 1);
        let mut registry = RulePackRolloutRegistry::new(initial_trust, START).unwrap();
        registry.apply(&validated, &pack, START + 1).unwrap();
        assert_eq!(registry.current_trust().generation, 2);

        let new_only_trust = trust(3, 1, &[&new]);
        let promotion_new = PromotionSigningKey::from_seed("release-new", [8; 32]).unwrap();
        let removal = metadata(
            &[old.clone(), new.clone()],
            MetadataRequest {
                sequence: 2,
                pack: &pack,
                previous: None,
                promotion: promotion(
                    &promotion_new,
                    &candidate,
                    &pack,
                    None,
                    2,
                    START + 1_000,
                    START + 62_000,
                ),
                stage: RulePackRolloutStage::General,
                trust: new_only_trust.clone(),
                issued_at: START + 1_000,
            },
        );
        let removal = validate(&removal, registry.current_trust(), START + 1_001);
        registry.apply(&removal, &pack, START + 1_001).unwrap();
        assert_eq!(registry.current_trust(), &new_only_trust);

        let refreshed = metadata(
            std::slice::from_ref(&new),
            MetadataRequest {
                sequence: 3,
                pack: &pack,
                previous: None,
                promotion: promotion(
                    &promotion_new,
                    &candidate,
                    &pack,
                    None,
                    3,
                    START + 2_000,
                    START + 63_000,
                ),
                stage: RulePackRolloutStage::General,
                trust: new_only_trust,
                issued_at: START + 2_000,
            },
        );
        let refreshed = validate(&refreshed, registry.current_trust(), START + 2_001);
        registry.apply(&refreshed, &pack, START + 2_001).unwrap();
        assert_eq!(registry.highest_sequence(), 3);
    }

    #[test]
    fn tampering_expiry_and_rollout_regression_fail_closed() {
        let key = RulePackMetadataSigningKey::from_seed("release-old", [7; 32]).unwrap();
        let promotion_key = PromotionSigningKey::from_seed("release-old", [7; 32]).unwrap();
        let current_trust = trust(1, 1, &[&key]);
        let candidate = candidate("tamper");
        let pack = pack(&candidate);
        let canary = metadata(
            std::slice::from_ref(&key),
            MetadataRequest {
                sequence: 1,
                pack: &pack,
                previous: None,
                promotion: promotion(
                    &promotion_key,
                    &candidate,
                    &pack,
                    None,
                    1,
                    START,
                    START + 61_000,
                ),
                stage: RulePackRolloutStage::Canary,
                trust: current_trust.clone(),
                issued_at: START,
            },
        );
        let mut tampered = canary.clone();
        tampered
            .metadata
            .eligible_workers
            .insert("worker-b".to_owned());
        assert_eq!(
            RulePackMetadataVerifier::new()
                .validate_at(&tampered, &current_trust, START + 1)
                .unwrap_err(),
            RulePackMetadataError::InvalidMetadataId
        );
        assert_eq!(
            RulePackMetadataVerifier::new()
                .validate_at(&canary, &current_trust, START + 60_000)
                .unwrap_err(),
            RulePackMetadataError::ExpiredMetadata
        );
        let mut unknown: serde_json::Value = serde_json::to_value(&canary).unwrap();
        unknown["unexpected"] = serde_json::json!(true);
        assert_eq!(
            RulePackMetadataVerifier::new()
                .validate_json_at(
                    &serde_json::to_vec(&unknown).unwrap(),
                    &current_trust,
                    START + 1
                )
                .unwrap_err(),
            RulePackMetadataError::MalformedArtifact
        );

        let validated = validate(&canary, &current_trust, START + 1);
        let mut registry = RulePackRolloutRegistry::new(current_trust.clone(), START).unwrap();
        registry.apply(&validated, &pack, START + 1).unwrap();
        let narrowed = metadata(
            std::slice::from_ref(&key),
            MetadataRequest {
                sequence: 2,
                pack: &pack,
                previous: None,
                promotion: promotion(
                    &promotion_key,
                    &candidate,
                    &pack,
                    None,
                    2,
                    START + 1_000,
                    START + 62_000,
                ),
                stage: RulePackRolloutStage::Canary,
                trust: current_trust,
                issued_at: START + 1_000,
            },
        );
        let mut narrowed = validate(&narrowed, registry.current_trust(), START + 1_001);
        narrowed.envelope.metadata.eligible_workers.clear();
        assert_eq!(
            registry.apply(&narrowed, &pack, START + 1_001).unwrap_err(),
            RulePackMetadataError::RolloutMismatch
        );
    }
}
