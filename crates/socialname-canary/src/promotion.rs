use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use socialname_domain::{RuleHealth, RuleHealthPolicy, RuleHealthRecord};
use socialname_rule_compiler::{CompiledRulePack, CompiledSiteRule, RuleCompiler};

pub const PROMOTION_V1: &str = "socialname.dev/rule-promotion/v1";
pub const ED25519_ALGORITHM: &str = "ed25519";

const RULE_PACK_V1: &str = "socialname.dev/rule-pack/v1";
const SIGNING_DOMAIN: &[u8] = b"socialname.dev/rule-promotion/v1\0";
const MAX_PROMOTION_VALIDITY_MS: i64 = 24 * 60 * 60 * 1_000;
const MAX_REGIONS: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionRegionEvidence {
    pub health_sequence: u64,
    pub observed_at_unix_ms: i64,
    pub evidence_expires_at_unix_ms: i64,
    pub aggregate_evidence_id: String,
    pub shadow_evidence_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionV1 {
    pub schema: String,
    pub sequence: u64,
    pub site_id: String,
    pub rule_hash: String,
    pub rule_pack_hash: String,
    pub previous_rule_pack_hash: Option<String>,
    pub manifest_hash: String,
    pub engine_hash: String,
    pub issued_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub regions: BTreeMap<String, PromotionRegionEvidence>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionEnvelope {
    pub promotion_id: String,
    pub key_id: String,
    pub algorithm: String,
    pub promotion: PromotionV1,
    pub signature: String,
}

pub struct PromotionSigningKey {
    key_id: String,
    signing_key: SigningKey,
}

impl PromotionSigningKey {
    pub fn from_seed(key_id: impl Into<String>, seed: [u8; 32]) -> Result<Self, PromotionError> {
        let key_id = key_id.into();
        if !valid_label(&key_id) {
            return Err(PromotionError::InvalidKeyId);
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
    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }
}

pub struct PromotionBuildRequest<'a> {
    pub sequence: u64,
    pub candidate: &'a CompiledSiteRule,
    pub rule_pack: &'a CompiledRulePack,
    pub previous_rule_pack_hash: Option<&'a str>,
    pub health_records: &'a [RuleHealthRecord],
    pub required_regions: &'a BTreeSet<String>,
    pub issued_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
}

#[derive(Clone, Debug, Default)]
pub struct PromotionBuilder;

impl PromotionBuilder {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    pub fn build(
        &self,
        signing_key: &PromotionSigningKey,
        request: PromotionBuildRequest<'_>,
    ) -> Result<PromotionEnvelope, PromotionError> {
        validate_request_surface(&request)?;
        validate_rule_pack(request.rule_pack, request.candidate)?;

        let (manifest_hash, engine_hash, regions) = bind_healthy_regions(&request)?;
        let promotion = PromotionV1 {
            schema: PROMOTION_V1.to_owned(),
            sequence: request.sequence,
            site_id: request.candidate.source.id.clone(),
            rule_hash: request.candidate.rule_hash.clone(),
            rule_pack_hash: request.rule_pack.content_hash.clone(),
            previous_rule_pack_hash: request.previous_rule_pack_hash.map(str::to_owned),
            manifest_hash,
            engine_hash,
            issued_at_unix_ms: request.issued_at_unix_ms,
            expires_at_unix_ms: request.expires_at_unix_ms,
            regions,
        };
        let signing_bytes = signing_bytes(&promotion)?;
        let promotion_id = sha256_hex(&signing_bytes);
        let signature = signing_key.signing_key.sign(&signing_bytes);
        Ok(PromotionEnvelope {
            promotion_id,
            key_id: signing_key.key_id.clone(),
            algorithm: ED25519_ALGORITHM.to_owned(),
            promotion,
            signature: hex::encode(signature.to_bytes()),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PromotionTrustPolicy {
    pub trusted_keys: BTreeMap<String, [u8; 32]>,
    pub expected_site_id: String,
    pub expected_rule_hash: String,
    pub expected_rule_pack_hash: String,
    pub expected_previous_rule_pack_hash: Option<String>,
    pub expected_manifest_hash: String,
    pub expected_engine_hash: String,
    pub required_regions: BTreeSet<String>,
    pub minimum_sequence_exclusive: u64,
}

#[derive(Clone, Debug)]
pub struct ValidatedPromotion {
    envelope: PromotionEnvelope,
}

impl ValidatedPromotion {
    #[must_use]
    pub fn envelope(&self) -> &PromotionEnvelope {
        &self.envelope
    }

    #[must_use]
    pub fn promotion(&self) -> &PromotionV1 {
        &self.envelope.promotion
    }
}

#[derive(Clone, Debug, Default)]
pub struct PromotionVerifier;

impl PromotionVerifier {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    pub fn validate_json_at(
        &self,
        input: &[u8],
        policy: &PromotionTrustPolicy,
        verified_at_unix_ms: i64,
    ) -> Result<ValidatedPromotion, PromotionError> {
        let envelope: PromotionEnvelope =
            serde_json::from_slice(input).map_err(|_| PromotionError::MalformedArtifact)?;
        self.validate_at(&envelope, policy, verified_at_unix_ms)
    }

    pub fn validate_at(
        &self,
        envelope: &PromotionEnvelope,
        policy: &PromotionTrustPolicy,
        verified_at_unix_ms: i64,
    ) -> Result<ValidatedPromotion, PromotionError> {
        validate_trust_policy(policy)?;
        if envelope.algorithm != ED25519_ALGORITHM {
            return Err(PromotionError::UnsupportedAlgorithm);
        }
        if !valid_label(&envelope.key_id) {
            return Err(PromotionError::InvalidKeyId);
        }
        let verifying_key_bytes = policy
            .trusted_keys
            .get(&envelope.key_id)
            .ok_or(PromotionError::UntrustedKey)?;
        let verifying_key = VerifyingKey::from_bytes(verifying_key_bytes)
            .map_err(|_| PromotionError::InvalidVerifyingKey)?;
        let signing_bytes = signing_bytes(&envelope.promotion)?;
        if envelope.promotion_id != sha256_hex(&signing_bytes) {
            return Err(PromotionError::InvalidPromotionId);
        }
        let signature_bytes =
            hex::decode(&envelope.signature).map_err(|_| PromotionError::InvalidSignature)?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|_| PromotionError::InvalidSignature)?;
        verifying_key
            .verify_strict(&signing_bytes, &signature)
            .map_err(|_| PromotionError::InvalidSignature)?;

        validate_promotion(&envelope.promotion, policy, verified_at_unix_ms)?;
        Ok(ValidatedPromotion {
            envelope: envelope.clone(),
        })
    }
}

#[derive(Clone, Debug)]
pub struct ActivatedPromotion {
    promotion_id: String,
    promotion: PromotionV1,
    rule_pack: CompiledRulePack,
    candidate: CompiledSiteRule,
}

impl ActivatedPromotion {
    #[must_use]
    pub fn promotion_id(&self) -> &str {
        &self.promotion_id
    }

    #[must_use]
    pub const fn promotion(&self) -> &PromotionV1 {
        &self.promotion
    }

    #[must_use]
    pub const fn rule_pack(&self) -> &CompiledRulePack {
        &self.rule_pack
    }

    #[must_use]
    pub const fn candidate(&self) -> &CompiledSiteRule {
        &self.candidate
    }
}

#[derive(Clone, Debug)]
pub struct PromotionActivationRegistry {
    site_id: String,
    highest_sequence: u64,
    active: Option<ActivatedPromotion>,
    last_known_good: Option<ActivatedPromotion>,
}

impl PromotionActivationRegistry {
    pub fn new(site_id: impl Into<String>) -> Result<Self, PromotionError> {
        let site_id = site_id.into();
        if !valid_label(&site_id) {
            return Err(PromotionError::InvalidSiteId);
        }
        Ok(Self {
            site_id,
            highest_sequence: 0,
            active: None,
            last_known_good: None,
        })
    }

    pub fn activate(
        &mut self,
        validated: &ValidatedPromotion,
        rule_pack: &CompiledRulePack,
        candidate: &CompiledSiteRule,
        activated_at_unix_ms: i64,
    ) -> Result<&ActivatedPromotion, PromotionError> {
        let promotion = validated.promotion();
        if promotion.site_id != self.site_id {
            return Err(PromotionError::SiteMismatch);
        }
        if promotion.sequence <= self.highest_sequence {
            return Err(PromotionError::SequenceReplay);
        }
        if promotion.expires_at_unix_ms <= activated_at_unix_ms
            || promotion.issued_at_unix_ms > activated_at_unix_ms
        {
            return Err(PromotionError::ExpiredPromotion);
        }
        let active_pack_hash = self
            .active
            .as_ref()
            .map(|active| active.rule_pack.content_hash.as_str());
        if promotion.previous_rule_pack_hash.as_deref() != active_pack_hash {
            return Err(PromotionError::PreviousPackMismatch);
        }
        validate_rule_pack(rule_pack, candidate)?;
        if promotion.rule_pack_hash != rule_pack.content_hash
            || promotion.rule_hash != candidate.rule_hash
            || promotion.site_id != candidate.source.id
        {
            return Err(PromotionError::RulePackMismatch);
        }

        let activated = ActivatedPromotion {
            promotion_id: validated.envelope.promotion_id.clone(),
            promotion: promotion.clone(),
            rule_pack: rule_pack.clone(),
            candidate: candidate.clone(),
        };
        self.last_known_good = self.active.take();
        self.highest_sequence = promotion.sequence;
        self.active = Some(activated);
        Ok(self.active.as_ref().expect("active promotion was inserted"))
    }

    pub fn rollback(&mut self) -> Result<&ActivatedPromotion, PromotionError> {
        let retained = self
            .last_known_good
            .take()
            .ok_or(PromotionError::NoLastKnownGood)?;
        self.active = Some(retained);
        Ok(self
            .active
            .as_ref()
            .expect("retained promotion was restored"))
    }

    #[must_use]
    pub const fn highest_sequence(&self) -> u64 {
        self.highest_sequence
    }

    #[must_use]
    pub const fn active(&self) -> Option<&ActivatedPromotion> {
        self.active.as_ref()
    }

    #[must_use]
    pub const fn last_known_good(&self) -> Option<&ActivatedPromotion> {
        self.last_known_good.as_ref()
    }
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum PromotionError {
    #[error("promotion artifact is malformed")]
    MalformedArtifact,
    #[error("promotion key id is invalid")]
    InvalidKeyId,
    #[error("promotion site id is invalid")]
    InvalidSiteId,
    #[error("promotion signing algorithm is unsupported")]
    UnsupportedAlgorithm,
    #[error("promotion signing key is not trusted")]
    UntrustedKey,
    #[error("promotion verifying key is invalid")]
    InvalidVerifyingKey,
    #[error("promotion signature is invalid")]
    InvalidSignature,
    #[error("promotion content identity is invalid")]
    InvalidPromotionId,
    #[error("promotion trust policy is invalid")]
    InvalidTrustPolicy,
    #[error("promotion payload is invalid")]
    InvalidPromotion,
    #[error("promotion does not match the trust policy")]
    PolicyMismatch,
    #[error("promotion has expired or is not yet valid")]
    ExpiredPromotion,
    #[error("promotion validity exceeds the maximum")]
    ExcessiveValidity,
    #[error("promotion rule pack or candidate is invalid")]
    RulePackMismatch,
    #[error("promotion region policy is incomplete or duplicated")]
    RegionPolicyMismatch,
    #[error("promotion requires healthy accepted regional evidence")]
    HealthNotAccepted,
    #[error("promotion health evidence is stale or version-mismatched")]
    HealthEvidenceMismatch,
    #[error("promotion sequence was already seen")]
    SequenceReplay,
    #[error("promotion does not extend the active rule pack")]
    PreviousPackMismatch,
    #[error("promotion site does not match the activation registry")]
    SiteMismatch,
    #[error("there is no retained last-known-good promotion")]
    NoLastKnownGood,
    #[error("promotion canonical serialization failed")]
    CanonicalSerialization,
}

fn validate_request_surface(request: &PromotionBuildRequest<'_>) -> Result<(), PromotionError> {
    if request.sequence == 0
        || !valid_regions(request.required_regions)
        || request.expires_at_unix_ms <= request.issued_at_unix_ms
    {
        return Err(PromotionError::InvalidPromotion);
    }
    if request.expires_at_unix_ms - request.issued_at_unix_ms > MAX_PROMOTION_VALIDITY_MS {
        return Err(PromotionError::ExcessiveValidity);
    }
    if request
        .previous_rule_pack_hash
        .is_some_and(|hash| !valid_sha256(hash) || hash == request.rule_pack.content_hash)
    {
        return Err(PromotionError::PreviousPackMismatch);
    }
    Ok(())
}

fn bind_healthy_regions(
    request: &PromotionBuildRequest<'_>,
) -> Result<(String, String, BTreeMap<String, PromotionRegionEvidence>), PromotionError> {
    let mut regions = BTreeMap::new();
    let mut shadow_evidence_ids = BTreeSet::new();
    let mut manifest_hash = None;
    let mut engine_hash = None;

    for record in request.health_records {
        record
            .validate(RuleHealthPolicy::default())
            .map_err(|_| PromotionError::HealthNotAccepted)?;
        if record.state != RuleHealth::Healthy || record.last_evidence_ids.len() != 2 {
            return Err(PromotionError::HealthNotAccepted);
        }
        if record.key.site_id.as_str() != request.candidate.source.id
            || record.key.rule_hash != request.candidate.rule_hash
            || !request.required_regions.contains(&record.key.region)
            || record.updated_at_unix_ms > request.issued_at_unix_ms
            || record
                .last_evidence_expires_at_unix_ms
                .is_none_or(|expiry| expiry < request.expires_at_unix_ms)
        {
            return Err(PromotionError::HealthEvidenceMismatch);
        }
        let record_manifest = record
            .last_manifest_hash
            .as_ref()
            .ok_or(PromotionError::HealthEvidenceMismatch)?;
        let record_engine = record
            .last_engine_hash
            .as_ref()
            .ok_or(PromotionError::HealthEvidenceMismatch)?;
        if manifest_hash
            .as_ref()
            .is_some_and(|expected| expected != record_manifest)
            || engine_hash
                .as_ref()
                .is_some_and(|expected| expected != record_engine)
        {
            return Err(PromotionError::HealthEvidenceMismatch);
        }
        manifest_hash.get_or_insert_with(|| record_manifest.clone());
        engine_hash.get_or_insert_with(|| record_engine.clone());

        let evidence = PromotionRegionEvidence {
            health_sequence: record.sequence,
            observed_at_unix_ms: record.updated_at_unix_ms,
            evidence_expires_at_unix_ms: record
                .last_evidence_expires_at_unix_ms
                .expect("validated non-initial record has evidence expiry"),
            aggregate_evidence_id: record.last_evidence_ids[0].clone(),
            shadow_evidence_id: record.last_evidence_ids[1].clone(),
        };
        if !shadow_evidence_ids.insert(evidence.shadow_evidence_id.clone()) {
            return Err(PromotionError::RegionPolicyMismatch);
        }
        if regions
            .insert(record.key.region.clone(), evidence)
            .is_some()
        {
            return Err(PromotionError::RegionPolicyMismatch);
        }
    }

    if regions.keys().ne(request.required_regions.iter()) {
        return Err(PromotionError::RegionPolicyMismatch);
    }
    Ok((
        manifest_hash.ok_or(PromotionError::RegionPolicyMismatch)?,
        engine_hash.ok_or(PromotionError::RegionPolicyMismatch)?,
        regions,
    ))
}

fn validate_trust_policy(policy: &PromotionTrustPolicy) -> Result<(), PromotionError> {
    if policy.trusted_keys.is_empty()
        || !policy.trusted_keys.keys().all(|key_id| valid_label(key_id))
        || !valid_label(&policy.expected_site_id)
        || !valid_sha256(&policy.expected_rule_hash)
        || !valid_sha256(&policy.expected_rule_pack_hash)
        || !valid_sha256(&policy.expected_manifest_hash)
        || !valid_sha256(&policy.expected_engine_hash)
        || policy
            .expected_previous_rule_pack_hash
            .as_deref()
            .is_some_and(|hash| !valid_sha256(hash))
        || !valid_regions(&policy.required_regions)
    {
        return Err(PromotionError::InvalidTrustPolicy);
    }
    Ok(())
}

fn validate_promotion(
    promotion: &PromotionV1,
    policy: &PromotionTrustPolicy,
    verified_at_unix_ms: i64,
) -> Result<(), PromotionError> {
    if promotion.schema != PROMOTION_V1
        || promotion.sequence == 0
        || !valid_label(&promotion.site_id)
        || !valid_sha256(&promotion.rule_hash)
        || !valid_sha256(&promotion.rule_pack_hash)
        || !valid_sha256(&promotion.manifest_hash)
        || !valid_sha256(&promotion.engine_hash)
        || promotion
            .previous_rule_pack_hash
            .as_deref()
            .is_some_and(|hash| !valid_sha256(hash) || hash == promotion.rule_pack_hash)
        || promotion.regions.is_empty()
        || promotion.regions.len() > MAX_REGIONS
    {
        return Err(PromotionError::InvalidPromotion);
    }
    if promotion.issued_at_unix_ms > verified_at_unix_ms
        || promotion.expires_at_unix_ms <= verified_at_unix_ms
        || promotion.expires_at_unix_ms <= promotion.issued_at_unix_ms
    {
        return Err(PromotionError::ExpiredPromotion);
    }
    if promotion.expires_at_unix_ms - promotion.issued_at_unix_ms > MAX_PROMOTION_VALIDITY_MS {
        return Err(PromotionError::ExcessiveValidity);
    }
    if promotion.site_id != policy.expected_site_id
        || promotion.rule_hash != policy.expected_rule_hash
        || promotion.rule_pack_hash != policy.expected_rule_pack_hash
        || promotion.previous_rule_pack_hash != policy.expected_previous_rule_pack_hash
        || promotion.manifest_hash != policy.expected_manifest_hash
        || promotion.engine_hash != policy.expected_engine_hash
        || promotion.sequence <= policy.minimum_sequence_exclusive
        || promotion.regions.keys().ne(policy.required_regions.iter())
    {
        return Err(PromotionError::PolicyMismatch);
    }
    if promotion.regions.iter().any(|(region, evidence)| {
        !valid_label(region)
            || evidence.health_sequence == 0
            || evidence.observed_at_unix_ms > promotion.issued_at_unix_ms
            || evidence.evidence_expires_at_unix_ms < promotion.expires_at_unix_ms
            || !valid_sha256(&evidence.aggregate_evidence_id)
            || !valid_sha256(&evidence.shadow_evidence_id)
            || evidence.aggregate_evidence_id == evidence.shadow_evidence_id
    }) {
        return Err(PromotionError::HealthEvidenceMismatch);
    }
    Ok(())
}

fn validate_rule_pack(
    rule_pack: &CompiledRulePack,
    candidate: &CompiledSiteRule,
) -> Result<(), PromotionError> {
    let compiler = RuleCompiler::new();
    let compiled_candidate = compiler
        .compile_source(candidate.source.clone(), Some(&candidate.source.id))
        .map_err(|_| PromotionError::RulePackMismatch)?;
    if compiled_candidate.rule_hash != candidate.rule_hash
        || compiled_candidate.canonical_json != candidate.canonical_json
        || !rule_pack
            .rules
            .iter()
            .any(|source| source == &candidate.source)
    {
        return Err(PromotionError::RulePackMismatch);
    }

    let compiled_rules = rule_pack
        .rules
        .iter()
        .map(|source| {
            compiler
                .compile_source(source.clone(), Some(&source.id))
                .map_err(|_| PromotionError::RulePackMismatch)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let rebuilt = compiler
        .compile_pack(&compiled_rules)
        .map_err(|_| PromotionError::RulePackMismatch)?;
    if rule_pack.schema != RULE_PACK_V1 || rebuilt.content_hash != rule_pack.content_hash {
        return Err(PromotionError::RulePackMismatch);
    }
    Ok(())
}

fn signing_bytes(promotion: &PromotionV1) -> Result<Vec<u8>, PromotionError> {
    let canonical =
        serde_json::to_vec(promotion).map_err(|_| PromotionError::CanonicalSerialization)?;
    let mut bytes = Vec::with_capacity(SIGNING_DOMAIN.len() + canonical.len());
    bytes.extend_from_slice(SIGNING_DOMAIN);
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
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
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use socialname_domain::{
        RuleClassificationFailure, RuleHealthEvent, RuleHealthKey, RuleHealthSignal, SiteId,
    };

    use super::*;

    const MANIFEST_HASH: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const ENGINE_HASH: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const ISSUED_AT: i64 = 1_000_000;
    const EXPIRES_AT: i64 = ISSUED_AT + 60_000;

    fn candidate(note: &str) -> CompiledSiteRule {
        let mut source = RuleCompiler::new()
            .compile_yaml(
                include_str!("../../../rules/sites/github.yaml"),
                Some("github"),
            )
            .expect("fixture candidate compiles")
            .source;
        source.metadata.notes = note.to_owned();
        RuleCompiler::new()
            .compile_source(source, Some("github"))
            .expect("candidate compiles")
    }

    fn pack(candidate: &CompiledSiteRule) -> CompiledRulePack {
        RuleCompiler::new()
            .compile_pack(std::slice::from_ref(candidate))
            .expect("pack compiles")
    }

    fn health(candidate: &CompiledSiteRule, region: &str, sequence: u64) -> RuleHealthRecord {
        let region_marker = if region == "region-a" {
            0x1_000_u64
        } else {
            0x2_000_u64
        };
        RuleHealthRecord {
            key: RuleHealthKey {
                site_id: SiteId::new("github"),
                rule_hash: candidate.rule_hash.clone(),
                region: region.to_owned(),
            },
            state: RuleHealth::Healthy,
            sequence,
            entered_at_unix_ms: ISSUED_AT - 2_000,
            updated_at_unix_ms: ISSUED_AT - 1_000,
            consecutive_recovery_passes: 0,
            consecutive_operational_failures: 0,
            last_manifest_hash: Some(MANIFEST_HASH.to_owned()),
            last_engine_hash: Some(ENGINE_HASH.to_owned()),
            last_evidence_expires_at_unix_ms: Some(EXPIRES_AT + 1_000),
            last_evidence_ids: vec![
                format!("{:064x}", 0x100_u64 + sequence),
                format!("{:064x}", region_marker + sequence),
            ],
        }
    }

    fn regions() -> BTreeSet<String> {
        BTreeSet::from(["region-a".to_owned(), "region-b".to_owned()])
    }

    fn signing_key() -> PromotionSigningKey {
        PromotionSigningKey::from_seed("release-2026", [7; 32]).expect("key is valid")
    }

    fn build(
        signing_key: &PromotionSigningKey,
        candidate: &CompiledSiteRule,
        pack: &CompiledRulePack,
        previous: Option<&str>,
        sequence: u64,
    ) -> PromotionEnvelope {
        let records = vec![
            health(candidate, "region-a", sequence * 2),
            health(candidate, "region-b", sequence * 2),
        ];
        PromotionBuilder::new()
            .build(
                signing_key,
                PromotionBuildRequest {
                    sequence,
                    candidate,
                    rule_pack: pack,
                    previous_rule_pack_hash: previous,
                    health_records: &records,
                    required_regions: &regions(),
                    issued_at_unix_ms: ISSUED_AT,
                    expires_at_unix_ms: EXPIRES_AT,
                },
            )
            .expect("promotion builds")
    }

    fn policy(
        key: &PromotionSigningKey,
        candidate: &CompiledSiteRule,
        pack: &CompiledRulePack,
        previous: Option<&str>,
        minimum_sequence_exclusive: u64,
    ) -> PromotionTrustPolicy {
        PromotionTrustPolicy {
            trusted_keys: BTreeMap::from([(key.key_id().to_owned(), key.verifying_key_bytes())]),
            expected_site_id: "github".to_owned(),
            expected_rule_hash: candidate.rule_hash.clone(),
            expected_rule_pack_hash: pack.content_hash.clone(),
            expected_previous_rule_pack_hash: previous.map(str::to_owned),
            expected_manifest_hash: MANIFEST_HASH.to_owned(),
            expected_engine_hash: ENGINE_HASH.to_owned(),
            required_regions: regions(),
            minimum_sequence_exclusive,
        }
    }

    #[test]
    fn signed_promotion_activates_and_retains_a_rollback_pack() {
        let key = signing_key();
        let first_candidate = candidate("first candidate");
        let first_pack = pack(&first_candidate);
        let first_envelope = build(&key, &first_candidate, &first_pack, None, 1);
        let first_json = serde_json::to_vec(&first_envelope).expect("serializes");
        let first = PromotionVerifier::new()
            .validate_json_at(
                &first_json,
                &policy(&key, &first_candidate, &first_pack, None, 0),
                ISSUED_AT + 1,
            )
            .expect("first promotion validates");

        let mut registry = PromotionActivationRegistry::new("github").expect("valid registry");
        registry
            .activate(&first, &first_pack, &first_candidate, ISSUED_AT + 2)
            .expect("first promotion activates");
        assert_eq!(
            registry.active().unwrap().rule_pack().content_hash,
            first_pack.content_hash
        );
        assert!(registry.last_known_good().is_none());

        let second_candidate = candidate("second candidate");
        let second_pack = pack(&second_candidate);
        let second_envelope = build(
            &key,
            &second_candidate,
            &second_pack,
            Some(&first_pack.content_hash),
            2,
        );
        let second = PromotionVerifier::new()
            .validate_at(
                &second_envelope,
                &policy(
                    &key,
                    &second_candidate,
                    &second_pack,
                    Some(&first_pack.content_hash),
                    1,
                ),
                ISSUED_AT + 3,
            )
            .expect("second promotion validates");
        registry
            .activate(&second, &second_pack, &second_candidate, ISSUED_AT + 4)
            .expect("second promotion activates");
        assert_eq!(
            registry.last_known_good().unwrap().rule_pack().content_hash,
            first_pack.content_hash
        );
        assert_eq!(registry.highest_sequence(), 2);

        registry.rollback().expect("retained pack rolls back");
        assert_eq!(
            registry.active().unwrap().rule_pack().content_hash,
            first_pack.content_hash
        );
        assert!(registry.last_known_good().is_none());
        assert_eq!(registry.highest_sequence(), 2);
        assert_eq!(
            registry
                .activate(&first, &first_pack, &first_candidate, ISSUED_AT + 5)
                .unwrap_err(),
            PromotionError::SequenceReplay
        );
    }

    #[test]
    fn rejects_tampering_wrong_keys_expiry_and_unknown_fields() {
        let key = signing_key();
        let candidate = candidate("candidate");
        let pack = pack(&candidate);
        let envelope = build(&key, &candidate, &pack, None, 1);
        let verifier = PromotionVerifier::new();
        let trust_policy = policy(&key, &candidate, &pack, None, 0);

        let mut tampered = envelope.clone();
        tampered
            .promotion
            .regions
            .get_mut("region-a")
            .unwrap()
            .health_sequence += 1;
        assert_eq!(
            verifier
                .validate_at(&tampered, &trust_policy, ISSUED_AT + 1)
                .unwrap_err(),
            PromotionError::InvalidPromotionId
        );

        let wrong_key = PromotionSigningKey::from_seed("release-2026", [8; 32]).unwrap();
        assert_eq!(
            verifier
                .validate_at(
                    &envelope,
                    &policy(&wrong_key, &candidate, &pack, None, 0),
                    ISSUED_AT + 1,
                )
                .unwrap_err(),
            PromotionError::InvalidSignature
        );
        assert_eq!(
            verifier
                .validate_at(&envelope, &trust_policy, EXPIRES_AT)
                .unwrap_err(),
            PromotionError::ExpiredPromotion
        );

        let mut value = serde_json::to_value(&envelope).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_owned(), serde_json::Value::Bool(true));
        assert_eq!(
            verifier
                .validate_json_at(
                    &serde_json::to_vec(&value).unwrap(),
                    &trust_policy,
                    ISSUED_AT + 1,
                )
                .unwrap_err(),
            PromotionError::MalformedArtifact
        );
    }

    #[test]
    fn only_complete_fresh_healthy_region_evidence_can_build() {
        let key = signing_key();
        let candidate = candidate("candidate");
        let pack = pack(&candidate);
        let required_regions = regions();
        let mut records = vec![
            health(&candidate, "region-a", 2),
            health(&candidate, "region-b", 2),
        ];
        records[0].state = RuleHealth::Degraded;
        records[0].last_evidence_ids.truncate(1);
        assert_eq!(
            PromotionBuilder::new()
                .build(
                    &key,
                    PromotionBuildRequest {
                        sequence: 1,
                        candidate: &candidate,
                        rule_pack: &pack,
                        previous_rule_pack_hash: None,
                        health_records: &records,
                        required_regions: &required_regions,
                        issued_at_unix_ms: ISSUED_AT,
                        expires_at_unix_ms: EXPIRES_AT,
                    },
                )
                .unwrap_err(),
            PromotionError::HealthNotAccepted
        );

        let partial = vec![health(&candidate, "region-a", 2)];
        assert_eq!(
            PromotionBuilder::new()
                .build(
                    &key,
                    PromotionBuildRequest {
                        sequence: 1,
                        candidate: &candidate,
                        rule_pack: &pack,
                        previous_rule_pack_hash: None,
                        health_records: &partial,
                        required_regions: &required_regions,
                        issued_at_unix_ms: ISSUED_AT,
                        expires_at_unix_ms: EXPIRES_AT,
                    },
                )
                .unwrap_err(),
            PromotionError::RegionPolicyMismatch
        );

        let mut expired = vec![
            health(&candidate, "region-a", 2),
            health(&candidate, "region-b", 2),
        ];
        expired[0].last_evidence_expires_at_unix_ms = Some(EXPIRES_AT - 1);
        assert_eq!(
            PromotionBuilder::new()
                .build(
                    &key,
                    PromotionBuildRequest {
                        sequence: 1,
                        candidate: &candidate,
                        rule_pack: &pack,
                        previous_rule_pack_hash: None,
                        health_records: &expired,
                        required_regions: &required_regions,
                        issued_at_unix_ms: ISSUED_AT,
                        expires_at_unix_ms: EXPIRES_AT,
                    },
                )
                .unwrap_err(),
            PromotionError::HealthEvidenceMismatch
        );
    }

    #[test]
    fn activation_rechecks_pack_bytes_and_previous_hash() {
        let key = signing_key();
        let initial_candidate = candidate("candidate");
        let initial_pack = pack(&initial_candidate);
        let envelope = build(&key, &initial_candidate, &initial_pack, None, 1);
        let validated = PromotionVerifier::new()
            .validate_at(
                &envelope,
                &policy(&key, &initial_candidate, &initial_pack, None, 0),
                ISSUED_AT + 1,
            )
            .unwrap();

        let other_candidate = candidate("other candidate");
        let other_pack = pack(&other_candidate);
        let mut registry = PromotionActivationRegistry::new("github").unwrap();
        assert_eq!(
            registry
                .activate(&validated, &other_pack, &other_candidate, ISSUED_AT + 2)
                .unwrap_err(),
            PromotionError::RulePackMismatch
        );
        registry
            .activate(&validated, &initial_pack, &initial_candidate, ISSUED_AT + 2)
            .unwrap();

        let replacement = candidate("replacement");
        let replacement_pack = pack(&replacement);
        let missing_previous = build(&key, &replacement, &replacement_pack, None, 2);
        let replacement_validated = PromotionVerifier::new()
            .validate_at(
                &missing_previous,
                &policy(&key, &replacement, &replacement_pack, None, 1),
                ISSUED_AT + 3,
            )
            .unwrap();
        assert_eq!(
            registry
                .activate(
                    &replacement_validated,
                    &replacement_pack,
                    &replacement,
                    ISSUED_AT + 4,
                )
                .unwrap_err(),
            PromotionError::PreviousPackMismatch
        );
    }

    #[test]
    fn multi_region_drift_blocks_promotion_until_recovery_and_rollback_stays_available() {
        let key = signing_key();
        let first_candidate = candidate("last known good");
        let first_pack = pack(&first_candidate);
        let first_envelope = build(&key, &first_candidate, &first_pack, None, 1);
        let first = PromotionVerifier::new()
            .validate_at(
                &first_envelope,
                &policy(&key, &first_candidate, &first_pack, None, 0),
                ISSUED_AT + 1,
            )
            .unwrap();
        let mut registry = PromotionActivationRegistry::new("github").unwrap();
        registry
            .activate(&first, &first_pack, &first_candidate, ISSUED_AT + 2)
            .unwrap();

        let next_candidate = candidate("candidate with measured update");
        let next_pack = pack(&next_candidate);
        let region_a = health(&next_candidate, "region-a", 2);
        let region_b = health(&next_candidate, "region-b", 2);
        let drift = RuleHealthEvent {
            key: region_b.key.clone(),
            sequence: 3,
            manifest_hash: MANIFEST_HASH.to_owned(),
            engine_hash: ENGINE_HASH.to_owned(),
            observed_at_unix_ms: ISSUED_AT - 900,
            expires_at_unix_ms: EXPIRES_AT + 1_000,
            signal: RuleHealthSignal::ClassificationFailure {
                evidence_id: "3".repeat(64),
                failure: RuleClassificationFailure::VerdictRegression,
            },
        };
        let (quarantined_b, transition) = region_b
            .apply_at(
                &drift,
                RuleHealthPolicy::default(),
                drift.observed_at_unix_ms + 1,
            )
            .unwrap();
        assert_eq!(transition.to, RuleHealth::Quarantined);
        assert_eq!(
            PromotionBuilder::new()
                .build(
                    &key,
                    PromotionBuildRequest {
                        sequence: 2,
                        candidate: &next_candidate,
                        rule_pack: &next_pack,
                        previous_rule_pack_hash: Some(&first_pack.content_hash),
                        health_records: &[region_a.clone(), quarantined_b.clone()],
                        required_regions: &regions(),
                        issued_at_unix_ms: ISSUED_AT,
                        expires_at_unix_ms: EXPIRES_AT,
                    },
                )
                .unwrap_err(),
            PromotionError::HealthNotAccepted
        );

        let first_recovery = RuleHealthEvent {
            key: quarantined_b.key.clone(),
            sequence: 4,
            manifest_hash: MANIFEST_HASH.to_owned(),
            engine_hash: ENGINE_HASH.to_owned(),
            observed_at_unix_ms: ISSUED_AT - 800,
            expires_at_unix_ms: EXPIRES_AT + 1_000,
            signal: RuleHealthSignal::AcceptancePassed {
                aggregate_evidence_id: "4".repeat(64),
                shadow_evidence_id: "5".repeat(64),
            },
        };
        let (recovering_b, _) = quarantined_b
            .apply_at(
                &first_recovery,
                RuleHealthPolicy::default(),
                first_recovery.observed_at_unix_ms + 1,
            )
            .unwrap();
        let second_recovery = RuleHealthEvent {
            key: recovering_b.key.clone(),
            sequence: 5,
            manifest_hash: MANIFEST_HASH.to_owned(),
            engine_hash: ENGINE_HASH.to_owned(),
            observed_at_unix_ms: ISSUED_AT - 700,
            expires_at_unix_ms: EXPIRES_AT + 1_000,
            signal: RuleHealthSignal::AcceptancePassed {
                aggregate_evidence_id: "6".repeat(64),
                shadow_evidence_id: "7".repeat(64),
            },
        };
        let (healthy_b, _) = recovering_b
            .apply_at(
                &second_recovery,
                RuleHealthPolicy::default(),
                second_recovery.observed_at_unix_ms + 1,
            )
            .unwrap();
        assert_eq!(healthy_b.state, RuleHealth::Healthy);

        let next_envelope = PromotionBuilder::new()
            .build(
                &key,
                PromotionBuildRequest {
                    sequence: 2,
                    candidate: &next_candidate,
                    rule_pack: &next_pack,
                    previous_rule_pack_hash: Some(&first_pack.content_hash),
                    health_records: &[region_a, healthy_b],
                    required_regions: &regions(),
                    issued_at_unix_ms: ISSUED_AT,
                    expires_at_unix_ms: EXPIRES_AT,
                },
            )
            .unwrap();
        let next = PromotionVerifier::new()
            .validate_at(
                &next_envelope,
                &policy(
                    &key,
                    &next_candidate,
                    &next_pack,
                    Some(&first_pack.content_hash),
                    1,
                ),
                ISSUED_AT + 3,
            )
            .unwrap();
        registry
            .activate(&next, &next_pack, &next_candidate, ISSUED_AT + 4)
            .unwrap();
        registry.rollback().unwrap();
        assert_eq!(
            registry.active().unwrap().rule_pack().content_hash,
            first_pack.content_hash
        );
        assert_eq!(registry.highest_sequence(), 2);
    }
}
