#![forbid(unsafe_code)]

mod delivery;
mod derivation;
mod job;

use socialname_canary::{RulePackRolloutStage, ValidatedRulePackMetadata};
use socialname_engine::{SearchEngine, SearchResult};
use socialname_rule_compiler::{CompiledRulePack, CompiledSiteRule, RuleCompiler};
use tokio_util::sync::CancellationToken;

pub use delivery::{
    DeliveryClaim, DeliveryError, DeliveryProcessConfig, DeliveryProcessOutcome, DeliverySecrets,
    DeliveryStore, ENDPOINT_ENCRYPTION_KEY_HEX_ENV, ENDPOINT_ENCRYPTION_KEY_ID_ENV,
    ManagedWebhookTransport, WEBHOOK_SIGNING_KEY_HEX_ENV, WEBHOOK_SIGNING_KEY_ID_ENV,
    WebhookRequest, WebhookSendError, WebhookTransport, process_one_delivery,
};
pub use job::{
    ExpandOutcome, JobClaim, JobDisposition, JobError, JobExecutionError, JobStore, RuleBinding,
    WORKER_DATABASE_URL_ENV, WatchPlanOutcome,
};

#[derive(Clone, Debug)]
pub struct ManagedRule {
    metadata_id: String,
    metadata_sequence: u64,
    rollout_stage: RulePackRolloutStage,
    promotion_id: String,
    promotion_sequence: u64,
    rule_pack_hash: String,
    region_class: String,
    metadata_expires_at_unix_ms: i64,
    promotion_expires_at_unix_ms: i64,
    evidence_expires_at_unix_ms: i64,
    candidate: CompiledSiteRule,
    engine: SearchEngine,
}

impl ManagedRule {
    pub fn activate(
        validated: &ValidatedRulePackMetadata,
        rule_pack: &CompiledRulePack,
        site_id: &str,
        region_class: impl Into<String>,
        worker_id: &str,
        activated_at_unix_ms: i64,
    ) -> Result<Self, WorkerError> {
        let region_class = region_class.into();
        if !valid_label(&region_class) {
            return Err(WorkerError::InvalidRegion);
        }
        if !valid_label(site_id) || !valid_label(worker_id) {
            return Err(WorkerError::InvalidWorkerIdentity);
        }
        let metadata = validated.metadata();
        if metadata.issued_at_unix_ms > activated_at_unix_ms
            || metadata.expires_at_unix_ms <= activated_at_unix_ms
        {
            return Err(WorkerError::ExpiredMetadata);
        }
        if !metadata.required_regions.contains(&region_class) {
            return Err(WorkerError::RegionNotAccepted);
        }
        if !validated.permits_worker(&region_class, worker_id) {
            return Err(WorkerError::WorkerNotEligible);
        }
        validated
            .validate_pack(rule_pack)
            .map_err(|_| WorkerError::RulePackMismatch)?;
        let validated_promotion = validated
            .promotion(site_id)
            .ok_or(WorkerError::RulePackMismatch)?;
        let promotion = validated_promotion.promotion();
        if promotion.issued_at_unix_ms > activated_at_unix_ms
            || promotion.expires_at_unix_ms <= activated_at_unix_ms
        {
            return Err(WorkerError::ExpiredPromotion);
        }
        let evidence = promotion
            .regions
            .get(&region_class)
            .ok_or(WorkerError::RegionNotAccepted)?;
        if evidence.evidence_expires_at_unix_ms <= activated_at_unix_ms {
            return Err(WorkerError::ExpiredEvidence);
        }

        let compiler = RuleCompiler::new();
        let compiled_rules = rule_pack
            .rules
            .iter()
            .map(|source| {
                compiler
                    .compile_source(source.clone(), Some(&source.id))
                    .map_err(|_| WorkerError::RulePackMismatch)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let rebuilt = compiler
            .compile_pack(&compiled_rules)
            .map_err(|_| WorkerError::RulePackMismatch)?;
        if rebuilt.schema != rule_pack.schema
            || rebuilt.content_hash != rule_pack.content_hash
            || promotion.rule_pack_hash != rule_pack.content_hash
        {
            return Err(WorkerError::RulePackMismatch);
        }
        let candidate = compiled_rules
            .into_iter()
            .find(|candidate| candidate.source.id == promotion.site_id)
            .ok_or(WorkerError::RulePackMismatch)?;
        if candidate.rule_hash != promotion.rule_hash {
            return Err(WorkerError::RulePackMismatch);
        }

        Ok(Self {
            metadata_id: validated.envelope().metadata_id.clone(),
            metadata_sequence: metadata.sequence,
            rollout_stage: metadata.rollout_stage,
            promotion_id: validated_promotion.envelope().promotion_id.clone(),
            promotion_sequence: promotion.sequence,
            rule_pack_hash: promotion.rule_pack_hash.clone(),
            region_class,
            metadata_expires_at_unix_ms: metadata.expires_at_unix_ms,
            promotion_expires_at_unix_ms: promotion.expires_at_unix_ms,
            evidence_expires_at_unix_ms: evidence.evidence_expires_at_unix_ms,
            candidate,
            engine: SearchEngine::new_managed().map_err(|_| WorkerError::TransportUnavailable)?,
        })
    }

    #[must_use]
    pub fn metadata_id(&self) -> &str {
        &self.metadata_id
    }

    #[must_use]
    pub const fn metadata_sequence(&self) -> u64 {
        self.metadata_sequence
    }

    #[must_use]
    pub const fn rollout_stage(&self) -> RulePackRolloutStage {
        self.rollout_stage
    }

    #[must_use]
    pub const fn permits_customer_work(&self) -> bool {
        matches!(
            self.rollout_stage,
            RulePackRolloutStage::General | RulePackRolloutStage::Rollback
        )
    }

    #[must_use]
    pub fn promotion_id(&self) -> &str {
        &self.promotion_id
    }

    #[must_use]
    pub const fn promotion_sequence(&self) -> u64 {
        self.promotion_sequence
    }

    #[must_use]
    pub fn site_id(&self) -> &str {
        &self.candidate.source.id
    }

    #[must_use]
    pub fn rule_hash(&self) -> &str {
        &self.candidate.rule_hash
    }

    #[must_use]
    pub fn rule_pack_hash(&self) -> &str {
        &self.rule_pack_hash
    }

    #[must_use]
    pub fn region_class(&self) -> &str {
        &self.region_class
    }

    #[must_use]
    pub fn normalize_username(&self, username: &str) -> Option<String> {
        self.candidate
            .normalize_username(username)
            .filter(|normalized| {
                (1..=256).contains(&normalized.len()) && !normalized.chars().any(char::is_control)
            })
    }

    #[must_use]
    pub fn maximum_inspected_bytes_per_search(&self) -> usize {
        self.candidate.maximum_inspected_bytes_per_search()
    }

    pub async fn execute(
        &self,
        username: &str,
        executed_at_unix_ms: i64,
        cancellation: &CancellationToken,
    ) -> Result<SearchResult, WorkerError> {
        if self.metadata_expires_at_unix_ms <= executed_at_unix_ms {
            return Err(WorkerError::ExpiredMetadata);
        }
        if self.promotion_expires_at_unix_ms <= executed_at_unix_ms {
            return Err(WorkerError::ExpiredPromotion);
        }
        if self.evidence_expires_at_unix_ms <= executed_at_unix_ms {
            return Err(WorkerError::ExpiredEvidence);
        }

        tokio::select! {
            biased;
            () = cancellation.cancelled() => Err(WorkerError::Cancelled),
            result = self.engine.search(&self.candidate, username) => Ok(result),
        }
    }
}

fn valid_label(value: &str) -> bool {
    let mut characters = value.chars();
    matches!(characters.next(), Some('a'..='z' | '0'..='9'))
        && value.len() <= 64
        && characters.all(|character| matches!(character, 'a'..='z' | '0'..='9' | '-'))
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum WorkerError {
    #[error("managed worker region is invalid")]
    InvalidRegion,
    #[error("managed worker identity is invalid")]
    InvalidWorkerIdentity,
    #[error("signed rule is not accepted in this region")]
    RegionNotAccepted,
    #[error("managed worker is outside the signed rollout stage")]
    WorkerNotEligible,
    #[error("signed rule-pack metadata is expired")]
    ExpiredMetadata,
    #[error("signed rule promotion is expired")]
    ExpiredPromotion,
    #[error("signed rule evidence is expired")]
    ExpiredEvidence,
    #[error("signed rule pack does not match the promotion")]
    RulePackMismatch,
    #[error("managed probe transport is unavailable")]
    TransportUnavailable,
    #[error("managed probe was cancelled")]
    Cancelled,
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use socialname_canary::{
        PromotionBuildRequest, PromotionBuilder, PromotionSigningKey, RULE_PACK_TRUST_V1,
        RulePackMetadataBuildRequest, RulePackMetadataBuilder, RulePackMetadataSigningKey,
        RulePackMetadataVerifier, RulePackTrustV1,
    };
    use socialname_domain::{RuleHealth, RuleHealthKey, RuleHealthRecord, SiteId, Verdict};

    use super::*;

    const MANIFEST_HASH: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const ENGINE_HASH: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const ISSUED_AT: i64 = 1_000_000;
    const EXPIRES_AT: i64 = ISSUED_AT + 60_000;

    fn candidate() -> CompiledSiteRule {
        RuleCompiler::new()
            .compile_yaml(
                include_str!("../../../rules/sites/github.yaml"),
                Some("github"),
            )
            .unwrap()
    }

    fn pack(candidate: &CompiledSiteRule) -> CompiledRulePack {
        RuleCompiler::new()
            .compile_pack(std::slice::from_ref(candidate))
            .unwrap()
    }

    fn regions() -> BTreeSet<String> {
        BTreeSet::from(["region-a".to_owned()])
    }

    fn health(candidate: &CompiledSiteRule) -> RuleHealthRecord {
        RuleHealthRecord {
            key: RuleHealthKey {
                site_id: SiteId::new("github"),
                rule_hash: candidate.rule_hash.clone(),
                region: "region-a".to_owned(),
            },
            state: RuleHealth::Healthy,
            sequence: 2,
            entered_at_unix_ms: ISSUED_AT - 2_000,
            updated_at_unix_ms: ISSUED_AT - 1_000,
            consecutive_recovery_passes: 0,
            consecutive_operational_failures: 0,
            last_manifest_hash: Some(MANIFEST_HASH.to_owned()),
            last_engine_hash: Some(ENGINE_HASH.to_owned()),
            last_evidence_expires_at_unix_ms: Some(EXPIRES_AT + 2_000),
            last_evidence_ids: vec!["3".repeat(64), "4".repeat(64)],
        }
    }

    fn validated_metadata(
        candidate: &CompiledSiteRule,
        pack: &CompiledRulePack,
        rollout_stage: RulePackRolloutStage,
    ) -> ValidatedRulePackMetadata {
        let key = PromotionSigningKey::from_seed("worker-test-key", [7; 32]).unwrap();
        let promotion = PromotionBuilder::new()
            .build(
                &key,
                PromotionBuildRequest {
                    sequence: 1,
                    candidate,
                    rule_pack: pack,
                    previous_rule_pack_hash: None,
                    health_records: &[health(candidate)],
                    required_regions: &regions(),
                    issued_at_unix_ms: ISSUED_AT,
                    expires_at_unix_ms: EXPIRES_AT + 1_000,
                },
            )
            .unwrap();
        let metadata_key =
            RulePackMetadataSigningKey::from_seed("worker-test-key", [7; 32]).unwrap();
        let trust = RulePackTrustV1 {
            schema: RULE_PACK_TRUST_V1.to_owned(),
            generation: 1,
            threshold: 1,
            keys: BTreeMap::from([(
                metadata_key.key_id().to_owned(),
                metadata_key.verifying_key_hex(),
            )]),
            expires_at_unix_ms: EXPIRES_AT + 100_000,
        };
        let eligible_regions = regions();
        let eligible_workers = if rollout_stage == RulePackRolloutStage::Canary {
            BTreeSet::from(["worker-a".to_owned()])
        } else {
            BTreeSet::new()
        };
        let envelope = RulePackMetadataBuilder::new()
            .build(
                &[metadata_key],
                RulePackMetadataBuildRequest {
                    sequence: 1,
                    rule_pack: pack,
                    previous_rule_pack_hash: None,
                    required_regions: &regions(),
                    rollout_stage,
                    eligible_regions: &eligible_regions,
                    eligible_workers: &eligible_workers,
                    issued_at_unix_ms: ISSUED_AT,
                    expires_at_unix_ms: EXPIRES_AT,
                    trust: trust.clone(),
                    promotions: &[promotion],
                },
            )
            .unwrap();
        RulePackMetadataVerifier::new()
            .validate_at(&envelope, &trust, ISSUED_AT + 1)
            .unwrap()
    }

    #[tokio::test]
    async fn only_a_validated_fresh_regional_rule_can_execute() {
        let candidate = candidate();
        let pack = pack(&candidate);
        let validated = validated_metadata(&candidate, &pack, RulePackRolloutStage::General);
        let managed = ManagedRule::activate(
            &validated,
            &pack,
            "github",
            "region-a",
            "worker-a",
            ISSUED_AT + 2,
        )
        .unwrap();
        assert_eq!(managed.site_id(), "github");
        assert_eq!(managed.region_class(), "region-a");
        assert_eq!(managed.metadata_id(), validated.envelope().metadata_id);
        assert!(managed.permits_customer_work());

        let result = managed
            .execute(
                "invalid target with spaces",
                ISSUED_AT + 3,
                &CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(result.classification.verdict, Verdict::InvalidUsername);
        assert!(result.probes.is_empty());

        assert_eq!(
            ManagedRule::activate(
                &validated,
                &pack,
                "github",
                "region-b",
                "worker-a",
                ISSUED_AT + 2,
            )
            .unwrap_err(),
            WorkerError::RegionNotAccepted
        );
        assert_eq!(
            ManagedRule::activate(
                &validated,
                &pack,
                "github",
                "Region-A",
                "worker-a",
                ISSUED_AT + 2,
            )
            .unwrap_err(),
            WorkerError::InvalidRegion
        );
        assert_eq!(
            ManagedRule::activate(
                &validated, &pack, "github", "region-a", "worker-a", EXPIRES_AT,
            )
            .unwrap_err(),
            WorkerError::ExpiredMetadata
        );
        let canary = validated_metadata(&candidate, &pack, RulePackRolloutStage::Canary);
        assert_eq!(
            ManagedRule::activate(
                &canary,
                &pack,
                "github",
                "region-a",
                "worker-b",
                ISSUED_AT + 2,
            )
            .unwrap_err(),
            WorkerError::WorkerNotEligible
        );
    }

    #[tokio::test]
    async fn cancellation_and_expiry_stop_before_network_execution() {
        let candidate = candidate();
        let pack = pack(&candidate);
        let validated = validated_metadata(&candidate, &pack, RulePackRolloutStage::General);
        let managed = ManagedRule::activate(
            &validated,
            &pack,
            "github",
            "region-a",
            "worker-a",
            ISSUED_AT + 2,
        )
        .unwrap();
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        assert_eq!(
            managed
                .execute("valid-target", ISSUED_AT + 3, &cancellation)
                .await
                .unwrap_err(),
            WorkerError::Cancelled
        );
        assert_eq!(
            managed
                .execute("valid-target", EXPIRES_AT, &CancellationToken::new())
                .await
                .unwrap_err(),
            WorkerError::ExpiredMetadata
        );
    }

    #[test]
    fn activation_recompiles_pack_bytes_and_errors_do_not_echo_targets() {
        let candidate = candidate();
        let mut pack = pack(&candidate);
        let validated = validated_metadata(&candidate, &pack, RulePackRolloutStage::General);
        pack.rules[0].metadata.notes = "tampered after verification".to_owned();
        assert_eq!(
            ManagedRule::activate(
                &validated,
                &pack,
                "github",
                "region-a",
                "worker-a",
                ISSUED_AT + 2,
            )
            .unwrap_err(),
            WorkerError::RulePackMismatch
        );

        let private_target = "private-target-that-must-not-appear";
        for error in [
            WorkerError::RegionNotAccepted,
            WorkerError::WorkerNotEligible,
            WorkerError::ExpiredMetadata,
            WorkerError::ExpiredPromotion,
            WorkerError::RulePackMismatch,
            WorkerError::Cancelled,
        ] {
            assert!(!error.to_string().contains(private_target));
            assert!(!format!("{error:?}").contains(private_target));
        }
    }
}
