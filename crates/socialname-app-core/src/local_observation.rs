use sha2::{Digest, Sha256};
use socialname_domain::{
    CollectionProfile, Observation, ObservationId, ProducerKind, ProducerReputation, SiteId,
    TargetKey, Verdict,
};
use socialname_engine::SearchResult;

use crate::AppCoreError;

const FOUND_TTL_MS: i64 = 24 * 60 * 60 * 1_000;
const NOT_FOUND_TTL_MS: i64 = 15 * 60 * 1_000;
const INCONCLUSIVE_TTL_MS: i64 = 5 * 60 * 1_000;

pub fn local_observation_from_result(
    result: &SearchResult,
    region_class: &str,
    observed_at_unix_ms: i64,
    rule_health_green: bool,
) -> Result<Option<Observation>, AppCoreError> {
    let ttl_ms = match result.classification.verdict {
        Verdict::Found => FOUND_TTL_MS,
        Verdict::NotFound => NOT_FOUND_TTL_MS,
        Verdict::Inconclusive => INCONCLUSIVE_TTL_MS,
        Verdict::InvalidUsername => return Ok(None),
    };
    let expires_at_unix_ms =
        observed_at_unix_ms
            .checked_add(ttl_ms)
            .ok_or(AppCoreError::ObservationExpiry {
                observed_at_unix_ms,
                ttl_ms,
            })?;
    Ok(Some(Observation {
        id: ObservationId::new(local_observation_id(
            result,
            region_class,
            observed_at_unix_ms,
        )),
        target: TargetKey {
            site_id: SiteId::new(result.site_id.clone()),
            normalized_username: result.username.clone(),
        },
        verdict: result.classification.verdict,
        inconclusive_reason: result.classification.inconclusive_reason,
        evidence_class: result.classification.evidence_class,
        observed_at_unix_ms,
        expires_at_unix_ms,
        region: region_class.to_owned(),
        network_group: "local-network".to_owned(),
        independence_group: "local-installation".to_owned(),
        producer_kind: ProducerKind::LocalCli,
        producer_reputation: ProducerReputation::New,
        collection_profile: CollectionProfile::LocalOnly,
        rule_hash: result.rule_hash.clone(),
        rule_health_green,
        evidence_digest: result.classification.evidence_digest.clone(),
    }))
}

fn local_observation_id(
    result: &SearchResult,
    region_class: &str,
    observed_at_unix_ms: i64,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"socialname.local-observation/v1\0");
    for value in [
        result.site_id.as_bytes(),
        result.username.as_bytes(),
        result.rule_hash.as_bytes(),
        region_class.as_bytes(),
        result.classification.evidence_digest.as_bytes(),
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }
    digest.update(observed_at_unix_ms.to_be_bytes());
    format!("local-{}", hex::encode(digest.finalize()))
}

#[cfg(test)]
mod tests {
    use socialname_domain::{EvidenceClass, InconclusiveReason};
    use socialname_engine::Classification;

    use super::*;

    fn result(verdict: Verdict) -> SearchResult {
        SearchResult {
            site_id: "example".to_owned(),
            username: "private-target".to_owned(),
            profile_url: None,
            rule_hash: "1".repeat(64),
            classification: Classification {
                verdict,
                inconclusive_reason: (verdict == Verdict::Inconclusive)
                    .then_some(InconclusiveReason::Timeout),
                evidence_class: EvidenceClass::E4StructuredIdentity,
                matcher_trace: Vec::new(),
                evidence_digest: "2".repeat(64),
            },
            probes: Vec::new(),
        }
    }

    #[test]
    fn verdict_ttls_remain_distinct() {
        let found = local_observation_from_result(&result(Verdict::Found), "local", 1_000, true)
            .unwrap()
            .unwrap();
        let not_found =
            local_observation_from_result(&result(Verdict::NotFound), "local", 1_000, true)
                .unwrap()
                .unwrap();
        let inconclusive =
            local_observation_from_result(&result(Verdict::Inconclusive), "local", 1_000, false)
                .unwrap()
                .unwrap();

        assert_eq!(found.expires_at_unix_ms, 86_401_000);
        assert_eq!(not_found.expires_at_unix_ms, 901_000);
        assert_eq!(inconclusive.expires_at_unix_ms, 301_000);
        assert!(!inconclusive.rule_health_green);
    }

    #[test]
    fn invalid_input_is_not_persisted() {
        assert!(
            local_observation_from_result(&result(Verdict::InvalidUsername), "local", 1_000, false)
                .unwrap()
                .is_none()
        );
    }
}
