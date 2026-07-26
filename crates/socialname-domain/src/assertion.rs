use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{EvidenceClass, Observation, ObservationId, ProducerKind, TargetKey, Verdict};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssertionQuality {
    Verified,
    Corroborated,
    SingleVantage,
    Stale,
    Conflicted,
    Untrusted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assertion {
    pub target: TargetKey,
    pub verdict: Verdict,
    pub quality: AssertionQuality,
    pub evidence_class: EvidenceClass,
    pub observed_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub regions: BTreeSet<String>,
    pub support_group_count: usize,
    pub managed_support: bool,
    pub supporting_observation_ids: Vec<ObservationId>,
    pub conflicting_observation_ids: Vec<ObservationId>,
    pub derivation_version: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DerivationPolicy {
    pub found_shared_groups: usize,
    pub found_network_groups: usize,
    pub found_regions: usize,
    pub not_found_shared_groups: usize,
    pub not_found_network_groups: usize,
    pub not_found_regions: usize,
    pub not_found_min_span_ms: i64,
}

impl Default for DerivationPolicy {
    fn default() -> Self {
        Self {
            found_shared_groups: 3,
            found_network_groups: 2,
            found_regions: 2,
            not_found_shared_groups: 5,
            not_found_network_groups: 3,
            not_found_regions: 2,
            not_found_min_span_ms: 10 * 60 * 1_000,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DerivationError {
    #[error("no assertion-eligible observations")]
    NoEligibleObservations,
    #[error("observations do not refer to the same target")]
    MixedTargets,
}

pub fn derive_assertion(
    observations: &[Observation],
    now_unix_ms: i64,
    policy: DerivationPolicy,
) -> Result<Assertion, DerivationError> {
    let eligible: Vec<&Observation> = observations
        .iter()
        .filter(|observation| observation.is_assertion_eligible(now_unix_ms))
        .collect();
    let first = eligible
        .first()
        .copied()
        .ok_or(DerivationError::NoEligibleObservations)?;

    if eligible
        .iter()
        .any(|observation| observation.target != first.target)
    {
        return Err(DerivationError::MixedTargets);
    }

    let found: Vec<&Observation> = eligible
        .iter()
        .copied()
        .filter(|observation| observation.verdict == Verdict::Found)
        .collect();
    let not_found: Vec<&Observation> = eligible
        .iter()
        .copied()
        .filter(|observation| observation.verdict == Verdict::NotFound)
        .collect();

    if !found.is_empty() && !not_found.is_empty() {
        let newest = eligible
            .iter()
            .map(|observation| observation.observed_at_unix_ms)
            .max()
            .unwrap_or(now_unix_ms);
        let expiry = eligible
            .iter()
            .map(|observation| observation.expires_at_unix_ms)
            .min()
            .unwrap_or(now_unix_ms);
        return Ok(Assertion {
            target: first.target.clone(),
            verdict: Verdict::Inconclusive,
            quality: AssertionQuality::Conflicted,
            evidence_class: eligible
                .iter()
                .map(|observation| observation.evidence_class)
                .max()
                .unwrap_or_default(),
            observed_at_unix_ms: newest,
            expires_at_unix_ms: expiry,
            regions: eligible
                .iter()
                .map(|observation| observation.region.clone())
                .collect(),
            support_group_count: 0,
            managed_support: eligible.iter().any(|observation| observation.is_managed()),
            supporting_observation_ids: Vec::new(),
            conflicting_observation_ids: eligible
                .iter()
                .map(|observation| observation.id.clone())
                .collect(),
            derivation_version: "assertion/v1",
        });
    }

    let support = if found.is_empty() { not_found } else { found };
    let verdict = support[0].verdict;
    let managed_support = support.iter().any(|observation| observation.is_managed());

    let shared_quorum_support: Vec<&Observation> = support
        .iter()
        .copied()
        .filter(|observation| {
            observation.producer_kind == ProducerKind::SharedCli
                && observation.producer_reputation.quorum_eligible()
        })
        .collect();
    let independence_groups = distinct(
        shared_quorum_support
            .iter()
            .map(|observation| observation.independence_group.as_str()),
    );
    let network_groups = distinct(
        shared_quorum_support
            .iter()
            .map(|observation| observation.network_group.as_str()),
    );
    let regions = distinct(
        shared_quorum_support
            .iter()
            .map(|observation| observation.region.as_str()),
    );

    let first_observed = shared_quorum_support
        .iter()
        .map(|observation| observation.observed_at_unix_ms)
        .min()
        .unwrap_or(now_unix_ms);
    let last_observed = shared_quorum_support
        .iter()
        .map(|observation| observation.observed_at_unix_ms)
        .max()
        .unwrap_or(now_unix_ms);

    let has_shared_quorum = match verdict {
        Verdict::Found => {
            independence_groups >= policy.found_shared_groups
                && network_groups >= policy.found_network_groups
                && regions >= policy.found_regions
        }
        Verdict::NotFound => {
            independence_groups >= policy.not_found_shared_groups
                && network_groups >= policy.not_found_network_groups
                && regions >= policy.not_found_regions
                && last_observed - first_observed >= policy.not_found_min_span_ms
        }
        Verdict::InvalidUsername | Verdict::Inconclusive => false,
    };

    let quality = if managed_support {
        AssertionQuality::Verified
    } else if has_shared_quorum {
        AssertionQuality::Corroborated
    } else if support.iter().any(|observation| {
        observation.is_managed()
            || observation.producer_reputation.quorum_eligible()
            || matches!(
                observation.producer_kind,
                ProducerKind::LocalCli | ProducerKind::LocalDesktop
            )
    }) {
        AssertionQuality::SingleVantage
    } else {
        AssertionQuality::Untrusted
    };

    Ok(Assertion {
        target: first.target.clone(),
        verdict,
        quality,
        evidence_class: support
            .iter()
            .map(|observation| observation.evidence_class)
            .max()
            .unwrap_or_default(),
        observed_at_unix_ms: support
            .iter()
            .map(|observation| observation.observed_at_unix_ms)
            .max()
            .unwrap_or(now_unix_ms),
        expires_at_unix_ms: support
            .iter()
            .map(|observation| observation.expires_at_unix_ms)
            .min()
            .unwrap_or(now_unix_ms),
        regions: support
            .iter()
            .map(|observation| observation.region.clone())
            .collect(),
        support_group_count: distinct(
            support
                .iter()
                .map(|observation| observation.independence_group.as_str()),
        ),
        managed_support,
        supporting_observation_ids: support
            .iter()
            .map(|observation| observation.id.clone())
            .collect(),
        conflicting_observation_ids: Vec::new(),
        derivation_version: "assertion/v1",
    })
}

pub fn derive_regional_assertions(
    observations: &[Observation],
    now_unix_ms: i64,
    policy: DerivationPolicy,
) -> Result<BTreeMap<String, Assertion>, DerivationError> {
    let eligible: Vec<&Observation> = observations
        .iter()
        .filter(|observation| observation.is_assertion_eligible(now_unix_ms))
        .collect();
    let first = eligible
        .first()
        .copied()
        .ok_or(DerivationError::NoEligibleObservations)?;
    if eligible
        .iter()
        .any(|observation| observation.target != first.target)
    {
        return Err(DerivationError::MixedTargets);
    }

    let mut grouped = BTreeMap::<String, Vec<Observation>>::new();
    for observation in eligible {
        grouped
            .entry(observation.region.clone())
            .or_default()
            .push(observation.clone());
    }
    grouped
        .into_iter()
        .map(|(region, observations)| {
            derive_assertion(&observations, now_unix_ms, policy)
                .map(|assertion| (region, assertion))
        })
        .collect()
}

fn distinct<'a>(values: impl IntoIterator<Item = &'a str>) -> usize {
    values.into_iter().collect::<BTreeSet<_>>().len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CollectionProfile, InconclusiveReason, ProducerReputation, SiteId};

    const NOW: i64 = 1_000_000;

    fn observation(
        index: usize,
        verdict: Verdict,
        producer_kind: ProducerKind,
        reputation: ProducerReputation,
        region: &str,
        network: &str,
        observed_at: i64,
    ) -> Observation {
        Observation {
            id: ObservationId::new(format!("observation-{index}")),
            target: TargetKey {
                site_id: SiteId::new("example"),
                normalized_username: "alice".to_owned(),
            },
            verdict,
            inconclusive_reason: Option::<InconclusiveReason>::None,
            evidence_class: EvidenceClass::E4StructuredIdentity,
            observed_at_unix_ms: observed_at,
            expires_at_unix_ms: NOW + 60_000,
            region: region.to_owned(),
            network_group: network.to_owned(),
            independence_group: format!("independence-{index}"),
            producer_kind,
            producer_reputation: reputation,
            collection_profile: CollectionProfile::SharedObservation,
            rule_hash: "rule-hash".to_owned(),
            rule_health_green: true,
            evidence_digest: format!("digest-{index}"),
        }
    }

    #[test]
    fn managed_strong_observation_is_verified() {
        let observations = [observation(
            1,
            Verdict::Found,
            ProducerKind::ManagedWorker,
            ProducerReputation::Trusted,
            "jp",
            "managed-jp",
            NOW - 1_000,
        )];

        let assertion = derive_assertion(&observations, NOW, DerivationPolicy::default()).unwrap();

        assert_eq!(assertion.quality, AssertionQuality::Verified);
        assert_eq!(assertion.verdict, Verdict::Found);
    }

    #[test]
    fn three_diverse_shared_found_observations_are_corroborated() {
        let observations = [
            observation(
                1,
                Verdict::Found,
                ProducerKind::SharedCli,
                ProducerReputation::Calibrated,
                "jp",
                "asn-a",
                NOW - 3_000,
            ),
            observation(
                2,
                Verdict::Found,
                ProducerKind::SharedCli,
                ProducerReputation::Trusted,
                "us",
                "asn-b",
                NOW - 2_000,
            ),
            observation(
                3,
                Verdict::Found,
                ProducerKind::SharedCli,
                ProducerReputation::Calibrated,
                "us",
                "asn-b",
                NOW - 1_000,
            ),
        ];

        let assertion = derive_assertion(&observations, NOW, DerivationPolicy::default()).unwrap();

        assert_eq!(assertion.quality, AssertionQuality::Corroborated);
        assert!(!assertion.managed_support);
    }

    #[test]
    fn shared_absence_needs_time_and_stronger_quorum() {
        let observations: Vec<_> = (0..5)
            .map(|index| {
                observation(
                    index,
                    Verdict::NotFound,
                    ProducerKind::SharedCli,
                    ProducerReputation::Trusted,
                    if index % 2 == 0 { "jp" } else { "us" },
                    match index % 3 {
                        0 => "asn-a",
                        1 => "asn-b",
                        _ => "asn-c",
                    },
                    NOW - (index as i64 * 3 * 60 * 1_000),
                )
            })
            .collect();

        let assertion = derive_assertion(&observations, NOW, DerivationPolicy::default()).unwrap();

        assert_eq!(assertion.quality, AssertionQuality::Corroborated);
    }

    #[test]
    fn opposing_strong_observations_are_conflicted() {
        let observations = [
            observation(
                1,
                Verdict::Found,
                ProducerKind::ManagedWorker,
                ProducerReputation::Trusted,
                "jp",
                "managed-jp",
                NOW - 2_000,
            ),
            observation(
                2,
                Verdict::NotFound,
                ProducerKind::SharedCli,
                ProducerReputation::Trusted,
                "us",
                "asn-b",
                NOW - 1_000,
            ),
        ];

        let assertion = derive_assertion(&observations, NOW, DerivationPolicy::default()).unwrap();

        assert_eq!(assertion.quality, AssertionQuality::Conflicted);
        assert_eq!(assertion.verdict, Verdict::Inconclusive);
        assert_eq!(assertion.conflicting_observation_ids.len(), 2);
    }

    #[test]
    fn regional_assertions_preserve_cross_region_truths_behind_a_global_conflict() {
        let observations = [
            observation(
                1,
                Verdict::Found,
                ProducerKind::ManagedWorker,
                ProducerReputation::Trusted,
                "jp",
                "managed-jp",
                NOW - 2_000,
            ),
            observation(
                2,
                Verdict::NotFound,
                ProducerKind::ManagedWorker,
                ProducerReputation::Trusted,
                "us",
                "managed-us",
                NOW - 1_000,
            ),
        ];

        let global = derive_assertion(&observations, NOW, DerivationPolicy::default()).unwrap();
        let regional =
            derive_regional_assertions(&observations, NOW, DerivationPolicy::default()).unwrap();

        assert_eq!(global.quality, AssertionQuality::Conflicted);
        assert_eq!(regional.len(), 2);
        assert_eq!(regional["jp"].verdict, Verdict::Found);
        assert_eq!(regional["jp"].quality, AssertionQuality::Verified);
        assert_eq!(regional["us"].verdict, Verdict::NotFound);
        assert_eq!(regional["us"].quality, AssertionQuality::Verified);
    }

    #[test]
    fn same_region_conflict_remains_conflicted_in_its_regional_assertion() {
        let observations = [
            observation(
                1,
                Verdict::Found,
                ProducerKind::ManagedWorker,
                ProducerReputation::Trusted,
                "jp",
                "managed-jp",
                NOW - 2_000,
            ),
            observation(
                2,
                Verdict::NotFound,
                ProducerKind::ManagedWorker,
                ProducerReputation::Trusted,
                "jp",
                "managed-jp",
                NOW - 1_000,
            ),
        ];

        let regional =
            derive_regional_assertions(&observations, NOW, DerivationPolicy::default()).unwrap();

        assert_eq!(regional.len(), 1);
        assert_eq!(regional["jp"].verdict, Verdict::Inconclusive);
        assert_eq!(regional["jp"].quality, AssertionQuality::Conflicted);
        assert_eq!(regional["jp"].conflicting_observation_ids.len(), 2);
    }
}
