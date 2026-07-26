use std::collections::BTreeMap;

use futures_util::future::join_all;
use socialname_domain::{EvidenceClass, InconclusiveReason, Verdict};
use socialname_rule_compiler::{CompiledSiteRule, render_url_template};
use socialname_rule_schema::{FallbackReason, ProbePlanSource, TransportOutcome};

use crate::{Classification, ProbeClient, ProbeResponse, SearchResult, classify};

#[derive(Clone, Debug)]
pub struct SearchEngine {
    probes: ProbeClient,
}

impl SearchEngine {
    pub fn new() -> Result<Self, reqwest::Error> {
        Ok(Self {
            probes: ProbeClient::new()?,
        })
    }

    pub fn new_managed() -> Result<Self, reqwest::Error> {
        Ok(Self {
            probes: ProbeClient::new_managed()?,
        })
    }

    pub async fn search(&self, rule: &CompiledSiteRule, username: &str) -> SearchResult {
        let Some(normalized) = rule.normalize_username(username) else {
            return SearchResult {
                site_id: rule.source.id.clone(),
                username: username.to_owned(),
                profile_url: None,
                rule_hash: rule.rule_hash.clone(),
                classification: Classification {
                    verdict: Verdict::InvalidUsername,
                    inconclusive_reason: None,
                    evidence_class: EvidenceClass::E0NoAccountEvidence,
                    matcher_trace: Vec::new(),
                    evidence_digest: String::new(),
                },
                probes: Vec::new(),
            };
        };

        let responses = self.execute_plan(rule, &normalized).await;
        let classification = classify(rule, &normalized, &responses);
        let profile_url = render_url_template(&rule.source.profile_url, &normalized)
            .ok()
            .map(|url| url.to_string());
        SearchResult {
            site_id: rule.source.id.clone(),
            username: normalized,
            profile_url,
            rule_hash: rule.rule_hash.clone(),
            classification,
            probes: responses.values().map(ProbeResponse::summary).collect(),
        }
    }

    async fn execute_plan(
        &self,
        rule: &CompiledSiteRule,
        username: &str,
    ) -> BTreeMap<String, ProbeResponse> {
        match &rule.source.plan {
            ProbePlanSource::Single { probe } => {
                let response = self.execute_named(rule, probe, username).await;
                response
                    .map(|response| BTreeMap::from([(probe.clone(), response)]))
                    .unwrap_or_default()
            }
            ProbePlanSource::ParallelAll { probes } => {
                let futures = probes.iter().map(|probe| async move {
                    (
                        probe.clone(),
                        self.execute_named(rule, probe, username).await,
                    )
                });
                join_all(futures)
                    .await
                    .into_iter()
                    .filter_map(|(id, response)| response.map(|response| (id, response)))
                    .collect()
            }
            ProbePlanSource::Fallback {
                primary,
                fallback,
                on,
            } => {
                let mut responses = BTreeMap::new();
                if let Some(response) = self.execute_named(rule, primary, username).await {
                    let should_fallback = match on {
                        FallbackReason::MethodNotAllowed => response.status == Some(405),
                        FallbackReason::TransportFailure => {
                            response.transport != TransportOutcome::Completed
                        }
                        FallbackReason::NoRuleMatched => {
                            let provisional = BTreeMap::from([(primary.clone(), response.clone())]);
                            classify(rule, username, &provisional).inconclusive_reason
                                == Some(InconclusiveReason::NoRuleMatched)
                        }
                    };
                    responses.insert(primary.clone(), response);
                    if should_fallback {
                        if let Some(response) = self.execute_named(rule, fallback, username).await {
                            responses.insert(fallback.clone(), response);
                        }
                    }
                }
                responses
            }
        }
    }

    async fn execute_named(
        &self,
        rule: &CompiledSiteRule,
        probe_id: &str,
        username: &str,
    ) -> Option<ProbeResponse> {
        let index = rule.probe_index.get(probe_id)?;
        let probe = &rule.source.probes[*index];
        Some(self.probes.execute(rule, probe, username).await)
    }
}
