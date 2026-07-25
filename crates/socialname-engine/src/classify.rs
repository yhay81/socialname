use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use socialname_domain::{EvidenceClass, InconclusiveReason, Verdict};
use socialname_rule_compiler::{CompiledSiteRule, render_identity_template};
use socialname_rule_schema::{
    BodyMatchOp, ConditionSource, JsonMatchOp, StringMatchOp, TransportOutcome,
};

use crate::{Classification, MatcherTrace, ProbeResponse};

pub fn classify(
    rule: &CompiledSiteRule,
    username: &str,
    responses: &BTreeMap<String, ProbeResponse>,
) -> Classification {
    let mut trace = Vec::new();

    if let Some(blocked) = &rule.source.classification.blocked {
        let outcome = evaluate(blocked, "blocked", rule, username, responses, &mut trace);
        if outcome.matched {
            return finish(
                Verdict::Inconclusive,
                Some(block_reason(responses)),
                EvidenceClass::E0NoAccountEvidence,
                trace,
                responses,
            );
        }
    }

    let found = evaluate(
        &rule.source.classification.found,
        "found",
        rule,
        username,
        responses,
        &mut trace,
    );
    let not_found = evaluate(
        &rule.source.classification.not_found,
        "not_found",
        rule,
        username,
        responses,
        &mut trace,
    );

    match (found.matched, not_found.matched) {
        (true, false) => finish(Verdict::Found, None, found.evidence, trace, responses),
        (false, true) => finish(
            Verdict::NotFound,
            None,
            not_found.evidence,
            trace,
            responses,
        ),
        (true, true) => finish(
            Verdict::Inconclusive,
            Some(InconclusiveReason::ConflictingEvidence),
            found.evidence.max(not_found.evidence),
            trace,
            responses,
        ),
        (false, false) => finish(
            Verdict::Inconclusive,
            Some(transport_or_no_match(responses)),
            EvidenceClass::E0NoAccountEvidence,
            trace,
            responses,
        ),
    }
}

#[derive(Clone, Copy, Debug)]
struct MatchOutcome {
    matched: bool,
    evidence: EvidenceClass,
}

fn evaluate(
    condition: &ConditionSource,
    path: &str,
    rule: &CompiledSiteRule,
    username: &str,
    responses: &BTreeMap<String, ProbeResponse>,
    trace: &mut Vec<MatcherTrace>,
) -> MatchOutcome {
    match condition {
        ConditionSource::All { all: children } => {
            let outcomes: Vec<_> = children
                .iter()
                .enumerate()
                .map(|(index, child)| {
                    evaluate(
                        child,
                        &format!("{path}.all[{index}]"),
                        rule,
                        username,
                        responses,
                        trace,
                    )
                })
                .collect();
            let matched = outcomes.iter().all(|outcome| outcome.matched);
            MatchOutcome {
                matched,
                evidence: if matched {
                    outcomes
                        .iter()
                        .map(|outcome| outcome.evidence)
                        .max()
                        .unwrap_or_default()
                } else {
                    EvidenceClass::default()
                },
            }
        }
        ConditionSource::Any { any: children } => {
            let outcomes: Vec<_> = children
                .iter()
                .enumerate()
                .map(|(index, child)| {
                    evaluate(
                        child,
                        &format!("{path}.any[{index}]"),
                        rule,
                        username,
                        responses,
                        trace,
                    )
                })
                .collect();
            let matched = outcomes.iter().any(|outcome| outcome.matched);
            MatchOutcome {
                matched,
                evidence: outcomes
                    .iter()
                    .filter(|outcome| outcome.matched)
                    .map(|outcome| outcome.evidence)
                    .max()
                    .unwrap_or_default(),
            }
        }
        ConditionSource::Not { not: child } => {
            let outcome = evaluate(
                child,
                &format!("{path}.not"),
                rule,
                username,
                responses,
                trace,
            );
            MatchOutcome {
                matched: !outcome.matched,
                evidence: outcome.evidence,
            }
        }
        ConditionSource::Status { status: matcher } => {
            let status = responses.get(&matcher.probe).and_then(|value| value.status);
            let matched = status.is_some_and(|value| matcher.statuses.contains(&value));
            push_trace(
                trace,
                path,
                matched,
                format!("status {status:?} in {:?}", matcher.statuses),
            );
            let evidence = if matched && matcher.statuses.contains(&404) {
                EvidenceClass::E3ExplicitEndpoint
            } else {
                EvidenceClass::E1WeakSignal
            };
            MatchOutcome { matched, evidence }
        }
        ConditionSource::FinalUrl { final_url: matcher } => {
            let actual = responses
                .get(&matcher.probe)
                .and_then(|value| value.final_url.as_deref())
                .unwrap_or_default();
            let matched = match_string(
                actual,
                matcher.op,
                &matcher.value,
                username,
                rule.source.username.case_sensitive,
                &rule.matcher_regexes,
            );
            push_trace(
                trace,
                path,
                matched,
                format!("final URL using {:?}", matcher.op),
            );
            MatchOutcome {
                matched,
                evidence: if matches!(
                    matcher.op,
                    StringMatchOp::Equals | StringMatchOp::EqualsTemplate
                ) {
                    EvidenceClass::E3ExplicitEndpoint
                } else {
                    EvidenceClass::E2DifferentialTemplate
                },
            }
        }
        ConditionSource::Header { header: matcher } => {
            let actual = responses
                .get(&matcher.probe)
                .and_then(|value| value.headers.get(&matcher.name.to_ascii_lowercase()))
                .map_or("", String::as_str);
            let matched = match_string(
                actual,
                matcher.op,
                &matcher.value,
                username,
                rule.source.username.case_sensitive,
                &rule.matcher_regexes,
            );
            push_trace(
                trace,
                path,
                matched,
                format!("header {} using {:?}", matcher.name, matcher.op),
            );
            MatchOutcome {
                matched,
                evidence: EvidenceClass::E2DifferentialTemplate,
            }
        }
        ConditionSource::Body { body: matcher } => {
            let body = responses
                .get(&matcher.probe)
                .map_or("", |value| value.body.as_str());
            let matched = match matcher.op {
                BodyMatchOp::Contains => body.contains(&matcher.value),
                BodyMatchOp::ContainsTemplate => render_identity_template(&matcher.value, username)
                    .is_ok_and(|expected| {
                        identity_contains(body, &expected, rule.source.username.case_sensitive)
                    }),
                BodyMatchOp::NotContains => !body.contains(&matcher.value),
                BodyMatchOp::Regex => rule
                    .matcher_regexes
                    .get(&matcher.value)
                    .is_some_and(|regex| regex.is_match(body)),
            };
            push_trace(trace, path, matched, format!("body using {:?}", matcher.op));
            MatchOutcome {
                matched,
                evidence: if matcher.op == BodyMatchOp::ContainsTemplate {
                    EvidenceClass::E3ExplicitEndpoint
                } else {
                    EvidenceClass::E2DifferentialTemplate
                },
            }
        }
        ConditionSource::Json { json: matcher } => {
            let json = responses
                .get(&matcher.probe)
                .and_then(|value| serde_json::from_str::<Value>(&value.body).ok());
            let selected = json.as_ref().and_then(|value| {
                if matcher.pointer.is_empty() {
                    Some(value)
                } else {
                    value.pointer(&matcher.pointer)
                }
            });
            let matched = match matcher.op {
                JsonMatchOp::Exists => selected.is_some(),
                JsonMatchOp::Absent => selected.is_none(),
                JsonMatchOp::Equals => selected == matcher.value.as_ref(),
                JsonMatchOp::EqualsTemplate => matcher.template.as_ref().is_some_and(|template| {
                    render_identity_template(template, username).is_ok_and(|expected| {
                        selected.and_then(Value::as_str).is_some_and(|actual| {
                            identity_equals(actual, &expected, rule.source.username.case_sensitive)
                        })
                    })
                }),
                JsonMatchOp::ArrayLength => {
                    selected.and_then(Value::as_array).map(Vec::len) == matcher.length
                }
            };
            push_trace(
                trace,
                path,
                matched,
                format!("JSON {} using {:?}", matcher.pointer, matcher.op),
            );
            MatchOutcome {
                matched,
                evidence: if matches!(
                    matcher.op,
                    JsonMatchOp::Equals | JsonMatchOp::EqualsTemplate | JsonMatchOp::ArrayLength
                ) {
                    EvidenceClass::E4StructuredIdentity
                } else {
                    EvidenceClass::E3ExplicitEndpoint
                },
            }
        }
        ConditionSource::BodyLength {
            body_length: matcher,
        } => {
            let length = responses
                .get(&matcher.probe)
                .map_or(0, |value| value.body_bytes);
            let matched = matcher.min.is_none_or(|minimum| length >= minimum)
                && matcher.max.is_none_or(|maximum| length <= maximum);
            push_trace(
                trace,
                path,
                matched,
                format!(
                    "body length {length} in {:?}..={:?}",
                    matcher.min, matcher.max
                ),
            );
            MatchOutcome {
                matched,
                evidence: EvidenceClass::E1WeakSignal,
            }
        }
        ConditionSource::Transport { transport: matcher } => {
            let actual = responses.get(&matcher.probe).map(|value| value.transport);
            let matched = actual.is_some_and(|value| matcher.outcomes.contains(&value));
            push_trace(
                trace,
                path,
                matched,
                format!("transport {actual:?} in {:?}", matcher.outcomes),
            );
            MatchOutcome {
                matched,
                evidence: EvidenceClass::E0NoAccountEvidence,
            }
        }
    }
}

fn match_string(
    actual: &str,
    operation: StringMatchOp,
    expected: &str,
    username: &str,
    case_sensitive: bool,
    regexes: &BTreeMap<String, regex::Regex>,
) -> bool {
    match operation {
        StringMatchOp::Equals => actual == expected,
        StringMatchOp::EqualsTemplate => render_identity_template(expected, username)
            .is_ok_and(|value| identity_equals(actual, &value, case_sensitive)),
        StringMatchOp::Contains => actual.contains(expected),
        StringMatchOp::ContainsTemplate => render_identity_template(expected, username)
            .is_ok_and(|value| identity_contains(actual, &value, case_sensitive)),
        StringMatchOp::Prefix => actual.starts_with(expected),
        StringMatchOp::Regex => regexes
            .get(expected)
            .is_some_and(|regex| regex.is_match(actual)),
    }
}

fn identity_equals(actual: &str, expected: &str, case_sensitive: bool) -> bool {
    if case_sensitive {
        actual == expected
    } else {
        actual.eq_ignore_ascii_case(expected)
    }
}

fn identity_contains(actual: &str, expected: &str, case_sensitive: bool) -> bool {
    if case_sensitive {
        actual.contains(expected)
    } else {
        actual
            .to_ascii_lowercase()
            .contains(&expected.to_ascii_lowercase())
    }
}

fn push_trace(trace: &mut Vec<MatcherTrace>, path: &str, matched: bool, detail: String) {
    trace.push(MatcherTrace {
        path: path.to_owned(),
        matched,
        detail,
    });
}

fn block_reason(responses: &BTreeMap<String, ProbeResponse>) -> InconclusiveReason {
    for response in responses.values() {
        match response.transport {
            TransportOutcome::RateLimited => return InconclusiveReason::RateLimited,
            TransportOutcome::Timeout => return InconclusiveReason::Timeout,
            TransportOutcome::Dns => return InconclusiveReason::Dns,
            TransportOutcome::Connect => return InconclusiveReason::Connect,
            TransportOutcome::Tls => return InconclusiveReason::Tls,
            TransportOutcome::RedirectRejected => {
                return InconclusiveReason::RedirectRejected;
            }
            TransportOutcome::ResponseTooLarge => {
                return InconclusiveReason::ResponseTooLarge;
            }
            TransportOutcome::Decode => return InconclusiveReason::Decode,
            TransportOutcome::Blocked | TransportOutcome::Completed => {}
        }
    }
    InconclusiveReason::Blocked
}

fn transport_or_no_match(responses: &BTreeMap<String, ProbeResponse>) -> InconclusiveReason {
    let reason = block_reason(responses);
    if reason == InconclusiveReason::Blocked
        && responses
            .values()
            .all(|response| response.transport == TransportOutcome::Completed)
    {
        InconclusiveReason::NoRuleMatched
    } else {
        reason
    }
}

fn finish(
    verdict: Verdict,
    inconclusive_reason: Option<InconclusiveReason>,
    evidence_class: EvidenceClass,
    matcher_trace: Vec<MatcherTrace>,
    responses: &BTreeMap<String, ProbeResponse>,
) -> Classification {
    Classification {
        verdict,
        inconclusive_reason,
        evidence_class,
        matcher_trace,
        evidence_digest: evidence_digest(responses),
    }
}

fn evidence_digest(responses: &BTreeMap<String, ProbeResponse>) -> String {
    #[derive(Serialize)]
    struct DigestEntry<'a> {
        probe_id: &'a str,
        transport: TransportOutcome,
        status: Option<u16>,
        final_url: Option<&'a str>,
        headers: &'a BTreeMap<String, String>,
        body_sha256: String,
        body_bytes: usize,
        body_truncated: bool,
    }

    let entries: Vec<_> = responses
        .values()
        .map(|response| DigestEntry {
            probe_id: &response.probe_id,
            transport: response.transport,
            status: response.status,
            final_url: response.final_url.as_deref(),
            headers: &response.headers,
            body_sha256: format!("{:x}", Sha256::digest(response.body.as_bytes())),
            body_bytes: response.body_bytes,
            body_truncated: response.body_truncated,
        })
        .collect();
    let bytes = serde_json::to_vec(&entries).unwrap_or_default();
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use socialname_rule_compiler::RuleCompiler;

    use super::*;

    const RULE: &str = r#"
schema: socialname.dev/site/v1
id: example
name: Example
homepage: https://example.test/
profile_url: https://example.test/u/{username:path}
namespace: person
username:
  pattern: '^[a-z][a-z0-9]{2,31}$'
  normalization: lowercase
probes:
  - id: api
    http:
      method: GET
      url: https://example.test/api/{username:path}
      allowed_hosts: [example.test]
      expected_body: json
      transport_profile: api_json
plan:
  type: single
  probe: api
classification:
  blocked:
    status:
      probe: api
      in: [403, 429]
  found:
    all:
      - status:
          probe: api
          in: [200]
      - json:
          probe: api
          pointer: /username
          op: equals_template
          template: '{username}'
  not_found:
    status:
      probe: api
      in: [404]
metadata:
  enabled: true
"#;

    fn response(status: u16, body: &str) -> BTreeMap<String, ProbeResponse> {
        BTreeMap::from([(
            "api".to_owned(),
            ProbeResponse {
                probe_id: "api".to_owned(),
                transport: TransportOutcome::Completed,
                status: Some(status),
                final_url: Some("https://example.test/api/alice".to_owned()),
                headers: BTreeMap::from([(
                    "content-type".to_owned(),
                    "application/json".to_owned(),
                )]),
                body: body.to_owned(),
                body_bytes: body.len(),
                body_truncated: false,
                elapsed_ms: 10,
            },
        )])
    }

    #[test]
    fn structured_identity_is_found() {
        let rule = RuleCompiler::new()
            .compile_yaml(RULE, Some("example"))
            .unwrap();
        let classification = classify(&rule, "alice", &response(200, r#"{"username":"alice"}"#));
        assert_eq!(classification.verdict, Verdict::Found);
        assert_eq!(
            classification.evidence_class,
            EvidenceClass::E4StructuredIdentity
        );
    }

    #[test]
    fn case_insensitive_identity_policy_applies_to_structured_matches() {
        let rule = RuleCompiler::new()
            .compile_yaml(RULE, Some("example"))
            .unwrap();
        let classification = classify(&rule, "ALICE", &response(200, r#"{"username":"alice"}"#));
        assert_eq!(classification.verdict, Verdict::Found);
    }

    #[test]
    fn block_never_becomes_not_found() {
        let rule = RuleCompiler::new()
            .compile_yaml(RULE, Some("example"))
            .unwrap();
        let classification = classify(&rule, "alice", &response(403, "<html>blocked</html>"));
        assert_eq!(classification.verdict, Verdict::Inconclusive);
        assert_eq!(
            classification.inconclusive_reason,
            Some(InconclusiveReason::Blocked)
        );
    }
}
