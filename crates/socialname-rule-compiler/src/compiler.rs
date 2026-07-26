use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::IpAddr,
    path::Path,
};

use regex::{Regex, RegexBuilder};
use schemars::schema_for;
use serde::Serialize;
use socialname_rule_schema::{
    BodyLengthCondition, BodyMatchOp, ConditionSource, HttpMethod, JsonCondition, JsonMatchOp,
    ProbePlanSource, SITE_RULE_V1, SiteRuleSource, StringMatchOp,
};
use url::Url;

use crate::{
    CompileError, CompileErrors,
    canonical::{canonical_json, sha256_hex},
    template::{validate_identity_template, validate_url_template},
};

const MAX_SOURCE_BYTES: usize = 64 * 1_024;
const MAX_LINE_BYTES: usize = 8 * 1_024;
const MAX_REGEX_BYTES: usize = 4 * 1_024;
const MAX_REGEX_COMPILED_BYTES: usize = 2 * 1_024 * 1_024;
const MAX_CONDITION_DEPTH: usize = 16;
const MAX_CONDITION_NODES: usize = 128;
const MAX_HEADER_BYTES: usize = 64 * 1_024;
const MAX_RESPONSE_BYTES: usize = 8 * 1_024 * 1_024;

#[derive(Clone, Debug)]
pub struct CompiledSiteRule {
    pub source: SiteRuleSource,
    pub rule_hash: String,
    pub canonical_json: Vec<u8>,
    pub username_regex: Regex,
    pub matcher_regexes: BTreeMap<String, Regex>,
    pub probe_index: BTreeMap<String, usize>,
}

impl CompiledSiteRule {
    #[must_use]
    pub fn id(&self) -> &str {
        &self.source.id
    }

    #[must_use]
    pub fn normalize_username(&self, username: &str) -> Option<String> {
        let normalized = match self.source.username.normalization {
            socialname_rule_schema::UsernameNormalization::Preserve => username.to_owned(),
            socialname_rule_schema::UsernameNormalization::Lowercase => username.to_lowercase(),
        };
        self.username_regex
            .is_match(&normalized)
            .then_some(normalized)
    }

    #[must_use]
    pub fn maximum_inspected_bytes_per_search(&self) -> usize {
        let probe_limit = |probe_id: &str| {
            self.probe_index
                .get(probe_id)
                .and_then(|index| self.source.probes.get(*index))
                .map_or(0, |probe| probe.http.limits.inspected_bytes)
        };
        match &self.source.plan {
            ProbePlanSource::Single { probe } => probe_limit(probe),
            ProbePlanSource::Fallback {
                primary, fallback, ..
            } => probe_limit(primary).saturating_add(probe_limit(fallback)),
            ProbePlanSource::ParallelAll { probes } => probes
                .iter()
                .map(|probe| probe_limit(probe))
                .fold(0_usize, usize::saturating_add),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct CompiledRulePack {
    pub schema: &'static str,
    pub rules: Vec<SiteRuleSource>,
    pub content_hash: String,
}

#[derive(Clone, Debug, Default)]
pub struct RuleCompiler;

impl RuleCompiler {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    pub fn compile_yaml(
        &self,
        source: &str,
        expected_file_stem: Option<&str>,
    ) -> Result<CompiledSiteRule, CompileErrors> {
        validate_yaml_surface(source).map_err(CompileErrors::new)?;
        let parsed: SiteRuleSource = serde_yaml_ng::from_str(source)
            .map_err(|error| CompileErrors::new(CompileError::InvalidYaml(error.to_string())))?;
        self.compile_source(parsed, expected_file_stem)
    }

    pub fn compile_source(
        &self,
        source: SiteRuleSource,
        expected_file_stem: Option<&str>,
    ) -> Result<CompiledSiteRule, CompileErrors> {
        let mut errors = Vec::new();

        if source.schema != SITE_RULE_V1 {
            errors.push(CompileError::UnsupportedSchema(source.schema.clone()));
        }
        if !valid_site_id(&source.id) {
            errors.push(CompileError::InvalidSiteId(source.id.clone()));
        }
        if let Some(expected) = expected_file_stem {
            if expected != source.id {
                errors.push(CompileError::FilenameMismatch {
                    expected: expected.to_owned(),
                    actual: source.id.clone(),
                });
            }
        }

        let username_regex =
            compile_regex(&source.username.pattern).map_err(CompileError::InvalidUsernameRegex);
        if let Err(error) = &username_regex {
            errors.push(error.clone());
        }

        validate_url_template(&source.homepage).unwrap_or_else(|error| errors.push(error));
        validate_url_template(&source.profile_url).unwrap_or_else(|error| errors.push(error));

        let mut probe_index = BTreeMap::new();
        for (index, probe) in source.probes.iter().enumerate() {
            if probe_index.insert(probe.id.clone(), index).is_some() {
                errors.push(CompileError::DuplicateProbe(probe.id.clone()));
            }
            validate_probe(probe, &mut errors);
        }

        validate_plan(&source.plan, &probe_index, &mut errors);

        let mut matcher_regexes = BTreeMap::new();
        let mut condition_nodes = 0;
        if let Some(blocked) = &source.classification.blocked {
            validate_condition(
                blocked,
                1,
                &mut condition_nodes,
                &probe_index,
                &mut matcher_regexes,
                &mut errors,
            );
        }
        validate_condition(
            &source.classification.found,
            1,
            &mut condition_nodes,
            &probe_index,
            &mut matcher_regexes,
            &mut errors,
        );
        validate_condition(
            &source.classification.not_found,
            1,
            &mut condition_nodes,
            &probe_index,
            &mut matcher_regexes,
            &mut errors,
        );
        if condition_nodes > MAX_CONDITION_NODES {
            errors.push(CompileError::ConditionTooComplex);
        }

        if !errors.is_empty() {
            return Err(CompileErrors(errors));
        }

        let canonical_json = canonical_json(&source).map_err(CompileErrors::new)?;
        let rule_hash = sha256_hex(&canonical_json);
        Ok(CompiledSiteRule {
            source,
            rule_hash,
            canonical_json,
            username_regex: username_regex.expect("validated above"),
            matcher_regexes,
            probe_index,
        })
    }

    pub fn load_directory(
        &self,
        directory: impl AsRef<Path>,
    ) -> Result<Vec<CompiledSiteRule>, CompileErrors> {
        let directory = directory.as_ref();
        let entries = fs::read_dir(directory).map_err(|error| {
            CompileErrors::new(CompileError::ReadRule {
                path: directory.to_path_buf(),
                message: error.to_string(),
            })
        })?;
        let mut paths: Vec<_> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "yaml")
            })
            .collect();
        paths.sort();
        if paths.is_empty() {
            return Err(CompileErrors::new(CompileError::EmptyRuleDirectory(
                directory.to_path_buf(),
            )));
        }

        let mut rules = Vec::with_capacity(paths.len());
        let mut errors = Vec::new();
        for path in paths {
            let source = match fs::read_to_string(&path) {
                Ok(source) => source,
                Err(error) => {
                    errors.push(CompileError::ReadRule {
                        path: path.clone(),
                        message: error.to_string(),
                    });
                    continue;
                }
            };
            let stem = path.file_stem().and_then(|value| value.to_str());
            match self.compile_yaml(&source, stem) {
                Ok(rule) => rules.push(rule),
                Err(rule_errors) => errors.extend(rule_errors.0),
            }
        }

        if errors.is_empty() {
            Ok(rules)
        } else {
            Err(CompileErrors(errors))
        }
    }

    pub fn compile_pack(
        &self,
        rules: &[CompiledSiteRule],
    ) -> Result<CompiledRulePack, CompileErrors> {
        let mut sorted: Vec<_> = rules.iter().map(|rule| rule.source.clone()).collect();
        sorted.sort_by(|left, right| left.id.cmp(&right.id));
        let bytes = canonical_json(&sorted).map_err(CompileErrors::new)?;
        Ok(CompiledRulePack {
            schema: "socialname.dev/rule-pack/v1",
            rules: sorted,
            content_hash: sha256_hex(&bytes),
        })
    }

    pub fn json_schema(&self) -> Result<String, CompileError> {
        serde_json::to_string_pretty(&schema_for!(SiteRuleSource))
            .map_err(|error| CompileError::CanonicalSerialization(error.to_string()))
    }
}

fn validate_yaml_surface(source: &str) -> Result<(), CompileError> {
    if source.len() > MAX_SOURCE_BYTES {
        return Err(CompileError::SourceTooLarge {
            maximum: MAX_SOURCE_BYTES,
        });
    }
    for (index, line) in source.lines().enumerate() {
        let line_number = index + 1;
        if line.len() > MAX_LINE_BYTES {
            return Err(CompileError::LineTooLarge {
                line: line_number,
                maximum: MAX_LINE_BYTES,
            });
        }
        let indent = line
            .chars()
            .take_while(|character| *character == ' ')
            .count();
        if line.starts_with('\t') {
            return Err(CompileError::TabIndentation { line: line_number });
        }
        if indent > 64 {
            return Err(CompileError::NestingTooDeep { line: line_number });
        }
        if has_forbidden_yaml_token(line) {
            return Err(CompileError::ForbiddenYamlFeature { line: line_number });
        }
    }
    Ok(())
}

fn has_forbidden_yaml_token(line: &str) -> bool {
    let mut single_quoted = false;
    let mut double_quoted = false;
    let mut escaped = false;
    let characters: Vec<_> = line.chars().collect();
    let mut index = 0;
    while index < characters.len() {
        let character = characters[index];
        if double_quoted && character == '\\' && !escaped {
            escaped = true;
            index += 1;
            continue;
        }
        if !double_quoted && character == '\'' {
            single_quoted = !single_quoted;
        } else if !single_quoted && character == '"' && !escaped {
            double_quoted = !double_quoted;
        } else if !single_quoted && !double_quoted {
            if character == '#' {
                break;
            }
            let boundary = index == 0
                || characters[index - 1].is_whitespace()
                || matches!(characters[index - 1], ':' | '-' | '[' | '{' | ',');
            let marker = matches!(character, '&' | '*' | '!');
            if boundary && marker {
                return true;
            }
            if character == '<'
                && characters.get(index + 1) == Some(&'<')
                && characters.get(index + 2) == Some(&':')
            {
                return true;
            }
        }
        escaped = false;
        index += 1;
    }
    false
}

fn valid_site_id(site_id: &str) -> bool {
    !site_id.is_empty()
        && site_id.len() <= 64
        && site_id.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'-' | b'_'))
        })
}

fn compile_regex(pattern: &str) -> Result<Regex, String> {
    if pattern.len() > MAX_REGEX_BYTES {
        return Err(format!("pattern exceeds {MAX_REGEX_BYTES} bytes"));
    }
    RegexBuilder::new(pattern)
        .size_limit(MAX_REGEX_COMPILED_BYTES)
        .build()
        .map_err(|error| error.to_string())
}

fn validate_probe(probe: &socialname_rule_schema::ProbeSource, errors: &mut Vec<CompileError>) {
    validate_url_template(&probe.http.url).unwrap_or_else(|error| errors.push(error));
    if probe.http.allowed_hosts.is_empty() {
        errors.push(CompileError::InvalidAllowedHost(String::new()));
    }

    let allowed_hosts: BTreeSet<_> = probe
        .http
        .allowed_hosts
        .iter()
        .map(|host| host.to_ascii_lowercase())
        .collect();
    for host in &probe.http.allowed_hosts {
        if !valid_allowed_host(host) {
            errors.push(CompileError::InvalidAllowedHost(host.clone()));
        }
    }

    let scrubbed = probe
        .http
        .url
        .replace("{username:path}", "socialname-probe")
        .replace("{username:query}", "socialname-probe")
        .replace("{username:subdomain}", "socialname-probe");
    if let Ok(url) = Url::parse(&scrubbed) {
        if let Some(host) = url.host_str() {
            if !allowed_hosts.contains(&host.to_ascii_lowercase()) {
                errors.push(CompileError::HostNotAllowed {
                    host: host.to_owned(),
                });
            }
        }
    }

    if !(0..=10).contains(&probe.http.redirects.max_hops) {
        errors.push(CompileError::InvalidRedirectHops);
    }
    let timeout = &probe.http.timeout;
    if timeout.dns_ms == 0
        || timeout.connect_ms == 0
        || timeout.first_byte_ms == 0
        || timeout.total_ms == 0
        || timeout.total_ms < timeout.connect_ms
        || timeout.total_ms < timeout.first_byte_ms
    {
        errors.push(CompileError::InvalidTimeout);
    }
    let limits = &probe.http.limits;
    if limits.header_bytes == 0
        || limits.compressed_bytes == 0
        || limits.decompressed_bytes == 0
        || limits.inspected_bytes == 0
        || limits.header_bytes > MAX_HEADER_BYTES
        || limits.compressed_bytes > MAX_RESPONSE_BYTES
        || limits.decompressed_bytes > MAX_RESPONSE_BYTES
        || limits.inspected_bytes > limits.decompressed_bytes
    {
        errors.push(CompileError::InvalidResponseLimits);
    }

    for name in probe.http.headers.keys() {
        let normalized = name.to_ascii_lowercase();
        if !matches!(
            normalized.as_str(),
            "accept" | "accept-language" | "content-type"
        ) {
            errors.push(CompileError::UnsafeRequestHeader(name.clone()));
        }
    }

    match (probe.http.method, probe.http.body.is_some()) {
        (HttpMethod::Post, false) => errors.push(CompileError::MissingPostBody),
        (HttpMethod::Get | HttpMethod::Head, true) => {
            errors.push(CompileError::BodyOnNonPost);
        }
        _ => {}
    }
}

fn valid_allowed_host(host: &str) -> bool {
    let host = host.trim().to_ascii_lowercase();
    !host.is_empty()
        && host.len() <= 253
        && host != "localhost"
        && !host.ends_with(".localhost")
        && host.parse::<IpAddr>().is_err()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn validate_plan(
    plan: &ProbePlanSource,
    probes: &BTreeMap<String, usize>,
    errors: &mut Vec<CompileError>,
) {
    let ids: Vec<&str> = match plan {
        ProbePlanSource::Single { probe } => vec![probe],
        ProbePlanSource::Fallback {
            primary, fallback, ..
        } => vec![primary, fallback],
        ProbePlanSource::ParallelAll { probes } => {
            if probes.is_empty() {
                errors.push(CompileError::EmptyProbePlan);
            }
            probes.iter().map(String::as_str).collect()
        }
    };
    for id in ids {
        if !probes.contains_key(id) {
            errors.push(CompileError::UnknownProbe(id.to_owned()));
        }
    }
}

fn validate_condition(
    condition: &ConditionSource,
    depth: usize,
    nodes: &mut usize,
    probes: &BTreeMap<String, usize>,
    regexes: &mut BTreeMap<String, Regex>,
    errors: &mut Vec<CompileError>,
) {
    *nodes += 1;
    if depth > MAX_CONDITION_DEPTH {
        errors.push(CompileError::ConditionTooComplex);
        return;
    }
    let probe_id = match condition {
        ConditionSource::All { all: children } => {
            if children.is_empty() {
                errors.push(CompileError::EmptyCondition("all"));
            }
            for child in children {
                validate_condition(child, depth + 1, nodes, probes, regexes, errors);
            }
            return;
        }
        ConditionSource::Any { any: children } => {
            if children.is_empty() {
                errors.push(CompileError::EmptyCondition("any"));
            }
            for child in children {
                validate_condition(child, depth + 1, nodes, probes, regexes, errors);
            }
            return;
        }
        ConditionSource::Not { not: child } => {
            validate_condition(child, depth + 1, nodes, probes, regexes, errors);
            return;
        }
        ConditionSource::Status { status: value } => {
            for status in &value.statuses {
                if !(100..=599).contains(status) {
                    errors.push(CompileError::InvalidStatus(*status));
                }
            }
            &value.probe
        }
        ConditionSource::FinalUrl { final_url: value } => {
            validate_string_match(value.op, &value.value, regexes, errors);
            &value.probe
        }
        ConditionSource::Header { header: value } => {
            validate_string_match(value.op, &value.value, regexes, errors);
            &value.probe
        }
        ConditionSource::Body { body: value } => {
            match value.op {
                BodyMatchOp::ContainsTemplate => {
                    validate_identity_template(&value.value)
                        .unwrap_or_else(|error| errors.push(error));
                }
                BodyMatchOp::Regex => compile_matcher_regex(&value.value, regexes, errors),
                BodyMatchOp::Contains | BodyMatchOp::NotContains => {}
            }
            &value.probe
        }
        ConditionSource::Json { json: value } => {
            validate_json_matcher(value, errors);
            &value.probe
        }
        ConditionSource::BodyLength { body_length: value } => {
            validate_body_length(value, errors);
            &value.probe
        }
        ConditionSource::Transport { transport: value } => &value.probe,
    };
    if !probes.contains_key(probe_id) {
        errors.push(CompileError::UnknownProbe(probe_id.clone()));
    }
}

fn validate_string_match(
    operation: StringMatchOp,
    value: &str,
    regexes: &mut BTreeMap<String, Regex>,
    errors: &mut Vec<CompileError>,
) {
    match operation {
        StringMatchOp::EqualsTemplate | StringMatchOp::ContainsTemplate => {
            validate_identity_template(value).unwrap_or_else(|error| errors.push(error));
        }
        StringMatchOp::Regex => compile_matcher_regex(value, regexes, errors),
        StringMatchOp::Equals | StringMatchOp::Contains | StringMatchOp::Prefix => {}
    }
}

fn compile_matcher_regex(
    pattern: &str,
    regexes: &mut BTreeMap<String, Regex>,
    errors: &mut Vec<CompileError>,
) {
    match compile_regex(pattern) {
        Ok(regex) => {
            regexes.insert(pattern.to_owned(), regex);
        }
        Err(message) => errors.push(CompileError::InvalidMatcherRegex {
            pattern: pattern.to_owned(),
            message,
        }),
    }
}

fn validate_json_matcher(value: &JsonCondition, errors: &mut Vec<CompileError>) {
    if !value.pointer.is_empty() && !value.pointer.starts_with('/') {
        errors.push(CompileError::InvalidJsonPointer(value.pointer.clone()));
    }
    let valid_fields = match value.op {
        JsonMatchOp::Exists | JsonMatchOp::Absent => {
            value.value.is_none() && value.template.is_none() && value.length.is_none()
        }
        JsonMatchOp::Equals => {
            value.value.is_some() && value.template.is_none() && value.length.is_none()
        }
        JsonMatchOp::EqualsTemplate => {
            value.value.is_none() && value.template.is_some() && value.length.is_none()
        }
        JsonMatchOp::ArrayLength => {
            value.value.is_none() && value.template.is_none() && value.length.is_some()
        }
    };
    if !valid_fields {
        errors.push(CompileError::InvalidJsonMatcher);
    }
    if let Some(template) = &value.template {
        validate_identity_template(template).unwrap_or_else(|error| errors.push(error));
    }
}

fn validate_body_length(value: &BodyLengthCondition, errors: &mut Vec<CompileError>) {
    if value.min.is_none() && value.max.is_none()
        || value
            .min
            .zip(value.max)
            .is_some_and(|(minimum, maximum)| minimum > maximum)
    {
        errors.push(CompileError::InvalidBodyLength);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_RULE: &str = r#"
schema: socialname.dev/site/v1
id: example
name: Example
homepage: https://example.test/
profile_url: https://example.test/u/{username:path}
namespace: person
username:
  pattern: '^[a-z][a-z0-9]{2,31}$'
  case_sensitive: false
  normalization: lowercase
probes:
  - id: profile
    http:
      method: GET
      url: https://example.test/u/{username:path}
      redirects:
        mode: follow
        max_hops: 2
      allowed_hosts: [example.test]
      expected_body: json
      transport_profile: api_json
plan:
  type: single
  probe: profile
classification:
  blocked:
    status:
      probe: profile
      in: [403, 429]
  found:
    all:
      - status:
          probe: profile
          in: [200]
      - json:
          probe: profile
          pointer: /username
          op: equals_template
          template: '{username}'
  not_found:
    status:
      probe: profile
      in: [404]
  otherwise: inconclusive
metadata:
  enabled: true
  tags: [test]
"#;

    #[test]
    fn compiles_valid_rule_deterministically() {
        let compiler = RuleCompiler::new();
        let first = compiler.compile_yaml(VALID_RULE, Some("example")).unwrap();
        let second = compiler.compile_yaml(VALID_RULE, Some("example")).unwrap();
        assert_eq!(first.rule_hash, second.rule_hash);
        assert_eq!(first.canonical_json, second.canonical_json);
    }

    #[test]
    fn rejects_unknown_fields() {
        let source = VALID_RULE.replace("name: Example", "name: Example\nunknown: true");
        let errors = RuleCompiler::new()
            .compile_yaml(&source, Some("example"))
            .unwrap_err();
        assert!(
            errors
                .0
                .iter()
                .any(|error| matches!(error, CompileError::InvalidYaml(_)))
        );
    }

    #[test]
    fn rejects_yaml_aliases() {
        let source = VALID_RULE.replace("tags: [test]", "tags: &shared [test]");
        let errors = RuleCompiler::new()
            .compile_yaml(&source, Some("example"))
            .unwrap_err();
        assert!(matches!(
            errors.0.as_slice(),
            [CompileError::ForbiddenYamlFeature { .. }]
        ));
    }

    #[test]
    fn rejects_unknown_probe_reference() {
        let source = VALID_RULE.replace(
            "probe: profile\n      in: [404]",
            "probe: missing\n      in: [404]",
        );
        let errors = RuleCompiler::new()
            .compile_yaml(&source, Some("example"))
            .unwrap_err();
        assert!(
            errors
                .0
                .iter()
                .any(|error| error == &CompileError::UnknownProbe("missing".to_owned()))
        );
    }
}
