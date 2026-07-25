use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use chrono::{DateTime, Utc};
use schemars::schema_for;
use serde::Serialize;
use sha2::{Digest, Sha256};
use socialname_rule_compiler::CompiledSiteRule;
use url::Url;

use crate::{
    CANARY_MANIFEST_V1, CanaryManifestError, CanaryManifestErrors, CanaryManifestSource,
    NegativeAlphabet,
};

const MAX_SOURCE_BYTES: usize = 64 * 1_024;
const MAX_LINE_BYTES: usize = 8 * 1_024;
const MIN_POSITIVE_CANARIES: usize = 5;
const MAX_POSITIVE_CANARIES: usize = 32;
const MIN_NEGATIVE_CANARIES: usize = 5;
const MAX_NEGATIVE_CANARIES: usize = 32;
const MAX_ATTEMPTS_PER_CANDIDATE: usize = 10;
const MAX_GENERATED_USERNAME_BYTES: usize = 128;

#[derive(Clone, Debug)]
pub struct CompiledCanaryManifest {
    pub source: CanaryManifestSource,
    pub validated_rule_hash: String,
    pub manifest_hash: String,
    pub canonical_json: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
pub struct CanaryManifestCompiler;

impl CanaryManifestCompiler {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    pub fn compile_yaml_at(
        &self,
        source: &str,
        rule: &CompiledSiteRule,
        expected_file_stem: Option<&str>,
        validation_time: DateTime<Utc>,
    ) -> Result<CompiledCanaryManifest, CanaryManifestErrors> {
        validate_yaml_surface(source).map_err(CanaryManifestErrors::new)?;
        let parsed: CanaryManifestSource = serde_yaml_ng::from_str(source).map_err(|error| {
            CanaryManifestErrors::new(CanaryManifestError::InvalidYaml(error.to_string()))
        })?;
        self.compile_source_at(parsed, rule, expected_file_stem, validation_time)
    }

    pub fn compile_source_at(
        &self,
        source: CanaryManifestSource,
        rule: &CompiledSiteRule,
        expected_file_stem: Option<&str>,
        validation_time: DateTime<Utc>,
    ) -> Result<CompiledCanaryManifest, CanaryManifestErrors> {
        let mut errors = Vec::new();

        if source.schema != CANARY_MANIFEST_V1 {
            errors.push(CanaryManifestError::UnsupportedSchema(
                source.schema.clone(),
            ));
        }
        if source.site_id != rule.source.id {
            errors.push(CanaryManifestError::SiteMismatch {
                manifest: source.site_id.clone(),
                rule: rule.source.id.clone(),
            });
        }
        if let Some(expected) = expected_file_stem
            && expected != source.site_id
        {
            errors.push(CanaryManifestError::FilenameMismatch {
                expected: expected.to_owned(),
                actual: source.site_id.clone(),
            });
        }

        validate_validity(&source, validation_time, &mut errors);
        validate_positive_canaries(&source, rule, validation_time, &mut errors);
        validate_negative_generator(&source, rule, &mut errors);

        if !errors.is_empty() {
            return Err(CanaryManifestErrors(errors));
        }

        let canonical_json = canonical_json(&source).map_err(CanaryManifestErrors::new)?;
        let manifest_hash = sha256_hex(&canonical_json);
        Ok(CompiledCanaryManifest {
            source,
            validated_rule_hash: rule.rule_hash.clone(),
            manifest_hash,
            canonical_json,
        })
    }

    pub fn load_directory_at(
        &self,
        manifests_dir: &Path,
        rules: &[CompiledSiteRule],
        validation_time: DateTime<Utc>,
    ) -> Result<Vec<CompiledCanaryManifest>, CanaryManifestErrors> {
        let entries = fs::read_dir(manifests_dir).map_err(|error| {
            CanaryManifestErrors::new(CanaryManifestError::ReadManifest {
                path: manifests_dir.to_path_buf(),
                message: error.to_string(),
            })
        })?;
        let mut paths = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| {
                CanaryManifestErrors::new(CanaryManifestError::ReadManifest {
                    path: manifests_dir.to_path_buf(),
                    message: error.to_string(),
                })
            })?;
            let path = entry.path();
            if path
                .extension()
                .is_some_and(|extension| extension == "yaml")
            {
                paths.push(path);
            }
        }
        paths.sort();

        let rule_index: BTreeMap<_, _> = rules.iter().map(|rule| (rule.id(), rule)).collect();
        let mut manifests = Vec::new();
        let mut seen_sites = BTreeSet::new();
        let mut errors = Vec::new();

        for path in paths {
            let source_text = match fs::read_to_string(&path) {
                Ok(source) => source,
                Err(error) => {
                    errors.push(CanaryManifestError::ReadManifest {
                        path,
                        message: error.to_string(),
                    });
                    continue;
                }
            };
            if let Err(error) = validate_yaml_surface(&source_text) {
                errors.push(error);
                continue;
            }
            let source: CanaryManifestSource = match serde_yaml_ng::from_str(&source_text) {
                Ok(source) => source,
                Err(error) => {
                    errors.push(CanaryManifestError::InvalidYaml(error.to_string()));
                    continue;
                }
            };
            let Some(rule) = rule_index.get(source.site_id.as_str()) else {
                errors.push(CanaryManifestError::UnknownSite(source.site_id));
                continue;
            };
            if !seen_sites.insert(source.site_id.clone()) {
                errors.push(CanaryManifestError::DuplicateManifest(source.site_id));
                continue;
            }
            let expected_stem = path.file_stem().and_then(|value| value.to_str());
            match self.compile_source_at(source, rule, expected_stem, validation_time) {
                Ok(manifest) => manifests.push(manifest),
                Err(manifest_errors) => errors.extend(manifest_errors.0),
            }
        }

        if errors.is_empty() {
            manifests.sort_by(|left, right| left.source.site_id.cmp(&right.source.site_id));
            Ok(manifests)
        } else {
            Err(CanaryManifestErrors(errors))
        }
    }

    pub fn json_schema(&self) -> Result<String, CanaryManifestError> {
        serde_json::to_string_pretty(&schema_for!(CanaryManifestSource))
            .map_err(|error| CanaryManifestError::CanonicalSerialization(error.to_string()))
    }
}

fn validate_validity(
    source: &CanaryManifestSource,
    validation_time: DateTime<Utc>,
    errors: &mut Vec<CanaryManifestError>,
) {
    if source.issued_at > validation_time {
        errors.push(CanaryManifestError::IssuedInFuture);
    }
    if source.expires_at <= source.issued_at {
        errors.push(CanaryManifestError::InvalidValidityWindow);
    } else if source.expires_at <= validation_time {
        errors.push(CanaryManifestError::Expired);
    }
}

fn validate_positive_canaries(
    source: &CanaryManifestSource,
    rule: &CompiledSiteRule,
    validation_time: DateTime<Utc>,
    errors: &mut Vec<CanaryManifestError>,
) {
    if !(MIN_POSITIVE_CANARIES..=MAX_POSITIVE_CANARIES).contains(&source.positive.len()) {
        errors.push(CanaryManifestError::InvalidPositiveCount);
    }

    let mut ids = BTreeSet::new();
    let mut usernames = BTreeSet::new();
    for canary in &source.positive {
        if !valid_canary_id(&canary.id) {
            errors.push(CanaryManifestError::InvalidPositiveId(canary.id.clone()));
        } else if !ids.insert(canary.id.clone()) {
            errors.push(CanaryManifestError::DuplicatePositiveId(canary.id.clone()));
        }

        match rule.normalize_username(&canary.username) {
            None => errors.push(CanaryManifestError::InvalidPositiveUsername(
                canary.username.clone(),
            )),
            Some(normalized) if normalized != canary.username => {
                errors.push(CanaryManifestError::NonCanonicalPositiveUsername {
                    actual: canary.username.clone(),
                    expected: normalized,
                });
            }
            Some(normalized) if !usernames.insert(normalized.clone()) => {
                errors.push(CanaryManifestError::DuplicatePositiveUsername(normalized));
            }
            Some(_) => {}
        }

        if canary.reviewed_at > source.issued_at || canary.reviewed_at > validation_time {
            errors.push(CanaryManifestError::InvalidReviewTime(canary.id.clone()));
        }
        if !valid_evidence_url(&canary.evidence_url) {
            errors.push(CanaryManifestError::InvalidEvidenceUrl {
                id: canary.id.clone(),
                url: canary.evidence_url.clone(),
            });
        }
    }
}

fn validate_negative_generator(
    source: &CanaryManifestSource,
    rule: &CompiledSiteRule,
    errors: &mut Vec<CanaryManifestError>,
) {
    let generator = &source.negative.generator;
    let minimum_random_length = match generator.alphabet {
        NegativeAlphabet::LowercaseAlnum => 13,
        NegativeAlphabet::Lowercase => 14,
    };
    if generator.random_length < minimum_random_length
        || !(MIN_NEGATIVE_CANARIES..=MAX_NEGATIVE_CANARIES).contains(&generator.count)
        || !(1..=MAX_ATTEMPTS_PER_CANDIDATE).contains(&generator.attempts_per_candidate)
    {
        errors.push(CanaryManifestError::InvalidNegativeGenerator);
        return;
    }

    let alphabet_probe = match generator.alphabet {
        NegativeAlphabet::LowercaseAlnum => "a1b2c3d4e5f6g7h8i9j0",
        NegativeAlphabet::Lowercase => "abcdefghijklmnopqrstuvwxyz",
    };
    let mut candidate: String = alphabet_probe
        .chars()
        .cycle()
        .take(generator.random_length)
        .collect();
    candidate.push_str(&generator.suffix);
    if candidate.len() > MAX_GENERATED_USERNAME_BYTES
        || rule.normalize_username(&candidate).as_deref() != Some(candidate.as_str())
        || source
            .positive
            .iter()
            .any(|positive| positive.username == candidate)
    {
        errors.push(CanaryManifestError::InvalidNegativeGenerator);
    }
}

fn valid_canary_id(value: &str) -> bool {
    let mut characters = value.chars();
    !value.starts_with("generated-negative-")
        && matches!(characters.next(), Some('a'..='z'))
        && value.len() <= 64
        && characters.all(|character| matches!(character, 'a'..='z' | '0'..='9' | '-'))
}

fn valid_evidence_url(value: &str) -> bool {
    Url::parse(value).is_ok_and(|url| {
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
    })
}

fn validate_yaml_surface(source: &str) -> Result<(), CanaryManifestError> {
    if source.len() > MAX_SOURCE_BYTES {
        return Err(CanaryManifestError::SourceTooLarge {
            maximum: MAX_SOURCE_BYTES,
        });
    }
    for (index, line) in source.lines().enumerate() {
        let line_number = index + 1;
        if line.len() > MAX_LINE_BYTES {
            return Err(CanaryManifestError::LineTooLarge {
                line: line_number,
                maximum: MAX_LINE_BYTES,
            });
        }
        let indent = line
            .chars()
            .take_while(|character| *character == ' ')
            .count();
        if line.starts_with('\t') {
            return Err(CanaryManifestError::TabIndentation { line: line_number });
        }
        if indent > 64 {
            return Err(CanaryManifestError::NestingTooDeep { line: line_number });
        }
        if has_forbidden_yaml_token(line) {
            return Err(CanaryManifestError::ForbiddenYamlFeature { line: line_number });
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

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, CanaryManifestError> {
    serde_json::to_vec(value)
        .map_err(|error| CanaryManifestError::CanonicalSerialization(error.to_string()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use socialname_rule_compiler::RuleCompiler;

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
      allowed_hosts: [example.test]
      expected_body: json
plan:
  type: single
  probe: profile
classification:
  found:
    status:
      probe: profile
      in: [200]
  not_found:
    status:
      probe: profile
      in: [404]
metadata:
  enabled: false
"#;

    const VALID_MANIFEST: &str = r#"
schema: socialname.dev/canary-manifest/v1
site_id: example
issued_at: 2026-07-25T00:00:00Z
expires_at: 2026-08-01T00:00:00Z
positive:
  - id: platform
    username: alpha
    kind: platform_official
    reviewed_at: 2026-07-24T00:00:00Z
    evidence_url: https://example.test/u/alpha
  - id: project
    username: bravo
    kind: project_controlled
    reviewed_at: 2026-07-24T00:00:00Z
    evidence_url: https://example.test/u/bravo
  - id: stable-one
    username: charlie
    kind: long_lived_public
    reviewed_at: 2026-07-24T00:00:00Z
    evidence_url: https://example.test/u/charlie
  - id: stable-two
    username: delta
    kind: long_lived_public
    reviewed_at: 2026-07-24T00:00:00Z
    evidence_url: https://example.test/u/delta
  - id: stable-three
    username: echo
    kind: long_lived_public
    reviewed_at: 2026-07-24T00:00:00Z
    evidence_url: https://example.test/u/echo
negative:
  generator:
    alphabet: lowercase_alnum
    random_length: 20
    count: 5
    attempts_per_candidate: 3
"#;

    fn validation_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 25, 12, 0, 0)
            .single()
            .expect("test timestamp is valid")
    }

    fn rule() -> CompiledSiteRule {
        RuleCompiler::new()
            .compile_yaml(VALID_RULE, Some("example"))
            .expect("test rule compiles")
    }

    #[test]
    fn compiles_valid_manifest_deterministically() {
        let compiler = CanaryManifestCompiler::new();
        let first = compiler
            .compile_yaml_at(VALID_MANIFEST, &rule(), Some("example"), validation_time())
            .unwrap();
        let second = compiler
            .compile_yaml_at(VALID_MANIFEST, &rule(), Some("example"), validation_time())
            .unwrap();

        assert_eq!(first.manifest_hash, second.manifest_hash);
        assert_eq!(first.canonical_json, second.canonical_json);
    }

    #[test]
    fn rejects_duplicate_positive_identity() {
        let source = VALID_MANIFEST.replace("username: echo", "username: delta");
        let errors = CanaryManifestCompiler::new()
            .compile_yaml_at(&source, &rule(), Some("example"), validation_time())
            .unwrap_err();

        assert!(errors.0.iter().any(|error| {
            error == &CanaryManifestError::DuplicatePositiveUsername("delta".to_owned())
        }));
    }

    #[test]
    fn rejects_positive_id_reserved_for_generated_negatives() {
        let source = VALID_MANIFEST.replace("id: platform", "id: generated-negative-001");
        let errors = CanaryManifestCompiler::new()
            .compile_yaml_at(&source, &rule(), Some("example"), validation_time())
            .unwrap_err();

        assert!(errors.0.contains(&CanaryManifestError::InvalidPositiveId(
            "generated-negative-001".to_owned()
        )));
    }

    #[test]
    fn rejects_expired_manifest() {
        let after_expiry = Utc
            .with_ymd_and_hms(2026, 8, 2, 0, 0, 0)
            .single()
            .expect("test timestamp is valid");
        let errors = CanaryManifestCompiler::new()
            .compile_yaml_at(VALID_MANIFEST, &rule(), Some("example"), after_expiry)
            .unwrap_err();

        assert!(errors.0.contains(&CanaryManifestError::Expired));
    }

    #[test]
    fn rejects_policy_incompatible_positive() {
        let source = VALID_MANIFEST.replace("username: echo", "username: bad_name");
        let errors = CanaryManifestCompiler::new()
            .compile_yaml_at(&source, &rule(), Some("example"), validation_time())
            .unwrap_err();

        assert!(errors.0.iter().any(|error| {
            error == &CanaryManifestError::InvalidPositiveUsername("bad_name".to_owned())
        }));
    }

    #[test]
    fn rejects_low_entropy_negative_generator() {
        let source = VALID_MANIFEST.replace("random_length: 20", "random_length: 8");
        let errors = CanaryManifestCompiler::new()
            .compile_yaml_at(&source, &rule(), Some("example"), validation_time())
            .unwrap_err();

        assert!(
            errors
                .0
                .contains(&CanaryManifestError::InvalidNegativeGenerator)
        );
    }

    #[test]
    fn rejects_unknown_fields() {
        let source =
            VALID_MANIFEST.replace("site_id: example", "site_id: example\nunexpected: true");
        let errors = CanaryManifestCompiler::new()
            .compile_yaml_at(&source, &rule(), Some("example"), validation_time())
            .unwrap_err();

        assert!(
            errors
                .0
                .iter()
                .any(|error| matches!(error, CanaryManifestError::InvalidYaml(_)))
        );
    }
}
