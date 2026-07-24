#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use serde::Deserialize;
use socialname_domain::{EvidenceClass, InconclusiveReason, Verdict};
use socialname_engine::{ProbeResponse, classify};
use socialname_rule_compiler::CompiledSiteRule;

pub const FIXTURE_V1: &str = "socialname.dev/fixture/v1";

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SiteFixture {
    pub schema: String,
    pub site_id: String,
    pub cases: Vec<FixtureCase>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureCase {
    pub id: String,
    pub username: String,
    pub expected: Verdict,
    #[serde(default)]
    pub expected_reason: Option<InconclusiveReason>,
    #[serde(default)]
    pub minimum_evidence: EvidenceClass,
    pub responses: Vec<ProbeResponse>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixtureReport {
    pub sites: usize,
    pub cases: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum FixtureError {
    #[error("failed to read fixture {path}: {message}")]
    Read { path: PathBuf, message: String },
    #[error("invalid fixture YAML {path}: {message}")]
    Parse { path: PathBuf, message: String },
    #[error("fixture {path} uses unsupported schema {schema:?}")]
    Schema { path: PathBuf, schema: String },
    #[error("fixture filename {filename:?} does not match site_id {site_id:?}")]
    FilenameMismatch { filename: String, site_id: String },
    #[error("fixture references unknown site {0:?}")]
    UnknownSite(String),
    #[error("site {0:?} has no fixture")]
    MissingFixture(String),
    #[error("site {site_id:?} fixture case {case_id:?} has duplicate probe {probe_id:?}")]
    DuplicateProbe {
        site_id: String,
        case_id: String,
        probe_id: String,
    },
    #[error("site {site_id:?} fixture case {case_id:?}: expected {expected:?}, got {actual:?}")]
    Verdict {
        site_id: String,
        case_id: String,
        expected: Verdict,
        actual: Verdict,
    },
    #[error(
        "site {site_id:?} fixture case {case_id:?}: expected reason {expected:?}, got {actual:?}"
    )]
    Reason {
        site_id: String,
        case_id: String,
        expected: Option<InconclusiveReason>,
        actual: Option<InconclusiveReason>,
    },
    #[error(
        "site {site_id:?} fixture case {case_id:?}: expected at least {minimum:?}, got {actual:?}"
    )]
    Evidence {
        site_id: String,
        case_id: String,
        minimum: EvidenceClass,
        actual: EvidenceClass,
    },
    #[error("site {site_id:?} fixture is missing a {verdict:?} case")]
    MissingVerdict { site_id: String, verdict: Verdict },
    #[error("fixture directory contains no YAML files")]
    EmptyDirectory,
}

pub fn verify_fixtures(
    rules: &[CompiledSiteRule],
    directory: impl AsRef<Path>,
) -> Result<FixtureReport, Vec<FixtureError>> {
    let directory = directory.as_ref();
    let rule_map: BTreeMap<_, _> = rules
        .iter()
        .map(|rule| (rule.source.id.as_str(), rule))
        .collect();
    let mut paths = match fs::read_dir(directory) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "yaml")
            })
            .collect::<Vec<_>>(),
        Err(error) => {
            return Err(vec![FixtureError::Read {
                path: directory.to_path_buf(),
                message: error.to_string(),
            }]);
        }
    };
    paths.sort();
    if paths.is_empty() {
        return Err(vec![FixtureError::EmptyDirectory]);
    }

    let mut errors = Vec::new();
    let mut covered_sites = BTreeSet::new();
    let mut case_count = 0;
    for path in paths {
        let fixture = match load_fixture(&path) {
            Ok(fixture) => fixture,
            Err(error) => {
                errors.push(error);
                continue;
            }
        };
        let file_stem = path
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        if file_stem != fixture.site_id {
            errors.push(FixtureError::FilenameMismatch {
                filename: file_stem.to_owned(),
                site_id: fixture.site_id.clone(),
            });
            continue;
        }
        let Some(rule) = rule_map.get(fixture.site_id.as_str()).copied() else {
            errors.push(FixtureError::UnknownSite(fixture.site_id));
            continue;
        };
        covered_sites.insert(rule.source.id.clone());

        let mut verdicts = BTreeSet::new();
        for case in fixture.cases {
            case_count += 1;
            verdicts.insert(verdict_rank(case.expected));
            let mut responses = BTreeMap::new();
            for mut response in case.responses {
                if response.body_bytes == 0 {
                    response.body_bytes = response.body.len();
                }
                let probe_id = response.probe_id.clone();
                if responses.insert(probe_id.clone(), response).is_some() {
                    errors.push(FixtureError::DuplicateProbe {
                        site_id: fixture.site_id.clone(),
                        case_id: case.id.clone(),
                        probe_id,
                    });
                }
            }
            let classification = classify(rule, &case.username, &responses);
            if classification.verdict != case.expected {
                errors.push(FixtureError::Verdict {
                    site_id: fixture.site_id.clone(),
                    case_id: case.id.clone(),
                    expected: case.expected,
                    actual: classification.verdict,
                });
            }
            if classification.inconclusive_reason != case.expected_reason {
                errors.push(FixtureError::Reason {
                    site_id: fixture.site_id.clone(),
                    case_id: case.id.clone(),
                    expected: case.expected_reason,
                    actual: classification.inconclusive_reason,
                });
            }
            if classification.evidence_class < case.minimum_evidence {
                errors.push(FixtureError::Evidence {
                    site_id: fixture.site_id.clone(),
                    case_id: case.id,
                    minimum: case.minimum_evidence,
                    actual: classification.evidence_class,
                });
            }
        }
        for verdict in [Verdict::Found, Verdict::NotFound, Verdict::Inconclusive] {
            if !verdicts.contains(&verdict_rank(verdict)) {
                errors.push(FixtureError::MissingVerdict {
                    site_id: fixture.site_id.clone(),
                    verdict,
                });
            }
        }
    }

    for rule in rules {
        if !covered_sites.contains(&rule.source.id) {
            errors.push(FixtureError::MissingFixture(rule.source.id.clone()));
        }
    }

    if errors.is_empty() {
        Ok(FixtureReport {
            sites: covered_sites.len(),
            cases: case_count,
        })
    } else {
        Err(errors)
    }
}

fn load_fixture(path: &Path) -> Result<SiteFixture, FixtureError> {
    let source = fs::read_to_string(path).map_err(|error| FixtureError::Read {
        path: path.to_path_buf(),
        message: error.to_string(),
    })?;
    let fixture: SiteFixture =
        serde_yaml_ng::from_str(&source).map_err(|error| FixtureError::Parse {
            path: path.to_path_buf(),
            message: error.to_string(),
        })?;
    if fixture.schema != FIXTURE_V1 {
        return Err(FixtureError::Schema {
            path: path.to_path_buf(),
            schema: fixture.schema,
        });
    }
    Ok(fixture)
}

const fn verdict_rank(verdict: Verdict) -> u8 {
    match verdict {
        Verdict::Found => 0,
        Verdict::NotFound => 1,
        Verdict::InvalidUsername => 2,
        Verdict::Inconclusive => 3,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use socialname_rule_compiler::RuleCompiler;

    use super::*;

    #[test]
    fn representative_pack_fixtures_pass() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let rules = RuleCompiler::new()
            .load_directory(root.join("rules/sites"))
            .unwrap();
        let report = verify_fixtures(&rules, root.join("rules/fixtures")).unwrap();
        assert_eq!(report.sites, 10);
        assert!(report.cases >= 30);
    }
}
