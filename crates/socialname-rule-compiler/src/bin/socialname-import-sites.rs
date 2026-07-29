#![forbid(unsafe_code)]

//! Converts upstream Sherlock site definitions into Site Rule v1 sources.
//!
//! Sherlock (MIT, <https://github.com/sherlock-project/sherlock>) maintains a
//! large, actively curated set of username-check definitions in three closed
//! shapes: `status_code`, `message`, and `response_url`. All three are
//! expressible in Site Rule v1 without a schema change, so this importer gives
//! the pack broad coverage while the curated hand-authored rules keep their
//! stronger structured-identity evidence.
//!
//! Every imported rule is written `enabled: false`. Import is a coverage
//! claim, never a trust claim: promotion still requires the live canary gate.
//!
//! ```text
//! socialname-import-sites --input <data.json> --output-dir <dir> \
//!     [--curated-dir <dir>] [--dry-run]
//! ```
//!
//! Sites the importer cannot represent safely are skipped and reported rather
//! than emitted in a weakened form.

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::ExitCode,
};

use regex::RegexBuilder;
use serde::Deserialize;
use serde_json::Value;
use socialname_rule_schema::{
    AccountNamespace, BodyCondition, BodyMatchOp, BodyPolicy, ClassificationSource,
    ConditionSource, FinalUrlCondition, HttpMethod, HttpProbeSource, OtherwiseVerdict,
    ProbePlanSource, ProbeSource, RedirectMode, RedirectPolicySource, RequestBodySource,
    ResponseLimits, SITE_RULE_V1, SiteMetadata, SiteRuleSource, StatusCondition, StringMatchOp,
    TimeoutPolicy, TransportCondition, TransportOutcome, TransportProfile, UsernameNormalization,
    UsernamePolicy,
};

/// Usernames accepted when upstream declares no `regexCheck`, or declares one
/// this engine's bounded regular-expression syntax cannot represent.
const DEFAULT_USERNAME_PATTERN: &str = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$";
const PROBE_ID: &str = "profile";
const IMPORTED_TAG: &str = "imported";
/// How the `imported` tag appears in emitted YAML, used to recognize a prior
/// run's output.
const IMPORTED_TAG_LINE: &str = "- imported";
/// The only request headers Site Rule v1 accepts. Upstream also sets `Cookie`,
/// `User-Agent`, `Host`, and `Sec-Fetch-Mode` on a few sites; those are
/// dropped rather than smuggled through, and the affected sites are reported.
const SAFE_HEADERS: [&str; 3] = ["accept", "accept-language", "content-type"];
const BLOCKED_STATUSES: [u16; 2] = [403, 429];
const BLOCKED_TRANSPORTS: [TransportOutcome; 9] = [
    TransportOutcome::Blocked,
    TransportOutcome::RateLimited,
    TransportOutcome::Timeout,
    TransportOutcome::Dns,
    TransportOutcome::Connect,
    TransportOutcome::Tls,
    TransportOutcome::RedirectRejected,
    TransportOutcome::ResponseTooLarge,
    TransportOutcome::Decode,
];

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

#[derive(Debug, Deserialize)]
struct SherlockSite {
    url: String,
    #[serde(rename = "urlMain")]
    url_main: String,
    #[serde(rename = "urlProbe")]
    url_probe: Option<String>,
    #[serde(rename = "errorType")]
    error_type: String,
    #[serde(rename = "errorMsg")]
    error_message: Option<OneOrMany<String>>,
    #[serde(rename = "errorUrl")]
    error_url: Option<String>,
    #[serde(rename = "errorCode")]
    error_code: Option<OneOrMany<u16>>,
    #[serde(rename = "regexCheck")]
    regex_check: Option<String>,
    #[serde(rename = "request_method")]
    request_method: Option<String>,
    #[serde(rename = "request_payload")]
    request_payload: Option<Value>,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(rename = "isNSFW", default)]
    is_nsfw: bool,
    #[serde(rename = "username_claimed")]
    username_claimed: Option<String>,
}

fn main() -> ExitCode {
    match run(env::args_os().skip(1).collect()) {
        Ok(report) => {
            report.print();
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("import_error={message}");
            ExitCode::FAILURE
        }
    }
}

#[derive(Default)]
struct Report {
    written: usize,
    skipped_curated: Vec<String>,
    skipped_insecure: Vec<String>,
    skipped_unsupported: Vec<(String, String)>,
    relaxed_username: Vec<String>,
    dropped_headers: Vec<String>,
    nsfw: usize,
    pruned: usize,
    dry_run: bool,
}

impl Report {
    fn print(&self) {
        if self.dry_run {
            println!("mode=dry_run");
        }
        println!("written={}", self.written);
        println!("skipped_curated={}", self.skipped_curated.len());
        println!("skipped_insecure={}", self.skipped_insecure.len());
        println!("skipped_unsupported={}", self.skipped_unsupported.len());
        println!("relaxed_username_pattern={}", self.relaxed_username.len());
        println!("dropped_unsafe_headers={}", self.dropped_headers.len());
        println!("nsfw_tagged={}", self.nsfw);
        println!("pruned_stale={}", self.pruned);
        for (site, reason) in &self.skipped_unsupported {
            println!("unsupported site={site} reason={reason}");
        }
        for site in &self.skipped_insecure {
            println!("insecure site={site}");
        }
        for site in &self.dropped_headers {
            println!("dropped_headers site={site}");
        }
    }
}

fn run(arguments: Vec<OsString>) -> Result<Report, String> {
    let options = Options::parse(arguments)?;
    let raw = fs::read_to_string(&options.input)
        .map_err(|error| format!("cannot read {}: {error}", options.input.display()))?;
    let sites: BTreeMap<String, Value> =
        serde_json::from_str(&raw).map_err(|error| format!("invalid input JSON: {error}"))?;

    let curated = curated_ids(options.curated_directory.as_deref())?;
    if !options.dry_run {
        fs::create_dir_all(&options.output_directory)
            .map_err(|error| format!("cannot create output directory: {error}"))?;
    }

    let mut report = Report {
        dry_run: options.dry_run,
        ..Report::default()
    };
    let mut used_ids = curated.clone();
    let mut written_ids = BTreeSet::new();

    for (name, raw_site) in sites {
        if name.starts_with('$') {
            continue;
        }
        let site: SherlockSite = match serde_json::from_value(raw_site) {
            Ok(site) => site,
            Err(error) => {
                report
                    .skipped_unsupported
                    .push((name, format!("unreadable definition: {error}")));
                continue;
            }
        };

        let Some(base_id) = slug(&name) else {
            report
                .skipped_unsupported
                .push((name, "no valid site ID could be derived".to_owned()));
            continue;
        };
        // A hand-authored rule always wins: it carries stronger structured
        // evidence than anything this importer can derive.
        if curated.contains(&base_id) {
            report.skipped_curated.push(base_id);
            continue;
        }
        let Some(id) = unique_site_id(&base_id, &used_ids) else {
            report
                .skipped_unsupported
                .push((name, "site ID collides beyond the retry bound".to_owned()));
            continue;
        };

        match build_rule(&id, &name, &site, &mut report) {
            Ok(rule) => {
                // A rule without a fixture cannot pass the repository gate, so
                // both artifacts are emitted together or neither is.
                let fixture = match build_fixture(&id, &rule, &site) {
                    Ok(fixture) => fixture,
                    Err(SkipReason::Unsupported(reason)) => {
                        report.skipped_unsupported.push((name, reason));
                        continue;
                    }
                    Err(SkipReason::Insecure) => {
                        report.skipped_insecure.push(name);
                        continue;
                    }
                };
                let yaml = serde_yaml_ng::to_string(&rule)
                    .map_err(|error| format!("cannot serialize {id}: {error}"))?;
                let yaml = quote_unsafe_scalars(&yaml);
                let fixture_yaml = serde_yaml_ng::to_string(&fixture)
                    .map_err(|error| format!("cannot serialize fixture {id}: {error}"))?;
                let fixture_yaml = quote_unsafe_scalars(&fixture_yaml);
                if !options.dry_run {
                    let path = options.output_directory.join(format!("{id}.yaml"));
                    fs::write(&path, yaml)
                        .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
                    if let Some(fixture_directory) = &options.fixture_directory {
                        let path = fixture_directory.join(format!("{id}.yaml"));
                        fs::write(&path, fixture_yaml)
                            .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
                    }
                }
                if site.is_nsfw {
                    report.nsfw += 1;
                }
                used_ids.insert(id.clone());
                written_ids.insert(id);
                report.written += 1;
            }
            Err(SkipReason::Insecure) => report.skipped_insecure.push(name),
            Err(SkipReason::Unsupported(reason)) => {
                report.skipped_unsupported.push((name, reason));
            }
        }
    }

    // A site upstream dropped, or one this run can no longer represent, must
    // not linger as a stale rule with no fixture behind it.
    if !options.dry_run {
        report.pruned = prune_stale_output(
            &options.output_directory,
            options.fixture_directory.as_deref(),
            &written_ids,
            &curated,
        )?;
    }

    Ok(report)
}

/// Deletes importer-generated rules that this run did not produce, together
/// with their fixtures. Hand-authored rules are never touched.
fn prune_stale_output(
    output_directory: &Path,
    fixture_directory: Option<&Path>,
    written_ids: &BTreeSet<String>,
    curated: &BTreeSet<String>,
) -> Result<usize, String> {
    let entries = fs::read_dir(output_directory)
        .map_err(|error| format!("cannot read {}: {error}", output_directory.display()))?;
    let mut pruned = 0;
    for entry in entries {
        let entry = entry.map_err(|error| format!("cannot read directory entry: {error}"))?;
        let path = entry.path();
        if !path
            .extension()
            .is_some_and(|extension| extension == "yaml")
        {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };
        if written_ids.contains(stem) || curated.contains(stem) {
            continue;
        }
        let content = fs::read_to_string(&path)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        if !is_importer_output(&content) {
            continue;
        }
        fs::remove_file(&path)
            .map_err(|error| format!("cannot remove {}: {error}", path.display()))?;
        if let Some(fixture_directory) = fixture_directory {
            let fixture = fixture_directory.join(format!("{stem}.yaml"));
            if fixture.exists() {
                fs::remove_file(&fixture)
                    .map_err(|error| format!("cannot remove {}: {error}", fixture.display()))?;
            }
        }
        pruned += 1;
    }
    Ok(pruned)
}

#[derive(Debug)]
enum SkipReason {
    Insecure,
    Unsupported(String),
}

/// A `socialname.dev/fixture/v1` document.
///
/// These cases are **synthetic**: they are derived from the upstream check the
/// rule was built from, not recorded from a live site. They therefore prove
/// that the compiled classification tree is coherent — that `found`,
/// `not_found`, and the blocked path are each reachable and mutually
/// exclusive — and deliberately prove nothing about how the site actually
/// behaves. Establishing that remains the live canary gate's job.
#[derive(Debug, serde::Serialize)]
struct FixtureFile {
    schema: String,
    site_id: String,
    cases: Vec<FixtureCase>,
}

#[derive(Debug, serde::Serialize)]
struct FixtureCase {
    id: String,
    username: String,
    expected: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_reason: Option<&'static str>,
    responses: Vec<FixtureResponse>,
}

#[derive(Debug, serde::Serialize)]
struct FixtureResponse {
    probe_id: String,
    transport: &'static str,
    status: u16,
    final_url: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    body: String,
}

const FIXTURE_V1: &str = "socialname.dev/fixture/v1";
/// A body for the `found` case of a message check: it must not contain the
/// upstream absence marker.
const PRESENT_BODY: &str = "<html><body>socialname fixture: account page</body></html>";
const NEGATIVE_BASES: [&str; 2] = [
    "snv1probe9f4d2c7b6a1e0000000000",
    "snvprobezqjxkvwmbtlfdghyrcpaeo",
];

fn build_fixture(
    id: &str,
    rule: &SiteRuleSource,
    site: &SherlockSite,
) -> Result<FixtureFile, SkipReason> {
    let pattern = RegexBuilder::new(&rule.username.pattern)
        .size_limit(2 * 1_024 * 1_024)
        .build()
        .map_err(|error| SkipReason::Unsupported(format!("username pattern: {error}")))?;
    let probe = &rule.probes[0];
    let present_username = acceptable_username(&pattern, site.username_claimed.as_deref());
    let absent_username = acceptable_username(&pattern, None);

    let present_url = render(&probe.http.url, &present_username);
    let absent_url = render(&probe.http.url, &absent_username);

    let (present, absent) = match site.error_type.as_str() {
        "status_code" => {
            let statuses = site
                .error_code
                .as_ref()
                .map_or_else(|| vec![404], clone_one_or_many);
            // A rule whose absence status is also its blocked status could
            // never produce `not_found`; refuse it instead of emitting a
            // fixture that contradicts the rule.
            let absent_status = statuses
                .into_iter()
                .find(|status| !BLOCKED_STATUSES.contains(status))
                .ok_or_else(|| {
                    SkipReason::Unsupported(
                        "absence status collides with the blocked statuses".to_owned(),
                    )
                })?;
            (
                (200, present_url.clone(), String::new()),
                (absent_status, absent_url.clone(), String::new()),
            )
        }
        "message" => {
            let messages = site
                .error_message
                .as_ref()
                .map(clone_one_or_many)
                .unwrap_or_default();
            let marker = messages.first().cloned().ok_or_else(|| {
                SkipReason::Unsupported("message check without errorMsg".to_owned())
            })?;
            if messages
                .iter()
                .any(|message| PRESENT_BODY.contains(message.as_str()))
            {
                return Err(SkipReason::Unsupported(
                    "absence marker also appears in a present page".to_owned(),
                ));
            }
            (
                (200, present_url.clone(), PRESENT_BODY.to_owned()),
                (200, absent_url.clone(), marker),
            )
        }
        "response_url" => {
            let error_url = site.error_url.clone().ok_or_else(|| {
                SkipReason::Unsupported("response_url check without errorUrl".to_owned())
            })?;
            if present_url.starts_with(&error_url) {
                return Err(SkipReason::Unsupported(
                    "present URL already matches the absence URL".to_owned(),
                ));
            }
            (
                (200, present_url.clone(), String::new()),
                (200, error_url, String::new()),
            )
        }
        other => {
            return Err(SkipReason::Unsupported(format!(
                "unsupported errorType {other}"
            )));
        }
    };

    let case = |case_id: &str,
                username: &str,
                expected: &'static str,
                expected_reason: Option<&'static str>,
                (status, final_url, body): (u16, String, String)| FixtureCase {
        id: case_id.to_owned(),
        username: username.to_owned(),
        expected,
        expected_reason,
        responses: vec![FixtureResponse {
            probe_id: probe.id.clone(),
            transport: "completed",
            status,
            final_url,
            body,
        }],
    };

    Ok(FixtureFile {
        schema: FIXTURE_V1.to_owned(),
        site_id: id.to_owned(),
        cases: vec![
            case(
                "declared-present",
                &present_username,
                "found",
                None,
                present,
            ),
            case(
                "declared-absent",
                &absent_username,
                "not_found",
                None,
                absent,
            ),
            case(
                "access-blocked",
                &present_username,
                "inconclusive",
                Some("blocked"),
                (403, present_url, String::new()),
            ),
        ],
    })
}

/// Picks a username the rule's own policy accepts, preferring the upstream
/// claimed account so the present case stays recognizable.
fn acceptable_username(pattern: &regex::Regex, preferred: Option<&str>) -> String {
    if let Some(preferred) = preferred
        && pattern.is_match(preferred)
    {
        return preferred.to_owned();
    }
    for base in NEGATIVE_BASES {
        for length in (1..=base.len()).rev() {
            let candidate = &base[..length];
            if pattern.is_match(candidate) {
                return candidate.to_owned();
            }
        }
    }
    NEGATIVE_BASES[0].to_owned()
}

fn render(template: &str, username: &str) -> String {
    template
        .replace("{username:path}", username)
        .replace("{username:query}", username)
        .replace("{username:subdomain}", username)
}

fn build_rule(
    id: &str,
    name: &str,
    site: &SherlockSite,
    report: &mut Report,
) -> Result<SiteRuleSource, SkipReason> {
    let probe_target = site.url_probe.as_deref().unwrap_or(&site.url);
    for candidate in [probe_target, site.url.as_str(), site.url_main.as_str()] {
        if candidate.starts_with("http://") {
            return Err(SkipReason::Insecure);
        }
    }

    let probe_url = url_template(probe_target)?;
    let profile_url = url_template(&site.url)?;

    let mut allowed_hosts = BTreeSet::new();
    allowed_hosts.extend(probe_hosts(probe_target)?);
    if let Some(error_url) = &site.error_url {
        allowed_hosts.extend(probe_hosts(error_url)?);
    }

    let method = match site.request_method.as_deref() {
        None | Some("GET") => HttpMethod::Get,
        Some("HEAD") => HttpMethod::Head,
        Some("POST") => HttpMethod::Post,
        Some(other) => {
            return Err(SkipReason::Unsupported(format!(
                "unsupported request method {other}"
            )));
        }
    };
    let body = match (method, &site.request_payload) {
        (HttpMethod::Post, Some(payload)) => Some(RequestBodySource::Json {
            value: payload.clone(),
        }),
        (HttpMethod::Post, None) => {
            return Err(SkipReason::Unsupported(
                "POST without a typed request body".to_owned(),
            ));
        }
        (_, Some(_)) => {
            return Err(SkipReason::Unsupported(
                "request body declared for a non-POST method".to_owned(),
            ));
        }
        (_, None) => None,
    };

    let mut headers = BTreeMap::new();
    let mut dropped_any = false;
    for (header, value) in &site.headers {
        if SAFE_HEADERS.contains(&header.to_ascii_lowercase().as_str()) {
            headers.insert(header.clone(), value.clone());
        } else {
            dropped_any = true;
        }
    }
    if dropped_any {
        report.dropped_headers.push(name.to_owned());
    }

    let username = username_policy(site.regex_check.as_deref(), name, report);
    let classification = classification(site)?;
    // `response_url` needs the post-redirect location, so those rules follow
    // redirects within the hosts the rule itself declares.
    let redirects = if site.error_type == "response_url" {
        RedirectPolicySource {
            mode: RedirectMode::Follow,
            max_hops: 3,
        }
    } else {
        RedirectPolicySource {
            mode: RedirectMode::SameSite,
            max_hops: 2,
        }
    };
    // Only `message` rules inspect the body; the rest never read one.
    let expected_body = if site.error_type == "message" {
        BodyPolicy::BoundedText
    } else {
        BodyPolicy::None
    };

    let tags = vec![
        IMPORTED_TAG.to_owned(),
        format!("check-{}", site.error_type.replace('_', "-")),
    ];

    Ok(SiteRuleSource {
        schema: SITE_RULE_V1.to_owned(),
        id: id.to_owned(),
        name: name.to_owned(),
        homepage: site.url_main.clone(),
        profile_url,
        namespace: AccountNamespace::Person,
        username,
        probes: vec![ProbeSource {
            id: PROBE_ID.to_owned(),
            http: HttpProbeSource {
                method,
                url: probe_url,
                redirects,
                timeout: TimeoutPolicy::default(),
                allowed_hosts: allowed_hosts.into_iter().collect(),
                headers,
                body,
                expected_body,
                limits: ResponseLimits::default(),
                transport_profile: TransportProfile::BrowserLike,
            },
        }],
        plan: ProbePlanSource::Single {
            probe: PROBE_ID.to_owned(),
        },
        classification,
        metadata: SiteMetadata {
            enabled: false,
            enabled_regions: Vec::new(),
            tags,
            adult: site.is_nsfw,
            notes: format!(
                "Imported from the Sherlock project (MIT) using its {} check. \
                 Discovery-only until the live canary gate passes.",
                site.error_type
            ),
        },
    })
}

fn classification(site: &SherlockSite) -> Result<ClassificationSource, SkipReason> {
    let blocked = Some(ConditionSource::Any {
        any: vec![
            ConditionSource::Status {
                status: StatusCondition {
                    probe: PROBE_ID.to_owned(),
                    statuses: BLOCKED_STATUSES.to_vec(),
                },
            },
            ConditionSource::Transport {
                transport: TransportCondition {
                    probe: PROBE_ID.to_owned(),
                    outcomes: BLOCKED_TRANSPORTS.to_vec(),
                },
            },
        ],
    });
    let found_status = ConditionSource::Status {
        status: StatusCondition {
            probe: PROBE_ID.to_owned(),
            statuses: vec![200],
        },
    };

    let (found, not_found) = match site.error_type.as_str() {
        "status_code" => {
            let statuses = site
                .error_code
                .as_ref()
                .map_or_else(|| vec![404], clone_one_or_many);
            (
                found_status,
                ConditionSource::Status {
                    status: StatusCondition {
                        probe: PROBE_ID.to_owned(),
                        statuses,
                    },
                },
            )
        }
        "message" => {
            let messages = site
                .error_message
                .as_ref()
                .map(clone_one_or_many)
                .filter(|messages| !messages.is_empty())
                .ok_or_else(|| {
                    SkipReason::Unsupported("message check without errorMsg".to_owned())
                })?;
            let absent = any_of(
                messages
                    .into_iter()
                    .map(|message| ConditionSource::Body {
                        body: BodyCondition {
                            probe: PROBE_ID.to_owned(),
                            op: BodyMatchOp::Contains,
                            value: message,
                        },
                    })
                    .collect(),
            );
            (
                ConditionSource::All {
                    all: vec![
                        found_status,
                        ConditionSource::Not {
                            not: Box::new(absent.clone()),
                        },
                    ],
                },
                absent,
            )
        }
        "response_url" => {
            let error_url = site.error_url.clone().ok_or_else(|| {
                SkipReason::Unsupported("response_url check without errorUrl".to_owned())
            })?;
            let redirected = ConditionSource::FinalUrl {
                final_url: FinalUrlCondition {
                    probe: PROBE_ID.to_owned(),
                    op: StringMatchOp::Prefix,
                    value: error_url,
                },
            };
            (
                ConditionSource::All {
                    all: vec![
                        found_status,
                        ConditionSource::Not {
                            not: Box::new(redirected.clone()),
                        },
                    ],
                },
                redirected,
            )
        }
        other => {
            return Err(SkipReason::Unsupported(format!(
                "unsupported errorType {other}"
            )));
        }
    };

    Ok(ClassificationSource {
        blocked,
        found,
        not_found,
        otherwise: OtherwiseVerdict::Inconclusive,
    })
}

fn any_of(mut conditions: Vec<ConditionSource>) -> ConditionSource {
    if conditions.len() == 1 {
        conditions.remove(0)
    } else {
        ConditionSource::Any { any: conditions }
    }
}

fn clone_one_or_many<T: Clone>(value: &OneOrMany<T>) -> Vec<T> {
    match value {
        OneOrMany::One(single) => vec![single.clone()],
        OneOrMany::Many(many) => many.clone(),
    }
}

fn username_policy(regex_check: Option<&str>, name: &str, report: &mut Report) -> UsernamePolicy {
    let pattern = match regex_check {
        Some(pattern) if compiles(pattern) => pattern.to_owned(),
        Some(_) => {
            // Upstream uses Python lookaround and back-references the bounded
            // engine deliberately does not support.
            report.relaxed_username.push(name.to_owned());
            DEFAULT_USERNAME_PATTERN.to_owned()
        }
        None => DEFAULT_USERNAME_PATTERN.to_owned(),
    };
    UsernamePolicy {
        pattern,
        case_sensitive: false,
        normalization: UsernameNormalization::Preserve,
    }
}

fn compiles(pattern: &str) -> bool {
    RegexBuilder::new(pattern)
        .size_limit(2 * 1_024 * 1_024)
        .build()
        .is_ok()
}

/// Rewrites Sherlock's positional `{}` into a context-tagged Site Rule v1
/// placeholder, so a username can never escape the URL component it belongs
/// to.
fn url_template(raw: &str) -> Result<String, SkipReason> {
    if raw.matches("{}").count() != 1 {
        return Err(SkipReason::Unsupported(
            "URL must contain exactly one username placeholder".to_owned(),
        ));
    }
    let placeholder_index = raw.find("{}").expect("checked above");
    let scheme_end = raw
        .find("://")
        .ok_or_else(|| SkipReason::Unsupported("URL has no scheme".to_owned()))?
        + 3;
    let authority_end = raw[scheme_end..]
        .find('/')
        .map_or(raw.len(), |offset| scheme_end + offset);
    let query_start = raw.find('?').unwrap_or(usize::MAX);

    let context = if placeholder_index < authority_end {
        "subdomain"
    } else if placeholder_index > query_start {
        "query"
    } else {
        "path"
    };
    Ok(raw.replacen("{}", &format!("{{username:{context}}}"), 1))
}

/// The hosts a probe URL may reach.
///
/// When the username renders into the authority, the reachable set is every
/// single-label child of the fixed parent, so the rule declares that parent as
/// a wildcard. The parent itself is included because sites of this shape
/// commonly redirect an absent account to their apex.
fn probe_hosts(raw: &str) -> Result<Vec<String>, SkipReason> {
    let authority = authority_of(raw)?;
    let Some((_, parent)) = authority.split_once('.') else {
        return Err(SkipReason::Unsupported(format!(
            "cannot determine a fixed host from {raw}"
        )));
    };
    if !authority.contains("{}") {
        return Ok(vec![authority]);
    }
    // Only a leading placeholder label is representable: anything else would
    // render a host the parent cannot bound.
    if !authority.starts_with("{}.") || parent.contains("{}") {
        return Err(SkipReason::Unsupported(format!(
            "username is not a single leading subdomain label in {raw}"
        )));
    }
    Ok(vec![format!("*.{parent}"), parent.to_owned()])
}

fn authority_of(raw: &str) -> Result<String, SkipReason> {
    let scheme_end = raw
        .find("://")
        .ok_or_else(|| SkipReason::Unsupported("URL has no scheme".to_owned()))?
        + 3;
    let rest = &raw[scheme_end..];
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .split('@')
        .next_back()
        .unwrap_or_default();
    let host = authority.split(':').next().unwrap_or_default();
    if host.is_empty() {
        return Err(SkipReason::Unsupported(format!(
            "cannot determine a host from {raw}"
        )));
    }
    Ok(host.to_ascii_lowercase())
}

/// Site Rule v1 rejects any unquoted `&`, `*`, `!`, or `<<:` at a token
/// boundary so a rule can never smuggle in a YAML anchor, alias, tag, or merge
/// key. Real matcher values legitimately contain those bytes — `&amp;` in an
/// HTML title, `*/*` in an Accept header, `:*` inside a character class — so
/// any emitted scalar that would trip that scanner is re-emitted single
/// quoted.
fn quote_unsafe_scalars(yaml: &str) -> String {
    let mut output = String::with_capacity(yaml.len());
    for line in yaml.lines() {
        output.push_str(&quote_line_if_unsafe(line));
        output.push('\n');
    }
    output
}

fn quote_line_if_unsafe(line: &str) -> String {
    let indent = line.len() - line.trim_start().len();
    let rest = &line[indent..];
    let value_start = if let Some(position) = rest.find(": ") {
        indent + position + 2
    } else if rest.starts_with("- ") {
        indent + 2
    } else {
        return line.to_owned();
    };
    let value = &line[value_start..];
    // Block scalars, flow collections, and already-quoted values are left
    // alone: the scanner ignores quoted spans and never sees the others.
    if value.is_empty()
        || value.starts_with(['|', '>', '\'', '"', '[', '{'])
        || !trips_anchor_scanner(value)
    {
        return line.to_owned();
    }
    format!("{}'{}'", &line[..value_start], value.replace('\'', "''"))
}

fn trips_anchor_scanner(value: &str) -> bool {
    value.char_indices().any(|(index, character)| {
        let boundary = index == 0
            || value[..index].chars().next_back().is_some_and(|previous| {
                previous.is_whitespace() || matches!(previous, ':' | '-' | '[' | '{' | ',')
            });
        boundary && matches!(character, '&' | '*' | '!')
    }) || value.contains("<<:")
}

fn unique_site_id(base: &str, used: &BTreeSet<String>) -> Option<String> {
    if !used.contains(base) {
        return Some(base.to_owned());
    }
    (2..100).find_map(|suffix| {
        let candidate = format!("{base}-{suffix}");
        (!used.contains(&candidate)).then_some(candidate)
    })
}

fn slug(name: &str) -> Option<String> {
    let mut slug = String::new();
    for character in name.chars() {
        if character.is_ascii_alphanumeric() {
            slug.push(character.to_ascii_lowercase());
        } else if !slug.ends_with('-') && !slug.is_empty() {
            slug.push('-');
        }
    }
    let slug = slug.trim_end_matches('-');
    let slug: String = slug.chars().take(64).collect();
    let slug = slug.trim_end_matches('-').to_owned();
    (!slug.is_empty() && slug.starts_with(|c: char| c.is_ascii_alphanumeric())).then_some(slug)
}

/// Collects the hand-authored rule IDs the importer must never overwrite.
///
/// A previous run's own output is deliberately excluded so re-importing a
/// newer upstream snapshot refreshes those rules in place instead of skipping
/// them as if they were curated.
fn curated_ids(directory: Option<&Path>) -> Result<BTreeSet<String>, String> {
    let Some(directory) = directory else {
        return Ok(BTreeSet::new());
    };
    let entries = fs::read_dir(directory)
        .map_err(|error| format!("cannot read {}: {error}", directory.display()))?;
    let mut ids = BTreeSet::new();
    for entry in entries {
        let entry = entry.map_err(|error| format!("cannot read directory entry: {error}"))?;
        let path = entry.path();
        if !path
            .extension()
            .is_some_and(|extension| extension == "yaml")
        {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };
        let content = fs::read_to_string(&path)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        if !is_importer_output(&content) {
            ids.insert(stem.to_owned());
        }
    }
    Ok(ids)
}

fn is_importer_output(rule: &str) -> bool {
    rule.lines().any(|line| line.trim() == IMPORTED_TAG_LINE)
}

struct Options {
    input: PathBuf,
    output_directory: PathBuf,
    fixture_directory: Option<PathBuf>,
    curated_directory: Option<PathBuf>,
    dry_run: bool,
}

impl Options {
    fn parse(arguments: Vec<OsString>) -> Result<Self, String> {
        let mut input = None;
        let mut output_directory = None;
        let mut fixture_directory = None;
        let mut curated_directory = None;
        let mut dry_run = false;
        let mut arguments = arguments.into_iter();
        while let Some(argument) = arguments.next() {
            let argument = argument
                .into_string()
                .map_err(|_| "arguments must be valid Unicode".to_owned())?;
            match argument.as_str() {
                "--input" => input = Some(PathBuf::from(next_value(&mut arguments, "--input")?)),
                "--output-dir" => {
                    output_directory =
                        Some(PathBuf::from(next_value(&mut arguments, "--output-dir")?));
                }
                "--fixture-dir" => {
                    fixture_directory =
                        Some(PathBuf::from(next_value(&mut arguments, "--fixture-dir")?));
                }
                "--curated-dir" => {
                    curated_directory =
                        Some(PathBuf::from(next_value(&mut arguments, "--curated-dir")?));
                }
                "--dry-run" => dry_run = true,
                other => return Err(format!("unsupported argument {other}")),
            }
        }
        Ok(Self {
            input: input.ok_or("--input is required")?,
            output_directory: output_directory.ok_or("--output-dir is required")?,
            fixture_directory,
            curated_directory,
            dry_run,
        })
    }
}

fn next_value(
    arguments: &mut impl Iterator<Item = OsString>,
    flag: &str,
) -> Result<String, String> {
    arguments
        .next()
        .ok_or_else(|| format!("{flag} requires a value"))?
        .into_string()
        .map_err(|_| format!("{flag} requires a valid Unicode value"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_templates_are_context_tagged() {
        assert_eq!(
            url_template("https://example.com/u/{}").unwrap(),
            "https://example.com/u/{username:path}"
        );
        assert_eq!(
            url_template("https://example.com/m.php?user={}").unwrap(),
            "https://example.com/m.php?user={username:query}"
        );
        assert_eq!(
            url_template("https://{}.example.com/").unwrap(),
            "https://{username:subdomain}.example.com/"
        );
    }

    #[test]
    fn hosts_come_from_the_fixed_part_of_the_url() {
        assert_eq!(
            probe_hosts("https://Example.com:443/u/{}").unwrap(),
            ["example.com"]
        );
    }

    #[test]
    fn a_username_subdomain_declares_its_parent_as_a_wildcard() {
        assert_eq!(
            probe_hosts("https://{}.example.com/").unwrap(),
            ["*.example.com", "example.com"]
        );
        // A placeholder anywhere but the leading label would render hosts the
        // declared parent cannot bound.
        assert!(probe_hosts("https://a.{}.example.com/").is_err());
        assert!(probe_hosts("https://user-{}.example.com/").is_err());
    }

    #[test]
    fn scalars_that_would_read_as_yaml_anchors_are_quoted() {
        for (line, expected) in [
            (
                "    value: <title>Find &amp; Share</title>",
                "    value: '<title>Find &amp; Share</title>'",
            ),
            (
                "      Accept: text/html,*/*;q=0.8",
                "      Accept: 'text/html,*/*;q=0.8'",
            ),
            (
                r#"  pattern: ^[^\/:*?"<>|@]{3,50}$"#,
                r#"  pattern: '^[^\/:*?"<>|@]{3,50}$'"#,
            ),
        ] {
            assert_eq!(quote_line_if_unsafe(line), expected);
        }
        for untouched in [
            "  id: github",
            "  pattern: ^[a-z]*$",
            "probes:",
            "  - id: profile",
        ] {
            assert_eq!(quote_line_if_unsafe(untouched), untouched);
        }
    }

    #[test]
    fn quoting_escapes_embedded_single_quotes() {
        assert_eq!(
            quote_line_if_unsafe("  value: it's &gone"),
            "  value: 'it''s &gone'"
        );
    }

    #[test]
    fn slugs_are_valid_site_ids() {
        assert_eq!(slug("161 Social").unwrap(), "161-social");
        assert_eq!(slug("About.me").unwrap(), "about-me");
        assert!(slug("!!!").is_none());
    }
}
