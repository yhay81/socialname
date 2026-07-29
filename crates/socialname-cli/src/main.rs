#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::de::DeserializeOwned;
use socialname_canary::{
    CanaryAggregationPolicy, CanaryHealthAssessor, CanaryManifestCompiler, CanaryReportAggregator,
    CanaryReportBuilder, CanaryReportPolicy, CanaryReportValidator, CanaryRunBudget,
    CanaryRunCompletion, CanaryRunner, CanaryShadowBuilder, CanaryShadowDisposition,
    CanaryShadowPair, CanaryShadowPolicy, CanaryShadowValidator, DeclaredVantage,
    PromotionBuildRequest, PromotionBuilder, PromotionEnvelope, PromotionSigningKey,
    PromotionTrustPolicy, PromotionVerifier, RulePackMetadataBuildRequest, RulePackMetadataBuilder,
    RulePackMetadataEnvelope, RulePackMetadataSigningKey, RulePackMetadataVerifier,
    RulePackRolloutStage, RulePackTrustV1, ValidatedCanaryReport, plan_negative_generator,
};
use socialname_domain::{RuleHealthPolicy, RuleHealthRecord};
use socialname_rule_compiler::RuleCompiler;
use socialname_testkit::verify_fixtures;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

mod search_command;

use search_command::{SearchPolicy, SearchRuleHealth, SearchSource, SyncPolicy};

const MAX_RULE_PACK_TRUST_BYTES: usize = 64 * 1_024;
const MAX_RULE_PACK_METADATA_BYTES: usize = 2 * 1_024 * 1_024;
const MAX_SIGNING_KEY_SPECIFICATIONS: usize = 32;

#[derive(Debug, Parser)]
#[command(
    name = "socialname",
    version,
    about = "Public identifier observability"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate, inspect, and compile Site Rule v1 sources.
    Rules(RulesArgs),
    /// Validate independent positive/negative canary manifests.
    Canaries(Box<CanaryArgs>),
    /// Verify deterministic response fixtures against the rule pack.
    Fixtures(FixtureArgs),
    /// Search one site with an explicit source and independent sync policy.
    Search(SearchArgs),
}

#[derive(Debug, Args)]
struct RulesArgs {
    #[command(subcommand)]
    command: RulesCommand,
}

#[derive(Debug, Subcommand)]
enum RulesCommand {
    /// Compile every rule and print the canonical pack hash.
    Validate {
        #[arg(long, default_value = "rules/sites")]
        rules_dir: PathBuf,
    },
    /// List validated rules.
    List {
        #[arg(long, default_value = "rules/sites")]
        rules_dir: PathBuf,
        #[arg(long)]
        all: bool,
    },
    /// Print the domain-separated identity of a strict public trust-root file.
    TrustId {
        #[arg(long)]
        trust_file: PathBuf,
    },
    /// Sign one exact pack, embedded site promotions, rollout stage, and trust generation.
    SignMetadata {
        #[arg(long, default_value = "rules/sites")]
        rules_dir: PathBuf,
        #[arg(long = "promotion", required = true)]
        promotions: Vec<PathBuf>,
        #[arg(long)]
        sequence: u64,
        #[arg(long)]
        previous_rule_pack_hash: Option<String>,
        #[arg(long = "required-region", required = true)]
        required_regions: Vec<String>,
        #[arg(long, value_enum)]
        rollout_stage: CliRolloutStage,
        #[arg(long = "eligible-region")]
        eligible_regions: Vec<String>,
        #[arg(long = "eligible-worker")]
        eligible_workers: Vec<String>,
        #[arg(long)]
        expires_at: DateTime<Utc>,
        /// Candidate trust generation embedded in the signed metadata.
        #[arg(long)]
        trust_file: PathBuf,
        /// Currently trusted generation; use the same file when no rotation occurs.
        #[arg(long)]
        current_trust_file: PathBuf,
        /// Repeated `key-id=private-seed-file` signer specification.
        #[arg(long = "signing-key", required = true)]
        signing_keys: Vec<String>,
    },
    /// Verify signed pack metadata, its promotions, exact pack, trust update, and worker stage.
    VerifyMetadata {
        #[arg(long)]
        artifact: PathBuf,
        #[arg(long, default_value = "rules/sites")]
        rules_dir: PathBuf,
        #[arg(long)]
        current_trust_file: PathBuf,
        #[arg(long, default_value_t = 0)]
        minimum_sequence_exclusive: u64,
        #[arg(long)]
        region: Option<String>,
        #[arg(long)]
        worker_id: Option<String>,
    },
    /// Print the generated JSON Schema.
    Schema,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliRolloutStage {
    Canary,
    Regional,
    General,
    Rollback,
}

impl From<CliRolloutStage> for RulePackRolloutStage {
    fn from(value: CliRolloutStage) -> Self {
        match value {
            CliRolloutStage::Canary => Self::Canary,
            CliRolloutStage::Regional => Self::Regional,
            CliRolloutStage::General => Self::General,
            CliRolloutStage::Rollback => Self::Rollback,
        }
    }
}

#[derive(Debug, Args)]
struct CanaryArgs {
    #[command(subcommand)]
    command: CanaryCommand,
}

#[derive(Debug, Subcommand)]
enum CanaryCommand {
    /// Validate every canary manifest against its current site rule.
    Validate {
        #[arg(long, default_value = "rules/sites")]
        rules_dir: PathBuf,
        #[arg(long, default_value = "rules/canaries")]
        manifests_dir: PathBuf,
    },
    /// Report which sites can hold a canary manifest at all.
    ///
    /// A generated negative must carry enough entropy to be almost certainly
    /// unclaimed, so a site whose username policy cannot accept a candidate
    /// that long can never satisfy the manifest contract. Knowing that before
    /// any review effort is spent is the point of this command.
    Plan {
        #[arg(long, default_value = "rules/sites")]
        rules_dir: PathBuf,
        /// Restrict the report to one site ID.
        #[arg(long)]
        site: Option<String>,
        /// List every site rather than only the summary and the blocked ones.
        #[arg(long)]
        verbose: bool,
    },
    /// Run one bounded live canary set through the production engine.
    Run {
        #[arg(long)]
        site: String,
        /// Coarse managed-region label recorded with the run.
        #[arg(long)]
        region: String,
        #[arg(long, default_value = "rules/sites")]
        rules_dir: PathBuf,
        #[arg(long, default_value = "rules/canaries")]
        manifests_dir: PathBuf,
        #[arg(long, default_value_t = 64)]
        max_requests: usize,
        #[arg(long, default_value_t = 4)]
        max_concurrency: usize,
        #[arg(long, default_value_t = 120_000)]
        max_elapsed_ms: u64,
        #[arg(long, default_value_t = 16_777_216)]
        max_response_bytes: usize,
        /// Acknowledge that this command sends bounded requests to a third party.
        #[arg(long)]
        allow_live: bool,
        #[arg(long)]
        json: bool,
    },
    /// Run a candidate beside its last-known-good rule on the same private cases.
    Shadow {
        #[arg(long)]
        candidate_rule: PathBuf,
        #[arg(long)]
        last_known_good_rule: PathBuf,
        #[arg(long)]
        manifest: PathBuf,
        /// Coarse managed-region label recorded with the paired run.
        #[arg(long)]
        region: String,
        /// Combined request cap across both rules.
        #[arg(long, default_value_t = 128)]
        max_requests: usize,
        /// Combined in-flight request cap across both rules.
        #[arg(long, default_value_t = 4)]
        max_concurrency: usize,
        /// Combined wall-time cap across both rules.
        #[arg(long, default_value_t = 120_000)]
        max_elapsed_ms: u64,
        /// Combined inspected-response-byte cap across both rules.
        #[arg(long, default_value_t = 33_554_432)]
        max_response_bytes: usize,
        /// Acknowledge that this command sends bounded requests to a third party.
        #[arg(long)]
        allow_live: bool,
        #[arg(long)]
        json: bool,
    },
    /// Aggregate validated reports over one explicit 24-hour window.
    Aggregate {
        #[arg(long)]
        reports_dir: PathBuf,
        #[arg(long)]
        site: String,
        #[arg(long)]
        manifest_hash: String,
        #[arg(long)]
        rule_hash: String,
        #[arg(long)]
        engine_hash: String,
        #[arg(long = "region", required = true)]
        regions: Vec<String>,
        #[arg(long)]
        window_start: DateTime<Utc>,
        #[arg(long)]
        window_end: DateTime<Utc>,
        #[arg(long, default_value_t = 3)]
        minimum_runs_per_region: u32,
        #[arg(long, default_value_t = 6_000)]
        maximum_p95_latency_ms: u64,
        #[arg(long, default_value_t = 64)]
        max_planned_requests: u32,
        #[arg(long, default_value_t = 16_777_216)]
        max_completed_response_bytes: u64,
        #[arg(long)]
        json: bool,
    },
    /// Derive and apply one regional rule-health event from aggregate and shadow evidence.
    Health {
        #[arg(long)]
        reports_dir: PathBuf,
        #[arg(long)]
        shadow_report: PathBuf,
        #[arg(long)]
        current_record: Option<PathBuf>,
        #[arg(long)]
        site: String,
        #[arg(long)]
        manifest_hash: String,
        #[arg(long)]
        candidate_rule_hash: String,
        #[arg(long)]
        last_known_good_rule_hash: String,
        #[arg(long)]
        engine_hash: String,
        /// Region whose health record is updated.
        #[arg(long)]
        region: String,
        /// Complete required region set for aggregate evaluation.
        #[arg(long = "required-region", required = true)]
        required_regions: Vec<String>,
        #[arg(long)]
        window_start: DateTime<Utc>,
        #[arg(long)]
        window_end: DateTime<Utc>,
        #[arg(long, default_value_t = 3)]
        minimum_runs_per_region: u32,
        #[arg(long, default_value_t = 6_000)]
        maximum_p95_latency_ms: u64,
        #[arg(long, default_value_t = 64)]
        max_planned_requests: u32,
        #[arg(long, default_value_t = 16_777_216)]
        max_completed_response_bytes: u64,
        #[arg(long, default_value_t = 2)]
        recovery_passes_required: u32,
        #[arg(long, default_value_t = 2)]
        operational_failures_to_quarantine: u32,
        #[arg(long)]
        json: bool,
    },
    /// Sign accepted regional health into a versioned promotion artifact.
    Promote {
        #[arg(long)]
        site: String,
        #[arg(long, default_value = "rules/sites")]
        rules_dir: PathBuf,
        #[arg(long = "health-record", required = true)]
        health_records: Vec<PathBuf>,
        #[arg(long = "required-region", required = true)]
        required_regions: Vec<String>,
        #[arg(long)]
        sequence: u64,
        #[arg(long)]
        previous_rule_pack_hash: Option<String>,
        #[arg(long)]
        expires_at: DateTime<Utc>,
        #[arg(long)]
        key_id: String,
        /// File containing one 32-byte Ed25519 seed as 64 hexadecimal characters.
        #[arg(long)]
        signing_key_file: PathBuf,
    },
    /// Verify a signed promotion against an exact local pack and trust policy.
    VerifyPromotion {
        #[arg(long)]
        artifact: PathBuf,
        #[arg(long)]
        site: String,
        #[arg(long, default_value = "rules/sites")]
        rules_dir: PathBuf,
        #[arg(long)]
        manifest_hash: String,
        #[arg(long)]
        engine_hash: String,
        #[arg(long = "required-region", required = true)]
        required_regions: Vec<String>,
        #[arg(long)]
        previous_rule_pack_hash: Option<String>,
        #[arg(long, default_value_t = 0)]
        minimum_sequence_exclusive: u64,
        #[arg(long)]
        key_id: String,
        /// File containing one 32-byte Ed25519 public key as 64 hexadecimal characters.
        #[arg(long)]
        verifying_key_file: PathBuf,
    },
    /// Print the generated JSON Schema.
    Schema,
}

#[derive(Debug, Args)]
struct FixtureArgs {
    #[arg(long, default_value = "rules/sites")]
    rules_dir: PathBuf,
    #[arg(long, default_value = "rules/fixtures")]
    fixtures_dir: PathBuf,
}

#[derive(Debug, Args)]
struct SearchArgs {
    username: String,
    #[arg(long)]
    site: String,
    #[arg(long, default_value = "rules/sites")]
    rules_dir: PathBuf,
    /// Select local, cache, remote, or hybrid execution.
    #[arg(long, default_value_t = SearchSource::Local)]
    source: SearchSource,
    /// Select never, private, or shared synchronization independently.
    #[arg(long, default_value_t = SyncPolicy::Never)]
    sync: SyncPolicy,
    /// User-controlled SQLite cache path. Required by cache source.
    #[arg(long)]
    cache_path: Option<PathBuf>,
    /// Exact regional rule-health record used for cache eligibility.
    #[arg(long)]
    rule_health_record: Option<PathBuf>,
    #[arg(long, default_value = "local")]
    region_class: String,
    #[arg(long, default_value_t = 86_400_000)]
    maximum_age_ms: i64,
    /// Permit a live probe for a rule that is still discovery-only.
    #[arg(long)]
    allow_disabled: bool,
    /// Managed SocialName API base URL. Required when the policy uses remote service.
    #[arg(long)]
    api_url: Option<String>,
    /// Environment variable containing the managed API key.
    #[arg(long, default_value = "SOCIALNAME_API_KEY")]
    api_key_env: String,
    /// Purpose-specific private-history or shared-observation consent grant.
    #[arg(long)]
    consent_grant_id: Option<String>,
    #[arg(long)]
    json: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    initialize_tracing();
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Rules(arguments) => run_rules(arguments),
        Command::Canaries(arguments) => run_canaries(*arguments).await,
        Command::Fixtures(arguments) => run_fixtures(arguments),
        Command::Search(arguments) => run_search(arguments).await,
    }
}

async fn run_canaries(arguments: CanaryArgs) -> Result<()> {
    let compiler = CanaryManifestCompiler::new();
    match arguments.command {
        CanaryCommand::Validate {
            rules_dir,
            manifests_dir,
        } => {
            let rules = RuleCompiler::new()
                .load_directory(&rules_dir)
                .map_err(format_compile_errors)?;
            let manifests = compiler
                .load_directory_at(&manifests_dir, &rules, Utc::now())
                .map_err(format_canary_errors)?;
            let discovery_rules = rules
                .iter()
                .filter(|rule| !rule.source.metadata.enabled)
                .count();
            println!(
                "validated {} canary manifests; {} site rules remain discovery-only",
                manifests.len(),
                discovery_rules
            );
        }
        CanaryCommand::Plan {
            rules_dir,
            site,
            verbose,
        } => {
            let rules = RuleCompiler::new()
                .load_directory(&rules_dir)
                .map_err(format_compile_errors)?;
            let selected: Vec<_> = rules
                .iter()
                .filter(|rule| site.as_ref().is_none_or(|id| &rule.source.id == id))
                .collect();
            if selected.is_empty() {
                anyhow::bail!("no site rule matched");
            }
            let mut ready = 0;
            let mut blocked = Vec::new();
            for rule in &selected {
                match plan_negative_generator(rule) {
                    Some(generator) => {
                        ready += 1;
                        if verbose {
                            println!(
                                "site={} negative_alphabet={:?} random_length={} count={}",
                                rule.source.id,
                                generator.alphabet,
                                generator.random_length,
                                generator.count
                            );
                        }
                    }
                    None => blocked.push(rule.source.id.clone()),
                }
            }
            for id in &blocked {
                println!("blocked site={id} reason=username_policy_rejects_generated_negative");
            }
            println!(
                "canary-ready {ready} of {} sites; {} blocked",
                selected.len(),
                blocked.len()
            );
            println!(
                "each ready site still needs {} reviewed positive controls, which are external evidence",
                5
            );
        }
        CanaryCommand::Run {
            site,
            region,
            rules_dir,
            manifests_dir,
            max_requests,
            max_concurrency,
            max_elapsed_ms,
            max_response_bytes,
            allow_live,
            json,
        } => {
            if !allow_live {
                bail!(
                    "live canary execution is explicit; pass --allow-live to acknowledge bounded third-party requests"
                );
            }
            let rules = RuleCompiler::new()
                .load_directory(&rules_dir)
                .map_err(format_compile_errors)?;
            let manifests = compiler
                .load_directory_at(&manifests_dir, &rules, Utc::now())
                .map_err(format_canary_errors)?;
            let rule = rules
                .iter()
                .find(|rule| rule.source.id == site)
                .with_context(|| format!("unknown site {site:?}"))?;
            let manifest = manifests
                .iter()
                .find(|manifest| manifest.source.site_id == site)
                .with_context(|| format!("no accepted canary manifest for site {site:?}"))?;
            let cancellation = CancellationToken::new();
            let signal = cancellation.clone();
            let _signal_task = tokio::spawn(async move {
                if tokio::signal::ctrl_c().await.is_ok() {
                    signal.cancel();
                }
            });
            let run = CanaryRunner::production()?
                .run(
                    rule,
                    manifest,
                    DeclaredVantage { region },
                    CanaryRunBudget {
                        max_requests,
                        max_concurrency,
                        max_elapsed_ms,
                        max_response_bytes,
                    },
                    &cancellation,
                )
                .await?;
            let completed = run.completion == CanaryRunCompletion::Complete;
            if !completed {
                if json {
                    println!("{}", serde_json::to_string_pretty(&run)?);
                } else {
                    println!(
                        "{}\t{:?}\tcompleted_cases={}\tcompleted_requests={}/{}\tcompleted_bytes={}",
                        run.site_id,
                        run.completion,
                        run.outcomes.len(),
                        run.completed_requests,
                        run.planned_requests,
                        run.completed_response_bytes,
                    );
                }
                bail!("canary run ended with {:?}", run.completion);
            }
            let report = CanaryReportBuilder::new().build(manifest, &run)?;
            let policy = CanaryReportPolicy {
                site_id: report.report.site_id.clone(),
                manifest_hash: report.report.manifest_hash.clone(),
                allowed_rule_hashes: BTreeSet::from([report.report.rule_hash.clone()]),
                allowed_engine_hashes: BTreeSet::from([report.report.engine_hash.clone()]),
                allowed_regions: BTreeSet::from([report.report.vantage.region.clone()]),
                max_planned_requests: u32::try_from(max_requests)
                    .context("max_requests does not fit report policy")?,
                max_completed_response_bytes: u64::try_from(max_response_bytes)
                    .context("max_response_bytes does not fit report policy")?,
            };
            CanaryReportValidator::new().validate_at(
                &report,
                &policy,
                &BTreeSet::new(),
                Utc::now(),
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "{}\t{}\tprecision={}/{}\tcoverage={}/{}\tcompleted_requests={}/{}\tcompleted_bytes={}",
                    report.report.site_id,
                    report.report_id,
                    report.report.summary.precision.numerator,
                    report.report.summary.precision.denominator,
                    report.report.summary.conclusive_coverage.numerator,
                    report.report.summary.conclusive_coverage.denominator,
                    report.report.summary.completed_requests,
                    report.report.summary.planned_requests,
                    report.report.summary.completed_response_bytes,
                );
            }
        }
        CanaryCommand::Shadow {
            candidate_rule,
            last_known_good_rule,
            manifest,
            region,
            max_requests,
            max_concurrency,
            max_elapsed_ms,
            max_response_bytes,
            allow_live,
            json,
        } => {
            if !allow_live {
                bail!(
                    "live shadow execution is explicit; pass --allow-live to acknowledge bounded third-party requests"
                );
            }
            let rule_compiler = RuleCompiler::new();
            let candidate_source = fs::read_to_string(&candidate_rule)
                .with_context(|| format!("failed to read candidate rule {candidate_rule:?}"))?;
            let candidate = rule_compiler
                .compile_yaml(&candidate_source, None)
                .map_err(format_compile_errors)?;
            let last_known_good_source =
                fs::read_to_string(&last_known_good_rule).with_context(|| {
                    format!("failed to read last-known-good rule {last_known_good_rule:?}")
                })?;
            let last_known_good = rule_compiler
                .compile_yaml(&last_known_good_source, None)
                .map_err(format_compile_errors)?;
            let manifest_source = fs::read_to_string(&manifest)
                .with_context(|| format!("failed to read canary manifest {manifest:?}"))?;
            let validation_time = Utc::now();
            let candidate_manifest = compiler
                .compile_yaml_at(&manifest_source, &candidate, None, validation_time)
                .map_err(format_canary_errors)?;
            let last_known_good_manifest = compiler
                .compile_yaml_at(&manifest_source, &last_known_good, None, validation_time)
                .map_err(format_canary_errors)?;

            let cancellation = CancellationToken::new();
            let signal = cancellation.clone();
            let _signal_task = tokio::spawn(async move {
                if tokio::signal::ctrl_c().await.is_ok() {
                    signal.cancel();
                }
            });
            let run = CanaryRunner::production()?
                .run_shadow(
                    CanaryShadowPair {
                        candidate_rule: &candidate,
                        candidate_manifest: &candidate_manifest,
                        last_known_good_rule: &last_known_good,
                        last_known_good_manifest: &last_known_good_manifest,
                    },
                    DeclaredVantage {
                        region: region.clone(),
                    },
                    CanaryRunBudget {
                        max_requests,
                        max_concurrency,
                        max_elapsed_ms,
                        max_response_bytes,
                    },
                    &cancellation,
                )
                .await?;
            if run.completion != CanaryRunCompletion::Complete {
                if json {
                    println!("{}", serde_json::to_string_pretty(&run)?);
                } else {
                    println!(
                        "{}\t{:?}\tcompleted_requests={}/{}\tcompleted_bytes={}",
                        run.candidate.site_id,
                        run.completion,
                        run.completed_requests,
                        run.planned_requests,
                        run.completed_response_bytes,
                    );
                }
                bail!("shadow run ended with {:?}", run.completion);
            }

            let envelope = CanaryShadowBuilder::new().build(
                &candidate_manifest,
                &last_known_good_manifest,
                &run,
            )?;
            let policy = CanaryShadowPolicy {
                site_id: candidate.source.id.clone(),
                manifest_hash: candidate_manifest.manifest_hash.clone(),
                candidate_rule_hash: candidate.rule_hash.clone(),
                last_known_good_rule_hash: last_known_good.rule_hash.clone(),
                engine_hash: envelope.comparison.candidate.report.engine_hash.clone(),
                allowed_regions: BTreeSet::from([region]),
                max_planned_requests_per_rule: u32::try_from(max_requests)
                    .context("max_requests does not fit shadow policy")?,
                max_completed_response_bytes_per_rule: u64::try_from(max_response_bytes)
                    .context("max_response_bytes does not fit shadow policy")?,
            };
            CanaryShadowValidator::new().validate_at(
                &envelope,
                &policy,
                &BTreeSet::new(),
                Utc::now(),
            )?;
            let disposition = envelope.comparison.summary.disposition;
            if json {
                println!("{}", serde_json::to_string_pretty(&envelope)?);
            } else {
                println!(
                    "{}\t{}\t{:?}\tagreements={}/{}\timprovements={}\tregressions={}\tissues={}",
                    envelope.comparison.candidate.report.site_id,
                    envelope.comparison_id,
                    disposition,
                    envelope.comparison.summary.verdict_agreements,
                    envelope.comparison.summary.total_cases,
                    envelope.comparison.summary.candidate_improvements,
                    envelope.comparison.summary.candidate_regressions,
                    envelope.comparison.summary.issues.len(),
                );
                for issue in &envelope.comparison.summary.issues {
                    println!("issue\t{issue:?}");
                }
            }
            if disposition == CanaryShadowDisposition::Rejected {
                bail!("candidate regressed against the last-known-good rule");
            }
        }
        CanaryCommand::Aggregate {
            reports_dir,
            site,
            manifest_hash,
            rule_hash,
            engine_hash,
            regions,
            window_start,
            window_end,
            minimum_runs_per_region,
            maximum_p95_latency_ms,
            max_planned_requests,
            max_completed_response_bytes,
            json,
        } => {
            let aggregation_time = Utc::now();
            let allowed_regions: BTreeSet<_> = regions.into_iter().collect();
            let report_policy = CanaryReportPolicy {
                site_id: site.clone(),
                manifest_hash: manifest_hash.clone(),
                allowed_rule_hashes: BTreeSet::from([rule_hash.clone()]),
                allowed_engine_hashes: BTreeSet::from([engine_hash.clone()]),
                allowed_regions: allowed_regions.clone(),
                max_planned_requests,
                max_completed_response_bytes,
            };
            let reports =
                load_validated_canary_reports(&reports_dir, &report_policy, aggregation_time)?;

            let evaluated = CanaryReportAggregator::new().aggregate_at(
                &reports,
                &CanaryAggregationPolicy {
                    site_id: site,
                    manifest_hash,
                    rule_hash,
                    engine_hash,
                    required_regions: allowed_regions,
                    window_start,
                    window_end,
                    minimum_runs_per_region,
                    maximum_p95_latency_ms,
                },
                aggregation_time,
            )?;
            let aggregate = evaluated.aggregate();
            if json {
                println!("{}", serde_json::to_string_pretty(&aggregate)?);
            } else {
                println!(
                    "{}\t{:?}\treports={}\tregions={}\tissues={}",
                    aggregate.site_id,
                    aggregate.disposition,
                    aggregate.report_ids.len(),
                    aggregate.regions.len(),
                    aggregate.issues.len()
                );
                for issue in &aggregate.issues {
                    println!("issue\t{issue:?}");
                }
            }
        }
        CanaryCommand::Health {
            reports_dir,
            shadow_report,
            current_record,
            site,
            manifest_hash,
            candidate_rule_hash,
            last_known_good_rule_hash,
            engine_hash,
            region,
            required_regions,
            window_start,
            window_end,
            minimum_runs_per_region,
            maximum_p95_latency_ms,
            max_planned_requests,
            max_completed_response_bytes,
            recovery_passes_required,
            operational_failures_to_quarantine,
            json,
        } => {
            let assessment_time = Utc::now();
            let required_regions: BTreeSet<_> = required_regions.into_iter().collect();
            if !required_regions.contains(&region) {
                bail!("health region must be included in --required-region");
            }
            let report_policy = CanaryReportPolicy {
                site_id: site.clone(),
                manifest_hash: manifest_hash.clone(),
                allowed_rule_hashes: BTreeSet::from([candidate_rule_hash.clone()]),
                allowed_engine_hashes: BTreeSet::from([engine_hash.clone()]),
                allowed_regions: required_regions.clone(),
                max_planned_requests,
                max_completed_response_bytes,
            };
            let reports =
                load_validated_canary_reports(&reports_dir, &report_policy, assessment_time)?;
            let evaluated = CanaryReportAggregator::new().aggregate_at(
                &reports,
                &CanaryAggregationPolicy {
                    site_id: site.clone(),
                    manifest_hash: manifest_hash.clone(),
                    rule_hash: candidate_rule_hash.clone(),
                    engine_hash: engine_hash.clone(),
                    required_regions,
                    window_start,
                    window_end,
                    minimum_runs_per_region,
                    maximum_p95_latency_ms,
                },
                assessment_time,
            )?;

            let shadow_source = fs::read_to_string(&shadow_report)
                .with_context(|| format!("failed to read shadow report {shadow_report:?}"))?;
            let validated_shadow = CanaryShadowValidator::new().parse_and_validate_json_at(
                &shadow_source,
                &CanaryShadowPolicy {
                    site_id: site,
                    manifest_hash,
                    candidate_rule_hash,
                    last_known_good_rule_hash,
                    engine_hash,
                    allowed_regions: BTreeSet::from([region.clone()]),
                    max_planned_requests_per_rule: max_planned_requests,
                    max_completed_response_bytes_per_rule: max_completed_response_bytes,
                },
                &BTreeSet::new(),
                assessment_time,
            )?;
            let health_policy = RuleHealthPolicy {
                recovery_passes_required,
                operational_failures_to_quarantine,
            };
            let current = if let Some(path) = current_record {
                let source = fs::read_to_string(&path)
                    .with_context(|| format!("failed to read health record {path:?}"))?;
                let value: serde_json::Value = serde_json::from_str(&source)
                    .with_context(|| format!("failed to parse health record {path:?}"))?;
                let record_value = value.get("record").cloned().unwrap_or(value);
                let record: RuleHealthRecord = serde_json::from_value(record_value)
                    .with_context(|| format!("failed to decode health record {path:?}"))?;
                record.validate(health_policy)?;
                record
            } else {
                let aggregate = evaluated.aggregate();
                RuleHealthRecord::quarantined(
                    socialname_domain::RuleHealthKey {
                        site_id: socialname_domain::SiteId::new(aggregate.site_id.clone()),
                        rule_hash: aggregate.rule_hash.clone(),
                        region: region.clone(),
                    },
                    aggregate.window_start.timestamp_millis(),
                )?
            };
            let sequence = current
                .sequence
                .checked_add(1)
                .context("health sequence overflowed")?;
            let event = CanaryHealthAssessor::new().assess_region(
                &evaluated,
                &validated_shadow,
                &region,
                sequence,
            )?;
            let (record, transition) =
                current.apply_at(&event, health_policy, Utc::now().timestamp_millis())?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "record": record,
                        "transition": transition,
                    }))?
                );
            } else {
                println!(
                    "{}\t{}\t{}\t{:?}->{:?}\tchanged={}\thealth_only=true",
                    record.key.site_id,
                    record.key.region,
                    record.sequence,
                    transition.from,
                    transition.to,
                    transition.changed,
                );
            }
        }
        CanaryCommand::Promote {
            site,
            rules_dir,
            health_records,
            required_regions,
            sequence,
            previous_rule_pack_hash,
            expires_at,
            key_id,
            signing_key_file,
        } => {
            let rule_compiler = RuleCompiler::new();
            let rules = rule_compiler
                .load_directory(&rules_dir)
                .map_err(format_compile_errors)?;
            let candidate = rules
                .iter()
                .find(|rule| rule.source.id == site)
                .with_context(|| format!("unknown site {site:?}"))?;
            let rule_pack = rule_compiler
                .compile_pack(&rules)
                .map_err(format_compile_errors)?;
            let health_records = health_records
                .iter()
                .map(|path| load_rule_health_record(path))
                .collect::<Result<Vec<_>>>()?;
            let required_regions: BTreeSet<_> = required_regions.into_iter().collect();
            let seed = load_hex_key::<32>(&signing_key_file, "Ed25519 signing seed")?;
            let signing_key = PromotionSigningKey::from_seed(key_id.clone(), seed)?;
            let issued_at = Utc::now();
            let envelope = PromotionBuilder::new().build(
                &signing_key,
                PromotionBuildRequest {
                    sequence,
                    candidate,
                    rule_pack: &rule_pack,
                    previous_rule_pack_hash: previous_rule_pack_hash.as_deref(),
                    health_records: &health_records,
                    required_regions: &required_regions,
                    issued_at_unix_ms: issued_at.timestamp_millis(),
                    expires_at_unix_ms: expires_at.timestamp_millis(),
                },
            )?;
            let trust_policy = PromotionTrustPolicy {
                trusted_keys: BTreeMap::from([(key_id, signing_key.verifying_key_bytes())]),
                expected_site_id: site,
                expected_rule_hash: candidate.rule_hash.clone(),
                expected_rule_pack_hash: rule_pack.content_hash.clone(),
                expected_previous_rule_pack_hash: previous_rule_pack_hash,
                expected_manifest_hash: envelope.promotion.manifest_hash.clone(),
                expected_engine_hash: envelope.promotion.engine_hash.clone(),
                required_regions,
                minimum_sequence_exclusive: sequence.saturating_sub(1),
            };
            PromotionVerifier::new().validate_at(
                &envelope,
                &trust_policy,
                issued_at.timestamp_millis(),
            )?;
            println!("{}", serde_json::to_string_pretty(&envelope)?);
        }
        CanaryCommand::VerifyPromotion {
            artifact,
            site,
            rules_dir,
            manifest_hash,
            engine_hash,
            required_regions,
            previous_rule_pack_hash,
            minimum_sequence_exclusive,
            key_id,
            verifying_key_file,
        } => {
            let rule_compiler = RuleCompiler::new();
            let rules = rule_compiler
                .load_directory(&rules_dir)
                .map_err(format_compile_errors)?;
            let candidate = rules
                .iter()
                .find(|rule| rule.source.id == site)
                .with_context(|| format!("unknown site {site:?}"))?;
            let rule_pack = rule_compiler
                .compile_pack(&rules)
                .map_err(format_compile_errors)?;
            let verifying_key = load_hex_key::<32>(&verifying_key_file, "Ed25519 verifying key")?;
            let source = fs::read(&artifact)
                .with_context(|| format!("failed to read promotion artifact {artifact:?}"))?;
            let validated = PromotionVerifier::new().validate_json_at(
                &source,
                &PromotionTrustPolicy {
                    trusted_keys: BTreeMap::from([(key_id, verifying_key)]),
                    expected_site_id: site,
                    expected_rule_hash: candidate.rule_hash.clone(),
                    expected_rule_pack_hash: rule_pack.content_hash,
                    expected_previous_rule_pack_hash: previous_rule_pack_hash,
                    expected_manifest_hash: manifest_hash,
                    expected_engine_hash: engine_hash,
                    required_regions: required_regions.into_iter().collect(),
                    minimum_sequence_exclusive,
                },
                Utc::now().timestamp_millis(),
            )?;
            println!(
                "verified promotion {} for {} at sequence {}; activate only with pack sha256={}",
                validated.envelope().promotion_id,
                validated.promotion().site_id,
                validated.promotion().sequence,
                validated.promotion().rule_pack_hash,
            );
        }
        CanaryCommand::Schema => {
            println!("{}", compiler.json_schema()?);
        }
    }
    Ok(())
}

fn load_rule_health_record(path: &Path) -> Result<RuleHealthRecord> {
    let source = fs::read_to_string(path)
        .with_context(|| format!("failed to read health record {path:?}"))?;
    let value: serde_json::Value = serde_json::from_str(&source)
        .with_context(|| format!("failed to parse health record {path:?}"))?;
    let record_value = value.get("record").cloned().unwrap_or(value);
    serde_json::from_value(record_value)
        .with_context(|| format!("failed to decode health record {path:?}"))
}

fn load_hex_key<const N: usize>(path: &Path, description: &str) -> Result<[u8; N]> {
    let source = fs::read_to_string(path)
        .with_context(|| format!("failed to read {description} {path:?}"))?;
    let decoded = hex::decode(source.trim())
        .with_context(|| format!("{description} must contain hexadecimal bytes"))?;
    decoded.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!(
            "{description} must contain exactly {N} bytes, found {}",
            bytes.len()
        )
    })
}

fn load_bounded_json<T: DeserializeOwned>(
    path: &Path,
    maximum_bytes: usize,
    description: &str,
) -> Result<T> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {description} {path:?}"))?;
    if bytes.len() > maximum_bytes {
        bail!("{description} exceeds its configured byte limit");
    }
    serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to decode {description} {path:?}"))
}

fn load_metadata_signing_keys(
    specifications: &[String],
) -> Result<Vec<RulePackMetadataSigningKey>> {
    if specifications.is_empty() || specifications.len() > MAX_SIGNING_KEY_SPECIFICATIONS {
        bail!("rule-pack metadata requires a bounded nonempty signer set");
    }
    let mut seen = BTreeSet::new();
    specifications
        .iter()
        .map(|specification| {
            let (key_id, path) = specification
                .split_once('=')
                .context("each --signing-key must use key-id=private-seed-file")?;
            if key_id.is_empty() || path.is_empty() || !seen.insert(key_id.to_owned()) {
                bail!("rule-pack metadata signer specifications are invalid or duplicated");
            }
            let seed = load_hex_key::<32>(Path::new(path), "Ed25519 signing seed")?;
            RulePackMetadataSigningKey::from_seed(key_id, seed).map_err(Into::into)
        })
        .collect()
}

fn unique_labels(values: Vec<String>, description: &str) -> Result<BTreeSet<String>> {
    let count = values.len();
    let values = values.into_iter().collect::<BTreeSet<_>>();
    if values.len() != count {
        bail!("{description} values must not be duplicated");
    }
    Ok(values)
}

const fn rollout_stage_name(stage: RulePackRolloutStage) -> &'static str {
    match stage {
        RulePackRolloutStage::Canary => "canary",
        RulePackRolloutStage::Regional => "regional",
        RulePackRolloutStage::General => "general",
        RulePackRolloutStage::Rollback => "rollback",
    }
}

fn load_validated_canary_reports(
    reports_dir: &Path,
    policy: &CanaryReportPolicy,
    validation_time: DateTime<Utc>,
) -> Result<Vec<ValidatedCanaryReport>> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(reports_dir)
        .with_context(|| format!("failed to read report directory {reports_dir:?}"))?
    {
        let path = entry
            .with_context(|| format!("failed to read report directory {reports_dir:?}"))?
            .path();
        if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            paths.push(path);
        }
    }
    paths.sort();

    let validator = CanaryReportValidator::new();
    let mut seen_report_ids = BTreeSet::new();
    let mut reports = Vec::new();
    for path in paths {
        let source =
            fs::read_to_string(&path).with_context(|| format!("failed to read report {path:?}"))?;
        let validated = validator.parse_and_validate_json_at(
            &source,
            policy,
            &seen_report_ids,
            validation_time,
        )?;
        seen_report_ids.insert(validated.envelope().report_id.clone());
        reports.push(validated);
    }
    Ok(reports)
}

fn run_rules(arguments: RulesArgs) -> Result<()> {
    let compiler = RuleCompiler::new();
    match arguments.command {
        RulesCommand::Validate { rules_dir } => {
            let rules = compiler
                .load_directory(&rules_dir)
                .map_err(format_compile_errors)?;
            let pack = compiler
                .compile_pack(&rules)
                .map_err(format_compile_errors)?;
            println!(
                "validated {} rules; pack sha256={}",
                pack.rules.len(),
                pack.content_hash
            );
        }
        RulesCommand::List { rules_dir, all } => {
            let rules = compiler
                .load_directory(&rules_dir)
                .map_err(format_compile_errors)?;
            for rule in rules {
                if all || rule.source.metadata.enabled {
                    let state = if rule.source.metadata.enabled {
                        "enabled"
                    } else {
                        "discovery"
                    };
                    println!("{}\t{}\t{state}", rule.source.id, rule.source.name);
                }
            }
        }
        RulesCommand::TrustId { trust_file } => {
            let trust: RulePackTrustV1 =
                load_bounded_json(&trust_file, MAX_RULE_PACK_TRUST_BYTES, "rule-pack trust")?;
            trust.validate_at(Utc::now().timestamp_millis())?;
            println!("{}", trust.content_id()?);
        }
        RulesCommand::SignMetadata {
            rules_dir,
            promotions,
            sequence,
            previous_rule_pack_hash,
            required_regions,
            rollout_stage,
            eligible_regions,
            eligible_workers,
            expires_at,
            trust_file,
            current_trust_file,
            signing_keys,
        } => {
            let rules = compiler
                .load_directory(&rules_dir)
                .map_err(format_compile_errors)?;
            let pack = compiler
                .compile_pack(&rules)
                .map_err(format_compile_errors)?;
            let promotions = promotions
                .iter()
                .map(|path| {
                    load_bounded_json::<PromotionEnvelope>(
                        path,
                        MAX_RULE_PACK_METADATA_BYTES,
                        "rule promotion",
                    )
                })
                .collect::<Result<Vec<_>>>()?;
            let trust: RulePackTrustV1 = load_bounded_json(
                &trust_file,
                MAX_RULE_PACK_TRUST_BYTES,
                "candidate rule-pack trust",
            )?;
            let current_trust: RulePackTrustV1 = load_bounded_json(
                &current_trust_file,
                MAX_RULE_PACK_TRUST_BYTES,
                "current rule-pack trust",
            )?;
            let signing_keys = load_metadata_signing_keys(&signing_keys)?;
            let required_regions = unique_labels(required_regions, "required region")?;
            let eligible_regions = unique_labels(eligible_regions, "eligible region")?;
            let eligible_workers = unique_labels(eligible_workers, "eligible worker")?;
            let issued_at_unix_ms = Utc::now().timestamp_millis();
            let envelope = RulePackMetadataBuilder::new().build(
                &signing_keys,
                RulePackMetadataBuildRequest {
                    sequence,
                    rule_pack: &pack,
                    previous_rule_pack_hash: previous_rule_pack_hash.as_deref(),
                    required_regions: &required_regions,
                    rollout_stage: rollout_stage.into(),
                    eligible_regions: &eligible_regions,
                    eligible_workers: &eligible_workers,
                    issued_at_unix_ms,
                    expires_at_unix_ms: expires_at.timestamp_millis(),
                    trust,
                    promotions: &promotions,
                },
            )?;
            let validated = RulePackMetadataVerifier::new().validate_at(
                &envelope,
                &current_trust,
                issued_at_unix_ms,
            )?;
            validated.validate_pack(&pack)?;
            println!("{}", serde_json::to_string_pretty(&envelope)?);
        }
        RulesCommand::VerifyMetadata {
            artifact,
            rules_dir,
            current_trust_file,
            minimum_sequence_exclusive,
            region,
            worker_id,
        } => {
            let rules = compiler
                .load_directory(&rules_dir)
                .map_err(format_compile_errors)?;
            let pack = compiler
                .compile_pack(&rules)
                .map_err(format_compile_errors)?;
            let envelope: RulePackMetadataEnvelope = load_bounded_json(
                &artifact,
                MAX_RULE_PACK_METADATA_BYTES,
                "rule-pack metadata",
            )?;
            let current_trust: RulePackTrustV1 = load_bounded_json(
                &current_trust_file,
                MAX_RULE_PACK_TRUST_BYTES,
                "current rule-pack trust",
            )?;
            let validated = RulePackMetadataVerifier::new().validate_at(
                &envelope,
                &current_trust,
                Utc::now().timestamp_millis(),
            )?;
            validated.validate_pack(&pack)?;
            if validated.metadata().sequence <= minimum_sequence_exclusive {
                bail!("rule-pack metadata sequence is not above the configured high-water mark");
            }
            let worker_eligible = match (region.as_deref(), worker_id.as_deref()) {
                (Some(region), Some(worker_id)) => {
                    Some(validated.permits_worker(region, worker_id))
                }
                (None, None) => None,
                _ => bail!("--region and --worker-id must be supplied together"),
            };
            println!(
                "metadata_id={}\tsequence={}\tpack_sha256={}\tstage={}\ttrust_generation={}\tcustomer_work={}",
                validated.envelope().metadata_id,
                validated.metadata().sequence,
                validated.metadata().rule_pack_hash,
                rollout_stage_name(validated.metadata().rollout_stage),
                validated.metadata().trust.generation,
                validated.permits_customer_work(),
            );
            if let Some(worker_eligible) = worker_eligible {
                println!("worker_eligible={worker_eligible}");
            }
        }
        RulesCommand::Schema => {
            println!("{}", compiler.json_schema()?);
        }
    }
    Ok(())
}

fn run_fixtures(arguments: FixtureArgs) -> Result<()> {
    let rules = RuleCompiler::new()
        .load_directory(&arguments.rules_dir)
        .map_err(format_compile_errors)?;
    let report = verify_fixtures(&rules, &arguments.fixtures_dir).map_err(|errors| {
        anyhow::anyhow!(
            "{}",
            errors
                .into_iter()
                .map(|error| error.to_string())
                .collect::<Vec<_>>()
                .join("\n")
        )
    })?;
    println!(
        "verified {} fixture cases across {} sites",
        report.cases, report.sites
    );
    Ok(())
}

async fn run_search(arguments: SearchArgs) -> Result<()> {
    let policy = SearchPolicy {
        source: arguments.source,
        sync: arguments.sync,
        region_class: arguments.region_class.clone(),
        maximum_age_ms: arguments.maximum_age_ms,
    };
    policy.validate_relation()?;
    if !policy.uses_managed_service()
        && (arguments.api_url.is_some() || arguments.consent_grant_id.is_some())
    {
        bail!("managed API options are only accepted by a remote-assisted policy");
    }
    if arguments.source == SearchSource::Remote && arguments.cache_path.is_some() {
        bail!("remote source does not use --cache-path; choose hybrid for a local-cache phase");
    }
    let rules = RuleCompiler::new()
        .load_directory(&arguments.rules_dir)
        .map_err(format_compile_errors)?;
    let rule = rules
        .iter()
        .find(|rule| rule.source.id == arguments.site)
        .with_context(|| format!("unknown site {:?}", arguments.site))?;
    if matches!(arguments.source, SearchSource::Local | SearchSource::Hybrid)
        && !rule.source.metadata.enabled
        && !arguments.allow_disabled
    {
        bail!(
            "site {:?} is discovery-only; pass --allow-disabled to probe explicitly",
            arguments.site
        );
    }

    let health = arguments
        .rule_health_record
        .as_deref()
        .map(load_rule_health_record)
        .transpose()?
        .map(|record| {
            record.validate(RuleHealthPolicy::default())?;
            if record.key.site_id.as_str() != rule.source.id
                || record.key.rule_hash != rule.rule_hash
                || record.key.region != arguments.region_class
            {
                bail!("rule-health record does not match the selected site, rule hash, and region");
            }
            Ok(SearchRuleHealth {
                state: record.state,
                evidence_expires_at_unix_ms: record.last_evidence_expires_at_unix_ms,
            })
        })
        .transpose()?;
    let cache = match arguments.cache_path.as_deref() {
        Some(path) if arguments.source == SearchSource::Cache && !path.exists() => None,
        Some(path) => Some(
            socialname_cache::LocalCache::open(path)
                .await
                .context("failed to open the local observation cache")?,
        ),
        None if arguments.source == SearchSource::Cache => {
            bail!("cache source requires --cache-path")
        }
        None => None,
    };
    if policy.uses_managed_service() {
        let api_url = arguments
            .api_url
            .context("remote-assisted search requires --api-url")?;
        let consent_grant_id = arguments
            .consent_grant_id
            .context("remote-assisted search requires --consent-grant-id")?;
        let api_key = std::env::var(&arguments.api_key_env).map_err(|_| {
            anyhow::anyhow!(
                "remote-assisted search requires an API key in environment variable {:?}",
                arguments.api_key_env
            )
        })?;
        let execution = search_command::execute_managed_search(
            rule,
            &arguments.username,
            policy,
            health,
            cache.as_ref(),
            socialname_app_core::ManagedSearchAccess {
                api_url,
                api_key,
                consent_grant_id,
            },
        )
        .await;
        if let Some(cache) = cache {
            cache.close().await;
        }
        let output = execution?;
        if arguments.json {
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else {
            println!("{}", output.human());
        }
        return Ok(());
    }
    let execution = search_command::execute_search(
        rule,
        &arguments.username,
        policy,
        health,
        cache.as_ref(),
        || socialname_engine::SearchEngine::new().map_err(Into::into),
    )
    .await;
    if let Some(cache) = cache {
        cache.close().await;
    }
    let output = execution?;
    if arguments.json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("{}", output.human());
    }
    Ok(())
}

fn format_compile_errors(errors: socialname_rule_compiler::CompileErrors) -> anyhow::Error {
    anyhow::anyhow!(
        "{}",
        errors
            .0
            .into_iter()
            .map(|error| error.to_string())
            .collect::<Vec<_>>()
            .join("\n")
    )
}

fn format_canary_errors(errors: socialname_canary::CanaryManifestErrors) -> anyhow::Error {
    anyhow::anyhow!(
        "{}",
        errors
            .0
            .into_iter()
            .map(|error| error.to_string())
            .collect::<Vec<_>>()
            .join("\n")
    )
}

fn initialize_tracing() {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("socialname=warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn search_defaults_to_local_with_sync_never() {
        let cli =
            Cli::try_parse_from(["socialname", "search", "octocat", "--site", "github"]).unwrap();
        let Command::Search(arguments) = cli.command else {
            panic!("expected search command");
        };
        assert_eq!(arguments.source, SearchSource::Local);
        assert_eq!(arguments.sync, SyncPolicy::Never);
        assert!(arguments.cache_path.is_none());
    }

    #[test]
    fn cache_source_is_explicit_and_invalid_policy_relation_is_rejected_at_runtime() {
        let cli = Cli::try_parse_from([
            "socialname",
            "search",
            "octocat",
            "--site",
            "github",
            "--source",
            "cache",
            "--sync",
            "never",
            "--cache-path",
            "cache.sqlite3",
        ])
        .unwrap();
        let Command::Search(arguments) = cli.command else {
            panic!("expected search command");
        };
        assert_eq!(arguments.source, SearchSource::Cache);
        assert_eq!(arguments.sync, SyncPolicy::Never);
        assert_eq!(
            arguments.cache_path.as_deref(),
            Some(Path::new("cache.sqlite3"))
        );

        let cli = Cli::try_parse_from([
            "socialname",
            "search",
            "octocat",
            "--site",
            "github",
            "--sync",
            "private",
        ])
        .unwrap();
        let Command::Search(arguments) = cli.command else {
            panic!("expected search command");
        };
        assert!(
            SearchPolicy {
                source: arguments.source,
                sync: arguments.sync,
                region_class: arguments.region_class,
                maximum_age_ms: arguments.maximum_age_ms,
            }
            .validate_relation()
            .is_err()
        );
    }

    #[test]
    fn remote_and_hybrid_sources_have_explicit_independent_inputs() {
        let cli = Cli::try_parse_from([
            "socialname",
            "search",
            "octocat",
            "--site",
            "github",
            "--source",
            "remote",
            "--sync",
            "private",
            "--api-url",
            "https://api.example.test",
            "--consent-grant-id",
            "grant_1",
        ])
        .unwrap();
        let Command::Search(arguments) = cli.command else {
            panic!("expected search command");
        };
        assert_eq!(arguments.source, SearchSource::Remote);
        assert_eq!(arguments.sync, SyncPolicy::Private);
        assert_eq!(arguments.api_key_env, "SOCIALNAME_API_KEY");

        assert!(
            Cli::try_parse_from([
                "socialname",
                "search",
                "octocat",
                "--site",
                "github",
                "--source",
                "hybrid",
                "--sync",
                "never",
            ])
            .is_ok()
        );
    }
}
