#![forbid(unsafe_code)]

use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use clap::{Args, Parser, Subcommand};
use socialname_canary::{
    CanaryAggregationPolicy, CanaryHealthAssessor, CanaryManifestCompiler, CanaryReportAggregator,
    CanaryReportBuilder, CanaryReportPolicy, CanaryReportValidator, CanaryRunBudget,
    CanaryRunCompletion, CanaryRunner, CanaryShadowBuilder, CanaryShadowDisposition,
    CanaryShadowPair, CanaryShadowPolicy, CanaryShadowValidator, DeclaredVantage,
    ValidatedCanaryReport,
};
use socialname_domain::{RuleHealthPolicy, RuleHealthRecord};
use socialname_engine::SearchEngine;
use socialname_rule_compiler::RuleCompiler;
use socialname_testkit::verify_fixtures;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

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
    /// Run one private local probe using the shared Rust engine.
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
    /// Print the generated JSON Schema.
    Schema,
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
    /// Permit a live probe for a rule that is still discovery-only.
    #[arg(long)]
    allow_disabled: bool,
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
        CanaryCommand::Schema => {
            println!("{}", compiler.json_schema()?);
        }
    }
    Ok(())
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
    let rules = RuleCompiler::new()
        .load_directory(&arguments.rules_dir)
        .map_err(format_compile_errors)?;
    let rule = rules
        .iter()
        .find(|rule| rule.source.id == arguments.site)
        .with_context(|| format!("unknown site {:?}", arguments.site))?;
    if !rule.source.metadata.enabled && !arguments.allow_disabled {
        bail!(
            "site {:?} is discovery-only; pass --allow-disabled to probe explicitly",
            arguments.site
        );
    }

    let result = SearchEngine::new()?.search(rule, &arguments.username).await;
    if arguments.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!(
            "{}\t{:?}\t{:?}\t{}",
            result.site_id,
            result.classification.verdict,
            result.classification.evidence_class,
            result.profile_url.as_deref().unwrap_or("-")
        );
        if let Some(reason) = result.classification.inconclusive_reason {
            println!("reason\t{reason:?}");
        }
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
