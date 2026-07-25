#![forbid(unsafe_code)]

use std::{path::PathBuf, process::ExitCode};

use anyhow::{Context, Result, bail};
use chrono::Utc;
use clap::{Args, Parser, Subcommand};
use socialname_canary::{
    CanaryManifestCompiler, CanaryRunBudget, CanaryRunCompletion, CanaryRunner, DeclaredVantage,
};
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
    Canaries(CanaryArgs),
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
        Command::Canaries(arguments) => run_canaries(arguments).await,
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
            if json {
                println!("{}", serde_json::to_string_pretty(&run)?);
            } else {
                let matched = run
                    .outcomes
                    .iter()
                    .filter(|outcome| outcome.matched_expectation)
                    .count();
                println!(
                    "{}\t{:?}\t{matched}/{}\tcompleted_requests={}/{}\tcompleted_bytes={}\telapsed_ms={}",
                    run.site_id,
                    run.completion,
                    run.outcomes.len(),
                    run.completed_requests,
                    run.planned_requests,
                    run.completed_response_bytes,
                    run.elapsed_ms
                );
            }
            if !completed {
                bail!("canary run ended with {:?}", run.completion);
            }
        }
        CanaryCommand::Schema => {
            println!("{}", compiler.json_schema()?);
        }
    }
    Ok(())
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
