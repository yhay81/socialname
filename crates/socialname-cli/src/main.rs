#![forbid(unsafe_code)]

use std::{path::PathBuf, process::ExitCode};

use anyhow::{Context, Result, bail};
use chrono::Utc;
use clap::{Args, Parser, Subcommand};
use socialname_canary::CanaryManifestCompiler;
use socialname_engine::SearchEngine;
use socialname_rule_compiler::RuleCompiler;
use socialname_testkit::verify_fixtures;
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
        Command::Canaries(arguments) => run_canaries(arguments),
        Command::Fixtures(arguments) => run_fixtures(arguments),
        Command::Search(arguments) => run_search(arguments).await,
    }
}

fn run_canaries(arguments: CanaryArgs) -> Result<()> {
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
