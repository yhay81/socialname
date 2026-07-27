#![forbid(unsafe_code)]

use std::{
    fs::File,
    future::Future,
    io::{self, Read},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};
use socialname_canary::{RulePackMetadataVerifier, RulePackRolloutStage, RulePackTrustV1};
use socialname_engine::SearchResult;
use socialname_rule_compiler::RuleCompiler;
use socialname_worker::{
    DeletionProcessOutcome, DeletionStore, DeliveryProcessConfig, DeliveryProcessOutcome,
    DeliverySecrets, DeliveryStore, DeveloperUsageRetentionStore, EmailGatewayConfig,
    ExpandOutcome, JobDisposition, JobExecutionError, JobStore, ManagedEmailGatewayTransport,
    ManagedRule, ManagedWebhookTransport, WatchPlanOutcome, WorkerError, process_one_delivery,
    process_one_email_delivery,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const MAX_RULE_PACK_METADATA_BYTES: usize = 2 * 1_024 * 1_024;
const MAX_RULE_PACK_TRUST_BYTES: usize = 64 * 1_024;
const MAX_INPUT_BYTES: usize = 1_024;

#[derive(Debug, Parser)]
#[command(name = "socialname-worker")]
#[command(about = "Signed-rule-only SocialName managed probe worker")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Execute one explicitly acknowledged managed probe; read the target from stdin JSON.
    Probe(ProbeArgs),
    /// Schedule due watches, expand pending consumers, and execute at most one managed job.
    ProcessOne(ProcessOneArgs),
    /// Claim and attempt at most one queued signed webhook delivery.
    DeliverOne(DeliverOneArgs),
    /// Claim and attempt at most one queued email delivery through the configured HTTPS gateway.
    DeliverEmailOne(DeliverOneArgs),
    /// Purge one bounded batch of Evidence Capsule data whose DB deadline has passed.
    EnforceRetention(EnforceRetentionArgs),
    /// Delete one bounded batch of target-free Developer usage records after 400 days.
    EnforceUsageRetention(EnforceRetentionArgs),
    /// Withdraw support and purge primary data for at most one deletion request.
    ProcessDeletion(ProcessDeletionArgs),
}

#[derive(Debug, Args)]
struct ActivationArgs {
    #[arg(long)]
    site: String,
    #[arg(long)]
    region: String,
    #[arg(long)]
    rules_dir: PathBuf,
    #[arg(long)]
    metadata: PathBuf,
    /// File containing the current public rule-pack trust generation.
    #[arg(long)]
    current_trust_file: PathBuf,
    #[arg(long)]
    minimum_metadata_sequence_exclusive: u64,
}

#[derive(Debug, Args)]
struct ProbeArgs {
    #[command(flatten)]
    activation: ActivationArgs,
    /// Closed deployment identity used by signed canary-stage selection.
    #[arg(long)]
    worker_id: String,
    /// Acknowledge that this command sends one bounded request plan to a third party.
    #[arg(long)]
    allow_live: bool,
}

#[derive(Debug, Args)]
struct ProcessOneArgs {
    #[command(flatten)]
    activation: ActivationArgs,
    /// Closed lowercase label recorded as the lease owner.
    #[arg(long)]
    worker_id: String,
    #[arg(long, default_value_t = 60)]
    lease_seconds: u64,
    #[arg(long, default_value_t = 3)]
    maximum_attempts: u32,
    #[arg(long, default_value_t = 32)]
    expansion_limit: u32,
    /// Acknowledge database mutation and at most one bounded third-party request.
    #[arg(long)]
    allow_live: bool,
}

#[derive(Debug, Args)]
struct DeliverOneArgs {
    /// Closed lowercase label recorded on the fenced delivery attempt.
    #[arg(long)]
    worker_id: String,
    #[arg(long, default_value_t = 15)]
    lease_seconds: u64,
    #[arg(long, default_value_t = 5)]
    maximum_attempts: u32,
    #[arg(long, default_value_t = 10)]
    request_timeout_seconds: u64,
    /// Acknowledge database mutation and at most one bounded webhook request.
    #[arg(long)]
    allow_live: bool,
}

#[derive(Debug, Args)]
struct EnforceRetentionArgs {
    #[arg(long, default_value_t = 128)]
    batch_limit: u32,
    /// Acknowledge irreversible deletion of evidence whose retention deadline has passed.
    #[arg(long)]
    allow_live: bool,
}

#[derive(Debug, Args)]
struct ProcessDeletionArgs {
    /// Closed lowercase label recorded as the fenced deletion lease owner.
    #[arg(long)]
    worker_id: String,
    #[arg(long, default_value_t = 60)]
    lease_seconds: u64,
    /// Acknowledge irreversible deletion of lineage-selected primary data.
    #[arg(long)]
    allow_live: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeInput {
    username: String,
}

#[derive(Serialize)]
struct ProbeOutput<'a> {
    schema: &'static str,
    metadata_id: &'a str,
    metadata_sequence: u64,
    rollout_stage: RulePackRolloutStage,
    promotion_id: &'a str,
    region_class: &'a str,
    result: &'a SearchResult,
}

#[derive(Serialize)]
struct ProcessOneOutput {
    schema: &'static str,
    status: &'static str,
    planned_watch_runs: u32,
    expanded_targets: u32,
    job_id: Option<Uuid>,
    attempt_count: Option<u32>,
}

#[derive(Serialize)]
struct DeliverOneOutput {
    schema: &'static str,
    status: &'static str,
    delivery_id: Option<Uuid>,
    attempt_count: Option<u32>,
}

#[derive(Serialize)]
struct EnforceRetentionOutput {
    schema: &'static str,
    research_excerpts_purged: u32,
    structured_capsules_purged: u32,
    expired_receipts_deleted: u32,
}

#[derive(Serialize)]
struct EnforceUsageRetentionOutput {
    schema: &'static str,
    usage_records_deleted: u32,
}

#[derive(Serialize)]
struct ProcessDeletionOutput {
    schema: &'static str,
    status: &'static str,
    deletion_request_id: Option<Uuid>,
    processing_attempt: Option<u32>,
    matched_resources: Option<u32>,
    recomputed_targets: Option<u32>,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("managed_worker_error={error:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    match Cli::parse().command {
        Command::Probe(args) => probe(args).await,
        Command::ProcessOne(args) => process_one(args).await,
        Command::DeliverOne(args) => deliver_one(args).await,
        Command::DeliverEmailOne(args) => deliver_email_one(args).await,
        Command::EnforceRetention(args) => enforce_retention(args).await,
        Command::EnforceUsageRetention(args) => enforce_usage_retention(args).await,
        Command::ProcessDeletion(args) => process_deletion(args).await,
    }
}

async fn process_deletion(args: ProcessDeletionArgs) -> Result<()> {
    if !args.allow_live {
        bail!("deletion processing requires --allow-live");
    }
    validate_worker_id(&args.worker_id)?;
    if !(5..=300).contains(&args.lease_seconds) {
        bail!("deletion lease must be between 5 and 300 seconds");
    }
    let store = DeletionStore::connect_from_env().await?;
    let outcome = store
        .process_one(&args.worker_id, Duration::from_secs(args.lease_seconds))
        .await;
    store.close().await;
    let output = match outcome? {
        DeletionProcessOutcome::Idle => ProcessDeletionOutput {
            schema: "socialname.dev/deletion-process/v1",
            status: "idle",
            deletion_request_id: None,
            processing_attempt: None,
            matched_resources: None,
            recomputed_targets: None,
        },
        DeletionProcessOutcome::Processed {
            deletion_request_id,
            processing_attempt,
            matched_resources,
            recomputed_targets,
        } => ProcessDeletionOutput {
            schema: "socialname.dev/deletion-process/v1",
            status: "processed",
            deletion_request_id: Some(deletion_request_id),
            processing_attempt: Some(processing_attempt),
            matched_resources: Some(matched_resources),
            recomputed_targets: Some(recomputed_targets),
        },
    };
    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}

async fn enforce_retention(args: EnforceRetentionArgs) -> Result<()> {
    if !args.allow_live {
        bail!("evidence retention enforcement requires --allow-live");
    }
    if !(1..=1_000).contains(&args.batch_limit) {
        bail!("evidence retention batch limit must be between 1 and 1000");
    }
    let store = JobStore::connect_from_env().await?;
    let outcome = store.enforce_evidence_retention(args.batch_limit).await;
    store.close().await;
    let outcome = outcome?;
    println!(
        "{}",
        serde_json::to_string(&EnforceRetentionOutput {
            schema: "socialname.dev/evidence-retention-run/v1",
            research_excerpts_purged: outcome.research_excerpts_purged,
            structured_capsules_purged: outcome.structured_capsules_purged,
            expired_receipts_deleted: outcome.expired_receipts_deleted,
        })?
    );
    Ok(())
}

async fn enforce_usage_retention(args: EnforceRetentionArgs) -> Result<()> {
    if !args.allow_live {
        bail!("Developer usage retention enforcement requires --allow-live");
    }
    if !(1..=1_000).contains(&args.batch_limit) {
        bail!("Developer usage retention batch limit must be between 1 and 1000");
    }
    let store = DeveloperUsageRetentionStore::connect_from_env().await?;
    let outcome = store.enforce(args.batch_limit).await;
    store.close().await;
    let outcome = outcome?;
    println!(
        "{}",
        serde_json::to_string(&EnforceUsageRetentionOutput {
            schema: "socialname.dev/developer-usage-retention-run/v1",
            usage_records_deleted: outcome.usage_records_deleted,
        })?
    );
    Ok(())
}

async fn deliver_one(args: DeliverOneArgs) -> Result<()> {
    if !args.allow_live {
        bail!("webhook delivery requires --allow-live");
    }
    validate_delivery_limits(
        args.lease_seconds,
        args.maximum_attempts,
        args.request_timeout_seconds,
    )?;
    validate_worker_id(&args.worker_id)?;
    let secrets = DeliverySecrets::from_env()?;
    let transport =
        ManagedWebhookTransport::new(Duration::from_secs(args.request_timeout_seconds))?;
    let store = DeliveryStore::connect_from_env().await?;
    let outcome = process_one_delivery(
        &store,
        &secrets,
        &transport,
        DeliveryProcessConfig {
            worker_id: &args.worker_id,
            lease: Duration::from_secs(args.lease_seconds),
            maximum_attempts: args.maximum_attempts,
            timestamp_unix_ms: now_unix_ms()?,
            cancellation: &shutdown_token(),
        },
    )
    .await;
    store.close().await;
    let output = deliver_one_output(outcome?);
    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}

async fn deliver_email_one(args: DeliverOneArgs) -> Result<()> {
    if !args.allow_live {
        bail!("email delivery requires --allow-live");
    }
    validate_delivery_limits(
        args.lease_seconds,
        args.maximum_attempts,
        args.request_timeout_seconds,
    )?;
    validate_worker_id(&args.worker_id)?;
    let secrets = DeliverySecrets::from_email_env()?;
    let gateway = EmailGatewayConfig::from_env()?;
    let transport =
        ManagedEmailGatewayTransport::new(Duration::from_secs(args.request_timeout_seconds))?;
    let store = DeliveryStore::connect_from_env().await?;
    let outcome = process_one_email_delivery(
        &store,
        &secrets,
        &gateway,
        &transport,
        DeliveryProcessConfig {
            worker_id: &args.worker_id,
            lease: Duration::from_secs(args.lease_seconds),
            maximum_attempts: args.maximum_attempts,
            timestamp_unix_ms: now_unix_ms()?,
            cancellation: &shutdown_token(),
        },
    )
    .await;
    store.close().await;
    let output = deliver_email_one_output(outcome?);
    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}

async fn probe(args: ProbeArgs) -> Result<()> {
    if !args.allow_live {
        bail!("live managed probing requires --allow-live");
    }
    validate_worker_id(&args.worker_id)?;
    let input = read_probe_input()?;
    let managed_rule = activate(args.activation, &args.worker_id)?;
    let cancellation = shutdown_token();
    let result = managed_rule
        .execute(&input.username, now_unix_ms()?, &cancellation)
        .await?;
    println!(
        "{}",
        serde_json::to_string(&ProbeOutput {
            schema: "socialname.dev/managed-probe-result/v1",
            metadata_id: managed_rule.metadata_id(),
            metadata_sequence: managed_rule.metadata_sequence(),
            rollout_stage: managed_rule.rollout_stage(),
            promotion_id: managed_rule.promotion_id(),
            region_class: managed_rule.region_class(),
            result: &result,
        })?
    );
    Ok(())
}

async fn process_one(args: ProcessOneArgs) -> Result<()> {
    if !args.allow_live {
        bail!("managed job processing requires --allow-live");
    }
    validate_process_limits(
        args.lease_seconds,
        args.maximum_attempts,
        args.expansion_limit,
    )?;
    validate_worker_id(&args.worker_id)?;
    let managed_rule = activate(args.activation, &args.worker_id)?;
    if !managed_rule.permits_customer_work() {
        bail!("managed customer work requires a signed general or rollback rollout stage");
    }
    let store = JobStore::connect_from_env().await?;
    let outcome = process_one_with_store(
        &store,
        &managed_rule,
        &args.worker_id,
        args.lease_seconds,
        args.maximum_attempts,
        args.expansion_limit,
    )
    .await;
    store.close().await;
    println!("{}", serde_json::to_string(&outcome?)?);
    Ok(())
}

async fn process_one_with_store(
    store: &JobStore,
    managed_rule: &ManagedRule,
    worker_id: &str,
    lease_seconds: u64,
    maximum_attempts: u32,
    expansion_limit: u32,
) -> Result<ProcessOneOutput> {
    let binding = store.bind_rule(managed_rule).await?;
    let planned_watch_runs = match store.plan_one_watch(&binding).await? {
        WatchPlanOutcome::Idle => 0,
        WatchPlanOutcome::Planned { .. } => 1,
    };
    let mut expanded_targets = 0_u32;
    let mut prefer_watch = true;
    while expanded_targets < expansion_limit {
        let first = if prefer_watch {
            store.expand_one_watch(&binding, managed_rule).await?
        } else {
            store.expand_one(&binding, managed_rule).await?
        };
        let outcome = if first == ExpandOutcome::Idle {
            if prefer_watch {
                store.expand_one(&binding, managed_rule).await?
            } else {
                store.expand_one_watch(&binding, managed_rule).await?
            }
        } else {
            first
        };
        if outcome == ExpandOutcome::Idle {
            break;
        }
        expanded_targets += 1;
        prefer_watch = !prefer_watch;
    }
    let Some(claim) = store
        .claim(&binding, worker_id, Duration::from_secs(lease_seconds))
        .await?
    else {
        return Ok(ProcessOneOutput {
            schema: "socialname.dev/managed-job-process/v1",
            status: "idle",
            planned_watch_runs,
            expanded_targets,
            job_id: None,
            attempt_count: None,
        });
    };
    let job_id = claim.job_id();
    let attempt_count = claim.attempt_count();
    let disposition = if attempt_count > maximum_attempts {
        store
            .record_capacity_unavailable(&claim, maximum_attempts)
            .await?
    } else {
        let shutdown = shutdown_token();
        match store
            .execute_claim(&claim, managed_rule, now_unix_ms()?, &shutdown)
            .await
        {
            Ok(result) => {
                store
                    .record_result(&claim, &result, maximum_attempts)
                    .await?
            }
            Err(JobExecutionError::Worker(WorkerError::Cancelled))
            | Err(JobExecutionError::Cancelled) => {
                bail!("managed job execution was cancelled; its lease will expire safely");
            }
            Err(JobExecutionError::AuthorizationRevoked) => {
                store.record_authorization_revoked(&claim).await?
            }
            Err(JobExecutionError::TargetSuppressed) => {
                store.record_target_suppressed(&claim).await?
            }
            Err(JobExecutionError::AuthorizationUnavailable) => {
                bail!(
                    "managed job authorization could not be rechecked; its lease will expire safely"
                );
            }
            Err(JobExecutionError::Worker(_)) => {
                store
                    .record_rule_unavailable(&claim, maximum_attempts)
                    .await?
            }
        }
    };
    Ok(ProcessOneOutput {
        schema: "socialname.dev/managed-job-process/v1",
        status: disposition_name(disposition),
        planned_watch_runs,
        expanded_targets,
        job_id: Some(job_id),
        attempt_count: Some(attempt_count),
    })
}

fn activate(args: ActivationArgs, worker_id: &str) -> Result<ManagedRule> {
    let compiler = RuleCompiler::new();
    let rules = compiler
        .load_directory(&args.rules_dir)
        .map_err(|_| anyhow::anyhow!("rule directory failed strict validation"))?;
    let candidate = rules
        .iter()
        .find(|candidate| candidate.source.id == args.site)
        .context("configured site is absent from the validated rule directory")?;
    let rule_pack = compiler
        .compile_pack(&rules)
        .map_err(|_| anyhow::anyhow!("rule pack failed canonical compilation"))?;
    let trust = load_rule_pack_trust(&args.current_trust_file)?;
    let metadata = read_bounded_file(
        &args.metadata,
        MAX_RULE_PACK_METADATA_BYTES,
        "rule-pack metadata",
    )?;
    let verified_at_unix_ms = now_unix_ms()?;
    let validated = RulePackMetadataVerifier::new()
        .validate_json_at(&metadata, &trust, verified_at_unix_ms)
        .map_err(|_| anyhow::anyhow!("rule-pack metadata failed the configured trust policy"))?;
    if validated.metadata().sequence <= args.minimum_metadata_sequence_exclusive {
        bail!("rule-pack metadata sequence is not above the configured high-water mark");
    }
    if validated.metadata().rule_pack_hash != rule_pack.content_hash
        || validated
            .promotion(&args.site)
            .is_none_or(|promotion| promotion.promotion().rule_hash != candidate.rule_hash)
    {
        bail!("rule-pack metadata does not match the configured site and pack");
    }
    ManagedRule::activate(
        &validated,
        &rule_pack,
        &args.site,
        args.region,
        worker_id,
        verified_at_unix_ms,
    )
    .map_err(Into::into)
}

fn shutdown_token() -> CancellationToken {
    let cancellation = CancellationToken::new();
    let cancellation_signal = cancellation.clone();
    tokio::spawn(cancel_when_signalled(
        cancellation_signal,
        shutdown_signal(),
    ));
    cancellation
}

async fn cancel_when_signalled(cancellation: CancellationToken, signal: impl Future<Output = ()>) {
    signal.await;
    cancellation.cancel();
}

#[cfg(unix)]
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    match signal(SignalKind::terminate()) {
        Ok(mut terminate) => {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            }
        }
        Err(_) => {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

fn validate_process_limits(
    lease_seconds: u64,
    maximum_attempts: u32,
    expansion_limit: u32,
) -> Result<()> {
    if !(5..=300).contains(&lease_seconds) {
        bail!("lease seconds must be between 5 and 300");
    }
    if !(1..=10).contains(&maximum_attempts) {
        bail!("maximum attempts must be between 1 and 10");
    }
    if !(1..=128).contains(&expansion_limit) {
        bail!("expansion limit must be between 1 and 128");
    }
    Ok(())
}

fn validate_delivery_limits(
    lease_seconds: u64,
    maximum_attempts: u32,
    request_timeout_seconds: u64,
) -> Result<()> {
    if !(1..=30).contains(&lease_seconds) {
        bail!("delivery lease seconds must be between 1 and 30");
    }
    if !(1..=10).contains(&maximum_attempts) {
        bail!("maximum attempts must be between 1 and 10");
    }
    if !(1..=30).contains(&request_timeout_seconds) || request_timeout_seconds >= lease_seconds {
        bail!("request timeout must be positive and shorter than the delivery lease");
    }
    Ok(())
}

fn validate_worker_id(worker_id: &str) -> Result<()> {
    let mut characters = worker_id.chars();
    if !matches!(characters.next(), Some('a'..='z' | '0'..='9'))
        || worker_id.len() > 64
        || !characters.all(|character| matches!(character, 'a'..='z' | '0'..='9' | '-'))
    {
        bail!("worker ID must be a closed lowercase label");
    }
    Ok(())
}

const fn disposition_name(disposition: JobDisposition) -> &'static str {
    match disposition {
        JobDisposition::Succeeded => "succeeded",
        JobDisposition::RetryScheduled => "retry_scheduled",
        JobDisposition::Failed => "failed",
        JobDisposition::Cancelled => "cancelled",
        JobDisposition::AlreadyFinal => "already_final",
    }
}

const fn deliver_one_output(outcome: DeliveryProcessOutcome) -> DeliverOneOutput {
    delivery_output(outcome, "socialname.dev/webhook-delivery-process/v1")
}

const fn deliver_email_one_output(outcome: DeliveryProcessOutcome) -> DeliverOneOutput {
    delivery_output(outcome, "socialname.dev/email-delivery-process/v1")
}

const fn delivery_output(
    outcome: DeliveryProcessOutcome,
    schema: &'static str,
) -> DeliverOneOutput {
    match outcome {
        DeliveryProcessOutcome::Idle => DeliverOneOutput {
            schema,
            status: "idle",
            delivery_id: None,
            attempt_count: None,
        },
        DeliveryProcessOutcome::Delivered {
            delivery_id,
            attempt_count,
        } => DeliverOneOutput {
            schema,
            status: "delivered",
            delivery_id: Some(delivery_id),
            attempt_count: Some(attempt_count),
        },
        DeliveryProcessOutcome::RetryScheduled {
            delivery_id,
            attempt_count,
        } => DeliverOneOutput {
            schema,
            status: "retry_scheduled",
            delivery_id: Some(delivery_id),
            attempt_count: Some(attempt_count),
        },
        DeliveryProcessOutcome::PermanentlyFailed {
            delivery_id,
            attempt_count,
        } => DeliverOneOutput {
            schema,
            status: "permanently_failed",
            delivery_id: Some(delivery_id),
            attempt_count: Some(attempt_count),
        },
        DeliveryProcessOutcome::Cancelled {
            delivery_id,
            attempt_count,
        } => DeliverOneOutput {
            schema,
            status: "cancelled",
            delivery_id: Some(delivery_id),
            attempt_count: Some(attempt_count),
        },
    }
}

fn read_probe_input() -> Result<ProbeInput> {
    let mut bytes = Vec::new();
    io::stdin()
        .take(u64::try_from(MAX_INPUT_BYTES + 1).expect("input limit fits u64"))
        .read_to_end(&mut bytes)
        .context("failed to read managed probe input")?;
    if bytes.len() > MAX_INPUT_BYTES {
        bail!("managed probe input exceeds its byte limit");
    }
    parse_probe_input(&bytes)
}

fn parse_probe_input(bytes: &[u8]) -> Result<ProbeInput> {
    let input: ProbeInput =
        serde_json::from_slice(bytes).context("managed probe input is not closed JSON")?;
    if input.username.is_empty()
        || input.username.len() > 256
        || input.username.chars().any(char::is_control)
    {
        bail!("managed probe username is invalid");
    }
    Ok(input)
}

fn load_rule_pack_trust(path: &Path) -> Result<RulePackTrustV1> {
    let bytes = read_bounded_file(path, MAX_RULE_PACK_TRUST_BYTES, "rule-pack trust file")?;
    parse_rule_pack_trust(&bytes)
}

fn parse_rule_pack_trust(bytes: &[u8]) -> Result<RulePackTrustV1> {
    serde_json::from_slice(bytes).map_err(|_| anyhow::anyhow!("rule-pack trust file is malformed"))
}

fn read_bounded_file(path: &Path, limit: usize, label: &str) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("failed to open {label}"))?;
    let mut bytes = Vec::new();
    file.take(u64::try_from(limit + 1).expect("file limit fits u64"))
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {label}"))?;
    if bytes.len() > limit {
        bail!("{label} exceeds its byte limit");
    }
    Ok(bytes)
}

fn now_unix_ms() -> Result<i64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?;
    i64::try_from(duration.as_millis()).context("system clock exceeds the supported range")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stdin_contract_is_closed_bounded_and_does_not_echo_invalid_targets() {
        let input = parse_probe_input(br#"{"username":"valid-target"}"#).unwrap();
        assert_eq!(input.username, "valid-target");
        assert!(
            parse_probe_input(br#"{"username":"valid","url":"https://example.test"}"#).is_err()
        );

        let private_target = "private-target-that-must-not-appear\n";
        let error = parse_probe_input(
            serde_json::to_string(&serde_json::json!({ "username": private_target }))
                .unwrap()
                .as_bytes(),
        )
        .err()
        .unwrap();
        assert!(!error.to_string().contains(private_target));
        assert!(!format!("{error:?}").contains(private_target));
    }

    #[test]
    fn trust_file_contract_is_closed_and_redacted() {
        let source = serde_json::to_vec(&serde_json::json!({
            "schema": "socialname.dev/rule-pack-trust/v1",
            "generation": 1,
            "threshold": 1,
            "keys": {
                "release-key": "07".repeat(32),
            },
            "expires_at_unix_ms": 9_999_999,
        }))
        .unwrap();
        let trust = parse_rule_pack_trust(&source).unwrap();
        assert_eq!(trust.generation, 1);
        assert_eq!(trust.keys.len(), 1);

        let mut unknown: serde_json::Value = serde_json::from_slice(&source).unwrap();
        unknown["unexpected"] = serde_json::json!(true);
        assert!(parse_rule_pack_trust(&serde_json::to_vec(&unknown).unwrap()).is_err());

        let invalid = "private-key-material-must-not-appear";
        let error = parse_rule_pack_trust(invalid.as_bytes()).unwrap_err();
        assert!(!error.to_string().contains(invalid));
        assert!(!format!("{error:?}").contains(invalid));
    }

    #[test]
    fn process_limits_are_closed_and_bounded() {
        assert!(validate_process_limits(5, 1, 1).is_ok());
        assert!(validate_process_limits(300, 10, 128).is_ok());
        assert!(validate_process_limits(4, 1, 1).is_err());
        assert!(validate_process_limits(5, 11, 1).is_err());
        assert!(validate_process_limits(5, 1, 129).is_err());
        assert!(validate_worker_id("worker-jp-1").is_ok());
        assert!(validate_worker_id("").is_err());
        assert!(validate_worker_id("Worker").is_err());
        assert!(validate_worker_id("worker_private").is_err());
        assert!(validate_delivery_limits(15, 5, 10).is_ok());
        assert!(validate_delivery_limits(10, 5, 10).is_err());
        assert!(validate_delivery_limits(31, 5, 10).is_err());
    }

    #[test]
    fn process_output_is_target_free() {
        let output = serde_json::to_string(&ProcessOneOutput {
            schema: "socialname.dev/managed-job-process/v1",
            status: disposition_name(JobDisposition::RetryScheduled),
            planned_watch_runs: 1,
            expanded_targets: 2,
            job_id: Some(Uuid::nil()),
            attempt_count: Some(1),
        })
        .unwrap();
        assert_eq!(
            output,
            "{\"schema\":\"socialname.dev/managed-job-process/v1\",\"status\":\"retry_scheduled\",\"planned_watch_runs\":1,\"expanded_targets\":2,\"job_id\":\"00000000-0000-0000-0000-000000000000\",\"attempt_count\":1}"
        );
        assert!(!output.contains("username"));
        assert!(!output.contains("result"));

        let delivery = serde_json::to_string(&deliver_one_output(
            DeliveryProcessOutcome::RetryScheduled {
                delivery_id: Uuid::nil(),
                attempt_count: 1,
            },
        ))
        .unwrap();
        assert_eq!(
            delivery,
            "{\"schema\":\"socialname.dev/webhook-delivery-process/v1\",\"status\":\"retry_scheduled\",\"delivery_id\":\"00000000-0000-0000-0000-000000000000\",\"attempt_count\":1}"
        );
        assert!(!delivery.contains("destination"));
        let email_delivery = serde_json::to_string(&deliver_email_one_output(
            DeliveryProcessOutcome::Delivered {
                delivery_id: Uuid::nil(),
                attempt_count: 2,
            },
        ))
        .unwrap();
        assert_eq!(
            email_delivery,
            "{\"schema\":\"socialname.dev/email-delivery-process/v1\",\"status\":\"delivered\",\"delivery_id\":\"00000000-0000-0000-0000-000000000000\",\"attempt_count\":2}"
        );
        assert!(!email_delivery.contains("address"));

        let retention = serde_json::to_string(&EnforceRetentionOutput {
            schema: "socialname.dev/evidence-retention-run/v1",
            research_excerpts_purged: 1,
            structured_capsules_purged: 2,
            expired_receipts_deleted: 3,
        })
        .unwrap();
        assert_eq!(
            retention,
            "{\"schema\":\"socialname.dev/evidence-retention-run/v1\",\"research_excerpts_purged\":1,\"structured_capsules_purged\":2,\"expired_receipts_deleted\":3}"
        );
        assert!(!retention.contains("target"));
        assert!(!retention.contains("username"));
        assert!(!retention.contains("payload"));

        let usage_retention = serde_json::to_string(&EnforceUsageRetentionOutput {
            schema: "socialname.dev/developer-usage-retention-run/v1",
            usage_records_deleted: 4,
        })
        .unwrap();
        assert_eq!(
            usage_retention,
            "{\"schema\":\"socialname.dev/developer-usage-retention-run/v1\",\"usage_records_deleted\":4}"
        );
        assert!(!usage_retention.contains("target"));
        assert!(!usage_retention.contains("username"));
        assert!(!usage_retention.contains("search_id"));
    }

    #[test]
    fn usage_retention_command_has_a_closed_bounded_shape() {
        let cli = Cli::try_parse_from([
            "socialname-worker",
            "enforce-usage-retention",
            "--batch-limit",
            "1000",
            "--allow-live",
        ])
        .unwrap();
        let Command::EnforceUsageRetention(args) = cli.command else {
            panic!("expected Developer usage retention command");
        };
        assert_eq!(args.batch_limit, 1000);
        assert!(args.allow_live);
    }

    #[test]
    fn email_delivery_command_has_a_closed_one_shot_shape() {
        let cli = Cli::try_parse_from([
            "socialname-worker",
            "deliver-email-one",
            "--worker-id",
            "email-worker",
            "--lease-seconds",
            "15",
            "--maximum-attempts",
            "5",
            "--request-timeout-seconds",
            "10",
            "--allow-live",
        ])
        .unwrap();
        let Command::DeliverEmailOne(args) = cli.command else {
            panic!("expected email delivery command");
        };
        assert_eq!(args.worker_id, "email-worker");
        assert_eq!(args.lease_seconds, 15);
        assert_eq!(args.maximum_attempts, 5);
        assert_eq!(args.request_timeout_seconds, 10);
        assert!(args.allow_live);
    }

    #[tokio::test]
    async fn shutdown_signal_cancels_the_shared_token() {
        let cancellation = CancellationToken::new();
        cancel_when_signalled(cancellation.clone(), std::future::ready(())).await;
        assert!(cancellation.is_cancelled());
    }
}
