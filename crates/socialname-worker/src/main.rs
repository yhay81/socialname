#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};
use socialname_canary::{PromotionTrustPolicy, PromotionVerifier};
use socialname_engine::SearchResult;
use socialname_rule_compiler::RuleCompiler;
use socialname_worker::ManagedRule;
use tokio_util::sync::CancellationToken;

const MAX_PROMOTION_BYTES: usize = 256 * 1_024;
const MAX_KEY_FILE_BYTES: usize = 1_024;
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
}

#[derive(Debug, Args)]
struct ProbeArgs {
    #[arg(long)]
    site: String,
    #[arg(long)]
    region: String,
    #[arg(long)]
    rules_dir: PathBuf,
    #[arg(long)]
    promotion: PathBuf,
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
    /// File containing one trusted 32-byte Ed25519 public key as 64 hexadecimal characters.
    #[arg(long)]
    verifying_key_file: PathBuf,
    /// Acknowledge that this command sends one bounded request plan to a third party.
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
    promotion_id: &'a str,
    region_class: &'a str,
    result: &'a SearchResult,
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
    }
}

async fn probe(args: ProbeArgs) -> Result<()> {
    if !args.allow_live {
        bail!("live managed probing requires --allow-live");
    }
    let input = read_probe_input()?;
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
    let verifying_key = load_verifying_key(&args.verifying_key_file)?;
    let promotion = read_bounded_file(&args.promotion, MAX_PROMOTION_BYTES, "promotion artifact")?;
    let verified_at_unix_ms = now_unix_ms()?;
    let validated = PromotionVerifier::new()
        .validate_json_at(
            &promotion,
            &PromotionTrustPolicy {
                trusted_keys: BTreeMap::from([(args.key_id, verifying_key)]),
                expected_site_id: args.site,
                expected_rule_hash: candidate.rule_hash.clone(),
                expected_rule_pack_hash: rule_pack.content_hash.clone(),
                expected_previous_rule_pack_hash: args.previous_rule_pack_hash,
                expected_manifest_hash: args.manifest_hash,
                expected_engine_hash: args.engine_hash,
                required_regions: args.required_regions.into_iter().collect::<BTreeSet<_>>(),
                minimum_sequence_exclusive: args.minimum_sequence_exclusive,
            },
            verified_at_unix_ms,
        )
        .map_err(|_| anyhow::anyhow!("promotion failed the configured trust policy"))?;
    let managed_rule =
        ManagedRule::activate(&validated, &rule_pack, args.region, verified_at_unix_ms)?;
    let cancellation = CancellationToken::new();
    let cancellation_signal = cancellation.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            cancellation_signal.cancel();
        }
    });
    let result = managed_rule
        .execute(&input.username, now_unix_ms()?, &cancellation)
        .await?;
    println!(
        "{}",
        serde_json::to_string(&ProbeOutput {
            schema: "socialname.dev/managed-probe-result/v1",
            promotion_id: managed_rule.promotion_id(),
            region_class: managed_rule.region_class(),
            result: &result,
        })?
    );
    Ok(())
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

fn load_verifying_key(path: &Path) -> Result<[u8; 32]> {
    let bytes = read_bounded_file(path, MAX_KEY_FILE_BYTES, "verifying-key file")?;
    parse_verifying_key(&bytes)
}

fn parse_verifying_key(bytes: &[u8]) -> Result<[u8; 32]> {
    let encoded =
        std::str::from_utf8(bytes).context("verifying-key file must contain UTF-8 hexadecimal")?;
    let decoded =
        hex::decode(encoded.trim()).context("verifying-key file must contain hexadecimal")?;
    decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("verifying-key file must contain exactly 32 bytes"))
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
    fn verifying_key_contract_is_exact_and_redacted() {
        assert_eq!(
            parse_verifying_key(b"07")
                .unwrap_err()
                .root_cause()
                .to_string(),
            "verifying-key file must contain exactly 32 bytes"
        );
        let key = parse_verifying_key(
            b"0707070707070707070707070707070707070707070707070707070707070707",
        )
        .unwrap();
        assert_eq!(key, [7; 32]);

        let invalid = "private-key-material-is-not-hex";
        let error = parse_verifying_key(invalid.as_bytes()).unwrap_err();
        assert!(!error.to_string().contains(invalid));
        assert!(!format!("{error:?}").contains(invalid));
    }
}
