use std::{env, error::Error, ffi::OsString, future};

use socialname_server::{
    ServerConfig, apply_rule_pack_metadata_from_env, bootstrap_workspace_from_env,
    connect_runtime_database_from_env, export_restore_ledger_from_env, issue_api_key_from_env,
    migrate_database_from_env, replay_restore_ledger_from_env, request_target_deletion_from_env,
    revoke_api_key_from_env, set_developer_quota_from_env, verify_backup_expiry_from_env,
};
use thiserror::Error;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    initialize_tracing();
    match command_from_args(env::args_os())? {
        Command::Serve => run_server().await?,
        Command::Migrate => migrate_database_from_env().await?,
        Command::BootstrapWorkspace => {
            bootstrap_workspace_from_env()
                .await?
                .write_once_to_stdout()?;
        }
        Command::IssueApiKey => {
            issue_api_key_from_env().await?.write_once_to_stdout()?;
        }
        Command::RevokeApiKey => {
            let api_key_id = revoke_api_key_from_env().await?;
            println!("api_key_id={api_key_id}");
            println!("state=revoked");
        }
        Command::SetDeveloperQuota => {
            set_developer_quota_from_env().await?.write_to_stdout()?;
        }
        Command::ApplyRulePack => {
            let applied = apply_rule_pack_metadata_from_env().await?;
            println!("{}", serde_json::to_string(&applied.output())?);
        }
        Command::RequestTargetDeletion => {
            let output = request_target_deletion_from_env().await?;
            println!("{}", serde_json::to_string(&output)?);
        }
        Command::VerifyBackupExpiry => {
            let output = verify_backup_expiry_from_env().await?;
            println!("{}", serde_json::to_string(&output)?);
        }
        Command::ExportRestoreLedger => {
            let output = export_restore_ledger_from_env().await?;
            println!("{}", serde_json::to_string(&output)?);
        }
        Command::ReplayRestoreLedger => {
            let output = replay_restore_ledger_from_env().await?;
            println!("{}", serde_json::to_string(&output)?);
        }
    }
    Ok(())
}

async fn run_server() -> Result<(), Box<dyn Error>> {
    let config = ServerConfig::from_env()?;
    let database = connect_runtime_database_from_env().await?;
    let listener = tokio::net::TcpListener::bind(config.bind_address()).await?;
    let local_address = listener.local_addr()?;
    tracing::info!(bind_address = %local_address, "socialname server listening");
    socialname_server::serve(listener, config, database, shutdown_signal()).await?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Command {
    Serve,
    Migrate,
    BootstrapWorkspace,
    IssueApiKey,
    RevokeApiKey,
    SetDeveloperQuota,
    ApplyRulePack,
    RequestTargetDeletion,
    VerifyBackupExpiry,
    ExportRestoreLedger,
    ReplayRestoreLedger,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("expected no arguments or a supported operator command")]
struct CommandError;

fn command_from_args(args: impl IntoIterator<Item = OsString>) -> Result<Command, CommandError> {
    let mut args = args.into_iter();
    let _executable = args.next();
    match (args.next(), args.next()) {
        (None, None) => Ok(Command::Serve),
        (Some(argument), None) if argument == "migrate" => Ok(Command::Migrate),
        (Some(argument), None) if argument == "bootstrap-workspace" => {
            Ok(Command::BootstrapWorkspace)
        }
        (Some(argument), None) if argument == "issue-api-key" => Ok(Command::IssueApiKey),
        (Some(argument), None) if argument == "revoke-api-key" => Ok(Command::RevokeApiKey),
        (Some(argument), None) if argument == "set-developer-quota" => {
            Ok(Command::SetDeveloperQuota)
        }
        (Some(argument), None) if argument == "apply-rule-pack" => Ok(Command::ApplyRulePack),
        (Some(argument), None) if argument == "request-target-deletion" => {
            Ok(Command::RequestTargetDeletion)
        }
        (Some(argument), None) if argument == "verify-backup-expiry" => {
            Ok(Command::VerifyBackupExpiry)
        }
        (Some(argument), None) if argument == "export-restore-ledger" => {
            Ok(Command::ExportRestoreLedger)
        }
        (Some(argument), None) if argument == "replay-restore-ledger" => {
            Ok(Command::ReplayRestoreLedger)
        }
        _ => Err(CommandError),
    }
}

fn initialize_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %error, "failed to register Ctrl-C handler");
            future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                tracing::error!(error = %error, "failed to register termination handler");
                future::pending::<()>().await;
            }
        }
    };

    #[cfg(unix)]
    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }

    #[cfg(not(unix))]
    ctrl_c.await;

    tracing::info!("shutdown signal received");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn exact_supported_commands_are_closed() {
        assert_eq!(command_from_args(args(&["server"])), Ok(Command::Serve));
        for (name, expected) in [
            ("migrate", Command::Migrate),
            ("bootstrap-workspace", Command::BootstrapWorkspace),
            ("issue-api-key", Command::IssueApiKey),
            ("revoke-api-key", Command::RevokeApiKey),
            ("set-developer-quota", Command::SetDeveloperQuota),
            ("apply-rule-pack", Command::ApplyRulePack),
            ("request-target-deletion", Command::RequestTargetDeletion),
            ("verify-backup-expiry", Command::VerifyBackupExpiry),
            ("export-restore-ledger", Command::ExportRestoreLedger),
            ("replay-restore-ledger", Command::ReplayRestoreLedger),
        ] {
            assert_eq!(command_from_args(args(&["server", name])), Ok(expected));
        }
    }

    #[test]
    fn unknown_or_extra_arguments_are_rejected_without_reflection() {
        for values in [
            &["server", "secret-value"][..],
            &["server", "migrate", "secret-value"][..],
        ] {
            let error = command_from_args(args(values)).unwrap_err();
            assert!(!error.to_string().contains("secret-value"));
            assert!(!format!("{error:?}").contains("secret-value"));
        }
    }
}
