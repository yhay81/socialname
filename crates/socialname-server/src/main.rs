use std::{env, error::Error, ffi::OsString, future};

use socialname_server::{ServerConfig, migrate_database_from_env};
use thiserror::Error;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    initialize_tracing();
    match command_from_args(env::args_os())? {
        Command::Serve => run_server().await?,
        Command::Migrate => migrate_database_from_env().await?,
    }
    Ok(())
}

async fn run_server() -> Result<(), Box<dyn Error>> {
    let config = ServerConfig::from_env()?;
    let listener = tokio::net::TcpListener::bind(config.bind_address()).await?;
    let local_address = listener.local_addr()?;
    tracing::info!(bind_address = %local_address, "socialname server listening");
    socialname_server::serve(listener, config, shutdown_signal()).await?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Command {
    Serve,
    Migrate,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("expected no arguments or exactly `migrate`")]
struct CommandError;

fn command_from_args(args: impl IntoIterator<Item = OsString>) -> Result<Command, CommandError> {
    let mut args = args.into_iter();
    let _executable = args.next();
    match (args.next(), args.next()) {
        (None, None) => Ok(Command::Serve),
        (Some(argument), None) if argument == "migrate" => Ok(Command::Migrate),
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
    fn no_subcommand_serves_and_exact_migrate_runs_migrations() {
        assert_eq!(command_from_args(args(&["server"])), Ok(Command::Serve));
        assert_eq!(
            command_from_args(args(&["server", "migrate"])),
            Ok(Command::Migrate)
        );
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
