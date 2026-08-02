use std::{env, time::Duration};

use sqlx::{PgPool, migrate::Migrator, postgres::PgPoolOptions};
use thiserror::Error;

pub const DATABASE_URL_ENV: &str = "SOCIALNAME_DATABASE_URL";
pub const RUNTIME_DATABASE_URL_ENV: &str = "SOCIALNAME_SERVER_DATABASE_URL";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MIGRATION_TIMEOUT: Duration = Duration::from_secs(60);
const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);
const RUNTIME_MAXIMUM_CONNECTIONS: u32 = 16;

pub static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum DatabaseError {
    #[error("{0} is required")]
    MissingUrl(&'static str),
    #[error("{0} must contain valid Unicode")]
    InvalidUrlEncoding(&'static str),
    #[error("database connection timed out")]
    ConnectionTimedOut,
    #[error("database connection failed")]
    ConnectionFailed,
    #[error("database migration timed out")]
    MigrationTimedOut,
    #[error("database migration failed")]
    MigrationFailed,
}

pub async fn migrate_database_from_env() -> Result<(), DatabaseError> {
    let database_url = database_url_from_env(DATABASE_URL_ENV)?;
    migrate_database(&database_url).await
}

pub async fn connect_runtime_database_from_env() -> Result<PgPool, DatabaseError> {
    let database_url = database_url_from_env(RUNTIME_DATABASE_URL_ENV)?;
    connect_database(&database_url, RUNTIME_MAXIMUM_CONNECTIONS).await
}

/// Builds the runtime pool without requiring PostgreSQL to be reachable during
/// process startup. The public liveness endpoint can therefore come up while a
/// scale-to-zero database resumes; readiness and every product operation still
/// fail closed until a real connection succeeds.
pub fn connect_runtime_database_lazy_from_env() -> Result<PgPool, DatabaseError> {
    let database_url = database_url_from_env(RUNTIME_DATABASE_URL_ENV)?;
    connect_database_lazy(&database_url, RUNTIME_MAXIMUM_CONNECTIONS)
}

pub async fn migrate_database(database_url: &str) -> Result<(), DatabaseError> {
    if database_url.is_empty() {
        return Err(DatabaseError::MissingUrl(DATABASE_URL_ENV));
    }

    let pool = connect_database(database_url, 1).await?;

    let migration_result = tokio::time::timeout(MIGRATION_TIMEOUT, MIGRATOR.run(&pool))
        .await
        .map_err(|_| DatabaseError::MigrationTimedOut)?
        .map_err(|_| DatabaseError::MigrationFailed);
    pool.close().await;
    migration_result
}

pub(crate) async fn connect_database(
    database_url: &str,
    maximum_connections: u32,
) -> Result<PgPool, DatabaseError> {
    if database_url.is_empty() {
        return Err(DatabaseError::MissingUrl(DATABASE_URL_ENV));
    }
    tokio::time::timeout(
        CONNECT_TIMEOUT,
        PgPoolOptions::new()
            .max_connections(maximum_connections)
            .acquire_timeout(ACQUIRE_TIMEOUT)
            .connect(database_url),
    )
    .await
    .map_err(|_| DatabaseError::ConnectionTimedOut)?
    .map_err(|_| DatabaseError::ConnectionFailed)
}

fn connect_database_lazy(
    database_url: &str,
    maximum_connections: u32,
) -> Result<PgPool, DatabaseError> {
    if database_url.is_empty() {
        return Err(DatabaseError::MissingUrl(RUNTIME_DATABASE_URL_ENV));
    }
    PgPoolOptions::new()
        .max_connections(maximum_connections)
        .acquire_timeout(ACQUIRE_TIMEOUT)
        .connect_lazy(database_url)
        .map_err(|_| DatabaseError::ConnectionFailed)
}

pub(crate) fn database_url_from_env(variable: &'static str) -> Result<String, DatabaseError> {
    let value = env::var(variable).map_err(|error| match error {
        env::VarError::NotPresent => DatabaseError::MissingUrl(variable),
        env::VarError::NotUnicode(_) => DatabaseError::InvalidUrlEncoding(variable),
    })?;
    if value.is_empty() {
        Err(DatabaseError::MissingUrl(variable))
    } else {
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_database_url_is_rejected_without_echoing_it() {
        let error = migrate_database("").await.unwrap_err();
        assert_eq!(error, DatabaseError::MissingUrl(DATABASE_URL_ENV));
        assert!(!error.to_string().contains("postgres"));
    }

    #[tokio::test]
    async fn failed_connection_does_not_echo_credentials() {
        let secret = "credential-that-must-not-leak";
        let database_url = format!("postgres://user:{secret}@127.0.0.1:not-a-port/database");
        let error = migrate_database(&database_url).await.unwrap_err();
        assert_eq!(error, DatabaseError::ConnectionFailed);
        assert!(!error.to_string().contains(secret));
        assert!(!format!("{error:?}").contains(secret));
    }

    #[tokio::test]
    async fn lazy_runtime_pool_does_not_require_database_availability() {
        let pool = connect_database_lazy(
            "postgres://unused:unused@127.0.0.1:1/unused",
            RUNTIME_MAXIMUM_CONNECTIONS,
        )
        .expect("a valid runtime URL builds a lazy pool without network I/O");
        pool.close().await;
    }

    #[test]
    fn lazy_runtime_pool_rejects_empty_and_malformed_urls() {
        assert_eq!(
            connect_database_lazy("", RUNTIME_MAXIMUM_CONNECTIONS).unwrap_err(),
            DatabaseError::MissingUrl(RUNTIME_DATABASE_URL_ENV)
        );
        assert_eq!(
            connect_database_lazy("not a postgres URL", RUNTIME_MAXIMUM_CONNECTIONS).unwrap_err(),
            DatabaseError::ConnectionFailed
        );
    }
}
