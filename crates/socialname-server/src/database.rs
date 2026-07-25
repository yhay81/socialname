use std::{env, time::Duration};

use sqlx::{migrate::Migrator, postgres::PgPoolOptions};
use thiserror::Error;

pub const DATABASE_URL_ENV: &str = "SOCIALNAME_DATABASE_URL";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MIGRATION_TIMEOUT: Duration = Duration::from_secs(60);

pub static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum DatabaseError {
    #[error("{DATABASE_URL_ENV} is required to run database migrations")]
    MissingUrl,
    #[error("{DATABASE_URL_ENV} must contain valid Unicode")]
    InvalidUrlEncoding,
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
    let database_url = env::var(DATABASE_URL_ENV).map_err(|error| match error {
        env::VarError::NotPresent => DatabaseError::MissingUrl,
        env::VarError::NotUnicode(_) => DatabaseError::InvalidUrlEncoding,
    })?;
    migrate_database(&database_url).await
}

pub async fn migrate_database(database_url: &str) -> Result<(), DatabaseError> {
    if database_url.is_empty() {
        return Err(DatabaseError::MissingUrl);
    }

    let pool = tokio::time::timeout(
        CONNECT_TIMEOUT,
        PgPoolOptions::new()
            .max_connections(1)
            .connect(database_url),
    )
    .await
    .map_err(|_| DatabaseError::ConnectionTimedOut)?
    .map_err(|_| DatabaseError::ConnectionFailed)?;

    let migration_result = tokio::time::timeout(MIGRATION_TIMEOUT, MIGRATOR.run(&pool))
        .await
        .map_err(|_| DatabaseError::MigrationTimedOut)?
        .map_err(|_| DatabaseError::MigrationFailed);
    pool.close().await;
    migration_result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_database_url_is_rejected_without_echoing_it() {
        let error = migrate_database("").await.unwrap_err();
        assert_eq!(error, DatabaseError::MissingUrl);
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
}
