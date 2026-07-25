#![forbid(unsafe_code)]

use std::{path::Path, str::FromStr, time::Duration};

use sqlx::{
    SqlitePool,
    migrate::Migrator,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions, SqliteSynchronous},
};

mod eligibility;
mod observation_store;

pub use eligibility::{CacheEligibilityQuery, CacheVerdictPolicy, MAX_ELIGIBLE_OBSERVATIONS};
pub use observation_store::{CacheMetadata, CachedObservation, StoreOutcome};

pub const CACHE_APPLICATION_ID: i64 = 1_397_637_453;
pub const CURRENT_SCHEMA_VERSION: i64 = 1;

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

#[derive(Clone, Debug)]
pub struct LocalCache {
    pool: SqlitePool,
}

impl LocalCache {
    pub async fn open(path: impl AsRef<Path>) -> Result<Self, CacheError> {
        let path = path.as_ref();
        if path.as_os_str().is_empty() {
            return Err(CacheError::InvalidPath);
        }
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .foreign_keys(true)
            .synchronous(SqliteSynchronous::Full)
            .busy_timeout(Duration::from_secs(5));
        Self::open_with_options(options, 4).await
    }

    pub async fn open_in_memory() -> Result<Self, CacheError> {
        let options = SqliteConnectOptions::from_str("sqlite::memory:")
            .map_err(CacheError::Database)?
            .foreign_keys(true)
            .synchronous(SqliteSynchronous::Full)
            .busy_timeout(Duration::from_secs(5));
        Self::open_with_options(options, 1).await
    }

    async fn open_with_options(
        options: SqliteConnectOptions,
        maximum_connections: u32,
    ) -> Result<Self, CacheError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(maximum_connections)
            .connect_with(options)
            .await?;

        let application_id: i64 = sqlx::query_scalar("PRAGMA application_id")
            .fetch_one(&pool)
            .await?;
        if !matches!(application_id, 0 | CACHE_APPLICATION_ID) {
            pool.close().await;
            return Err(CacheError::ForeignDatabase { application_id });
        }
        let has_migration_table: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table' AND name = '_sqlx_migrations'",
        )
        .fetch_one(&pool)
        .await?;
        if has_migration_table == 1 {
            let version: i64 = sqlx::query_scalar(
                "SELECT COALESCE(MAX(version), 0) FROM _sqlx_migrations WHERE success = TRUE",
            )
            .fetch_one(&pool)
            .await?;
            if version > CURRENT_SCHEMA_VERSION {
                pool.close().await;
                return Err(CacheError::UnsupportedSchema {
                    found: version,
                    supported: CURRENT_SCHEMA_VERSION,
                });
            }
        }

        let _: String = sqlx::query_scalar("PRAGMA journal_mode = WAL")
            .fetch_one(&pool)
            .await?;
        MIGRATOR.run(&pool).await?;
        let cache = Self { pool };
        let schema_version = cache.schema_version().await?;
        if schema_version != CURRENT_SCHEMA_VERSION {
            cache.pool.close().await;
            return Err(CacheError::UnsupportedSchema {
                found: schema_version,
                supported: CURRENT_SCHEMA_VERSION,
            });
        }
        cache.check_integrity().await?;
        Ok(cache)
    }

    pub async fn schema_version(&self) -> Result<i64, CacheError> {
        sqlx::query_scalar(
            "SELECT COALESCE(MAX(version), 0) FROM _sqlx_migrations WHERE success = TRUE",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(CacheError::Database)
    }

    pub async fn check_integrity(&self) -> Result<(), CacheError> {
        let result: String = sqlx::query_scalar("PRAGMA quick_check")
            .fetch_one(&self.pool)
            .await?;
        if result != "ok" {
            return Err(CacheError::IntegrityCheckFailed);
        }
        Ok(())
    }

    pub async fn close(self) {
        self.pool.close().await;
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("local cache path is invalid")]
    InvalidPath,
    #[error(
        "refusing to open a SQLite database owned by another application (id {application_id})"
    )]
    ForeignDatabase { application_id: i64 },
    #[error("local cache schema {found} is not supported; expected {supported}")]
    UnsupportedSchema { found: i64, supported: i64 },
    #[error("local cache integrity check failed")]
    IntegrityCheckFailed,
    #[error("observation is invalid for local persistence: {field}")]
    InvalidObservation { field: &'static str },
    #[error("an observation with the same identity has different immutable content")]
    ObservationConflict,
    #[error("stored observation is invalid: {field}")]
    InvalidStoredObservation { field: &'static str },
    #[error("cache eligibility query is invalid: {field}")]
    InvalidEligibilityQuery { field: &'static str },
    #[error("eligible observation set exceeds the safe maximum of {maximum}")]
    TooManyEligibleObservations { maximum: usize },
    #[error("stored cache access count cannot be incremented")]
    AccessCountOverflow,
    #[error("local cache database operation failed")]
    Database(#[from] sqlx::Error),
    #[error("local cache migration failed")]
    Migration(#[from] sqlx::migrate::MigrateError),
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    use sqlx::Connection;

    use super::*;

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

    struct TempDatabase {
        path: PathBuf,
    }

    impl TempDatabase {
        fn new(label: &str) -> Self {
            let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "socialname-cache-{label}-{}-{id}.sqlite3",
                std::process::id()
            ));
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDatabase {
        fn drop(&mut self) {
            for path in [
                self.path.clone(),
                self.path.with_extension("sqlite3-shm"),
                self.path.with_extension("sqlite3-wal"),
            ] {
                let _ = fs::remove_file(path);
            }
        }
    }

    #[tokio::test]
    async fn embedded_migration_creates_versioned_immutable_schema() {
        let cache = LocalCache::open_in_memory().await.unwrap();
        assert_eq!(
            cache.schema_version().await.unwrap(),
            CURRENT_SCHEMA_VERSION
        );

        let application_id: i64 = sqlx::query_scalar("PRAGMA application_id")
            .fetch_one(&cache.pool)
            .await
            .unwrap();
        assert_eq!(application_id, CACHE_APPLICATION_ID);
        for object in [
            "local_observations",
            "observation_cache_metadata",
            "local_observations_are_immutable",
        ] {
            let found: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM sqlite_schema WHERE name = ? AND type IN ('table', 'trigger')",
            )
            .bind(object)
            .fetch_one(&cache.pool)
            .await
            .unwrap();
            assert_eq!(found, 1, "missing schema object {object}");
        }
        cache.check_integrity().await.unwrap();
    }

    #[tokio::test]
    async fn opening_the_same_file_reapplies_no_migration() {
        let database = TempDatabase::new("reopen");
        let first = LocalCache::open(database.path()).await.unwrap();
        assert_eq!(first.schema_version().await.unwrap(), 1);
        first.close().await;

        let second = LocalCache::open(database.path()).await.unwrap();
        let applied: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM _sqlx_migrations WHERE version = 1 AND success = TRUE",
        )
        .fetch_one(&second.pool)
        .await
        .unwrap();
        assert_eq!(applied, 1);
        second.close().await;
    }

    #[tokio::test]
    async fn refuses_foreign_or_corrupt_database_files() {
        let foreign = TempDatabase::new("foreign");
        let options = SqliteConnectOptions::new()
            .filename(foreign.path())
            .create_if_missing(true);
        let mut connection = sqlx::SqliteConnection::connect_with(&options)
            .await
            .unwrap();
        sqlx::query("PRAGMA application_id = 123")
            .execute(&mut connection)
            .await
            .unwrap();
        connection.close().await.unwrap();
        assert!(matches!(
            LocalCache::open(foreign.path()).await.unwrap_err(),
            CacheError::ForeignDatabase {
                application_id: 123
            }
        ));
        let mut connection = sqlx::SqliteConnection::connect_with(&options)
            .await
            .unwrap();
        let journal_mode: String = sqlx::query_scalar("PRAGMA journal_mode")
            .fetch_one(&mut connection)
            .await
            .unwrap();
        assert_eq!(journal_mode, "delete");
        connection.close().await.unwrap();

        let corrupt = TempDatabase::new("corrupt");
        fs::write(corrupt.path(), b"not a sqlite database").unwrap();
        assert!(matches!(
            LocalCache::open(corrupt.path()).await.unwrap_err(),
            CacheError::Database(_)
        ));
    }

    #[tokio::test]
    async fn refuses_a_future_schema_without_modifying_it() {
        let database = TempDatabase::new("future");
        let cache = LocalCache::open(database.path()).await.unwrap();
        sqlx::query(
            "INSERT INTO _sqlx_migrations (
                version, description, success, checksum, execution_time
            ) VALUES (999, 'future schema', TRUE, X'00', 0)",
        )
        .execute(&cache.pool)
        .await
        .unwrap();
        cache.close().await;

        assert!(matches!(
            LocalCache::open(database.path()).await.unwrap_err(),
            CacheError::UnsupportedSchema {
                found: 999,
                supported: CURRENT_SCHEMA_VERSION
            }
        ));
    }

    #[tokio::test]
    async fn observations_cannot_be_updated_but_can_be_deleted_for_pruning() {
        let cache = LocalCache::open_in_memory().await.unwrap();
        sqlx::query(
            "INSERT INTO local_observations (
                observation_id, site_id, normalized_username, verdict,
                inconclusive_reason, evidence_class, observed_at_unix_ms,
                expires_at_unix_ms, region_class, network_group,
                independence_group, producer_kind, producer_reputation,
                collection_profile, rule_hash, rule_health_green,
                evidence_digest, inserted_at_unix_ms
            ) VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind("observation-1")
        .bind("example")
        .bind("private-target")
        .bind("found")
        .bind("e4_structured_identity")
        .bind(1_000_i64)
        .bind(2_000_i64)
        .bind("local")
        .bind("local-network")
        .bind("local-installation")
        .bind("local_cli")
        .bind("new")
        .bind("local_only")
        .bind("1".repeat(64))
        .bind(true)
        .bind("2".repeat(64))
        .bind(1_001_i64)
        .execute(&cache.pool)
        .await
        .unwrap();
        assert!(
            sqlx::query(
                "UPDATE local_observations SET verdict = 'not_found' WHERE observation_id = ?",
            )
            .bind("observation-1")
            .execute(&cache.pool)
            .await
            .is_err()
        );
        let deleted = sqlx::query("DELETE FROM local_observations WHERE observation_id = ?")
            .bind("observation-1")
            .execute(&cache.pool)
            .await
            .unwrap()
            .rows_affected();
        assert_eq!(deleted, 1);
    }
}
