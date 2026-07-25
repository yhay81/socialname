#![forbid(unsafe_code)]

use std::{
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use sqlx::{
    SqlitePool,
    migrate::Migrator,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions, SqliteSynchronous},
};

mod eligibility;
mod export;
mod lifecycle;
mod maintenance;
mod observation_store;

pub use eligibility::{CacheEligibilityQuery, CacheVerdictPolicy, MAX_ELIGIBLE_OBSERVATIONS};
pub use export::{CacheExportReport, LOCAL_CACHE_EXPORT_SCHEMA};
pub use lifecycle::{CacheDeletionReport, RecoveredCache};
pub use maintenance::{CacheMaintenancePolicy, CacheMaintenanceReport};
pub use observation_store::{CacheMetadata, CachedObservation, StoreOutcome};

pub const CACHE_APPLICATION_ID: i64 = 1_397_637_453;
pub const CURRENT_SCHEMA_VERSION: i64 = 2;

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

#[derive(Clone, Debug)]
pub struct LocalCache {
    pool: SqlitePool,
    path: Option<PathBuf>,
}

impl LocalCache {
    pub async fn open(path: impl AsRef<Path>) -> Result<Self, CacheError> {
        let path = resolve_cache_path(path.as_ref())?;
        let options = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true)
            .foreign_keys(true)
            .synchronous(SqliteSynchronous::Full)
            .busy_timeout(Duration::from_secs(5));
        Self::open_with_options(options, 4, Some(path)).await
    }

    pub async fn open_in_memory() -> Result<Self, CacheError> {
        let options = SqliteConnectOptions::from_str("sqlite::memory:")
            .map_err(CacheError::Database)?
            .foreign_keys(true)
            .synchronous(SqliteSynchronous::Full)
            .busy_timeout(Duration::from_secs(5));
        Self::open_with_options(options, 1, None).await
    }

    async fn open_with_options(
        options: SqliteConnectOptions,
        maximum_connections: u32,
        path: Option<PathBuf>,
    ) -> Result<Self, CacheError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(maximum_connections)
            .connect_with(options)
            .await?;
        let cache = Self { pool, path };
        if let Err(error) = cache.initialize().await {
            cache.pool.close().await;
            return Err(error);
        }
        Ok(cache)
    }

    async fn initialize(&self) -> Result<(), CacheError> {
        let application_id: i64 = sqlx::query_scalar("PRAGMA application_id")
            .fetch_one(&self.pool)
            .await?;
        if !matches!(application_id, 0 | CACHE_APPLICATION_ID) {
            return Err(CacheError::ForeignDatabase { application_id });
        }
        let has_migration_table: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table' AND name = '_sqlx_migrations'",
        )
        .fetch_one(&self.pool)
        .await?;
        if application_id == 0 && has_migration_table == 0 {
            let existing_schema_objects: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
            )
            .fetch_one(&self.pool)
            .await?;
            if existing_schema_objects != 0 {
                return Err(CacheError::UnrecognizedDatabase);
            }
        }
        if has_migration_table == 1 {
            let version: i64 = sqlx::query_scalar(
                "SELECT COALESCE(MAX(version), 0) FROM _sqlx_migrations WHERE success = TRUE",
            )
            .fetch_one(&self.pool)
            .await?;
            if version > CURRENT_SCHEMA_VERSION {
                return Err(CacheError::UnsupportedSchema {
                    found: version,
                    supported: CURRENT_SCHEMA_VERSION,
                });
            }
        }

        let _: String = sqlx::query_scalar("PRAGMA journal_mode = WAL")
            .fetch_one(&self.pool)
            .await?;
        MIGRATOR.run(&self.pool).await?;
        let schema_version = self.schema_version().await?;
        if schema_version != CURRENT_SCHEMA_VERSION {
            return Err(CacheError::UnsupportedSchema {
                found: schema_version,
                supported: CURRENT_SCHEMA_VERSION,
            });
        }
        self.check_integrity().await
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
        let result: String = sqlx::query_scalar("PRAGMA integrity_check")
            .fetch_one(&self.pool)
            .await?;
        if result != "ok" {
            return Err(CacheError::IntegrityCheckFailed);
        }
        let foreign_key_violations: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM pragma_foreign_key_check")
                .fetch_one(&self.pool)
                .await?;
        let observations_without_metadata: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)
             FROM local_observations AS o
             LEFT JOIN observation_cache_metadata AS m
                 ON m.observation_id = o.observation_id
             WHERE m.observation_id IS NULL",
        )
        .fetch_one(&self.pool)
        .await?;
        if foreign_key_violations != 0 || observations_without_metadata != 0 {
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
    #[error("refusing to adopt a nonempty SQLite database without SocialName ownership")]
    UnrecognizedDatabase,
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
    #[error("cache maintenance policy is invalid: {field}")]
    InvalidMaintenancePolicy { field: &'static str },
    #[error("cache maintenance did not reach its configured limits")]
    MaintenanceLimitNotReached,
    #[error("local cache file operation failed")]
    Io(#[from] std::io::Error),
    #[error("local cache export serialization failed")]
    ExportSerialization(#[from] serde_json::Error),
    #[error("failed to remove an incomplete local cache export")]
    ExportCleanup(#[source] std::io::Error),
    #[error("the requested cache recovery is not needed")]
    RecoveryNotRequired,
    #[error("the operation requires a file-backed local cache")]
    FileBackedCacheRequired,
    #[error("failed to quarantine the corrupt local cache")]
    RecoveryQuarantine(#[source] std::io::Error),
    #[error("failed to restore the original cache after recovery failed")]
    RecoveryRollback(#[source] std::io::Error),
    #[error("complete cache deletion stopped after removing {removed_files} files")]
    DeletionIncomplete {
        removed_files: usize,
        #[source]
        source: std::io::Error,
    },
    #[error("local cache database operation failed")]
    Database(#[from] sqlx::Error),
    #[error("local cache migration failed")]
    Migration(#[from] sqlx::migrate::MigrateError),
}

fn resolve_cache_path(path: &Path) -> Result<PathBuf, CacheError> {
    if path.as_os_str().is_empty() {
        return Err(CacheError::InvalidPath);
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    if absolute.exists() {
        return Ok(std::fs::canonicalize(&absolute)?);
    }
    if let (Some(parent), Some(file_name)) = (absolute.parent(), absolute.file_name())
        && parent.exists()
    {
        return Ok(std::fs::canonicalize(parent)?.join(file_name));
    }
    Ok(absolute)
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
    static V1_MIGRATOR: Migrator = sqlx::migrate!("./tests/migrations-v1");

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
        assert_eq!(
            first.schema_version().await.unwrap(),
            CURRENT_SCHEMA_VERSION
        );
        first.close().await;

        let second = LocalCache::open(database.path()).await.unwrap();
        let applied: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations WHERE success = TRUE")
                .fetch_one(&second.pool)
                .await
                .unwrap();
        assert_eq!(applied, CURRENT_SCHEMA_VERSION);
        second.close().await;
    }

    #[tokio::test]
    async fn version_one_migrates_without_losing_observation_lineage() {
        let database = TempDatabase::new("v1-to-v2");
        let options = SqliteConnectOptions::new()
            .filename(database.path())
            .create_if_missing(true)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .unwrap();
        V1_MIGRATOR.run(&pool).await.unwrap();
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
        .bind("v1-observation")
        .bind("example")
        .bind("private-target")
        .bind("found")
        .bind("e4_structured_identity")
        .bind(1_000_i64)
        .bind(10_000_i64)
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
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO observation_cache_metadata (
                observation_id, cached_at_unix_ms,
                last_accessed_at_unix_ms, access_count
            ) VALUES (?, ?, ?, ?)",
        )
        .bind("v1-observation")
        .bind(1_001_i64)
        .bind(1_100_i64)
        .bind(3_i64)
        .execute(&pool)
        .await
        .unwrap();
        pool.close().await;

        let cache = LocalCache::open(database.path()).await.unwrap();
        assert_eq!(
            cache.schema_version().await.unwrap(),
            CURRENT_SCHEMA_VERSION
        );
        let cached = cache
            .get_observation(&socialname_domain::ObservationId::new("v1-observation"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            cached.observation.producer_kind,
            socialname_domain::ProducerKind::LocalCli
        );
        assert_eq!(cached.metadata.access_count, 3);
        cache.close().await;
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
