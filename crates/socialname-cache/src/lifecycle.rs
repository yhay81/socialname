use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{CacheError, LocalCache, resolve_cache_path};

static NEXT_QUARANTINE_ID: AtomicU64 = AtomicU64::new(1);
const SIDECAR_SUFFIXES: [&str; 3] = ["-wal", "-shm", "-journal"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheDeletionReport {
    pub removed_files: usize,
}

#[derive(Debug)]
pub struct RecoveredCache {
    pub cache: LocalCache,
    pub quarantine_path: PathBuf,
}

impl LocalCache {
    pub async fn delete_database(self) -> Result<CacheDeletionReport, CacheError> {
        let path = self
            .path
            .clone()
            .ok_or(CacheError::FileBackedCacheRequired)?;
        self.pool.close().await;

        let mut removed_files = 0;
        for file in cache_file_paths(&path).into_iter().rev() {
            match remove_with_retry(&file).await {
                Ok(()) => removed_files += 1,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(CacheError::DeletionIncomplete {
                        removed_files,
                        source,
                    });
                }
            }
        }
        Ok(CacheDeletionReport { removed_files })
    }

    pub async fn recover(path: impl AsRef<Path>) -> Result<RecoveredCache, CacheError> {
        let path = resolve_cache_path(path.as_ref())?;
        if !path.exists() {
            return Err(CacheError::RecoveryNotRequired);
        }

        match Self::open(&path).await {
            Ok(cache) => {
                cache.close().await;
                return Err(CacheError::RecoveryNotRequired);
            }
            Err(error)
                if matches!(
                    error,
                    CacheError::ForeignDatabase { .. }
                        | CacheError::UnrecognizedDatabase
                        | CacheError::UnsupportedSchema { .. }
                        | CacheError::InvalidPath
                ) =>
            {
                return Err(error);
            }
            Err(_) => {}
        }

        let quarantine_path = unused_quarantine_path(&path)?;
        let moved = quarantine_files(&path, &quarantine_path).await?;
        match Self::open(&path).await {
            Ok(cache) => Ok(RecoveredCache {
                cache,
                quarantine_path,
            }),
            Err(open_error) => {
                remove_new_cache_files(&path).await?;
                restore_quarantined_files(&moved)?;
                Err(open_error)
            }
        }
    }
}

fn cache_file_paths(path: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::with_capacity(1 + SIDECAR_SUFFIXES.len());
    paths.push(path.to_path_buf());
    paths.extend(
        SIDECAR_SUFFIXES
            .into_iter()
            .map(|suffix| path_with_suffix(path, suffix)),
    );
    paths
}

fn path_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value: OsString = path.as_os_str().to_owned();
    value.push(suffix);
    PathBuf::from(value)
}

fn unused_quarantine_path(path: &Path) -> Result<PathBuf, CacheError> {
    let parent = path.parent().ok_or(CacheError::InvalidPath)?;
    let file_name = path.file_name().ok_or(CacheError::InvalidPath)?;
    for _ in 0..1_000 {
        let sequence = NEXT_QUARANTINE_ID.fetch_add(1, Ordering::Relaxed);
        let mut quarantine_name = file_name.to_os_string();
        quarantine_name.push(format!(".corrupt-{}-{sequence}", std::process::id()));
        let candidate = parent.join(quarantine_name);
        if cache_file_paths(&candidate)
            .iter()
            .all(|file| !file.exists())
        {
            return Ok(candidate);
        }
    }
    Err(CacheError::RecoveryQuarantine(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "no unused quarantine filename is available",
    )))
}

async fn quarantine_files(
    source_path: &Path,
    quarantine_path: &Path,
) -> Result<Vec<(PathBuf, PathBuf)>, CacheError> {
    let sources = cache_file_paths(source_path);
    let destinations = cache_file_paths(quarantine_path);
    let mut moved = Vec::new();
    for (source, destination) in sources.into_iter().zip(destinations) {
        if !source.exists() {
            continue;
        }
        if let Err(error) = rename_with_retry(&source, &destination).await {
            restore_quarantined_files(&moved)?;
            return Err(CacheError::RecoveryQuarantine(error));
        }
        moved.push((source, destination));
    }
    if moved.is_empty() {
        return Err(CacheError::RecoveryNotRequired);
    }
    Ok(moved)
}

fn restore_quarantined_files(moved: &[(PathBuf, PathBuf)]) -> Result<(), CacheError> {
    for (source, destination) in moved.iter().rev() {
        if let Err(error) = fs::rename(destination, source) {
            return Err(CacheError::RecoveryRollback(error));
        }
    }
    Ok(())
}

async fn remove_new_cache_files(path: &Path) -> Result<(), CacheError> {
    for file in cache_file_paths(path).into_iter().rev() {
        match remove_with_retry(&file).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(CacheError::RecoveryRollback(error)),
        }
    }
    Ok(())
}

async fn rename_with_retry(source: &Path, destination: &Path) -> Result<(), std::io::Error> {
    let attempts = if cfg!(windows) { 50 } else { 1 };
    for attempt in 0..attempts {
        match fs::rename(source, destination) {
            Ok(()) => return Ok(()),
            Err(error) if attempt + 1 == attempts => return Err(error),
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
        }
    }
    unreachable!("rename retry loop always returns")
}

async fn remove_with_retry(path: &Path) -> Result<(), std::io::Error> {
    let attempts = if cfg!(windows) { 50 } else { 1 };
    for attempt in 0..attempts {
        match fs::remove_file(path) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Err(error),
            Err(error) if attempt + 1 == attempts => return Err(error),
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
        }
    }
    unreachable!("remove retry loop always returns")
}

#[cfg(test)]
mod tests {
    use std::{
        path::Path,
        sync::atomic::{AtomicU64, Ordering},
    };

    use socialname_domain::{
        CollectionProfile, EvidenceClass, Observation, ObservationId, ProducerKind,
        ProducerReputation, SiteId, TargetKey, Verdict,
    };
    use sqlx::Connection;

    use super::*;

    static NEXT_DATABASE_ID: AtomicU64 = AtomicU64::new(1);

    struct TempDatabase {
        path: PathBuf,
    }

    impl TempDatabase {
        fn new(label: &str) -> Self {
            let id = NEXT_DATABASE_ID.fetch_add(1, Ordering::Relaxed);
            Self {
                path: std::env::temp_dir().join(format!(
                    "socialname-cache-lifecycle-{label}-{}-{id}.sqlite3",
                    std::process::id()
                )),
            }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDatabase {
        fn drop(&mut self) {
            for file in cache_file_paths(&self.path).into_iter().rev() {
                let _ = fs::remove_file(file);
            }
        }
    }

    fn observation(id: &str) -> Observation {
        Observation {
            id: ObservationId::new(id),
            target: TargetKey {
                site_id: SiteId::new("example"),
                normalized_username: "private-target".to_owned(),
            },
            verdict: Verdict::Found,
            inconclusive_reason: None,
            evidence_class: EvidenceClass::E4StructuredIdentity,
            observed_at_unix_ms: 1_000,
            expires_at_unix_ms: 2_000,
            region: "local".to_owned(),
            network_group: "local-network".to_owned(),
            independence_group: "local-installation".to_owned(),
            producer_kind: ProducerKind::LocalCli,
            producer_reputation: ProducerReputation::New,
            collection_profile: CollectionProfile::LocalOnly,
            rule_hash: "1".repeat(64),
            rule_health_green: true,
            evidence_digest: "2".repeat(64),
        }
    }

    #[tokio::test]
    async fn corrupt_bytes_are_quarantined_before_an_empty_cache_is_created() {
        let database = TempDatabase::new("recover-corrupt");
        let corrupt_bytes = b"not a sqlite database";
        fs::write(database.path(), corrupt_bytes).unwrap();

        let recovered = LocalCache::recover(database.path()).await.unwrap();
        assert_eq!(fs::read(&recovered.quarantine_path).unwrap(), corrupt_bytes);
        assert_eq!(
            recovered.cache.schema_version().await.unwrap(),
            crate::CURRENT_SCHEMA_VERSION
        );
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM local_observations")
            .fetch_one(&recovered.cache.pool)
            .await
            .unwrap();
        assert_eq!(count, 0);

        recovered.cache.delete_database().await.unwrap();
        fs::remove_file(recovered.quarantine_path).unwrap();
    }

    #[tokio::test]
    async fn healthy_cache_recovery_is_refused_and_data_is_preserved() {
        let database = TempDatabase::new("recover-healthy");
        let expected = observation("preserved");
        let cache = LocalCache::open(database.path()).await.unwrap();
        cache.store_observation(&expected, 1_001).await.unwrap();
        cache.close().await;

        assert!(matches!(
            LocalCache::recover(database.path()).await.unwrap_err(),
            CacheError::RecoveryNotRequired
        ));
        let reopened = LocalCache::open(database.path()).await.unwrap();
        assert_eq!(
            reopened
                .get_observation(&expected.id)
                .await
                .unwrap()
                .unwrap()
                .observation,
            expected
        );
        reopened.close().await;
    }

    #[tokio::test]
    async fn foreign_database_recovery_is_refused_without_renaming_it() {
        let database = TempDatabase::new("recover-foreign");
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(database.path())
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
            LocalCache::recover(database.path()).await.unwrap_err(),
            CacheError::ForeignDatabase {
                application_id: 123
            }
        ));
        assert!(database.path().exists());
    }

    #[tokio::test]
    async fn unowned_nonempty_database_is_neither_adopted_nor_recovered() {
        let database = TempDatabase::new("recover-unowned");
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(database.path())
            .create_if_missing(true);
        let mut connection = sqlx::SqliteConnection::connect_with(&options)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE unrelated_data (value TEXT NOT NULL)")
            .execute(&mut connection)
            .await
            .unwrap();
        connection.close().await.unwrap();

        assert!(matches!(
            LocalCache::open(database.path()).await.unwrap_err(),
            CacheError::UnrecognizedDatabase
        ));
        assert!(matches!(
            LocalCache::recover(database.path()).await.unwrap_err(),
            CacheError::UnrecognizedDatabase
        ));
        let mut connection = sqlx::SqliteConnection::connect_with(&options)
            .await
            .unwrap();
        let table_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_schema WHERE name = 'unrelated_data'")
                .fetch_one(&mut connection)
                .await
                .unwrap();
        let journal_mode: String = sqlx::query_scalar("PRAGMA journal_mode")
            .fetch_one(&mut connection)
            .await
            .unwrap();
        assert_eq!(table_count, 1);
        assert_eq!(journal_mode, "delete");
        connection.close().await.unwrap();
    }

    #[tokio::test]
    async fn future_schema_is_not_downgraded_or_quarantined() {
        let database = TempDatabase::new("recover-future");
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
            LocalCache::recover(database.path()).await.unwrap_err(),
            CacheError::UnsupportedSchema {
                found: 999,
                supported: crate::CURRENT_SCHEMA_VERSION
            }
        ));
        assert!(database.path().exists());
    }

    #[tokio::test]
    async fn delete_database_removes_main_file_and_sidecars() {
        let database = TempDatabase::new("delete");
        let cache = LocalCache::open(database.path()).await.unwrap();
        cache
            .store_observation(&observation("deleted"), 1_001)
            .await
            .unwrap();
        let journal = path_with_suffix(database.path(), "-journal");
        fs::write(&journal, b"test sidecar").unwrap();

        let report = cache.delete_database().await.unwrap();
        assert!(report.removed_files >= 1);
        for file in cache_file_paths(database.path()) {
            assert!(!file.exists(), "{} still exists", file.display());
        }
    }

    #[tokio::test]
    async fn in_memory_cache_cannot_claim_file_deletion() {
        let cache = LocalCache::open_in_memory().await.unwrap();
        assert!(matches!(
            cache.delete_database().await.unwrap_err(),
            CacheError::FileBackedCacheRequired
        ));
    }
}
