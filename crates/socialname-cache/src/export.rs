use std::{
    fs::{self, File, OpenOptions},
    io::{BufWriter, Write},
    path::Path,
};

use futures_util::TryStreamExt;
use serde::Serialize;

use crate::{CacheError, LocalCache, observation_store::StoredObservationRow};

pub const LOCAL_CACHE_EXPORT_SCHEMA: &str = "socialname.dev/local-cache-export/v1";

const ALL_OBSERVATIONS_SELECT: &str = "
    SELECT
        o.observation_id,
        o.site_id,
        o.normalized_username,
        o.verdict,
        o.inconclusive_reason,
        o.evidence_class,
        o.observed_at_unix_ms,
        o.expires_at_unix_ms,
        o.region_class,
        o.network_group,
        o.independence_group,
        o.producer_kind,
        o.producer_reputation,
        o.collection_profile,
        o.rule_hash,
        o.rule_health_green,
        o.evidence_digest,
        m.cached_at_unix_ms,
        m.last_accessed_at_unix_ms,
        m.access_count
    FROM local_observations AS o
    LEFT JOIN observation_cache_metadata AS m
        ON m.observation_id = o.observation_id
    ORDER BY o.observed_at_unix_ms ASC, o.observation_id ASC
";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheExportReport {
    pub observation_count: u64,
    pub bytes_written: u64,
}

#[derive(Serialize)]
struct ExportManifest {
    schema: &'static str,
    record_type: &'static str,
    exported_at_unix_ms: i64,
    observation_count: u64,
}

#[derive(Serialize)]
struct ExportObservation<'a> {
    schema: &'static str,
    record_type: &'static str,
    observation: &'a socialname_domain::Observation,
    cache_metadata: ExportCacheMetadata,
}

#[derive(Serialize)]
struct ExportCacheMetadata {
    cached_at_unix_ms: i64,
    last_accessed_at_unix_ms: i64,
    access_count: u64,
}

impl LocalCache {
    pub async fn export_jsonl(
        &self,
        path: impl AsRef<Path>,
        exported_at_unix_ms: i64,
    ) -> Result<CacheExportReport, CacheError> {
        let path = path.as_ref();
        if path.as_os_str().is_empty() {
            return Err(CacheError::InvalidPath);
        }
        self.check_integrity().await?;

        let file = create_export_file(path)?;
        let mut writer = BufWriter::new(file);
        let export_result = async {
            let mut transaction = self.pool.begin().await?;
            let observation_count: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM local_observations")
                    .fetch_one(&mut *transaction)
                    .await?;
            let observation_count = u64::try_from(observation_count).map_err(|_| {
                CacheError::InvalidStoredObservation {
                    field: "observation_count",
                }
            })?;
            let mut bytes_written = write_json_line(
                &mut writer,
                &ExportManifest {
                    schema: LOCAL_CACHE_EXPORT_SCHEMA,
                    record_type: "manifest",
                    exported_at_unix_ms,
                    observation_count,
                },
            )?;

            let mut exported_count = 0_u64;
            let mut rows = sqlx::query_as::<_, StoredObservationRow>(ALL_OBSERVATIONS_SELECT)
                .fetch(&mut *transaction);
            while let Some(row) = rows.try_next().await? {
                let cached = row.into_cached()?;
                bytes_written = bytes_written
                    .checked_add(write_json_line(
                        &mut writer,
                        &ExportObservation {
                            schema: LOCAL_CACHE_EXPORT_SCHEMA,
                            record_type: "observation",
                            observation: &cached.observation,
                            cache_metadata: ExportCacheMetadata {
                                cached_at_unix_ms: cached.metadata.cached_at_unix_ms,
                                last_accessed_at_unix_ms: cached.metadata.last_accessed_at_unix_ms,
                                access_count: cached.metadata.access_count,
                            },
                        },
                    )?)
                    .ok_or(CacheError::InvalidStoredObservation {
                        field: "export_size",
                    })?;
                exported_count =
                    exported_count
                        .checked_add(1)
                        .ok_or(CacheError::InvalidStoredObservation {
                            field: "observation_count",
                        })?;
            }
            drop(rows);
            if exported_count != observation_count {
                return Err(CacheError::InvalidStoredObservation {
                    field: "observation_count",
                });
            }
            writer.flush()?;
            writer.get_ref().sync_all()?;
            transaction.commit().await?;
            Ok(CacheExportReport {
                observation_count,
                bytes_written,
            })
        }
        .await;

        if export_result.is_err() {
            drop(writer);
            if let Err(error) = fs::remove_file(path)
                && error.kind() != std::io::ErrorKind::NotFound
            {
                return Err(CacheError::ExportCleanup(error));
            }
        }
        export_result
    }
}

fn create_export_file(path: &Path) -> Result<File, std::io::Error> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
    }
    options.open(path)
}

fn write_json_line(
    writer: &mut BufWriter<File>,
    value: &impl Serialize,
) -> Result<u64, CacheError> {
    let encoded = serde_json::to_vec(value)?;
    writer.write_all(&encoded)?;
    writer.write_all(b"\n")?;
    u64::try_from(encoded.len() + 1).map_err(|_| CacheError::InvalidStoredObservation {
        field: "export_size",
    })
}

#[cfg(test)]
mod tests {
    use std::{
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    use serde_json::Value;
    use socialname_domain::{
        CollectionProfile, EvidenceClass, Observation, ObservationId, ProducerKind,
        ProducerReputation, SiteId, TargetKey, Verdict,
    };

    use super::*;

    static NEXT_EXPORT_ID: AtomicU64 = AtomicU64::new(1);

    struct TempExport {
        path: PathBuf,
    }

    impl TempExport {
        fn new(label: &str) -> Self {
            let id = NEXT_EXPORT_ID.fetch_add(1, Ordering::Relaxed);
            Self {
                path: std::env::temp_dir().join(format!(
                    "socialname-cache-export-{label}-{}-{id}.jsonl",
                    std::process::id()
                )),
            }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempExport {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    fn observation(id: &str, observed_at_unix_ms: i64) -> Observation {
        Observation {
            id: ObservationId::new(id),
            target: TargetKey {
                site_id: SiteId::new("example"),
                normalized_username: "private-target".to_owned(),
            },
            verdict: Verdict::Found,
            inconclusive_reason: None,
            evidence_class: EvidenceClass::E4StructuredIdentity,
            observed_at_unix_ms,
            expires_at_unix_ms: observed_at_unix_ms + 10_000,
            region: "local".to_owned(),
            network_group: "local-network".to_owned(),
            independence_group: format!("installation-{id}"),
            producer_kind: ProducerKind::LocalCli,
            producer_reputation: ProducerReputation::New,
            collection_profile: CollectionProfile::LocalOnly,
            rule_hash: "1".repeat(64),
            rule_health_green: true,
            evidence_digest: "2".repeat(64),
        }
    }

    #[tokio::test]
    async fn export_is_versioned_complete_and_deterministic() {
        let cache = LocalCache::open_in_memory().await.unwrap();
        let newer = observation("newer", 2_000);
        let older = observation("older", 1_000);
        cache.store_observation(&newer, 2_001).await.unwrap();
        cache.store_observation(&older, 2_001).await.unwrap();
        let export = TempExport::new("complete");

        let report = cache.export_jsonl(export.path(), 3_000).await.unwrap();
        let bytes = fs::read(export.path()).unwrap();
        assert_eq!(report.observation_count, 2);
        assert_eq!(report.bytes_written, bytes.len() as u64);
        assert!(bytes.ends_with(b"\n"));
        let records = String::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0]["schema"], LOCAL_CACHE_EXPORT_SCHEMA);
        assert_eq!(records[0]["record_type"], "manifest");
        assert_eq!(records[0]["exported_at_unix_ms"], 3_000);
        assert_eq!(records[0]["observation_count"], 2);
        assert_eq!(records[1]["observation"]["id"], "older");
        assert_eq!(records[2]["observation"]["id"], "newer");
        assert_eq!(records[1]["cache_metadata"]["cached_at_unix_ms"], 2_001);
    }

    #[tokio::test]
    async fn export_refuses_to_overwrite_an_existing_file() {
        let cache = LocalCache::open_in_memory().await.unwrap();
        let export = TempExport::new("existing");
        fs::write(export.path(), b"user-owned").unwrap();

        assert!(matches!(
            cache.export_jsonl(export.path(), 3_000).await.unwrap_err(),
            CacheError::Io(_)
        ));
        assert_eq!(fs::read(export.path()).unwrap(), b"user-owned");
    }

    #[tokio::test]
    async fn invalid_cache_creates_no_partial_export() {
        let cache = LocalCache::open_in_memory().await.unwrap();
        let expected = observation("orphan", 1_000);
        cache.store_observation(&expected, 1_001).await.unwrap();
        sqlx::query("DELETE FROM observation_cache_metadata WHERE observation_id = ?")
            .bind(expected.id.as_str())
            .execute(&cache.pool)
            .await
            .unwrap();
        let export = TempExport::new("partial");

        assert!(matches!(
            cache.export_jsonl(export.path(), 3_000).await.unwrap_err(),
            CacheError::IntegrityCheckFailed
        ));
        assert!(!export.path().exists());
    }
}
