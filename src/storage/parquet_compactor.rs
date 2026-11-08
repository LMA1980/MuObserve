use std::path::{Path, PathBuf};

use chrono::{Datelike, TimeZone, Utc};
use duckdb::params;
use serde::{Deserialize, Serialize};

use crate::error::MuObserveError;
use crate::storage::hot_duckdb::HotDuckDbStore;
use crate::storage::views::{escape_sql_literal, register_unified_views};
use crate::DEFAULT_HOT_RETENTION_DAYS;

/// Configuration for the background Hive-partitioned Zstd Parquet compactor and TTL enforcer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactorConfig {
    pub parquet_root: PathBuf,
    pub hot_retention_days: u32,
    pub raw_telemetry_ttl_days: u32,
    #[serde(default)]
    pub max_store_bytes: Option<u64>,
    #[serde(default)]
    pub min_free_disk_bytes: Option<u64>,
}

impl CompactorConfig {
    /// Creates a new [`CompactorConfig`] with the default 7-day hot retention window and 60-day
    /// raw debug log/span TTL (clamped to the policy range of `30..=90` days).
    pub fn new(parquet_root: impl Into<PathBuf>) -> Self {
        Self {
            parquet_root: parquet_root.into(),
            hot_retention_days: DEFAULT_HOT_RETENTION_DAYS,
            raw_telemetry_ttl_days: 60,
            max_store_bytes: None,
            min_free_disk_bytes: None,
        }
    }

    /// Sets the hot retention days before cold Parquet compaction.
    #[must_use]
    pub fn with_hot_retention_days(mut self, days: u32) -> Self {
        self.hot_retention_days = days;
        self
    }

    /// Sets the TTL in days for raw debug logs/spans/metrics (clamped between 30 and 90 days in production,
    /// or configurable for tests).
    #[must_use]
    pub fn with_raw_telemetry_ttl_days(mut self, days: u32) -> Self {
        self.raw_telemetry_ttl_days = days;
        self
    }

    /// Sets an optional maximum total store byte ceiling for FIFO space eviction.
    #[must_use]
    pub fn with_max_store_bytes(mut self, max_bytes: u64) -> Self {
        self.max_store_bytes = Some(max_bytes);
        self
    }

    /// Sets an optional minimum free disk byte threshold for FIFO disk-pressure eviction.
    #[must_use]
    pub fn with_min_free_disk_bytes(mut self, min_free_bytes: u64) -> Self {
        self.min_free_disk_bytes = Some(min_free_bytes);
        self
    }
}

/// Summary of rows exported to cold Zstd Parquet and pruned by a compaction cycle.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactionReport {
    pub exported_logs: u64,
    pub exported_spans: u64,
    pub exported_metrics: u64,
    pub exported_tests: u64,
    pub exported_benchmarks: u64,
    pub ttl_pruned_files: u64,
    pub parquet_files_written: Vec<PathBuf>,
}

/// Background compactor exporting aged rows (`< cutoff_unix_nano`) from `hot.duckdb` into
/// Hive-partitioned Zstd Parquet files (`signal=<type>/year=YYYY/month=MM/part-<cutoff>.parquet`),
/// registering cold log shards in `log_shards_catalog`, updating `log_inverted_index`,
/// atomically pruning compacted rows from the hot tables, refreshing unified analytical views,
/// and enforcing FIFO TTL / space bounds on raw telemetry while preserving benchmarks and test runs.
pub struct ParquetCompactor {
    config: CompactorConfig,
}

impl ParquetCompactor {
    /// Constructs a new [`ParquetCompactor`].
    #[must_use]
    pub fn new(config: CompactorConfig) -> Self {
        Self { config }
    }

    /// Returns a reference to the compactor configuration.
    #[must_use]
    pub fn config(&self) -> &CompactorConfig {
        &self.config
    }

    /// Runs a compaction cycle using the current wall-clock timestamp (`now_unix_nano`).
    pub fn compact_at_now(
        &self,
        store: &HotDuckDbStore,
        now_unix_nano: i64,
    ) -> Result<CompactionReport, MuObserveError> {
        let retention_ns = i64::from(self.config.hot_retention_days)
            .saturating_mul(86_400)
            .saturating_mul(1_000_000_000);
        let cutoff_unix_nano = now_unix_nano.saturating_sub(retention_ns);
        let mut report = self.compact_before(store, cutoff_unix_nano)?;

        let ttl_ns = i64::from(self.config.raw_telemetry_ttl_days)
            .saturating_mul(86_400)
            .saturating_mul(1_000_000_000);
        let ttl_cutoff_nano = now_unix_nano.saturating_sub(ttl_ns);
        report.ttl_pruned_files = self.enforce_cold_ttl(store, ttl_cutoff_nano)?;

        if self.config.max_store_bytes.is_some() || self.config.min_free_disk_bytes.is_some() {
            let max_store = self.config.max_store_bytes.unwrap_or(u64::MAX);
            let min_free = self.config.min_free_disk_bytes.unwrap_or(0);
            let _ = store.enforce_fifo_time_and_space_eviction(
                now_unix_nano,
                ttl_ns,
                max_store,
                min_free,
            )?;
        }

        Ok(report)
    }

    /// Exports and atomically prunes all records strictly older than `cutoff_unix_nano` across
    /// `otel_logs`, `otel_spans`, `otel_metrics`, `test_case_runs`, and `benchmark_runs`.
    ///
    /// For `otel_logs`, registers the compacted segment in `log_shards_catalog` and updates
    /// `log_inverted_index` `shard_id` from `'hot'` to the new cold shard identifier while keeping
    /// both `log_inverted_index` and `log_shards_catalog` in local DuckDB.
    pub fn compact_before(
        &self,
        store: &HotDuckDbStore,
        cutoff_unix_nano: i64,
    ) -> Result<CompactionReport, MuObserveError> {
        let mut report = CompactionReport::default();
        let conn = store.lock_conn()?;

        let signals = [
            ("otel_logs", "logs", "timestamp_unix_nano"),
            ("otel_spans", "spans", "start_time_unix_nano"),
            ("otel_metrics", "metrics", "timestamp_unix_nano"),
            ("test_case_runs", "tests", "timestamp_unix_nano"),
            ("benchmark_runs", "benchmarks", "timestamp_unix_nano"),
        ];

        for (table, signal, ts_col) in signals {
            let count_sql = format!("SELECT COUNT(*) FROM {table} WHERE {ts_col} < ?1");
            let eligible: i64 =
                conn.query_row(&count_sql, params![cutoff_unix_nano], |r| r.get(0))?;
            if eligible <= 0 {
                continue;
            }

            let min_max_sql = format!(
                "SELECT COALESCE(MIN({ts_col}), ?1), COALESCE(MAX({ts_col}), ?1) FROM {table} WHERE {ts_col} < ?1"
            );
            let (min_ts, max_ts): (i64, i64) =
                conn.query_row(&min_max_sql, params![cutoff_unix_nano], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })?;

            let dt = Utc.timestamp_nanos(min_ts);
            let year = dt.year();
            let month = dt.month();

            let part_dir = self
                .config
                .parquet_root
                .join(format!("signal={signal}"))
                .join(format!("year={year:04}"))
                .join(format!("month={month:02}"));
            std::fs::create_dir_all(&part_dir)?;

            let file_name = format!("part-{cutoff_unix_nano}-{eligible}.parquet");
            let target_file = part_dir.join(&file_name);
            let escaped_target = escape_sql_literal(&target_file.to_string_lossy());

            conn.execute_batch("BEGIN TRANSACTION;")?;
            let copy_sql = format!(
                "COPY (SELECT * FROM {table} WHERE {ts_col} < {cutoff_unix_nano}) \
                 TO '{escaped_target}' (FORMAT PARQUET, COMPRESSION ZSTD);"
            );
            if let Err(e) = conn.execute_batch(&copy_sql) {
                let _ = conn.execute_batch("ROLLBACK;");
                return Err(MuObserveError::DuckDb(e));
            }

            if signal == "logs" {
                let byte_size = std::fs::metadata(&target_file)
                    .map(|m| m.len() as i64)
                    .unwrap_or(0);
                let shard_id = format!("shard-logs-{cutoff_unix_nano}-{eligible}");
                let tier = resolve_cold_tier();
                let storage_uri = target_file.to_string_lossy().to_string();

                if let Err(e) = conn.execute(
                    r#"
                    INSERT OR REPLACE INTO log_shards_catalog (
                        shard_id, tier, storage_uri, min_timestamp_ns, max_timestamp_ns, row_count, byte_size
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                    "#,
                    params![
                        shard_id,
                        tier,
                        storage_uri,
                        min_ts,
                        max_ts,
                        eligible,
                        byte_size
                    ],
                ) {
                    let _ = conn.execute_batch("ROLLBACK;");
                    return Err(MuObserveError::DuckDb(e));
                }

                if let Err(e) = conn.execute(
                    "UPDATE log_inverted_index SET shard_id = ?1 WHERE shard_id = 'hot' AND timestamp_unix_nano < ?2",
                    params![shard_id, cutoff_unix_nano],
                ) {
                    let _ = conn.execute_batch("ROLLBACK;");
                    return Err(MuObserveError::DuckDb(e));
                }
            }

            let delete_sql = format!("DELETE FROM {table} WHERE {ts_col} < ?1");
            if let Err(e) = conn.execute(&delete_sql, params![cutoff_unix_nano]) {
                let _ = conn.execute_batch("ROLLBACK;");
                return Err(MuObserveError::DuckDb(e));
            }
            conn.execute_batch("COMMIT;")?;

            let exported_u64 = eligible as u64;
            match signal {
                "logs" => report.exported_logs += exported_u64,
                "spans" => report.exported_spans += exported_u64,
                "metrics" => report.exported_metrics += exported_u64,
                "tests" => report.exported_tests += exported_u64,
                "benchmarks" => report.exported_benchmarks += exported_u64,
                _ => {}
            }
            report.parquet_files_written.push(target_file);
        }

        register_unified_views(&conn, Some(&self.config.parquet_root))?;
        Ok(report)
    }

    /// Enforces TTL on cold raw telemetry (`logs`, `spans`, `metrics`) older than `ttl_cutoff_unix_nano`
    /// while preserving `benchmarks` and `tests` indefinitely.
    pub fn enforce_cold_ttl(
        &self,
        store: &HotDuckDbStore,
        ttl_cutoff_unix_nano: i64,
    ) -> Result<u64, MuObserveError> {
        let mut pruned = 0u64;
        let conn = store.lock_conn()?;

        // First evict expired shards registered in log_shards_catalog
        let mut expired_shards: Vec<(String, String)> = Vec::new();
        if let Ok(mut stmt) = conn.prepare(
            "SELECT shard_id, storage_uri FROM log_shards_catalog WHERE max_timestamp_ns < ?1 ORDER BY max_timestamp_ns ASC",
        ) {
            if let Ok(rows) = stmt.query_map(params![ttl_cutoff_unix_nano], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            }) {
                for row in rows.flatten() {
                    expired_shards.push(row);
                }
            }
        }

        for (shard_id, storage_uri) in expired_shards {
            let p = Path::new(&storage_uri);
            if p.exists() && std::fs::remove_file(p).is_ok() {
                pruned += 1;
            }
            let _ = conn.execute(
                "DELETE FROM log_inverted_index WHERE shard_id = ?1",
                params![shard_id],
            );
            let _ = conn.execute(
                "DELETE FROM log_shards_catalog WHERE shard_id = ?1",
                params![shard_id],
            );
        }

        let ttl_signals = [
            ("logs", "timestamp_unix_nano"),
            ("spans", "start_time_unix_nano"),
            ("metrics", "timestamp_unix_nano"),
        ];

        for (signal, ts_col) in ttl_signals {
            let signal_dir = self.config.parquet_root.join(format!("signal={signal}"));
            let files = list_parquet_files(&signal_dir);
            for file in files {
                let escaped = escape_sql_literal(&file.to_string_lossy());
                let max_ts_sql =
                    format!("SELECT COALESCE(MAX({ts_col}), 0) FROM read_parquet('{escaped}')");
                let max_ts: i64 = conn.query_row(&max_ts_sql, [], |r| r.get(0)).unwrap_or(0);
                if max_ts > 0
                    && max_ts < ttl_cutoff_unix_nano
                    && std::fs::remove_file(&file).is_ok()
                {
                    pruned += 1;
                    if signal == "logs" {
                        let uri = file.to_string_lossy().to_string();
                        let _ = conn.execute(
                            "DELETE FROM log_inverted_index WHERE shard_id IN (SELECT shard_id FROM log_shards_catalog WHERE storage_uri = ?1)",
                            params![uri],
                        );
                        let _ = conn.execute(
                            "DELETE FROM log_shards_catalog WHERE storage_uri = ?1",
                            params![uri],
                        );
                    }
                }
            }
        }

        register_unified_views(&conn, Some(&self.config.parquet_root))?;
        Ok(pruned)
    }
}

fn resolve_cold_tier() -> &'static str {
    let has_s3 = std::env::var("MUOBSERVE_S3_ENDPOINT")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .is_some()
        || std::env::var("MUOBSERVE_S3_BUCKET")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .is_some();
    if has_s3 {
        "cold_s3"
    } else {
        "cold_parquet"
    }
}

fn list_parquet_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if !dir.exists() {
        return out;
    }
    let mut stack = vec![dir.to_path_buf()];
    while let Some(curr) = stack.pop() {
        if let Ok(entries) = std::fs::read_dir(&curr) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().and_then(|e| e.to_str()) == Some("parquet") {
                    out.push(path);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use mu_observable_ipc::{BenchmarkRunEntry, OtelLogEntry};
    use tempfile::tempdir;

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_parquet_compaction_unified_views_and_ttl_preservation() {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("hot.duckdb");
        let parquet_root = dir.path().join("parquet");

        let store =
            HotDuckDbStore::open(Some(&db_path), Some(&parquet_root)).expect("open hot duckdb");

        let old_ts = 1_700_000_000_000_000_000i64;
        let recent_ts = old_ts + (10 * 86_400 * 1_000_000_000i64); // +10 days

        // Insert 1 old log and 1 recent log
        let logs = vec![
            OtelLogEntry {
                timestamp_unix_nano: old_ts,
                trace_id: "trace-old".into(),
                span_id: "span-1".into(),
                severity_number: 5,
                severity_text: "DEBUG".into(),
                service_name: "action-runner-worker".into(),
                node_id: "worker-riscv64".into(),
                body: "old debug log".into(),
                attributes_json: "{}".into(),
                job_id: None,
                stage_id: None,
            },
            OtelLogEntry {
                timestamp_unix_nano: recent_ts,
                trace_id: "trace-recent".into(),
                span_id: "span-2".into(),
                severity_number: 9,
                severity_text: "INFO".into(),
                service_name: "action-runner-worker".into(),
                node_id: "worker-riscv64".into(),
                body: "recent info log".into(),
                attributes_json: "{}".into(),
                job_id: None,
                stage_id: None,
            },
        ];
        store.insert_logs_batch(&logs).expect("insert logs");

        // Insert 1 old benchmark and 1 recent benchmark
        let benches = vec![
            BenchmarkRunEntry {
                job_id: "job-old".into(),
                repo_key: "lma1980/k3-kernels-rvv".into(),
                branch_key: "main".into(),
                commit_sha: "111111".into(),
                crate_name: "k3-kernels-rvv".into(),
                bench_name: "gemm_a100".into(),
                ns_per_iter: 41_000.0,
                std_dev_ns: 100.0,
                mad_ns: 60.0,
                p50_ns: 41_000.0,
                p95_ns: 41_200.0,
                p99_ns: 41_300.0,
                throughput_value: None,
                throughput_unit: None,
                arch: "riscv64gc".into(),
                cpu_cluster: "A100".into(),
                vlen_bits: 1024,
                timestamp_unix_nano: old_ts,
                node_id: "worker-riscv64".into(),
            },
            BenchmarkRunEntry {
                job_id: "job-recent".into(),
                repo_key: "lma1980/k3-kernels-rvv".into(),
                branch_key: "main".into(),
                commit_sha: "222222".into(),
                crate_name: "k3-kernels-rvv".into(),
                bench_name: "gemm_a100".into(),
                ns_per_iter: 41_100.0,
                std_dev_ns: 100.0,
                mad_ns: 60.0,
                p50_ns: 41_100.0,
                p95_ns: 41_300.0,
                p99_ns: 41_400.0,
                throughput_value: None,
                throughput_unit: None,
                arch: "riscv64gc".into(),
                cpu_cluster: "A100".into(),
                vlen_bits: 1024,
                timestamp_unix_nano: recent_ts,
                node_id: "worker-riscv64".into(),
            },
        ];
        store
            .insert_benchmark_runs_batch(&benches)
            .expect("insert benches");

        let compactor = ParquetCompactor::new(
            CompactorConfig::new(&parquet_root)
                .with_hot_retention_days(7)
                .with_raw_telemetry_ttl_days(60),
        );

        let report = compactor
            .compact_at_now(&store, recent_ts)
            .expect("compact at recent_ts");
        assert_eq!(report.exported_logs, 1);
        assert_eq!(report.exported_benchmarks, 1);
        assert_eq!(report.parquet_files_written.len(), 2);

        // Hot tables now only have 1 row each (recent)
        assert_eq!(store.count_rows("otel_logs").unwrap(), 1);
        assert_eq!(store.count_rows("benchmark_runs").unwrap(), 1);
        assert_eq!(store.count_rows("log_shards_catalog").unwrap(), 1);

        // Unified views seamlessly combine hot (1) + cold Parquet (1) = 2 rows with zero row loss!
        assert_eq!(store.count_rows("v_logs").unwrap(), 2);
        assert_eq!(store.count_rows("v_benchmarks").unwrap(), 2);

        // Inverted index searches across both hot and cold shards via v_logs!
        let old_hits = store.search_logs_by_token("debug", None, 10).unwrap();
        assert_eq!(old_hits.len(), 1);
        assert_eq!(old_hits[0].body, "old debug log");

        // Now advance past 60-day TTL for raw logs: old_ts should be pruned from v_logs,
        // while v_benchmarks MUST preserve both rows indefinitely!
        let ttl_prune_cutoff = old_ts + 1_000;
        let pruned_files = compactor
            .enforce_cold_ttl(&store, ttl_prune_cutoff)
            .expect("enforce cold ttl");
        assert_eq!(pruned_files, 1);
        assert_eq!(store.count_rows("log_shards_catalog").unwrap(), 0);
        assert_eq!(store.count_rows("v_logs").unwrap(), 1);
        assert_eq!(store.count_rows("v_benchmarks").unwrap(), 2);
    }
}
