use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use arrow::record_batch::RecordBatch;
use duckdb::{params, Connection};
use mu_observable_ipc::{
    record_batch_to_benchmark_runs, record_batch_to_log_entries, record_batch_to_metric_entries,
    record_batch_to_span_entries, record_batch_to_test_runs, BenchmarkRunEntry,
    CentralBranchSnapshot, CentralJobRecord, CentralSubmoduleSnapshot, OtelLogEntry,
    OtelMetricEntry, OtelSpanEntry, QueryBranchSnapshotsRequest, QueryJobsHistoryRequest,
    QuerySubmoduleSnapshotsRequest, TestCaseRunEntry,
};

use crate::error::MuObserveError;
use crate::storage::views::register_unified_views;

const INTERNAL_LOG_REPO_KEY: &str = "__ar_job_logs__";
const INTERNAL_LEASE_REPO_KEY: &str = "__ar_ha_lease__";
const MAX_PERSISTED_JOB_LOGS: usize = 100;
const DEFAULT_FLUSH_INTERVAL_MS: u64 = 30_000;

fn now_epoch_ms() -> u64 {
    chrono::Utc::now().timestamp_millis().max(0) as u64
}

#[derive(Default)]
struct WriteBehindCache {
    /// Ephemeral HA lease snapshots keyed by `(branch_key, submodule_key)`.
    /// Served in O(1) from RAM without touching DuckDB on every 5s heartbeat.
    lease_snapshots: BTreeMap<(String, String), CentralSubmoduleSnapshot>,
    /// Active and recently updated job logs keyed by `(branch_key, submodule_key)`.
    job_logs: BTreeMap<(String, String), CentralSubmoduleSnapshot>,
    /// Keys in `job_logs` that have been modified in memory since the last DuckDB flush.
    dirty_job_logs: BTreeSet<(String, String)>,
}

impl WriteBehindCache {
    fn prune_job_logs_to_limit(&mut self, max_entries: usize) {
        while self.job_logs.len() > max_entries {
            let oldest_key = self
                .job_logs
                .iter()
                .min_by_key(|(_, snap)| snap.latest_active_queued_us.unwrap_or(0))
                .map(|(k, _)| k.clone());
            if let Some(k) = oldest_key {
                self.job_logs.remove(&k);
                self.dirty_job_logs.remove(&k);
            } else {
                break;
            }
        }
    }
}

/// Parameterized Hot DuckDB storage engine (`hot.duckdb`) hosting the 7-day OTEL telemetry
/// tables (`otel_logs`, `otel_spans`, `otel_metrics`), granular CI execution tables
/// (`test_case_runs`, `benchmark_runs`), and the centralized `ActionRunner-controller` catalog
/// (`jobs_history`, `branch_snapshots`, `submodule_snapshots`, `job_logs_store`).
#[derive(Clone)]
pub struct HotDuckDbStore {
    conn: Arc<Mutex<Connection>>,
    db_path: Option<PathBuf>,
    parquet_root: Option<PathBuf>,
    cache: Arc<Mutex<WriteBehindCache>>,
    dirty_writes: Arc<AtomicU64>,
    last_flush_ms: Arc<AtomicU64>,
    flush_interval_ms: u64,
}

impl HotDuckDbStore {
    /// Opens a file-backed `HotDuckDbStore` at `db_path` (or in-memory if `None`) and initializes
    /// all canonical tables, bounded DuckDB resource pragmas, and analytical views.
    pub fn open(
        db_path: Option<&Path>,
        parquet_root: Option<&Path>,
    ) -> Result<Self, MuObserveError> {
        let conn = match db_path {
            Some(p) => {
                if let Some(parent) = p.parent() {
                    if !parent.as_os_str().is_empty() {
                        std::fs::create_dir_all(parent)?;
                    }
                }
                match Connection::open(p) {
                    Ok(c) => c,
                    Err(e) if p.exists() => {
                        let snap = std::env::temp_dir().join(format!(
                            "muobserve-ro-{}-{}.duckdb",
                            std::process::id(),
                            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
                        ));
                        std::fs::copy(p, &snap)?;
                        let wal_src = PathBuf::from(format!("{}.wal", p.display()));
                        if wal_src.exists() {
                            let wal_dst = PathBuf::from(format!("{}.wal", snap.display()));
                            let _ = std::fs::copy(&wal_src, &wal_dst);
                        }
                        Connection::open(&snap).map_err(|_| e)?
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            None => Connection::open_in_memory()?,
        };

        let flush_interval_ms = std::env::var("MUOBSERVE_FLUSH_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(|s| s.clamp(1, 3600) * 1000)
            .unwrap_or(DEFAULT_FLUSH_INTERVAL_MS);

        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
            db_path: db_path.map(Path::to_path_buf),
            parquet_root: parquet_root.map(Path::to_path_buf),
            cache: Arc::new(Mutex::new(WriteBehindCache::default())),
            dirty_writes: Arc::new(AtomicU64::new(0)),
            last_flush_ms: Arc::new(AtomicU64::new(now_epoch_ms())),
            flush_interval_ms,
        };
        store.init_schema()?;
        store.refresh_views()?;
        Ok(store)
    }

    /// Convenience constructor for an in-memory `HotDuckDbStore` without cold Parquet directories.
    pub fn open_in_memory() -> Result<Self, MuObserveError> {
        Self::open(None, None)
    }

    /// Acquires the underlying DuckDB connection lock.
    pub fn lock_conn(&self) -> Result<MutexGuard<'_, Connection>, MuObserveError> {
        self.conn
            .lock()
            .map_err(|_| MuObserveError::LockPoisoned("HotDuckDbStore connection mutex".into()))
    }

    /// Returns the configured database path, if file-backed.
    #[must_use]
    pub fn db_path(&self) -> Option<&Path> {
        self.db_path.as_deref()
    }

    /// Returns the configured cold Parquet root directory, if any.
    #[must_use]
    pub fn parquet_root(&self) -> Option<&Path> {
        self.parquet_root.as_deref()
    }

    /// Updates the cold Parquet root directory and refreshes unified analytical views.
    pub fn set_parquet_root(&mut self, root: Option<PathBuf>) -> Result<(), MuObserveError> {
        self.parquet_root = root;
        self.refresh_views()
    }

    /// Refreshes the unified DuckDB analytical views (`v_logs`, `v_traces`, `v_metrics`,
    /// `v_tests`, `v_benchmarks`, `v_jobs_history`).
    pub fn refresh_views(&self) -> Result<(), MuObserveError> {
        let conn = self.lock_conn()?;
        register_unified_views(&conn, self.parquet_root.as_deref())
    }

    fn init_schema(&self) -> Result<(), MuObserveError> {
        let conn = self.lock_conn()?;
        if self.db_path.is_some() {
            let mem_limit = std::env::var("MUOBSERVE_DUCKDB_MEMORY_LIMIT")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| "1GB".to_string());
            let threads: usize = std::env::var("MUOBSERVE_DUCKDB_THREADS")
                .ok()
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(2)
                .clamp(1, 16);
            let _ = conn.execute_batch(&format!(
                "SET memory_limit = '{}'; SET threads = {}; SET allocator_flush_threshold = '16MB'; SET wal_autocheckpoint = '64MB';",
                mem_limit.replace('\'', ""),
                threads
            ));
        }

        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS otel_logs (
                timestamp_unix_nano BIGINT NOT NULL,
                trace_id VARCHAR NOT NULL,
                span_id VARCHAR NOT NULL,
                severity_number INTEGER NOT NULL,
                severity_text VARCHAR NOT NULL,
                service_name VARCHAR NOT NULL,
                node_id VARCHAR NOT NULL,
                body VARCHAR NOT NULL,
                attributes_json VARCHAR NOT NULL,
                job_id VARCHAR,
                stage_id VARCHAR
            );

            CREATE TABLE IF NOT EXISTS otel_spans (
                trace_id VARCHAR NOT NULL,
                span_id VARCHAR NOT NULL,
                parent_span_id VARCHAR,
                service_name VARCHAR NOT NULL,
                node_id VARCHAR NOT NULL,
                span_name VARCHAR NOT NULL,
                span_kind VARCHAR NOT NULL,
                start_time_unix_nano BIGINT NOT NULL,
                end_time_unix_nano BIGINT NOT NULL,
                duration_ns BIGINT NOT NULL,
                status_code VARCHAR NOT NULL,
                status_message VARCHAR,
                attributes_json VARCHAR NOT NULL
            );

            CREATE TABLE IF NOT EXISTS otel_metrics (
                timestamp_unix_nano BIGINT NOT NULL,
                service_name VARCHAR NOT NULL,
                node_id VARCHAR NOT NULL,
                metric_name VARCHAR NOT NULL,
                metric_unit VARCHAR NOT NULL,
                value_f64 DOUBLE NOT NULL,
                arch VARCHAR NOT NULL,
                cpu_cluster VARCHAR,
                vlen_bits INTEGER,
                memlock_used_bytes BIGINT,
                memlock_limit_bytes BIGINT,
                trace_id VARCHAR,
                span_id VARCHAR,
                attributes_json VARCHAR NOT NULL
            );

            CREATE TABLE IF NOT EXISTS test_case_runs (
                job_id VARCHAR NOT NULL,
                repo_key VARCHAR NOT NULL,
                branch_key VARCHAR NOT NULL,
                commit_sha VARCHAR NOT NULL,
                crate_name VARCHAR NOT NULL,
                test_binary VARCHAR NOT NULL,
                test_name VARCHAR NOT NULL,
                status VARCHAR NOT NULL,
                duration_ms DOUBLE NOT NULL,
                failure_summary VARCHAR,
                timestamp_unix_nano BIGINT NOT NULL,
                node_id VARCHAR NOT NULL,
                arch VARCHAR NOT NULL
            );

            CREATE TABLE IF NOT EXISTS benchmark_runs (
                job_id VARCHAR NOT NULL,
                repo_key VARCHAR NOT NULL,
                branch_key VARCHAR NOT NULL,
                commit_sha VARCHAR NOT NULL,
                crate_name VARCHAR NOT NULL,
                bench_name VARCHAR NOT NULL,
                ns_per_iter DOUBLE NOT NULL,
                std_dev_ns DOUBLE NOT NULL,
                mad_ns DOUBLE NOT NULL,
                p50_ns DOUBLE NOT NULL,
                p95_ns DOUBLE NOT NULL,
                p99_ns DOUBLE NOT NULL,
                throughput_value DOUBLE,
                throughput_unit VARCHAR,
                arch VARCHAR NOT NULL,
                cpu_cluster VARCHAR NOT NULL,
                vlen_bits INTEGER NOT NULL,
                timestamp_unix_nano BIGINT NOT NULL,
                node_id VARCHAR NOT NULL
            );

            CREATE TABLE IF NOT EXISTS jobs_history (
                job_id VARCHAR PRIMARY KEY,
                event_type VARCHAR NOT NULL,
                repo_name VARCHAR NOT NULL,
                repo_key VARCHAR NOT NULL,
                clone_url VARCHAR NOT NULL,
                commit_sha VARCHAR NOT NULL,
                ref_name VARCHAR NOT NULL,
                branch_key VARCHAR NOT NULL,
                sender VARCHAR NOT NULL,
                queued_at_us BIGINT NOT NULL,
                updated_at_us BIGINT NOT NULL,
                status_state VARCHAR NOT NULL,
                exit_code INTEGER,
                duration_secs BIGINT,
                quality_score INTEGER,
                letter_grade VARCHAR,
                coverage_pct DOUBLE,
                benchmark_summary VARCHAR,
                tests_passed INTEGER,
                tests_total INTEGER,
                advisories_count INTEGER,
                clippy_warnings INTEGER,
                record_json VARCHAR NOT NULL
            );

            CREATE TABLE IF NOT EXISTS branch_snapshots (
                repo_key VARCHAR NOT NULL,
                branch_key VARCHAR NOT NULL,
                repo_name VARCHAR NOT NULL,
                ref_name VARCHAR NOT NULL,
                latest_active_job_id VARCHAR,
                latest_active_json VARCHAR,
                latest_active_queued_us BIGINT,
                latest_completed_job_id VARCHAR,
                latest_completed_json VARCHAR,
                latest_completed_queued_us BIGINT,
                PRIMARY KEY (repo_key, branch_key)
            );

            CREATE TABLE IF NOT EXISTS submodule_snapshots (
                parent_repo_key VARCHAR NOT NULL,
                branch_key VARCHAR NOT NULL,
                submodule_key VARCHAR NOT NULL,
                submodule_path_key VARCHAR NOT NULL,
                latest_active_job_id VARCHAR,
                latest_active_json VARCHAR,
                latest_active_queued_us BIGINT,
                latest_completed_job_id VARCHAR,
                latest_completed_json VARCHAR,
                latest_completed_queued_us BIGINT,
                PRIMARY KEY (parent_repo_key, branch_key, submodule_key)
            );

            CREATE TABLE IF NOT EXISTS job_logs_store (
                branch_key VARCHAR NOT NULL,
                submodule_key VARCHAR NOT NULL,
                submodule_path_key VARCHAR NOT NULL,
                latest_active_job_id VARCHAR,
                latest_active_json VARCHAR,
                latest_active_queued_us BIGINT,
                latest_completed_job_id VARCHAR,
                latest_completed_json VARCHAR,
                latest_completed_queued_us BIGINT,
                PRIMARY KEY (branch_key, submodule_key)
            );
            "#,
        )?;

        // Hydrate any persisted HA lease rows into the in-memory cache before purging
        // synthetic __ar_ha_lease__ and __ar_job_logs__ rows from submodule_snapshots.
        if let Ok(mut stmt) = conn.prepare(
            r#"
            SELECT
                parent_repo_key, branch_key, submodule_key, submodule_path_key,
                latest_active_job_id, latest_active_json, latest_active_queued_us,
                latest_completed_job_id, latest_completed_json, latest_completed_queued_us
            FROM submodule_snapshots
            WHERE parent_repo_key = '__ar_ha_lease__'
            "#,
        ) {
            if let Ok(rows) = stmt.query_map([], |row| {
                Ok(CentralSubmoduleSnapshot {
                    parent_repo_key: row.get(0)?,
                    branch_key: row.get(1)?,
                    submodule_key: row.get(2)?,
                    submodule_path_key: row.get(3)?,
                    latest_active_job_id: row.get(4)?,
                    latest_active_json: row.get(5)?,
                    latest_active_queued_us: row.get(6)?,
                    latest_completed_job_id: row.get(7)?,
                    latest_completed_json: row.get(8)?,
                    latest_completed_queued_us: row.get(9)?,
                })
            }) {
                if let Ok(mut cache) = self.cache.lock() {
                    for snap in rows.flatten() {
                        cache
                            .lease_snapshots
                            .insert((snap.branch_key.clone(), snap.submodule_key.clone()), snap);
                    }
                }
            }
        }

        // Migrate newest job logs from submodule_snapshots into dedicated job_logs_store,
        // remove __ar_job_logs__ and __ar_ha_lease__ bloat from submodule_snapshots, and prune retention.
        let migrated_or_purged: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM submodule_snapshots WHERE parent_repo_key IN ('__ar_job_logs__', '__ar_ha_lease__')",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);

        if migrated_or_purged > 0 {
            conn.execute_batch(
                r#"
                BEGIN TRANSACTION;
                INSERT OR REPLACE INTO job_logs_store (
                    branch_key, submodule_key, submodule_path_key,
                    latest_active_job_id, latest_active_json, latest_active_queued_us,
                    latest_completed_job_id, latest_completed_json, latest_completed_queued_us
                )
                SELECT
                    branch_key, submodule_key, submodule_path_key,
                    latest_active_job_id, latest_active_json, latest_active_queued_us,
                    latest_completed_job_id, latest_completed_json, latest_completed_queued_us
                FROM submodule_snapshots
                WHERE parent_repo_key = '__ar_job_logs__'
                ORDER BY COALESCE(latest_active_queued_us, 0) DESC
                LIMIT 100;

                DELETE FROM submodule_snapshots
                WHERE parent_repo_key IN ('__ar_job_logs__', '__ar_ha_lease__');
                COMMIT;
                "#,
            )?;
            if self.db_path.is_some() {
                let _ = conn.execute_batch("CHECKPOINT;");
            }
        }

        Ok(())
    }

    /// Flushes dirty in-memory write-behind entries (`__ar_job_logs__`) to `job_logs_store`,
    /// prunes `job_logs_store` retention to `MAX_PERSISTED_JOB_LOGS`, and executes a DuckDB
    /// `CHECKPOINT` when `force_checkpoint` is `true` or the delayed flush interval has elapsed.
    pub fn flush_delayed(&self, force_checkpoint: bool) -> Result<u32, MuObserveError> {
        let now_ms = now_epoch_ms();
        let last_ms = self.last_flush_ms.load(Ordering::Relaxed);
        let interval_elapsed = now_ms.saturating_sub(last_ms) >= self.flush_interval_ms;

        if !force_checkpoint && !interval_elapsed {
            return Ok(0);
        }

        let dirty_logs: Vec<CentralSubmoduleSnapshot> = {
            let mut cache = self
                .cache
                .lock()
                .map_err(|_| MuObserveError::LockPoisoned("WriteBehindCache mutex".into()))?;
            let keys: Vec<(String, String)> = cache.dirty_job_logs.iter().cloned().collect();
            let mut out = Vec::with_capacity(keys.len());
            for k in keys {
                if let Some(snap) = cache.job_logs.get(&k) {
                    out.push(snap.clone());
                }
            }
            cache.dirty_job_logs.clear();
            cache.prune_job_logs_to_limit(MAX_PERSISTED_JOB_LOGS);
            out
        };

        let prior_dirty = self.dirty_writes.swap(0, Ordering::Relaxed);
        self.last_flush_ms.store(now_ms, Ordering::Relaxed);

        if dirty_logs.is_empty() && prior_dirty == 0 && !force_checkpoint {
            return Ok(0);
        }

        let conn = self.lock_conn()?;
        let mut flushed_count = 0u32;

        if !dirty_logs.is_empty() {
            conn.execute_batch("BEGIN TRANSACTION;")?;
            {
                let mut stmt = conn.prepare(
                    r#"
                    INSERT OR REPLACE INTO job_logs_store (
                        branch_key, submodule_key, submodule_path_key,
                        latest_active_job_id, latest_active_json, latest_active_queued_us,
                        latest_completed_job_id, latest_completed_json, latest_completed_queued_us
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                    "#,
                )?;
                for s in &dirty_logs {
                    stmt.execute(params![
                        s.branch_key,
                        s.submodule_key,
                        s.submodule_path_key,
                        s.latest_active_job_id,
                        s.latest_active_json,
                        s.latest_active_queued_us,
                        s.latest_completed_job_id,
                        s.latest_completed_json,
                        s.latest_completed_queued_us,
                    ])?;
                    flushed_count = flushed_count.saturating_add(1);
                }
            }
            let _ = conn.execute(
                r#"
                DELETE FROM job_logs_store
                WHERE (branch_key, submodule_key) NOT IN (
                    SELECT branch_key, submodule_key
                    FROM job_logs_store
                    ORDER BY COALESCE(latest_active_queued_us, 0) DESC
                    LIMIT ?1
                )
                "#,
                params![MAX_PERSISTED_JOB_LOGS as i64],
            );
            conn.execute_batch("COMMIT;")?;
        }

        if self.db_path.is_some() && (force_checkpoint || !dirty_logs.is_empty() || prior_dirty > 0)
        {
            let _ = conn.execute_batch("CHECKPOINT;");
        }

        Ok(flushed_count)
    }

    fn record_write_and_maybe_flush(&self) {
        self.dirty_writes.fetch_add(1, Ordering::Relaxed);
        let now_ms = now_epoch_ms();
        let last_ms = self.last_flush_ms.load(Ordering::Relaxed);
        if now_ms.saturating_sub(last_ms) >= self.flush_interval_ms {
            let _ = self.flush_delayed(false);
        }
    }

    /// Inserts a batch of [`OtelLogEntry`] rows using strictly parameterized statements (`?1..`).
    pub fn insert_logs_batch(&self, entries: &[OtelLogEntry]) -> Result<u32, MuObserveError> {
        if entries.is_empty() {
            return Ok(0);
        }
        let count = {
            let conn = self.lock_conn()?;
            conn.execute_batch("BEGIN TRANSACTION;")?;
            let mut stmt = conn.prepare(
                r#"
                INSERT INTO otel_logs (
                    timestamp_unix_nano, trace_id, span_id, severity_number, severity_text,
                    service_name, node_id, body, attributes_json, job_id, stage_id
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                "#,
            )?;

            let mut count = 0u32;
            for e in entries {
                stmt.execute(params![
                    e.timestamp_unix_nano,
                    e.trace_id,
                    e.span_id,
                    e.severity_number,
                    e.severity_text,
                    e.service_name,
                    e.node_id,
                    e.body,
                    e.attributes_json,
                    e.job_id,
                    e.stage_id,
                ])?;
                count = count.saturating_add(1);
            }
            drop(stmt);
            conn.execute_batch("COMMIT;")?;
            count
        };
        self.record_write_and_maybe_flush();
        Ok(count)
    }

    /// Ingests an Apache Arrow [`RecordBatch`] of `otel_logs`.
    pub fn ingest_arrow_logs(&self, batch: &RecordBatch) -> Result<u32, MuObserveError> {
        let entries = record_batch_to_log_entries(batch)?;
        self.insert_logs_batch(&entries)
    }

    /// Inserts a batch of [`OtelSpanEntry`] rows using strictly parameterized statements (`?1..`).
    pub fn insert_spans_batch(&self, entries: &[OtelSpanEntry]) -> Result<u32, MuObserveError> {
        if entries.is_empty() {
            return Ok(0);
        }
        let count = {
            let conn = self.lock_conn()?;
            conn.execute_batch("BEGIN TRANSACTION;")?;
            let mut stmt = conn.prepare(
                r#"
                INSERT INTO otel_spans (
                    trace_id, span_id, parent_span_id, service_name, node_id,
                    span_name, span_kind, start_time_unix_nano, end_time_unix_nano,
                    duration_ns, status_code, status_message, attributes_json
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
                "#,
            )?;

            let mut count = 0u32;
            for e in entries {
                stmt.execute(params![
                    e.trace_id,
                    e.span_id,
                    e.parent_span_id,
                    e.service_name,
                    e.node_id,
                    e.span_name,
                    e.span_kind,
                    e.start_time_unix_nano,
                    e.end_time_unix_nano,
                    e.duration_ns as i64,
                    e.status_code,
                    e.status_message,
                    e.attributes_json,
                ])?;
                count = count.saturating_add(1);
            }
            drop(stmt);
            conn.execute_batch("COMMIT;")?;
            count
        };
        self.record_write_and_maybe_flush();
        Ok(count)
    }

    /// Ingests an Apache Arrow [`RecordBatch`] of `otel_spans`.
    pub fn ingest_arrow_spans(&self, batch: &RecordBatch) -> Result<u32, MuObserveError> {
        let entries = record_batch_to_span_entries(batch)?;
        self.insert_spans_batch(&entries)
    }

    /// Inserts a batch of [`OtelMetricEntry`] rows using strictly parameterized statements (`?1..`).
    pub fn insert_metrics_batch(&self, entries: &[OtelMetricEntry]) -> Result<u32, MuObserveError> {
        if entries.is_empty() {
            return Ok(0);
        }
        let count = {
            let conn = self.lock_conn()?;
            conn.execute_batch("BEGIN TRANSACTION;")?;
            let mut stmt = conn.prepare(
                r#"
                INSERT INTO otel_metrics (
                    timestamp_unix_nano, service_name, node_id, metric_name, metric_unit,
                    value_f64, arch, cpu_cluster, vlen_bits, memlock_used_bytes,
                    memlock_limit_bytes, trace_id, span_id, attributes_json
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
                "#,
            )?;

            let mut count = 0u32;
            for e in entries {
                let vlen_i32 = e.vlen_bits.map(|v| v as i32);
                let mem_used_i64 = e.memlock_used_bytes.map(|v| v as i64);
                let mem_limit_i64 = e.memlock_limit_bytes.map(|v| v as i64);
                stmt.execute(params![
                    e.timestamp_unix_nano,
                    e.service_name,
                    e.node_id,
                    e.metric_name,
                    e.metric_unit,
                    e.value_f64,
                    e.arch,
                    e.cpu_cluster,
                    vlen_i32,
                    mem_used_i64,
                    mem_limit_i64,
                    e.trace_id,
                    e.span_id,
                    e.attributes_json,
                ])?;
                count = count.saturating_add(1);
            }
            drop(stmt);
            conn.execute_batch("COMMIT;")?;
            count
        };
        self.record_write_and_maybe_flush();
        Ok(count)
    }

    /// Ingests an Apache Arrow [`RecordBatch`] of `otel_metrics`.
    pub fn ingest_arrow_metrics(&self, batch: &RecordBatch) -> Result<u32, MuObserveError> {
        let entries = record_batch_to_metric_entries(batch)?;
        self.insert_metrics_batch(&entries)
    }

    /// Inserts a batch of [`TestCaseRunEntry`] rows using strictly parameterized statements (`?1..`).
    pub fn insert_test_runs_batch(
        &self,
        entries: &[TestCaseRunEntry],
    ) -> Result<u32, MuObserveError> {
        if entries.is_empty() {
            return Ok(0);
        }
        let count = {
            let conn = self.lock_conn()?;
            conn.execute_batch("BEGIN TRANSACTION;")?;
            let mut stmt = conn.prepare(
                r#"
                INSERT INTO test_case_runs (
                    job_id, repo_key, branch_key, commit_sha, crate_name,
                    test_binary, test_name, status, duration_ms, failure_summary,
                    timestamp_unix_nano, node_id, arch
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
                "#,
            )?;

            let mut count = 0u32;
            for e in entries {
                stmt.execute(params![
                    e.job_id,
                    e.repo_key,
                    e.branch_key,
                    e.commit_sha,
                    e.crate_name,
                    e.test_binary,
                    e.test_name,
                    e.status,
                    e.duration_ms,
                    e.failure_summary,
                    e.timestamp_unix_nano,
                    e.node_id,
                    e.arch,
                ])?;
                count = count.saturating_add(1);
            }
            drop(stmt);
            conn.execute_batch("COMMIT;")?;
            count
        };
        self.record_write_and_maybe_flush();
        Ok(count)
    }

    /// Ingests an Apache Arrow [`RecordBatch`] of `test_case_runs`.
    pub fn ingest_arrow_test_runs(&self, batch: &RecordBatch) -> Result<u32, MuObserveError> {
        let entries = record_batch_to_test_runs(batch)?;
        self.insert_test_runs_batch(&entries)
    }

    /// Inserts a batch of [`BenchmarkRunEntry`] rows using strictly parameterized statements (`?1..`).
    pub fn insert_benchmark_runs_batch(
        &self,
        entries: &[BenchmarkRunEntry],
    ) -> Result<u32, MuObserveError> {
        if entries.is_empty() {
            return Ok(0);
        }
        let count = {
            let conn = self.lock_conn()?;
            conn.execute_batch("BEGIN TRANSACTION;")?;
            let mut stmt = conn.prepare(
                r#"
                INSERT INTO benchmark_runs (
                    job_id, repo_key, branch_key, commit_sha, crate_name,
                    bench_name, ns_per_iter, std_dev_ns, mad_ns, p50_ns,
                    p95_ns, p99_ns, throughput_value, throughput_unit, arch,
                    cpu_cluster, vlen_bits, timestamp_unix_nano, node_id
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)
                "#,
            )?;

            let mut count = 0u32;
            for e in entries {
                stmt.execute(params![
                    e.job_id,
                    e.repo_key,
                    e.branch_key,
                    e.commit_sha,
                    e.crate_name,
                    e.bench_name,
                    e.ns_per_iter,
                    e.std_dev_ns,
                    e.mad_ns,
                    e.p50_ns,
                    e.p95_ns,
                    e.p99_ns,
                    e.throughput_value,
                    e.throughput_unit,
                    e.arch,
                    e.cpu_cluster,
                    e.vlen_bits as i32,
                    e.timestamp_unix_nano,
                    e.node_id,
                ])?;
                count = count.saturating_add(1);
            }
            drop(stmt);
            conn.execute_batch("COMMIT;")?;
            count
        };
        self.record_write_and_maybe_flush();
        Ok(count)
    }

    /// Ingests an Apache Arrow [`RecordBatch`] of `benchmark_runs`.
    pub fn ingest_arrow_benchmark_runs(&self, batch: &RecordBatch) -> Result<u32, MuObserveError> {
        let entries = record_batch_to_benchmark_runs(batch)?;
        self.insert_benchmark_runs_batch(&entries)
    }

    /// Upserts a batch of centralized `ActionRunner-controller` job records, branch snapshots,
    /// and submodule snapshots atomically.
    ///
    /// - `__ar_ha_lease__` rows are updated in the in-memory `WriteBehindCache` in `O(1)` without
    ///   touching DuckDB or triggering disk checkpoints.
    /// - `__ar_job_logs__` rows are buffered in the in-memory `WriteBehindCache` and flushed to
    ///   the dedicated `job_logs_store` table on the delayed flush interval.
    pub fn upsert_ci_state_batch(
        &self,
        records: &[CentralJobRecord],
        branch_snapshots: &[CentralBranchSnapshot],
        submodule_snapshots: &[CentralSubmoduleSnapshot],
    ) -> Result<u32, MuObserveError> {
        let mut total = 0u32;
        let mut regular_sub_snapshots: Vec<&CentralSubmoduleSnapshot> = Vec::new();
        let mut had_cached_log_update = false;

        if !submodule_snapshots.is_empty() {
            let mut cache = self
                .cache
                .lock()
                .map_err(|_| MuObserveError::LockPoisoned("WriteBehindCache mutex".into()))?;
            for s in submodule_snapshots {
                if s.parent_repo_key == INTERNAL_LEASE_REPO_KEY {
                    cache
                        .lease_snapshots
                        .insert((s.branch_key.clone(), s.submodule_key.clone()), s.clone());
                    total = total.saturating_add(1);
                } else if s.parent_repo_key == INTERNAL_LOG_REPO_KEY {
                    let key = (s.branch_key.clone(), s.submodule_key.clone());
                    cache.job_logs.insert(key.clone(), s.clone());
                    cache.dirty_job_logs.insert(key);
                    had_cached_log_update = true;
                    total = total.saturating_add(1);
                } else {
                    regular_sub_snapshots.push(s);
                }
            }
            if had_cached_log_update {
                cache.prune_job_logs_to_limit(MAX_PERSISTED_JOB_LOGS);
            }
        }

        let has_db_writes = !records.is_empty()
            || !branch_snapshots.is_empty()
            || !regular_sub_snapshots.is_empty();

        if has_db_writes {
            let conn = self.lock_conn()?;
            conn.execute_batch("BEGIN TRANSACTION;")?;

            if !records.is_empty() {
                let mut stmt = conn.prepare(
                    r#"
                    INSERT OR REPLACE INTO jobs_history (
                        job_id, event_type, repo_name, repo_key, clone_url,
                        commit_sha, ref_name, branch_key, sender, queued_at_us,
                        updated_at_us, status_state, exit_code, duration_secs, quality_score,
                        letter_grade, coverage_pct, benchmark_summary, tests_passed, tests_total,
                        advisories_count, clippy_warnings, record_json
                    ) VALUES (
                        ?1, ?2, ?3, ?4, ?5,
                        ?6, ?7, ?8, ?9, ?10,
                        ?11, ?12, ?13, ?14, ?15,
                        ?16, ?17, ?18, ?19, ?20,
                        ?21, ?22, ?23
                    )
                    "#,
                )?;
                for r in records {
                    stmt.execute(params![
                        r.job_id,
                        r.event_type,
                        r.repo_name,
                        r.repo_key,
                        r.clone_url,
                        r.commit_sha,
                        r.ref_name,
                        r.branch_key,
                        r.sender,
                        r.queued_at_us,
                        r.updated_at_us,
                        r.status_state,
                        r.exit_code,
                        r.duration_secs,
                        r.quality_score,
                        r.letter_grade,
                        r.coverage_pct,
                        r.benchmark_summary,
                        r.tests_passed,
                        r.tests_total,
                        r.advisories_count,
                        r.clippy_warnings,
                        r.record_json,
                    ])?;
                    total = total.saturating_add(1);
                }
            }

            if !branch_snapshots.is_empty() {
                let mut stmt = conn.prepare(
                    r#"
                    INSERT OR REPLACE INTO branch_snapshots (
                        repo_key, branch_key, repo_name, ref_name,
                        latest_active_job_id, latest_active_json, latest_active_queued_us,
                        latest_completed_job_id, latest_completed_json, latest_completed_queued_us
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                    "#,
                )?;
                for b in branch_snapshots {
                    stmt.execute(params![
                        b.repo_key,
                        b.branch_key,
                        b.repo_name,
                        b.ref_name,
                        b.latest_active_job_id,
                        b.latest_active_json,
                        b.latest_active_queued_us,
                        b.latest_completed_job_id,
                        b.latest_completed_json,
                        b.latest_completed_queued_us,
                    ])?;
                    total = total.saturating_add(1);
                }
            }

            if !regular_sub_snapshots.is_empty() {
                let mut stmt = conn.prepare(
                    r#"
                    INSERT OR REPLACE INTO submodule_snapshots (
                        parent_repo_key, branch_key, submodule_key, submodule_path_key,
                        latest_active_job_id, latest_active_json, latest_active_queued_us,
                        latest_completed_job_id, latest_completed_json, latest_completed_queued_us
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                    "#,
                )?;
                for s in regular_sub_snapshots {
                    stmt.execute(params![
                        s.parent_repo_key,
                        s.branch_key,
                        s.submodule_key,
                        s.submodule_path_key,
                        s.latest_active_job_id,
                        s.latest_active_json,
                        s.latest_active_queued_us,
                        s.latest_completed_job_id,
                        s.latest_completed_json,
                        s.latest_completed_queued_us,
                    ])?;
                    total = total.saturating_add(1);
                }
            }

            conn.execute_batch("COMMIT;")?;
        }

        if has_db_writes || had_cached_log_update {
            self.record_write_and_maybe_flush();
        }
        Ok(total)
    }

    /// Queries centralized `jobs_history` (via `v_jobs_history`) with parameterized filters.
    pub fn query_jobs_history(
        &self,
        req: &QueryJobsHistoryRequest,
    ) -> Result<Vec<CentralJobRecord>, MuObserveError> {
        let conn = self.lock_conn()?;
        let limit = if req.limit == 0 {
            100
        } else {
            req.limit.min(5000)
        } as i64;
        let mut stmt = conn.prepare(
            r#"
            SELECT
                job_id, event_type, repo_name, repo_key, clone_url,
                commit_sha, ref_name, branch_key, sender, queued_at_us,
                updated_at_us, status_state, exit_code, duration_secs, quality_score,
                letter_grade, coverage_pct, benchmark_summary, tests_passed, tests_total,
                advisories_count, clippy_warnings, record_json
            FROM v_jobs_history
            WHERE (?1 IS NULL OR repo_key = ?1)
              AND (?2 IS NULL OR branch_key = ?2)
              AND (?3 IS NULL OR job_id = ?3)
            ORDER BY queued_at_us DESC
            LIMIT ?4
            "#,
        )?;

        let rows = stmt.query_map(
            params![req.repo_key, req.branch_key, req.job_id, limit],
            |row| {
                Ok(CentralJobRecord {
                    job_id: row.get(0)?,
                    event_type: row.get(1)?,
                    repo_name: row.get(2)?,
                    repo_key: row.get(3)?,
                    clone_url: row.get(4)?,
                    commit_sha: row.get(5)?,
                    ref_name: row.get(6)?,
                    branch_key: row.get(7)?,
                    sender: row.get(8)?,
                    queued_at_us: row.get(9)?,
                    updated_at_us: row.get(10)?,
                    status_state: row.get(11)?,
                    exit_code: row.get(12)?,
                    duration_secs: row.get(13)?,
                    quality_score: row.get(14)?,
                    letter_grade: row.get(15)?,
                    coverage_pct: row.get(16)?,
                    benchmark_summary: row.get(17)?,
                    tests_passed: row.get(18)?,
                    tests_total: row.get(19)?,
                    advisories_count: row.get(20)?,
                    clippy_warnings: row.get(21)?,
                    record_json: row.get(22)?,
                })
            },
        )?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Queries centralized `branch_snapshots` with parameterized filters.
    pub fn query_branch_snapshots(
        &self,
        req: &QueryBranchSnapshotsRequest,
    ) -> Result<Vec<CentralBranchSnapshot>, MuObserveError> {
        let conn = self.lock_conn()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT
                repo_key, branch_key, repo_name, ref_name,
                latest_active_job_id, latest_active_json, latest_active_queued_us,
                latest_completed_job_id, latest_completed_json, latest_completed_queued_us
            FROM branch_snapshots
            WHERE (?1 IS NULL OR repo_key = ?1)
              AND (?2 IS NULL OR branch_key = ?2)
            ORDER BY repo_key ASC, branch_key ASC
            "#,
        )?;

        let rows = stmt.query_map(params![req.repo_key, req.branch_key], |row| {
            Ok(CentralBranchSnapshot {
                repo_key: row.get(0)?,
                branch_key: row.get(1)?,
                repo_name: row.get(2)?,
                ref_name: row.get(3)?,
                latest_active_job_id: row.get(4)?,
                latest_active_json: row.get(5)?,
                latest_active_queued_us: row.get(6)?,
                latest_completed_job_id: row.get(7)?,
                latest_completed_json: row.get(8)?,
                latest_completed_queued_us: row.get(9)?,
            })
        })?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Queries centralized `submodule_snapshots` with parameterized filters.
    ///
    /// - Queries targeting `__ar_ha_lease__` are served directly from the in-memory `WriteBehindCache`.
    /// - Queries targeting `__ar_job_logs__` merge the in-memory `WriteBehindCache` with `job_logs_store`.
    pub fn query_submodule_snapshots(
        &self,
        req: &QuerySubmoduleSnapshotsRequest,
    ) -> Result<Vec<CentralSubmoduleSnapshot>, MuObserveError> {
        if req.parent_repo_key.as_deref() == Some(INTERNAL_LEASE_REPO_KEY) {
            let cache = self
                .cache
                .lock()
                .map_err(|_| MuObserveError::LockPoisoned("WriteBehindCache mutex".into()))?;
            let out: Vec<CentralSubmoduleSnapshot> = cache
                .lease_snapshots
                .values()
                .filter(|s| {
                    req.submodule_key
                        .as_deref()
                        .map(|sk| s.submodule_key == sk)
                        .unwrap_or(true)
                        && req
                            .branch_key
                            .as_deref()
                            .map(|bk| s.branch_key == bk)
                            .unwrap_or(true)
                })
                .cloned()
                .collect();
            return Ok(out);
        }

        if req.parent_repo_key.as_deref() == Some(INTERNAL_LOG_REPO_KEY) {
            let mut merged: BTreeMap<(String, String), CentralSubmoduleSnapshot> = {
                let cache = self
                    .cache
                    .lock()
                    .map_err(|_| MuObserveError::LockPoisoned("WriteBehindCache mutex".into()))?;
                cache
                    .job_logs
                    .iter()
                    .filter(|((bk, sk), _)| {
                        req.submodule_key
                            .as_deref()
                            .map(|q_sk| sk == q_sk)
                            .unwrap_or(true)
                            && req
                                .branch_key
                                .as_deref()
                                .map(|q_bk| bk == q_bk)
                                .unwrap_or(true)
                    })
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            };

            // If a specific (branch_key, submodule_key) was requested and already hit in memory,
            // return immediately without acquiring the DuckDB mutex.
            if req.submodule_key.is_some() && !merged.is_empty() {
                return Ok(merged.into_values().collect());
            }

            let conn = self.lock_conn()?;
            let mut stmt = conn.prepare(
                r#"
                SELECT
                    branch_key, submodule_key, submodule_path_key,
                    latest_active_job_id, latest_active_json, latest_active_queued_us,
                    latest_completed_job_id, latest_completed_json, latest_completed_queued_us
                FROM job_logs_store
                WHERE (?1 IS NULL OR submodule_key = ?1)
                  AND (?2 IS NULL OR branch_key = ?2)
                ORDER BY branch_key ASC, submodule_key ASC
                "#,
            )?;
            let rows = stmt.query_map(params![req.submodule_key, req.branch_key], |row| {
                Ok(CentralSubmoduleSnapshot {
                    parent_repo_key: INTERNAL_LOG_REPO_KEY.to_string(),
                    branch_key: row.get(0)?,
                    submodule_key: row.get(1)?,
                    submodule_path_key: row.get(2)?,
                    latest_active_job_id: row.get(3)?,
                    latest_active_json: row.get(4)?,
                    latest_active_queued_us: row.get(5)?,
                    latest_completed_job_id: row.get(6)?,
                    latest_completed_json: row.get(7)?,
                    latest_completed_queued_us: row.get(8)?,
                })
            })?;
            for r in rows {
                let snap = r?;
                merged
                    .entry((snap.branch_key.clone(), snap.submodule_key.clone()))
                    .or_insert(snap);
            }
            return Ok(merged.into_values().collect());
        }

        let conn = self.lock_conn()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT
                parent_repo_key, branch_key, submodule_key, submodule_path_key,
                latest_active_job_id, latest_active_json, latest_active_queued_us,
                latest_completed_job_id, latest_completed_json, latest_completed_queued_us
            FROM submodule_snapshots
            WHERE (?1 IS NULL OR parent_repo_key = ?1)
              AND (?1 IS NOT NULL OR NOT starts_with(parent_repo_key, '__ar_'))
              AND (?2 IS NULL OR submodule_key = ?2)
              AND (?3 IS NULL OR branch_key = ?3)
            ORDER BY parent_repo_key ASC, branch_key ASC, submodule_key ASC
            "#,
        )?;

        let rows = stmt.query_map(
            params![req.parent_repo_key, req.submodule_key, req.branch_key],
            |row| {
                Ok(CentralSubmoduleSnapshot {
                    parent_repo_key: row.get(0)?,
                    branch_key: row.get(1)?,
                    submodule_key: row.get(2)?,
                    submodule_path_key: row.get(3)?,
                    latest_active_job_id: row.get(4)?,
                    latest_active_json: row.get(5)?,
                    latest_active_queued_us: row.get(6)?,
                    latest_completed_job_id: row.get(7)?,
                    latest_completed_json: row.get(8)?,
                    latest_completed_queued_us: row.get(9)?,
                })
            },
        )?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Returns row count in a hot table or unified view (for diagnostics & verification).
    pub fn count_rows(&self, relation: &str) -> Result<u64, MuObserveError> {
        let allowed = [
            "otel_logs",
            "otel_spans",
            "otel_metrics",
            "test_case_runs",
            "benchmark_runs",
            "jobs_history",
            "branch_snapshots",
            "submodule_snapshots",
            "job_logs_store",
            "v_logs",
            "v_traces",
            "v_metrics",
            "v_tests",
            "v_benchmarks",
            "v_jobs_history",
        ];
        if !allowed.contains(&relation) {
            return Err(MuObserveError::Validation(format!(
                "Disallowed relation name in count_rows: {relation}"
            )));
        }
        let conn = self.lock_conn()?;
        let sql = format!("SELECT COUNT(*) FROM {relation}");
        let cnt: i64 = conn.query_row(&sql, [], |r| r.get(0))?;
        Ok(cnt.max(0) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mu_observable_ipc::{
        benchmark_runs_to_record_batch, log_entries_to_record_batch,
        metric_entries_to_record_batch, span_entries_to_record_batch, test_runs_to_record_batch,
    };

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_hot_duckdb_crud_and_arrow_ingestion() {
        let store = HotDuckDbStore::open_in_memory().expect("open in memory");

        let logs = vec![OtelLogEntry {
            timestamp_unix_nano: 1_700_000_000_000_000_000,
            trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".into(),
            span_id: "00f067aa0ba902b7".into(),
            severity_number: 9,
            severity_text: "INFO".into(),
            service_name: "action-runner-worker".into(),
            node_id: "worker-riscv64".into(),
            body: "Stage completed".into(),
            attributes_json: r#"{"stage":"test"}"#.into(),
            job_id: Some("job-1".into()),
            stage_id: Some("test".into()),
        }];
        let log_batch = log_entries_to_record_batch(&logs).expect("record batch");
        assert_eq!(store.ingest_arrow_logs(&log_batch).unwrap(), 1);
        assert_eq!(store.count_rows("otel_logs").unwrap(), 1);

        let spans = vec![OtelSpanEntry {
            trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".into(),
            span_id: "00f067aa0ba902b7".into(),
            parent_span_id: None,
            service_name: "action-runner-controller".into(),
            node_id: "node-a".into(),
            span_name: "ci.job".into(),
            span_kind: "SERVER".into(),
            start_time_unix_nano: 1_700_000_000_000_000_000,
            end_time_unix_nano: 1_700_000_001_000_000_000,
            duration_ns: 1_000_000_000,
            status_code: "OK".into(),
            status_message: None,
            attributes_json: "{}".into(),
        }];
        let span_batch = span_entries_to_record_batch(&spans).expect("span batch");
        assert_eq!(store.ingest_arrow_spans(&span_batch).unwrap(), 1);
        assert_eq!(store.count_rows("otel_spans").unwrap(), 1);

        let metrics = vec![OtelMetricEntry {
            timestamp_unix_nano: 1_700_000_000_000_000_000,
            service_name: "k3-manager".into(),
            node_id: "worker-riscv64".into(),
            metric_name: "cpu.utilization".into(),
            metric_unit: "pct".into(),
            value_f64: 72.5,
            arch: "riscv64gc".into(),
            cpu_cluster: Some("A100".into()),
            vlen_bits: Some(1024),
            memlock_used_bytes: Some(1024 * 1024),
            memlock_limit_bytes: Some(28 * 1024 * 1024 * 1024),
            trace_id: None,
            span_id: None,
            attributes_json: "{}".into(),
        }];
        let metric_batch = metric_entries_to_record_batch(&metrics).expect("metric batch");
        assert_eq!(store.ingest_arrow_metrics(&metric_batch).unwrap(), 1);
        assert_eq!(store.count_rows("otel_metrics").unwrap(), 1);

        let tests = vec![TestCaseRunEntry {
            job_id: "job-1".into(),
            repo_key: "lma1980/k3-core".into(),
            branch_key: "main".into(),
            commit_sha: "abcdef".into(),
            crate_name: "k3-core".into(),
            test_binary: "k3_core".into(),
            test_name: "test_tensor".into(),
            status: "ok".into(),
            duration_ms: 2.5,
            failure_summary: None,
            timestamp_unix_nano: 1_700_000_000_000_000_000,
            node_id: "worker-riscv64".into(),
            arch: "riscv64gc".into(),
        }];
        let test_batch = test_runs_to_record_batch(&tests).expect("test batch");
        assert_eq!(store.ingest_arrow_test_runs(&test_batch).unwrap(), 1);
        assert_eq!(store.count_rows("test_case_runs").unwrap(), 1);

        let benches = vec![BenchmarkRunEntry {
            job_id: "job-1".into(),
            repo_key: "lma1980/k3-kernels-rvv".into(),
            branch_key: "main".into(),
            commit_sha: "abcdef".into(),
            crate_name: "k3-kernels-rvv".into(),
            bench_name: "gemm_a100".into(),
            ns_per_iter: 41_000.0,
            std_dev_ns: 200.0,
            mad_ns: 120.0,
            p50_ns: 40_950.0,
            p95_ns: 41_300.0,
            p99_ns: 41_500.0,
            throughput_value: Some(800.0),
            throughput_unit: Some("GB/s".into()),
            arch: "riscv64gc".into(),
            cpu_cluster: "A100".into(),
            vlen_bits: 1024,
            timestamp_unix_nano: 1_700_000_000_000_000_000,
            node_id: "worker-riscv64".into(),
        }];
        let bench_batch = benchmark_runs_to_record_batch(&benches).expect("bench batch");
        assert_eq!(store.ingest_arrow_benchmark_runs(&bench_batch).unwrap(), 1);
        assert_eq!(store.count_rows("benchmark_runs").unwrap(), 1);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_sql_injection_immunity_in_parameterized_inserts_and_queries() {
        let store = HotDuckDbStore::open_in_memory().expect("open in memory");
        let malicious_payload = "'); DROP TABLE jobs_history; --";

        let job = CentralJobRecord {
            job_id: malicious_payload.to_string(),
            event_type: "push".into(),
            repo_name: "LMA1980/MuObserve".into(),
            repo_key: malicious_payload.to_string(),
            clone_url: "https://github.com/LMA1980/MuObserve.git".into(),
            commit_sha: "123456".into(),
            ref_name: "refs/heads/main".into(),
            branch_key: "main".into(),
            sender: "LMA1980".into(),
            queued_at_us: 1000,
            updated_at_us: 2000,
            status_state: "Completed".into(),
            exit_code: Some(0),
            duration_secs: Some(10),
            quality_score: Some(100),
            letter_grade: Some("A+".into()),
            coverage_pct: Some(95.0),
            benchmark_summary: Some(malicious_payload.to_string()),
            tests_passed: Some(10),
            tests_total: Some(10),
            advisories_count: Some(0),
            clippy_warnings: Some(0),
            record_json: "{}".into(),
        };

        store
            .upsert_ci_state_batch(std::slice::from_ref(&job), &[], &[])
            .expect("upsert malicious string safely");

        assert_eq!(store.count_rows("jobs_history").unwrap(), 1);

        let queried = store
            .query_jobs_history(&QueryJobsHistoryRequest {
                request_id: "q-1".into(),
                repo_key: Some(malicious_payload.to_string()),
                branch_key: None,
                job_id: None,
                limit: 10,
            })
            .expect("query jobs");
        assert_eq!(queried.len(), 1);
        assert_eq!(queried[0].job_id, malicious_payload);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_query_submodule_snapshots_excludes_ar_internal_rows_when_unfiltered() {
        let store = HotDuckDbStore::open_in_memory().expect("open in memory");

        let legit_repos = vec![
            "lma1980/k3",
            "near_protocol",
            "gear_engine",
            "bear_claw",
            "search",
            "spark",
            "start",
            "smart",
            "learn",
            "board",
            "00ar_foo",
            "star_tracker",
            "_ar_something",
            "__ar",
            "normal-repo/proj",
            "🦀ar_unicode",
        ];

        let mut batch = Vec::new();
        for (idx, repo) in legit_repos.iter().enumerate() {
            batch.push(CentralSubmoduleSnapshot {
                parent_repo_key: (*repo).into(),
                branch_key: "main".into(),
                submodule_key: format!("sub-{}", idx),
                submodule_path_key: format!("path/{}", idx),
                latest_active_job_id: Some(format!("job-{}", idx)),
                latest_active_json: Some(format!("{{\"stage\":\"build-{}\"}}", idx)),
                latest_active_queued_us: Some(1_000_000 + idx as i64),
                latest_completed_job_id: Some(format!("job-prev-{}", idx)),
                latest_completed_json: Some("{\"status\":\"success\"}".into()),
                latest_completed_queued_us: Some(900_000 + idx as i64),
            });
        }

        let internal_log = CentralSubmoduleSnapshot {
            parent_repo_key: "__ar_job_logs__".into(),
            branch_key: "log".into(),
            submodule_key: "job-100".into(),
            submodule_path_key: "log".into(),
            latest_active_job_id: Some("job-100".into()),
            latest_active_json: Some("raw CI build log chunk...".into()),
            latest_active_queued_us: Some(1_200_000),
            latest_completed_job_id: None,
            latest_completed_json: None,
            latest_completed_queued_us: None,
        };

        let internal_lease = CentralSubmoduleSnapshot {
            parent_repo_key: "__ar_ha_lease__".into(),
            branch_key: "lease".into(),
            submodule_key: "leader".into(),
            submodule_path_key: "lease".into(),
            latest_active_job_id: None,
            latest_active_json: Some("{\"leader\":\"node-a\"}".into()),
            latest_active_queued_us: Some(1_300_000),
            latest_completed_job_id: None,
            latest_completed_json: None,
            latest_completed_queued_us: None,
        };

        batch.push(internal_log);
        batch.push(internal_lease);

        store
            .upsert_ci_state_batch(&[], &[], &batch)
            .expect("upsert batch");

        // 1. Unfiltered query (parent_repo_key: None) MUST exclude all __ar_* synthetic rows
        let unfiltered_req = QuerySubmoduleSnapshotsRequest {
            request_id: "req-unfiltered".into(),
            parent_repo_key: None,
            submodule_key: None,
            branch_key: None,
        };
        let unfiltered = store
            .query_submodule_snapshots(&unfiltered_req)
            .expect("query unfiltered submodule snapshots");

        let returned_repos: Vec<String> = unfiltered
            .iter()
            .map(|r| r.parent_repo_key.clone())
            .collect();

        assert_eq!(
            unfiltered.len(),
            legit_repos.len(),
            "Unfiltered query must return all legitimate snapshots, excluding __ar_* internal rows. Returned: {:?}",
            returned_repos
        );

        for repo in &legit_repos {
            assert!(
                returned_repos.contains(&repo.to_string()),
                "Legitimate repo '{}' was falsely excluded by SQL filter!",
                repo
            );
        }

        // 2. Filtered query explicitly targeting __ar_job_logs__ MUST return the requested internal row
        let internal_req = QuerySubmoduleSnapshotsRequest {
            request_id: "req-internal-log".into(),
            parent_repo_key: Some("__ar_job_logs__".into()),
            submodule_key: None,
            branch_key: None,
        };
        let internal_results = store
            .query_submodule_snapshots(&internal_req)
            .expect("query specific internal submodule snapshots");

        assert_eq!(
            internal_results.len(),
            1,
            "Explicit query for __ar_job_logs__ must succeed and return exactly the requested row"
        );
        assert_eq!(internal_results[0].parent_repo_key, "__ar_job_logs__");
        assert_eq!(internal_results[0].submodule_key, "job-100");

        // 3. Targeted query for near_protocol MUST succeed and return near_protocol
        let near_req = QuerySubmoduleSnapshotsRequest {
            request_id: "req-near".into(),
            parent_repo_key: Some("near_protocol".into()),
            submodule_key: None,
            branch_key: None,
        };
        let near_results = store
            .query_submodule_snapshots(&near_req)
            .expect("query near_protocol snapshots");
        assert_eq!(near_results.len(), 1);
        assert_eq!(near_results[0].parent_repo_key, "near_protocol");

        // 4. Verify submodule_snapshots table itself never stores __ar_job_logs__ or __ar_ha_lease__,
        // and flush_delayed persists dirty job logs into job_logs_store.
        assert_eq!(
            store.count_rows("submodule_snapshots").unwrap(),
            legit_repos.len() as u64
        );
        assert_eq!(store.count_rows("job_logs_store").unwrap(), 0);
        let flushed = store.flush_delayed(true).expect("force delayed flush");
        assert_eq!(flushed, 1);
        assert_eq!(store.count_rows("job_logs_store").unwrap(), 1);

        // 5. Verify __ar_ha_lease__ query returns the in-memory lease snapshot
        let lease_req = QuerySubmoduleSnapshotsRequest {
            request_id: "req-lease".into(),
            parent_repo_key: Some("__ar_ha_lease__".into()),
            submodule_key: Some("leader".into()),
            branch_key: Some("lease".into()),
        };
        let lease_results = store
            .query_submodule_snapshots(&lease_req)
            .expect("query lease snapshot");
        assert_eq!(lease_results.len(), 1);
        assert_eq!(
            lease_results[0].latest_active_json.as_deref(),
            Some("{\"leader\":\"node-a\"}")
        );
    }
}
