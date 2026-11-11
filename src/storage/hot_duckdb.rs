use std::collections::{BTreeMap, HashSet, VecDeque};
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
use serde_json::{json, Value};

use crate::error::MuObserveError;
use crate::server::console_api::ConsoleLogItem;
use crate::server::sanitize::PrivacyRedactor;
use crate::storage::views::{escape_sql_literal, register_unified_views};

/// Type alias for [`MuObserveError`] used across storage operations.
pub type StorageError = MuObserveError;

/// Type alias for [`ConsoleLogItem`] returned by token and line-indexed log queries.
pub type SanitizedLogRecord = ConsoleLogItem;

const INTERNAL_LOG_REPO_KEY: &str = "__ar_job_logs__";
const INTERNAL_LEASE_REPO_KEY: &str = "__ar_ha_lease__";
const DEFAULT_FLUSH_INTERVAL_MS: u64 = 30_000;
const MAX_DEDUP_CACHE_ENTRIES: usize = 65_536;
const MAX_TOKENS_PER_LINE: usize = 32;
const FIFO_HOT_EVICTION_BATCH_CAP: usize = 512;
const DEFAULT_MAX_STORE_BYTES: u64 = 10 * 1024 * 1024 * 1024; // 10 GiB

const FNV1A_64_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV1A_64_PRIME: u64 = 0x0000_0100_0000_01b3;

fn now_epoch_ms() -> u64 {
    chrono::Utc::now().timestamp_millis().max(0) as u64
}

fn fnv1a_update(mut hash: u64, bytes: &[u8]) -> u64 {
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(FNV1A_64_PRIME);
    }
    hash ^= 0xff;
    hash.wrapping_mul(FNV1A_64_PRIME)
}

/// Computes a deterministic 64-bit FNV-1a deduplication hash for a single log line.
///
/// - When `job_id` is `Some(jid)` and `line_no > 0`: hashes
///   `("ci_line", jid, stage_id.unwrap_or(""), stream, line_no, single_line_body.trim_end())`,
///   excluding timestamp so identical `(job_id, stage_id, stream, line_no, body)` records
///   arriving from worker and controller produce the exact same `dedup_hash`.
/// - Otherwise: hashes
///   `("daemon_line", node_id, service_name, job_id.unwrap_or(""), stage_id.unwrap_or(""), stream, timestamp_unix_nano / 1_000_000_000, single_line_body.trim_end())`.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn compute_log_dedup_hash(
    node_id: &str,
    service_name: &str,
    job_id: Option<&str>,
    stage_id: Option<&str>,
    stream: u8,
    line_no: u32,
    timestamp_unix_nano: i64,
    single_line_body: &str,
) -> u64 {
    let mut h = FNV1A_64_OFFSET;
    let trimmed_body = single_line_body.trim_end();
    if let Some(jid) = job_id.filter(|j| !j.is_empty()) {
        if line_no > 0 {
            h = fnv1a_update(h, b"ci_line");
            h = fnv1a_update(h, jid.as_bytes());
            h = fnv1a_update(h, stage_id.unwrap_or("").as_bytes());
            h = fnv1a_update(h, &[stream]);
            h = fnv1a_update(h, &line_no.to_le_bytes());
            h = fnv1a_update(h, trimmed_body.as_bytes());
            return if h == 0 { 1 } else { h };
        }
    }
    h = fnv1a_update(h, b"daemon_line");
    h = fnv1a_update(h, node_id.as_bytes());
    h = fnv1a_update(h, service_name.as_bytes());
    h = fnv1a_update(h, job_id.unwrap_or("").as_bytes());
    h = fnv1a_update(h, stage_id.unwrap_or("").as_bytes());
    h = fnv1a_update(h, &[stream]);
    let ts_sec = timestamp_unix_nano / 1_000_000_000;
    h = fnv1a_update(h, &ts_sec.to_le_bytes());
    h = fnv1a_update(h, trimmed_body.as_bytes());
    if h == 0 {
        1
    } else {
        h
    }
}

/// Extracts normalized lowercase tokens (`len >= 2`, splitting on non-alphanumeric characters
/// except `_`, `-`, `.`, `/`, up to 32 unique tokens per line) from `line_body`, `service_name`,
/// `node_id`, `job_id`, and `stage_id`.
#[must_use]
pub fn tokenize_log_line(entry: &OtelLogEntry, line_body: &str) -> Vec<String> {
    let mut seen = HashSet::with_capacity(MAX_TOKENS_PER_LINE);
    let mut out = Vec::with_capacity(MAX_TOKENS_PER_LINE);

    let mut push_tokens = |text: &str| {
        for raw in text.split(|c: char| {
            !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | '<' | '>'))
        }) {
            if out.len() >= MAX_TOKENS_PER_LINE {
                break;
            }
            let trimmed = raw.trim_matches(|c: char| matches!(c, '.' | '-' | '/'));
            if trimmed.len() < 2
                || !trimmed
                    .bytes()
                    .any(|b| b.is_ascii_alphanumeric() || matches!(b, b'<' | b'>'))
            {
                continue;
            }
            let lower = trimmed.to_ascii_lowercase();
            if seen.insert(lower.clone()) {
                out.push(lower);
            }
        }
    };

    push_tokens(line_body);
    push_tokens(&entry.service_name);
    push_tokens(&entry.node_id);
    if let Some(jid) = entry.job_id.as_deref() {
        push_tokens(jid);
    }
    if let Some(sid) = entry.stage_id.as_deref() {
        push_tokens(sid);
    }
    out
}

fn tokenize_query_text(query: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for raw in query.split(|c: char| {
        !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | '<' | '>'))
    }) {
        let trimmed = raw.trim_matches(|c: char| matches!(c, '.' | '-' | '/'));
        if trimmed.len() < 2
            || !trimmed
                .bytes()
                .any(|b| b.is_ascii_alphanumeric() || matches!(b, b'<' | b'>'))
        {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();
        if seen.insert(lower.clone()) {
            out.push(lower);
        }
    }
    out
}

/// Returns the available unprivileged disk space in bytes on the filesystem containing `path`
/// via `libc::statvfs`.
#[must_use]
pub fn available_disk_bytes(path: &Path) -> Option<u64> {
    #[cfg(all(unix, not(miri)))]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let mut candidate = path.to_path_buf();
        while !candidate.exists() {
            if let Some(parent) = candidate.parent() {
                if parent.as_os_str().is_empty() {
                    candidate = PathBuf::from(".");
                    break;
                }
                candidate = parent.to_path_buf();
            } else {
                candidate = PathBuf::from(".");
                break;
            }
        }

        let c_path = CString::new(candidate.as_os_str().as_bytes()).ok()?;
        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
        if rc == 0 {
            #[allow(clippy::unnecessary_cast)]
            let bavail = stat.f_bavail as u64;
            #[allow(clippy::unnecessary_cast)]
            let frsize = stat.f_frsize as u64;
            let block_size = if frsize > 0 {
                frsize
            } else {
                #[allow(clippy::unnecessary_cast)]
                {
                    stat.f_bsize as u64
                }
            };
            Some(bavail.saturating_mul(block_size))
        } else {
            None
        }
    }
    #[cfg(not(all(unix, not(miri))))]
    {
        let _ = path;
        None
    }
}

#[derive(Default)]
struct WriteBehindCache {
    /// Ephemeral HA lease snapshots keyed by `(branch_key, submodule_key)`.
    /// Served in O(1) from RAM without touching DuckDB on every 5s heartbeat.
    lease_snapshots: BTreeMap<(String, String), CentralSubmoduleSnapshot>,
}

struct DedupFifoCache {
    order: VecDeque<u64>,
    set: HashSet<u64>,
}

impl Default for DedupFifoCache {
    fn default() -> Self {
        Self {
            order: VecDeque::with_capacity(1024),
            set: HashSet::with_capacity(1024),
        }
    }
}

impl DedupFifoCache {
    fn contains(&self, hash: u64) -> bool {
        self.set.contains(&hash)
    }

    fn insert(&mut self, hash: u64) {
        if self.set.contains(&hash) {
            return;
        }
        while self.order.len() >= MAX_DEDUP_CACHE_ENTRIES {
            if let Some(evicted) = self.order.pop_front() {
                self.set.remove(&evicted);
            } else {
                break;
            }
        }
        self.order.push_back(hash);
        self.set.insert(hash);
    }

    fn clear(&mut self) {
        self.order.clear();
        self.set.clear();
    }
}

/// Parameterized Hot DuckDB storage engine (`hot.duckdb`) hosting the 7-day OTEL telemetry
/// tables (`otel_logs`, `otel_spans`, `otel_metrics`), the OpenSearch-style inverted token
/// index (`log_inverted_index`) and tiered cold shard catalog (`log_shards_catalog`), granular
/// CI execution tables (`test_case_runs`, `benchmark_runs`), and the centralized
/// `ActionRunner-controller` catalog (`jobs_history`, `branch_snapshots`, `submodule_snapshots`).
#[derive(Clone)]
pub struct HotDuckDbStore {
    conn: Arc<Mutex<Connection>>,
    db_path: Option<PathBuf>,
    parquet_root: Option<PathBuf>,
    cache: Arc<Mutex<WriteBehindCache>>,
    dedup_cache: Arc<Mutex<DedupFifoCache>>,
    dirty_writes: Arc<AtomicU64>,
    last_flush_ms: Arc<AtomicU64>,
    flush_interval_ms: u64,
    event_tx: tokio::sync::broadcast::Sender<String>,
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

        let (event_tx, _) = tokio::sync::broadcast::channel(2048);
        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
            db_path: db_path.map(Path::to_path_buf),
            parquet_root: parquet_root.map(Path::to_path_buf),
            cache: Arc::new(Mutex::new(WriteBehindCache::default())),
            dedup_cache: Arc::new(Mutex::new(DedupFifoCache::default())),
            dirty_writes: Arc::new(AtomicU64::new(0)),
            last_flush_ms: Arc::new(AtomicU64::new(now_epoch_ms())),
            flush_interval_ms,
            event_tx,
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

    /// Broadcasts an SSE event payload to active streaming subscribers.
    pub fn broadcast_event(&self, event: &str) {
        let _ = self.event_tx.send(event.to_string());
    }

    /// Subscribes to the live SSE event broadcast channel.
    #[must_use]
    pub fn subscribe_events(&self) -> tokio::sync::broadcast::Receiver<String> {
        self.event_tx.subscribe()
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

    /// Alias for [`Self::refresh_views`] refreshing unified DuckDB analytical views.
    pub fn refresh_unified_views(&self) -> Result<(), MuObserveError> {
        self.refresh_views()
    }

    /// Extracts normalized lowercase tokens (`len >= 2`) from a log line and its metadata.
    #[must_use]
    pub fn tokenize_log_line(entry: &OtelLogEntry, line_body: &str) -> Vec<String> {
        tokenize_log_line(entry, line_body)
    }

    fn init_schema(&self) -> Result<(), MuObserveError> {
        let mut legacy_log_snapshots: Vec<CentralSubmoduleSnapshot> = Vec::new();
        {
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
                    stage_id VARCHAR,
                    line_no UINTEGER DEFAULT 0,
                    stream UTINYINT DEFAULT 1,
                    dedup_hash UBIGINT DEFAULT 0
                );
                ALTER TABLE otel_logs ADD COLUMN IF NOT EXISTS line_no UINTEGER DEFAULT 0;
                ALTER TABLE otel_logs ADD COLUMN IF NOT EXISTS stream UTINYINT DEFAULT 1;
                ALTER TABLE otel_logs ADD COLUMN IF NOT EXISTS dedup_hash UBIGINT DEFAULT 0;
                CREATE INDEX IF NOT EXISTS idx_otel_logs_dedup ON otel_logs (dedup_hash);
                CREATE INDEX IF NOT EXISTS idx_otel_logs_job_line ON otel_logs (job_id, line_no, timestamp_unix_nano);

                CREATE TABLE IF NOT EXISTS log_inverted_index (
                    token VARCHAR NOT NULL,
                    timestamp_unix_nano BIGINT NOT NULL,
                    shard_id VARCHAR NOT NULL,
                    dedup_hash UBIGINT NOT NULL,
                    job_id VARCHAR,
                    node_id VARCHAR NOT NULL,
                    service_name VARCHAR NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_log_inv_token_ts ON log_inverted_index (token, timestamp_unix_nano);
                CREATE INDEX IF NOT EXISTS idx_log_inv_dedup ON log_inverted_index (dedup_hash);

                CREATE TABLE IF NOT EXISTS log_shards_catalog (
                    shard_id VARCHAR PRIMARY KEY,
                    tier VARCHAR NOT NULL,
                    storage_uri VARCHAR NOT NULL,
                    min_timestamp_ns BIGINT NOT NULL,
                    max_timestamp_ns BIGINT NOT NULL,
                    row_count BIGINT NOT NULL,
                    byte_size BIGINT NOT NULL
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

                DROP TABLE IF EXISTS job_logs_store;
                "#,
            )?;

            // Hydrate any persisted HA lease rows into the in-memory cache and collect any
            // legacy __ar_job_logs__ rows before purging them from submodule_snapshots.
            if let Ok(mut stmt) = conn.prepare(
                r#"
                SELECT
                    parent_repo_key, branch_key, submodule_key, submodule_path_key,
                    latest_active_job_id, latest_active_json, latest_active_queued_us,
                    latest_completed_job_id, latest_completed_json, latest_completed_queued_us
                FROM submodule_snapshots
                WHERE parent_repo_key IN ('__ar_ha_lease__', '__ar_job_logs__')
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
                            if snap.parent_repo_key == INTERNAL_LEASE_REPO_KEY {
                                cache.lease_snapshots.insert(
                                    (snap.branch_key.clone(), snap.submodule_key.clone()),
                                    snap,
                                );
                            } else if snap.parent_repo_key == INTERNAL_LOG_REPO_KEY {
                                legacy_log_snapshots.push(snap);
                            }
                        }
                    }
                }
            }

            let purged: usize = conn
                .execute(
                    "DELETE FROM submodule_snapshots WHERE parent_repo_key IN ('__ar_job_logs__', '__ar_ha_lease__')",
                    [],
                )
                .unwrap_or(0);
            if purged > 0 && self.db_path.is_some() {
                let _ = conn.execute_batch("CHECKPOINT;");
            }
        }

        if !legacy_log_snapshots.is_empty() {
            let mut entries = Vec::new();
            for snap in &legacy_log_snapshots {
                entries.extend(split_legacy_job_log_snapshot(snap));
            }
            if !entries.is_empty() {
                let _ = self.insert_logs(&entries)?;
            }
        }

        Ok(())
    }

    /// Executes a DuckDB `CHECKPOINT` when `force_checkpoint` is `true` or the delayed flush
    /// interval has elapsed after writes.
    pub fn flush_delayed(&self, force_checkpoint: bool) -> Result<u32, MuObserveError> {
        let now_ms = now_epoch_ms();
        let last_ms = self.last_flush_ms.load(Ordering::Relaxed);
        let interval_elapsed = now_ms.saturating_sub(last_ms) >= self.flush_interval_ms;

        if !force_checkpoint && !interval_elapsed {
            return Ok(0);
        }

        let prior_dirty = self.dirty_writes.swap(0, Ordering::Relaxed);
        self.last_flush_ms.store(now_ms, Ordering::Relaxed);

        if prior_dirty == 0 && !force_checkpoint {
            return Ok(0);
        }

        let conn = self.lock_conn()?;
        if self.db_path.is_some() {
            let _ = conn.execute_batch("CHECKPOINT;");
        }

        Ok(prior_dirty.min(u64::from(u32::MAX)) as u32)
    }

    fn record_write_and_maybe_flush(&self) {
        self.dirty_writes.fetch_add(1, Ordering::Relaxed);
        let now_ms = now_epoch_ms();
        let last_ms = self.last_flush_ms.load(Ordering::Relaxed);
        if now_ms.saturating_sub(last_ms) >= self.flush_interval_ms {
            let _ = self.flush_delayed(false);
        }
    }

    /// Inserts a slice of [`OtelLogEntry`] records into `otel_logs` and `log_inverted_index`:
    ///
    /// - Splits any multi-line `body` (`\n`) into individual single-line records (trimming
    ///   trailing `\r`, skipping empty trailing newline, and incrementing `line_no`).
    /// - Parses `line_no: u32` and `stream: u8` (`1` = stdout, `2` = stderr) from `attributes_json`
    ///   or `[stderr]` prefix in `body`.
    /// - Computes a deterministic 64-bit `dedup_hash` and deduplicates against both the bounded
    ///   65,536-entry FIFO in-memory cache and SQL `WHERE NOT EXISTS (SELECT 1 FROM otel_logs WHERE dedup_hash = ?)`.
    /// - Indexes tokens for each newly inserted line in `log_inverted_index` with `shard_id = "hot"`.
    pub fn insert_logs(&self, entries: &[OtelLogEntry]) -> Result<u32, MuObserveError> {
        if entries.is_empty() {
            return Ok(0);
        }

        let expanded = expand_log_entries_to_single_lines(entries);
        if expanded.is_empty() {
            return Ok(0);
        }

        let count = {
            let conn = self.lock_conn()?;
            let mut dedup = self
                .dedup_cache
                .lock()
                .map_err(|_| MuObserveError::LockPoisoned("DedupFifoCache mutex".into()))?;

            conn.execute_batch("BEGIN TRANSACTION;")?;
            let mut log_stmt = conn.prepare(
                r#"
                INSERT INTO otel_logs (
                    timestamp_unix_nano, trace_id, span_id, severity_number, severity_text,
                    service_name, node_id, body, attributes_json, job_id, stage_id,
                    line_no, stream, dedup_hash
                )
                SELECT
                    CAST(?1 AS BIGINT),
                    CAST(?2 AS VARCHAR),
                    CAST(?3 AS VARCHAR),
                    CAST(?4 AS INTEGER),
                    CAST(?5 AS VARCHAR),
                    CAST(?6 AS VARCHAR),
                    CAST(?7 AS VARCHAR),
                    CAST(?8 AS VARCHAR),
                    CAST(?9 AS VARCHAR),
                    CAST(?10 AS VARCHAR),
                    CAST(?11 AS VARCHAR),
                    CAST(?12 AS UINTEGER),
                    CAST(?13 AS UTINYINT),
                    CAST(?14 AS UBIGINT)
                WHERE NOT EXISTS (
                    SELECT 1 FROM otel_logs WHERE dedup_hash = CAST(?14 AS UBIGINT)
                )
                "#,
            )?;

            let mut inv_stmt = conn.prepare(
                r#"
                INSERT INTO log_inverted_index (
                    token, timestamp_unix_nano, shard_id, dedup_hash, job_id, node_id, service_name
                ) VALUES (?1, ?2, 'hot', ?3, ?4, ?5, ?6)
                "#,
            )?;

            let mut count = 0u32;
            for item in &expanded {
                if dedup.contains(item.dedup_hash) {
                    continue;
                }

                let inserted = log_stmt.execute(params![
                    item.entry.timestamp_unix_nano,
                    item.entry.trace_id,
                    item.entry.span_id,
                    item.entry.severity_number,
                    item.entry.severity_text,
                    item.entry.service_name,
                    item.entry.node_id,
                    item.entry.body,
                    item.entry.attributes_json,
                    item.entry.job_id,
                    item.entry.stage_id,
                    item.line_no,
                    item.stream,
                    item.dedup_hash,
                ])?;

                dedup.insert(item.dedup_hash);

                if inserted > 0 {
                    count = count.saturating_add(1);
                    let tokens = tokenize_log_line(&item.entry, &item.entry.body);
                    for tok in tokens {
                        inv_stmt.execute(params![
                            tok,
                            item.entry.timestamp_unix_nano,
                            item.dedup_hash,
                            item.entry.job_id,
                            item.entry.node_id,
                            item.entry.service_name,
                        ])?;
                    }
                }
            }
            drop(inv_stmt);
            drop(log_stmt);
            conn.execute_batch("COMMIT;")?;
            count
        };

        if count > 0 {
            self.record_write_and_maybe_flush();
            let redactor = PrivacyRedactor::new();
            for item in expanded.iter().take(100) {
                let ev = serde_json::json!({
                    "log_entry": true,
                    "timestamp_ms": (item.entry.timestamp_unix_nano / 1_000_000) as u64,
                    "severity": item.entry.severity_text,
                    "service": redactor.redact_str(&item.entry.service_name),
                    "trace_id": item.entry.trace_id,
                    "span_id": if item.entry.span_id.is_empty() { None } else { Some(&item.entry.span_id) },
                    "message": redactor.redact_str(&item.entry.body),
                });
                if let Ok(payload) = serde_json::to_string(&ev) {
                    self.broadcast_event(&payload);
                }
            }
        }
        Ok(count)
    }

    /// Alias for [`Self::insert_logs`].
    pub fn insert_logs_batch(&self, entries: &[OtelLogEntry]) -> Result<u32, MuObserveError> {
        self.insert_logs(entries)
    }

    /// Ingests an Apache Arrow [`RecordBatch`] of `otel_logs`.
    pub fn ingest_arrow_logs(&self, batch: &RecordBatch) -> Result<u32, MuObserveError> {
        let entries = record_batch_to_log_entries(batch)?;
        self.insert_logs(&entries)
    }

    /// Resolves candidate deduplication hashes from `log_inverted_index` for a tokenized query.
    /// Returns `Ok(None)` if `token_query` contains no valid tokens.
    /// Returns `Ok(Some(empty_set))` if tokens were queried but produced 0 matches.
    /// Returns `Ok(Some(matched_set))` if matching deduplication hashes were found.
    pub fn candidate_hashes_for_query(
        &self,
        token_query: &str,
        job_id: Option<&str>,
    ) -> Result<Option<HashSet<u64>>, StorageError> {
        let conn = self.lock_conn()?;
        Self::candidate_hashes_for_query_conn(&conn, token_query, job_id)
    }

    pub(crate) fn candidate_hashes_for_query_conn(
        conn: &duckdb::Connection,
        token_query: &str,
        job_id: Option<&str>,
    ) -> Result<Option<HashSet<u64>>, StorageError> {
        let query_tokens = tokenize_query_text(token_query);
        if query_tokens.is_empty() {
            return Ok(None);
        }

        let mut candidate_hashes: Option<HashSet<u64>> = None;
        let mut idx_stmt = conn.prepare(
            r#"
            SELECT DISTINCT dedup_hash
            FROM log_inverted_index
            WHERE token = ?1
              AND (?2 IS NULL OR job_id = ?2)
            "#,
        )?;
        for tok in &query_tokens {
            let rows = idx_stmt.query_map(params![tok, job_id], |r| r.get::<_, u64>(0))?;
            let mut set = HashSet::new();
            for h in rows {
                set.insert(h?);
            }
            candidate_hashes = Some(match candidate_hashes {
                None => set,
                Some(prev) => prev.intersection(&set).copied().collect(),
            });
            if candidate_hashes.as_ref().is_some_and(HashSet::is_empty) {
                return Ok(Some(HashSet::new()));
            }
        }
        Ok(candidate_hashes)
    }

    /// Searches logs via the OpenSearch-style inverted token index (`log_inverted_index`),
    /// joining against `v_logs` (spanning both hot DuckDB and cold Parquet shards), and returns
    /// sanitized [`SanitizedLogRecord`] rows ordered by `timestamp_unix_nano DESC, line_no DESC`.
    pub fn search_logs_by_token(
        &self,
        token_query: &str,
        job_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<SanitizedLogRecord>, StorageError> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let bounded_limit = limit.clamp(1, 1000);
        let redactor = PrivacyRedactor::new();
        let conn = self.lock_conn()?;

        let Some(matched_hashes) =
            Self::candidate_hashes_for_query_conn(&conn, token_query, job_id)?
        else {
            return Ok(Vec::new());
        };
        if matched_hashes.is_empty() {
            return Ok(Vec::new());
        }

        let matched_hashes_vec: Vec<u64> = matched_hashes.into_iter().collect();
        let placeholders = (2..=matched_hashes_vec.len() + 1)
            .map(|i| format!("?{i}"))
            .collect::<Vec<_>>()
            .join(", ");
        let limit_idx = matched_hashes_vec.len() + 2;

        let sql = format!(
            r#"
            SELECT
                timestamp_unix_nano, trace_id, span_id, severity_number, severity_text,
                service_name, node_id, body, attributes_json, job_id, stage_id,
                COALESCE(line_no, 0), COALESCE(stream, 1), COALESCE(dedup_hash, 0)
            FROM v_logs
            WHERE (?1 IS NULL OR job_id = ?1)
              AND dedup_hash IN ({placeholders})
            ORDER BY timestamp_unix_nano DESC, COALESCE(line_no, 0) DESC
            LIMIT ?{limit_idx}
            "#
        );

        let lim = bounded_limit as i64;
        let mut param_refs: Vec<&dyn duckdb::types::ToSql> =
            Vec::with_capacity(matched_hashes_vec.len() + 2);
        param_refs.push(&job_id);
        for h in &matched_hashes_vec {
            param_refs.push(h);
        }
        param_refs.push(&lim);

        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(&param_refs[..], |r| {
            let ts_ns: i64 = r.get(0)?;
            let raw_svc: String = r.get(5)?;
            let raw_node: String = r.get(6)?;
            let raw_body: String = r.get(7)?;
            let raw_attrs: String = r.get(8)?;
            let line_no_u32 = r.get::<_, i64>(11).unwrap_or(0).max(0) as u32;
            let stream_u8 = r.get::<_, i64>(12).unwrap_or(1).clamp(1, 2) as u8;
            let clean_svc = redactor.redact_str(&raw_svc);
            Ok(SanitizedLogRecord {
                timestamp_unix_nano: ts_ns,
                timestamp_ms: ts_ns / 1_000_000,
                trace_id: r.get(1)?,
                span_id: r.get(2)?,
                severity_number: r.get(3)?,
                severity_text: r.get(4)?,
                service: clean_svc.clone(),
                service_name: clean_svc,
                node_id: redactor.redact_host(&raw_node),
                body: redactor.redact_str(&raw_body),
                attributes: redactor.redact_attributes_json(&raw_attrs),
                job_id: r.get(9)?,
                stage_id: r.get(10)?,
                line_no: line_no_u32,
                stream: stream_u8,
            })
        })?;

        let mut out = Vec::with_capacity(bounded_limit);
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Reconstructs and sanitizes the full execution log for `job_id` line-by-line from `v_logs`
    /// (`WHERE job_id = ? ORDER BY CASE WHEN line_no > 0 THEN 0 ELSE 1 END ASC, line_no ASC, timestamp_unix_nano ASC`),
    /// joining redacted lines with `\n`.
    ///
    /// Returns `Ok(Some(reconstructed))` when at least one line exists, or `Ok(None)` when none exist.
    pub fn query_sanitized_job_log(&self, job_id: &str) -> Result<Option<String>, StorageError> {
        let trimmed_job = job_id.trim();
        if trimmed_job.is_empty() {
            return Ok(None);
        }
        let redactor = PrivacyRedactor::new();
        let conn = self.lock_conn()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT body
            FROM v_logs
            WHERE job_id = ?1
            ORDER BY CASE WHEN COALESCE(line_no, 0) > 0 THEN 0 ELSE 1 END ASC,
                     COALESCE(line_no, 0) ASC,
                     timestamp_unix_nano ASC
            "#,
        )?;
        let rows = stmt.query_map(params![trimmed_job], |r| r.get::<_, String>(0))?;
        let mut lines = Vec::new();
        for r in rows {
            let raw_line = r?;
            lines.push(redactor.redact_str(&raw_line));
        }
        if lines.is_empty() {
            Ok(None)
        } else {
            Ok(Some(lines.join("\n")))
        }
    }

    /// Enforces strict FIFO eviction by timestamp (`now_ns - max_age_ns`) and byte/disk budget
    /// (`max_store_bytes` and `min_free_disk_bytes`) across `otel_logs`, `log_inverted_index`,
    /// `otel_spans`, `otel_metrics`, and cold shards in `log_shards_catalog`.
    pub fn enforce_fifo_time_and_space_eviction(
        &self,
        now_ns: i64,
        max_age_ns: i64,
        max_store_bytes: u64,
        min_free_disk_bytes: u64,
    ) -> Result<usize, StorageError> {
        let mut evicted_total = 0usize;
        let mut removed_cold_file = false;
        let conn = self.lock_conn()?;

        // 1. Time-based FIFO eviction (all records older than now_ns - max_age_ns)
        if max_age_ns > 0 {
            let cutoff_ns = now_ns.saturating_sub(max_age_ns);

            let mut expired_shards: Vec<(String, String, i64)> = Vec::new();
            if let Ok(mut stmt) = conn.prepare(
                r#"
                SELECT shard_id, storage_uri, row_count
                FROM log_shards_catalog
                WHERE max_timestamp_ns < ?1
                ORDER BY max_timestamp_ns ASC
                "#,
            ) {
                if let Ok(rows) = stmt.query_map(params![cutoff_ns], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(2)?,
                    ))
                }) {
                    for row in rows.flatten() {
                        expired_shards.push(row);
                    }
                }
            }

            for (shard_id, storage_uri, row_count) in expired_shards {
                let p = Path::new(&storage_uri);
                if p.exists() && std::fs::remove_file(p).is_ok() {
                    removed_cold_file = true;
                }
                let _ = conn.execute(
                    "DELETE FROM log_inverted_index WHERE shard_id = ?1",
                    params![shard_id],
                );
                let _ = conn.execute(
                    "DELETE FROM log_shards_catalog WHERE shard_id = ?1",
                    params![shard_id],
                );
                evicted_total = evicted_total.saturating_add(row_count.max(1) as usize);
            }

            let del_logs = conn.execute(
                "DELETE FROM otel_logs WHERE timestamp_unix_nano < ?1",
                params![cutoff_ns],
            )?;
            let _ = conn.execute(
                "DELETE FROM log_inverted_index WHERE timestamp_unix_nano < ?1",
                params![cutoff_ns],
            )?;
            let del_spans = conn.execute(
                "DELETE FROM otel_spans WHERE start_time_unix_nano < ?1",
                params![cutoff_ns],
            )?;
            let del_metrics = conn.execute(
                "DELETE FROM otel_metrics WHERE timestamp_unix_nano < ?1",
                params![cutoff_ns],
            )?;
            evicted_total = evicted_total
                .saturating_add(del_logs)
                .saturating_add(del_spans)
                .saturating_add(del_metrics);
        }

        // 2. Space & free-disk budget FIFO eviction
        let disk_probe_path = self
            .db_path
            .as_deref()
            .or(self.parquet_root.as_deref())
            .unwrap_or_else(|| Path::new("."));

        loop {
            let (total_store_bytes, total_hot_rows) = self.estimate_store_bytes_locked(&conn)?;
            let over_store_budget = total_store_bytes > max_store_bytes;
            let low_free_disk = min_free_disk_bytes > 0
                && available_disk_bytes(disk_probe_path)
                    .map(|free| free < min_free_disk_bytes)
                    .unwrap_or(false);

            if !over_store_budget && !low_free_disk {
                break;
            }

            // Identify oldest cold shard in log_shards_catalog
            let oldest_shard: Option<(String, String, i64, i64)> = conn
                .query_row(
                    r#"
                    SELECT shard_id, storage_uri, max_timestamp_ns, row_count
                    FROM log_shards_catalog
                    ORDER BY max_timestamp_ns ASC, min_timestamp_ns ASC
                    LIMIT 1
                    "#,
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .ok();

            // Identify oldest hot timestamp across otel_logs, otel_spans, and otel_metrics
            let min_log_ts: Option<i64> = conn
                .query_row("SELECT MIN(timestamp_unix_nano) FROM otel_logs", [], |r| {
                    r.get(0)
                })
                .ok()
                .flatten();
            let min_span_ts: Option<i64> = conn
                .query_row(
                    "SELECT MIN(start_time_unix_nano) FROM otel_spans",
                    [],
                    |r| r.get(0),
                )
                .ok()
                .flatten();
            let min_metric_ts: Option<i64> = conn
                .query_row(
                    "SELECT MIN(timestamp_unix_nano) FROM otel_metrics",
                    [],
                    |r| r.get(0),
                )
                .ok()
                .flatten();

            let oldest_hot_ts = [min_log_ts, min_span_ts, min_metric_ts]
                .into_iter()
                .flatten()
                .min();

            if oldest_shard.is_none() && oldest_hot_ts.is_none() {
                break;
            }

            // Evict the oldest cold shard if it is older than (or equal to) the oldest hot row,
            // or if no hot rows remain.
            if let Some((shard_id, storage_uri, shard_max_ts, row_count)) = oldest_shard {
                if oldest_hot_ts.map(|ht| shard_max_ts <= ht).unwrap_or(true) {
                    let p = Path::new(&storage_uri);
                    if p.exists() && std::fs::remove_file(p).is_ok() {
                        removed_cold_file = true;
                    }
                    let _ = conn.execute(
                        "DELETE FROM log_inverted_index WHERE shard_id = ?1",
                        params![shard_id],
                    );
                    let _ = conn.execute(
                        "DELETE FROM log_shards_catalog WHERE shard_id = ?1",
                        params![shard_id],
                    );
                    evicted_total = evicted_total.saturating_add(row_count.max(1) as usize);
                    continue;
                }
            }

            // Otherwise evict the oldest batch of hot rows strictly in FIFO timestamp order
            let batch_limit: i64 = if over_store_budget && total_hot_rows > 0 {
                let excess = total_store_bytes.saturating_sub(max_store_bytes);
                let avg_row_bytes = (total_store_bytes / total_hot_rows).max(64);
                ((excess.div_ceil(avg_row_bytes)) as usize).clamp(1, FIFO_HOT_EVICTION_BATCH_CAP)
                    as i64
            } else {
                total_hot_rows
                    .min(FIFO_HOT_EVICTION_BATCH_CAP as u64)
                    .max(1) as i64
            };

            let target_ts = oldest_hot_ts.expect("oldest_hot_ts is Some");
            let evicted_step = if min_log_ts == Some(target_ts) {
                let n = conn.execute(
                    r#"
                    DELETE FROM otel_logs
                    WHERE rowid IN (
                        SELECT rowid FROM otel_logs
                        ORDER BY timestamp_unix_nano ASC, line_no ASC
                        LIMIT ?1
                    )
                    "#,
                    params![batch_limit],
                )?;
                let _ = conn.execute(
                    r#"
                    DELETE FROM log_inverted_index
                    WHERE shard_id = 'hot'
                      AND dedup_hash NOT IN (SELECT dedup_hash FROM otel_logs)
                    "#,
                    [],
                )?;
                n
            } else if min_span_ts == Some(target_ts) {
                conn.execute(
                    r#"
                    DELETE FROM otel_spans
                    WHERE rowid IN (
                        SELECT rowid FROM otel_spans
                        ORDER BY start_time_unix_nano ASC
                        LIMIT ?1
                    )
                    "#,
                    params![batch_limit],
                )?
            } else {
                conn.execute(
                    r#"
                    DELETE FROM otel_metrics
                    WHERE rowid IN (
                        SELECT rowid FROM otel_metrics
                        ORDER BY timestamp_unix_nano ASC
                        LIMIT ?1
                    )
                    "#,
                    params![batch_limit],
                )?
            };

            if evicted_step == 0 {
                break;
            }
            evicted_total = evicted_total.saturating_add(evicted_step);
        }

        if evicted_total > 0 {
            let _ = conn.execute(
                r#"
                DELETE FROM log_inverted_index
                WHERE shard_id = 'hot'
                  AND dedup_hash NOT IN (SELECT dedup_hash FROM otel_logs)
                "#,
                [],
            );
            if let Ok(mut dedup) = self.dedup_cache.lock() {
                dedup.clear();
            }
        }

        if removed_cold_file {
            register_unified_views(&conn, self.parquet_root.as_deref())?;
        }

        Ok(evicted_total)
    }

    /// Evicts expired logs, spans, metrics, and cold shards older than `now_ns - max_age_ns`,
    /// while also enforcing any configured `MUOBSERVE_MAX_STORE_BYTES` and `MUOBSERVE_MIN_FREE_DISK_BYTES`.
    pub fn evict_expired_logs(&self, now_ns: i64, max_age_ns: i64) -> Result<usize, StorageError> {
        let max_store_bytes = std::env::var("MUOBSERVE_MAX_STORE_BYTES")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(DEFAULT_MAX_STORE_BYTES);
        let min_free_disk_bytes = std::env::var("MUOBSERVE_MIN_FREE_DISK_BYTES")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(0);
        self.enforce_fifo_time_and_space_eviction(
            now_ns,
            max_age_ns,
            max_store_bytes,
            min_free_disk_bytes,
        )
    }

    fn estimate_store_bytes_locked(&self, conn: &Connection) -> Result<(u64, u64), StorageError> {
        let cold_shard_bytes: i64 = conn
            .query_row(
                "SELECT COALESCE(SUM(byte_size), 0) FROM log_shards_catalog",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);

        let (log_rows, log_bytes): (i64, i64) = conn
            .query_row(
                r#"
                SELECT
                    COUNT(*),
                    COALESCE(SUM(LENGTH(body) + LENGTH(attributes_json) + LENGTH(service_name) + LENGTH(node_id) + 64), 0)
                FROM otel_logs
                "#,
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap_or((0, 0));

        let inv_bytes: i64 = conn
            .query_row(
                "SELECT COALESCE(SUM(LENGTH(token) + 48), 0) FROM log_inverted_index",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);

        let (span_rows, span_bytes): (i64, i64) = conn
            .query_row(
                r#"
                SELECT
                    COUNT(*),
                    COALESCE(SUM(LENGTH(span_name) + LENGTH(attributes_json) + COALESCE(LENGTH(status_message), 0) + 96), 0)
                FROM otel_spans
                "#,
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap_or((0, 0));

        let (metric_rows, metric_bytes): (i64, i64) = conn
            .query_row(
                "SELECT COUNT(*), COALESCE(COUNT(*) * 128, 0) FROM otel_metrics",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap_or((0, 0));

        let estimated_hot_bytes = (log_bytes.max(0) as u64)
            .saturating_add(inv_bytes.max(0) as u64)
            .saturating_add(span_bytes.max(0) as u64)
            .saturating_add(metric_bytes.max(0) as u64);

        let total_hot_rows = (log_rows.max(0) as u64)
            .saturating_add(span_rows.max(0) as u64)
            .saturating_add(metric_rows.max(0) as u64);

        // DuckDB's minimum empty database file allocation on disk is ~256-512 KB and does not
        // shrink on DELETE; count file growth above the 512 KB baseline header when hot/cold
        // records exist so small byte-budget thresholds work deterministically in both
        // in-memory and file-backed stores.
        let db_file_bytes = if total_hot_rows > 0 || cold_shard_bytes > 0 {
            self.db_path
                .as_deref()
                .and_then(|p| std::fs::metadata(p).ok().map(|m| m.len()))
                .unwrap_or(0)
                .saturating_sub(512 * 1024)
        } else {
            0
        };

        let total_bytes = db_file_bytes
            .saturating_add(cold_shard_bytes.max(0) as u64)
            .saturating_add(estimated_hot_bytes);

        Ok((total_bytes, total_hot_rows))
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

    /// Upserts a slice of [`CentralSubmoduleSnapshot`] records.
    pub fn upsert_submodule_snapshots(
        &self,
        submodule_snapshots: &[CentralSubmoduleSnapshot],
    ) -> Result<u32, MuObserveError> {
        self.upsert_ci_state_batch(&[], &[], submodule_snapshots)
    }

    /// Upserts a batch of centralized `ActionRunner-controller` job records, branch snapshots,
    /// and submodule snapshots atomically.
    ///
    /// - `__ar_ha_lease__` rows are updated in the in-memory `WriteBehindCache` in `O(1)` without
    ///   touching DuckDB or triggering disk checkpoints.
    /// - Legacy `__ar_job_logs__` snapshots are split line-by-line (`1..=N`) into 1-line
    ///   [`OtelLogEntry`] records and passed to [`Self::insert_logs`] instead of storing a full-file blob.
    pub fn upsert_ci_state_batch(
        &self,
        records: &[CentralJobRecord],
        branch_snapshots: &[CentralBranchSnapshot],
        submodule_snapshots: &[CentralSubmoduleSnapshot],
    ) -> Result<u32, MuObserveError> {
        let mut total = 0u32;
        let mut regular_sub_snapshots: Vec<&CentralSubmoduleSnapshot> = Vec::new();
        let mut legacy_log_entries: Vec<OtelLogEntry> = Vec::new();

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
                    legacy_log_entries.extend(split_legacy_job_log_snapshot(s));
                    total = total.saturating_add(1);
                } else {
                    regular_sub_snapshots.push(s);
                }
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

        if !legacy_log_entries.is_empty() {
            let _ = self.insert_logs(&legacy_log_entries)?;
        }

        if has_db_writes {
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
    /// - Queries targeting `__ar_job_logs__` reconstruct per-job logs on the fly from `v_logs`.
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
            let conn = self.lock_conn()?;
            let mut stmt = conn.prepare(
                r#"
                SELECT job_id, body, timestamp_unix_nano
                FROM v_logs
                WHERE job_id IS NOT NULL
                  AND (?1 IS NULL OR LOWER(job_id) = LOWER(?1))
                ORDER BY job_id ASC,
                         CASE WHEN COALESCE(line_no, 0) > 0 THEN 0 ELSE 1 END ASC,
                         COALESCE(line_no, 0) ASC,
                         timestamp_unix_nano ASC
                "#,
            )?;
            let rows = stmt.query_map(params![req.submodule_key], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })?;

            let mut grouped: BTreeMap<String, (Vec<String>, i64)> = BTreeMap::new();
            for row in rows {
                let (jid, body, ts_ns) = row?;
                let entry = grouped
                    .entry(jid)
                    .or_insert_with(|| (Vec::new(), ts_ns / 1_000));
                entry.0.push(body);
                entry.1 = entry.1.max(ts_ns / 1_000);
            }

            let mut out = Vec::with_capacity(grouped.len());
            for (jid, (lines, max_us)) in grouped {
                out.push(CentralSubmoduleSnapshot {
                    parent_repo_key: INTERNAL_LOG_REPO_KEY.to_string(),
                    branch_key: req.branch_key.clone().unwrap_or_else(|| "log".to_string()),
                    submodule_key: jid.clone(),
                    submodule_path_key: "log".to_string(),
                    latest_active_job_id: Some(jid),
                    latest_active_json: Some(lines.join("\n")),
                    latest_active_queued_us: Some(max_us),
                    latest_completed_job_id: None,
                    latest_completed_json: None,
                    latest_completed_queued_us: None,
                });
            }
            return Ok(out);
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

    /// Returns row count in a hot table, index/catalog table, or unified view (for diagnostics & verification).
    pub fn count_rows(&self, relation: &str) -> Result<u64, MuObserveError> {
        let allowed = [
            "otel_logs",
            "log_inverted_index",
            "log_shards_catalog",
            "otel_spans",
            "otel_metrics",
            "test_case_runs",
            "benchmark_runs",
            "jobs_history",
            "branch_snapshots",
            "submodule_snapshots",
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
        let sql = format!("SELECT COUNT(*) FROM {}", escape_sql_literal(relation));
        let cnt: i64 = conn.query_row(&sql, [], |r| r.get(0))?;
        Ok(cnt.max(0) as u64)
    }
}

struct ExpandedSingleLineLog {
    entry: OtelLogEntry,
    line_no: u32,
    stream: u8,
    dedup_hash: u64,
}

fn parse_line_no_and_stream(attributes_json: &str, body: &str) -> (u32, u8) {
    let mut line_no = 0u32;
    let mut stream = 1u8;

    if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(attributes_json) {
        if let Some(v) = map.get("line_no") {
            if let Some(n) = v.as_u64() {
                line_no = n.min(u64::from(u32::MAX)) as u32;
            } else if let Some(s) = v.as_str().and_then(|s| s.trim().parse::<u32>().ok()) {
                line_no = s;
            }
        }
        if let Some(v) = map.get("stream") {
            if let Some(n) = v.as_u64() {
                if n == 2 {
                    stream = 2;
                } else if n == 1 {
                    stream = 1;
                }
            } else if let Some(s) = v.as_str() {
                if s.eq_ignore_ascii_case("stderr") || s == "2" {
                    stream = 2;
                } else if s.eq_ignore_ascii_case("stdout") || s == "1" {
                    stream = 1;
                }
            }
        }
    }

    let trimmed = body.trim_start();
    if trimmed.starts_with("[stderr]") || trimmed.contains(" [stderr] ") {
        stream = 2;
    }

    (line_no, stream)
}

fn expand_log_entries_to_single_lines(entries: &[OtelLogEntry]) -> Vec<ExpandedSingleLineLog> {
    let mut out = Vec::with_capacity(entries.len());

    for e in entries {
        let (base_line_no, base_stream) = parse_line_no_and_stream(&e.attributes_json, &e.body);

        if e.body.contains('\n') {
            let mut raw_segments: Vec<&str> = e.body.split('\n').collect();
            if raw_segments
                .last()
                .is_some_and(|last| last.strip_suffix('\r').unwrap_or(last).is_empty())
            {
                raw_segments.pop();
            }

            for (idx, seg) in raw_segments.into_iter().enumerate() {
                let single_line = seg.strip_suffix('\r').unwrap_or(seg);
                let line_no = if base_line_no > 0 {
                    base_line_no.saturating_add(idx as u32)
                } else {
                    (idx as u32).saturating_add(1)
                };
                let stream = if single_line.trim_start().starts_with("[stderr]")
                    || single_line.contains(" [stderr] ")
                {
                    2
                } else {
                    base_stream
                };
                let ts_ns = e
                    .timestamp_unix_nano
                    .saturating_add((idx as i64).saturating_mul(1_000));
                let dedup_hash = compute_log_dedup_hash(
                    &e.node_id,
                    &e.service_name,
                    e.job_id.as_deref(),
                    e.stage_id.as_deref(),
                    stream,
                    line_no,
                    ts_ns,
                    single_line,
                );
                let mut line_entry = e.clone();
                line_entry.timestamp_unix_nano = ts_ns;
                line_entry.body = single_line.to_string();
                out.push(ExpandedSingleLineLog {
                    entry: line_entry,
                    line_no,
                    stream,
                    dedup_hash,
                });
            }
        } else {
            let single_line = e.body.strip_suffix('\r').unwrap_or(&e.body);
            let dedup_hash = compute_log_dedup_hash(
                &e.node_id,
                &e.service_name,
                e.job_id.as_deref(),
                e.stage_id.as_deref(),
                base_stream,
                base_line_no,
                e.timestamp_unix_nano,
                single_line,
            );
            let mut line_entry = e.clone();
            line_entry.body = single_line.to_string();
            out.push(ExpandedSingleLineLog {
                entry: line_entry,
                line_no: base_line_no,
                stream: base_stream,
                dedup_hash,
            });
        }
    }

    out
}

fn derive_ci_short_job_and_trace(job_id: &str) -> (String, String) {
    let suffix = job_id.rsplit('-').next().unwrap_or(job_id);
    let short_job: String = if suffix.len() >= 6 {
        suffix.chars().take(6).collect()
    } else if !job_id.is_empty() {
        job_id.chars().take(6).collect()
    } else {
        "live".to_string()
    };
    let trace_id = format!("tr-ci-{short_job}");
    (short_job, trace_id)
}

struct ParsedCiLogLine {
    timestamp_ns: Option<i64>,
    node_id: String,
    stage_id: Option<String>,
    is_stderr: bool,
    body: String,
}

fn parse_ci_job_log_line(line: &str) -> ParsedCiLogLine {
    let trimmed = line.trim();
    if let Some((first_tok, rest1)) = trimmed.split_once(" [") {
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(first_tok.trim()) {
            let ts_ns = dt
                .timestamp_nanos_opt()
                .unwrap_or_else(|| dt.timestamp_micros().saturating_mul(1_000));
            if let Some((node_tok, rest2)) = rest1.split_once("] [") {
                if let Some((stage_tok, rest3)) = rest2.split_once("] ") {
                    let (is_stderr, content) = if let Some(c) = rest3.strip_prefix("[stderr] ") {
                        (true, c)
                    } else if let Some(c) = rest3.strip_prefix("[stdout] ") {
                        (false, c)
                    } else {
                        (false, rest3)
                    };
                    return ParsedCiLogLine {
                        timestamp_ns: Some(ts_ns),
                        node_id: node_tok.trim().to_string(),
                        stage_id: Some(stage_tok.trim().to_string()),
                        is_stderr,
                        body: format!("[{}] {}", stage_tok.trim(), content.trim()),
                    };
                }
            }
        }
    }

    if let Some(after_stage) = trimmed.strip_prefix("=== Stage '") {
        if let Some((stage_tok, after_quote)) = after_stage.split_once('\'') {
            let node_id = after_quote
                .split_once("worker '")
                .and_then(|(_, w)| w.split_once('\''))
                .map(|(n, _)| n.to_string())
                .unwrap_or_else(|| "controller".to_string());
            return ParsedCiLogLine {
                timestamp_ns: None,
                node_id,
                stage_id: Some(stage_tok.to_string()),
                is_stderr: false,
                body: trimmed.to_string(),
            };
        }
    }

    ParsedCiLogLine {
        timestamp_ns: None,
        node_id: "controller".to_string(),
        stage_id: None,
        is_stderr: false,
        body: trimmed.to_string(),
    }
}

fn classify_ci_log_severity(line: &str, is_stderr: bool) -> (i32, &'static str) {
    let lower = line.to_ascii_lowercase();
    if lower.contains("error:")
        || lower.contains("error[")
        || lower.contains("panicked at")
        || lower.contains("exited with status code")
        || lower.contains("test result: failed")
        || lower.contains("exit_code=some(1")
        || (is_stderr && (lower.contains("failed") || lower.contains("fatal")))
    {
        (17, "ERROR")
    } else if lower.contains("warning:") || lower.contains("[warn]") {
        (13, "WARN")
    } else {
        (9, "INFO")
    }
}

fn split_legacy_job_log_snapshot(snap: &CentralSubmoduleSnapshot) -> Vec<OtelLogEntry> {
    let canonical_job_id = snap
        .latest_active_job_id
        .as_deref()
        .or(snap.latest_completed_job_id.as_deref())
        .unwrap_or(&snap.submodule_key)
        .to_string();
    let (short_job, ci_trace_id) = derive_ci_short_job_and_trace(&canonical_job_id);

    let Some(raw_log) = snap
        .latest_active_json
        .as_deref()
        .or(snap.latest_completed_json.as_deref())
        .filter(|s| !s.trim().is_empty())
    else {
        return Vec::new();
    };

    let base_queued_us = snap
        .latest_active_queued_us
        .or(snap.latest_completed_queued_us)
        .unwrap_or(1_700_000_000_000_000);
    let base_ts_ns = base_queued_us.saturating_mul(1_000);

    let mut entries = Vec::new();
    let mut line_no = 0u32;
    for (idx, raw_line) in raw_log.lines().enumerate() {
        let trimmed = raw_line.trim_end_matches('\r');
        if trimmed.trim().is_empty() {
            continue;
        }
        line_no = line_no.saturating_add(1);
        let parsed = parse_ci_job_log_line(trimmed);
        let (sev_num, sev_txt) = classify_ci_log_severity(&parsed.body, parsed.is_stderr);
        let ts_ns = parsed
            .timestamp_ns
            .unwrap_or_else(|| base_ts_ns.saturating_add((idx as i64).saturating_mul(1_000_000)));
        let span_id = match &parsed.stage_id {
            Some(st) => format!("sp-{short_job}-{st}"),
            None => format!("sp-{short_job}-1"),
        };
        let stream_str = if parsed.is_stderr { "stderr" } else { "stdout" };
        let attrs = json!({
            "line_no": line_no,
            "stream": stream_str,
            "job_id": canonical_job_id,
            "stage_id": parsed.stage_id,
        });
        entries.push(OtelLogEntry {
            timestamp_unix_nano: ts_ns,
            trace_id: ci_trace_id.clone(),
            span_id,
            severity_number: sev_num,
            severity_text: sev_txt.to_string(),
            service_name: "actionrunner-rs".to_string(),
            node_id: parsed.node_id,
            body: parsed.body,
            attributes_json: attrs.to_string(),
            job_id: Some(canonical_job_id.clone()),
            stage_id: parsed.stage_id,
        });
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::parquet_compactor::{CompactorConfig, ParquetCompactor};
    use mu_observable_ipc::{
        benchmark_runs_to_record_batch, log_entries_to_record_batch,
        metric_entries_to_record_batch, span_entries_to_record_batch, test_runs_to_record_batch,
    };
    use tempfile::tempdir;

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

        // 2. Filtered query explicitly targeting __ar_job_logs__ reconstructs from v_logs
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
            "Explicit query for __ar_job_logs__ must succeed and return reconstructed row"
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
        // and __ar_job_logs__ lines were ingested into otel_logs.
        assert_eq!(
            store.count_rows("submodule_snapshots").unwrap(),
            legit_repos.len() as u64
        );
        assert_eq!(store.count_rows("otel_logs").unwrap(), 1);

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

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_multiline_splitting_and_single_line_deduplication() {
        let store = HotDuckDbStore::open_in_memory().expect("open in memory");

        // 1. Multi-line log chunk splits into individual 1-line rows with sequential line_no
        let multiline_entry = OtelLogEntry {
            timestamp_unix_nano: 1_700_000_000_000_000_000,
            trace_id: "trace-dedup-1".into(),
            span_id: "span-1".into(),
            severity_number: 9,
            severity_text: "INFO".into(),
            service_name: "action-runner-worker".into(),
            node_id: "worker-riscv64".into(),
            body: "Compiling k3-core v0.1.0\r\n[stderr] warning: unused variable\r\nFinished test profile\n".into(),
            attributes_json: r#"{"line_no":1,"stream":"stdout"}"#.into(),
            job_id: Some("job-dedup-42".into()),
            stage_id: Some("clippy-check".into()),
        };

        let inserted = store
            .insert_logs(std::slice::from_ref(&multiline_entry))
            .expect("insert multiline");
        assert_eq!(inserted, 3);
        assert_eq!(store.count_rows("otel_logs").unwrap(), 3);

        // 2. Re-inserting the exact same lines (even with a different controller timestamp/node)
        // produces the exact same ci_line dedup_hash and inserts 0 duplicate rows!
        let duplicate_from_controller = OtelLogEntry {
            timestamp_unix_nano: 1_700_000_005_999_999_999,
            trace_id: "trace-dedup-1".into(),
            span_id: "span-1".into(),
            severity_number: 9,
            severity_text: "INFO".into(),
            service_name: "action-runner-controller".into(),
            node_id: "node-a".into(),
            body: "Compiling k3-core v0.1.0".into(),
            attributes_json: r#"{"line_no":1,"stream":1}"#.into(),
            job_id: Some("job-dedup-42".into()),
            stage_id: Some("clippy-check".into()),
        };

        let dup_inserted = store
            .insert_logs(std::slice::from_ref(&duplicate_from_controller))
            .expect("insert duplicate line");
        assert_eq!(dup_inserted, 0);
        assert_eq!(store.count_rows("otel_logs").unwrap(), 3);

        // Even if the in-memory FIFO dedup cache is cleared, SQL WHERE NOT EXISTS still blocks duplicates
        store.dedup_cache.lock().unwrap().clear();
        let dup_sql_inserted = store
            .insert_logs(std::slice::from_ref(&duplicate_from_controller))
            .expect("insert duplicate line against SQL guard");
        assert_eq!(dup_sql_inserted, 0);
        assert_eq!(store.count_rows("otel_logs").unwrap(), 3);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_inverted_index_tokenization_and_search_logs_by_token() {
        let store = HotDuckDbStore::open_in_memory().expect("open in memory");
        let base_ts = 1_700_000_010_000_000_000i64;

        let entries = vec![
            OtelLogEntry {
                timestamp_unix_nano: base_ts,
                trace_id: "tr-1".into(),
                span_id: "sp-1".into(),
                severity_number: 9,
                severity_text: "INFO".into(),
                service_name: "k3-engine".into(),
                node_id: "worker-riscv64".into(),
                body: "Initialized XSMTVDotII matrix kernel on cluster A100".into(),
                attributes_json: r#"{"line_no":1,"stream":1}"#.into(),
                job_id: Some("job-rvv-1".into()),
                stage_id: Some("bench-stage".into()),
            },
            OtelLogEntry {
                timestamp_unix_nano: base_ts + 1_000_000,
                trace_id: "tr-1".into(),
                span_id: "sp-1".into(),
                severity_number: 17,
                severity_text: "ERROR".into(),
                service_name: "k3-engine".into(),
                node_id: "worker-riscv64".into(),
                body: "InsufficientLockableMemory admission refusal at src/kv_cache.rs".into(),
                attributes_json: r#"{"line_no":2,"stream":2}"#.into(),
                job_id: Some("job-rvv-1".into()),
                stage_id: Some("bench-stage".into()),
            },
        ];

        let tokens = tokenize_log_line(&entries[0], &entries[0].body);
        assert!(tokens.contains(&"xsmtvdotii".to_string()));
        assert!(tokens.contains(&"a100".to_string()));
        assert!(tokens.contains(&"k3-engine".to_string()));
        assert!(tokens.contains(&"worker-riscv64".to_string()));
        assert!(tokens.contains(&"job-rvv-1".to_string()));
        assert!(tokens.contains(&"bench-stage".to_string()));

        store.insert_logs(&entries).expect("insert logs");
        assert!(store.count_rows("log_inverted_index").unwrap() >= 10);

        let hits = store
            .search_logs_by_token("InsufficientLockableMemory src/kv_cache.rs", None, 10)
            .expect("search by token");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].line_no, 2);
        assert_eq!(hits[0].stream, 2);
        assert!(hits[0].body.contains("InsufficientLockableMemory"));

        let both_hits = store
            .search_logs_by_token("worker-riscv64", Some("job-rvv-1"), 10)
            .expect("search metadata token");
        assert_eq!(both_hits.len(), 2);
        // Ordered by timestamp_unix_nano DESC, line_no DESC
        assert_eq!(both_hits[0].line_no, 2);
        assert_eq!(both_hits[1].line_no, 1);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_query_sanitized_job_log_ordered_line_reconstruction() {
        let store = HotDuckDbStore::open_in_memory().expect("open in memory");
        let base_ts = 1_700_000_020_000_000_000i64;

        // Insert out-of-order line_no records (3, 1, 2) to verify deterministic line_no ASC reconstruction
        let entries = vec![
            OtelLogEntry {
                timestamp_unix_nano: base_ts + 3_000,
                trace_id: "tr-job-99".into(),
                span_id: "sp-1".into(),
                severity_number: 9,
                severity_text: "INFO".into(),
                service_name: "action-runner-worker".into(),
                node_id: "worker-riscv64".into(),
                body: "line three: completed on 10.0.0.42".into(),
                attributes_json: r#"{"line_no":3,"stream":1}"#.into(),
                job_id: Some("job-reconstruct-99".into()),
                stage_id: Some("test".into()),
            },
            OtelLogEntry {
                timestamp_unix_nano: base_ts + 1_000,
                trace_id: "tr-job-99".into(),
                span_id: "sp-1".into(),
                severity_number: 9,
                severity_text: "INFO".into(),
                service_name: "action-runner-worker".into(),
                node_id: "worker-riscv64".into(),
                body: "line one: started stage".into(),
                attributes_json: r#"{"line_no":1,"stream":1}"#.into(),
                job_id: Some("job-reconstruct-99".into()),
                stage_id: Some("test".into()),
            },
            OtelLogEntry {
                timestamp_unix_nano: base_ts + 2_000,
                trace_id: "tr-job-99".into(),
                span_id: "sp-1".into(),
                severity_number: 13,
                severity_text: "WARN".into(),
                service_name: "action-runner-worker".into(),
                node_id: "worker-riscv64".into(),
                body: "line two: running crate tests".into(),
                attributes_json: r#"{"line_no":2,"stream":2}"#.into(),
                job_id: Some("job-reconstruct-99".into()),
                stage_id: Some("test".into()),
            },
        ];

        store
            .insert_logs(&entries)
            .expect("insert out-of-order lines");

        let reconstructed = store
            .query_sanitized_job_log("job-reconstruct-99")
            .expect("query job log")
            .expect("job log exists");
        let lines: Vec<&str> = reconstructed.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "line one: started stage");
        assert_eq!(lines[1], "line two: running crate tests");
        assert!(lines[2].starts_with("line three: completed on 192.0.2."));
        assert!(!lines[2].contains("10.0.0.42"));

        assert_eq!(
            store
                .query_sanitized_job_log("nonexistent-job-id")
                .expect("query missing job"),
            None
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_strict_fifo_eviction_by_timestamp_and_space_budget() {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("fifo.duckdb");
        let parquet_root = dir.path().join("parquet");
        let store =
            HotDuckDbStore::open(Some(&db_path), Some(&parquet_root)).expect("open file store");

        let t0 = 1_700_000_000_000_000_000i64;
        let day_ns = 86_400 * 1_000_000_000i64;

        // Insert 4 logs at t0 (expired), t0 + 2d (will be compacted to cold shard),
        // t0 + 9d (hot old), and t0 + 10d (hot newest).
        let logs = vec![
            OtelLogEntry {
                timestamp_unix_nano: t0,
                trace_id: "tr-0".into(),
                span_id: "sp-0".into(),
                severity_number: 9,
                severity_text: "INFO".into(),
                service_name: "svc-a".into(),
                node_id: "node-a".into(),
                body: "log-t0-expired".into(),
                attributes_json: r#"{"line_no":1}"#.into(),
                job_id: Some("job-0".into()),
                stage_id: None,
            },
            OtelLogEntry {
                timestamp_unix_nano: t0 + 2 * day_ns,
                trace_id: "tr-2".into(),
                span_id: "sp-2".into(),
                severity_number: 9,
                severity_text: "INFO".into(),
                service_name: "svc-a".into(),
                node_id: "node-a".into(),
                body: "log-t2-cold-shard".into(),
                attributes_json: r#"{"line_no":1}"#.into(),
                job_id: Some("job-2".into()),
                stage_id: None,
            },
            OtelLogEntry {
                timestamp_unix_nano: t0 + 9 * day_ns,
                trace_id: "tr-9".into(),
                span_id: "sp-9".into(),
                severity_number: 9,
                severity_text: "INFO".into(),
                service_name: "svc-a".into(),
                node_id: "node-a".into(),
                body: "log-t9-hot-older".into(),
                attributes_json: r#"{"line_no":1}"#.into(),
                job_id: Some("job-9".into()),
                stage_id: None,
            },
            OtelLogEntry {
                timestamp_unix_nano: t0 + 10 * day_ns,
                trace_id: "tr-10".into(),
                span_id: "sp-10".into(),
                severity_number: 9,
                severity_text: "INFO".into(),
                service_name: "svc-a".into(),
                node_id: "node-a".into(),
                body: "log-t10-hot-newest".into(),
                attributes_json: r#"{"line_no":1}"#.into(),
                job_id: Some("job-10".into()),
                stage_id: None,
            },
        ];
        store.insert_logs(&logs).expect("insert 4 logs");

        // Compact records older than 7 days (t0 and t0 + 2d) into cold Parquet shards
        let compactor = ParquetCompactor::new(CompactorConfig::new(&parquet_root));
        compactor
            .compact_before(&store, t0 + day_ns)
            .expect("compact t0 shard");
        compactor
            .compact_before(&store, t0 + 3 * day_ns)
            .expect("compact t2 shard");
        assert_eq!(store.count_rows("log_shards_catalog").unwrap(), 2);
        assert_eq!(store.count_rows("otel_logs").unwrap(), 2);
        assert_eq!(store.count_rows("v_logs").unwrap(), 4);

        // 1. Time-based eviction: max_age = 9 days from now = t0 + 10d -> evicts the t0 shard (< t0 + 1d)
        let now_ns = t0 + 10 * day_ns;
        let evicted_by_age = store
            .enforce_fifo_time_and_space_eviction(now_ns, 9 * day_ns, u64::MAX, 0)
            .expect("evict by age");
        assert!(evicted_by_age >= 1);
        assert_eq!(store.count_rows("log_shards_catalog").unwrap(), 1);
        assert_eq!(store.count_rows("v_logs").unwrap(), 3);

        // 2. Space-budget FIFO eviction: set max_store_bytes small enough that only the single
        // newest hot log (t10) fits; must evict the remaining cold shard (t2) first, then the
        // older hot row (t9), preserving only the newest row (t10)!
        let evicted_by_space = store
            .enforce_fifo_time_and_space_eviction(now_ns, 30 * day_ns, 450, 0)
            .expect("evict by space budget");
        assert!(evicted_by_space >= 2);
        assert_eq!(store.count_rows("log_shards_catalog").unwrap(), 0);
        assert_eq!(store.count_rows("otel_logs").unwrap(), 1);
        assert_eq!(
            store.query_sanitized_job_log("job-10").unwrap().as_deref(),
            Some("log-t10-hot-newest")
        );
        assert_eq!(store.query_sanitized_job_log("job-9").unwrap(), None);

        // Verify statvfs helper returns Some(> 0) on the tempdir path
        assert!(available_disk_bytes(dir.path()).unwrap_or(1) > 0);
    }
}
