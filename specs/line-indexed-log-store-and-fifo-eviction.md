# Spec: Line-Indexed Deduplicated Log Store, Inverted Token Index & Strict FIFO Eviction

## Location: `specs/line-indexed-log-store-and-fifo-eviction.md`

### 1. Overview & Motivation

`mu-observable-hub` replaces full-file CI job log blob re-writes (`job_logs_store` / `__ar_job_logs__`) with a single-line deduplicated OpenTelemetry log store (`otel_logs`), a local DuckDB inverted token and metadata index (`log_inverted_index`), a tiered shard catalog (`log_shards_catalog`) spanning hot DuckDB and cold Zstd Parquet / S3 segments, and strict FIFO eviction governed by both retention TTL and physical disk space (`libc::statvfs`).

---

### 2. Single-Line Log Schema & Deterministic Deduplication (`otel_logs`)

#### 2.1 `otel_logs` Table Schema

```sql
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

CREATE INDEX IF NOT EXISTS idx_otel_logs_ts ON otel_logs (timestamp_unix_nano);
CREATE INDEX IF NOT EXISTS idx_otel_logs_trace ON otel_logs (trace_id);
CREATE INDEX IF NOT EXISTS idx_otel_logs_job ON otel_logs (job_id);
CREATE INDEX IF NOT EXISTS idx_otel_logs_dedup ON otel_logs (dedup_hash);
CREATE INDEX IF NOT EXISTS idx_otel_logs_job_line ON otel_logs (job_id, line_no, timestamp_unix_nano);
```

- **1 Line = 1 Record**: Incoming `OtelLogEntry` payloads whose `body` contains embedded newlines (`\n`) are split into individual single-line records prior to persistence. When `line_no > 0` is present in `attributes_json`, subsequent split lines increment `line_no` monotonically (`base_line_no + idx`).
- **Stream Attribution (`stream UTINYINT`)**: Extracted from `attributes_json` (`"stream": "stderr" | "stdout" | 1 | 2`) or `[stderr]` line prefixes (`1` = `stdout`, `2` = `stderr`).
- **Retirement of `job_logs_store`**: Full-file `job_logs_store` (`__ar_job_logs__`) blobs are retired (`DROP TABLE IF EXISTS job_logs_store`). Any transitional `__ar_job_logs__` snapshot received via `upsert_submodule_snapshots` is split line-by-line (`1..=N`) into single-line `OtelLogEntry` records and routed through `insert_logs`.

#### 2.2 Deterministic 64-Bit FNV-1a Deduplication (`dedup_hash`)

Every normalized single-line record is assigned a deterministic 64-bit FNV-1a `dedup_hash`:

1. **CI Job Lines (`job_id.is_some() && line_no > 0`)**:
   $$\text{dedup\_hash} = \text{FNV1a}_{64}(\texttt{"ci\_line"}, \text{job\_id}, \text{stage\_id}, \text{stream}, \text{line\_no}, \text{trim\_end}(\text{body}))$$
   Timestamp is intentionally excluded so identical `(job_id, stage_id, stream, line_no, body)` records arriving via different transport paths deduplicate deterministically.
2. **General Daemon & Kernel Lines (`line_no == 0` or `job_id.is_none()`)**:
   $$\text{dedup\_hash} = \text{FNV1a}_{64}(\texttt{"daemon\_line"}, \text{node\_id}, \text{service\_name}, \text{job\_id}, \text{stage\_id}, \text{stream}, \lfloor\text{timestamp\_unix\_nano} / 10^9\rfloor, \text{trim\_end}(\text{body}))$$

`HotDuckDbStore` enforces deduplication at two layers:
- A bounded in-memory FIFO deduplication ring (`VecDeque<u64>` + `HashSet<u64>`, capacity `65,536` hashes) that drops duplicate lines in $O(1)$ before acquiring a SQL statement.
- A parameterized SQL guard `WHERE NOT EXISTS (SELECT 1 FROM otel_logs WHERE dedup_hash = ?)` preventing duplicate persistence across restarts.

---

### 3. OpenSearch-Style Inverted Token Index & Tiered Shard Catalog

#### 3.1 Schema Definitions

```sql
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
```

#### 3.2 Tokenization & Search (`tokenize_log_line` / `search_logs_by_token`)

- For each newly inserted log line, `tokenize_log_line` extracts up to `32` unique lowercase tokens (`len >= 2`, splitting on characters outside `[a-z0-9_.\-/]`) across `body`, `service_name`, `node_id`, `job_id`, and `stage_id`, inserting `(token, timestamp_unix_nano, 'hot', dedup_hash, job_id, node_id, service_name)` into `log_inverted_index`.
- `search_logs_by_token(query, job_id, limit)` tokenizes the query string, intersects matching `dedup_hash` entries in `log_inverted_index` (requiring all query tokens to match the line), and joins against the unified `v_logs` view ordered by `timestamp_unix_nano DESC, line_no DESC`.

#### 3.3 Tiered Compaction (`hot` $\rightarrow$ `cold_parquet` / `cold_s3`)

- When `ParquetCompactor` compacts aged `otel_logs` records into Hive-partitioned Zstd Parquet segments (`<parquet_root>/otel_logs/date=YYYY-MM-DD/part-<cutoff_ns>.parquet`), it registers the segment in `log_shards_catalog` (`tier = 'cold_s3'` when `MUOBSERVE_S3_ENDPOINT` or `MUOBSERVE_S3_BUCKET` is configured, else `'cold_parquet'`) and updates `log_inverted_index SET shard_id = ?` for the compacted window while deleting the compacted rows from hot `otel_logs`.
- Unified view `v_logs` transparently unions hot `otel_logs` with `read_parquet(..., hive_partitioning = true, union_by_name = true)`.

---

### 4. Ordered Line Reconstruction for Console & Job Log APIs

- `GET /api/v1/jobs/{job_id}/log` (`HotDuckDbStore::query_sanitized_job_log`) reconstructs the complete job log directly from `v_logs`:
  ```sql
  SELECT body, line_no, timestamp_unix_nano
  FROM v_logs
  WHERE job_id = ?
  ORDER BY CASE WHEN line_no > 0 THEN 0 ELSE 1 END ASC,
           line_no ASC,
           timestamp_unix_nano ASC
  ```
- `GET /api/v1/logs` (`query_sanitized_logs_with_token`) supports optional `job_id`, `node_id`, `service_name`, `severity_min`, and `q`/`token` full-text inverted index filtering, returning `line_no` and `stream` metadata on every `ConsoleLogItem`.
- `mtls_ingest` preserves `entry.node_id` and `entry.service_name` when `entry.job_id.is_some() && !entry.node_id.is_empty()` so worker stage logs forwarded by `mu-ci-controller` retain their originating worker node attribution (e.g. `node-a`, `worker-riscv64`).

---

### 5. Strict FIFO Time & Physical Disk-Space Eviction

`HotDuckDbStore::enforce_fifo_time_and_space_eviction(now_ns, max_age_ns, max_store_bytes, min_free_disk_bytes)` enforces two non-negotiable storage bounds strictly in **FIFO timestamp order**:

1. **TTL Expiration (`cutoff_ns = now_ns - max_age_ns`)**:
   - Deletes all rows with `timestamp_unix_nano < cutoff_ns` across `otel_logs`, `log_inverted_index`, `otel_spans`, and `otel_metrics`, and removes expired cold shards (`max_timestamp_ns < cutoff_ns`) from `log_shards_catalog` and disk.
2. **Physical Disk Space & Store Byte Budget (`libc::statvfs`)**:
   - Queries available filesystem bytes via `libc::statvfs` (`MUOBSERVE_MIN_FREE_DISK_BYTES`, default `2 GiB`) and total store footprint (`db_file_bytes + cold_shard_bytes + estimated_hot_bytes` vs `MUOBSERVE_MAX_STORE_BYTES`, default `4 GiB`).
   - While store footprint exceeds `max_store_bytes` or free disk space is below `min_free_disk_bytes`, evicts the oldest cold shard (`ORDER BY max_timestamp_ns ASC LIMIT 1`) or the oldest batch of `512` hot rows (`ORDER BY timestamp_unix_nano ASC LIMIT 512`) across `otel_logs`, `log_inverted_index`, `otel_spans`, and `otel_metrics`, followed by `CHECKPOINT`.
