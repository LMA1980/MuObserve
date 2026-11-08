# mu-observable-hub

<p align="center">
  <a href="https://hook.lma1980.duckdns.org/jobs">
    <img src="https://hook.lma1980.duckdns.org/cards/LMA1980/mu-observable-hub/card.svg" alt="mu-observable-hub Factory Scorecard" width="520"/>
  </a>
</p>

<p align="center">
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/mu-observable-hub/status.svg" alt="CI Status"/></a>
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/mu-observable-hub/score.svg" alt="Quality Score"/></a>
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/mu-observable-hub/coverage.svg" alt="Coverage"/></a>
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/mu-observable-hub/benchmark.svg" alt="Benchmark"/></a>
</p>

---

Distributed **OpenTelemetry (OTEL) + DuckDB/Parquet** observability backend, centralized `ActionRunner-controller` state store, hardware-aware benchmark & test regression analytics engine, and **Antigravity Model Context Protocol (MCP) server**.

## Architectural Scope

- **Zero-Trust `step-ca` mTLS Ingestion & Centralized State**:
  - Verifies client certificate DNS/URI SANs to enforce cryptographic node and service attribution.
  - Hosts the centralized `ActionRunner-controller` operational catalog (`jobs_history`, `branch_snapshots`, `submodule_snapshots`) alongside unified `otel_spans`, `otel_logs`, `otel_metrics`, `test_case_runs`, and `benchmark_runs`.
- **3-Tier Hybrid DuckDB + Zstd Parquet Storage Lifecycle & OpenSearch-Style Line Index**:
  - **Single-Line Deduplicated Log Store (`otel_logs`)**: Stores every CI and daemon log line once (`1 line = 1 record`) with `line_no`, `stream`, and a deterministic 64-bit FNV-1a `dedup_hash` (bounded 65,536-entry FIFO ring + SQL `WHERE NOT EXISTS` guard), retiring full-file `job_logs_store` (`__ar_job_logs__`) blob rewrites.
  - **Inverted Token Index & Shard Catalog (`log_inverted_index`, `log_shards_catalog`)**: Indexes up to 32 normalized lowercase tokens per log line in local DuckDB and tracks hot and cold Zstd Parquet / Garage S3 (`cold_parquet` / `cold_s3`) segments for sub-millisecond keyword search and ordered line-by-line `/api/v1/jobs/{job_id}/log` reconstruction.
  - **Strict FIFO Time & Disk-Space Eviction**: Evicts oldest cold shards and hot records strictly in FIFO timestamp order whenever retention TTL expires or available physical disk space (`libc::statvfs` vs `MUOBSERVE_MIN_FREE_DISK_BYTES`) / store byte ceiling (`MUOBSERVE_MAX_STORE_BYTES`) is exceeded. See [`specs/line-indexed-log-store-and-fifo-eviction.md`](specs/line-indexed-log-store-and-fifo-eviction.md).
- **Hardware-Aware Benchmark & Test Regression Engine**:
  - Compares `feat/**` candidate runs against rolling `main` baselines stratified by hardware profile (`arch`, `cpu_cluster` e.g. `X100` `VLEN=256` vs `A100` `VLEN=1024` vs `x86_64`), computing relative deltas and MAD modified $z$-scores, plus rolling 30-day test flakiness indices.
- **Antigravity MCP Server (`mu-observable-mcp`) & CLI (`mu-observable-cli`)**:
  - Provides deterministic MCP tools (`check_benchmark_regressions`, `get_test_flakiness`, `compare_branches`, `query_trace_waterfall`, `correlate_logs_by_trace_id`, `search_error_anomalies`, `assert_service_slo`, `inspect_node_utilization`, `compare_cluster_efficiency`, `execute_analytics_sql`) so Antigravity can autonomously assert operational efficiency and performance.

## License

Licensed under `AGPL-3.0-only`. See [`LICENSE`](LICENSE) for details.
