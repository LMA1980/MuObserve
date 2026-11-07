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
- **3-Tier Hybrid DuckDB + Zstd Parquet Storage Lifecycle**:
  - **Hot Tier (`/var/lib/muobserve/hot.duckdb`)**: Fast indexed DuckDB tables for the active 7-day window and live CI state.
  - **Cold Tier (`/var/lib/muobserve/parquet/signal=<type>/year=YYYY/month=MM/`)**: Scheduled background compaction into Hive-partitioned Zstd Parquet files on Btrfs RAID1, queried transparently via unified DuckDB views (`v_logs`, `v_traces`, `v_metrics`, `v_tests`, `v_benchmarks`).
- **Hardware-Aware Benchmark & Test Regression Engine**:
  - Compares `feat/**` candidate runs against rolling `main` baselines stratified by hardware profile (`arch`, `cpu_cluster` e.g. `X100` `VLEN=256` vs `A100` `VLEN=1024` vs `x86_64`), computing relative deltas and MAD modified $z$-scores, plus rolling 30-day test flakiness indices.
- **Antigravity MCP Server (`mu-observable-mcp`) & CLI (`mu-observable-cli`)**:
  - Provides deterministic MCP tools (`check_benchmark_regressions`, `get_test_flakiness`, `compare_branches`, `query_trace_waterfall`, `correlate_logs_by_trace_id`, `search_error_anomalies`, `assert_service_slo`, `inspect_node_utilization`, `compare_cluster_efficiency`, `execute_analytics_sql`) so Antigravity can autonomously assert operational efficiency and performance.

## License

Licensed under `AGPL-3.0-only`. See [`LICENSE`](LICENSE) for details.
