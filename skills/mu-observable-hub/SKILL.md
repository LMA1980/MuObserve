---
name: mu-observable-hub
description: "Query and analyze distributed OpenTelemetry logs, W3C trace waterfalls, hardware-stratified SpacemiT K3 (X100 vs A100) benchmark regressions, 30-day test flakiness, canary deployment SLOs, and guarded DuckDB/Parquet SQL analytics via mu-observable-mcp and mu-observable-cli."
---

# `mu-observable-hub` Observability, Regression Analytics & MCP Usage

Use this skill when investigating CI pipeline failures, W3C distributed traces, hardware-stratified benchmark regressions across SpacemiT K3 Cluster 0 (`X100`, `VLEN=256`) and Cluster 1 (`A100`, `VLEN=1024`) vs `x86_64`, evaluating canary deployment SLOs, or running read-only analytical SQL queries against `mu-observable-hub`.

## 1. MCP Server Tools (`mu-observable-mcp`)

`mu-observable-mcp` exposes 10 structured JSON-RPC 2.0 MCP tools over `stdio` or HTTP:

| MCP Tool Name | Required Arguments | Purpose |
| :--- | :--- | :--- |
| `check_benchmark_regressions` | `repo_key`, `candidate_commit` | Evaluates candidate benchmark runs against rolling `main` baselines stratified by `(arch, cpu_cluster, vlen_bits)` using MAD Z-score and slowdown thresholds. |
| `get_test_flakiness` | `repo_key` | Computes the rolling 30-day pass/fail flip-flop flakiness index per test case in `v_tests`. |
| `compare_branches` | `repo_key`, `candidate_branch` | Compares benchmark performance and regressions between `candidate_branch` and `baseline_branch` (`main`). |
| `query_trace_waterfall` | `trace_id` | Reconstructs the ordered parent-child W3C span waterfall and durations from `v_traces`. |
| `correlate_logs_by_trace_id` | `trace_id` | Retrieves all structured logs from `v_logs` sharing `trace_id` in chronological order. |
| `search_error_anomalies` | *(optional)* `service_name`, `node_id`, `limit` | Searches recent `ERROR` / `FATAL` logs (`severity_number >= 17`) across services and nodes (e.g., `node-a`, `worker-riscv64`). |
| `assert_service_slo` | `service_name` | Evaluates `MuConDe` canary bake-window SLOs (`max_error_logs`, `max_p99_latency_ms`) and returns `should_rollback_and_taint`. |
| `inspect_node_utilization` | `node_id` | Inspects hardware telemetry (`arch`, `cpu_cluster`, `vlen_bits`, `memlock_used_bytes`, `memlock_limit_bytes`) from `v_metrics`. |
| `compare_cluster_efficiency` | *(optional)* `repo_key`, `bench_name` | Compares SpacemiT K3 Cluster 0 (`X100`, `VLEN=256`) vs Cluster 1 (`A100`, `VLEN=1024`) vs `x86_64` execution efficiency. |
| `execute_analytics_sql` | `sql` | Executes a guarded read-only DuckDB query (`SELECT`/`WITH`/`EXPLAIN` only; DDL/DML/ATTACH/COPY rejected; 5s timeout; 1,000-row cap). |

## 2. CLI Subcommand (`cargo agents mu-observable-hub` / `mu-observable-cli`)

```bash
# Check hardware-stratified benchmark & test regressions for a candidate commit
mu-observable-cli --db /var/lib/muobserve/db/muobserve.duckdb \
  regressions --repo lma1980/k3-core --commit HEAD --baseline main

# Evaluate canary service SLO over a 300s bake window
mu-observable-cli --db /var/lib/muobserve/db/muobserve.duckdb \
  slo --service action-runner-controller --digest HEAD --window-secs 300 --max-errors 0 --max-p99-ms 250.0

# Inspect a W3C trace waterfall and correlated logs
mu-observable-cli --db /var/lib/muobserve/db/muobserve.duckdb \
  traces --trace-id <32-hex-trace-id>

# Run a guarded read-only SQL query across unified hot DuckDB + cold Parquet views
mu-observable-cli --db /var/lib/muobserve/db/muobserve.duckdb \
  sql --query "SELECT repo_key, status_state, COUNT(*) AS jobs FROM v_jobs_history GROUP BY repo_key, status_state ORDER BY jobs DESC"
```
