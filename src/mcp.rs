use std::io::{BufRead, Write};
use std::time::Duration;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use duckdb::params;
use mu_observable_ipc::{CanarySloAssertionRequest, RegressionGateRequest};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::analytics::{
    compute_test_flakiness, evaluate_benchmark_regressions, evaluate_canary_slo,
    evaluate_regression_gate, DEFAULT_MAX_MAD_Z_SCORE,
};
use crate::error::MuObserveError;
use crate::sql_guard::{execute_guarded_sql, DEFAULT_SQL_MAX_ROWS, DEFAULT_SQL_TIMEOUT_MS};
use crate::storage::hot_duckdb::HotDuckDbStore;

/// Canonical names of the 10 Antigravity MCP tools exposed by `MuObserve`.
pub const MCP_TOOL_NAMES: &[&str] = &[
    "check_benchmark_regressions",
    "get_test_flakiness",
    "compare_branches",
    "query_trace_waterfall",
    "correlate_logs_by_trace_id",
    "search_error_anomalies",
    "assert_service_slo",
    "inspect_node_utilization",
    "compare_cluster_efficiency",
    "execute_analytics_sql",
    "analyze_causal_root_cause",
    "diagnose_anomaly_ai",
];

/// JSON-RPC 2.0 request envelope for MCP (`initialize`, `tools/list`, `tools/call`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    #[serde(default)]
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

/// JSON-RPC 2.0 response envelope for MCP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

/// JSON-RPC 2.0 structured error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// Antigravity Model Context Protocol (MCP) server exposing all 10 observability, regression,
/// and SpacemiT K3 cluster efficiency tools over `stdio` and HTTP/SSE.
#[derive(Clone)]
pub struct McpServer {
    store: HotDuckDbStore,
}

fn block_on_future<F: std::future::Future>(future: F) -> F::Output {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        tokio::task::block_in_place(|| handle.block_on(future))
    } else {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to build tokio runtime")
            .block_on(future)
    }
}

impl McpServer {
    /// Creates a new [`McpServer`] backed by `store`.
    #[must_use]
    pub fn new(store: HotDuckDbStore) -> Self {
        Self { store }
    }

    /// Returns the JSON schema definitions for all 10 MCP tools (`tools/list`).
    #[must_use]
    pub fn tool_definitions() -> Value {
        json!({
            "tools": [
                {
                    "name": "check_benchmark_regressions",
                    "description": "Evaluate candidate benchmark runs against rolling main baselines stratified by (arch, cpu_cluster, vlen_bits).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "repo_key": { "type": "string" },
                            "candidate_commit": { "type": "string" },
                            "baseline_branch": { "type": "string", "default": "main" },
                            "max_slowdown_pct": { "type": "number", "default": 5.0 },
                            "max_flakiness_pct": { "type": "number", "default": 2.0 }
                        },
                        "required": ["repo_key", "candidate_commit"]
                    }
                },
                {
                    "name": "get_test_flakiness",
                    "description": "Compute rolling 30-day test pass/fail flip-flop flakiness index for a repository.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "repo_key": { "type": "string" },
                            "candidate_commit": { "type": "string" },
                            "window_days": { "type": "integer", "default": 30 }
                        },
                        "required": ["repo_key"]
                    }
                },
                {
                    "name": "compare_branches",
                    "description": "Compare benchmark performance, test pass rates, and CI quality scores between two branches.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "repo_key": { "type": "string" },
                            "candidate_branch": { "type": "string" },
                            "baseline_branch": { "type": "string", "default": "main" },
                            "max_slowdown_pct": { "type": "number", "default": 5.0 }
                        },
                        "required": ["repo_key", "candidate_branch"]
                    }
                },
                {
                    "name": "query_trace_waterfall",
                    "description": "Retrieve the ordered parent-child W3C span waterfall and critical-path duration for a trace_id.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "trace_id": { "type": "string" }
                        },
                        "required": ["trace_id"]
                    }
                },
                {
                    "name": "correlate_logs_by_trace_id",
                    "description": "Retrieve all structured OpenTelemetry logs correlated with a W3C trace_id in chronological order.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "trace_id": { "type": "string" },
                            "min_severity": { "type": "integer", "default": 0 }
                        },
                        "required": ["trace_id"]
                    }
                },
                {
                    "name": "search_error_anomalies",
                    "description": "Search recent ERROR/FATAL logs and failed spans across services and nodes.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "service_name": { "type": "string" },
                            "node_id": { "type": "string" },
                            "limit": { "type": "integer", "default": 50 }
                        }
                    }
                },
                {
                    "name": "assert_service_slo",
                    "description": "Evaluate canary deployment SLO bounds (error logs, p99 span latency, crash telemetry) and taint recommendation.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "service_name": { "type": "string" },
                            "candidate_digest": { "type": "string", "default": "HEAD" },
                            "node_id": { "type": "string", "default": "" },
                            "bake_window_secs": { "type": "integer", "default": 300 },
                            "max_error_logs": { "type": "integer", "default": 0 },
                            "max_p99_latency_ms": { "type": "number", "default": 250.0 }
                        },
                        "required": ["service_name"]
                    }
                },
                {
                    "name": "inspect_node_utilization",
                    "description": "Inspect hardware metric telemetry, CPU cluster tags, VLEN width, and RLIMIT_MEMLOCK usage for a node.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "node_id": { "type": "string" },
                            "limit": { "type": "integer", "default": 50 }
                        },
                        "required": ["node_id"]
                    }
                },
                {
                    "name": "compare_cluster_efficiency",
                    "description": "Compare SpacemiT K3 Cluster 0 (X100, VLEN=256) vs Cluster 1 (A100, VLEN=1024) vs x86_64 execution efficiency.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "repo_key": { "type": "string" },
                            "bench_name": { "type": "string" }
                        }
                    }
                },
                {
                    "name": "execute_analytics_sql",
                    "description": "Execute a guarded read-only DuckDB analytical query (SELECT/WITH/EXPLAIN only, 5s timeout, 1000 row limit).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "sql": { "type": "string" },
                            "max_rows": { "type": "integer", "default": 1000 }
                        },
                        "required": ["sql"]
                    }
                },
                {
                    "name": "analyze_causal_root_cause",
                    "description": "Analyze causal root cause of latency and error anomalies across distributed traces and logs.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "window_secs": { "type": "integer", "default": 300 },
                            "service_name": { "type": "string" }
                        }
                    }
                },
                {
                    "name": "diagnose_anomaly_ai",
                    "description": "Generate AI-powered root-cause diagnosis for an anomaly trace using statistical inference or SLM synthesis.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "trace_id": { "type": "string" },
                            "service_name": { "type": "string" }
                        },
                        "required": ["trace_id"]
                    }
                }
            ]
        })
    }

    /// Handles a single JSON-RPC 2.0 request and returns a [`JsonRpcResponse`].
    pub fn handle_request(&self, req: &JsonRpcRequest) -> JsonRpcResponse {
        match req.method.as_str() {
            "initialize" => JsonRpcResponse {
                jsonrpc: "2.0".into(),
                id: req.id.clone(),
                result: Some(json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": { "tools": {} },
                    "serverInfo": {
                        "name": "mu-observable-mcp",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                })),
                error: None,
            },
            "tools/list" => JsonRpcResponse {
                jsonrpc: "2.0".into(),
                id: req.id.clone(),
                result: Some(Self::tool_definitions()),
                error: None,
            },
            "tools/call" => {
                let tool_name = req
                    .params
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let args = req
                    .params
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));

                match self.call_tool(tool_name, &args) {
                    Ok(payload) => JsonRpcResponse {
                        jsonrpc: "2.0".into(),
                        id: req.id.clone(),
                        result: Some(json!({
                            "content": [
                                {
                                    "type": "text",
                                    "text": serde_json::to_string(&payload).unwrap_or_default()
                                }
                            ],
                            "structuredContent": payload,
                            "isError": false
                        })),
                        error: None,
                    },
                    Err(err) => JsonRpcResponse {
                        jsonrpc: "2.0".into(),
                        id: req.id.clone(),
                        result: None,
                        error: Some(JsonRpcError {
                            code: -32602,
                            message: err.to_string(),
                            data: None,
                        }),
                    },
                }
            }
            other => JsonRpcResponse {
                jsonrpc: "2.0".into(),
                id: req.id.clone(),
                result: None,
                error: Some(JsonRpcError {
                    code: -32601,
                    message: format!("Method not found: {other}"),
                    data: None,
                }),
            },
        }
    }

    /// Invokes one of the 10 MCP tools directly by name and JSON arguments.
    pub fn call_tool(&self, name: &str, args: &Value) -> Result<Value, MuObserveError> {
        match name {
            "check_benchmark_regressions" => {
                let repo_key = required_str(args, "repo_key")?;
                let candidate_commit = required_str(args, "candidate_commit")?;
                let baseline_branch =
                    opt_str(args, "baseline_branch").unwrap_or_else(|| "main".into());
                let max_slowdown_pct = args
                    .get("max_slowdown_pct")
                    .and_then(Value::as_f64)
                    .unwrap_or(5.0);
                let max_flakiness_pct = args
                    .get("max_flakiness_pct")
                    .and_then(Value::as_f64)
                    .unwrap_or(2.0);

                let gate_req = RegressionGateRequest {
                    request_id: "mcp-check-bench".into(),
                    repo_key: repo_key.clone(),
                    candidate_commit: candidate_commit.clone(),
                    baseline_branch: baseline_branch.clone(),
                    max_slowdown_pct,
                    max_flakiness_pct,
                };
                let report = evaluate_regression_gate(&self.store, &gate_req)?;
                let all_items = evaluate_benchmark_regressions(
                    &self.store,
                    &repo_key,
                    &candidate_commit,
                    &baseline_branch,
                    max_slowdown_pct,
                    DEFAULT_MAX_MAD_Z_SCORE,
                )?;
                Ok(json!({
                    "report": report,
                    "evaluated_benchmarks": all_items
                }))
            }
            "get_test_flakiness" => {
                let repo_key = required_str(args, "repo_key")?;
                let candidate_commit = opt_str(args, "candidate_commit");
                let window_days = args
                    .get("window_days")
                    .and_then(Value::as_u64)
                    .unwrap_or(30) as u32;
                let items = compute_test_flakiness(
                    &self.store,
                    &repo_key,
                    candidate_commit.as_deref(),
                    window_days,
                    None,
                )?;
                Ok(json!({
                    "repo_key": repo_key,
                    "window_days": window_days,
                    "tests": items
                }))
            }
            "compare_branches" => {
                let repo_key = required_str(args, "repo_key")?;
                let candidate_branch = required_str(args, "candidate_branch")?;
                let baseline_branch =
                    opt_str(args, "baseline_branch").unwrap_or_else(|| "main".into());
                let max_slowdown_pct = args
                    .get("max_slowdown_pct")
                    .and_then(Value::as_f64)
                    .unwrap_or(5.0);

                let benches = evaluate_benchmark_regressions(
                    &self.store,
                    &repo_key,
                    &candidate_branch,
                    &baseline_branch,
                    max_slowdown_pct,
                    DEFAULT_MAX_MAD_Z_SCORE,
                )?;
                Ok(json!({
                    "repo_key": repo_key,
                    "candidate_branch": candidate_branch,
                    "baseline_branch": baseline_branch,
                    "benchmark_comparisons": benches
                }))
            }
            "query_trace_waterfall" => {
                let trace_id = required_str(args, "trace_id")?;
                let conn = self.store.lock_conn()?;
                let mut stmt = conn.prepare(
                    r#"
                    SELECT
                        span_id, parent_span_id, service_name, node_id, span_name,
                        span_kind, start_time_unix_nano, end_time_unix_nano, duration_ns,
                        status_code, status_message, attributes_json
                    FROM v_traces
                    WHERE trace_id = ?1
                    ORDER BY start_time_unix_nano ASC
                    "#,
                )?;
                let rows = stmt.query_map(params![trace_id], |r| {
                    Ok(json!({
                        "span_id": r.get::<_, String>(0)?,
                        "parent_span_id": r.get::<_, Option<String>>(1)?,
                        "service_name": r.get::<_, String>(2)?,
                        "node_id": r.get::<_, String>(3)?,
                        "span_name": r.get::<_, String>(4)?,
                        "span_kind": r.get::<_, String>(5)?,
                        "start_time_unix_nano": r.get::<_, i64>(6)?,
                        "end_time_unix_nano": r.get::<_, i64>(7)?,
                        "duration_ns": r.get::<_, i64>(8)?,
                        "status_code": r.get::<_, String>(9)?,
                        "status_message": r.get::<_, Option<String>>(10)?,
                        "attributes_json": r.get::<_, String>(11)?,
                    }))
                })?;
                let mut spans = Vec::new();
                for s in rows {
                    spans.push(s?);
                }
                Ok(json!({
                    "trace_id": trace_id,
                    "span_count": spans.len(),
                    "spans": spans
                }))
            }
            "correlate_logs_by_trace_id" => {
                let trace_id = required_str(args, "trace_id")?;
                let min_sev = args
                    .get("min_severity")
                    .and_then(Value::as_i64)
                    .unwrap_or(0) as i32;
                let conn = self.store.lock_conn()?;
                let mut stmt = conn.prepare(
                    r#"
                    SELECT
                        timestamp_unix_nano, span_id, severity_number, severity_text,
                        service_name, node_id, body, attributes_json, job_id, stage_id
                    FROM v_logs
                    WHERE trace_id = ?1
                      AND severity_number >= ?2
                    ORDER BY timestamp_unix_nano ASC
                    "#,
                )?;
                let rows = stmt.query_map(params![trace_id, min_sev], |r| {
                    Ok(json!({
                        "timestamp_unix_nano": r.get::<_, i64>(0)?,
                        "span_id": r.get::<_, String>(1)?,
                        "severity_number": r.get::<_, i32>(2)?,
                        "severity_text": r.get::<_, String>(3)?,
                        "service_name": r.get::<_, String>(4)?,
                        "node_id": r.get::<_, String>(5)?,
                        "body": r.get::<_, String>(6)?,
                        "attributes_json": r.get::<_, String>(7)?,
                        "job_id": r.get::<_, Option<String>>(8)?,
                        "stage_id": r.get::<_, Option<String>>(9)?,
                    }))
                })?;
                let mut logs = Vec::new();
                for l in rows {
                    logs.push(l?);
                }
                Ok(json!({
                    "trace_id": trace_id,
                    "log_count": logs.len(),
                    "logs": logs
                }))
            }
            "search_error_anomalies" => {
                let service_name = opt_str(args, "service_name");
                let node_id = opt_str(args, "node_id");
                let limit = args
                    .get("limit")
                    .and_then(Value::as_i64)
                    .unwrap_or(50)
                    .clamp(1, 500);
                let conn = self.store.lock_conn()?;
                let mut stmt = conn.prepare(
                    r#"
                    SELECT
                        timestamp_unix_nano, trace_id, span_id, severity_number,
                        severity_text, service_name, node_id, body
                    FROM v_logs
                    WHERE (?1 IS NULL OR service_name = ?1)
                      AND (?2 IS NULL OR node_id = ?2)
                      AND (severity_number >= 17 OR UPPER(severity_text) IN ('ERROR', 'FATAL', 'CRITICAL'))
                    ORDER BY timestamp_unix_nano DESC
                    LIMIT ?3
                    "#,
                )?;
                let rows = stmt.query_map(params![service_name, node_id, limit], |r| {
                    Ok(json!({
                        "timestamp_unix_nano": r.get::<_, i64>(0)?,
                        "trace_id": r.get::<_, String>(1)?,
                        "span_id": r.get::<_, String>(2)?,
                        "severity_number": r.get::<_, i32>(3)?,
                        "severity_text": r.get::<_, String>(4)?,
                        "service_name": r.get::<_, String>(5)?,
                        "node_id": r.get::<_, String>(6)?,
                        "body": r.get::<_, String>(7)?,
                    }))
                })?;
                let mut anomalies = Vec::new();
                for a in rows {
                    anomalies.push(a?);
                }
                Ok(json!({
                    "anomaly_count": anomalies.len(),
                    "anomalies": anomalies
                }))
            }
            "assert_service_slo" => {
                let service_name = required_str(args, "service_name")?;
                let candidate_digest =
                    opt_str(args, "candidate_digest").unwrap_or_else(|| "HEAD".into());
                let node_id = opt_str(args, "node_id").unwrap_or_default();
                let bake_window_secs = args
                    .get("bake_window_secs")
                    .and_then(Value::as_u64)
                    .unwrap_or(300);
                let max_error_logs = args
                    .get("max_error_logs")
                    .and_then(Value::as_u64)
                    .unwrap_or(0) as u32;
                let max_p99_latency_ms = args
                    .get("max_p99_latency_ms")
                    .and_then(Value::as_f64)
                    .unwrap_or(250.0);

                let req = CanarySloAssertionRequest {
                    request_id: "mcp-slo".into(),
                    service_name,
                    candidate_digest,
                    node_id,
                    bake_window_secs,
                    max_error_logs,
                    max_p99_latency_ms,
                };
                let resp = evaluate_canary_slo(&self.store, &req, None)?;
                Ok(serde_json::to_value(resp)?)
            }
            "inspect_node_utilization" => {
                let node_id = required_str(args, "node_id")?;
                let limit = args
                    .get("limit")
                    .and_then(Value::as_i64)
                    .unwrap_or(50)
                    .clamp(1, 500);
                let conn = self.store.lock_conn()?;
                let mut stmt = conn.prepare(
                    r#"
                    SELECT
                        timestamp_unix_nano, service_name, metric_name, metric_unit,
                        value_f64, arch, cpu_cluster, vlen_bits, memlock_used_bytes, memlock_limit_bytes
                    FROM v_metrics
                    WHERE node_id = ?1
                    ORDER BY timestamp_unix_nano DESC
                    LIMIT ?2
                    "#,
                )?;
                let rows = stmt.query_map(params![node_id, limit], |r| {
                    Ok(json!({
                        "timestamp_unix_nano": r.get::<_, i64>(0)?,
                        "service_name": r.get::<_, String>(1)?,
                        "metric_name": r.get::<_, String>(2)?,
                        "metric_unit": r.get::<_, String>(3)?,
                        "value_f64": r.get::<_, f64>(4)?,
                        "arch": r.get::<_, String>(5)?,
                        "cpu_cluster": r.get::<_, Option<String>>(6)?,
                        "vlen_bits": r.get::<_, Option<i32>>(7)?,
                        "memlock_used_bytes": r.get::<_, Option<i64>>(8)?,
                        "memlock_limit_bytes": r.get::<_, Option<i64>>(9)?,
                    }))
                })?;
                let mut samples = Vec::new();
                for s in rows {
                    samples.push(s?);
                }
                Ok(json!({
                    "node_id": node_id,
                    "sample_count": samples.len(),
                    "metrics": samples
                }))
            }
            "compare_cluster_efficiency" => {
                let repo_key = opt_str(args, "repo_key");
                let bench_name = opt_str(args, "bench_name");
                let conn = self.store.lock_conn()?;
                let mut stmt = conn.prepare(
                    r#"
                    SELECT
                        arch,
                        cpu_cluster,
                        vlen_bits,
                        COUNT(*) AS run_count,
                        AVG(ns_per_iter) AS avg_ns_per_iter,
                        MIN(ns_per_iter) AS min_ns_per_iter,
                        MAX(ns_per_iter) AS max_ns_per_iter
                    FROM v_benchmarks
                    WHERE (?1 IS NULL OR repo_key = ?1)
                      AND (?2 IS NULL OR bench_name = ?2)
                    GROUP BY arch, cpu_cluster, vlen_bits
                    ORDER BY avg_ns_per_iter ASC
                    "#,
                )?;
                let rows = stmt.query_map(params![repo_key, bench_name], |r| {
                    Ok(json!({
                        "arch": r.get::<_, String>(0)?,
                        "cpu_cluster": r.get::<_, String>(1)?,
                        "vlen_bits": r.get::<_, i32>(2)?,
                        "run_count": r.get::<_, i64>(3)?,
                        "avg_ns_per_iter": r.get::<_, f64>(4)?,
                        "min_ns_per_iter": r.get::<_, f64>(5)?,
                        "max_ns_per_iter": r.get::<_, f64>(6)?,
                    }))
                })?;
                let mut clusters = Vec::new();
                for c in rows {
                    clusters.push(c?);
                }
                Ok(json!({
                    "clusters": clusters
                }))
            }
            "execute_analytics_sql" => {
                let sql = required_str(args, "sql")?;
                let max_rows = args
                    .get("max_rows")
                    .and_then(Value::as_u64)
                    .map_or(DEFAULT_SQL_MAX_ROWS, |v| v as usize);
                let res = execute_guarded_sql(
                    &self.store,
                    &sql,
                    max_rows,
                    Duration::from_millis(DEFAULT_SQL_TIMEOUT_MS),
                )?;
                Ok(serde_json::to_value(res)?)
            }
            "analyze_causal_root_cause" => {
                let window_secs = args
                    .get("window_secs")
                    .and_then(Value::as_u64)
                    .unwrap_or(300);
                let service_filter = opt_str(args, "service_name");
                let mut problems = crate::analytics::causal::compute_causal_problems(
                    &self.store,
                    window_secs,
                    None,
                )?;
                if let Some(svc) = service_filter {
                    problems.retain(|p| {
                        p.impacted_entity == svc
                            || p.root_cause_service == svc
                            || p.affected_services.contains(&svc)
                    });
                }
                Ok(json!({
                    "problem_count": problems.len(),
                    "problems": problems
                }))
            }
            "diagnose_anomaly_ai" => {
                let trace_id = required_str(args, "trace_id")?;
                let service_name =
                    opt_str(args, "service_name").unwrap_or_else(|| "unknown".into());
                let problems =
                    crate::analytics::causal::compute_causal_problems(&self.store, 300, None)?;
                if let Some(card) = problems
                    .into_iter()
                    .find(|p| p.root_cause_trace_id.as_deref() == Some(&trace_id))
                {
                    let ai_diag =
                        block_on_future(crate::analytics::causal::synthesize_ai_diagnosis(
                            &card.impacted_entity,
                            &card.root_cause_service,
                            &card.causal_chain,
                            card.root_cause_error_message.as_deref(),
                            &card.slo_metric,
                            card.confidence_score,
                        ));
                    Ok(json!({
                        "trace_id": trace_id,
                        "problem_id": card.problem_id,
                        "impacted_entity": card.impacted_entity,
                        "root_cause_service": card.root_cause_service,
                        "causal_chain": card.causal_chain,
                        "confidence_score": card.confidence_score,
                        "ai_diagnosis": ai_diag,
                        "summary": card.summary,
                    }))
                } else {
                    let fallback_chain = vec![service_name.clone()];
                    let ai_diag =
                        block_on_future(crate::analytics::causal::synthesize_ai_diagnosis(
                            &service_name,
                            &service_name,
                            &fallback_chain,
                            None,
                            "trace_inspection",
                            0.70,
                        ));
                    Ok(json!({
                        "trace_id": trace_id,
                        "impacted_entity": service_name.clone(),
                        "root_cause_service": service_name,
                        "ai_diagnosis": ai_diag,
                    }))
                }
            }
            other => Err(MuObserveError::Validation(format!(
                "Unknown MCP tool: {other}"
            ))),
        }
    }

    /// Runs the line-delimited JSON-RPC 2.0 MCP loop over `reader` (`stdin`) and `writer` (`stdout`).
    pub fn serve_stdio<R: BufRead, W: Write>(
        &self,
        mut reader: R,
        mut writer: W,
    ) -> Result<(), MuObserveError> {
        let mut line = String::new();
        loop {
            line.clear();
            let bytes = reader.read_line(&mut line)?;
            if bytes == 0 {
                break;
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let resp = match serde_json::from_str::<JsonRpcRequest>(trimmed) {
                Ok(req) => self.handle_request(&req),
                Err(e) => JsonRpcResponse {
                    jsonrpc: "2.0".into(),
                    id: None,
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32700,
                        message: format!("Parse error: {e}"),
                        data: None,
                    }),
                },
            };
            let serialized = serde_json::to_string(&resp)?;
            writeln!(writer, "{serialized}")?;
            writer.flush()?;
        }
        Ok(())
    }

    /// Builds an Axum HTTP/SSE router exposing `POST /mcp` (JSON-RPC), `GET /mcp/sse` (SSE endpoint discovery),
    /// and the read-only M6 observability console API (`/api/v1/*`, `/api/v1/console/*`, `/api/observe/*`).
    pub fn router(self) -> Router {
        let store = self.store.clone();
        Router::new()
            .route("/mcp", post(http_mcp_post_handler))
            .route("/mcp/sse", get(http_mcp_sse_handler))
            .with_state(self)
            .merge(crate::server::build_console_api_router(store))
    }
}

async fn http_mcp_post_handler(
    State(server): State<McpServer>,
    Json(req): Json<JsonRpcRequest>,
) -> Json<JsonRpcResponse> {
    Json(server.handle_request(&req))
}

async fn http_mcp_sse_handler() -> Response {
    let body = "event: endpoint\ndata: /mcp\n\n";
    (
        StatusCode::OK,
        [
            ("content-type", "text/event-stream"),
            ("cache-control", "no-cache"),
        ],
        body,
    )
        .into_response()
}

fn required_str(args: &Value, key: &str) -> Result<String, MuObserveError> {
    args.get(key)
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| {
            MuObserveError::Validation(format!("Missing required string argument '{key}'"))
        })
}

fn opt_str(args: &Value, key: &str) -> Option<String> {
    args.get(key)
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mu_observable_ipc::{
        BenchmarkRunEntry, OtelLogEntry, OtelMetricEntry, OtelSpanEntry, TestCaseRunEntry,
    };

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_all_10_mcp_tools_and_ddl_dml_sql_rejection() {
        let store = HotDuckDbStore::open_in_memory().expect("open in memory");
        let now_ts = 1_700_000_000_000_000_000i64;

        store
            .insert_logs_batch(&[OtelLogEntry {
                timestamp_unix_nano: now_ts,
                trace_id: "trace-abc".into(),
                span_id: "span-1".into(),
                severity_number: 17,
                severity_text: "ERROR".into(),
                service_name: "k3-manager".into(),
                node_id: "worker-riscv64".into(),
                body: "inference queue timeout".into(),
                attributes_json: "{}".into(),
                job_id: Some("job-1".into()),
                stage_id: None,
            }])
            .unwrap();

        store
            .insert_spans_batch(&[OtelSpanEntry {
                trace_id: "trace-abc".into(),
                span_id: "span-1".into(),
                parent_span_id: None,
                service_name: "k3-manager".into(),
                node_id: "worker-riscv64".into(),
                span_name: "k3.decode".into(),
                span_kind: "INTERNAL".into(),
                start_time_unix_nano: now_ts - 10_000_000,
                end_time_unix_nano: now_ts,
                duration_ns: 10_000_000,
                status_code: "OK".into(),
                status_message: None,
                attributes_json: "{}".into(),
            }])
            .unwrap();

        store
            .insert_metrics_batch(&[OtelMetricEntry {
                timestamp_unix_nano: now_ts,
                service_name: "k3-manager".into(),
                node_id: "worker-riscv64".into(),
                metric_name: "k3.decode.tok_s".into(),
                metric_unit: "tok/s".into(),
                value_f64: 50.0,
                arch: "riscv64gc".into(),
                cpu_cluster: Some("A100".into()),
                vlen_bits: Some(1024),
                memlock_used_bytes: Some(2048),
                memlock_limit_bytes: Some(4096),
                trace_id: Some("trace-abc".into()),
                span_id: Some("span-1".into()),
                attributes_json: "{}".into(),
            }])
            .unwrap();

        store
            .insert_test_runs_batch(&[TestCaseRunEntry {
                job_id: "job-1".into(),
                repo_key: "lma1980/k3-core".into(),
                branch_key: "main".into(),
                commit_sha: "sha-1".into(),
                crate_name: "k3-core".into(),
                test_binary: "k3_core".into(),
                test_name: "test_alloc".into(),
                status: "ok".into(),
                duration_ms: 1.1,
                failure_summary: None,
                timestamp_unix_nano: now_ts,
                node_id: "worker-riscv64".into(),
                arch: "riscv64gc".into(),
            }])
            .unwrap();

        store
            .insert_benchmark_runs_batch(&[
                BenchmarkRunEntry {
                    job_id: "job-base".into(),
                    repo_key: "lma1980/k3-core".into(),
                    branch_key: "main".into(),
                    commit_sha: "sha-base".into(),
                    crate_name: "k3-core".into(),
                    bench_name: "bench_dot".into(),
                    ns_per_iter: 1000.0,
                    std_dev_ns: 10.0,
                    mad_ns: 8.0,
                    p50_ns: 1000.0,
                    p95_ns: 1015.0,
                    p99_ns: 1020.0,
                    throughput_value: None,
                    throughput_unit: None,
                    arch: "riscv64gc".into(),
                    cpu_cluster: "A100".into(),
                    vlen_bits: 1024,
                    timestamp_unix_nano: now_ts - 1_000_000,
                    node_id: "worker-riscv64".into(),
                },
                BenchmarkRunEntry {
                    job_id: "job-cand".into(),
                    repo_key: "lma1980/k3-core".into(),
                    branch_key: "feat/fast".into(),
                    commit_sha: "sha-cand".into(),
                    crate_name: "k3-core".into(),
                    bench_name: "bench_dot".into(),
                    ns_per_iter: 1005.0,
                    std_dev_ns: 10.0,
                    mad_ns: 8.0,
                    p50_ns: 1005.0,
                    p95_ns: 1020.0,
                    p99_ns: 1025.0,
                    throughput_value: None,
                    throughput_unit: None,
                    arch: "riscv64gc".into(),
                    cpu_cluster: "A100".into(),
                    vlen_bits: 1024,
                    timestamp_unix_nano: now_ts,
                    node_id: "worker-riscv64".into(),
                },
            ])
            .unwrap();

        let mcp = McpServer::new(store);

        // Verify tools/list returns all 10 tools
        let list_resp = mcp.handle_request(&JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(json!(1)),
            method: "tools/list".into(),
            params: json!({}),
        });
        let tools_arr = list_resp
            .result
            .unwrap()
            .get("tools")
            .unwrap()
            .as_array()
            .unwrap()
            .clone();
        assert_eq!(tools_arr.len(), MCP_TOOL_NAMES.len());
        for expected_name in MCP_TOOL_NAMES {
            assert!(
                tools_arr
                    .iter()
                    .any(|t| t.get("name").and_then(Value::as_str) == Some(*expected_name)),
                "Missing MCP tool {expected_name}"
            );
        }

        // Call each of the MCP tools
        assert!(mcp
            .call_tool("analyze_causal_root_cause", &json!({"window_secs": 300}))
            .is_ok());
        assert!(mcp
            .call_tool(
                "diagnose_anomaly_ai",
                &json!({"trace_id": "test-trace-id", "service_name": "checkout"})
            )
            .is_ok());
        assert!(mcp
            .call_tool(
                "check_benchmark_regressions",
                &json!({"repo_key": "lma1980/k3-core", "candidate_commit": "sha-cand"})
            )
            .is_ok());
        assert!(mcp
            .call_tool(
                "get_test_flakiness",
                &json!({"repo_key": "lma1980/k3-core"})
            )
            .is_ok());
        assert!(mcp
            .call_tool(
                "compare_branches",
                &json!({"repo_key": "lma1980/k3-core", "candidate_branch": "feat/fast"})
            )
            .is_ok());
        assert!(mcp
            .call_tool("query_trace_waterfall", &json!({"trace_id": "trace-abc"}))
            .is_ok());
        assert!(mcp
            .call_tool(
                "correlate_logs_by_trace_id",
                &json!({"trace_id": "trace-abc"})
            )
            .is_ok());
        assert!(mcp
            .call_tool(
                "search_error_anomalies",
                &json!({"service_name": "k3-manager"})
            )
            .is_ok());
        assert!(mcp
            .call_tool(
                "assert_service_slo",
                &json!({"service_name": "k3-manager", "max_error_logs": 5})
            )
            .is_ok());
        assert!(mcp
            .call_tool(
                "inspect_node_utilization",
                &json!({"node_id": "worker-riscv64"})
            )
            .is_ok());
        assert!(mcp
            .call_tool(
                "compare_cluster_efficiency",
                &json!({"repo_key": "lma1980/k3-core"})
            )
            .is_ok());
        assert!(mcp
            .call_tool(
                "execute_analytics_sql",
                &json!({"sql": "SELECT COUNT(*) AS cnt FROM v_logs"})
            )
            .is_ok());

        // Verify DDL/DML SQL is rejected via MCP tools/call
        let bad_sql_resp = mcp.handle_request(&JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(json!(99)),
            method: "tools/call".into(),
            params: json!({
                "name": "execute_analytics_sql",
                "arguments": { "sql": "DROP TABLE otel_logs" }
            }),
        });
        assert!(bad_sql_resp.error.is_some());
    }
}
