use std::path::Path;

use axum::{
    extract::{Path as AxumPath, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use duckdb::params;
use mu_observable_ipc::{QueryJobsHistoryRequest, QuerySubmoduleSnapshotsRequest};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::analytics::purepath::{
    compute_purepath_waterfall, list_trace_summaries, TraceListFilter, TraceListQuery,
};
use crate::analytics::smartscape::{
    compute_smartscape_topology, evaluate_deterministic_problems, DEFAULT_SMARTSCAPE_WINDOW_SECS,
};
use crate::error::MuObserveError;
use crate::server::sanitize::PrivacyRedactor;
use crate::storage::hot_duckdb::HotDuckDbStore;
use crate::DEFAULT_HOT_RETENTION_DAYS;

/// Sanitized log row returned by `GET /api/v1/logs` (`M6.4`, `#44`–`#45`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConsoleLogItem {
    pub timestamp_unix_nano: i64,
    pub timestamp_ms: i64,
    pub trace_id: String,
    pub span_id: String,
    pub severity_number: i32,
    pub severity_text: String,
    pub service: String,
    pub service_name: String,
    pub node_id: String,
    pub body: String,
    pub attributes: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage_id: Option<String>,
}

/// Paginated response for `GET /api/v1/logs`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LogsQueryResponse {
    pub severity: String,
    pub total: usize,
    pub logs: Vec<ConsoleLogItem>,
}

/// Single metric timeseries sample with optional W3C exemplar linkage (`M6.4`, `#44`, `#46`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricTimeseriesPoint {
    pub timestamp_unix_nano: i64,
    pub timestamp_ms: i64,
    pub service: String,
    pub service_name: String,
    pub node_id: String,
    pub metric_name: String,
    pub metric_unit: String,
    pub value_f64: f64,
    pub arch: String,
    pub cpu_cluster: Option<String>,
    pub vlen_bits: Option<u32>,
    pub memlock_used_bytes: Option<u64>,
    pub memlock_limit_bytes: Option<u64>,
    pub exemplar_trace_id: Option<String>,
    pub exemplar_span_id: Option<String>,
    pub attributes: Value,
}

/// Hardware cluster efficiency comparison row (`X100` vs `A100` vs `x86_64`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClusterEfficiencyItem {
    pub arch: String,
    pub cpu_cluster: String,
    pub vlen_bits: u32,
    pub run_count: u64,
    pub avg_ns_per_iter: f64,
    pub min_ns_per_iter: f64,
    pub max_ns_per_iter: f64,
}

/// Response payload for `GET /api/v1/metrics/timeseries` and `GET /api/observe/metrics`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricsTimeseriesResponse {
    pub metric: String,
    pub window: String,
    pub window_secs: u64,
    pub total: usize,
    pub series: Vec<MetricTimeseriesPoint>,
    pub cluster_efficiency: Vec<ClusterEfficiencyItem>,
}

/// Sanitized hybrid DuckDB + cold Zstd Parquet storage health summary (`M6.4`, `#47`–`#49`).
/// Strictly omits any host filesystem paths or raw SQL queries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoreStatusResponse {
    pub total_spans: u64,
    pub total_logs: u64,
    pub total_metric_points: u64,
    pub total_test_runs: u64,
    pub total_benchmark_runs: u64,
    pub hot_spans: u64,
    pub hot_logs: u64,
    pub hot_metric_points: u64,
    pub cold_spans: u64,
    pub cold_logs: u64,
    pub cold_metric_points: u64,
    pub parquet_segments: u64,
    pub storage_bytes: u64,
    pub hot_duckdb_bytes: u64,
    pub cold_parquet_bytes: u64,
    pub compression_codec: String,
    pub estimated_compression_ratio: f64,
    pub retention_days: u32,
    pub cold_ttl_days: u32,
    pub healthy: bool,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct SmartscapeQueryParams {
    window_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct TraceListQueryParams {
    filter: Option<String>,
    service: Option<String>,
    status: Option<String>,
    job_id: Option<String>,
    digest: Option<String>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct LogsQueryParams {
    severity: Option<String>,
    service: Option<String>,
    trace_id: Option<String>,
    job_id: Option<String>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct MetricsQueryParams {
    metric: Option<String>,
    window: Option<String>,
    cluster: Option<String>,
    limit: Option<usize>,
}

/// Builds the read-only observability Axum [`Router`] mounting `/api/v1/*`, `/api/v1/console/*`,
/// `/api/observe/*`, and `/api/*` endpoints with `Cache-Control: no-store`.
pub fn build_console_api_router(store: HotDuckDbStore) -> Router {
    Router::new()
        // Smartscape topology
        .route("/api/v1/smartscape", get(handle_get_smartscape))
        .route("/api/v1/console/smartscape", get(handle_get_smartscape))
        .route("/api/observe/smartscape", get(handle_get_smartscape))
        .route("/api/smartscape", get(handle_get_smartscape))
        // Deterministic SLO problems & SSE feed
        .route("/api/v1/problems", get(handle_get_problems))
        .route("/api/v1/console/problems", get(handle_get_problems))
        .route("/api/observe/problems", get(handle_get_problems))
        .route("/api/problems", get(handle_get_problems))
        .route("/api/v1/events", get(handle_get_problem_events_sse))
        .route("/api/observe/events", get(handle_get_problem_events_sse))
        .route("/api/events", get(handle_get_problem_events_sse))
        // PurePath traces list & waterfall
        .route("/api/v1/traces", get(handle_get_traces))
        .route("/api/v1/console/traces", get(handle_get_traces))
        .route("/api/observe/traces", get(handle_get_traces))
        .route("/api/traces", get(handle_get_traces))
        .route("/api/v1/traces/{trace_id}", get(handle_get_trace_purepath))
        .route(
            "/api/v1/traces/{trace_id}/purepath",
            get(handle_get_trace_purepath),
        )
        .route(
            "/api/v1/console/traces/{trace_id}",
            get(handle_get_trace_purepath),
        )
        .route(
            "/api/v1/console/traces/{trace_id}/purepath",
            get(handle_get_trace_purepath),
        )
        .route(
            "/api/observe/traces/{trace_id}",
            get(handle_get_trace_purepath),
        )
        .route(
            "/api/observe/traces/{trace_id}/purepath",
            get(handle_get_trace_purepath),
        )
        .route("/api/traces/{trace_id}", get(handle_get_trace_purepath))
        .route(
            "/api/traces/{trace_id}/purepath",
            get(handle_get_trace_purepath),
        )
        // Fixed-filter structured logs & CI job log stream
        .route("/api/v1/logs", get(handle_get_logs))
        .route("/api/v1/console/logs", get(handle_get_logs))
        .route("/api/observe/logs", get(handle_get_logs))
        .route("/api/logs", get(handle_get_logs))
        // Sanitized per-job CI build log endpoint for anonymous/public access
        .route("/api/v1/jobs/{job_id}/log", get(handle_get_job_log))
        .route("/api/v1/jobs/{job_id}/logs", get(handle_get_job_log))
        .route("/api/v1/console/jobs/{job_id}/log", get(handle_get_job_log))
        .route(
            "/api/v1/console/jobs/{job_id}/logs",
            get(handle_get_job_log),
        )
        .route("/api/observe/jobs/{job_id}/log", get(handle_get_job_log))
        .route("/api/observe/jobs/{job_id}/logs", get(handle_get_job_log))
        .route("/api/jobs/{job_id}/log", get(handle_get_job_log))
        .route("/api/jobs/{job_id}/logs", get(handle_get_job_log))
        // Fixed-filter metrics timeseries & cluster efficiency
        .route("/api/v1/metrics/timeseries", get(handle_get_metrics))
        .route("/api/v1/metrics", get(handle_get_metrics))
        .route("/api/v1/console/metrics", get(handle_get_metrics))
        .route(
            "/api/v1/console/metrics/timeseries",
            get(handle_get_metrics),
        )
        .route("/api/observe/metrics", get(handle_get_metrics))
        .route("/api/metrics", get(handle_get_metrics))
        .route("/api/metrics/timeseries", get(handle_get_metrics))
        // Sanitized storage health status
        .route("/api/v1/store/status", get(handle_get_store_status))
        .route("/api/v1/datastore", get(handle_get_store_status))
        .route("/api/v1/console/store/status", get(handle_get_store_status))
        .route("/api/v1/console/datastore", get(handle_get_store_status))
        .route("/api/observe/datastore", get(handle_get_store_status))
        .route("/api/observe/store/status", get(handle_get_store_status))
        .route("/api/store/status", get(handle_get_store_status))
        .route("/api/datastore", get(handle_get_store_status))
        .with_state(store)
}

async fn handle_get_smartscape(
    State(store): State<HotDuckDbStore>,
    q_res: Result<Query<SmartscapeQueryParams>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let Query(params) = match q_res {
        Ok(q) => q,
        Err(e) => return json_error_response(StatusCode::BAD_REQUEST, &e.to_string()),
    };
    let window_secs = match params.window_secs {
        Some(0) => {
            return json_error_response(
                StatusCode::BAD_REQUEST,
                "window_secs must be between 1 and 604800",
            )
        }
        Some(w) if w > 604_800 => {
            return json_error_response(
                StatusCode::BAD_REQUEST,
                "window_secs must not exceed 604800 (7 days)",
            )
        }
        Some(w) => w,
        None => DEFAULT_SMARTSCAPE_WINDOW_SECS,
    };

    match compute_smartscape_topology(&store, window_secs, None) {
        Ok(topo) => no_store_json(StatusCode::OK, &topo),
        Err(e) => json_error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

async fn handle_get_problems(
    State(store): State<HotDuckDbStore>,
    q_res: Result<Query<SmartscapeQueryParams>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let Query(params) = match q_res {
        Ok(q) => q,
        Err(e) => return json_error_response(StatusCode::BAD_REQUEST, &e.to_string()),
    };
    let window_secs = match params.window_secs {
        Some(0) | Some(604_801..) => {
            return json_error_response(
                StatusCode::BAD_REQUEST,
                "window_secs must be between 1 and 604800",
            )
        }
        Some(w) => w,
        None => DEFAULT_SMARTSCAPE_WINDOW_SECS,
    };

    match evaluate_deterministic_problems(&store, window_secs, None) {
        Ok(feed) => no_store_json(StatusCode::OK, &feed),
        Err(e) => json_error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

async fn handle_get_problem_events_sse(State(store): State<HotDuckDbStore>) -> Response {
    let feed = evaluate_deterministic_problems(&store, DEFAULT_SMARTSCAPE_WINDOW_SECS, None)
        .unwrap_or(crate::analytics::smartscape::ProblemsFeedResponse {
            window_secs: DEFAULT_SMARTSCAPE_WINDOW_SECS,
            open_count: 0,
            total: 0,
            problems: Vec::new(),
        });

    let mut body = String::new();
    for card in &feed.problems {
        if let Ok(json_line) = serde_json::to_string(card) {
            body.push_str("event: problem_opened\n");
            body.push_str("data: ");
            body.push_str(&json_line);
            body.push_str("\n\n");
        }
    }
    if body.is_empty() {
        body.push_str("event: heartbeat\ndata: {\"open_count\":0}\n\n");
    }

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/event-stream"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
        .into_response()
}

async fn handle_get_traces(
    State(store): State<HotDuckDbStore>,
    q_res: Result<Query<TraceListQueryParams>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let Query(params) = match q_res {
        Ok(q) => q,
        Err(e) => return json_error_response(StatusCode::BAD_REQUEST, &e.to_string()),
    };

    let filter = match params.filter.as_deref() {
        Some(raw) => match TraceListFilter::parse_param(raw) {
            Ok(f) => f,
            Err(e) => return json_error_response(StatusCode::BAD_REQUEST, &e.to_string()),
        },
        None => TraceListFilter::All,
    };

    if let Some(st) = params.status.as_deref() {
        if !matches!(
            st.trim().to_ascii_lowercase().as_str(),
            "all" | "ok" | "error" | "errors"
        ) {
            return json_error_response(
                StatusCode::BAD_REQUEST,
                "Invalid status filter; expected one of: all, ok, error",
            );
        }
    }

    for val in [&params.service, &params.job_id, &params.digest]
        .into_iter()
        .flatten()
    {
        if let Err(msg) = validate_safe_filter_token(val) {
            return json_error_response(StatusCode::BAD_REQUEST, msg);
        }
    }

    let limit = match params.limit {
        Some(0) | Some(101..) => {
            return json_error_response(StatusCode::BAD_REQUEST, "limit must be between 1 and 100")
        }
        Some(l) => l,
        None => 50,
    };

    let query = TraceListQuery {
        filter,
        service: params.service,
        status: params.status.map(|s| {
            if s.eq_ignore_ascii_case("errors") {
                "ERROR".to_string()
            } else {
                s
            }
        }),
        job_id: params.job_id,
        digest: params.digest,
        limit,
    };

    match list_trace_summaries(&store, &query) {
        Ok(resp) => no_store_json(StatusCode::OK, &resp),
        Err(e) => json_error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

async fn handle_get_trace_purepath(
    State(store): State<HotDuckDbStore>,
    AxumPath(trace_id): AxumPath<String>,
) -> Response {
    if let Err(msg) = validate_safe_filter_token(&trace_id) {
        return json_error_response(StatusCode::BAD_REQUEST, msg);
    }

    match compute_purepath_waterfall(&store, &trace_id) {
        Ok(Some(pp)) => no_store_json(StatusCode::OK, &pp),
        Ok(None) => json_error_response(
            StatusCode::NOT_FOUND,
            &format!("Trace '{trace_id}' not found"),
        ),
        Err(e) => json_error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

async fn handle_get_logs(
    State(store): State<HotDuckDbStore>,
    q_res: Result<Query<LogsQueryParams>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let Query(params) = match q_res {
        Ok(q) => q,
        Err(e) => return json_error_response(StatusCode::BAD_REQUEST, &e.to_string()),
    };

    let sev_raw = params.severity.as_deref().unwrap_or("all").trim();
    let sev_norm = sev_raw.to_ascii_lowercase();
    let min_sev_range: Option<(i32, i32, &str)> = match sev_norm.as_str() {
        "" | "all" => None,
        "error" | "errors" | "fatal" => Some((17, 24, "ERROR")),
        "warn" | "warning" => Some((13, 16, "WARN")),
        "info" => Some((9, 12, "INFO")),
        "debug" | "trace" => Some((1, 8, "DEBUG")),
        _ => {
            return json_error_response(
                StatusCode::BAD_REQUEST,
                "Invalid severity filter; expected one of: all, error, warn, info, debug",
            )
        }
    };

    if let Some(svc) = &params.service {
        if let Err(msg) = validate_safe_filter_token(svc) {
            return json_error_response(StatusCode::BAD_REQUEST, msg);
        }
    }
    if let Some(tid) = &params.trace_id {
        if let Err(msg) = validate_safe_filter_token(tid) {
            return json_error_response(StatusCode::BAD_REQUEST, msg);
        }
    }
    if let Some(jid) = &params.job_id {
        if let Err(msg) = validate_safe_filter_token(jid) {
            return json_error_response(StatusCode::BAD_REQUEST, msg);
        }
    }

    let max_limit = if params.job_id.is_some() { 500 } else { 100 };
    let limit = match params.limit {
        Some(0) => {
            return json_error_response(StatusCode::BAD_REQUEST, "limit must be between 1 and 100")
        }
        Some(l) if l > max_limit => {
            return json_error_response(StatusCode::BAD_REQUEST, "limit must be between 1 and 100")
        }
        Some(l) => l,
        None if params.job_id.is_some() => 200,
        None => 50,
    };

    match query_sanitized_logs_with_job(
        &store,
        &sev_norm,
        min_sev_range,
        params.service.as_deref(),
        params.trace_id.as_deref(),
        params.job_id.as_deref(),
        limit,
    ) {
        Ok(resp) => no_store_json(StatusCode::OK, &resp),
        Err(e) => json_error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

async fn handle_get_job_log(
    State(store): State<HotDuckDbStore>,
    AxumPath(job_id): AxumPath<String>,
) -> Response {
    if let Err(msg) = validate_safe_filter_token(&job_id) {
        return json_error_response(StatusCode::BAD_REQUEST, msg);
    }

    match query_sanitized_job_log(&store, &job_id) {
        Ok(Some(body)) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            body,
        )
            .into_response(),
        Ok(None) => json_error_response(
            StatusCode::NOT_FOUND,
            &format!("Job log for '{job_id}' not found"),
        ),
        Err(e) => json_error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// Queries `v_logs` and `job_logs_store` using fixed parameterized SQL filters and applies
/// the 3-stage [`PrivacyRedactor`].
pub fn query_sanitized_logs(
    store: &HotDuckDbStore,
    severity_label: &str,
    sev_range: Option<(i32, i32, &str)>,
    service_filter: Option<&str>,
    trace_id_filter: Option<&str>,
    limit: usize,
) -> Result<LogsQueryResponse, MuObserveError> {
    query_sanitized_logs_with_job(
        store,
        severity_label,
        sev_range,
        service_filter,
        trace_id_filter,
        None,
        limit,
    )
}

/// Queries `v_logs` and `job_logs_store` (`__ar_job_logs__`) with optional `job_id_filter`,
/// applying the 3-stage [`PrivacyRedactor`] to both OTLP collector logs and CI stage logs.
#[allow(clippy::too_many_arguments)]
pub fn query_sanitized_logs_with_job(
    store: &HotDuckDbStore,
    severity_label: &str,
    sev_range: Option<(i32, i32, &str)>,
    service_filter: Option<&str>,
    trace_id_filter: Option<&str>,
    job_id_filter: Option<&str>,
    limit: usize,
) -> Result<LogsQueryResponse, MuObserveError> {
    let redactor = PrivacyRedactor::new();
    let max_cap = if job_id_filter.is_some() { 500 } else { 100 };
    let bounded_limit = limit.clamp(1, max_cap);

    let mut logs = query_v_logs_rows(
        store,
        &redactor,
        sev_range,
        service_filter,
        trace_id_filter,
        job_id_filter,
        bounded_limit,
    )?;

    let ci_logs = extract_sanitized_ci_job_log_items(
        store,
        &redactor,
        sev_range,
        service_filter,
        trace_id_filter,
        job_id_filter,
        bounded_limit,
    )?;
    logs.extend(ci_logs);

    logs.sort_by_key(|a| std::cmp::Reverse(a.timestamp_unix_nano));
    logs.truncate(bounded_limit);

    Ok(LogsQueryResponse {
        severity: if severity_label.is_empty() {
            "all".to_string()
        } else {
            severity_label.to_string()
        },
        total: logs.len(),
        logs,
    })
}

fn query_v_logs_rows(
    store: &HotDuckDbStore,
    redactor: &PrivacyRedactor,
    sev_range: Option<(i32, i32, &str)>,
    service_filter: Option<&str>,
    trace_id_filter: Option<&str>,
    job_id_filter: Option<&str>,
    bounded_limit: usize,
) -> Result<Vec<ConsoleLogItem>, MuObserveError> {
    let conn = store.lock_conn()?;
    let mut stmt = conn.prepare(
        r#"
        SELECT
            timestamp_unix_nano, trace_id, span_id, severity_number, severity_text,
            service_name, node_id, body, attributes_json, job_id, stage_id
        FROM v_logs
        WHERE (?1 IS NULL OR trace_id = ?1)
          AND (?2 IS NULL OR job_id = ?2)
        ORDER BY timestamp_unix_nano DESC
        LIMIT 500
        "#,
    )?;

    let rows = stmt.query_map(params![trace_id_filter, job_id_filter], |r| {
        let ts_ns: i64 = r.get(0)?;
        let raw_svc: String = r.get(5)?;
        let raw_node: String = r.get(6)?;
        let raw_body: String = r.get(7)?;
        let raw_attrs: String = r.get(8)?;
        let clean_svc = redactor.redact_str(&raw_svc);
        Ok(ConsoleLogItem {
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
        })
    })?;

    let mut logs = Vec::new();
    for r in rows {
        let item = r?;
        if !matches_severity(&item, sev_range) {
            continue;
        }
        if let Some(svc) = service_filter {
            if !item.service.eq_ignore_ascii_case(svc) {
                continue;
            }
        }
        logs.push(item);
        if logs.len() >= bounded_limit {
            break;
        }
    }
    Ok(logs)
}

fn matches_severity(item: &ConsoleLogItem, sev_range: Option<(i32, i32, &str)>) -> bool {
    let Some((min_n, max_n, txt)) = sev_range else {
        return true;
    };
    let num_matches = item.severity_number >= min_n && item.severity_number <= max_n;
    let text_matches = item.severity_text.eq_ignore_ascii_case(txt)
        || (txt == "ERROR" && item.severity_text.eq_ignore_ascii_case("FATAL"));
    num_matches || text_matches
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
    // Worker log format from ActionRunner-controller:
    // "<RFC3339> [<node_id>] [<stage_id>] [stdout|stderr] <content>"
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

    // Controller stage lifecycle lines:
    // "=== Stage '<stage_id>' started on worker '<node_id>' ==="
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

fn extract_sanitized_ci_job_log_items(
    store: &HotDuckDbStore,
    redactor: &PrivacyRedactor,
    sev_range: Option<(i32, i32, &str)>,
    service_filter: Option<&str>,
    trace_id_filter: Option<&str>,
    job_id_filter: Option<&str>,
    bounded_limit: usize,
) -> Result<Vec<ConsoleLogItem>, MuObserveError> {
    if let Some(svc) = service_filter {
        if !svc.eq_ignore_ascii_case("actionrunner-rs")
            && !svc.eq_ignore_ascii_case("action-runner")
            && !svc.eq_ignore_ascii_case("action-runner-controller")
        {
            return Ok(Vec::new());
        }
    }

    let mut snapshots = store.query_submodule_snapshots(&QuerySubmoduleSnapshotsRequest {
        request_id: "console-api-logs".to_string(),
        parent_repo_key: Some("__ar_job_logs__".to_string()),
        submodule_key: job_id_filter.map(|j| j.to_ascii_lowercase()),
        branch_key: Some("log".to_string()),
    })?;

    snapshots.sort_by_key(|s| {
        std::cmp::Reverse(
            s.latest_active_queued_us
                .or(s.latest_completed_queued_us)
                .unwrap_or(0),
        )
    });

    let per_job_cap = if job_id_filter.is_some() || trace_id_filter.is_some() {
        bounded_limit
    } else {
        15
    };

    let mut out = Vec::new();
    for snap in snapshots {
        let canonical_job_id = snap
            .latest_active_job_id
            .as_deref()
            .or(snap.latest_completed_job_id.as_deref())
            .unwrap_or(&snap.submodule_key)
            .to_string();
        let (short_job, ci_trace_id) = derive_ci_short_job_and_trace(&canonical_job_id);

        if let Some(tf) = trace_id_filter {
            if !tf.eq_ignore_ascii_case(&ci_trace_id) && !tf.eq_ignore_ascii_case(&canonical_job_id)
            {
                continue;
            }
        }
        if let Some(jf) = job_id_filter {
            if !jf.eq_ignore_ascii_case(&canonical_job_id)
                && !jf.eq_ignore_ascii_case(&snap.submodule_key)
            {
                continue;
            }
        }

        let Some(raw_log) = snap
            .latest_active_json
            .as_deref()
            .or(snap.latest_completed_json.as_deref())
            .filter(|s| !s.trim().is_empty())
        else {
            continue;
        };

        let base_queued_us = snap
            .latest_active_queued_us
            .or(snap.latest_completed_queued_us)
            .unwrap_or(1_700_000_000_000_000);
        let base_ts_ns = base_queued_us.saturating_mul(1_000);

        let mut job_items = Vec::new();
        for (idx, raw_line) in raw_log.lines().enumerate() {
            if raw_line.trim().is_empty() {
                continue;
            }
            let parsed = parse_ci_job_log_line(raw_line);
            let (sev_num, sev_txt) = classify_ci_log_severity(&parsed.body, parsed.is_stderr);
            let ts_ns = parsed.timestamp_ns.unwrap_or_else(|| {
                base_ts_ns.saturating_add((idx as i64).saturating_mul(1_000_000))
            });
            let span_id = match &parsed.stage_id {
                Some(st) => format!("sp-{short_job}-{}", redactor.redact_str(st)),
                None => format!("sp-{short_job}-1"),
            };
            let item = ConsoleLogItem {
                timestamp_unix_nano: ts_ns,
                timestamp_ms: ts_ns / 1_000_000,
                trace_id: ci_trace_id.clone(),
                span_id,
                severity_number: sev_num,
                severity_text: sev_txt.to_string(),
                service: "actionrunner-rs".to_string(),
                service_name: "actionrunner-rs".to_string(),
                node_id: redactor.redact_host(&parsed.node_id),
                body: redactor.redact_str(&parsed.body),
                attributes: json!({
                    "job_id": canonical_job_id,
                    "stage_id": parsed.stage_id,
                }),
                job_id: Some(canonical_job_id.clone()),
                stage_id: parsed.stage_id,
            };
            if matches_severity(&item, sev_range) {
                job_items.push(item);
            }
        }

        if job_items.len() > per_job_cap {
            // Preserve high-signal ERROR/WARN/stage header lines + tail of the job log
            let mut selected = Vec::with_capacity(per_job_cap);
            let tail_start = job_items.len().saturating_sub(per_job_cap);
            for (i, it) in job_items.into_iter().enumerate() {
                if i >= tail_start || it.severity_number >= 13 || it.body.starts_with("=== Stage") {
                    selected.push(it);
                }
            }
            if selected.len() > per_job_cap {
                let drop_count = selected.len() - per_job_cap;
                selected.drain(0..drop_count);
            }
            out.extend(selected);
        } else {
            out.extend(job_items);
        }

        if out.len() >= bounded_limit.saturating_mul(2) {
            break;
        }
    }

    Ok(out)
}

/// Retrieves and 3-stage sanitizes the full execution log for `job_id` from `job_logs_store`
/// (merged with `WriteBehindCache.job_logs`), falling back to a sanitized status summary from
/// `jobs_history` if no log chunks have been written yet.
pub fn query_sanitized_job_log(
    store: &HotDuckDbStore,
    job_id: &str,
) -> Result<Option<String>, MuObserveError> {
    let redactor = PrivacyRedactor::new();
    let key = job_id.trim().to_ascii_lowercase();
    let snapshots = store.query_submodule_snapshots(&QuerySubmoduleSnapshotsRequest {
        request_id: "console-api-job-log".to_string(),
        parent_repo_key: Some("__ar_job_logs__".to_string()),
        submodule_key: Some(key),
        branch_key: Some("log".to_string()),
    })?;

    if let Some(snap) = snapshots.first() {
        if let Some(raw_log) = snap
            .latest_active_json
            .as_deref()
            .or(snap.latest_completed_json.as_deref())
            .filter(|s| !s.trim().is_empty())
        {
            let mut sanitized = String::with_capacity(raw_log.len());
            for line in raw_log.lines() {
                sanitized.push_str(&redactor.redact_str(line));
                sanitized.push('\n');
            }
            return Ok(Some(sanitized));
        }
    }

    let jobs = store.query_jobs_history(&QueryJobsHistoryRequest {
        request_id: "console-api-job-history".to_string(),
        job_id: Some(job_id.trim().to_string()),
        repo_key: None,
        branch_key: None,
        limit: 1,
    })?;

    if let Some(rec) = jobs.first() {
        let summary = format!(
            "[MuObserve] Job '{}' ({}) on branch '{}' @ {} — status: {}\n",
            redactor.redact_str(&rec.job_id),
            redactor.redact_str(&rec.repo_key),
            redactor.redact_str(&rec.branch_key),
            redactor.redact_str(&rec.commit_sha),
            redactor.redact_str(&rec.status_state),
        );
        return Ok(Some(summary));
    }

    Ok(None)
}

async fn handle_get_metrics(
    State(store): State<HotDuckDbStore>,
    q_res: Result<Query<MetricsQueryParams>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let Query(params) = match q_res {
        Ok(q) => q,
        Err(e) => return json_error_response(StatusCode::BAD_REQUEST, &e.to_string()),
    };

    let metric_raw = params.metric.as_deref().unwrap_or("all").trim();
    let metric_filter: Option<&str> = match metric_raw {
        "" | "all" => None,
        "cpu_utilization" | "cpu.utilization" => Some("cpu.utilization"),
        "memlock_usage" | "memlock.used_bytes" => Some("memlock.used_bytes"),
        "decode_tok_s" | "k3.decode.tok_s" => Some("k3.decode.tok_s"),
        "kv_cache_bytes" | "k3.kv_cache.bytes" => Some("k3.kv_cache.bytes"),
        "request_latency_ms" | "http.server.duration" => Some("http.server.duration"),
        "bench_ns_per_iter" => Some("bench_ns_per_iter"),
        _ => {
            return json_error_response(
                StatusCode::BAD_REQUEST,
                "Invalid metric enum; expected one of: all, cpu_utilization, memlock_usage, decode_tok_s, kv_cache_bytes, request_latency_ms, bench_ns_per_iter",
            )
        }
    };

    let window_raw = params.window.as_deref().unwrap_or("1h").trim();
    let window_secs: u64 = match window_raw {
        "5m" | "300" => 300,
        "15m" | "900" => 900,
        "" | "1h" | "3600" => 3600,
        "6h" | "21600" => 21_600,
        "24h" | "86400" => 86_400,
        "7d" | "604800" => 604_800,
        _ => {
            return json_error_response(
                StatusCode::BAD_REQUEST,
                "Invalid window enum; expected one of: 5m, 15m, 1h, 6h, 24h, 7d",
            )
        }
    };

    let cluster_raw = params.cluster.as_deref().unwrap_or("all").trim();
    let cluster_filter: Option<&str> = match cluster_raw {
        "" | "all" => None,
        "X100" | "x100" => Some("X100"),
        "A100" | "a100" => Some("A100"),
        "x86_64" => Some("x86_64"),
        _ => {
            return json_error_response(
                StatusCode::BAD_REQUEST,
                "Invalid cluster enum; expected one of: all, X100, A100, x86_64",
            )
        }
    };

    let limit = match params.limit {
        Some(0) | Some(101..) => {
            return json_error_response(StatusCode::BAD_REQUEST, "limit must be between 1 and 100")
        }
        Some(l) => l,
        None => 60,
    };

    match query_sanitized_metrics(
        &store,
        metric_raw,
        metric_filter,
        window_raw,
        window_secs,
        cluster_filter,
        limit,
    ) {
        Ok(resp) => no_store_json(StatusCode::OK, &resp),
        Err(e) => json_error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// Queries `v_metrics` and `v_benchmarks` using fixed enum parameters and returns sanitized
/// timeseries points with exemplar `trace_id` links and cluster efficiency summaries.
pub fn query_sanitized_metrics(
    store: &HotDuckDbStore,
    metric_label: &str,
    metric_filter: Option<&str>,
    window_label: &str,
    window_secs: u64,
    cluster_filter: Option<&str>,
    limit: usize,
) -> Result<MetricsTimeseriesResponse, MuObserveError> {
    let redactor = PrivacyRedactor::new();
    let conn = store.lock_conn()?;
    let bounded_limit = limit.clamp(1, 100) as i64;

    let max_ts: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(timestamp_unix_nano), 0) FROM v_metrics",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let cutoff_ts = if max_ts > 0 {
        max_ts.saturating_sub((window_secs as i64).saturating_mul(1_000_000_000))
    } else {
        0
    };

    let mut stmt = conn.prepare(
        r#"
        SELECT
            timestamp_unix_nano, service_name, node_id, metric_name, metric_unit,
            value_f64, arch, cpu_cluster, vlen_bits, memlock_used_bytes,
            memlock_limit_bytes, trace_id, span_id, attributes_json
        FROM v_metrics
        WHERE timestamp_unix_nano >= ?1
          AND (?2 IS NULL OR metric_name = ?2)
          AND (?3 IS NULL OR cpu_cluster = ?3 OR arch = ?3)
        ORDER BY timestamp_unix_nano DESC
        LIMIT ?4
        "#,
    )?;

    let rows = stmt.query_map(
        params![cutoff_ts, metric_filter, cluster_filter, bounded_limit],
        |r| {
            let ts_ns: i64 = r.get(0)?;
            let raw_svc: String = r.get(1)?;
            let raw_node: String = r.get(2)?;
            let vlen: Option<i32> = r.get(8)?;
            let mem_used: Option<i64> = r.get(9)?;
            let mem_limit: Option<i64> = r.get(10)?;
            let raw_attrs: String = r.get(13)?;
            let clean_svc = redactor.redact_str(&raw_svc);
            Ok(MetricTimeseriesPoint {
                timestamp_unix_nano: ts_ns,
                timestamp_ms: ts_ns / 1_000_000,
                service: clean_svc.clone(),
                service_name: clean_svc,
                node_id: redactor.redact_host(&raw_node),
                metric_name: r.get(3)?,
                metric_unit: r.get(4)?,
                value_f64: r.get(5)?,
                arch: r.get(6)?,
                cpu_cluster: r.get(7)?,
                vlen_bits: vlen.map(|v| v.max(0) as u32),
                memlock_used_bytes: mem_used.map(|v| v.max(0) as u64),
                memlock_limit_bytes: mem_limit.map(|v| v.max(0) as u64),
                exemplar_trace_id: r.get(11)?,
                exemplar_span_id: r.get(12)?,
                attributes: redactor.redact_attributes_json(&raw_attrs),
            })
        },
    )?;

    let mut series = Vec::new();
    for r in rows {
        series.push(r?);
    }
    drop(stmt);

    let mut eff_stmt = conn.prepare(
        r#"
        SELECT
            arch,
            cpu_cluster,
            vlen_bits,
            COUNT(*) AS run_count,
            AVG(ns_per_iter) AS avg_ns,
            MIN(ns_per_iter) AS min_ns,
            MAX(ns_per_iter) AS max_ns
        FROM v_benchmarks
        GROUP BY arch, cpu_cluster, vlen_bits
        ORDER BY avg_ns ASC
        "#,
    )?;
    let eff_rows = eff_stmt.query_map([], |r| {
        let vlen_i32: i32 = r.get(2)?;
        Ok(ClusterEfficiencyItem {
            arch: r.get(0)?,
            cpu_cluster: r.get(1)?,
            vlen_bits: vlen_i32.max(0) as u32,
            run_count: r.get::<_, i64>(3)?.max(0) as u64,
            avg_ns_per_iter: r.get(4)?,
            min_ns_per_iter: r.get(5)?,
            max_ns_per_iter: r.get(6)?,
        })
    })?;
    let mut cluster_efficiency = Vec::new();
    for er in eff_rows {
        cluster_efficiency.push(er?);
    }

    Ok(MetricsTimeseriesResponse {
        metric: if metric_label.is_empty() {
            "all".to_string()
        } else {
            metric_label.to_string()
        },
        window: if window_label.is_empty() {
            "1h".to_string()
        } else {
            window_label.to_string()
        },
        window_secs,
        total: series.len(),
        series,
        cluster_efficiency,
    })
}

async fn handle_get_store_status(State(store): State<HotDuckDbStore>) -> Response {
    match collect_storage_health_status(&store) {
        Ok(status) => no_store_json(StatusCode::OK, &status),
        Err(e) => json_error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// Collects sanitized storage health metrics across `HotDuckDbStore` and cold Zstd Parquet
/// partitions (`M6.4`, `#47`–`#49`) without exposing any filesystem paths or SQL queries.
pub fn collect_storage_health_status(
    store: &HotDuckDbStore,
) -> Result<StoreStatusResponse, MuObserveError> {
    let total_spans = store.count_rows("v_traces")?;
    let total_logs = store.count_rows("v_logs")?;
    let total_metric_points = store.count_rows("v_metrics")?;
    let total_test_runs = store.count_rows("v_tests")?;
    let total_benchmark_runs = store.count_rows("v_benchmarks")?;

    let hot_spans = store.count_rows("otel_spans")?;
    let hot_logs = store.count_rows("otel_logs")?;
    let hot_metric_points = store.count_rows("otel_metrics")?;

    let cold_spans = total_spans.saturating_sub(hot_spans);
    let cold_logs = total_logs.saturating_sub(hot_logs);
    let cold_metric_points = total_metric_points.saturating_sub(hot_metric_points);

    let hot_duckdb_bytes = store
        .db_path()
        .and_then(|p| std::fs::metadata(p).ok().map(|m| m.len()))
        .unwrap_or_else(|| (hot_spans + hot_logs + hot_metric_points).saturating_mul(256));

    let (parquet_segments, cold_parquet_bytes) = store
        .parquet_root()
        .map(scan_parquet_stats)
        .unwrap_or((0, 0));

    let storage_bytes = hot_duckdb_bytes.saturating_add(cold_parquet_bytes);
    let estimated_compression_ratio = if parquet_segments > 0 { 4.2 } else { 1.0 };

    Ok(StoreStatusResponse {
        total_spans,
        total_logs,
        total_metric_points,
        total_test_runs,
        total_benchmark_runs,
        hot_spans,
        hot_logs,
        hot_metric_points,
        cold_spans,
        cold_logs,
        cold_metric_points,
        parquet_segments,
        storage_bytes,
        hot_duckdb_bytes,
        cold_parquet_bytes,
        compression_codec: "ZSTD".to_string(),
        estimated_compression_ratio,
        retention_days: DEFAULT_HOT_RETENTION_DAYS,
        cold_ttl_days: 60,
        healthy: true,
    })
}

fn scan_parquet_stats(root: &Path) -> (u64, u64) {
    if !root.exists() {
        return (0, 0);
    }
    let mut files = 0u64;
    let mut bytes = 0u64;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().and_then(|e| e.to_str()) == Some("parquet") {
                    files = files.saturating_add(1);
                    if let Ok(meta) = std::fs::metadata(&path) {
                        bytes = bytes.saturating_add(meta.len());
                    }
                }
            }
        }
    }
    (files, bytes)
}

fn validate_safe_filter_token(input: &str) -> Result<(), &'static str> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("Filter parameter cannot be empty");
    }
    if trimmed.len() > 128 {
        return Err("Filter parameter exceeds maximum length (128)");
    }
    if trimmed.contains("--") || trimmed.contains("/*") || trimmed.contains("*/") {
        return Err("SQL comment tokens are forbidden in filter parameters");
    }
    for b in trimmed.bytes() {
        if !(b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':' | b'/')) {
            return Err("Filter parameter contains disallowed SQL/regex metacharacters");
        }
    }
    Ok(())
}

fn no_store_json<T: Serialize>(status: StatusCode, payload: &T) -> Response {
    (status, [(header::CACHE_CONTROL, "no-store")], Json(payload)).into_response()
}

fn json_error_response(status: StatusCode, message: &str) -> Response {
    let redactor = PrivacyRedactor::new();
    let clean_msg = redactor.redact_str(message);
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({
            "error": clean_msg,
            "status": status.as_u16()
        })),
    )
        .into_response()
}
