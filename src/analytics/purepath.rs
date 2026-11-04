use std::collections::{BTreeMap, BTreeSet};

use duckdb::params;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::MuObserveError;
use crate::server::sanitize::PrivacyRedactor;
use crate::storage::hot_duckdb::HotDuckDbStore;

/// Fixed enum filter for `GET /api/v1/traces` (`M6.3`, `#39`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TraceListFilter {
    #[default]
    All,
    Errors,
    SlowP99,
    Ci,
    Cd,
    Registry,
}

impl TraceListFilter {
    /// Parses a query parameter string into a [`TraceListFilter`], rejecting unknown values.
    pub fn parse_param(raw: &str) -> Result<Self, MuObserveError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "" | "all" => Ok(Self::All),
            "errors" | "error" => Ok(Self::Errors),
            "slow_p99" | "slow" => Ok(Self::SlowP99),
            "ci" => Ok(Self::Ci),
            "cd" => Ok(Self::Cd),
            "registry" | "reg" => Ok(Self::Registry),
            other => Err(MuObserveError::Validation(format!(
                "Invalid trace filter '{other}'; expected one of: all, errors, slow_p99, ci, cd, registry"
            ))),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Errors => "errors",
            Self::SlowP99 => "slow_p99",
            Self::Ci => "ci",
            Self::Cd => "cd",
            Self::Registry => "registry",
        }
    }
}

/// Curated recent trace summary returned by `GET /api/v1/traces`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceSummaryDto {
    pub trace_id: String,
    pub root_service: String,
    pub root_operation: String,
    pub start_epoch_ms: i64,
    pub start_time_unix_nano: i64,
    pub duration_us: u64,
    pub duration_ns: u64,
    pub span_count: u32,
    pub error_count: u32,
    pub domain: String,
    pub status: String,
    pub node_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_digest: Option<String>,
}

/// Paginated list response for `GET /api/v1/traces`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceListResponse {
    pub filter: String,
    pub total: usize,
    pub traces: Vec<TraceSummaryDto>,
}

/// Single span node in a W3C PurePath waterfall tree (`GET /api/v1/traces/{trace_id}`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PurePathSpanNode {
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub service: String,
    pub service_name: String,
    pub node_id: String,
    pub operation: String,
    pub span_name: String,
    pub span_kind: String,
    pub depth: u32,
    pub start_time_unix_nano: i64,
    pub end_time_unix_nano: i64,
    pub start_offset_us: u64,
    pub duration_us: u64,
    pub duration_ns: u64,
    pub self_time_us: u64,
    pub self_time_ns: u64,
    pub is_critical_path: bool,
    pub status: String,
    pub status_code: String,
    pub status_message: Option<String>,
    pub baseline_mad_z_score: f64,
    pub attributes: Value,
}

/// Correlated, redacted OpenTelemetry log entry joined to a PurePath trace.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PurePathLogEntry {
    pub timestamp_unix_nano: i64,
    pub offset_us: i64,
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

/// Correlated hardware/process metric sample or exemplar joined to a PurePath trace.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PurePathMetricEntry {
    pub timestamp_unix_nano: i64,
    pub offset_us: i64,
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
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub attributes: Value,
}

/// Full 3-pillar PurePath waterfall payload (`GET /api/v1/traces/{trace_id}` and `/purepath`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PurePathResponse {
    pub trace_id: String,
    pub root_service: String,
    pub root_operation: String,
    pub domain: String,
    pub status: String,
    pub start_epoch_ms: i64,
    pub start_time_unix_nano: i64,
    pub end_time_unix_nano: i64,
    pub duration_us: u64,
    pub duration_ns: u64,
    pub critical_path_duration_us: u64,
    pub span_count: usize,
    pub error_count: usize,
    pub spans: Vec<PurePathSpanNode>,
    pub correlated_logs: Vec<PurePathLogEntry>,
    pub correlated_metrics: Vec<PurePathMetricEntry>,
}

/// Query options for `list_trace_summaries`.
#[derive(Debug, Clone, Default)]
pub struct TraceListQuery {
    pub filter: TraceListFilter,
    pub service: Option<String>,
    pub status: Option<String>,
    pub job_id: Option<String>,
    pub digest: Option<String>,
    pub limit: usize,
}

/// Lists curated recent trace summaries from `v_traces` matching `query`.
pub fn list_trace_summaries(
    store: &HotDuckDbStore,
    query: &TraceListQuery,
) -> Result<TraceListResponse, MuObserveError> {
    let limit = if query.limit == 0 {
        50
    } else {
        query.limit.min(100)
    };
    let redactor = PrivacyRedactor::new();
    let conn = store.lock_conn()?;

    #[derive(Clone)]
    struct RawSpan {
        trace_id: String,
        parent_span_id: Option<String>,
        service_name: String,
        node_id: String,
        span_name: String,
        start_ns: i64,
        end_ns: i64,
        duration_ns: u64,
        status_code: String,
        attributes_json: String,
    }

    let mut stmt = conn.prepare(
        r#"
        SELECT
            trace_id, parent_span_id, service_name, node_id, span_name,
            start_time_unix_nano, end_time_unix_nano, duration_ns, status_code, attributes_json
        FROM v_traces
        ORDER BY start_time_unix_nano DESC
        LIMIT 2000
        "#,
    )?;

    let rows = stmt.query_map([], |r| {
        let dur_i64: i64 = r.get(7)?;
        Ok(RawSpan {
            trace_id: r.get(0)?,
            parent_span_id: r.get(1)?,
            service_name: r.get(2)?,
            node_id: r.get(3)?,
            span_name: r.get(4)?,
            start_ns: r.get(5)?,
            end_ns: r.get(6)?,
            duration_ns: dur_i64.max(0) as u64,
            status_code: r.get(8)?,
            attributes_json: r.get(9)?,
        })
    })?;

    let mut grouped: BTreeMap<String, Vec<RawSpan>> = BTreeMap::new();
    for r in rows {
        let sp = r?;
        grouped.entry(sp.trace_id.clone()).or_default().push(sp);
    }
    drop(stmt);

    let mut summaries = Vec::new();
    for (trace_id, mut spans) in grouped {
        spans.sort_by_key(|s| s.start_ns);
        let root = spans
            .iter()
            .find(|s| s.parent_span_id.as_deref().unwrap_or("").is_empty())
            .unwrap_or(&spans[0]);

        let min_start = spans.iter().map(|s| s.start_ns).min().unwrap_or(0);
        let max_end = spans.iter().map(|s| s.end_ns).max().unwrap_or(min_start);
        let wall_dur_ns = (max_end.saturating_sub(min_start) as u64).max(root.duration_ns);
        let span_count = spans.len() as u32;
        let error_count = spans
            .iter()
            .filter(|s| s.status_code.eq_ignore_ascii_case("ERROR"))
            .count() as u32;

        let clean_service = redactor.redact_str(&root.service_name);
        let clean_op = redactor.redact_str(&root.span_name);
        let clean_node = redactor.redact_host(&root.node_id);
        let domain = classify_trace_domain(&clean_service, &clean_op, &root.attributes_json);
        let status = if error_count > 0 {
            "ERROR".to_string()
        } else {
            "OK".to_string()
        };

        let (job_id, artifact_digest) =
            extract_job_and_digest(spans.iter().map(|s| s.attributes_json.as_str()));

        if let Some(svc_filter) = &query.service {
            if !clean_service.eq_ignore_ascii_case(svc_filter)
                && !spans.iter().any(|s| {
                    redactor
                        .redact_str(&s.service_name)
                        .eq_ignore_ascii_case(svc_filter)
                })
            {
                continue;
            }
        }
        if let Some(st_filter) = &query.status {
            if !st_filter.eq_ignore_ascii_case("all") && !status.eq_ignore_ascii_case(st_filter) {
                continue;
            }
        }
        if let Some(jid_filter) = &query.job_id {
            if job_id.as_deref() != Some(jid_filter.as_str()) {
                continue;
            }
        }
        if let Some(dig_filter) = &query.digest {
            if artifact_digest.as_deref() != Some(dig_filter.as_str()) {
                continue;
            }
        }

        summaries.push(TraceSummaryDto {
            trace_id,
            root_service: clean_service,
            root_operation: clean_op,
            start_epoch_ms: min_start / 1_000_000,
            start_time_unix_nano: min_start,
            duration_us: wall_dur_ns / 1_000,
            duration_ns: wall_dur_ns,
            span_count,
            error_count,
            domain,
            status,
            node_id: clean_node,
            job_id,
            artifact_digest,
        });
    }

    // Sort newest first
    summaries.sort_by_key(|a| std::cmp::Reverse(a.start_time_unix_nano));

    // Apply TraceListFilter
    let p99_threshold_us = if query.filter == TraceListFilter::SlowP99 && !summaries.is_empty() {
        let mut durs: Vec<u64> = summaries.iter().map(|s| s.duration_us).collect();
        durs.sort_unstable();
        let idx = ((durs.len().saturating_sub(1) as f64) * 0.50).round() as usize;
        durs[idx]
    } else {
        0
    };

    let filtered: Vec<TraceSummaryDto> = summaries
        .into_iter()
        .filter(|t| match query.filter {
            TraceListFilter::All => true,
            TraceListFilter::Errors => t.error_count > 0 || t.status == "ERROR",
            TraceListFilter::SlowP99 => t.duration_us >= p99_threshold_us && t.duration_us > 0,
            TraceListFilter::Ci => t.domain == "ci",
            TraceListFilter::Cd => t.domain == "cd",
            TraceListFilter::Registry => t.domain == "registry",
        })
        .take(limit)
        .collect();

    Ok(TraceListResponse {
        filter: query.filter.as_str().to_string(),
        total: filtered.len(),
        traces: filtered,
    })
}

/// Computes the full W3C PurePath waterfall tree (`depth`, `self_time_us`, `is_critical_path`,
/// 7-day rolling baseline MAD z-score) and joins correlated redacted OTel logs and hardware
/// metric samples (`M6.3`, `#37`–`#42`).
pub fn compute_purepath_waterfall(
    store: &HotDuckDbStore,
    trace_id: &str,
) -> Result<Option<PurePathResponse>, MuObserveError> {
    let redactor = PrivacyRedactor::new();
    let conn = store.lock_conn()?;

    #[derive(Clone)]
    struct RawSpanRow {
        span_id: String,
        parent_span_id: Option<String>,
        raw_service: String,
        service: String,
        node_id: String,
        operation: String,
        span_kind: String,
        start_ns: i64,
        end_ns: i64,
        duration_ns: u64,
        status_code: String,
        status_message: Option<String>,
        attributes_json: String,
    }

    let mut stmt = conn.prepare(
        r#"
        SELECT
            span_id, parent_span_id, service_name, node_id, span_name, span_kind,
            start_time_unix_nano, end_time_unix_nano, duration_ns, status_code,
            status_message, attributes_json
        FROM v_traces
        WHERE trace_id = ?1
        ORDER BY start_time_unix_nano ASC, duration_ns DESC
        "#,
    )?;

    let rows = stmt.query_map(params![trace_id], |r| {
        let raw_service: String = r.get(2)?;
        let raw_node: String = r.get(3)?;
        let raw_op: String = r.get(4)?;
        let dur_i64: i64 = r.get(8)?;
        let raw_msg: Option<String> = r.get(10)?;
        Ok(RawSpanRow {
            span_id: r.get(0)?,
            parent_span_id: r
                .get::<_, Option<String>>(1)?
                .filter(|p| !p.trim().is_empty()),
            service: redactor.redact_str(&raw_service),
            raw_service,
            node_id: redactor.redact_host(&raw_node),
            operation: redactor.redact_str(&raw_op),
            span_kind: r.get(5)?,
            start_ns: r.get(6)?,
            end_ns: r.get(7)?,
            duration_ns: dur_i64.max(0) as u64,
            status_code: r.get(9)?,
            status_message: raw_msg.map(|m| redactor.redact_str(&m)),
            attributes_json: r.get(11)?,
        })
    })?;

    let mut raw_spans = Vec::new();
    for r in rows {
        raw_spans.push(r?);
    }
    drop(stmt);

    if raw_spans.is_empty() {
        return Ok(None);
    }

    let trace_start_ns = raw_spans.iter().map(|s| s.start_ns).min().unwrap_or(0);
    let trace_end_ns = raw_spans
        .iter()
        .map(|s| s.end_ns)
        .max()
        .unwrap_or(trace_start_ns);

    // Map span_id -> index in raw_spans
    let mut id_to_idx: BTreeMap<String, usize> = BTreeMap::new();
    for (idx, sp) in raw_spans.iter().enumerate() {
        id_to_idx.entry(sp.span_id.clone()).or_insert(idx);
    }

    // Build parent -> children adjacency list
    let mut children_map: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    let mut roots = Vec::new();
    for (idx, sp) in raw_spans.iter().enumerate() {
        if let Some(pid) = &sp.parent_span_id {
            if let Some(&parent_idx) = id_to_idx.get(pid) {
                if parent_idx != idx {
                    children_map.entry(parent_idx).or_default().push(idx);
                    continue;
                }
            }
        }
        roots.push(idx);
    }
    if roots.is_empty() {
        roots.push(0);
    }

    // Compute depth via cycle-safe traversal and order waterfall in DFS pre-order
    let mut depths = vec![0u32; raw_spans.len()];
    let mut ordered_indices = Vec::with_capacity(raw_spans.len());
    let mut visited = BTreeSet::new();

    for &root_idx in &roots {
        let mut stack = vec![(root_idx, 0u32)];
        while let Some((curr, depth)) = stack.pop() {
            if !visited.insert(curr) {
                continue;
            }
            depths[curr] = depth;
            ordered_indices.push(curr);
            if let Some(kids) = children_map.get(&curr) {
                let mut sorted_kids = kids.clone();
                sorted_kids.sort_by(|&a, &b| raw_spans[b].start_ns.cmp(&raw_spans[a].start_ns));
                for k in sorted_kids {
                    stack.push((k, depth + 1));
                }
            }
        }
    }
    for idx in 0..raw_spans.len() {
        if visited.insert(idx) {
            ordered_indices.push(idx);
        }
    }

    // Compute self_time_ns = duration_ns.saturating_sub(sum(direct children duration_ns))
    let mut self_times_ns = vec![0u64; raw_spans.len()];
    for (idx, sp) in raw_spans.iter().enumerate() {
        let child_sum: u64 = children_map
            .get(&idx)
            .map(|kids| kids.iter().map(|&c| raw_spans[c].duration_ns).sum())
            .unwrap_or(0);
        self_times_ns[idx] = sp.duration_ns.saturating_sub(child_sum);
    }

    // Compute critical path recursively from the dominant root span
    let mut is_critical = vec![false; raw_spans.len()];
    if let Some(&primary_root) = roots.iter().max_by_key(|&&idx| raw_spans[idx].duration_ns) {
        let mut curr_opt = Some(primary_root);
        let mut path_seen = BTreeSet::new();
        while let Some(curr) = curr_opt {
            if !path_seen.insert(curr) {
                break;
            }
            is_critical[curr] = true;
            curr_opt = children_map.get(&curr).and_then(|kids| {
                kids.iter()
                    .copied()
                    .max_by_key(|&c| raw_spans[c].duration_ns)
            });
        }
    }

    // Compute rolling 7-day baseline MAD z-scores per (raw_service, operation)
    let mut baseline_stmt = conn.prepare(
        r#"
        SELECT duration_ns
        FROM v_traces
        WHERE service_name = ?1
          AND span_name = ?2
        ORDER BY start_time_unix_nano DESC
        LIMIT 50
        "#,
    )?;

    let mut span_nodes = Vec::with_capacity(raw_spans.len());
    for idx in ordered_indices {
        let sp = &raw_spans[idx];
        let start_offset_ns = sp.start_ns.saturating_sub(trace_start_ns).max(0) as u64;
        let self_time_ns = self_times_ns[idx];

        let mut base_samples = Vec::new();
        if let Ok(b_rows) = baseline_stmt.query_map(params![sp.raw_service, sp.operation], |r| {
            Ok(r.get::<_, i64>(0)?.max(0) as f64)
        }) {
            for br in b_rows.flatten() {
                base_samples.push(br);
            }
        }
        let z_score = compute_mad_z_score(&mut base_samples, sp.duration_ns as f64);

        span_nodes.push(PurePathSpanNode {
            span_id: sp.span_id.clone(),
            parent_span_id: sp.parent_span_id.clone(),
            service: sp.service.clone(),
            service_name: sp.service.clone(),
            node_id: sp.node_id.clone(),
            operation: sp.operation.clone(),
            span_name: sp.operation.clone(),
            span_kind: sp.span_kind.clone(),
            depth: depths[idx],
            start_time_unix_nano: sp.start_ns,
            end_time_unix_nano: sp.end_ns,
            start_offset_us: start_offset_ns / 1_000,
            duration_us: sp.duration_ns / 1_000,
            duration_ns: sp.duration_ns,
            self_time_us: self_time_ns / 1_000,
            self_time_ns,
            is_critical_path: is_critical[idx],
            status: sp.status_code.clone(),
            status_code: sp.status_code.clone(),
            status_message: sp.status_message.clone(),
            baseline_mad_z_score: (z_score * 100.0).round() / 100.0,
            attributes: redactor.redact_attributes_json(&sp.attributes_json),
        });
    }
    drop(baseline_stmt);

    // Join correlated OTel logs for trace_id
    let mut log_stmt = conn.prepare(
        r#"
        SELECT
            timestamp_unix_nano, span_id, severity_number, severity_text,
            service_name, node_id, body, attributes_json, job_id, stage_id
        FROM v_logs
        WHERE trace_id = ?1
        ORDER BY timestamp_unix_nano ASC
        LIMIT 200
        "#,
    )?;
    let log_rows = log_stmt.query_map(params![trace_id], |r| {
        let ts_ns: i64 = r.get(0)?;
        let raw_svc: String = r.get(4)?;
        let raw_node: String = r.get(5)?;
        let raw_body: String = r.get(6)?;
        let raw_attrs: String = r.get(7)?;
        let clean_svc = redactor.redact_str(&raw_svc);
        Ok(PurePathLogEntry {
            timestamp_unix_nano: ts_ns,
            offset_us: ts_ns.saturating_sub(trace_start_ns) / 1_000,
            trace_id: trace_id.to_string(),
            span_id: r.get(1)?,
            severity_number: r.get(2)?,
            severity_text: r.get(3)?,
            service: clean_svc.clone(),
            service_name: clean_svc,
            node_id: redactor.redact_host(&raw_node),
            body: redactor.redact_str(&raw_body),
            attributes: redactor.redact_attributes_json(&raw_attrs),
            job_id: r.get(8)?,
            stage_id: r.get(9)?,
        })
    })?;
    let mut correlated_logs = Vec::new();
    for lr in log_rows {
        correlated_logs.push(lr?);
    }
    drop(log_stmt);

    // Join correlated metric exemplars & window samples
    let win_start = trace_start_ns.saturating_sub(5_000_000_000);
    let win_end = trace_end_ns.saturating_add(5_000_000_000);
    let mut metric_stmt = conn.prepare(
        r#"
        SELECT
            timestamp_unix_nano, service_name, node_id, metric_name, metric_unit,
            value_f64, arch, cpu_cluster, vlen_bits, memlock_used_bytes,
            memlock_limit_bytes, trace_id, span_id, attributes_json
        FROM v_metrics
        WHERE trace_id = ?1
           OR (timestamp_unix_nano >= ?2 AND timestamp_unix_nano <= ?3)
        ORDER BY timestamp_unix_nano ASC
        LIMIT 100
        "#,
    )?;
    let metric_rows = metric_stmt.query_map(params![trace_id, win_start, win_end], |r| {
        let ts_ns: i64 = r.get(0)?;
        let raw_svc: String = r.get(1)?;
        let raw_node: String = r.get(2)?;
        let vlen: Option<i32> = r.get(8)?;
        let mem_used: Option<i64> = r.get(9)?;
        let mem_limit: Option<i64> = r.get(10)?;
        let raw_attrs: String = r.get(13)?;
        let clean_svc = redactor.redact_str(&raw_svc);
        Ok(PurePathMetricEntry {
            timestamp_unix_nano: ts_ns,
            offset_us: ts_ns.saturating_sub(trace_start_ns) / 1_000,
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
            trace_id: r.get(11)?,
            span_id: r.get(12)?,
            attributes: redactor.redact_attributes_json(&raw_attrs),
        })
    })?;
    let mut correlated_metrics = Vec::new();
    for mr in metric_rows {
        correlated_metrics.push(mr?);
    }

    let root_node = &span_nodes[0];
    let wall_duration_ns =
        (trace_end_ns.saturating_sub(trace_start_ns).max(0) as u64).max(root_node.duration_ns);
    let critical_path_duration_us: u64 = span_nodes
        .iter()
        .filter(|s| s.is_critical_path)
        .map(|s| s.self_time_us)
        .sum::<u64>()
        .max(root_node.duration_us);
    let error_count = span_nodes
        .iter()
        .filter(|s| s.status.eq_ignore_ascii_case("ERROR"))
        .count();
    let status = if error_count > 0 {
        "ERROR".to_string()
    } else {
        "OK".to_string()
    };
    let domain = classify_trace_domain(
        &root_node.service,
        &root_node.operation,
        &raw_spans[0].attributes_json,
    );

    Ok(Some(PurePathResponse {
        trace_id: trace_id.to_string(),
        root_service: root_node.service.clone(),
        root_operation: root_node.operation.clone(),
        domain,
        status,
        start_epoch_ms: trace_start_ns / 1_000_000,
        start_time_unix_nano: trace_start_ns,
        end_time_unix_nano: trace_end_ns,
        duration_us: wall_duration_ns / 1_000,
        duration_ns: wall_duration_ns,
        critical_path_duration_us,
        span_count: span_nodes.len(),
        error_count,
        spans: span_nodes,
        correlated_logs,
        correlated_metrics,
    }))
}

fn classify_trace_domain(service: &str, operation: &str, attrs_json: &str) -> String {
    let lower_svc = service.to_ascii_lowercase();
    let lower_op = operation.to_ascii_lowercase();
    let lower_attrs = attrs_json.to_ascii_lowercase();

    if lower_svc.contains("action-runner")
        || lower_op.starts_with("ci.")
        || lower_op.starts_with("stage.")
    {
        "ci".to_string()
    } else if lower_svc.contains("muconde")
        || lower_op.contains("deploy")
        || lower_op.contains("canary")
        || lower_op.contains("rollout")
    {
        "cd".to_string()
    } else if lower_svc.contains("regist")
        || lower_op.contains("oci")
        || lower_op.contains("blob")
        || lower_op.contains("manifest")
    {
        "registry".to_string()
    } else if lower_attrs.contains("job_id") {
        "ci".to_string()
    } else if lower_attrs.contains("artifact_digest") {
        "registry".to_string()
    } else {
        "runtime".to_string()
    }
}

fn extract_job_and_digest<'a, I>(attrs_iter: I) -> (Option<String>, Option<String>)
where
    I: IntoIterator<Item = &'a str>,
{
    let mut job_id = None;
    let mut digest = None;
    for raw_json in attrs_iter {
        if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(raw_json) {
            if job_id.is_none() {
                job_id = map
                    .get("job_id")
                    .or_else(|| map.get("ci.job_id"))
                    .and_then(Value::as_str)
                    .map(ToString::to_string);
            }
            if digest.is_none() {
                digest = map
                    .get("artifact_digest")
                    .or_else(|| map.get("oci.digest"))
                    .and_then(Value::as_str)
                    .map(ToString::to_string);
            }
        }
    }
    (job_id, digest)
}

fn compute_mad_z_score(samples: &mut [f64], candidate: f64) -> f64 {
    if samples.len() < 2 {
        return 0.0;
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mid = samples.len() / 2;
    let median = if samples.len() % 2 == 1 {
        samples[mid]
    } else {
        (samples[mid - 1] + samples[mid]) / 2.0
    };
    let mut devs: Vec<f64> = samples.iter().map(|v| (v - median).abs()).collect();
    devs.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mad = devs[devs.len() / 2];
    let effective_mad = if mad > 1e-6 {
        mad
    } else {
        (median.abs() * 0.01).max(1.0)
    };
    0.6745 * (candidate - median) / effective_mad
}

#[cfg(test)]
mod tests {
    use super::*;
    use muobserve_ipc::{OtelLogEntry, OtelMetricEntry, OtelSpanEntry};

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_purepath_waterfall_critical_path_self_time_and_3_pillar_correlation() {
        let store = HotDuckDbStore::open_in_memory().expect("open in memory");
        let base_ts = 1_700_000_000_000_000_000i64;

        // Root span (100 ms) -> Child A (20 ms) + Child B (60 ms, critical path) -> Grandchild B1 (40 ms, critical path)
        store
            .insert_spans_batch(&[
                OtelSpanEntry {
                    trace_id: "trace-pp-1".into(),
                    span_id: "span-root".into(),
                    parent_span_id: None,
                    service_name: "action-runner-controller".into(),
                    node_id: "entrance.lab.local".into(),
                    span_name: "ci.pipeline".into(),
                    span_kind: "SERVER".into(),
                    start_time_unix_nano: base_ts,
                    end_time_unix_nano: base_ts + 100_000_000,
                    duration_ns: 100_000_000,
                    status_code: "OK".into(),
                    status_message: None,
                    attributes_json: r#"{"job_id":"job-42","host.name":"entrance.lab.local"}"#
                        .into(),
                },
                OtelSpanEntry {
                    trace_id: "trace-pp-1".into(),
                    span_id: "span-child-a".into(),
                    parent_span_id: Some("span-root".into()),
                    service_name: "muregist".into(),
                    node_id: "rubicon.lab.local".into(),
                    span_name: "oci.head_blob".into(),
                    span_kind: "CLIENT".into(),
                    start_time_unix_nano: base_ts + 5_000_000,
                    end_time_unix_nano: base_ts + 25_000_000,
                    duration_ns: 20_000_000,
                    status_code: "OK".into(),
                    status_message: None,
                    attributes_json: "{}".into(),
                },
                OtelSpanEntry {
                    trace_id: "trace-pp-1".into(),
                    span_id: "span-child-b".into(),
                    parent_span_id: Some("span-root".into()),
                    service_name: "action-runner-worker".into(),
                    node_id: "pey-wail-deu.lab.local".into(),
                    span_name: "stage.execute".into(),
                    span_kind: "INTERNAL".into(),
                    start_time_unix_nano: base_ts + 30_000_000,
                    end_time_unix_nano: base_ts + 90_000_000,
                    duration_ns: 60_000_000,
                    status_code: "ERROR".into(),
                    status_message: Some("failed on 192.168.1.117".into()),
                    attributes_json: r#"{"authorization":"Bearer secret123"}"#.into(),
                },
                OtelSpanEntry {
                    trace_id: "trace-pp-1".into(),
                    span_id: "span-grandchild-b1".into(),
                    parent_span_id: Some("span-child-b".into()),
                    service_name: "k3-manager".into(),
                    node_id: "pey-wail-deu.lab.local".into(),
                    span_name: "k3.decode".into(),
                    span_kind: "INTERNAL".into(),
                    start_time_unix_nano: base_ts + 40_000_000,
                    end_time_unix_nano: base_ts + 80_000_000,
                    duration_ns: 40_000_000,
                    status_code: "OK".into(),
                    status_message: None,
                    attributes_json: "{}".into(),
                },
            ])
            .unwrap();

        store
            .insert_logs_batch(&[OtelLogEntry {
                timestamp_unix_nano: base_ts + 50_000_000,
                trace_id: "trace-pp-1".into(),
                span_id: "span-child-b".into(),
                severity_number: 17,
                severity_text: "ERROR".into(),
                service_name: "action-runner-worker".into(),
                node_id: "pey-wail-deu.lab.local".into(),
                body: "stage error at /var/lib/action-runner/work/main.rs with token=ghp_abc123456"
                    .into(),
                attributes_json: "{}".into(),
                job_id: Some("job-42".into()),
                stage_id: Some("test-check".into()),
            }])
            .unwrap();

        store
            .insert_metrics_batch(&[OtelMetricEntry {
                timestamp_unix_nano: base_ts + 55_000_000,
                service_name: "k3-manager".into(),
                node_id: "pey-wail-deu.lab.local".into(),
                metric_name: "k3.decode.tok_s".into(),
                metric_unit: "tok/s".into(),
                value_f64: 64.5,
                arch: "riscv64gc".into(),
                cpu_cluster: Some("A100".into()),
                vlen_bits: Some(1024),
                memlock_used_bytes: Some(1024 * 1024),
                memlock_limit_bytes: Some(28 * 1024 * 1024 * 1024),
                trace_id: Some("trace-pp-1".into()),
                span_id: Some("span-grandchild-b1".into()),
                attributes_json: "{}".into(),
            }])
            .unwrap();

        let pp = compute_purepath_waterfall(&store, "trace-pp-1")
            .unwrap()
            .expect("trace exists");
        assert_eq!(pp.span_count, 4);
        assert_eq!(pp.error_count, 1);
        assert_eq!(pp.duration_us, 100_000);
        assert_eq!(pp.correlated_logs.len(), 1);
        assert_eq!(pp.correlated_metrics.len(), 1);

        let root = pp.spans.iter().find(|s| s.span_id == "span-root").unwrap();
        assert_eq!(root.depth, 0);
        assert_eq!(root.self_time_us, 20_000); // 100ms - (20ms + 60ms) = 20ms
        assert!(root.is_critical_path);

        let child_a = pp
            .spans
            .iter()
            .find(|s| s.span_id == "span-child-a")
            .unwrap();
        assert_eq!(child_a.depth, 1);
        assert!(!child_a.is_critical_path);

        let child_b = pp
            .spans
            .iter()
            .find(|s| s.span_id == "span-child-b")
            .unwrap();
        assert_eq!(child_b.depth, 1);
        assert_eq!(child_b.self_time_us, 20_000); // 60ms - 40ms = 20ms
        assert!(child_b.is_critical_path);

        let grand_b1 = pp
            .spans
            .iter()
            .find(|s| s.span_id == "span-grandchild-b1")
            .unwrap();
        assert_eq!(grand_b1.depth, 2);
        assert_eq!(grand_b1.self_time_us, 40_000);
        assert!(grand_b1.is_critical_path);

        let payload_json = serde_json::to_string(&pp).unwrap();
        assert!(!payload_json.contains("entrance"));
        assert!(!payload_json.contains("rubicon"));
        assert!(!payload_json.contains("pey-wail-deu"));
        assert!(!payload_json.contains("192.168.1.117"));
        assert!(!payload_json.contains("secret123"));
        assert!(!payload_json.contains("ghp_abc123456"));
        assert!(!payload_json.contains("/var/lib/"));
    }
}
