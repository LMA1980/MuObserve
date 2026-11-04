use std::collections::BTreeMap;

use duckdb::params;
use serde::{Deserialize, Serialize};

use crate::analytics::regression::{
    compute_test_flakiness, evaluate_benchmark_regressions, DEFAULT_MAX_MAD_Z_SCORE,
};
use crate::error::MuObserveError;
use crate::server::sanitize::PrivacyRedactor;
use crate::storage::hot_duckdb::HotDuckDbStore;

/// Default Smartscape and Problems evaluation window in seconds (`1 hour`).
pub const DEFAULT_SMARTSCAPE_WINDOW_SECS: u64 = 3600;

/// Service-layer node in the 3-layer vertical Smartscape topology graph (`M6.2`, `#30`–`#32`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SmartscapeServiceNode {
    pub id: String,
    pub name: String,
    pub layer: String,
    pub health_state: String,
    pub request_rate_rps: f64,
    pub error_rate_pct: f64,
    pub p50_latency_ms: f64,
    pub p95_latency_ms: f64,
    pub p99_latency_ms: f64,
    pub span_count: u64,
    pub error_count: u64,
}

/// Process-layer node (`service@host`) in the 3-layer vertical Smartscape topology graph.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SmartscapeProcessNode {
    pub id: String,
    pub name: String,
    pub service_name: String,
    pub host_id: String,
    pub layer: String,
    pub health_state: String,
    pub request_rate_rps: f64,
    pub error_rate_pct: f64,
    pub p95_latency_ms: f64,
    pub span_count: u64,
    pub error_count: u64,
}

/// Host-layer node in the 3-layer vertical Smartscape topology graph.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SmartscapeHostNode {
    pub id: String,
    pub name: String,
    pub arch: String,
    pub cpu_cluster: Option<String>,
    pub vlen_bits: Option<u32>,
    pub layer: String,
    pub health_state: String,
    pub request_rate_rps: f64,
    pub error_rate_pct: f64,
    pub p95_latency_ms: f64,
    pub span_count: u64,
    pub error_count: u64,
}

/// Directed edge in the Smartscape graph (`calls`, `runs_on_process`, or `runs_on_host`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SmartscapeEdge {
    pub source: String,
    pub target: String,
    pub relation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller_service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callee_service: Option<String>,
    pub call_count: u64,
    pub request_rate_rps: f64,
    pub error_rate_pct: f64,
    pub p50_latency_ms: f64,
    pub p95_latency_ms: f64,
    pub p99_latency_ms: f64,
}

/// Sanitized 3-layer vertical Smartscape topology response (`GET /api/v1/smartscape`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SmartscapeTopology {
    pub window_secs: u64,
    pub generated_at_ms: i64,
    pub services: Vec<SmartscapeServiceNode>,
    pub processes: Vec<SmartscapeProcessNode>,
    pub hosts: Vec<SmartscapeHostNode>,
    pub edges: Vec<SmartscapeEdge>,
}

/// Deterministic SLO problem card (`GET /api/v1/problems`, issues `#33`–`#35`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProblemCard {
    pub problem_id: String,
    pub title: String,
    pub severity: String,
    pub status: String,
    pub category: String,
    pub impacted_entity: String,
    pub slo_metric: String,
    pub root_cause_trace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_digest: Option<String>,
    pub detected_at_ms: i64,
    pub summary: String,
}

/// Alias matching issue `#34` naming (`ProblemSummary`).
pub type ProblemSummary = ProblemCard;

/// Sanitized problems feed payload (`GET /api/v1/problems`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProblemsFeedResponse {
    pub window_secs: u64,
    pub open_count: usize,
    pub total: usize,
    pub problems: Vec<ProblemCard>,
}

/// Computes the sanitized 3-layer vertical Smartscape topology (`services`, `processes`, `hosts`,
/// and directed `edges`) over `v_traces` and `v_metrics` within `window_secs`.
pub fn compute_smartscape_topology(
    store: &HotDuckDbStore,
    window_secs: u64,
    now_unix_nano: Option<i64>,
) -> Result<SmartscapeTopology, MuObserveError> {
    let bounded_window = window_secs.clamp(1, 604_800);
    let redactor = PrivacyRedactor::new();
    let conn = store.lock_conn()?;

    let anchor_ts: i64 = match now_unix_nano {
        Some(ts) => ts,
        None => conn
            .query_row(
                "SELECT COALESCE(MAX(end_time_unix_nano), 0) FROM v_traces",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0),
    };

    let cutoff_ts = if anchor_ts > 0 {
        anchor_ts.saturating_sub((bounded_window as i64).saturating_mul(1_000_000_000))
    } else {
        0
    };

    #[derive(Clone)]
    struct SpanRow {
        trace_id: String,
        span_id: String,
        parent_span_id: Option<String>,
        service_name: String,
        node_id: String,
        duration_ms: f64,
        is_error: bool,
    }

    let mut stmt = conn.prepare(
        r#"
        SELECT
            trace_id, span_id, parent_span_id, service_name, node_id, duration_ns, status_code
        FROM v_traces
        WHERE end_time_unix_nano >= ?1
        ORDER BY start_time_unix_nano ASC
        "#,
    )?;

    let rows = stmt.query_map(params![cutoff_ts], |r| {
        let dur_ns: i64 = r.get(5)?;
        let status: String = r.get(6)?;
        let raw_svc: String = r.get(3)?;
        let raw_node: String = r.get(4)?;
        Ok(SpanRow {
            trace_id: r.get(0)?,
            span_id: r.get(1)?,
            parent_span_id: r.get(2)?,
            service_name: redactor.redact_str(&raw_svc),
            node_id: redactor.redact_host(&raw_node),
            duration_ms: (dur_ns.max(0) as f64) / 1_000_000.0,
            is_error: status.eq_ignore_ascii_case("ERROR"),
        })
    })?;

    let mut all_spans = Vec::new();
    for r in rows {
        all_spans.push(r?);
    }
    drop(stmt);

    // Query host hardware metadata from v_metrics and v_benchmarks
    let mut host_meta: BTreeMap<String, (String, Option<String>, Option<u32>)> = BTreeMap::new();
    if let Ok(mut m_stmt) = conn.prepare(
        r#"
        SELECT node_id, arch, cpu_cluster, vlen_bits
        FROM v_metrics
        ORDER BY timestamp_unix_nano DESC
        LIMIT 500
        "#,
    ) {
        if let Ok(m_rows) = m_stmt.query_map([], |r| {
            let raw_node: String = r.get(0)?;
            let arch: String = r.get(1)?;
            let cluster: Option<String> = r.get(2)?;
            let vlen: Option<i32> = r.get(3)?;
            Ok((
                redactor.redact_host(&raw_node),
                arch,
                cluster,
                vlen.map(|v| v.max(0) as u32),
            ))
        }) {
            for mr in m_rows.flatten() {
                host_meta.entry(mr.0).or_insert((mr.1, mr.2, mr.3));
            }
        }
    }

    // Aggregate per service, per process (service@host), and per host
    let mut svc_buckets: BTreeMap<String, (Vec<f64>, u64)> = BTreeMap::new();
    let mut proc_buckets: BTreeMap<(String, String), (Vec<f64>, u64)> = BTreeMap::new();
    let mut host_buckets: BTreeMap<String, (Vec<f64>, u64)> = BTreeMap::new();
    let mut span_lookup: BTreeMap<(String, String), String> = BTreeMap::new();

    for sp in &all_spans {
        span_lookup.insert(
            (sp.trace_id.clone(), sp.span_id.clone()),
            sp.service_name.clone(),
        );

        let svc_entry = svc_buckets
            .entry(sp.service_name.clone())
            .or_insert_with(|| (Vec::new(), 0));
        svc_entry.0.push(sp.duration_ms);
        if sp.is_error {
            svc_entry.1 += 1;
        }

        let proc_entry = proc_buckets
            .entry((sp.service_name.clone(), sp.node_id.clone()))
            .or_insert_with(|| (Vec::new(), 0));
        proc_entry.0.push(sp.duration_ms);
        if sp.is_error {
            proc_entry.1 += 1;
        }

        let host_entry = host_buckets
            .entry(sp.node_id.clone())
            .or_insert_with(|| (Vec::new(), 0));
        host_entry.0.push(sp.duration_ms);
        if sp.is_error {
            host_entry.1 += 1;
        }
    }

    let win_f64 = bounded_window as f64;

    let mut services = Vec::new();
    for (svc_name, (mut durs, err_cnt)) in svc_buckets {
        let count = durs.len() as u64;
        let rps = (count as f64) / win_f64;
        let err_pct = if count > 0 {
            (err_cnt as f64 * 100.0) / (count as f64)
        } else {
            0.0
        };
        let p50 = percentile(&mut durs, 0.50);
        let p95 = percentile(&mut durs, 0.95);
        let p99 = percentile(&mut durs, 0.99);
        services.push(SmartscapeServiceNode {
            id: format!("svc:{svc_name}"),
            name: svc_name,
            layer: "service".into(),
            health_state: classify_health(err_pct, p95),
            request_rate_rps: round_metric(rps),
            error_rate_pct: round_metric(err_pct),
            p50_latency_ms: round_metric(p50),
            p95_latency_ms: round_metric(p95),
            p99_latency_ms: round_metric(p99),
            span_count: count,
            error_count: err_cnt,
        });
    }

    let mut processes = Vec::new();
    let mut vertical_edges = Vec::new();
    for ((svc_name, host_name), (mut durs, err_cnt)) in proc_buckets {
        let count = durs.len() as u64;
        let rps = (count as f64) / win_f64;
        let err_pct = if count > 0 {
            (err_cnt as f64 * 100.0) / (count as f64)
        } else {
            0.0
        };
        let p50 = percentile(&mut durs, 0.50);
        let p95 = percentile(&mut durs, 0.95);
        let p99 = percentile(&mut durs, 0.99);
        let proc_id = format!("proc:{svc_name}@{host_name}");
        let svc_id = format!("svc:{svc_name}");
        let host_id = format!("host:{host_name}");

        processes.push(SmartscapeProcessNode {
            id: proc_id.clone(),
            name: format!("{svc_name}@{host_name}"),
            service_name: svc_name,
            host_id: host_id.clone(),
            layer: "process".into(),
            health_state: classify_health(err_pct, p95),
            request_rate_rps: round_metric(rps),
            error_rate_pct: round_metric(err_pct),
            p95_latency_ms: round_metric(p95),
            span_count: count,
            error_count: err_cnt,
        });

        vertical_edges.push(SmartscapeEdge {
            source: svc_id,
            target: proc_id.clone(),
            relation: "runs_on_process".into(),
            caller_service: None,
            callee_service: None,
            call_count: count,
            request_rate_rps: round_metric(rps),
            error_rate_pct: round_metric(err_pct),
            p50_latency_ms: round_metric(p50),
            p95_latency_ms: round_metric(p95),
            p99_latency_ms: round_metric(p99),
        });

        vertical_edges.push(SmartscapeEdge {
            source: proc_id,
            target: host_id,
            relation: "runs_on_host".into(),
            caller_service: None,
            callee_service: None,
            call_count: count,
            request_rate_rps: round_metric(rps),
            error_rate_pct: round_metric(err_pct),
            p50_latency_ms: round_metric(p50),
            p95_latency_ms: round_metric(p95),
            p99_latency_ms: round_metric(p99),
        });
    }

    let mut hosts = Vec::new();
    for (host_name, (mut durs, err_cnt)) in host_buckets {
        let count = durs.len() as u64;
        let rps = (count as f64) / win_f64;
        let err_pct = if count > 0 {
            (err_cnt as f64 * 100.0) / (count as f64)
        } else {
            0.0
        };
        let p95 = percentile(&mut durs, 0.95);
        let default_arch = if host_name.contains("riscv64") {
            "riscv64gc".to_string()
        } else {
            "x86_64".to_string()
        };
        let (arch, cpu_cluster, vlen_bits) =
            host_meta
                .get(&host_name)
                .cloned()
                .unwrap_or((default_arch, None, None));

        hosts.push(SmartscapeHostNode {
            id: format!("host:{host_name}"),
            name: host_name,
            arch,
            cpu_cluster,
            vlen_bits,
            layer: "host".into(),
            health_state: classify_health(err_pct, p95),
            request_rate_rps: round_metric(rps),
            error_rate_pct: round_metric(err_pct),
            p95_latency_ms: round_metric(p95),
            span_count: count,
            error_count: err_cnt,
        });
    }

    // Aggregate parent -> child service call edges
    let mut call_buckets: BTreeMap<(String, String), (Vec<f64>, u64)> = BTreeMap::new();
    for sp in &all_spans {
        if let Some(parent_id) = &sp.parent_span_id {
            if !parent_id.is_empty() {
                if let Some(caller_svc) = span_lookup.get(&(sp.trace_id.clone(), parent_id.clone()))
                {
                    let entry = call_buckets
                        .entry((caller_svc.clone(), sp.service_name.clone()))
                        .or_insert_with(|| (Vec::new(), 0));
                    entry.0.push(sp.duration_ms);
                    if sp.is_error {
                        entry.1 += 1;
                    }
                }
            }
        }
    }

    let mut edges = Vec::new();
    for ((caller, callee), (mut durs, err_cnt)) in call_buckets {
        let count = durs.len() as u64;
        let rps = (count as f64) / win_f64;
        let err_pct = if count > 0 {
            (err_cnt as f64 * 100.0) / (count as f64)
        } else {
            0.0
        };
        let p50 = percentile(&mut durs, 0.50);
        let p95 = percentile(&mut durs, 0.95);
        let p99 = percentile(&mut durs, 0.99);
        edges.push(SmartscapeEdge {
            source: format!("svc:{caller}"),
            target: format!("svc:{callee}"),
            relation: "calls".into(),
            caller_service: Some(caller),
            callee_service: Some(callee),
            call_count: count,
            request_rate_rps: round_metric(rps),
            error_rate_pct: round_metric(err_pct),
            p50_latency_ms: round_metric(p50),
            p95_latency_ms: round_metric(p95),
            p99_latency_ms: round_metric(p99),
        });
    }
    edges.extend(vertical_edges);

    let generated_at_ms = if anchor_ts > 0 {
        anchor_ts / 1_000_000
    } else {
        chrono::Utc::now().timestamp_millis()
    };

    Ok(SmartscapeTopology {
        window_secs: bounded_window,
        generated_at_ms,
        services,
        processes,
        hosts,
        edges,
    })
}

/// Evaluates deterministic SLO rules (latency p95 breach, error rate breach, canary taint,
/// heartbeat staleness, benchmark regression, and flaky test spikes) and returns sanitized
/// [`ProblemCard`] items with `root_cause_trace_id` deep-links (`M6.2`, `#33`–`#35`).
pub fn evaluate_deterministic_problems(
    store: &HotDuckDbStore,
    window_secs: u64,
    now_unix_nano: Option<i64>,
) -> Result<ProblemsFeedResponse, MuObserveError> {
    let bounded_window = window_secs.clamp(1, 604_800);
    let redactor = PrivacyRedactor::new();
    let topology = compute_smartscape_topology(store, bounded_window, now_unix_nano)?;
    let conn = store.lock_conn()?;

    let anchor_ts: i64 = match now_unix_nano {
        Some(ts) => ts,
        None => {
            let max_span: i64 = conn
                .query_row(
                    "SELECT COALESCE(MAX(end_time_unix_nano), 0) FROM v_traces",
                    [],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            let max_log: i64 = conn
                .query_row(
                    "SELECT COALESCE(MAX(timestamp_unix_nano), 0) FROM v_logs",
                    [],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            max_span.max(max_log)
        }
    };
    let cutoff_ts = if anchor_ts > 0 {
        anchor_ts.saturating_sub((bounded_window as i64).saturating_mul(1_000_000_000))
    } else {
        0
    };
    let detected_at_ms = if anchor_ts > 0 {
        anchor_ts / 1_000_000
    } else {
        chrono::Utc::now().timestamp_millis()
    };

    let mut problems = Vec::new();

    // 1 & 2. Evaluate Latency p95 breach (> 250 ms) and Error rate breach (> 5%) per service
    for svc in &topology.services {
        if svc.p95_latency_ms > 250.0 {
            let root_trace = find_slowest_trace_for_service(&conn, &svc.name, cutoff_ts);
            problems.push(ProblemCard {
                problem_id: format!("PROB-LATENCY-{}", svc.name),
                title: format!("SLO Latency p95 Breach on {}", svc.name),
                severity: if svc.p95_latency_ms > 500.0 {
                    "critical".into()
                } else {
                    "warning".into()
                },
                status: "OPEN".into(),
                category: "latency_p95_breach".into(),
                impacted_entity: svc.name.clone(),
                slo_metric: format!(
                    "p95_latency_ms={:.2}ms (threshold=250.00ms)",
                    svc.p95_latency_ms
                ),
                root_cause_trace_id: root_trace,
                artifact_digest: None,
                detected_at_ms,
                summary: redactor.redact_str(&format!(
                    "Service '{}' p95 span latency reached {:.2} ms across {} spans",
                    svc.name, svc.p95_latency_ms, svc.span_count
                )),
            });
        }

        if svc.error_rate_pct > 5.0 || svc.error_count > 0 {
            let root_trace = find_error_trace_for_service(&conn, &svc.name, cutoff_ts)
                .or_else(|| find_slowest_trace_for_service(&conn, &svc.name, cutoff_ts));
            problems.push(ProblemCard {
                problem_id: format!("PROB-ERRORS-{}", svc.name),
                title: format!("SLO Error Rate Breach on {}", svc.name),
                severity: if svc.error_rate_pct >= 10.0 {
                    "critical".into()
                } else {
                    "error".into()
                },
                status: "OPEN".into(),
                category: "error_rate_breach".into(),
                impacted_entity: svc.name.clone(),
                slo_metric: format!(
                    "error_rate_pct={:.2}% ({}/{} spans)",
                    svc.error_rate_pct, svc.error_count, svc.span_count
                ),
                root_cause_trace_id: root_trace,
                artifact_digest: None,
                detected_at_ms,
                summary: redactor.redact_str(&format!(
                    "Service '{}' recorded {} error spans ({:.2}% error rate)",
                    svc.name, svc.error_count, svc.error_rate_pct
                )),
            });
        }
    }

    // 3. Evaluate Canary Taint / Crash Telemetry from v_logs
    if let Ok(mut crash_stmt) = conn.prepare(
        r#"
        SELECT service_name, trace_id, body, timestamp_unix_nano
        FROM v_logs
        WHERE timestamp_unix_nano >= ?1
          AND (
              severity_number >= 21
              OR UPPER(severity_text) IN ('FATAL', 'CRITICAL')
              OR LOWER(body) LIKE '%panic%'
              OR LOWER(body) LIKE '%sigsegv%'
              OR LOWER(body) LIKE '%sigill%'
              OR LOWER(body) LIKE '%crash%'
              OR LOWER(body) LIKE '%taint%'
          )
        ORDER BY timestamp_unix_nano DESC
        LIMIT 20
        "#,
    ) {
        let mut seen_canary_svcs = BTreeMap::new();
        if let Ok(rows) = crash_stmt.query_map(params![cutoff_ts], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
            ))
        }) {
            for row in rows.flatten() {
                let clean_svc = redactor.redact_str(&row.0);
                seen_canary_svcs
                    .entry(clean_svc)
                    .or_insert((row.1, row.2, row.3));
            }
        }

        for (svc_name, (trace_id, body, ts_ns)) in seen_canary_svcs {
            let clean_body = redactor.redact_str(&body);
            let trace_opt = if trace_id.trim().is_empty() {
                find_slowest_trace_for_service(&conn, &svc_name, cutoff_ts)
            } else {
                Some(trace_id)
            };
            problems.push(ProblemCard {
                problem_id: format!("PROB-CANARY-{svc_name}"),
                title: format!("Canary Taint / Crash Telemetry on {svc_name}"),
                severity: "critical".into(),
                status: "OPEN".into(),
                category: "canary_taint".into(),
                impacted_entity: svc_name.clone(),
                slo_metric: "crash_telemetry_count >= 1 (taint_recommended=true)".into(),
                root_cause_trace_id: trace_opt,
                artifact_digest: Some("sha256:canary".into()),
                detected_at_ms: ts_ns / 1_000_000,
                summary: clean_body,
            });
        }
    }

    // 4. Evaluate Heartbeat Staleness across nodes when anchor_ts > 0
    if anchor_ts > 0 {
        let staleness_threshold_ns: i64 = 300_000_000_000; // 5 minutes
        if let Ok(mut hb_stmt) = conn.prepare(
            r#"
            SELECT node_id, MAX(end_time_unix_nano) AS last_seen_ns
            FROM v_traces
            GROUP BY node_id
            "#,
        ) {
            if let Ok(rows) =
                hb_stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
            {
                for (raw_node, last_seen_ns) in rows.flatten() {
                    let lag_ns = anchor_ts.saturating_sub(last_seen_ns);
                    if lag_ns > staleness_threshold_ns {
                        let clean_node = redactor.redact_host(&raw_node);
                        let last_trace: Option<String> = conn
                            .query_row(
                                "SELECT trace_id FROM v_traces WHERE node_id = ?1 ORDER BY end_time_unix_nano DESC LIMIT 1",
                                params![raw_node],
                                |r| r.get(0),
                            )
                            .ok();
                        let lag_secs = lag_ns / 1_000_000_000;
                        problems.push(ProblemCard {
                            problem_id: format!("PROB-HEARTBEAT-{clean_node}"),
                            title: format!("Node Heartbeat Staleness on {clean_node}"),
                            severity: "warning".into(),
                            status: "OPEN".into(),
                            category: "heartbeat_staleness".into(),
                            impacted_entity: clean_node.clone(),
                            slo_metric: format!("heartbeat_lag_secs={lag_secs}s (threshold=300s)"),
                            root_cause_trace_id: last_trace,
                            artifact_digest: None,
                            detected_at_ms,
                            summary: format!(
                                "Host '{clean_node}' last reported telemetry {lag_secs}s ago"
                            ),
                        });
                    }
                }
            }
        }
    }

    // 5. Evaluate hardware-stratified benchmark regressions and 30-day flaky tests (#34)
    let mut bench_repos = Vec::new();
    if let Ok(mut b_stmt) = conn.prepare(
        "SELECT DISTINCT repo_key, commit_sha FROM v_benchmarks ORDER BY timestamp_unix_nano DESC LIMIT 10",
    ) {
        if let Ok(rows) = b_stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        }) {
            for pair in rows.flatten() {
                if !bench_repos.iter().any(|(rk, _)| rk == &pair.0) {
                    bench_repos.push(pair);
                }
            }
        }
    }
    let mut test_repos = Vec::new();
    if let Ok(mut t_stmt) = conn
        .prepare("SELECT DISTINCT repo_key FROM v_tests ORDER BY timestamp_unix_nano DESC LIMIT 10")
    {
        if let Ok(rows) = t_stmt.query_map([], |r| r.get::<_, String>(0)) {
            for rk in rows.flatten() {
                if !test_repos.contains(&rk) {
                    test_repos.push(rk);
                }
            }
        }
    }
    drop(conn);

    for (repo_key, latest_commit) in bench_repos {
        if let Ok(items) = evaluate_benchmark_regressions(
            store,
            &repo_key,
            &latest_commit,
            "main",
            5.0,
            DEFAULT_MAX_MAD_Z_SCORE,
        ) {
            for reg in items.into_iter().filter(|i| i.regressed) {
                let clean_repo = redactor.redact_str(&repo_key);
                problems.push(ProblemCard {
                    problem_id: format!("PROB-BENCH-{}-{}", reg.crate_name, reg.bench_name),
                    title: format!(
                        "Benchmark Regression in {}::{} ({})",
                        reg.crate_name, reg.bench_name, reg.cpu_cluster
                    ),
                    severity: "error".into(),
                    status: "OPEN".into(),
                    category: "benchmark_regression".into(),
                    impacted_entity: clean_repo,
                    slo_metric: format!(
                        "delta_pct=+{:.1}%, mad_z_score={:.2} ({} VLEN={})",
                        reg.delta_pct, reg.mad_z_score, reg.cpu_cluster, reg.vlen_bits
                    ),
                    root_cause_trace_id: None,
                    artifact_digest: Some(latest_commit.clone()),
                    detected_at_ms,
                    summary: format!(
                        "Benchmark '{}' on {} regressed from {:.1} ns to {:.1} ns (+{:.1}%)",
                        reg.bench_name,
                        reg.cpu_cluster,
                        reg.baseline_median_ns,
                        reg.candidate_ns,
                        reg.delta_pct
                    ),
                });
            }
        }
    }

    for repo_key in test_repos {
        if let Ok(flaky_items) = compute_test_flakiness(store, &repo_key, None, 30, now_unix_nano) {
            for item in flaky_items
                .into_iter()
                .filter(|t| t.flip_flop_count > 0 || !t.status.eq_ignore_ascii_case("ok"))
            {
                let clean_repo = redactor.redact_str(&repo_key);
                problems.push(ProblemCard {
                    problem_id: format!("PROB-TEST-{}-{}", item.crate_name, item.test_name),
                    title: format!(
                        "Flaky / Failing Test {}::{}",
                        item.crate_name, item.test_name
                    ),
                    severity: if item.status.eq_ignore_ascii_case("ok") {
                        "warning".into()
                    } else {
                        "error".into()
                    },
                    status: "OPEN".into(),
                    category: "test_flakiness".into(),
                    impacted_entity: clean_repo,
                    slo_metric: format!(
                        "flakiness_pct={:.1}%, flip_flops={}",
                        item.flakiness_pct, item.flip_flop_count
                    ),
                    root_cause_trace_id: None,
                    artifact_digest: None,
                    detected_at_ms,
                    summary: redactor.redact_str(
                        item.failure_summary
                            .as_deref()
                            .unwrap_or("Test exhibited pass/fail flip-flops in 30-day window"),
                    ),
                });
            }
        }
    }

    let open_count = problems.len();
    Ok(ProblemsFeedResponse {
        window_secs: bounded_window,
        open_count,
        total: open_count,
        problems,
    })
}

fn find_slowest_trace_for_service(
    conn: &duckdb::Connection,
    sanitized_service: &str,
    cutoff_ts: i64,
) -> Option<String> {
    conn.query_row(
        r#"
        SELECT trace_id
        FROM v_traces
        WHERE service_name = ?1
          AND end_time_unix_nano >= ?2
        ORDER BY duration_ns DESC
        LIMIT 1
        "#,
        params![sanitized_service, cutoff_ts],
        |r| r.get(0),
    )
    .ok()
}

fn find_error_trace_for_service(
    conn: &duckdb::Connection,
    sanitized_service: &str,
    cutoff_ts: i64,
) -> Option<String> {
    conn.query_row(
        r#"
        SELECT trace_id
        FROM v_traces
        WHERE service_name = ?1
          AND end_time_unix_nano >= ?2
          AND UPPER(status_code) = 'ERROR'
        ORDER BY end_time_unix_nano DESC
        LIMIT 1
        "#,
        params![sanitized_service, cutoff_ts],
        |r| r.get(0),
    )
    .ok()
}

fn classify_health(error_rate_pct: f64, p95_latency_ms: f64) -> String {
    if error_rate_pct >= 10.0 || p95_latency_ms > 500.0 {
        "critical".into()
    } else if error_rate_pct > 0.0 || p95_latency_ms > 250.0 {
        "degraded".into()
    } else {
        "healthy".into()
    }
}

fn percentile(values: &mut [f64], q: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = values.len();
    let idx = ((n as f64 - 1.0) * q.clamp(0.0, 1.0)).round() as usize;
    values[idx.min(n - 1)]
}

fn round_metric(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use muobserve_ipc::{OtelLogEntry, OtelSpanEntry};

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_smartscape_3_layer_topology_and_problems_detection() {
        let store = HotDuckDbStore::open_in_memory().expect("open in memory");
        let now_ts = 1_700_000_100_000_000_000i64;

        // Parent span on entrance.lab.local calling child span on pey-wail-deu.lab.local
        store
            .insert_spans_batch(&[
                OtelSpanEntry {
                    trace_id: "trace-call-1".into(),
                    span_id: "span-root".into(),
                    parent_span_id: None,
                    service_name: "action-runner-controller".into(),
                    node_id: "entrance.lab.local".into(),
                    span_name: "dispatch.stage".into(),
                    span_kind: "CLIENT".into(),
                    start_time_unix_nano: now_ts - 600_000_000,
                    end_time_unix_nano: now_ts,
                    duration_ns: 600_000_000, // 600 ms -> triggers latency_p95_breach
                    status_code: "OK".into(),
                    status_message: None,
                    attributes_json: "{}".into(),
                },
                OtelSpanEntry {
                    trace_id: "trace-call-1".into(),
                    span_id: "span-child".into(),
                    parent_span_id: Some("span-root".into()),
                    service_name: "model-runner".into(), // private service stays visible!
                    node_id: "pey-wail-deu.lab.local".into(),
                    span_name: "k3.execute".into(),
                    span_kind: "SERVER".into(),
                    start_time_unix_nano: now_ts - 550_000_000,
                    end_time_unix_nano: now_ts - 50_000_000,
                    duration_ns: 500_000_000,
                    status_code: "ERROR".into(), // triggers error_rate_breach
                    status_message: Some("failed on 192.168.1.117".into()),
                    attributes_json: "{}".into(),
                },
            ])
            .unwrap();

        store
            .insert_logs_batch(&[OtelLogEntry {
                timestamp_unix_nano: now_ts - 100_000_000,
                trace_id: "trace-call-1".into(),
                span_id: "span-child".into(),
                severity_number: 21,
                severity_text: "FATAL".into(),
                service_name: "model-runner".into(),
                node_id: "pey-wail-deu.lab.local".into(),
                body: "worker panic at /var/lib/muobserve/secret.db on 192.168.1.117".into(),
                attributes_json: "{}".into(),
                job_id: None,
                stage_id: None,
            }])
            .unwrap();

        let topo = compute_smartscape_topology(&store, 3600, Some(now_ts)).unwrap();
        assert_eq!(topo.services.len(), 2);
        assert_eq!(topo.processes.len(), 2);
        assert_eq!(topo.hosts.len(), 2);

        // Verify internal hostnames were aliased to node-a and worker-riscv64
        let host_names: Vec<&str> = topo.hosts.iter().map(|h| h.name.as_str()).collect();
        assert!(host_names.contains(&"node-a"));
        assert!(host_names.contains(&"worker-riscv64"));
        assert!(!host_names.contains(&"entrance"));
        assert!(!host_names.contains(&"pey-wail-deu"));

        // Verify call edge exists between action-runner-controller -> model-runner
        assert!(topo.edges.iter().any(|e| {
            e.relation == "calls"
                && e.caller_service.as_deref() == Some("action-runner-controller")
                && e.callee_service.as_deref() == Some("model-runner")
        }));

        let problems = evaluate_deterministic_problems(&store, 3600, Some(now_ts)).unwrap();
        assert!(problems.open_count >= 3);
        assert!(problems
            .problems
            .iter()
            .any(|p| p.category == "latency_p95_breach"
                && p.root_cause_trace_id.as_deref() == Some("trace-call-1")));
        assert!(problems
            .problems
            .iter()
            .any(|p| p.category == "error_rate_breach"
                && p.root_cause_trace_id.as_deref() == Some("trace-call-1")));
        assert!(problems
            .problems
            .iter()
            .any(|p| p.category == "canary_taint"
                && p.root_cause_trace_id.as_deref() == Some("trace-call-1")));

        let json_str = serde_json::to_string(&problems).unwrap();
        assert!(!json_str.contains("pey-wail-deu"));
        assert!(!json_str.contains("192.168.1.117"));
        assert!(!json_str.contains("/var/lib/"));
    }
}
