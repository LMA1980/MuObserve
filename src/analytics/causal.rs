// SPDX-License-Identifier: AGPL-3.0-only
//! AI-Powered Causal Root-Cause Engine for `mu-observable-hub` (Dynatrace replacement).
//!
//! Evaluates dynamic latency anomaly baselines via Median Absolute Deviation (MAD) Z-scores,
//! decomposes trace duration into span self-time vs child-time, traverses the distributed
//! call dependency graph to isolate the originating root-cause service, and correlates
//! contemporaneous error logs from `v_logs`.

use crate::error::MuObserveError;
use crate::server::sanitize::PrivacyRedactor;
use crate::storage::HotDuckDbStore;
use duckdb::params;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Causal root-cause problem attribution card.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CausalProblemCard {
    pub problem_id: String,
    pub title: String,
    pub severity: String,
    pub status: String,
    pub category: String,
    pub impacted_entity: String,
    pub slo_metric: String,
    pub root_cause_service: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_cause_trace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_cause_span_id: Option<String>,
    pub causal_chain: Vec<String>,
    pub confidence_score: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_cause_error_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_digest: Option<String>,
    pub detected_at_ms: i64,
    pub summary: String,
}

/// Problems feed response matching API contracts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CausalProblemsFeedResponse {
    pub window_secs: u64,
    pub open_count: usize,
    pub total: usize,
    pub problems: Vec<CausalProblemCard>,
}

#[derive(Debug, Clone)]
struct TraceSpanNode {
    span_id: String,
    parent_span_id: Option<String>,
    service_name: String,
    _start_time_unix_nano: i64,
    _end_time_unix_nano: i64,
    duration_ns: u64,
    status_code: String,
}

/// Computes causal root-cause problems across the active trace and log telemetry.
pub fn compute_causal_problems(
    store: &HotDuckDbStore,
    window_secs: u64,
    now_unix_nano: Option<i64>,
) -> Result<Vec<CausalProblemCard>, MuObserveError> {
    let bounded_window = window_secs.clamp(1, 604_800);
    let redactor = PrivacyRedactor::new();
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
            let max_ts = max_span.max(max_log);
            if max_ts > 0 {
                max_ts
            } else {
                chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
            }
        }
    };

    let cutoff_ts = anchor_ts.saturating_sub((bounded_window as i64) * 1_000_000_000);
    let detected_at_ms = if anchor_ts > 0 {
        anchor_ts / 1_000_000
    } else {
        chrono::Utc::now().timestamp_millis()
    };

    let mut stmt = conn.prepare(
        r#"
        SELECT service_name, duration_ns, UPPER(status_code)
        FROM v_traces
        WHERE start_time_unix_nano >= ?1
        "#,
    )?;

    struct ServiceStats {
        durations: Vec<f64>,
        error_count: u64,
    }

    let mut service_map: HashMap<String, ServiceStats> = HashMap::new();
    let mut rows = stmt.query(params![cutoff_ts])?;
    while let Some(row) = rows.next()? {
        let raw_svc: String = row.get(0)?;
        let svc = redactor.redact_str(&raw_svc);
        let duration_ns: i64 = row.get(1)?;
        let status: String = row.get(2)?;

        let entry = service_map.entry(svc).or_insert_with(|| ServiceStats {
            durations: Vec::new(),
            error_count: 0,
        });
        entry
            .durations
            .push((duration_ns.max(0) as f64) / 1_000_000.0);
        if status == "ERROR" {
            entry.error_count += 1;
        }
    }

    let mut problems = Vec::new();
    let mut processed_services = HashSet::new();

    for (service_name, stats) in &service_map {
        if stats.durations.is_empty() {
            continue;
        }
        let total = stats.durations.len();
        let error_rate_pct = (stats.error_count as f64 * 100.0) / (total as f64);
        let (median, mad) = compute_median_and_mad(&stats.durations);
        let p95 = compute_percentile(&stats.durations, 0.95);
        let mad_z = if mad > 1e-6 {
            0.6745 * (p95 - median) / mad
        } else {
            0.0
        };

        // Anomaly threshold: MAD Z-score > 3.0 OR error rate > 5.0% OR errors > 0
        let is_anomaly = mad_z > 3.0 || error_rate_pct > 5.0 || stats.error_count > 0;
        if !is_anomaly || !processed_services.insert(service_name.clone()) {
            continue;
        }

        // Find representative anomalous trace for this service
        let trace_id_opt: Option<String> = if stats.error_count > 0 {
            conn.query_row(
                r#"
                SELECT trace_id
                FROM v_traces
                WHERE service_name = ?1 AND start_time_unix_nano >= ?2 AND UPPER(status_code) = 'ERROR'
                ORDER BY start_time_unix_nano DESC LIMIT 1
                "#,
                params![service_name, cutoff_ts],
                |r| r.get(0),
            )
            .ok()
        } else {
            conn.query_row(
                r#"
                SELECT trace_id
                FROM v_traces
                WHERE service_name = ?1 AND start_time_unix_nano >= ?2
                ORDER BY duration_ns DESC LIMIT 1
                "#,
                params![service_name, cutoff_ts],
                |r| r.get(0),
            )
            .ok()
        };

        if let Some(trace_id) = trace_id_opt {
            // Fetch all spans in this trace to assemble call tree and compute self-times
            let mut span_stmt = conn.prepare(
                r#"
                SELECT span_id, parent_span_id, service_name, start_time_unix_nano, end_time_unix_nano, duration_ns, UPPER(status_code)
                FROM v_traces
                WHERE trace_id = ?1
                ORDER BY start_time_unix_nano ASC
                "#,
            )?;
            let mut span_nodes = Vec::new();
            let mut span_rows = span_stmt.query(params![trace_id])?;
            while let Some(r) = span_rows.next()? {
                let raw_s: String = r.get(2)?;
                span_nodes.push(TraceSpanNode {
                    span_id: r.get(0)?,
                    parent_span_id: r.get(1)?,
                    service_name: redactor.redact_str(&raw_s),
                    _start_time_unix_nano: r.get(3)?,
                    _end_time_unix_nano: r.get(4)?,
                    duration_ns: r.get::<_, i64>(5)?.max(0) as u64,
                    status_code: r.get(6)?,
                });
            }

            let (root_service, root_span_id, causal_chain, self_time_ratio) =
                traverse_causal_tree(&span_nodes, service_name);

            // Correlate with error logs from v_logs
            let mut root_err_msg: Option<String> = None;
            if let Some(ref s_id) = root_span_id {
                root_err_msg = conn
                    .query_row(
                        r#"
                        SELECT body
                        FROM v_logs
                        WHERE trace_id = ?1 AND span_id = ?2
                          AND (severity_number >= 17 OR UPPER(severity_text) LIKE '%ERR%' OR UPPER(severity_text) LIKE '%FATAL%')
                        ORDER BY timestamp_unix_nano DESC LIMIT 1
                        "#,
                        params![trace_id, s_id],
                        |r| r.get(0),
                    )
                    .ok();
            }
            if root_err_msg.is_none() {
                root_err_msg = conn
                    .query_row(
                        r#"
                        SELECT body
                        FROM v_logs
                        WHERE trace_id = ?1 AND service_name = ?2
                          AND (severity_number >= 17 OR UPPER(severity_text) LIKE '%ERR%' OR UPPER(severity_text) LIKE '%FATAL%')
                        ORDER BY timestamp_unix_nano DESC LIMIT 1
                        "#,
                        params![trace_id, root_service],
                        |r| r.get(0),
                    )
                    .ok();
            }

            let root_err_msg = root_err_msg.map(|m| redactor.redact_str(&m));

            let mut confidence = 0.50;
            if self_time_ratio > 0.50 {
                confidence += (self_time_ratio - 0.50) * 0.50;
            }
            if root_err_msg.is_some() {
                confidence += 0.25;
            }
            let confidence_score = confidence.clamp(0.50, 1.00);

            let severity = if mad_z > 5.0 || error_rate_pct > 20.0 || stats.error_count > 0 {
                "critical".to_string()
            } else {
                "warning".to_string()
            };
            let category = if stats.error_count > 0 || error_rate_pct > 5.0 {
                "error_rate_spike".to_string()
            } else {
                "latency_regression".to_string()
            };

            let slo_metric = redactor.redact_str(&if error_rate_pct > 0.0 {
                format!(
                    "error_rate={:.1}% (errors={})",
                    error_rate_pct, stats.error_count
                )
            } else {
                format!(
                    "p95={:.1}ms (mad_z={:.2}, baseline={:.1}ms)",
                    p95, mad_z, median
                )
            });

            let summary = redactor.redact_str(&format!(
                "Service '{}' degraded along [{}] with root cause in '{}' (confidence: {:.0}%).{}",
                service_name,
                causal_chain.join(" -> "),
                root_service,
                confidence_score * 100.0,
                root_err_msg
                    .as_deref()
                    .map(|e| format!(" Correlated error: {}", e))
                    .unwrap_or_default()
            ));

            let title = redactor.redact_str(&format!(
                "Causal Degradation on {}: Root Cause in {}",
                service_name, root_service
            ));

            problems.push(CausalProblemCard {
                problem_id: format!("PROB-CAUSAL-{}-{}", service_name, root_service),
                title,
                severity,
                status: "OPEN".into(),
                category,
                impacted_entity: service_name.clone(),
                slo_metric,
                root_cause_service: root_service,
                root_cause_trace_id: Some(trace_id),
                root_cause_span_id: root_span_id,
                causal_chain,
                confidence_score,
                root_cause_error_message: root_err_msg,
                artifact_digest: None,
                detected_at_ms,
                summary,
            });
        }
    }

    Ok(problems)
}

fn traverse_causal_tree(
    spans: &[TraceSpanNode],
    impacted_service: &str,
) -> (String, Option<String>, Vec<String>, f64) {
    if spans.is_empty() {
        return (
            impacted_service.to_string(),
            None,
            vec![impacted_service.to_string()],
            1.0,
        );
    }

    let mut span_map = HashMap::new();
    let mut children_map: HashMap<usize, Vec<usize>> = HashMap::new();
    for (i, s) in spans.iter().enumerate() {
        span_map.insert(s.span_id.as_str(), i);
    }
    for (i, s) in spans.iter().enumerate() {
        if let Some(ref pid) = s.parent_span_id {
            if let Some(&p_idx) = span_map.get(pid.as_str()) {
                children_map.entry(p_idx).or_default().push(i);
            }
        }
    }

    // Compute self-time = duration - sum(children duration)
    let mut self_times = vec![0u64; spans.len()];
    for (i, s) in spans.iter().enumerate() {
        let child_sum: u64 = children_map
            .get(&i)
            .map(|kids| kids.iter().map(|&k| spans[k].duration_ns).sum())
            .unwrap_or(0);
        self_times[i] = s.duration_ns.saturating_sub(child_sum);
    }

    // Find starting entrypoint: first span matching impacted_service, or span 0
    let start_idx = spans
        .iter()
        .position(|s| s.service_name == impacted_service)
        .unwrap_or(0);

    let mut curr_idx = start_idx;
    let mut causal_chain = vec![spans[curr_idx].service_name.clone()];
    let mut visited = HashSet::new();
    visited.insert(curr_idx);

    // Walk call tree down along error or dominant latency path
    while let Some(kids) = children_map.get(&curr_idx) {
        if kids.is_empty() {
            break;
        }

        // First priority: child with ERROR status
        let error_kid = kids
            .iter()
            .find(|&&k| spans[k].status_code == "ERROR" && !visited.contains(&k));
        if let Some(&ek) = error_kid {
            visited.insert(ek);
            if spans[ek].service_name != spans[curr_idx].service_name {
                causal_chain.push(spans[ek].service_name.clone());
            }
            curr_idx = ek;
            continue;
        }

        // Second priority: child with significant duration (> 40% of parent duration)
        let max_kid = kids
            .iter()
            .filter(|&&k| !visited.contains(&k))
            .max_by_key(|&&k| spans[k].duration_ns);

        if let Some(&mk) = max_kid {
            let parent_dur = spans[curr_idx].duration_ns.max(1);
            if spans[mk].duration_ns * 10 >= parent_dur * 4 {
                // Child consumed significant chunk of time, descend
                visited.insert(mk);
                if spans[mk].service_name != spans[curr_idx].service_name {
                    causal_chain.push(spans[mk].service_name.clone());
                }
                curr_idx = mk;
                continue;
            }
        }

        // Bottleneck remains in curr_idx
        break;
    }

    let root_span = &spans[curr_idx];
    let self_time = self_times[curr_idx];
    let self_time_ratio = (self_time as f64) / (root_span.duration_ns.max(1) as f64);

    (
        root_span.service_name.clone(),
        Some(root_span.span_id.clone()),
        causal_chain,
        self_time_ratio,
    )
}

fn compute_median_and_mad(samples: &[f64]) -> (f64, f64) {
    if samples.is_empty() {
        return (0.0, 0.0);
    }
    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mid = sorted.len() / 2;
    let median = if sorted.len() % 2 == 1 {
        sorted[mid]
    } else {
        (sorted[mid - 1] + sorted[mid]) / 2.0
    };

    let mut devs: Vec<f64> = sorted.iter().map(|v| (v - median).abs()).collect();
    devs.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mad = devs[devs.len() / 2];
    (median, mad)
}

fn compute_percentile(samples: &[f64], pct: f64) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let idx = (((sorted.len() as f64) * pct).ceil() as usize).saturating_sub(1);
    sorted[idx.min(sorted.len() - 1)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use mu_observable_ipc::{OtelLogEntry, OtelSpanEntry};

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_causal_root_cause_analysis_multi_hop_waterfall() {
        let store = HotDuckDbStore::open_in_memory().expect("open store");
        let now = 1_700_000_000_000_000_000i64;
        let trace_id = "trace-causal-test-01";

        // Entrypoint: Gateway (duration 5.0s, child 4.8s)
        let s1 = OtelSpanEntry {
            trace_id: trace_id.into(),
            span_id: "span-gw-1".into(),
            parent_span_id: None,
            service_name: "mu-ingress".into(),
            node_id: "node-a".into(),
            span_name: "GET /api/checkout".into(),
            span_kind: "SERVER".into(),
            start_time_unix_nano: now,
            end_time_unix_nano: now + 5_000_000_000,
            duration_ns: 5_000_000_000,
            status_code: "ERROR".into(),
            status_message: Some("Downstream failure".into()),
            attributes_json: "{}".into(),
        };

        // Hop 2: Checkout Service (duration 4.8s, child 4.6s)
        let s2 = OtelSpanEntry {
            trace_id: trace_id.into(),
            span_id: "span-chk-2".into(),
            parent_span_id: Some("span-gw-1".into()),
            service_name: "checkout-service".into(),
            node_id: "node-a".into(),
            span_name: "POST /internal/charge".into(),
            span_kind: "INTERNAL".into(),
            start_time_unix_nano: now + 100_000_000,
            end_time_unix_nano: now + 4_900_000_000,
            duration_ns: 4_800_000_000,
            status_code: "ERROR".into(),
            status_message: Some("Database query failed".into()),
            attributes_json: "{}".into(),
        };

        // Hop 3: Payment DB (duration 4.6s, self-time 4.6s, ERROR)
        let s3 = OtelSpanEntry {
            trace_id: trace_id.into(),
            span_id: "span-db-3".into(),
            parent_span_id: Some("span-chk-2".into()),
            service_name: "payment-db".into(),
            node_id: "node-b".into(),
            span_name: "SELECT payment_state".into(),
            span_kind: "CLIENT".into(),
            start_time_unix_nano: now + 200_000_000,
            end_time_unix_nano: now + 4_800_000_000,
            duration_ns: 4_600_000_000,
            status_code: "ERROR".into(),
            status_message: Some("Connection reset by peer".into()),
            attributes_json: "{}".into(),
        };

        // Correlated error log on payment-db
        let log = OtelLogEntry {
            timestamp_unix_nano: now + 4_700_000_000,
            trace_id: trace_id.into(),
            span_id: "span-db-3".into(),
            severity_number: 17,
            severity_text: "ERROR".into(),
            body: "FATAL: Connection pool exhausted, query timed out after 4600ms".into(),
            service_name: "payment-db".into(),
            node_id: "node-b".into(),
            job_id: None,
            stage_id: None,
            attributes_json: "{}".into(),
        };

        store
            .insert_spans_batch(&[s1, s2, s3])
            .expect("insert spans");
        store.insert_logs_batch(&[log]).expect("insert logs");

        let problems = compute_causal_problems(&store, 300, Some(now + 6_000_000_000))
            .expect("compute causal problems");

        assert!(
            !problems.is_empty(),
            "expected causal problem to be detected"
        );
        let prob = problems
            .iter()
            .find(|p| p.impacted_entity == "mu-ingress" || p.impacted_entity == "checkout-service")
            .expect("problem found for entrypoint");

        assert_eq!(prob.root_cause_service, "payment-db");
        assert_eq!(prob.root_cause_span_id.as_deref(), Some("span-db-3"));
        assert!(prob.causal_chain.contains(&"payment-db".to_string()));
        assert!(prob.confidence_score >= 0.75);
        assert!(prob
            .root_cause_error_message
            .as_ref()
            .unwrap()
            .contains("Connection pool exhausted"));
    }
}
