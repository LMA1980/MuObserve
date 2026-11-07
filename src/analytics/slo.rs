use duckdb::params;
use mu_observable_ipc::{CanarySloAssertionRequest, CanarySloAssertionResponse};

use crate::error::MuObserveError;
use crate::storage::hot_duckdb::HotDuckDbStore;

/// Evaluates service SLOs during an A/B canary bake window (`bake_window_secs`) for
/// `MuConDe-controller`, checking error log counts, `p99` span latency (in milliseconds),
/// and crash/panic telemetry (`FATAL` severity or crash markers) on `node_id`.
pub fn evaluate_canary_slo(
    store: &HotDuckDbStore,
    req: &CanarySloAssertionRequest,
    now_unix_nano: Option<i64>,
) -> Result<CanarySloAssertionResponse, MuObserveError> {
    let conn = store.lock_conn()?;

    let anchor_ts: i64 = match now_unix_nano {
        Some(ts) => ts,
        None => {
            let max_log_ts: i64 = conn
                .query_row(
                    "SELECT COALESCE(MAX(timestamp_unix_nano), 0) FROM v_logs WHERE service_name = ?1",
                    params![req.service_name],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            let max_span_ts: i64 = conn
                .query_row(
                    "SELECT COALESCE(MAX(end_time_unix_nano), 0) FROM v_traces WHERE service_name = ?1",
                    params![req.service_name],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            max_log_ts.max(max_span_ts)
        }
    };

    let bake_secs = req.bake_window_secs.max(1);
    let bake_window_ns = (bake_secs as i64).saturating_mul(1_000_000_000);
    let cutoff_ts = anchor_ts.saturating_sub(bake_window_ns);
    let node_filter = if req.node_id.trim().is_empty() {
        None
    } else {
        Some(req.node_id.trim().to_string())
    };

    // Count ERROR/FATAL logs (severity_number >= 17 or severity_text IN ('ERROR', 'FATAL'))
    let error_log_count_i64: i64 = conn.query_row(
        r#"
        SELECT COUNT(*)
        FROM v_logs
        WHERE service_name = ?1
          AND (?2 IS NULL OR node_id = ?2)
          AND timestamp_unix_nano >= ?3
          AND (severity_number >= 17 OR UPPER(severity_text) IN ('ERROR', 'FATAL', 'CRITICAL'))
        "#,
        params![req.service_name, node_filter, cutoff_ts],
        |r| r.get(0),
    )?;

    // Detect crash/panic telemetry (FATAL severity >= 21 or crash/panic/SIGSEGV/SIGABRT in log body or attributes)
    let crash_count_i64: i64 = conn.query_row(
        r#"
        SELECT COUNT(*)
        FROM v_logs
        WHERE service_name = ?1
          AND (?2 IS NULL OR node_id = ?2)
          AND timestamp_unix_nano >= ?3
          AND (
              severity_number >= 21
              OR UPPER(severity_text) = 'FATAL'
              OR LOWER(body) LIKE '%panic%'
              OR LOWER(body) LIKE '%sigsegv%'
              OR LOWER(body) LIKE '%sigill%'
              OR LOWER(body) LIKE '%crash%'
          )
        "#,
        params![req.service_name, node_filter, cutoff_ts],
        |r| r.get(0),
    )?;

    // Gather span durations in the bake window to compute p99 latency in milliseconds
    let mut span_stmt = conn.prepare(
        r#"
        SELECT duration_ns, status_code
        FROM v_traces
        WHERE service_name = ?1
          AND (?2 IS NULL OR node_id = ?2)
          AND end_time_unix_nano >= ?3
        ORDER BY duration_ns ASC
        "#,
    )?;

    let span_rows = span_stmt
        .query_map(params![req.service_name, node_filter, cutoff_ts], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
        })?;

    let mut durations_ms = Vec::new();
    let mut error_spans = 0u32;
    for sr in span_rows {
        let (dur_ns, status) = sr?;
        durations_ms.push((dur_ns.max(0) as f64) / 1_000_000.0);
        if status.eq_ignore_ascii_case("ERROR") {
            error_spans = error_spans.saturating_add(1);
        }
    }

    let p99_latency_ms = compute_percentile(&mut durations_ms, 0.99);
    let error_log_count = (error_log_count_i64.max(0) as u32).saturating_add(error_spans);

    let mut breaches = Vec::new();
    if crash_count_i64 > 0 {
        breaches.push(format!("crash_telemetry_count ({crash_count_i64} > 0)"));
    }
    if error_log_count > req.max_error_logs {
        breaches.push(format!(
            "error_log_count ({error_log_count} > {})",
            req.max_error_logs
        ));
    }
    if req.max_p99_latency_ms > 0.0 && p99_latency_ms > req.max_p99_latency_ms {
        breaches.push(format!(
            "p99_latency_ms ({p99_latency_ms:.2} > {:.2})",
            req.max_p99_latency_ms
        ));
    }

    let healthy = breaches.is_empty();
    let taint_recommended = !healthy;
    let reason = if healthy {
        format!(
            "Canary digest '{}' on service '{}' passed SLOs (errors={error_log_count}, p99={p99_latency_ms:.2}ms)",
            req.candidate_digest, req.service_name
        )
    } else {
        format!(
            "Canary digest '{}' breached SLOs: {}",
            req.candidate_digest,
            breaches.join(", ")
        )
    };

    Ok(CanarySloAssertionResponse {
        request_id: req.request_id.clone(),
        healthy,
        error_log_count,
        p99_latency_ms,
        taint_recommended,
        reason,
    })
}

fn compute_percentile(sorted_or_unsorted: &mut [f64], q: f64) -> f64 {
    if sorted_or_unsorted.is_empty() {
        return 0.0;
    }
    sorted_or_unsorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = sorted_or_unsorted.len();
    let idx = ((n as f64 - 1.0) * q.clamp(0.0, 1.0)).round() as usize;
    sorted_or_unsorted[idx.min(n - 1)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use mu_observable_ipc::{OtelLogEntry, OtelSpanEntry};

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_canary_slo_evaluation_healthy_and_breach_taint_recommendation() {
        let store = HotDuckDbStore::open_in_memory().expect("open in memory");
        let now_ts = 1_700_000_100_000_000_000i64;

        // Healthy span (20 ms) and INFO log
        store
            .insert_spans_batch(&[OtelSpanEntry {
                trace_id: "trace-1".into(),
                span_id: "span-1".into(),
                parent_span_id: None,
                service_name: "action-runner-worker".into(),
                node_id: "worker-riscv64".into(),
                span_name: "stage.run".into(),
                span_kind: "INTERNAL".into(),
                start_time_unix_nano: now_ts - 2_000_000_000,
                end_time_unix_nano: now_ts - 1_980_000_000,
                duration_ns: 20_000_000, // 20 ms
                status_code: "OK".into(),
                status_message: None,
                attributes_json: "{}".into(),
            }])
            .unwrap();

        let healthy_req = CanarySloAssertionRequest {
            request_id: "slo-pass".into(),
            service_name: "action-runner-worker".into(),
            candidate_digest: "sha256:good".into(),
            node_id: "worker-riscv64".into(),
            bake_window_secs: 60,
            max_error_logs: 0,
            max_p99_latency_ms: 100.0,
        };
        let resp = evaluate_canary_slo(&store, &healthy_req, Some(now_ts)).unwrap();
        assert!(resp.healthy);
        assert!(!resp.taint_recommended);
        assert_eq!(resp.error_log_count, 0);
        assert!((resp.p99_latency_ms - 20.0).abs() < 1e-6);

        // Now inject an ERROR log and a high-latency span (500 ms)
        store
            .insert_logs_batch(&[OtelLogEntry {
                timestamp_unix_nano: now_ts - 1_000_000_000,
                trace_id: "trace-2".into(),
                span_id: "span-2".into(),
                severity_number: 17,
                severity_text: "ERROR".into(),
                service_name: "action-runner-worker".into(),
                node_id: "worker-riscv64".into(),
                body: "worker panicked during stage initialization".into(),
                attributes_json: "{}".into(),
                job_id: None,
                stage_id: None,
            }])
            .unwrap();
        store
            .insert_spans_batch(&[OtelSpanEntry {
                trace_id: "trace-2".into(),
                span_id: "span-2".into(),
                parent_span_id: None,
                service_name: "action-runner-worker".into(),
                node_id: "worker-riscv64".into(),
                span_name: "stage.run".into(),
                span_kind: "INTERNAL".into(),
                start_time_unix_nano: now_ts - 1_500_000_000,
                end_time_unix_nano: now_ts - 1_000_000_000,
                duration_ns: 500_000_000, // 500 ms
                status_code: "OK".into(),
                status_message: None,
                attributes_json: "{}".into(),
            }])
            .unwrap();

        let breach_req = CanarySloAssertionRequest {
            request_id: "slo-fail".into(),
            service_name: "action-runner-worker".into(),
            candidate_digest: "sha256:bad".into(),
            node_id: "worker-riscv64".into(),
            bake_window_secs: 60,
            max_error_logs: 0,
            max_p99_latency_ms: 100.0,
        };
        let breach_resp = evaluate_canary_slo(&store, &breach_req, Some(now_ts)).unwrap();
        assert!(!breach_resp.healthy);
        assert!(breach_resp.taint_recommended);
        assert_eq!(breach_resp.error_log_count, 1);
        assert!((breach_resp.p99_latency_ms - 500.0).abs() < 1e-6);
    }
}
