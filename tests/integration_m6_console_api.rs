use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use mu_observable_hub::{
    build_console_api_router, CompactorConfig, HotDuckDbStore, McpServer, ParquetCompactor,
};
use mu_observable_ipc::{
    BenchmarkRunEntry, CentralSubmoduleSnapshot, OtelLogEntry, OtelMetricEntry, OtelSpanEntry,
    TestCaseRunEntry,
};
use serde_json::Value;
use tempfile::tempdir;
use tower::ServiceExt;

async fn get_json(router: &axum::Router, uri: &str) -> (StatusCode, String, Value) {
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let cache_control = resp
        .headers()
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json_val: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, cache_control, json_val)
}

#[tokio::test]
async fn test_m6_readonly_observability_apis_end_to_end() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("muobserve.duckdb");
    let parquet_root = dir.path().join("parquet");
    let store =
        HotDuckDbStore::open(Some(&db_path), Some(&parquet_root)).expect("open HotDuckDbStore");

    let now_ts = 1_700_000_500_000_000_000i64;
    let old_ts = now_ts - (10 * 86_400 * 1_000_000_000i64);

    // Seed spans across CI, CD, Registry, and private runtime services with internal hostnames, IPs, and secrets
    store
        .insert_spans_batch(&[
            OtelSpanEntry {
                trace_id: "trace-ci-100".into(),
                span_id: "span-ci-root".into(),
                parent_span_id: None,
                service_name: "action-runner-controller".into(),
                node_id: "entrance.lab.local".into(),
                span_name: "ci.pipeline".into(),
                span_kind: "SERVER".into(),
                start_time_unix_nano: now_ts - 800_000_000,
                end_time_unix_nano: now_ts,
                duration_ns: 800_000_000, // 800 ms -> triggers p95 latency breach
                status_code: "ERROR".into(),
                status_message: Some(
                    "stage failed on pey-wail-deu.lab.local (192.168.1.117)".into(),
                ),
                attributes_json: r#"{"job_id":"job-100","artifact_digest":"sha256:abcd","authorization":"Bearer secret_token_999","config_path":"/etc/action-runner/config.toml"}"#.into(),
            },
            OtelSpanEntry {
                trace_id: "trace-ci-100".into(),
                span_id: "span-ci-worker".into(),
                parent_span_id: Some("span-ci-root".into()),
                service_name: "action-runner-worker".into(),
                node_id: "pey-wail-deu.lab.local".into(),
                span_name: "stage.test".into(),
                span_kind: "INTERNAL".into(),
                start_time_unix_nano: now_ts - 700_000_000,
                end_time_unix_nano: now_ts - 100_000_000,
                duration_ns: 600_000_000,
                status_code: "ERROR".into(),
                status_message: Some("cargo test failed in /Users/developer/repo/src/lib.rs".into()),
                attributes_json: r#"{"peer.ip":"10.0.0.42"}"#.into(),
            },
            OtelSpanEntry {
                trace_id: "trace-reg-200".into(),
                span_id: "span-reg-root".into(),
                parent_span_id: None,
                service_name: "muregist".into(),
                node_id: "rubicon.lab.local".into(),
                span_name: "oci.manifest.put".into(),
                span_kind: "SERVER".into(),
                start_time_unix_nano: now_ts - 50_000_000,
                end_time_unix_nano: now_ts - 10_000_000,
                duration_ns: 40_000_000,
                status_code: "OK".into(),
                status_message: None,
                attributes_json: r#"{"artifact_digest":"sha256:ef01"}"#.into(),
            },
        ])
        .unwrap();

    // Seed logs (one old log to compact to Parquet, one recent error log with secrets/paths)
    store
        .insert_logs_batch(&[
            OtelLogEntry {
                timestamp_unix_nano: old_ts,
                trace_id: "trace-old-1".into(),
                span_id: "span-old-1".into(),
                severity_number: 9,
                severity_text: "INFO".into(),
                service_name: "muregist".into(),
                node_id: "rubicon.lab.local".into(),
                body: "archived registry startup on 192.168.1.10".into(),
                attributes_json: "{}".into(),
                job_id: None,
                stage_id: None,
            },
            OtelLogEntry {
                timestamp_unix_nano: now_ts - 200_000_000,
                trace_id: "trace-ci-100".into(),
                span_id: "span-ci-worker".into(),
                severity_number: 21,
                severity_text: "FATAL".into(),
                service_name: "action-runner-worker".into(),
                node_id: "pey-wail-deu.lab.local".into(),
                body: "worker panic at /var/lib/action-runner/state.db with token ghp_supersecret987654 on 192.168.1.117".into(),
                attributes_json: r#"{"cookie":"session=secretcookie"}"#.into(),
                job_id: Some("job-100".into()),
                stage_id: Some("test-check".into()),
            },
        ])
        .unwrap();

    // Seed metrics and benchmarks
    store
        .insert_metrics_batch(&[OtelMetricEntry {
            timestamp_unix_nano: now_ts - 150_000_000,
            service_name: "action-runner-worker".into(),
            node_id: "pey-wail-deu.lab.local".into(),
            metric_name: "cpu.utilization".into(),
            metric_unit: "pct".into(),
            value_f64: 88.5,
            arch: "riscv64gc".into(),
            cpu_cluster: Some("A100".into()),
            vlen_bits: Some(1024),
            memlock_used_bytes: Some(1024 * 1024),
            memlock_limit_bytes: Some(28 * 1024 * 1024 * 1024),
            trace_id: Some("trace-ci-100".into()),
            span_id: Some("span-ci-worker".into()),
            attributes_json: r#"{"host.name":"pey-wail-deu.lab.local"}"#.into(),
        }])
        .unwrap();

    store
        .insert_benchmark_runs_batch(&[
            BenchmarkRunEntry {
                job_id: "job-99".into(),
                repo_key: "lma1980/k3-kernels-rvv".into(),
                branch_key: "main".into(),
                commit_sha: "sha-base".into(),
                crate_name: "k3-kernels-rvv".into(),
                bench_name: "gemm_int8".into(),
                ns_per_iter: 40_000.0,
                std_dev_ns: 100.0,
                mad_ns: 80.0,
                p50_ns: 40_000.0,
                p95_ns: 40_200.0,
                p99_ns: 40_300.0,
                throughput_value: None,
                throughput_unit: None,
                arch: "riscv64gc".into(),
                cpu_cluster: "A100".into(),
                vlen_bits: 1024,
                timestamp_unix_nano: now_ts - 10_000_000_000,
                node_id: "worker-riscv64".into(),
            },
            BenchmarkRunEntry {
                job_id: "job-100".into(),
                repo_key: "lma1980/k3-kernels-rvv".into(),
                branch_key: "main".into(),
                commit_sha: "sha-base".into(),
                crate_name: "k3-kernels-rvv".into(),
                bench_name: "gemm_int8".into(),
                ns_per_iter: 118_000.0,
                std_dev_ns: 200.0,
                mad_ns: 150.0,
                p50_ns: 118_000.0,
                p95_ns: 118_400.0,
                p99_ns: 118_600.0,
                throughput_value: None,
                throughput_unit: None,
                arch: "riscv64gc".into(),
                cpu_cluster: "X100".into(),
                vlen_bits: 256,
                timestamp_unix_nano: now_ts - 9_000_000_000,
                node_id: "worker-riscv64".into(),
            },
        ])
        .unwrap();

    store
        .insert_test_runs_batch(&[TestCaseRunEntry {
            job_id: "job-100".into(),
            repo_key: "lma1980/k3-kernels-rvv".into(),
            branch_key: "main".into(),
            commit_sha: "sha-base".into(),
            crate_name: "k3-kernels-rvv".into(),
            test_binary: "k3_kernels".into(),
            test_name: "test_vmadot".into(),
            status: "ok".into(),
            duration_ms: 1.5,
            failure_summary: None,
            timestamp_unix_nano: now_ts,
            node_id: "worker-riscv64".into(),
            arch: "riscv64gc".into(),
        }])
        .unwrap();

    // Compact old log to Parquet so we have both hot DuckDB and cold Parquet segments
    let compactor = ParquetCompactor::new(CompactorConfig::new(&parquet_root));
    compactor.compact_at_now(&store, now_ts).unwrap();

    let app = McpServer::new(store.clone()).router();
    let standalone_app = build_console_api_router(store);

    // 1. Test GET /api/v1/smartscape & /api/observe/smartscape
    let (status, cc, smartscape) = get_json(&app, "/api/v1/smartscape?window_secs=3600").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(cc, "no-store");
    assert_eq!(smartscape["services"].as_array().unwrap().len(), 3);
    assert_eq!(smartscape["processes"].as_array().unwrap().len(), 3);
    assert_eq!(smartscape["hosts"].as_array().unwrap().len(), 3);
    let sc_text = serde_json::to_string(&smartscape).unwrap();
    assert!(!sc_text.contains("entrance"));
    assert!(!sc_text.contains("rubicon"));
    assert!(!sc_text.contains("pey-wail-deu"));
    assert!(sc_text.contains("node-a"));
    assert!(sc_text.contains("node-b"));
    assert!(sc_text.contains("worker-riscv64"));

    // Invalid window_secs -> 400 Bad Request
    let (bad_sc_status, _, _) = get_json(&standalone_app, "/api/v1/smartscape?window_secs=0").await;
    assert_eq!(bad_sc_status, StatusCode::BAD_REQUEST);

    // 2. Test GET /api/v1/problems & SSE /api/observe/events
    let (prob_status, prob_cc, problems) = get_json(&app, "/api/v1/problems").await;
    assert_eq!(prob_status, StatusCode::OK);
    assert_eq!(prob_cc, "no-store");
    let prob_arr = problems["problems"].as_array().unwrap();
    assert!(!prob_arr.is_empty());
    assert!(prob_arr
        .iter()
        .any(|p| p["root_cause_trace_id"] == "trace-ci-100"));
    let prob_text = serde_json::to_string(&problems).unwrap();
    assert!(!prob_text.contains("pey-wail-deu"));
    assert!(!prob_text.contains("192.168.1.117"));
    assert!(!prob_text.contains("/var/lib/"));
    assert!(!prob_text.contains("ghp_supersecret987654"));

    let sse_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/observe/events")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(sse_resp.status(), StatusCode::OK);
    let sse_bytes = sse_resp.into_body().collect().await.unwrap().to_bytes();
    let sse_str = String::from_utf8_lossy(&sse_bytes);
    assert!(sse_str.contains("event: problem_opened"));

    // 3. Test GET /api/v1/traces (filters & 400 rejection)
    for filter in ["all", "errors", "slow_p99", "ci", "registry"] {
        let (t_status, t_cc, t_json) =
            get_json(&app, &format!("/api/v1/traces?filter={filter}&limit=10")).await;
        assert_eq!(t_status, StatusCode::OK);
        assert_eq!(t_cc, "no-store");
        assert!(!t_json["traces"].as_array().unwrap().is_empty());
    }
    let (bad_tr_status, _, _) = get_json(&app, "/api/v1/traces?filter=sql_inject").await;
    assert_eq!(bad_tr_status, StatusCode::BAD_REQUEST);

    // 4. Test GET /api/v1/traces/{trace_id} & /api/observe/traces/{trace_id}/purepath
    let (pp_status, pp_cc, pp) = get_json(&app, "/api/v1/traces/trace-ci-100").await;
    assert_eq!(pp_status, StatusCode::OK);
    assert_eq!(pp_cc, "no-store");
    assert_eq!(pp["trace_id"], "trace-ci-100");
    assert_eq!(pp["span_count"], 2);
    assert_eq!(pp["correlated_logs"].as_array().unwrap().len(), 1);
    assert_eq!(pp["correlated_metrics"].as_array().unwrap().len(), 1);
    let pp_text = serde_json::to_string(&pp).unwrap();
    assert!(!pp_text.contains("entrance"));
    assert!(!pp_text.contains("pey-wail-deu"));
    assert!(!pp_text.contains("192.168.1.117"));
    assert!(!pp_text.contains("10.0.0.42"));
    assert!(!pp_text.contains("secret_token_999"));
    assert!(!pp_text.contains("ghp_supersecret987654"));
    assert!(!pp_text.contains("secretcookie"));
    assert!(!pp_text.contains("/etc/action-runner"));
    assert!(!pp_text.contains("/Users/developer"));
    assert!(!pp_text.contains("/var/lib/action-runner"));

    let (missing_status, _, _) = get_json(&app, "/api/v1/traces/nonexistent-trace-id").await;
    assert_eq!(missing_status, StatusCode::NOT_FOUND);

    // 5. Test GET /api/v1/logs with enum filters & SQL injection rejection
    let (l_status, l_cc, logs_json) = get_json(
        &app,
        "/api/v1/logs?severity=error&trace_id=trace-ci-100&limit=20",
    )
    .await;
    assert_eq!(l_status, StatusCode::OK);
    assert_eq!(l_cc, "no-store");
    assert_eq!(logs_json["total"], 1);
    let log_str = serde_json::to_string(&logs_json).unwrap();
    assert!(!log_str.contains("ghp_supersecret987654"));
    assert!(!log_str.contains("/var/lib/"));
    assert!(!log_str.contains("192.168.1.117"));

    // Reject unknown severity or SQL/regex injection attempts with 400 Bad Request
    let (bad_sev, _, _) = get_json(&app, "/api/v1/logs?severity=critical_sql").await;
    assert_eq!(bad_sev, StatusCode::BAD_REQUEST);
    let (bad_inj, _, _) = get_json(&app, "/api/v1/logs?service=k3'%20OR%201=1--").await;
    assert_eq!(bad_inj, StatusCode::BAD_REQUEST);
    let (bad_unknown_param, _, _) = get_json(&app, "/api/v1/logs?sql=SELECT%201").await;
    assert_eq!(bad_unknown_param, StatusCode::BAD_REQUEST);

    // 6. Test GET /api/v1/metrics/timeseries
    let (m_status, m_cc, metrics_json) = get_json(
        &app,
        "/api/v1/metrics/timeseries?metric=cpu_utilization&window=1h&cluster=A100&limit=10",
    )
    .await;
    assert_eq!(m_status, StatusCode::OK);
    assert_eq!(m_cc, "no-store");
    assert_eq!(metrics_json["total"], 1);
    assert_eq!(
        metrics_json["series"][0]["exemplar_trace_id"],
        "trace-ci-100"
    );
    assert_eq!(
        metrics_json["cluster_efficiency"].as_array().unwrap().len(),
        2
    );

    let (bad_m_status, _, _) =
        get_json(&app, "/api/v1/metrics/timeseries?metric=arbitrary_sql").await;
    assert_eq!(bad_m_status, StatusCode::BAD_REQUEST);

    // 7. Test GET /api/v1/store/status & /api/observe/datastore
    let (st_status, st_cc, store_status) = get_json(&app, "/api/v1/store/status").await;
    assert_eq!(st_status, StatusCode::OK);
    assert_eq!(st_cc, "no-store");
    assert_eq!(store_status["total_spans"], 3);
    assert_eq!(store_status["total_logs"], 2);
    assert_eq!(store_status["hot_logs"], 1);
    assert_eq!(store_status["cold_logs"], 1);
    assert_eq!(store_status["total_metric_points"], 1);
    assert_eq!(store_status["parquet_segments"], 1);
    assert_eq!(store_status["retention_days"], 7);
    assert_eq!(store_status["healthy"], true);

    // Verify zero filesystem paths in store/status response
    let st_raw = serde_json::to_string(&store_status).unwrap();
    assert!(!st_raw.contains('/'));
    assert!(!st_raw.contains('\\'));
    assert!(!st_raw.contains("muobserve.duckdb"));
    assert!(!st_raw.contains("SELECT"));
}

async fn get_text(router: &axum::Router, uri: &str) -> (StatusCode, String, String) {
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let cache_control = resp
        .headers()
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&bytes).into_owned();
    (status, cache_control, text)
}

#[tokio::test]
async fn test_sanitized_ci_job_logs_in_logs_and_job_log_endpoint() {
    let store = HotDuckDbStore::open_in_memory().expect("open in-memory HotDuckDbStore");
    let raw_log = concat!(
        "=== Stage 'test-check' started on worker 'worker-riscv64' ===\n",
        "2026-11-07T21:36:55.123456Z [node-b] [test-check] [stdout] Running /var/lib/action-runner/work/tests on 10.0.0.42\n",
        "2026-11-07T21:36:56.654321Z [node-b] [test-check] [stderr] error: test failed with token ghp_supersecret9876543210\n",
    );

    store
        .upsert_ci_state_batch(
            &[],
            &[],
            &[CentralSubmoduleSnapshot {
                parent_repo_key: "__ar_job_logs__".into(),
                branch_key: "log".into(),
                submodule_key: "job-1794087359-65d5b504".into(),
                submodule_path_key: "log".into(),
                latest_active_job_id: Some("job-1794087359-65d5b504".into()),
                latest_active_json: Some(raw_log.into()),
                latest_active_queued_us: Some(1_794_087_415_000_000),
                latest_completed_job_id: None,
                latest_completed_json: None,
                latest_completed_queued_us: None,
            }],
        )
        .expect("upsert job log snapshot");

    let app = build_console_api_router(store);

    // 1. Verify /api/v1/logs surfaces sanitized CI job log lines with trace_id "tr-ci-65d5b5"
    let (status, cc, logs_json) =
        get_json(&app, "/api/v1/logs?job_id=job-1794087359-65d5b504&limit=50").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(cc, "no-store");
    assert_eq!(logs_json["total"], 3);
    let serialized = serde_json::to_string(&logs_json).unwrap();
    assert!(serialized.contains("tr-ci-65d5b5"));
    assert!(serialized.contains("job-1794087359-65d5b504"));
    assert!(serialized.contains("192.0.2."));
    assert!(!serialized.contains("10.0.0.42"));
    assert!(!serialized.contains("/var/lib/action-runner"));
    assert!(!serialized.contains("ghp_supersecret9876543210"));

    // 2. Verify /api/logs (without /v1 prefix, as proxied by /api/obs/logs) works identically
    let (alias_status, _, alias_json) =
        get_json(&app, "/api/logs?severity=error&trace_id=tr-ci-65d5b5").await;
    assert_eq!(alias_status, StatusCode::OK);
    assert_eq!(alias_json["total"], 1);
    assert_eq!(alias_json["logs"][0]["severity_text"], "ERROR");
    assert_eq!(alias_json["logs"][0]["stage_id"], "test-check");

    // 3. Verify anonymous/public per-job sanitized log endpoint (/api/v1/jobs/{job_id}/log and /api/jobs/{job_id}/log)
    let (jl_status, jl_cc, jl_text) =
        get_text(&app, "/api/v1/jobs/job-1794087359-65d5b504/log").await;
    assert_eq!(jl_status, StatusCode::OK);
    assert_eq!(jl_cc, "no-store");
    assert!(jl_text.contains("[test-check]"));
    assert!(jl_text.contains("192.0.2."));
    assert!(!jl_text.contains("10.0.0.42"));
    assert!(!jl_text.contains("/var/lib/action-runner"));
    assert!(!jl_text.contains("ghp_supersecret9876543210"));

    let (jl_alias_status, _, jl_alias_text) =
        get_text(&app, "/api/jobs/job-1794087359-65d5b504/log").await;
    assert_eq!(jl_alias_status, StatusCode::OK);
    assert_eq!(jl_alias_text, jl_text);

    // 4. Non-existent job returns 404 Not Found
    let (missing_status, _, _) = get_json(&app, "/api/v1/jobs/job-nonexistent-000000/log").await;
    assert_eq!(missing_status, StatusCode::NOT_FOUND);
}
