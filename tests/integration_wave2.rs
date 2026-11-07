use std::io::Cursor;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use mu_observable_hub::{
    build_mtls_server_config, dispatch_frame, execute_cli_command, parse_cli_args,
    resolve_san_identity, CompactorConfig, HotDuckDbStore, IngestServerConfig, JsonRpcRequest,
    JsonRpcResponse, McpServer, MtlsIngestServer, ParquetCompactor, SanAttribution,
    SanEnforcementPolicy, MSG_TYPE_ARROW_LOGS, MSG_TYPE_ARROW_METRICS, MSG_TYPE_ARROW_SPANS,
};
use mu_observable_ipc::{
    decode_control_envelope, encode_benchmark_run_batch, encode_control_envelope, encode_log_batch,
    encode_metric_batch, encode_span_batch, encode_test_run_batch, write_frame, BenchmarkRunEntry,
    CanarySloAssertionRequest, CentralBranchSnapshot, CentralJobRecord, CentralSubmoduleSnapshot,
    ControlRpcEnvelope, IpcHeader, OtelLogEntry, OtelMetricEntry, OtelSpanEntry,
    QueryBranchSnapshotsRequest, QueryJobsHistoryRequest, QuerySubmoduleSnapshotsRequest,
    RegressionGateRequest, RegressionVerdict, TestCaseRunEntry, UpsertJobBatchRequest,
    MSG_TYPE_ARROW_BENCH_RUNS, MSG_TYPE_ARROW_TEST_RUNS, MSG_TYPE_FORY_CONTROL, MSG_TYPE_WAL_ACK,
};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use serde_json::json;
use tempfile::tempdir;
use tower::ServiceExt;

#[tokio::test]
async fn test_end_to_end_mtls_stream_arrow_and_fory_pipeline() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("hot.duckdb");
    let parquet_root = dir.path().join("parquet");
    let store =
        HotDuckDbStore::open(Some(&db_path), Some(&parquet_root)).expect("open HotDuckDbStore");

    let attr = SanAttribution {
        raw_sans: vec!["worker-riscv64.cluster.internal".into()],
        node_id: "worker-riscv64".into(),
        service_name: Some("k3-manager".into()),
    };
    let config = IngestServerConfig {
        san_policy: SanEnforcementPolicy::OverrideWithCertSan,
        redact_on_ingest: true,
        allowed_dns_suffix: Some("cluster.internal".into()),
    };

    let now_ts = 1_700_000_500_000_000_000i64;

    // 1. Stream Arrow logs over async duplex via handle_single_frame_on_stream
    let logs = vec![OtelLogEntry {
        timestamp_unix_nano: now_ts,
        trace_id: "trace-e2e-1".into(),
        span_id: "span-e2e-1".into(),
        severity_number: 9,
        severity_text: "INFO".into(),
        service_name: "spoofed-service".into(),
        node_id: "spoofed-node".into(),
        body: "token=ghp_supersecret123456".into(),
        attributes_json: "{}".into(),
        job_id: Some("job-e2e".into()),
        stage_id: Some("build".into()),
    }];
    let log_bytes = encode_log_batch(&logs).unwrap();
    let log_hdr = IpcHeader::new(MSG_TYPE_ARROW_LOGS, log_bytes.len() as u32, 0, 10);

    let (mut client, mut server) = tokio::io::duplex(65_536);
    write_frame(&mut client, &log_hdr, &log_bytes)
        .await
        .unwrap();
    MtlsIngestServer::handle_single_frame_on_stream(&store, &config, &attr, &mut server)
        .await
        .expect("handle single frame on stream");

    let (ack_hdr, ack_payload) = mu_observable_ipc::read_frame(&mut client).await.unwrap();
    assert_eq!(ack_hdr.msg_type, MSG_TYPE_WAL_ACK);
    let ack_env = decode_control_envelope(&ack_payload).unwrap();
    assert!(matches!(
        ack_env,
        ControlRpcEnvelope::WalAck(mu_observable_ipc::WalBatchAck {
            sequence: 10,
            accepted_rows: 1,
            ok: true,
            ..
        })
    ));

    // Verify spans, metrics, tests, and benchmarks via dispatch_frame
    let spans = vec![OtelSpanEntry {
        trace_id: "trace-e2e-1".into(),
        span_id: "span-e2e-1".into(),
        parent_span_id: None,
        service_name: "k3-manager".into(),
        node_id: "worker-riscv64".into(),
        span_name: "k3.prefill".into(),
        span_kind: "INTERNAL".into(),
        start_time_unix_nano: now_ts - 5_000_000,
        end_time_unix_nano: now_ts,
        duration_ns: 5_000_000,
        status_code: "OK".into(),
        status_message: Some("password=secret999".into()),
        attributes_json: "{}".into(),
    }];
    let span_bytes = encode_span_batch(&spans).unwrap();
    let span_hdr = IpcHeader::new(MSG_TYPE_ARROW_SPANS, span_bytes.len() as u32, 0, 11);
    dispatch_frame(&store, &config, &attr, &span_hdr, &span_bytes).unwrap();

    let metrics = vec![OtelMetricEntry {
        timestamp_unix_nano: now_ts,
        service_name: "k3-manager".into(),
        node_id: "worker-riscv64".into(),
        metric_name: "k3.kv_cache.bytes".into(),
        metric_unit: "bytes".into(),
        value_f64: 65536.0,
        arch: "riscv64gc".into(),
        cpu_cluster: Some("A100".into()),
        vlen_bits: Some(1024),
        memlock_used_bytes: Some(65536),
        memlock_limit_bytes: Some(29_360_128 * 1024),
        trace_id: Some("trace-e2e-1".into()),
        span_id: Some("span-e2e-1".into()),
        attributes_json: "{}".into(),
    }];
    let metric_bytes = encode_metric_batch(&metrics).unwrap();
    let metric_hdr = IpcHeader::new(MSG_TYPE_ARROW_METRICS, metric_bytes.len() as u32, 0, 12);
    dispatch_frame(&store, &config, &attr, &metric_hdr, &metric_bytes).unwrap();

    let tests = vec![TestCaseRunEntry {
        job_id: "job-e2e".into(),
        repo_key: "lma1980/k3-engine".into(),
        branch_key: "main".into(),
        commit_sha: "sha-main-1".into(),
        crate_name: "k3-engine".into(),
        test_binary: "k3_engine".into(),
        test_name: "test_paged_kv".into(),
        status: "ok".into(),
        duration_ms: 3.2,
        failure_summary: None,
        timestamp_unix_nano: now_ts,
        node_id: "worker-riscv64".into(),
        arch: "riscv64gc".into(),
    }];
    let test_bytes = encode_test_run_batch(&tests).unwrap();
    let test_hdr = IpcHeader::new(MSG_TYPE_ARROW_TEST_RUNS, test_bytes.len() as u32, 0, 13);
    dispatch_frame(&store, &config, &attr, &test_hdr, &test_bytes).unwrap();

    let benches = vec![BenchmarkRunEntry {
        job_id: "job-e2e".into(),
        repo_key: "lma1980/k3-engine".into(),
        branch_key: "main".into(),
        commit_sha: "sha-main-1".into(),
        crate_name: "k3-engine".into(),
        bench_name: "kv_append".into(),
        ns_per_iter: 1200.0,
        std_dev_ns: 20.0,
        mad_ns: 15.0,
        p50_ns: 1200.0,
        p95_ns: 1230.0,
        p99_ns: 1250.0,
        throughput_value: None,
        throughput_unit: None,
        arch: "riscv64gc".into(),
        cpu_cluster: "A100".into(),
        vlen_bits: 1024,
        timestamp_unix_nano: now_ts,
        node_id: "worker-riscv64".into(),
    }];
    let bench_bytes = encode_benchmark_run_batch(&benches).unwrap();
    let bench_hdr = IpcHeader::new(MSG_TYPE_ARROW_BENCH_RUNS, bench_bytes.len() as u32, 0, 14);
    dispatch_frame(&store, &config, &attr, &bench_hdr, &bench_bytes).unwrap();

    // 2. Test Fory ControlRpcEnvelope batch upsert & queries + RegressionGateReq + CanarySloReq
    let batch_req = ControlRpcEnvelope::UpsertJobBatchReq(UpsertJobBatchRequest {
        request_id: "batch-1".into(),
        records: vec![CentralJobRecord {
            job_id: "job-e2e".into(),
            event_type: "push".into(),
            repo_name: "LMA1980/k3-engine".into(),
            repo_key: "lma1980/k3-engine".into(),
            clone_url: "https://github.com/LMA1980/k3-engine.git".into(),
            commit_sha: "sha-main-1".into(),
            ref_name: "refs/heads/main".into(),
            branch_key: "main".into(),
            sender: "LMA1980".into(),
            queued_at_us: 100,
            updated_at_us: 200,
            status_state: "Completed".into(),
            exit_code: Some(0),
            duration_secs: Some(20),
            quality_score: Some(98),
            letter_grade: Some("A+".into()),
            coverage_pct: Some(91.0),
            benchmark_summary: None,
            tests_passed: Some(10),
            tests_total: Some(10),
            advisories_count: Some(0),
            clippy_warnings: Some(0),
            record_json: "{}".into(),
        }],
        branch_snapshots: vec![CentralBranchSnapshot {
            repo_key: "lma1980/k3-engine".into(),
            branch_key: "main".into(),
            repo_name: "LMA1980/k3-engine".into(),
            ref_name: "refs/heads/main".into(),
            latest_active_job_id: None,
            latest_active_json: None,
            latest_active_queued_us: None,
            latest_completed_job_id: Some("job-e2e".into()),
            latest_completed_json: Some("{}".into()),
            latest_completed_queued_us: Some(100),
        }],
        submodule_snapshots: vec![CentralSubmoduleSnapshot {
            parent_repo_key: "lma1980/k3".into(),
            branch_key: "main".into(),
            submodule_key: "k3-engine".into(),
            submodule_path_key: "engine".into(),
            latest_active_job_id: None,
            latest_active_json: None,
            latest_active_queued_us: None,
            latest_completed_job_id: Some("job-e2e".into()),
            latest_completed_json: Some("{}".into()),
            latest_completed_queued_us: Some(100),
        }],
    });
    let b_bytes = encode_control_envelope(&batch_req).unwrap();
    let b_hdr = IpcHeader::new(MSG_TYPE_FORY_CONTROL, b_bytes.len() as u32, 0, 15);
    dispatch_frame(&store, &config, &attr, &b_hdr, &b_bytes).unwrap();

    // Query branch & submodule snapshots via Fory RPC
    let qb_bytes = encode_control_envelope(&ControlRpcEnvelope::QueryBranchSnapshotsReq(
        QueryBranchSnapshotsRequest {
            request_id: "qb".into(),
            repo_key: Some("lma1980/k3-engine".into()),
            branch_key: None,
        },
    ))
    .unwrap();
    let (_, qb_resp) = dispatch_frame(
        &store,
        &config,
        &attr,
        &IpcHeader::new(MSG_TYPE_FORY_CONTROL, qb_bytes.len() as u32, 0, 16),
        &qb_bytes,
    )
    .unwrap();
    assert!(matches!(
        decode_control_envelope(&qb_resp).unwrap(),
        ControlRpcEnvelope::QueryBranchSnapshotsResp(_)
    ));

    let qs_bytes = encode_control_envelope(&ControlRpcEnvelope::QuerySubmoduleSnapshotsReq(
        QuerySubmoduleSnapshotsRequest {
            request_id: "qs".into(),
            parent_repo_key: Some("lma1980/k3".into()),
            submodule_key: None,
            branch_key: None,
        },
    ))
    .unwrap();
    let (_, qs_resp) = dispatch_frame(
        &store,
        &config,
        &attr,
        &IpcHeader::new(MSG_TYPE_FORY_CONTROL, qs_bytes.len() as u32, 0, 17),
        &qs_bytes,
    )
    .unwrap();
    assert!(matches!(
        decode_control_envelope(&qs_resp).unwrap(),
        ControlRpcEnvelope::QuerySubmoduleSnapshotsResp(_)
    ));

    let rg_bytes = encode_control_envelope(&ControlRpcEnvelope::RegressionGateReq(
        RegressionGateRequest {
            request_id: "rg-1".into(),
            repo_key: "lma1980/k3-engine".into(),
            candidate_commit: "sha-main-1".into(),
            baseline_branch: "main".into(),
            max_slowdown_pct: 5.0,
            max_flakiness_pct: 2.0,
        },
    ))
    .unwrap();
    let (_, rg_resp) = dispatch_frame(
        &store,
        &config,
        &attr,
        &IpcHeader::new(MSG_TYPE_FORY_CONTROL, rg_bytes.len() as u32, 0, 18),
        &rg_bytes,
    )
    .unwrap();
    match decode_control_envelope(&rg_resp).unwrap() {
        ControlRpcEnvelope::RegressionGateResp(rep) => {
            assert_eq!(rep.verdict, RegressionVerdict::Pass);
        }
        other => panic!("unexpected: {other:?}"),
    }

    let slo_bytes = encode_control_envelope(&ControlRpcEnvelope::CanarySloReq(
        CanarySloAssertionRequest {
            request_id: "slo-1".into(),
            service_name: "k3-manager".into(),
            candidate_digest: "sha256:1234".into(),
            node_id: "worker-riscv64".into(),
            bake_window_secs: 60,
            max_error_logs: 0,
            max_p99_latency_ms: 100.0,
        },
    ))
    .unwrap();
    let (_, slo_resp) = dispatch_frame(
        &store,
        &config,
        &attr,
        &IpcHeader::new(MSG_TYPE_FORY_CONTROL, slo_bytes.len() as u32, 0, 19),
        &slo_bytes,
    )
    .unwrap();
    match decode_control_envelope(&slo_resp).unwrap() {
        ControlRpcEnvelope::CanarySloResp(r) => assert!(r.healthy),
        other => panic!("unexpected: {other:?}"),
    }

    // 3. Test MCP stdio and HTTP/SSE router
    let mcp = McpServer::new(store.clone());
    let stdio_in = serde_json::to_string(&JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: Some(json!(1)),
        method: "initialize".into(),
        params: json!({}),
    })
    .unwrap()
        + "\n";
    let mut stdio_out = Vec::new();
    mcp.serve_stdio(Cursor::new(stdio_in.into_bytes()), &mut stdio_out)
        .unwrap();
    let init_resp: JsonRpcResponse = serde_json::from_slice(&stdio_out).unwrap();
    assert!(init_resp.result.is_some());

    let app = mcp.router();
    let sse_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mcp/sse")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(sse_resp.status(), StatusCode::OK);

    let post_resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&JsonRpcRequest {
                        jsonrpc: "2.0".into(),
                        id: Some(json!(2)),
                        method: "tools/list".into(),
                        params: json!({}),
                    })
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(post_resp.status(), StatusCode::OK);
    let body_bytes = post_resp.into_body().collect().await.unwrap().to_bytes();
    let post_rpc: JsonRpcResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(
        post_rpc.result.unwrap()["tools"].as_array().unwrap().len(),
        10
    );

    // 4. Test CLI subcommands (traces, regressions, slo)
    let (_, tr_cmd) =
        parse_cli_args(&["traces".into(), "--trace-id".into(), "trace-e2e-1".into()]).unwrap();
    let tr_out = execute_cli_command(&store, &tr_cmd).unwrap();
    assert_eq!(tr_out["waterfall"]["span_count"], 1);

    let (_, rg_cmd) = parse_cli_args(&[
        "regressions".into(),
        "--repo".into(),
        "lma1980/k3-engine".into(),
        "--commit".into(),
        "sha-main-1".into(),
    ])
    .unwrap();
    let rg_out = execute_cli_command(&store, &rg_cmd).unwrap();
    assert_eq!(rg_out["verdict"], "Pass");

    let (_, slo_cmd) = parse_cli_args(&[
        "slo".into(),
        "--service".into(),
        "k3-manager".into(),
        "--node".into(),
        "worker-riscv64".into(),
    ])
    .unwrap();
    let slo_out = execute_cli_command(&store, &slo_cmd).unwrap();
    assert_eq!(slo_out["healthy"], true);

    // 5. Compact everything and verify QueryJobsHistory works
    let compactor = ParquetCompactor::new(CompactorConfig::new(&parquet_root));
    let comp_report = compactor.compact_before(&store, now_ts + 1_000).unwrap();
    assert_eq!(comp_report.exported_logs, 1);
    assert_eq!(comp_report.exported_spans, 1);
    assert_eq!(comp_report.exported_metrics, 1);
    assert_eq!(comp_report.exported_tests, 1);
    assert_eq!(comp_report.exported_benchmarks, 1);

    let jobs = store
        .query_jobs_history(&QueryJobsHistoryRequest {
            request_id: "qj".into(),
            repo_key: None,
            branch_key: None,
            job_id: Some("job-e2e".into()),
            limit: 10,
        })
        .unwrap();
    assert_eq!(jobs.len(), 1);
}

#[test]
fn test_tls_config_and_san_dns_resolution() {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(vec!["node-a.cluster.internal".to_string()]).unwrap();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "node-a.cluster.internal");
    params.distinguished_name = dn;
    let cert = params.self_signed(&key_pair).unwrap();

    let server_cfg = build_mtls_server_config(&cert.pem(), &cert.pem(), &key_pair.serialize_pem())
        .expect("build mtls server config");
    assert_eq!(server_cfg.max_early_data_size, 0);

    let attr = resolve_san_identity(cert.der(), Some("cluster.internal")).expect("resolve dns san");
    assert_eq!(attr.node_id, "node-a");
    assert_eq!(attr.service_name, None);
}
