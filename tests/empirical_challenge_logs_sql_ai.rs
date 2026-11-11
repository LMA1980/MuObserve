// SPDX-License-Identifier: AGPL-3.0-only
//! Empirical Challenger 2 Test Suite: Log SQL Pushdown, Facet Filtering, Tokenizer Operators,
//! SSE Event Classification, and AI Diagnosis Fallback (Milestone 2).

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use mu_observable_hub::analytics::{
    generate_statistical_diagnosis, synthesize_ai_diagnosis, CausalProblemsFeedResponse,
};
use mu_observable_hub::mcp::McpServer;
use mu_observable_hub::server::console_api::LogFacetsResponse;
use mu_observable_hub::server::LogsQueryResponse;
use mu_observable_hub::storage::tokenize_log_line;
use mu_observable_hub::{build_console_api_router, HotDuckDbStore};
use mu_observable_ipc::{OtelLogEntry, OtelSpanEntry};
use tower::ServiceExt;

/// Challenge 1: Log Search SQL pushdown.
///
/// Ingest 600 logs total:
/// - 550 newer logs with timestamps 10_000_000_000_000 ns to 10_549_000_000_000 ns:
///   severity INFO (9), service "frontend"
/// - 50 older logs with timestamps 1_000_000_000_000 ns to 1_049_000_000_000 ns:
///   severity ERROR (17), service "backend-auth"
///
/// Pre-pushdown SQL (`SELECT ... FROM v_logs ORDER BY ts DESC LIMIT 500`) with memory filtering
/// would load only the 500 newest INFO logs and return 0 hits for severity=error, service=backend-auth,
/// or older time ranges.
///
/// With SQL pushdown WHERE filtering, DuckDB filters before LIMIT 500, correctly returning the
/// older matching logs.
#[tokio::test]
async fn test_empirical_challenge_1_sql_pushdown_where_filtering() {
    let store = HotDuckDbStore::open_in_memory().expect("open store");
    let router = build_console_api_router(store.clone());

    let mut logs = Vec::with_capacity(600);

    // 50 older ERROR logs on "backend-auth" (timestamps 1_000_000 ms to 1_049_000 ms)
    for i in 0..50 {
        let ts_ms = 1_000_000 + i * 1_000;
        logs.push(OtelLogEntry {
            timestamp_unix_nano: ts_ms * 1_000_000,
            trace_id: format!("trace-auth-{i}"),
            span_id: format!("span-auth-{i}"),
            severity_number: 17,
            severity_text: "ERROR".into(),
            body: format!("Authentication failed for user {i}: invalid credential hash"),
            service_name: "backend-auth".into(),
            node_id: "node-a".into(),
            job_id: None,
            stage_id: None,
            attributes_json: "{}".into(),
        });
    }

    // 550 newer INFO logs on "frontend" (timestamps 10_000_000 ms to 10_549_000 ms)
    for i in 0..550 {
        let ts_ms = 10_000_000 + i * 1_000;
        logs.push(OtelLogEntry {
            timestamp_unix_nano: ts_ms * 1_000_000,
            trace_id: format!("trace-front-{i}"),
            span_id: format!("span-front-{i}"),
            severity_number: 9,
            severity_text: "INFO".into(),
            body: format!("Page rendered index successfully item {i}"),
            service_name: "frontend".into(),
            node_id: "node-a".into(),
            job_id: None,
            stage_id: None,
            attributes_json: "{}".into(),
        });
    }

    let inserted = store.insert_logs(&logs).expect("insert 600 logs");
    assert_eq!(inserted, 600, "Must insert all 600 logs");

    // 1. Query by severity=error: MUST return all 50 older ERROR logs past the 550 top logs
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/logs?severity=error&limit=100")
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let query_resp: LogsQueryResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        query_resp.total, 50,
        "SQL pushdown must retrieve all 50 older ERROR logs without truncation by LIMIT 500"
    );
    for item in &query_resp.logs {
        assert_eq!(item.severity_text, "ERROR");
        assert_eq!(item.service, "backend-auth");
    }

    // 2. Query by service=backend-auth: MUST return all 50 older logs
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/logs?service=backend-auth&limit=100")
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let query_resp: LogsQueryResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        query_resp.total, 50,
        "SQL pushdown must retrieve all 50 backend-auth logs beyond the 550 newer frontend logs"
    );

    // 3. Query with time window from/to targeting older logs: from=900000, to=1100000 (ms)
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/logs?from=900000&to=1100000&limit=100")
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let query_resp: LogsQueryResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        query_resp.total, 50,
        "SQL pushdown on from/to bounds must return all 50 logs in the older time window"
    );

    // 4. Combined pushdown: severity=error & service=backend-auth & to=1100000
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/logs?severity=error&service=backend-auth&to=1100000&limit=100")
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let query_resp: LogsQueryResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(query_resp.total, 50);
}

/// Challenge 2: Facet query token filtering.
///
/// Ingest logs with distinct services and tokens:
/// - 20 logs: service: "payment-service", severity: ERROR, body: "database timeout in checkout flow"
/// - 30 logs: service: "auth-service", severity: INFO, body: "user login successful token issued"
/// - 50 logs: service: "search-service", severity: WARN, body: "cache miss on query index"
///
/// When querying /api/v1/logs/facets with ?q=checkout or ?token=checkout:
/// Verify all 4 queries (total_count, services, levels, histogram) reflect only the candidate token
/// hashes (20 payment-service ERROR logs) and not full database totals (100 logs).
#[tokio::test]
async fn test_empirical_challenge_2_facet_query_token_filtering() {
    let store = HotDuckDbStore::open_in_memory().expect("open store");
    let router = build_console_api_router(store.clone());

    let mut logs = Vec::new();
    let base_ts = 1_700_000_000_000_i64; // ms

    // 20 payment-service ERROR logs
    for i in 0..20 {
        logs.push(OtelLogEntry {
            timestamp_unix_nano: (base_ts + i * 1_000) * 1_000_000,
            trace_id: format!("tr-pay-{i}"),
            span_id: format!("sp-pay-{i}"),
            severity_number: 17,
            severity_text: "ERROR".into(),
            body: format!("database timeout in checkout flow transaction {i}"),
            service_name: "payment-service".into(),
            node_id: "node-a".into(),
            job_id: None,
            stage_id: None,
            attributes_json: "{}".into(),
        });
    }

    // 30 auth-service INFO logs
    for i in 0..30 {
        logs.push(OtelLogEntry {
            timestamp_unix_nano: (base_ts + (20 + i) * 1_000) * 1_000_000,
            trace_id: format!("tr-auth-{i}"),
            span_id: format!("sp-auth-{i}"),
            severity_number: 9,
            severity_text: "INFO".into(),
            body: format!("user login successful token issued session {i}"),
            service_name: "auth-service".into(),
            node_id: "node-a".into(),
            job_id: None,
            stage_id: None,
            attributes_json: "{}".into(),
        });
    }

    // 50 search-service WARN logs
    for i in 0..50 {
        logs.push(OtelLogEntry {
            timestamp_unix_nano: (base_ts + (50 + i) * 1_000) * 1_000_000,
            trace_id: format!("tr-search-{i}"),
            span_id: format!("sp-search-{i}"),
            severity_number: 13,
            severity_text: "WARN".into(),
            body: format!("cache miss on query index lookup {i}"),
            service_name: "search-service".into(),
            node_id: "node-a".into(),
            job_id: None,
            stage_id: None,
            attributes_json: "{}".into(),
        });
    }

    store.insert_logs(&logs).expect("insert 100 logs");

    // 1. Unfiltered facets: must show all 100 logs across 3 services and 3 levels
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/logs/facets")
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let full_facets: LogFacetsResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(full_facets.total_count, 100);
    assert_eq!(full_facets.services.len(), 3);
    assert_eq!(full_facets.levels.len(), 3);
    let full_hist_sum: u64 = full_facets.histogram.iter().map(|b| b.count).sum();
    assert_eq!(full_hist_sum, 100);

    // 2. Filtered facets with ?q=checkout: must isolate the 20 payment-service ERROR logs
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/logs/facets?q=checkout")
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let q_facets: LogFacetsResponse = serde_json::from_slice(&bytes).unwrap();

    // Query 1: total_count
    assert_eq!(
        q_facets.total_count, 20,
        "total_count must reflect candidate token hashes (20), not full db (100)"
    );

    // Query 2: services
    assert_eq!(
        q_facets.services.len(),
        1,
        "services facet must only contain payment-service"
    );
    assert_eq!(q_facets.services[0].name, "payment-service");
    assert_eq!(q_facets.services[0].count, 20);

    // Query 3: levels
    assert_eq!(
        q_facets.levels.len(),
        1,
        "levels facet must only contain ERROR"
    );
    assert_eq!(q_facets.levels[0].name, "ERROR");
    assert_eq!(q_facets.levels[0].count, 20);

    // Query 4: histogram
    let hist_sum: u64 = q_facets.histogram.iter().map(|b| b.count).sum();
    let hist_err_sum: u64 = q_facets.histogram.iter().map(|b| b.error_count).sum();
    let hist_warn_sum: u64 = q_facets.histogram.iter().map(|b| b.warn_count).sum();
    let hist_info_sum: u64 = q_facets.histogram.iter().map(|b| b.info_count).sum();
    assert_eq!(hist_sum, 20, "histogram total count must sum to 20");
    assert_eq!(hist_err_sum, 20, "histogram error count must sum to 20");
    assert_eq!(hist_warn_sum, 0, "histogram warn count must be 0");
    assert_eq!(hist_info_sum, 0, "histogram info count must be 0");

    // 3. Filtered facets with ?token=login: must isolate the 30 auth-service INFO logs
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/logs/facets?token=login")
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let login_facets: LogFacetsResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(login_facets.total_count, 30);
    assert_eq!(login_facets.services.len(), 1);
    assert_eq!(login_facets.services[0].name, "auth-service");
    assert_eq!(login_facets.services[0].count, 30);
    assert_eq!(login_facets.levels.len(), 1);
    assert_eq!(login_facets.levels[0].name, "INFO");
    assert_eq!(login_facets.levels[0].count, 30);

    // 4. Filtered facets with unmatched token: ?q=nonexistent_token_xyz
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/logs/facets?q=nonexistent_token_xyz")
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let empty_facets: LogFacetsResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(empty_facets.total_count, 0);
    assert!(empty_facets.services.is_empty());
    assert!(empty_facets.levels.is_empty());
    assert!(empty_facets.histogram.is_empty());
}

/// Challenge 3: Tokenizer `<` and `>` operator preservation.
///
/// Verifies strings like `cpu>90` or `<critical>` preserve the operators in token indexing
/// and query tokenization, without splitting or stripping them.
#[tokio::test]
async fn test_empirical_challenge_3_tokenizer_operators_preservation() {
    let store = HotDuckDbStore::open_in_memory().expect("open store");
    let router = build_console_api_router(store.clone());

    let entry = OtelLogEntry {
        timestamp_unix_nano: 1_700_000_000_000_000_000,
        trace_id: "tr-tok-1".into(),
        span_id: "sp-tok-1".into(),
        severity_number: 17,
        severity_text: "ERROR".into(),
        body: "Alert triggered: cpu>90 threshold breached, system entered <critical> status".into(),
        service_name: "telemetry-agent".into(),
        node_id: "node-a".into(),
        job_id: None,
        stage_id: None,
        attributes_json: "{}".into(),
    };

    // 1. Direct unit verification of tokenize_log_line
    let tokens = tokenize_log_line(&entry, &entry.body);
    assert!(
        tokens.contains(&"cpu>90".to_string()),
        "Tokens must preserve 'cpu>90'; got tokens: {:?}",
        tokens
    );
    assert!(
        tokens.contains(&"<critical>".to_string()),
        "Tokens must preserve '<critical>'; got tokens: {:?}",
        tokens
    );

    // 2. Ingest into store and search using inverted index
    store.insert_logs(&[entry]).expect("insert log entry");

    // Search by "cpu>90"
    let hits_cpu = store
        .search_logs_by_token("cpu>90", None, 10)
        .expect("search cpu>90");
    assert_eq!(hits_cpu.len(), 1, "Must find log by token 'cpu>90'");
    assert!(hits_cpu[0].body.contains("cpu>90"));

    // Search by "<critical>"
    let hits_crit = store
        .search_logs_by_token("<critical>", None, 10)
        .expect("search <critical>");
    assert_eq!(hits_crit.len(), 1, "Must find log by token '<critical>'");
    assert!(hits_crit[0].body.contains("<critical>"));

    // 3. Search via console API router with URL encoded operators
    let req_cpu = Request::builder()
        .method("GET")
        .uri("/api/v1/logs?q=cpu%3E90")
        .body(Body::empty())
        .unwrap();
    let resp_cpu = router.clone().oneshot(req_cpu).await.unwrap();
    assert_eq!(resp_cpu.status(), StatusCode::OK);
    let bytes = resp_cpu.into_body().collect().await.unwrap().to_bytes();
    let query_cpu: LogsQueryResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(query_cpu.total, 1);

    let req_crit = Request::builder()
        .method("GET")
        .uri("/api/v1/logs?token=%3Ccritical%3E")
        .body(Body::empty())
        .unwrap();
    let resp_crit = router.clone().oneshot(req_crit).await.unwrap();
    assert_eq!(resp_crit.status(), StatusCode::OK);
    let bytes = resp_crit.into_body().collect().await.unwrap().to_bytes();
    let query_crit: LogsQueryResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(query_crit.total, 1);
}

/// Challenge 4: SSE event classification.
///
/// Broadcast a log entry containing the text `"problem_id"`.
/// Verify the SSE event is emitted as `event: log_entry` and not `event: problem_opened`.
#[tokio::test]
async fn test_empirical_challenge_4_sse_event_classification() {
    let store = HotDuckDbStore::open_in_memory().expect("open store");
    let router = build_console_api_router(store.clone());

    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/events")
        .body(Body::empty())
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let mut body = resp.into_body();

    // Now insert a log entry containing "problem_id" in its body
    let log_with_problem_id = OtelLogEntry {
        timestamp_unix_nano: 1_700_000_100_000_000_000,
        trace_id: "tr-sse-1".into(),
        span_id: "sp-sse-1".into(),
        severity_number: 17,
        severity_text: "ERROR".into(),
        body: "Out of memory in worker task, associated problem_id: prob-98765 assigned".into(),
        service_name: "worker-pool".into(),
        node_id: "node-a".into(),
        job_id: None,
        stage_id: None,
        attributes_json: "{}".into(),
    };

    // Ingest the log, which triggers broadcast_event with {"log_entry": true, ..., "message": "..."}
    store
        .insert_logs(&[log_with_problem_id])
        .expect("insert log entry");

    // Read next frame from SSE stream
    let frame_opt = tokio::time::timeout(Duration::from_secs(2), body.frame())
        .await
        .expect("SSE frame read timed out")
        .expect("SSE stream ended unexpectedly");

    let frame = frame_opt.expect("frame result");
    let data_bytes = frame.into_data().unwrap_or_default();
    let sse_text = String::from_utf8_lossy(&data_bytes);

    println!("SSE Stream Output Frame:\n{sse_text}");

    // In SSE framing, Axum serializes event name as `event: <name>\n`
    assert!(
        sse_text.contains("event: log_entry"),
        "Log entry mentioning 'problem_id' must be classified as 'event: log_entry', got:\n{sse_text}"
    );
    assert!(
        !sse_text.contains("event: problem_opened"),
        "Must NOT be misclassified as 'event: problem_opened', got:\n{sse_text}"
    );
    assert!(
        sse_text.contains("problem_id: prob-98765"),
        "Frame data must contain the log message body"
    );
}

/// Challenge 5: AI diagnosis fallback.
///
/// Query problems when `JERO_MANAGER_URL` / `OPENAI_API_BASE` is unset or pointing to a dead port.
/// Verify the handler falls back cleanly to statistical diagnosis without panicking or returning HTTP 500.
#[tokio::test(flavor = "multi_thread")]
async fn test_empirical_challenge_5_ai_diagnosis_fallback() {
    let store = HotDuckDbStore::open_in_memory().expect("open store");

    let now = 1_700_000_000_000_000_000_i64;
    let trace_id = "trace-ai-test-1";

    // Insert 4-hop causal problem trace
    let s1 = OtelSpanEntry {
        trace_id: trace_id.into(),
        span_id: "s-ingress-1".into(),
        parent_span_id: None,
        service_name: "ingress-gateway".into(),
        node_id: "node-a".into(),
        span_name: "GET /api/checkout".into(),
        span_kind: "SERVER".into(),
        start_time_unix_nano: now,
        end_time_unix_nano: now + 5_000_000_000,
        duration_ns: 5_000_000_000,
        status_code: "ERROR".into(),
        status_message: Some("500 Internal Server Error".into()),
        attributes_json: "{}".into(),
    };

    let s2 = OtelSpanEntry {
        trace_id: trace_id.into(),
        span_id: "s-order-2".into(),
        parent_span_id: Some("s-ingress-1".into()),
        service_name: "order-service".into(),
        node_id: "node-a".into(),
        span_name: "order.create".into(),
        span_kind: "INTERNAL".into(),
        start_time_unix_nano: now + 100_000_000,
        end_time_unix_nano: now + 4_900_000_000,
        duration_ns: 4_800_000_000,
        status_code: "ERROR".into(),
        status_message: Some("inventory check failed".into()),
        attributes_json: "{}".into(),
    };

    let s3 = OtelSpanEntry {
        trace_id: trace_id.into(),
        span_id: "s-inventory-3".into(),
        parent_span_id: Some("s-order-2".into()),
        service_name: "inventory-service".into(),
        node_id: "node-b".into(),
        span_name: "inventory.reserve".into(),
        span_kind: "INTERNAL".into(),
        start_time_unix_nano: now + 200_000_000,
        end_time_unix_nano: now + 4_800_000_000,
        duration_ns: 4_600_000_000,
        status_code: "ERROR".into(),
        status_message: Some("database lock timeout".into()),
        attributes_json: "{}".into(),
    };

    let s4 = OtelSpanEntry {
        trace_id: trace_id.into(),
        span_id: "s-db-4".into(),
        parent_span_id: Some("s-inventory-3".into()),
        service_name: "inventory-db".into(),
        node_id: "node-c".into(),
        span_name: "SELECT FOR UPDATE items".into(),
        span_kind: "CLIENT".into(),
        start_time_unix_nano: now + 300_000_000,
        end_time_unix_nano: now + 4_700_000_000,
        duration_ns: 4_400_000_000,
        status_code: "ERROR".into(),
        status_message: Some("Deadlock detected on item locks".into()),
        attributes_json: "{}".into(),
    };

    let log = OtelLogEntry {
        timestamp_unix_nano: now + 4_600_000_000,
        trace_id: trace_id.into(),
        span_id: "s-db-4".into(),
        severity_number: 17,
        severity_text: "FATAL".into(),
        body: "FATAL: deadlock detected in postgres process 8192; transaction aborted".into(),
        service_name: "inventory-db".into(),
        node_id: "node-c".into(),
        job_id: None,
        stage_id: None,
        attributes_json: "{}".into(),
    };

    store.insert_spans_batch(&[s1, s2, s3, s4]).unwrap();
    store.insert_logs_batch(&[log]).unwrap();

    // --- Sub-test 5A: Environment variables UNSET ---
    std::env::remove_var("JERO_MANAGER_URL");
    std::env::remove_var("OPENAI_API_BASE");

    // 1. Direct synthesize_ai_diagnosis call
    let chain = vec![
        "ingress-gateway".to_string(),
        "order-service".to_string(),
        "inventory-service".to_string(),
        "inventory-db".to_string(),
    ];
    let direct_fallback = synthesize_ai_diagnosis(
        "ingress-gateway",
        "inventory-db",
        &chain,
        Some("Deadlock detected on item locks"),
        "error_rate",
        0.95,
    )
    .await;
    let expected_stat = generate_statistical_diagnosis(
        "ingress-gateway",
        "inventory-db",
        &chain,
        Some("Deadlock detected on item locks"),
        "error_rate",
        0.95,
    );
    assert_eq!(
        direct_fallback, expected_stat,
        "When env vars are unset, synthesize_ai_diagnosis must match statistical fallback exactly"
    );

    // 2. HTTP GET /api/v1/problems with env vars unset
    let router_unset = build_console_api_router(store.clone());
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/problems?window_secs=300")
        .body(Body::empty())
        .unwrap();
    let resp = router_unset.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "Endpoint must return 200 OK when LLM env vars are unset"
    );
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let prob_resp: CausalProblemsFeedResponse = serde_json::from_slice(&bytes).unwrap();
    assert!(
        !prob_resp.problems.is_empty(),
        "Expected causal problems detected"
    );
    for p in &prob_resp.problems {
        let ai = p
            .ai_diagnosis
            .as_ref()
            .expect("ai_diagnosis must be populated");
        assert!(
            ai.contains("Statistical Root-Cause Synthesis"),
            "ai_diagnosis must contain statistical fallback summary, got: {ai}"
        );
    }

    // --- Sub-test 5B: JERO_MANAGER_URL pointing to a DEAD port ---
    // Port 1 is standard tcpmux and closed; connection will be refused immediately.
    std::env::set_var("JERO_MANAGER_URL", "http://127.0.0.1:1");

    // 1. Direct synthesize_ai_diagnosis with dead port: must return within timeout and fallback cleanly
    let dead_port_diag = synthesize_ai_diagnosis(
        "ingress-gateway",
        "inventory-db",
        &chain,
        Some("Deadlock detected on item locks"),
        "error_rate",
        0.95,
    )
    .await;
    assert_eq!(
        dead_port_diag, expected_stat,
        "Dead port must gracefully fall back to statistical diagnosis"
    );

    // 2. HTTP GET /api/v1/problems with dead port: must return HTTP 200 without panicking
    let router_dead = build_console_api_router(store.clone());
    let req_dead = Request::builder()
        .method("GET")
        .uri("/api/v1/problems?window_secs=300")
        .body(Body::empty())
        .unwrap();
    let resp_dead = router_dead.oneshot(req_dead).await.unwrap();
    assert_eq!(
        resp_dead.status(),
        StatusCode::OK,
        "Endpoint must return 200 OK (not 500) even when JERO_MANAGER_URL points to dead port"
    );
    let bytes_dead = resp_dead.into_body().collect().await.unwrap().to_bytes();
    let prob_resp_dead: CausalProblemsFeedResponse = serde_json::from_slice(&bytes_dead).unwrap();
    for p in &prob_resp_dead.problems {
        let ai = p.ai_diagnosis.as_ref().unwrap();
        assert!(
            ai.contains("Statistical Root-Cause Synthesis"),
            "Dead port ai_diagnosis must contain statistical fallback, got: {ai}"
        );
    }

    // --- Sub-test 5C: MCP server diagnose_anomaly_ai tool with dead port ---
    let mcp = McpServer::new(store.clone());
    let rpc_req = mu_observable_hub::mcp::JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(serde_json::json!(1)),
        method: "tools/call".to_string(),
        params: serde_json::json!({
            "name": "diagnose_anomaly_ai",
            "arguments": {
                "trace_id": trace_id,
                "service_name": "ingress-gateway"
            }
        }),
    };
    let mcp_resp = mcp.handle_request(&rpc_req);
    assert!(
        mcp_resp.error.is_none(),
        "MCP call must not return RPC error: {:?}",
        mcp_resp.error
    );
    let result_val = mcp_resp.result.expect("result in mcp response");
    let ai_diag = result_val["structuredContent"]["ai_diagnosis"]
        .as_str()
        .expect("ai_diagnosis field in structuredContent");
    assert!(
        ai_diag.contains("Statistical Root-Cause Synthesis"),
        "MCP tool result must contain statistical fallback diagnosis, got: {ai_diag}"
    );

    // Clean up environment variables
    std::env::remove_var("JERO_MANAGER_URL");
}

/// Adversarial Challenge 6: Stress test SQL Pushdown edge cases.
///
/// Inverted time bounds (`from` > `to`), case-insensitive service filters,
/// negative timestamps, and severity aliases (`FATAL`, `errors`).
#[tokio::test]
async fn test_empirical_challenge_6_adversarial_sql_pushdown_edge_cases() {
    let store = HotDuckDbStore::open_in_memory().expect("open store");
    let router = build_console_api_router(store.clone());

    let entry_fatal = OtelLogEntry {
        timestamp_unix_nano: 1_700_000_000_000_000_000,
        trace_id: "tr-fat-1".into(),
        span_id: "sp-fat-1".into(),
        severity_number: 21,
        severity_text: "FATAL".into(),
        body: "Fatal kernel panicking condition".into(),
        service_name: "Host-Kernel".into(),
        node_id: "node-a".into(),
        job_id: None,
        stage_id: None,
        attributes_json: "{}".into(),
    };
    store.insert_logs(&[entry_fatal]).unwrap();

    // 1. Inverted time window: from > to
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/logs?from=2000000000000&to=1000000000000")
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let q: LogsQueryResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        q.total, 0,
        "Inverted time window must return 0 hits cleanly"
    );

    // 2. Case-insensitive service pushdown: "host-kernel" vs "Host-Kernel"
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/logs?service=host-kernel")
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let q: LogsQueryResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        q.total, 1,
        "Case-insensitive SQL pushdown must match service"
    );

    // 3. Severity alias "errors" matching FATAL (severity_number 21)
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/logs?severity=errors")
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let q: LogsQueryResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(q.total, 1, "Severity filter 'errors' must match FATAL log");

    // 4. Negative timestamp bound
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/logs?from=-1000")
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let q: LogsQueryResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        q.total, 1,
        "Negative timestamp must clamp to 0 without underflow"
    );
}

/// Adversarial Challenge 7: Stress test Facets with operator tokens and token intersections.
#[tokio::test]
async fn test_empirical_challenge_7_adversarial_facets_operators_and_multi_token() {
    let store = HotDuckDbStore::open_in_memory().expect("open store");
    let router = build_console_api_router(store.clone());

    let e1 = OtelLogEntry {
        timestamp_unix_nano: 1_700_000_000_000_000_000,
        trace_id: "tr-op-1".into(),
        span_id: "sp-op-1".into(),
        severity_number: 17,
        severity_text: "ERROR".into(),
        body: "Alert cpu>90 detected along with memory<10%".into(),
        service_name: "node-agent".into(),
        node_id: "node-a".into(),
        job_id: None,
        stage_id: None,
        attributes_json: "{}".into(),
    };

    let e2 = OtelLogEntry {
        timestamp_unix_nano: 1_700_000_001_000_000_000,
        trace_id: "tr-op-2".into(),
        span_id: "sp-op-2".into(),
        severity_number: 13,
        severity_text: "WARN".into(),
        body: "Alert cpu>90 detected but system stable".into(),
        service_name: "node-agent".into(),
        node_id: "node-a".into(),
        job_id: None,
        stage_id: None,
        attributes_json: "{}".into(),
    };

    let e3 = OtelLogEntry {
        timestamp_unix_nano: 1_700_000_002_000_000_000,
        trace_id: "tr-op-3".into(),
        span_id: "sp-op-3".into(),
        severity_number: 9,
        severity_text: "INFO".into(),
        body: "Regular heartbeat report normal".into(),
        service_name: "telemetry-srv".into(),
        node_id: "node-a".into(),
        job_id: None,
        stage_id: None,
        attributes_json: "{}".into(),
    };

    store.insert_logs(&[e1, e2, e3]).unwrap();

    // 1. Facet search for "cpu>90" (URL encoded as cpu%3E90)
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/logs/facets?q=cpu%3E90")
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let f: LogFacetsResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        f.total_count, 2,
        "Facets for cpu>90 must match exactly 2 logs"
    );
    assert_eq!(f.services.len(), 1);
    assert_eq!(f.services[0].name, "node-agent");
    assert_eq!(f.levels.len(), 2); // 1 ERROR, 1 WARN

    // 2. Multi-token intersection: "cpu>90" and "detected"
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/logs/facets?q=cpu%3E90%20memory%3C10%25")
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let f: LogFacetsResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(f.total_count, 1, "Intersection must isolate 1 log");
    assert_eq!(f.levels[0].name, "ERROR");
}

/// Adversarial Challenge 8: Raw JSON in log body containing `"problem_id"`.
#[tokio::test]
async fn test_empirical_challenge_8_adversarial_sse_raw_json_problem_id() {
    let store = HotDuckDbStore::open_in_memory().expect("open store");
    let router = build_console_api_router(store.clone());

    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/events")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mut body = resp.into_body();

    // Ingest a log entry where the body itself is verbatim JSON containing "problem_id": "prob-crash-44"
    let raw_json_log = OtelLogEntry {
        timestamp_unix_nano: 1_700_000_999_000_000_000,
        trace_id: "tr-sse-raw".into(),
        span_id: "sp-sse-raw".into(),
        severity_number: 17,
        severity_text: "ERROR".into(),
        body: r#"{"problem_id":"prob-crash-44","detail":"kernel panic occurred"}"#.into(),
        service_name: "crash-reporter".into(),
        node_id: "node-a".into(),
        job_id: None,
        stage_id: None,
        attributes_json: "{}".into(),
    };

    store.insert_logs(&[raw_json_log]).unwrap();

    let frame_opt = tokio::time::timeout(Duration::from_secs(2), body.frame())
        .await
        .expect("SSE frame read timed out")
        .expect("SSE stream ended unexpectedly");
    let frame = frame_opt.expect("frame result");
    let data_bytes = frame.into_data().unwrap_or_default();
    let sse_text = String::from_utf8_lossy(&data_bytes);

    assert!(
        sse_text.contains("event: log_entry"),
        "Must be classified as log_entry despite containing raw JSON problem_id, got:\n{sse_text}"
    );
    assert!(
        !sse_text.contains("event: problem_opened"),
        "Must not be misclassified as problem_opened"
    );
}

/// Adversarial Challenge 9: AI diagnosis fallback under malformed URLs and broken HTTP upstreams.
#[tokio::test]
async fn test_empirical_challenge_9_adversarial_ai_fallback_broken_upstreams() {
    let chain = vec!["web".to_string(), "api".to_string()];

    // 1. Malformed URL strings
    for bad_url in &[
        "not_a_valid_url",
        "http://",
        "http://256.256.256.256:8080",
        "http://127.0.0.1:99999",
        "ftp://invalid-scheme",
    ] {
        std::env::set_var("JERO_MANAGER_URL", bad_url);
        let diag = synthesize_ai_diagnosis(
            "web",
            "api",
            &chain,
            Some("Service Unavailable"),
            "latency",
            0.88,
        )
        .await;
        assert!(
            diag.contains("Statistical Root-Cause Synthesis"),
            "Failed fallback for malformed URL '{bad_url}': {diag}"
        );
    }

    // 2. Upstream HTTP server that returns HTTP 500
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await;
            let resp = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n";
            let _ = socket.write_all(resp.as_bytes()).await;
        }
    });

    let mock_url = format!("http://{local_addr}");
    std::env::set_var("JERO_MANAGER_URL", &mock_url);

    let diag = synthesize_ai_diagnosis(
        "web",
        "api",
        &chain,
        Some("Upstream Error"),
        "latency",
        0.88,
    )
    .await;
    assert!(
        diag.contains("Statistical Root-Cause Synthesis"),
        "HTTP 500 upstream must trigger clean statistical fallback, got: {diag}"
    );

    std::env::remove_var("JERO_MANAGER_URL");
}
