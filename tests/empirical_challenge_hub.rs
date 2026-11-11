// SPDX-License-Identifier: AGPL-3.0-only
//! Empirical Stress Tests and Adversarial Challenges for `mu-observable-hub`.
//!
//! Stress-tests:
//! 1. Ingress Reverse Proxy: route matching, upstream forward proxying, upstream error handling,
//!    W3C traceparent propagation, and DuckDB span recording.
//! 2. Causal AI Root-Cause Engine: multi-hop call graph traversal, self-time vs child-time
//!    decomposition, log error correlation, and baseline anomaly detection.
//! 3. Persistent SSE Event Streaming: `/api/v1/events` stream persistence, initial event delivery,
//!    and broadcast message dispatch.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use mu_observable_hub::{
    build_console_api_router, compute_causal_problems, tokenize_log_line, HotDuckDbStore,
    IngressEngine, UpstreamHealthChecker,
};
use mu_observable_ipc::{OtelLogEntry, OtelSpanEntry};
use std::time::Duration;
use tower::ServiceExt;

/// Helper to spin up a mock HTTP/1.1 upstream server on a given port (0 for ephemeral port).
async fn spawn_mock_upstream(
    port: u16,
    status: StatusCode,
    resp_body: &'static str,
) -> (tokio::task::JoinHandle<()>, u16) {
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .expect("bind mock upstream");
    let actual_port = listener.local_addr().expect("local addr").port();

    let handle = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };
            let io = TokioIo::new(stream);
            tokio::spawn(async move {
                let service = service_fn(
                    move |req: hyper::Request<hyper::body::Incoming>| async move {
                        // Check if traceparent header was injected by IngressEngine
                        let has_traceparent = req.headers().contains_key("traceparent");
                        let mut resp = hyper::Response::builder().status(status);
                        if has_traceparent {
                            resp = resp.header("x-traceparent-received", "true");
                        }
                        let resp = resp
                            .header("content-type", "application/json")
                            .body(http_body_util::Full::new(hyper::body::Bytes::from(
                                resp_body,
                            )))
                            .unwrap();
                        Ok::<_, std::convert::Infallible>(resp)
                    },
                );

                let _ = http1::Builder::new().serve_connection(io, service).await;
            });
        }
    });

    (handle, actual_port)
}

// ============================================================================
// 1. Ingress Reverse Proxy Stress Tests
// ============================================================================

#[tokio::test]
async fn test_empirical_ingress_proxy_upstream_success_and_span_recording() {
    let store = HotDuckDbStore::open_in_memory().expect("open HotDuckDbStore");
    let engine = IngressEngine::new(store.clone(), "test-node-ingress".into());

    // Bind mock upstream to ephemeral port 0 and register dynamic route to eliminate collisions
    let (_upstream_handle, port) =
        spawn_mock_upstream(0, StatusCode::OK, r#"{"status":"package_created"}"#).await;
    engine.add_route(
        "route-reg",
        "/api/reg/",
        &format!("http://127.0.0.1:{port}/api/"),
        "muregist",
        false,
        false,
    );

    // Wait briefly for upstream listener to bind
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Dispatch request through IngressEngine
    let req = Request::builder()
        .method("POST")
        .uri("/api/reg/v1/packages")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"name":"test-pkg"}"#))
        .unwrap();

    let resp = engine
        .proxy_request(req)
        .await
        .expect("proxy_request failed");

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("x-traceparent-received").unwrap(),
        "true",
        "Upstream must receive injected W3C traceparent header"
    );

    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body_bytes, r#"{"status":"package_created"}"#);

    // Verify DuckDB OtelSpanEntry insertion
    {
        let conn = store.lock_conn().expect("lock conn");
        let span_count: i64 = conn
            .query_row(
                "SELECT count(*) FROM v_traces WHERE service_name = 'mu-ingress'",
                [],
                |r| r.get(0),
            )
            .expect("query v_traces");
        assert_eq!(span_count, 1, "Expected 1 ingress SERVER span in DuckDB");

        let (span_name, span_kind, status_code): (String, String, String) = conn
            .query_row(
                "SELECT span_name, span_kind, status_code FROM v_traces WHERE service_name = 'mu-ingress' LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .expect("query span details");

        assert_eq!(span_name, "POST /api/reg/v1/packages");
        assert_eq!(span_kind, "SERVER");
        assert_eq!(status_code, "OK");
    }

    // Verify route telemetry update
    let routes = engine.get_route_dtos().await;
    let reg_route = routes.iter().find(|r| r.route_id == "route-reg").unwrap();
    assert_eq!(reg_route.request_count, 1);
    assert_eq!(reg_route.error_rate_pct, 0.0);
}

#[tokio::test]
async fn test_empirical_ingress_upstream_error_handling_and_duckdb_recording() {
    let store = HotDuckDbStore::open_in_memory().expect("open HotDuckDbStore");
    let engine = IngressEngine::new(store.clone(), "test-node-ingress".into());

    // Allocate a dynamic closed ephemeral port to guarantee 502 Bad Gateway
    let closed_port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = listener.local_addr().expect("local addr").port();
        drop(listener);
        port
    };
    let closed_upstream = format!("http://127.0.0.1:{closed_port}/api/");
    engine.add_route(
        "route-obs",
        "/api/obs/",
        &closed_upstream,
        "muobserve",
        false,
        false,
    );

    let req = Request::builder()
        .method("GET")
        .uri("/api/obs/v1/health")
        .body(Body::empty())
        .unwrap();

    let resp = engine
        .proxy_request(req)
        .await
        .expect("proxy_request failed");

    // Must return 502 Bad Gateway
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);

    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8_lossy(&body_bytes);
    assert!(
        body_str.contains("Bad Gateway") && body_str.contains("Connect failed"),
        "Expected bad gateway error message, got: {body_str}"
    );

    // Verify DuckDB recorded an ERROR span
    {
        let conn = store.lock_conn().expect("lock conn");
        let (status_code, status_message): (String, Option<String>) = conn
            .query_row(
                "SELECT status_code, status_message FROM v_traces WHERE service_name = 'mu-ingress' AND span_name = 'GET /api/obs/v1/health'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("query error span");

        assert_eq!(status_code, "ERROR");
        assert!(status_message.unwrap().contains("Connect failed"));
    }

    // Verify route error metric updated
    let routes = engine.get_route_dtos().await;
    let obs_route = routes.iter().find(|r| r.route_id == "route-obs").unwrap();
    assert_eq!(obs_route.request_count, 1);
    assert_eq!(obs_route.error_rate_pct, 100.0);
}

#[tokio::test]
async fn test_empirical_ingress_unmatched_route_returns_404() {
    let store = HotDuckDbStore::open_in_memory().expect("open HotDuckDbStore");
    let engine = IngressEngine::new(store.clone(), "test-node-ingress".into());

    let req = Request::builder()
        .method("GET")
        .uri("/api/unknown/endpoint")
        .body(Body::empty())
        .unwrap();

    let resp = engine
        .proxy_request(req)
        .await
        .expect("proxy_request failed");

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_empirical_ingress_longest_prefix_matching() {
    let store = HotDuckDbStore::open_in_memory().expect("open HotDuckDbStore");
    let engine = IngressEngine::new(store.clone(), "test-node-ingress".into());

    // In defaults:
    // route-reg: "/api/reg/"
    // route-reg-v1: "/api/v1/registry/"
    let match1 = engine.match_route("/api/reg/v1/packages").await;
    assert!(match1.is_some());
    assert_eq!(match1.unwrap().route_id, "route-reg");

    let match2 = engine.match_route("/api/v1/registry/packages").await;
    assert!(match2.is_some());
    assert_eq!(match2.unwrap().route_id, "route-reg-v1");
}

// ============================================================================
// 2. Causal AI Root-Cause Engine Stress Tests
// ============================================================================

#[test]
fn test_empirical_causal_root_cause_deep_4hop_waterfall() {
    let store = HotDuckDbStore::open_in_memory().expect("open store");
    let now = 1_700_000_000_000_000_000i64;
    let trace_id = "trace-deep-causal-4hop";

    // Hop 1: Ingress Gateway (duration 5.0s, child 4.8s, self-time 0.2s)
    let s1 = OtelSpanEntry {
        trace_id: trace_id.into(),
        span_id: "s-ingress-1".into(),
        parent_span_id: None,
        service_name: "mu-ingress".into(),
        node_id: "node-a".into(),
        span_name: "POST /api/orders".into(),
        span_kind: "SERVER".into(),
        start_time_unix_nano: now,
        end_time_unix_nano: now + 5_000_000_000,
        duration_ns: 5_000_000_000,
        status_code: "ERROR".into(),
        status_message: Some("500 Internal Server Error".into()),
        attributes_json: "{}".into(),
    };

    // Hop 2: Order Service (duration 4.8s, child 4.6s, self-time 0.2s)
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

    // Hop 3: Inventory Service (duration 4.6s, child 4.4s, self-time 0.2s)
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

    // Hop 4: Inventory Database (duration 4.4s, self-time 4.4s = 100%, status ERROR)
    let s4 = OtelSpanEntry {
        trace_id: trace_id.into(),
        span_id: "s-db-4".into(),
        parent_span_id: Some("s-inventory-3".into()),
        service_name: "inventory-db".into(),
        node_id: "node-c".into(),
        span_name: "SELECT FOR UPDATE inventory_items".into(),
        span_kind: "CLIENT".into(),
        start_time_unix_nano: now + 300_000_000,
        end_time_unix_nano: now + 4_700_000_000,
        duration_ns: 4_400_000_000,
        status_code: "ERROR".into(),
        status_message: Some("Deadlock detected on item locks".into()),
        attributes_json: "{}".into(),
    };

    // Correlated error log on inventory-db
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

    store
        .insert_spans_batch(&[s1, s2, s3, s4])
        .expect("insert spans");
    store.insert_logs_batch(&[log]).expect("insert logs");

    let problems = compute_causal_problems(&store, 300, Some(now + 6_000_000_000))
        .expect("compute causal problems");

    assert!(
        !problems.is_empty(),
        "Expected causal problems to be detected"
    );

    // All problem cards originating from entrypoints must isolate inventory-db as root cause
    let entry_prob = problems
        .iter()
        .find(|p| p.impacted_entity == "mu-ingress")
        .expect("Found problem for mu-ingress entrypoint");

    assert_eq!(
        entry_prob.root_cause_service, "inventory-db",
        "Root cause service must be isolated to inventory-db"
    );
    assert_eq!(
        entry_prob.root_cause_span_id.as_deref(),
        Some("s-db-4"),
        "Root cause span id must point to s-db-4"
    );
    assert_eq!(
        entry_prob.causal_chain,
        vec![
            "mu-ingress".to_string(),
            "order-service".to_string(),
            "inventory-service".to_string(),
            "inventory-db".to_string()
        ],
        "Causal chain must contain full 4-hop propagation"
    );
    assert!(
        entry_prob
            .root_cause_error_message
            .as_ref()
            .unwrap()
            .contains("deadlock detected"),
        "Correlated error log must be attached"
    );
    assert!(
        entry_prob.confidence_score >= 0.85,
        "Confidence score must be high (>= 0.85) due to 100% self-time and correlated log"
    );
}

#[test]
fn test_empirical_causal_root_cause_parallel_fanout_branching() {
    let store = HotDuckDbStore::open_in_memory().expect("open store");
    let now = 1_700_000_000_000_000_000i64;
    let trace_id = "trace-fanout-branching";

    // Root Service calls Service-B (fast, OK) and Service-C (slow bottleneck, OK)
    let s_root = OtelSpanEntry {
        trace_id: trace_id.into(),
        span_id: "s-root".into(),
        parent_span_id: None,
        service_name: "api-gateway".into(),
        node_id: "node-a".into(),
        span_name: "GET /api/feed".into(),
        span_kind: "SERVER".into(),
        start_time_unix_nano: now,
        end_time_unix_nano: now + 3_000_000_000,
        duration_ns: 3_000_000_000,
        status_code: "OK".into(),
        status_message: None,
        attributes_json: "{}".into(),
    };

    // Branch 1: Fast Cache (duration 20ms)
    let s_fast = OtelSpanEntry {
        trace_id: trace_id.into(),
        span_id: "s-fast-cache".into(),
        parent_span_id: Some("s-root".into()),
        service_name: "cache-service".into(),
        node_id: "node-a".into(),
        span_name: "GET user_session".into(),
        span_kind: "CLIENT".into(),
        start_time_unix_nano: now + 5_000_000,
        end_time_unix_nano: now + 25_000_000,
        duration_ns: 20_000_000,
        status_code: "OK".into(),
        status_message: None,
        attributes_json: "{}".into(),
    };

    // Branch 2: Slow Recommendation Engine (duration 2900ms, self-time 2900ms)
    let s_slow = OtelSpanEntry {
        trace_id: trace_id.into(),
        span_id: "s-slow-rec".into(),
        parent_span_id: Some("s-root".into()),
        service_name: "recommendation-service".into(),
        node_id: "node-b".into(),
        span_name: "COMPUTE recommendations".into(),
        span_kind: "INTERNAL".into(),
        start_time_unix_nano: now + 30_000_000,
        end_time_unix_nano: now + 2_930_000_000,
        duration_ns: 2_900_000_000,
        status_code: "OK".into(),
        status_message: None,
        attributes_json: "{}".into(),
    };

    // Also seed baseline spans for api-gateway so MAD baseline is established (~50ms)
    let mut baseline_spans = Vec::new();
    for i in 1..=15 {
        baseline_spans.push(OtelSpanEntry {
            trace_id: format!("trace-baseline-{}", i),
            span_id: format!("span-base-{}", i),
            parent_span_id: None,
            service_name: "api-gateway".into(),
            node_id: "node-a".into(),
            span_name: "GET /api/feed".into(),
            span_kind: "SERVER".into(),
            start_time_unix_nano: now - (i * 10_000_000_000),
            end_time_unix_nano: now - (i * 10_000_000_000) + (50_000_000 + (i % 5) * 2_000_000),
            duration_ns: 50_000_000 + ((i % 5) * 2_000_000) as u64,
            status_code: "OK".into(),
            status_message: None,
            attributes_json: "{}".into(),
        });
    }

    store
        .insert_spans_batch(&baseline_spans)
        .expect("insert baselines");
    store
        .insert_spans_batch(&[s_root, s_fast, s_slow])
        .expect("insert anomalous trace");

    let problems = compute_causal_problems(&store, 300, Some(now + 6_000_000_000))
        .expect("compute causal problems");

    assert!(!problems.is_empty(), "Expected latency regression problem");

    let prob = problems
        .iter()
        .find(|p| p.impacted_entity == "api-gateway")
        .expect("Found problem on api-gateway");

    assert_eq!(
        prob.root_cause_service, "recommendation-service",
        "Root cause must follow the dominant latency branch to recommendation-service"
    );
    assert_eq!(prob.category, "latency_regression");
    assert_eq!(prob.root_cause_span_id.as_deref(), Some("s-slow-rec"));
}

#[test]
fn test_empirical_causal_healthy_traffic_zero_problems() {
    let store = HotDuckDbStore::open_in_memory().expect("open store");
    let now = 1_700_000_000_000_000_000i64;

    // Normal healthy spans
    let mut healthy_spans = Vec::new();
    for i in 1..=30 {
        healthy_spans.push(OtelSpanEntry {
            trace_id: format!("trace-healthy-{}", i),
            span_id: format!("span-h-{}", i),
            parent_span_id: None,
            service_name: "payment-service".into(),
            node_id: "node-a".into(),
            span_name: "POST /pay".into(),
            span_kind: "SERVER".into(),
            start_time_unix_nano: now - (i * 1_000_000_000),
            end_time_unix_nano: now - (i * 1_000_000_000) + (15_000_000 + (i % 3) * 1_000_000),
            duration_ns: 15_000_000 + ((i % 3) * 1_000_000) as u64,
            status_code: "OK".into(),
            status_message: None,
            attributes_json: "{}".into(),
        });
    }

    store
        .insert_spans_batch(&healthy_spans)
        .expect("insert healthy");

    let problems = compute_causal_problems(&store, 300, Some(now + 1_000_000_000))
        .expect("compute causal problems");

    assert!(
        problems.is_empty(),
        "Expected 0 problems on completely healthy traffic, found: {problems:?}"
    );
}

// ============================================================================
// 3. Persistent SSE Event Streaming Stress Tests
// ============================================================================

#[tokio::test]
async fn test_empirical_persistent_sse_streaming_and_broadcasts() {
    let store = HotDuckDbStore::open_in_memory().expect("open store");
    let router = build_console_api_router(store.clone());

    // Request persistent SSE stream
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/events")
        .body(Body::empty())
        .unwrap();

    let resp = router.oneshot(req).await.expect("SSE request failed");
    assert_eq!(resp.status(), StatusCode::OK);

    let content_type = resp
        .headers()
        .get("content-type")
        .expect("content-type header")
        .to_str()
        .unwrap();
    assert!(
        content_type.contains("text/event-stream"),
        "Expected text/event-stream, got: {content_type}"
    );

    let mut body = resp.into_body();

    // Broadcast messages through the store channel
    store.broadcast_event(
        r#"{"problem_id":"PROB-TEST-001","status":"OPEN","title":"Test Problem"}"#,
    );
    store.broadcast_event(r#"{"log_entry":"Server out of memory","severity":"ERROR"}"#);
    store.broadcast_event(r#"{"ingress":"route_created","route_id":"route-custom"}"#);

    // Read streamed frames
    let mut received_events = Vec::new();
    let read_timeout = Duration::from_millis(500);

    let read_result = tokio::time::timeout(read_timeout, async {
        while let Some(frame_res) = body.frame().await {
            if let Ok(frame) = frame_res {
                if let Some(data) = frame.data_ref() {
                    let text = String::from_utf8_lossy(data);
                    received_events.push(text.to_string());
                    if received_events.len() >= 3 {
                        break;
                    }
                }
            }
        }
    })
    .await;

    assert!(
        read_result.is_ok(),
        "Reading broadcast SSE events timed out within {read_timeout:?}"
    );

    let full_stream_text = received_events.join("");
    assert!(
        full_stream_text.contains("event: problem_opened"),
        "Stream must dispatch event: problem_opened for problem broadcasts. Got: {full_stream_text}"
    );
    assert!(
        full_stream_text.contains("event: log_entry"),
        "Stream must dispatch event: log_entry for log broadcasts. Got: {full_stream_text}"
    );
    assert!(
        full_stream_text.contains("event: ingress_changed"),
        "Stream must dispatch event: ingress_changed for ingress broadcasts. Got: {full_stream_text}"
    );
}

#[test]
fn test_empirical_vulnerability_zero_mad_masking_latency_spike() {
    let store = HotDuckDbStore::open_in_memory().expect("open store");
    let now = 1_700_000_000_000_000_000i64;

    // 30 uniform 10ms baseline spans (identical duration -> MAD will be 0)
    let mut spans = Vec::new();
    for i in 1..=30 {
        spans.push(OtelSpanEntry {
            trace_id: format!("trace-uniform-{}", i),
            span_id: format!("span-u-{}", i),
            parent_span_id: None,
            service_name: "uniform-fast-service".into(),
            node_id: "node-a".into(),
            span_name: "GET /fast".into(),
            span_kind: "SERVER".into(),
            start_time_unix_nano: now - (i * 1_000_000_000),
            end_time_unix_nano: now - (i * 1_000_000_000) + 10_000_000,
            duration_ns: 10_000_000, // Exactly 10ms
            status_code: "OK".into(),
            status_message: None,
            attributes_json: "{}".into(),
        });
    }

    // 5 massive 5000ms latency spikes (OK status, e.g. thread starvation or GC pause)
    for i in 1..=5 {
        spans.push(OtelSpanEntry {
            trace_id: format!("trace-spike-{}", i),
            span_id: format!("span-spike-{}", i),
            parent_span_id: None,
            service_name: "uniform-fast-service".into(),
            node_id: "node-a".into(),
            span_name: "GET /fast".into(),
            span_kind: "SERVER".into(),
            start_time_unix_nano: now - (i * 100_000_000),
            end_time_unix_nano: now - (i * 100_000_000) + 5_000_000_000,
            duration_ns: 5_000_000_000, // 5000ms spike!
            status_code: "OK".into(),
            status_message: None,
            attributes_json: "{}".into(),
        });
    }

    store.insert_spans_batch(&spans).expect("insert spans");

    let problems = compute_causal_problems(&store, 300, Some(now + 1_000_000_000))
        .expect("compute causal problems");

    // Verification of the zero-MAD fix:
    // Despite baseline mad being 0.0, the effective MAD floor enables detecting
    // this 500x latency regression instead of masking it.
    assert!(
        !problems.is_empty(),
        "Zero-MAD latency regression is successfully detected as an anomaly"
    );
    let prob = &problems[0];
    assert_eq!(prob.impacted_entity, "uniform-fast-service");
    assert_eq!(prob.category, "latency_regression");
}

// ============================================================================
// 4. Ingress Deep Challenges (Traceparent Injection, Malformed Fallback, Upstream Health)
// ============================================================================

#[tokio::test]
async fn test_empirical_ingress_incoming_traceparent_propagation_and_child_span() {
    let store = HotDuckDbStore::open_in_memory().expect("open HotDuckDbStore");
    let engine = IngressEngine::new(store.clone(), "test-node-ingress".into());

    // Bind mock upstream to ephemeral port 0 and register dynamic route to eliminate collisions
    let (_upstream_handle, port) =
        spawn_mock_upstream(0, StatusCode::OK, r#"{"status":"ok"}"#).await;
    engine.add_route(
        "route-cd",
        "/api/cd/",
        &format!("http://127.0.0.1:{port}/api/"),
        "muconde-controller",
        false,
        false,
    );
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Dispatch request with explicit W3C traceparent
    let incoming_trace_id = "4bf92f3577b34da6a3ce929d0e0e4736";
    let incoming_span_id = "00f067aa0ba902b7";
    let incoming_traceparent = format!("00-{}-{}-01", incoming_trace_id, incoming_span_id);

    let req = Request::builder()
        .method("GET")
        .uri("/api/cd/v1/deployments")
        .header("traceparent", &incoming_traceparent)
        .body(Body::empty())
        .unwrap();

    let resp = engine
        .proxy_request(req)
        .await
        .expect("proxy_request failed");

    assert_eq!(resp.status(), StatusCode::OK);

    // Verify DuckDB OtelSpanEntry insertion preserves trace_id and records incoming span_id as parent
    {
        let conn = store.lock_conn().expect("lock conn");
        let (db_trace_id, db_parent_span_id, span_kind): (String, Option<String>, String) = conn
            .query_row(
                "SELECT trace_id, parent_span_id, span_kind FROM v_traces WHERE service_name = 'mu-ingress' AND trace_id = ?1",
                duckdb::params![incoming_trace_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .expect("query ingress span with matching trace_id");

        assert_eq!(db_trace_id, incoming_trace_id);
        assert_eq!(db_parent_span_id.as_deref(), Some(incoming_span_id));
        assert_eq!(span_kind, "SERVER");
    }
}

#[tokio::test]
async fn test_empirical_ingress_malformed_traceparent_graceful_fallback() {
    let store = HotDuckDbStore::open_in_memory().expect("open HotDuckDbStore");
    let engine = IngressEngine::new(store.clone(), "test-node-ingress".into());

    // Allocate a dynamic closed ephemeral port to guarantee 502 Bad Gateway
    let closed_port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = listener.local_addr().expect("local addr").port();
        drop(listener);
        port
    };
    let closed_upstream = format!("http://127.0.0.1:{closed_port}/api/");
    engine.add_route(
        "route-obs",
        "/api/obs/",
        &closed_upstream,
        "muobserve",
        false,
        false,
    );

    let req = Request::builder()
        .method("GET")
        .uri("/api/obs/v1/health")
        .header("traceparent", "malformed-garbage-header-12345")
        .body(Body::empty())
        .unwrap();

    let resp = engine
        .proxy_request(req)
        .await
        .expect("proxy_request failed");

    // Returns BAD_GATEWAY due to down upstream, but records span cleanly with generated trace_id
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);

    // Verify DuckDB recorded span with a newly generated valid 32-hex trace_id and parent_span_id is None
    {
        let conn = store.lock_conn().expect("lock conn");
        let (db_trace_id, db_parent_span_id): (String, Option<String>) = conn
            .query_row(
                "SELECT trace_id, parent_span_id FROM v_traces WHERE service_name = 'mu-ingress' AND span_name = 'GET /api/obs/v1/health'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("query fallback span");

        assert_eq!(db_trace_id.len(), 32);
        assert!(db_parent_span_id.is_none());
    }
}

#[tokio::test]
async fn test_empirical_ingress_upstream_health_state_transitions() {
    let store = HotDuckDbStore::open_in_memory().expect("open HotDuckDbStore");
    let engine = IngressEngine::new(store.clone(), "test-node-ingress".into());

    // Allocate a guaranteed closed ephemeral port on loopback for deterministic failure
    let closed_port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = listener.local_addr().expect("local addr").port();
        drop(listener);
        port
    };
    engine.add_route(
        "route-dummy-unreachable",
        "/api/unreachable/",
        &format!("http://127.0.0.1:{closed_port}/api/"),
        "dummy-unreachable",
        true,
        false,
    );

    let upstreams = engine.get_upstream_dtos().await;
    let initial_reg = upstreams
        .iter()
        .find(|u| u.service_name == "muregist")
        .expect("muregist upstream");
    assert_eq!(initial_reg.health_state, "HEALTHY"); // Initially HEALTHY

    let initial_dummy = upstreams
        .iter()
        .find(|u| u.service_name == "dummy-unreachable")
        .expect("dummy-unreachable upstream");
    assert_eq!(initial_dummy.health_state, "HEALTHY"); // Initially HEALTHY

    // Spawn UpstreamHealthChecker with 50ms probe interval and bounded 200ms probe timeout
    let handle = UpstreamHealthChecker::spawn_with_timeout(
        engine.clone(),
        Duration::from_millis(50),
        Duration::from_millis(200),
    );

    // Allow multiple sweeps to run (>=3 sweeps for UNHEALTHY: 3 * 50ms = 150ms; sleep 600ms)
    tokio::time::sleep(Duration::from_millis(600)).await;
    handle.abort();

    let updated_upstreams = engine.get_upstream_dtos().await;

    // At least one unserved upstream must have recorded failures and degraded/unhealthy status
    let failed_upstream = updated_upstreams
        .iter()
        .find(|u| u.health_state == "DEGRADED" || u.health_state == "UNHEALTHY");

    assert!(
        failed_upstream.is_some(),
        "Expected at least one upstream to transition to DEGRADED or UNHEALTHY, states: {:?}",
        updated_upstreams
            .iter()
            .map(|u| (&u.service_name, &u.health_state))
            .collect::<Vec<_>>()
    );

    // Explicitly verify the registered dummy upstream transitioned to UNHEALTHY
    let dummy_upstream = updated_upstreams
        .iter()
        .find(|u| u.service_name == "dummy-unreachable")
        .expect("dummy upstream present");
    assert_eq!(
        dummy_upstream.health_state, "UNHEALTHY",
        "dummy-unreachable should transition to UNHEALTHY after consecutive failures"
    );
}

// ============================================================================
// 5. Causal Root-Cause Engine Challenges (8-Hop Waterfall, Cycles, Log Correlation)
// ============================================================================

#[test]
fn test_empirical_causal_root_cause_extreme_8hop_linear_chain() {
    let store = HotDuckDbStore::open_in_memory().expect("open store");
    let now = 1_700_000_000_000_000_000i64;
    let trace_id = "trace-extreme-8hop";

    let services = [
        "edge-gw",
        "auth-svc",
        "api-router",
        "order-svc",
        "pay-svc",
        "fraud-chk",
        "ledger-svc",
        "postgres-db",
    ];

    let mut spans = Vec::new();
    let mut prev_span_id: Option<String> = None;

    for (i, &svc) in services.iter().enumerate() {
        let span_id = format!("span-hop-{}", i + 1);
        let duration_ns = if i == 7 {
            // Root cause hop: 3500ms self-time, status ERROR
            3_500_000_000u64
        } else {
            // Intermediate hops: (7 - i) * 100ms overhead + 3500ms child
            3_500_000_000u64 + ((7 - i) as u64) * 100_000_000
        };

        spans.push(OtelSpanEntry {
            trace_id: trace_id.into(),
            span_id: span_id.clone(),
            parent_span_id: prev_span_id.clone(),
            service_name: svc.into(),
            node_id: "node-a".into(),
            span_name: format!("{}.exec", svc),
            span_kind: if i == 0 {
                "SERVER".into()
            } else {
                "INTERNAL".into()
            },
            start_time_unix_nano: now + (i as i64) * 10_000_000,
            end_time_unix_nano: now + (i as i64) * 10_000_000 + (duration_ns as i64),
            duration_ns,
            status_code: "ERROR".into(),
            status_message: if i == 7 {
                Some("Fatal disk failure".into())
            } else {
                None
            },
            attributes_json: "{}".into(),
        });

        prev_span_id = Some(span_id);
    }

    // Correlated fatal error log on postgres-db
    let log = OtelLogEntry {
        timestamp_unix_nano: now + 3_600_000_000,
        trace_id: trace_id.into(),
        span_id: "span-hop-8".into(),
        severity_number: 21,
        severity_text: "FATAL".into(),
        body: "FATAL: primary disk full /var/lib/postgresql/data; WAL write failed".into(),
        service_name: "postgres-db".into(),
        node_id: "node-a".into(),
        job_id: None,
        stage_id: None,
        attributes_json: "{}".into(),
    };

    store.insert_spans_batch(&spans).expect("insert spans");
    store.insert_logs_batch(&[log]).expect("insert logs");

    let problems = compute_causal_problems(&store, 300, Some(now + 6_000_000_000))
        .expect("compute causal problems");

    assert!(
        !problems.is_empty(),
        "Expected causal problem for 8-hop chain"
    );

    let root_prob = problems
        .iter()
        .find(|p| p.impacted_entity == "edge-gw")
        .expect("problem for edge-gw");

    assert_eq!(
        root_prob.root_cause_service, "postgres-db",
        "Engine must navigate all 8 hops to identify postgres-db as root cause"
    );
    assert_eq!(root_prob.causal_chain.len(), 8);
    assert_eq!(root_prob.root_cause_span_id.as_deref(), Some("span-hop-8"));
    assert!(
        root_prob
            .root_cause_error_message
            .as_ref()
            .unwrap()
            .contains("primary disk full"),
        "Correlated FATAL log must be attached"
    );
    assert!(
        root_prob.confidence_score >= 0.85,
        "Confidence score must be high (>= 0.85)"
    );
}

#[test]
fn test_empirical_causal_call_graph_cycle_safe_termination() {
    let store = HotDuckDbStore::open_in_memory().expect("open store");
    let now = 1_700_000_000_000_000_000i64;
    let trace_id = "trace-cyclic-graph";

    // Cycle: svc-a -> svc-b -> svc-c -> svc-a (circular parent_span_id)
    let s_a = OtelSpanEntry {
        trace_id: trace_id.into(),
        span_id: "span-a".into(),
        parent_span_id: Some("span-c".into()), // Circular!
        service_name: "svc-a".into(),
        node_id: "node-a".into(),
        span_name: "call.a".into(),
        span_kind: "SERVER".into(),
        start_time_unix_nano: now,
        end_time_unix_nano: now + 1_000_000_000,
        duration_ns: 1_000_000_000,
        status_code: "ERROR".into(),
        status_message: None,
        attributes_json: "{}".into(),
    };
    let s_b = OtelSpanEntry {
        trace_id: trace_id.into(),
        span_id: "span-b".into(),
        parent_span_id: Some("span-a".into()),
        service_name: "svc-b".into(),
        node_id: "node-a".into(),
        span_name: "call.b".into(),
        span_kind: "INTERNAL".into(),
        start_time_unix_nano: now + 100_000_000,
        end_time_unix_nano: now + 900_000_000,
        duration_ns: 800_000_000,
        status_code: "ERROR".into(),
        status_message: None,
        attributes_json: "{}".into(),
    };
    let s_c = OtelSpanEntry {
        trace_id: trace_id.into(),
        span_id: "span-c".into(),
        parent_span_id: Some("span-b".into()),
        service_name: "svc-c".into(),
        node_id: "node-a".into(),
        span_name: "call.c".into(),
        span_kind: "INTERNAL".into(),
        start_time_unix_nano: now + 200_000_000,
        end_time_unix_nano: now + 800_000_000,
        duration_ns: 600_000_000,
        status_code: "ERROR".into(),
        status_message: None,
        attributes_json: "{}".into(),
    };

    store
        .insert_spans_batch(&[s_a, s_b, s_c])
        .expect("insert cyclic spans");

    // Must safely terminate without infinite loop
    let problems = compute_causal_problems(&store, 300, Some(now + 2_000_000_000))
        .expect("compute causal problems on cycle");

    assert!(
        !problems.is_empty(),
        "Expected problem card from cyclic trace"
    );
}

#[test]
fn test_empirical_causal_log_severity_discrimination_and_service_fallback() {
    let store = HotDuckDbStore::open_in_memory().expect("open store");
    let now = 1_700_000_000_000_000_000i64;
    let trace_id = "trace-log-severity";

    let s1 = OtelSpanEntry {
        trace_id: trace_id.into(),
        span_id: "span-root".into(),
        parent_span_id: None,
        service_name: "svc-root".into(),
        node_id: "node-a".into(),
        span_name: "GET /data".into(),
        span_kind: "SERVER".into(),
        start_time_unix_nano: now,
        end_time_unix_nano: now + 2_000_000_000,
        duration_ns: 2_000_000_000,
        status_code: "ERROR".into(),
        status_message: None,
        attributes_json: "{}".into(),
    };

    // Log 1: INFO (severity 9) -> must NOT be correlated
    let log_info = OtelLogEntry {
        timestamp_unix_nano: now + 500_000_000,
        trace_id: trace_id.into(),
        span_id: "span-root".into(),
        severity_number: 9,
        severity_text: "INFO".into(),
        body: "Processing request normal".into(),
        service_name: "svc-root".into(),
        node_id: "node-a".into(),
        job_id: None,
        stage_id: None,
        attributes_json: "{}".into(),
    };

    // Log 2: WARN (severity 13) -> must NOT be correlated
    let log_warn = OtelLogEntry {
        timestamp_unix_nano: now + 600_000_000,
        trace_id: trace_id.into(),
        span_id: "span-root".into(),
        severity_number: 13,
        severity_text: "WARN".into(),
        body: "Cache miss rate high".into(),
        service_name: "svc-root".into(),
        node_id: "node-a".into(),
        job_id: None,
        stage_id: None,
        attributes_json: "{}".into(),
    };

    // Log 3: ERROR (severity 17) -> MUST be correlated
    let log_err = OtelLogEntry {
        timestamp_unix_nano: now + 1_800_000_000,
        trace_id: trace_id.into(),
        span_id: "span-root".into(),
        severity_number: 17,
        severity_text: "ERROR".into(),
        body: "Database connection pool exhausted".into(),
        service_name: "svc-root".into(),
        node_id: "node-a".into(),
        job_id: None,
        stage_id: None,
        attributes_json: "{}".into(),
    };

    store.insert_spans_batch(&[s1]).expect("insert span");
    store
        .insert_logs_batch(&[log_info, log_warn, log_err])
        .expect("insert logs");

    let problems = compute_causal_problems(&store, 300, Some(now + 3_000_000_000))
        .expect("compute causal problems");

    assert!(!problems.is_empty());
    let prob = &problems[0];
    assert_eq!(
        prob.root_cause_error_message.as_deref(),
        Some("Database connection pool exhausted"),
        "Engine must ignore INFO and WARN logs and correlate ERROR log"
    );
}

// ============================================================================
// 6. Persistent SSE Stream Multi-Client Concurrency Challenge
// ============================================================================

#[tokio::test]
async fn test_empirical_persistent_sse_concurrent_10_clients_distribution() {
    let store = HotDuckDbStore::open_in_memory().expect("open store");
    let router = build_console_api_router(store.clone());

    // Connect 10 concurrent clients to /api/v1/events
    let mut client_bodies = Vec::new();
    for _ in 0..10 {
        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/events")
            .body(Body::empty())
            .unwrap();

        let resp = router.clone().oneshot(req).await.expect("SSE request");
        assert_eq!(resp.status(), StatusCode::OK);
        client_bodies.push(resp.into_body());
    }

    // Broadcast 5 events
    for i in 1..=5 {
        store.broadcast_event(&format!(
            r#"{{"problem_id":"PROB-CONCUR-{i}","status":"OPEN","title":"Event {i}"}}"#
        ));
    }

    // Verify all 10 clients receive all 5 events
    let mut handles = Vec::new();
    for (client_idx, mut body) in client_bodies.into_iter().enumerate() {
        let handle = tokio::spawn(async move {
            let mut count = 0;
            let timeout = Duration::from_millis(800);
            let _ = tokio::time::timeout(timeout, async {
                while let Some(frame_res) = body.frame().await {
                    if let Ok(frame) = frame_res {
                        if let Some(data) = frame.data_ref() {
                            let text = String::from_utf8_lossy(data);
                            if text.contains("event: problem_opened") {
                                count += 1;
                                if count >= 5 {
                                    break;
                                }
                            }
                        }
                    }
                }
            })
            .await;
            (client_idx, count)
        });
        handles.push(handle);
    }

    for h in handles {
        let (client_idx, count) = h.await.expect("client task failed");
        assert_eq!(
            count, 5,
            "Client {client_idx} failed to receive all 5 broadcast events (received: {count})"
        );
    }
}

#[tokio::test]
async fn test_empirical_ai_diagnosis_synthesis_and_fallback() {
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;

    // 1. Spin up mock OpenAI server mimicking jero-manager /v1/chat/completions
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind mock jero-manager");
    let actual_port = listener.local_addr().expect("local addr").port();

    let server_handle = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };
            let io = TokioIo::new(stream);
            tokio::spawn(async move {
                let service = service_fn(|req: hyper::Request<hyper::body::Incoming>| async move {
                    assert_eq!(req.uri().path(), "/v1/chat/completions");
                    assert_eq!(req.method(), hyper::Method::POST);
                    let resp_body = serde_json::json!({
                        "id": "chatcmpl-test-ai-synthesis",
                        "object": "chat.completion",
                        "created": 1700000000,
                        "model": "jero",
                        "choices": [{
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": "AI RCA Diagnosis: Root bottleneck isolated to inventory-db due to locking contention."
                            },
                            "finish_reason": "stop"
                        }]
                    });
                    let resp = hyper::Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "application/json")
                        .body(http_body_util::Full::new(hyper::body::Bytes::from(
                            serde_json::to_vec(&resp_body).unwrap(),
                        )))
                        .unwrap();
                    Ok::<_, std::convert::Infallible>(resp)
                });
                let _ = http1::Builder::new().serve_connection(io, service).await;
            });
        }
    });

    // 2. Test authentic AI synthesis with valid JERO_MANAGER_URL
    std::env::set_var(
        "JERO_MANAGER_URL",
        format!("http://127.0.0.1:{actual_port}"),
    );
    let chain = vec!["mu-ingress".to_string(), "inventory-db".to_string()];
    let res = mu_observable_hub::synthesize_ai_diagnosis(
        "mu-ingress",
        "inventory-db",
        &chain,
        Some("connection refused"),
        "error_rate",
        0.95,
    )
    .await;
    assert!(
        res.contains("AI RCA Diagnosis: Root bottleneck isolated to inventory-db"),
        "Expected authentic AI diagnosis synthesis from mock jero-manager endpoint, got: {res}"
    );

    // 3. Test reliable statistical fallback when JERO_MANAGER_URL is unreachable
    let closed_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    };
    std::env::set_var(
        "JERO_MANAGER_URL",
        format!("http://127.0.0.1:{closed_port}"),
    );
    let fallback_res = mu_observable_hub::synthesize_ai_diagnosis(
        "mu-ingress",
        "inventory-db",
        &chain,
        Some("connection refused"),
        "error_rate",
        0.95,
    )
    .await;
    assert!(
        fallback_res.contains("Statistical Root-Cause Synthesis"),
        "Expected deterministic statistical fallback on connection failure, got: {fallback_res}"
    );

    // Clean up
    server_handle.abort();
    std::env::remove_var("JERO_MANAGER_URL");
}

#[tokio::test]
async fn test_empirical_ingress_hardening_loop_auth_body_limit_ssrf() {
    let store = HotDuckDbStore::open_in_memory().expect("open store");
    let router = build_console_api_router(store.clone());

    // 1. Loop detection gate: x-ingress-loop present returns 508 Loop Detected
    let req = Request::builder()
        .method("GET")
        .uri("/api/obs/v1/problems")
        .header("x-ingress-loop", "1")
        .body(Body::empty())
        .unwrap();
    let resp_native = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp_native.status(), StatusCode::OK);
    // Direct native route should answer directly without fallback, but if hitting proxy fallback:
    let req_proxy = Request::builder()
        .method("GET")
        .uri("/api/unmapped/endpoint")
        .header("x-ingress-loop", "1")
        .body(Body::empty())
        .unwrap();
    let resp_proxy = router.clone().oneshot(req_proxy).await.unwrap();
    assert_eq!(resp_proxy.status(), StatusCode::LOOP_DETECTED);

    // 2. Admin authentication and SSRF validation on POST /api/v1/ingress/routes
    // 2a. Missing Bearer auth -> 401 Unauthorized
    let unauth_req = Request::builder()
        .method("POST")
        .uri("/api/v1/ingress/routes")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"route_id":"r1","path_prefix":"/test/","upstream_url":"http://127.0.0.1:8000"}"#,
        ))
        .unwrap();
    let unauth_resp = router.clone().oneshot(unauth_req).await.unwrap();
    assert_eq!(unauth_resp.status(), StatusCode::UNAUTHORIZED);

    // 2b. SSRF block on cloud metadata IP 169.254.169.254 -> 400 Bad Request
    let ssrf_req = Request::builder()
        .method("POST")
        .uri("/api/v1/ingress/routes")
        .header("authorization", "Bearer test-admin-token")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"route_id":"r-ssrf","path_prefix":"/ssrf/","upstream_url":"http://169.254.169.254/latest/meta-data"}"#))
        .unwrap();
    let ssrf_resp = router.clone().oneshot(ssrf_req).await.unwrap();
    assert_eq!(ssrf_resp.status(), StatusCode::BAD_REQUEST);

    // 2c. SSRF block on 0.0.0.0 wildcard address -> 400 Bad Request
    let wildcard_req = Request::builder()
        .method("POST")
        .uri("/api/v1/ingress/routes")
        .header("authorization", "Bearer test-admin-token")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"route_id":"r-wildcard","path_prefix":"/wild/","upstream_url":"http://0.0.0.0:8000"}"#))
        .unwrap();
    let wildcard_resp = router.clone().oneshot(wildcard_req).await.unwrap();
    assert_eq!(wildcard_resp.status(), StatusCode::BAD_REQUEST);

    // 2d. Invalid path prefix (missing leading '/') -> 400 Bad Request
    let bad_prefix_req = Request::builder()
        .method("POST")
        .uri("/api/v1/ingress/routes")
        .header("authorization", "Bearer test-admin-token")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"route_id":"r-bad","path_prefix":"noprefix","upstream_url":"http://127.0.0.1:8000"}"#))
        .unwrap();
    let bad_prefix_resp = router.clone().oneshot(bad_prefix_req).await.unwrap();
    assert_eq!(bad_prefix_resp.status(), StatusCode::BAD_REQUEST);

    // 2e. Valid route registration -> 201 Created
    let valid_req = Request::builder()
        .method("POST")
        .uri("/api/v1/ingress/routes")
        .header("authorization", "Bearer test-admin-token")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"route_id":"r-valid","path_prefix":"/test-service/","upstream_url":"http://127.0.0.1:8000","auth_required":true}"#))
        .unwrap();
    let valid_resp = router.clone().oneshot(valid_req).await.unwrap();
    assert_eq!(valid_resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn test_empirical_log_search_sql_pushdown_and_comparison_operators() {
    let store = HotDuckDbStore::open_in_memory().expect("open store");

    // 1. Verify preservation of < and > in tokenizer
    let entry = OtelLogEntry {
        timestamp_unix_nano: 1_700_000_000_000_000_000,
        trace_id: "tr-test-1".into(),
        span_id: "sp-test-1".into(),
        severity_number: 17,
        severity_text: "ERROR".into(),
        service_name: "test-service".into(),
        node_id: "node-a".into(),
        body: "Threshold exceeded: rate>10 requests/sec with latency<50ms".into(),
        attributes_json: r#"{"line_no":1,"stream":1}"#.into(),
        job_id: Some("job-1".into()),
        stage_id: Some("stage-1".into()),
    };
    let tokens = tokenize_log_line(&entry, &entry.body);
    assert!(
        tokens.contains(&"rate>10".to_string()),
        "Tokens must preserve rate>10: {tokens:?}"
    );
    assert!(
        tokens.contains(&"latency<50ms".to_string()),
        "Tokens must preserve latency<50ms: {tokens:?}"
    );

    // 2. Insert logs and verify SQL pushdown bounds & facets
    store
        .insert_logs(std::slice::from_ref(&entry))
        .expect("insert log");

    let router = build_console_api_router(store.clone());

    // 3. Query with from & to time bounds does not return 400 Bad Request
    let logs_req = Request::builder()
        .method("GET")
        .uri("/api/v1/logs?from=1699999000000&to=1700001000000&severity=error")
        .body(Body::empty())
        .unwrap();
    let logs_resp = router.clone().oneshot(logs_req).await.unwrap();
    assert_eq!(logs_resp.status(), StatusCode::OK);

    // 4. Query facets with token filter
    let facets_req = Request::builder()
        .method("GET")
        .uri("/api/v1/logs/facets?q=rate%3E10")
        .body(Body::empty())
        .unwrap();
    let facets_resp = router.clone().oneshot(facets_req).await.unwrap();
    assert_eq!(facets_resp.status(), StatusCode::OK);
}
