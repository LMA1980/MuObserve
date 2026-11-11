// SPDX-License-Identifier: AGPL-3.0-only
//! Empirical Challenger 1 Test Suite for Ingress & Security (Milestone 2).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use mu_observable_hub::{build_console_api_router, HotDuckDbStore, IngressEngine};
use serde_json::json;
use tokio::sync::Mutex;
use tower::ServiceExt;

static ENV_LOCK: Mutex<()> = Mutex::const_new(());

/// Spawns a mock HTTP/1.1 upstream server for proxy testing.
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
                        let has_loop = req.headers().contains_key("x-ingress-loop");
                        let mut resp = hyper::Response::builder().status(status);
                        if has_loop {
                            resp = resp.header("x-loop-header-received", "true");
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

/// 1. Test Loop Prevention:
/// Send requests with x-ingress-loop: 1 through proxy_request and verify it immediately returns 508 Loop Detected.
#[tokio::test]
async fn test_empirical_ingress_loop_prevention() {
    let store = HotDuckDbStore::open_in_memory().expect("open store");
    let engine = IngressEngine::new(store.clone(), "challenger-node".into());

    // Case 1a: Direct proxy_request invocation with x-ingress-loop header
    let req = Request::builder()
        .method("GET")
        .uri("/api/ci/jobs")
        .header("x-ingress-loop", "1")
        .body(Body::empty())
        .unwrap();

    let resp = engine.proxy_request(req).await.expect("proxy_request call");
    assert_eq!(
        resp.status(),
        StatusCode::LOOP_DETECTED,
        "Direct proxy_request with x-ingress-loop must return 508 Loop Detected"
    );

    // Case 1b: Router fallback invocation with x-ingress-loop header
    let router = build_console_api_router(store.clone());
    let req_router = Request::builder()
        .method("GET")
        .uri("/api/unmapped/loop/test")
        .header("x-ingress-loop", "1")
        .body(Body::empty())
        .unwrap();

    let resp_router = router.oneshot(req_router).await.unwrap();
    assert_eq!(
        resp_router.status(),
        StatusCode::LOOP_DETECTED,
        "Router fallback with x-ingress-loop must return 508 Loop Detected"
    );

    // Case 1c: Verify forward_http stamps x-ingress-loop: 1 onto outgoing upstream requests
    let (_handle, mock_port) =
        spawn_mock_upstream(0, StatusCode::OK, r#"{"status":"upstream-ok"}"#).await;
    engine.add_route(
        "route-loop-verify",
        "/api/loop-verify/",
        &format!("http://127.0.0.1:{mock_port}/"),
        "loop-test-svc",
        true,
        false,
    );

    let req_forward = Request::builder()
        .method("GET")
        .uri("/api/loop-verify/ping")
        .body(Body::empty())
        .unwrap();

    let resp_forward = engine
        .proxy_request(req_forward)
        .await
        .expect("proxy_request forward");
    assert_eq!(resp_forward.status(), StatusCode::OK);
    assert_eq!(
        resp_forward
            .headers()
            .get("x-loop-header-received")
            .and_then(|v| v.to_str().ok()),
        Some("true"),
        "Forwarded upstream request MUST have x-ingress-loop: 1 header stamped"
    );
}

/// 2. Test SSRF Protection on Route Creation:
/// Verify that attempts to register invalid schemes (e.g. file://, ftp://),
/// cloud metadata IP 169.254.169.254, 0.0.0.0, or link-local IPv6 addresses are rejected with HTTP 400.
#[tokio::test]
async fn test_empirical_ingress_ssrf_protection_route_creation() {
    let _guard = ENV_LOCK.lock().await;
    let auth_token = "ssrf-test-admin-token";
    std::env::set_var("MUOBSERVE_INGRESS_ADMIN_TOKEN", auth_token);

    let store = HotDuckDbStore::open_in_memory().expect("open store");
    let router = build_console_api_router(store.clone());

    let forbidden_targets = vec![
        ("invalid scheme file://", "file:///etc/passwd"),
        ("invalid scheme ftp://", "ftp://ftp.example.com/data"),
        ("invalid scheme gopher://", "gopher://127.0.0.1:70/"),
        (
            "cloud metadata ipv4 literal",
            "http://169.254.169.254/latest/meta-data",
        ),
        ("cloud metadata subnet", "http://169.254.1.1:8080/status"),
        ("wildcard ipv4 0.0.0.0", "http://0.0.0.0:8000/api/"),
        (
            "broadcast ipv4 255.255.255.255",
            "http://255.255.255.255:8000/",
        ),
        ("link-local ipv6 without port", "http://[fe80::1]/"),
        ("link-local ipv6 with port", "http://[fe80::1]:8080/"),
        (
            "link-local ipv6 complex",
            "http://[fe80::200:5aee:feaa:20a2]:8443/",
        ),
        ("unspecified ipv6 [::]", "http://[::]:8080/"),
    ];

    let mut failed_ssrf_blocks = Vec::new();

    for (desc, target_url) in &forbidden_targets {
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/ingress/routes")
            .header("authorization", format!("Bearer {auth_token}"))
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "route_id": format!("r-ssrf-{}", desc.replace(' ', "-")),
                    "path_prefix": "/ssrf-test/",
                    "upstream_url": target_url,
                })
                .to_string(),
            ))
            .unwrap();

        let resp = router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8_lossy(&body_bytes);

        println!("SSRF Test '{desc}' ({target_url}) -> status: {status}, body: {body_str}");
        if status != StatusCode::BAD_REQUEST {
            failed_ssrf_blocks.push(format!(
                "{desc} ({target_url}) allowed with status {status}"
            ));
        }
    }

    std::env::remove_var("MUOBSERVE_INGRESS_ADMIN_TOKEN");

    assert!(
        failed_ssrf_blocks.is_empty(),
        "VULNERABILITY DETECTED: Following SSRF payloads were NOT blocked with 400 Bad Request:\n{}",
        failed_ssrf_blocks.join("\n")
    );
}

/// 3. Test Admin Authentication:
/// Verify that requests to POST /api/v1/ingress/routes and POST /api/v1/ingress/tls
/// without a valid Bearer token return HTTP 401 Unauthorized.
#[tokio::test]
async fn test_empirical_ingress_admin_authentication() {
    let _guard = ENV_LOCK.lock().await;

    let store = HotDuckDbStore::open_in_memory().expect("open store");
    let router = build_console_api_router(store.clone());

    // Test 3a: No token at all -> 401 Unauthorized on routes
    let req_no_auth = Request::builder()
        .method("POST")
        .uri("/api/v1/ingress/routes")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "route_id": "r-unauth",
                "path_prefix": "/unauth/",
                "upstream_url": "http://127.0.0.1:8000"
            })
            .to_string(),
        ))
        .unwrap();

    let resp_no_auth = router.clone().oneshot(req_no_auth).await.unwrap();
    assert_eq!(
        resp_no_auth.status(),
        StatusCode::UNAUTHORIZED,
        "POST /api/v1/ingress/routes without auth must return 401"
    );

    // Test 3b: No token at all -> 401 Unauthorized on tls
    let req_no_auth_tls = Request::builder()
        .method("POST")
        .uri("/api/v1/ingress/tls")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "domain": "test.k3.internal",
                "certificate_issuer": "test-ca",
                "valid_until_epoch_ms": 1700000000,
                "days_remaining": 30,
                "alpn_protocols": ["h2"],
                "ocsp_stapling": false,
                "mutual_tls": false
            })
            .to_string(),
        ))
        .unwrap();

    let resp_no_auth_tls = router.clone().oneshot(req_no_auth_tls).await.unwrap();
    assert_eq!(
        resp_no_auth_tls.status(),
        StatusCode::UNAUTHORIZED,
        "POST /api/v1/ingress/tls without auth must return 401"
    );

    // Test 3c: Configured admin token in env: invalid token -> 401, valid token -> 200/201
    std::env::set_var(
        "MUOBSERVE_INGRESS_ADMIN_TOKEN",
        "super-secret-admin-token-1234",
    );

    // Invalid bearer token
    let req_bad_token = Request::builder()
        .method("POST")
        .uri("/api/v1/ingress/routes")
        .header("authorization", "Bearer invalid-wrong-token")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "route_id": "r-bad-token",
                "path_prefix": "/bad-token/",
                "upstream_url": "http://127.0.0.1:8000"
            })
            .to_string(),
        ))
        .unwrap();

    let resp_bad_token = router.clone().oneshot(req_bad_token).await.unwrap();
    assert_eq!(
        resp_bad_token.status(),
        StatusCode::UNAUTHORIZED,
        "POST /api/v1/ingress/routes with invalid token must return 401"
    );

    // Invalid token on TLS
    let req_bad_tls = Request::builder()
        .method("POST")
        .uri("/api/v1/ingress/tls")
        .header("authorization", "Bearer invalid-wrong-token")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "domain": "test.k3.internal",
                "certificate_issuer": "test-ca",
                "valid_until_epoch_ms": 1700000000,
                "days_remaining": 30,
                "alpn_protocols": ["h2"],
                "ocsp_stapling": false,
                "mutual_tls": false
            })
            .to_string(),
        ))
        .unwrap();

    let resp_bad_tls = router.clone().oneshot(req_bad_tls).await.unwrap();
    assert_eq!(
        resp_bad_tls.status(),
        StatusCode::UNAUTHORIZED,
        "POST /api/v1/ingress/tls with invalid token must return 401"
    );

    // Valid token on routes -> 201 Created
    let req_valid = Request::builder()
        .method("POST")
        .uri("/api/v1/ingress/routes")
        .header("authorization", "Bearer super-secret-admin-token-1234")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "route_id": "r-valid-admin",
                "path_prefix": "/valid-admin/",
                "upstream_url": "http://127.0.0.1:8000"
            })
            .to_string(),
        ))
        .unwrap();

    let resp_valid = router.clone().oneshot(req_valid).await.unwrap();
    assert_eq!(
        resp_valid.status(),
        StatusCode::CREATED,
        "POST /api/v1/ingress/routes with valid token must return 201"
    );

    // Valid token on tls -> 200 OK
    let req_valid_tls = Request::builder()
        .method("POST")
        .uri("/api/v1/ingress/tls")
        .header("authorization", "Bearer super-secret-admin-token-1234")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "domain": "test.k3.internal",
                "certificate_issuer": "test-ca",
                "valid_until_epoch_ms": 1700000000,
                "days_remaining": 30,
                "alpn_protocols": ["h2"],
                "ocsp_stapling": false,
                "mutual_tls": false
            })
            .to_string(),
        ))
        .unwrap();

    let resp_valid_tls = router.clone().oneshot(req_valid_tls).await.unwrap();
    assert_eq!(
        resp_valid_tls.status(),
        StatusCode::OK,
        "POST /api/v1/ingress/tls with valid token must return 200"
    );

    std::env::remove_var("MUOBSERVE_INGRESS_ADMIN_TOKEN");
}

/// 4. Test 16MB Payload Limit:
/// Verify that request payloads exceeding 16MB are rejected with HTTP 413 Payload Too Large.
#[tokio::test]
async fn test_empirical_ingress_16mb_payload_limit() {
    let store = HotDuckDbStore::open_in_memory().expect("open store");
    let engine = IngressEngine::new(store.clone(), "challenger-node".into());

    let (_handle, mock_port) =
        spawn_mock_upstream(0, StatusCode::OK, r#"{"status":"uploaded"}"#).await;
    engine.add_route(
        "route-upload",
        "/api/upload/",
        &format!("http://127.0.0.1:{mock_port}/"),
        "upload-svc",
        true,
        false,
    );

    // 4a. Within 16MB limit: 1MB payload should succeed with 200 OK
    let small_payload = vec![b'A'; 1024 * 1024]; // 1MB
    let req_small = Request::builder()
        .method("POST")
        .uri("/api/upload/file")
        .header("content-type", "application/octet-stream")
        .body(Body::from(small_payload))
        .unwrap();

    let resp_small = engine
        .proxy_request(req_small)
        .await
        .expect("proxy 1MB payload");
    assert_eq!(
        resp_small.status(),
        StatusCode::OK,
        "1MB payload within limit must succeed with 200 OK"
    );

    // 4b. Exceeding 16MB limit: (16MB + 1KB) payload MUST return HTTP 413 Payload Too Large
    const OVERSIZE_BYTES: usize = 16 * 1024 * 1024 + 1024; // 16MB + 1KB
    let large_payload = vec![b'X'; OVERSIZE_BYTES];
    let req_large = Request::builder()
        .method("POST")
        .uri("/api/upload/file")
        .header("content-type", "application/octet-stream")
        .body(Body::from(large_payload))
        .unwrap();

    let resp_large = engine
        .proxy_request(req_large)
        .await
        .expect("proxy 16MB+ payload");
    let status_large = resp_large.status();
    let body_bytes = resp_large.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8_lossy(&body_bytes);

    println!("16MB+ payload response: status={status_large}, body={body_str}");
    assert_eq!(
        status_large,
        StatusCode::PAYLOAD_TOO_LARGE,
        "Payload exceeding 16MB must return 413 Payload Too Large, got {status_large}: {body_str}"
    );
}

/// 5. Test Constant-Time Token Comparison:
/// Verify that constant_time_eq properly matches valid tokens and rejects arbitrary/empty/mismatched tokens.
#[tokio::test]
async fn test_empirical_ingress_constant_time_token_comparison() {
    let _guard = ENV_LOCK.lock().await;

    let store = HotDuckDbStore::open_in_memory().expect("open store");
    let engine = IngressEngine::new(store.clone(), "challenger-node".into());

    let (_handle, mock_port) = spawn_mock_upstream(0, StatusCode::OK, r#"{"secret":"data"}"#).await;
    engine.add_route(
        "route-auth-test",
        "/api/secure/",
        &format!("http://127.0.0.1:{mock_port}/"),
        "secure-svc",
        true,
        true, // auth_required = true
    );

    const EXPECTED_SECRET: &str = "muobserve-secure-token-xy7890abcdef";
    std::env::set_var("MUOBSERVE_BEARER_TOKEN", EXPECTED_SECRET);

    // 5a. Exactly matching token -> 200 OK
    let req_valid = Request::builder()
        .method("GET")
        .uri("/api/secure/data")
        .header("authorization", format!("Bearer {EXPECTED_SECRET}"))
        .body(Body::empty())
        .unwrap();
    let resp_valid = engine.proxy_request(req_valid).await.unwrap();
    assert_eq!(
        resp_valid.status(),
        StatusCode::OK,
        "Valid token must be accepted"
    );

    // 5b. Single bit flipped in first character -> 401 Unauthorized
    let mut flip_first = EXPECTED_SECRET.as_bytes().to_vec();
    flip_first[0] ^= 0x01;
    let flip_first_str = String::from_utf8(flip_first).unwrap();
    let req_flip_first = Request::builder()
        .method("GET")
        .uri("/api/secure/data")
        .header("authorization", format!("Bearer {flip_first_str}"))
        .body(Body::empty())
        .unwrap();
    let resp_flip_first = engine.proxy_request(req_flip_first).await.unwrap();
    assert_eq!(
        resp_flip_first.status(),
        StatusCode::UNAUTHORIZED,
        "Bit flip in first byte must be rejected"
    );

    // 5c. Single bit flipped in last character -> 401 Unauthorized
    let mut flip_last = EXPECTED_SECRET.as_bytes().to_vec();
    let last_idx = flip_last.len() - 1;
    flip_last[last_idx] ^= 0x01;
    let flip_last_str = String::from_utf8(flip_last).unwrap();
    let req_flip_last = Request::builder()
        .method("GET")
        .uri("/api/secure/data")
        .header("authorization", format!("Bearer {flip_last_str}"))
        .body(Body::empty())
        .unwrap();
    let resp_flip_last = engine.proxy_request(req_flip_last).await.unwrap();
    assert_eq!(
        resp_flip_last.status(),
        StatusCode::UNAUTHORIZED,
        "Bit flip in last byte must be rejected"
    );

    // 5d. Length mismatch (truncated by 1 byte) -> 401 Unauthorized
    let truncated = &EXPECTED_SECRET[..EXPECTED_SECRET.len() - 1];
    let req_trunc = Request::builder()
        .method("GET")
        .uri("/api/secure/data")
        .header("authorization", format!("Bearer {truncated}"))
        .body(Body::empty())
        .unwrap();
    let resp_trunc = engine.proxy_request(req_trunc).await.unwrap();
    assert_eq!(
        resp_trunc.status(),
        StatusCode::UNAUTHORIZED,
        "Truncated token must be rejected"
    );

    // 5e. Length mismatch (extended by 1 byte) -> 401 Unauthorized
    let extended = format!("{EXPECTED_SECRET}x");
    let req_ext = Request::builder()
        .method("GET")
        .uri("/api/secure/data")
        .header("authorization", format!("Bearer {extended}"))
        .body(Body::empty())
        .unwrap();
    let resp_ext = engine.proxy_request(req_ext).await.unwrap();
    assert_eq!(
        resp_ext.status(),
        StatusCode::UNAUTHORIZED,
        "Extended token must be rejected"
    );

    // 5f. Empty bearer token -> 401 Unauthorized
    let req_empty = Request::builder()
        .method("GET")
        .uri("/api/secure/data")
        .header("authorization", "Bearer ")
        .body(Body::empty())
        .unwrap();
    let resp_empty = engine.proxy_request(req_empty).await.unwrap();
    assert_eq!(
        resp_empty.status(),
        StatusCode::UNAUTHORIZED,
        "Empty token must be rejected"
    );

    // 5g. Missing Authorization header -> 401 Unauthorized
    let req_missing = Request::builder()
        .method("GET")
        .uri("/api/secure/data")
        .body(Body::empty())
        .unwrap();
    let resp_missing = engine.proxy_request(req_missing).await.unwrap();
    assert_eq!(
        resp_missing.status(),
        StatusCode::UNAUTHORIZED,
        "Missing auth header must be rejected"
    );

    std::env::remove_var("MUOBSERVE_BEARER_TOKEN");
}
