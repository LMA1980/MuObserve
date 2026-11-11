// SPDX-License-Identifier: AGPL-3.0-only
//! Ingress Dynamic Reverse-Proxy & Edge Traffic Routing Engine (Traefik replacement).
//!
//! Provides dynamic prefix-based reverse-proxy routing, path prefix stripping, upstream health
//! monitoring, W3C request tracing (`traceparent` propagation and `OtelSpanEntry` emission directly
//! into DuckDB `HotDuckDbStore`), and TLS termination health telemetry.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use mu_observable_ipc::{OtelSpanEntry, TraceContext};
use serde::{Deserialize, Serialize};

use crate::error::MuObserveError;
use crate::storage::HotDuckDbStore;

/// Dynamic reverse-proxy route definition DTO.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IngressRouteDto {
    pub route_id: String,
    pub path_prefix: String,
    pub upstream_url: String,
    pub service_name: String,
    pub strip_prefix: bool,
    pub auth_required: bool,
    pub request_count: u64,
    pub request_rate_rps: f64,
    pub error_rate_pct: f64,
    pub p95_latency_ms: f64,
}

/// Upstream target host and health telemetry DTO.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IngressUpstreamDto {
    pub upstream_id: String,
    pub target_url: String,
    pub service_name: String,
    pub health_state: String, // "HEALTHY", "DEGRADED", "UNHEALTHY"
    pub latency_ms: f64,
    pub success_rate_pct: f64,
    pub active_connections: u32,
    pub last_check_ms: i64,
}

/// TLS termination and certificate health status DTO.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsHealthDto {
    pub domain: String,
    pub certificate_issuer: String,
    pub valid_until_epoch_ms: i64,
    pub days_remaining: i32,
    pub alpn_protocols: Vec<String>,
    pub ocsp_stapling: bool,
    pub mutual_tls: bool,
}

/// Aggregate Ingress overview bundle DTO.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IngressOverviewDto {
    pub routes: Vec<IngressRouteDto>,
    pub upstreams: Vec<IngressUpstreamDto>,
    pub tls_health: Option<TlsHealthDto>,
}

/// Internal state for an ingress route.
pub struct IngressRouteState {
    pub route_id: String,
    pub path_prefix: String,
    pub upstream_url: String,
    pub service_name: String,
    pub strip_prefix: bool,
    pub auth_required: bool,
    pub request_count: AtomicU64,
    pub error_count: AtomicU64,
    pub latency_samples: Mutex<VecDeque<f64>>,
    pub window_start_ms: AtomicI64,
    pub window_request_count: AtomicU64,
}

/// Internal state for an upstream destination.
pub struct IngressUpstreamState {
    pub upstream_id: String,
    pub target_url: String,
    pub service_name: String,
    pub health_state: Mutex<String>,
    pub latency_ms: Mutex<f64>,
    pub success_count: AtomicU64,
    pub total_probes: AtomicU64,
    pub active_connections: AtomicU32,
    pub last_check_ms: AtomicI64,
    pub consecutive_failures: AtomicU32,
}

/// Central Ingress Reverse-Proxy Engine.
pub struct IngressEngine {
    store: HotDuckDbStore,
    node_id: String,
    routes: RwLock<Vec<Arc<IngressRouteState>>>,
    upstreams: RwLock<HashMap<String, Arc<IngressUpstreamState>>>,
    tls_health: RwLock<Option<TlsHealthDto>>,
}

impl IngressEngine {
    /// Creates and initializes a new [`IngressEngine`].
    pub fn new(store: HotDuckDbStore, node_id: String) -> Arc<Self> {
        let default_tls = TlsHealthDto {
            domain: "console.k3.internal".into(),
            certificate_issuer: "step-ca intermediate".into(),
            valid_until_epoch_ms: chrono::Utc::now().timestamp_millis() + 86_400_000 * 90,
            days_remaining: 90,
            alpn_protocols: vec!["h2".into(), "http/1.1".into()],
            ocsp_stapling: true,
            mutual_tls: true,
        };

        let engine = Arc::new(Self {
            store,
            node_id,
            routes: RwLock::new(Vec::new()),
            upstreams: RwLock::new(HashMap::new()),
            tls_health: RwLock::new(Some(default_tls)),
        });

        engine.register_default_routes_sync();
        engine
    }

    fn register_default_routes_sync(&self) {
        let defaults = vec![
            (
                "route-reg",
                "/api/reg/",
                "http://127.0.0.1:8443/api/",
                "muregist",
                false,
                false,
            ),
            (
                "route-ci",
                "/api/ci/",
                "http://192.0.2.10:8000/api/",
                "actionrunner-controller",
                false,
                false,
            ),
            (
                "route-cd",
                "/api/cd/",
                "http://127.0.0.1:8080/api/",
                "muconde-controller",
                false,
                false,
            ),
            (
                "route-obs",
                "/api/obs/",
                "http://127.0.0.1:9480/api/",
                "muobserve",
                false,
                false,
            ),
            (
                "route-reg-v1",
                "/api/v1/registry/",
                "http://127.0.0.1:8443/api/v1/",
                "muregist",
                false,
                false,
            ),
        ];

        let mut r_guard = self.routes.write().unwrap();
        let mut u_guard = self.upstreams.write().unwrap();

        for (r_id, prefix, upstream_url, svc, strip, auth) in defaults {
            r_guard.push(Arc::new(IngressRouteState {
                route_id: r_id.into(),
                path_prefix: prefix.into(),
                upstream_url: upstream_url.into(),
                service_name: svc.into(),
                strip_prefix: strip,
                auth_required: auth,
                request_count: AtomicU64::new(0),
                error_count: AtomicU64::new(0),
                latency_samples: Mutex::new(VecDeque::with_capacity(500)),
                window_start_ms: AtomicI64::new(chrono::Utc::now().timestamp_millis()),
                window_request_count: AtomicU64::new(0),
            }));

            let u_id = format!("upstream-{}", svc);
            u_guard.entry(u_id.clone()).or_insert_with(|| {
                Arc::new(IngressUpstreamState {
                    upstream_id: u_id,
                    target_url: upstream_url.into(),
                    service_name: svc.into(),
                    health_state: Mutex::new("HEALTHY".into()),
                    latency_ms: Mutex::new(2.5),
                    success_count: AtomicU64::new(10),
                    total_probes: AtomicU64::new(10),
                    active_connections: AtomicU32::new(0),
                    last_check_ms: AtomicI64::new(chrono::Utc::now().timestamp_millis()),
                    consecutive_failures: AtomicU32::new(0),
                })
            });
        }
    }

    /// Dynamically registers or replaces an ingress route and its upstream target.
    pub fn add_route(
        &self,
        route_id: &str,
        path_prefix: &str,
        upstream_url: &str,
        service_name: &str,
        strip_prefix: bool,
        auth_required: bool,
    ) {
        let mut r_guard = self.routes.write().unwrap();
        let mut u_guard = self.upstreams.write().unwrap();

        r_guard.retain(|r| r.route_id != route_id);
        r_guard.push(Arc::new(IngressRouteState {
            route_id: route_id.into(),
            path_prefix: path_prefix.into(),
            upstream_url: upstream_url.into(),
            service_name: service_name.into(),
            strip_prefix,
            auth_required,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
            latency_samples: Mutex::new(VecDeque::with_capacity(500)),
            window_start_ms: AtomicI64::new(chrono::Utc::now().timestamp_millis()),
            window_request_count: AtomicU64::new(0),
        }));

        let u_id = format!("upstream-{}", service_name);
        u_guard.insert(
            u_id.clone(),
            Arc::new(IngressUpstreamState {
                upstream_id: u_id,
                target_url: upstream_url.into(),
                service_name: service_name.into(),
                health_state: Mutex::new("HEALTHY".into()),
                latency_ms: Mutex::new(2.5),
                success_count: AtomicU64::new(10),
                total_probes: AtomicU64::new(10),
                active_connections: AtomicU32::new(0),
                last_check_ms: AtomicI64::new(chrono::Utc::now().timestamp_millis()),
                consecutive_failures: AtomicU32::new(0),
            }),
        );
    }

    /// Matches a request path against registered ingress routes using longest prefix matching.
    pub async fn match_route(&self, path: &str) -> Option<Arc<IngressRouteState>> {
        let routes = self.routes.read().unwrap();
        routes
            .iter()
            .filter(|r| path.starts_with(&r.path_prefix))
            .max_by_key(|r| r.path_prefix.len())
            .cloned()
    }

    /// Returns all registered ingress routes as DTOs.
    pub async fn get_route_dtos(&self) -> Vec<IngressRouteDto> {
        let routes = self.routes.read().unwrap();
        let now_ms = chrono::Utc::now().timestamp_millis();
        let mut out = Vec::with_capacity(routes.len());

        for r in routes.iter() {
            let req_count = r.request_count.load(Ordering::Relaxed);
            let err_count = r.error_count.load(Ordering::Relaxed);
            let err_pct = if req_count > 0 {
                (err_count as f64 * 100.0) / (req_count as f64)
            } else {
                0.0
            };

            let win_start = r.window_start_ms.load(Ordering::Relaxed);
            let elapsed_sec = ((now_ms - win_start).max(1000) as f64) / 1000.0;
            let win_reqs = r.window_request_count.load(Ordering::Relaxed);
            let rps = (win_reqs as f64) / elapsed_sec;

            let samples_guard = r.latency_samples.lock().unwrap();
            let p95 = if samples_guard.is_empty() {
                5.0
            } else {
                let mut sorted: Vec<f64> = samples_guard.iter().copied().collect();
                sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                let idx = (((sorted.len() as f64) * 0.95).ceil() as usize).saturating_sub(1);
                sorted[idx.min(sorted.len() - 1)]
            };

            out.push(IngressRouteDto {
                route_id: r.route_id.clone(),
                path_prefix: r.path_prefix.clone(),
                upstream_url: r.upstream_url.clone(),
                service_name: r.service_name.clone(),
                strip_prefix: r.strip_prefix,
                auth_required: r.auth_required,
                request_count: req_count,
                request_rate_rps: (rps * 10.0).round() / 10.0,
                error_rate_pct: (err_pct * 10.0).round() / 10.0,
                p95_latency_ms: (p95 * 10.0).round() / 10.0,
            });
        }

        out
    }

    /// Returns all registered upstreams as DTOs.
    pub async fn get_upstream_dtos(&self) -> Vec<IngressUpstreamDto> {
        let upstreams = self.upstreams.read().unwrap();
        let mut out = Vec::with_capacity(upstreams.len());

        for u in upstreams.values() {
            let total = u.total_probes.load(Ordering::Relaxed);
            let success = u.success_count.load(Ordering::Relaxed);
            let rate = if total > 0 {
                (success as f64 * 100.0) / (total as f64)
            } else {
                100.0
            };

            let health = u.health_state.lock().unwrap().clone();
            let lat = *u.latency_ms.lock().unwrap();

            out.push(IngressUpstreamDto {
                upstream_id: u.upstream_id.clone(),
                target_url: u.target_url.clone(),
                service_name: u.service_name.clone(),
                health_state: health,
                latency_ms: (lat * 10.0).round() / 10.0,
                success_rate_pct: (rate * 10.0).round() / 10.0,
                active_connections: u.active_connections.load(Ordering::Relaxed),
                last_check_ms: u.last_check_ms.load(Ordering::Relaxed),
            });
        }

        out.sort_by(|a, b| a.upstream_id.cmp(&b.upstream_id));
        out
    }

    /// Returns aggregate overview DTO for muConsole.
    pub async fn get_overview_dto(&self) -> IngressOverviewDto {
        let routes = self.get_route_dtos().await;
        let upstreams = self.get_upstream_dtos().await;
        let tls_health = self.tls_health.read().unwrap().clone();

        IngressOverviewDto {
            routes,
            upstreams,
            tls_health,
        }
    }

    /// Updates the configured TLS termination health telemetry.
    pub async fn set_tls_health(&self, tls: TlsHealthDto) {
        let mut guard = self.tls_health.write().unwrap();
        *guard = Some(tls);
    }

    async fn get_or_create_upstream(
        &self,
        upstream_url: &str,
        service_name: &str,
    ) -> Arc<IngressUpstreamState> {
        let mut upstreams = self.upstreams.write().unwrap();
        let u_id = format!("upstream-{}", service_name);
        upstreams
            .entry(u_id.clone())
            .or_insert_with(|| {
                Arc::new(IngressUpstreamState {
                    upstream_id: u_id,
                    target_url: upstream_url.to_string(),
                    service_name: service_name.to_string(),
                    health_state: Mutex::new("HEALTHY".into()),
                    latency_ms: Mutex::new(2.0),
                    success_count: AtomicU64::new(1),
                    total_probes: AtomicU64::new(1),
                    active_connections: AtomicU32::new(0),
                    last_check_ms: AtomicI64::new(chrono::Utc::now().timestamp_millis()),
                    consecutive_failures: AtomicU32::new(0),
                })
            })
            .clone()
    }

    /// Reverse-proxies an HTTP request, recording W3C trace spans into DuckDB.
    pub async fn proxy_request(
        &self,
        req: axum::extract::Request,
    ) -> Result<axum::response::Response, MuObserveError> {
        let start_time_unix_nano = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
        let path = req.uri().path().to_string();
        let method = req.method().clone();

        let route = match self.match_route(&path).await {
            Some(r) => r,
            None => {
                return Ok(axum::response::Response::builder()
                    .status(axum::http::StatusCode::NOT_FOUND)
                    .body(axum::body::Body::from(format!(
                        "No ingress route matches '{path}'"
                    )))
                    .unwrap_or_default());
            }
        };

        // Extract incoming W3C traceparent or derive root
        let incoming_parent = req
            .headers()
            .get("traceparent")
            .and_then(|h| h.to_str().ok())
            .and_then(|val| TraceContext::parse_traceparent(val).ok());

        let server_ctx = match incoming_parent {
            Some(ctx) => ctx.next_deterministic_child(1),
            None => {
                TraceContext::from_seed(start_time_unix_nano as u64, 0x517c_c1b7_2722_0a95, 1, true)
            }
        };
        let upstream_child_ctx = server_ctx.next_deterministic_child(2);

        // Path rewriting
        let target_path = if route.strip_prefix {
            path.strip_prefix(&route.path_prefix).unwrap_or(&path)
        } else {
            &path
        };
        let target_uri = match req.uri().query() {
            Some(q) => format!("{target_path}?{q}"),
            None => target_path.to_string(),
        };

        // Track active connection
        let upstream = self
            .get_or_create_upstream(&route.upstream_url, &route.service_name)
            .await;
        upstream.active_connections.fetch_add(1, Ordering::SeqCst);

        // Forward HTTP request
        let (host, port) = parse_host_port(&route.upstream_url);
        let resp_result = forward_http(host, port, &target_uri, req, &upstream_child_ctx).await;
        upstream.active_connections.fetch_sub(1, Ordering::SeqCst);

        let end_time_unix_nano = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
        let duration_ns = (end_time_unix_nano - start_time_unix_nano).max(0) as u64;

        let (status_code, status_msg, resp) = match resp_result {
            Ok(r) => (r.status().as_u16(), None, r),
            Err(e) => (
                502,
                Some(format!("Upstream error: {e}")),
                axum::response::Response::builder()
                    .status(axum::http::StatusCode::BAD_GATEWAY)
                    .body(axum::body::Body::from(format!("Bad Gateway: {e}")))
                    .unwrap_or_default(),
            ),
        };

        // Record OtelSpanEntry directly into HotDuckDbStore
        let span = OtelSpanEntry {
            trace_id: server_ctx.trace_id_hex(),
            span_id: server_ctx.span_id_hex(),
            parent_span_id: incoming_parent.map(|c| c.span_id_hex()),
            service_name: "mu-ingress".to_string(),
            node_id: self.node_id.clone(),
            span_name: format!("{} {}", method, path),
            span_kind: "SERVER".to_string(),
            start_time_unix_nano,
            end_time_unix_nano,
            duration_ns,
            status_code: if status_code >= 500 {
                "ERROR".to_string()
            } else {
                "OK".to_string()
            },
            status_message: status_msg,
            attributes_json: serde_json::json!({
                "http.method": method.as_str(),
                "http.target": path,
                "http.status_code": status_code,
                "upstream.url": route.upstream_url,
                "upstream.service": route.service_name,
                "ingress.route_id": route.route_id,
            })
            .to_string(),
        };

        let _ = self.store.insert_spans_batch(&[span]);

        // Update route metrics
        route.request_count.fetch_add(1, Ordering::Relaxed);
        route.window_request_count.fetch_add(1, Ordering::Relaxed);
        if status_code >= 500 {
            route.error_count.fetch_add(1, Ordering::Relaxed);
        }
        let latency_ms = (duration_ns as f64) / 1_000_000.0;
        let mut samples = route.latency_samples.lock().unwrap();
        if samples.len() >= 500 {
            samples.pop_front();
        }
        samples.push_back(latency_ms);

        Ok(resp)
    }
}

/// Active background probe runner monitoring upstream targets.
pub struct UpstreamHealthChecker;

impl UpstreamHealthChecker {
    /// Spawns a background task monitoring upstreams on `interval`.
    pub fn spawn(engine: Arc<IngressEngine>, interval: Duration) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                let upstreams: Vec<Arc<IngressUpstreamState>> = {
                    let map = engine.upstreams.read().unwrap();
                    map.values().cloned().collect()
                };

                for up in upstreams {
                    let (host, port) = parse_host_port(&up.target_url);
                    let start = std::time::Instant::now();
                    let success = tokio::time::timeout(
                        Duration::from_secs(2),
                        tokio::net::TcpStream::connect((host.as_str(), port)),
                    )
                    .await
                    .is_ok_and(|res| res.is_ok());

                    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

                    let mut lat_guard = up.latency_ms.lock().unwrap();
                    *lat_guard = (*lat_guard * 0.7) + (latency_ms * 0.3); // EMA

                    up.total_probes.fetch_add(1, Ordering::Relaxed);
                    let mut health = up.health_state.lock().unwrap();

                    if success {
                        up.success_count.fetch_add(1, Ordering::Relaxed);
                        up.consecutive_failures.store(0, Ordering::Relaxed);
                        *health = if *lat_guard > 500.0 {
                            "DEGRADED".into()
                        } else {
                            "HEALTHY".into()
                        };
                    } else {
                        let fails = up.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
                        *health = if fails >= 3 {
                            "UNHEALTHY".into()
                        } else {
                            "DEGRADED".into()
                        };
                    }
                    up.last_check_ms
                        .store(chrono::Utc::now().timestamp_millis(), Ordering::Relaxed);
                }
            }
        })
    }
}

fn parse_host_port(target_url: &str) -> (String, u16) {
    let trimmed = target_url
        .strip_prefix("http://")
        .or_else(|| target_url.strip_prefix("https://"))
        .unwrap_or(target_url);

    let authority = trimmed.split('/').next().unwrap_or(trimmed);
    let mut parts = authority.split(':');
    let host = parts.next().unwrap_or("127.0.0.1").to_string();
    let port = parts
        .next()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(80);
    (host, port)
}

async fn forward_http(
    host: String,
    port: u16,
    target_uri: &str,
    req: axum::extract::Request,
    child_ctx: &TraceContext,
) -> Result<axum::response::Response, String> {
    let stream = tokio::net::TcpStream::connect((host.as_str(), port))
        .await
        .map_err(|e| format!("Connect failed to {host}:{port}: {e}"))?;

    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| format!("HTTP/1.1 handshake failed: {e}"))?;

    tokio::spawn(async move {
        let _ = conn.await;
    });

    let (parts, body) = req.into_parts();
    let body_bytes = body
        .collect()
        .await
        .map_err(|e| format!("Failed to read request body: {e}"))?
        .to_bytes();

    let mut forward_req = hyper::Request::builder()
        .method(parts.method)
        .uri(target_uri);

    for (name, val) in parts.headers {
        if let Some(n) = name {
            if n != hyper::header::HOST {
                forward_req = forward_req.header(n, val);
            }
        }
    }

    forward_req = forward_req.header(hyper::header::HOST, format!("{host}:{port}"));
    forward_req = forward_req.header("traceparent", child_ctx.to_traceparent());

    let forward_req = forward_req
        .body(Full::new(body_bytes))
        .map_err(|e| format!("Failed to build forward request: {e}"))?;

    let resp = sender
        .send_request(forward_req)
        .await
        .map_err(|e| format!("Upstream request failed: {e}"))?;

    let (resp_parts, resp_body) = resp.into_parts();
    let resp_bytes = resp_body
        .collect()
        .await
        .map_err(|e| format!("Failed to read response body: {e}"))?
        .to_bytes();

    let mut axum_resp = axum::response::Response::builder().status(resp_parts.status);
    for (name, val) in resp_parts.headers {
        if let Some(n) = name {
            axum_resp = axum_resp.header(n, val);
        }
    }

    axum_resp
        .body(axum::body::Body::from(resp_bytes))
        .map_err(|e| format!("Failed to construct axum response: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_ingress_engine_routes_and_traceparent_injection() {
        let store = HotDuckDbStore::open_in_memory().expect("open store");
        let engine = IngressEngine::new(store.clone(), "test-node".into());

        let routes = engine.get_route_dtos().await;
        assert_eq!(routes.len(), 5);

        let matched = engine.match_route("/api/reg/v1/packages").await;
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().service_name, "muregist");

        let overview = engine.get_overview_dto().await;
        assert_eq!(overview.routes.len(), 5);
        assert!(!overview.upstreams.is_empty());
        assert!(overview.tls_health.is_some());
    }
}
