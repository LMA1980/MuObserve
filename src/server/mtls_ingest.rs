use std::ffi::OsString;
use std::io::Cursor;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use mu_isolation::{
    EffectiveSandboxPolicy, IsolationBackend, KernelSandbox, NetworkEgressMode, SandboxBackendKind,
    SandboxExecutionPlan,
};
use muobserve_ipc::{
    decode_benchmark_run_batch, decode_control_envelope, decode_log_batch, decode_metric_batch,
    decode_span_batch, decode_test_run_batch, encode_control_envelope, read_frame, write_frame,
    ControlRpcEnvelope, DeterministicSecretRedactor, IpcHeader, QueryBranchSnapshotsResponse,
    QueryJobsHistoryResponse, QuerySubmoduleSnapshotsResponse, UpsertJobRecordResponse,
    WalBatchAck, MSG_TYPE_ARROW_BENCH_RUNS, MSG_TYPE_ARROW_OTEL_LOGS, MSG_TYPE_ARROW_OTEL_METRICS,
    MSG_TYPE_ARROW_OTEL_SPANS, MSG_TYPE_ARROW_TEST_RUNS, MSG_TYPE_FORY_CONTROL, MSG_TYPE_WAL_ACK,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use x509_parser::prelude::*;

use crate::analytics::{evaluate_canary_slo, evaluate_regression_gate};
use crate::error::MuObserveError;
use crate::storage::hot_duckdb::HotDuckDbStore;

/// Alias for [`WalBatchAck`] returned to `MuObserve-collector` upon Arrow batch ingestion.
pub type CollectorBatchAck = WalBatchAck;

/// Alias constants matching both `MSG_TYPE_ARROW_LOGS` and `MSG_TYPE_ARROW_OTEL_LOGS` naming.
pub const MSG_TYPE_ARROW_LOGS: u16 = MSG_TYPE_ARROW_OTEL_LOGS;
/// Alias constant for `MSG_TYPE_ARROW_OTEL_SPANS`.
pub const MSG_TYPE_ARROW_SPANS: u16 = MSG_TYPE_ARROW_OTEL_SPANS;
/// Alias constant for `MSG_TYPE_ARROW_OTEL_METRICS`.
pub const MSG_TYPE_ARROW_METRICS: u16 = MSG_TYPE_ARROW_OTEL_METRICS;

/// Policy governing how client certificate Subject Alternative Names (SANs) are enforced
/// against `node_id` and `service_name` fields in ingested Arrow batches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SanEnforcementPolicy {
    /// Rejects any batch whose `node_id` (or `service_name` when bound) does not match
    /// the authenticated client certificate SAN (`MuObserveError::SanViolation`).
    #[default]
    RejectMismatch,
    /// Overrides the batch's `node_id` (and `service_name` if present in the SAN) with the
    /// cryptographically verified client certificate SAN.
    OverrideWithCertSan,
}

/// Cryptographically verified node and optional service identity extracted from a `step-ca`
/// client certificate's DNS/URI Subject Alternative Names (SANs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SanAttribution {
    pub raw_sans: Vec<String>,
    pub node_id: String,
    pub service_name: Option<String>,
}

/// Configuration for the `MuObserve` mTLS ingestion server and `MuIsolation` startup sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestServerConfig {
    pub san_policy: SanEnforcementPolicy,
    pub redact_on_ingest: bool,
    pub allowed_dns_suffix: Option<String>,
}

impl Default for IngestServerConfig {
    fn default() -> Self {
        Self {
            san_policy: SanEnforcementPolicy::RejectMismatch,
            redact_on_ingest: true,
            allowed_dns_suffix: None,
        }
    }
}

/// Extracts all DNS and URI Subject Alternative Names (SANs) from a DER-encoded X.509 certificate.
pub fn extract_cert_sans(cert_der: &[u8]) -> Result<Vec<String>, MuObserveError> {
    if cert_der.is_empty() {
        return Err(MuObserveError::Tls(
            "Empty client certificate DER bytes".into(),
        ));
    }
    let (_, x509) = X509Certificate::from_der(cert_der)
        .map_err(|e| MuObserveError::Tls(format!("Failed to parse X.509 DER certificate: {e}")))?;

    let mut sans = Vec::new();
    for ext in x509.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for general_name in &san.general_names {
                match general_name {
                    GeneralName::DNSName(dns) => sans.push((*dns).to_string()),
                    GeneralName::URI(uri) => sans.push((*uri).to_string()),
                    GeneralName::RFC822Name(rfc) => sans.push((*rfc).to_string()),
                    _ => {}
                }
            }
        }
    }

    if sans.is_empty() {
        return Err(MuObserveError::SanViolation(
            "Client certificate contains no DNS or URI SAN entries".into(),
        ));
    }
    Ok(sans)
}

/// Resolves a [`SanAttribution`] (`node_id` and optional `service_name`) from DER-encoded client
/// certificate bytes.
///
/// Supported SAN conventions:
/// - URI SAN: `spiffe://<trust-domain>/node/<node_id>/service/<service_name>` or `spiffe://<trust-domain>/<node_id>/<service_name>`
/// - DNS SAN: `<service_name>.<node_id>.<domain>` or `<node_id>.<domain>` or `<node_id>`
pub fn resolve_san_identity(
    cert_der: &[u8],
    allowed_dns_suffix: Option<&str>,
) -> Result<SanAttribution, MuObserveError> {
    let sans = extract_cert_sans(cert_der)?;
    resolve_san_identity_from_list(&sans, allowed_dns_suffix)
}

/// Resolves a [`SanAttribution`] directly from a slice of SAN strings.
pub fn resolve_san_identity_from_list(
    sans: &[String],
    allowed_dns_suffix: Option<&str>,
) -> Result<SanAttribution, MuObserveError> {
    if sans.is_empty() {
        return Err(MuObserveError::SanViolation(
            "No SAN entries available for client attribution".into(),
        ));
    }

    if let Some(suffix) = allowed_dns_suffix {
        let clean_suffix = suffix.trim_start_matches('.');
        let matches_suffix = sans.iter().any(|s| {
            s == clean_suffix
                || s.ends_with(&format!(".{clean_suffix}"))
                || s.starts_with(&format!("spiffe://{clean_suffix}/"))
        });
        if !matches_suffix {
            return Err(MuObserveError::SanViolation(format!(
                "Client certificate SANs {sans:?} do not match required domain '{clean_suffix}'"
            )));
        }
    }

    let mut resolved_node: Option<String> = None;
    let mut resolved_service: Option<String> = None;

    for san in sans {
        if let Some(rest) = san.strip_prefix("spiffe://") {
            let parts: Vec<&str> = rest.split('/').collect();
            // e.g. spiffe://cluster.internal/node/worker-riscv64/service/action-runner-worker
            if parts.len() >= 5 && parts[1] == "node" && parts[3] == "service" {
                resolved_node = Some(parts[2].to_string());
                resolved_service = Some(parts[4].to_string());
                break;
            } else if parts.len() >= 3 {
                resolved_node = Some(parts[1].to_string());
                resolved_service = Some(parts[2].to_string());
                break;
            }
        }
    }

    if resolved_node.is_none() {
        for san in sans {
            if san.contains("://") {
                continue;
            }
            let stripped = if let Some(suffix) = allowed_dns_suffix {
                let clean_suffix = format!(".{}", suffix.trim_start_matches('.'));
                san.strip_suffix(&clean_suffix).unwrap_or(san.as_str())
            } else {
                san.split('.').next().unwrap_or(san.as_str())
            };
            let labels: Vec<&str> = stripped.split('.').filter(|s| !s.is_empty()).collect();
            if labels.len() >= 2 {
                resolved_service = Some(labels[0].to_string());
                resolved_node = Some(labels[1].to_string());
                break;
            } else if labels.len() == 1 {
                resolved_node = Some(labels[0].to_string());
                break;
            }
        }
    }

    let node_id = resolved_node.ok_or_else(|| {
        MuObserveError::SanViolation(format!(
            "Could not extract node_id from client SANs {sans:?}"
        ))
    })?;

    Ok(SanAttribution {
        raw_sans: sans.to_vec(),
        node_id,
        service_name: resolved_service,
    })
}

/// Builds a `rustls::ServerConfig` enforcing mutual TLS (`WebPkiClientVerifier`) rooted in
/// the provided `step-ca` CA bundle PEM.
pub fn build_mtls_server_config(
    ca_cert_pem: &str,
    server_cert_pem: &str,
    server_key_pem: &str,
) -> Result<ServerConfig, MuObserveError> {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    let mut ca_cursor = Cursor::new(ca_cert_pem.as_bytes());
    let ca_certs: Vec<CertificateDer<'static>> = CertificateDer::pem_reader_iter(&mut ca_cursor)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| MuObserveError::Tls(format!("Failed to parse CA PEM: {e}")))?;
    if ca_certs.is_empty() {
        return Err(MuObserveError::Tls(
            "CA PEM contains no certificates".into(),
        ));
    }

    let mut root_store = RootCertStore::empty();
    for cert in ca_certs {
        root_store
            .add(cert)
            .map_err(|e| MuObserveError::Tls(format!("Failed to add CA cert: {e}")))?;
    }

    let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .map_err(|e| MuObserveError::Tls(format!("Failed to build client verifier: {e}")))?;

    let mut srv_cursor = Cursor::new(server_cert_pem.as_bytes());
    let srv_certs: Vec<CertificateDer<'static>> = CertificateDer::pem_reader_iter(&mut srv_cursor)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| MuObserveError::Tls(format!("Failed to parse server cert PEM: {e}")))?;

    let mut key_cursor = Cursor::new(server_key_pem.as_bytes());
    let key: PrivateKeyDer<'static> = PrivateKeyDer::from_pem_reader(&mut key_cursor)
        .map_err(|e| MuObserveError::Tls(format!("Failed to parse server key PEM: {e}")))?;

    let server_config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(srv_certs, key)
        .map_err(|e| MuObserveError::Tls(format!("Failed to build ServerConfig: {e}")))?;

    Ok(server_config)
}

/// Builds and validates a `MuIsolation` [`KernelSandbox`] execution plan confining the
/// `MuObserve` daemon's filesystem access to `data_dir` and bounded `RLIMIT_MEMLOCK`.
pub fn build_sandbox_execution_plan(
    data_dir: &Path,
    arch: &str,
) -> Result<SandboxExecutionPlan, MuObserveError> {
    let sandbox = KernelSandbox::new();
    let policy = EffectiveSandboxPolicy {
        node_id: "node-a".to_string(),
        arch: arch.to_string(),
        backend: SandboxBackendKind::Kernel,
        read_paths: vec![
            Path::new("/usr").to_path_buf(),
            Path::new("/etc").to_path_buf(),
        ],
        write_paths: vec![data_dir.to_path_buf()],
        exec_paths: vec![Path::new("/usr/local/bin").to_path_buf()],
        network_mode: NetworkEgressMode::RestrictedCidrs(vec!["192.0.2.0/24".to_string()]),
        memlock_limit_kb: 65_536,
        max_pids: 128,
        max_memory_mb: 4096,
        max_cpu_cores: 4,
        cpu_affinity_mask: None,
        require_set_ai_thread: false,
    };
    sandbox.validate_host_support(&policy)?;
    let argv = vec![OsString::from("/usr/local/bin/muobserve")];
    let plan = sandbox.build_execution_plan(&policy, &argv)?;
    Ok(plan)
}

/// Validates or overrides `node_id` and `service_name` on a batch item using [`SanAttribution`].
fn enforce_san_on_item(
    attr: &SanAttribution,
    policy: SanEnforcementPolicy,
    node_id: &mut String,
    service_name: Option<&mut String>,
) -> Result<(), MuObserveError> {
    match policy {
        SanEnforcementPolicy::RejectMismatch => {
            if *node_id != attr.node_id {
                return Err(MuObserveError::SanViolation(format!(
                    "Batch node_id '{}' spoofs or mismatches authenticated client certificate SAN node_id '{}'",
                    node_id, attr.node_id
                )));
            }
            if let (Some(batch_svc), Some(expected_svc)) =
                (service_name, attr.service_name.as_ref())
            {
                if *batch_svc != *expected_svc {
                    return Err(MuObserveError::SanViolation(format!(
                        "Batch service_name '{}' mismatches authenticated client certificate SAN service_name '{}'",
                        batch_svc, expected_svc
                    )));
                }
            }
            Ok(())
        }
        SanEnforcementPolicy::OverrideWithCertSan => {
            *node_id = attr.node_id.clone();
            if let (Some(batch_svc), Some(expected_svc)) =
                (service_name, attr.service_name.as_ref())
            {
                *batch_svc = expected_svc.clone();
            }
            Ok(())
        }
    }
}

/// Dispatches a single `MUOB`-framed payload (`MSG_TYPE_ARROW_*` or `MSG_TYPE_FORY_CONTROL`)
/// against `HotDuckDbStore`, enforcing client certificate [`SanAttribution`] and returning the
/// response frame (`(IpcHeader, Vec<u8>)`).
pub fn dispatch_frame(
    store: &HotDuckDbStore,
    config: &IngestServerConfig,
    attribution: &SanAttribution,
    header: &IpcHeader,
    payload: &[u8],
) -> Result<(IpcHeader, Vec<u8>), MuObserveError> {
    match header.msg_type {
        MSG_TYPE_ARROW_OTEL_LOGS => {
            let mut entries = decode_log_batch(payload)?;
            let redactor = DeterministicSecretRedactor::new();
            for e in &mut entries {
                enforce_san_on_item(
                    attribution,
                    config.san_policy,
                    &mut e.node_id,
                    Some(&mut e.service_name),
                )?;
                if config.redact_on_ingest {
                    e.redact_in_place(&redactor);
                }
            }
            let accepted_rows = store.insert_logs_batch(&entries)?;
            encode_wal_ack_frame(header.sequence, accepted_rows, true, None)
        }
        MSG_TYPE_ARROW_OTEL_SPANS => {
            let mut entries = decode_span_batch(payload)?;
            let redactor = DeterministicSecretRedactor::new();
            for e in &mut entries {
                enforce_san_on_item(
                    attribution,
                    config.san_policy,
                    &mut e.node_id,
                    Some(&mut e.service_name),
                )?;
                if config.redact_on_ingest {
                    e.redact_in_place(&redactor);
                }
            }
            let accepted_rows = store.insert_spans_batch(&entries)?;
            encode_wal_ack_frame(header.sequence, accepted_rows, true, None)
        }
        MSG_TYPE_ARROW_OTEL_METRICS => {
            let mut entries = decode_metric_batch(payload)?;
            for e in &mut entries {
                enforce_san_on_item(
                    attribution,
                    config.san_policy,
                    &mut e.node_id,
                    Some(&mut e.service_name),
                )?;
            }
            let accepted_rows = store.insert_metrics_batch(&entries)?;
            encode_wal_ack_frame(header.sequence, accepted_rows, true, None)
        }
        MSG_TYPE_ARROW_TEST_RUNS => {
            let mut entries = decode_test_run_batch(payload)?;
            for e in &mut entries {
                enforce_san_on_item(attribution, config.san_policy, &mut e.node_id, None)?;
            }
            let accepted_rows = store.insert_test_runs_batch(&entries)?;
            encode_wal_ack_frame(header.sequence, accepted_rows, true, None)
        }
        MSG_TYPE_ARROW_BENCH_RUNS => {
            let mut entries = decode_benchmark_run_batch(payload)?;
            for e in &mut entries {
                enforce_san_on_item(attribution, config.san_policy, &mut e.node_id, None)?;
            }
            let accepted_rows = store.insert_benchmark_runs_batch(&entries)?;
            encode_wal_ack_frame(header.sequence, accepted_rows, true, None)
        }
        MSG_TYPE_FORY_CONTROL => {
            let req_env = decode_control_envelope(payload)?;
            let resp_env = dispatch_control_rpc(store, req_env)?;
            let resp_bytes = encode_control_envelope(&resp_env)?;
            let resp_hdr = IpcHeader::new(
                MSG_TYPE_FORY_CONTROL,
                resp_bytes.len() as u32,
                0,
                header.sequence,
            );
            Ok((resp_hdr, resp_bytes))
        }
        other => Err(MuObserveError::Validation(format!(
            "Unsupported MUOB frame message type: {other:#06x}"
        ))),
    }
}

fn encode_wal_ack_frame(
    sequence: u64,
    accepted_rows: u32,
    ok: bool,
    error_message: Option<String>,
) -> Result<(IpcHeader, Vec<u8>), MuObserveError> {
    let ack = WalBatchAck {
        sequence,
        accepted_rows,
        ok,
        error_message,
    };
    let env = ControlRpcEnvelope::WalAck(ack);
    let bytes = encode_control_envelope(&env)?;
    let hdr = IpcHeader::new(MSG_TYPE_WAL_ACK, bytes.len() as u32, 0, sequence);
    Ok((hdr, bytes))
}

fn dispatch_control_rpc(
    store: &HotDuckDbStore,
    envelope: ControlRpcEnvelope,
) -> Result<ControlRpcEnvelope, MuObserveError> {
    match envelope {
        ControlRpcEnvelope::Noop => Ok(ControlRpcEnvelope::Noop),
        ControlRpcEnvelope::UpsertJobRecordReq(req) => {
            let branch_slice = req.branch_snapshot.as_slice();
            let count = store.upsert_ci_state_batch(
                std::slice::from_ref(&req.record),
                branch_slice,
                &req.submodule_snapshots,
            )?;
            Ok(ControlRpcEnvelope::UpsertJobRecordResp(
                UpsertJobRecordResponse {
                    request_id: req.request_id,
                    accepted: true,
                    upserted_count: count,
                    error_message: None,
                },
            ))
        }
        ControlRpcEnvelope::UpsertJobBatchReq(req) => {
            let count = store.upsert_ci_state_batch(
                &req.records,
                &req.branch_snapshots,
                &req.submodule_snapshots,
            )?;
            Ok(ControlRpcEnvelope::UpsertJobRecordResp(
                UpsertJobRecordResponse {
                    request_id: req.request_id,
                    accepted: true,
                    upserted_count: count,
                    error_message: None,
                },
            ))
        }
        ControlRpcEnvelope::QueryJobsHistoryReq(req) => {
            let records = store.query_jobs_history(&req)?;
            Ok(ControlRpcEnvelope::QueryJobsHistoryResp(
                QueryJobsHistoryResponse {
                    request_id: req.request_id,
                    records,
                },
            ))
        }
        ControlRpcEnvelope::QueryBranchSnapshotsReq(req) => {
            let snapshots = store.query_branch_snapshots(&req)?;
            Ok(ControlRpcEnvelope::QueryBranchSnapshotsResp(
                QueryBranchSnapshotsResponse {
                    request_id: req.request_id,
                    snapshots,
                },
            ))
        }
        ControlRpcEnvelope::QuerySubmoduleSnapshotsReq(req) => {
            let snapshots = store.query_submodule_snapshots(&req)?;
            Ok(ControlRpcEnvelope::QuerySubmoduleSnapshotsResp(
                QuerySubmoduleSnapshotsResponse {
                    request_id: req.request_id,
                    snapshots,
                },
            ))
        }
        ControlRpcEnvelope::RegressionGateReq(req) => {
            let report = evaluate_regression_gate(store, &req)?;
            Ok(ControlRpcEnvelope::RegressionGateResp(report))
        }
        ControlRpcEnvelope::CanarySloReq(req) => {
            let resp = evaluate_canary_slo(store, &req, None)?;
            Ok(ControlRpcEnvelope::CanarySloResp(resp))
        }
        other => Err(MuObserveError::Validation(format!(
            "Unexpected ControlRpcEnvelope variant on server ingress: {other:?}"
        ))),
    }
}

/// Zero-trust `step-ca` mTLS ingestion server handling `MUOB`-framed Arrow telemetry batches
/// and Apache Fory control-plane RPC requests.
pub struct MtlsIngestServer {
    store: HotDuckDbStore,
    config: IngestServerConfig,
    tls_config: Arc<ServerConfig>,
}

impl MtlsIngestServer {
    /// Creates a new [`MtlsIngestServer`].
    #[must_use]
    pub fn new(
        store: HotDuckDbStore,
        config: IngestServerConfig,
        tls_config: Arc<ServerConfig>,
    ) -> Self {
        Self {
            store,
            config,
            tls_config,
        }
    }

    /// Processes a single framed request on an already-authenticated stream with verified [`SanAttribution`].
    pub async fn handle_single_frame_on_stream<S>(
        store: &HotDuckDbStore,
        config: &IngestServerConfig,
        attribution: &SanAttribution,
        stream: &mut S,
    ) -> Result<(), MuObserveError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (hdr, payload) = read_frame(stream).await?;
        let (resp_hdr, resp_payload) = dispatch_frame(store, config, attribution, &hdr, &payload)?;
        write_frame(stream, &resp_hdr, &resp_payload).await?;
        Ok(())
    }

    /// Binds a TCP listener and serves mTLS connections until the listener task is aborted.
    pub async fn serve(&self, listener: TcpListener) -> Result<(), MuObserveError> {
        let flush_store = self.store.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(15));
            loop {
                ticker.tick().await;
                let store_clone = flush_store.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    let _ = store_clone.flush_delayed(false);
                })
                .await;
            }
        });

        let acceptor = TlsAcceptor::from(Arc::clone(&self.tls_config));
        loop {
            let (tcp_stream, peer_addr): (tokio::net::TcpStream, SocketAddr) =
                listener.accept().await?;
            let acceptor = acceptor.clone();
            let store = self.store.clone();
            let config = self.config.clone();

            tokio::spawn(async move {
                let mut tls_stream = match acceptor.accept(tcp_stream).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(peer = %peer_addr, error = %e, "mTLS handshake failed");
                        return;
                    }
                };
                let (_, server_conn) = tls_stream.get_ref();
                let Some(certs) = server_conn.peer_certificates() else {
                    tracing::warn!(peer = %peer_addr, "mTLS peer did not present client certificates");
                    let _ = tls_stream.shutdown().await;
                    return;
                };
                let Some(leaf_cert) = certs.first() else {
                    tracing::warn!(peer = %peer_addr, "mTLS peer presented empty client certificate chain");
                    let _ = tls_stream.shutdown().await;
                    return;
                };
                let attribution = match resolve_san_identity(
                    leaf_cert.as_ref(),
                    config.allowed_dns_suffix.as_deref(),
                ) {
                    Ok(attr) => attr,
                    Err(e) => {
                        tracing::warn!(peer = %peer_addr, error = %e, "mTLS SAN identity resolution failed");
                        let _ = tls_stream.shutdown().await;
                        return;
                    }
                };

                while let Ok((hdr, payload)) = read_frame(&mut tls_stream).await {
                    match dispatch_frame(&store, &config, &attribution, &hdr, &payload) {
                        Ok((resp_hdr, resp_payload)) => {
                            if let Err(e) =
                                write_frame(&mut tls_stream, &resp_hdr, &resp_payload).await
                            {
                                tracing::warn!(peer = %peer_addr, error = %e, "Failed to write mTLS frame response");
                                break;
                            }
                        }
                        Err(e) => {
                            tracing::warn!(peer = %peer_addr, error = %e, "mTLS frame dispatch error");
                            if let Ok((err_hdr, err_payload)) =
                                encode_wal_ack_frame(hdr.sequence, 0, false, Some(e.to_string()))
                            {
                                let _ = write_frame(&mut tls_stream, &err_hdr, &err_payload).await;
                            }
                            break;
                        }
                    }
                }

                let _ = tls_stream.shutdown().await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use muobserve_ipc::{
        encode_log_batch, CentralJobRecord, OtelLogEntry, QueryJobsHistoryRequest,
        UpsertJobRecordRequest,
    };
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
    use tempfile::tempdir;

    fn generate_client_cert_with_sans(dns_san: &str, uri_san: Option<&str>) -> Vec<u8> {
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::new(vec![dns_san.to_string()]).unwrap();
        if let Some(uri) = uri_san {
            params
                .subject_alt_names
                .push(SanType::URI(uri.try_into().unwrap()));
        }
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, dns_san);
        params.distinguished_name = dn;
        let cert = params.self_signed(&key_pair).unwrap();
        cert.der().to_vec()
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_san_extraction_and_spoofing_rejection() {
        let store = HotDuckDbStore::open_in_memory().expect("open in memory");
        let cert_der = generate_client_cert_with_sans(
            "action-runner-worker.worker-riscv64.cluster.internal",
            Some("spiffe://cluster.internal/node/worker-riscv64/service/action-runner-worker"),
        );

        let attr = resolve_san_identity(&cert_der, Some("cluster.internal"))
            .expect("resolve san identity");
        assert_eq!(attr.node_id, "worker-riscv64");
        assert_eq!(attr.service_name.as_deref(), Some("action-runner-worker"));

        // Attempt to ingest a batch spoofing node_id = "node-a" when client cert SAN is "worker-riscv64"
        let spoofed_logs = vec![OtelLogEntry {
            timestamp_unix_nano: 1_700_000_000_000_000_000,
            trace_id: "trace-1".into(),
            span_id: "span-1".into(),
            severity_number: 9,
            severity_text: "INFO".into(),
            service_name: "action-runner-worker".into(),
            node_id: "node-a".into(), // Spoofed!
            body: "spoofed log".into(),
            attributes_json: "{}".into(),
            job_id: None,
            stage_id: None,
        }];
        let payload = encode_log_batch(&spoofed_logs).expect("encode logs");
        let hdr = IpcHeader::new(MSG_TYPE_ARROW_LOGS, payload.len() as u32, 0, 77);

        let config = IngestServerConfig {
            san_policy: SanEnforcementPolicy::RejectMismatch,
            redact_on_ingest: true,
            allowed_dns_suffix: Some("cluster.internal".into()),
        };

        let res = dispatch_frame(&store, &config, &attr, &hdr, &payload);
        assert!(
            matches!(res, Err(MuObserveError::SanViolation(_))),
            "Spoofed node_id must be rejected with SanViolation"
        );
        assert_eq!(store.count_rows("otel_logs").unwrap(), 0);

        // Now verify authentic batch with matching node_id = "worker-riscv64" succeeds
        let valid_logs = vec![OtelLogEntry {
            node_id: "worker-riscv64".into(),
            ..spoofed_logs[0].clone()
        }];
        let valid_payload = encode_log_batch(&valid_logs).expect("encode valid logs");
        let valid_hdr = IpcHeader::new(MSG_TYPE_ARROW_LOGS, valid_payload.len() as u32, 0, 78);

        let (ack_hdr, ack_bytes) =
            dispatch_frame(&store, &config, &attr, &valid_hdr, &valid_payload)
                .expect("dispatch valid batch");
        assert_eq!(ack_hdr.msg_type, MSG_TYPE_WAL_ACK);
        let decoded_env = decode_control_envelope(&ack_bytes).expect("decode ack");
        assert_eq!(
            decoded_env,
            ControlRpcEnvelope::WalAck(CollectorBatchAck {
                sequence: 78,
                accepted_rows: 1,
                ok: true,
                error_message: None,
            })
        );
        assert_eq!(store.count_rows("otel_logs").unwrap(), 1);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_fory_ci_state_crud_and_muisolation_sandbox_plan() {
        let store = HotDuckDbStore::open_in_memory().expect("open in memory");
        let attr = SanAttribution {
            raw_sans: vec!["node-a.cluster.internal".into()],
            node_id: "node-a".into(),
            service_name: Some("action-runner-controller".into()),
        };
        let config = IngestServerConfig::default();

        let job = CentralJobRecord {
            job_id: "job-777".into(),
            event_type: "push".into(),
            repo_name: "LMA1980/MuObserve".into(),
            repo_key: "lma1980/muobserve".into(),
            clone_url: "https://github.com/LMA1980/MuObserve.git".into(),
            commit_sha: "abcdef".into(),
            ref_name: "refs/heads/main".into(),
            branch_key: "main".into(),
            sender: "LMA1980".into(),
            queued_at_us: 100,
            updated_at_us: 200,
            status_state: "Completed".into(),
            exit_code: Some(0),
            duration_secs: Some(12),
            quality_score: Some(99),
            letter_grade: Some("A+".into()),
            coverage_pct: Some(94.0),
            benchmark_summary: None,
            tests_passed: Some(25),
            tests_total: Some(25),
            advisories_count: Some(0),
            clippy_warnings: Some(0),
            record_json: "{}".into(),
        };

        let req_env = ControlRpcEnvelope::UpsertJobRecordReq(UpsertJobRecordRequest {
            request_id: "req-upsert-1".into(),
            record: job.clone(),
            branch_snapshot: None,
            submodule_snapshots: Vec::new(),
        });
        let req_bytes = encode_control_envelope(&req_env).unwrap();
        let req_hdr = IpcHeader::new(MSG_TYPE_FORY_CONTROL, req_bytes.len() as u32, 0, 1);

        let (_, resp_bytes) = dispatch_frame(&store, &config, &attr, &req_hdr, &req_bytes).unwrap();
        let resp_env = decode_control_envelope(&resp_bytes).unwrap();
        assert!(matches!(
            resp_env,
            ControlRpcEnvelope::UpsertJobRecordResp(UpsertJobRecordResponse {
                accepted: true,
                upserted_count: 1,
                ..
            })
        ));

        let q_env = ControlRpcEnvelope::QueryJobsHistoryReq(QueryJobsHistoryRequest {
            request_id: "req-q-1".into(),
            repo_key: Some("lma1980/muobserve".into()),
            branch_key: None,
            job_id: None,
            limit: 10,
        });
        let q_bytes = encode_control_envelope(&q_env).unwrap();
        let q_hdr = IpcHeader::new(MSG_TYPE_FORY_CONTROL, q_bytes.len() as u32, 0, 2);
        let (_, q_resp_bytes) = dispatch_frame(&store, &config, &attr, &q_hdr, &q_bytes).unwrap();
        let q_resp = decode_control_envelope(&q_resp_bytes).unwrap();
        match q_resp {
            ControlRpcEnvelope::QueryJobsHistoryResp(r) => {
                assert_eq!(r.records, vec![job]);
            }
            other => panic!("unexpected response: {other:?}"),
        }

        // Verify MuIsolation KernelSandbox execution plan
        let dir = tempdir().unwrap();
        let plan = build_sandbox_execution_plan(dir.path(), "riscv64gc")
            .expect("build KernelSandbox plan");
        assert_eq!(plan.backend, SandboxBackendKind::Kernel);
        assert!(!plan.landlock_rules.is_empty());
    }
}
