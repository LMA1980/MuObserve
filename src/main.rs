use std::path::PathBuf;
use std::sync::Arc;

use muobserve::{
    build_mtls_server_config, execute_cli_command, parse_cli_args, HotDuckDbStore,
    IngestServerConfig, McpServer, MtlsIngestServer, SanEnforcementPolicy,
};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("mcp-stdio") {
        let db_path = std::env::var("MUOBSERVE_DB_PATH").ok().map(PathBuf::from);
        let parquet_root = std::env::var("MUOBSERVE_PARQUET_ROOT")
            .ok()
            .map(PathBuf::from);
        let store = HotDuckDbStore::open(db_path.as_deref(), parquet_root.as_deref())
            .expect("failed to initialize HotDuckDbStore");
        let mcp = McpServer::new(store);
        let stdin = std::io::stdin();
        let stdout = std::io::stdout();
        if let Err(e) = mcp.serve_stdio(stdin.lock(), stdout.lock()) {
            eprintln!("muobserve mcp-stdio error: {e}");
            std::process::exit(1);
        }
        return;
    }

    let serve_flag = matches!(args.first().map(String::as_str), Some("serve" | "--serve"))
        || std::env::var("MUOBSERVE_SERVE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

    if serve_flag {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .init();

        let db_path = std::env::var("MUOBSERVE_DB_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/var/lib/muobserve/db/muobserve.duckdb"));
        let parquet_root = std::env::var("MUOBSERVE_PARQUET_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/var/lib/muobserve/parquet"));

        let store = HotDuckDbStore::open(Some(&db_path), Some(&parquet_root))
            .expect("failed to open HotDuckDbStore");

        let mcp_http_addr = std::env::var("MUOBSERVE_MCP_HTTP_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:9480".to_string());
        let mcp_store = store.clone();
        tokio::spawn(async move {
            if let Ok(listener) = tokio::net::TcpListener::bind(&mcp_http_addr).await {
                tracing::info!(%mcp_http_addr, "MuObserve MCP HTTP/SSE server listening");
                let _ = axum::serve(listener, McpServer::new(mcp_store).router()).await;
            }
        });

        let listen_addr =
            std::env::var("MUOBSERVE_LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:9443".to_string());
        let ca_path = std::env::var("MUOBSERVE_CA_CERT")
            .unwrap_or_else(|_| "/etc/muobserve/tls/ca.crt".to_string());
        let cert_path = std::env::var("MUOBSERVE_SERVER_CERT")
            .unwrap_or_else(|_| "/etc/muobserve/tls/server.crt".to_string());
        let key_path = std::env::var("MUOBSERVE_SERVER_KEY")
            .unwrap_or_else(|_| "/etc/muobserve/tls/server.key".to_string());

        let ca_pem = std::fs::read_to_string(&ca_path).expect("failed to read MUOBSERVE_CA_CERT");
        let cert_pem =
            std::fs::read_to_string(&cert_path).expect("failed to read MUOBSERVE_SERVER_CERT");
        let key_pem =
            std::fs::read_to_string(&key_path).expect("failed to read MUOBSERVE_SERVER_KEY");

        let tls_cfg =
            build_mtls_server_config(&ca_pem, &cert_pem, &key_pem).expect("failed to build mTLS");
        let san_policy = match std::env::var("MUOBSERVE_SAN_POLICY")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str()
        {
            "reject" | "reject_mismatch" => SanEnforcementPolicy::RejectMismatch,
            _ => SanEnforcementPolicy::OverrideWithCertSan,
        };
        let ingest_cfg = IngestServerConfig {
            san_policy,
            redact_on_ingest: true,
            allowed_dns_suffix: std::env::var("MUOBSERVE_ALLOWED_DNS_SUFFIX")
                .ok()
                .filter(|s| !s.trim().is_empty()),
        };

        let server = MtlsIngestServer::new(store, ingest_cfg, Arc::new(tls_cfg));
        let listener = tokio::net::TcpListener::bind(&listen_addr)
            .await
            .expect("failed to bind MUOBSERVE_LISTEN_ADDR");
        tracing::info!(
            %listen_addr,
            db = %db_path.display(),
            parquet = %parquet_root.display(),
            "muobserve v{} mTLS ingestion & Fory RPC server listening",
            env!("CARGO_PKG_VERSION")
        );
        if let Err(e) = server.serve(listener).await {
            eprintln!("muobserve server error: {e}");
            std::process::exit(1);
        }
        return;
    }

    if !args.is_empty() {
        match parse_cli_args(&args) {
            Ok((db_path, cmd)) => {
                let parquet_root = db_path
                    .as_ref()
                    .and_then(|p| p.parent().map(|dir| dir.join("parquet")));
                let store = HotDuckDbStore::open(db_path.as_deref(), parquet_root.as_deref())
                    .expect("failed to open HotDuckDbStore");
                match execute_cli_command(&store, &cmd) {
                    Ok(out) => {
                        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
                        return;
                    }
                    Err(e) => {
                        eprintln!("muobserve error: {e}");
                        std::process::exit(1);
                    }
                }
            }
            Err(_) => {
                let _ = PathBuf::new();
            }
        }
    }

    println!(
        "muobserve v{} initialized (hot retention window: {} days)",
        env!("CARGO_PKG_VERSION"),
        muobserve::DEFAULT_HOT_RETENTION_DAYS
    );
}
