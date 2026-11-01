use thiserror::Error;

/// Unified error type for the `MuObserve` observability backend, regression engine, and MCP server.
#[derive(Debug, Error)]
pub enum MuObserveError {
    #[error("DuckDB storage error: {0}")]
    DuckDb(#[from] duckdb::Error),

    #[error("IPC wire error: {0}")]
    Ipc(#[from] muobserve_ipc::IpcError),

    #[error("Isolation sandbox error: {0}")]
    Isolation(#[from] mu_isolation::IsolationError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("TLS / X.509 error: {0}")]
    Tls(String),

    #[error("SAN spoofing or attribution violation: {0}")]
    SanViolation(String),

    #[error("SQL guard violation: {0}")]
    SqlGuard(String),

    #[error("SQL query timeout after {timeout_ms} ms")]
    SqlTimeout { timeout_ms: u64 },

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Internal lock poisoned: {0}")]
    LockPoisoned(String),
}
