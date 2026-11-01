//! `muobserve`: Distributed OTEL + DuckDB/Parquet observability backend, centralized
//! `ActionRunner-controller` state catalog, hardware-aware benchmark & test regression
//! analytics engine, and Antigravity Model Context Protocol (MCP) server.

pub mod analytics;
pub mod cli;
pub mod error;
pub mod mcp;
pub mod server;
pub mod sql_guard;
pub mod storage;

/// Default hot DuckDB retention window in days before cold Zstd Parquet compaction.
pub const DEFAULT_HOT_RETENTION_DAYS: u32 = 7;

pub use analytics::{
    compute_test_flakiness, evaluate_benchmark_regressions, evaluate_canary_slo,
    evaluate_regression_gate, FlakyTestItem,
};
pub use cli::{
    execute_cli_command, migrate_actionrunner_duckdb, parse_cli_args, ActionRunnerMigrationReport,
    CliCommand,
};
pub use error::MuObserveError;
pub use mcp::{JsonRpcError, JsonRpcRequest, JsonRpcResponse, McpServer, MCP_TOOL_NAMES};
pub use server::{
    build_mtls_server_config, build_sandbox_execution_plan, dispatch_frame, extract_cert_sans,
    resolve_san_identity, CollectorBatchAck, IngestServerConfig, MtlsIngestServer, SanAttribution,
    SanEnforcementPolicy, MSG_TYPE_ARROW_LOGS, MSG_TYPE_ARROW_METRICS, MSG_TYPE_ARROW_SPANS,
};
pub use sql_guard::{
    execute_guarded_sql, validate_readonly_sql, SqlQueryResult, DEFAULT_SQL_MAX_ROWS,
    DEFAULT_SQL_TIMEOUT_MS,
};
pub use storage::{
    register_unified_views, CompactionReport, CompactorConfig, HotDuckDbStore, ParquetCompactor,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_retention_window() {
        assert_eq!(DEFAULT_HOT_RETENTION_DAYS, 7);
    }
}
