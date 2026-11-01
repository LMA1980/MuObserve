//! `muobserve`: Distributed OTEL + DuckDB/Parquet observability backend, regression engine, and Antigravity MCP server.

/// Default hot DuckDB retention window in days before cold Zstd Parquet compaction.
pub const DEFAULT_HOT_RETENTION_DAYS: u32 = 7;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_retention_window() {
        assert_eq!(DEFAULT_HOT_RETENTION_DAYS, 7);
    }
}
