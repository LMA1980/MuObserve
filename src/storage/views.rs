use std::path::Path;

use duckdb::Connection;

use crate::error::MuObserveError;

const VIEW_SPECS: &[(&str, &str, &str, &str)] = &[
    (
        "v_logs",
        "otel_logs",
        "logs",
        "timestamp_unix_nano, trace_id, span_id, severity_number, severity_text, service_name, node_id, body, attributes_json, job_id, stage_id, COALESCE(line_no, 0::UINTEGER) AS line_no, COALESCE(stream, 1::UTINYINT) AS stream, COALESCE(dedup_hash, 0::UBIGINT) AS dedup_hash",
    ),
    (
        "v_traces",
        "otel_spans",
        "spans",
        "trace_id, span_id, parent_span_id, service_name, node_id, span_name, span_kind, start_time_unix_nano, end_time_unix_nano, duration_ns, status_code, status_message, attributes_json",
    ),
    (
        "v_metrics",
        "otel_metrics",
        "metrics",
        "timestamp_unix_nano, service_name, node_id, metric_name, metric_unit, value_f64, arch, cpu_cluster, vlen_bits, memlock_used_bytes, memlock_limit_bytes, trace_id, span_id, attributes_json",
    ),
    (
        "v_tests",
        "test_case_runs",
        "tests",
        "job_id, repo_key, branch_key, commit_sha, crate_name, test_binary, test_name, status, duration_ms, failure_summary, timestamp_unix_nano, node_id, arch",
    ),
    (
        "v_benchmarks",
        "benchmark_runs",
        "benchmarks",
        "job_id, repo_key, branch_key, commit_sha, crate_name, bench_name, ns_per_iter, std_dev_ns, mad_ns, p50_ns, p95_ns, p99_ns, throughput_value, throughput_unit, arch, cpu_cluster, vlen_bits, timestamp_unix_nano, node_id",
    ),
    (
        "v_jobs_history",
        "jobs_history",
        "jobs_history",
        "job_id, event_type, repo_name, repo_key, clone_url, commit_sha, ref_name, branch_key, sender, queued_at_us, updated_at_us, status_state, exit_code, duration_secs, quality_score, letter_grade, coverage_pct, benchmark_summary, tests_passed, tests_total, advisories_count, clippy_warnings, record_json",
    ),
];

/// Registers or refreshes the unified DuckDB analytical views (`v_logs`, `v_traces`, `v_metrics`,
/// `v_tests`, `v_benchmarks`, `v_jobs_history`) combining `hot.duckdb` tables with cold
/// Hive-partitioned Zstd Parquet files under `parquet_root/signal=<signal>/**/*.parquet`.
pub fn register_unified_views(
    conn: &Connection,
    parquet_root: Option<&Path>,
) -> Result<(), MuObserveError> {
    for &(view_name, hot_table, signal_name, cols) in VIEW_SPECS {
        let cold_files = parquet_root
            .map(|root| collect_parquet_files(&root.join(format!("signal={signal_name}"))))
            .unwrap_or_default();

        let sql = if cold_files.is_empty() {
            format!("CREATE OR REPLACE VIEW {view_name} AS SELECT {cols} FROM {hot_table};")
        } else {
            let root = parquet_root.expect("parquet_root present when cold_files non-empty");
            let signal_dir = root.join(format!("signal={signal_name}"));
            let glob_pattern = format!(
                "{}/**/*.parquet",
                escape_sql_literal(&signal_dir.to_string_lossy())
            );
            format!(
                "CREATE OR REPLACE VIEW {view_name} AS \
                 SELECT {cols} FROM ( \
                     SELECT * FROM {hot_table} \
                     UNION ALL BY NAME \
                     SELECT * FROM read_parquet('{glob_pattern}', hive_partitioning = true, union_by_name = true) \
                 );"
            )
        };
        conn.execute_batch(&sql)?;
    }
    Ok(())
}

fn collect_parquet_files(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if !dir.exists() {
        return out;
    }
    let mut stack = vec![dir.to_path_buf()];
    while let Some(curr) = stack.pop() {
        if let Ok(entries) = std::fs::read_dir(&curr) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().and_then(|e| e.to_str()) == Some("parquet") {
                    out.push(path);
                }
            }
        }
    }
    out
}

pub(crate) fn escape_sql_literal(input: &str) -> String {
    input.replace('\'', "''")
}
