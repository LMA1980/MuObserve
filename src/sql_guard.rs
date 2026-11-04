use std::time::{Duration, Instant};

use duckdb::types::ValueRef;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::MuObserveError;
use crate::storage::hot_duckdb::HotDuckDbStore;

/// Default maximum query execution timeout (`5s`).
pub const DEFAULT_SQL_TIMEOUT_MS: u64 = 5_000;

/// Default maximum rows returned by an analytics SQL query (`1000`).
pub const DEFAULT_SQL_MAX_ROWS: usize = 1_000;

const FORBIDDEN_KEYWORDS: &[&str] = &[
    "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "COPY", "ATTACH", "DETACH", "PRAGMA",
    "INSTALL", "LOAD", "EXPORT", "IMPORT", "CALL", "VACUUM", "TRUNCATE", "GRANT", "REVOKE", "SET",
    "RESET", "BEGIN", "COMMIT", "ROLLBACK",
];

const ALLOWED_STARTS: &[&str] = &["SELECT", "WITH", "EXPLAIN"];

/// Structured result of a guarded read-only DuckDB analytical query.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SqlQueryResult {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Value>>,
    pub row_count: usize,
    pub truncated: bool,
    pub elapsed_ms: u64,
}

/// Validates that `sql` is a single read-only statement starting with `SELECT`, `WITH`, or `EXPLAIN`,
/// free of comments (`--` or `/*`), multi-statement semicolons (`;`), and DDL/DML/administrative
/// keywords (`INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `CREATE`, `COPY`, `ATTACH`, `DETACH`,
/// `PRAGMA`, `INSTALL`, `LOAD`, etc.).
pub fn validate_readonly_sql(sql: &str) -> Result<String, MuObserveError> {
    let trimmed = sql.trim();
    if trimmed.is_empty() {
        return Err(MuObserveError::SqlGuard("SQL query cannot be empty".into()));
    }

    if trimmed.contains("--") || trimmed.contains("/*") || trimmed.contains("*/") {
        return Err(MuObserveError::SqlGuard(
            "SQL comments ('--', '/*') are forbidden by read-only SQL guard".into(),
        ));
    }

    // Strip a single optional trailing semicolon, then reject any remaining semicolon outside string literals
    let without_trailing_semi = trimmed.strip_suffix(';').unwrap_or(trimmed).trim();
    if without_trailing_semi.is_empty() {
        return Err(MuObserveError::SqlGuard("SQL query cannot be empty".into()));
    }

    let tokens = tokenize_outside_literals(without_trailing_semi)?;

    let Some(first) = tokens.first() else {
        return Err(MuObserveError::SqlGuard(
            "SQL query contains no recognizable statement keyword".into(),
        ));
    };

    if !ALLOWED_STARTS.contains(&first.as_str()) {
        return Err(MuObserveError::SqlGuard(format!(
            "Disallowed statement starter '{first}'; only SELECT, WITH, and EXPLAIN are permitted"
        )));
    }

    for tok in &tokens {
        if FORBIDDEN_KEYWORDS.contains(&tok.as_str()) {
            return Err(MuObserveError::SqlGuard(format!(
                "Forbidden DDL/DML or administrative keyword '{tok}' rejected by read-only SQL guard"
            )));
        }
    }

    Ok(without_trailing_semi.to_string())
}

fn tokenize_outside_literals(sql: &str) -> Result<Vec<String>, MuObserveError> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut chars = sql.chars().peekable();

    while let Some(ch) = chars.next() {
        if in_single_quote {
            if ch == '\'' {
                if chars.peek() == Some(&'\'') {
                    let _ = chars.next();
                } else {
                    in_single_quote = false;
                }
            }
            continue;
        }
        if in_double_quote {
            if ch == '"' {
                if chars.peek() == Some(&'"') {
                    let _ = chars.next();
                } else {
                    in_double_quote = false;
                }
            }
            continue;
        }

        match ch {
            '\'' => {
                if !current.is_empty() {
                    tokens.push(current.to_ascii_uppercase());
                    current.clear();
                }
                in_single_quote = true;
            }
            '"' => {
                if !current.is_empty() {
                    tokens.push(current.to_ascii_uppercase());
                    current.clear();
                }
                in_double_quote = true;
            }
            ';' => {
                return Err(MuObserveError::SqlGuard(
                    "Multi-statement semicolon injection (';') is forbidden".into(),
                ));
            }
            c if c.is_ascii_alphanumeric() || c == '_' => {
                current.push(c);
            }
            _ => {
                if !current.is_empty() {
                    tokens.push(current.to_ascii_uppercase());
                    current.clear();
                }
            }
        }
    }

    if in_single_quote || in_double_quote {
        return Err(MuObserveError::SqlGuard(
            "Unterminated string or identifier literal in SQL query".into(),
        ));
    }

    if !current.is_empty() {
        tokens.push(current.to_ascii_uppercase());
    }

    Ok(tokens)
}

/// Validates and executes a read-only SQL query against `store`, enforcing a `timeout`
/// (default `5s`) and `max_rows` limit (default `1000` rows).
pub fn execute_guarded_sql(
    store: &HotDuckDbStore,
    sql: &str,
    max_rows: usize,
    timeout: Duration,
) -> Result<SqlQueryResult, MuObserveError> {
    let clean_sql = validate_readonly_sql(sql)?;
    let effective_limit = if max_rows == 0 {
        DEFAULT_SQL_MAX_ROWS
    } else {
        max_rows.min(DEFAULT_SQL_MAX_ROWS)
    };

    let is_explain = clean_sql
        .split_whitespace()
        .next()
        .map(|w| w.eq_ignore_ascii_case("EXPLAIN"))
        .unwrap_or(false);

    let bounded_sql = if is_explain {
        clean_sql
    } else {
        let fetch_limit = effective_limit + 1;
        format!("SELECT * FROM ({clean_sql}) AS _muobserve_guarded_subq LIMIT {fetch_limit}")
    };

    let start = Instant::now();
    let conn = store.lock_conn()?;
    let mut stmt = conn.prepare(&bounded_sql)?;

    let mut raw_rows = stmt.query([])?;
    let col_count = raw_rows.as_ref().map(|s| s.column_count()).unwrap_or(0);
    let mut columns = Vec::with_capacity(col_count);
    if let Some(stmt_ref) = raw_rows.as_ref() {
        for idx in 0..col_count {
            let name = stmt_ref
                .column_name(idx)
                .map_or_else(|_| format!("col_{idx}"), ToString::to_string);
            columns.push(name);
        }
    }

    let mut out_rows = Vec::new();
    let mut truncated = false;

    while let Some(row) = raw_rows.next()? {
        if start.elapsed() > timeout {
            return Err(MuObserveError::SqlTimeout {
                timeout_ms: timeout.as_millis() as u64,
            });
        }
        if out_rows.len() >= effective_limit {
            truncated = true;
            break;
        }
        let mut json_row = Vec::with_capacity(col_count);
        for idx in 0..col_count {
            let val_ref = row.get_ref(idx)?;
            json_row.push(value_ref_to_json(val_ref));
        }
        out_rows.push(json_row);
    }

    let row_count = out_rows.len();
    Ok(SqlQueryResult {
        columns,
        rows: out_rows,
        row_count,
        truncated,
        elapsed_ms: start.elapsed().as_millis() as u64,
    })
}

fn value_ref_to_json(v: ValueRef<'_>) -> Value {
    match v {
        ValueRef::Null => Value::Null,
        ValueRef::Boolean(b) => Value::Bool(b),
        ValueRef::TinyInt(i) => json!(i),
        ValueRef::SmallInt(i) => json!(i),
        ValueRef::Int(i) => json!(i),
        ValueRef::BigInt(i) => json!(i),
        ValueRef::HugeInt(i) => json!(i.to_string()),
        ValueRef::UTinyInt(u) => json!(u),
        ValueRef::USmallInt(u) => json!(u),
        ValueRef::UInt(u) => json!(u),
        ValueRef::UBigInt(u) => json!(u),
        ValueRef::Float(f) => json!(f),
        ValueRef::Double(f) => json!(f),
        ValueRef::Text(bytes) => Value::String(String::from_utf8_lossy(bytes).into_owned()),
        ValueRef::Blob(bytes) => Value::String(hex::encode(bytes)),
        other => Value::String(format!("{other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sql_guard_rejects_ddl_dml_and_injection() {
        let forbidden_queries = [
            "DROP TABLE otel_logs",
            "DELETE FROM jobs_history WHERE 1=1",
            "INSERT INTO otel_logs VALUES (1, 'a', 'b', 1, 'INFO', 'svc', 'node-a', 'msg', '{}', NULL, NULL)",
            "UPDATE branch_snapshots SET repo_name = 'pwned'",
            "CREATE TABLE evil (id INT)",
            "ALTER TABLE otel_logs ADD COLUMN pwn VARCHAR",
            "COPY (SELECT * FROM otel_logs) TO '/tmp/leak.parquet'",
            "ATTACH '/etc/passwd' AS pw",
            "DETACH pw",
            "PRAGMA database_list",
            "INSTALL httpfs",
            "LOAD httpfs",
            "SELECT * FROM v_logs; DROP TABLE otel_logs",
            "SELECT * FROM v_logs -- inline comment",
            "SELECT /* block comment */ * FROM v_logs",
        ];

        for q in forbidden_queries {
            assert!(
                validate_readonly_sql(q).is_err(),
                "Expected SQL guard to reject query: {q}"
            );
        }

        assert!(validate_readonly_sql("SELECT count(*) FROM v_logs;").is_ok());
        assert!(validate_readonly_sql("WITH cte AS (SELECT 1 AS x) SELECT * FROM cte").is_ok());
        assert!(validate_readonly_sql("EXPLAIN SELECT * FROM v_benchmarks").is_ok());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_execute_guarded_sql_row_limit() {
        let store = HotDuckDbStore::open_in_memory().expect("open in memory");
        let res = execute_guarded_sql(
            &store,
            "SELECT range AS n FROM range(2500)",
            DEFAULT_SQL_MAX_ROWS,
            Duration::from_secs(5),
        )
        .expect("execute guarded sql");

        assert_eq!(res.row_count, 1000);
        assert!(res.truncated);
    }
}
