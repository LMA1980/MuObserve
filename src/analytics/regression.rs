use std::collections::BTreeMap;

use duckdb::params;
use muobserve_ipc::{
    BenchmarkRegressionItem, RegressionGateReport, RegressionGateRequest, RegressionVerdict,
    TestRegressionItem,
};

use crate::error::MuObserveError;
use crate::storage::hot_duckdb::HotDuckDbStore;

/// Type alias providing compatibility with both `FlakyTestItem` and `TestRegressionItem` naming.
pub type FlakyTestItem = TestRegressionItem;

/// Default maximum rolling baseline sample window on `main`.
pub const DEFAULT_BASELINE_WINDOW: usize = 20;

/// Default modified MAD $z$-score threshold for flagging a statistically significant benchmark slowdown.
pub const DEFAULT_MAX_MAD_Z_SCORE: f64 = 3.5;

/// Evaluates candidate benchmark runs for `candidate_commit` in `repo_key` against the last
/// `N <= 20` baseline runs on `baseline_branch` (typically `"main"`), strictly stratified by
/// `(repo_key, crate_name, bench_name, arch, cpu_cluster, vlen_bits)` so SpacemiT K3 Cluster 0
/// (`X100`, `VLEN=256`) and Cluster 1 (`A100`, `VLEN=1024`) never cross-contaminate.
pub fn evaluate_benchmark_regressions(
    store: &HotDuckDbStore,
    repo_key: &str,
    candidate_commit: &str,
    baseline_branch: &str,
    max_slowdown_pct: f64,
    max_mad_z_score: f64,
) -> Result<Vec<BenchmarkRegressionItem>, MuObserveError> {
    let conn = store.lock_conn()?;

    let mut cand_stmt = conn.prepare(
        r#"
        SELECT
            crate_name, bench_name, arch, cpu_cluster, vlen_bits, ns_per_iter
        FROM v_benchmarks
        WHERE repo_key = ?1
          AND (commit_sha = ?2 OR branch_key = ?2)
        ORDER BY timestamp_unix_nano DESC
        "#,
    )?;

    #[derive(Clone)]
    struct CandidateRow {
        crate_name: String,
        bench_name: String,
        arch: String,
        cpu_cluster: String,
        vlen_bits: u32,
        ns_per_iter: f64,
    }

    let rows = cand_stmt.query_map(params![repo_key, candidate_commit], |r| {
        let vlen_i32: i32 = r.get(4)?;
        Ok(CandidateRow {
            crate_name: r.get(0)?,
            bench_name: r.get(1)?,
            arch: r.get(2)?,
            cpu_cluster: r.get(3)?,
            vlen_bits: vlen_i32.max(0) as u32,
            ns_per_iter: r.get(5)?,
        })
    })?;

    // Deduplicate latest candidate per (crate_name, bench_name, arch, cpu_cluster, vlen_bits)
    let mut latest_candidates: BTreeMap<(String, String, String, String, u32), CandidateRow> =
        BTreeMap::new();
    for r in rows {
        let row = r?;
        let key = (
            row.crate_name.clone(),
            row.bench_name.clone(),
            row.arch.clone(),
            row.cpu_cluster.clone(),
            row.vlen_bits,
        );
        latest_candidates.entry(key).or_insert(row);
    }
    drop(cand_stmt);

    let mut base_stmt = conn.prepare(
        r#"
        SELECT ns_per_iter, mad_ns
        FROM v_benchmarks
        WHERE repo_key = ?1
          AND branch_key = ?2
          AND commit_sha != ?3
          AND crate_name = ?4
          AND bench_name = ?5
          AND arch = ?6
          AND cpu_cluster = ?7
          AND vlen_bits = ?8
        ORDER BY timestamp_unix_nano DESC
        LIMIT ?9
        "#,
    )?;

    let mut items = Vec::new();
    for cand in latest_candidates.into_values() {
        let base_rows = base_stmt.query_map(
            params![
                repo_key,
                baseline_branch,
                candidate_commit,
                cand.crate_name,
                cand.bench_name,
                cand.arch,
                cand.cpu_cluster,
                cand.vlen_bits as i32,
                DEFAULT_BASELINE_WINDOW as i64
            ],
            |r| Ok((r.get::<_, f64>(0)?, r.get::<_, f64>(1)?)),
        )?;

        let mut samples = Vec::new();
        let mut recorded_mads = Vec::new();
        for br in base_rows {
            let (ns, mad) = br?;
            samples.push(ns);
            if mad > 0.0 {
                recorded_mads.push(mad);
            }
        }

        if samples.is_empty() {
            continue;
        }

        let baseline_median_ns = compute_median(&mut samples);
        let sample_mad = compute_mad(&samples, baseline_median_ns);
        let effective_mad = if sample_mad > 1e-9 {
            sample_mad
        } else if !recorded_mads.is_empty() {
            compute_median(&mut recorded_mads)
        } else {
            // Fallback floor of 0.5% of baseline median to avoid division by zero on constant series
            (baseline_median_ns.abs() * 0.005).max(1e-6)
        };

        let delta_pct = if baseline_median_ns.abs() > 1e-9 {
            ((cand.ns_per_iter - baseline_median_ns) / baseline_median_ns) * 100.0
        } else {
            0.0
        };

        let mad_z_score = 0.6745 * (cand.ns_per_iter - baseline_median_ns) / effective_mad;
        let regressed = delta_pct > max_slowdown_pct && mad_z_score > max_mad_z_score;

        items.push(BenchmarkRegressionItem {
            crate_name: cand.crate_name,
            bench_name: cand.bench_name,
            arch: cand.arch,
            cpu_cluster: cand.cpu_cluster,
            vlen_bits: cand.vlen_bits,
            baseline_median_ns,
            candidate_ns: cand.ns_per_iter,
            delta_pct,
            mad_z_score,
            regressed,
        });
    }

    Ok(items)
}

/// Computes rolling 30-day test flakiness (pass/fail flip-flops across commits) and identifies
/// failed or flaky tests for `repo_key`.
pub fn compute_test_flakiness(
    store: &HotDuckDbStore,
    repo_key: &str,
    candidate_commit: Option<&str>,
    window_days: u32,
    now_unix_nano: Option<i64>,
) -> Result<Vec<TestRegressionItem>, MuObserveError> {
    let conn = store.lock_conn()?;

    let max_ts: i64 = match now_unix_nano {
        Some(ts) => ts,
        None => conn
            .query_row(
                "SELECT COALESCE(MAX(timestamp_unix_nano), 0) FROM v_tests WHERE repo_key = ?1",
                params![repo_key],
                |r| r.get(0),
            )
            .unwrap_or(0),
    };

    let window_ns = i64::from(window_days.max(1))
        .saturating_mul(86_400)
        .saturating_mul(1_000_000_000);
    let cutoff_ts = max_ts.saturating_sub(window_ns);

    let mut stmt = conn.prepare(
        r#"
        SELECT
            crate_name, test_binary, test_name, status, failure_summary, commit_sha, timestamp_unix_nano
        FROM v_tests
        WHERE repo_key = ?1
          AND timestamp_unix_nano >= ?2
        ORDER BY timestamp_unix_nano ASC
        "#,
    )?;

    #[derive(Clone)]
    struct TestRunObs {
        crate_name: String,
        test_binary: String,
        test_name: String,
        status: String,
        failure_summary: Option<String>,
        commit_sha: String,
    }

    let rows = stmt.query_map(params![repo_key, cutoff_ts], |r| {
        Ok(TestRunObs {
            crate_name: r.get(0)?,
            test_binary: r.get(1)?,
            test_name: r.get(2)?,
            status: r.get(3)?,
            failure_summary: r.get(4)?,
            commit_sha: r.get(5)?,
        })
    })?;

    let mut grouped: BTreeMap<(String, String), Vec<TestRunObs>> = BTreeMap::new();
    for r in rows {
        let obs = r?;
        grouped
            .entry((obs.crate_name.clone(), obs.test_name.clone()))
            .or_default()
            .push(obs);
    }

    let mut results = Vec::new();
    for ((crate_name, test_name), history) in grouped {
        if history.is_empty() {
            continue;
        }
        let mut flip_flops = 0u32;
        let mut prev_passed: Option<bool> = None;
        let mut latest_for_candidate: Option<&TestRunObs> = None;
        let mut latest_failure_summary: Option<String> = None;

        for item in &history {
            let passed = is_pass_status(&item.status);
            if !passed && item.failure_summary.is_some() {
                latest_failure_summary.clone_from(&item.failure_summary);
            }
            if let Some(prev) = prev_passed {
                if prev != passed {
                    flip_flops = flip_flops.saturating_add(1);
                }
            }
            prev_passed = Some(passed);
            if let Some(cand) = candidate_commit {
                if item.commit_sha == cand {
                    latest_for_candidate = Some(item);
                }
            }
        }

        let transitions = history.len().saturating_sub(1);
        let flakiness_pct = if transitions > 0 {
            (f64::from(flip_flops) / (transitions as f64)) * 100.0
        } else {
            0.0
        };

        let representative = latest_for_candidate.unwrap_or_else(|| history.last().unwrap());
        results.push(TestRegressionItem {
            crate_name,
            test_binary: representative.test_binary.clone(),
            test_name,
            status: representative.status.clone(),
            flakiness_pct,
            flip_flop_count: flip_flops,
            failure_summary: representative
                .failure_summary
                .clone()
                .or(latest_failure_summary),
        });
    }

    Ok(results)
}

/// Evaluates a full [`RegressionGateRequest`] combining hardware-stratified benchmark regressions
/// and rolling 30-day test failures/flakiness into a [`RegressionGateReport`].
pub fn evaluate_regression_gate(
    store: &HotDuckDbStore,
    req: &RegressionGateRequest,
) -> Result<RegressionGateReport, MuObserveError> {
    let max_slowdown = if req.max_slowdown_pct <= 0.0 {
        5.0
    } else {
        req.max_slowdown_pct
    };
    let max_flakiness = if req.max_flakiness_pct <= 0.0 {
        2.0
    } else {
        req.max_flakiness_pct
    };

    let all_benches = evaluate_benchmark_regressions(
        store,
        &req.repo_key,
        &req.candidate_commit,
        &req.baseline_branch,
        max_slowdown,
        DEFAULT_MAX_MAD_Z_SCORE,
    )?;

    let regressed_benchmarks: Vec<BenchmarkRegressionItem> =
        all_benches.into_iter().filter(|b| b.regressed).collect();

    let all_tests =
        compute_test_flakiness(store, &req.repo_key, Some(&req.candidate_commit), 30, None)?;

    let mut hard_test_failure = false;
    let mut flaky_warning = false;
    let mut flaky_or_failed_tests = Vec::new();

    for t in all_tests {
        let failed = !is_pass_status(&t.status);
        let flaky = t.flakiness_pct > max_flakiness || t.flip_flop_count > 0;
        if failed {
            hard_test_failure = true;
            flaky_or_failed_tests.push(t);
        } else if flaky {
            flaky_warning = true;
            flaky_or_failed_tests.push(t);
        }
    }

    let verdict = if !regressed_benchmarks.is_empty() || hard_test_failure {
        RegressionVerdict::Fail
    } else if flaky_warning {
        RegressionVerdict::Warn
    } else {
        RegressionVerdict::Pass
    };

    let summary = format!(
        "verdict={verdict:?}: {} regressed benchmarks, {} flaky/failed tests (candidate={}, baseline={})",
        regressed_benchmarks.len(),
        flaky_or_failed_tests.len(),
        req.candidate_commit,
        req.baseline_branch
    );

    Ok(RegressionGateReport {
        request_id: req.request_id.clone(),
        repo_key: req.repo_key.clone(),
        candidate_commit: req.candidate_commit.clone(),
        baseline_branch: req.baseline_branch.clone(),
        verdict,
        regressed_benchmarks,
        flaky_or_failed_tests,
        summary,
    })
}

fn is_pass_status(status: &str) -> bool {
    matches!(
        status.trim().to_ascii_lowercase().as_str(),
        "ok" | "pass" | "passed" | "success"
    )
}

fn compute_median(values: &mut [f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mid = values.len() / 2;
    if values.len() % 2 == 1 {
        values[mid]
    } else {
        (values[mid - 1] + values[mid]) / 2.0
    }
}

fn compute_mad(values: &[f64], median: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut deviations: Vec<f64> = values.iter().map(|v| (v - median).abs()).collect();
    compute_median(&mut deviations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use muobserve_ipc::{BenchmarkRunEntry, TestCaseRunEntry};

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_hardware_stratified_x100_vs_a100_regression_isolation() {
        let store = HotDuckDbStore::open_in_memory().expect("open in memory");
        let base_ts = 1_700_000_000_000_000_000i64;

        let mut runs = Vec::new();
        // 6 baseline runs on main for BOTH A100 (VLEN=1024, ~40_000 ns) and X100 (VLEN=256, ~120_000 ns)
        for i in 0..6 {
            let a100_ns = 40_000.0 + (f64::from(i % 3) * 100.0);
            runs.push(BenchmarkRunEntry {
                job_id: format!("job-base-{i}"),
                repo_key: "lma1980/k3-kernels-rvv".into(),
                branch_key: "main".into(),
                commit_sha: format!("base-sha-{i}"),
                crate_name: "k3-kernels-rvv".into(),
                bench_name: "q8_0_matvec".into(),
                ns_per_iter: a100_ns,
                std_dev_ns: 120.0,
                mad_ns: 100.0,
                p50_ns: a100_ns,
                p95_ns: a100_ns + 200.0,
                p99_ns: a100_ns + 300.0,
                throughput_value: None,
                throughput_unit: None,
                arch: "riscv64gc".into(),
                cpu_cluster: "A100".into(),
                vlen_bits: 1024,
                timestamp_unix_nano: base_ts + i64::from(i) * 1_000_000_000,
                node_id: "worker-riscv64".into(),
            });

            let x100_ns = 120_000.0 + (f64::from(i % 3) * 200.0);
            runs.push(BenchmarkRunEntry {
                job_id: format!("job-base-{i}"),
                repo_key: "lma1980/k3-kernels-rvv".into(),
                branch_key: "main".into(),
                commit_sha: format!("base-sha-{i}"),
                crate_name: "k3-kernels-rvv".into(),
                bench_name: "q8_0_matvec".into(),
                ns_per_iter: x100_ns,
                std_dev_ns: 250.0,
                mad_ns: 200.0,
                p50_ns: x100_ns,
                p95_ns: x100_ns + 400.0,
                p99_ns: x100_ns + 600.0,
                throughput_value: None,
                throughput_unit: None,
                arch: "riscv64gc".into(),
                cpu_cluster: "X100".into(),
                vlen_bits: 256,
                timestamp_unix_nano: base_ts + i64::from(i) * 1_000_000_000,
                node_id: "worker-riscv64".into(),
            });
        }

        // Candidate commit: A100 regresses by +15% (46_000 ns), while X100 stays healthy (120_100 ns)
        runs.push(BenchmarkRunEntry {
            job_id: "job-cand".into(),
            repo_key: "lma1980/k3-kernels-rvv".into(),
            branch_key: "feat/tile-experiment".into(),
            commit_sha: "cand-sha-99".into(),
            crate_name: "k3-kernels-rvv".into(),
            bench_name: "q8_0_matvec".into(),
            ns_per_iter: 46_000.0,
            std_dev_ns: 150.0,
            mad_ns: 100.0,
            p50_ns: 46_000.0,
            p95_ns: 46_200.0,
            p99_ns: 46_400.0,
            throughput_value: None,
            throughput_unit: None,
            arch: "riscv64gc".into(),
            cpu_cluster: "A100".into(),
            vlen_bits: 1024,
            timestamp_unix_nano: base_ts + 100_000_000_000,
            node_id: "worker-riscv64".into(),
        });
        runs.push(BenchmarkRunEntry {
            job_id: "job-cand".into(),
            repo_key: "lma1980/k3-kernels-rvv".into(),
            branch_key: "feat/tile-experiment".into(),
            commit_sha: "cand-sha-99".into(),
            crate_name: "k3-kernels-rvv".into(),
            bench_name: "q8_0_matvec".into(),
            ns_per_iter: 120_100.0,
            std_dev_ns: 200.0,
            mad_ns: 200.0,
            p50_ns: 120_100.0,
            p95_ns: 120_400.0,
            p99_ns: 120_600.0,
            throughput_value: None,
            throughput_unit: None,
            arch: "riscv64gc".into(),
            cpu_cluster: "X100".into(),
            vlen_bits: 256,
            timestamp_unix_nano: base_ts + 100_000_000_000,
            node_id: "worker-riscv64".into(),
        });

        store
            .insert_benchmark_runs_batch(&runs)
            .expect("insert benches");

        let items = evaluate_benchmark_regressions(
            &store,
            "lma1980/k3-kernels-rvv",
            "cand-sha-99",
            "main",
            5.0,
            3.5,
        )
        .expect("evaluate regressions");

        assert_eq!(items.len(), 2);
        let a100 = items
            .iter()
            .find(|i| i.cpu_cluster == "A100" && i.vlen_bits == 1024)
            .expect("A100 item");
        assert!(a100.regressed);
        assert!(a100.delta_pct > 14.0);
        assert!(a100.mad_z_score > 3.5);

        let x100 = items
            .iter()
            .find(|i| i.cpu_cluster == "X100" && i.vlen_bits == 256)
            .expect("X100 item");
        assert!(!x100.regressed);
        assert!(x100.delta_pct.abs() < 1.0);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_rolling_30_day_test_flakiness_and_gate_report() {
        let store = HotDuckDbStore::open_in_memory().expect("open in memory");
        let base_ts = 1_700_000_000_000_000_000i64;

        let statuses = ["ok", "failed", "ok", "failed", "ok"];
        let mut entries = Vec::new();
        for (idx, status) in statuses.iter().enumerate() {
            entries.push(TestCaseRunEntry {
                job_id: format!("job-{idx}"),
                repo_key: "lma1980/k3-core".into(),
                branch_key: "main".into(),
                commit_sha: format!("sha-{idx}"),
                crate_name: "k3-core".into(),
                test_binary: "k3_core".into(),
                test_name: "test_flaky_scheduler".into(),
                status: (*status).into(),
                duration_ms: 4.0,
                failure_summary: if *status == "failed" {
                    Some("intermittent timeout".into())
                } else {
                    None
                },
                timestamp_unix_nano: base_ts + (idx as i64) * 1_000_000_000,
                node_id: "worker-riscv64".into(),
                arch: "riscv64gc".into(),
            });
        }
        store
            .insert_test_runs_batch(&entries)
            .expect("insert test runs");

        let flakiness = compute_test_flakiness(&store, "lma1980/k3-core", Some("sha-4"), 30, None)
            .expect("compute flakiness");
        assert_eq!(flakiness.len(), 1);
        assert_eq!(flakiness[0].flip_flop_count, 4);
        assert!((flakiness[0].flakiness_pct - 100.0).abs() < 1e-6);

        let report = evaluate_regression_gate(
            &store,
            &RegressionGateRequest {
                request_id: "gate-1".into(),
                repo_key: "lma1980/k3-core".into(),
                candidate_commit: "sha-4".into(),
                baseline_branch: "main".into(),
                max_slowdown_pct: 5.0,
                max_flakiness_pct: 10.0,
            },
        )
        .expect("gate report");
        assert_eq!(report.verdict, RegressionVerdict::Warn);
        assert_eq!(report.flaky_or_failed_tests.len(), 1);
    }
}
