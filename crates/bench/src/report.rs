//! Runs a scenario over a concurrency sweep and prints the result as a table
//! or as JSON.

use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use serde::Serialize;

use crate::load::{self, Connector, LoadResult, LoadSpec};
use crate::procstat::{Monitor, Usage};

/// One concurrency level of a sweep.
#[derive(Debug, Clone, Serialize)]
pub struct Run {
    pub concurrency: usize,
    #[serde(flatten)]
    pub result: LoadResult,
    /// CPU and memory of the target process during this level; `None` when
    /// no process is observed.
    pub target: Option<Usage>,
}

/// The whole report of one invocation.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    /// `gateway` or `session`.
    pub scenario: String,
    /// `tunnel`, `forward`, `passthrough` or `mitm`.
    pub mode: String,
    pub keepalive: bool,
    pub payload_bytes: usize,
    /// How the target ran: `spawned`, `attached` or `in_process_stub`.
    pub target_kind: String,
    pub warmup_secs: f64,
    pub runs: Vec<Run>,
}

impl Report {
    /// Total failed requests over every level.
    pub fn total_errors(&self) -> u64 {
        self.runs.iter().map(|r| r.result.errors).sum()
    }

    /// Total completed requests over every level.
    pub fn total_requests(&self) -> u64 {
        self.runs.iter().map(|r| r.result.requests).sum()
    }

    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// A fixed-width table, one row per concurrency level, then the error
    /// classes of any level that had errors.
    pub fn to_table(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "{} {}  keepalive={}  payload={} B  target={}",
            self.scenario, self.mode, self.keepalive, self.payload_bytes, self.target_kind
        );
        let _ = writeln!(
            out,
            "{:>5} {:>9} {:>7} {:>10} {:>8} {:>9} {:>9} {:>9} {:>9} {:>8} {:>9}",
            "conc",
            "requests",
            "errors",
            "req/s",
            "MB/s",
            "p50 ms",
            "p95 ms",
            "p99 ms",
            "max ms",
            "cpu s",
            "rss MiB"
        );
        for run in &self.runs {
            let r = &run.result;
            let (cpu, rss) = match &run.target {
                Some(u) => (
                    format!("{:.2}", u.cpu_seconds),
                    format!("{:.1}", u.peak_rss_kb as f64 / 1024.0),
                ),
                None => ("-".to_owned(), "-".to_owned()),
            };
            let ms = |us: u64| format!("{:.2}", us as f64 / 1000.0);
            let _ = writeln!(
                out,
                "{:>5} {:>9} {:>7} {:>10.1} {:>8.2} {:>9} {:>9} {:>9} {:>9} {:>8} {:>9}",
                run.concurrency,
                r.requests,
                r.errors,
                r.requests_per_sec,
                r.megabytes_per_sec,
                ms(r.latency.p50_us),
                ms(r.latency.p95_us),
                ms(r.latency.p99_us),
                ms(r.latency.max_us),
                cpu,
                rss
            );
        }
        for run in &self.runs {
            for (class, n) in &run.result.error_classes {
                let example = run
                    .result
                    .error_examples
                    .get(class)
                    .map_or("", String::as_str);
                let _ = writeln!(
                    out,
                    "  concurrency {}: {n} x {class} ({example})",
                    run.concurrency
                );
            }
        }
        out
    }
}

/// What to run and how.
pub struct Sweep {
    pub levels: Vec<usize>,
    pub duration: Option<Duration>,
    pub requests: Option<u64>,
    pub keepalive: bool,
    pub timeout: Duration,
    pub warmup: Duration,
    /// The process whose CPU and memory are sampled.
    pub pid: Option<u32>,
}

impl Sweep {
    fn spec(&self, concurrency: usize) -> LoadSpec {
        LoadSpec {
            concurrency,
            duration: self.duration,
            requests: self.requests,
            keepalive: self.keepalive,
            timeout: self.timeout,
        }
    }
}

/// Run `connector` at every level of `sweep`, after an optional warmup at the
/// first level. The warmup result is dropped.
pub async fn run_sweep<C: Connector>(connector: Arc<C>, sweep: &Sweep) -> Result<Vec<Run>> {
    if !sweep.warmup.is_zero()
        && let Some(&first) = sweep.levels.first()
    {
        let spec = LoadSpec {
            duration: Some(sweep.warmup),
            requests: None,
            ..sweep.spec(first)
        };
        load::run(Arc::clone(&connector), spec).await?;
    }
    let mut runs = Vec::with_capacity(sweep.levels.len());
    for &concurrency in &sweep.levels {
        let monitor = sweep.pid.map(Monitor::start).transpose()?;
        let result = load::run(Arc::clone(&connector), sweep.spec(concurrency)).await?;
        let target = match monitor {
            Some(m) => Some(m.finish().await?),
            None => None,
        };
        runs.push(Run {
            concurrency,
            result,
            target,
        });
    }
    Ok(runs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::load::LoadError;
    use crate::stats::LatencySummary;
    use std::collections::BTreeMap;

    fn result(requests: u64, errors: u64) -> LoadResult {
        let mut classes = BTreeMap::new();
        let mut examples = BTreeMap::new();
        if errors > 0 {
            classes.insert("connect_refused".to_owned(), errors);
            examples.insert("connect_refused".to_owned(), "nobody".to_owned());
        }
        LoadResult {
            requests,
            errors,
            error_classes: classes,
            bytes: requests * 2048,
            elapsed_secs: 2.0,
            requests_per_sec: requests as f64 / 2.0,
            megabytes_per_sec: requests as f64 * 2048.0 / 2.0 / 1e6,
            latency: LatencySummary {
                count: requests,
                min_us: 100,
                mean_us: 1500.0,
                p50_us: 1200,
                p95_us: 3400,
                p99_us: 9900,
                max_us: 20_000,
            },
            connect_latency: LatencySummary::default(),
            error_examples: examples,
        }
    }

    fn report(errors: u64) -> Report {
        Report {
            scenario: "session".into(),
            mode: "passthrough".into(),
            keepalive: true,
            payload_bytes: 1024,
            target_kind: "spawned".into(),
            warmup_secs: 0.0,
            runs: vec![
                Run {
                    concurrency: 4,
                    result: result(1000, errors),
                    target: None,
                },
                Run {
                    concurrency: 16,
                    result: result(3000, 0),
                    target: Some(Usage {
                        pid: 9,
                        cpu_seconds: 1.5,
                        cpu_user_seconds: 1.0,
                        cpu_system_seconds: 0.5,
                        cpu_percent_of_one_core: 75.0,
                        rss_kb: 20_480,
                        peak_rss_kb: 30_720,
                    }),
                },
            ],
        }
    }

    #[test]
    fn totals_add_over_levels() {
        let r = report(3);
        assert_eq!(r.total_requests(), 4000);
        assert_eq!(r.total_errors(), 3);
    }

    #[test]
    fn the_table_has_a_row_per_level_and_names_error_classes() {
        let t = report(3).to_table();
        let rows: Vec<&str> = t.lines().collect();
        assert!(rows[0].starts_with("session passthrough"));
        assert!(rows[1].contains("req/s") && rows[1].contains("p99 ms"));
        assert!(rows[2].trim_start().starts_with('4'));
        assert!(rows[3].trim_start().starts_with("16"));
        assert!(rows[3].contains("30.0"), "peak RSS in MiB: {}", rows[3]);
        assert!(t.contains("3 x connect_refused (nobody)"), "{t}");
        assert!(rows[2].contains("9.90"), "p99 in ms: {}", rows[2]);
    }

    #[test]
    fn the_json_carries_the_flattened_result_and_the_target_usage() {
        let json = report(0).to_json().expect("json");
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(v["scenario"], "session");
        let run = &v["runs"][1];
        assert_eq!(run["concurrency"], 16);
        assert_eq!(run["requests"], 3000);
        assert_eq!(run["latency"]["p99_us"], 9900);
        assert_eq!(run["target"]["peak_rss_kb"], 30_720);
        assert!(v["runs"][0]["target"].is_null());
    }

    struct Instant0;

    impl Connector for Instant0 {
        type Conn = ();
        async fn connect(&self) -> Result<(), LoadError> {
            Ok(())
        }
        async fn exchange(&self, _: &mut (), _: bool) -> Result<u64, LoadError> {
            tokio::task::yield_now().await;
            Ok(10)
        }
    }

    #[tokio::test]
    async fn a_sweep_runs_every_level_and_samples_the_target() {
        let sweep = Sweep {
            levels: vec![1, 3],
            duration: None,
            requests: Some(50),
            keepalive: true,
            timeout: Duration::from_secs(5),
            warmup: Duration::from_millis(20),
            pid: Some(std::process::id()),
        };
        let runs = run_sweep(Arc::new(Instant0), &sweep).await.expect("sweep");
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].concurrency, 1);
        assert_eq!(runs[1].result.requests, 50);
        assert!(runs.iter().all(|r| r.target.is_some()));
    }
}
