//! The load driver: N concurrent workers, each running requests against a
//! [`Connector`] until a deadline or a request budget is spent.

use std::collections::BTreeMap;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use serde::Serialize;

use crate::stats::{Latencies, LatencySummary};

/// Most workers one run accepts. Each holds a socket (two for a tunnel), so
/// this keeps a run inside a default descriptor limit with room to spare.
pub const MAX_CONCURRENCY: usize = 20_000;
/// Largest `--payload-bytes`.
pub const MAX_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;

/// Why a request failed, as a short stable class name for the report.
#[derive(Debug, Clone)]
pub struct LoadError {
    pub class: String,
    pub detail: String,
}

impl LoadError {
    pub fn new(class: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            class: class.into(),
            detail: detail.into(),
        }
    }

    /// Classify an I/O error from `stage` (`connect`, `read`, `write`, ...).
    pub fn io(stage: &str, e: &io::Error) -> Self {
        let kind = match e.kind() {
            io::ErrorKind::ConnectionRefused => "refused",
            io::ErrorKind::ConnectionReset => "reset",
            io::ErrorKind::ConnectionAborted => "aborted",
            io::ErrorKind::BrokenPipe => "broken_pipe",
            io::ErrorKind::UnexpectedEof => "eof",
            io::ErrorKind::TimedOut => "timed_out",
            io::ErrorKind::AddrInUse | io::ErrorKind::AddrNotAvailable => "no_address",
            _ => "other",
        };
        Self::new(format!("{stage}_{kind}"), e.to_string())
    }

    pub fn timeout(stage: &str) -> Self {
        Self::new("timeout", format!("{stage} timed out"))
    }

    pub fn protocol(detail: impl Into<String>) -> Self {
        Self::new("protocol", detail)
    }
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.class, self.detail)
    }
}

/// What a scenario provides: how to open a connection and how to run one
/// request on it. A request is complete when the full response is read.
pub trait Connector: Send + Sync + 'static {
    type Conn: Send + 'static;

    /// Open a connection that is ready for [`Connector::exchange`]: for a
    /// proxy this includes the `CONNECT` and, in MITM mode, the TLS handshake.
    fn connect(&self) -> impl Future<Output = Result<Self::Conn, LoadError>> + Send;

    /// Run one request and read its response. Returns the application bytes
    /// moved (request body plus response body).
    fn exchange(
        &self,
        conn: &mut Self::Conn,
        close: bool,
    ) -> impl Future<Output = Result<u64, LoadError>> + Send;
}

/// How long and how hard to push.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct LoadSpec {
    pub concurrency: usize,
    /// Stop after this long (measured from the first request).
    pub duration: Option<Duration>,
    /// Stop after this many requests (failed ones count).
    pub requests: Option<u64>,
    /// Reuse each connection for many requests when true; one connection per
    /// request when false.
    pub keepalive: bool,
    /// Per-operation limit (connect, or one request).
    pub timeout: Duration,
}

impl LoadSpec {
    pub fn validate(&self) -> Result<()> {
        if self.concurrency == 0 || self.concurrency > MAX_CONCURRENCY {
            bail!("--concurrency must be between 1 and {MAX_CONCURRENCY}");
        }
        if self.duration.is_none() && self.requests.is_none() {
            bail!("give --duration or --requests");
        }
        if self.duration.is_some_and(|d| d.is_zero()) {
            bail!("--duration must be above zero");
        }
        if self.requests == Some(0) {
            bail!("--requests must be above zero");
        }
        if self.timeout.is_zero() {
            bail!("--timeout must be above zero");
        }
        Ok(())
    }
}

/// What one run measured.
#[derive(Debug, Clone, Serialize)]
pub struct LoadResult {
    /// Requests that completed with a full response.
    pub requests: u64,
    /// Requests that failed, over all classes.
    pub errors: u64,
    pub error_classes: BTreeMap<String, u64>,
    /// Application bytes moved by the successful requests.
    pub bytes: u64,
    pub elapsed_secs: f64,
    pub requests_per_sec: f64,
    /// Megabytes (10^6 bytes) of application payload per second.
    pub megabytes_per_sec: f64,
    /// Latency of a request. With one connection per request it includes the
    /// connection setup.
    pub latency: LatencySummary,
    /// Time to open a connection (for a proxy: through the `200`, and the TLS
    /// handshake in MITM mode).
    pub connect_latency: LatencySummary,
    /// One example detail per error class.
    pub error_examples: BTreeMap<String, String>,
}

impl LoadResult {
    pub fn error_rate(&self) -> f64 {
        let total = self.requests + self.errors;
        if total == 0 {
            0.0
        } else {
            self.errors as f64 / total as f64
        }
    }
}

#[derive(Default)]
struct Worker {
    ok: u64,
    bytes: u64,
    latency: Latencies,
    connect: Latencies,
    errors: BTreeMap<String, u64>,
    examples: BTreeMap<String, String>,
}

impl Worker {
    fn fail(&mut self, e: LoadError) {
        *self.errors.entry(e.class.clone()).or_default() += 1;
        self.examples.entry(e.class).or_insert(e.detail);
    }
}

/// Run the load. Returns when the deadline passed or the budget is spent and
/// every worker has finished its last operation.
pub async fn run<C: Connector>(connector: Arc<C>, spec: LoadSpec) -> Result<LoadResult> {
    spec.validate()?;
    let budget = spec.requests.map(|n| Arc::new(AtomicU64::new(n)));
    let started = Instant::now();
    let deadline = spec.duration.map(|d| started + d);

    let mut tasks = Vec::with_capacity(spec.concurrency);
    for _ in 0..spec.concurrency {
        tasks.push(tokio::spawn(worker(
            Arc::clone(&connector),
            spec,
            budget.clone(),
            deadline,
        )));
    }
    let mut total = Worker::default();
    for task in tasks {
        let w = task.await?;
        total.ok += w.ok;
        total.bytes += w.bytes;
        total.latency.merge(&w.latency);
        total.connect.merge(&w.connect);
        for (class, n) in w.errors {
            *total.errors.entry(class).or_default() += n;
        }
        for (class, detail) in w.examples {
            total.examples.entry(class).or_insert(detail);
        }
    }
    let elapsed = started.elapsed();
    let secs = elapsed.as_secs_f64().max(f64::EPSILON);
    let errors: u64 = total.errors.values().sum();
    Ok(LoadResult {
        requests: total.ok,
        errors,
        error_classes: total.errors,
        bytes: total.bytes,
        elapsed_secs: elapsed.as_secs_f64(),
        requests_per_sec: total.ok as f64 / secs,
        megabytes_per_sec: total.bytes as f64 / 1e6 / secs,
        latency: total.latency.summary(),
        connect_latency: total.connect.summary(),
        error_examples: total.examples,
    })
}

/// Claim one request from the budget. `true` when the worker may go on.
fn claim(budget: &Option<Arc<AtomicU64>>) -> bool {
    match budget {
        None => true,
        Some(left) => left
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
            .is_ok(),
    }
}

async fn worker<C: Connector>(
    connector: Arc<C>,
    spec: LoadSpec,
    budget: Option<Arc<AtomicU64>>,
    deadline: Option<Instant>,
) -> Worker {
    let mut w = Worker::default();
    let mut conn: Option<C::Conn> = None;
    loop {
        if deadline.is_some_and(|d| Instant::now() >= d) || !claim(&budget) {
            break;
        }
        let began = Instant::now();
        let mut c = match conn.take() {
            Some(c) => c,
            None => match tokio::time::timeout(spec.timeout, connector.connect()).await {
                Ok(Ok(c)) => {
                    w.connect.record(began.elapsed());
                    c
                }
                Ok(Err(e)) => {
                    w.fail(e);
                    continue;
                }
                Err(_) => {
                    w.fail(LoadError::timeout("connect"));
                    continue;
                }
            },
        };
        let close = !spec.keepalive;
        match tokio::time::timeout(spec.timeout, connector.exchange(&mut c, close)).await {
            Ok(Ok(bytes)) => {
                w.ok += 1;
                w.bytes += bytes;
                w.latency.record(began.elapsed());
                if spec.keepalive {
                    conn = Some(c);
                }
            }
            Ok(Err(e)) => w.fail(e),
            Err(_) => w.fail(LoadError::timeout("request")),
        }
    }
    w
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    /// A connector that never touches the network: every connect and request
    /// takes `delay`, and request number `fail_every` (1-based) fails.
    struct Fake {
        delay: Duration,
        fail_every: u64,
        connects: AtomicUsize,
        calls: AtomicU64,
        connect_fails: bool,
    }

    impl Fake {
        fn new(delay: Duration, fail_every: u64) -> Self {
            Self {
                delay,
                fail_every,
                connects: AtomicUsize::new(0),
                calls: AtomicU64::new(0),
                connect_fails: false,
            }
        }
    }

    impl Connector for Fake {
        type Conn = ();

        async fn connect(&self) -> Result<(), LoadError> {
            self.connects.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(self.delay).await;
            if self.connect_fails {
                return Err(LoadError::new("connect_refused", "nobody home"));
            }
            Ok(())
        }

        async fn exchange(&self, _: &mut (), _close: bool) -> Result<u64, LoadError> {
            tokio::time::sleep(self.delay).await;
            let n = self.calls.fetch_add(1, Ordering::Relaxed) + 1;
            if self.fail_every != 0 && n.is_multiple_of(self.fail_every) {
                return Err(LoadError::new("proxy_status_502", "bad gateway"));
            }
            Ok(100)
        }
    }

    fn spec(concurrency: usize, requests: u64, keepalive: bool) -> LoadSpec {
        LoadSpec {
            concurrency,
            duration: None,
            requests: Some(requests),
            keepalive,
            timeout: Duration::from_secs(5),
        }
    }

    #[tokio::test]
    async fn a_request_budget_is_spent_exactly() {
        let fake = Arc::new(Fake::new(Duration::from_millis(1), 0));
        let r = run(fake.clone(), spec(8, 200, true)).await.expect("run");
        assert_eq!(r.requests, 200);
        assert_eq!(r.errors, 0);
        assert_eq!(r.bytes, 200 * 100);
        assert_eq!(r.latency.count, 200);
        assert!(r.requests_per_sec > 0.0 && r.megabytes_per_sec > 0.0);
        assert_eq!(r.error_rate(), 0.0);
    }

    #[tokio::test]
    async fn keepalive_connects_once_per_worker() {
        let fake = Arc::new(Fake::new(Duration::from_millis(1), 0));
        let r = run(fake.clone(), spec(4, 100, true)).await.expect("run");
        assert_eq!(r.requests, 100);
        assert_eq!(fake.connects.load(Ordering::Relaxed), 4);
        assert_eq!(r.connect_latency.count, 4);
    }

    #[tokio::test]
    async fn without_keepalive_every_request_connects() {
        let fake = Arc::new(Fake::new(Duration::from_millis(1), 0));
        let r = run(fake.clone(), spec(4, 100, false)).await.expect("run");
        assert_eq!(r.requests, 100);
        assert_eq!(fake.connects.load(Ordering::Relaxed), 100);
        // the request latency includes the connect: two sleeps of 1 ms
        assert!(r.latency.p50_us >= 2_000, "p50 {}", r.latency.p50_us);
    }

    #[tokio::test]
    async fn errors_are_counted_by_class_and_do_not_stop_the_run() {
        let fake = Arc::new(Fake::new(Duration::from_millis(1), 10));
        let r = run(fake, spec(2, 100, true)).await.expect("run");
        assert_eq!(r.requests + r.errors, 100);
        assert_eq!(r.errors, 10);
        assert_eq!(r.error_classes.get("proxy_status_502"), Some(&10));
        assert_eq!(
            r.error_examples.get("proxy_status_502").map(String::as_str),
            Some("bad gateway")
        );
        assert!((r.error_rate() - 0.1).abs() < 1e-9);
    }

    #[tokio::test]
    async fn connect_failures_count_against_the_budget() {
        let mut fake = Fake::new(Duration::from_millis(1), 0);
        fake.connect_fails = true;
        let r = run(Arc::new(fake), spec(3, 30, true)).await.expect("run");
        assert_eq!(r.requests, 0);
        assert_eq!(r.error_classes.get("connect_refused"), Some(&30));
        assert_eq!(r.error_rate(), 1.0);
    }

    #[tokio::test]
    async fn a_duration_stops_the_run() {
        let fake = Arc::new(Fake::new(Duration::from_millis(2), 0));
        let s = LoadSpec {
            concurrency: 2,
            duration: Some(Duration::from_millis(200)),
            requests: None,
            keepalive: true,
            timeout: Duration::from_secs(5),
        };
        let r = run(fake, s).await.expect("run");
        assert!(r.requests > 10, "requests {}", r.requests);
        assert!(
            r.elapsed_secs >= 0.2 && r.elapsed_secs < 2.0,
            "{}",
            r.elapsed_secs
        );
    }

    #[tokio::test]
    async fn a_slow_request_is_a_timeout_error() {
        let fake = Arc::new(Fake::new(Duration::from_millis(200), 0));
        let s = LoadSpec {
            timeout: Duration::from_millis(20),
            ..spec(1, 3, true)
        };
        let r = run(fake, s).await.expect("run");
        assert_eq!(r.requests, 0);
        assert_eq!(r.error_classes.get("timeout"), Some(&3));
    }

    #[test]
    fn the_spec_is_validated() {
        let ok = spec(1, 1, true);
        assert!(ok.validate().is_ok());
        assert!(
            LoadSpec {
                concurrency: 0,
                ..ok
            }
            .validate()
            .is_err()
        );
        assert!(
            LoadSpec {
                concurrency: MAX_CONCURRENCY + 1,
                ..ok
            }
            .validate()
            .is_err()
        );
        assert!(
            LoadSpec {
                requests: None,
                ..ok
            }
            .validate()
            .is_err()
        );
        assert!(
            LoadSpec {
                requests: Some(0),
                ..ok
            }
            .validate()
            .is_err()
        );
        assert!(
            LoadSpec {
                duration: Some(Duration::ZERO),
                ..ok
            }
            .validate()
            .is_err()
        );
        assert!(
            LoadSpec {
                timeout: Duration::ZERO,
                ..ok
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn io_errors_get_stable_class_names() {
        let e = io::Error::from(io::ErrorKind::ConnectionRefused);
        assert_eq!(LoadError::io("connect", &e).class, "connect_refused");
        let e = io::Error::from(io::ErrorKind::ConnectionReset);
        assert_eq!(LoadError::io("read", &e).class, "read_reset");
        let e = io::Error::from(io::ErrorKind::UnexpectedEof);
        assert_eq!(LoadError::io("read", &e).class, "read_eof");
        let e = io::Error::other("x");
        assert_eq!(LoadError::io("write", &e).class, "write_other");
    }
}
