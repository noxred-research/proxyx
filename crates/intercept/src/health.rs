//! Liveness and readiness.
//!
//! `/health/live` says the process runs and the admin API answers.
//! `/health/ready` (and its alias `/health`) says the proxy should receive
//! traffic. Readiness is the conjunction of:
//!
//! - `redis`: a periodic `PING` through the shared connection manager
//!   succeeds; `redis_failure_threshold` failures in a row fail the check and
//!   the first success clears it;
//! - `capture_pipeline`: the capture queue has not been full for longer than
//!   `capture_stall_window_ms`, the writer made progress within
//!   `capture_publish_stale_ms` while work was pending, and the writer is not
//!   dropping captures (it dropped one after its attempts and no batch has
//!   published cleanly since; a probe the broker answers clears this too);
//! - `listeners`: every accept loop is bound and still running;
//! - not draining: the shutdown signal has not arrived.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
use serde::Serialize;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::config::HealthConfig;
use crate::pipeline::RequestLogWriter;

/// Names of the checks, as in the `check` label and the JSON body.
pub const CHECK_REDIS: &str = "redis";
pub const CHECK_CAPTURE_PIPELINE: &str = "capture_pipeline";
pub const CHECK_LISTENERS: &str = "listeners";

/// Outcome of one check.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CheckReport {
    pub ok: bool,
    /// Why the check fails; absent while it passes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Body of `/health/ready`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReadinessReport {
    pub ready: bool,
    pub draining: bool,
    pub checks: BTreeMap<&'static str, CheckReport>,
}

#[derive(Default)]
struct CheckState {
    failing: Mutex<Option<String>>,
}

impl CheckState {
    fn set(&self, result: Result<(), String>) {
        *self.failing.lock() = result.err();
    }

    fn report(&self) -> CheckReport {
        let failing = self.failing.lock().clone();
        CheckReport {
            ok: failing.is_none(),
            detail: failing,
        }
    }
}

/// Shared readiness state: written by the monitor task, the accept loops and
/// the shutdown path, read by the admin API.
pub struct Readiness {
    draining: AtomicBool,
    redis: CheckState,
    pipeline: CheckState,
    listeners: Mutex<Vec<(&'static str, Arc<AtomicBool>)>>,
}

impl Default for Readiness {
    fn default() -> Self {
        Self::new()
    }
}

impl Readiness {
    pub fn new() -> Self {
        Self {
            draining: AtomicBool::new(false),
            redis: CheckState::default(),
            pipeline: CheckState::default(),
            listeners: Mutex::new(Vec::new()),
        }
    }

    /// Register an accept loop and get the flag it sets once bound (see
    /// `listener::common::UpGuard`). Until then the listener counts as down.
    pub fn register_listener(&self, name: &'static str) -> Arc<AtomicBool> {
        let up = Arc::new(AtomicBool::new(false));
        self.listeners.lock().push((name, up.clone()));
        up
    }

    /// Start reporting not ready. Called when the shutdown signal arrives,
    /// before anything is closed, so a balancer stops sending first.
    pub fn set_draining(&self) {
        self.draining.store(true, Ordering::Release);
        common::metrics::PROXY_DRAINING.set(1);
        self.publish();
    }

    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Acquire)
    }

    fn listeners_report(&self) -> CheckReport {
        let down: Vec<&str> = self
            .listeners
            .lock()
            .iter()
            .filter(|(_, up)| !up.load(Ordering::Acquire))
            .map(|(name, _)| *name)
            .collect();
        if down.is_empty() {
            CheckReport {
                ok: true,
                detail: None,
            }
        } else {
            CheckReport {
                ok: false,
                detail: Some(format!("not accepting: {}", down.join(", "))),
            }
        }
    }

    /// The current verdict. Also refreshes the readiness gauges, so a scrape
    /// and a probe never disagree.
    pub fn report(&self) -> ReadinessReport {
        let checks = BTreeMap::from([
            (CHECK_REDIS, self.redis.report()),
            (CHECK_CAPTURE_PIPELINE, self.pipeline.report()),
            (CHECK_LISTENERS, self.listeners_report()),
        ]);
        let draining = self.is_draining();
        let ready = !draining && checks.values().all(|c| c.ok);
        for (name, check) in &checks {
            common::metrics::PROXY_READINESS_CHECK
                .with_label_values(&[name])
                .set(i64::from(check.ok));
        }
        common::metrics::PROXY_READY.set(i64::from(ready));
        common::metrics::PROXY_DRAINING.set(i64::from(draining));
        ReadinessReport {
            ready,
            draining,
            checks,
        }
    }

    fn publish(&self) {
        let _ = self.report();
    }
}

/// Decides `capture_pipeline` from successive samples of the writer.
pub struct PipelineWatch {
    full_since: Option<Instant>,
}

impl PipelineWatch {
    pub fn new() -> Self {
        Self { full_since: None }
    }

    /// One sample. `since_progress` and `has_work` come from
    /// [`RequestLogWriter`].
    pub fn check(
        &mut self,
        now: Instant,
        queued: usize,
        capacity: usize,
        has_work: bool,
        since_progress: Duration,
        cfg: &HealthConfig,
    ) -> Result<(), String> {
        let full = capacity > 0 && queued as f64 >= capacity as f64 * cfg.capture_stall_fraction;
        if full {
            let since = *self.full_since.get_or_insert(now);
            let window = Duration::from_millis(cfg.capture_stall_window_ms);
            if now.saturating_duration_since(since) > window {
                return Err(format!(
                    "capture queue at {queued}/{capacity} for {}s",
                    now.saturating_duration_since(since).as_secs()
                ));
            }
        } else {
            self.full_since = None;
        }
        let stale = Duration::from_millis(cfg.capture_publish_stale_ms);
        if has_work && since_progress > stale {
            return Err(format!(
                "no capture published for {}s with work pending",
                since_progress.as_secs()
            ));
        }
        Ok(())
    }
}

impl Default for PipelineWatch {
    fn default() -> Self {
        Self::new()
    }
}

/// One Redis `PING` through the manager, bounded by `timeout`.
async fn ping(redis: &redis::aio::ConnectionManager, timeout: Duration) -> Result<(), String> {
    let mut conn = redis.clone();
    let reply: redis::RedisResult<String> =
        tokio::time::timeout(timeout, redis::cmd("PING").query_async(&mut conn))
            .await
            .map_err(|_| format!("PING timed out after {timeout:?}"))?;
    reply.map(|_| ()).map_err(|e| format!("PING failed: {e}"))
}

/// Run the Redis and capture pipeline checks every `check_interval_ms`
/// until `cancel` fires.
pub fn spawn_monitor(
    readiness: Arc<Readiness>,
    redis: redis::aio::ConnectionManager,
    writer: Arc<RequestLogWriter>,
    cfg: HealthConfig,
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(cfg.check_interval_ms));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let redis_timeout = Duration::from_millis(cfg.redis_timeout_ms);
        let mut watch = PipelineWatch::new();
        let mut redis_failures = 0u32;
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = cancel.cancelled() => return,
            }

            match ping(&redis, redis_timeout).await {
                Ok(()) => {
                    if redis_failures >= cfg.redis_failure_threshold {
                        tracing::info!("redis reachable again; readiness check recovered");
                    }
                    redis_failures = 0;
                    readiness.redis.set(Ok(()));
                }
                Err(e) => {
                    redis_failures = redis_failures.saturating_add(1);
                    tracing::warn!(error = %e, failures = redis_failures, "redis readiness ping failed");
                    if redis_failures >= cfg.redis_failure_threshold {
                        readiness
                            .redis
                            .set(Err(format!("{e} ({redis_failures} consecutive failures)")));
                    }
                }
            }

            let mut verdict = watch.check(
                Instant::now(),
                writer.queued(),
                writer.capacity(),
                writer.has_work(),
                writer.since_progress(),
                &cfg,
            );
            // Fast failures (a refused connection, a nack) never stall the
            // writer: it drops the capture after its attempts and moves on.
            // Those show only here.
            let probe_timeout = Duration::from_millis(cfg.check_interval_ms);
            if let Some(failure) = writer.publish_failure(probe_timeout).await {
                verdict = Err(format!(
                    "captures are being dropped, publishing has failed for {}s: {}",
                    failure.since.as_secs(),
                    failure.error
                ));
            }
            // Settles a gauge that a racing sender left stale.
            common::metrics::PROXY_CAPTURE_BUFFER_DEPTH.set(writer.queued() as i64);
            if let Err(reason) = &verdict {
                tracing::warn!(%reason, "capture pipeline readiness check failing");
            }
            readiness.pipeline.set(verdict);

            readiness.publish();
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> HealthConfig {
        HealthConfig {
            capture_stall_fraction: 0.5,
            capture_stall_window_ms: 1_000,
            capture_publish_stale_ms: 2_000,
            ..HealthConfig::default()
        }
    }

    #[tokio::test(start_paused = true)]
    async fn queue_full_only_fails_after_the_window() {
        let mut watch = PipelineWatch::new();
        let cfg = cfg();
        let t0 = Instant::now();
        assert!(watch.check(t0, 5, 10, true, Duration::ZERO, &cfg).is_ok());
        tokio::time::advance(Duration::from_millis(900)).await;
        assert!(
            watch
                .check(Instant::now(), 9, 10, true, Duration::ZERO, &cfg)
                .is_ok()
        );
        tokio::time::advance(Duration::from_millis(200)).await;
        let err = watch
            .check(Instant::now(), 10, 10, true, Duration::ZERO, &cfg)
            .expect_err("full for longer than the window");
        assert!(err.contains("10/10"), "{err}");
        // Draining below the fraction clears it.
        assert!(
            watch
                .check(Instant::now(), 2, 10, true, Duration::ZERO, &cfg)
                .is_ok()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_burst_that_drains_never_fails() {
        let mut watch = PipelineWatch::new();
        let cfg = cfg();
        for _ in 0..10 {
            assert!(
                watch
                    .check(Instant::now(), 10, 10, true, Duration::ZERO, &cfg)
                    .is_ok()
            );
            tokio::time::advance(Duration::from_millis(900)).await;
            assert!(
                watch
                    .check(Instant::now(), 0, 10, false, Duration::ZERO, &cfg)
                    .is_ok()
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn stale_progress_matters_only_with_work_pending() {
        let mut watch = PipelineWatch::new();
        let cfg = cfg();
        let idle_for = Duration::from_secs(3600);
        assert!(
            watch
                .check(Instant::now(), 0, 10, false, idle_for, &cfg)
                .is_ok(),
            "an idle writer is healthy"
        );
        let err = watch
            .check(
                Instant::now(),
                0,
                10,
                true,
                Duration::from_millis(2_001),
                &cfg,
            )
            .expect_err("work pending without progress");
        assert!(err.contains("no capture published"), "{err}");
        assert!(
            watch
                .check(
                    Instant::now(),
                    1,
                    10,
                    true,
                    Duration::from_millis(1_999),
                    &cfg
                )
                .is_ok()
        );
    }

    #[test]
    fn report_follows_checks_listeners_and_draining() {
        let readiness = Readiness::new();
        let up = readiness.register_listener("connect");
        let report = readiness.report();
        assert!(!report.ready, "a listener that is not bound yet is down");
        assert_eq!(
            report.checks[CHECK_LISTENERS].detail.as_deref(),
            Some("not accepting: connect")
        );

        up.store(true, Ordering::Release);
        assert!(readiness.report().ready);

        readiness.redis.set(Err("PING failed".into()));
        let report = readiness.report();
        assert!(!report.ready);
        assert!(!report.checks[CHECK_REDIS].ok);
        assert!(report.checks[CHECK_CAPTURE_PIPELINE].ok);
        readiness.redis.set(Ok(()));
        assert!(readiness.report().ready);

        readiness.set_draining();
        let report = readiness.report();
        assert!(!report.ready && report.draining);
        assert!(
            report.checks.values().all(|c| c.ok),
            "draining is not a check"
        );

        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["ready"], false);
        assert_eq!(json["draining"], true);
        assert_eq!(json["checks"]["redis"]["ok"], true);
        assert!(json["checks"]["redis"].get("detail").is_none());
    }
}

/// Fixtures for the tests that run the monitor against real sockets.
#[cfg(test)]
pub(crate) mod testkit {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::time::Duration;

    use bytes::Bytes;
    use common::log::CaptureLogProducer;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::task::JoinHandle;

    /// Publishes once `open` is true; until then every publish waits.
    pub(crate) struct GatedProducer {
        open: Arc<tokio::sync::watch::Sender<bool>>,
    }

    impl GatedProducer {
        /// The producer and the switch that opens or closes it.
        pub(crate) fn new(open: bool) -> (Self, Arc<tokio::sync::watch::Sender<bool>>) {
            let gate = Arc::new(tokio::sync::watch::channel(open).0);
            (Self { open: gate.clone() }, gate)
        }
    }

    impl CaptureLogProducer for GatedProducer {
        fn publish<'life0, 'life1, 'async_trait>(
            &'life0 self,
            _key: &'life1 [u8],
            _payload: Bytes,
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            let mut open = self.open.subscribe();
            Box::pin(async move {
                let _ = open.wait_for(|open| *open).await;
                Ok(())
            })
        }

        fn flush_and_close<'life0, 'async_trait>(
            &'life0 self,
            _timeout: Duration,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async {})
        }
    }

    /// A Redis stand-in that answers every command with `+OK`.
    pub(crate) async fn fake_redis() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    while stream.read(&mut buf).await.unwrap_or(0) > 0 {
                        let _ = stream.write_all(b"+OK\r\n+OK\r\n+OK\r\n+OK\r\n").await;
                    }
                });
            }
        });
        format!("redis://{addr}/")
    }

    /// A TCP forwarder to a real server that can be stopped (the port then
    /// refuses connections) and started again on the same port.
    pub(crate) struct Forwarder {
        pub port: u16,
        target: String,
        tasks: Vec<JoinHandle<()>>,
    }

    impl Forwarder {
        pub(crate) async fn start(target: &str) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let mut forwarder = Self {
                port,
                target: target.to_string(),
                tasks: Vec::new(),
            };
            forwarder.run(listener);
            forwarder
        }

        fn run(&mut self, listener: TcpListener) {
            let target = self.target.clone();
            let conns: Arc<parking_lot::Mutex<Vec<JoinHandle<()>>>> = Arc::default();
            let accept_conns = conns.clone();
            let accept = tokio::spawn(async move {
                loop {
                    let Ok((mut client, _)) = listener.accept().await else {
                        return;
                    };
                    let target = target.clone();
                    let conn = tokio::spawn(async move {
                        if let Ok(mut upstream) = TcpStream::connect(&target).await {
                            let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                        }
                    });
                    accept_conns.lock().push(conn);
                }
            });
            // Aborting the accept task drops the listener; the connections are
            // aborted with it by the guard task below.
            let guard = tokio::spawn(async move {
                struct AbortAll(Arc<parking_lot::Mutex<Vec<JoinHandle<()>>>>);
                impl Drop for AbortAll {
                    fn drop(&mut self) {
                        for conn in self.0.lock().drain(..) {
                            conn.abort();
                        }
                    }
                }
                let _abort = AbortAll(conns);
                std::future::pending::<()>().await;
            });
            self.tasks = vec![accept, guard];
        }

        /// Close the port and every connection through it.
        pub(crate) async fn stop(&mut self) {
            for task in self.tasks.drain(..) {
                task.abort();
                let _ = task.await;
            }
        }

        /// Listen on the same port again.
        pub(crate) async fn restart(&mut self) {
            let listener = TcpListener::bind(("127.0.0.1", self.port)).await.unwrap();
            self.run(listener);
        }
    }
}
