//! Per-upstream circuit breakers for the egress path.
//!
//! Every dial to an upstream goes through [`UpstreamBreakers::acquire`]. A
//! breaker is kept per target: the egress proxy address, a session's private
//! override target, or an origin `host:port`. A target that keeps failing to
//! accept connections is cut off for a while, so the proxy answers at once
//! instead of spending the connect timeout and the retries on every request.
//!
//! States: closed (dials go through), open (dials fail at once until the open
//! period ends), half-open (a few probe dials are let through; enough
//! successes close the breaker, one failure opens it again with a longer
//! period).
//!
//! The table of breakers is a bounded `moka` cache with idle eviction. An
//! evicted breaker starts closed again the next time its target is dialed.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use moka::sync::Cache;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::time::Instant;

/// What a breaker protects. The `target_kind` label of the breaker metrics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TargetKind {
    /// The address of a session's egress proxy.
    EgressProxy,
    /// The private upstream a session maps a logical authority to.
    PrivateOverride,
    /// An origin `host:port` dialed directly.
    Origin,
}

impl TargetKind {
    const ALL: [TargetKind; 3] = [
        TargetKind::EgressProxy,
        TargetKind::PrivateOverride,
        TargetKind::Origin,
    ];

    pub fn label(self) -> &'static str {
        match self {
            TargetKind::EgressProxy => "egress_proxy",
            TargetKind::PrivateOverride => "private_override",
            TargetKind::Origin => "origin",
        }
    }

    fn index(self) -> usize {
        match self {
            TargetKind::EgressProxy => 0,
            TargetKind::PrivateOverride => 1,
            TargetKind::Origin => 2,
        }
    }
}

impl fmt::Display for TargetKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Externally visible breaker state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BreakerState {
    Closed,
    Open,
    HalfOpen,
}

impl BreakerState {
    fn label(self) -> &'static str {
        match self {
            BreakerState::Closed => "closed",
            BreakerState::Open => "open",
            BreakerState::HalfOpen => "half_open",
        }
    }
}

/// The breaker refused a dial.
#[derive(Debug, thiserror::Error)]
#[error("upstream {kind} {target} unavailable: circuit breaker open")]
pub struct BreakerOpen {
    pub kind: TargetKind,
    pub target: String,
    /// How long until the breaker lets a probe through.
    pub retry_after: Duration,
}

impl BreakerOpen {
    /// `Retry-After` value: whole seconds, rounded up, at least 1.
    pub fn retry_after_secs(&self) -> u64 {
        self.retry_after.as_millis().div_ceil(1000).max(1) as u64
    }
}

/// Circuit breaker settings (`[breaker]`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct BreakerConfig {
    /// `false` turns the breaker off: every dial is attempted.
    pub enabled: bool,
    /// Consecutive failed dials that open a closed breaker.
    pub consecutive_failures: u32,
    /// Failure share in percent over `rate_window_ms` that opens a closed
    /// breaker, once `rate_min_calls` dials were seen. 0 turns the rate rule
    /// off.
    pub failure_rate_pct: u32,
    /// Dials in the window before the rate rule applies.
    pub rate_min_calls: u32,
    /// Length of the rolling window of the rate rule.
    pub rate_window_ms: u64,
    /// How long the breaker stays open the first time it trips.
    pub open_duration_ms: u64,
    /// Each trip without an intervening close multiplies the open period by
    /// this factor (1.0 keeps it constant).
    pub open_backoff_factor: f64,
    /// Upper bound of the open period.
    pub max_open_duration_ms: u64,
    /// Probe dials allowed at the same time while half-open.
    pub half_open_max_probes: u32,
    /// Successful probes that close a half-open breaker.
    pub success_threshold: u32,
    /// Most targets tracked at once.
    pub max_targets: u64,
    /// A target idle this long is forgotten (its breaker resets).
    pub idle_ttl_ms: u64,
}

impl Default for BreakerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            consecutive_failures: 5,
            failure_rate_pct: 90,
            rate_min_calls: 20,
            rate_window_ms: 60_000,
            open_duration_ms: 30_000,
            open_backoff_factor: 2.0,
            max_open_duration_ms: 300_000,
            half_open_max_probes: 1,
            success_threshold: 2,
            max_targets: 10_000,
            idle_ttl_ms: 900_000,
        }
    }
}

impl BreakerConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.enabled {
            return Ok(());
        }
        anyhow::ensure!(
            self.consecutive_failures > 0,
            "breaker.consecutive_failures must be at least 1"
        );
        anyhow::ensure!(
            self.failure_rate_pct <= 100,
            "breaker.failure_rate_pct must be between 0 and 100"
        );
        if self.failure_rate_pct > 0 {
            anyhow::ensure!(
                self.rate_min_calls > 0,
                "breaker.rate_min_calls must be at least 1 while the rate rule is on"
            );
            anyhow::ensure!(
                self.rate_window_ms > 0,
                "breaker.rate_window_ms must be greater than 0 while the rate rule is on"
            );
        }
        anyhow::ensure!(
            self.open_duration_ms > 0,
            "breaker.open_duration_ms must be greater than 0"
        );
        anyhow::ensure!(
            self.open_backoff_factor.is_finite() && self.open_backoff_factor >= 1.0,
            "breaker.open_backoff_factor must be a number of at least 1.0"
        );
        anyhow::ensure!(
            self.max_open_duration_ms >= self.open_duration_ms,
            "breaker.max_open_duration_ms must not be below breaker.open_duration_ms"
        );
        anyhow::ensure!(
            self.half_open_max_probes > 0,
            "breaker.half_open_max_probes must be at least 1"
        );
        anyhow::ensure!(
            self.success_threshold > 0,
            "breaker.success_threshold must be at least 1"
        );
        anyhow::ensure!(
            self.max_targets > 0,
            "breaker.max_targets must be greater than 0"
        );
        anyhow::ensure!(
            self.idle_ttl_ms >= self.max_open_duration_ms,
            "breaker.idle_ttl_ms must not be below breaker.max_open_duration_ms, \
             or an open breaker would be forgotten before its period ends"
        );
        Ok(())
    }

    fn open_period(&self, trips: u32) -> Duration {
        let ms = self.open_duration_ms as f64 * self.open_backoff_factor.powi(trips.min(32) as i32);
        Duration::from_millis(ms.min(self.max_open_duration_ms as f64) as u64)
    }
}

const WINDOW_SLOTS: usize = 10;

#[derive(Clone, Copy, Default)]
struct Slot {
    id: u64,
    ok: u32,
    failed: u32,
}

/// Rolling success/failure counts in ten slots that together span the window.
struct Window {
    slot_ms: u64,
    slots: [Slot; WINDOW_SLOTS],
}

impl Window {
    fn new(window_ms: u64) -> Self {
        Self {
            slot_ms: (window_ms / WINDOW_SLOTS as u64).max(1),
            slots: [Slot::default(); WINDOW_SLOTS],
        }
    }

    fn record(&mut self, at_ms: u64, ok: bool) {
        let id = at_ms / self.slot_ms;
        let slot = &mut self.slots[(id % WINDOW_SLOTS as u64) as usize];
        if slot.id != id {
            *slot = Slot {
                id,
                ok: 0,
                failed: 0,
            };
        }
        if ok {
            slot.ok = slot.ok.saturating_add(1);
        } else {
            slot.failed = slot.failed.saturating_add(1);
        }
    }

    /// `(total, failed)` over the slots still inside the window.
    fn totals(&self, at_ms: u64) -> (u64, u64) {
        let now_id = at_ms / self.slot_ms;
        self.slots
            .iter()
            .filter(|slot| {
                (slot.ok > 0 || slot.failed > 0)
                    && now_id.saturating_sub(slot.id) < WINDOW_SLOTS as u64
            })
            .fold((0, 0), |(total, failed), slot| {
                (
                    total + u64::from(slot.ok) + u64::from(slot.failed),
                    failed + u64::from(slot.failed),
                )
            })
    }

    fn clear(&mut self) {
        self.slots = [Slot::default(); WINDOW_SLOTS];
    }
}

enum State {
    Closed,
    Open { until: Instant },
    HalfOpen { in_flight: u32, successes: u32 },
}

impl State {
    fn public(&self) -> BreakerState {
        match self {
            State::Closed => BreakerState::Closed,
            State::Open { .. } => BreakerState::Open,
            State::HalfOpen { .. } => BreakerState::HalfOpen,
        }
    }
}

struct Inner {
    state: State,
    /// Bumped on every state change; a [`Permit`] only counts in the epoch it
    /// was issued in.
    epoch: u64,
    consecutive_failures: u32,
    /// Trips since the breaker was last closed; drives the open backoff.
    trips: u32,
    window: Window,
    /// The cache dropped this breaker; it no longer feeds the shared counts.
    evicted: bool,
}

/// Counts of tracked breakers per kind that are open or half-open, behind the
/// worst-state gauge.
struct Stats {
    open: [AtomicI64; 3],
    half_open: [AtomicI64; 3],
}

impl Stats {
    fn new() -> Self {
        Self {
            open: Default::default(),
            half_open: Default::default(),
        }
    }

    fn counter(&self, kind: TargetKind, state: BreakerState) -> Option<&AtomicI64> {
        match state {
            BreakerState::Closed => None,
            BreakerState::Open => Some(&self.open[kind.index()]),
            BreakerState::HalfOpen => Some(&self.half_open[kind.index()]),
        }
    }

    fn worst(&self, kind: TargetKind) -> BreakerState {
        if self.open[kind.index()].load(Ordering::Relaxed) > 0 {
            BreakerState::Open
        } else if self.half_open[kind.index()].load(Ordering::Relaxed) > 0 {
            BreakerState::HalfOpen
        } else {
            BreakerState::Closed
        }
    }

    fn publish(&self, kind: TargetKind) {
        let value = match self.worst(kind) {
            BreakerState::Closed => 0,
            BreakerState::Open => 1,
            BreakerState::HalfOpen => 2,
        };
        common::metrics::PROXY_UPSTREAM_BREAKER_STATE
            .with_label_values(&[kind.label()])
            .set(value);
    }

    /// A breaker changed state.
    fn moved(&self, kind: TargetKind, from: BreakerState, to: BreakerState) {
        if let Some(c) = self.counter(kind, from) {
            c.fetch_sub(1, Ordering::Relaxed);
        }
        if let Some(c) = self.counter(kind, to) {
            c.fetch_add(1, Ordering::Relaxed);
        }
        self.publish(kind);
        common::metrics::PROXY_UPSTREAM_BREAKER_TRANSITIONS_TOTAL
            .with_label_values(&[kind.label(), to.label()])
            .inc();
    }

    /// A breaker left the table in `state`.
    fn forgot(&self, kind: TargetKind, state: BreakerState) {
        if let Some(c) = self.counter(kind, state) {
            c.fetch_sub(1, Ordering::Relaxed);
            self.publish(kind);
        }
    }
}

struct Breaker {
    kind: TargetKind,
    target: String,
    cfg: Arc<BreakerConfig>,
    /// Time zero of the rolling window.
    origin: Instant,
    stats: Arc<Stats>,
    inner: Mutex<Inner>,
}

impl Breaker {
    fn new(kind: TargetKind, target: String, cfg: Arc<BreakerConfig>, stats: Arc<Stats>) -> Self {
        Self {
            kind,
            target,
            origin: Instant::now(),
            stats,
            inner: Mutex::new(Inner {
                state: State::Closed,
                epoch: 0,
                consecutive_failures: 0,
                trips: 0,
                window: Window::new(cfg.rate_window_ms),
                evicted: false,
            }),
            cfg,
        }
    }

    fn at_ms(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.origin).as_millis() as u64
    }

    fn rejection(&self, retry_after: Duration) -> BreakerOpen {
        BreakerOpen {
            kind: self.kind,
            target: self.target.clone(),
            retry_after,
        }
    }

    fn enter(&self, inner: &mut Inner, state: State) {
        let from = inner.state.public();
        let to = state.public();
        inner.state = state;
        inner.epoch += 1;
        if matches!(inner.state, State::Closed) {
            inner.consecutive_failures = 0;
            inner.trips = 0;
            inner.window.clear();
        }
        if !inner.evicted {
            self.stats.moved(self.kind, from, to);
        }
    }

    fn trip(&self, inner: &mut Inner, now: Instant) {
        let period = self.cfg.open_period(inner.trips);
        inner.trips = inner.trips.saturating_add(1);
        tracing::warn!(
            kind = self.kind.label(),
            target = %self.target,
            open_ms = period.as_millis() as u64,
            "upstream circuit breaker opened"
        );
        self.enter(
            inner,
            State::Open {
                until: now + period,
            },
        );
    }

    fn admit(self: &Arc<Self>) -> Result<Permit, BreakerOpen> {
        let now = Instant::now();
        let mut inner = self.inner.lock();
        if let State::Open { until } = inner.state {
            if now < until {
                return Err(self.rejection(until - now));
            }
            self.enter(
                &mut inner,
                State::HalfOpen {
                    in_flight: 0,
                    successes: 0,
                },
            );
        }
        let probe = match &mut inner.state {
            State::Closed => false,
            State::HalfOpen { in_flight, .. } => {
                if *in_flight >= self.cfg.half_open_max_probes {
                    return Err(self.rejection(Duration::from_secs(1)));
                }
                *in_flight += 1;
                true
            }
            // Handled above: an open breaker either rejected or turned half-open.
            State::Open { until } => return Err(self.rejection(*until - now)),
        };
        Ok(Permit {
            breaker: Some(self.clone()),
            epoch: inner.epoch,
            probe,
        })
    }

    fn record(&self, epoch: u64, probe: bool, ok: bool) {
        let now = Instant::now();
        let at_ms = self.at_ms(now);
        let mut guard = self.inner.lock();
        let inner = &mut *guard;
        if inner.epoch != epoch {
            return;
        }
        match &mut inner.state {
            State::Closed => {
                inner.window.record(at_ms, ok);
                if ok {
                    inner.consecutive_failures = 0;
                    return;
                }
                inner.consecutive_failures += 1;
                let by_count = inner.consecutive_failures >= self.cfg.consecutive_failures;
                let by_rate = self.cfg.failure_rate_pct > 0 && {
                    let (total, failed) = inner.window.totals(at_ms);
                    total >= u64::from(self.cfg.rate_min_calls)
                        && failed * 100 >= total * u64::from(self.cfg.failure_rate_pct)
                };
                if by_count || by_rate {
                    self.trip(inner, now);
                }
            }
            State::HalfOpen {
                in_flight,
                successes,
            } if probe => {
                *in_flight = in_flight.saturating_sub(1);
                if !ok {
                    self.trip(inner, now);
                    return;
                }
                *successes += 1;
                if *successes >= self.cfg.success_threshold {
                    tracing::info!(
                        kind = self.kind.label(),
                        target = %self.target,
                        "upstream circuit breaker closed"
                    );
                    self.enter(inner, State::Closed);
                }
            }
            _ => {}
        }
    }

    /// A permit ended without a verdict: free its probe slot.
    fn release(&self, epoch: u64, probe: bool) {
        let mut inner = self.inner.lock();
        if inner.epoch != epoch || !probe {
            return;
        }
        if let State::HalfOpen { in_flight, .. } = &mut inner.state {
            *in_flight = in_flight.saturating_sub(1);
        }
    }

    #[cfg(test)]
    fn state(&self) -> BreakerState {
        self.inner.lock().state.public()
    }

    fn forget(&self) {
        let mut inner = self.inner.lock();
        if !inner.evicted {
            inner.evicted = true;
            self.stats.forgot(self.kind, inner.state.public());
        }
    }
}

/// Right to make one dial. Report how it went with [`Permit::success`] or
/// [`Permit::failure`]; dropping it without a verdict (see [`Permit::ignore`])
/// counts neither way.
#[must_use = "report the dial outcome, or the permit counts as no verdict"]
pub struct Permit {
    breaker: Option<Arc<Breaker>>,
    epoch: u64,
    probe: bool,
}

impl Permit {
    /// The target accepted the connection (or answered a protocol-level
    /// refusal, which shows it is up).
    pub fn success(mut self) {
        if let Some(b) = self.breaker.take() {
            b.record(self.epoch, self.probe, true);
        }
    }

    /// The target could not be reached or did not answer in time.
    pub fn failure(mut self) {
        if let Some(b) = self.breaker.take() {
            b.record(self.epoch, self.probe, false);
        }
    }

    /// The dial failed for a reason that says nothing about the target.
    pub fn ignore(self) {}
}

impl Drop for Permit {
    fn drop(&mut self) {
        if let Some(b) = self.breaker.take() {
            b.release(self.epoch, self.probe);
        }
    }
}

/// The table of breakers.
#[derive(Clone)]
pub struct UpstreamBreakers {
    cfg: Arc<BreakerConfig>,
    stats: Arc<Stats>,
    /// `None` when the breaker is off.
    table: Option<Cache<(TargetKind, String), Arc<Breaker>>>,
}

impl UpstreamBreakers {
    pub fn new(cfg: &BreakerConfig) -> Self {
        let stats = Arc::new(Stats::new());
        let table = cfg.enabled.then(|| {
            Cache::builder()
                .max_capacity(cfg.max_targets)
                .time_to_idle(Duration::from_millis(cfg.idle_ttl_ms))
                .eviction_listener(|_key, breaker: Arc<Breaker>, _cause| breaker.forget())
                .build()
        });
        Self {
            cfg: Arc::new(cfg.clone()),
            stats,
            table,
        }
    }

    /// Ask to dial `target` (`host:port` or the egress proxy address).
    /// Fails at once while the target's breaker is open.
    pub fn acquire(&self, kind: TargetKind, target: &str) -> Result<Permit, BreakerOpen> {
        let Some(table) = &self.table else {
            return Ok(Permit {
                breaker: None,
                epoch: 0,
                probe: false,
            });
        };
        let key = (kind, target.to_ascii_lowercase());
        let breaker = table.get_with(key.clone(), || {
            Arc::new(Breaker::new(
                kind,
                key.1.clone(),
                self.cfg.clone(),
                self.stats.clone(),
            ))
        });
        breaker.admit().inspect_err(|_| {
            common::metrics::PROXY_UPSTREAM_BREAKER_REJECTED_TOTAL
                .with_label_values(&[kind.label()])
                .inc();
        })
    }

    /// State of the tracked breaker of one target; `None` when untracked.
    #[cfg(test)]
    pub fn state(&self, kind: TargetKind, target: &str) -> Option<BreakerState> {
        let table = self.table.as_ref()?;
        table
            .get(&(kind, target.to_ascii_lowercase()))
            .map(|b| b.state())
    }

    /// The worst state among the tracked breakers of one kind.
    #[cfg(test)]
    pub fn worst_state(&self, kind: TargetKind) -> BreakerState {
        self.stats.worst(kind)
    }

    /// Targets currently tracked (after pending evictions are applied).
    #[cfg(test)]
    pub fn tracked_targets(&self) -> u64 {
        match &self.table {
            Some(table) => {
                table.run_pending_tasks();
                table.entry_count()
            }
            None => 0,
        }
    }

    /// Set every gauge to the current worst state. Call once at startup so
    /// the series exist before the first transition.
    pub fn publish_gauges(&self) {
        for kind in TargetKind::ALL {
            self.stats.publish(kind);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> BreakerConfig {
        BreakerConfig {
            consecutive_failures: 3,
            failure_rate_pct: 0,
            open_duration_ms: 1_000,
            open_backoff_factor: 2.0,
            max_open_duration_ms: 8_000,
            half_open_max_probes: 1,
            success_threshold: 2,
            ..BreakerConfig::default()
        }
    }

    fn fail(b: &UpstreamBreakers, kind: TargetKind, target: &str) {
        b.acquire(kind, target)
            .expect("closed breaker admits")
            .failure();
    }

    #[tokio::test(start_paused = true)]
    async fn closed_open_half_open_closed() {
        let b = UpstreamBreakers::new(&cfg());
        let t = "origin.example:443";
        let k = TargetKind::Origin;
        assert_eq!(b.state(k, t), None);

        fail(&b, k, t);
        fail(&b, k, t);
        assert_eq!(b.state(k, t), Some(BreakerState::Closed));
        fail(&b, k, t);
        assert_eq!(b.state(k, t), Some(BreakerState::Open));
        assert_eq!(b.worst_state(k), BreakerState::Open);

        let err = b.acquire(k, t).err().expect("open breaker rejects");
        assert_eq!(err.kind, k);
        assert_eq!(err.target, t);
        assert!(err.retry_after <= Duration::from_secs(1));
        assert_eq!(err.retry_after_secs(), 1);

        tokio::time::advance(Duration::from_millis(999)).await;
        assert!(b.acquire(k, t).is_err(), "still inside the open period");
        tokio::time::advance(Duration::from_millis(2)).await;

        // Half-open: one probe at a time.
        let probe = b.acquire(k, t).expect("probe after the open period");
        assert_eq!(b.state(k, t), Some(BreakerState::HalfOpen));
        assert_eq!(b.worst_state(k), BreakerState::HalfOpen);
        assert!(b.acquire(k, t).is_err(), "second concurrent probe refused");
        probe.success();
        assert_eq!(b.state(k, t), Some(BreakerState::HalfOpen));
        b.acquire(k, t).expect("next probe").success();
        assert_eq!(b.state(k, t), Some(BreakerState::Closed));
        assert_eq!(b.worst_state(k), BreakerState::Closed);

        // Closed again: the failure count starts over.
        fail(&b, k, t);
        assert_eq!(b.state(k, t), Some(BreakerState::Closed));
    }

    #[tokio::test(start_paused = true)]
    async fn half_open_failure_reopens_with_backoff() {
        let b = UpstreamBreakers::new(&cfg());
        let t = "10.0.0.1:8080";
        let k = TargetKind::PrivateOverride;
        for _ in 0..3 {
            fail(&b, k, t);
        }
        tokio::time::advance(Duration::from_millis(1_001)).await;
        b.acquire(k, t).expect("probe").failure();
        assert_eq!(b.state(k, t), Some(BreakerState::Open));

        // Second trip: twice the first period.
        let err = b.acquire(k, t).err().expect("open again");
        assert!(err.retry_after > Duration::from_millis(1_500));
        assert!(err.retry_after <= Duration::from_millis(2_000));
        tokio::time::advance(Duration::from_millis(2_001)).await;
        b.acquire(k, t).expect("probe").failure();

        // Third trip: 4 s, then capped at 8 s.
        let err = b.acquire(k, t).err().expect("open a third time");
        assert!(err.retry_after > Duration::from_millis(3_500));
        tokio::time::advance(Duration::from_millis(4_001)).await;
        b.acquire(k, t).expect("probe").failure();
        tokio::time::advance(Duration::from_millis(8_001)).await;
        b.acquire(k, t).expect("probe").failure();
        let err = b.acquire(k, t).err().expect("open a fifth time");
        assert!(err.retry_after <= Duration::from_millis(8_000), "capped");
        assert!(err.retry_after > Duration::from_millis(7_500));
    }

    #[tokio::test(start_paused = true)]
    async fn success_resets_the_consecutive_count() {
        let b = UpstreamBreakers::new(&cfg());
        let t = "a.example:80";
        let k = TargetKind::Origin;
        for _ in 0..10 {
            fail(&b, k, t);
            fail(&b, k, t);
            b.acquire(k, t).expect("closed").success();
        }
        assert_eq!(b.state(k, t), Some(BreakerState::Closed));
    }

    #[tokio::test(start_paused = true)]
    async fn rate_rule_opens_without_consecutive_failures() {
        let b = UpstreamBreakers::new(&BreakerConfig {
            consecutive_failures: 1_000,
            failure_rate_pct: 50,
            rate_min_calls: 10,
            rate_window_ms: 10_000,
            ..cfg()
        });
        let t = "flaky.example:443";
        let k = TargetKind::Origin;
        // Alternate: never more than one failure in a row, 50% overall.
        for i in 0..9 {
            let permit = b.acquire(k, t).expect("closed");
            if i % 2 == 0 {
                permit.failure();
            } else {
                permit.success();
            }
        }
        assert_eq!(b.state(k, t), Some(BreakerState::Closed), "below min calls");
        b.acquire(k, t).expect("closed").failure();
        assert_eq!(b.state(k, t), Some(BreakerState::Open));
    }

    #[tokio::test(start_paused = true)]
    async fn rate_rule_forgets_old_calls() {
        let b = UpstreamBreakers::new(&BreakerConfig {
            consecutive_failures: 1_000,
            failure_rate_pct: 50,
            rate_min_calls: 4,
            rate_window_ms: 10_000,
            ..cfg()
        });
        let t = "slow.example:443";
        let k = TargetKind::Origin;
        for _ in 0..3 {
            fail(&b, k, t);
        }
        // The window rolls past those failures.
        tokio::time::advance(Duration::from_secs(11)).await;
        for _ in 0..3 {
            b.acquire(k, t).expect("closed").success();
        }
        b.acquire(k, t).expect("closed").failure();
        assert_eq!(b.state(k, t), Some(BreakerState::Closed));
    }

    #[tokio::test(start_paused = true)]
    async fn dropped_permit_frees_the_probe_slot() {
        let b = UpstreamBreakers::new(&cfg());
        let t = "dns.example:443";
        let k = TargetKind::Origin;
        for _ in 0..3 {
            fail(&b, k, t);
        }
        tokio::time::advance(Duration::from_millis(1_001)).await;
        b.acquire(k, t).expect("probe").ignore();
        assert_eq!(b.state(k, t), Some(BreakerState::HalfOpen));
        b.acquire(k, t).expect("slot is free again").success();
    }

    #[tokio::test(start_paused = true)]
    async fn kinds_and_targets_are_independent() {
        let b = UpstreamBreakers::new(&cfg());
        for _ in 0..3 {
            fail(&b, TargetKind::Origin, "x.example:443");
        }
        assert!(b.acquire(TargetKind::Origin, "x.example:443").is_err());
        assert!(b.acquire(TargetKind::Origin, "y.example:443").is_ok());
        assert!(b.acquire(TargetKind::Origin, "x.example:80").is_ok());
        assert!(
            b.acquire(TargetKind::PrivateOverride, "x.example:443")
                .is_ok()
        );
        // Host names compare case-insensitively.
        assert!(b.acquire(TargetKind::Origin, "X.Example:443").is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn disabled_breaker_never_rejects() {
        let b = UpstreamBreakers::new(&BreakerConfig {
            enabled: false,
            ..cfg()
        });
        for _ in 0..50 {
            fail(&b, TargetKind::Origin, "down.example:443");
        }
        assert!(b.acquire(TargetKind::Origin, "down.example:443").is_ok());
        assert_eq!(b.tracked_targets(), 0);
    }

    #[test]
    fn table_is_bounded() {
        let b = UpstreamBreakers::new(&BreakerConfig {
            max_targets: 8,
            ..cfg()
        });
        for i in 0..200 {
            b.acquire(TargetKind::Origin, &format!("host-{i}.example:443"))
                .expect("closed")
                .success();
        }
        assert!(
            b.tracked_targets() <= 8,
            "tracked {} targets with a cap of 8",
            b.tracked_targets()
        );
    }

    #[test]
    fn idle_targets_are_evicted_and_stop_counting() {
        let b = UpstreamBreakers::new(&BreakerConfig {
            consecutive_failures: 1,
            open_duration_ms: 50,
            max_open_duration_ms: 50,
            idle_ttl_ms: 50,
            ..cfg()
        });
        let k = TargetKind::PrivateOverride;
        b.acquire(k, "evict.example:1").expect("closed").failure();
        assert_eq!(b.worst_state(k), BreakerState::Open);
        std::thread::sleep(Duration::from_millis(120));
        assert_eq!(b.tracked_targets(), 0);
        assert_eq!(
            b.worst_state(k),
            BreakerState::Closed,
            "an evicted breaker no longer counts"
        );
        assert!(
            b.acquire(k, "evict.example:1").is_ok(),
            "starts closed again"
        );
    }

    #[test]
    fn config_validation_names_the_key() {
        let bad = |f: fn(&mut BreakerConfig)| {
            let mut c = BreakerConfig::default();
            f(&mut c);
            c.validate().expect_err("invalid").to_string()
        };
        assert!(BreakerConfig::default().validate().is_ok());
        assert!(bad(|c| c.consecutive_failures = 0).contains("breaker.consecutive_failures"));
        assert!(bad(|c| c.open_duration_ms = 0).contains("breaker.open_duration_ms"));
        assert!(bad(|c| c.open_backoff_factor = 0.5).contains("breaker.open_backoff_factor"));
        assert!(bad(|c| c.open_backoff_factor = f64::NAN).contains("breaker.open_backoff_factor"));
        assert!(bad(|c| c.max_open_duration_ms = 1).contains("breaker.max_open_duration_ms"));
        assert!(bad(|c| c.half_open_max_probes = 0).contains("breaker.half_open_max_probes"));
        assert!(bad(|c| c.success_threshold = 0).contains("breaker.success_threshold"));
        assert!(bad(|c| c.max_targets = 0).contains("breaker.max_targets"));
        assert!(bad(|c| c.idle_ttl_ms = 1).contains("breaker.idle_ttl_ms"));
        assert!(bad(|c| c.failure_rate_pct = 101).contains("breaker.failure_rate_pct"));
        let off = BreakerConfig {
            enabled: false,
            consecutive_failures: 0,
            ..BreakerConfig::default()
        };
        assert!(
            off.validate().is_ok(),
            "a disabled breaker is not validated"
        );
    }
}
