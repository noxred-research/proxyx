//! Circuit breakers and health trackers.
//!
//! A [`Breaker`] guards one parent proxy or one egress address from the
//! results of real requests. Closed: requests pass and failures in a row are
//! counted. Open: nothing passes until `open_duration` has gone by. Half open:
//! up to `half_open_probes` requests pass at once; `success_threshold` good
//! results close it, one bad result opens it again. A [`HealthTracker`] is the
//! other signal, fed by the active checks: it flips with a streak of failed or
//! good probes.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use parking_lot::Mutex;
use prometheus::IntCounter;

use crate::config::BreakerConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerState {
    Closed,
    HalfOpen,
    Open,
}

impl BreakerState {
    /// Value of the state gauges: 0 closed, 1 half open, 2 open.
    pub const fn as_i64(self) -> i64 {
        match self {
            BreakerState::Closed => 0,
            BreakerState::HalfOpen => 1,
            BreakerState::Open => 2,
        }
    }
}

/// Counters of the transitions of one kind of breaker.
#[derive(Clone)]
pub struct Transitions {
    pub closed: IntCounter,
    pub half_open: IntCounter,
    pub open: IntCounter,
}

impl Transitions {
    /// Counters that are not exported anywhere (tests, `--check`).
    pub fn detached() -> Self {
        let c = || IntCounter::new("detached", "detached").expect("valid counter");
        Self {
            closed: c(),
            half_open: c(),
            open: c(),
        }
    }
}

#[derive(Debug)]
struct Inner {
    state: BreakerState,
    failures: u32,
    successes: u32,
    probes: u32,
    /// When the state was entered, or the last probe was let through.
    since: Instant,
}

pub struct Breaker {
    cfg: BreakerConfig,
    inner: Mutex<Inner>,
    tr: Transitions,
}

impl std::fmt::Debug for Breaker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Breaker")
            .field("state", &self.state())
            .finish()
    }
}

impl Breaker {
    pub fn new(cfg: BreakerConfig, tr: Transitions) -> Self {
        Self {
            cfg,
            inner: Mutex::new(Inner {
                state: BreakerState::Closed,
                failures: 0,
                successes: 0,
                probes: 0,
                since: Instant::now(),
            }),
            tr,
        }
    }

    fn enter(&self, i: &mut Inner, to: BreakerState) {
        if i.state == to {
            return;
        }
        i.state = to;
        i.failures = 0;
        i.successes = 0;
        i.probes = 0;
        i.since = Instant::now();
        match to {
            BreakerState::Closed => self.tr.closed.inc(),
            BreakerState::HalfOpen => self.tr.half_open.inc(),
            BreakerState::Open => self.tr.open.inc(),
        }
    }

    /// The state as a request would find it: an open breaker whose time is up
    /// reads as half open.
    pub fn state(&self) -> BreakerState {
        let i = self.inner.lock();
        if i.state == BreakerState::Open && i.since.elapsed() >= self.cfg.open_duration {
            BreakerState::HalfOpen
        } else {
            i.state
        }
    }

    /// True when a request would be let through now. Takes nothing.
    pub fn available(&self) -> bool {
        let i = self.inner.lock();
        match i.state {
            BreakerState::Closed => true,
            BreakerState::Open => i.since.elapsed() >= self.cfg.open_duration,
            BreakerState::HalfOpen => {
                i.probes < self.cfg.half_open_probes || i.since.elapsed() >= self.cfg.open_duration
            }
        }
    }

    /// Ask to send a request. A half-open slot taken here is given back by
    /// [`Self::record`] or [`Self::cancel`]; one that is never given back (the
    /// request was dropped) is reclaimed after `open_duration`.
    pub fn try_acquire(&self) -> bool {
        let mut i = self.inner.lock();
        match i.state {
            BreakerState::Closed => true,
            BreakerState::Open => {
                if i.since.elapsed() < self.cfg.open_duration {
                    return false;
                }
                self.enter(&mut i, BreakerState::HalfOpen);
                i.probes = 1;
                true
            }
            BreakerState::HalfOpen => {
                if i.probes >= self.cfg.half_open_probes {
                    if i.since.elapsed() < self.cfg.open_duration {
                        return false;
                    }
                    i.probes = 0;
                }
                i.probes += 1;
                i.since = Instant::now();
                true
            }
        }
    }

    /// The result of a request that [`Self::try_acquire`] let through (or that
    /// went through a closed breaker).
    pub fn record(&self, ok: bool) {
        let mut i = self.inner.lock();
        match i.state {
            BreakerState::Closed => {
                if ok {
                    i.failures = 0;
                } else {
                    i.failures += 1;
                    if i.failures >= self.cfg.failure_threshold {
                        self.enter(&mut i, BreakerState::Open);
                    }
                }
            }
            BreakerState::HalfOpen => {
                i.probes = i.probes.saturating_sub(1);
                if !ok {
                    self.enter(&mut i, BreakerState::Open);
                } else {
                    i.successes += 1;
                    if i.successes >= self.cfg.success_threshold {
                        self.enter(&mut i, BreakerState::Closed);
                    }
                }
            }
            // A late result of a request that started before the breaker opened.
            BreakerState::Open => {}
        }
    }

    /// Give back a half-open slot without a verdict (the failure was not this
    /// breaker's business).
    pub fn cancel(&self) {
        let mut i = self.inner.lock();
        if i.state == BreakerState::HalfOpen {
            i.probes = i.probes.saturating_sub(1);
        }
    }
}

/// Healthy or not by the streak of the last probes.
#[derive(Debug)]
pub struct HealthTracker {
    healthy: AtomicBool,
    streak: Mutex<(u32, u32)>,
    unhealthy_after: u32,
    healthy_after: u32,
}

impl HealthTracker {
    pub fn new(unhealthy_after: u32, healthy_after: u32) -> Self {
        Self {
            healthy: AtomicBool::new(true),
            streak: Mutex::new((0, 0)),
            unhealthy_after: unhealthy_after.max(1),
            healthy_after: healthy_after.max(1),
        }
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    /// Record one probe. Returns `Some(now_healthy)` when it changed the verdict.
    pub fn observe(&self, ok: bool) -> Option<bool> {
        let mut s = self.streak.lock();
        if ok {
            s.0 += 1;
            s.1 = 0;
        } else {
            s.1 += 1;
            s.0 = 0;
        }
        let now = self.is_healthy();
        if now && s.1 >= self.unhealthy_after {
            self.healthy.store(false, Ordering::Relaxed);
            return Some(false);
        }
        if !now && s.0 >= self.healthy_after {
            self.healthy.store(true, Ordering::Relaxed);
            return Some(true);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn breaker(failures: u32, open_ms: u64, probes: u32, successes: u32) -> Breaker {
        Breaker::new(
            BreakerConfig {
                failure_threshold: failures,
                open_duration: Duration::from_millis(open_ms),
                half_open_probes: probes,
                success_threshold: successes,
            },
            Transitions::detached(),
        )
    }

    #[test]
    fn opens_after_failures_in_a_row_only() {
        let b = breaker(3, 10_000, 1, 1);
        b.record(false);
        b.record(false);
        b.record(true);
        b.record(false);
        b.record(false);
        assert_eq!(
            b.state(),
            BreakerState::Closed,
            "a success resets the count"
        );
        b.record(false);
        assert_eq!(b.state(), BreakerState::Open);
        assert!(!b.available() && !b.try_acquire());
        assert_eq!(b.tr.open.get(), 1);
    }

    #[test]
    fn half_open_lets_a_limited_number_of_probes_through() {
        let b = breaker(1, 40, 2, 2);
        b.record(false);
        assert!(!b.try_acquire());
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(b.state(), BreakerState::HalfOpen);
        assert!(b.available());
        assert!(b.try_acquire() && b.try_acquire());
        assert!(
            !b.try_acquire() && !b.available(),
            "only two probes at once"
        );
        b.record(true);
        assert_eq!(
            b.state(),
            BreakerState::HalfOpen,
            "the second good result is still to come"
        );
        assert!(b.try_acquire(), "a finished probe frees its slot");
        b.record(true);
        assert_eq!(b.state(), BreakerState::Closed);
        assert_eq!((b.tr.half_open.get(), b.tr.closed.get()), (1, 1));
    }

    #[test]
    fn a_failed_probe_opens_it_again_for_a_full_period() {
        let b = breaker(1, 40, 1, 1);
        b.record(false);
        std::thread::sleep(Duration::from_millis(60));
        assert!(b.try_acquire());
        b.record(false);
        assert_eq!(b.state(), BreakerState::Open);
        assert!(!b.try_acquire());
        assert_eq!(b.tr.open.get(), 2);
    }

    #[test]
    fn a_cancelled_probe_gives_the_slot_back_without_a_verdict() {
        let b = breaker(1, 20, 1, 1);
        b.record(false);
        std::thread::sleep(Duration::from_millis(40));
        assert!(b.try_acquire());
        assert!(!b.try_acquire());
        b.cancel();
        assert!(b.try_acquire());
    }

    #[test]
    fn a_probe_that_never_reports_is_reclaimed() {
        let b = breaker(1, 30, 1, 1);
        b.record(false);
        std::thread::sleep(Duration::from_millis(50));
        assert!(b.try_acquire());
        assert!(!b.try_acquire());
        std::thread::sleep(Duration::from_millis(50));
        assert!(b.available());
        assert!(b.try_acquire(), "the lost probe does not wedge the breaker");
    }

    #[test]
    fn late_results_while_open_are_ignored() {
        let b = breaker(1, 10_000, 1, 1);
        b.record(false);
        b.record(true);
        assert_eq!(b.state(), BreakerState::Open);
    }

    #[test]
    fn health_flips_on_streaks() {
        let h = HealthTracker::new(2, 2);
        assert_eq!(h.observe(false), None);
        assert_eq!(
            h.observe(true),
            None,
            "a good probe breaks the failure streak"
        );
        assert_eq!(h.observe(false), None);
        assert_eq!(h.observe(false), Some(false));
        assert!(!h.is_healthy());
        assert_eq!(h.observe(true), None);
        assert_eq!(h.observe(false), None);
        assert_eq!(h.observe(true), None);
        assert_eq!(h.observe(true), Some(true));
        assert!(h.is_healthy());
    }
}
