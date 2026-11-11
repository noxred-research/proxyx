//! The pure arithmetic of the rotating reconcile loop.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use store::UnitCounts;

/// `target = min(max_ready, min_ready + extra)`, `extra` from [`extra_target`].
pub(crate) fn target(min_ready: u32, max_ready: u32, extra: u32) -> u32 {
    min_ready.saturating_add(extra).min(max_ready)
}

/// The ready sessions kept above `min_ready` for the lease rate `L`
/// (`leases_per_min`): `ceil(headroom x L)`. With `auto` and a measured create
/// latency `C` (`create_secs`) it is the larger of that and `ceil(L x C / 60)`,
/// the leases that arrive while one create runs. Without a
/// measurement only the floor applies.
pub(crate) fn extra_target(
    headroom: u32,
    auto: bool,
    leases_per_min: f64,
    create_secs: Option<f64>,
) -> u32 {
    let rate = leases_per_min.max(0.0);
    let floor = ceil_u32(f64::from(headroom) * rate);
    match create_secs {
        Some(secs) if auto => floor.max(ceil_u32(rate * secs.max(0.0) / 60.0)),
        _ => floor,
    }
}

fn ceil_u32(x: f64) -> u32 {
    // `x` is non-negative; a huge value saturates the cast.
    x.ceil() as u32
}

/// Exponential average of how long a create takes to become ready: the first
/// sample seeds it, each later one moves it 20% of the way.
#[derive(Debug, Default)]
pub(crate) struct CreateLatency {
    secs: Option<f64>,
}

const LATENCY_WEIGHT: f64 = 0.2;

impl CreateLatency {
    pub(crate) fn record(&mut self, took: Duration) {
        let sample = took.as_secs_f64();
        self.secs = Some(match self.secs {
            None => sample,
            Some(avg) => avg + LATENCY_WEIGHT * (sample - avg),
        });
    }

    pub(crate) fn secs(&self) -> Option<f64> {
        self.secs
    }
}

/// A degraded session is kept in the cache up to a quarter of `max_ready`.
const DEGRADED_SHARE: u32 = 4;

/// Most free degraded sessions a partition keeps.
pub(crate) fn degraded_cap(max_ready: u32) -> u64 {
    u64::from(max_ready.div_ceil(DEGRADED_SHARE))
}

/// `need = min(target - (normal free + in flight + reserved), max_ready -
/// (ready + in flight + reserved))`: the second bound counts the leased
/// sessions too, so `max_ready` caps every session the provider has given, not
/// only the idle ones. A degraded session fills room but not the target: the
/// warmer still wants normal ones.
pub(crate) fn need(target: u32, max_ready: u32, counts: &UnitCounts) -> u32 {
    let pending = counts.creating.saturating_add(counts.reserved);
    let free = counts
        .ready_free
        .saturating_sub(counts.degraded_free)
        .saturating_add(pending);
    let all = counts
        .ready_free
        .saturating_add(pending)
        .saturating_add(counts.leased);
    let want = u64::from(target).saturating_sub(free);
    let room = u64::from(max_ready).saturating_sub(all);
    u32::try_from(want.min(room)).unwrap_or(u32::MAX)
}

/// Everything that can hold a start back.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Bounds {
    pub need: u32,
    pub refill_concurrency: u32,
    pub creating: u64,
    pub tokens: u32,
    pub creates_left: u64,
}

/// `min(need, refill_concurrency - in flight, rate tokens, budget left)`.
pub(crate) fn starts(b: &Bounds) -> u32 {
    let slots = u64::from(b.refill_concurrency).saturating_sub(b.creating);
    let n = u64::from(b.need)
        .min(slots)
        .min(u64::from(b.tokens))
        .min(b.creates_left);
    // `n` is at most `need`, which is a u32.
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// How many new leases per minute a partition sees, estimated from the
/// growth of its leased count: the warmer has no lease counter of its own
/// (assumption). Only increases count, so releases never hide demand.
#[derive(Debug, Default)]
pub(crate) struct LeaseRate {
    samples: VecDeque<(Instant, u64)>,
}

const RATE_WINDOW: Duration = Duration::from_secs(300);

impl LeaseRate {
    pub(crate) fn observe(&mut self, now: Instant, leased: u64) {
        self.samples.push_back((now, leased));
        while self
            .samples
            .front()
            .is_some_and(|(t, _)| now.saturating_duration_since(*t) > RATE_WINDOW)
        {
            self.samples.pop_front();
        }
    }

    pub(crate) fn per_minute(&self) -> f64 {
        let (Some((first, _)), Some((last, _))) = (self.samples.front(), self.samples.back())
        else {
            return 0.0;
        };
        let grown: u64 = self
            .samples
            .iter()
            .zip(self.samples.iter().skip(1))
            .map(|((_, a), (_, b))| b.saturating_sub(*a))
            .sum();
        // Under a minute of history still divides by a minute, so one lease
        // seen in a second is not read as 60 per minute.
        let minutes = last.duration_since(*first).as_secs_f64() / 60.0;
        grown as f64 / minutes.max(1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_adds_extra_and_stops_at_max_ready() {
        assert_eq!(target(10, 20, 0), 10);
        assert_eq!(target(10, 20, 3), 13);
        assert_eq!(target(10, 20, 100), 20);
        assert_eq!(target(10, 10, 5), 10);
        assert_eq!(target(10, 20, u32::MAX), 20, "no overflow");
    }

    #[test]
    fn extra_is_the_headroom_floor_without_auto() {
        assert_eq!(extra_target(0, false, 7.0, None), 0);
        assert_eq!(extra_target(2, false, 0.0, None), 0);
        assert_eq!(extra_target(2, false, 1.5, None), 3);
        assert_eq!(extra_target(1, false, 0.2, None), 1, "a fraction rounds up");
        assert_eq!(
            extra_target(1, false, 6.0, Some(600.0)),
            6,
            "auto off ignores the measurement"
        );
    }

    #[test]
    fn extra_with_auto_is_the_larger_of_floor_and_measured_part() {
        assert_eq!(extra_target(2, true, 1.5, None), 3, "no measurement: floor");
        // Floor 2 x 6 = 12; measured 6 x 30 / 60 = 3.
        assert_eq!(extra_target(2, true, 6.0, Some(30.0)), 12);
        // Floor 1 x 6 = 6; measured 6 x 90 / 60 = 9.
        assert_eq!(extra_target(1, true, 6.0, Some(90.0)), 9);
        assert_eq!(extra_target(0, true, 6.0, Some(10.5)), 2, "rounds up");
        assert_eq!(extra_target(3, true, 0.0, Some(120.0)), 0, "no leases");
        let extra = extra_target(1, true, 60.0, Some(60.0));
        assert_eq!(target(5, 20, extra), 20, "max_ready caps it");
    }

    #[test]
    fn create_latency_seeds_then_moves_a_fifth() {
        let mut c = CreateLatency::default();
        assert_eq!(c.secs(), None);
        c.record(Duration::from_secs(10));
        assert_eq!(c.secs(), Some(10.0), "the first sample seeds it");
        c.record(Duration::from_secs(20));
        let avg = c.secs().unwrap_or_default();
        assert!((avg - 12.0).abs() < 1e-9, "{avg}");
        c.record(Duration::from_secs(2));
        let avg = c.secs().unwrap_or_default();
        assert!((avg - 10.0).abs() < 1e-9, "{avg}");
    }

    fn counts(ready_free: u64, leased: u64, creating: u64, reserved: u64) -> UnitCounts {
        UnitCounts {
            ready_free,
            degraded_free: 0,
            leased,
            creating,
            reserved,
        }
    }

    #[test]
    fn degraded_sessions_fill_room_but_not_the_target() {
        let with_degraded = |ready_free, degraded_free| UnitCounts {
            degraded_free,
            ..counts(ready_free, 0, 0, 0)
        };
        // 4 ready, 3 of them degraded: one normal session counts towards target 4.
        assert_eq!(need(4, 20, &with_degraded(4, 3)), 3);
        assert_eq!(need(4, 20, &with_degraded(4, 0)), 0);
        // max_ready still counts every ready session.
        assert_eq!(need(4, 5, &with_degraded(4, 3)), 1);
        assert_eq!(degraded_cap(8), 2);
        assert_eq!(degraded_cap(1), 1);
    }

    #[test]
    fn need_counts_ready_in_flight_and_reserved() {
        assert_eq!(need(10, 20, &counts(4, 0, 3, 2)), 1);
        assert_eq!(need(10, 20, &counts(4, 0, 3, 3)), 0);
        assert_eq!(need(10, 20, &counts(20, 0, 0, 0)), 0, "never negative");
    }

    #[test]
    fn need_never_goes_past_max_ready_counting_leased_sessions() {
        // 1 leased, min 2 = max 2: one free session already fills the cap.
        assert_eq!(need(2, 2, &counts(0, 1, 0, 0)), 1);
        assert_eq!(need(2, 2, &counts(1, 1, 0, 0)), 0);
        // Without the leased term the warmer would keep buying free sessions.
        assert_eq!(need(10, 12, &counts(0, 7, 0, 0)), 5);
        assert_eq!(need(10, 12, &counts(3, 7, 1, 0)), 1);
        assert_eq!(need(10, 12, &counts(3, 9, 0, 0)), 0, "over the cap");
    }

    #[test]
    fn starts_is_the_smallest_bound() {
        let base = Bounds {
            need: 10,
            refill_concurrency: 4,
            creating: 1,
            tokens: 50,
            creates_left: 50,
        };
        let with = |edit: fn(&mut Bounds)| {
            let mut b = base;
            edit(&mut b);
            starts(&b)
        };
        assert_eq!(starts(&base), 3, "concurrency minus in flight");
        assert_eq!(with(|b| b.tokens = 2), 2, "rate tokens");
        assert_eq!(with(|b| b.creates_left = 1), 1, "budget");
        assert_eq!(with(|b| b.need = 2), 2, "need");
        assert_eq!(with(|b| b.creating = 4), 0, "full");
        assert_eq!(with(|b| b.creating = 9), 0, "over full");
    }

    #[test]
    fn lease_rate_counts_growth_not_releases() {
        let t0 = Instant::now();
        let mut r = LeaseRate::default();
        assert!(r.per_minute().abs() < f64::EPSILON);
        r.observe(t0, 2);
        r.observe(t0 + Duration::from_secs(60), 5);
        r.observe(t0 + Duration::from_secs(120), 3);
        r.observe(t0 + Duration::from_secs(180), 4);
        // Growth 3 + 0 + 1 over 3 minutes.
        assert!(
            (r.per_minute() - 4.0 / 3.0).abs() < 1e-9,
            "{}",
            r.per_minute()
        );
    }

    #[test]
    fn lease_rate_forgets_old_samples() {
        let t0 = Instant::now();
        let mut r = LeaseRate::default();
        r.observe(t0, 0);
        r.observe(t0 + Duration::from_secs(10), 50);
        r.observe(t0 + Duration::from_secs(600), 50);
        r.observe(t0 + Duration::from_secs(660), 50);
        assert!(r.per_minute().abs() < f64::EPSILON);
    }
}
