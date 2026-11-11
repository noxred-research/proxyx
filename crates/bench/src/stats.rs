//! Latency recording and percentile summaries.

use std::time::Duration;

use hdrhistogram::Histogram;
use serde::Serialize;

/// Longest latency the histogram tracks: two minutes, in microseconds.
const MAX_US: u64 = 120_000_000;

/// A histogram of latencies with microsecond resolution and three significant
/// digits (0.1 % relative error). Values above two minutes are clamped.
#[derive(Clone)]
pub struct Latencies {
    hist: Histogram<u64>,
}

impl Default for Latencies {
    fn default() -> Self {
        Self::new()
    }
}

impl Latencies {
    pub fn new() -> Self {
        // 1 us .. 2 min at 3 significant digits: the bounds are valid, so
        // `new_with_bounds` cannot fail; the fallback keeps clippy's
        // `unwrap_used` satisfied without a panic path.
        let hist = Histogram::new_with_bounds(1, MAX_US, 3)
            .unwrap_or_else(|_| Histogram::new(2).expect("two significant digits are valid"));
        Self { hist }
    }

    /// Record one latency. Sub-microsecond values count as 1 us.
    pub fn record(&mut self, d: Duration) {
        let us = u64::try_from(d.as_micros()).unwrap_or(u64::MAX).max(1);
        self.hist.saturating_record(us);
    }

    /// Add every sample of `other`.
    pub fn merge(&mut self, other: &Latencies) {
        // Both histograms share the same bounds, so `add` cannot overflow.
        let _ = self.hist.add(&other.hist);
    }

    pub fn count(&self) -> u64 {
        self.hist.len()
    }

    /// Value at quantile `q` (0.0 to 1.0), in microseconds.
    pub fn quantile_us(&self, q: f64) -> u64 {
        self.hist.value_at_quantile(q)
    }

    pub fn summary(&self) -> LatencySummary {
        if self.hist.is_empty() {
            return LatencySummary::default();
        }
        LatencySummary {
            count: self.hist.len(),
            min_us: self.hist.min(),
            mean_us: self.hist.mean(),
            p50_us: self.hist.value_at_quantile(0.50),
            p95_us: self.hist.value_at_quantile(0.95),
            p99_us: self.hist.value_at_quantile(0.99),
            max_us: self.hist.max(),
        }
    }
}

/// Percentiles of one histogram, in microseconds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize)]
pub struct LatencySummary {
    pub count: u64,
    pub min_us: u64,
    pub mean_us: f64,
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
    pub max_us: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn empty_histogram_summarises_to_zeroes() {
        let l = Latencies::new();
        assert_eq!(l.count(), 0);
        assert_eq!(l.summary(), LatencySummary::default());
    }

    #[test]
    fn uniform_samples_give_the_expected_percentiles() {
        let mut l = Latencies::new();
        for n in 1..=1000 {
            l.record(ms(n));
        }
        let s = l.summary();
        assert_eq!(s.count, 1000);
        // three significant digits: 0.1 % of the value at most
        let near = |got: u64, want: u64| got.abs_diff(want) * 1000 <= want;
        assert!(near(s.p50_us, 500_000), "p50 {}", s.p50_us);
        assert!(near(s.p95_us, 950_000), "p95 {}", s.p95_us);
        assert!(near(s.p99_us, 990_000), "p99 {}", s.p99_us);
        assert!(near(s.max_us, 1_000_000), "max {}", s.max_us);
        assert!(near(s.min_us, 1_000), "min {}", s.min_us);
        assert!(
            (s.mean_us - 500_500.0).abs() < 1_000.0,
            "mean {}",
            s.mean_us
        );
    }

    #[test]
    fn a_single_slow_sample_is_only_visible_at_the_top() {
        let mut l = Latencies::new();
        for _ in 0..999 {
            l.record(ms(1));
        }
        l.record(ms(500));
        let s = l.summary();
        assert!(s.p99_us < 2_000, "p99 {}", s.p99_us);
        assert!(s.max_us >= 499_000, "max {}", s.max_us);
    }

    #[test]
    fn merging_equals_recording_everything_in_one_histogram() {
        let (mut a, mut b, mut both) = (Latencies::new(), Latencies::new(), Latencies::new());
        for n in 1..=500 {
            a.record(ms(n));
            both.record(ms(n));
        }
        for n in 501..=1000 {
            b.record(ms(n));
            both.record(ms(n));
        }
        a.merge(&b);
        assert_eq!(a.summary(), both.summary());
    }

    #[test]
    fn zero_and_huge_durations_are_clamped_not_dropped() {
        let mut l = Latencies::new();
        l.record(Duration::ZERO);
        l.record(Duration::from_secs(3600));
        assert_eq!(l.count(), 2);
        let s = l.summary();
        assert_eq!(s.min_us, 1);
        assert!(s.max_us >= 119_000_000, "max {}", s.max_us);
    }
}
