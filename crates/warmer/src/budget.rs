//! The cost meter's decision: slow at 80% of a limit, stop at 100%,
//! resume when the window (UTC day for traffic, UTC hour for creates) ends.

use common::session::BYTES_PER_GB;
use policy::Cost;
use store::CostUsage;

/// Share of a limit at which the warmer only keeps `min_ready`.
const SLOW_AT: f64 = 0.8;

/// Bytes one create is charged against the byte limit before it runs: what
/// every create meters at least (its exit-IP check, [`EXIT_CHECK_BYTES`]). A
/// larger estimate would halt creates while the metered ratio, which drives
/// the 0.9 alert, is still well below the limit.
const CREATE_BYTES: u64 = EXIT_CHECK_BYTES;

/// Estimated bytes of one keepalive: one TLS request to the echo endpoint.
pub(crate) const KEEPALIVE_BYTES: u64 = 8 * 1024;

/// Estimated bytes of one exit-IP quorum check.
pub(crate) const EXIT_CHECK_BYTES: u64 = 24 * 1024;

/// What the budget allows the warmer to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Budget {
    Open,
    /// Create only up to `min_ready`, one at a time.
    Slow,
    /// Create nothing until the window resets.
    Stopped,
}

/// The state of one provider's budget.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Spend {
    /// The larger of the traffic and the create share, for the gauge.
    pub ratio: f64,
    pub budget: Budget,
    /// Creates the limits still pay for (smaller of count and bytes).
    pub creates_left: u64,
}

fn share(used: f64, limit: f64) -> f64 {
    if limit <= 0.0 { 1.0 } else { used / limit }
}

/// Judge `used` against `cost`. A limit of 0 is exhausted from the start.
pub(crate) fn assess(cost: &Cost, used: CostUsage) -> Spend {
    let byte_limit = cost.max_gb_per_day * BYTES_PER_GB;
    // Counts are far below 2^52, so the casts are exact.
    let bytes_ratio = share(used.bytes_today as f64, byte_limit);
    let creates_ratio = share(
        used.creates_this_hour as f64,
        f64::from(cost.max_creates_per_hour),
    );
    let ratio = bytes_ratio.max(creates_ratio);
    let budget = if ratio >= 1.0 {
        Budget::Stopped
    } else if ratio >= SLOW_AT {
        Budget::Slow
    } else {
        Budget::Open
    };
    let by_count = u64::from(cost.max_creates_per_hour).saturating_sub(used.creates_this_hour);
    let by_bytes = (byte_limit.max(0.0) as u64).saturating_sub(used.bytes_today) / CREATE_BYTES;
    Spend {
        ratio,
        budget,
        creates_left: by_count.min(by_bytes),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cost(gb: f64, creates: u32) -> Cost {
        Cost {
            max_gb_per_day: gb,
            max_creates_per_hour: creates,
            fair_use_gb_per_ip_month: 80.0,
        }
    }

    fn used(bytes: u64, creates: u64) -> CostUsage {
        CostUsage {
            bytes_today: bytes,
            creates_this_hour: creates,
        }
    }

    #[test]
    fn slows_at_eighty_percent_and_stops_at_one_hundred() {
        let c = cost(5.0, 100);
        assert_eq!(assess(&c, used(0, 79)).budget, Budget::Open);
        assert_eq!(assess(&c, used(0, 80)).budget, Budget::Slow);
        assert_eq!(assess(&c, used(0, 99)).budget, Budget::Slow);
        assert_eq!(assess(&c, used(0, 100)).budget, Budget::Stopped);
        assert_eq!(assess(&c, used(3_999_999_999, 0)).budget, Budget::Open);
        assert_eq!(assess(&c, used(4_000_000_000, 0)).budget, Budget::Slow);
        assert_eq!(assess(&c, used(5_000_000_000, 0)).budget, Budget::Stopped);
    }

    #[test]
    fn the_tighter_limit_decides_the_ratio() {
        let c = cost(5.0, 10);
        let s = assess(&c, used(1_000_000_000, 9));
        assert!((s.ratio - 0.9).abs() < 1e-9, "{s:?}");
        assert_eq!(s.budget, Budget::Slow);
        assert_eq!(s.creates_left, 1);
    }

    #[test]
    fn creates_left_is_bounded_by_bytes_too() {
        // Room for three creates and a bit.
        let limit = 3 * EXIT_CHECK_BYTES + 100;
        let c = cost(limit as f64 / BYTES_PER_GB, 1000);
        assert_eq!(assess(&c, used(0, 0)).creates_left, 3);
        assert_eq!(assess(&c, used(limit - 10, 0)).creates_left, 0);
    }

    #[test]
    fn creates_halt_only_when_the_metered_ratio_is_near_the_limit() {
        // With a small byte limit (0.0003 GB, as in the lab) the charge of a
        // create must not stop creation while the metered ratio, which the
        // 0.9 alert reads, is still far from the limit.
        let gb = 0.000_3;
        let c = cost(gb, 1_000_000);
        let limit = (gb * BYTES_PER_GB) as u64;
        let halted_at = (0..limit)
            .step_by(1024)
            .find(|bytes| assess(&c, used(*bytes, 0)).creates_left == 0)
            .expect("creates halt before the limit");
        let ratio = halted_at as f64 / (gb * BYTES_PER_GB);
        assert!(ratio > 0.9, "creates halted at ratio {ratio}");
    }

    #[test]
    fn a_zero_limit_is_exhausted() {
        assert_eq!(assess(&cost(0.0, 10), used(0, 0)).budget, Budget::Stopped);
        assert_eq!(assess(&cost(5.0, 0), used(0, 0)).budget, Budget::Stopped);
    }
}
