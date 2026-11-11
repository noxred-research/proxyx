//! Session constants that the gateway and the warmer must agree on. Both
//! render the same provider credential from a session id and both compute the
//! deadlines of a unit record, so one definition here keeps them from drifting.

use std::time::Duration;

/// Provider session length for `ttl_minutes` when the adapter sets no maximum.
pub const DEFAULT_SESSION_MINUTES: u32 = 30;

/// A rotating unit record lives this long past its `max_age`.
pub const UNIT_MARGIN: Duration = Duration::from_secs(60);

/// Share of random extra time on the first keepalive of a session job, so
/// sessions created together do not all fall due together.
pub const JOB_JITTER: f64 = 0.2;

/// Bytes in a gigabyte of the daily and monthly budgets: providers bill
/// decimal GB, not GiB.
pub const BYTES_PER_GB: f64 = 1_000_000_000.0;

/// Whole bytes of a limit written in decimal GB, rounded to the nearest byte.
///
/// A decimal GB value is rarely an exact `f64` product (`0.0000077 * 1e9` is
/// `7700.000000000001`), so comparing a byte count with the raw product puts
/// "used == limit" on the wrong side of the limit. A negative or NaN limit is 0.
#[must_use]
pub fn gb_to_bytes(gb: f64) -> u64 {
    // `as` saturates and maps NaN to 0.
    (gb * BYTES_PER_GB).round().max(0.0) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_decimal_gb_limit_is_a_whole_number_of_bytes_even_when_the_product_drifts() {
        // These products are not whole in f64: 7700.000000000001 and 129999.99999999999.
        assert_ne!(0.000_007_7 * BYTES_PER_GB, 7_700.0);
        assert_eq!(gb_to_bytes(0.000_007_7), 7_700);
        assert_ne!(0.000_13 * BYTES_PER_GB, 130_000.0);
        assert_eq!(gb_to_bytes(0.000_13), 130_000);
        assert_eq!(gb_to_bytes(5.0), 5_000_000_000);
        assert_eq!(gb_to_bytes(0.0), 0);
        assert_eq!(gb_to_bytes(-1.0), 0);
        assert_eq!(gb_to_bytes(f64::NAN), 0);
    }
}
