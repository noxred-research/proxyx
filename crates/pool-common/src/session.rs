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
