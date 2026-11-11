//! Fair-use traffic of a static IP per UTC month (`cost.fair_use_gb_per_ip_month`).
//!
//! The gateway counts the bytes of every tunnel on the IP
//! (`fair:{tag}:{ip}:{yyyymm}`, 35 days). At 80% of the limit the caller logs
//! a warning; at 100% this script sets `fairstop:{tag}:{ip}` until the month
//! ends, and the lease script leaves that IP out of every NEW lease. A lease
//! the IP already holds goes on. The next UTC month has a new counter and no
//! stop key, so the IP is leasable again.

use std::net::IpAddr;
use std::time::Duration;

use common::types::Partition;
use serde_json::json;
use time::{Date, Month, OffsetDateTime, Time};

use super::{Hot, ms};
use crate::error::{Result, StoreError};

/// A counter outlives its month by a few days, so a late read still sees it.
const COUNTER_TTL: Duration = Duration::from_secs(35 * 86_400);

/// What one [`Hot::fair_use_add`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FairUse {
    /// Bytes of the IP in the current month, this call included.
    pub used: u64,
    /// This call took the IP to 80% of its limit.
    pub warned: bool,
    /// This call took the IP to its limit: no new leases until the month ends.
    pub stopped: bool,
}

/// `yyyymm` of the UTC month containing `at`, and how long until the next
/// one starts.
fn month_of(at: OffsetDateTime) -> (String, Duration) {
    let at = at.to_offset(time::UtcOffset::UTC);
    let (year, month) = (at.year(), at.month());
    let (next_year, next_month) = if month == Month::December {
        (year + 1, Month::January)
    } else {
        (year, month.next())
    };
    let next = Date::from_calendar_date(next_year, next_month, 1)
        .map_or(at, |d| d.with_time(Time::MIDNIGHT).assume_utc());
    let left = Duration::try_from(next - at).unwrap_or(Duration::ZERO);
    (format!("{year}{:02}", u8::from(month)), left)
}

impl Hot {
    /// Count `bytes` of a static IP in the UTC month of `at` against
    /// `limit_bytes` (0: no limit, only counted).
    pub async fn fair_use_add(
        &self,
        p: &Partition,
        ip: IpAddr,
        bytes: u64,
        limit_bytes: u64,
        at: OffsetDateTime,
    ) -> Result<FairUse> {
        let (month, left) = month_of(at);
        let v: Vec<u64> = self
            .run_ready(
                &self.scripts.fair_use_add,
                p,
                json!({
                    "ip": ip.to_string(),
                    "month": month,
                    "bytes": bytes,
                    "limit": limit_bytes,
                    "warn_at": limit_bytes - limit_bytes / 5,
                    "stop_ms": ms(left),
                    "counter_ttl": ms(COUNTER_TTL),
                }),
            )
            .await?;
        match v[..] {
            [used, warned, stopped] => Ok(FairUse {
                used,
                warned: warned > 0,
                stopped: stopped > 0,
            }),
            _ => Err(StoreError::decode("fair use reply", format!("{v:?}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(y: i32, m: Month, d: u8, h: u8) -> OffsetDateTime {
        Date::from_calendar_date(y, m, d)
            .expect("date")
            .with_hms(h, 0, 0)
            .expect("time")
            .assume_utc()
    }

    #[test]
    fn a_month_ends_at_the_first_of_the_next_one_and_december_rolls_the_year() {
        let (key, left) = month_of(at(2026, Month::October, 31, 23));
        assert_eq!((key.as_str(), left), ("202610", Duration::from_secs(3600)));
        let (key, left) = month_of(at(2026, Month::December, 31, 12));
        assert_eq!(
            (key.as_str(), left),
            ("202612", Duration::from_secs(12 * 3600))
        );
        let (key, _) = month_of(at(2027, Month::January, 1, 0));
        assert_eq!(key, "202701");
    }
}
