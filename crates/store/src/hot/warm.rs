//! Warmer helpers: the cost meter, the stuck-state sweep, a membership test
//! and a once-per-window claim.

use std::time::Duration;

use common::types::{OrgId, Partition, ProviderId};
use serde_json::json;
use time::OffsetDateTime;

use super::{DAY_KEY_TTL, DAY_SECS, Hot, ReleaseRule, UnitLoad, incr_px, ms, ready_key};
use crate::error::{Result, StoreError, ensure};

const HOUR_SECS: i64 = 3_600;
const HOUR_KEY_TTL: Duration = Duration::from_secs(2 * 3_600);

/// What one [`Hot::sweep`] reclaimed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Swept {
    /// Creates that outlived twice `create_deadline`, and ready ids whose
    /// unit record is gone.
    pub sessions: u64,
    /// Reservations past their 120 s.
    pub reservations: u64,
    /// Lease fields past their expiry.
    pub leases: u64,
}

/// Spend of one provider in the current windows.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CostUsage {
    /// Bytes counted in the current UTC day.
    pub bytes_today: u64,
    /// Creates started in the current UTC hour.
    pub creates_this_hour: u64,
}

fn day_key(provider: &ProviderId, at: OffsetDateTime) -> String {
    format!(
        "cost:{{{provider}}}:bytes:{}",
        at.unix_timestamp().div_euclid(DAY_SECS)
    )
}

fn hour_key(provider: &ProviderId, at: OffsetDateTime) -> String {
    format!(
        "cost:{{{provider}}}:creates:{}",
        at.unix_timestamp().div_euclid(HOUR_SECS)
    )
}

impl Hot {
    /// Bind a ready unit to an org's sticky key without opening a tunnel, so
    /// the org's next [`Hot::lease_ranked`] for that key gets exactly this unit
    /// (a `HIT`). The warmer reserves a browser-sample candidate for the
    /// probe org this way. Returns false when the unit is not leasable.
    ///
    /// Fails with `StoreError::Invalid` for an empty sticky key or a zero
    /// ttl.
    pub async fn lease_pin(
        &self,
        p: &Partition,
        org: &OrgId,
        sticky: &str,
        unit: &str,
        ttl: Duration,
    ) -> Result<bool> {
        ensure(
            !sticky.is_empty() && !ttl.is_zero(),
            "a pinned lease needs a sticky key and a ttl above zero",
        )?;
        self.run_ready(
            &self.scripts.pin,
            p,
            json!({ "org": org.as_str(), "sticky": sticky, "unit": unit, "ttl": ms(ttl) }),
        )
        .await
    }

    /// Reclaim stuck state of one partition and say how much. For a rotating
    /// partition `after` applies `rotating.after_release` to every session
    /// that was leased and now has no lease and no tunnel.
    pub async fn sweep(&self, p: &Partition, after: Option<ReleaseRule<'_>>) -> Result<Swept> {
        let mut args = json!({});
        if let Some(rule) = after {
            args["after"] = rule.mode().into();
            args["probe_org"] = rule.probe_org.as_str().into();
        }
        let v: Vec<u64> = self.run_ready(&self.scripts.sweep, p, args).await?;
        match v[..] {
            [sessions, reservations, leases] => Ok(Swept {
                sessions,
                reservations,
                leases,
            }),
            _ => Err(StoreError::decode("sweep reply", format!("{v:?}"))),
        }
    }

    /// True when `id` is in the ready set of the partition (rotating
    /// session or static IP is leasable).
    pub async fn is_ready(&self, p: &Partition, id: &str) -> Result<bool> {
        self.cmd(redis::cmd("SISMEMBER").arg(ready_key(p)).arg(id))
            .await
    }

    /// [`Hot::unit_load`] without the leases of `skip_leases_of`: the probe
    /// org's sample pin is a reservation, not use. Its open tunnels still
    /// count, so a sample that is running keeps its session in use.
    pub async fn unit_load_without_pins(
        &self,
        p: &Partition,
        id: &str,
        skip_leases_of: &OrgId,
    ) -> Result<UnitLoad> {
        let args = json!({ "id": id, "skip_leases_of": skip_leases_of.as_str() });
        let v: Vec<u64> = self.run_ready(&self.scripts.unit_load, p, args).await?;
        match v[..] {
            [orgs, leases, tunnels] => Ok(UnitLoad {
                orgs,
                leases,
                tunnels,
            }),
            _ => Err(StoreError::decode("load reply", format!("{v:?}"))),
        }
    }

    /// Count bytes (a day window) and creates (an hour window) against the
    /// provider's budget. Gateway and warmer replicas share the counters.
    pub async fn cost_add(
        &self,
        provider: &ProviderId,
        bytes: u64,
        creates: u64,
        at: OffsetDateTime,
    ) -> Result<()> {
        let mut pipe = redis::pipe();
        if bytes > 0 {
            incr_px(&mut pipe, &day_key(provider, at), bytes, DAY_KEY_TTL);
        }
        if creates > 0 {
            incr_px(&mut pipe, &hour_key(provider, at), creates, HOUR_KEY_TTL);
        }
        self.pipe(&pipe).await
    }

    /// The provider's spend in the windows that contain `at`.
    pub async fn cost_used(&self, provider: &ProviderId, at: OffsetDateTime) -> Result<CostUsage> {
        let (bytes, creates): (Option<u64>, Option<u64>) = self
            .pipe(
                redis::pipe()
                    .cmd("GET")
                    .arg(day_key(provider, at))
                    .cmd("GET")
                    .arg(hour_key(provider, at)),
            )
            .await?;
        Ok(CostUsage {
            bytes_today: bytes.unwrap_or(0),
            creates_this_hour: creates.unwrap_or(0),
        })
    }

    /// Take a named once-per-`ttl` slot (`SET NX PX`). True for the first
    /// caller in the window, false for every later one. The warmer uses it
    /// to emit a replacement report once per day per IP across replicas.
    ///
    /// Fails with `StoreError::Invalid` for an empty key or a zero ttl.
    pub async fn claim_once(&self, key: &str, ttl: Duration) -> Result<bool> {
        ensure(
            !key.is_empty() && !ttl.is_zero(),
            "a once-claim needs a key and a ttl above zero",
        )?;
        self.set_nx_px(format!("once:{key}"), 1, ttl).await
    }
}
