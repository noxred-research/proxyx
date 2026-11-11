//! Redis hot state: leases, ready sets, tunnel counters, reservations,
//! cooldowns, locks and the `due` set.
//!
//! Every key of one partition carries the hash tag `{partition.tag()}`, and
//! each decision that touches more than one key is one Lua script, so two
//! replicas cannot both exceed a cap. Every lease, tunnel, reservation, lock,
//! memo and claim has a TTL, so a crashed pod leaves nothing stuck. Three
//! keys have an owner instead: ready sets and static unit records
//! ([`Hot::unit_drop`]), the `due` set ([`Hot::due_done`]) and the org-block
//! hash (its fields carry their own expiry; the snapshot rebuild restores it).

mod affinity;
mod breaker;
mod create;
mod fair_use;
mod lease;
mod misc;
mod ops;
mod org_cost;
mod warm;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use common::types::{OrgId, Partition, Tier};
use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use redis::{Cmd, FromRedisValue, Pipeline, Script, ScriptInvocation, ToRedisArgs};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use time::OffsetDateTime;

use crate::error::{Result, StoreError};

pub use affinity::{AffinityRecord, AffinityStats};
pub use breaker::Admit;
pub use create::{RESERVATION_TTL, Reservation};
pub use fair_use::FairUse;
pub use lease::{
    Grant, LeaseLimits, LeaseOutcome, LeaseRequest, MAX_RANK, ReleaseRule, TunnelRef, sid_sticky,
};
pub use misc::{ExitIpClaim, FAILED_LEASE_MEMO_TTL};
pub use ops::{SampleJob, SessionRecord, Verdict};
pub use warm::{CostUsage, Swept};

const COMMON: &str = include_str!("lua/common.lua");
/// Seconds of a UTC day, shared by the cost meters of a provider and of an org.
pub(crate) const DAY_SECS: i64 = 86_400;
/// A meter key outlives its window by one window, so a late read still sees it.
pub(crate) const DAY_KEY_TTL: Duration = Duration::from_secs(2 * 86_400);
/// A closed tunnel is remembered this long, so a touch that was in flight
/// when it closed does not count it again. Such a touch ends within a few
/// replies of [`IO_TIMEOUT`] each.
pub(crate) const CLOSED_MARK_TTL: Duration = Duration::from_secs(30);
/// Set by [`Hot::mark_seeded`] after a rebuild from Postgres. The only key
/// outside a partition: no script touches it, so it needs no hash tag.
const SEEDED_KEY: &str = "pool:seeded";
/// Bound on connecting and on every reply, so no caller waits on a half-open
/// socket forever. The gateway puts a tighter bound on the tunnel path.
const IO_TIMEOUT: Duration = Duration::from_secs(5);
/// The manager's defaults retry six times with delays growing to a minute,
/// and every call waits for the reconnect, so a Redis outage would hang
/// callers for minutes. Two retries capped at one second bound it.
const RECONNECT_RETRIES: usize = 2;
const RECONNECT_MAX_DELAY_MS: u64 = 1_000;

/// How long a unit that failed a tunnel at IP level is leased last
/// ([`Hot::unit_failed`]); it doubles on every failure that follows, up to
/// [`UNIT_PENALTY_MAX`], which is also how long the failures are remembered
/// after a penalty ends.
pub const UNIT_PENALTY_BASE: Duration = Duration::from_secs(10);
pub const UNIT_PENALTY_MAX: Duration = Duration::from_secs(300);

/// A static IP or a rotating session that may be leased.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitRecord {
    /// Static: the IP as text. Rotating: the session id.
    pub id: String,
    /// The exit IP the gateway reports and cooldowns key on.
    pub ip: IpAddr,
    /// End of life of a rotating session (`max_age`); `None` for a static IP.
    pub expires_at: Option<OffsetDateTime>,
    /// TTL of the unit record. Rotating: the remaining life plus a margin.
    /// `None`: the record stays until dropped (static IPs).
    pub ttl: Option<Duration>,
    /// The only org that may lease this unit (a customer upstream); `None`:
    /// any org, subject to the policy.
    pub owner: Option<OrgId>,
}

impl UnitRecord {
    /// A static IP: the id is the address and nothing expires.
    pub fn static_ip(ip: IpAddr) -> Self {
        Self {
            id: ip.to_string(),
            ip,
            expires_at: None,
            ttl: None,
            owner: None,
        }
    }
}

/// How many units of a partition are in each phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnitCounts {
    /// Leasable units with no lease and no tunnel, of both tiers.
    pub ready_free: u64,
    /// Of `ready_free`, the units of the degraded tier.
    pub degraded_free: u64,
    /// Leasable units with a lease or a tunnel.
    pub leased: u64,
    /// Creates that started and are not ready yet.
    pub creating: u64,
    /// Reservations not yet turned into a create.
    pub reserved: u64,
}

/// What [`Hot::unit_retire`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retired {
    /// The unit was leasable until now.
    pub was_ready: bool,
    /// Nothing of the unit is left in Redis.
    pub forgotten: bool,
}

/// Load of one unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnitLoad {
    pub orgs: u64,
    pub leases: u64,
    pub tunnels: u64,
}

/// One `Script` per file of `lua/`, named after it, each with `common.lua` in
/// front.
macro_rules! scripts {
    ($($name:ident),+ $(,)?) => {
        struct Scripts {
            $($name: Script,)+
        }

        impl Scripts {
            fn new() -> Self {
                Self {
                    $($name: Script::new(&format!(
                        "{COMMON}\n{}",
                        include_str!(concat!("lua/", stringify!($name), ".lua"))
                    )),)+
                }
            }
        }
    };
}

scripts!(
    affinity,
    lease,
    release,
    tunnel_close,
    org_tunnel_close,
    tunnel_touch,
    traffic,
    unit_put,
    unit_tier,
    unit_strike,
    unit_drop,
    unit_load,
    counts,
    reserve,
    create_start,
    create_abort,
    lock_renew,
    lock_release,
    due_claim,
    exit_ip_claim,
    exit_ip_release,
    org_tunnel_open,
    provider_tunnel,
    org_tunnel_count,
    org_tunnel_touch,
    org_block_get,
    pin,
    sweep,
    fair_use_add,
    breaker,
    dial_failed,
);

/// Handle to the private ProxyX Redis. Cheap to clone.
#[derive(Clone)]
pub struct Hot {
    conn: ConnectionManager,
    scripts: Arc<Scripts>,
}

/// Hash tag of a partition, with braces: `{provider:region}`.
pub(crate) fn tag(p: &Partition) -> String {
    format!("{{{}}}", p.tag())
}

/// The set of leasable unit ids of a partition; the key every partition script is given.
pub(crate) fn ready_key(p: &Partition) -> String {
    format!("ready:{}", tag(p))
}

pub(crate) fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

pub(crate) fn unix_ms(t: OffsetDateTime) -> i64 {
    i64::try_from(t.unix_timestamp_nanos() / 1_000_000).unwrap_or(i64::MAX)
}

pub(crate) fn encode<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(|e| StoreError::Invalid(e.to_string()))
}

/// Queue `INCRBY key by` and `PEXPIRE key ttl` on `pipe`.
pub(crate) fn incr_px(pipe: &mut Pipeline, key: &str, by: u64, ttl: Duration) {
    pipe.cmd("INCRBY")
        .arg(key)
        .arg(by)
        .ignore()
        .cmd("PEXPIRE")
        .arg(key)
        .arg(ms(ttl))
        .ignore();
}

impl Hot {
    /// Connect and keep a reconnecting connection.
    pub async fn connect(url: &str) -> Result<Self> {
        Self::open(url, IO_TIMEOUT).await
    }

    async fn open(url: &str, timeout: Duration) -> Result<Self> {
        let client = redis::Client::open(url)?;
        let config = ConnectionManagerConfig::new()
            .set_connection_timeout(timeout)
            .set_response_timeout(timeout)
            .set_number_of_retries(RECONNECT_RETRIES)
            .set_max_delay(RECONNECT_MAX_DELAY_MS);
        let conn = ConnectionManager::new_with_config(client, config).await?;
        Ok(Self {
            conn,
            scripts: Arc::new(Scripts::new()),
        })
    }

    pub(crate) fn conn(&self) -> ConnectionManager {
        self.conn.clone()
    }

    pub(crate) async fn cmd<T: FromRedisValue>(&self, cmd: &Cmd) -> Result<T> {
        Ok(cmd.query_async(&mut self.conn()).await?)
    }

    pub(crate) async fn invoke<T: FromRedisValue>(&self, call: &ScriptInvocation<'_>) -> Result<T> {
        Ok(call.invoke_async(&mut self.conn()).await?)
    }

    pub(crate) async fn pipe<T: FromRedisValue>(&self, pipe: &Pipeline) -> Result<T> {
        Ok(pipe.query_async(&mut self.conn()).await?)
    }

    /// Parse the JSON stored under `key`, `None` for a missing key.
    pub(crate) async fn get_json<T: DeserializeOwned>(
        &self,
        key: String,
        what: &'static str,
    ) -> Result<Option<T>> {
        let body: Option<String> = self.cmd(redis::cmd("GET").arg(key)).await?;
        body.map(|b| serde_json::from_str(&b).map_err(|e| StoreError::decode(what, e)))
            .transpose()
    }

    /// `SET key value PX ttl`.
    pub(crate) async fn set_px(
        &self,
        key: String,
        value: impl ToRedisArgs,
        ttl: Duration,
    ) -> Result<()> {
        self.cmd(redis::cmd("SET").arg(key).arg(value).arg("PX").arg(ms(ttl)))
            .await
    }

    /// `SET key value NX PX ttl`; true when this call set the key.
    pub(crate) async fn set_nx_px(
        &self,
        key: String,
        value: impl ToRedisArgs,
        ttl: Duration,
    ) -> Result<bool> {
        let set: Option<String> = self
            .cmd(
                redis::cmd("SET")
                    .arg(key)
                    .arg(value)
                    .arg("NX")
                    .arg("PX")
                    .arg(ms(ttl)),
            )
            .await?;
        Ok(set.is_some())
    }

    pub(crate) async fn run<T: FromRedisValue>(
        &self,
        script: &Script,
        key: &str,
        args: &Value,
    ) -> Result<T> {
        self.invoke(script.key(key).arg(args.to_string())).await
    }

    /// Run a partition script: key `ready:{tag}`, `args` plus the tag.
    pub(crate) async fn run_ready<T: FromRedisValue>(
        &self,
        script: &Script,
        p: &Partition,
        mut args: Value,
    ) -> Result<T> {
        args["tag"] = tag(p).into();
        self.run(script, &ready_key(p), &args).await
    }

    pub async fn ping(&self) -> Result<()> {
        self.cmd(&redis::cmd("PING")).await
    }

    /// True when [`Hot::mark_seeded`] ran and Redis has not lost its data
    /// since. The warmer rebuilds from Postgres when this is false.
    pub async fn is_seeded(&self) -> Result<bool> {
        self.cmd(redis::cmd("EXISTS").arg(SEEDED_KEY)).await
    }

    pub async fn mark_seeded(&self) -> Result<()> {
        self.cmd(
            redis::cmd("SET")
                .arg(SEEDED_KEY)
                .arg(unix_ms(OffsetDateTime::now_utc())),
        )
        .await
    }

    /// Make a unit leasable in the normal tier (or refresh its record).
    /// Lease history and tunnels of an existing unit stay. A rotating session
    /// leaves the in-flight set.
    pub async fn ready_put(&self, p: &Partition, unit: &UnitRecord) -> Result<()> {
        self.ready_put_tier(p, unit, Tier::Normal).await
    }

    /// [`Hot::ready_put`] in `tier`: a degraded unit stays in the ready set
    /// and is leased only when no normal unit is left.
    pub async fn ready_put_tier(&self, p: &Partition, unit: &UnitRecord, tier: Tier) -> Result<()> {
        self.put_unit(p, unit, tier, false).await.map(|_| ())
    }

    /// Refresh the record of a unit that is leasable now (a session that
    /// moved to a new exit IP), and do nothing for one that left the ready
    /// set meanwhile (drained by a block, a canary or the release rule):
    /// it must not come back. Returns whether the unit was written.
    pub async fn ready_update(&self, p: &Partition, unit: &UnitRecord, tier: Tier) -> Result<bool> {
        self.put_unit(p, unit, tier, true).await
    }

    async fn put_unit(
        &self,
        p: &Partition,
        unit: &UnitRecord,
        tier: Tier,
        if_ready: bool,
    ) -> Result<bool> {
        let args = json!({
            "id": unit.id,
            "ip": unit.ip.to_string(),
            "expires_at": unit.expires_at.map_or(0, unix_ms),
            "ttl": unit.ttl.map_or(0, ms),
            "owner": unit.owner.as_ref().map_or("", OrgId::as_str),
            "degraded": tier == Tier::Degraded,
            "if_ready": if_ready,
        });
        let written: i64 = self.run_ready(&self.scripts.unit_put, p, args).await?;
        Ok(written > 0)
    }

    /// Move a leasable unit to `tier` without touching anything else. Does
    /// nothing for a unit that has no record. Returns whether it had one.
    pub async fn set_tier(&self, p: &Partition, id: &str, tier: Tier) -> Result<bool> {
        let args = json!({ "id": id, "degraded": tier == Tier::Degraded });
        self.run_ready(&self.scripts.unit_tier, p, args).await
    }

    /// A tunnel failed on a unit at IP level: the unit is leased after every
    /// other one for `base`, twice that when it failed again within `max` of
    /// its last penalty ending, and so on up to `max` (`lease.lua`, Failed
    /// units; the gateway passes [`UNIT_PENALTY_BASE`] and
    /// [`UNIT_PENALTY_MAX`]). The unit stays leasable: it is the last resort,
    /// and its penalty ends by itself. Does nothing for a unit that has no
    /// record. Returns the penalty set.
    pub async fn unit_failed(
        &self,
        p: &Partition,
        id: &str,
        base: Duration,
        max: Duration,
    ) -> Result<Duration> {
        self.unit_strike(p, id, "fail", base, max).await
    }

    /// The unit served a tunnel: forget its failures ([`Hot::unit_failed`]).
    pub async fn unit_served(&self, p: &Partition, id: &str) -> Result<()> {
        self.unit_strike(p, id, "ok", Duration::ZERO, Duration::ZERO)
            .await
            .map(|_| ())
    }

    async fn unit_strike(
        &self,
        p: &Partition,
        id: &str,
        op: &str,
        base: Duration,
        max: Duration,
    ) -> Result<Duration> {
        let args = json!({ "id": id, "op": op, "base": ms(base), "max": ms(max) });
        let penalty: u64 = self.run_ready(&self.scripts.unit_strike, p, args).await?;
        Ok(Duration::from_millis(penalty))
    }

    /// The tier of a unit; normal for one without a record.
    pub async fn tier(&self, p: &Partition, id: &str) -> Result<Tier> {
        let tier: Option<String> = self
            .cmd(
                redis::cmd("HGET")
                    .arg(format!("unit:{}:{id}", tag(p)))
                    .arg("tier"),
            )
            .await?;
        Ok(match tier.as_deref() {
            Some("degraded") => Tier::Degraded,
            _ => Tier::Normal,
        })
    }

    /// Stop leasing a unit (cooldown, quarantine, drain). Existing leases
    /// fail their next renew; open tunnels are not touched. Returns whether
    /// the unit was leasable.
    pub async fn ready_take(&self, p: &Partition, id: &str) -> Result<bool> {
        self.cmd(redis::cmd("SREM").arg(ready_key(p)).arg(id)).await
    }

    /// Forget a unit and its lease and tunnel records.
    pub async fn unit_drop(&self, p: &Partition, id: &str) -> Result<bool> {
        self.run_ready(&self.scripts.unit_drop, p, json!({ "id": id }))
            .await
    }

    /// Take a unit out of leasing and forget its record once no tunnel uses
    /// it (a retired IP, or one listed in another partition now). A unit
    /// with tunnels keeps its record: call this again until `forgotten`.
    pub async fn unit_retire(&self, p: &Partition, id: &str) -> Result<Retired> {
        let was_ready = self.ready_take(p, id).await?;
        let has_record: bool = self
            .cmd(redis::cmd("EXISTS").arg(format!("unit:{}:{id}", tag(p))))
            .await?;
        let forgotten = !has_record
            || (self.unit_load(p, id).await?.tunnels == 0 && {
                self.unit_drop(p, id).await?;
                true
            });
        Ok(Retired {
            was_ready,
            forgotten,
        })
    }

    /// Ids of the leasable units of a partition.
    pub async fn ready_ids(&self, p: &Partition) -> Result<Vec<String>> {
        let mut ids: Vec<String> = self.cmd(redis::cmd("SMEMBERS").arg(ready_key(p))).await?;
        ids.sort();
        Ok(ids)
    }

    /// Counts for the warmer loop and metrics.
    pub async fn counts(&self, p: &Partition) -> Result<UnitCounts> {
        let v: Vec<u64> = self.run_ready(&self.scripts.counts, p, json!({})).await?;
        match v[..] {
            [ready_free, degraded_free, leased, creating, reserved] => Ok(UnitCounts {
                ready_free,
                degraded_free,
                leased,
                creating,
                reserved,
            }),
            _ => Err(StoreError::decode("counts reply", format!("{v:?}"))),
        }
    }

    /// Orgs, leases and open tunnels of one unit.
    pub async fn unit_load(&self, p: &Partition, id: &str) -> Result<UnitLoad> {
        let v: Vec<u64> = self
            .run_ready(&self.scripts.unit_load, p, json!({ "id": id }))
            .await?;
        match v[..] {
            [orgs, leases, tunnels] => Ok(UnitLoad {
                orgs,
                leases,
                tunnels,
            }),
            _ => Err(StoreError::decode("load reply", format!("{v:?}"))),
        }
    }

    /// Add bytes to the 5-minute traffic window of a unit (the third
    /// tie-break when sharing) and mark it used now.
    pub async fn record_traffic(&self, p: &Partition, unit: &str, bytes: u64) -> Result<()> {
        self.run_ready::<i64>(
            &self.scripts.traffic,
            p,
            json!({ "unit": unit, "bytes": bytes }),
        )
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tokio::net::TcpListener;

    use super::*;

    #[tokio::test]
    async fn a_redis_that_never_answers_fails_the_call_instead_of_hanging() {
        let silent = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let url = format!("redis://{}", silent.local_addr().expect("local addr"));
        let holder = tokio::spawn(async move {
            let _socket = silent.accept().await;
            std::future::pending::<()>().await;
        });

        let outcome = tokio::time::timeout(Duration::from_secs(30), async {
            let hot = Hot::open(&url, Duration::from_millis(200)).await?;
            hot.ping().await
        })
        .await;
        holder.abort();

        assert!(matches!(outcome, Ok(Err(_))), "{outcome:?}");
    }
}
