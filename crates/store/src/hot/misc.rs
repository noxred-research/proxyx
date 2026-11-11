//! Cooldowns, org-block cache, failed-lease memo, partition lock, `due`
//! set, duplicate exit IP and the per-org tunnel counter.

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::time::Duration;

use common::Cause;
use common::types::{OrgId, Partition, Target};
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{CLOSED_MARK_TTL, Hot, ms, tag, unix_ms};
use crate::db::{BlockScope, OrgBlock, merged_org_blocks};
use crate::error::{Result, StoreError, ensure};
use crate::session_job::{Phase, SessionJob};

/// A failed lease is remembered this long, so retries do not multiply
/// creates.
pub const FAILED_LEASE_MEMO_TTL: Duration = Duration::from_secs(5);

/// Value of a cooldown that no failed tunnel set (a block signal, a rebuild).
/// `lease.lua` tells it from the cause code of a failure by this value.
const PLAIN_COOLDOWN: &str = "1";

/// Result of [`Hot::claim_exit_ip`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitIpClaim {
    /// The session owns the exit IP.
    Claimed,
    /// Another session already has this exit IP: the new one is a duplicate
    /// and must drain.
    Duplicate { owner: String },
}

fn cool_key(p: &Partition, ip: IpAddr, target: &Target) -> String {
    format!("cool:{}:{ip}:{}", tag(p), target.host.to_ascii_lowercase())
}

fn org_block_key(org: &OrgId) -> String {
    format!("orgblock:{{{org}}}")
}

fn lock_key(p: &Partition) -> String {
    format!("lock:{}", tag(p))
}

fn memo_key(org: &OrgId, sticky: &str) -> String {
    format!("memo:{{{org}}}:{sticky}")
}

fn org_tunnel_key(org: &OrgId) -> String {
    format!("orgtun:{{{org}}}")
}

/// Marker that a tunnel was closed; same hash tag as [`org_tunnel_key`].
fn org_tunnel_closed_key(org: &OrgId, tunnel: Uuid) -> String {
    format!("orgtunx:{{{org}}}:{tunnel}")
}

/// Key of an applied-event mark ([`Hot::event_done`]).
fn event_key(key: &str) -> String {
    format!("done:{key}")
}

impl Hot {
    /// Has the event `key` been marked by [`Hot::event_done`]? A caller that
    /// can be retried in the middle of a list (a batch of block signals)
    /// asks before it applies an event and marks it after, so a retry does
    /// not apply the events that went through the first time again.
    pub async fn event_seen(&self, key: &str) -> Result<bool> {
        self.cmd(redis::cmd("EXISTS").arg(event_key(key))).await
    }

    /// Mark the event `key` applied; it is remembered for `ttl`.
    ///
    /// Fails with `StoreError::Invalid` for an empty key or a zero `ttl`.
    pub async fn event_done(&self, key: &str, ttl: Duration) -> Result<()> {
        ensure(
            !key.is_empty() && !ttl.is_zero(),
            "an event mark needs a key and a ttl above zero",
        )?;
        self.set_px(event_key(key), 1, ttl).await
    }

    /// Cool an IP for one target: leases for that target skip the IP for
    /// `ttl` (`cool:{ip}:{target}`); other targets keep it.
    ///
    /// Refuses a zero `ttl`.
    pub async fn cool_target(
        &self,
        p: &Partition,
        ip: IpAddr,
        target: &Target,
        ttl: Duration,
    ) -> Result<()> {
        self.cool(p, ip, target, ttl, PLAIN_COOLDOWN).await
    }

    /// [`Hot::cool_target`] for an IP whose tunnel to the target just failed
    /// with `cause`. When every unit of a partition is cooled this way, a lease
    /// answers [`LeaseOutcome::Cooled`](super::LeaseOutcome::Cooled) with the
    /// latest cause, so the client hears why at once instead of waiting.
    pub async fn cool_target_failed(
        &self,
        p: &Partition,
        ip: IpAddr,
        target: &Target,
        ttl: Duration,
        cause: Cause,
    ) -> Result<()> {
        self.cool(p, ip, target, ttl, cause.code()).await
    }

    async fn cool(
        &self,
        p: &Partition,
        ip: IpAddr,
        target: &Target,
        ttl: Duration,
        value: &str,
    ) -> Result<()> {
        ensure(!ttl.is_zero(), "cooldown ttl must be above zero")?;
        self.set_px(cool_key(p, ip, target), value, ttl).await
    }

    pub async fn is_cooled(&self, p: &Partition, ip: IpAddr, target: &Target) -> Result<bool> {
        self.cmd(redis::cmd("EXISTS").arg(cool_key(p, ip, target)))
            .await
    }

    /// Forget the cooldowns a failed tunnel set on `ip` for every target
    /// (`cool:{ip}:*` holding a cause code). The login of a unit changed, so
    /// those failures say nothing about the new one. A cooldown
    /// a block signal set stays. Returns how many were removed.
    pub async fn cool_clear_failed(&self, p: &Partition, ip: IpAddr) -> Result<u64> {
        let pattern = format!("cool:{}:{ip}:*", tag(p));
        let mut cursor = 0u64;
        let mut cleared = 0u64;
        loop {
            let (next, keys): (u64, Vec<String>) = self
                .cmd(
                    redis::cmd("SCAN")
                        .arg(cursor)
                        .arg("MATCH")
                        .arg(&pattern)
                        .arg("COUNT")
                        .arg(1000),
                )
                .await?;
            for key in keys {
                let value: Option<String> = self.cmd(redis::cmd("GET").arg(&key)).await?;
                if value.is_some_and(|v| v != PLAIN_COOLDOWN) {
                    let n: u64 = self.cmd(redis::cmd("DEL").arg(&key)).await?;
                    cleared += n;
                }
            }
            if next == 0 {
                return Ok(cleared);
            }
            cursor = next;
        }
    }

    /// Cache an org block. `expires_at` `None` blocks until cleared.
    pub async fn org_block_set(
        &self,
        org: &OrgId,
        scope: &BlockScope,
        expires_at: Option<OffsetDateTime>,
    ) -> Result<()> {
        self.cmd(
            redis::cmd("HSET")
                .arg(org_block_key(org))
                .arg(scope.field())
                .arg(expires_at.map_or(0, unix_ms)),
        )
        .await
    }

    pub async fn org_block_clear(&self, org: &OrgId, scope: &BlockScope) -> Result<bool> {
        self.cmd(
            redis::cmd("HDEL")
                .arg(org_block_key(org))
                .arg(scope.field()),
        )
        .await
    }

    /// Make the cached field of `org` and `scope` match the **active** blocks
    /// `active` (from Postgres, after the write that changed them): the latest
    /// expiry of the blocks of that pair, never expiring when one has none, and
    /// no field when none is left. Idempotent, so a failed call can be repeated.
    pub async fn org_block_sync(
        &self,
        org: &OrgId,
        scope: &BlockScope,
        active: &[OrgBlock],
    ) -> Result<()> {
        let own: Vec<OrgBlock> = active
            .iter()
            .filter(|b| b.org == *org && b.scope == *scope)
            .cloned()
            .collect();
        match merged_org_blocks(&own).into_iter().next() {
            Some((_, _, expires_at)) => self.org_block_set(org, scope, expires_at).await,
            None => self.org_block_clear(org, scope).await.map(|_| ()),
        }
    }

    /// Live block fields of an org (`ip:1.2.3.4`, `provider:x`,
    /// `route_class:x:fr`, `pool:shared`); expired ones are dropped.
    pub async fn org_blocks(&self, org: &OrgId) -> Result<Vec<String>> {
        self.run(&self.scripts.org_block_get, &org_block_key(org), &json!({}))
            .await
    }

    /// Remember that a lease failed with `cause` for 5 seconds.
    pub async fn memo_failed_lease(&self, org: &OrgId, sticky: &str, cause: Cause) -> Result<()> {
        self.set_px(memo_key(org, sticky), cause.code(), FAILED_LEASE_MEMO_TTL)
            .await
    }

    /// The remembered failure of the last 5 seconds, if any.
    ///
    /// A memo that holds an unknown code is an error.
    pub async fn failed_lease(&self, org: &OrgId, sticky: &str) -> Result<Option<Cause>> {
        let code: Option<String> = self
            .cmd(redis::cmd("GET").arg(memo_key(org, sticky)))
            .await?;
        code.map(|c| {
            Cause::ALL
                .into_iter()
                .find(|k| k.code() == c)
                .ok_or_else(|| StoreError::decode("lease memo", c))
        })
        .transpose()
    }

    /// Record that the dial through static unit `unit` of `p` failed. Returns
    /// how many distinct units of the partition failed one within `window`,
    /// this one included: one or two is a bad unit, more is the provider.
    pub async fn dial_failed(&self, p: &Partition, unit: &str, window: Duration) -> Result<u64> {
        self.run_ready(
            &self.scripts.dial_failed,
            p,
            json!({ "unit": unit, "window": ms(window) }),
        )
        .await
    }

    /// Take the partition lock for `ttl` (`SET NX PX`). Only the holder
    /// starts creates, retests and rotations.
    pub async fn lock_acquire(&self, p: &Partition, holder: &str, ttl: Duration) -> Result<bool> {
        self.set_nx_px(lock_key(p), holder, ttl).await
    }

    /// Extend the lock if `holder` still owns it.
    pub async fn lock_renew(&self, p: &Partition, holder: &str, ttl: Duration) -> Result<bool> {
        self.invoke(
            self.scripts
                .lock_renew
                .key(lock_key(p))
                .arg(holder)
                .arg(ms(ttl)),
        )
        .await
    }

    /// Release the lock if `holder` still owns it.
    pub async fn lock_release(&self, p: &Partition, holder: &str) -> Result<bool> {
        self.invoke(self.scripts.lock_release.key(lock_key(p)).arg(holder))
            .await
    }

    /// Schedule (or reschedule) a check job at `at`. The set has no TTL: a
    /// job stays until [`Hot::due_done`]; the warmer's keepalive loop
    /// reschedules a live session and ends the rest.
    pub async fn due_schedule(&self, job: &str, at: OffsetDateTime) -> Result<()> {
        self.cmd(redis::cmd("ZADD").arg("due").arg(unix_ms(at)).arg(job))
            .await
    }

    /// Claim up to `limit` jobs that are due. A claimed job comes back after
    /// `visibility` unless [`Hot::due_done`] removes it, so a crashed
    /// claimer loses nothing.
    pub async fn due_claim(&self, limit: u32, visibility: Duration) -> Result<Vec<String>> {
        self.invoke(
            self.scripts
                .due_claim
                .key("due")
                .arg(limit)
                .arg(ms(visibility)),
        )
        .await
    }

    pub async fn due_done(&self, job: &str) -> Result<bool> {
        self.cmd(redis::cmd("ZREM").arg("due").arg(job)).await
    }

    /// How many rotating sessions wait in the `due` set to be drained (no
    /// longer leasable, tunnels still open). The sessions of every partition.
    pub async fn draining_sessions(&self) -> Result<u64> {
        let mut cursor = 0u64;
        let mut draining = 0u64;
        loop {
            let (next, members): (u64, Vec<String>) = self
                .cmd(
                    redis::cmd("ZSCAN")
                        .arg("due")
                        .arg(cursor)
                        .arg("COUNT")
                        .arg(1000),
                )
                .await?;
            // ZSCAN replies member, score, member, score ...
            draining += members
                .iter()
                .step_by(2)
                .filter_map(|m| SessionJob::parse(m))
                .filter(|job| matches!(job.phase, Phase::Drain { .. }))
                .count() as u64;
            if next == 0 {
                return Ok(draining);
            }
            cursor = next;
        }
    }

    /// Mark the exit IP as owned by `session` for `ttl` (`ip:{ip}` NX). A
    /// second session with the same exit IP is a duplicate and must drain.
    pub async fn claim_exit_ip(
        &self,
        ip: IpAddr,
        session: &str,
        ttl: Duration,
    ) -> Result<ExitIpClaim> {
        let owner: String = self
            .invoke(
                self.scripts
                    .exit_ip_claim
                    .key(format!("ip:{ip}"))
                    .arg(session)
                    .arg(ms(ttl)),
            )
            .await?;
        Ok(if owner.is_empty() {
            ExitIpClaim::Claimed
        } else {
            ExitIpClaim::Duplicate { owner }
        })
    }

    pub async fn release_exit_ip(&self, ip: IpAddr, session: &str) -> Result<bool> {
        self.invoke(
            self.scripts
                .exit_ip_release
                .key(format!("ip:{ip}"))
                .arg(session),
        )
        .await
    }

    /// Count a tunnel of `org` against `max_tunnels_per_org` (`None`: no
    /// cap). Returns false when the org is at the cap (`503 org_capacity`).
    /// Counting the same tunnel again only refreshes it. [`Hot::tunnel_close`]
    /// removes it; call [`Hot::org_tunnel_close`] when the tunnel never
    /// opened.
    pub async fn org_tunnel_open(
        &self,
        org: &OrgId,
        tunnel: Uuid,
        cap: Option<NonZeroU32>,
        ttl: Duration,
    ) -> Result<bool> {
        self.invoke(
            self.scripts
                .org_tunnel_open
                .key(org_tunnel_key(org))
                .arg(tunnel.to_string())
                .arg(cap.map_or(0, NonZeroU32::get))
                .arg(ms(ttl)),
        )
        .await
    }

    /// Stop counting a tunnel of `org`. A touch that is still in flight does
    /// not count it again.
    pub async fn org_tunnel_close(&self, org: &OrgId, tunnel: Uuid) -> Result<()> {
        self.invoke::<i64>(
            self.scripts
                .org_tunnel_close
                .key(org_tunnel_key(org))
                .key(org_tunnel_closed_key(org, tunnel))
                .arg(tunnel.to_string())
                .arg(ms(CLOSED_MARK_TTL)),
        )
        .await?;
        Ok(())
    }

    /// Extend a counted tunnel, counting it again when the zset lost it.
    /// False when the tunnel was closed.
    pub(crate) async fn org_tunnel_touch(
        &self,
        org: &OrgId,
        tunnel: Uuid,
        ttl: Duration,
    ) -> Result<bool> {
        self.invoke(
            self.scripts
                .org_tunnel_touch
                .key(org_tunnel_key(org))
                .key(org_tunnel_closed_key(org, tunnel))
                .arg(tunnel.to_string())
                .arg(ms(ttl)),
        )
        .await
    }

    /// Open tunnels of an org.
    pub async fn org_tunnel_count(&self, org: &OrgId) -> Result<u64> {
        self.invoke(&self.scripts.org_tunnel_count.key(org_tunnel_key(org)))
            .await
    }
}
