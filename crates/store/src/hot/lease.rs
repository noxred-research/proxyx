//! Leasing: the Lua scripts that hand an exit IP to an org and track its tunnels.
//! Every key of one partition shares a hash tag, so each script is atomic.

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::time::Duration;

use common::Cause;
use common::types::{Kind, OrgId, Partition, ProviderId, Target};
use policy::{AfterRelease, Pool};
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{CLOSED_MARK_TTL, Hot, ms, tag};
use crate::error::{Result, StoreError, ensure};

/// How long the org's previous static IP is remembered.
const PREV_TTL: Duration = Duration::from_secs(24 * 3600);
/// A lease younger than this does not move to another unit: a
/// client holding `px-sid-*` keeps its exit IP for at least this long.
const MIN_LEASE_DWELL: Duration = Duration::from_secs(60);

/// The rank of the lowest unit a lease may take: a unit that failed a tunnel at
/// IP level a moment ago ([`Hot::unit_failed`]). `lease.lua` ranks the units
/// of a partition 0 (normal, within the limits), 1 (degraded, within the
/// limits), 2 to 5 (normal, breaking `rest`, `orgs_hard`, `max_conns`, the
/// fair-use stop in that order), 6 to 9 (degraded, the same) and 10 (a unit
/// that failed lately, whatever its tier or limit). The gateway walks several
/// partitions and applies the tiers and limits across all of them with it
///: see [`Hot::lease_ranked`].
pub const MAX_RANK: u8 = 10;

/// The soft limits a last-resort lease may break, in the order the script
/// breaks them (`lease.lua`, Last resort).
const LIMITS: [&str; 4] = ["rest", "orgs_hard", "max_conns", "fair_use"];

/// The sticky key of a `sid` option: the key the gateway leases under for
/// `px-sid-<sid>`. Whoever reserves a unit for a `sid` ahead of the tunnel
/// (the warmer's browser sample, [`Hot::lease_pin`]) must use it, or the
/// tunnel never finds the unit it was reserved.
pub fn sid_sticky(sid: &str) -> String {
    format!("sid:{sid}")
}

/// Limits of one lease call, taken from the effective policy.
#[derive(Debug, Clone)]
pub struct LeaseLimits {
    /// Idle time after which the lease ends (`lease_ttl`).
    pub lease_ttl: Duration,
    /// A tunnel counts against its unit this long unless touched. The
    /// gateway touches it about every third of this time.
    pub tunnel_ttl: Duration,
    /// Cap on distinct orgs per unit; `None`: no cap.
    pub orgs_hard: Option<NonZeroU32>,
    /// Cap on open tunnels per unit; `None`: no cap. A last-resort lease may
    /// break it up to [`LeaseLimits::conns_ceiling`].
    pub max_conns_per_ip: Option<NonZeroU32>,
    /// What the provider allows per IP, a hard limit: the last-resort ceiling
    /// never goes above it, so breaking `max_conns_per_ip` cannot push a unit
    /// past what the provider serves. `None`: the provider states no limit.
    pub provider_conns_per_ip: Option<NonZeroU32>,
    /// A free unit that another org held last must rest this long.
    pub rest_after_release: Duration,
    /// Rotating: life a session must have left to take a new lease.
    pub min_remaining: Duration,
    /// Rotating: answer [`LeaseOutcome::NeedCreate`] when no unit is free
    /// (`on_empty = create` and a reservation may be possible).
    pub allow_create: bool,
}

impl LeaseLimits {
    /// The last-resort ceiling on a unit's tunnels: twice `max_conns_per_ip`,
    /// and never more than the provider allows per IP. 0: no ceiling.
    pub(crate) fn conns_ceiling(&self) -> u32 {
        let Some(max) = self.max_conns_per_ip else {
            return 0;
        };
        let twice = max.get().saturating_mul(2);
        self.provider_conns_per_ip
            .map_or(twice, |hard| twice.min(hard.get()))
    }
}

/// One tunnel asking for a unit.
#[derive(Debug, Clone)]
pub struct LeaseRequest<'a> {
    pub partition: &'a Partition,
    pub kind: Kind,
    pub org: &'a OrgId,
    /// The sticky key: `sid`, or the scope default (`org`, target host, a
    /// connection id).
    pub sticky: &'a str,
    pub target: &'a Target,
    /// Identifies the tunnel in the unit's and the org's counters.
    pub tunnel: Uuid,
    /// Pool of the policy, checked against pool org blocks.
    pub pool: Pool,
    pub limits: LeaseLimits,
}

/// `rotating.after_release` for the session of a released lease.
#[derive(Debug, Clone, Copy)]
pub struct ReleaseRule<'a> {
    pub after: AfterRelease,
    /// The probe org: a session it used last is left alone, so a browser
    /// sample does not burn the session it tested.
    pub probe_org: &'a OrgId,
}

impl ReleaseRule<'_> {
    pub(crate) fn mode(&self) -> &'static str {
        match self.after {
            AfterRelease::Drain => "drain",
            AfterRelease::ReuseSameOrg => "same_org",
        }
    }
}

/// Handle on an open tunnel's counters; close it when the tunnel ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelRef {
    pub partition: Partition,
    pub unit: String,
    pub org: OrgId,
    pub id: Uuid,
    /// The tunnel is counted among its org's tunnels on its provider
    /// ([`Hot::provider_tunnel_open`]): closing and touching it keeps that
    /// count too.
    pub provider_counted: bool,
}

impl TunnelRef {
    pub(crate) fn member(&self) -> String {
        format!("{}|{}", self.org, self.id)
    }
}

/// A unit bound to the org, with one tunnel counted against it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// Static: the IP as text. Rotating: the session id.
    pub unit: String,
    pub ip: IpAddr,
    /// Distinct orgs on the unit after this grant.
    pub orgs: u32,
    /// Open tunnels on the unit after this grant.
    pub tunnels: u32,
    /// End of life of a rotating session.
    pub expires_at: Option<OffsetDateTime>,
    /// The soft limit this lease broke because no unit was left within the
    /// limits: `rest`, `orgs_hard`, `max_conns` or `fair_use`.
    pub broke: Option<&'static str>,
    /// The unit holds failure strikes ([`Hot::unit_failed`]): report its
    /// success with [`Hot::unit_served`] once it serves the tunnel.
    pub struck: bool,
    /// This call bound the lease to the unit (new, or moved from another
    /// one) and set the dwell key: when the tunnel is not served on the unit,
    /// undo it with [`Hot::lease_unserved`].
    pub fresh: bool,
    pub tunnel: TunnelRef,
}

/// Result of the lease script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseOutcome {
    /// The org's existing lease, renewed.
    Hit(Grant),
    /// A unit that nobody held.
    Free(Grant),
    /// A unit that other orgs or tunnels already use.
    Shared(Grant),
    /// Rotating: no free session; reserve a create ([`Hot::reserve_create`]).
    NeedCreate,
    /// No unit can take the tunnel now (apply `on_empty`): none is left but
    /// those cooled, blocked, skipped or kept for another org. A unit only a
    /// soft limit keeps back is leased instead ([`Grant::broke`]).
    Empty,
    /// A [`Reach`] too short: the best unit has this rank, above the one asked
    /// for. Nothing was leased.
    Lower(u8),
    /// Every unit that could take the tunnel failed a tunnel to this target a
    /// moment ago ([`Hot::cool_target_failed`]) and no create is under way:
    /// waiting would only delay the answer. The cause is the latest failure.
    Cooled(Cause),
    /// Only org blocks stop the org: answer `403 org_blocked`.
    Blocked,
}

/// Org-block fields that cover the whole partition, or the exit IPs they
/// block.
struct BlockView {
    partition_blocked: bool,
    ips: Vec<String>,
}

fn block_view(fields: &[String], p: &Partition, pool: Pool) -> BlockView {
    let pool_field = match pool {
        Pool::Shared => "pool:shared",
        Pool::Private => "pool:private",
    };
    let provider_field = format!("provider:{}", p.provider);
    let route_field = format!("route_class:{}", p.tag());
    BlockView {
        partition_blocked: fields
            .iter()
            .any(|f| *f == pool_field || *f == provider_field || *f == route_field),
        ips: fields
            .iter()
            .filter_map(|f| f.strip_prefix("ip:").map(str::to_owned))
            .collect(),
    }
}

fn args(
    req: &LeaseRequest<'_>,
    mode: &str,
    blocked_ips: &[String],
    skip: &[String],
    max_rank: u8,
) -> Result<serde_json::Value> {
    let l = &req.limits;
    ensure(!req.sticky.is_empty(), "empty sticky key")?;
    ensure(
        !l.lease_ttl.is_zero() && !l.tunnel_ttl.is_zero(),
        "lease_ttl and tunnel_ttl must be above zero",
    )?;
    Ok(json!({
        "mode": mode,
        "org": req.org.as_str(),
        "sticky": req.sticky,
        "host": req.target.host.to_ascii_lowercase(),
        "tunnel": req.tunnel.to_string(),
        "kind": req.kind.as_str(),
        "lease_ttl": ms(l.lease_ttl),
        "tunnel_ttl": ms(l.tunnel_ttl),
        "prev_ttl": ms(PREV_TTL),
        "rest": ms(l.rest_after_release),
        "min_remaining": ms(l.min_remaining),
        "min_dwell": ms(MIN_LEASE_DWELL),
        "orgs_hard": l.orgs_hard.map_or(0, NonZeroU32::get),
        "max_conns": l.max_conns_per_ip.map_or(0, NonZeroU32::get),
        "conns_ceiling": l.conns_ceiling(),
        "allow_create": l.allow_create,
        "blocked_ips": blocked_ips,
        "skip": skip,
        "max_rank": max_rank,
    }))
}

fn dec<E: ToString>(what: &'static str) -> impl Fn(E) -> StoreError {
    move |e| StoreError::decode(what, e)
}

fn grant(req: &LeaseRequest<'_>, reply: &[String]) -> Result<Grant> {
    let [_, unit, ip, orgs, tunnels, expires_at, limit, struck, fresh] = reply else {
        return Err(StoreError::decode("lease reply", format!("{reply:?}")));
    };
    let broke = if limit.is_empty() {
        None
    } else {
        Some(
            LIMITS
                .into_iter()
                .find(|name| name == limit)
                .ok_or_else(|| StoreError::decode("lease limit", limit.clone()))?,
        )
    };
    let expires_ms: i64 = expires_at.parse().map_err(dec("expiry"))?;
    Ok(Grant {
        unit: unit.clone(),
        ip: ip.parse().map_err(dec("unit ip"))?,
        orgs: orgs.parse().map_err(dec("orgs"))?,
        tunnels: tunnels.parse().map_err(dec("tunnels"))?,
        expires_at: (expires_ms != 0)
            .then(|| OffsetDateTime::from_unix_timestamp_nanos(i128::from(expires_ms) * 1_000_000))
            .transpose()
            .map_err(dec("expiry"))?,
        broke,
        struck: !struck.is_empty(),
        fresh: !fresh.is_empty(),
        tunnel: TunnelRef {
            partition: req.partition.clone(),
            unit: unit.clone(),
            org: req.org.clone(),
            id: req.tunnel,
            provider_counted: false,
        },
    })
}

impl Hot {
    /// Run the lease script in `mode` (`lease` or `renew`). `None` when an
    /// org block covers the partition: the script does not run.
    async fn run_lease_script(
        &self,
        req: &LeaseRequest<'_>,
        mode: &str,
        skip: &[String],
        max_rank: u8,
    ) -> Result<Option<Vec<String>>> {
        let fields = self.org_blocks(req.org).await?;
        let view = block_view(&fields, req.partition, req.pool);
        if view.partition_blocked {
            return Ok(None);
        }
        let args = args(req, mode, &view.ips, skip, max_rank)?;
        self.run_ready(&self.scripts.lease, req.partition, args)
            .await
            .map(Some)
    }

    /// Lease a unit for one new tunnel: renew the org's lease for the sticky
    /// key, else take a free unit, else (rotating) ask for a create, else
    /// share the least-loaded unit. One atomic script per partition.
    ///
    /// The tunnel is counted against the unit; call [`Hot::tunnel_close`]
    /// when it ends. An org block that covers the partition answers
    /// [`LeaseOutcome::Blocked`] without running the script.
    ///
    /// The units in `skip` are left out for this call only: a tunnel that
    /// failed on a unit without withdrawing it tries another. No unit below
    /// `max_rank` is taken (see [`MAX_RANK`]): when the best unit ranks lower,
    /// nothing is leased and the answer is [`LeaseOutcome::Lower`] with its
    /// rank. A walk over several partitions asks all of them for rank 0, then
    /// for the best rank any of them named, so the tiers and limits apply
    /// across partitions.
    ///
    /// The gateway answers `503 cache_unavailable` when Redis fails.
    pub async fn lease_ranked(
        &self,
        req: &LeaseRequest<'_>,
        skip: &[String],
        max_rank: u8,
    ) -> Result<LeaseOutcome> {
        let Some(reply) = self.run_lease_script(req, "lease", skip, max_rank).await? else {
            return Ok(LeaseOutcome::Blocked);
        };
        match reply.first().map(String::as_str) {
            Some("HIT") => Ok(LeaseOutcome::Hit(grant(req, &reply)?)),
            Some("FREE") => Ok(LeaseOutcome::Free(grant(req, &reply)?)),
            Some("SHARED") => Ok(LeaseOutcome::Shared(grant(req, &reply)?)),
            Some("CREATE") => Ok(LeaseOutcome::NeedCreate),
            Some("EMPTY") => Ok(LeaseOutcome::Empty),
            Some("LOWER") => reply
                .get(1)
                .and_then(|rank| rank.parse().ok())
                .map(LeaseOutcome::Lower)
                .ok_or_else(|| StoreError::decode("lease reply", format!("{reply:?}"))),
            Some("COOLED") => Ok(reply
                .get(1)
                .and_then(|code| Cause::from_code(code))
                .map_or(LeaseOutcome::Empty, LeaseOutcome::Cooled)),
            Some("BLOCKED") => Ok(LeaseOutcome::Blocked),
            _ => Err(StoreError::decode("lease reply", format!("{reply:?}"))),
        }
    }

    /// Renew the org's existing lease without opening a tunnel (traffic
    /// renews at most every 5 s). `None` when the lease is gone, its unit is
    /// no longer leasable, or the unit is cooled for the target or blocked
    /// for the org: call [`Hot::lease_ranked`] for a new unit then.
    pub async fn renew(&self, req: &LeaseRequest<'_>) -> Result<Option<Grant>> {
        let Some(reply) = self.run_lease_script(req, "renew", &[], MAX_RANK).await? else {
            return Ok(None);
        };
        match reply.first().map(String::as_str) {
            Some("HIT") => Ok(Some(grant(req, &reply)?)),
            Some("NONE") => Ok(None),
            _ => Err(StoreError::decode("renew reply", format!("{reply:?}"))),
        }
    }

    /// End the org's lease for a sticky key now. A unit left with no lease
    /// and no tunnel starts resting. With `after` (a rotating session), the
    /// session is then drained or kept for the org, as the policy says.
    /// Returns whether a lease existed.
    pub async fn release(
        &self,
        p: &Partition,
        org: &OrgId,
        sticky: &str,
        after: Option<ReleaseRule<'_>>,
    ) -> Result<bool> {
        let mut args = json!({ "org": org.as_str(), "sticky": sticky });
        if let Some(rule) = after {
            args["after"] = rule.mode().into();
            args["probe_org"] = rule.probe_org.as_str().into();
        }
        self.run_ready(&self.scripts.release, p, args).await
    }

    /// Remove a tunnel from its unit's and its org's counters. A touch that
    /// is still in flight does not count it again.
    pub async fn tunnel_close(&self, t: &TunnelRef) -> Result<()> {
        self.unit_tunnel_close(t).await?;
        if t.provider_counted {
            self.provider_tunnel_op(
                &t.org,
                &t.partition.provider,
                "close",
                t.id,
                0,
                Duration::ZERO,
            )
            .await?;
        }
        self.org_tunnel_close(&t.org, t.id).await
    }

    /// Remove a tunnel from its unit's counter only: the org keeps counting
    /// it. For a tunnel that failed on this unit and goes on to another one.
    pub async fn unit_tunnel_close(&self, t: &TunnelRef) -> Result<()> {
        self.run_ready::<i64>(
            &self.scripts.tunnel_close,
            &t.partition,
            json!({ "unit": t.unit, "member": t.member(), "mark_ttl": ms(CLOSED_MARK_TTL) }),
        )
        .await
        .map(|_| ())
    }

    /// Remove a race loser's unit counter without marking the tunnel closed.
    /// The winner can use the same tunnel id on another unit of the partition.
    /// Only use before traffic renewal has started for this attempt; unlike
    /// [`Hot::unit_tunnel_close`], this does not fence a late tunnel touch.
    ///
    /// # Errors
    /// Returns a Redis error when removing the unit counter fails.
    pub async fn unit_tunnel_cancel(&self, t: &TunnelRef) -> Result<()> {
        self.run_ready::<i64>(
            &self.scripts.tunnel_close,
            &t.partition,
            json!({ "unit": t.unit, "member": t.member(), "mark": false }),
        )
        .await
        .map(|_| ())
    }

    /// Push the deadline of an open tunnel in both counters. A counter that
    /// lost the tunnel (Redis data loss, or an outage longer than the tunnel
    /// TTL) counts it again. Returns false when the tunnel was closed with
    /// [`Hot::tunnel_close`]: it is not counted again.
    pub async fn tunnel_touch(&self, t: &TunnelRef, ttl: Duration) -> Result<bool> {
        let in_unit: i64 = self
            .run_ready(
                &self.scripts.tunnel_touch,
                &t.partition,
                json!({ "unit": t.unit, "member": t.member(), "ttl": ms(ttl) }),
            )
            .await?;
        if t.provider_counted {
            self.provider_tunnel_op(&t.org, &t.partition.provider, "touch", t.id, 0, ttl)
                .await?;
        }
        let in_org = self.org_tunnel_touch(&t.org, t.id, ttl).await?;
        Ok(in_unit > 0 && in_org)
    }

    /// Count a tunnel of `org` among its tunnels on `provider` unless it holds
    /// `cap` already: false then, and nothing is counted. A route class's
    /// `max_tunnels_per_org` is compared with this count, not with the org's
    /// total. Counting the same tunnel again only refreshes it.
    /// Close it with [`Hot::provider_tunnel_close`] when the provider does not
    /// serve the tunnel; when it does, set [`TunnelRef::provider_counted`] and
    /// [`Hot::tunnel_close`] and [`Hot::tunnel_touch`] keep the count.
    pub async fn provider_tunnel_open(
        &self,
        org: &OrgId,
        provider: &ProviderId,
        tunnel: Uuid,
        cap: NonZeroU32,
        ttl: Duration,
    ) -> Result<bool> {
        self.provider_tunnel_op(org, provider, "open", tunnel, cap.get(), ttl)
            .await
    }

    /// Stop counting a tunnel among the org's tunnels on `provider`.
    pub async fn provider_tunnel_close(
        &self,
        org: &OrgId,
        provider: &ProviderId,
        tunnel: Uuid,
    ) -> Result<()> {
        self.provider_tunnel_op(org, provider, "close", tunnel, 0, Duration::ZERO)
            .await
            .map(|_| ())
    }

    async fn provider_tunnel_op(
        &self,
        org: &OrgId,
        provider: &ProviderId,
        op: &str,
        tunnel: Uuid,
        cap: u32,
        ttl: Duration,
    ) -> Result<bool> {
        let n: i64 = self
            .invoke(
                self.scripts
                    .provider_tunnel
                    .key(format!("orgtunp:{{{org}}}:{provider}"))
                    .arg(op)
                    .arg(tunnel.to_string())
                    .arg(ms(ttl))
                    .arg(cap),
            )
            .await?;
        Ok(n > 0)
    }

    /// True while the org's lease on this sticky key in `p` is younger than
    /// the dwell ([`MIN_LEASE_DWELL`]): such a lease stays where it is, so a
    /// walk over several partitions asks this one first.
    pub async fn lease_is_young(&self, p: &Partition, org: &OrgId, sticky: &str) -> Result<bool> {
        let n: i64 = self
            .cmd(redis::cmd("EXISTS").arg(format!("since:{}:{org}:{sticky}", tag(p))))
            .await?;
        Ok(n > 0)
    }

    /// The tunnel that [`Grant::fresh`] bound the lease to its unit was not
    /// served there: end the lease and its dwell, so the key is not held to a
    /// unit it never used, and does not count as young for it.
    pub async fn lease_unserved(&self, grant: &Grant, sticky: &str) -> Result<()> {
        let t = &grant.tunnel;
        self.run_ready::<i64>(
            &self.scripts.release,
            &t.partition,
            json!({ "org": t.org.as_str(), "sticky": sticky, "unit": grant.unit }),
        )
        .await
        .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn partition() -> Partition {
        Partition {
            provider: "oxy".parse().expect("provider"),
            region: "fr".parse().expect("region"),
        }
    }

    fn limits() -> LeaseLimits {
        LeaseLimits {
            lease_ttl: Duration::from_secs(60),
            tunnel_ttl: Duration::from_secs(30),
            orgs_hard: None,
            max_conns_per_ip: NonZeroU32::new(5),
            provider_conns_per_ip: None,
            rest_after_release: Duration::ZERO,
            min_remaining: Duration::ZERO,
            allow_create: false,
        }
    }

    fn request<'a>(
        p: &'a Partition,
        org: &'a OrgId,
        target: &'a Target,
        sticky: &'a str,
    ) -> LeaseRequest<'a> {
        LeaseRequest {
            partition: p,
            kind: Kind::Static,
            org,
            sticky,
            target,
            tunnel: Uuid::nil(),
            pool: Pool::Shared,
            limits: limits(),
        }
    }

    fn fields(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn org_blocks_cover_the_partition_only_by_pool_provider_or_route_class() {
        let p = partition();
        for covering in ["pool:shared", "provider:oxy", "route_class:oxy:fr"] {
            let view = block_view(&fields(&[covering]), &p, Pool::Shared);
            assert!(view.partition_blocked, "{covering}");
        }
        for other in [
            "pool:private",
            "provider:other",
            "route_class:oxy:de",
            "ip:1.2.3.4",
        ] {
            let view = block_view(&fields(&[other]), &p, Pool::Shared);
            assert!(!view.partition_blocked, "{other}");
        }
        let view = block_view(
            &fields(&["ip:1.2.3.4", "ip:5.6.7.8", "pool:private"]),
            &p,
            Pool::Shared,
        );
        assert_eq!(view.ips, ["1.2.3.4", "5.6.7.8"]);
    }

    #[test]
    fn script_args_are_validated_and_normalised() {
        let (p, org) = (partition(), "acme".parse::<OrgId>().expect("org"));
        let target = Target {
            host: "Example.COM".into(),
            port: 443,
        };
        let a = args(
            &request(&p, &org, &target, "s1"),
            "lease",
            &[],
            &[],
            MAX_RANK,
        )
        .expect("args");
        assert_eq!(a["host"], "example.com");
        assert_eq!(a["lease_ttl"], 60_000);
        assert_eq!(a["orgs_hard"], 0, "no cap is 0 for the script");
        assert_eq!(a["max_conns"], 5);
        assert_eq!(a["min_dwell"], 60_000);

        assert!(args(&request(&p, &org, &target, ""), "lease", &[], &[], MAX_RANK).is_err());
        let mut zero = request(&p, &org, &target, "s1");
        zero.limits.tunnel_ttl = Duration::ZERO;
        assert!(args(&zero, "lease", &[], &[], MAX_RANK).is_err());
    }

    #[test]
    fn grant_parses_the_script_reply_and_rejects_a_malformed_one() {
        let (p, org) = (partition(), "acme".parse::<OrgId>().expect("org"));
        let target = Target {
            host: "example.com".into(),
            port: 443,
        };
        let req = request(&p, &org, &target, "s1");
        let reply =
            |expiry: &str| fields(&["HIT", "10.0.0.1", "10.0.0.1", "2", "3", expiry, "", "", ""]);

        let g = grant(&req, &reply("0")).expect("static grant");
        assert_eq!((g.orgs, g.tunnels, g.expires_at), (2, 3, None));
        assert_eq!(g.tunnel.unit, "10.0.0.1");

        let g = grant(&req, &reply("1700000000123")).expect("rotating grant");
        assert_eq!(
            g.expires_at.map(|t| t.unix_timestamp_nanos()),
            Some(1_700_000_000_123_000_000)
        );

        let limited = fields(&[
            "SHARED",
            "10.0.0.1",
            "10.0.0.1",
            "2",
            "3",
            "0",
            "max_conns",
            "1",
            "1",
        ]);
        let limited = grant(&req, &limited).expect("grant");
        assert_eq!(
            (limited.broke, limited.struck, limited.fresh),
            (Some("max_conns"), true, true)
        );
        let plain = grant(&req, &reply("0")).expect("grant");
        assert_eq!(
            (plain.broke, plain.struck, plain.fresh),
            (None, false, false)
        );
        let unknown = fields(&[
            "SHARED", "10.0.0.1", "10.0.0.1", "2", "3", "0", "bogus", "", "",
        ]);
        assert!(grant(&req, &unknown).is_err());
        assert!(grant(&req, &fields(&["HIT", "10.0.0.1"])).is_err());
        assert!(
            grant(
                &req,
                &fields(&["HIT", "u", "not-an-ip", "1", "1", "0", "", "", ""])
            )
            .is_err()
        );
    }
}
