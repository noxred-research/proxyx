//! Find a unit for one tunnel and open the upstream tunnel to the target.
//!
//! Order: the providers keep their
//! priority order, and the tiers and limits apply across them.
//! The walk asks every partition of the narrowed request (kinds, providers,
//! regions, in order) for a normal unit within the limits first, then for the
//! best unit any of them reported (a degraded one within the limits, then one
//! that breaks a soft limit, lowest first), so a degraded or limit-bound
//! provider gives way to a normal one that is within its limits. A lease
//! younger than a minute stays on its partition before any of this, so a
//! sticky key does not return to a higher-priority provider at once. For each
//! unit render the provider credential, re-check the exit IP when the last
//! check is old, and dial with a few retries. When no partition has a unit,
//! `on_empty` of the first empty partition applies: create a session
//! (rotating), wait for a free unit, or refuse. The whole walk stays inside
//! [`crate::gateway::TOTAL_BUDGET`]: the exit-IP re-check, the dial and its
//! retries, the waits and the creates all end with it, and the answer is ours
//!. No path dials the target directly.
//!
//! How many static IPs an org holds. the session proxy gives every session
//! its own sticky key (`px-sid-<hash>`), so without a bound an org with many
//! sessions would take every free IP and leave none exclusive for the next
//! org. `store/src/hot/lua/lease.lua` therefore gives an org that already holds
//! `max(1, ceil(IPs of the partition / orgs holding a lease in it))` static IPs
//! no further one: a new sticky key reuses the org's least-loaded IP. An org
//! alone may use the whole pool, three orgs on ten IPs hold three or four each
//! and do not share an IP while the pool lasts. The cap counts the IPs the
//! tunnel can use (not cooled for the target, not blocked). An org that took
//! the whole pool while alone gives IPs up to a later org: new leases take
//! them, and a lease whose IP another org shares moves to an IP of the org's
//! own at its next tunnel once it is older than a minute (an open tunnel is
//! never cut). The cap does not apply to rotating partitions or to a
//! customer's own upstream.
//!
//! No org is refused while a unit can serve it. The rest between
//! orgs, `orgs_hard`, `max_conns_per_ip` and the monthly fair-use stop keep a
//! unit back only while another is free of them; with none left the lease
//! breaks the lowest of them first, and
//! `lease_limit_broken_total` names it. A slow (degraded) unit goes after the
//! normal ones.
//!
//! A failed dial of a static IP withdraws the IP only when it is the one IP of
//! its route class failing ([`PROVIDER_FAULT_UNITS`]); when more fail, the
//! provider did: nothing is withdrawn, the tunnel tries one other IP and then
//! answers with the cause. Any other failure of the IP (a status, a SOCKS
//! reply, a dropped or silent handshake, a bad reply) cools it for the target
//! and the tunnel tries another IP, inside the budget and [`MAX_RELEASES`]
//!. The IP is also leased last, for every target, for a few
//! seconds that double on each failure and end by themselves or when it
//! serves a tunnel, so the retry and the next new sticky keys find the IPs
//! that work first. The breaker of a route class is
//! charged once per tunnel that ends refused, or served by another provider
//! ([`Req::owed`]).

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use common::Cause;
use common::Secret;
use common::retry::jittered;
use common::session::{JOB_JITTER, UNIT_MARGIN};
use common::types::{
    IpState, Kind, OrgId, Partition, ProviderId, Region, Subtype, Target, Tier, UpstreamEndpoint,
    UpstreamScheme,
};
use dial::DialTimeouts;
use policy::{EffectivePolicy, InboundOptions, LeaseRequest as Narrowed, OnEmpty};
use provider::{Adapter, UnitSpec};
use rand::Rng as _;
use rand::distributions::Alphanumeric;
use store::loaded::Loaded;
use store::{
    Admit, CostUsage, ExitIpClaim, Grant, InventoryRow, LeaseLimits, LeaseOutcome, LeaseRequest,
    MAX_RANK, Phase, SessionJob, Transition, UNIT_PENALTY_BASE, UNIT_PENALTY_MAX, UnitRecord,
};
use time::OffsetDateTime;
use tokio::net::TcpStream;
use tokio::time::{Instant, sleep, timeout, timeout_at};
use uuid::Uuid;
use verify::{AdmitError, ExitIpError, ExitQuery, Refusal};

use crate::gateway::{Gateway, TUNNEL_TTL, budget_spent, db_write, redis, redis_lease};
use crate::relay::LeaseData;

/// How an upstream dial failed: the answer for the client, whether the
/// provider itself failed to serve (what the breaker counts), whether the
/// provider answered at all, whether the failure was a local resource limit
/// that says nothing about the provider, and whether the leased
/// unit misbehaved.
struct DialFailure {
    cause: Cause,
    provider_failed: bool,
    /// The upstream replied with an HTTP status or a SOCKS reply
    /// ([`dial::DialError::answered`]).
    answered: bool,
    local: bool,
    unit_failed: bool,
    /// Another IP may get through ([`dial::DialError::ip_level`]).
    ip_level: bool,
}

impl DialFailure {
    /// The budget ran out: it says nothing about the provider.
    fn late() -> Self {
        Self {
            cause: Cause::ProviderTimeout,
            provider_failed: false,
            answered: false,
            local: false,
            unit_failed: false,
            ip_level: false,
        }
    }

    /// `direct`: the upstream is the machine's own address (`scheme = "local"`)
    /// and the dial goes straight to the target. What fails there is the
    /// target or the machine's network, never a provider: a refused or timed
    /// out connect, a name that does not resolve and a target that answers
    /// nothing say nothing about the unit or its route class, so nothing is
    /// charged to the breaker and the unit is not withdrawn. Only the source
    /// address can fail the unit ([`dial::DialError::source_unusable`]): the
    /// unit is then cooled for the target and the tunnel moves to another IP.
    fn of(e: &dial::DialError, public_only: bool, direct: bool) -> Self {
        if direct {
            return Self {
                cause: e.cause(),
                provider_failed: false,
                answered: false,
                local: e.is_local(),
                unit_failed: e.source_unusable(),
                ip_level: e.source_unusable(),
            };
        }
        Self {
            cause: e.cause(),
            // A customer's own upstream failing, whether it refuses the login
            // or cannot be reached, is not the provider's: every org's
            // customer upstream of a region shares one route class, so one
            // org's dead upstream must not open it for the others.
            provider_failed: !public_only && (e.provider_unreachable() || e.provider_rejected()),
            answered: e.answered(),
            local: e.is_local(),
            unit_failed: e.unit_misbehaves(),
            ip_level: e.ip_level(),
        }
    }

    fn outcome(&self) -> Outcome {
        if self.provider_failed {
            Outcome::Failed
        } else if self.answered {
            Outcome::Answered
        } else {
            Outcome::Silent
        }
    }
}

/// What a dial or a create tells the route class breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// The provider failed to serve.
    Failed,
    /// The provider replied: it is up.
    Answered,
    /// No answer either way (out of time, a customer's own upstream failing):
    /// a probe that gets it proves nothing.
    Silent,
}

/// A static IP is re-checked when its last check is older than this.
pub(crate) const STATIC_RECHECK: Duration = Duration::from_secs(300);
/// Where the re-check of a rotating session expires from the local cache.
pub(crate) const ROTATING_RECHECK: Duration = Duration::from_secs(30);
/// One exit-IP re-check on the tunnel path. A slower check counts as
/// unverified: the tunnel goes on.
const RECHECK_TIMEOUT: Duration = Duration::from_secs(3);
/// Tries of a dial and the wait before the second one; it doubles.
const DIAL_TRIES: u32 = 3;
const DIAL_RETRY_BASE: Duration = Duration::from_millis(100);
/// A degraded session is kept in the cache up to a quarter of `max_ready`
/// (the same share as the warmer's `DEGRADED_SHARE`, `warmer::plan`).
const DEGRADED_SHARE: u32 = 4;
/// Creates tried inside `create_deadline`.
pub(crate) const CREATE_TRIES: u32 = 2;
/// How often `on_empty = wait` looks for a free unit.
const WAIT_POLL: Duration = Duration::from_millis(100);
/// Re-leases after a failed exit-IP check, per partition.
const MAX_RELEASES: u32 = 3;
/// How long a unit that failed a tunnel is skipped for that target, so the
/// sticky lease moves to another unit.
const UNIT_FAILED_COOLDOWN: Duration = Duration::from_secs(10);
/// How long a static IP whose dial failed rests before the warmer retests it:
/// long enough to stop failing tunnels, short enough that a provider blip
/// does not take the IPs out for the policy's whole cooldown.
const DIAL_FAILED_REST: Duration = Duration::from_secs(60);
/// A failed dial takes its static IP out of leasing only while it is the one
/// IP of its route class that failed a dial within [`UNIT_FAULT_WINDOW`]. When
/// [`PROVIDER_FAULT_UNITS`] distinct IPs fail in it, the provider failed, not
/// the IPs: nothing more is withdrawn (a withdrawn IP rests for
/// [`DIAL_FAILED_REST`] and until the warmer retests it, so a blip would take
/// the whole class out for far longer than it lasts) and the breaker alone
/// answers.
const UNIT_FAULT_WINDOW: Duration = Duration::from_secs(10);
const PROVIDER_FAULT_UNITS: u64 = 2;

/// One tunnel's request, after authentication and narrowing.
pub(crate) struct Req<'a> {
    pub org: &'a OrgId,
    pub target: &'a Target,
    pub loaded: &'a Loaded,
    pub narrowed: &'a Narrowed,
    /// The partitions to try, each with its own policy ([`candidates`]).
    pub cands: Vec<Candidate<'a>>,
    pub tunnel_id: Uuid,
    /// Lease key of the sticky scope; a per-connection one ends with its tunnel.
    pub sticky: &'a str,
    pub per_connection: bool,
    /// The cap the org's slot was counted against: `max_tunnels_per_org` of the
    /// org-wide policy (global and org, no route class). A route class's own
    /// cap bounds the org's tunnels on that provider ([`Gateway::refused_by_org`],
    /// D6).
    pub org_cap: Option<NonZeroU32>,
    pub deadline: Instant,
    /// Route classes this tunnel failed on for a reason that is the provider's
    ///: the breaker is charged once for each, when the tunnel
    /// ends and none of them served it ([`Gateway::settle_breaker`]).
    pub owed: parking_lot::Mutex<Vec<Partition>>,
    /// Providers whose route-class cap counted this tunnel
    /// ([`Gateway::refused_by_org`]); [`Gateway::acquire`] frees all but the
    /// one that served it.
    pub reserved: parking_lot::Mutex<Vec<ProviderId>>,
    /// Set once the tunnel has used its one extra IP after a provider-wide
    /// dial failure ([`Self::first_provider_retry`]).
    pub provider_retried: std::sync::atomic::AtomicBool,
}

impl Req<'_> {
    /// Remember that this tunnel owes the breaker of `partition` a failure.
    fn owe(&self, partition: &Partition) {
        let mut owed = self.owed.lock();
        if !owed.contains(partition) {
            owed.push(partition.clone());
        }
    }

    /// True the first time: after a provider-wide dial failure the tunnel may
    /// try one more IP, never a second one.
    fn first_provider_retry(&self) -> bool {
        !self
            .provider_retried
            .swap(true, std::sync::atomic::Ordering::Relaxed)
    }
}

/// A leased unit with an open tunnel to the target.
pub(crate) struct Established {
    pub stream: TcpStream,
    pub lease: LeaseData,
}

pub(crate) struct Candidate<'a> {
    kind: Kind,
    adapter: &'a Adapter,
    partition: Partition,
    policy: &'a EffectivePolicy,
    /// Lease idle time: the request's `ttl` narrowed by this provider's own
    /// policy, route class included.
    ttl: Duration,
}

enum Step {
    Served(Box<Established>),
    NeedCreate,
    Empty,
    Blocked,
    Failed(Cause),
    /// Units are left, but of a rank above the one asked for: the walk
    /// comes back for this rank ([`Gateway::walk`]).
    Lower(u8),
}

enum Serve {
    Ready(Box<Established>),
    /// The unit failed its exit-IP check and was withdrawn: lease again.
    Retry,
    /// The static IP refused or dropped the dial and was withdrawn: lease
    /// again, and answer with this cause when no other unit serves.
    Dead(Cause),
    Failed(Cause),
    /// Two IPs of the route class failed within [`UNIT_FAULT_WINDOW`]: the
    /// provider did, so nothing is withdrawn. The tunnel may try one other IP
    /// (this one is left out) and answers with the cause when that fails too.
    ProviderWide(Cause, String),
    /// The unit failed the dial in a way another IP may not: it is cooled for
    /// the target (not withdrawn) and left out; lease again, and answer with
    /// this cause when no other unit serves.
    Elsewhere(Cause, String),
}

enum Created {
    Ready,
    /// `max_ready` is reached and creates are in flight: wait for them or share.
    Full,
    /// The route class breaker is open and no probe is due.
    Blocked,
    Failed,
}

/// Why an on-demand session was not made ready, and whether the provider
/// gave no session (what the breaker counts; a rejected IP does not).
struct CreateFailed {
    reason: &'static str,
    provider_fault: bool,
}

impl From<&'static str> for CreateFailed {
    fn from(reason: &'static str) -> Self {
        Self {
            reason,
            provider_fault: false,
        }
    }
}

enum CheckError {
    /// The exit does not match: withdraw the unit.
    Failed,
    /// Too few services answered or the check was slow: serve anyway.
    Unverified,
}

/// True when the org has a live upstream of its own (a customer unit). Such
/// an org is served only by it: when the unit is not leasable the tunnel
/// fails closed instead of leaving through a shared provider IP, which the
/// customer did not ask for.
fn owns_upstream(loaded: &Loaded, org: &OrgId) -> bool {
    loaded
        .snapshot
        .inventory
        .iter()
        .any(|row| row.owner.as_ref() == Some(org) && row.state != IpState::Retired)
}

/// The partitions to try, with each provider's own effective policy: the
/// route class of a provider may narrow regions and `lease_ttl` and caps the
/// org's tunnels, whether or not the username names the provider (`prov`,
/// A provider whose policy refuses an option the request
/// carries is skipped; when every one does, the request is `option_denied`.
pub(crate) fn candidates<'a>(
    loaded: &'a Loaded,
    org: &OrgId,
    narrowed: &Narrowed,
    opts: &InboundOptions,
) -> Result<Vec<Candidate<'a>>, Cause> {
    let mut out = Vec::new();
    let mut denied = None;
    let pinned = owns_upstream(loaded, org);
    for &kind in &narrowed.kinds {
        if pinned && kind != Kind::Static {
            continue;
        }
        let adapters: Vec<&Adapter> = if narrowed.providers.is_empty() {
            loaded.adapters.iter().collect()
        } else {
            narrowed
                .providers
                .iter()
                .filter_map(|p| loaded.adapters.get(p))
                .collect()
        };
        for adapter in adapters.into_iter().filter(|a| a.kind() == kind) {
            let policy = loaded.policies.effective(org, Some(adapter.id()));
            let own = match policy.narrow(opts) {
                Ok(own) => own,
                Err(cause) => {
                    denied = Some(cause);
                    continue;
                }
            };
            for region in regions_for(loaded, org, pinned, adapter, kind, &own.regions) {
                out.push(Candidate {
                    kind,
                    adapter,
                    partition: Partition {
                        provider: adapter.id().clone(),
                        region,
                    },
                    policy,
                    ttl: own.ttl,
                });
            }
        }
    }
    match denied {
        Some(cause) if out.is_empty() => Err(cause),
        _ => Ok(out),
    }
}

/// Partitions of one provider for the wanted regions, in order. A rotating
/// partition is the wanted region itself (the warmer fills it). A static
/// partition is the region of an inventory entry that satisfies the wanted
/// one. A unit owned by another org is not seen; an org with an upstream of
/// its own sees only that.
fn regions_for(
    loaded: &Loaded,
    org: &OrgId,
    pinned: bool,
    adapter: &Adapter,
    kind: Kind,
    wanted: &[Region],
) -> Vec<Region> {
    let mut out: Vec<Region> = Vec::new();
    for want in wanted {
        match kind {
            Kind::Rotating => {
                if !out.contains(want) {
                    out.push(want.clone());
                }
            }
            Kind::Static => {
                let mut here: Vec<&Region> = loaded
                    .snapshot
                    .inventory
                    .iter()
                    .filter(|row| {
                        row.entry.provider == *adapter.id()
                            && row.state != IpState::Retired
                            && if pinned {
                                row.owner.as_ref() == Some(org)
                            } else {
                                row.owner.is_none()
                            }
                            && row.entry.region.satisfies(want)
                    })
                    .map(|row| &row.entry.region)
                    .collect();
                here.sort();
                here.dedup();
                for region in here {
                    if !out.contains(region) {
                        out.push(region.clone());
                    }
                }
            }
        }
    }
    out
}

impl Gateway {
    /// Count the tunnel against the org cap.
    pub(crate) async fn open_slot(&self, r: &Req<'_>) -> Result<(), Cause> {
        let ok = redis(
            "count a tunnel against the org cap",
            self.hot
                .org_tunnel_open(r.org, r.tunnel_id, r.org_cap, TUNNEL_TTL),
        )
        .await?;
        if ok {
            Ok(())
        } else {
            self.metrics.org_capacity_refusals_total.inc();
            Err(Cause::OrgCapacity)
        }
    }

    /// Why the org's own limits stop a tunnel on this candidate: the cap on
    /// its open tunnels and its daily byte budget, both of the candidate's
    /// effective policy (a route class may set them). The slot
    /// counted this tunnel against the org's total already; a route class's own
    /// cap is compared with the org's tunnels on its provider, and counts this
    /// one ([`Req::reserved`]) until [`Gateway::acquire`] knows who served it
    ///.
    async fn refused_by_org(&self, r: &Req<'_>, c: &Candidate<'_>) -> Result<Option<Cause>, Cause> {
        let cap = c.policy.max_tunnels_per_org.and_then(NonZeroU32::new);
        if let Some(cap) = cap
            && Some(cap) != r.org_cap
        {
            let provider = c.adapter.id();
            let counted = redis(
                "count the org's tunnels on the provider",
                self.hot
                    .provider_tunnel_open(r.org, provider, r.tunnel_id, cap, TUNNEL_TTL),
            )
            .await?;
            if !counted {
                self.metrics.org_capacity_refusals_total.inc();
                return Ok(Some(Cause::OrgCapacity));
            }
            let mut reserved = r.reserved.lock();
            if !reserved.contains(provider) {
                reserved.push(provider.clone());
            }
        }
        match self
            .check_org_budget(r.org, c.policy.limits.org_max_gb_per_day)
            .await
        {
            Ok(()) => Ok(None),
            Err(Cause::OrgBudget) => Ok(Some(Cause::OrgBudget)),
            Err(cause) => Err(cause),
        }
    }

    /// Walk the partitions and return an open tunnel, or the cause to refuse
    /// with. A tunnel the org's daily budget refused is counted once, however
    /// many candidate partitions refused it. When it is over,
    /// the breakers are charged for what failed it ([`Self::settle_breaker`])
    /// and the providers that did not serve it stop counting it.
    pub(crate) async fn acquire(&self, r: &Req<'_>) -> Result<Established, Cause> {
        let result = self.walk(r).await;
        if matches!(result, Err(Cause::OrgBudget)) {
            self.metrics.org_budget_refusals_total.inc();
        }
        let served = result.as_ref().ok().map(|e| &e.lease);
        self.settle_breaker(r, served.map(|l| &l.partition)).await;
        let reserved = std::mem::take(&mut *r.reserved.lock());
        for provider in reserved
            .iter()
            .filter(|p| Some(*p) != served.map(|l| &l.provider))
        {
            // Best effort: redis() logged a failure already.
            let _ = redis(
                "free a provider tunnel count",
                self.hot.provider_tunnel_close(r.org, provider, r.tunnel_id),
            )
            .await;
        }
        result
    }

    async fn walk(&self, r: &Req<'_>) -> Result<Established, Cause> {
        let cands = &r.cands;
        let mut deferred: Vec<(usize, bool)> = Vec::new(); // (candidate, needs create)
        let mut failure = None;
        let mut blocked = false;
        let mut port_refused = 0usize;

        // The partitions with a lease younger than the dwell go first, whatever
        // their priority: a sticky key does not return to a higher-priority
        // provider within a minute of moving.
        let mut order: Vec<usize> = (0..cands.len()).collect();
        if cands.len() > 1 && !r.per_connection {
            let mut young = Vec::new();
            for (i, c) in cands.iter().enumerate() {
                let is_young = redis(
                    "look for a young lease",
                    self.hot.lease_is_young(&c.partition, r.org, r.sticky),
                )
                .await?;
                if is_young {
                    young.push(i);
                }
            }
            order.sort_by_key(|i| !young.contains(i));
        }

        // Every partition is asked for a unit of rank 0 (a normal one within
        // its limits); the ones that hold only worse are asked again for the
        // best rank any of them named, and so on: the tiers and limits apply
        // across the providers, which keep their priority order inside each
        // rank. `next[i]` is the rank partition `i` is asked
        // for next, `None` once it answered for good.
        // A lone partition has nothing to give way to: it is asked for any rank.
        let first = if cands.len() > 1 { 0 } else { MAX_RANK };
        let mut next: Vec<Option<u8>> = vec![Some(first); cands.len()];
        let mut vetted = vec![false; cands.len()];
        let mut rank = first;
        'ranks: loop {
            for &i in &order {
                if next[i] != Some(rank) {
                    continue;
                }
                let c = &cands[i];
                if !vetted[i] {
                    vetted[i] = true;
                    if !c.adapter.port_allowed(r.target.port) {
                        port_refused += 1;
                        next[i] = None;
                        continue;
                    }
                    if Instant::now() >= r.deadline {
                        break 'ranks;
                    }
                    if let Some(cause) = self.refused_by_org(r, c).await? {
                        failure = Some(cause);
                        next[i] = None;
                        continue;
                    }
                } else if Instant::now() >= r.deadline {
                    break 'ranks;
                }
                let allow_create = c.kind == Kind::Rotating
                    && c.policy.on_empty.for_kind(c.kind) == OnEmpty::Create;
                next[i] = None;
                match self.try_candidate(r, c, allow_create, None, rank).await? {
                    Step::Served(e) => return Ok(*e),
                    Step::Lower(better) => next[i] = Some(better.max(rank + 1)),
                    Step::NeedCreate => deferred.push((i, true)),
                    Step::Empty => deferred.push((i, false)),
                    Step::Blocked => blocked = true,
                    Step::Failed(cause) => failure = Some(cause),
                }
            }
            match next.iter().flatten().min() {
                Some(&lowest) => rank = lowest,
                None => break,
            }
        }

        let mut waiting: Vec<usize> = Vec::new();
        let mut create_failed = false;
        for &(i, needs_create) in &deferred {
            let c = &cands[i];
            if needs_create {
                // Past the deadline a create or a lease could only be dialed
                // late and given back: the budget is the cause.
                if Instant::now() >= r.deadline {
                    failure = Some(Cause::ProviderTimeout);
                    continue;
                }
                let after_create = match self.create_session(r, c).await? {
                    Created::Ready => {
                        self.try_candidate(r, c, false, Some("created"), MAX_RANK)
                            .await?
                    }
                    // Units are still being created for other tunnels: wait for them.
                    Created::Full => self.wait_for_creates(r, c).await?,
                    Created::Blocked => Step::Failed(Cause::ProviderUnavailable),
                    // nothing was created: still lease what is there, a
                    // soft limit broken if need be
                    Created::Failed => self.try_candidate(r, c, false, None, MAX_RANK).await?,
                };
                match after_create {
                    Step::Served(e) => return Ok(*e),
                    // the dial or lease failure is the cause, not an empty cache
                    Step::Failed(cause) => failure = Some(cause),
                    Step::Blocked => blocked = true,
                    Step::NeedCreate | Step::Empty | Step::Lower(_) => create_failed = true,
                }
            } else if c.policy.on_empty.for_kind(c.kind) != OnEmpty::Fail
                && !drained_static(r.loaded, r.org, c)
            {
                waiting.push(i);
            }
        }

        if !waiting.is_empty() {
            let wait = cands[waiting[0]].policy.lease_wait;
            let until = (Instant::now() + wait).min(r.deadline);
            while Instant::now() < until {
                sleep(WAIT_POLL.min(until.saturating_duration_since(Instant::now()))).await;
                for &i in &waiting {
                    match self
                        .try_candidate(r, &cands[i], false, None, MAX_RANK)
                        .await?
                    {
                        Step::Served(e) => return Ok(*e),
                        Step::Failed(cause) => failure = Some(cause),
                        Step::Blocked => blocked = true,
                        Step::NeedCreate | Step::Empty | Step::Lower(_) => {}
                    }
                }
            }
        }

        let static_only = || r.narrowed.kinds.iter().all(|k| *k == Kind::Static);
        Err(if let Some(cause) = failure {
            cause
        } else if !waiting.is_empty() {
            Cause::LeaseTimeout
        } else if create_failed {
            Cause::CacheEmpty
        } else if !cands.is_empty() && port_refused == cands.len() {
            Cause::PortNotAllowed
        } else if let Some(&(i, _)) = deferred.first() {
            if cands[i].kind == Kind::Static {
                Cause::NoHealthyIp
            } else {
                Cause::CacheEmpty
            }
        } else if blocked {
            Cause::OrgBlocked
        } else if static_only() {
            Cause::NoHealthyIp
        } else {
            Cause::CacheEmpty
        })
    }

    /// `max_ready` is reached, so other tunnels are creating the units this
    /// one needs. Lease as soon as one is ready (or an existing one can be
    /// shared), for as long as a create may take.
    async fn wait_for_creates(&self, r: &Req<'_>, c: &Candidate<'_>) -> Result<Step, Cause> {
        let until = (Instant::now() + c.policy.create_deadline).min(r.deadline);
        loop {
            let step = self.try_candidate(r, c, false, None, MAX_RANK).await?;
            if !matches!(step, Step::Empty | Step::NeedCreate) || Instant::now() >= until {
                return Ok(step);
            }
            sleep(WAIT_POLL.min(until.saturating_duration_since(Instant::now()))).await;
        }
    }

    fn limits(&self, c: &Candidate<'_>, allow_create: bool) -> LeaseLimits {
        let p = c.policy;
        LeaseLimits {
            lease_ttl: c.ttl,
            tunnel_ttl: TUNNEL_TTL,
            orgs_hard: p.orgs_hard.and_then(NonZeroU32::new),
            max_conns_per_ip: match c.adapter.max_conns_per_ip() {
                Some(limit) => NonZeroU32::new(p.conns_per_ip(limit)),
                None => p.max_conns_per_ip.and_then(NonZeroU32::new),
            },
            provider_conns_per_ip: c.adapter.max_conns_per_ip().and_then(NonZeroU32::new),
            rest_after_release: p.rest_after_release,
            min_remaining: p.rotating.min_remaining,
            allow_create,
        }
    }

    /// Lease from one partition and serve the unit, if it holds one of rank
    /// `max_rank` or better ([`store::Hot::lease_ranked`]). `how` overrides
    /// the `cache_leases_total` outcome of a lease (`created` after a create).
    async fn try_candidate(
        &self,
        r: &Req<'_>,
        c: &Candidate<'_>,
        allow_create: bool,
        how: Option<&'static str>,
        max_rank: u8,
    ) -> Result<Step, Cause> {
        // A route class whose breaker is open is skipped, so the walk goes on
        // to the next provider or kind instead of spending its budget on a
        // dead provider. A probe that is due goes through.
        let (_, admit) = redis(
            "peek at the route class breaker",
            self.hot.breaker_peek(&c.partition, &self.pacing.breaker),
        )
        .await?;
        let probing = match admit {
            Admit::Go => false,
            Admit::Probe => true,
            Admit::Blocked => {
                self.metrics
                    .breaker_skips_total
                    .with_label_values(&[c.adapter.id().as_str()])
                    .inc();
                return Ok(Step::Failed(Cause::ProviderUnavailable));
            }
        };
        let limits = self.limits(c, allow_create);
        let mut dead = None;
        let mut probe_held = false;
        let mut skip: Vec<String> = Vec::new();
        for _ in 0..MAX_RELEASES {
            let req = LeaseRequest {
                partition: &c.partition,
                kind: c.kind,
                org: r.org,
                sticky: r.sticky,
                target: r.target,
                tunnel: r.tunnel_id,
                pool: c.policy.pool,
                limits: limits.clone(),
            };
            let leased =
                match redis_lease("lease a unit", self.hot.lease_ranked(&req, &skip, max_rank))
                    .await
                {
                    Ok(leased) => leased,
                    Err(cause) => {
                        self.release_unseen_lease(r, c).await;
                        return Err(cause);
                    }
                };
            let (grant, outcome) = match leased {
                LeaseOutcome::Hit(g) | LeaseOutcome::Free(g) => (g, "hit"),
                LeaseOutcome::Shared(g) => (g, "shared"),
                LeaseOutcome::NeedCreate => return Ok(Step::NeedCreate),
                // a dead unit was the one that failed: that is the cause, not an
                // empty partition it left behind
                LeaseOutcome::Empty | LeaseOutcome::Cooled(_) if dead.is_some() => {
                    return Ok(Step::Failed(dead.unwrap_or(Cause::CacheEmpty)));
                }
                LeaseOutcome::Empty => return Ok(Step::Empty),
                LeaseOutcome::Cooled(cause) => return Ok(Step::Failed(cause)),
                LeaseOutcome::Blocked => return Ok(Step::Blocked),
                LeaseOutcome::Lower(next) => return Ok(Step::Lower(next)),
            };
            match self
                .serve_grant(
                    r,
                    c,
                    grant,
                    limits.clone(),
                    how.unwrap_or(outcome),
                    probing,
                    &mut probe_held,
                )
                .await?
            {
                Serve::Ready(e) => return Ok(Step::Served(e)),
                Serve::Failed(cause) => return Ok(Step::Failed(cause)),
                Serve::Dead(cause) => dead = Some(cause),
                Serve::ProviderWide(cause, unit) => {
                    if Instant::now() >= r.deadline || !r.first_provider_retry() {
                        return Ok(Step::Failed(cause));
                    }
                    dead = Some(cause);
                    skip.push(unit);
                }
                Serve::Retry => {}
                Serve::Elsewhere(cause, unit) => {
                    if Instant::now() >= r.deadline {
                        return Ok(Step::Failed(cause));
                    }
                    dead = Some(cause);
                    skip.push(unit);
                }
            }
        }
        Ok(Step::Failed(dead.unwrap_or(Cause::CacheEmpty)))
    }

    #[allow(clippy::too_many_arguments)]
    async fn serve_grant(
        &self,
        r: &Req<'_>,
        c: &Candidate<'_>,
        grant: Grant,
        limits: LeaseLimits,
        outcome: &'static str,
        probing: bool,
        probe_held: &mut bool,
    ) -> Result<Serve, Cause> {
        let (endpoint, row) = match self.render(c, &grant, r.loaded).await {
            Ok(v) => v,
            Err(cause) => {
                self.give_back(r, &grant).await;
                return Ok(Serve::Failed(cause));
            }
        };
        if !self.exit_ok(c, &grant, &endpoint, row, r.deadline).await {
            self.withdraw(c, &grant, "gateway exit ip check failed", None)
                .await;
            self.give_back(r, &grant).await;
            return Ok(Serve::Retry);
        }
        if probing && !*probe_held {
            // Peeking did not take the probe: take it now, or let the next
            // candidate have this request. It is kept for the retries of this
            // request on another unit.
            let (_, admit) = redis(
                "claim the route class probe",
                self.hot.breaker_claim(&c.partition, &self.pacing.breaker),
            )
            .await?;
            if admit == Admit::Blocked {
                self.give_back(r, &grant).await;
                return Ok(Serve::Failed(Cause::ProviderUnavailable));
            }
            *probe_held = true;
        }
        let dialed = self.dial_with_retry(&endpoint, r.target, r.deadline).await;
        match dialed {
            Ok(stream) => {
                self.report_breaker(r, c, probing, Outcome::Answered).await;
                if grant.struck {
                    // Best effort: redis() logged a failure already.
                    let _ = redis(
                        "forget the failures of a unit that served",
                        self.hot.unit_served(&c.partition, &grant.unit),
                    )
                    .await;
                }
                let provider = c.adapter.id().as_str();
                if let Some(limit) = grant.broke {
                    self.metrics
                        .lease_limit_broken_total
                        .with_label_values(&[limit, provider])
                        .inc();
                }
                self.metrics
                    .cache_leases_total
                    .with_label_values(&[c.kind.as_str(), outcome, provider])
                    .inc();
                let mut grant = grant;
                grant.tunnel.provider_counted = r.reserved.lock().contains(c.adapter.id());
                Ok(Serve::Ready(Box::new(Established {
                    stream,
                    lease: LeaseData {
                        org: r.org.clone(),
                        partition: c.partition.clone(),
                        kind: c.kind,
                        provider: c.adapter.id().clone(),
                        sticky: r.sticky.to_owned(),
                        target: r.target.clone(),
                        tunnel_id: r.tunnel_id,
                        pool: c.policy.pool,
                        limits,
                        grant,
                        per_connection: r.per_connection,
                        after_release: (c.kind == Kind::Rotating)
                            .then_some(c.policy.rotating.after_release),
                        fair_use_gb: (c.kind == Kind::Static)
                            .then_some(c.policy.cost.fair_use_gb_per_ip_month),
                    },
                })))
            }
            Err(failure) => {
                // A static IP has a port of its own at the provider, so what
                // fails there is that IP, not the route class: the IP rests for DIAL_FAILED_REST and the warmer
                // retests it, instead of failing every tunnel that lands on it.
                // Unless it is the second IP of the class to fail within
                // UNIT_FAULT_WINDOW: then the provider failed and nothing is
                // withdrawn: the tunnel leaves that IP out and tries one
                // other, then answers with the cause. The
                // breaker hears of the route class once per tunnel
                // ([`Req::charge`]), from the tunnel that took the IP
                // out, so one dead IP never opens the route class and several
                // do. A customer's own upstream is not the provider's to
                // demote.
                let own_unit = c.kind == Kind::Static && failure.provider_failed;
                // Any other failure of the IP (or of the target through it)
                // moves the tunnel to another IP, except on a customer's own
                // upstream: it fails closed.
                let elsewhere = !own_unit && failure.ip_level && !c.adapter.public_only();
                let provider_wide = own_unit && self.provider_wide(c, &grant).await;
                let counts = if own_unit && !provider_wide {
                    self.withdraw(c, &grant, "gateway dial failed", Some(DIAL_FAILED_REST))
                        .await
                } else {
                    true
                };
                // another unit gets the tunnel next, so a failed probe on a dead
                // unit reopens the route class like any failed probe
                // our own exhausted ports or descriptors say nothing about the provider
                if counts && !failure.local {
                    self.report_breaker(r, c, probing, failure.outcome()).await;
                }
                if failure.unit_failed || elsewhere {
                    self.cool_unit(c, &grant, r, failure.cause).await;
                }
                self.give_back(r, &grant).await;
                if provider_wide {
                    return Ok(Serve::ProviderWide(failure.cause, grant.unit));
                }
                if own_unit {
                    return Ok(Serve::Dead(failure.cause));
                }
                if elsewhere {
                    return Ok(Serve::Elsewhere(failure.cause, grant.unit));
                }
                Ok(Serve::Failed(failure.cause))
            }
        }
    }

    /// Record the failed dial of a static IP and say whether the provider
    /// failed rather than the IP: [`PROVIDER_FAULT_UNITS`] distinct IPs of the
    /// route class failed a dial within [`UNIT_FAULT_WINDOW`].
    async fn provider_wide(&self, c: &Candidate<'_>, grant: &Grant) -> bool {
        let failed = redis(
            "record a failed dial",
            self.hot
                .dial_failed(&c.partition, &grant.unit, UNIT_FAULT_WINDOW),
        )
        .await
        // without the count the IP is taken for a bad one, as before
        .unwrap_or(1);
        failed >= PROVIDER_FAULT_UNITS
    }

    /// A unit that failed a tunnel is skipped for this target for
    /// [`UNIT_FAILED_COOLDOWN`]: the lease script does not renew a lease on a
    /// cooled unit, so the next tunnel of the sticky key moves to another unit
    /// instead of failing the same way until `lease_ttl`. The
    /// cooldown keeps the cause: when every unit is cooled this way the lease
    /// answers with it at once ([`LeaseOutcome::Cooled`]) instead of waiting
    /// for a unit that cannot come back within the wait.
    /// The unit is also leased after every other one, for any target, for
    /// [`UNIT_PENALTY_BASE`] and twice as long for every failure that follows
    /// ([`store::Hot::unit_failed`]): the retry of this tunnel and the new
    /// sticky keys go to the IPs that work first, instead of the failing IP,
    /// which holds the fewest leases, taking them. It is
    /// not withdrawn: it still takes a lease when nothing else can.
    /// Best effort: `redis()` logged a failure already.
    async fn cool_unit(&self, c: &Candidate<'_>, grant: &Grant, r: &Req<'_>, cause: Cause) {
        let _ = redis(
            "cool a unit that failed a tunnel",
            self.hot.cool_target_failed(
                &c.partition,
                grant.ip,
                r.target,
                UNIT_FAILED_COOLDOWN,
                cause,
            ),
        )
        .await;
        let _ = redis(
            "rank a unit that failed a tunnel last",
            self.hot.unit_failed(
                &c.partition,
                &grant.unit,
                UNIT_PENALTY_BASE,
                UNIT_PENALTY_MAX,
            ),
        )
        .await;
    }

    /// Undo the unit counter of a grant that will not be served. The org slot
    /// stays counted for the next try: giving it up and taking it again let a
    /// concurrent tunnel of the org take it, and a dial failure then answered
    /// `org_capacity`. A lease this call bound to the unit goes too, with its
    /// dwell key: a key whose tunnel failed on a provider is not young there,
    /// so it goes back to it as soon as it works, not a minute later.
    async fn give_back(&self, r: &Req<'_>, grant: &Grant) {
        // Best effort: redis() logged a failure already.
        let _ = redis(
            "close an unused tunnel counter",
            self.hot.unit_tunnel_close(&grant.tunnel),
        )
        .await;
        if grant.fresh {
            let _ = redis(
                "end a lease that served no tunnel",
                self.hot.lease_unserved(grant, r.sticky),
            )
            .await;
        }
    }

    /// The lease call failed or timed out, and its script may still run in
    /// Redis: a per-connection lease nobody will ever release would hold a
    /// unit for the whole `lease_ttl`. Release it now, best effort (a sticky
    /// lease is found again by the retry). `redis()` logged a failure already.
    async fn release_unseen_lease(&self, r: &Req<'_>, c: &Candidate<'_>) {
        if r.per_connection {
            let _ = redis(
                "release a lease the failed call may have taken",
                self.hot.release(&c.partition, r.org, r.sticky, None),
            )
            .await;
        }
    }

    /// The upstream credential of a leased unit, and its inventory row.
    async fn render<'a>(
        &self,
        c: &Candidate<'_>,
        grant: &Grant,
        loaded: &'a Loaded,
    ) -> Result<(UpstreamEndpoint, Option<&'a InventoryRow>), Cause> {
        match c.kind {
            Kind::Static => {
                let Some(row) = loaded
                    .snapshot
                    .inventory
                    .iter()
                    .find(|row| row.entry.ip.to_string() == grant.unit)
                else {
                    // Not in this snapshot: it may be newer than the unit.
                    tracing::warn!(provider = %c.adapter.id(), "leased static ip is not in the inventory snapshot");
                    return Err(Cause::ProviderUnavailable);
                };
                if row.partition() != c.partition {
                    // The IP moved to another provider or region in the
                    // inventory: it must not be leased from this partition.
                    tracing::warn!(partition = %c.partition, "leased static ip belongs to another partition now, withdrawing it");
                    // Best effort: redis() logged a failure already.
                    let _ = redis(
                        "withdraw a unit that moved partition",
                        self.hot.ready_take(&c.partition, &grant.unit),
                    )
                    .await;
                    return Err(Cause::ProviderUnavailable);
                }
                let credentials = match (&row.owner, &row.entry.credentials) {
                    // A customer unit: the login of its owner, from the snapshot
                    // (a unit with no stored login dials without one).
                    (Some(owner), _) => loaded
                        .snapshot
                        .customer_logins
                        .get(owner)
                        .map(|l| (l.username.clone(), l.password.clone())),
                    (None, Some(name)) => {
                        let pair = self.credentials(name).await?;
                        Some((pair.0.clone(), pair.1.clone()))
                    }
                    (None, None) => None,
                };
                let up = recipe(
                    c.adapter,
                    &UnitSpec::Static {
                        entry: &row.entry,
                        credentials,
                    },
                )
                .ok_or(Cause::ProviderUnavailable)?;
                Ok((up, Some(row)))
            }
            Kind::Rotating => {
                let up = rotating_recipe(c, &grant.unit).ok_or(Cause::ProviderUnavailable)?;
                Ok((up, None))
            }
        }
    }

    /// `username:password` of an inventory entry, read from the secrets
    /// directory and cached for a minute.
    async fn credentials(&self, name: &str) -> Result<Arc<(Secret, Secret)>, Cause> {
        let settings = Arc::clone(&self.settings);
        let file = name.to_owned();
        let read = async move {
            tokio::task::spawn_blocking(move || {
                let secret = settings.read_secret(&file)?;
                let (user, pass) = secret
                    .expose()
                    .split_once(':')
                    .filter(|(user, _)| !user.is_empty())
                    .ok_or_else(|| anyhow::anyhow!("secret {file:?} is not username:password"))?;
                Ok::<_, anyhow::Error>(Arc::new((Secret::new(user), Secret::new(pass))))
            })
            .await?
        };
        self.credentials
            .try_get_with(name.to_owned(), read)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "failed to read inventory credentials");
                Cause::ProviderUnavailable
            })
    }

    /// False when the unit fails its exit-IP re-check, which runs when the
    /// last check is older than 30 s (static: 5 min), once per unit even when
    /// many tunnels arrive together. An unverifiable exit is served, and so is
    /// one still unverified when the tunnel's `deadline` comes (the dial then
    /// finds no time left and answers).
    async fn exit_ok(
        &self,
        c: &Candidate<'_>,
        grant: &Grant,
        endpoint: &UpstreamEndpoint,
        row: Option<&InventoryRow>,
        deadline: Instant,
    ) -> bool {
        if let Some(at) = row.and_then(|r| r.last_check_at)
            && let Ok(age) = Duration::try_from(OffsetDateTime::now_utc() - at)
            && age < STATIC_RECHECK
        {
            return true;
        }
        let cache = match c.kind {
            Kind::Static => &self.static_checks,
            Kind::Rotating => &self.rotating_checks,
        };
        let key = format!("{}|{}", c.partition, grant.unit);
        let Ok(checked) = timeout_at(
            deadline,
            cache.try_get_with(key, self.run_check(c, grant, endpoint, row)),
        )
        .await
        else {
            return true;
        };
        !matches!(checked.err().as_deref(), Some(CheckError::Failed))
    }

    async fn run_check(
        &self,
        c: &Candidate<'_>,
        grant: &Grant,
        endpoint: &UpstreamEndpoint,
        row: Option<&InventoryRow>,
    ) -> Result<(), CheckError> {
        let query = ExitQuery {
            region: (c.kind == Kind::Rotating).then_some(&c.partition.region),
            // a SIM box changes its exit IP, so its entry is no expectation; a
            // customer upstream's entry is its address, not its exit
            ip: row
                .filter(|r| r.entry.subtype != Subtype::MobileBox && r.owner.is_none())
                .map(|r| r.entry.ip),
            echo_url: c.adapter.echo_url(),
        };
        match timeout(RECHECK_TIMEOUT, self.exit_ip.check(endpoint, &query)).await {
            Ok(Ok(exit)) => {
                let seen = IpAddr::V4(exit.ip);
                if c.kind == Kind::Rotating && seen != grant.ip {
                    tracing::warn!(provider = %c.adapter.id(), "rotating session changed its exit ip");
                    // once per session: the check is single-flight per unit
                    self.metrics
                        .cache_evictions_total
                        .with_label_values(&["ip_changed"])
                        .inc();
                    return Err(CheckError::Failed);
                }
                if let Some(row) = row {
                    self.record_check(row.entry.ip, seen);
                }
                Ok(())
            }
            Ok(Err(e)) if e.is_outage() || matches!(e, ExitIpError::Client(_)) => {
                tracing::warn!(provider = %c.adapter.id(), error = %e, "exit ip check unavailable, serving unverified");
                Err(CheckError::Unverified)
            }
            Ok(Err(e)) => {
                tracing::warn!(provider = %c.adapter.id(), error = %e, "exit ip check failed");
                Err(CheckError::Failed)
            }
            Err(_) => {
                tracing::warn!(provider = %c.adapter.id(), "exit ip check timed out, serving unverified");
                Err(CheckError::Unverified)
            }
        }
    }

    fn record_check(&self, ip: IpAddr, seen: IpAddr) {
        let db = self.db.clone();
        self.tracker.spawn(async move {
            db_write(
                "record an exit ip check",
                db.record_check(ip, Some(seen), OffsetDateTime::now_utc()),
            )
            .await;
        });
    }

    /// A unit failed a check or a dial: stop leasing it. A static IP also goes
    /// to cooldown in Postgres, where the warmer retests it: for `rest`, or
    /// the policy's `cooldown` with `None`. True when this call took the unit
    /// out of the ready set, so exactly one of several callers that find the
    /// unit dead says so (an unknown state counts as taken).
    async fn withdraw(
        &self,
        c: &Candidate<'_>,
        grant: &Grant,
        why: &'static str,
        rest: Option<Duration>,
    ) -> bool {
        let took = redis(
            "withdraw a unit that failed",
            self.hot.ready_take(&c.partition, &grant.unit),
        )
        .await
        .unwrap_or(true);
        if c.kind != Kind::Static || !took {
            return took;
        }
        let Ok(ip) = grant.unit.parse::<IpAddr>() else {
            return took;
        };
        let Ok(cooldown) = time::Duration::try_from(rest.unwrap_or(c.policy.static_ips.cooldown))
        else {
            return took;
        };
        let db = self.db.clone();
        self.tracker
            .spawn(db_write("cool a static ip that failed", async move {
                let change = Transition::to(IpState::Cooldown, why)
                    .cooldown_until(OffsetDateTime::now_utc() + cooldown);
                match db.transition_ip(ip, &change, "gateway").await {
                    // The warmer's own re-check moved the IP out of
                    // Available/Leased first (to Candidate): it is out of
                    // leasing either way, and its row says why.
                    Err(store::StoreError::InvalidTransition { from, .. }) => {
                        tracing::debug!(%ip, from = from.as_str(), "static ip already left leasing");
                        Ok(())
                    }
                    other => other.map(|_| ()),
                }
            }));
        took
    }

    async fn dial_with_retry(
        &self,
        up: &UpstreamEndpoint,
        target: &Target,
        deadline: Instant,
    ) -> Result<TcpStream, DialFailure> {
        let timeouts = DialTimeouts {
            keepalive: self.settings.keepalive(),
            ..DialTimeouts::default()
        };
        let mut attempt = 0;
        let late = DialFailure::late;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(late());
            }
            let dialed = dial::dial(up, target, &timeouts, &self.metrics);
            match timeout(left, dialed).await {
                Ok(Ok(dialed)) => return Ok(dialed),
                Ok(Err(e)) if e.is_retryable() && attempt + 1 < DIAL_TRIES => {
                    tracing::debug!(provider = %up.provider, error = %e, attempt, "retrying upstream dial");
                    sleep((DIAL_RETRY_BASE * 2u32.pow(attempt)).min(left)).await;
                    attempt += 1;
                }
                Ok(Err(e)) => {
                    tracing::warn!(provider = %up.provider, error = %e, "upstream dial failed");
                    return Err(DialFailure::of(
                        &e,
                        up.public_only,
                        up.scheme == UpstreamScheme::Local,
                    ));
                }
                // The whole budget ran out: it says nothing about the provider.
                Err(_) => return Err(late()),
            }
        }
    }

    /// Tell the shared breaker how a dial or an on-demand create ended. Only
    /// a probe reports success, and only for an [`Outcome::Answered`]: a probe
    /// that ran out of time or got no answer proves nothing and its claim
    /// expires. A [failure](Outcome::Failed) counts when the provider failed
    /// to serve (a dial) or gave no session (a create). A failed probe
    /// reports at once (it reopens the class). Any other failure is only owed
    /// ([`Req::owed`]) until the tunnel ends ([`Self::settle_breaker`]). A
    /// Redis error is logged: the breaker only gets less accurate.
    async fn report_breaker(
        &self,
        r: &Req<'_>,
        c: &Candidate<'_>,
        probing: bool,
        outcome: Outcome,
    ) {
        let cfg = &self.pacing.breaker;
        let result = if outcome == Outcome::Failed {
            if !probing {
                r.owe(&c.partition);
                return;
            }
            self.hot.breaker_failure(&c.partition, cfg).await
        } else if probing && outcome == Outcome::Answered {
            self.hot.breaker_success(&c.partition, cfg).await
        } else {
            return;
        };
        if let Err(error) = result {
            tracing::warn!(partition = %c.partition, %error, "failed to record a breaker result");
        }
    }

    /// Charge the breaker of every route class this tunnel owes a failure,
    /// once each, now that its end is known. A class that finally served the
    /// tunnel, after failing on another of its IPs, is not charged: the
    /// provider answered. A tunnel refused, or served by
    /// another provider, charges the classes that failed it.
    async fn settle_breaker(&self, r: &Req<'_>, served: Option<&Partition>) {
        let owed = std::mem::take(&mut *r.owed.lock());
        for partition in owed.iter().filter(|p| Some(*p) != served) {
            if let Err(error) = self
                .hot
                .breaker_failure(partition, &self.pacing.breaker)
                .await
            {
                tracing::warn!(%partition, %error, "failed to record a breaker result");
            }
        }
    }

    /// Create a session on demand (`on_empty = create`): reserve, start, open
    /// the session through the provider, run the exit-IP quorum, make it
    /// leasable. Two tries inside `create_deadline`.
    async fn create_session(&self, r: &Req<'_>, c: &Candidate<'_>) -> Result<Created, Cause> {
        let Some(id_len) = c.adapter.session_id_len() else {
            tracing::warn!(provider = %c.adapter.id(), "adapter has no session id option, cannot create");
            return Ok(Created::Failed);
        };
        let until = (Instant::now() + c.policy.create_deadline).min(r.deadline);
        let max_ready = c.policy.capacity.target(&c.partition.region).max_ready;
        let used = redis(
            "read the provider budget",
            self.hot
                .cost_used(c.adapter.id(), OffsetDateTime::now_utc()),
        )
        .await?;
        if over_budget(&c.policy.cost, &used) {
            tracing::warn!(provider = %c.adapter.id(), "provider budget is used up, not creating a session");
            return Ok(Created::Failed);
        }
        for _ in 0..CREATE_TRIES {
            if Instant::now() >= until {
                break;
            }
            let Some(reservation) = redis(
                "reserve a create",
                self.hot.reserve_create(&c.partition, max_ready),
            )
            .await?
            else {
                return Ok(Created::Full);
            };
            // Like a dial, a create goes through the route class breaker: an
            // open one refuses it, and a due probe is taken by one caller.
            let (_, admit) = redis(
                "claim the route class for a create",
                self.hot.breaker_claim(&c.partition, &self.pacing.breaker),
            )
            .await?;
            let probing = match admit {
                Admit::Go => false,
                Admit::Probe => true,
                Admit::Blocked => {
                    let _ = redis(
                        "give a reservation back",
                        self.hot
                            .create_abort(&c.partition, &reservation.id.to_string()),
                    )
                    .await;
                    self.metrics
                        .warm_creates_total
                        .with_label_values(&[c.adapter.id().as_str(), "breaker"])
                        .inc();
                    return Ok(Created::Blocked);
                }
            };
            let session: String = rand::thread_rng()
                .sample_iter(Alphanumeric)
                .take(id_len)
                .map(char::from)
                .collect();
            let started = redis(
                "start a create",
                self.hot.create_start(
                    &c.partition,
                    &reservation,
                    &session,
                    c.policy.create_deadline * 2,
                ),
            )
            .await?;
            if !started {
                continue;
            }
            let _ = redis(
                "meter a create",
                self.hot
                    .cost_add(c.adapter.id(), 0, 1, OffsetDateTime::now_utc()),
            )
            .await;
            match self.verify_new_session(r, c, &session, until).await {
                Ok((unit, tier)) => {
                    redis(
                        "make a created unit ready",
                        self.hot.ready_put_tier(&c.partition, &unit, tier),
                    )
                    .await?;
                    self.report_breaker(r, c, probing, Outcome::Answered).await;
                    return Ok(Created::Ready);
                }
                Err(failed) => {
                    tracing::warn!(provider = %c.adapter.id(), reason = failed.reason, "on-demand create failed");
                    let _ = redis(
                        "abort a create",
                        self.hot.create_abort(&c.partition, &session),
                    )
                    .await;
                    let outcome = if failed.provider_fault {
                        Outcome::Failed
                    } else {
                        Outcome::Answered
                    };
                    self.report_breaker(r, c, probing, outcome).await;
                }
            }
        }
        Ok(Created::Failed)
    }

    /// Everything a warmed session passes before `ready_put`, in the warmer's
    /// order (`warmer::reconcile`): exit-IP quorum, exit-IP claim, the
    /// admission checks of [`verify::admit`] inside `until`, and the
    /// [`SessionJob`] in the `due` set. The job comes first on purpose: a
    /// failure after it leaves a job for a session that is not ready, which
    /// its first step drains; the other order would leave a ready session
    /// that nothing keeps alive, re-checks or drains. A check that cannot
    /// finish by `until` follows the policy (see [`verify::admit`]). A session
    /// that is clean but slow is admitted in the degraded tier, like the
    /// warmer does, while the partition holds fewer than
    /// [`degraded_cap`] free degraded sessions; the tier comes
    /// back with the unit.
    async fn verify_new_session(
        &self,
        r: &Req<'_>,
        c: &Candidate<'_>,
        session: &str,
        until: Instant,
    ) -> Result<(UnitRecord, Tier), CreateFailed> {
        let up = rotating_recipe(c, session).ok_or("recipe refused")?;
        let query = ExitQuery {
            region: Some(&c.partition.region),
            ip: None,
            echo_url: c.adapter.echo_url(),
        };
        let exit = match timeout_at(until, self.exit_ip.check(&up, &query)).await {
            Ok(Ok(exit)) => exit,
            Ok(Err(e)) => {
                tracing::warn!(provider = %c.adapter.id(), error = %e, "new session failed the exit ip check");
                return Err(CreateFailed {
                    reason: "exit ip check failed",
                    provider_fault: e.is_outage(),
                });
            }
            Err(_) => {
                return Err(CreateFailed {
                    reason: "create deadline passed",
                    provider_fault: true,
                });
            }
        };
        let ip = IpAddr::V4(exit.ip);
        let max_age = c.policy.rotating.max_age_for(c.adapter.session_life());
        let ttl = max_age + UNIT_MARGIN;
        let now = OffsetDateTime::now_utc();
        let expires_at = time::Duration::try_from(max_age)
            .map(|d| now + d)
            .map_err(|_| "max_age out of range")?;
        match redis(
            "claim the exit ip",
            self.hot.claim_exit_ip(ip, session, ttl),
        )
        .await
        {
            Ok(ExitIpClaim::Claimed) => {}
            Ok(ExitIpClaim::Duplicate { .. }) => return Err("duplicate exit ip".into()),
            Err(_) => return Err("redis unavailable".into()),
        }

        let targets = r.loaded.probe_targets.for_region(&c.partition.region);
        let admitted = verify::admit(
            &self.reputation,
            &self.probe,
            ip,
            &up,
            &targets,
            c.policy,
            Some(until),
        )
        .await;
        // Clean but slow: kept as a degraded session while the partition has
        // room for one, as the warmer does (`warmer::reconcile`).
        let slow = matches!(
            &admitted,
            Err(AdmitError::Refused {
                cause: Refusal::Slow,
                ..
            })
        );
        let tier = if slow && self.degraded_room(c).await {
            Tier::Degraded
        } else {
            Tier::Normal
        };
        if let Err(e) = admitted
            && tier == Tier::Normal
        {
            self.release_claim(ip, session).await;
            return Err(match e {
                AdmitError::Refused { cause, .. } => {
                    self.metrics
                        .cache_evictions_total
                        .with_label_values(&[cause.label()])
                        .inc();
                    cause.label()
                }
                AdmitError::Probe(error) => {
                    tracing::warn!(provider = %c.adapter.id(), %error, "probe client refused the upstream");
                    "probe client refused the upstream"
                }
            }
            .into());
        }

        let unix = now.unix_timestamp();
        let job = SessionJob {
            partition: c.partition.clone(),
            session: session.to_owned(),
            ip: exit.ip,
            born: unix,
            expires: unix + i64::try_from(max_age.as_secs()).unwrap_or(i64::MAX / 2),
            phase: Phase::fresh(unix),
        };
        let first = jittered(c.policy.keepalive_interval(), JOB_JITTER);
        if redis(
            "schedule the session job",
            self.hot.due_schedule(&job.encode(), now + first),
        )
        .await
        .is_err()
        {
            self.release_claim(ip, session).await;
            return Err("redis unavailable".into());
        }
        Ok((
            UnitRecord {
                id: session.to_owned(),
                ip,
                expires_at: Some(expires_at),
                ttl: Some(ttl),
                owner: None,
            },
            tier,
        ))
    }

    /// True when the partition keeps fewer free degraded sessions than
    /// [`degraded_cap`]. A Redis failure says no.
    async fn degraded_room(&self, c: &Candidate<'_>) -> bool {
        let max_ready = c.policy.capacity.target(&c.partition.region).max_ready;
        redis("count the degraded sessions", self.hot.counts(&c.partition))
            .await
            .is_ok_and(|counts| counts.degraded_free < degraded_cap(max_ready))
    }

    /// Give the exit-IP claim of a refused create back, so the IP is not
    /// counted as a duplicate until the claim expires.
    async fn release_claim(&self, ip: IpAddr, session: &str) {
        let _ = redis(
            "release an exit ip claim",
            self.hot.release_exit_ip(ip, session),
        )
        .await;
    }
}

/// Most free degraded sessions a partition keeps.
fn degraded_cap(max_ready: u32) -> u64 {
    u64::from(max_ready.div_ceil(DEGRADED_SHARE))
}

/// True when the snapshot has static IPs in the candidate's partition that
/// this org may use, and none of them is leasable: a route class a failed
/// canary drained. Waiting for a unit cannot help (the IPs rest for a
/// cooldown), so the answer is `no_healthy_ip` at once.
fn drained_static(loaded: &Loaded, org: &OrgId, c: &Candidate<'_>) -> bool {
    if c.kind != Kind::Static {
        return false;
    }
    let mut rows = loaded
        .snapshot
        .inventory
        .iter()
        .filter(|row| {
            row.entry.provider == *c.adapter.id()
                && row.entry.region == c.partition.region
                && row.state != IpState::Retired
                && row.owner.as_ref().is_none_or(|owner| owner == org)
        })
        .peekable();
    rows.peek().is_some() && rows.all(|row| !row.state.is_leasable())
}

/// The upstream endpoint of `spec`; a recipe the adapter refuses is logged.
fn recipe(adapter: &Adapter, spec: &UnitSpec<'_>) -> Option<UpstreamEndpoint> {
    adapter
        .recipe(spec)
        .inspect_err(|error| {
            tracing::warn!(provider = %adapter.id(), %error, "provider recipe refused");
        })
        .ok()
}

fn rotating_recipe(c: &Candidate<'_>, session: &str) -> Option<UpstreamEndpoint> {
    let spec = UnitSpec::Rotating {
        session_id: session,
        ttl_minutes: c.adapter.session_minutes(),
        region: &c.partition.region,
        strict: false,
    };
    recipe(c.adapter, &spec)
}

/// True when the provider's day or hour budget is spent (`policy.cost`). Both
/// the gateway (tunnel bytes, on-demand creates) and the warmer add to the
/// counters, so a create that would exceed a limit is refused here.
fn over_budget(cost: &policy::Cost, used: &CostUsage) -> bool {
    used.creates_this_hour >= u64::from(cost.max_creates_per_hour)
        || budget_spent(used.bytes_today, cost.max_gb_per_day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_create_is_refused_at_either_limit() {
        let used = |bytes_today, creates_this_hour| CostUsage {
            bytes_today,
            creates_this_hour,
        };
        let c = policy::Cost {
            max_gb_per_day: 5.0,
            max_creates_per_hour: 100,
            fair_use_gb_per_ip_month: 0.0,
        };
        assert!(!over_budget(&c, &used(4_999_999_999, 99)));
        assert!(
            over_budget(&c, &used(5_000_000_000, 0)),
            "day bytes at the limit"
        );
        assert!(over_budget(&c, &used(0, 100)), "creates at the limit");
    }

    fn refused() -> dial::DialError {
        dial::DialError::Connect(std::io::Error::from(std::io::ErrorKind::ConnectionRefused))
    }

    /// Every org's customer upstream of a region shares one
    /// route class, so an unreachable or rejecting customer upstream says
    /// nothing to its breaker, while the same failure of a provider counts.
    #[test]
    fn a_customers_own_upstream_failing_does_not_charge_the_shared_breaker() {
        use dial::{DialError, Stage};
        let failures = || {
            [
                refused(),
                DialError::Dns(std::io::Error::other("no such host")),
                DialError::Timeout {
                    stage: Stage::Tcp,
                    after: Duration::from_secs(2),
                },
                DialError::Auth,
                DialError::Io(std::io::Error::from(std::io::ErrorKind::ConnectionReset)),
            ]
        };
        for e in failures() {
            let own = DialFailure::of(&e, true, false);
            assert!(!own.provider_failed, "{e}");
            assert_eq!(own.outcome(), Outcome::Silent, "{e}");
            let provider = DialFailure::of(&e, false, false);
            assert!(provider.provider_failed, "{e}");
            assert_eq!(provider.outcome(), Outcome::Failed, "{e}");
        }
    }

    /// A half-open probe reports a pass only when the upstream
    /// replied. A budget that ran out, a silent handshake and a bad
    /// credential prove nothing, so none of them is a pass.
    #[test]
    fn only_a_reply_from_the_upstream_is_a_pass_for_a_probe() {
        use dial::{DialError, Stage};
        for answered in [DialError::Status(403), DialError::SocksReply(5)] {
            assert_eq!(
                DialFailure::of(&answered, false, false).outcome(),
                Outcome::Answered
            );
        }
        for silent in [
            DialError::Timeout {
                stage: Stage::Handshake,
                after: Duration::from_secs(3),
            },
            DialError::BadCredential("too long"),
            DialError::Protocol("garbage"),
            DialError::DeniedAddress,
        ] {
            assert_eq!(
                DialFailure::of(&silent, false, false).outcome(),
                Outcome::Silent,
                "{silent}"
            );
        }
        assert_eq!(DialFailure::late().outcome(), Outcome::Silent);
    }

    /// A `local` unit dials the target itself: a target that refuses, a
    /// connect that times out or a name that does not resolve is not the
    /// provider's failure (no breaker charge, no withdrawn IP) and not the
    /// unit's (no other IP gets the tunnel). A source address that cannot be
    /// bound is the unit's: it cools and the tunnel moves on, still without a
    /// breaker charge.
    #[test]
    fn a_local_unit_whose_target_fails_charges_nobody() {
        use dial::{DialError, Stage};
        let target_side = [
            refused(),
            DialError::Dns(std::io::Error::other("no such host")),
            DialError::Connect(std::io::Error::from(std::io::ErrorKind::TimedOut)),
            DialError::Timeout {
                stage: Stage::Tcp,
                after: Duration::from_secs(2),
            },
            DialError::Connect(std::io::Error::from_raw_os_error(libc::ENETUNREACH)),
        ];
        for e in target_side {
            let f = DialFailure::of(&e, false, true);
            assert!(!f.provider_failed, "{e}");
            assert!(!f.unit_failed && !f.ip_level, "{e}");
            assert_eq!(f.outcome(), Outcome::Silent, "{e}");
            // the client still hears a 502/504 cause
            assert_eq!(f.cause, e.cause(), "{e}");
        }
        for e in [
            DialError::LocalSource("not a unicast address"),
            DialError::Connect(std::io::Error::from_raw_os_error(libc::EADDRNOTAVAIL)),
        ] {
            let f = DialFailure::of(&e, false, true);
            assert!(!f.provider_failed, "{e}");
            assert!(f.unit_failed && f.ip_level, "{e}");
            assert_eq!(f.outcome(), Outcome::Silent, "{e}");
        }
        // the same refusal charges a proxy provider
        assert!(DialFailure::of(&refused(), false, false).provider_failed);
    }
}
