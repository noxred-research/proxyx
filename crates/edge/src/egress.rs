//! Outgoing address pools: the local IPs the proxy connects from.
//!
//! A pool is a list of addresses assigned to this machine, written out or
//! discovered from an interface. Every address is checked at startup (and on
//! each reload): it must be assigned locally and bindable, so a typo fails at
//! `--check` time and never on the first request. [`Pool::pick`] chooses one
//! address of the destination's IP family by the pool's strategy; the caller
//! binds it before `connect`.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ipnet::IpNet;
use nix::ifaddrs::getifaddrs;
use nix::net::if_::InterfaceFlags;
use rand::Rng as _;
use sha2::{Digest as _, Sha256};

use crate::breaker::{Breaker, BreakerState, HealthTracker, Transitions};
use crate::config::{BreakerConfig, PoolConfig, Strategy};

/// IP family of a destination address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    pub fn of(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(_) => Family::V4,
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(Family::V6, |_| Family::V4),
        }
    }
}

/// One address of a pool.
#[derive(Debug)]
pub struct Addr {
    pub ip: IpAddr,
    /// Connections opened from this address and not closed yet.
    open: AtomicUsize,
    /// Guards the address from the results of real connects; `None` for an
    /// address drawn from a prefix, which lives for one connection.
    breaker: Option<Breaker>,
    /// Is the address still assigned to this host (the active check)?
    health: HealthTracker,
}

impl Addr {
    fn usable(&self) -> bool {
        self.health.is_healthy() && self.breaker.as_ref().is_none_or(Breaker::available)
    }

    fn acquire(&self) -> bool {
        self.breaker.as_ref().is_none_or(Breaker::try_acquire)
    }
}

/// An address in use. Dropping it closes the count of open connections.
#[derive(Debug)]
pub struct Lease {
    addr: Arc<Addr>,
    pool: Arc<str>,
    settled: bool,
}

impl Lease {
    /// The result of the connect from this address: a bind or routing failure
    /// is the address's, anything else the destination's and not reported.
    pub fn report(&mut self, ok: bool) {
        if !self.settled
            && let Some(b) = &self.addr.breaker
        {
            b.record(ok);
        }
        self.settled = true;
    }

    pub fn ip(&self) -> IpAddr {
        self.addr.ip
    }

    pub fn pool(&self) -> &str {
        &self.pool
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        if !self.settled
            && let Some(b) = &self.addr.breaker
        {
            b.cancel();
        }
        self.addr.open.fetch_sub(1, Ordering::Relaxed);
    }
}

/// What a sticky pick hashes.
#[derive(Debug, Clone, Copy)]
pub struct PickKey<'a> {
    pub session: Option<&'a str>,
    pub user: Option<&'a str>,
    pub client: IpAddr,
}

impl PickKey<'_> {
    /// The key as text, for filing idle connections.
    pub fn bytes_for_reuse(&self) -> Vec<u8> {
        self.bytes()
    }

    fn bytes(&self) -> Vec<u8> {
        match (self.session, self.user) {
            (Some(s), _) => format!("s:{s}"),
            (None, Some(u)) => format!("u:{u}"),
            (None, None) => format!("c:{}", self.client),
        }
        .into_bytes()
    }
}

/// Why a pick found nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PickError {
    /// The pool has no address of the destination's family.
    NoAddressOfFamily,
    /// The login asked for an address that does not exist or has the wrong family.
    BadIndex,
    /// Every address of the family is open (breaker), unhealthy, or at its probe limit.
    Unavailable,
}

#[derive(Debug)]
pub struct Pool {
    name: Arc<str>,
    addrs: Vec<Arc<Addr>>,
    /// Routed networks an address is drawn from per connection (one per IP family).
    prefixes: Vec<IpNet>,
    /// The active check of the prefixes: are they still routed to this host?
    prefix_health: HealthTracker,
    strategy: Strategy,
    rr: AtomicUsize,
}

impl Pool {
    /// Build a pool from explicit addresses (already checked by the caller).
    pub fn new(
        name: &str,
        ips: Vec<IpAddr>,
        strategy: Strategy,
        breaker: BreakerConfig,
        tr: &Transitions,
    ) -> Self {
        Self {
            name: Arc::from(name),
            addrs: ips
                .into_iter()
                .map(|ip| {
                    Arc::new(Addr {
                        ip,
                        open: AtomicUsize::new(0),
                        breaker: Some(Breaker::new(breaker, tr.clone())),
                        health: HealthTracker::new(1, 1),
                    })
                })
                .collect(),
            prefixes: Vec::new(),
            prefix_health: HealthTracker::new(1, 1),
            strategy,
            rr: AtomicUsize::new(0),
        }
    }

    /// Add networks to draw addresses from.
    pub fn with_prefixes(mut self, prefixes: Vec<IpNet>) -> Self {
        self.prefixes = prefixes;
        self
    }

    pub fn prefix_count(&self) -> usize {
        self.prefixes.len()
    }

    pub fn prefixes(&self) -> &[IpNet] {
        &self.prefixes
    }

    /// An address of `net` by the pool's strategy (or by `index`), a transient lease.
    fn pick_prefix(
        &self,
        net: &IpNet,
        key: &PickKey<'_>,
        index: Option<usize>,
        avoid: &[IpAddr],
    ) -> Result<Lease, PickError> {
        if !self.prefix_health.is_healthy() {
            return Err(PickError::Unavailable);
        }
        let host_bits = u32::from(net.max_prefix_len() - net.prefix_len());
        let span: u128 = if host_bits >= 128 {
            u128::MAX
        } else {
            (1u128 << host_bits) - 1
        };
        let usable = |o: u128| -> u128 {
            if span == 0 {
                return 0;
            }
            // Not the network address, and for IPv4 not the broadcast address.
            let o = o & span;
            if o == 0 {
                1
            } else if net.addr().is_ipv4() && host_bits >= 2 && o == span {
                span - 1
            } else {
                o
            }
        };
        let at = |o: u128| -> IpAddr {
            match net.network() {
                IpAddr::V4(b) => IpAddr::V4(std::net::Ipv4Addr::from(
                    u32::from(b).wrapping_add(o as u32),
                )),
                IpAddr::V6(b) => {
                    IpAddr::V6(std::net::Ipv6Addr::from(u128::from(b).wrapping_add(o)))
                }
            }
        };
        let mut chosen = if let Some(n) = index {
            let n = n as u128;
            if n == 0 || n > span {
                return Err(PickError::BadIndex);
            }
            at(n)
        } else {
            let offset = match self.strategy {
                Strategy::First => 1,
                Strategy::RoundRobin => self.rr.fetch_add(1, Ordering::Relaxed) as u128 + 1,
                Strategy::Sticky => {
                    let d = Sha256::digest(key.bytes());
                    u128::from_be_bytes(d[..16].try_into().unwrap_or([0; 16]))
                }
                Strategy::Random | Strategy::LeastConnections => rand::thread_rng().r#gen::<u128>(),
            };
            at(usable(offset))
        };
        // A retry after a failed bind draws again (a sticky or fixed pick keeps its address).
        for _ in 0..4 {
            if !avoid.contains(&chosen) || index.is_some() {
                break;
            }
            chosen = at(usable(rand::thread_rng().r#gen::<u128>()));
        }
        let addr = Arc::new(Addr {
            ip: chosen,
            open: AtomicUsize::new(1),
            breaker: None,
            health: HealthTracker::new(1, 1),
        });
        Ok(Lease {
            addr,
            pool: Arc::clone(&self.name),
            settled: true,
        })
    }

    /// Build a pool from its config: explicit addresses plus the interface's,
    /// each checked to be assigned to this host and bindable.
    pub fn from_config(
        c: &PoolConfig,
        breaker: BreakerConfig,
        tr: &Transitions,
    ) -> Result<Self, String> {
        let exclude: Vec<IpNet> = c
            .exclude
            .iter()
            .map(|e| {
                e.parse::<IpNet>()
                    .or_else(|_| e.parse::<IpAddr>().map(IpNet::from))
                    .map_err(|_| format!("pool {}: bad exclude {e:?}", c.name))
            })
            .collect::<Result<_, _>>()?;
        let mut ips: Vec<IpAddr> = Vec::new();
        for ip in &c.addresses {
            if !ips.contains(ip) {
                ips.push(*ip);
            }
        }
        if let Some(iface) = &c.interface {
            for ip in interface_addresses(iface, c.ipv4, c.ipv6)
                .map_err(|e| format!("pool {}: {e}", c.name))?
            {
                if !exclude.iter().any(|n| n.contains(&ip)) && !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
        }
        let prefixes: Vec<IpNet> = c
            .prefixes
            .iter()
            .map(|p| {
                p.parse::<IpNet>()
                    .map(|n| n.trunc())
                    .map_err(|_| format!("pool {}: bad prefix {p:?}", c.name))
            })
            .collect::<Result<_, _>>()?;
        if ips.is_empty() && prefixes.is_empty() {
            return Err(format!(
                "pool {}: no addresses (list `addresses` or `prefixes`, or name an `interface` that has some)",
                c.name
            ));
        }
        for ip in &ips {
            check_usable(*ip).map_err(|e| format!("pool {}: {e}", c.name))?;
        }
        for (i, net) in prefixes.iter().enumerate() {
            if prefixes[..i]
                .iter()
                .any(|o| Family::of(o.addr()) == Family::of(net.addr()))
            {
                return Err(format!("pool {}: one prefix per IP family", c.name));
            }
            if ips
                .iter()
                .any(|ip| Family::of(*ip) == Family::of(net.addr()))
            {
                return Err(format!(
                    "pool {}: {net} and the pool's own {} addresses cannot be mixed: use one or the other per IP family",
                    c.name,
                    if net.addr().is_ipv4() { "IPv4" } else { "IPv6" }
                ));
            }
            check_prefix(net).map_err(|e| format!("pool {}: {e}", c.name))?;
        }
        Ok(Self::new(&c.name, ips, c.strategy, breaker, tr).with_prefixes(prefixes))
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn addresses(&self) -> Vec<IpAddr> {
        self.addrs.iter().map(|a| a.ip).collect()
    }

    pub fn len(&self) -> usize {
        self.addrs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.addrs.is_empty()
    }

    /// Counts for the gauges: addresses open (breaker), half open, unhealthy (active check).
    pub fn states(&self) -> (usize, usize, usize) {
        let (mut open, mut half, mut unhealthy) = (0, 0, 0);
        for a in &self.addrs {
            if !a.health.is_healthy() {
                unhealthy += 1;
            }
            match a.breaker.as_ref().map(Breaker::state) {
                Some(BreakerState::Open) => open += 1,
                Some(BreakerState::HalfOpen) => half += 1,
                _ => {}
            }
        }
        (open, half, unhealthy)
    }

    /// Can this pool serve a connection now: an address that is healthy and
    /// not shut out by its breaker, or a prefix that is still routed here.
    pub fn is_usable(&self) -> bool {
        (!self.prefixes.is_empty() && self.prefix_health.is_healthy())
            || self.addrs.iter().any(|a| a.usable())
    }

    /// Run the active checks: is each address still assigned and bindable, is
    /// each prefix still routed here. Blocks (reads the interface list and
    /// binds sockets); call it from a blocking thread. Returns the results
    /// and the checks that changed a verdict, `(address text, now healthy)`.
    pub fn recheck(&self) -> Recheck {
        let local = local_addresses();
        let mut out = Recheck::default();
        for a in &self.addrs {
            let ok = check_usable_in(a.ip, &local).is_ok();
            if ok {
                out.ok += 1;
            } else {
                out.failed += 1;
            }
            if let Some(now) = a.health.observe(ok) {
                out.changed.push((a.ip.to_string(), now));
            }
        }
        for net in &self.prefixes {
            let ok = check_prefix(net).is_ok();
            if ok {
                out.ok += 1;
            } else {
                out.failed += 1;
            }
            if let Some(now) = self.prefix_health.observe(ok) {
                out.changed.push((net.to_string(), now));
            }
        }
        out
    }

    fn lease(&self, a: &Arc<Addr>) -> Lease {
        a.open.fetch_add(1, Ordering::Relaxed);
        Lease {
            addr: Arc::clone(a),
            pool: Arc::clone(&self.name),
            settled: false,
        }
    }

    /// Pick an address of `family`. `index` is the 1-based position the login
    /// asked for (`-ip-<n>`). `avoid` holds addresses that just failed.
    /// Addresses that are unhealthy or shut out by their breaker are never
    /// picked; when none is left the error is [`PickError::Unavailable`].
    pub fn pick(
        &self,
        family: Family,
        key: &PickKey<'_>,
        index: Option<usize>,
        avoid: &[IpAddr],
    ) -> Result<Lease, PickError> {
        if let Some(net) = self
            .prefixes
            .iter()
            .find(|n| Family::of(n.addr()) == family)
        {
            return self.pick_prefix(net, key, index, avoid);
        }
        if let Some(n) = index {
            let a = n
                .checked_sub(1)
                .and_then(|i| self.addrs.get(i))
                .filter(|a| Family::of(a.ip) == family)
                .ok_or(PickError::BadIndex)?;
            return if a.health.is_healthy() && a.acquire() {
                Ok(self.lease(a))
            } else {
                Err(PickError::Unavailable)
            };
        }
        let all: Vec<&Arc<Addr>> = self
            .addrs
            .iter()
            .filter(|a| Family::of(a.ip) == family)
            .collect();
        if all.is_empty() {
            return Err(PickError::NoAddressOfFamily);
        }
        let mut cands: Vec<&Arc<Addr>> = all.into_iter().filter(|a| a.usable()).collect();
        let fresh: Vec<&Arc<Addr>> = cands
            .iter()
            .copied()
            .filter(|a| !avoid.contains(&a.ip))
            .collect();
        if !fresh.is_empty() {
            cands = fresh;
        }
        let sticky_key = key.bytes();
        while !cands.is_empty() {
            let i = match self.strategy {
                Strategy::First => 0,
                Strategy::RoundRobin => self.rr.fetch_add(1, Ordering::Relaxed) % cands.len(),
                Strategy::Random => rand::thread_rng().gen_range(0..cands.len()),
                Strategy::LeastConnections => cands
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, a)| a.open.load(Ordering::Relaxed))
                    .map_or(0, |(i, _)| i),
                Strategy::Sticky => cands
                    .iter()
                    .enumerate()
                    .max_by_key(|(_, a)| rendezvous(&sticky_key, a.ip))
                    .map_or(0, |(i, _)| i),
            };
            // A half-open breaker lets only a few probes through: take the slot
            // or move on to the next address.
            if cands[i].acquire() {
                return Ok(self.lease(cands[i]));
            }
            cands.remove(i);
        }
        Err(PickError::Unavailable)
    }
}

/// What a round of active checks of one pool found.
#[derive(Debug, Default)]
pub struct Recheck {
    pub ok: usize,
    pub failed: usize,
    pub changed: Vec<(String, bool)>,
}

/// Highest-random-weight score of `(key, address)`: the same key keeps the
/// same address while the address set stays, and removing an address moves
/// only the keys that were on it.
fn rendezvous(key: &[u8], ip: IpAddr) -> u64 {
    let mut h = Sha256::new();
    h.update(key);
    h.update([0]);
    h.update(ip.to_string().as_bytes());
    let d = h.finalize();
    u64::from_be_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]])
}

/// Addresses of an interface that can be an exit: no loopback (unless the
/// interface is a loopback one), link-local, multicast or unspecified.
pub fn interface_addresses(iface: &str, v4: bool, v6: bool) -> Result<Vec<IpAddr>, String> {
    let all = getifaddrs().map_err(|e| format!("list interfaces: {e}"))?;
    let mut found = false;
    let mut out = Vec::new();
    for ia in all.filter(|ia| ia.interface_name == iface) {
        found = true;
        let loopback = ia.flags.contains(InterfaceFlags::IFF_LOOPBACK);
        let Some(addr) = ia.address else { continue };
        let ip = if let Some(a) = addr.as_sockaddr_in() {
            IpAddr::V4(a.ip())
        } else if let Some(a) = addr.as_sockaddr_in6() {
            IpAddr::V6(a.ip())
        } else {
            continue;
        };
        let usable = match ip {
            IpAddr::V4(a) => {
                v4 && !a.is_unspecified()
                    && !a.is_multicast()
                    && !a.is_link_local()
                    && (loopback || !a.is_loopback())
            }
            IpAddr::V6(a) => {
                v6 && !a.is_unspecified()
                    && !a.is_multicast()
                    && a.segments()[0] & 0xffc0 != 0xfe80
                    && (loopback || !a.is_loopback())
            }
        };
        if usable && !out.contains(&ip) {
            out.push(ip);
        }
    }
    if !found {
        return Err(format!("interface {iface:?} not found"));
    }
    Ok(out)
}

/// Every address assigned to a local interface.
fn local_addresses() -> HashSet<IpAddr> {
    let mut set = HashSet::new();
    if let Ok(all) = getifaddrs() {
        for ia in all {
            let Some(addr) = ia.address else { continue };
            if let Some(a) = addr.as_sockaddr_in() {
                set.insert(IpAddr::V4(a.ip()));
            } else if let Some(a) = addr.as_sockaddr_in6() {
                set.insert(IpAddr::V6(a.ip()));
            }
        }
    }
    set
}

/// Check that addresses of `net` can be sources: the network must be routed to
/// this host (`ip route add local <net> dev lo`), so that binding any of its
/// addresses works. A few of them are tried: the first, the last, and two at random.
pub fn check_prefix(net: &IpNet) -> Result<(), String> {
    let host_bits = u32::from(net.max_prefix_len() - net.prefix_len());
    if host_bits >= 128 || (net.addr().is_ipv4() && host_bits >= 32) {
        return Err(format!("{net} is not a network"));
    }
    let span: u128 = (1u128 << host_bits) - 1;
    let at = |o: u128| -> IpAddr {
        match net.network() {
            IpAddr::V4(b) => IpAddr::V4(std::net::Ipv4Addr::from(
                u32::from(b).wrapping_add(o as u32),
            )),
            IpAddr::V6(b) => IpAddr::V6(std::net::Ipv6Addr::from(u128::from(b).wrapping_add(o))),
        }
    };
    let mut rng = rand::thread_rng();
    let samples = [
        1u128.min(span),
        span.saturating_sub(1).max(1).min(span),
        rng.r#gen::<u128>() & span,
        rng.r#gen::<u128>() & span,
    ];
    for o in samples {
        let ip = at(o);
        let domain = if ip.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        };
        let sock = socket2::Socket::new(domain, socket2::Type::STREAM, None)
            .map_err(|e| format!("open socket: {e}"))?;
        sock.bind(&SocketAddr::new(ip, 0).into()).map_err(|e| {
            format!("cannot bind {ip} from {net}: {e} (route the prefix to this host: `ip route add local {net} dev lo`)")
        })?;
    }
    Ok(())
}

/// Check that `ip` can be a source address: assigned to this host (the
/// loopback networks count as assigned: `127.0.0.2` works on Linux with no
/// alias) and bindable.
pub fn check_usable(ip: IpAddr) -> Result<(), String> {
    check_usable_in(ip, &local_addresses())
}

/// [`check_usable`] against an interface list read once for many addresses.
fn check_usable_in(ip: IpAddr, local: &HashSet<IpAddr>) -> Result<(), String> {
    if ip.is_unspecified() || ip.is_multicast() {
        return Err(format!("{ip} is not a unicast address"));
    }
    if !ip.is_loopback() && !local.contains(&ip) {
        return Err(format!(
            "{ip} is not assigned to any local interface (add it with `ip addr add`)"
        ));
    }
    let domain = match ip {
        IpAddr::V4(_) => socket2::Domain::IPV4,
        IpAddr::V6(_) => socket2::Domain::IPV6,
    };
    let sock = socket2::Socket::new(domain, socket2::Type::STREAM, None)
        .map_err(|e| format!("open socket for {ip}: {e}"))?;
    sock.bind(&SocketAddr::new(ip, 0).into())
        .map_err(|e| format!("cannot bind {ip}: {e}"))
}

#[cfg(test)]
impl Pool {
    fn from_config_test(c: &PoolConfig) -> Result<Self, String> {
        Self::from_config(c, BreakerConfig::default(), &Transitions::detached())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(strategy: Strategy, addrs: &[&str]) -> Pool {
        pool_with(strategy, addrs, BreakerConfig::default())
    }

    fn pool_with(strategy: Strategy, addrs: &[&str], b: BreakerConfig) -> Pool {
        Pool::new(
            "p",
            addrs.iter().map(|a| a.parse().expect("ip")).collect(),
            strategy,
            b,
            &Transitions::detached(),
        )
    }

    fn key() -> PickKey<'static> {
        PickKey {
            session: None,
            user: None,
            client: "198.51.100.7".parse().expect("ip"),
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("ip")
    }

    #[test]
    fn first_always_picks_the_first_of_the_family() {
        let p = pool(Strategy::First, &["::1", "127.0.0.2", "127.0.0.3"]);
        for _ in 0..4 {
            assert_eq!(
                p.pick(Family::V4, &key(), None, &[]).expect("pick").ip(),
                ip("127.0.0.2")
            );
        }
        assert_eq!(
            p.pick(Family::V6, &key(), None, &[]).expect("pick").ip(),
            ip("::1")
        );
    }

    #[test]
    fn round_robin_cycles_inside_the_family() {
        let p = pool(
            Strategy::RoundRobin,
            &["127.0.0.2", "::1", "127.0.0.3", "127.0.0.4"],
        );
        let got: Vec<IpAddr> = (0..6)
            .map(|_| p.pick(Family::V4, &key(), None, &[]).expect("pick").ip())
            .collect();
        let want: Vec<IpAddr> = [
            "127.0.0.2",
            "127.0.0.3",
            "127.0.0.4",
            "127.0.0.2",
            "127.0.0.3",
            "127.0.0.4",
        ]
        .iter()
        .map(|s| ip(s))
        .collect();
        assert_eq!(got, want);
    }

    #[test]
    fn random_reaches_every_address() {
        let p = pool(Strategy::Random, &["127.0.0.2", "127.0.0.3", "127.0.0.4"]);
        let seen: HashSet<IpAddr> = (0..200)
            .map(|_| p.pick(Family::V4, &key(), None, &[]).expect("pick").ip())
            .collect();
        assert_eq!(seen.len(), 3);
    }

    #[test]
    fn least_connections_follows_the_open_count() {
        let p = pool(Strategy::LeastConnections, &["127.0.0.2", "127.0.0.3"]);
        let a = p.pick(Family::V4, &key(), None, &[]).expect("pick");
        let b = p.pick(Family::V4, &key(), None, &[]).expect("pick");
        assert_ne!(a.ip(), b.ip());
        let freed = a.ip();
        drop(a);
        assert_eq!(
            p.pick(Family::V4, &key(), None, &[]).expect("pick").ip(),
            freed
        );
        drop(b);
    }

    #[test]
    fn sticky_keeps_a_key_on_one_address_and_spreads_keys() {
        let p = pool(
            Strategy::Sticky,
            &["127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.5"],
        );
        let pick = |s: &str| {
            p.pick(
                Family::V4,
                &PickKey {
                    session: Some(s),
                    user: Some("u"),
                    client: ip("1.1.1.1"),
                },
                None,
                &[],
            )
            .expect("pick")
            .ip()
        };
        assert_eq!(pick("abc"), pick("abc"));
        let spread: HashSet<IpAddr> = (0..64).map(|i| pick(&format!("sid{i}"))).collect();
        assert!(spread.len() >= 3, "{spread:?}");
        // the session id outranks the user, the user outranks the client address
        let by_user = |u: &str, c: &str| {
            p.pick(
                Family::V4,
                &PickKey {
                    session: None,
                    user: Some(u),
                    client: ip(c),
                },
                None,
                &[],
            )
            .expect("pick")
            .ip()
        };
        assert_eq!(by_user("bob", "1.1.1.1"), by_user("bob", "2.2.2.2"));
    }

    #[test]
    fn sticky_moves_only_the_keys_of_a_removed_address() {
        let full = pool(Strategy::Sticky, &["127.0.0.2", "127.0.0.3", "127.0.0.4"]);
        let less = pool(Strategy::Sticky, &["127.0.0.2", "127.0.0.3"]);
        for i in 0..100 {
            let k = PickKey {
                session: Some(&format!("s{i}")),
                user: None,
                client: ip("1.1.1.1"),
            };
            let before = full.pick(Family::V4, &k, None, &[]).expect("pick").ip();
            let after = less.pick(Family::V4, &k, None, &[]).expect("pick").ip();
            if before != ip("127.0.0.4") {
                assert_eq!(before, after, "key s{i} moved though its address stayed");
            }
        }
    }

    #[test]
    fn family_without_addresses_is_an_error() {
        let p = pool(Strategy::RoundRobin, &["127.0.0.2"]);
        assert_eq!(
            p.pick(Family::V6, &key(), None, &[]).expect_err("none"),
            PickError::NoAddressOfFamily
        );
    }

    #[test]
    fn an_index_picks_by_position_and_checks_the_family() {
        let p = pool(Strategy::RoundRobin, &["127.0.0.2", "::1", "127.0.0.3"]);
        assert_eq!(
            p.pick(Family::V4, &key(), Some(3), &[]).expect("pick").ip(),
            ip("127.0.0.3")
        );
        assert_eq!(
            p.pick(Family::V6, &key(), Some(2), &[]).expect("pick").ip(),
            ip("::1")
        );
        for (fam, n) in [(Family::V4, 2), (Family::V4, 0), (Family::V4, 9)] {
            assert_eq!(
                p.pick(fam, &key(), Some(n), &[]).expect_err("bad"),
                PickError::BadIndex
            );
        }
    }

    fn fast_breaker() -> BreakerConfig {
        BreakerConfig {
            failure_threshold: 2,
            open_duration: std::time::Duration::from_millis(80),
            half_open_probes: 1,
            success_threshold: 1,
        }
    }

    #[test]
    fn a_failing_address_opens_its_breaker_and_traffic_moves_on() {
        let p = pool_with(Strategy::First, &["127.0.0.2", "127.0.0.3"], fast_breaker());
        for _ in 0..2 {
            let mut l = p.pick(Family::V4, &key(), None, &[]).expect("pick");
            assert_eq!(l.ip(), ip("127.0.0.2"));
            l.report(false);
        }
        assert_eq!(p.states(), (1, 0, 0));
        assert_eq!(
            p.pick(Family::V4, &key(), None, &[]).expect("pick").ip(),
            ip("127.0.0.3")
        );
        // after the open time one probe goes to the first address again; success closes it
        std::thread::sleep(std::time::Duration::from_millis(120));
        let mut probe = p.pick(Family::V4, &key(), None, &[]).expect("probe");
        assert_eq!(probe.ip(), ip("127.0.0.2"));
        assert_eq!(p.states(), (0, 1, 0));
        // the probe slot is taken: the next pick goes elsewhere
        assert_eq!(
            p.pick(Family::V4, &key(), None, &[]).expect("pick").ip(),
            ip("127.0.0.3")
        );
        probe.report(true);
        assert_eq!(p.states(), (0, 0, 0));
        assert_eq!(
            p.pick(Family::V4, &key(), None, &[]).expect("pick").ip(),
            ip("127.0.0.2")
        );
    }

    #[test]
    fn a_pool_with_every_address_shut_out_is_unavailable_not_forced() {
        let p = pool_with(Strategy::First, &["127.0.0.2"], fast_breaker());
        for _ in 0..2 {
            p.pick(Family::V4, &key(), None, &[])
                .expect("pick")
                .report(false);
        }
        assert!(!p.is_usable());
        assert_eq!(
            p.pick(Family::V4, &key(), None, &[]).expect_err("open"),
            PickError::Unavailable
        );
        assert_eq!(
            p.pick(Family::V4, &key(), Some(1), &[]).expect_err("open"),
            PickError::Unavailable
        );
        std::thread::sleep(std::time::Duration::from_millis(120));
        assert!(p.is_usable());
        assert!(p.pick(Family::V4, &key(), None, &[]).is_ok());
    }

    #[test]
    fn an_unreported_lease_is_not_a_verdict() {
        let p = pool_with(Strategy::First, &["127.0.0.2"], fast_breaker());
        for _ in 0..5 {
            drop(p.pick(Family::V4, &key(), None, &[]).expect("pick"));
        }
        assert_eq!(
            p.states(),
            (0, 0, 0),
            "the destination's refusals are not the address's"
        );
    }

    #[test]
    fn a_failed_active_check_takes_an_address_out_until_it_passes() {
        let p = pool_with(
            Strategy::First,
            &["127.0.0.2", "127.0.0.3"],
            BreakerConfig::default(),
        );
        // 127.0.0.2 stays "assigned" (loopback), so force the tracker the way a failed check would
        assert_eq!(p.addrs[0].health.observe(false), Some(false));
        assert_eq!(p.states(), (0, 0, 1));
        assert_eq!(
            p.pick(Family::V4, &key(), None, &[]).expect("pick").ip(),
            ip("127.0.0.3")
        );
        assert_eq!(
            p.pick(Family::V4, &key(), Some(1), &[]).expect_err("down"),
            PickError::Unavailable
        );
        let r = p.recheck();
        assert_eq!((r.ok, r.failed), (2, 0), "{r:?}");
        assert_eq!(r.changed, vec![("127.0.0.2".to_owned(), true)]);
        assert_eq!(
            p.pick(Family::V4, &key(), None, &[]).expect("pick").ip(),
            ip("127.0.0.2")
        );
    }

    #[test]
    fn recheck_marks_an_address_that_is_no_longer_local() {
        // not assigned anywhere: the check fails the way a removed `ip addr` would
        let p = pool_with(
            Strategy::First,
            &["203.0.113.5", "127.0.0.2"],
            BreakerConfig::default(),
        );
        let r = p.recheck();
        assert_eq!((r.ok, r.failed), (1, 1));
        assert_eq!(r.changed, vec![("203.0.113.5".to_owned(), false)]);
        assert!(p.is_usable());
    }

    #[test]
    fn avoid_steers_a_retry_to_another_address() {
        let p = pool(Strategy::First, &["127.0.0.2", "127.0.0.3"]);
        let got = p
            .pick(Family::V4, &key(), None, &[ip("127.0.0.2")])
            .expect("pick");
        assert_eq!(got.ip(), ip("127.0.0.3"));
        let only = pool(Strategy::First, &["127.0.0.2"]);
        assert_eq!(
            only.pick(Family::V4, &key(), None, &[ip("127.0.0.2")])
                .expect("pick")
                .ip(),
            ip("127.0.0.2"),
            "nothing else to try"
        );
    }

    #[test]
    fn family_of_maps_v4_in_v6() {
        assert_eq!(Family::of(ip("::ffff:1.2.3.4")), Family::V4);
        assert_eq!(Family::of(ip("2001:db8::1")), Family::V6);
    }

    #[test]
    fn loopback_aliases_are_usable_and_foreign_addresses_are_not() {
        assert!(check_usable(ip("127.0.0.2")).is_ok());
        assert!(check_usable(ip("127.0.0.3")).is_ok());
        let err = check_usable(ip("203.0.113.77")).expect_err("not local");
        assert!(err.contains("not assigned"), "{err}");
        assert!(check_usable(ip("0.0.0.0")).is_err());
        assert!(check_usable(ip("224.0.0.1")).is_err());
    }

    #[test]
    fn from_config_validates_and_discovers_loopback() {
        let c = |toml: &str| {
            crate::config::Config::parse(toml)
                .expect("parse")
                .pools
                .remove(0)
        };
        let p = Pool::from_config_test(&c(
            "[[pool]]\nname = \"lo\"\ninterface = \"lo\"\nipv6 = false\n",
        ))
        .expect("lo pool");
        assert!(p.addresses().contains(&ip("127.0.0.1")));
        assert!(
            Pool::from_config_test(&c("[[pool]]\nname = \"x\"\ninterface = \"nonexistent0\"\n"))
                .is_err()
        );
        assert!(Pool::from_config_test(&c("[[pool]]\nname = \"x\"\n")).is_err());
        assert!(
            Pool::from_config_test(&c(
                "[[pool]]\nname = \"x\"\naddresses = [\"203.0.113.9\"]\n"
            ))
            .is_err()
        );
        let ex = Pool::from_config_test(&c(
            "[[pool]]\nname = \"lo\"\ninterface = \"lo\"\nexclude = [\"127.0.0.0/8\"]\nipv6 = false\naddresses = [\"127.0.0.2\"]\n",
        ))
        .expect("excluded");
        assert_eq!(ex.addresses(), vec![ip("127.0.0.2")]);
    }
}

#[cfg(test)]
mod prefix_tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("ip")
    }

    fn key(s: &str) -> PickKey<'_> {
        PickKey {
            session: Some(s),
            user: None,
            client: ip("198.51.100.7"),
        }
    }

    fn prefix_pool(strategy: Strategy, net: &str) -> Pool {
        Pool::new(
            "p",
            Vec::new(),
            strategy,
            BreakerConfig::default(),
            &Transitions::detached(),
        )
        .with_prefixes(vec![net.parse::<IpNet>().expect("net")])
    }

    #[test]
    fn random_draws_stay_inside_the_prefix_and_vary() {
        let p = prefix_pool(Strategy::Random, "127.0.1.0/24");
        let net: IpNet = "127.0.1.0/24".parse().expect("net");
        let mut seen = HashSet::new();
        for _ in 0..200 {
            let l = p.pick(Family::V4, &key("a"), None, &[]).expect("pick");
            assert!(net.contains(&l.ip()), "{}", l.ip());
            assert_ne!(l.ip(), ip("127.0.1.0"), "network address");
            assert_ne!(l.ip(), ip("127.0.1.255"), "broadcast address");
            seen.insert(l.ip());
        }
        assert!(seen.len() > 50, "{}", seen.len());
        assert_eq!(
            p.pick(Family::V6, &key("a"), None, &[]).expect_err("v6"),
            PickError::NoAddressOfFamily
        );
    }

    #[test]
    fn sticky_maps_a_session_to_one_address_and_round_robin_walks() {
        let p = prefix_pool(Strategy::Sticky, "2001:db8:1234::/64");
        let a = p
            .pick(Family::V6, &key("sess"), None, &[])
            .expect("pick")
            .ip();
        let b = p
            .pick(Family::V6, &key("sess"), None, &[])
            .expect("pick")
            .ip();
        let c = p
            .pick(Family::V6, &key("other"), None, &[])
            .expect("pick")
            .ip();
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(
            "2001:db8:1234::/64"
                .parse::<IpNet>()
                .expect("net")
                .contains(&a)
        );
        let rr = prefix_pool(Strategy::RoundRobin, "127.0.2.0/24");
        let got: Vec<IpAddr> = (0..3)
            .map(|_| {
                rr.pick(Family::V4, &key("x"), None, &[])
                    .expect("pick")
                    .ip()
            })
            .collect();
        assert_eq!(got, vec![ip("127.0.2.1"), ip("127.0.2.2"), ip("127.0.2.3")]);
    }

    #[test]
    fn an_index_picks_by_offset_and_avoid_redraws() {
        let p = prefix_pool(Strategy::Random, "127.0.3.0/24");
        assert_eq!(
            p.pick(Family::V4, &key("x"), Some(7), &[])
                .expect("pick")
                .ip(),
            ip("127.0.3.7")
        );
        assert_eq!(
            p.pick(Family::V4, &key("x"), Some(0), &[])
                .expect_err("bad"),
            PickError::BadIndex
        );
        assert_eq!(
            p.pick(Family::V4, &key("x"), Some(256), &[])
                .expect_err("bad"),
            PickError::BadIndex
        );
        let one = prefix_pool(Strategy::First, "127.0.4.9/32");
        assert_eq!(
            one.pick(Family::V4, &key("x"), None, &[])
                .expect("pick")
                .ip(),
            ip("127.0.4.9")
        );
    }

    #[test]
    fn config_checks_prefixes() {
        let cfg = |t: &str| {
            crate::config::Config::parse(t)
                .expect("parse")
                .pools
                .remove(0)
        };
        let ok = Pool::from_config_test(&cfg(
            "[[pool]]\nname = \"p\"\nprefixes = [\"127.0.5.0/24\"]\nstrategy = \"random\"\n",
        ))
        .expect("pool");
        assert_eq!(ok.prefix_count(), 1);
        assert!(ok.addresses().is_empty());
        for bad in [
            "[[pool]]\nname = \"p\"\nprefixes = [\"nonsense\"]\n",
            "[[pool]]\nname = \"p\"\nprefixes = [\"127.0.5.0/24\", \"127.0.6.0/24\"]\n",
            "[[pool]]\nname = \"p\"\naddresses = [\"127.0.0.2\"]\nprefixes = [\"127.0.5.0/24\"]\n",
            // routed nowhere: binding an address of it fails
            "[[pool]]\nname = \"p\"\nprefixes = [\"203.0.113.0/24\"]\n",
        ] {
            assert!(Pool::from_config_test(&cfg(bad)).is_err(), "{bad}");
        }
        // a pool of both families: IPv4 explicit, IPv6 prefix
        let _ = Pool::from_config_test(&cfg(
            "[[pool]]\nname = \"p\"\naddresses = [\"127.0.0.2\"]\nprefixes = [\"::1/128\"]\n",
        ));
    }
}
