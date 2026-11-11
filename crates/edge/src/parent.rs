//! Parent proxies: weights, priority tiers and passive health.
//!
//! The parents of a request are the configured ones, or the subset a
//! `[[route]]` names. The lowest priority tier with a parent that is not
//! down serves it; inside the tier the choice is random by weight. A parent
//! that trips its circuit breaker (`[breaker.parent]`) or fails its active
//! health check (`[health]`) is out of use; the breaker lets probes through
//! after `open_duration`.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::Secret;
use common::types::{ProviderId, UpstreamEndpoint, UpstreamScheme};
use parking_lot::Mutex;
use rand::Rng as _;
use sha2::{Digest as _, Sha256};
use tokio_util::sync::CancellationToken;

use crate::breaker::{Breaker, BreakerState, HealthTracker, Transitions};
use crate::config::{
    BreakerConfig, HealthConfig, ParentConfig, ParentKind, SelectorConfig, SendProxyProtocol,
    Strategy,
};
use crate::egress::PickKey;

#[derive(Debug)]
pub struct Parent {
    pub name: String,
    pub kind: ParentKind,
    pub host: String,
    pub port: u16,
    pub weight: u32,
    pub priority: u32,
    pub pool: Option<String>,
    pub send_proxy_protocol: SendProxyProtocol,
    endpoint: UpstreamEndpoint,
    /// Results of real requests.
    pub breaker: Breaker,
    /// Results of the active probes.
    pub health: HealthTracker,
    pub backup: bool,
    pub default: bool,
    pub probe: Option<crate::config::ProbeConfig>,
    active: AtomicU64,
    attempts: AtomicU64,
    failures: AtomicU64,
    latency_us: AtomicU64,
    latency_total_us: AtomicU64,
    latency_samples: AtomicU64,
}

/// Split `host:port` / `[v6]:port`.
pub fn split_host_port(s: &str) -> Option<(String, u16)> {
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (h, rest) = rest.split_once(']')?;
        (h, rest.strip_prefix(':')?)
    } else {
        let (h, p) = s.rsplit_once(':')?;
        if h.contains(':') {
            return None;
        }
        (h, p)
    };
    let port: u16 = port.parse().ok().filter(|&p| p != 0)?;
    if host.is_empty() || host.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return None;
    }
    Some((host.to_owned(), port))
}

impl Parent {
    pub fn from_config(
        c: &ParentConfig,
        breaker: BreakerConfig,
        health: &HealthConfig,
        tr: &Transitions,
    ) -> Result<Self, String> {
        let breaker = BreakerConfig {
            failure_threshold: c.max_fails.unwrap_or(breaker.failure_threshold),
            open_duration: c.fail_timeout.unwrap_or(breaker.open_duration),
            ..breaker
        };
        breaker.check(&format!("parent {}", c.name))?;
        let provider: ProviderId = c.name.parse().map_err(|_| {
            format!(
                "parent {:?}: the name must be [a-z0-9_-], at most 48 characters",
                c.name
            )
        })?;
        let (host, port) = split_host_port(&c.address).ok_or_else(|| {
            format!(
                "parent {}: address {:?} is not host:port",
                c.name, c.address
            )
        })?;
        if c.weight == 0 {
            return Err(format!("parent {}: weight must be above zero", c.name));
        }
        if c.kind != ParentKind::Socks4 && c.username.is_some() != c.password.is_some() {
            return Err(format!(
                "parent {}: set username and password together",
                c.name
            ));
        }
        if c.kind == ParentKind::Socks4 && c.password.is_some() {
            return Err(format!(
                "parent {}: SOCKS4 uses username as user ID and has no password",
                c.name
            ));
        }
        let endpoint = UpstreamEndpoint {
            provider,
            scheme: match c.kind {
                ParentKind::Http => UpstreamScheme::Http,
                ParentKind::Https => UpstreamScheme::Https,
                // SOCKS4 handshakes use the parent kind directly, not this dial scheme.
                ParentKind::Socks4 | ParentKind::Socks5 => UpstreamScheme::Socks5,
            },
            host: host.clone(),
            port,
            username: Secret::new(c.username.clone().unwrap_or_default()),
            password: c.password.clone().unwrap_or_default(),
            public_only: false,
        };
        Ok(Self {
            name: c.name.clone(),
            kind: c.kind,
            host,
            port,
            weight: c.weight,
            priority: c.priority,
            pool: c.pool.clone(),
            send_proxy_protocol: c.send_proxy_protocol,
            endpoint,
            breaker: Breaker::new(breaker, tr.clone()),
            health: HealthTracker::new(health.unhealthy_threshold, health.healthy_threshold),
            backup: c.backup,
            default: c.default,
            probe: c.probe.clone(),
            active: AtomicU64::new(0),
            attempts: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            latency_us: AtomicU64::new(0),
            latency_total_us: AtomicU64::new(0),
            latency_samples: AtomicU64::new(0),
        })
    }

    /// The endpoint the `dial` handshakes read the credential from.
    pub fn endpoint(&self) -> &UpstreamEndpoint {
        &self.endpoint
    }

    /// True while the parent is out of use: unhealthy by its probes, or shut
    /// out by its breaker.
    pub fn is_down(&self) -> bool {
        !self.health.is_healthy() || !self.breaker.available()
    }

    pub fn state(&self) -> BreakerState {
        self.breaker.state()
    }

    /// The result of a request through the parent (a connect or handshake).
    pub fn report(&self, ok: bool) {
        self.breaker.record(ok);
    }

    pub(crate) fn failed_attempt(&self) {
        self.attempts.fetch_add(1, Ordering::Relaxed);
        self.failures.fetch_add(1, Ordering::Relaxed);
        self.report(false);
    }

    pub fn record_latency(&self, elapsed: Duration) {
        let us = u64::try_from(elapsed.as_micros())
            .unwrap_or(u64::MAX)
            .max(1);
        self.latency_us.store(us, Ordering::Relaxed);
        self.latency_total_us.fetch_add(us, Ordering::Relaxed);
        self.latency_samples.fetch_add(1, Ordering::Relaxed);
    }

    pub fn latency(&self) -> Option<Duration> {
        match self.latency_us.load(Ordering::Relaxed) {
            0 => None,
            us => Some(Duration::from_micros(us)),
        }
    }

    pub fn stats(&self) -> ParentStats {
        let samples = self.latency_samples.load(Ordering::Relaxed);
        ParentStats {
            active: self.active.load(Ordering::Relaxed),
            attempts: self.attempts.load(Ordering::Relaxed),
            failures: self.failures.load(Ordering::Relaxed),
            mean_latency_ms: if samples == 0 {
                0.0
            } else {
                self.latency_total_us.load(Ordering::Relaxed) as f64 / samples as f64 / 1000.0
            },
        }
    }

    /// `Basic ...` for the `Proxy-Authorization` header of an HTTP parent.
    pub fn proxy_authorization(&self) -> Option<String> {
        if self.endpoint.username.is_empty() {
            return None;
        }
        let raw = format!(
            "{}:{}",
            self.endpoint.username.expose(),
            self.endpoint.password.expose()
        );
        Some(format!("Basic {}", STANDARD.encode(raw)))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ParentStats {
    pub active: u64,
    pub attempts: u64,
    pub failures: u64,
    pub mean_latency_ms: f64,
}

/// Returns a half-open slot when a race or request is canceled.
pub struct Attempt {
    parent: Arc<Parent>,
    started: Instant,
    finished: bool,
}

impl Attempt {
    pub fn start(parent: &Arc<Parent>) -> Option<Self> {
        parent.breaker.try_acquire().then(|| Self {
            parent: Arc::clone(parent),
            started: Instant::now(),
            finished: false,
        })
    }

    pub fn finish(mut self, ok: bool) {
        self.finished = true;
        self.parent.attempts.fetch_add(1, Ordering::Relaxed);
        if ok {
            self.parent.record_latency(self.started.elapsed());
        } else {
            self.parent.failures.fetch_add(1, Ordering::Relaxed);
        }
        self.parent.report(ok);
    }

    /// HTTP forwarding has not proved proxy credentials or target reachability yet.
    /// Its response supplies the breaker verdict; abandoned reservations expire normally.
    pub fn defer_http(mut self, reused: bool) {
        self.finished = true;
        self.parent.attempts.fetch_add(1, Ordering::Relaxed);
        if !reused {
            self.parent.record_latency(self.started.elapsed());
        }
    }
}

impl Drop for Attempt {
    fn drop(&mut self) {
        if !self.finished {
            self.parent.breaker.cancel();
        }
    }
}

/// Counts parents for the complete stream lifetime, including idle keep-alive.
pub struct ParentUse(pub Vec<Arc<Parent>>);

impl ParentUse {
    pub fn new(parents: Vec<Arc<Parent>>) -> Self {
        for parent in &parents {
            parent.active.fetch_add(1, Ordering::Relaxed);
        }
        Self(parents)
    }
    pub fn failed(&self) {
        for parent in &self.0 {
            parent.failures.fetch_add(1, Ordering::Relaxed);
            parent.report(false);
        }
    }
}

impl Drop for ParentUse {
    fn drop(&mut self) {
        for parent in &self.0 {
            parent.active.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// State belongs to one selector, not to individual calls or shared parent nodes.
#[derive(Debug)]
pub struct Selector {
    pub cfg: SelectorConfig,
    cursor: AtomicU64,
    current: Mutex<Option<usize>>,
    last_used: Mutex<Instant>,
    switch: Mutex<CancellationToken>,
}

impl Selector {
    pub fn new(cfg: SelectorConfig) -> Self {
        Self {
            cfg,
            cursor: AtomicU64::new(0),
            current: Mutex::new(None),
            last_used: Mutex::new(Instant::now()),
            switch: Mutex::new(CancellationToken::new()),
        }
    }

    pub fn touch(&self) {
        *self.last_used.lock() = Instant::now();
    }
    pub fn idle(&self) -> bool {
        !self.cfg.idle_timeout.is_zero() && self.last_used.lock().elapsed() >= self.cfg.idle_timeout
    }
    pub fn token(&self) -> Option<CancellationToken> {
        self.cfg
            .interrupt_on_switch
            .then(|| self.switch.lock().clone())
    }

    /// A dial finishing after a switch must not attach the new generation to an old path.
    pub fn token_for(&self, index: usize) -> Option<CancellationToken> {
        if !self.cfg.interrupt_on_switch {
            return None;
        }
        let current = self.current.lock();
        if self.cfg.strategy == Strategy::Latency
            && current.is_some_and(|selected| selected != index)
        {
            let token = CancellationToken::new();
            token.cancel();
            return Some(token);
        }
        Some(self.switch.lock().clone())
    }
    pub fn choose_probe(
        &self,
        parents: &Parents,
        allowed: &[usize],
        key: &PickKey<'_>,
    ) -> Option<usize> {
        self.choose_candidates(parents, &parents.candidates(allowed, &[]), key)
    }
    pub fn choose(
        &self,
        parents: &Parents,
        allowed: &[usize],
        exclude: &[usize],
        key: &PickKey<'_>,
    ) -> Option<usize> {
        self.touch();
        let candidates = parents.candidates(allowed, exclude);
        self.choose_candidates(parents, &candidates, key)
    }

    fn choose_candidates(
        &self,
        parents: &Parents,
        candidates: &[usize],
        key: &PickKey<'_>,
    ) -> Option<usize> {
        let first = *candidates.first()?;
        let total: u64 = candidates
            .iter()
            .map(|&i| u64::from(parents.list[i].weight))
            .sum();
        let weighted = |mut n: u64| {
            for &i in candidates {
                let weight = u64::from(parents.list[i].weight);
                if n < weight {
                    return i;
                }
                n -= weight;
            }
            first
        };
        let picked = match self.cfg.strategy {
            Strategy::First | Strategy::Fifo => first,
            Strategy::RoundRobin | Strategy::Race => {
                weighted(self.cursor.fetch_add(1, Ordering::Relaxed) % total)
            }
            Strategy::Random => weighted(rand::thread_rng().gen_range(0..total)),
            Strategy::LeastConnections => *candidates.iter().min_by_key(|&&i| {
                (
                    parents.list[i]
                        .active
                        .load(Ordering::Relaxed)
                        .saturating_mul(1_000_000)
                        / u64::from(parents.list[i].weight),
                    i,
                )
            })?,
            Strategy::Hash | Strategy::Userhash | Strategy::Sourcehash => {
                let digest = match self.cfg.strategy {
                    Strategy::Userhash => key.hash_bytes(crate::config::HashKey::User),
                    Strategy::Sourcehash => key.hash_bytes(crate::config::HashKey::ClientIp),
                    _ => key.hash_bytes(self.cfg.hash_key),
                };
                let hash = u64::from_be_bytes([
                    digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6],
                    digest[7],
                ]);
                weighted(hash % total)
            }
            Strategy::Sticky | Strategy::Carp => {
                let digest = match self.cfg.strategy {
                    Strategy::Sticky => key.hash_bytes(if key.session.is_some() {
                        crate::config::HashKey::SessionId
                    } else if key.user.is_some() {
                        crate::config::HashKey::User
                    } else {
                        crate::config::HashKey::ClientIp
                    }),
                    _ => key.hash_bytes(self.cfg.hash_key),
                };
                *candidates.iter().min_by(|&&a, &&b| {
                    rendezvous(&digest, &parents.list[a])
                        .total_cmp(&rendezvous(&digest, &parents.list[b]))
                })?
            }
            Strategy::Latency => {
                let best = *candidates
                    .iter()
                    .min_by_key(|&&i| parents.list[i].latency().unwrap_or(Duration::ZERO))?;
                let mut current = self.current.lock();
                let picked = current
                    .filter(|i| candidates.contains(i))
                    .filter(|&i| {
                        parents.list[best].latency().is_some()
                            && parents.list[i].latency().unwrap_or(Duration::MAX)
                                <= parents.list[best]
                                    .latency()
                                    .unwrap_or(Duration::MAX)
                                    .saturating_add(Duration::from_millis(self.cfg.tolerance_ms))
                    })
                    .unwrap_or(best);
                if current.is_some_and(|old| old != picked) && self.cfg.interrupt_on_switch {
                    let mut token = self.switch.lock();
                    token.cancel();
                    *token = CancellationToken::new();
                }
                *current = Some(picked);
                picked
            }
        };
        Some(picked)
    }

    /// Re-evaluate latency after probes without refreshing user activity.
    pub fn refresh(&self, parents: &Parents, allowed: &[usize]) {
        if self.cfg.strategy == Strategy::Latency && !self.idle() {
            let key = PickKey {
                session: None,
                user: None,
                client: [0, 0, 0, 0].into(),
                target_host: "",
            };
            self.choose_candidates(parents, &parents.candidates(allowed, &[]), &key);
        }
    }
}

fn rendezvous(key: &[u8; 32], parent: &Parent) -> f64 {
    let mut h = Sha256::new();
    h.update(key);
    h.update(parent.name.as_bytes());
    let bytes = h.finalize();
    let value = u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]);
    let uniform = (value as f64 + 1.0) / (u64::MAX as f64 + 2.0);
    -uniform.ln() / f64::from(parent.weight)
}

#[derive(Debug, Default)]
pub struct Parents {
    list: Vec<Arc<Parent>>,
}

impl Parents {
    pub fn build(
        cfg: &[ParentConfig],
        breaker: BreakerConfig,
        health: &HealthConfig,
        tr: &Transitions,
    ) -> Result<Self, String> {
        let mut list: Vec<Arc<Parent>> = Vec::with_capacity(cfg.len());
        for c in cfg {
            if list.iter().any(|p| p.name == c.name) {
                return Err(format!("parent {:?} is defined twice", c.name));
            }
            list.push(Arc::new(Parent::from_config(c, breaker, health, tr)?));
        }
        Ok(Self { list })
    }

    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    pub fn all(&self) -> &[Arc<Parent>] {
        &self.list
    }

    pub fn index_of(&self, name: &str) -> Option<usize> {
        self.list.iter().position(|p| p.name == name)
    }

    pub fn get(&self, i: usize) -> Option<&Arc<Parent>> {
        self.list.get(i)
    }

    /// Choose among `allowed` (every parent when empty) minus `exclude`.
    pub fn select(&self, allowed: &[usize], exclude: &[usize]) -> Option<usize> {
        let tier = self.candidates(allowed, exclude);
        let total: u64 = tier.iter().map(|&i| u64::from(self.list[i].weight)).sum();
        if total == 0 {
            return None;
        }
        let mut pick = rand::thread_rng().gen_range(0..total);
        for &i in &tier {
            let weight = u64::from(self.list[i].weight);
            if pick < weight {
                return Some(i);
            }
            pick -= weight;
        }
        None
    }

    pub fn candidates(&self, allowed: &[usize], exclude: &[usize]) -> Vec<usize> {
        let eligible = |i: usize, parent: &Parent| {
            (allowed.is_empty() || allowed.contains(&i))
                && !exclude.contains(&i)
                && !parent.is_down()
        };
        let tier = self
            .list
            .iter()
            .enumerate()
            .filter(|(i, p)| eligible(*i, p))
            .map(|(_, p)| (p.default, p.backup, p.priority))
            .min();
        self.list
            .iter()
            .enumerate()
            .filter(|(i, p)| eligible(*i, p) && Some((p.default, p.backup, p.priority)) == tier)
            .map(|(i, _)| i)
            .collect()
    }

    pub fn any_up(&self, allowed: &[usize]) -> bool {
        self.list.iter().enumerate().any(|(index, parent)| {
            (allowed.is_empty() || allowed.contains(&index)) && !parent.is_down()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    use std::time::Duration;

    fn build(toml: &str) -> Result<Parents, String> {
        Parents::build(
            &Config::parse(toml).expect("parse").parents,
            BreakerConfig {
                failure_threshold: 2,
                open_duration: Duration::from_millis(50),
                half_open_probes: 1,
                success_threshold: 1,
            },
            &HealthConfig::default(),
            &Transitions::detached(),
        )
    }

    fn parents(toml: &str) -> Parents {
        build(toml).expect("parents")
    }

    const TWO: &str = r#"
        [[parent]]
        name = "a"
        type = "http"
        address = "10.0.0.1:3128"
        weight = 3
        [[parent]]
        name = "b"
        type = "socks5"
        address = "10.0.0.2:1080"
        weight = 1
        [[parent]]
        name = "backup"
        type = "http"
        address = "[2001:db8::1]:3128"
        priority = 1
    "#;

    #[test]
    fn host_port_forms() {
        assert_eq!(
            split_host_port("example.com:8080"),
            Some(("example.com".into(), 8080))
        );
        assert_eq!(split_host_port("[::1]:1080"), Some(("::1".into(), 1080)));
        for bad in [
            "nohost",
            "host:0",
            "host:99999",
            "::1:80",
            "[::1]80",
            ":80",
            "a b:80",
        ] {
            assert_eq!(split_host_port(bad), None, "{bad}");
        }
    }

    #[test]
    fn weights_split_traffic_inside_the_lowest_tier() {
        let p = parents(TWO);
        let (mut a, mut b) = (0, 0);
        for _ in 0..4000 {
            match p.select(&[], &[]).map(|i| p.get(i).map(|x| x.name.clone())) {
                Some(Some(n)) if n == "a" => a += 1,
                Some(Some(n)) if n == "b" => b += 1,
                other => panic!("backup tier used while the first is up: {other:?}"),
            }
        }
        assert!(a > 2700 && a < 3300, "a={a} b={b}");
    }

    #[test]
    fn failover_goes_to_the_next_tier_and_recovers() {
        let p = parents(TWO);
        let (a, b, backup) = (
            p.index_of("a").expect("a"),
            p.index_of("b").expect("b"),
            p.index_of("backup").expect("backup"),
        );
        for _ in 0..2 {
            p.get(a).expect("a").report(false);
        }
        for _ in 0..2 {
            p.get(b).expect("b").report(false);
        }
        assert!(p.get(a).expect("a").is_down() && p.get(b).expect("b").is_down());
        assert_eq!(p.select(&[], &[]), Some(backup));
        assert_eq!(p.select(&[], &[backup]), None, "nothing left");
        // b comes back after its retry time and a success clears the failures
        std::thread::sleep(Duration::from_millis(80));
        assert!(!p.get(b).expect("b").is_down());
        assert!(
            [Some(a), Some(b)].contains(&p.select(&[], &[])),
            "both recovered: the first tier serves again"
        );
        p.get(b).expect("b").report(true);
        // one failure of a recovered parent no longer takes it down
        p.get(b).expect("b").report(false);
        assert!(!p.get(b).expect("b").is_down());
    }

    #[test]
    fn a_failed_health_probe_takes_a_parent_out_and_a_good_one_brings_it_back() {
        let p = parents(TWO);
        let a = p.get(p.index_of("a").expect("a")).expect("a");
        assert_eq!(a.health.observe(false), None);
        assert_eq!(a.health.observe(false), Some(false), "two failed probes");
        assert!(a.is_down());
        for _ in 0..200 {
            assert_ne!(p.select(&[], &[]), p.index_of("a"));
        }
        assert_eq!(a.health.observe(true), Some(true));
        assert!(!a.is_down());
    }

    #[test]
    fn a_route_subset_limits_the_choice() {
        let p = parents(TWO);
        let b = p.index_of("b").expect("b");
        for _ in 0..50 {
            assert_eq!(p.select(&[b], &[]), Some(b));
        }
        assert!(p.any_up(&[b]));
    }

    #[test]
    fn credentials_render_and_bad_parents_are_refused() {
        let p = parents(
            "[[parent]]\nname = \"a\"\ntype = \"http\"\naddress = \"h:1\"\nusername = \"u\"\npassword = \"p\"\n",
        );
        assert_eq!(
            p.get(0).and_then(|x| x.proxy_authorization()).as_deref(),
            Some("Basic dTpw")
        );
        for bad in [
            "[[parent]]\nname = \"A B\"\ntype = \"http\"\naddress = \"h:1\"\n",
            "[[parent]]\nname = \"a\"\ntype = \"http\"\naddress = \"h\"\n",
            "[[parent]]\nname = \"a\"\ntype = \"http\"\naddress = \"h:1\"\nweight = 0\n",
            "[[parent]]\nname = \"a\"\ntype = \"http\"\naddress = \"h:1\"\nusername = \"u\"\n",
            "[[parent]]\nname = \"a\"\ntype = \"http\"\naddress = \"h:1\"\n[[parent]]\nname = \"a\"\ntype = \"http\"\naddress = \"h:2\"\n",
        ] {
            assert!(build(bad).is_err(), "{bad}");
        }
    }
}
