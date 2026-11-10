//! Parent proxies: weights, priority tiers and passive health.
//!
//! The parents of a request are the configured ones, or the subset a
//! `[[route]]` names. The lowest priority tier with a parent that is not
//! down serves it; inside the tier the choice is random by weight. A parent
//! that trips its circuit breaker (`[breaker.parent]`) or fails its active
//! health check (`[health]`) is out of use; the breaker lets probes through
//! after `open_duration`.

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::Secret;
use common::types::{ProviderId, UpstreamEndpoint, UpstreamScheme};
use rand::Rng as _;

use crate::breaker::{Breaker, BreakerState, HealthTracker, Transitions};
use crate::config::{BreakerConfig, HealthConfig, ParentConfig, ParentKind, SendProxyProtocol};

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
        if c.username.is_some() != c.password.is_some() {
            return Err(format!(
                "parent {}: set username and password together",
                c.name
            ));
        }
        let endpoint = UpstreamEndpoint {
            provider,
            scheme: match c.kind {
                ParentKind::Http => UpstreamScheme::Http,
                ParentKind::Socks5 => UpstreamScheme::Socks5,
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
        let all: Vec<usize> = (0..self.list.len()).collect();
        let pool = if allowed.is_empty() { &all } else { allowed };
        let live: Vec<usize> = pool
            .iter()
            .copied()
            .filter(|i| !exclude.contains(i) && !self.list[*i].is_down())
            .collect();
        let tier = live.iter().map(|&i| self.list[i].priority).min()?;
        let tier: Vec<usize> = live
            .into_iter()
            .filter(|&i| self.list[i].priority == tier)
            .collect();
        let total: u64 = tier.iter().map(|&i| u64::from(self.list[i].weight)).sum();
        let mut pick = rand::thread_rng().gen_range(0..total);
        for &i in &tier {
            let w = u64::from(self.list[i].weight);
            if pick < w {
                return Some(i);
            }
            pick -= w;
        }
        tier.last().copied()
    }

    pub fn any_up(&self, allowed: &[usize]) -> bool {
        self.select(allowed, &[]).is_some()
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
