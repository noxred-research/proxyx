//! The compiled configuration: everything a connection needs, built from a
//! [`Config`] and swapped as one unit on reload.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{Context as _, bail};
use ipnet::IpNet;

use crate::acl::{Known, Match, Req, Rules};
use crate::auth::{Login, Users};
use crate::config::{Config, ListenerAuth, ListenerConfig, ProxyProtocolMode, Route, Strategy};
use crate::dns::Resolver;
use crate::egress::{Pool, check_usable};
use crate::headers::HeaderPolicy;
use crate::limits::LimitSet;
use crate::metrics::Metrics;
use crate::parent::Parents;

/// A listener with its parsed extras.
#[derive(Debug, Clone)]
pub struct ListenerRt {
    pub cfg: ListenerConfig,
    pub trusted: Vec<IpNet>,
}

struct EgressRule {
    m: Match,
    pool: Arc<Pool>,
}

struct RouteRule {
    m: Match,
    route: Route,
    parents: Vec<usize>,
}

/// Why an egress choice could not be made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressError {
    /// The login named a pool that does not exist.
    UnknownPool(String),
}

/// The pool a request leaves from, and the `-ip-<n>` the login asked for.
pub struct EgressPick {
    pub pool: Option<Arc<Pool>>,
    pub index: Option<usize>,
}

pub struct State {
    pub cfg: Config,
    pub users: Users,
    pub rules: Rules,
    pub limits: LimitSet,
    pub pools: HashMap<String, Arc<Pool>>,
    pub parents: Parents,
    pub listeners: HashMap<String, ListenerRt>,
    pub headers: HeaderPolicy,
    pub resolver: Arc<Resolver>,
    pub utc_offset_secs: i32,
    /// Some rule needs the destination addresses before it can decide.
    pub uses_dst: bool,
    egress_rules: Vec<EgressRule>,
    route_rules: Vec<RouteRule>,
}

fn parse_offset(s: &str) -> anyhow::Result<i32> {
    let bad = || anyhow::anyhow!("utc_offset {s:?}: expected +HH:MM or -HH:MM");
    let (sign, rest) = match s.as_bytes().first() {
        Some(b'+') => (1, &s[1..]),
        Some(b'-') => (-1, &s[1..]),
        _ => return Err(bad()),
    };
    let (h, m) = rest.split_once(':').ok_or_else(bad)?;
    let (h, m): (i32, i32) = (h.parse().map_err(|_| bad())?, m.parse().map_err(|_| bad())?);
    if !(0..=14).contains(&h) || !(0..60).contains(&m) {
        return Err(bad());
    }
    Ok(sign * (h * 3600 + m * 60))
}

fn parse_net(s: &str) -> anyhow::Result<IpNet> {
    s.parse::<IpNet>()
        .or_else(|_| s.parse::<IpAddr>().map(IpNet::from))
        .map(|n| n.trunc())
        .map_err(|_| anyhow::anyhow!("bad network {s:?}"))
}

fn check_health(h: &crate::config::HealthConfig) -> anyhow::Result<()> {
    if h.unhealthy_threshold == 0 || h.healthy_threshold == 0 {
        bail!("health: unhealthy_threshold and healthy_threshold must be above zero");
    }
    if !h.interval.is_zero() && h.timeout.is_zero() {
        bail!("health.timeout must be above zero");
    }
    if let Some(t) = &h.parent_target
        && crate::parent::split_host_port(t).is_none()
    {
        bail!("health.parent_target {t:?} is not host:port");
    }
    Ok(())
}

fn is_option_value(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

impl State {
    /// Compile `cfg`. `prev` lends its DNS resolver (and its cache) when the
    /// DNS settings did not change.
    pub fn build(cfg: Config, prev: Option<&State>, metrics: &Metrics) -> anyhow::Result<Self> {
        if cfg.listeners.is_empty() {
            bail!("no [[listener]] is defined");
        }
        let utc_offset_secs = parse_offset(&cfg.server.utc_offset)?;
        cfg.breaker
            .parent
            .check("breaker.parent")
            .map_err(anyhow::Error::msg)?;
        cfg.breaker
            .egress
            .check("breaker.egress")
            .map_err(anyhow::Error::msg)?;
        crate::sockopt::check(&cfg.tcp.client, "tcp.client").map_err(anyhow::Error::msg)?;
        crate::sockopt::check(&cfg.tcp.upstream, "tcp.upstream").map_err(anyhow::Error::msg)?;
        check_health(&cfg.health)?;
        let t = &cfg.timeouts;
        for (name, d) in [
            ("handshake", t.handshake),
            ("connect", t.connect),
            ("idle", t.idle),
            ("keepalive", t.keepalive),
            ("response_header", t.response_header),
        ] {
            if d.is_zero() {
                bail!(
                    "timeouts.{name} must be above zero (only timeouts.total may be 0, meaning no limit)"
                );
            }
        }
        let egress_tr = metrics.transitions("egress");
        let parent_tr = metrics.transitions("parent");

        // pools
        let mut pools: HashMap<String, Arc<Pool>> = HashMap::new();
        for p in &cfg.pools {
            if pools.contains_key(&p.name) {
                bail!("pool {:?} is defined twice", p.name);
            }
            if p.name.is_empty()
                || !p
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            {
                bail!("pool name {:?}: use letters, digits, '_' and '-'", p.name);
            }
            pools.insert(
                p.name.clone(),
                Arc::new(
                    Pool::from_config(p, cfg.breaker.egress, &egress_tr)
                        .map_err(anyhow::Error::msg)?,
                ),
            );
        }
        let pool_exists = |what: &str, name: &str| -> anyhow::Result<()> {
            if pools.contains_key(name) {
                Ok(())
            } else {
                bail!("{what}: pool {name:?} is not defined")
            }
        };
        if let Some(d) = &cfg.server.default_pool {
            pool_exists("server.default_pool", d)?;
        }

        // users
        let users = Users::build(
            &cfg.users,
            cfg.auth.users_file.as_deref(),
            cfg.auth.login_options,
        )?;
        for u in &cfg.users {
            if let Some(p) = &u.pool {
                pool_exists(&format!("user {}", u.name), p)?;
            }
            for p in &u.allowed_pools {
                pool_exists(&format!("user {}: allowed_pools", u.name), p)?;
                if cfg.auth.login_options && !is_option_value(p) {
                    bail!(
                        "user {}: pool {p:?} cannot be named in a login: with login_options pool names in allowed_pools use [a-z0-9_]",
                        u.name
                    );
                }
            }
            for l in &u.allowed_listeners {
                if !cfg.listeners.iter().any(|x| &x.name == l) {
                    bail!(
                        "user {}: allowed_listeners: listener {l:?} is not defined",
                        u.name
                    );
                }
            }
        }

        // listeners
        let mut listeners: HashMap<String, ListenerRt> = HashMap::new();
        let mut binds: HashSet<std::net::SocketAddr> = HashSet::new();
        for l in &cfg.listeners {
            if l.name.is_empty() {
                bail!("a listener has no name");
            }
            if listeners.contains_key(&l.name) {
                bail!("listener {:?} is defined twice", l.name);
            }
            if l.listen.port() != 0 && !binds.insert(l.listen) {
                bail!(
                    "listener {:?}: {} is already used by another listener",
                    l.name,
                    l.listen
                );
            }
            if let Some(p) = &l.pool {
                pool_exists(&format!("listener {}", l.name), p)?;
            }
            if l.auth == ListenerAuth::Users && users.is_empty() {
                bail!(
                    "listener {:?} wants logins (auth = \"users\") but no users are defined: add [[user]] tables or auth.users_file, or set auth = \"none\"",
                    l.name
                );
            }
            let trusted: Vec<IpNet> = l
                .trusted_proxies
                .iter()
                .map(|t| {
                    parse_net(t).with_context(|| format!("listener {}: trusted_proxies", l.name))
                })
                .collect::<anyhow::Result<_>>()?;
            if l.proxy_protocol != ProxyProtocolMode::Off && trusted.is_empty() {
                bail!(
                    "listener {:?}: proxy_protocol needs trusted_proxies (only those peers may state a client address)",
                    l.name
                );
            }
            if l.udp && l.protocol == crate::config::ListenerProtocol::Http {
                bail!(
                    "listener {:?}: udp needs protocol = \"socks\" or \"auto\"",
                    l.name
                );
            }
            listeners.insert(
                l.name.clone(),
                ListenerRt {
                    cfg: l.clone(),
                    trusted,
                },
            );
        }

        // parents
        let parents = Parents::build(&cfg.parents, cfg.breaker.parent, &cfg.health, &parent_tr)
            .map_err(anyhow::Error::msg)?;
        for p in &cfg.parents {
            if let Some(pool) = &p.pool {
                pool_exists(&format!("parent {}", p.name), pool)?;
            }
        }
        if cfg.server.default_route != Route::Direct && parents.is_empty() {
            bail!("server.default_route needs at least one [[parent]]");
        }

        // rules
        let known = Known {
            listeners: cfg.listeners.iter().map(|l| l.name.as_str()).collect(),
            users: users.names(),
            groups: users.groups(),
        };
        let rules = Rules::compile(&cfg.rules, &known).map_err(anyhow::Error::msg)?;
        let limits = LimitSet::compile(&cfg.limits, &known).map_err(anyhow::Error::msg)?;

        let mut egress_rules = Vec::new();
        for (i, e) in cfg.egress.iter().enumerate() {
            let what = format!("egress #{}", i + 1);
            let pool = match (&e.pool, e.address) {
                (Some(p), None) => {
                    pool_exists(&what, p)?;
                    Arc::clone(&pools[p])
                }
                (None, Some(ip)) => {
                    check_usable(ip).map_err(|err| anyhow::anyhow!("{what}: {err}"))?;
                    Arc::new(Pool::new(
                        &format!("egress-{}", i + 1),
                        vec![ip],
                        Strategy::First,
                        cfg.breaker.egress,
                        &egress_tr,
                    ))
                }
                _ => bail!("{what}: set exactly one of pool or address"),
            };
            egress_rules.push(EgressRule {
                m: Match::compile(&e.when, &known)
                    .map_err(|err| anyhow::anyhow!("{what}: {err}"))?,
                pool,
            });
        }

        let mut route_rules = Vec::new();
        for (i, r) in cfg.routes.iter().enumerate() {
            let what = format!("route #{}", i + 1);
            if r.route != Route::Direct && parents.is_empty() {
                bail!("{what}: needs at least one [[parent]]");
            }
            let idx = r
                .parents
                .iter()
                .map(|n| {
                    parents
                        .index_of(n)
                        .ok_or_else(|| anyhow::anyhow!("{what}: parent {n:?} is not defined"))
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            if r.route == Route::Direct && !idx.is_empty() {
                bail!("{what}: parents go with route = \"parent\" or \"parent_or_direct\"");
            }
            route_rules.push(RouteRule {
                m: Match::compile(&r.when, &known)
                    .map_err(|err| anyhow::anyhow!("{what}: {err}"))?,
                route: r.route,
                parents: idx,
            });
        }

        let headers = HeaderPolicy::compile(&cfg.http)?;
        let resolver = match prev {
            Some(p) if p.cfg.dns == cfg.dns => Arc::clone(&p.resolver),
            _ => Arc::new(Resolver::new(&cfg.dns)?),
        };
        let uses_dst = rules.uses_dst()
            || limits.uses_dst()
            || egress_rules.iter().any(|e| e.m.uses_dst())
            || route_rules.iter().any(|r| r.m.uses_dst());

        Ok(Self {
            cfg,
            users,
            rules,
            limits,
            pools,
            parents,
            listeners,
            headers,
            resolver,
            utc_offset_secs,
            uses_dst,
            egress_rules,
            route_rules,
        })
    }

    /// Choose the pool: a matching `[[egress]]` rule, else the login's
    /// `-pool-` option, the user's pool, the listener's pool, the default pool.
    pub fn egress_for(
        &self,
        req: &Req<'_>,
        login: Option<&Login>,
        listener: &ListenerRt,
    ) -> Result<EgressPick, EgressError> {
        let index = login.and_then(|l| l.options.ip);
        if let Some(e) = self.egress_rules.iter().find(|e| e.m.matches(req)) {
            return Ok(EgressPick {
                pool: Some(Arc::clone(&e.pool)),
                index,
            });
        }
        let named = match login.and_then(|l| l.options.pool.as_ref()) {
            Some(n) => Some(
                self.pools
                    .get(n)
                    .ok_or_else(|| EgressError::UnknownPool(n.clone()))?,
            ),
            None => None,
        };
        let pool = named
            .or_else(|| {
                login
                    .and_then(|l| l.user.pool.as_ref())
                    .and_then(|n| self.pools.get(n))
            })
            .or_else(|| listener.cfg.pool.as_ref().and_then(|n| self.pools.get(n)))
            .or_else(|| {
                self.cfg
                    .server
                    .default_pool
                    .as_ref()
                    .and_then(|n| self.pools.get(n))
            });
        Ok(EgressPick {
            pool: pool.map(Arc::clone),
            index,
        })
    }

    /// Every pool: the named ones and the ones `[[egress]]` rules with a fixed address made.
    pub fn all_pools(&self) -> Vec<Arc<Pool>> {
        let mut out: Vec<Arc<Pool>> = self.pools.values().cloned().collect();
        for e in &self.egress_rules {
            if !out.iter().any(|p| Arc::ptr_eq(p, &e.pool)) {
                out.push(Arc::clone(&e.pool));
            }
        }
        out
    }

    /// The pool a request without a more specific choice uses.
    pub fn default_pool(&self) -> Option<Arc<Pool>> {
        self.cfg
            .server
            .default_pool
            .as_ref()
            .and_then(|n| self.pools.get(n))
            .cloned()
    }

    /// Is there an egress path that can serve a request now: a pool with a
    /// usable address (or no pool: the operating system picks), or a parent
    /// that is up, according to what the default route needs.
    pub fn egress_healthy(&self) -> bool {
        let direct = self.pools.is_empty() || self.pools.values().any(|p| p.is_usable());
        let parent = self.parents.any_up(&[]);
        match self.cfg.server.default_route {
            Route::Direct => direct,
            Route::Parent => parent,
            Route::ParentOrDirect => direct || parent,
        }
    }

    /// The route of a request and the parents it may use (indexes into
    /// [`Parents`]; empty means every parent).
    pub fn route_for(&self, req: &Req<'_>) -> (Route, &[usize]) {
        self.route_rules
            .iter()
            .find(|r| r.m.matches(req))
            .map_or((self.cfg.server.default_route, &[][..]), |r| {
                (r.route, r.parents.as_slice())
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(toml: &str) -> anyhow::Result<State> {
        let mut text = String::from(
            "[dns]\nnameservers = [\"127.0.0.1\"]\n[[listener]]\nname = \"main\"\nlisten = \"127.0.0.1:0\"\nauth = \"none\"\n",
        );
        text.push_str(toml);
        State::build(Config::parse(&text)?, None, &Metrics::new())
    }

    fn err(toml: &str) -> String {
        match build(toml) {
            Ok(_) => panic!("must fail: {toml}"),
            Err(e) => format!("{e:#}"),
        }
    }

    #[test]
    fn the_minimal_config_builds() {
        assert!(build("").is_ok());
    }

    #[test]
    fn references_to_missing_things_are_refused() {
        assert!(err("[server]\ndefault_pool = \"nope\"").contains("nope"));
        assert!(err("[[egress]]\npool = \"nope\"").contains("nope"));
        assert!(err("[[egress]]\n").contains("exactly one"));
        assert!(err("[[route]]\nroute = \"parent\"\n").contains("parent"));
        assert!(
            err("[[parent]]\nname = \"a\"\ntype = \"http\"\naddress = \"h:1\"\npool = \"nope\"")
                .contains("nope")
        );
        assert!(err("[[route]]\nroute = \"parent\"\nparents = [\"x\"]\n[[parent]]\nname = \"a\"\ntype = \"http\"\naddress = \"h:1\"").contains("\"x\""));
        assert!(
            err("[[user]]\nname = \"u\"\npassword = \"p\"\nallowed_listeners = [\"nope\"]")
                .contains("nope")
        );
    }

    #[test]
    fn listeners_are_checked() {
        let base = "[dns]\nnameservers = [\"127.0.0.1\"]\n";
        let mk = |l: &str| {
            State::build(
                Config::parse(&format!("{base}{l}")).expect("parse"),
                None,
                &Metrics::new(),
            )
            .err()
        };
        assert!(mk("").is_some(), "no listener");
        assert!(
            mk("[[listener]]\nname = \"a\"\nlisten = \"127.0.0.1:1\"\n").is_some(),
            "auth users without users"
        );
        assert!(mk("[[listener]]\nname = \"a\"\nlisten = \"127.0.0.1:1\"\nauth = \"none\"\n[[listener]]\nname = \"a\"\nlisten = \"127.0.0.1:2\"\nauth = \"none\"\n").is_some());
        assert!(mk("[[listener]]\nname = \"a\"\nlisten = \"127.0.0.1:1\"\nauth = \"none\"\n[[listener]]\nname = \"b\"\nlisten = \"127.0.0.1:1\"\nauth = \"none\"\n").is_some());
        assert!(mk("[[listener]]\nname = \"a\"\nlisten = \"127.0.0.1:1\"\nauth = \"none\"\nproxy_protocol = \"required\"\n").is_some());
        assert!(mk("[[listener]]\nname = \"a\"\nlisten = \"127.0.0.1:1\"\nauth = \"none\"\nproxy_protocol = \"required\"\ntrusted_proxies = [\"10.0.0.0/8\"]\n").is_none());
        assert!(mk("[[listener]]\nname = \"a\"\nlisten = \"127.0.0.1:1\"\nauth = \"none\"\nprotocol = \"http\"\nudp = true\n").is_some());
    }

    #[test]
    fn pools_and_egress_pick_by_priority() {
        let s = build(
            r#"
            [server]
            default_pool = "dflt"
            [[pool]]
            name = "dflt"
            addresses = ["127.0.0.2"]
            [[pool]]
            name = "lst"
            addresses = ["127.0.0.3"]
            [[pool]]
            name = "usr"
            addresses = ["127.0.0.4"]
            [[pool]]
            name = "rul"
            addresses = ["127.0.0.5"]
            [[egress]]
            when = { domain = [".special.test"] }
            pool = "rul"
            [[egress]]
            when = { domain = [".fixed.test"] }
            address = "127.0.0.6"
        "#,
        )
        .expect("build");
        let l = s.listeners.get("main").expect("listener").clone();
        let mut lcfg = l.clone();
        let req = |host: &'static str| Req {
            src: "10.0.0.1".parse().expect("ip"),
            listener: "main",
            proto: crate::acl::Proto::Connect,
            method: "CONNECT",
            host,
            port: 443,
            dst_ips: &[],
            user: None,
            groups: &[],
            clock: crate::acl::Clock {
                weekday: 0,
                minute: 0,
            },
        };
        let name = |p: EgressPick| p.pool.map(|p| p.name().to_owned());
        assert_eq!(
            name(s.egress_for(&req("a.test"), None, &l).expect("egress")).as_deref(),
            Some("dflt")
        );
        assert_eq!(
            name(
                s.egress_for(&req("x.special.test"), None, &l)
                    .expect("egress")
            )
            .as_deref(),
            Some("rul")
        );
        assert_eq!(
            name(
                s.egress_for(&req("x.fixed.test"), None, &l)
                    .expect("egress")
            )
            .as_deref(),
            Some("egress-2")
        );
        lcfg.cfg.pool = Some("lst".into());
        assert_eq!(
            name(s.egress_for(&req("a.test"), None, &lcfg).expect("egress")).as_deref(),
            Some("lst")
        );
    }

    #[test]
    fn egress_address_must_be_local() {
        assert!(err("[[egress]]\naddress = \"203.0.113.9\"").contains("not assigned"));
    }

    #[test]
    fn offsets_parse() {
        assert_eq!(parse_offset("+02:00").expect("off"), 7200);
        assert_eq!(parse_offset("-05:30").expect("off"), -(5 * 3600 + 1800));
        for bad in ["02:00", "+2", "+25:00", "+01:60", ""] {
            assert!(parse_offset(bad).is_err(), "{bad}");
        }
    }
}
