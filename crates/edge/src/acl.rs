//! Rule conditions and the ordered access rules.
//!
//! A [`Match`] is the compiled form of a `when = { ... }` table: every field
//! that is set must match, the values inside one field are alternatives, and
//! `not` negates a nested match. [`Rules::evaluate`] walks the access rules
//! in order; the first match decides, and no match is a deny.

use std::net::IpAddr;
use std::time::SystemTime;

use ipnet::IpNet;
use regex::Regex;

pub use crate::config::RuleStage;
use crate::config::{Action, MatchConfig, RuleConfig, TimeWindowConfig};

/// The wire protocol a request arrived on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Http,
    Connect,
    Socks4,
    Socks5,
    Udp,
}

impl Proto {
    pub const fn as_str(self) -> &'static str {
        match self {
            Proto::Http => "http",
            Proto::Connect => "connect",
            Proto::Socks4 => "socks4",
            Proto::Socks5 => "socks5",
            Proto::Udp => "udp",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "http" => Proto::Http,
            "connect" => Proto::Connect,
            "socks4" => Proto::Socks4,
            "socks5" => Proto::Socks5,
            "udp" => Proto::Udp,
            _ => return None,
        })
    }
}

/// Weekday (0 is Monday) and minute of the day in the configured offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Clock {
    pub weekday: u8,
    pub minute: u16,
}

impl Clock {
    pub fn at(now: SystemTime, utc_offset_secs: i32) -> Self {
        let secs = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let local = secs.saturating_add_signed(i64::from(utc_offset_secs));
        let days = local / 86_400;
        // 1970-01-01 was a Thursday
        let weekday = ((days + 3) % 7) as u8;
        let minute = ((local % 86_400) / 60) as u16;
        Self { weekday, minute }
    }
}

/// What the conditions look at: one request.
#[derive(Debug, Clone, Copy)]
pub struct Req<'a> {
    pub src: IpAddr,
    pub listener: &'a str,
    pub proto: Proto,
    pub method: &'a str,
    /// Lowercase, no brackets, no trailing dot.
    pub host: &'a str,
    pub port: u16,
    /// Addresses the host resolves to (the literal itself for an IP host).
    /// Empty until resolved; `dst` conditions match nothing then.
    pub dst_ips: &'a [IpAddr],
    pub user: Option<&'a str>,
    pub groups: &'a [String],
    pub clock: Clock,
}

#[derive(Debug, Clone)]
enum AddrSpec {
    Net(IpNet),
    Range(IpAddr, IpAddr),
}

impl AddrSpec {
    fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if let Some((a, b)) = s.split_once('-') {
            let lo: IpAddr = a
                .trim()
                .parse()
                .map_err(|_| format!("bad address range {s:?}"))?;
            let hi: IpAddr = b
                .trim()
                .parse()
                .map_err(|_| format!("bad address range {s:?}"))?;
            if lo.is_ipv4() != hi.is_ipv4() || lo > hi {
                return Err(format!(
                    "address range {s:?} must be ascending and of one family"
                ));
            }
            return Ok(Self::Range(lo, hi));
        }
        if s.contains('/') {
            return s
                .parse::<IpNet>()
                .map(|n| Self::Net(n.trunc()))
                .map_err(|_| format!("bad network {s:?}"));
        }
        s.parse::<IpAddr>()
            .map(|ip| Self::Net(IpNet::from(ip)))
            .map_err(|_| format!("bad address {s:?}"))
    }

    fn contains(&self, ip: IpAddr) -> bool {
        let ip = unmap(ip);
        match self {
            Self::Net(n) => n.contains(&ip),
            Self::Range(lo, hi) => lo.is_ipv4() == ip.is_ipv4() && *lo <= ip && ip <= *hi,
        }
    }
}

/// IPv4-mapped IPv6 addresses match the rules of the IPv4 address inside.
fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

#[derive(Debug, Clone)]
enum DomainSpec {
    Exact(String),
    /// The name itself and every subdomain.
    Suffix(String),
    /// Subdomains only.
    Sub(String),
    Regex(Regex),
}

impl DomainSpec {
    fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if let Some(re) = s.strip_prefix("re:") {
            return Regex::new(&format!("(?i){re}"))
                .map(Self::Regex)
                .map_err(|e| format!("bad domain regex {s:?}: {e}"));
        }
        let lower = s.to_ascii_lowercase();
        let (kind, name) = if let Some(n) = lower.strip_prefix("*.") {
            (1, n)
        } else if let Some(n) = lower.strip_prefix('.') {
            (2, n)
        } else {
            (0, lower.as_str())
        };
        let name = name.trim_end_matches('.');
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        {
            return Err(format!("bad domain {s:?}"));
        }
        Ok(match kind {
            1 => Self::Sub(name.to_owned()),
            2 => Self::Suffix(name.to_owned()),
            _ => Self::Exact(name.to_owned()),
        })
    }

    fn matches(&self, host: &str) -> bool {
        let is_sub = |name: &str| {
            host.len() > name.len() + 1
                && host.ends_with(name)
                && host.as_bytes()[host.len() - name.len() - 1] == b'.'
        };
        match self {
            Self::Exact(n) => host == n,
            Self::Suffix(n) => host == n || is_sub(n),
            Self::Sub(n) => is_sub(n),
            Self::Regex(re) => re.is_match(host),
        }
    }
}

#[derive(Debug, Clone)]
struct TimeWindow {
    /// Bit 0 is Monday.
    days: u8,
    from: u16,
    to: u16,
}

impl TimeWindow {
    fn compile(c: &TimeWindowConfig) -> Result<Self, String> {
        let mut days = 0u8;
        for d in &c.days {
            let i = match d.to_ascii_lowercase().as_str() {
                "mon" => 0,
                "tue" => 1,
                "wed" => 2,
                "thu" => 3,
                "fri" => 4,
                "sat" => 5,
                "sun" => 6,
                other => return Err(format!("bad weekday {other:?}: use mon..sun")),
            };
            days |= 1 << i;
        }
        if days == 0 {
            days = 0x7f;
        }
        let hhmm = |s: &str| -> Result<u16, String> {
            let (h, m) = s
                .split_once(':')
                .ok_or_else(|| format!("bad time {s:?}: use HH:MM"))?;
            let (h, m): (u16, u16) = (
                h.parse().map_err(|_| format!("bad time {s:?}"))?,
                m.parse().map_err(|_| format!("bad time {s:?}"))?,
            );
            if h > 24 || m > 59 || (h == 24 && m != 0) {
                return Err(format!("bad time {s:?}"));
            }
            Ok(h * 60 + m)
        };
        Ok(Self {
            days,
            from: c.from.as_deref().map_or(Ok(0), hhmm)?,
            to: c.to.as_deref().map_or(Ok(24 * 60), hhmm)?,
        })
    }

    fn contains(&self, c: Clock) -> bool {
        let today = self.days & (1 << c.weekday) != 0;
        if self.from <= self.to {
            today && c.minute >= self.from && c.minute < self.to
        } else {
            // Wraps over midnight: the late part belongs to the day it starts on,
            // the early part to the day before it started.
            let yesterday = self.days & (1 << ((c.weekday + 6) % 7)) != 0;
            (today && c.minute >= self.from) || (yesterday && c.minute < self.to)
        }
    }
}

/// A compiled `when` table.
#[derive(Debug, Clone, Default)]
pub struct Match {
    src: Vec<AddrSpec>,
    dst: Vec<AddrSpec>,
    domain: Vec<DomainSpec>,
    port: Vec<(u16, u16)>,
    method: Vec<String>,
    proto: Vec<Proto>,
    user: Vec<String>,
    group: Vec<String>,
    listener: Vec<String>,
    time: Vec<TimeWindow>,
    authenticated: Option<bool>,
    not: Option<Box<Match>>,
}

fn each<T>(
    items: &[String],
    what: &str,
    f: impl Fn(&str) -> Result<T, String>,
) -> Result<Vec<T>, String> {
    items
        .iter()
        .map(|s| f(s).map_err(|e| format!("{what}: {e}")))
        .collect()
}

fn parse_port(s: &str) -> Result<(u16, u16), String> {
    let one = |p: &str| -> Result<u16, String> {
        p.trim()
            .parse::<u16>()
            .ok()
            .filter(|&p| p != 0)
            .ok_or_else(|| format!("bad port {s:?}"))
    };
    match s.split_once('-') {
        Some((a, b)) => {
            let (lo, hi) = (one(a)?, one(b)?);
            if lo > hi {
                return Err(format!("port range {s:?} must be ascending"));
            }
            Ok((lo, hi))
        }
        None => one(s).map(|p| (p, p)),
    }
}

impl Match {
    /// Compile a `when` table. `listeners` are the configured listener names
    /// and `users`/`groups` the known login names and groups: a name that
    /// does not exist is a typo, and a typo in a rule must not pass silently.
    pub fn compile(c: &MatchConfig, known: &Known<'_>) -> Result<Self, String> {
        let check = |what: &str, items: &[String], set: &dyn Fn(&str) -> bool| {
            items
                .iter()
                .find(|i| !set(i))
                .map_or(Ok(()), |i| Err(format!("{what} {i:?} is not defined")))
        };
        check("listener", &c.listener, &|n| known.listeners.contains(&n))?;
        check("user", &c.user, &|n| known.users.contains(&n))?;
        check("group", &c.group, &|n| known.groups.contains(&n))?;
        let method = c.method.iter().map(|m| m.to_ascii_uppercase()).collect();
        let proto = each(&c.protocol, "protocol", |p| {
            Proto::parse(p).ok_or_else(|| format!("unknown protocol {p:?}"))
        })?;
        Ok(Self {
            src: each(&c.src, "src", AddrSpec::parse)?,
            dst: each(&c.dst, "dst", AddrSpec::parse)?,
            domain: each(&c.domain, "domain", DomainSpec::parse)?,
            port: each(&c.port, "port", parse_port)?,
            method,
            proto,
            user: c.user.clone(),
            group: c.group.clone(),
            listener: c.listener.clone(),
            time: c
                .time
                .iter()
                .map(TimeWindow::compile)
                .collect::<Result<_, _>>()
                .map_err(|e| format!("time: {e}"))?,
            authenticated: c.authenticated,
            not: c
                .not
                .as_deref()
                .map(|n| Self::compile(n, known).map(Box::new))
                .transpose()?,
        })
    }

    fn validate_stage(c: &MatchConfig, stage: RuleStage) -> Result<(), String> {
        if matches!(stage, RuleStage::PreNegotiation | RuleStage::PostAuth) {
            if !c.dst.is_empty()
                || !c.domain.is_empty()
                || !c.port.is_empty()
                || !c.method.is_empty()
            {
                return Err("destination and method conditions require a request stage".into());
            }
            if stage == RuleStage::PreNegotiation
                && (!c.protocol.is_empty()
                    || !c.user.is_empty()
                    || !c.group.is_empty()
                    || c.authenticated.is_some())
            {
                return Err(
                    "protocol and identity conditions are unavailable before negotiation".into(),
                );
            }
        }
        if let Some(nested) = c.not.as_deref() {
            Self::validate_stage(nested, stage)?;
        }
        Ok(())
    }

    /// True when a `dst` condition needs the resolved addresses.
    pub fn uses_dst(&self) -> bool {
        !self.dst.is_empty() || self.not.as_ref().is_some_and(|n| n.uses_dst())
    }

    pub fn matches(&self, r: &Req<'_>) -> bool {
        if !self.src.is_empty() && !self.src.iter().any(|s| s.contains(r.src)) {
            return false;
        }
        if !self.dst.is_empty()
            && !r
                .dst_ips
                .iter()
                .any(|ip| self.dst.iter().any(|s| s.contains(*ip)))
        {
            return false;
        }
        if !self.domain.is_empty() && !self.domain.iter().any(|d| d.matches(r.host)) {
            return false;
        }
        if !self.port.is_empty()
            && !self
                .port
                .iter()
                .any(|&(lo, hi)| (lo..=hi).contains(&r.port))
        {
            return false;
        }
        if !self.method.is_empty() && !self.method.iter().any(|m| m.eq_ignore_ascii_case(r.method))
        {
            return false;
        }
        if !self.proto.is_empty() && !self.proto.contains(&r.proto) {
            return false;
        }
        if !self.user.is_empty() && !r.user.is_some_and(|u| self.user.iter().any(|x| x == u)) {
            return false;
        }
        if !self.group.is_empty() && !r.groups.iter().any(|g| self.group.contains(g)) {
            return false;
        }
        if !self.listener.is_empty() && !self.listener.iter().any(|l| l == r.listener) {
            return false;
        }
        if !self.time.is_empty() && !self.time.iter().any(|t| t.contains(r.clock)) {
            return false;
        }
        if let Some(want) = self.authenticated
            && r.user.is_some() != want
        {
            return false;
        }
        if let Some(not) = &self.not
            && not.matches(r)
        {
            return false;
        }
        true
    }
}

/// Names a rule may refer to.
pub struct Known<'a> {
    pub listeners: Vec<&'a str>,
    pub users: Vec<&'a str>,
    pub groups: Vec<&'a str>,
}

/// An access rule.
#[derive(Debug, Clone)]
pub struct Rule {
    pub name: Option<String>,
    pub action: Action,
    pub stage: RuleStage,
    pub allow_internal: bool,
    m: Match,
}

/// The verdict of the access rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub action: Action,
    /// Name of the deciding rule, `#<n>` (1-based) when it has none; absent for the default deny.
    pub rule: Option<String>,
    pub allow_internal: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Rules {
    rules: Vec<Rule>,
}

impl Rules {
    pub fn compile(cfg: &[RuleConfig], known: &Known<'_>) -> Result<Self, String> {
        let mut rules = Vec::with_capacity(cfg.len());
        for (i, r) in cfg.iter().enumerate() {
            if r.allow_internal && r.action != Action::Allow {
                return Err(format!(
                    "rule #{}: allow_internal only goes with action = \"allow\"",
                    i + 1
                ));
            }
            Match::validate_stage(&r.when, r.stage).map_err(|e| format!("rule #{}: {e}", i + 1))?;
            if r.allow_internal
                && matches!(r.stage, RuleStage::PreNegotiation | RuleStage::PostAuth)
            {
                return Err(format!(
                    "rule #{}: allow_internal requires a request stage",
                    i + 1
                ));
            }
            rules.push(Rule {
                name: r.name.clone(),
                action: r.action,
                stage: r.stage,
                allow_internal: r.allow_internal,
                m: Match::compile(&r.when, known).map_err(|e| format!("rule #{}: {e}", i + 1))?,
            });
        }
        Ok(Self { rules })
    }

    pub fn uses_dst(&self) -> bool {
        self.rules.iter().any(|r| r.m.uses_dst())
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn evaluate(&self, r: &Req<'_>) -> Verdict {
        self.evaluate_stage(RuleStage::Request, r)
    }

    /// An absent non-request stage adds no policy; a configured stage defaults to deny.
    pub fn has_stage(&self, stage: RuleStage) -> bool {
        self.rules.iter().any(|rule| rule.stage == stage)
    }

    /// Evaluate only rules explicitly assigned to this stage.
    pub fn evaluate_stage(&self, stage: RuleStage, r: &Req<'_>) -> Verdict {
        for (i, rule) in self.rules.iter().enumerate() {
            if rule.stage == stage && rule.m.matches(r) {
                return Verdict {
                    action: rule.action,
                    rule: Some(rule.name.clone().unwrap_or_else(|| format!("#{}", i + 1))),
                    allow_internal: rule.allow_internal,
                };
            }
        }
        Verdict {
            action: Action::Deny,
            rule: None,
            allow_internal: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::config::Config;

    fn known() -> Known<'static> {
        Known {
            listeners: vec!["main", "alt"],
            users: vec!["alice", "bob"],
            groups: vec!["staff", "guests"],
        }
    }

    fn compile(toml: &str) -> Rules {
        let c = Config::parse(toml).expect("parse");
        Rules::compile(&c.rules, &known()).expect("compile")
    }

    fn req<'a>(host: &'a str, port: u16) -> Req<'a> {
        Req {
            src: "10.1.2.3".parse().expect("ip"),
            listener: "main",
            proto: Proto::Connect,
            method: "CONNECT",
            host,
            port,
            dst_ips: &[],
            user: Some("alice"),
            groups: &[],
            clock: Clock {
                weekday: 2,
                minute: 12 * 60,
            },
        }
    }

    #[test]
    fn first_match_wins_and_default_is_deny() {
        let rules = compile(
            r#"
            [[rule]]
            name = "no-ads"
            action = "deny"
            when = { domain = [".ads.example"] }
            [[rule]]
            action = "allow"
            when = { port = ["80", "443"] }
        "#,
        );
        let v = rules.evaluate(&req("x.ads.example", 443));
        assert_eq!(
            (v.action, v.rule.as_deref()),
            (Action::Deny, Some("no-ads"))
        );
        let v = rules.evaluate(&req("example.com", 443));
        assert_eq!((v.action, v.rule.as_deref()), (Action::Allow, Some("#2")));
        let v = rules.evaluate(&req("example.com", 25));
        assert_eq!((v.action, v.rule), (Action::Deny, None));
        assert_eq!(
            Rules::default().evaluate(&req("a.test", 1)).action,
            Action::Deny
        );
    }

    #[test]
    fn domain_forms() {
        let m = |spec: &str, host: &str| DomainSpec::parse(spec).expect("spec").matches(host);
        assert!(m("example.com", "example.com"));
        assert!(!m("example.com", "www.example.com"));
        assert!(m(".example.com", "example.com"));
        assert!(m(".example.com", "a.b.example.com"));
        assert!(!m(".example.com", "badexample.com"));
        assert!(!m("*.example.com", "example.com"));
        assert!(m("*.example.com", "www.example.com"));
        assert!(!m("*.example.com", "wwwexample.com"));
        assert!(m(
            "re:^cdn[0-9]+\\.example\\.com$",
            "CDN12.example.com".to_ascii_lowercase().as_str()
        ));
        assert!(DomainSpec::parse("bad domain").is_err());
        assert!(DomainSpec::parse("re:(").is_err());
        assert!(DomainSpec::parse("").is_err());
    }

    #[test]
    fn address_specs_cover_nets_ranges_and_mapped_v6() {
        let m = |spec: &str, ip: &str| {
            AddrSpec::parse(spec)
                .expect("spec")
                .contains(ip.parse().expect("ip"))
        };
        assert!(m("10.0.0.0/8", "10.200.1.1"));
        assert!(!m("10.0.0.0/8", "11.0.0.1"));
        assert!(m("192.0.2.7", "192.0.2.7"));
        assert!(m("10.0.0.1-10.0.0.9", "10.0.0.5"));
        assert!(!m("10.0.0.1-10.0.0.9", "10.0.0.10"));
        assert!(m("2001:db8::/32", "2001:db8:1::1"));
        assert!(m("10.0.0.0/8", "::ffff:10.1.1.1"));
        assert!(!m("10.0.0.0/8", "2001:db8::1"));
        for bad in ["10.0.0.9-10.0.0.1", "10.0.0.1-::1", "nope", "10.0.0.0/33"] {
            assert!(AddrSpec::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn port_ranges_and_errors() {
        assert_eq!(parse_port("443"), Ok((443, 443)));
        assert_eq!(parse_port("8000-8100"), Ok((8000, 8100)));
        for bad in ["0", "70000", "9-1", "x", ""] {
            assert!(parse_port(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn user_group_listener_method_protocol_and_authenticated() {
        let rules = compile(
            r#"
            [[rule]]
            action = "allow"
            when = { user = ["alice"], listener = ["main"], method = ["connect"], protocol = ["connect", "socks5"], authenticated = true }
            [[rule]]
            action = "allow"
            when = { group = ["staff"] }
        "#,
        );
        assert_eq!(rules.evaluate(&req("a.test", 1)).action, Action::Allow);
        let mut r = req("a.test", 1);
        r.listener = "alt";
        assert_eq!(rules.evaluate(&r).action, Action::Deny);
        let groups = vec!["staff".to_owned()];
        r.groups = &groups;
        assert_eq!(rules.evaluate(&r).rule.as_deref(), Some("#2"));
        let mut r = req("a.test", 1);
        r.user = None;
        assert_eq!(rules.evaluate(&r).action, Action::Deny);
    }

    #[test]
    fn not_inverts_a_nested_match() {
        let rules = compile(
            r#"
            [[rule]]
            action = "allow"
            when = { not = { domain = [".blocked.example"] } }
        "#,
        );
        assert_eq!(rules.evaluate(&req("a.test", 1)).action, Action::Allow);
        assert_eq!(
            rules.evaluate(&req("x.blocked.example", 1)).action,
            Action::Deny
        );
    }

    #[test]
    fn dst_matches_resolved_addresses_only() {
        let rules = compile(
            r#"
            [[rule]]
            action = "deny"
            when = { dst = ["203.0.113.0/24"] }
            [[rule]]
            action = "allow"
        "#,
        );
        assert!(rules.uses_dst());
        let ips: Vec<IpAddr> = vec!["203.0.113.9".parse().expect("ip")];
        let mut r = req("a.test", 1);
        assert_eq!(rules.evaluate(&r).action, Action::Allow, "not resolved yet");
        r.dst_ips = &ips;
        assert_eq!(rules.evaluate(&r).action, Action::Deny);
    }

    #[test]
    fn time_windows_and_the_clock() {
        // Wednesday (2) 1970-01-07 12:00 UTC
        let wed_noon = SystemTime::UNIX_EPOCH + Duration::from_secs(6 * 86_400 + 12 * 3_600);
        assert_eq!(
            Clock::at(wed_noon, 0),
            Clock {
                weekday: 2,
                minute: 720
            }
        );
        assert_eq!(
            Clock::at(wed_noon, 13 * 3_600).weekday,
            3,
            "offset moves the day"
        );
        let w = |days: &[&str], from: &str, to: &str| {
            TimeWindow::compile(&TimeWindowConfig {
                days: days.iter().map(|d| (*d).to_owned()).collect(),
                from: Some(from.to_owned()),
                to: Some(to.to_owned()),
            })
            .expect("window")
        };
        let office = w(&["mon", "tue", "wed", "thu", "fri"], "08:00", "18:00");
        assert!(office.contains(Clock {
            weekday: 2,
            minute: 12 * 60
        }));
        assert!(!office.contains(Clock {
            weekday: 2,
            minute: 18 * 60
        }));
        assert!(!office.contains(Clock {
            weekday: 5,
            minute: 12 * 60
        }));
        let night = w(&["fri"], "22:00", "06:00");
        assert!(night.contains(Clock {
            weekday: 4,
            minute: 23 * 60
        }));
        assert!(
            night.contains(Clock {
                weekday: 5,
                minute: 5 * 60
            }),
            "Saturday morning belongs to Friday's window"
        );
        assert!(!night.contains(Clock {
            weekday: 4,
            minute: 5 * 60
        }));
        assert!(
            TimeWindow::compile(&TimeWindowConfig {
                days: vec!["xyz".into()],
                from: None,
                to: None
            })
            .is_err()
        );
        assert!(
            TimeWindow::compile(&TimeWindowConfig {
                days: vec![],
                from: Some("25:00".into()),
                to: None
            })
            .is_err()
        );
    }

    #[test]
    fn stages_are_isolated_and_configured_stages_default_to_deny() {
        let rules = compile(
            r#"
[[rule]]
stage = "pre_negotiation"
action = "allow"
when = { src = ["192.0.2.0/24"] }
[[rule]]
stage = "post_auth"
action = "allow"
when = { user = ["bob"], authenticated = true }
[[rule]]
stage = "bind"
action = "allow"
when = { port = ["443"] }
[[rule]]
stage = "udp"
action = "allow"
when = { port = ["53"] }
[[rule]]
action = "allow"
"#,
        );
        let mut r = req("example.com", 443);
        assert_eq!(rules.evaluate(&r).action, Action::Allow);
        assert_eq!(
            rules.evaluate_stage(RuleStage::PreNegotiation, &r).action,
            Action::Deny
        );
        r.src = "192.0.2.1".parse().expect("ip");
        assert_eq!(
            rules.evaluate_stage(RuleStage::PreNegotiation, &r).action,
            Action::Allow
        );
        assert_eq!(
            rules.evaluate_stage(RuleStage::PostAuth, &r).action,
            Action::Deny
        );
        r.user = Some("bob");
        assert_eq!(
            rules.evaluate_stage(RuleStage::PostAuth, &r).action,
            Action::Allow
        );
        assert_eq!(
            rules.evaluate_stage(RuleStage::Bind, &r).action,
            Action::Allow
        );
        assert_eq!(
            rules.evaluate_stage(RuleStage::Udp, &r).action,
            Action::Deny
        );
        r.port = 53;
        assert_eq!(
            rules.evaluate_stage(RuleStage::Bind, &r).action,
            Action::Deny
        );
        assert_eq!(
            rules.evaluate_stage(RuleStage::Udp, &r).action,
            Action::Allow
        );
        assert!(!compile("[[rule]]\naction = \"allow\"").has_stage(RuleStage::PostAuth));
    }

    #[test]
    fn early_stages_reject_unavailable_fields_even_under_negation() {
        for (stage, condition) in [
            ("pre_negotiation", "user = [\"alice\"]"),
            ("pre_negotiation", "authenticated = false"),
            ("pre_negotiation", "protocol = [\"socks5\"]"),
            ("post_auth", "dst = [\"127.0.0.1\"]"),
            ("post_auth", "domain = [\"example.com\"]"),
            ("post_auth", "port = [\"443\"]"),
            ("post_auth", "method = [\"CONNECT\"]"),
        ] {
            for when in [condition.to_owned(), format!("not = {{ {condition} }}")] {
                let text = format!(
                    "[[rule]]\nstage = \"{stage}\"\naction = \"allow\"\nwhen = {{ {when} }}"
                );
                let cfg = Config::parse(&text).expect("parse");
                assert!(Rules::compile(&cfg.rules, &known()).is_err(), "{text}");
            }
        }
    }

    #[test]
    fn unknown_names_and_bad_internal_flag_are_refused() {
        for bad in [
            "[[rule]]\naction = \"allow\"\nwhen = { user = [\"mallory\"] }",
            "[[rule]]\naction = \"allow\"\nwhen = { group = [\"nope\"] }",
            "[[rule]]\naction = \"allow\"\nwhen = { listener = [\"nope\"] }",
            "[[rule]]\naction = \"allow\"\nwhen = { protocol = [\"gopher\"] }",
            "[[rule]]\naction = \"deny\"\nallow_internal = true",
        ] {
            let c = Config::parse(bad).expect("parse");
            assert!(Rules::compile(&c.rules, &known()).is_err(), "{bad}");
        }
    }
}
