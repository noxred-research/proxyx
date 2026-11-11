//! Configuration file of `proxyx edge`: one TOML file, no database.
//!
//! The file is parsed strictly (`deny_unknown_fields` everywhere: a typo in a
//! security rule must fail at startup, never silently match everything).
//! This module holds the raw, serde-facing types and the syntax-level checks;
//! [`crate::state::State::build`] compiles them into the runtime form and does
//! the cross-references (pools, parents, listeners) and the host checks
//! (addresses assigned locally).

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context as _;
use common::Secret;
use serde::Deserialize;
use serde::de::{Deserializer, Error as _};

use crate::accesslog::AccessLogConfig;

/// Parse a duration: `500ms`, `30s`, `5m`, `2h`, `1d`, or a bare number of seconds.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (digits, unit) = s.split_at(split);
    let n: u64 = digits.parse().map_err(|_| format!("bad duration {s:?}"))?;
    let ms = match unit.trim() {
        "ms" => return Ok(Duration::from_millis(n)),
        "" | "s" => 1,
        "m" => 60,
        "h" => 3_600,
        "d" => 86_400,
        _ => return Err(format!("bad duration unit in {s:?}")),
    };
    n.checked_mul(ms)
        .map(Duration::from_secs)
        .ok_or_else(|| format!("duration {s:?} overflows"))
}

/// Serde adapter: integer seconds or a duration string.
pub mod duration {
    use super::*;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        Secs(u64),
        Text(String),
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        match Raw::deserialize(d)? {
            Raw::Secs(n) => Ok(Duration::from_secs(n)),
            Raw::Text(s) => parse_duration(&s).map_err(D::Error::custom),
        }
    }
}

/// A transfer rate in bytes per second. Written as a number of bytes per
/// second or a string: `512K`, `2M`, `1G` and `KB`/`MB`/`GB` are decimal
/// (1000-based) bytes, `KiB`/`MiB`/`GiB` binary, `Kbit`/`Mbit`/`Gbit`
/// decimal bits; a trailing `/s` is optional (`"10Mbit/s"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bandwidth(pub u64);

impl Bandwidth {
    pub fn parse(s: &str) -> Result<Self, String> {
        let t = s.trim();
        let t = t.strip_suffix("/s").unwrap_or(t).trim();
        let split = t.find(|c: char| !c.is_ascii_digit()).unwrap_or(t.len());
        let (digits, unit) = t.split_at(split);
        let n: u64 = digits
            .parse()
            .map_err(|_| format!("bad bandwidth {s:?}: expected a number with an optional unit"))?;
        // (numerator, denominator) of bytes per unit
        let (num, den): (u64, u64) = match unit.trim() {
            "" | "B" => (1, 1),
            "K" | "kB" | "KB" => (1_000, 1),
            "M" | "MB" => (1_000_000, 1),
            "G" | "GB" => (1_000_000_000, 1),
            "KiB" => (1 << 10, 1),
            "MiB" => (1 << 20, 1),
            "GiB" => (1 << 30, 1),
            "bit" => (1, 8),
            "Kbit" | "kbit" => (1_000, 8),
            "Mbit" => (1_000_000, 8),
            "Gbit" => (1_000_000_000, 8),
            other => return Err(format!("bad bandwidth unit {other:?} in {s:?}")),
        };
        let bytes = n
            .checked_mul(num)
            .map(|v| v / den)
            .ok_or_else(|| format!("bandwidth {s:?} overflows"))?;
        if bytes == 0 {
            return Err(format!("bandwidth {s:?} must be above zero"));
        }
        Ok(Self(bytes))
    }
}

impl<'de> Deserialize<'de> for Bandwidth {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Int(u64),
            Text(String),
        }
        match Raw::deserialize(d)? {
            Raw::Int(0) => Err(D::Error::custom("bandwidth must be above zero")),
            Raw::Int(n) => Ok(Self(n)),
            Raw::Text(s) => Self::parse(&s).map_err(D::Error::custom),
        }
    }
}

/// An event rate written `N/s`, `N/m` (or `N/min`), `N/h`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RequestRate {
    /// Events allowed per period; also the bucket size.
    pub count: u32,
    pub per: Duration,
}

impl RequestRate {
    pub fn parse(s: &str) -> Result<Self, String> {
        let (n, unit) = s
            .trim()
            .split_once('/')
            .ok_or_else(|| format!("bad rate {s:?}: expected N/s, N/m or N/h"))?;
        let count: u32 = n
            .trim()
            .parse()
            .map_err(|_| format!("bad rate count in {s:?}"))?;
        if count == 0 {
            return Err(format!("rate {s:?} must be above zero"));
        }
        let per = match unit.trim() {
            "s" | "sec" => Duration::from_secs(1),
            "m" | "min" => Duration::from_secs(60),
            "h" | "hour" => Duration::from_secs(3_600),
            other => return Err(format!("bad rate period {other:?} in {s:?}")),
        };
        Ok(Self { count, per })
    }
}

impl<'de> Deserialize<'de> for RequestRate {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::parse(&String::deserialize(d)?).map_err(D::Error::custom)
    }
}

/// Root of the file.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub server: ServerConfig,
    pub timeouts: Timeouts,
    pub tcp: TcpConfig,
    pub breaker: BreakersConfig,
    pub health: HealthConfig,
    pub dns: DnsConfig,
    pub selector: SelectorConfig,
    pub stick: StickConfig,
    #[serde(rename = "chain")]
    pub chains: Vec<ChainConfig>,
    pub log: LogConfig,
    pub access_log: AccessLogConfig,
    pub http: HttpConfig,
    pub auth: AuthConfig,
    #[serde(rename = "listener")]
    pub listeners: Vec<ListenerConfig>,
    #[serde(rename = "pool")]
    pub pools: Vec<PoolConfig>,
    #[serde(rename = "parent")]
    pub parents: Vec<ParentConfig>,
    #[serde(rename = "user")]
    pub users: Vec<UserConfig>,
    /// Access rules, first match wins, default deny.
    #[serde(rename = "rule")]
    pub rules: Vec<RuleConfig>,
    /// Outgoing address selection, first match wins.
    #[serde(rename = "egress")]
    pub egress: Vec<EgressRuleConfig>,
    /// Parent routing, first match wins.
    #[serde(rename = "route")]
    pub routes: Vec<RouteRuleConfig>,
    /// Bandwidth, connection and request-rate limits; every match applies.
    #[serde(rename = "limit")]
    pub limits: Vec<LimitConfig>,
}

/// Parent selection and its connection budget.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SelectorConfig {
    pub strategy: Strategy,
    pub hash_key: HashKey,
    pub race_width: usize,
    pub tolerance_ms: u64,
    #[serde(with = "duration")]
    pub idle_timeout: Duration,
    pub interrupt_on_switch: bool,
    pub connect_retries: usize,
    #[serde(with = "duration")]
    pub forward_timeout: Duration,
}

impl Default for SelectorConfig {
    fn default() -> Self {
        Self {
            strategy: Strategy::Random,
            hash_key: HashKey::ClientIp,
            race_width: 2,
            tolerance_ms: 50,
            idle_timeout: Duration::from_secs(300),
            interrupt_on_switch: false,
            connect_retries: 2,
            forward_timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct StickConfig {
    pub capacity: usize,
    #[serde(with = "duration")]
    pub ttl: Duration,
    pub redis: Option<StickRedisConfig>,
}

impl Default for StickConfig {
    fn default() -> Self {
        Self {
            capacity: 65536,
            ttl: Duration::from_secs(600),
            redis: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StickRedisConfig {
    pub url: Secret,
    #[serde(default = "stick_prefix")]
    pub key_prefix: String,
    #[serde(default = "probe_timeout", with = "duration")]
    pub timeout: Duration,
    #[serde(default, deserialize_with = "optional_duration")]
    pub ttl: Option<Duration>,
}

fn stick_prefix() -> String {
    "proxyx:edge:stick".to_owned()
}
fn probe_timeout() -> Duration {
    Duration::from_secs(5)
}
fn probe_status() -> u16 {
    200
}
fn probe_body_limit() -> usize {
    65536
}
fn optional_duration<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Duration>, D::Error> {
    duration::deserialize(d).map(Some)
}

/// Each entry defines one named chain; hops run in listed order.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainConfig {
    pub name: String,
    pub hops: Vec<HopConfig>,
    #[serde(default)]
    pub probe: Option<ProbeConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HopConfig {
    pub parents: Vec<String>,
    #[serde(default)]
    pub selector: Option<SelectorConfig>,
}

/// HTTP and verified HTTPS checks tunnel through every configured parent hop.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProbeConfig {
    Tcp {
        target: String,
    },
    Http {
        url: String,
        #[serde(default = "probe_status")]
        status: u16,
        #[serde(default)]
        body_contains: Option<String>,
        #[serde(default = "probe_body_limit")]
        max_body_bytes: usize,
    },
    Command {
        command: Vec<String>,
    },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ServerConfig {
    /// `/metrics`, `/healthz`, `/readyz`. Absent: no ops listener.
    pub ops_listen: Option<SocketAddr>,
    /// Most client connections served at once, over all listeners.
    pub max_connections: usize,
    /// Most connections of one source address; 0 is unlimited.
    pub max_connections_per_src: usize,
    /// Pool used when no egress rule, login option, user or listener names
    /// one. Absent: the operating system picks the source address.
    pub default_pool: Option<String>,
    /// Route used when no `[[route]]` matches.
    pub default_route: Route,
    /// Offset of the zone `time` conditions are read in, `+HH:MM` or `-HH:MM`.
    pub utc_offset: String,
    /// How long a stopping process waits for open tunnels.
    #[serde(with = "duration")]
    pub shutdown_grace: Duration,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            ops_listen: None,
            max_connections: 10_000,
            max_connections_per_src: 0,
            default_pool: None,
            default_route: Route::Direct,
            utc_offset: "+00:00".to_owned(),
            shutdown_grace: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Timeouts {
    /// Reading the first request and the login, per connection.
    #[serde(with = "duration")]
    pub handshake: Duration,
    /// Name resolution plus TCP connect to the target (or the parent).
    #[serde(with = "duration")]
    pub connect: Duration,
    /// A tunnel with no byte in either direction this long is closed.
    #[serde(with = "duration")]
    pub idle: Duration,
    /// A client connection waiting for its next HTTP request.
    #[serde(with = "duration")]
    pub keepalive: Duration,
    /// Waiting for the target's response head after the request was sent.
    #[serde(with = "duration")]
    pub response_header: Duration,
    /// Longest a single request, tunnel or UDP association may last, whatever
    /// moves on it; `0` is no limit.
    #[serde(with = "duration")]
    pub total: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            handshake: Duration::from_secs(30),
            connect: Duration::from_secs(10),
            idle: Duration::from_secs(600),
            keepalive: Duration::from_secs(60),
            response_header: Duration::from_secs(60),
            total: Duration::ZERO,
        }
    }
}

/// TCP options of one side of the proxy.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SocketOptions {
    /// Turn on TCP keepalive: a peer that vanished without closing is found.
    pub keepalive: bool,
    /// Idle time before the first probe.
    #[serde(with = "duration")]
    pub keepalive_time: Duration,
    /// Time between probes.
    #[serde(with = "duration")]
    pub keepalive_interval: Duration,
    /// Unanswered probes after which the kernel drops the connection.
    pub keepalive_retries: u32,
    pub nodelay: bool,
}

impl Default for SocketOptions {
    fn default() -> Self {
        Self {
            keepalive: true,
            keepalive_time: Duration::from_secs(60),
            keepalive_interval: Duration::from_secs(15),
            keepalive_retries: 4,
            nodelay: true,
        }
    }
}

/// Socket options of the client side and of the target or parent side.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TcpConfig {
    pub client: SocketOptions,
    pub upstream: SocketOptions,
}

/// Circuit breaker thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct BreakerConfig {
    /// Failures in a row that open the breaker.
    pub failure_threshold: u32,
    /// How long it stays open before probes are let through.
    #[serde(with = "duration")]
    pub open_duration: Duration,
    /// Requests let through at once while half open.
    pub half_open_probes: u32,
    /// Successes in half-open state that close it again.
    pub success_threshold: u32,
}

impl Default for BreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 3,
            open_duration: Duration::from_secs(30),
            half_open_probes: 1,
            success_threshold: 1,
        }
    }
}

impl BreakerConfig {
    pub fn check(&self, what: &str) -> Result<(), String> {
        if self.failure_threshold == 0 || self.half_open_probes == 0 || self.success_threshold == 0
        {
            return Err(format!(
                "{what}: failure_threshold, half_open_probes and success_threshold must be above zero"
            ));
        }
        if self.open_duration.is_zero() {
            return Err(format!("{what}: open_duration must be above zero"));
        }
        Ok(())
    }
}

/// One breaker per parent proxy and one per egress address.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct BreakersConfig {
    pub parent: BreakerConfig,
    pub egress: BreakerConfig,
}

/// Active health checks of parents and local egress addresses.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HealthConfig {
    /// Time between rounds of checks; `0` turns active checks off.
    #[serde(with = "duration")]
    pub interval: Duration,
    /// Bound on one probe.
    #[serde(with = "duration")]
    pub timeout: Duration,
    /// `host:port` a probe opens a tunnel to through each parent
    /// (HTTP CONNECT or SOCKS5 CONNECT). Absent: the probe only connects to the parent.
    pub parent_target: Option<String>,
    /// Failed probes in a row that mark a parent unhealthy.
    pub unhealthy_threshold: u32,
    /// Good probes in a row that mark it healthy again.
    pub healthy_threshold: u32,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(10),
            timeout: Duration::from_secs(5),
            parent_target: None,
            unhealthy_threshold: 2,
            healthy_threshold: 1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpVersion {
    PreferIpv4,
    PreferIpv6,
    Ipv4Only,
    Ipv6Only,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DnsConfig {
    /// Resolvers to ask. Empty: the system resolver configuration.
    pub nameservers: Vec<IpAddr>,
    /// Cached answers.
    pub cache_size: u64,
    #[serde(with = "duration")]
    pub timeout: Duration,
    pub attempts: usize,
    /// Cached answers live at least / at most this long.
    #[serde(with = "duration")]
    pub min_ttl: Duration,
    #[serde(with = "duration")]
    pub max_ttl: Duration,
    pub ip_version: IpVersion,
    /// Fixed answers that bypass DNS (`name = [addresses]`).
    pub hosts: BTreeMap<String, Vec<IpAddr>>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            nameservers: Vec::new(),
            cache_size: 4096,
            timeout: Duration::from_secs(5),
            attempts: 2,
            min_ttl: Duration::from_secs(30),
            max_ttl: Duration::from_secs(3_600),
            ip_version: IpVersion::PreferIpv4,
            hosts: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LogConfig {
    /// `tracing` filter; `RUST_LOG` overrides it.
    pub level: String,
    /// One JSON object per line (the default); plain text when false.
    pub json: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".to_owned(),
            json: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForwardedFor {
    /// Append the client address.
    On,
    /// Send `X-Forwarded-For: unknown`.
    Off,
    /// Remove the header.
    Delete,
    /// Replace every entry with the client address.
    Truncate,
    /// Pass the client's header through unchanged.
    Transparent,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HttpConfig {
    pub forwarded_for: ForwardedFor,
    /// Add `Via: 1.1 <proxy_name>`; off by default (identity stays hidden).
    pub via: bool,
    pub proxy_name: String,
    /// Header names removed from forwarded requests.
    pub request_headers_remove: Vec<String>,
    /// Headers set (replacing any value) on forwarded requests.
    pub request_headers_set: BTreeMap<String, String>,
    pub response_headers_remove: Vec<String>,
    pub response_headers_set: BTreeMap<String, String>,
    /// Header edits applied after the global policy for the deciding access rule.
    #[serde(rename = "header_rule")]
    pub header_rules: Vec<HeaderRuleConfig>,
    /// Largest request or response head accepted.
    pub max_header_bytes: usize,
    /// Requests served on one client connection before it is closed; `0` is no limit.
    pub client_max_requests: u32,
    /// Keep connections to HTTP parents open for the next bodyless request.
    pub parent_keepalive: bool,
    /// How long an idle parent connection is kept.
    #[serde(with = "duration")]
    pub parent_idle_timeout: Duration,
    /// Idle parent connections kept in all (and half of it per client key).
    pub parent_max_idle: usize,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            forwarded_for: ForwardedFor::Delete,
            via: false,
            proxy_name: "proxyx".to_owned(),
            request_headers_remove: Vec::new(),
            request_headers_set: BTreeMap::new(),
            response_headers_remove: Vec::new(),
            response_headers_set: BTreeMap::new(),
            header_rules: Vec::new(),
            max_header_bytes: 32 * 1024,
            client_max_requests: 1000,
            parent_keepalive: true,
            parent_idle_timeout: Duration::from_secs(30),
            parent_max_idle: 64,
        }
    }
}

/// Safe request and response edits scoped to a named request-stage allow rule.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HeaderRuleConfig {
    pub rule: String,
    pub request_headers_remove: Vec<String>,
    pub request_headers_set: BTreeMap<String, String>,
    pub response_headers_remove: Vec<String>,
    pub response_headers_set: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AuthConfig {
    /// `Proxy-Authenticate` realm.
    pub realm: String,
    /// htpasswd-style file (`user:hash`); `[[user]]` entries of the same name
    /// add settings to it.
    pub users_file: Option<PathBuf>,
    /// Read `-sid-<id>`, `-pool-<name>` and `-ip-<n>` option pairs off the end
    /// of the login name.
    pub login_options: bool,
    /// Failed logins one source may make per `fail_window` before it is refused.
    pub fail_limit: u32,
    #[serde(with = "duration")]
    pub fail_window: Duration,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            realm: "proxyx".to_owned(),
            users_file: None,
            login_options: false,
            fail_limit: 20,
            fail_window: Duration::from_secs(60),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListenerProtocol {
    /// HTTP proxy and SOCKS4/4a/5 on one port, told apart by the first byte.
    Auto,
    Http,
    Socks,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListenerAuth {
    Users,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyProtocolMode {
    Off,
    /// Use a header when one comes from a trusted peer.
    Optional,
    /// Refuse a connection without a header.
    Required,
}

/// PEM certificate chain and matching PEM private key for an encrypted listener.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerConfig {
    pub name: String,
    pub listen: SocketAddr,
    #[serde(default = "default_protocol")]
    pub protocol: ListenerProtocol,
    #[serde(default = "default_auth")]
    pub auth: ListenerAuth,
    /// Default egress pool of this listener.
    #[serde(default)]
    pub pool: Option<String>,
    #[serde(default = "default_proxy_protocol")]
    pub proxy_protocol: ProxyProtocolMode,
    /// Peers whose PROXY header is believed (required with `proxy_protocol`).
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// Serve SOCKS5 UDP ASSOCIATE.
    #[serde(default)]
    pub udp: bool,
    /// Encrypt HTTP, SOCKS or mixed protocol traffic with TLS.
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    /// Most connections on this listener; 0 is unlimited.
    #[serde(default)]
    pub max_connections: usize,
}

fn default_protocol() -> ListenerProtocol {
    ListenerProtocol::Auto
}
fn default_auth() -> ListenerAuth {
    ListenerAuth::Users
}
fn default_proxy_protocol() -> ProxyProtocolMode {
    ProxyProtocolMode::Off
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Strategy {
    /// Always the first address (3proxy `-e`).
    First,
    /// First healthy address in configuration order.
    Fifo,
    #[default]
    RoundRobin,
    Random,
    LeastConnections,
    /// Hash of the session id, else the user, else the client address.
    Sticky,
    /// Rendezvous affinity using the configured hash key.
    Hash,
    Userhash,
    Sourcehash,
    /// Equal-weight CARP-style rendezvous affinity.
    Carp,
    /// Dial all available addresses concurrently; retain the first success.
    Race,
    /// Prefer the measured fastest address, with switching tolerance.
    Latency,
}

/// Request attribute used by hash and CARP selectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum HashKey {
    #[default]
    ClientIp,
    TargetHost,
    User,
    SessionId,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolConfig {
    pub name: String,
    /// Explicit local addresses.
    #[serde(default)]
    pub addresses: Vec<IpAddr>,
    /// Networks routed to this host (`ip route add local <net> dev lo`); each
    /// connection draws its source address from one, at random, round robin
    /// or by session hash. One per IP family, not mixed with `addresses`.
    #[serde(default)]
    pub prefixes: Vec<String>,
    /// Add every address assigned to this interface.
    #[serde(default)]
    pub interface: Option<String>,
    #[serde(default = "yes")]
    pub ipv4: bool,
    #[serde(default = "yes")]
    pub ipv6: bool,
    /// Networks left out of an interface's addresses.
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub strategy: Strategy,
    #[serde(default)]
    pub hash_key: HashKey,
    /// Local addresses reserved for when every primary address is unavailable.
    #[serde(default)]
    pub backup_addresses: Vec<IpAddr>,
    /// Override the egress breaker's consecutive-failure threshold.
    #[serde(default)]
    pub max_fails: Option<u32>,
    /// Override the egress breaker's open interval.
    #[serde(default, deserialize_with = "PoolConfig::deserialize_fail_timeout")]
    pub fail_timeout: Option<Duration>,
    /// Keep the current latency choice while it is within this of the fastest.
    #[serde(default = "PoolConfig::default_latency_tolerance", with = "duration")]
    pub latency_tolerance: Duration,
    /// Maximum local source addresses dialed concurrently by the race selector.
    #[serde(default = "PoolConfig::default_race_width")]
    pub race_width: usize,
}

impl PoolConfig {
    fn default_race_width() -> usize {
        2
    }

    fn default_latency_tolerance() -> Duration {
        Duration::from_millis(50)
    }

    fn deserialize_fail_timeout<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<Duration>, D::Error> {
        duration::deserialize(d).map(Some)
    }
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParentKind {
    Http,
    Https,
    Socks4,
    Socks5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SendProxyProtocol {
    #[default]
    Off,
    V1,
    V2,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParentConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: ParentKind,
    /// `host:port`.
    pub address: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<Secret>,
    /// Share of the traffic inside one priority tier.
    #[serde(default = "one")]
    pub weight: u32,
    /// Lower tiers are used first; a higher tier takes over when every
    /// parent below it is down.
    #[serde(default)]
    pub priority: u32,
    /// Local source address pool for the connection to the parent.
    #[serde(default)]
    pub pool: Option<String>,
    #[serde(default)]
    pub send_proxy_protocol: SendProxyProtocol,
    #[serde(default)]
    pub backup: bool,
    #[serde(default)]
    pub default: bool,
    #[serde(default)]
    pub max_fails: Option<u32>,
    #[serde(default, deserialize_with = "optional_duration")]
    pub fail_timeout: Option<Duration>,
    #[serde(default)]
    pub probe: Option<ProbeConfig>,
}

fn one() -> u32 {
    1
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserConfig {
    pub name: String,
    /// Plaintext password. Prefer a hash.
    #[serde(default)]
    pub password: Option<Secret>,
    /// htpasswd-style hash (bcrypt, apr1, md5/sha256/sha512-crypt, argon2, `{SHA}`).
    #[serde(default)]
    pub password_hash: Option<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    /// Egress pool of this user.
    #[serde(default)]
    pub pool: Option<String>,
    /// Pools the user may pick with a `-pool-<name>` login option.
    #[serde(default)]
    pub allowed_pools: Vec<String>,
    /// May pick an address of the pool with `-ip-<n>` (1-based).
    #[serde(default)]
    pub allow_ip_select: bool,
    /// Listeners the user may log in on; empty is all.
    #[serde(default)]
    pub allowed_listeners: Vec<String>,
    /// Most connections of this user; absent is unlimited.
    #[serde(default)]
    pub max_connections: Option<usize>,
    /// Accept this user on SOCKS4 with the user id alone (SOCKS4 carries no password).
    #[serde(default)]
    pub socks4: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Route {
    /// Connect to the target from this machine (squid `always_direct`).
    #[default]
    Direct,
    /// Only through a parent; 503 when none is up (squid `never_direct`).
    Parent,
    /// Through a parent while one is up, else direct.
    ParentOrDirect,
}

/// A day-and-time window. `days` empty is every day; `from`/`to` are
/// `HH:MM` in the configured offset, `to` exclusive; a window that ends
/// before it starts wraps over midnight.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeWindowConfig {
    #[serde(default)]
    pub days: Vec<String>,
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub to: Option<String>,
}

/// Conditions of a rule. Every field that is set must match; the values of
/// one field are alternatives.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct MatchConfig {
    /// Client addresses: `192.0.2.7`, `10.0.0.0/8`, `10.0.0.1-10.0.0.9`.
    pub src: Vec<String>,
    /// Destination addresses (the name is resolved): same syntax.
    pub dst: Vec<String>,
    /// `example.com` exact, `.example.com` the name and its subdomains,
    /// `*.example.com` subdomains only, `re:<regex>` regular expression.
    pub domain: Vec<String>,
    /// `443` or `8000-8100`.
    pub port: Vec<String>,
    /// `GET`, `POST`, `CONNECT`, ...; SOCKS commands count as `CONNECT` and `UDP`.
    pub method: Vec<String>,
    /// `http`, `connect`, `socks4`, `socks5`, `udp`.
    pub protocol: Vec<String>,
    pub user: Vec<String>,
    pub group: Vec<String>,
    pub listener: Vec<String>,
    pub time: Vec<TimeWindowConfig>,
    /// `true`: a login was presented and accepted; `false`: none.
    pub authenticated: Option<bool>,
    /// The nested conditions must NOT match.
    pub not: Option<Box<MatchConfig>>,
}

/// The point in the protocol lifecycle where an access rule applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuleStage {
    #[default]
    Request,
    PreNegotiation,
    PostAuth,
    Bind,
    Udp,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleConfig {
    #[serde(default)]
    pub name: Option<String>,
    pub action: Action,
    /// Unspecified stages retain the existing request-rule behavior.
    #[serde(default)]
    pub stage: RuleStage,
    #[serde(default)]
    pub when: MatchConfig,
    /// Let this rule reach private and internal destinations, which are
    /// refused by default. Allow rules only.
    #[serde(default)]
    pub allow_internal: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressRuleConfig {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub when: MatchConfig,
    /// Pool to pick the source address from.
    #[serde(default)]
    pub pool: Option<String>,
    /// One fixed local source address (squid `tcp_outgoing_address`).
    #[serde(default)]
    pub address: Option<IpAddr>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteRuleConfig {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub when: MatchConfig,
    pub route: Route,
    /// Parents this rule may use; empty is every configured parent.
    #[serde(default)]
    pub parents: Vec<String>,
    /// Named, ordered multi-hop chain. Mutually exclusive with parents.
    #[serde(default)]
    pub chain: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LimitScope {
    /// One budget per user (per source address when there is no login).
    #[default]
    User,
    /// One budget per client source address.
    Src,
    /// One budget shared by everything that matches the rule.
    Rule,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitConfig {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub when: MatchConfig,
    #[serde(default)]
    pub scope: LimitScope,
    /// Target to client rate.
    #[serde(default)]
    pub bandwidth_down: Option<Bandwidth>,
    /// Client to target rate.
    #[serde(default)]
    pub bandwidth_up: Option<Bandwidth>,
    /// Simultaneous connections.
    #[serde(default)]
    pub max_connections: Option<usize>,
    /// New requests (HTTP requests, CONNECT and SOCKS commands).
    #[serde(default)]
    pub request_rate: Option<RequestRate>,
}

impl Config {
    /// Read and parse a file. Syntax only; see [`crate::state::State::build`].
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read config {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("config {}", path.display()))
    }

    pub fn parse(text: &str) -> anyhow::Result<Self> {
        toml::from_str(text).map_err(|e| anyhow::anyhow!("{e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_parse_millis_and_units() {
        assert_eq!(parse_duration("250ms"), Ok(Duration::from_millis(250)));
        assert_eq!(parse_duration("5m"), Ok(Duration::from_secs(300)));
        assert_eq!(parse_duration("7"), Ok(Duration::from_secs(7)));
        assert!(parse_duration("fast").is_err());
        assert!(parse_duration("5x").is_err());
    }

    #[test]
    fn bandwidth_units() {
        assert_eq!(Bandwidth::parse("1000").map(|b| b.0), Ok(1000));
        assert_eq!(Bandwidth::parse("2M").map(|b| b.0), Ok(2_000_000));
        assert_eq!(Bandwidth::parse("2MiB/s").map(|b| b.0), Ok(2 << 20));
        assert_eq!(Bandwidth::parse("8Mbit/s").map(|b| b.0), Ok(1_000_000));
        assert!(Bandwidth::parse("0").is_err());
        assert!(Bandwidth::parse("5 parsecs").is_err());
        assert!(Bandwidth::parse("").is_err());
    }

    #[test]
    fn request_rates() {
        let r = RequestRate::parse("60/min").expect("rate");
        assert_eq!((r.count, r.per), (60, Duration::from_secs(60)));
        assert!(RequestRate::parse("0/s").is_err());
        assert!(RequestRate::parse("10").is_err());
        assert!(RequestRate::parse("10/fortnight").is_err());
    }

    #[test]
    fn unknown_fields_are_refused_everywhere() {
        for bad in [
            "bogus = 1",
            "[server]\nops = 1",
            "[[rule]]\naction = \"allow\"\nwhen = { domian = [\"x\"] }",
            "[[listener]]\nname = \"a\"\nlisten = \"127.0.0.1:1\"\nsocks = true",
        ] {
            assert!(Config::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn an_empty_file_is_a_valid_default() {
        let c = Config::parse("").expect("empty");
        assert!(c.listeners.is_empty());
        assert_eq!(c.http.forwarded_for, ForwardedFor::Delete);
        assert!(!c.http.via);
    }

    #[test]
    fn full_example_parses() {
        let text = r#"
            [server]
            ops_listen = "127.0.0.1:9180"
            default_pool = "all"

            [[listener]]
            name = "main"
            listen = "0.0.0.0:3128"
            auth = "users"

            [[pool]]
            name = "all"
            addresses = ["127.0.0.2", "::1"]
            strategy = "least_connections"

            [[user]]
            name = "alice"
            password = "s3cret"
            groups = ["staff"]

            [[rule]]
            action = "allow"
            when = { user = ["alice"], port = ["80", "443"], time = [{ days = ["mon"], from = "08:00", to = "18:00" }] }

            [[limit]]
            when = { group = ["staff"] }
            bandwidth_down = "10Mbit/s"
            request_rate = "100/min"
        "#;
        let c = Config::parse(text).expect("parse");
        assert_eq!(c.pools[0].strategy, Strategy::LeastConnections);
        assert_eq!(c.limits[0].bandwidth_down, Some(Bandwidth(1_250_000)));
        assert_eq!(c.rules[0].when.time.len(), 1);
    }
}
