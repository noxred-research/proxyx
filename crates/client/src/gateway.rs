//! The pool gateway: selecting an exit by proxy username, reading the tunnel head, and the
//! refusal causes.
//!
//! The gateway takes a CONNECT on `:8080` and SOCKS5 on `:1080`. The caller authenticates with
//! the org key as the proxy *password*; the *username* is `px` followed by `-key-value` pairs
//! that narrow the policy (for example `px-kind-rotating-cc-fr-sid-scan42`). Values are
//! `[a-z0-9_]` and never contain `-`. The gateway refuses a username it cannot parse and never
//! repairs one, so [`PoolSelector`] checks the same rules locally and refuses to render a
//! username the gateway would deny.

use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use reqwest::Url;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

use crate::error::{Error, Result};
use crate::secret::Secret;

/// Longest accepted username in bytes.
pub const MAX_USERNAME_LEN: usize = 128;
/// Longest city and provider value (their slug types are capped at 48).
const MAX_SLUG_LEN: usize = 48;
/// The gateway's CONNECT port.
pub const CONNECT_PORT: u16 = 8080;
/// The gateway's SOCKS5 port.
pub const SOCKS5_PORT: u16 = 1080;
/// Response header carrying the gateway's id for the tunnel.
pub const SESSION_HEADER: &str = "X-ProxyX-Pool-Session";
/// Response header carrying the exit IP of the tunnel.
pub const EXIT_IP_HEADER: &str = "X-ProxyX-Exit-IP";
/// Longest status line plus headers the client reads from a CONNECT answer.
const MAX_HEAD_LEN: usize = 8 * 1024;

// --- selector -------------------------------------------------------------------------------

/// Proxy kind: rented static IPs, or quota-based rotating sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// Rented, known IPs or modems.
    Static,
    /// Sessions created on demand.
    Rotating,
}

impl Kind {
    /// Wire value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::Rotating => "rotating",
        }
    }
}

/// Whether the exit IP stays with the sticky key or changes per tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rotation {
    /// Keep one exit while the lease lives.
    Sticky,
    /// A new exit for every tunnel. Cannot be combined with a `sid`.
    Each,
}

impl Rotation {
    /// Wire value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sticky => "sticky",
            Self::Each => "each",
        }
    }
}

/// A selector the gateway would deny, with the rule it breaks.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SelectorError {
    /// Longer than [`MAX_USERNAME_LEN`] bytes.
    #[error("username is {0} bytes; the gateway accepts at most 128")]
    TooLong(usize),
    /// Does not start with `px`.
    #[error("username must start with `px`")]
    MissingPrefix,
    /// A key without a value, or a value that contains `-`.
    #[error("username has a key without a value")]
    Unpaired,
    /// A key the gateway does not know.
    #[error("unknown option {0:?}")]
    UnknownKey(String),
    /// A key given twice.
    #[error("option {0:?} given twice")]
    DuplicateKey(&'static str),
    /// A value outside its grammar.
    #[error("invalid value for `{key}`: {reason}")]
    InvalidValue {
        /// The option.
        key: &'static str,
        /// The rule broken.
        reason: &'static str,
    },
    /// `city` without `cc`.
    #[error("`city` needs `cc`")]
    CityWithoutCountry,
    /// `sid` with `rot-each`.
    #[error("`sid` cannot be combined with `rot-each`")]
    SidWithEachRotation,
}

/// The options of a pool username. Build one, then [`PoolSelector::username`] renders it.
///
/// Every setter stores its value as given; [`PoolSelector::username`] checks the whole
/// selector with the gateway's rules (see [`SelectorError`]) and renders the keys in a fixed
/// order: `kind`, `cc`, `city`, `prov`, `ttl`, `sid`, `rot`. Values must already be lowercase
/// `[a-z0-9_]`: the gateway refuses `FR` instead of folding it to `fr`.
///
/// ```
/// use proxyx_client::gateway::{Kind, PoolSelector};
///
/// let username = PoolSelector::new()
///     .kind(Kind::Rotating)
///     .country("fr")
///     .sid("scan42")
///     .username()?;
/// assert_eq!(username, "px-kind-rotating-cc-fr-sid-scan42");
/// # Ok::<(), proxyx_client::gateway::SelectorError>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PoolSelector {
    kind: Option<Kind>,
    country: Option<String>,
    city: Option<String>,
    provider: Option<String>,
    ttl: Option<Duration>,
    sid: Option<String>,
    rotation: Option<Rotation>,
    strict: Option<bool>,
}

fn is_value(v: &str) -> bool {
    !v.is_empty()
        && v.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn bad(key: &'static str, reason: &'static str) -> SelectorError {
    SelectorError::InvalidValue { key, reason }
}

fn set<T>(slot: &mut Option<T>, key: &'static str, value: T) -> Result<(), SelectorError> {
    match slot.replace(value) {
        Some(_) => Err(SelectorError::DuplicateKey(key)),
        None => Ok(()),
    }
}

/// `30`, `30s`, `5m`, `2h` or `1d`, like the gateway's duration parser.
fn parse_ttl(value: &str) -> Option<Duration> {
    let (digits, unit) = value
        .find(|c: char| !c.is_ascii_digit())
        .map_or((value, ""), |i| value.split_at(i));
    let n: u64 = digits.parse().ok()?;
    let mult = match unit {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3_600,
        "d" => 86_400,
        _ => return None,
    };
    n.checked_mul(mult).map(Duration::from_secs)
}

fn render_ttl(ttl: Duration) -> Result<String, SelectorError> {
    if ttl.subsec_nanos() != 0 {
        return Err(bad("ttl", "must be a whole number of seconds"));
    }
    let secs = ttl.as_secs();
    if secs == 0 {
        return Err(bad("ttl", "must be above zero"));
    }
    Ok(match secs {
        s if s.is_multiple_of(86_400) => format!("{}d", s / 86_400),
        s if s.is_multiple_of(3_600) => format!("{}h", s / 3_600),
        s if s.is_multiple_of(60) => format!("{}m", s / 60),
        s => format!("{s}s"),
    })
}

impl PoolSelector {
    /// A selector with no option: the policy's defaults. Renders as `px`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Proxy kind.
    #[must_use]
    pub fn kind(mut self, kind: Kind) -> Self {
        self.kind = Some(kind);
        self
    }

    /// Country: two lowercase letters (ISO 3166-1 alpha-2).
    #[must_use]
    pub fn country(mut self, country: impl Into<String>) -> Self {
        self.country = Some(country.into());
        self
    }

    /// City slug, `[a-z0-9_]` up to 48 bytes. Needs a country.
    #[must_use]
    pub fn city(mut self, city: impl Into<String>) -> Self {
        self.city = Some(city.into());
        self
    }

    /// Provider id, `[a-z0-9_]` up to 48 bytes. A provider id with `-` cannot be selected.
    #[must_use]
    pub fn provider(mut self, provider: impl Into<String>) -> Self {
        self.provider = Some(provider.into());
        self
    }

    /// Lease idle time: a whole, non-zero number of seconds. The policy caps it.
    #[must_use]
    pub fn ttl(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Sticky key chosen by the caller, `[a-z0-9_]`. Equal keys share an exit.
    #[must_use]
    pub fn sid(mut self, sid: impl Into<String>) -> Self {
        self.sid = Some(sid.into());
        self
    }

    /// Rotation mode.
    #[must_use]
    pub fn rotation(mut self, rotation: Rotation) -> Self {
        self.rotation = Some(rotation);
        self
    }

    /// Ask the provider for a strict sticky session (`strict-true`): the exit IP must
    /// not change during the session, and the lease fails rather than falling back to
    /// another IP. `strict-false` explicitly allows a non-strict session.
    #[must_use]
    pub fn strict(mut self, strict: bool) -> Self {
        self.strict = Some(strict);
        self
    }

    /// Check the selector and render the proxy username.
    pub fn username(&self) -> Result<String, SelectorError> {
        if let Some(country) = &self.country
            && !(country.len() == 2 && country.bytes().all(|b| b.is_ascii_lowercase()))
        {
            return Err(bad("cc", "must be two lowercase letters"));
        }
        if let Some(city) = &self.city {
            if self.country.is_none() {
                return Err(SelectorError::CityWithoutCountry);
            }
            if !is_value(city) || city.len() > MAX_SLUG_LEN {
                return Err(bad("city", "must be [a-z0-9_], 1 to 48 bytes"));
            }
        }
        if let Some(provider) = &self.provider
            && (!is_value(provider) || provider.len() > MAX_SLUG_LEN)
        {
            return Err(bad("prov", "must be [a-z0-9_], 1 to 48 bytes"));
        }
        let ttl = self.ttl.map(render_ttl).transpose()?;
        if let Some(sid) = &self.sid {
            if !is_value(sid) {
                return Err(bad("sid", "must be [a-z0-9_], at least 1 byte"));
            }
            if self.rotation == Some(Rotation::Each) {
                return Err(SelectorError::SidWithEachRotation);
            }
        }

        let mut name = String::from("px");
        let mut push = |key: &str, value: &str| {
            name.push('-');
            name.push_str(key);
            name.push('-');
            name.push_str(value);
        };
        if let Some(kind) = self.kind {
            push("kind", kind.as_str());
        }
        if let Some(country) = &self.country {
            push("cc", country);
        }
        if let Some(city) = &self.city {
            push("city", city);
        }
        if let Some(provider) = &self.provider {
            push("prov", provider);
        }
        if let Some(ttl) = &ttl {
            push("ttl", ttl);
        }
        if let Some(sid) = &self.sid {
            push("sid", sid);
        }
        if let Some(rotation) = self.rotation {
            push("rot", rotation.as_str());
        }
        if let Some(strict) = self.strict {
            push("strict", if strict { "true" } else { "false" });
        }
        if name.len() > MAX_USERNAME_LEN {
            return Err(SelectorError::TooLong(name.len()));
        }
        Ok(name)
    }

    /// Read a username back into a selector, with the gateway's parsing rules.
    pub fn parse(username: &str) -> Result<Self, SelectorError> {
        if username.len() > MAX_USERNAME_LEN {
            return Err(SelectorError::TooLong(username.len()));
        }
        let mut parts = username.split('-');
        if parts.next() != Some("px") {
            return Err(SelectorError::MissingPrefix);
        }
        let parts: Vec<&str> = parts.collect();
        if !parts.len().is_multiple_of(2) {
            return Err(SelectorError::Unpaired);
        }
        let mut out = Self::default();
        for pair in parts.chunks_exact(2) {
            let (key, value) = (pair[0], pair[1]);
            if !is_value(value) {
                return Err(SelectorError::Unpaired);
            }
            match key {
                "kind" => {
                    let kind = match value {
                        "static" => Kind::Static,
                        "rotating" => Kind::Rotating,
                        _ => return Err(bad("kind", "must be static or rotating")),
                    };
                    set(&mut out.kind, "kind", kind)?;
                }
                "cc" => set(&mut out.country, "cc", value.to_owned())?,
                "city" => set(&mut out.city, "city", value.to_owned())?,
                "prov" => set(&mut out.provider, "prov", value.to_owned())?,
                "ttl" => {
                    let ttl = parse_ttl(value)
                        .filter(|t| !t.is_zero())
                        .ok_or(bad("ttl", "not a non-zero duration"))?;
                    set(&mut out.ttl, "ttl", ttl)?;
                }
                "sid" => set(&mut out.sid, "sid", value.to_owned())?,
                "rot" => {
                    let rotation = match value {
                        "sticky" => Rotation::Sticky,
                        "each" => Rotation::Each,
                        _ => return Err(bad("rot", "must be sticky or each")),
                    };
                    set(&mut out.rotation, "rot", rotation)?;
                }
                "strict" => {
                    let strict = match value {
                        "true" => true,
                        "false" => false,
                        _ => return Err(bad("strict", "must be true or false")),
                    };
                    set(&mut out.strict, "strict", strict)?;
                }
                other => return Err(SelectorError::UnknownKey(other.to_owned())),
            }
        }
        // The same checks as rendering: catches `city` without `cc`, a bad `cc` or length,
        // and `sid` with `rot-each`.
        out.username()?;
        Ok(out)
    }

    /// Proxy kind, if set.
    pub fn get_kind(&self) -> Option<Kind> {
        self.kind
    }

    /// Country, if set.
    pub fn get_country(&self) -> Option<&str> {
        self.country.as_deref()
    }

    /// City, if set.
    pub fn get_city(&self) -> Option<&str> {
        self.city.as_deref()
    }

    /// Provider, if set.
    pub fn get_provider(&self) -> Option<&str> {
        self.provider.as_deref()
    }

    /// Lease idle time, if set.
    pub fn get_ttl(&self) -> Option<Duration> {
        self.ttl
    }

    /// Sticky key, if set.
    pub fn get_sid(&self) -> Option<&str> {
        self.sid.as_deref()
    }

    /// Rotation mode, if set.
    pub fn get_rotation(&self) -> Option<Rotation> {
        self.rotation
    }

    /// Strict sticky session request, if set.
    pub fn get_strict(&self) -> Option<bool> {
        self.strict
    }
}

impl FromStr for PoolSelector {
    type Err = SelectorError;

    fn from_str(s: &str) -> Result<Self, SelectorError> {
        Self::parse(s)
    }
}

// --- causes ---------------------------------------------------------------------------------

/// Why the gateway refused or failed a tunnel. It is the reason phrase of the refusal status
/// line (`HTTP/1.1 503 cache_empty`). The gateway never falls back to a direct dial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Cause {
    /// Missing or unknown org key.
    AuthRequired,
    /// The org key exists but an operator disabled it.
    OrgDisabled,
    /// A username option widens the policy or is malformed.
    OptionDenied,
    /// An operator block stops this org in the requested scope.
    OrgBlocked,
    /// The provider does not allow the target port.
    PortNotAllowed,
    /// The target is a private, loopback, link-local, metadata or cluster address.
    DestinationDenied,
    /// The org reached its tunnel cap.
    OrgCapacity,
    /// The org used its daily traffic budget.
    OrgBudget,
    /// No session or IP could be leased and the policy says create or fail.
    CacheEmpty,
    /// A static partition has no healthy IP.
    NoHealthyIp,
    /// The gateway's cache is unreachable; new leases are refused.
    CacheUnavailable,
    /// The policy waits for a lease and the wait ran out.
    LeaseTimeout,
    /// The provider refused the connection or is in an open breaker.
    ProviderUnavailable,
    /// The provider rejected the rendered credential.
    ProviderAuth,
    /// The provider did not answer in time.
    ProviderTimeout,
    /// The provider answered the CONNECT with an unexpected status.
    UpstreamError,
}

impl Cause {
    /// Every cause.
    pub const ALL: [Cause; 16] = [
        Cause::AuthRequired,
        Cause::OrgDisabled,
        Cause::OptionDenied,
        Cause::OrgBlocked,
        Cause::PortNotAllowed,
        Cause::DestinationDenied,
        Cause::OrgCapacity,
        Cause::OrgBudget,
        Cause::CacheEmpty,
        Cause::NoHealthyIp,
        Cause::CacheUnavailable,
        Cause::LeaseTimeout,
        Cause::ProviderUnavailable,
        Cause::ProviderAuth,
        Cause::ProviderTimeout,
        Cause::UpstreamError,
    ];

    /// HTTP status the gateway answers with.
    pub const fn status(self) -> u16 {
        match self {
            Cause::AuthRequired => 407,
            Cause::OptionDenied
            | Cause::OrgDisabled
            | Cause::OrgBlocked
            | Cause::PortNotAllowed
            | Cause::DestinationDenied => 403,
            Cause::OrgCapacity
            | Cause::OrgBudget
            | Cause::CacheEmpty
            | Cause::NoHealthyIp
            | Cause::CacheUnavailable => 503,
            Cause::LeaseTimeout | Cause::ProviderTimeout => 504,
            Cause::ProviderUnavailable | Cause::ProviderAuth | Cause::UpstreamError => 502,
        }
    }

    /// The reason phrase.
    pub const fn code(self) -> &'static str {
        match self {
            Cause::AuthRequired => "auth_required",
            Cause::OptionDenied => "option_denied",
            Cause::OrgDisabled => "org_disabled",
            Cause::OrgBlocked => "org_blocked",
            Cause::PortNotAllowed => "port_not_allowed",
            Cause::OrgBudget => "org_budget",
            Cause::DestinationDenied => "destination_denied",
            Cause::OrgCapacity => "org_capacity",
            Cause::CacheEmpty => "cache_empty",
            Cause::NoHealthyIp => "no_healthy_ip",
            Cause::CacheUnavailable => "cache_unavailable",
            Cause::LeaseTimeout => "lease_timeout",
            Cause::ProviderUnavailable => "provider_unavailable",
            Cause::ProviderAuth => "provider_auth",
            Cause::ProviderTimeout => "provider_timeout",
            Cause::UpstreamError => "upstream_error",
        }
    }

    /// The cause with this [`Cause::code`], if there is one.
    pub fn from_code(code: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|cause| cause.code() == code)
    }

    /// True when the same request can succeed later without any change on the caller's side.
    ///
    /// Retry (with backoff) on a full org, an empty or unhealthy pool, an unreachable cache,
    /// a lease wait that ran out, and on provider failures and timeouts. Do not retry what
    /// the caller or an operator must fix first: authentication, a disabled org, a denied
    /// option, an operator block, a blocked port or destination, an exhausted daily budget
    /// (it resets with the day, not with a retry) and a rejected provider credential.
    pub const fn is_retryable(self) -> bool {
        matches!(
            self,
            Cause::OrgCapacity
                | Cause::CacheEmpty
                | Cause::NoHealthyIp
                | Cause::CacheUnavailable
                | Cause::LeaseTimeout
                | Cause::ProviderUnavailable
                | Cause::ProviderTimeout
                | Cause::UpstreamError
        )
    }
}

impl std::fmt::Display for Cause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.status(), self.code())
    }
}

impl std::error::Error for Cause {}

// --- CONNECT answer -------------------------------------------------------------------------

/// What the gateway says about an open tunnel (the headers of its `200`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectInfo {
    /// `X-ProxyX-Pool-Session`: the gateway's id for the tunnel. Name it in a block signal.
    pub session: String,
    /// `X-ProxyX-Exit-IP`: the IP the target sees.
    pub exit_ip: IpAddr,
}

/// A CONNECT that did not open a tunnel.
#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    /// The gateway answered with a refusal.
    #[error("gateway refused the tunnel: {status} {reason}")]
    Refused {
        /// HTTP status of the refusal.
        status: u16,
        /// Reason phrase, as sent.
        reason: String,
        /// The cause, when the reason phrase is a known code.
        cause: Option<Cause>,
    },
    /// The answer is not a gateway `200` or refusal.
    #[error("malformed CONNECT answer: {0}")]
    Malformed(&'static str),
    /// A target the client will not put in a request line.
    #[error("invalid CONNECT target: {0}")]
    InvalidTarget(&'static str),
    /// The connect or the handshake ran out of time.
    #[error("CONNECT handshake timed out")]
    Timeout,
    /// The socket failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl ConnectError {
    /// The refusal cause, if the gateway named one.
    pub fn cause(&self) -> Option<Cause> {
        match self {
            Self::Refused { cause, .. } => *cause,
            _ => None,
        }
    }

    /// True when repeating the CONNECT can succeed. A named cause decides with
    /// [`Cause::is_retryable`]; an unnamed 502, 503 or 504, a timeout or a socket error is
    /// retryable; anything else is not.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Refused {
                cause: Some(cause), ..
            } => cause.is_retryable(),
            Self::Refused { status, .. } => matches!(status, 502..=504),
            Self::Timeout | Self::Io(_) => true,
            Self::Malformed(_) | Self::InvalidTarget(_) => false,
        }
    }
}

impl ConnectInfo {
    /// Parse a complete CONNECT answer head (status line, headers, blank line).
    ///
    /// `200` returns the tunnel headers; both must be present and valid, since a `200` that
    /// lacks them did not come from the pool gateway. Any other status is
    /// [`ConnectError::Refused`], with the reason phrase read as a [`Cause`] code.
    pub fn parse(head: &[u8]) -> Result<Self, ConnectError> {
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut response = httparse::Response::new(&mut headers);
        match response.parse(head) {
            Ok(httparse::Status::Complete(_)) => {}
            Ok(httparse::Status::Partial) => {
                return Err(ConnectError::Malformed("incomplete head"));
            }
            Err(_) => return Err(ConnectError::Malformed("not an HTTP response")),
        }
        let status = response
            .code
            .ok_or(ConnectError::Malformed("no status code"))?;
        if status != 200 {
            let reason = response.reason.unwrap_or_default().trim().to_owned();
            let cause = Cause::from_code(&reason);
            return Err(ConnectError::Refused {
                status,
                reason,
                cause,
            });
        }
        let header = |name: &str| {
            response
                .headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case(name))
                .and_then(|h| std::str::from_utf8(h.value).ok())
                .map(str::trim)
        };
        let session = header(SESSION_HEADER)
            .filter(|s| !s.is_empty())
            .ok_or(ConnectError::Malformed("200 without X-ProxyX-Pool-Session"))?;
        let exit_ip = header(EXIT_IP_HEADER)
            .ok_or(ConnectError::Malformed("200 without X-ProxyX-Exit-IP"))?
            .parse::<IpAddr>()
            .map_err(|_| ConnectError::Malformed("X-ProxyX-Exit-IP is not an IP address"))?;
        Ok(Self {
            session: session.to_owned(),
            exit_ip,
        })
    }
}

// --- gateway endpoint -----------------------------------------------------------------------

/// A pool gateway: its host and ports. Builds proxy URLs and opens CONNECT tunnels.
#[derive(Debug, Clone)]
pub struct PoolGateway {
    host: String,
    connect_port: u16,
    socks5_port: u16,
}

impl PoolGateway {
    /// A gateway at `host` (an IPv6 literal in brackets) on the default ports.
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            connect_port: CONNECT_PORT,
            socks5_port: SOCKS5_PORT,
        }
    }

    /// Use another CONNECT port.
    #[must_use]
    pub fn connect_port(mut self, port: u16) -> Self {
        self.connect_port = port;
        self
    }

    /// Use another SOCKS5 port.
    #[must_use]
    pub fn socks5_port(mut self, port: u16) -> Self {
        self.socks5_port = port;
        self
    }

    fn url(
        &self,
        scheme: &str,
        port: u16,
        selector: &PoolSelector,
        org_key: &Secret,
    ) -> Result<Secret> {
        let username = selector.username()?;
        let mut url = Url::parse(&format!("{scheme}://{}:{port}", self.host))
            .map_err(|err| Error::InvalidInput(format!("gateway host: {err}")))?;
        // setters percent-encode, so an org key with reserved characters survives
        url.set_username(&username)
            .map_err(|()| Error::InvalidInput("gateway URL cannot carry credentials".into()))?;
        url.set_password(Some(org_key.expose()))
            .map_err(|()| Error::InvalidInput("gateway URL cannot carry credentials".into()))?;
        Ok(Secret::new(url.as_str().trim_end_matches('/')))
    }

    /// `http://px-...:<org key>@host:8080`, for CONNECT. Contains the org key.
    pub fn proxy_url(&self, selector: &PoolSelector, org_key: &Secret) -> Result<Secret> {
        self.url("http", self.connect_port, selector, org_key)
    }

    /// `socks5://px-...:<org key>@host:1080`. Contains the org key.
    pub fn socks5_url(&self, selector: &PoolSelector, org_key: &Secret) -> Result<Secret> {
        self.url("socks5", self.socks5_port, selector, org_key)
    }

    /// A `reqwest` proxy for `https` targets, which `reqwest` reaches with CONNECT.
    ///
    /// Plain `http` targets are not covered: `reqwest` would forward them as absolute-URI
    /// requests, and the gateway only accepts CONNECT.
    pub fn reqwest_proxy(
        &self,
        selector: &PoolSelector,
        org_key: &Secret,
    ) -> Result<reqwest::Proxy> {
        let username = selector.username()?;
        let proxy = reqwest::Proxy::https(format!("http://{}:{}", self.host, self.connect_port))?
            .basic_auth(&username, org_key.expose());
        Ok(proxy)
    }

    /// Open a tunnel to `target_host:target_port` and return the socket with the gateway's
    /// tunnel headers. `timeout` covers the TCP connect and the handshake together.
    ///
    /// The returned stream is positioned right after the gateway's blank line: nothing the
    /// target sent early is lost. Take [`ConnectInfo::session`] and [`ConnectInfo::exit_ip`]
    /// for block signals and logs.
    pub async fn connect_tunnel(
        &self,
        selector: &PoolSelector,
        org_key: &Secret,
        target_host: &str,
        target_port: u16,
        timeout: Duration,
    ) -> Result<(TcpStream, ConnectInfo), ConnectError> {
        let username = selector
            .username()
            .map_err(|_| ConnectError::InvalidTarget("invalid selector"))?;
        let authority = authority(target_host, target_port)?;
        let credentials = STANDARD.encode(format!("{username}:{}", org_key.expose()));
        let request = format!(
            "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Authorization: Basic {credentials}\r\n\r\n"
        );
        let address = format!("{}:{}", self.host, self.connect_port);
        tokio::time::timeout(timeout, async {
            let mut stream = TcpStream::connect(&address).await?;
            stream.set_nodelay(true)?;
            stream.write_all(request.as_bytes()).await?;
            let head = read_head(&mut stream).await?;
            let info = ConnectInfo::parse(&head)?;
            Ok((stream, info))
        })
        .await
        .map_err(|_| ConnectError::Timeout)?
    }
}

/// `host:port` for a request line; an IPv6 literal gets brackets. Refuses anything that could
/// end the request line or add a header.
fn authority(host: &str, port: u16) -> Result<String, ConnectError> {
    if host.is_empty() {
        return Err(ConnectError::InvalidTarget("empty host"));
    }
    if host
        .bytes()
        .any(|b| b <= b' ' || b == 0x7f || matches!(b, b'/' | b'@' | b'?' | b'#'))
    {
        return Err(ConnectError::InvalidTarget(
            "host has a forbidden character",
        ));
    }
    if port == 0 {
        return Err(ConnectError::InvalidTarget("port is zero"));
    }
    Ok(if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    })
}

/// Read up to and including the blank line, one byte at a time so no tunnel byte is consumed.
async fn read_head(stream: &mut TcpStream) -> Result<Vec<u8>, ConnectError> {
    let mut head = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_HEAD_LEN {
            return Err(ConnectError::Malformed("head too long"));
        }
        if stream.read(&mut byte).await? == 0 {
            return Err(ConnectError::Malformed("closed before the end of the head"));
        }
        head.push(byte[0]);
    }
    Ok(head)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_renders_in_fixed_order() {
        let name = PoolSelector::new()
            .rotation(Rotation::Sticky)
            .sid("scan42")
            .ttl(Duration::from_secs(300))
            .provider("oxy_isp")
            .city("paris")
            .country("fr")
            .kind(Kind::Rotating)
            .username()
            .expect("valid");
        assert_eq!(
            name,
            "px-kind-rotating-cc-fr-city-paris-prov-oxy_isp-ttl-5m-sid-scan42-rot-sticky"
        );
        assert_eq!(PoolSelector::new().username().expect("valid"), "px");
    }

    #[test]
    fn ttl_uses_the_largest_exact_unit() {
        let render = |s| render_ttl(Duration::from_secs(s)).expect("ttl");
        assert_eq!(render(45), "45s");
        assert_eq!(render(120), "2m");
        assert_eq!(render(7_200), "2h");
        assert_eq!(render(86_400 * 3), "3d");
        assert_eq!(render(90), "90s");
        assert!(render_ttl(Duration::ZERO).is_err());
        assert!(render_ttl(Duration::from_millis(1500)).is_err());
    }

    #[test]
    fn selector_rejects_what_the_gateway_denies() {
        let long = "a".repeat(MAX_USERNAME_LEN);
        let cases = [
            PoolSelector::new().country("FR"),
            PoolSelector::new().country("fra"),
            PoolSelector::new().country("f1"),
            PoolSelector::new().city("paris"),
            PoolSelector::new().country("fr").city("pa-ris"),
            PoolSelector::new().provider("oxy-isp"),
            PoolSelector::new().sid(""),
            PoolSelector::new().sid("a-b"),
            PoolSelector::new().sid("Scan"),
            PoolSelector::new().sid("a").rotation(Rotation::Each),
            PoolSelector::new().sid(long),
        ];
        for selector in cases {
            assert!(selector.username().is_err(), "{selector:?}");
        }
    }

    #[test]
    fn parse_round_trips_a_rendered_selector() {
        let selector = PoolSelector::new()
            .kind(Kind::Static)
            .country("de")
            .ttl(Duration::from_secs(3_600))
            .rotation(Rotation::Each);
        let name = selector.username().expect("valid");
        assert_eq!(PoolSelector::parse(&name).expect("parse"), selector);
        assert_eq!(name.parse::<PoolSelector>().expect("from_str"), selector);
    }

    #[test]
    fn cause_codes_round_trip() {
        for cause in Cause::ALL {
            assert_eq!(Cause::from_code(cause.code()), Some(cause));
        }
        assert_eq!(Cause::from_code(""), None);
        assert_eq!(Cause::from_code("Cache_Empty"), None);
        assert_eq!(Cause::CacheEmpty.to_string(), "503 cache_empty");
    }

    #[test]
    fn retryable_split() {
        let never = [
            Cause::AuthRequired,
            Cause::OrgDisabled,
            Cause::OptionDenied,
            Cause::OrgBlocked,
            Cause::PortNotAllowed,
            Cause::DestinationDenied,
            Cause::OrgBudget,
            Cause::ProviderAuth,
        ];
        for cause in Cause::ALL {
            assert_eq!(cause.is_retryable(), !never.contains(&cause), "{cause}");
        }
    }

    #[test]
    fn connect_info_reads_the_200() {
        let head = b"HTTP/1.1 200 Connection established\r\nx-proxyx-pool-session: abc123\r\nX-ProxyX-Exit-IP: 203.0.113.9\r\n\r\n";
        let info = ConnectInfo::parse(head).expect("info");
        assert_eq!(info.session, "abc123");
        assert_eq!(info.exit_ip, "203.0.113.9".parse::<IpAddr>().expect("ip"));
        let v6 =
            b"HTTP/1.1 200 OK\r\nX-ProxyX-Pool-Session: s\r\nX-ProxyX-Exit-IP: 2001:db8::1\r\n\r\n";
        assert!(ConnectInfo::parse(v6).expect("v6").exit_ip.is_ipv6());
    }

    #[test]
    fn connect_info_reads_a_refusal_cause() {
        let err = ConnectInfo::parse(b"HTTP/1.1 503 cache_empty\r\n\r\n").expect_err("refused");
        assert_eq!(err.cause(), Some(Cause::CacheEmpty));
        assert!(err.is_retryable());
        let err = ConnectInfo::parse(
            b"HTTP/1.1 407 auth_required\r\nProxy-Authenticate: Basic realm=\"proxyx\"\r\n\r\n",
        )
        .expect_err("refused");
        assert_eq!(err.cause(), Some(Cause::AuthRequired));
        assert!(!err.is_retryable());
        let err = ConnectInfo::parse(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").expect_err("refused");
        assert_eq!(err.cause(), None);
        assert!(err.is_retryable());
        let err = ConnectInfo::parse(b"HTTP/1.1 403 Forbidden\r\n\r\n").expect_err("refused");
        assert!(!err.is_retryable());
    }

    #[test]
    fn connect_info_fails_closed_on_a_200_without_tunnel_headers() {
        for head in [
            &b"HTTP/1.1 200 OK\r\n\r\n"[..],
            b"HTTP/1.1 200 OK\r\nX-ProxyX-Pool-Session: s\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nX-ProxyX-Exit-IP: 203.0.113.9\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nX-ProxyX-Pool-Session: s\r\nX-ProxyX-Exit-IP: nope\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nX-ProxyX-Pool-Session: s\r\n",
            b"garbage\r\n\r\n",
        ] {
            assert!(
                matches!(ConnectInfo::parse(head), Err(ConnectError::Malformed(_))),
                "{head:?}"
            );
        }
    }

    #[test]
    fn urls_carry_selector_and_key() {
        let gateway = PoolGateway::new("pool.example.com");
        let selector = PoolSelector::new().kind(Kind::Rotating);
        let key = Secret::new("org key/with:reserved");
        let http = gateway.proxy_url(&selector, &key).expect("http url");
        assert!(
            http.expose().starts_with(
                "http://px-kind-rotating:org%20key%2Fwith%3Areserved@pool.example.com:8080"
            ),
            "{}",
            http.expose()
        );
        let socks = gateway
            .socks5_url(&selector, &Secret::new("k"))
            .expect("socks url");
        assert_eq!(
            socks.expose(),
            "socks5://px-kind-rotating:k@pool.example.com:1080"
        );
        assert!(
            PoolGateway::new("pool.example.com")
                .proxy_url(&PoolSelector::new().sid("A"), &key)
                .is_err()
        );
    }

    #[test]
    fn authority_brackets_ipv6_and_refuses_injection() {
        assert_eq!(
            authority("example.com", 443).expect("ok"),
            "example.com:443"
        );
        assert_eq!(
            authority("2001:db8::1", 443).expect("ok"),
            "[2001:db8::1]:443"
        );
        assert_eq!(
            authority("[2001:db8::1]", 443).expect("ok"),
            "[2001:db8::1]:443"
        );
        for host in ["", "a b", "a\r\nX: y", "a/b", "u@h"] {
            assert!(authority(host, 443).is_err(), "{host:?}");
        }
        assert!(authority("example.com", 0).is_err());
    }
}
