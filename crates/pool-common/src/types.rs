//! Identifiers and closed vocabularies shared by every crate.
//!
//! Strings from the outside world are parsed into these types at the
//! boundary (config files, API bodies, the inbound username), so the rest of
//! the code never re-validates them.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Error for a value that does not parse into a domain type.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid {what}: {reason}")]
pub struct ParseError {
    what: &'static str,
    reason: String,
}

impl ParseError {
    fn new(what: &'static str, reason: impl Into<String>) -> Self {
        Self {
            what,
            reason: reason.into(),
        }
    }
}

fn is_slug(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

macro_rules! slug_newtype {
    ($(#[$m:meta])* $name:ident, $what:literal, $max:literal) => {
        $(#[$m])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = ParseError;
            fn try_from(s: String) -> Result<Self, ParseError> {
                if is_slug(&s, $max) {
                    Ok(Self(s))
                } else {
                    Err(ParseError::new($what, format!("{s:?} is not [a-z0-9_-]{{1,{}}}", $max)))
                }
            }
        }

        impl FromStr for $name {
            type Err = ParseError;
            fn from_str(s: &str) -> Result<Self, ParseError> {
                Self::try_from(s.to_owned())
            }
        }

        impl From<$name> for String {
            fn from(v: $name) -> String {
                v.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

slug_newtype!(
    /// An ProxyX organisation id as ProxyX sees it (from the org key).
    OrgId,
    "org id",
    64
);
slug_newtype!(
    /// A configured provider adapter id, for example `oxylabs_isp`.
    ProviderId,
    "provider id",
    48
);

/// Proxy kind. Drives the cache, the warmer and the lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// Rented, known IPs or modems; nothing is created.
    Static,
    /// Quota-based sessions that the warmer creates.
    Rotating,
}

impl Kind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Kind::Static => "static",
            Kind::Rotating => "rotating",
        }
    }
}

impl FromStr for Kind {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, ParseError> {
        match s {
            "static" => Ok(Kind::Static),
            "rotating" => Ok(Kind::Rotating),
            _ => Err(ParseError::new("kind", s)),
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Provider product family. Each subtype belongs to exactly one kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Subtype {
    Datacenter,
    Isp,
    /// SIM box or modem farm: fixed endpoint, changing exit IP, `rotate_ip`.
    MobileBox,
    Residential,
    Mobile,
    IspRotating,
}

impl Subtype {
    pub const fn kind(self) -> Kind {
        match self {
            Subtype::Datacenter | Subtype::Isp | Subtype::MobileBox => Kind::Static,
            Subtype::Residential | Subtype::Mobile | Subtype::IspRotating => Kind::Rotating,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Subtype::Datacenter => "datacenter",
            Subtype::Isp => "isp",
            Subtype::MobileBox => "mobile_box",
            Subtype::Residential => "residential",
            Subtype::Mobile => "mobile",
            Subtype::IspRotating => "isp_rotating",
        }
    }
}

/// A region: ISO 3166-1 alpha-2 country, lowercase, with an optional city
/// slug. Text form `fr` or `fr/paris`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Region {
    country: String,
    city: Option<String>,
}

impl Region {
    /// A region is two ASCII letters of country and an optional city slug of
    /// `[a-z0-9_]`; both are lowercased, anything else is refused.
    pub fn new(country: &str, city: Option<&str>) -> Result<Self, ParseError> {
        let country = country.to_ascii_lowercase();
        if country.len() != 2 || !country.bytes().all(|b| b.is_ascii_lowercase()) {
            return Err(ParseError::new("region", format!("country {country:?}")));
        }
        let city = match city {
            Some(c) => {
                let c = c.to_ascii_lowercase();
                if c.is_empty()
                    || c.len() > 48
                    || !c
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                {
                    return Err(ParseError::new("region", format!("city {c:?}")));
                }
                Some(c)
            }
            None => None,
        };
        Ok(Self { country, city })
    }

    pub fn country(&self) -> &str {
        &self.country
    }

    pub fn city(&self) -> Option<&str> {
        self.city.as_deref()
    }

    /// True when `self` satisfies a request for `wanted` (same country, and the
    /// same city when `wanted` names one).
    pub fn satisfies(&self, wanted: &Region) -> bool {
        self.country == wanted.country && (wanted.city.is_none() || self.city == wanted.city)
    }
}

impl TryFrom<String> for Region {
    type Error = ParseError;
    fn try_from(s: String) -> Result<Self, ParseError> {
        s.parse()
    }
}

impl FromStr for Region {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, ParseError> {
        match s.split_once('/') {
            Some((c, city)) => Region::new(c, Some(city)),
            None => Region::new(s, None),
        }
    }
}

impl From<Region> for String {
    fn from(r: Region) -> String {
        r.to_string()
    }
}

impl fmt::Display for Region {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.city {
            Some(c) => write!(f, "{}/{}", self.country, c),
            None => f.write_str(&self.country),
        }
    }
}

/// A route class: one provider plus one region. The unit of warming,
/// locking, breakers and Redis partitions.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Partition {
    pub provider: ProviderId,
    pub region: Region,
}

impl Partition {
    /// Redis hash tag body, so every key of one partition lands in one slot.
    pub fn tag(&self) -> String {
        format!("{}:{}", self.provider, self.region)
    }
}

impl fmt::Display for Partition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.provider, self.region)
    }
}

/// What the lease key is bound to when the caller sends no `sid`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StickyScope {
    /// One session or IP for all traffic of the org.
    #[default]
    Org,
    /// One per target host.
    Target,
    /// A new one per tunnel.
    Connection,
}

/// Whether a lease keeps its unit (`sticky`) or takes a new one per tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rotation {
    #[default]
    Sticky,
    Each,
}

/// The tunnel target, as sent in CONNECT or SOCKS5.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Target {
    pub host: String,
    pub port: u16,
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// States of a static IP or SIM box.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpState {
    Candidate,
    Available,
    Leased,
    /// Leasable but slow: clean answers over the TTFB or load limit. Blocks
    /// and errors cool the IP instead. The gateway prefers normal units.
    Degraded,
    Cooldown,
    Quarantined,
    Rotating,
    Offline,
    ReplaceRequested,
    Retired,
}

impl IpState {
    pub const ALL: [IpState; 10] = [
        IpState::Candidate,
        IpState::Available,
        IpState::Leased,
        IpState::Degraded,
        IpState::Cooldown,
        IpState::Quarantined,
        IpState::Rotating,
        IpState::Offline,
        IpState::ReplaceRequested,
        IpState::Retired,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            IpState::Candidate => "candidate",
            IpState::Available => "available",
            IpState::Leased => "leased",
            IpState::Degraded => "degraded",
            IpState::Cooldown => "cooldown",
            IpState::Quarantined => "quarantined",
            IpState::Rotating => "rotating",
            IpState::Offline => "offline",
            IpState::ReplaceRequested => "replace_requested",
            IpState::Retired => "retired",
        }
    }

    /// True when the gateway may lease an IP in this state.
    pub const fn is_leasable(self) -> bool {
        matches!(
            self,
            IpState::Available | IpState::Leased | IpState::Degraded
        )
    }

    /// The tier a leasable unit in this state is leased from.
    pub const fn tier(self) -> Tier {
        match self {
            IpState::Degraded => Tier::Degraded,
            _ => Tier::Normal,
        }
    }
}

/// Which of the two leasable tiers a unit is in. Both live in the same ready
/// set; the unit record carries the tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Tier {
    #[default]
    Normal,
    Degraded,
}

impl Tier {
    pub const fn as_str(self) -> &'static str {
        match self {
            Tier::Normal => "normal",
            Tier::Degraded => "degraded",
        }
    }
}

impl FromStr for IpState {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, ParseError> {
        IpState::ALL
            .into_iter()
            .find(|v| v.as_str() == s)
            .ok_or_else(|| ParseError::new("ip state", s))
    }
}

/// Where a block signal came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalSource {
    Probe,
    Canary,
    Operator,
    Client,
}

impl SignalSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            SignalSource::Probe => "probe",
            SignalSource::Canary => "canary",
            SignalSource::Operator => "operator",
            SignalSource::Client => "client",
        }
    }
}

/// Wire protocol to an upstream proxy, or `Local` for no proxy at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamScheme {
    Http,
    Socks5,
    /// HTTP proxy reached over TLS (an `https://` proxy endpoint): TLS to the
    /// proxy, then `CONNECT` inside it. The proxy's certificate is verified.
    Https,
    /// No upstream proxy: the machine's own address is the exit. The
    /// endpoint's `host` is a local IP literal; the dial binds that address
    /// as the source and connects straight to the target.
    Local,
}

/// A rendered upstream: where to dial and with which credential. Produced
/// by a provider adapter; consumed by `dial` and `verify`. Never logged:
/// `Debug` hides the credential through [`Secret`](crate::Secret).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamEndpoint {
    pub provider: ProviderId,
    pub scheme: UpstreamScheme,
    pub host: String,
    pub port: u16,
    pub username: crate::Secret,
    pub password: crate::Secret,
    /// The customer chose this upstream: whoever connects to `host` must
    /// resolve it once, refuse every non-public address and connect to the
    /// checked address only (`dial`, `verify`). Set by the adapter's
    /// `public_only`.
    pub public_only: bool,
}

/// One static IP or SIM box in the inventory. Keyed by `ip`; the
/// port may change. Credentials are a file name in the secrets directory,
/// never the value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryEntry {
    pub provider: ProviderId,
    pub subtype: Subtype,
    /// Provider plan or product name, for the replacement report.
    #[serde(default)]
    pub plan: String,
    /// Expected exit IP. For a `mobile_box` this is the last seen IP.
    pub ip: std::net::IpAddr,
    /// Upstream host (gateway or the IP itself) and port.
    pub host: String,
    pub port: u16,
    pub region: Region,
    #[serde(default)]
    pub asn: Option<u32>,
    /// File in the secrets directory holding `username:password`.
    #[serde(default)]
    pub credentials: Option<String>,
    /// Opaque handle for `rotate_ip` (SIM box id or modem index).
    #[serde(default)]
    pub box_handle: Option<String>,
    /// Last day of the rental, `YYYY-MM-DD`.
    #[serde(default)]
    pub rental_end: Option<String>,
}

/// What kind of block a signal reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalType {
    /// HTTP 429.
    RateLimited,
    /// 403 or 503 with a challenge or captcha marker, or a `/sorry/` redirect.
    Challenge,
    /// Repeated plain 403 on one target.
    Forbidden,
    /// Reset or TLS failure after a successful tunnel.
    Reset,
}

impl SignalType {
    pub const fn as_str(self) -> &'static str {
        match self {
            SignalType::RateLimited => "rate_limited",
            SignalType::Challenge => "challenge",
            SignalType::Forbidden => "forbidden",
            SignalType::Reset => "reset",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn region_parses_and_matches() {
        let paris: Region = "FR/paris".parse().expect("region");
        let fr: Region = "fr".parse().expect("region");
        assert_eq!(paris.to_string(), "fr/paris");
        assert!(paris.satisfies(&fr));
        assert!(!fr.satisfies(&paris));
        assert!("fra".parse::<Region>().is_err());
        assert!("fr/pa-ris".parse::<Region>().is_err());
    }

    #[test]
    fn slugs_reject_separators_and_case() {
        assert!("org_42".parse::<OrgId>().is_ok());
        assert!("Org".parse::<OrgId>().is_err());
        assert!("a b".parse::<ProviderId>().is_err());
        assert!("".parse::<ProviderId>().is_err());
    }

    #[test]
    fn subtype_kind_is_fixed() {
        assert_eq!(Subtype::MobileBox.kind(), Kind::Static);
        assert_eq!(Subtype::IspRotating.kind(), Kind::Rotating);
    }
}
