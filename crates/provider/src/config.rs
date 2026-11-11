//! The adapter file format: one TOML file holds `[[adapter]]` tables. The
//! structs only describe the text; [`AdapterSet`](crate::AdapterSet) parses
//! them into checked, ready-to-render adapters.

use std::time::Duration;

use common::config::humantime_secs;
use common::types::{Kind, ProviderId, Subtype, UpstreamScheme};
use serde::Deserialize;

/// A file of adapters.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterFile {
    #[serde(default)]
    pub adapter: Vec<AdapterConfig>,
}

/// One provider adapter, as written in TOML.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterConfig {
    pub id: ProviderId,
    /// Must agree with `subtype`; written out so a file reads on its own.
    pub kind: Kind,
    pub subtype: Subtype,
    #[serde(default = "default_scheme")]
    pub scheme: UpstreamScheme,
    /// Gateway host, with `{opts}` where an option with `to = "host"` goes.
    /// Required for rotating adapters. A static adapter that leaves it out
    /// dials the host of each inventory entry.
    pub host: Option<String>,
    /// Gateway port. Required for rotating adapters (unless an option sets
    /// it). A static adapter that leaves it out dials the port of each
    /// inventory entry (port-per-IP gateways).
    pub port: Option<u16>,
    /// Secret file with the base username.
    pub user_file: Option<String>,
    /// Secret file with the base password.
    pub pass_file: Option<String>,
    /// A missing base username or password renders as empty instead of
    /// failing (an upstream that needs no login).
    #[serde(default)]
    pub credentials_optional: bool,
    /// Username template. Placeholders: `{base_user}`, `{base_pass}`, `{opts}`.
    #[serde(default = "default_user")]
    pub user: String,
    /// Password template. Same placeholders as `user`.
    #[serde(default = "default_pass")]
    pub pass: String,
    /// Options in the order they are written into the credential.
    #[serde(default)]
    pub option: Vec<OptionConfig>,
    /// Target ports the provider allows. Empty means any port.
    #[serde(default)]
    pub allowed_ports: Vec<u16>,
    pub max_conns_per_ip: Option<u32>,
    pub max_session_minutes: Option<u32>,
    /// Whether the provider pins an exit or rotates it on every request.
    #[serde(default)]
    pub session_mode: SessionMode,
    /// Provider echo endpoint that returns the exit IP.
    pub echo_url: Option<String>,
    /// The upstream address of every entry must be public routable
    /// (`customer`).
    #[serde(default)]
    pub public_only: bool,
    /// How to reset a SIM box. Required for `mobile_box`, refused otherwise.
    pub rotate: Option<RotateConfig>,
}

fn default_scheme() -> UpstreamScheme {
    UpstreamScheme::Http
}

fn default_user() -> String {
    "{base_user}{opts}".to_owned()
}

fn default_pass() -> String {
    "{base_pass}{opts}".to_owned()
}

/// Provider exit selection behavior, independent of the local lease lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionMode {
    #[default]
    Sticky,
    PerRequest,
}

/// What an option carries. A closed list: each key has one source in the
/// lease spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OptionKey {
    /// Country of the region.
    Country,
    /// City of the region; left out when the region has none.
    City,
    /// Session id (rotating).
    Sid,
    /// Session duration (rotating), from the requested `Duration`.
    Ttl,
    /// Strict mode flag (rotating): written only when the lease is strict.
    Strict,
    /// Exact IP to pin (static).
    Ip,
}

impl OptionKey {
    pub const fn name(self) -> &'static str {
        match self {
            OptionKey::Country => "country",
            OptionKey::City => "city",
            OptionKey::Sid => "sid",
            OptionKey::Ttl => "ttl",
            OptionKey::Strict => "strict",
            OptionKey::Ip => "ip",
        }
    }
}

/// The credential field an option is written into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    User,
    Pass,
    Host,
    Port,
}

/// Characters a value may hold. Each set is a subset of what every provider
/// accepts, so a value that passes needs no escaping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Charset {
    Digits,
    Alpha,
    Alnum,
    /// Letters, digits and `_`.
    Word,
    /// ASCII letters and `_`, as required by some providers' city targeting.
    AlphaUnderscore,
    /// Hex digits, `.` and `:` (an IP literal).
    Ip,
}

impl Charset {
    pub(crate) fn allows(self, c: char) -> bool {
        match self {
            Charset::Digits => c.is_ascii_digit(),
            Charset::Alpha => c.is_ascii_alphabetic(),
            Charset::Alnum => c.is_ascii_alphanumeric(),
            Charset::Word => c.is_ascii_alphanumeric() || c == '_',
            Charset::AlphaUnderscore => c.is_ascii_alphabetic() || c == '_',
            Charset::Ip => c.is_ascii_hexdigit() || c == '.' || c == ':',
        }
    }

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Charset::Digits => "digits",
            Charset::Alpha => "alpha",
            Charset::Alnum => "alnum",
            Charset::Word => "word",
            Charset::AlphaUnderscore => "alpha_underscore",
            Charset::Ip => "ip",
        }
    }
}

/// Letter case a provider wants for a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Case {
    #[default]
    Keep,
    Upper,
    Lower,
}

/// Unit of a `ttl` option. Durations round up to a whole provider unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Unit {
    #[default]
    Min,
    Sec,
}

/// One option fragment: where it goes and which values it accepts.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OptionConfig {
    pub name: OptionKey,
    pub to: Field,
    /// Text written for the option. `{v}` marks the value; `strict` has no
    /// value and no `{v}`.
    pub frag: String,
    /// `sid` only: written instead of `frag` when the lease is strict
    /// (the `sessid_oneip` and `session_iplock` forms).
    pub strict_frag: Option<String>,
    /// Default per option: country `alpha`, city `word`, sid `alnum`, ip `ip`.
    pub charset: Option<Charset>,
    /// Exact length in characters. Country defaults to 2.
    pub len: Option<usize>,
    /// Longest value in characters. Default 64.
    pub max_len: Option<usize>,
    /// `ttl` only: largest value, in `unit`.
    pub max: Option<u32>,
    /// `ttl` only; default `min`.
    pub unit: Option<Unit>,
    /// `country` and `city` only; default `keep`.
    pub case: Option<Case>,
}

/// HTTP method of the SIM box reset call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
}

/// The SIM box reset call (`rotate_ip`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotateConfig {
    pub method: HttpMethod,
    /// `http` or `https` URL. `{handle}` may appear after the host only.
    pub url: String,
    /// JSON body sent with the call; `{handle}` is replaced.
    pub body: Option<String>,
    /// Secret file with a bearer token.
    pub bearer_file: Option<String>,
    #[serde(default = "default_rotate_timeout", with = "humantime_secs")]
    pub timeout: Duration,
}

fn default_rotate_timeout() -> Duration {
    Duration::from_secs(20)
}
