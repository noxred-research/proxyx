//! One provider adapter: credential templates, option checks, the pure
//! `recipe` and the port allow-list.

use std::borrow::Cow;
use std::net::IpAddr;
use std::time::Duration;

use common::session::DEFAULT_SESSION_MINUTES;
use common::types::{
    InventoryEntry, Kind, ProviderId, Region, Subtype, UpstreamEndpoint, UpstreamScheme,
};
use common::{Secret, types::Target};

use crate::MAX_FIELD_BYTES;
use crate::config::{
    AdapterConfig, Case, Charset, Field, OptionConfig, OptionKey, SessionMode, Unit,
};
use crate::error::ProviderError;
use crate::rotate::RotateCall;

/// Longest option value when a file gives neither `len` nor `max_len`.
const DEFAULT_MAX_LEN: usize = 64;

/// What a lease asks the adapter to render.
#[derive(Debug, Clone)]
pub enum UnitSpec<'a> {
    /// A rented IP or SIM box from the inventory. `credentials` is the parsed
    /// `username:password` file of the entry; it replaces the adapter's base
    /// credentials.
    Static {
        entry: &'a InventoryEntry,
        credentials: Option<(Secret, Secret)>,
    },
    /// A rotating session. Sticky adapters set the session id; per-request
    /// adapters rotate exits independently of this local tracking id.
    Rotating {
        session_id: &'a str,
        ttl: Duration,
        region: &'a Region,
        strict: bool,
    },
}

/// Persisted provider recipe parameters, borrowed from a unit identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionRecipe<'a> {
    pub session_id: &'a str,
    pub ttl: Duration,
    pub strict: bool,
}

/// A provider adapter, built from an [`AdapterConfig`].
#[derive(Debug, Clone)]
pub struct Adapter {
    id: ProviderId,
    subtype: Subtype,
    scheme: UpstreamScheme,
    host: Option<Template>,
    port: Option<u16>,
    user: Template,
    pass: Template,
    base_user: Option<Secret>,
    base_pass: Option<Secret>,
    credentials_optional: bool,
    options: Vec<OptionRule>,
    allowed_ports: Vec<u16>,
    max_conns_per_ip: Option<u32>,
    max_session_minutes: Option<u32>,
    session_mode: SessionMode,
    echo_url: Option<String>,
    public_only: bool,
    pub(crate) rotate: Option<RotateCall>,
}

impl Adapter {
    /// Wire protocol to the provider.
    pub fn scheme(&self) -> UpstreamScheme {
        self.scheme
    }

    /// Render the endpoint of a `local` unit: no credential, no port; the
    /// host is the source address the dial binds.
    fn local_endpoint(&self, spec: &UnitSpec<'_>) -> Result<UpstreamEndpoint, ProviderError> {
        let values = self.prepare(spec)?;
        let entry = values
            .entry
            .ok_or_else(|| self.mismatch("a local adapter serves inventory entries only"))?;
        if values.credentials.is_some() || entry.credentials.is_some() {
            return Err(self.mismatch("a local unit takes no credentials"));
        }
        let source = local_source(&entry.host)?;
        Ok(UpstreamEndpoint {
            provider: self.id.clone(),
            scheme: UpstreamScheme::Local,
            host: source.to_string(),
            port: 0,
            username: Secret::new(""),
            password: Secret::new(""),
            public_only: false,
        })
    }

    /// Check a parsed adapter file entry and load its secret files.
    pub(crate) fn from_config(
        cfg: AdapterConfig,
        secrets: &impl Fn(&str) -> anyhow::Result<Secret>,
    ) -> Result<Self, ProviderError> {
        let fail = |reason: String| ProviderError::Config {
            id: cfg.id.clone(),
            reason,
        };
        if cfg.kind != cfg.subtype.kind() {
            return Err(fail(format!(
                "subtype {} is {}, not {}",
                cfg.subtype.as_str(),
                cfg.subtype.kind(),
                cfg.kind
            )));
        }
        validate_local(&cfg).map_err(&fail)?;
        let user = Template::parse(&cfg.user, true).map_err(|e| fail(format!("user: {e}")))?;
        let pass = Template::parse(&cfg.pass, true).map_err(|e| fail(format!("pass: {e}")))?;
        let host = cfg
            .host
            .as_deref()
            .map(|h| Template::parse(h, false))
            .transpose()
            .map_err(|e| fail(format!("host: {e}")))?;

        let options = cfg
            .option
            .iter()
            .map(|o| OptionRule::from_config(o, cfg.kind))
            .collect::<Result<Vec<_>, _>>()
            .map_err(&fail)?;
        validate_options(&cfg, &options, &user, &pass, host.as_ref()).map_err(&fail)?;
        validate_misc(&cfg).map_err(&fail)?;

        let read = |name: Option<&str>| name.map(|n| read_secret(&cfg.id, n, secrets)).transpose();
        let base_user = read(cfg.user_file.as_deref())?;
        let base_pass = read(cfg.pass_file.as_deref())?;
        let rotate = cfg
            .rotate
            .map(|r| RotateCall::build(&cfg.id, r, secrets))
            .transpose()?;

        let adapter = Self {
            id: cfg.id,
            subtype: cfg.subtype,
            scheme: cfg.scheme,
            host,
            port: cfg.port,
            user,
            pass,
            base_user,
            base_pass,
            credentials_optional: cfg.credentials_optional,
            options,
            allowed_ports: cfg.allowed_ports,
            max_conns_per_ip: cfg.max_conns_per_ip,
            max_session_minutes: cfg.max_session_minutes,
            session_mode: cfg.session_mode,
            echo_url: cfg.echo_url,
            public_only: cfg.public_only,
            rotate,
        };
        if adapter.public_only
            && let Some(h) = adapter.host.as_ref().and_then(Template::as_literal)
        {
            ensure_public_address(h)?;
        }
        adapter.check_bases(
            adapter.base_user.as_ref().map_or("", Secret::expose),
            adapter.base_pass.as_ref().map_or("", Secret::expose),
        )?;
        Ok(adapter)
    }

    pub fn id(&self) -> &ProviderId {
        &self.id
    }

    pub fn kind(&self) -> Kind {
        self.subtype.kind()
    }

    /// True when every upstream address of this adapter must be public
    /// routable (`customer`); false for cluster-internal upstreams
    /// (`vpn-pool`).
    pub fn public_only(&self) -> bool {
        self.public_only
    }

    /// Provider cap on tunnels per IP, for the lease counters.
    pub fn max_conns_per_ip(&self) -> Option<u32> {
        self.max_conns_per_ip
    }

    /// Session life the credential carries, in minutes: the provider maximum,
    /// or [`DEFAULT_SESSION_MINUTES`] when the adapter sets none.
    pub fn session_minutes(&self) -> u32 {
        self.max_session_minutes.unwrap_or(DEFAULT_SESSION_MINUTES)
    }

    /// [`Self::session_minutes`] as a duration: the provider maximum for `max_age`.
    pub fn session_life(&self) -> Duration {
        Duration::from_secs(60 * u64::from(self.session_minutes()))
    }

    /// Provider echo endpoint that returns the exit IP.
    pub fn echo_url(&self) -> Option<&str> {
        self.echo_url.as_deref()
    }

    /// Length of the session id this adapter accepts. Per-request adapters
    /// still need a local tracking id, although it is not sent upstream.
    pub fn session_id_len(&self) -> Option<usize> {
        if !self.rotating() {
            return None;
        }
        Some(
            self.options
                .iter()
                .find(|o| o.key == OptionKey::Sid)
                .map_or(16, |o| o.len.unwrap_or(o.max_len)),
        )
    }

    /// Alphabet for generating session ids accepted by this adapter.
    pub fn session_id_alphabet(&self) -> &'static [u8] {
        if self
            .options
            .iter()
            .any(|o| o.key == OptionKey::Sid && o.charset == Charset::Digits)
        {
            b"0123456789"
        } else {
            b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        }
    }

    /// Whether separate requests can share a provider exit.
    pub fn session_mode(&self) -> SessionMode {
        self.session_mode
    }

    /// Round a positive whole-second request up to the provider's duration
    /// unit. Refuse lifetimes beyond the configured cap, never truncate them.
    pub fn normalize_session_ttl(&self, ttl: Duration) -> Result<Duration, ProviderError> {
        if ttl.is_zero() || ttl.subsec_nanos() != 0 {
            return Err(refuse(
                "ttl",
                "a positive whole-second duration is required",
            ));
        }
        let rule = self.options.iter().find(|o| o.key == OptionKey::Ttl);
        let quantum = match rule.map(|o| o.unit) {
            Some(Unit::Min) => 60,
            Some(Unit::Sec) | None => 1,
        };
        let seconds = ttl
            .as_secs()
            .div_ceil(quantum)
            .checked_mul(quantum)
            .ok_or_else(|| refuse("ttl", "out of range"))?;
        let normalized = Duration::from_secs(seconds);
        if self.max_session_minutes.is_some() && normalized > self.session_life() {
            return Err(refuse("ttl", "above the adapter's max_session_minutes"));
        }
        if let Some(rule) = rule {
            rule.ttl_number(normalized)?;
        }
        Ok(normalized)
    }

    /// Encode all recipe inputs into a stable unit identity. The separator
    /// cannot occur in a session id, so malformed identities are unambiguous.
    pub fn encode_session(
        &self,
        session_id: &str,
        ttl: Duration,
        strict: bool,
    ) -> Result<String, ProviderError> {
        self.check_session(session_id, strict)?;
        let ttl = self.normalize_session_ttl(ttl)?;
        Ok(format!(
            "{session_id}~{}~{}",
            ttl.as_secs(),
            u8::from(strict)
        ))
    }

    /// Decode a persisted identity. Legacy bare ids use the adapter's default
    /// lifetime and non-strict mode. Invalid identities never fall back.
    pub fn decode_session<'a>(
        &self,
        identity: &'a str,
    ) -> Result<SessionRecipe<'a>, ProviderError> {
        let (session_id, ttl, strict) = if let Some((sid, options)) = identity.split_once('~') {
            let (seconds, strict) = options
                .split_once('~')
                .ok_or_else(|| refuse("sid", "malformed session identity"))?;
            let seconds: u64 = seconds
                .parse()
                .map_err(|_| refuse("ttl", "malformed session identity"))?;
            let strict = match strict {
                "0" => false,
                "1" => true,
                _ => return Err(refuse("strict", "malformed session identity")),
            };
            (sid, Duration::from_secs(seconds), strict)
        } else {
            (identity, self.session_life(), false)
        };
        self.check_session(session_id, strict)?;
        let normalized = self.normalize_session_ttl(ttl)?;
        if normalized != ttl {
            return Err(refuse(
                "ttl",
                "session identity has a non-normalized duration",
            ));
        }
        Ok(SessionRecipe {
            session_id,
            ttl,
            strict,
        })
    }

    fn check_session(&self, session_id: &str, strict: bool) -> Result<(), ProviderError> {
        if !self.rotating() {
            return Err(self.mismatch("rotating spec for a static adapter"));
        }
        if strict && !self.supports_strict() {
            return Err(self.mismatch("the provider has no strict session mode"));
        }
        if let Some(rule) = self.options.iter().find(|o| o.key == OptionKey::Sid) {
            rule.check_text(session_id)?;
        } else if session_id.is_empty()
            || session_id.len() > DEFAULT_MAX_LEN
            || !session_id.bytes().all(|c| c.is_ascii_alphanumeric())
        {
            return Err(refuse("sid", "invalid local tracking id"));
        }
        Ok(())
    }

    /// True when the provider allows tunnels to `port`. An adapter with no
    /// list allows every port. A `false` answer is `Cause::PortNotAllowed`.
    pub fn port_allowed(&self, port: u16) -> bool {
        self.allowed_ports.is_empty() || self.allowed_ports.contains(&port)
    }

    /// Render the upstream endpoint for a lease. Pure: the same spec gives
    /// the same endpoint, byte for byte. Refuses (never escapes) a value
    /// outside its charset, length or maximum, a field over 255 bytes, a base
    /// credential that holds an option fragment, and a spec that does not fit
    /// the adapter.
    pub fn recipe(&self, spec: &UnitSpec<'_>) -> Result<UpstreamEndpoint, ProviderError> {
        if self.scheme == UpstreamScheme::Local {
            return self.local_endpoint(spec);
        }
        let values = self.prepare(spec)?;
        let entry = values.entry;
        let (base_user, base_pass) = self.bases(values.credentials)?;
        self.check_bases(base_user, base_pass)?;

        let mut frags = Fragments::default();
        for rule in &self.options {
            if let Some(text) = rule.render(&values)? {
                frags.push(rule.to, &text);
            }
        }
        let username = self.user.render(base_user, base_pass, &frags.user);
        let password = self.pass.render(base_user, base_pass, &frags.pass);
        let host = match (&self.host, entry) {
            (Some(t), _) => t.render("", "", &frags.host),
            (None, Some(e)) => e.host.clone(),
            (None, None) => return Err(self.mismatch("no host")),
        };
        let port = if frags.port.is_empty() {
            self.port.or(entry.map(|e| e.port))
        } else {
            Some(
                frags
                    .port
                    .parse::<u16>()
                    .map_err(|_| refuse("port", "not a port number"))?,
            )
        };
        let port = port
            .filter(|p| *p != 0)
            .ok_or_else(|| self.mismatch("no port"))?;

        // Basic auth splits on `:`, so a username holds none.
        check_field("username", &username, |c| c.is_control() || c == ':')?;
        check_field("password", &password, char::is_control)?;
        if host.is_empty() {
            return Err(ProviderError::BadChar { field: "host" });
        }
        check_field("host", &host, |c| {
            !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '[' | ']'))
        })?;
        if self.public_only {
            ensure_public_address(&host)?;
        }
        Ok(UpstreamEndpoint {
            provider: self.id.clone(),
            scheme: self.scheme,
            host,
            port,
            username: Secret::new(username),
            password: Secret::new(password),
            public_only: self.public_only,
        })
    }

    fn rotating(&self) -> bool {
        self.kind() == Kind::Rotating
    }

    fn mismatch(&self, reason: &str) -> ProviderError {
        ProviderError::SpecMismatch {
            id: self.id.clone(),
            reason: reason.to_owned(),
        }
    }

    /// Check the spec against the adapter and gather the option values.
    fn prepare<'a>(&self, spec: &'a UnitSpec<'a>) -> Result<Values<'a>, ProviderError> {
        match spec {
            UnitSpec::Static { entry, credentials } => {
                if self.rotating() {
                    return Err(self.mismatch("static spec for a rotating adapter"));
                }
                if entry.provider != self.id {
                    return Err(self.mismatch("inventory entry belongs to another provider"));
                }
                if entry.subtype != self.subtype {
                    return Err(self.mismatch("inventory entry has another subtype"));
                }
                Ok(Values {
                    country: entry.region.country(),
                    city: entry.region.city(),
                    sid: None,
                    ttl: None,
                    strict: false,
                    ip: Some(entry.ip.to_string()),
                    credentials: credentials.as_ref(),
                    entry: Some(entry),
                })
            }
            UnitSpec::Rotating {
                session_id,
                ttl,
                region,
                strict,
            } => {
                self.check_session(session_id, *strict)?;
                let ttl = self.normalize_session_ttl(*ttl)?;
                if region.city().is_some() && !self.has_option(OptionKey::City) {
                    return Err(refuse("city", "the adapter has no city option"));
                }
                Ok(Values {
                    country: region.country(),
                    city: region.city(),
                    sid: Some(session_id),
                    ttl: Some(ttl),
                    strict: *strict,
                    ip: None,
                    credentials: None,
                    entry: None,
                })
            }
        }
    }

    fn has_option(&self, key: OptionKey) -> bool {
        self.options.iter().any(|o| o.key == key)
    }

    fn supports_strict(&self) -> bool {
        self.options
            .iter()
            .any(|o| o.key == OptionKey::Strict || o.strict_frag.is_some())
    }

    /// Credentials for this lease: the entry's, else the adapter's.
    fn bases<'a>(
        &'a self,
        credentials: Option<&'a (Secret, Secret)>,
    ) -> Result<(&'a str, &'a str), ProviderError> {
        let (user, pass) = match credentials {
            Some((u, p)) => (Some(u), Some(p)),
            None => (self.base_user.as_ref(), self.base_pass.as_ref()),
        };
        let resolve = |secret: Option<&'a Secret>,
                       part: &Part,
                       field: &'static str|
         -> Result<&'a str, ProviderError> {
            match secret {
                Some(s) => Ok(s.expose()),
                None if self.credentials_optional
                    || !(self.user.uses(part) || self.pass.uses(part)) =>
                {
                    Ok("")
                }
                None => Err(ProviderError::MissingCredential {
                    id: self.id.clone(),
                    field,
                }),
            }
        };
        Ok((
            resolve(user, &Part::BaseUser, "username")?,
            resolve(pass, &Part::BasePass, "password")?,
        ))
    }

    /// Refuse a base credential that holds the text an option fragment
    /// starts with: the rendered option could not be told from the base.
    fn check_bases(&self, base_user: &str, base_pass: &str) -> Result<(), ProviderError> {
        for (field, tpl) in [(Field::User, &self.user), (Field::Pass, &self.pass)] {
            for (part, base, name) in [
                (Part::BaseUser, base_user, "base username"),
                (Part::BasePass, base_pass, "base password"),
            ] {
                if !tpl.uses(&part) {
                    continue;
                }
                if let Some(sep) = self.separators(field).find(|s| base.contains(s)) {
                    return Err(ProviderError::SeparatorInBase {
                        base: name,
                        separator: sep.to_owned(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Leading literal text of every fragment written into `field`.
    fn separators(&self, field: Field) -> impl Iterator<Item = &str> {
        self.options
            .iter()
            .filter(move |o| o.to == field)
            .flat_map(|o| [Some(o.frag.as_str()), o.strict_frag.as_deref()])
            .flatten()
            .map(|f| f.find("{v}").map_or(f, |i| &f[..i]))
            .filter(|p| !p.is_empty())
    }
}

/// Refuse a customer address that is not public routable (private, loopback,
/// link-local, CGNAT, metadata and cluster addresses and names). Used at load,
/// at recipe time, and by the API when an entry is written.
pub fn ensure_public_address(host: &str) -> Result<(), ProviderError> {
    let target = Target {
        host: host.to_owned(),
        port: 0,
    };
    if dial::is_denied_destination(&target) {
        Err(ProviderError::NotPublic)
    } else {
        Ok(())
    }
}

/// Read one secret file for an adapter, naming the file (never its content)
/// in the error.
pub(crate) fn read_secret(
    id: &ProviderId,
    name: &str,
    secrets: &impl Fn(&str) -> anyhow::Result<Secret>,
) -> Result<Secret, ProviderError> {
    secrets(name).map_err(|error| ProviderError::Secret {
        id: id.clone(),
        name: name.to_owned(),
        error,
    })
}

fn refuse(option: &'static str, reason: &str) -> ProviderError {
    ProviderError::OptionRefused {
        option,
        reason: reason.to_owned(),
    }
}

/// Fields cap at 255 bytes. `bad` marks a character the field cannot hold.
fn check_field(
    field: &'static str,
    value: &str,
    bad: impl Fn(char) -> bool,
) -> Result<(), ProviderError> {
    if value.len() > MAX_FIELD_BYTES {
        return Err(ProviderError::FieldTooLong {
            field,
            len: value.len(),
        });
    }
    if value.chars().any(bad) {
        return Err(ProviderError::BadChar { field });
    }
    Ok(())
}

/// Values a lease offers to options.
struct Values<'a> {
    country: &'a str,
    city: Option<&'a str>,
    sid: Option<&'a str>,
    ttl: Option<Duration>,
    strict: bool,
    ip: Option<String>,
    credentials: Option<&'a (Secret, Secret)>,
    entry: Option<&'a InventoryEntry>,
}

#[derive(Default)]
struct Fragments {
    user: String,
    pass: String,
    host: String,
    port: String,
}

impl Fragments {
    fn push(&mut self, field: Field, text: &str) {
        match field {
            Field::User => self.user.push_str(text),
            Field::Pass => self.pass.push_str(text),
            Field::Host => self.host.push_str(text),
            Field::Port => self.port.push_str(text),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Part {
    Lit(String),
    BaseUser,
    BasePass,
    Opts,
}

/// A field template: literal text plus `{base_user}`, `{base_pass}` and
/// `{opts}`.
#[derive(Debug, Clone)]
struct Template(Vec<Part>);

impl Template {
    fn parse(s: &str, allow_base: bool) -> Result<Self, String> {
        let mut parts = Vec::new();
        let mut lit = String::new();
        let mut rest = s;
        while let Some(i) = rest.find(['{', '}']) {
            lit.push_str(&rest[..i]);
            if rest[i..].starts_with('}') {
                return Err("unmatched `}`".to_owned());
            }
            let after = &rest[i + 1..];
            let end = after.find('}').ok_or("unclosed `{`")?;
            let part = match &after[..end] {
                "opts" => Part::Opts,
                "base_user" if allow_base => Part::BaseUser,
                "base_pass" if allow_base => Part::BasePass,
                other => return Err(format!("unknown placeholder {{{other}}}")),
            };
            if !lit.is_empty() {
                parts.push(Part::Lit(std::mem::take(&mut lit)));
            }
            parts.push(part);
            rest = &after[end + 1..];
        }
        lit.push_str(rest);
        if !lit.is_empty() {
            parts.push(Part::Lit(lit));
        }
        Ok(Self(parts))
    }

    fn uses(&self, part: &Part) -> bool {
        self.0.contains(part)
    }

    /// The text when the template has no placeholder.
    fn as_literal(&self) -> Option<&str> {
        match self.0.as_slice() {
            [Part::Lit(s)] => Some(s),
            _ => None,
        }
    }

    fn render(&self, base_user: &str, base_pass: &str, opts: &str) -> String {
        let mut out = String::new();
        for part in &self.0 {
            match part {
                Part::Lit(s) => out.push_str(s),
                Part::BaseUser => out.push_str(base_user),
                Part::BasePass => out.push_str(base_pass),
                Part::Opts => out.push_str(opts),
            }
        }
        out
    }
}

/// An option after load-time checks.
#[derive(Debug, Clone)]
struct OptionRule {
    key: OptionKey,
    to: Field,
    frag: String,
    strict_frag: Option<String>,
    charset: Charset,
    len: Option<usize>,
    max_len: usize,
    max: Option<u32>,
    unit: Unit,
    case: Case,
}

impl OptionRule {
    fn from_config(c: &OptionConfig, kind: Kind) -> Result<Self, String> {
        let name = c.name.name();
        let key = c.name;
        let rotating_only = matches!(key, OptionKey::Sid | OptionKey::Ttl | OptionKey::Strict);
        match (kind, rotating_only) {
            (Kind::Static, true) => {
                return Err(format!("option {name}: a static adapter has no sessions"));
            }
            (Kind::Rotating, false) if key == OptionKey::Ip => {
                return Err("option ip: a rotating adapter has no fixed IP".to_owned());
            }
            _ => {}
        }
        check_frag(name, &c.frag, key != OptionKey::Strict, c.to)?;
        if let Some(sf) = &c.strict_frag {
            if key != OptionKey::Sid {
                return Err(format!("option {name}: strict_frag belongs to sid"));
            }
            check_frag(name, sf, true, c.to)?;
        }
        let text_key = !matches!(key, OptionKey::Ttl | OptionKey::Strict);
        if !text_key && (c.charset.is_some() || c.len.is_some() || c.max_len.is_some()) {
            return Err(format!(
                "option {name}: charset, len and max_len do not apply"
            ));
        }
        if key != OptionKey::Ttl && (c.max.is_some() || c.unit.is_some()) {
            return Err(format!("option {name}: max and unit belong to ttl"));
        }
        if !matches!(key, OptionKey::Country | OptionKey::City) && c.case.is_some() {
            return Err(format!("option {name}: case belongs to country and city"));
        }
        let default_charset = match key {
            OptionKey::Country => Charset::Alpha,
            OptionKey::City => Charset::Word,
            OptionKey::Ip => Charset::Ip,
            _ => Charset::Alnum,
        };
        let charset = c.charset.unwrap_or(default_charset);
        if key == OptionKey::Sid
            && !matches!(charset, Charset::Alnum | Charset::Word | Charset::Digits)
        {
            return Err("option sid: charset must be alnum, word or digits".to_owned());
        }
        let len = c.len.or((key == OptionKey::Country).then_some(2));
        let max_len = c.max_len.unwrap_or(DEFAULT_MAX_LEN);
        if len == Some(0) || max_len == 0 || c.max == Some(0) {
            return Err(format!(
                "option {name}: len, max_len and max must be above 0"
            ));
        }
        if len.is_some_and(|l| l > max_len) && c.max_len.is_some() {
            return Err(format!("option {name}: len is above max_len"));
        }
        Ok(Self {
            key,
            to: c.to,
            frag: c.frag.clone(),
            strict_frag: c.strict_frag.clone(),
            charset,
            len,
            max_len,
            max: c.max,
            unit: c.unit.unwrap_or_default(),
            case: c.case.unwrap_or_default(),
        })
    }

    /// The fragment for a lease, or `None` when the option does not apply.
    fn render(&self, v: &Values<'_>) -> Result<Option<String>, ProviderError> {
        let value: Cow<'_, str> = match self.key {
            OptionKey::Strict => return Ok(v.strict.then(|| self.frag.clone())),
            OptionKey::Country => v.country.into(),
            OptionKey::City => match v.city {
                Some(c) => c.into(),
                None => return Ok(None),
            },
            OptionKey::Sid => match v.sid {
                Some(s) => s.into(),
                None => return Ok(None),
            },
            OptionKey::Ip => match &v.ip {
                Some(ip) => ip.as_str().into(),
                None => return Ok(None),
            },
            OptionKey::Ttl => match v.ttl {
                Some(ttl) => self.ttl_value(ttl)?.into(),
                None => return Ok(None),
            },
        };
        let value = match self.case {
            Case::Keep => value,
            Case::Upper => value.to_ascii_uppercase().into(),
            Case::Lower => value.to_ascii_lowercase().into(),
        };
        if self.key != OptionKey::Ttl {
            self.check_text(&value)?;
        }
        let frag = match (&self.strict_frag, v.strict) {
            (Some(strict), true) => strict,
            _ => &self.frag,
        };
        Ok(Some(frag.replacen("{v}", &value, 1)))
    }

    fn check_text(&self, value: &str) -> Result<(), ProviderError> {
        let name = self.key.name();
        let n = value.chars().count();
        if n == 0 {
            return Err(refuse(name, "empty"));
        }
        if !value.chars().all(|c| self.charset.allows(c)) {
            return Err(refuse(
                name,
                &format!("characters outside {}", self.charset.name()),
            ));
        }
        match self.len {
            Some(l) if n != l => Err(refuse(name, &format!("length {n}, the adapter wants {l}"))),
            None if n > self.max_len => Err(refuse(
                name,
                &format!("length {n}, the adapter allows {}", self.max_len),
            )),
            _ => Ok(()),
        }
    }

    fn ttl_value(&self, ttl: Duration) -> Result<String, ProviderError> {
        Ok(self.ttl_number(ttl)?.to_string())
    }

    fn ttl_number(&self, ttl: Duration) -> Result<u32, ProviderError> {
        let n = match self.unit {
            Unit::Min => ttl.as_secs() / 60,
            Unit::Sec => ttl.as_secs(),
        };
        let n = u32::try_from(n)
            .ok()
            .filter(|n| *n > 0)
            .ok_or_else(|| refuse("ttl", "out of range"))?;
        if self.max.is_some_and(|m| n > m) {
            return Err(refuse("ttl", "above the option maximum"));
        }
        Ok(n)
    }
}

/// A fragment holds `{v}` exactly once (or never, for a flag) and no other
/// brace; a username fragment holds no `:`.
fn check_frag(name: &str, frag: &str, has_value: bool, to: Field) -> Result<(), String> {
    let marks = frag.matches("{v}").count();
    if marks != usize::from(has_value) {
        return Err(format!(
            "option {name}: frag must hold `{{v}}` {}",
            if has_value { "exactly once" } else { "never" }
        ));
    }
    if frag.replace("{v}", "").contains(['{', '}']) {
        return Err(format!("option {name}: frag holds a stray brace"));
    }
    if to == Field::User && frag.contains(':') {
        return Err(format!(
            "option {name}: a username fragment cannot hold `:`"
        ));
    }
    Ok(())
}

/// Cross-option and template rules.
fn validate_options(
    cfg: &AdapterConfig,
    rules: &[OptionRule],
    user: &Template,
    pass: &Template,
    host: Option<&Template>,
) -> Result<(), String> {
    for (i, r) in rules.iter().enumerate() {
        if rules[..i].iter().any(|p| p.key == r.key) {
            return Err(format!("option {} appears twice", r.key.name()));
        }
        let has_slot = match r.to {
            Field::User => user.uses(&Part::Opts),
            Field::Pass => pass.uses(&Part::Opts),
            Field::Host => host.is_some_and(|h| h.uses(&Part::Opts)),
            Field::Port => true,
        };
        if !has_slot {
            return Err(format!(
                "option {} writes to a field whose template has no {{opts}}",
                r.key.name()
            ));
        }
    }
    if rules.iter().filter(|r| r.to == Field::Port).count() > 1 {
        return Err("at most one option may set the port".to_owned());
    }
    if cfg.kind == Kind::Rotating {
        let required: &[OptionKey] = if cfg.session_mode == SessionMode::PerRequest {
            &[OptionKey::Country]
        } else {
            &[OptionKey::Country, OptionKey::Sid]
        };
        if cfg.session_mode == SessionMode::PerRequest
            && rules
                .iter()
                .any(|r| matches!(r.key, OptionKey::Sid | OptionKey::Ttl | OptionKey::Strict))
        {
            return Err("per_request adapters cannot set session options".to_owned());
        }
        for &key in required {
            if !rules.iter().any(|r| r.key == key) {
                return Err(format!("a rotating adapter needs a {} option", key.name()));
            }
        }
        if host.is_none() {
            return Err("a rotating adapter needs `host`".to_owned());
        }
        if cfg.port.is_none() && !rules.iter().any(|r| r.to == Field::Port) {
            return Err("a rotating adapter needs `port`".to_owned());
        }
        for (file, part, name) in [
            (&cfg.user_file, Part::BaseUser, "user"),
            (&cfg.pass_file, Part::BasePass, "pass"),
        ] {
            if file.is_none() && !cfg.credentials_optional && (user.uses(&part) || pass.uses(&part))
            {
                return Err(format!(
                    "the template uses {{base_{name}}} but `{name}_file` is not set"
                ));
            }
        }
    }
    Ok(())
}

fn validate_misc(cfg: &AdapterConfig) -> Result<(), String> {
    if cfg.kind == Kind::Static && cfg.session_mode != SessionMode::Sticky {
        return Err("session_mode belongs to rotating adapters".to_owned());
    }
    if cfg.port == Some(0) || cfg.allowed_ports.contains(&0) {
        return Err("port 0 is not a port".to_owned());
    }
    if cfg.max_conns_per_ip == Some(0) || cfg.max_session_minutes == Some(0) {
        return Err("max_conns_per_ip and max_session_minutes must be above 0".to_owned());
    }
    if let Some(url) = &cfg.echo_url {
        crate::rotate::check_http_url(url).map_err(|e| format!("echo_url: {e}"))?;
    }
    match (cfg.subtype, &cfg.rotate) {
        (Subtype::MobileBox, None) => Err("a mobile_box adapter needs a `rotate` call".to_owned()),
        (Subtype::MobileBox, Some(_)) | (_, None) => Ok(()),
        (_, Some(_)) => Err("only a mobile_box adapter has a `rotate` call".to_owned()),
    }
}

/// Rules of `scheme = "local"`: no upstream proxy exists, so everything that
/// describes one is refused instead of silently ignored. The address of each
/// unit comes from its inventory entry.
fn validate_local(cfg: &AdapterConfig) -> Result<(), String> {
    if cfg.scheme != UpstreamScheme::Local {
        return Ok(());
    }
    if cfg.subtype.kind() != Kind::Static || cfg.subtype == Subtype::MobileBox {
        return Err(
            "scheme local needs a static subtype without a rotate call (datacenter or isp)"
                .to_owned(),
        );
    }
    let refused = [
        (cfg.host.is_some(), "host"),
        (cfg.port.is_some(), "port"),
        (cfg.user_file.is_some(), "user_file"),
        (cfg.pass_file.is_some(), "pass_file"),
        (!cfg.option.is_empty(), "option"),
        (cfg.public_only, "public_only"),
        (cfg.rotate.is_some(), "rotate"),
    ];
    match refused.iter().find(|(set, _)| *set) {
        Some((_, name)) => Err(format!(
            "scheme local has no upstream proxy: `{name}` does not apply (the local address is the host of each inventory entry)"
        )),
        None => Ok(()),
    }
}

/// The local source address of an inventory entry: its `host`, which must be
/// an IP literal a socket can bind (not unspecified, multicast, broadcast, or
/// an IPv6 link-local address, which needs a scope id).
fn local_source(host: &str) -> Result<IpAddr, ProviderError> {
    let bad = |reason: &str| ProviderError::OptionRefused {
        option: "host",
        reason: reason.to_owned(),
    };
    let ip = host
        .parse::<IpAddr>()
        .map_err(|_| bad("a local unit needs an IP literal as host"))?;
    let unusable = match ip {
        IpAddr::V4(v4) => v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast(),
        IpAddr::V6(v6) => {
            v6.is_unspecified() || v6.is_multicast() || v6.segments()[0] & 0xffc0 == 0xfe80
        }
    };
    if unusable {
        return Err(bad("not a bindable unicast address"));
    }
    Ok(ip)
}
