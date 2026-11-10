//! Process configuration.
//!
//! Sources, lowest to highest priority: `/etc/proxyx/pool.toml`,
//! `PROXYX_POOL_*` environment variables (`__` nests), then the `--config`
//! file (same order as the session proxy). Provider adapters, policies and the static
//! inventory are not here: they are versioned data under `data_dir` and in
//! Postgres.

use std::cell::Cell;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context as _;
use figment::Figment;
use figment::providers::{Env, Format, Toml};
use figment::value::{Dict, Value};
use serde::Deserialize;
use serde::de::{Deserializer, Visitor};

use crate::secret::Secret;
use crate::sentry::SentryConfig;
use crate::types::OrgId;

const DEFAULT_FILE: &str = "/etc/proxyx/pool.toml";

/// How long a tunnel may keep running on a unit that was drained (rotating
/// session removed from the ready set, static IP out of leasing, org block in
/// scope). The gateway closes the tunnel and the warmer cuts the unit's
/// counters after this long (10 minutes).
pub const DRAIN_CAP: Duration = Duration::from_secs(600);

/// TCP keepalive timers: first probe after `time` of silence, then one every
/// `interval`, dropping the peer after `retries` unanswered probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpKeepalive {
    pub time: Duration,
    pub interval: Duration,
    pub retries: u32,
}

/// Every field has an environment variable `PROXYX_POOL_<FIELD>` (`__` nests, so
/// `sentry.dsn` is `PROXYX_POOL_SENTRY__DSN`). Durations take plain seconds or
/// `30s`, `5m`, `2h`. [`Settings::load`] refuses values that would fail later.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Database URL (source of truth: policies, inventory, blocks, audit). The
    /// scheme selects the backend: `postgres://` (default), `mysql://` or
    /// `mariadb://` (MariaDB 10.6+), `sqlite://PATH?mode=rwc` (one node only,
    /// see `docs/databases.md`). Env: `PROXYX_POOL_DATABASE_URL`.
    pub database_url: Secret,
    /// Private ProxyX Redis URL (hot state: leases, ready sets, cooldowns).
    /// Env: `PROXYX_POOL_REDIS_URL`.
    pub redis_url: Secret,
    /// HTTP CONNECT listener (the session proxy, prober browsers). Env:
    /// `PROXYX_POOL_CONNECT_LISTEN` (default: `0.0.0.0:8080`).
    pub connect_listen: SocketAddr,
    /// SOCKS5 listener (the session proxy). Env: `PROXYX_POOL_SOCKS_LISTEN` (default:
    /// `0.0.0.0:1080`).
    pub socks_listen: SocketAddr,
    /// Separate CONNECT listener that accepts only the probe org key.
    /// Env: `PROXYX_POOL_PROBE_LISTEN` (default: `0.0.0.0:8082`).
    pub probe_listen: SocketAddr,
    /// Control API (`/v1/...`). Env: `PROXYX_POOL_API_LISTEN` (default:
    /// `0.0.0.0:8081`).
    pub api_listen: SocketAddr,
    /// `/healthz`, `/readyz`, `/metrics`. Env: `PROXYX_POOL_OPS_LISTEN` (default:
    /// `0.0.0.0:8888`).
    pub ops_listen: SocketAddr,
    /// Directory with `adapters/*.toml`, `policies/*.toml`, `inventory/*.toml`.
    /// Env: `PROXYX_POOL_DATA_DIR` (default: `/etc/proxyx/data`).
    pub data_dir: PathBuf,
    /// Directory where the `ExternalSecret` mounts provider and scorer secrets
    /// as files; adapters and inventory entries name a file in it. Env:
    /// `PROXYX_POOL_SECRETS_DIR` (default: `/etc/proxyx/secrets`).
    pub secrets_dir: PathBuf,
    /// File with the admin bearer token for mutating `/v1` routes. Env:
    /// `PROXYX_POOL_ADMIN_TOKEN_FILE` (default:
    /// `/etc/proxyx/secrets/admin-token`).
    pub admin_token_file: PathBuf,
    /// File with the probe secret (the Vault `PROBE_ORG_KEY`), mounted into
    /// the gateway pods only. It signs the short-lived tokens that
    /// `POST /v1/probe/token` issues and the probe listener accepts
    /// ([`crate::probe_token`]); it is never a password itself, and the prober
    /// does not mount it. Read once at start: rotating it takes a gateway
    /// restart. A missing file means no prober in this environment (no token
    /// is issued, the probe listener refuses every login). Env:
    /// `PROXYX_POOL_PROBE_KEY_FILE` (default: `/etc/proxyx/secrets/probe-key`).
    pub probe_key_file: PathBuf,
    /// Org id the probe listener's tokens log in as (the policy of the
    /// prober's route classes); must be a valid org id (`[a-z0-9_-]{1,64}`).
    /// Env: `PROXYX_POOL_PROBE_ORG` (default: `proxyx-probe`).
    pub probe_org: String,
    /// How long a stopping pod keeps open tunnels; must be above zero.
    /// `terminationGracePeriodSeconds` has to cover the preStop sleep, this
    /// drain and the roles' 15 s stop margin: gitops sets 330 s = 10 s preStop
    /// + 300 s + margin. Env: `PROXYX_POOL_DRAIN_TIMEOUT` (default: `300s`).
    #[serde(with = "humantime_secs")]
    pub drain_timeout: Duration,
    /// Policy and inventory snapshot reload interval; at least one second.
    /// Env: `PROXYX_POOL_RELOAD_EVERY` (default: `30s`).
    #[serde(with = "humantime_secs")]
    pub reload_every: Duration,
    /// Most tunnels the gateway serves at once across the CONNECT, SOCKS5 and
    /// probe listeners; a connection over the cap is closed at accept.
    /// Must be above zero. Each tunnel takes two file descriptors, so the
    /// gateway refuses to start when the open files limit (`ulimit -n`) is
    /// below `2 x max_connections + 512`. Env: `PROXYX_POOL_MAX_CONNECTIONS`
    /// (default: `10000`).
    pub max_connections: usize,
    /// Most connections that have not authenticated yet, across all
    /// listeners: one that is accepted takes a slot until its request head is
    /// read and its key checked. Over it a new connection is closed at accept
    /// (`over_limit`), so silent or slow clients cannot fill
    /// `max_connections`. Must be above zero and at most `max_connections`.
    /// Env: `PROXYX_POOL_MAX_PENDING_CONNECTIONS` (default: `max_connections / 2`,
    /// at least 1).
    pub max_pending_connections: Option<usize>,
    /// Most connections of one source that have not authenticated yet, so one
    /// host cannot take the whole pre-auth pool from the others. An IPv4
    /// source counts alone, an IPv6 one by its /64 prefix. Over it a new
    /// connection is closed at accept (`over_limit`). Must be above zero and
    /// at most the pending limit. Env: `PROXYX_POOL_MAX_PENDING_PER_IP` (default:
    /// a quarter of the pending limit, at least 16, at most the pending
    /// limit: one source can never hold more than a quarter of the pool, so
    /// at least four sources are needed to fill it and a third one is not
    /// locked out by two hostile ones. A caller behind one NAT address or a
    /// load balancer without PROXY protocol counts as one source: raise it
    /// for such a path).
    pub max_pending_per_ip: Option<usize>,
    /// How long an open tunnel may carry no byte in either direction (and a
    /// write may make no progress) before the gateway closes it. Must be above
    /// zero. Env: `PROXYX_POOL_TUNNEL_IDLE_TIMEOUT` (default: `10m`).
    #[serde(with = "humantime_secs")]
    pub tunnel_idle_timeout: Duration,
    /// Turn TCP keepalive on for client sockets the gateway accepts and for
    /// the upstream sockets it dials, so a peer that vanished without a FIN
    /// (a crashed host, a dropped NAT mapping) is found and its tunnel and
    /// leases released. Env: `PROXYX_POOL_TCP_KEEPALIVE` (default: `true`).
    pub tcp_keepalive: bool,
    /// Idle time before the first keepalive probe; must be above zero when
    /// keepalive is on. Env: `PROXYX_POOL_TCP_KEEPALIVE_TIME` (default: `60s`).
    #[serde(with = "humantime_secs")]
    pub tcp_keepalive_time: Duration,
    /// Time between keepalive probes; must be above zero when keepalive is
    /// on. Env: `PROXYX_POOL_TCP_KEEPALIVE_INTERVAL` (default: `15s`).
    #[serde(with = "humantime_secs")]
    pub tcp_keepalive_interval: Duration,
    /// Unanswered probes before the peer is dropped; must be above zero when
    /// keepalive is on. Env: `PROXYX_POOL_TCP_KEEPALIVE_RETRIES` (default: `4`).
    pub tcp_keepalive_retries: u32,
    /// How long a client may take to send its request head or finish a SOCKS5
    /// handshake; must be above zero. Env: `PROXYX_POOL_HANDSHAKE_TIMEOUT`
    /// (default: `10s`).
    #[serde(with = "humantime_secs")]
    pub handshake_timeout: Duration,
    /// How long a new connection may stay silent before its first byte; must
    /// be above zero and at most `handshake_timeout`. Env:
    /// `PROXYX_POOL_FIRST_BYTE_TIMEOUT` (default: `3s`).
    #[serde(with = "humantime_secs")]
    pub first_byte_timeout: Duration,
    /// Replaces the public exit-IP check services with a comma list of
    /// `kind=url`, for a benchmark or an isolated environment with a stub
    /// provider. The list needs `cloudflare`, `ipinfo` or `ifconfig_co`: only
    /// they report the exit country. Unset uses the public list. Env:
    /// `PROXYX_POOL_EXIT_IP_SERVICES`.
    pub exit_ip_services: Option<String>,
    /// Origin of the IPQS reputation API. Only a benchmark or an isolated
    /// environment with a stand-in changes it. Env: `PROXYX_POOL_IPQS_BASE_URL`
    /// (default: `https://ipqualityscore.com`).
    pub ipqs_base_url: String,
    /// Origin of the AbuseIPDB reputation API, like `ipqs_base_url`. Env:
    /// `PROXYX_POOL_ABUSEIPDB_BASE_URL` (default: `https://api.abuseipdb.com`).
    pub abuseipdb_base_url: String,
    /// Origin of the Scamalytics reputation API, like `ipqs_base_url` (the
    /// EU node; the US node is `https://api11.scamalytics.com`). Env:
    /// `PROXYX_POOL_SCAMALYTICS_BASE_URL` (default: `https://api12.scamalytics.com`).
    pub scamalytics_base_url: String,
    /// Scamalytics account name: the path segment of every lookup. Needed
    /// when the `scamalytics_api_key` secret exists, and startup fails
    /// without it. Env: `PROXYX_POOL_SCAMALYTICS_CUSTOMER` (default: unset).
    pub scamalytics_customer: Option<String>,
    /// Emit JSON logs (Loki parses them), plain text when false. Env:
    /// `PROXYX_POOL_JSON_LOGS` (default: `true`).
    pub json_logs: bool,
    /// Error reporting. Env: `PROXYX_POOL_SENTRY__DSN` and the other
    /// `PROXYX_POOL_SENTRY__*` fields.
    pub sentry: SentryConfig,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            database_url: Secret::new("postgres://proxyx@localhost/proxyx"),
            redis_url: Secret::new("redis://localhost:6379"),
            connect_listen: ([0, 0, 0, 0], 8080).into(),
            socks_listen: ([0, 0, 0, 0], 1080).into(),
            probe_listen: ([0, 0, 0, 0], 8082).into(),
            api_listen: ([0, 0, 0, 0], 8081).into(),
            ops_listen: ([0, 0, 0, 0], 8888).into(),
            data_dir: PathBuf::from("/etc/proxyx/data"),
            secrets_dir: PathBuf::from("/etc/proxyx/secrets"),
            admin_token_file: PathBuf::from("/etc/proxyx/secrets/admin-token"),
            probe_key_file: PathBuf::from("/etc/proxyx/secrets/probe-key"),
            probe_org: "proxyx-probe".to_owned(),
            drain_timeout: Duration::from_secs(300),
            reload_every: Duration::from_secs(30),
            max_connections: 10_000,
            max_pending_connections: None,
            max_pending_per_ip: None,
            tunnel_idle_timeout: Duration::from_secs(600),
            tcp_keepalive: true,
            tcp_keepalive_time: Duration::from_secs(60),
            tcp_keepalive_interval: Duration::from_secs(15),
            tcp_keepalive_retries: 4,
            handshake_timeout: Duration::from_secs(10),
            first_byte_timeout: Duration::from_secs(3),
            exit_ip_services: None,
            ipqs_base_url: "https://ipqualityscore.com".to_owned(),
            scamalytics_base_url: "https://api12.scamalytics.com".to_owned(),
            scamalytics_customer: None,
            abuseipdb_base_url: "https://api.abuseipdb.com".to_owned(),
            json_logs: true,
            sentry: SentryConfig::default(),
        }
    }
}

impl Settings {
    /// Load settings (lowest to highest priority): the default file,
    /// `PROXYX_POOL_*` environment variables, the explicit `--config` file.
    pub fn load(explicit: Option<&Path>) -> anyhow::Result<Self> {
        let default_file = Path::new(DEFAULT_FILE);
        // A file the operator named must exist: a wrong mount path would
        // otherwise run the process on defaults (0.0.0.0 listeners).
        if let Some(path) = explicit {
            anyhow::ensure!(
                path.is_file(),
                "configuration file {} does not exist",
                path.display()
            );
        }
        // Typos in a file fail at startup. The environment is not checked:
        // Kubernetes injects `PROXYX_POOL_SERVICE_HOST` and similar variables for
        // a Service named proxyx, so unknown `PROXYX_POOL_*` names are normal.
        let default = default_file.exists().then_some(default_file);
        for path in default.into_iter().chain(explicit) {
            reject_unknown_keys(path)?;
        }
        let settings: Self = layered(default_file, explicit)
            .extract()
            .context("failed to load configuration")?;
        settings.validate()?;
        Ok(settings)
    }

    /// Fail at startup on values that would otherwise surface at first use.
    fn validate(&self) -> anyhow::Result<()> {
        // refused here instead of being raised to 1 s by the reload loop
        anyhow::ensure!(
            self.reload_every >= Duration::from_secs(1),
            "reload_every must be at least 1s, got {:?}",
            self.reload_every
        );
        anyhow::ensure!(
            !self.drain_timeout.is_zero(),
            "drain_timeout must be above zero: open tunnels would be cut on stop"
        );
        anyhow::ensure!(
            self.max_connections > 0,
            "max_connections must be above zero: the gateway would accept no tunnel"
        );
        if let Some(pending) = self.max_pending_connections {
            anyhow::ensure!(
                (1..=self.max_connections).contains(&pending),
                "max_pending_connections must be between 1 and max_connections ({}), got {pending}",
                self.max_connections
            );
        }
        if let Some(per_ip) = self.max_pending_per_ip {
            anyhow::ensure!(
                (1..=self.pending_limit()).contains(&per_ip),
                "max_pending_per_ip must be between 1 and the pending limit ({}), got {per_ip}",
                self.pending_limit()
            );
        }
        anyhow::ensure!(
            !self.tunnel_idle_timeout.is_zero(),
            "tunnel_idle_timeout must be above zero: every tunnel would be cut at once"
        );
        if self.tcp_keepalive {
            anyhow::ensure!(
                !self.tcp_keepalive_time.is_zero()
                    && !self.tcp_keepalive_interval.is_zero()
                    && self.tcp_keepalive_retries > 0,
                "tcp_keepalive_time, tcp_keepalive_interval and tcp_keepalive_retries must be above zero (or set tcp_keepalive = false)"
            );
        }
        anyhow::ensure!(
            !self.handshake_timeout.is_zero(),
            "handshake_timeout must be above zero: no client could finish its handshake"
        );
        anyhow::ensure!(
            !self.first_byte_timeout.is_zero() && self.first_byte_timeout <= self.handshake_timeout,
            "first_byte_timeout must be above zero and at most handshake_timeout ({:?}), got {:?}",
            self.handshake_timeout,
            self.first_byte_timeout
        );
        self.probe_org
            .parse::<OrgId>()
            .context("probe_org is not a valid org id")?;
        for (name, url) in [
            ("ipqs_base_url", &self.ipqs_base_url),
            ("abuseipdb_base_url", &self.abuseipdb_base_url),
            ("scamalytics_base_url", &self.scamalytics_base_url),
        ] {
            anyhow::ensure!(
                url.strip_prefix("https://")
                    .or_else(|| url.strip_prefix("http://"))
                    .is_some_and(|host| !host.is_empty() && !host.starts_with('/')),
                "{name} must be an http:// or https:// origin, got {url:?}"
            );
        }
        self.sentry.validate()?;
        Ok(())
    }

    /// The keepalive timers to put on client and upstream sockets, or `None`
    /// when `tcp_keepalive` is off.
    pub fn keepalive(&self) -> Option<TcpKeepalive> {
        self.tcp_keepalive.then_some(TcpKeepalive {
            time: self.tcp_keepalive_time,
            interval: self.tcp_keepalive_interval,
            retries: self.tcp_keepalive_retries,
        })
    }

    /// Slots for connections that have not authenticated yet.
    pub fn pending_limit(&self) -> usize {
        self.max_pending_connections
            .unwrap_or(self.max_connections / 2)
            .max(1)
    }

    /// Slots of one source for connections that have not authenticated yet.
    pub fn pending_per_ip_limit(&self) -> usize {
        let pending = self.pending_limit();
        self.max_pending_per_ip
            .unwrap_or_else(|| (pending / 4).max(16))
            .min(pending)
    }

    /// Read a secret file from `secrets_dir`. A name that is not a plain
    /// relative name, and a missing or empty file, are refused.
    pub fn read_secret(&self, name: &str) -> anyhow::Result<Secret> {
        if name.is_empty() || name.contains("..") || name.starts_with('/') {
            anyhow::bail!("secret name {name:?} is not a plain relative name");
        }
        read_secret_file(&self.secrets_dir.join(name))
            .with_context(|| format!("failed to read secret {name:?}"))
    }
}

/// Read a secret from a file, trimming one trailing newline. A missing or
/// empty file is refused.
pub fn read_secret_file(path: &Path) -> anyhow::Result<Secret> {
    let value = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let value = value.strip_suffix('\n').unwrap_or(&value);
    anyhow::ensure!(!value.is_empty(), "{} is empty", path.display());
    Ok(Secret::new(value))
}

fn layered(default_file: &Path, explicit: Option<&Path>) -> Figment {
    let mut figment = Figment::new();
    if default_file.exists() {
        figment = figment.merge(Toml::file(default_file));
    }
    figment = figment.merge(Env::prefixed("PROXYX_POOL_").split("__"));
    if let Some(path) = explicit {
        figment = figment.merge(Toml::file(path));
    }
    figment
}

/// Refuse a config file with a key [`Settings`] or [`SentryConfig`] does not
/// have (a typo such as `max_connection`), which serde would ignore.
fn reject_unknown_keys(path: &Path) -> anyhow::Result<()> {
    let file: Dict = Figment::from(Toml::file(path))
        .extract()
        .with_context(|| format!("failed to read {}", path.display()))?;
    let check = |table: &str, keys: &Dict, known: &[&str]| -> anyhow::Result<()> {
        match keys.keys().find(|key| !known.contains(&key.as_str())) {
            Some(key) => anyhow::bail!(
                "unknown key `{key}`{table} in {} (known: {})",
                path.display(),
                known.join(", ")
            ),
            None => Ok(()),
        }
    };
    check("", &file, field_names::<Settings>())?;
    if let Some(Value::Dict(_, sentry)) = file.get("sentry") {
        check(" in [sentry]", sentry, field_names::<SentryConfig>())?;
    }
    Ok(())
}

/// The field names serde derived for `T` (the `fields` argument of
/// `deserialize_struct`), so the known keys cannot drift from the structs.
fn field_names<T: for<'de> Deserialize<'de>>() -> &'static [&'static str] {
    struct Capture(Cell<&'static [&'static str]>);

    impl<'de> Deserializer<'de> for &Capture {
        type Error = serde::de::value::Error;

        fn deserialize_any<V: Visitor<'de>>(self, _: V) -> Result<V::Value, Self::Error> {
            Err(serde::de::Error::custom("not a struct"))
        }

        fn deserialize_struct<V: Visitor<'de>>(
            self,
            _name: &'static str,
            fields: &'static [&'static str],
            _: V,
        ) -> Result<V::Value, Self::Error> {
            self.0.set(fields);
            Err(serde::de::Error::custom("fields captured"))
        }

        serde::forward_to_deserialize_any! {
            bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
            bytes byte_buf option unit unit_struct newtype_struct seq tuple
            tuple_struct map enum identifier ignored_any
        }
    }

    let capture = Capture(Cell::new(&[]));
    let _ = T::deserialize(&capture);
    capture.0.get()
}

/// Durations in config files are plain seconds or `30s`, `5m`, `2h`.
pub mod humantime_secs {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer};

    /// Parse `30`, `30s`, `5m`, `2h` or `1d`.
    pub fn parse(s: &str) -> Result<Duration, String> {
        let s = s.trim();
        let (digits, unit) = s
            .find(|c: char| !c.is_ascii_digit())
            .map_or((s, ""), |i| s.split_at(i));
        let n: u64 = digits.parse().map_err(|_| format!("bad duration {s:?}"))?;
        let mult = match unit {
            "" | "s" => 1,
            "m" => 60,
            "h" => 3_600,
            "d" => 86_400,
            _ => return Err(format!("bad duration unit in {s:?}")),
        };
        n.checked_mul(mult)
            .map(Duration::from_secs)
            .ok_or_else(|| format!("duration {s:?} overflows"))
    }

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        Secs(u64),
        Text(String),
    }

    /// Serde adapter: accept an integer of seconds or a duration string.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        match Raw::deserialize(d)? {
            Raw::Secs(n) => Ok(Duration::from_secs(n)),
            Raw::Text(s) => parse(&s).map_err(serde::de::Error::custom),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::humantime_secs::parse;
    use super::*;

    #[test]
    fn durations_parse_units_and_reject_garbage() {
        assert_eq!(parse("30"), Ok(Duration::from_secs(30)));
        assert_eq!(parse("5m"), Ok(Duration::from_secs(300)));
        assert_eq!(parse("2h"), Ok(Duration::from_secs(7_200)));
        assert!(parse("").is_err());
        assert!(parse("5w").is_err());
        assert!(parse("99999999999999999999d").is_err());
    }

    fn org(figment: &figment::Figment) -> String {
        figment.extract::<Settings>().expect("settings").probe_org
    }

    /// The error text of loading `body` as the `--config` file `name`.
    fn refused(jail: &figment::Jail, name: &str, body: &str) -> String {
        jail.create_file(name, body).expect("file");
        format!(
            "{:#}",
            Settings::load(Some(Path::new(name))).expect_err(name)
        )
    }

    /// Each `(file name, body, field)` is refused and the error names the field.
    fn assert_refused(jail: &figment::Jail, cases: &[(&str, &str, &str)]) {
        for (name, body, field) in cases {
            let err = refused(jail, name, body);
            assert!(err.contains(field), "{name}: {err}");
        }
    }

    #[test]
    #[allow(clippy::result_large_err)] // figment::Jail fixes the closure's error type
    fn file_is_below_env_and_env_is_below_the_explicit_config() {
        figment::Jail::expect_with(|jail| {
            jail.create_file("default.toml", "probe_org = \"file\"")?;
            jail.create_file("explicit.toml", "probe_org = \"explicit\"")?;
            let default = Path::new("default.toml");
            let explicit = Some(Path::new("explicit.toml"));

            assert_eq!(org(&layered(default, None)), "file");
            jail.set_env("PROXYX_POOL_PROBE_ORG", "env");
            assert_eq!(org(&layered(default, None)), "env");
            assert_eq!(org(&layered(default, explicit)), "explicit");
            Ok(())
        });
    }

    #[test]
    #[allow(clippy::result_large_err)] // figment::Jail fixes the closure's error type
    fn secrets_are_plain_names_in_the_secrets_dir_and_not_empty() {
        figment::Jail::expect_with(|jail| {
            jail.create_file("token", "abc\n")?;
            jail.create_file("blank", "\n")?;
            let settings = Settings {
                secrets_dir: jail.directory().to_path_buf(),
                ..Settings::default()
            };
            assert_eq!(settings.read_secret("token").expect("read").expose(), "abc");
            for bad in ["../token", "/token", "", "blank"] {
                assert!(settings.read_secret(bad).is_err(), "{bad:?}");
            }
            let missing = settings.read_secret("missing").expect_err("missing");
            assert!(
                format!("{missing:#}").contains("\"missing\""),
                "{missing:#}"
            );
            Ok(())
        });
    }

    #[test]
    #[allow(clippy::result_large_err)] // figment::Jail fixes the closure's error type
    fn a_reload_period_under_one_second_is_refused_at_load() {
        figment::Jail::expect_with(|jail| {
            assert_refused(jail, &[("zero.toml", "reload_every = 0", "reload_every")]);
            jail.create_file("fast.toml", "reload_every = \"1s\"")?;
            let ok = Settings::load(Some(Path::new("fast.toml"))).expect("one second");
            assert_eq!(ok.reload_every, Duration::from_secs(1));
            Ok(())
        });
    }

    #[test]
    #[allow(clippy::result_large_err)] // figment::Jail fixes the closure's error type
    fn a_zero_drain_a_zero_connection_cap_or_a_bad_probe_org_is_refused_at_load() {
        figment::Jail::expect_with(|jail| {
            assert_refused(
                jail,
                &[
                    ("drain.toml", "drain_timeout = \"0s\"", "drain_timeout"),
                    ("cap.toml", "max_connections = 0", "max_connections"),
                    ("org.toml", "probe_org = \"Not An Org\"", "probe_org"),
                ],
            );
            jail.create_file(
                "ok.toml",
                "drain_timeout = 1\nmax_connections = 5\nprobe_org = \"probe-1\"",
            )?;
            let ok = Settings::load(Some(Path::new("ok.toml"))).expect("valid");
            assert_eq!(ok.drain_timeout, Duration::from_secs(1));
            assert_eq!(ok.max_connections, 5);
            assert_eq!(ok.probe_org, "probe-1");
            Ok(())
        });
    }

    #[test]
    #[allow(clippy::result_large_err)] // figment::Jail fixes the closure's error type
    fn scorer_origins_default_to_the_vendors_and_must_be_http_origins() {
        figment::Jail::expect_with(|jail| {
            let defaults = Settings::default();
            assert_eq!(defaults.ipqs_base_url, "https://ipqualityscore.com");
            assert_eq!(defaults.abuseipdb_base_url, "https://api.abuseipdb.com");
            assert_eq!(
                defaults.scamalytics_base_url,
                "https://api12.scamalytics.com"
            );
            assert_eq!(defaults.scamalytics_customer, None);

            jail.create_file(
                "stub.toml",
                "ipqs_base_url = \"http://127.0.0.1:9\"\nabuseipdb_base_url = \"http://stub.test\"\n\
                 scamalytics_base_url = \"http://scam.test\"\nscamalytics_customer = \"acme\"",
            )?;
            let ok = Settings::load(Some(Path::new("stub.toml"))).expect("stand-in origins");
            assert_eq!(ok.ipqs_base_url, "http://127.0.0.1:9");
            assert_eq!(ok.abuseipdb_base_url, "http://stub.test");
            assert_eq!(ok.scamalytics_base_url, "http://scam.test");
            assert_eq!(ok.scamalytics_customer.as_deref(), Some("acme"));

            assert_refused(
                jail,
                &[
                    (
                        "scheme.toml",
                        "ipqs_base_url = \"ftp://x\"",
                        "ipqs_base_url",
                    ),
                    (
                        "empty.toml",
                        "abuseipdb_base_url = \"https://\"",
                        "abuseipdb_base_url",
                    ),
                    (
                        "bare.toml",
                        "ipqs_base_url = \"ipqualityscore.com\"",
                        "ipqs_base_url",
                    ),
                    (
                        "scam.toml",
                        "scamalytics_base_url = \"scamalytics.com\"",
                        "scamalytics_base_url",
                    ),
                ],
            );
            Ok(())
        });
    }

    #[test]
    fn the_probe_key_file_defaults_to_the_mounted_secret() {
        assert_eq!(
            Settings::default().probe_key_file,
            Path::new("/etc/proxyx/secrets/probe-key")
        );
    }

    #[test]
    #[allow(clippy::result_large_err)] // figment::Jail fixes the closure's error type
    fn the_pending_pool_defaults_to_half_the_cap_and_the_idle_timeout_must_be_set() {
        figment::Jail::expect_with(|jail| {
            let settings = Settings {
                max_connections: 7,
                ..Settings::default()
            };
            assert_eq!(settings.pending_limit(), 3);
            let one = Settings {
                max_connections: 1,
                ..Settings::default()
            };
            assert_eq!(one.pending_limit(), 1, "never zero");
            assert_eq!(
                Settings::default().tunnel_idle_timeout,
                Duration::from_secs(600)
            );

            assert_refused(
                jail,
                &[
                    (
                        "idle.toml",
                        "tunnel_idle_timeout = 0",
                        "tunnel_idle_timeout",
                    ),
                    (
                        "zero.toml",
                        "max_pending_connections = 0",
                        "max_pending_connections",
                    ),
                    (
                        "over.toml",
                        "max_connections = 5\nmax_pending_connections = 6",
                        "max_pending_connections",
                    ),
                ],
            );
            jail.create_file(
                "ok.toml",
                "max_connections = 10\nmax_pending_connections = 4\ntunnel_idle_timeout = \"2m\"",
            )?;
            let ok = Settings::load(Some(Path::new("ok.toml"))).expect("valid");
            assert_eq!(ok.pending_limit(), 4);
            assert_eq!(ok.tunnel_idle_timeout, Duration::from_secs(120));
            Ok(())
        });
    }

    #[test]
    #[allow(clippy::result_large_err)] // figment::Jail fixes the closure's error type
    fn the_per_source_pending_cap_defaults_to_a_quarter_of_the_pool_and_is_checked_against_it() {
        figment::Jail::expect_with(|jail| {
            let with_pool = |max_connections: usize| Settings {
                max_connections,
                ..Settings::default()
            };
            // pending pool = max_connections / 2
            assert_eq!(with_pool(2_000).pending_limit(), 1_000);
            assert_eq!(
                with_pool(2_000).pending_per_ip_limit(),
                250,
                "a quarter: three sources of 250 leave the pool open to a fourth"
            );
            assert_eq!(with_pool(20_000).pending_per_ip_limit(), 2_500);
            assert_eq!(with_pool(80).pending_limit(), 40);
            assert_eq!(with_pool(80).pending_per_ip_limit(), 16, "at least 16");
            assert_eq!(with_pool(7).pending_limit(), 3);
            assert_eq!(
                with_pool(7).pending_per_ip_limit(),
                3,
                "never above the pool"
            );
            let set = Settings {
                max_pending_per_ip: Some(2),
                ..with_pool(10_000)
            };
            assert_eq!(set.pending_per_ip_limit(), 2, "the setting wins");

            assert_refused(
                jail,
                &[
                    ("zero.toml", "max_pending_per_ip = 0", "max_pending_per_ip"),
                    (
                        "over.toml",
                        "max_connections = 10\nmax_pending_connections = 4\nmax_pending_per_ip = 5",
                        "max_pending_per_ip",
                    ),
                    (
                        "over_default.toml",
                        "max_connections = 10\nmax_pending_per_ip = 6",
                        "max_pending_per_ip",
                    ),
                ],
            );
            jail.create_file(
                "ok.toml",
                "max_connections = 10\nmax_pending_connections = 4\nmax_pending_per_ip = 4",
            )?;
            let ok = Settings::load(Some(Path::new("ok.toml"))).expect("valid");
            assert_eq!(ok.pending_per_ip_limit(), 4);
            Ok(())
        });
    }

    #[test]
    #[allow(clippy::result_large_err)] // figment::Jail fixes the closure's error type
    fn keepalive_and_handshake_timers_default_to_the_old_constants_and_are_validated() {
        figment::Jail::expect_with(|jail| {
            let defaults = layered(Path::new("missing.toml"), None)
                .extract::<Settings>()
                .expect("settings");
            assert_eq!(
                defaults.keepalive(),
                Some(TcpKeepalive {
                    time: Duration::from_secs(60),
                    interval: Duration::from_secs(15),
                    retries: 4,
                })
            );
            assert_eq!(defaults.handshake_timeout, Duration::from_secs(10));
            assert_eq!(defaults.first_byte_timeout, Duration::from_secs(3));

            jail.set_env("PROXYX_POOL_TCP_KEEPALIVE_TIME", "2m");
            jail.set_env("PROXYX_POOL_TCP_KEEPALIVE", "false");
            let env = Settings::load(None).expect("load");
            assert_eq!(env.tcp_keepalive_time, Duration::from_secs(120));
            assert_eq!(env.keepalive(), None);
            Ok(())
        });
        figment::Jail::expect_with(|jail| {
            assert_refused(
                jail,
                &[
                    ("a.toml", "tcp_keepalive_time = 0", "tcp_keepalive_time"),
                    (
                        "b.toml",
                        "tcp_keepalive_retries = 0",
                        "tcp_keepalive_retries",
                    ),
                    ("c.toml", "handshake_timeout = 0", "handshake_timeout"),
                    (
                        "d.toml",
                        "handshake_timeout = 2\nfirst_byte_timeout = 3",
                        "first_byte_timeout",
                    ),
                ],
            );
            // Off, the timers are not checked.
            jail.create_file("e.toml", "tcp_keepalive = false\ntcp_keepalive_time = 0")?;
            Settings::load(Some(Path::new("e.toml"))).expect("keepalive off");
            Ok(())
        });
    }

    #[test]
    #[allow(clippy::result_large_err)] // figment::Jail fixes the closure's error type
    fn a_missing_config_file_is_refused_not_ignored() {
        figment::Jail::expect_with(|_jail| {
            let err =
                Settings::load(Some(Path::new("/nonexistent/typo.toml"))).expect_err("missing");
            assert!(
                format!("{err:#}").contains("/nonexistent/typo.toml"),
                "{err:#}"
            );
            assert!(Settings::load(None).is_ok(), "no --config is fine");
            Ok(())
        });
    }

    #[test]
    #[allow(clippy::result_large_err)] // figment::Jail fixes the closure's error type
    fn an_unknown_key_in_a_config_file_is_refused_but_unknown_env_is_not() {
        figment::Jail::expect_with(|jail| {
            let err = refused(jail, "typo.toml", "max_connection = 5");
            assert!(err.contains("`max_connection`"), "{err}");
            let err = refused(jail, "sentry.toml", "[sentry]\nbogus = 1");
            assert!(err.contains("`bogus`") && err.contains("[sentry]"), "{err}");

            jail.create_file(
                "ok.toml",
                "max_connections = 5\n[sentry]\nsample_rate = 0.5",
            )?;
            // Kubernetes service links inject variables like these.
            jail.set_env("PROXYX_POOL_SERVICE_HOST", "10.0.0.1");
            jail.set_env("PROXYX_POOL_PORT", "tcp://10.0.0.1:8081");
            let ok = Settings::load(Some(Path::new("ok.toml"))).expect("known keys");
            assert_eq!(ok.max_connections, 5);
            Ok(())
        });
    }

    #[test]
    #[allow(clippy::result_large_err)] // figment::Jail fixes the closure's error type
    fn a_bad_sentry_dsn_or_rate_is_a_configuration_error() {
        figment::Jail::expect_with(|jail| {
            let err = refused(jail, "dsn.toml", "[sentry]\ndsn = \"not a dsn\"");
            assert!(err.contains("sentry.dsn"), "{err}");
            assert!(!err.contains("not a dsn"), "the value is a secret: {err}");
            let err = refused(jail, "rate.toml", "[sentry]\nsample_rate = 2.0");
            assert!(err.contains("sentry.sample_rate"), "{err}");
            let err = refused(jail, "traces.toml", "[sentry]\ntraces_sample_rate = -0.1");
            assert!(err.contains("sentry.traces_sample_rate"), "{err}");

            jail.set_env("PROXYX_POOL_SENTRY__DSN", "garbage");
            let err = Settings::load(None).expect_err("env dsn");
            assert!(format!("{err:#}").contains("sentry.dsn"), "{err:#}");

            jail.set_env(
                "PROXYX_POOL_SENTRY__DSN",
                "https://publickey@o1.ingest.sentry.io/42",
            );
            Settings::load(None).expect("valid dsn");
            jail.set_env("PROXYX_POOL_SENTRY__DSN", "");
            Settings::load(None).expect("empty dsn leaves sentry off");
            Ok(())
        });
    }
}
