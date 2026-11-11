//! Test harness: a loopback "provider" that is also the exit-IP services,
//! the reputation scorers and the SIM box API, plus the local Redis (DB 2)
//! and Postgres. Tests skip with a message when the environment variables are
//! unset (`PROXYX_TEST_REDIS_URL`, `PROXYX_TEST_DATABASE_URL`).
//!
//! The fake proxy decides the exit IP of a request from the user name in
//! `Proxy-Authorization`, so every session (and every static IP, through its
//! credentials file) has an exit IP the test controls.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use base64::Engine as _;
use common::Secret;
use common::config::Settings;
use common::metrics::Metrics;
use common::types::{InventoryEntry, Kind, Partition, Subtype, Target};
use parking_lot::Mutex;
use policy::{PolicyFile, PolicySet, Pool};
use provider::{AdapterFile, AdapterSet, MobileBoxClient};
use store::loaded::{Loaded, ProbeTargets};
use store::{
    Db, Grant, Hot, InventoryRow, LeaseLimits, LeaseOutcome, LeaseRequest, Snapshot, Transition,
    UnitRecord,
};
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use verify::{
    CheckService, ExitIpChecker, ExitIpConfig, LightProbe, ProbeConfig, Reputation,
    ReputationConfig, Scorer, ScorerAccount, ScorerSlot, ServiceKind, Url,
};

use crate::WarmerCtx;
use crate::state::{Timing, Warmer};

pub(crate) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Unwrap a started [`Harness`]. Without the local services the test ends
/// early (skipped).
macro_rules! harness {
    ($start:expr) => {
        match $start.await? {
            Some(h) => h,
            None => return Ok(()),
        }
    };
}
pub(crate) use harness;

/// Redis DB index of this crate (contract: warmer 2).
const REDIS_DB: &str = "2";

/// One test at a time: they share Redis DB 2 and one Postgres database, and
/// the flush test wipes both.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

// --- The fake provider ---

#[derive(Clone, Copy, Debug)]
pub(crate) enum RotateMode {
    /// 200 and the box exits from this IP from now on.
    Change(Ipv4Addr),
    /// 200 and nothing changes.
    Unchanged,
    /// 200, then the box stops answering.
    GoDark,
    /// The call hangs until the client gives up.
    Hang,
    /// 500.
    Fail,
}

/// How the fake treats the connections of one user name.
#[derive(Clone, Copy, Debug)]
pub(crate) enum UserMode {
    /// Closes the connection without a reply (a dead IP behind the provider).
    Drop,
    /// Answers 407 (a revoked login).
    Auth,
}

#[derive(Default)]
pub(crate) struct Fake {
    pub port: u16,
    down: AtomicBool,
    echo_down: AtomicBool,
    checks_down: AtomicBool,
    scorers_down: AtomicBool,
    probe_status: AtomicU16,
    ipify_delay_ms: AtomicU64,
    probe_delay_ms: AtomicU64,
    active: AtomicU32,
    peak: AtomicU32,
    next_ip: AtomicU32,
    users: Mutex<HashMap<String, Ipv4Addr>>,
    same_ip: Mutex<Option<Ipv4Addr>>,
    risk: Mutex<HashMap<Ipv4Addr, u32>>,
    default_risk: AtomicU32,
    hits: Mutex<HashMap<String, u64>>,
    auth_users: Mutex<HashMap<String, String>>,
    rotate: Mutex<Option<RotateMode>>,
    modes: Mutex<HashMap<String, UserMode>>,
}

impl Fake {
    pub(crate) async fn start() -> TestResult<Arc<Self>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let fake = Arc::new(Self {
            port: listener.local_addr()?.port(),
            probe_status: AtomicU16::new(200),
            ..Self::default()
        });
        let served = fake.clone();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                tokio::spawn(serve(served.clone(), sock));
            }
        });
        Ok(fake)
    }

    pub(crate) fn set_down(&self, down: bool) {
        self.down.store(down, Ordering::SeqCst);
    }

    pub(crate) fn set_echo_down(&self, down: bool) {
        self.echo_down.store(down, Ordering::SeqCst);
    }

    /// The public exit-IP services fail; the provider echo still answers.
    pub(crate) fn set_checks_down(&self, down: bool) {
        self.checks_down.store(down, Ordering::SeqCst);
    }

    /// Status of every probe target; anything but 200 carries a captcha page.
    pub(crate) fn set_probe_status(&self, status: u16) {
        self.probe_status.store(status, Ordering::SeqCst);
    }

    /// The reputation scorers answer 500; everything else works.
    pub(crate) fn set_scorers_down(&self, down: bool) {
        self.scorers_down.store(down, Ordering::SeqCst);
    }

    pub(crate) fn set_ipify_delay(&self, ms: u64) {
        self.ipify_delay_ms.store(ms, Ordering::SeqCst);
    }

    /// Every probe target answers after this long (a slow IP: clean answers
    /// over the TTFB limit).
    pub(crate) fn set_probe_delay(&self, ms: u64) {
        self.probe_delay_ms.store(ms, Ordering::SeqCst);
    }

    /// The exit IP of a user name (a session, a static IP, the box).
    pub(crate) fn set_user_ip(&self, user: &str, ip: Ipv4Addr) {
        self.users.lock().insert(user.to_owned(), ip);
    }

    /// Refuse the connections of a user name; `None` restores it.
    pub(crate) fn set_user_mode(&self, user: &str, mode: Option<UserMode>) {
        let mut modes = self.modes.lock();
        match mode {
            Some(mode) => modes.insert(user.to_owned(), mode),
            None => modes.remove(user),
        };
    }

    /// Every user exits from this IP (duplicate sessions).
    pub(crate) fn set_same_ip(&self, ip: Option<Ipv4Addr>) {
        *self.same_ip.lock() = ip;
    }

    pub(crate) fn set_risk(&self, ip: Ipv4Addr, risk: u32) {
        self.risk.lock().insert(ip, risk);
    }

    /// The risk of every IP without its own.
    pub(crate) fn set_default_risk(&self, risk: u32) {
        self.default_risk.store(risk, Ordering::SeqCst);
    }

    pub(crate) fn set_rotate(&self, mode: RotateMode) {
        *self.rotate.lock() = Some(mode);
    }

    pub(crate) fn hits(&self, path: &str) -> u64 {
        self.hits.lock().get(path).copied().unwrap_or(0)
    }

    /// Last proxy user name received for a path.
    pub(crate) fn auth_user(&self, path: &str) -> Option<String> {
        self.auth_users.lock().get(path).cloned()
    }

    /// Most `/ipify` requests that were in flight at once: one per create.
    pub(crate) fn peak_creates(&self) -> u32 {
        self.peak.load(Ordering::SeqCst)
    }
    fn ip_of(&self, user: &str) -> Ipv4Addr {
        if let Some(ip) = *self.same_ip.lock() {
            return ip;
        }
        let mut users = self.users.lock();
        *users.entry(user.to_owned()).or_insert_with(|| {
            let n = self.next_ip.fetch_add(1, Ordering::SeqCst) + 1;
            Ipv4Addr::new(
                10,
                1,
                u8::try_from(n / 250).unwrap_or(0),
                u8::try_from(n % 250).unwrap_or(0) + 1,
            )
        })
    }

    async fn respond(&self, path: &str, direct: bool, user: &str) -> (u16, String) {
        if direct {
            return self.direct(path).await;
        }
        if self.down.load(Ordering::SeqCst) {
            return (503, "provider down".into());
        }
        let ip = self.ip_of(user);
        *self.hits.lock().entry(path.to_owned()).or_default() += 1;
        match path {
            "/ipify" | "/cf" | "/ipinfo" if self.checks_down.load(Ordering::SeqCst) => {
                (503, "check service down".into())
            }
            "/ipify" => {
                let now = self.active.fetch_add(1, Ordering::SeqCst) + 1;
                self.peak.fetch_max(now, Ordering::SeqCst);
                let delay = self.ipify_delay_ms.load(Ordering::SeqCst);
                if delay > 0 {
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }
                self.active.fetch_sub(1, Ordering::SeqCst);
                (200, format!(r#"{{"ip":"{ip}"}}"#))
            }
            "/cf" => (200, format!("fl=1\nip={ip}\nloc=FR\n")),
            "/ipinfo" => (200, format!(r#"{{"ip":"{ip}","country":"FR"}}"#)),
            "/echo" if self.echo_down.load(Ordering::SeqCst) => (500, "echo down".into()),
            "/echo" => (200, ip.to_string()),
            p if p.starts_with("/probe") => {
                let delay = self.probe_delay_ms.load(Ordering::SeqCst);
                if delay > 0 {
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }
                let status = self.probe_status.load(Ordering::SeqCst);
                if status == 200 || p.contains("/fine") {
                    (200, "<html>hello</html>".into())
                } else {
                    (status, "please solve this captcha".into())
                }
            }
            _ => (404, "unknown".into()),
        }
    }

    /// Requests made straight to the fake: scorers and the box API.
    async fn direct(&self, path: &str) -> (u16, String) {
        let score_of = |ip: &str| -> u32 {
            ip.parse::<Ipv4Addr>()
                .ok()
                .and_then(|ip| self.risk.lock().get(&ip).copied())
                .unwrap_or_else(|| self.default_risk.load(Ordering::SeqCst))
        };
        if self.scorers_down.load(Ordering::SeqCst)
            && (path.starts_with("/api/json/ip/") || path.starts_with("/api/v2/check"))
        {
            return (500, "down".into());
        }
        if let Some(rest) = path.strip_prefix("/api/json/ip/") {
            let ip = rest.rsplit('/').next().unwrap_or_default();
            return (
                200,
                format!(
                    r#"{{"success":true,"fraud_score":{},"tor":false}}"#,
                    score_of(ip)
                ),
            );
        }
        if path.starts_with("/api/v2/check") {
            let ip = path
                .split("ipAddress=")
                .nth(1)
                .and_then(|q| q.split('&').next())
                .unwrap_or_default();
            return (
                200,
                format!(r#"{{"data":{{"abuseConfidenceScore":{}}}}}"#, score_of(ip)),
            );
        }
        if path.starts_with("/rotate/") {
            let mode = *self.rotate.lock();
            return match mode {
                Some(RotateMode::Change(ip)) => {
                    self.users.lock().insert("box".into(), ip);
                    (200, "ok".into())
                }
                Some(RotateMode::GoDark) => {
                    self.down.store(true, Ordering::SeqCst);
                    (200, "ok".into())
                }
                Some(RotateMode::Hang) => {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    (200, "late".into())
                }
                Some(RotateMode::Fail) => (500, "no".into()),
                Some(RotateMode::Unchanged) | None => (200, "ok".into()),
            };
        }
        (404, "unknown".into())
    }
}

async fn serve(st: Arc<Fake>, mut sock: TcpStream) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        match sock.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
        if buf.len() > 16 * 1024 {
            return;
        }
    }
    let head = String::from_utf8_lossy(&buf).into_owned();
    let mut lines = head.lines();
    let request = lines.next().unwrap_or_default();
    let target = request.split(' ').nth(1).unwrap_or("/");
    let (direct, path) = match target.strip_prefix("http://") {
        Some(rest) => (
            false,
            format!("/{}", rest.split_once('/').map_or("", |(_, p)| p)),
        ),
        None => (true, target.to_owned()),
    };
    let user = lines
        .find_map(|l| {
            l.to_ascii_lowercase()
                .starts_with("proxy-authorization: basic ")
                .then(|| l.split_whitespace().last().unwrap_or_default().to_owned())
        })
        .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok())
        .and_then(|raw| String::from_utf8(raw).ok())
        .map(|creds| creds.split(':').next().unwrap_or_default().to_owned())
        .unwrap_or_default();
    if !direct {
        st.auth_users.lock().insert(path.clone(), user.clone());
    }
    let mode = st.modes.lock().get(&user).copied();
    match mode {
        Some(UserMode::Drop) if !direct => return,
        Some(UserMode::Auth) if !direct => {
            let reply = "HTTP/1.1 407 Proxy Authentication Required\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
            sock.write_all(reply.as_bytes()).await.ok();
            sock.shutdown().await.ok();
            return;
        }
        _ => {}
    }
    let (status, body) = st.respond(&path, direct, &user).await;
    let reply = format!(
        "HTTP/1.1 {status} X\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    sock.write_all(reply.as_bytes()).await.ok();
    sock.shutdown().await.ok();
}

// --- Adapters and policies ---

pub(crate) fn rotating_adapter(port: u16) -> String {
    format!(
        r#"
[[adapter]]
id = "rot"
kind = "rotating"
subtype = "residential"
host = "127.0.0.1"
port = {port}
credentials_optional = true
user = "u{{opts}}"
max_session_minutes = 30
echo_url = "http://echo.test/echo"

[[adapter.option]]
name = "sid"
to = "user"
frag = "-s-{{v}}"
charset = "alnum"
len = 12

[[adapter.option]]
name = "country"
to = "user"
frag = "-c-{{v}}"
"#
    )
}

pub(crate) fn static_adapter(_port: u16) -> String {
    r#"
[[adapter]]
id = "stat"
kind = "static"
subtype = "isp"
credentials_optional = true
echo_url = "http://echo.test/echo"
"#
    .to_owned()
}

pub(crate) fn box_adapter(port: u16) -> String {
    format!(
        r#"
[[adapter]]
id = "bx"
kind = "static"
subtype = "mobile_box"
credentials_optional = true
user = "box"
echo_url = "http://echo.test/echo"

[adapter.rotate]
method = "POST"
url = "http://127.0.0.1:{port}/rotate/{{handle}}"
timeout = "1s"
"#
    )
}

/// A policy file: `keys` are top-level fields, `tables` the `[policy.x]` tables.
/// Browser samples are off unless `tables` has its own `[policy.criteria]`:
/// a random sample would reserve a candidate and make counts flaky.
pub(crate) fn policy_toml(keys: &str, tables: &str) -> String {
    let criteria = if tables.contains("[policy.criteria]") {
        ""
    } else {
        "[policy.criteria]\nbrowser_sample = 0.0\n"
    };
    format!("[[policy]]\nname = \"global\"\nregions = [\"fr\"]\n{keys}\n{tables}\n{criteria}")
}

// --- The harness ---

pub(crate) struct Setup {
    /// Adapter files, built from the port of the fake provider.
    pub adapters: Vec<fn(u16) -> String>,
    pub policy: String,
    pub timing: fn(&mut Timing),
    /// Both IPQS and AbuseIPDB (the replacement rule needs two services).
    pub two_scorers: bool,
    /// Probe targets; a path with `/fine` is never blocked.
    pub probe_targets: Vec<&'static str>,
}

impl Default for Setup {
    fn default() -> Self {
        Self {
            adapters: Vec::new(),
            policy: policy_toml("", ""),
            timing: |_| {},
            two_scorers: false,
            probe_targets: vec!["http://probe.test/probe/ok"],
        }
    }
}

impl Setup {
    /// One adapter and a policy file made of `keys` and `tables` (see
    /// [`policy_toml`]).
    pub(crate) fn new(adapter: fn(u16) -> String, keys: &str, tables: &str) -> Self {
        Self {
            adapters: vec![adapter],
            policy: policy_toml(keys, tables),
            ..Self::default()
        }
    }
}

pub(crate) struct Harness {
    pub w: Arc<Warmer>,
    pub fake: Arc<Fake>,
    pub hot: Hot,
    pub db: Db,
    pub metrics: Arc<Metrics>,
    pub raw: redis::aio::MultiplexedConnection,
    pub settings: Settings,
    loaded_tx: watch::Sender<Arc<Loaded>>,
    _guard: tokio::sync::MutexGuard<'static, ()>,
}

fn redis_url() -> Option<String> {
    let base = std::env::var("PROXYX_TEST_REDIS_URL").ok()?;
    let (scheme, rest) = base.split_once("://")?;
    let authority = rest.split('/').next().unwrap_or(rest);
    let db = rest
        .split_once('/')
        .map(|(_, db)| db)
        .filter(|db| !db.is_empty())
        .unwrap_or(REDIS_DB);
    Some(format!("{scheme}://{authority}/{db}"))
}

/// Create (once) the database `proxyx_warmer_test` and return its URL.
async fn database_url() -> TestResult<Option<String>> {
    Ok(store::testing::backend_database("proxyx_warmer_test", false).await?)
}

impl Harness {
    /// `None` (a skipped test) when the local services are not configured.
    pub(crate) async fn start(setup: Setup) -> TestResult<Option<Self>> {
        let (Some(redis_url), Some(db_url)) = (redis_url(), database_url().await?) else {
            eprintln!("SKIP: PROXYX_TEST_REDIS_URL or the test database variable is not set");
            return Ok(None);
        };
        let guard = SERIAL.lock().await;
        let hot = Hot::connect(&redis_url).await?;
        let mut raw = redis::Client::open(redis_url.as_str())?
            .get_multiplexed_async_connection()
            .await?;
        redis::cmd("FLUSHDB").query_async::<()>(&mut raw).await?;
        let db = Db::connect(&db_url).await?;
        db.migrate().await?;
        let sql = proxyx_db::testing::Raw::connect(&db_url).await?;
        // The audit table is append-only and stays; the rest starts empty,
        // with its ids numbered from 1 again.
        match sql.backend() {
            proxyx_db::Backend::Postgres => {
                sql.execute(
                    "TRUNCATE inventory, ip_scores, ip_blocks RESTART IDENTITY",
                    &[],
                )
                .await?;
            }
            proxyx_db::Backend::MariaDb => {
                for table in ["inventory", "ip_scores", "ip_blocks"] {
                    sql.execute(&format!("TRUNCATE TABLE {table}"), &[]).await?;
                }
            }
            proxyx_db::Backend::Sqlite => {
                for table in ["inventory", "ip_scores", "ip_blocks"] {
                    sql.execute(&format!("DELETE FROM {table}"), &[]).await?;
                }
                sql.execute(
                    "DELETE FROM sqlite_sequence WHERE name IN ('ip_scores', 'ip_blocks')",
                    &[],
                )
                .await?;
            }
        }

        let fake = Fake::start().await?;
        let dir = std::env::temp_dir().join(format!("proxyx-warmer-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(dir.join("secrets"))?;
        let settings = Settings {
            secrets_dir: dir.join("secrets"),
            data_dir: dir.clone(),
            ..Settings::default()
        };

        let mut adapter_configs = Vec::new();
        for make in &setup.adapters {
            adapter_configs.extend(toml::from_str::<AdapterFile>(&make(fake.port))?.adapter);
        }
        let no_secrets = |name: &str| -> anyhow::Result<Secret> {
            anyhow::bail!("test adapters read no secret, asked for {name}")
        };
        let adapters = AdapterSet::from_configs(adapter_configs, &no_secrets)?;
        let policies = PolicySet::from_docs(PolicyFile::parse(&setup.policy)?.policies)?;

        let metrics = Arc::new(Metrics::new("test"));
        let exit_cfg = ExitIpConfig {
            services: [
                (ServiceKind::Ipify, "http://checks.test/ipify"),
                (ServiceKind::Cloudflare, "http://checks.test/cf"),
                (ServiceKind::Ipinfo, "http://checks.test/ipinfo"),
            ]
            .into_iter()
            .map(|(kind, url)| CheckService {
                kind,
                url: url.to_owned(),
            })
            .collect(),
            min_agree: 2,
            timeout: Duration::from_secs(3),
        };
        let account = || ScorerAccount {
            base_url: format!("http://127.0.0.1:{}", fake.port),
            key: Secret::new("key"),
        };
        let mut slots = vec![ScorerSlot {
            scorer: Scorer::Ipqs(account()),
            daily_budget: 10_000,
        }];
        if setup.two_scorers {
            slots.push(ScorerSlot {
                scorer: Scorer::AbuseIpdb(account()),
                daily_budget: 10_000,
            });
        }
        let probe_targets = ProbeTargets::new(
            setup
                .probe_targets
                .iter()
                .map(|u| Url::parse(u))
                .collect::<Result<_, _>>()?,
            HashMap::new(),
        );
        let loaded = Loaded {
            policies,
            adapters,
            probe_targets,
            snapshot: Snapshot::load(&db).await?,
            loaded_at: Instant::now(),
        };
        let (loaded_tx, loaded_rx) = watch::channel(Arc::new(loaded));
        let ctx = WarmerCtx {
            settings: settings.clone(),
            db: db.clone(),
            hot: hot.clone(),
            loaded: loaded_rx,
            metrics: metrics.clone(),
            exit_ip: ExitIpChecker::new(exit_cfg, metrics.clone()),
            reputation: Reputation::new(
                // Fresh scores on every check: a test changes a risk and expects the next check to see it.
                ReputationConfig {
                    cache_ttl: Duration::ZERO,
                    ..ReputationConfig::default()
                },
                slots,
                metrics.clone(),
            )?,
            probe: LightProbe::new(ProbeConfig {
                timeout: Duration::from_secs(3),
                ..ProbeConfig::default()
            }),
            rotate: MobileBoxClient::new()?,
        };
        let mut timing = Timing {
            backoff_base: Duration::ZERO,
            box_poll: Duration::from_millis(50),
            drain_poll: Duration::from_millis(20),
            ..Timing::default()
        };
        (setup.timing)(&mut timing);
        let w = Arc::new(Warmer::new(ctx, timing, CancellationToken::new())?);
        Ok(Some(Self {
            w,
            fake,
            hot,
            db,
            metrics,
            raw,
            settings,
            loaded_tx,
            _guard: guard,
        }))
    }

    /// Publish a fresh snapshot (after the test changed the inventory).
    pub(crate) async fn reload(&self) -> TestResult {
        let current = self.w.loaded();
        self.loaded_tx.send_replace(Arc::new(Loaded {
            policies: current.policies.clone(),
            adapters: current.adapters.clone(),
            probe_targets: current.probe_targets.clone(),
            snapshot: Snapshot::load(&self.db).await?,
            loaded_at: Instant::now(),
        }));
        Ok(())
    }

    pub(crate) fn partition(&self, provider: &str) -> TestResult<Partition> {
        Ok(Partition {
            provider: provider.parse()?,
            region: "fr".parse()?,
        })
    }

    /// Take the locks, then run one rotating reconcile.
    pub(crate) async fn reconcile_tick(&self) {
        self.w.locks_tick().await;
        self.w.reconcile_tick().await;
    }

    /// One rotating reconcile, and wait for the creates it started.
    pub(crate) async fn reconcile(&self) {
        self.reconcile_tick().await;
        self.settle().await;
    }

    /// Wait for the creates and box resets in flight.
    pub(crate) async fn settle(&self) {
        self.w.tracker.close();
        self.w.tracker.wait().await;
        self.w.tracker.reopen();
    }

    pub(crate) async fn static_tick(&self) {
        self.w.locks_tick().await;
        self.w.static_tick().await;
    }

    pub(crate) async fn box_tick(&self) {
        self.w.locks_tick().await;
        self.w.box_tick().await;
    }

    /// Add a static IP or box to the inventory and publish it. Its
    /// credentials file names a user whose exit IP is `ip`.
    pub(crate) async fn add_inventory(
        &self,
        provider: &str,
        subtype: Subtype,
        ip: Ipv4Addr,
        handle: Option<&str>,
    ) -> TestResult {
        let dashed = ip.to_string().replace('.', "-");
        let user = if subtype == Subtype::MobileBox {
            "box".to_owned()
        } else {
            format!("st-{dashed}")
        };
        let secret = format!("cred-{dashed}");
        std::fs::write(
            self.settings.secrets_dir.join(&secret),
            format!("{user}:pw"),
        )?;
        self.fake.set_user_ip(&user, ip);
        let entry = InventoryEntry {
            provider: provider.parse()?,
            subtype,
            plan: "test plan".into(),
            ip: IpAddr::V4(ip),
            host: "127.0.0.1".into(),
            port: self.fake.port,
            region: "fr".parse()?,
            asn: None,
            credentials: (subtype != Subtype::MobileBox).then_some(secret),
            box_handle: handle.map(str::to_owned),
            rental_end: Some("2030-01-01".into()),
        };
        self.db.upsert_inventory_entry(&entry, "test").await?;
        self.reload().await
    }

    pub(crate) async fn row(&self, ip: impl Into<IpAddr>) -> TestResult<InventoryRow> {
        let row = self.db.inventory_row(ip.into()).await?;
        Ok(row.ok_or("inventory row is missing")?)
    }

    /// Move the inventory row of `ip` to another state, as the test.
    pub(crate) async fn transition(
        &self,
        ip: Ipv4Addr,
        change: Transition,
    ) -> TestResult<InventoryRow> {
        Ok(self
            .db
            .transition_ip(IpAddr::V4(ip), &change, "test")
            .await?)
    }

    /// Pretend the last check of `ip` was an hour ago, so the next pass
    /// checks it again.
    pub(crate) async fn make_stale(&self, ip: impl Into<IpAddr>) -> TestResult {
        let an_hour_ago = OffsetDateTime::now_utc() - time::Duration::hours(1);
        self.db.record_check(ip.into(), None, an_hour_ago).await?;
        Ok(())
    }

    pub(crate) async fn counts(&self, p: &Partition) -> TestResult<store::UnitCounts> {
        Ok(self.hot.counts(p).await?)
    }

    // --- The due set ---

    pub(crate) async fn due_jobs(&mut self) -> TestResult<Vec<String>> {
        Ok(redis::cmd("ZRANGE")
            .arg("due")
            .arg(0)
            .arg(-1)
            .query_async(&mut self.raw)
            .await?)
    }

    /// Make every job in the `due` set due now.
    pub(crate) async fn make_due(&mut self) -> TestResult<Vec<String>> {
        let jobs = self.due_jobs().await?;
        for job in &jobs {
            self.due_now(job).await?;
        }
        Ok(jobs)
    }

    async fn due_now(&mut self, job: &str) -> TestResult {
        redis::cmd("ZADD")
            .arg("due")
            .arg(0)
            .arg(job)
            .query_async::<()>(&mut self.raw)
            .await?;
        Ok(())
    }

    /// Swap the job `old` in the `due` set for `new`, due now.
    pub(crate) async fn replace_due(&mut self, old: &str, new: &str) -> TestResult {
        redis::cmd("ZREM")
            .arg("due")
            .arg(old)
            .query_async::<()>(&mut self.raw)
            .await?;
        self.due_now(new).await
    }

    /// Lease from `p` as `org` under the sticky key `sticky`, for `ttl`. The
    /// target is always `example.com:443`.
    pub(crate) async fn lease(
        &self,
        p: &Partition,
        kind: Kind,
        org: &str,
        sticky: &str,
        ttl: Duration,
    ) -> TestResult<LeaseOutcome> {
        let target = Target {
            host: "example.com".into(),
            port: 443,
        };
        let request = LeaseRequest {
            partition: p,
            kind,
            org: &org.parse()?,
            sticky,
            target: &target,
            tunnel: uuid::Uuid::new_v4(),
            pool: Pool::Shared,
            limits: LeaseLimits {
                lease_ttl: ttl,
                tunnel_ttl: Duration::from_secs(60),
                orgs_hard: None,
                max_conns_per_ip: None,
                provider_conns_per_ip: None,
                rest_after_release: Duration::ZERO,
                min_remaining: Duration::ZERO,
                allow_create: false,
            },
        };
        Ok(self
            .hot
            .lease_ranked(&request, &[], store::MAX_RANK)
            .await?)
    }

    /// [`Harness::lease`], which must grant a unit nobody held.
    pub(crate) async fn lease_free(
        &self,
        p: &Partition,
        kind: Kind,
        org: &str,
        sticky: &str,
        ttl: Duration,
    ) -> TestResult<Grant> {
        match self.lease(p, kind, org, sticky, ttl).await? {
            LeaseOutcome::Free(grant) => Ok(grant),
            other => Err(format!("expected a free grant, got {other:?}").into()),
        }
    }
}

pub(crate) fn unix_now() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

pub(crate) fn evictions(h: &Harness, cause: &str) -> u64 {
    h.metrics
        .cache_evictions_total
        .with_label_values(&[cause])
        .get()
}

/// A ready-set record of `id` that exits from `ip` and never expires.
pub(crate) fn unit(id: &str, ip: IpAddr) -> UnitRecord {
    UnitRecord {
        id: id.to_owned(),
        ip,
        expires_at: None,
        ttl: None,
        owner: None,
    }
}

/// Captures the log lines of the test as JSON, one per line.
pub(crate) struct LogCapture {
    buf: Arc<Mutex<Vec<u8>>>,
    _guard: tracing::subscriber::DefaultGuard,
}

struct BufWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for BufWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0.lock().extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl LogCapture {
    /// Install the capture on this thread (the tests run on a current-thread
    /// runtime, so every task logs here).
    pub(crate) fn start() -> Self {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let writer = buf.clone();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::INFO)
            .with_writer(move || BufWriter(writer.clone()))
            .finish();
        Self {
            buf,
            _guard: tracing::subscriber::set_default(subscriber),
        }
    }

    /// The captured events whose message is `message`.
    pub(crate) fn events(&self, message: &str) -> Vec<serde_json::Value> {
        let text = self.text();
        text.lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter(|v| v["fields"]["message"] == message)
            .map(|v| v["fields"].clone())
            .collect()
    }

    pub(crate) fn text(&self) -> String {
        String::from_utf8_lossy(&self.buf.lock()).into_owned()
    }
}
