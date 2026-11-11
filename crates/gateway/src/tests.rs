//! End-to-end tests of the gateway with loopback stubs: a stub provider (an
//! HTTP proxy that tunnels to a stub target and answers exit-IP checks), the
//! local Redis (DB 3) and Postgres. They skip with a message when
//! `PROXYX_TEST_REDIS_URL` or `PROXYX_TEST_DATABASE_URL` is unset.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::Secret;
use common::config::Settings;
use common::metrics::Metrics;
use common::retry::{BreakerConfig, BreakerState};
use common::types::{InventoryEntry, IpState, OrgId, Partition, Subtype, Tier};
use parking_lot::Mutex;
use policy::{PolicyFile, PolicySet};
use provider::{AdapterFile, AdapterSet};
use store::loaded::{Loaded, ProbeTargets};
use store::{
    Admit, BlockScope, Db, ExitIpClaim, Hot, InventoryRow, Phase, SessionJob, Snapshot, UnitRecord,
};
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use verify::{
    CheckService, ExitIpChecker, ExitIpConfig, LightProbe, ProbeConfig, Reputation,
    ReputationConfig, Scorer, ScorerAccount, ScorerSlot, ServiceKind, Url,
};

use crate::gateway::Pacing;
use crate::{Bound, GatewayCtx, Tunnels, run_bound};

type BoxErr = Box<dyn std::error::Error>;
type TestResult = Result<(), BoxErr>;

const REDIS_DB: &str = "3";
const PROVIDER_USER: &str = "provuser";
const PROVIDER_PASS: &str = "provpass";

fn uniq(prefix: &str) -> String {
    format!("{prefix}{}", &Uuid::new_v4().simple().to_string()[..10])
}

/// An address in 198.18.0.0/15 that no other run is likely to use.
fn uniq_ip() -> IpAddr {
    let b = Uuid::new_v4();
    let b = b.as_bytes();
    IpAddr::from([198, 18 + (b[0] & 1), b[1], b[2].max(1)])
}

// --- stubs ---

/// What the stub provider saw.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seen {
    /// A CONNECT with the requested target and the decoded `user:password`.
    Connect { target: String, login: String },
    /// An exit-IP check (plain GET through the proxy).
    Check,
}

struct StubProvider {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl StubProvider {
    fn connects(&self) -> Vec<(String, String)> {
        self.seen
            .lock()
            .iter()
            .filter_map(|s| match s {
                Seen::Connect { target, login } => Some((target.clone(), login.clone())),
                Seen::Check => None,
            })
            .collect()
    }

    fn checks(&self) -> usize {
        self.seen
            .lock()
            .iter()
            .filter(|s| **s == Seen::Check)
            .count()
    }
}

async fn read_head(s: &mut TcpStream) -> Option<String> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(s.read_u8().await.ok()?);
        if head.len() > 16 * 1024 {
            return None;
        }
    }
    String::from_utf8(head).ok()
}

/// Run `handler` on every connection `listener` accepts.
fn serve_on<F, Fut>(listener: TcpListener, handler: F)
where
    F: Fn(TcpStream) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        while let Ok((s, _)) = listener.accept().await {
            tokio::spawn(handler(s));
        }
    });
}

/// [`serve_on`] on a fresh loopback port.
async fn serve<F, Fut>(handler: F) -> SocketAddr
where
    F: Fn(TcpStream) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind stub");
    let addr = listener.local_addr().expect("stub addr");
    serve_on(listener, handler);
    addr
}

/// A reserved loopback port with no listener. The bound socket prevents
/// parallel test stubs from reusing a supposedly unreachable endpoint.
struct ClosedEndpoint(socket2::Socket);

impl ClosedEndpoint {
    fn addr(&self) -> SocketAddr {
        self.0
            .local_addr()
            .expect("bound address")
            .as_socket()
            .expect("TCP address")
    }

    fn port(&self) -> u16 {
        self.addr().port()
    }

    fn listen(self) -> std::io::Result<TcpListener> {
        self.0.listen(1024)?;
        self.0.set_nonblocking(true)?;
        TcpListener::from_std(self.0.into())
    }
}

fn closed_endpoint() -> ClosedEndpoint {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )
    .expect("TCP socket");
    socket
        .bind(
            &"127.0.0.1:0"
                .parse::<SocketAddr>()
                .expect("loopback")
                .into(),
        )
        .expect("bind reserved endpoint");
    ClosedEndpoint(socket)
}

#[tokio::test]
async fn closed_endpoint_refuses_connections_and_reserves_its_port_until_revived() {
    let endpoint = closed_endpoint();
    let addr = endpoint.addr();
    let error = TcpStream::connect(addr).await.expect_err("not listening");
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionRefused);
    assert!(
        TcpListener::bind(addr).await.is_err(),
        "port remains reserved"
    );
    let listener = endpoint.listen().expect("revive the reserved socket");
    let stream = TcpStream::connect(addr).await.expect("revived listener");
    let _accepted = listener.accept().await.expect("accept");
    drop(stream);
}

/// Answer with a complete `Connection: close` reply and end the connection.
async fn respond(s: &mut TcpStream, status: &str, body: &str) {
    let reply = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = s.write_all(reply.as_bytes()).await;
    let _ = s.shutdown().await;
}

/// The request line and the decoded `user:password` of a proxy request head.
fn request_and_login(head: &str) -> (String, String) {
    let mut lines = head.split("\r\n");
    let first = lines.next().unwrap_or_default().to_owned();
    let login = lines
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.eq_ignore_ascii_case("proxy-authorization"))
        .and_then(|(_, v)| v.trim().strip_prefix("Basic "))
        .and_then(|b| STANDARD.decode(b.trim()).ok())
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_default();
    (first, login)
}

/// Answer `200` to the client and copy bytes both ways until one side ends.
async fn splice(mut client: TcpStream, mut upstream: TcpStream) {
    if client
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await
        .is_ok()
    {
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    }
}

/// An HTTP proxy that accepts one login (`user_prefix*` : `pass`), tunnels
/// every CONNECT to `target` whatever host was asked, and answers plain GETs
/// as an exit-IP service for `exit_ip`.
async fn stub_provider(pass: &str, target: SocketAddr, exit_ip: IpAddr) -> StubProvider {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind provider");
    stub_provider_on(listener, pass, target, exit_ip)
}

/// [`stub_provider`] on a listener the test bound itself.
fn stub_provider_on(
    listener: TcpListener,
    pass: &str,
    target: SocketAddr,
    exit_ip: IpAddr,
) -> StubProvider {
    let addr = listener.local_addr().expect("provider addr");
    let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
    let (task_seen, pass, exit_ip) = (Arc::clone(&seen), pass.to_owned(), exit_ip.to_string());
    serve_on(listener, move |mut s| {
        let (seen, pass, exit_ip) = (Arc::clone(&task_seen), pass.clone(), exit_ip.clone());
        async move {
            let Some(head) = read_head(&mut s).await else {
                return;
            };
            let (first, login) = request_and_login(&head);
            let ok = login.starts_with(PROVIDER_USER) && login.ends_with(&format!(":{pass}"));
            if !ok {
                respond(&mut s, "407 Proxy Authentication Required", "").await;
                return;
            }
            let mut parts = first.split(' ');
            match (parts.next(), parts.next()) {
                (Some("CONNECT"), Some(requested)) => {
                    seen.lock().push(Seen::Connect {
                        target: requested.to_owned(),
                        login,
                    });
                    match TcpStream::connect(target).await {
                        Ok(upstream) => splice(s, upstream).await,
                        Err(_) => {
                            let _ = s.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                        }
                    }
                }
                _ => {
                    seen.lock().push(Seen::Check);
                    if first.contains("/blocked") {
                        respond(&mut s, "403 Forbidden", "please solve this captcha").await;
                    } else {
                        if first.contains("/slow") {
                            sleep(Duration::from_millis(150)).await;
                        }
                        let body = format!(r#"{{"ip":"{exit_ip}","country":"fr"}}"#);
                        respond(&mut s, "200 OK", &body).await;
                    }
                }
            }
        }
    });
    StubProvider { addr, seen }
}

/// A target that answers `pong:<bytes>` to every chunk it receives.
async fn stub_target() -> SocketAddr {
    serve(|mut s| async move {
        let mut buf = [0u8; 1024];
        while let Ok(n) = s.read(&mut buf).await {
            if n == 0 {
                return;
            }
            let mut reply = b"pong:".to_vec();
            reply.extend_from_slice(&buf[..n]);
            if s.write_all(&reply).await.is_err() {
                return;
            }
        }
    })
    .await
}

/// A fraud-score scorer that gives every IP the risk `risk`.
async fn stub_scorer(risk: u32) -> SocketAddr {
    serve(move |mut s| async move {
        if read_head(&mut s).await.is_some() {
            let body = format!(r#"{{"success":true,"fraud_score":{risk},"tor":false}}"#);
            respond(&mut s, "200 OK", &body).await;
        }
    })
    .await
}

// --- harness ---

struct Env {
    redis_url: String,
}

fn env() -> Option<Env> {
    let redis = std::env::var("PROXYX_TEST_REDIS_URL").ok();
    let database_var = proxyx_db::testing::env_var(proxyx_db::testing::selected());
    let database = std::env::var(database_var).ok();
    let (Some(redis), Some(_)) = (redis, database) else {
        eprintln!("SKIP: PROXYX_TEST_REDIS_URL and {database_var} must be set");
        return None;
    };
    let (scheme, rest) = redis.split_once("://")?;
    let authority = rest.split('/').next().unwrap_or(rest);
    // the database index of the URL when it names one
    let db = rest
        .split_once('/')
        .map(|(_, db)| db)
        .filter(|db| !db.is_empty())
        .unwrap_or(REDIS_DB);
    Some(Env {
        redis_url: format!("{scheme}://{authority}/{db}"),
    })
}

/// Create (once) and migrate `proxyx_gateway_test`.
async fn test_db() -> Result<Db, BoxErr> {
    let url = store::testing::backend_database("proxyx_gateway_test", false)
        .await?
        .ok_or("the test database is not configured")?;
    let db = Db::connect(&url).await?;
    db.migrate().await?;
    Ok(db)
}

/// One test's world: ids no other test uses, a stub target and provider.
struct Setup {
    provider: String,
    org: OrgId,
    key: String,
    probe_org: OrgId,
    probe_key: String,
    /// What the probe listener's tokens are signed with.
    probe_secret: String,
    /// A second org with a key, for isolation tests.
    rival: OrgId,
    rival_key: String,
    /// Logins of customer upstreams in the snapshot, by owner org.
    customer_logins: std::collections::HashMap<OrgId, store::CustomerLogin>,
    /// Global policy fields beyond `regions`, as TOML lines.
    policy: String,
    /// `[[policy]]` tables after the global one.
    extra_policies: String,
    kinds: &'static str,
    /// The global policy's `regions`, as a TOML list.
    regions: &'static str,
    /// Gateway settings; the listeners and the probe org are set by [`start`].
    settings: Settings,
    check: bool,
    adapter_toml: Option<String>,
    pacing: Pacing,
    /// Risk the one reputation scorer gives every IP. `None`: no scorer is on,
    /// so `on_score_unavailable` decides.
    scorer_risk: Option<u32>,
    /// Light-probe targets of every region.
    probe_targets: Vec<&'static str>,
}

impl Setup {
    fn new() -> Self {
        Self {
            provider: uniq("p"),
            org: uniq("org-").parse().expect("org id"),
            key: uniq("key"),
            probe_org: uniq("probe-").parse().expect("probe org id"),
            probe_key: uniq("pkey"),
            probe_secret: uniq("psecret"),
            rival: uniq("rival-").parse().expect("rival org id"),
            rival_key: uniq("rkey"),
            customer_logins: std::collections::HashMap::new(),
            policy: String::new(),
            extra_policies: String::new(),
            kinds: r#"["static", "rotating"]"#,
            regions: r#"["fr"]"#,
            settings: Settings {
                drain_timeout: Duration::from_secs(5),
                ..Settings::default()
            },
            check: false,
            adapter_toml: None,
            pacing: Pacing::default(),
            scorer_risk: None,
            probe_targets: vec![],
        }
    }

    fn partition(&self) -> Partition {
        Partition {
            provider: self.provider.parse().expect("provider id"),
            region: "fr".parse().expect("region"),
        }
    }

    fn static_adapter(&self, ports: &str) -> String {
        static_adapter_toml(&self.provider, ports)
    }

    fn rotating_adapter(&self, port: u16) -> String {
        format!(
            r#"[[adapter]]
id = "{}"
kind = "rotating"
subtype = "residential"
host = "127.0.0.1"
port = {port}
user_file = "u"
pass_file = "p"
user = "{{base_user}}{{opts}}"
pass = "{{base_pass}}"
max_session_minutes = 60

[[adapter.option]]
name = "country"
to = "user"
frag = "-cc-{{v}}"
case = "upper"

[[adapter.option]]
name = "sid"
to = "user"
frag = "-sid-{{v}}"
charset = "alnum"
len = 12

[[adapter.option]]
name = "ttl"
to = "user"
frag = "-t-{{v}}"
unit = "min"
max = 60
"#,
            self.provider
        )
    }

    /// Create on demand in front of the stub provider at `port`, with the
    /// exit-IP check on.
    fn rotating_via(&mut self, port: u16) {
        self.kinds = r#"["rotating"]"#;
        self.check = true;
        self.adapter_toml = Some(self.rotating_adapter(port));
    }
}

/// One static adapter `id`; `ports` is its `allowed_ports` as a TOML list.
fn static_adapter_toml(id: &str, ports: &str) -> String {
    format!(
        r#"[[adapter]]
id = "{id}"
kind = "static"
subtype = "isp"
user_file = "u"
pass_file = "p"
user = "{{base_user}}"
pass = "{{base_pass}}"
allowed_ports = {ports}
"#
    )
}

struct Harness {
    connect: SocketAddr,
    socks: SocketAddr,
    probe: SocketAddr,
    cancel: CancellationToken,
    task: JoinHandle<anyhow::Result<()>>,
    hot: Hot,
    metrics: Arc<Metrics>,
    tunnels: Tunnels,
    // publishes snapshots, and keeps the channel open
    loaded: watch::Sender<Arc<Loaded>>,
    /// The file of the probe secret, removed with the harness.
    _probe_secret: RemoveOnDrop,
}

struct RemoveOnDrop(std::path::PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn entry(setup: &Setup, ip: IpAddr, provider_port: u16) -> InventoryEntry {
    InventoryEntry {
        provider: setup.provider.parse().expect("provider id"),
        subtype: Subtype::Isp,
        plan: "test".into(),
        ip,
        host: "127.0.0.1".into(),
        port: provider_port,
        region: "fr".parse().expect("region"),
        asn: None,
        credentials: None,
        box_handle: None,
        rental_end: None,
    }
}

fn row(entry: &InventoryEntry, checked: bool) -> InventoryRow {
    let now = OffsetDateTime::now_utc();
    InventoryRow {
        entry: entry.clone(),
        state: IpState::Available,
        state_since: now,
        cooldown_until: None,
        quarantined_at: None,
        retest_at: None,
        offline_since: None,
        last_check_at: checked.then_some(now),
        exit_ip: None,
        owner: None,
    }
}

/// The snapshot a gateway of `setup` sees: the stub provider's adapter, the
/// global policy and `inventory`.
fn loaded_for(setup: &Setup, inventory: Vec<InventoryRow>) -> Result<Loaded, BoxErr> {
    let adapter_toml = setup
        .adapter_toml
        .clone()
        .unwrap_or_else(|| setup.static_adapter("[]"));
    let adapters = AdapterSet::from_configs(
        toml::from_str::<AdapterFile>(&adapter_toml)?.adapter,
        &|name: &str| match name {
            "u" => Ok(Secret::new(PROVIDER_USER)),
            "p" => Ok(Secret::new(PROVIDER_PASS)),
            other => Err(anyhow::anyhow!("no secret {other}")),
        },
    )?;
    let policy_text = format!(
        "[[policy]]\nname = \"global\"\nkinds = {}\nregions = {}\nmin_ready = 1\nmax_ready = 2\n\
         lease_ttl = \"10m\"\nlease_wait = \"1s\"\ncreate_deadline = \"3s\"\n{}\n{}",
        setup.kinds, setup.regions, setup.policy, setup.extra_policies
    );
    let policies = PolicySet::from_docs(PolicyFile::parse(&policy_text)?.policies)?;
    Ok(Loaded {
        policies,
        adapters,
        // every test connects to `example.test`; the probe listener may open it
        probe_targets: ProbeTargets::new(
            setup
                .probe_targets
                .iter()
                .map(|t| Url::parse(t))
                .collect::<Result<_, _>>()?,
            Default::default(),
        )
        .with_extra_hosts(&["example.test".to_owned()])?,
        snapshot: Snapshot {
            policies: Vec::new().into(),
            inventory,
            customer_logins: setup.customer_logins.clone(),
            loaded_at: OffsetDateTime::now_utc(),
        },
        loaded_at: std::time::Instant::now(),
    })
}

/// Start a gateway for `setup` with `inventory` rows in the snapshot, the
/// stub provider's adapter and the keys of `setup` in Postgres.
async fn start(env: &Env, setup: &Setup, inventory: Vec<InventoryRow>) -> Result<Harness, BoxErr> {
    let db = test_db().await?;
    for (org, key) in [
        (&setup.org, &setup.key),
        (&setup.probe_org, &setup.probe_key),
        (&setup.rival, &setup.rival_key),
    ] {
        db.add_org_key(org, &Secret::new(key.clone()), "test", "test")
            .await?;
    }
    let hot = Hot::connect(&env.redis_url).await?;

    let loaded = loaded_for(setup, inventory)?;
    let (tx, rx) = watch::channel(Arc::new(loaded));

    let metrics = Arc::new(Metrics::new("test"));
    let mut cfg = ExitIpConfig {
        services: vec![],
        min_agree: 1,
        timeout: Duration::from_secs(2),
    };
    if setup.check {
        cfg.services.push(CheckService {
            kind: ServiceKind::IpJson,
            url: "http://check.test/ip".into(),
        });
    }
    let exit_ip = ExitIpChecker::new(cfg, Arc::clone(&metrics));
    let mut slots = vec![];
    if let Some(risk) = setup.scorer_risk {
        slots.push(ScorerSlot {
            scorer: Scorer::FraudScore(ScorerAccount {
                base_url: format!("http://{}", stub_scorer(risk).await),
                key: Secret::new("key"),
            }),
            daily_budget: 1_000,
        });
    }
    let reputation = Reputation::new(ReputationConfig::default(), slots, Arc::clone(&metrics))?;

    let any: SocketAddr = "127.0.0.1:0".parse()?;
    let probe_secret_file = std::env::temp_dir().join(format!("proxyx-{}", setup.probe_secret));
    std::fs::write(&probe_secret_file, &setup.probe_secret)?;
    let probe_secret_guard = RemoveOnDrop(probe_secret_file.clone());
    let settings = Settings {
        connect_listen: any,
        socks_listen: any,
        probe_listen: any,
        probe_org: setup.probe_org.to_string(),
        probe_key_file: probe_secret_file,
        ..setup.settings.clone()
    };
    let bound = Bound::bind(&settings).await?;
    let [connect, socks, probe] = bound.addrs()?;
    let tunnels = Tunnels::default();
    let ctx = GatewayCtx {
        settings,
        db,
        hot: hot.clone(),
        loaded: rx,
        metrics: Arc::clone(&metrics),
        exit_ip,
        reputation,
        probe: LightProbe::new(ProbeConfig::default()),
        tunnels: tunnels.clone(),
    };
    let cancel = CancellationToken::new();
    let task = tokio::spawn(run_bound(ctx, bound, cancel.clone(), setup.pacing));
    Ok(Harness {
        connect,
        socks,
        probe,
        cancel,
        task,
        hot,
        metrics,
        tunnels,
        loaded: tx,
        _probe_secret: probe_secret_guard,
    })
}

impl Harness {
    /// Connections of `listener` that ended in `outcome`, whichever provider
    /// served them.
    fn connections(&self, listener: &str, outcome: &str) -> u64 {
        let wanted = format!("listener=\"{listener}\",outcome=\"{outcome}\",provider=\"");
        self.metrics
            .render()
            .lines()
            .filter(|l| l.starts_with("proxyx_pool_connections_total{") && l.contains(&wanted))
            .filter_map(|l| l.rsplit(' ').next()?.parse::<u64>().ok())
            .sum()
    }

    /// A snapshot reload: the gateway sees `loaded` from now on.
    fn reload(&self, loaded: Loaded) {
        self.loaded.send_replace(Arc::new(loaded));
    }

    /// Put the static unit `ip` in the ready set of `partition`.
    async fn ready(&self, partition: &Partition, ip: IpAddr) -> Result<(), BoxErr> {
        self.hot
            .ready_put(partition, &UnitRecord::static_ip(ip))
            .await?;
        Ok(())
    }
}

/// A breaker that opens after `failures_to_open` failures and does not probe
/// within a test.
fn breaker(failures_to_open: u32) -> BreakerConfig {
    BreakerConfig {
        failures_to_open,
        window: Duration::from_secs(60),
        first_probe_after: Duration::from_secs(60),
        max_probe_after: Duration::from_secs(60),
        passes_to_close: 2,
    }
}

// --- clients ---

struct Reply {
    status: u16,
    reason: String,
    headers: Vec<(String, String)>,
    stream: TcpStream,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Status and reason of the reply.
    fn answer(&self) -> (u16, &str) {
        (self.status, self.reason.as_str())
    }
}

/// A token the probe listener of a gateway of `setup` accepts.
fn probe_token(setup: &Setup) -> String {
    common::probe_token::issue(
        &Secret::new(setup.probe_secret.clone()),
        std::time::SystemTime::now(),
    )
    .expose()
    .to_owned()
}

/// CONNECT to `example.test:443`.
async fn connect_via(proxy: SocketAddr, username: &str, key: &str) -> Result<Reply, BoxErr> {
    connect_to(proxy, "example.test:443", username, key).await
}

async fn connect_to(
    proxy: SocketAddr,
    target: &str,
    username: &str,
    key: &str,
) -> Result<Reply, BoxErr> {
    connect_on(TcpStream::connect(proxy).await?, target, username, key).await
}

/// CONNECT to `target` on a connection that is already open.
async fn connect_on(
    mut s: TcpStream,
    target: &str,
    username: &str,
    key: &str,
) -> Result<Reply, BoxErr> {
    let auth = STANDARD.encode(format!("{username}:{key}"));
    s.write_all(
        format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic {auth}\r\n\r\n")
            .as_bytes(),
    )
    .await?;
    let head = timeout(Duration::from_secs(12), read_head(&mut s))
        .await?
        .ok_or("no reply head")?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().ok_or("empty reply")?;
    let mut parts = status_line.splitn(3, ' ');
    parts.next();
    let status = parts.next().ok_or("no status")?.parse()?;
    let reason = parts.next().unwrap_or_default().to_owned();
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect();
    Ok(Reply {
        status,
        reason,
        headers,
        stream: s,
    })
}

async fn ping<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, msg: &str) -> Result<String, BoxErr> {
    s.write_all(msg.as_bytes()).await?;
    let mut buf = vec![0u8; "pong:".len() + msg.len()];
    timeout(Duration::from_secs(5), s.read_exact(&mut buf)).await??;
    Ok(String::from_utf8(buf)?)
}

/// Poll `cond` for up to 5 s.
async fn eventually<F, Fut>(what: &str, mut cond: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    for _ in 0..100 {
        if cond().await {
            return;
        }
        sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {what}");
}

/// Poll until a CONNECT with `key` is served.
async fn eventually_served(what: &str, h: &Harness, key: &str) {
    eventually(what, || async {
        matches!(connect_via(h.connect, "px", key).await, Ok(r) if r.status == 200)
    })
    .await;
}

/// True when no tunnel is open in this pod and the org holds no slot.
async fn tunnels_closed(h: &Harness, org: &OrgId) -> bool {
    h.tunnels.count() == 0 && h.hot.org_tunnel_count(org).await.is_ok_and(|n| n == 0)
}

/// A static partition with a checked (or not) inventory row of a unit in
/// front of the provider at `addr`, not yet in the ready set. Returns the
/// unit's IP.
async fn unready_unit(
    env: &Env,
    setup: &Setup,
    addr: SocketAddr,
    checked: bool,
) -> Result<(Harness, IpAddr), BoxErr> {
    let ip = uniq_ip();
    let e = entry(setup, ip, addr.port());
    let h = start(env, setup, vec![row(&e, checked)]).await?;
    Ok((h, ip))
}

/// [`unready_unit`] with the unit in the ready set: a leasable unit.
async fn static_unit(
    env: &Env,
    setup: &Setup,
    addr: SocketAddr,
    checked: bool,
) -> Result<(Harness, IpAddr), BoxErr> {
    let (h, ip) = unready_unit(env, setup, addr, checked).await?;
    h.ready(&setup.partition(), ip).await?;
    Ok((h, ip))
}

/// [`static_unit`] with a checked row in front of a fresh stub provider that
/// tunnels to `target`.
async fn unit_for(
    env: &Env,
    setup: &Setup,
    target: SocketAddr,
) -> Result<(Harness, StubProvider, IpAddr), BoxErr> {
    let provider = stub_provider(PROVIDER_PASS, target, uniq_ip()).await;
    let (h, ip) = static_unit(env, setup, provider.addr, true).await?;
    Ok((h, provider, ip))
}

/// [`unit_for`] a fresh stub target.
async fn static_fixture(
    env: &Env,
    setup: &Setup,
) -> Result<(Harness, StubProvider, IpAddr), BoxErr> {
    unit_for(env, setup, stub_target().await).await
}

/// Bytes metered today against `provider`.
async fn metered_bytes(h: &Harness, provider: &str) -> Result<u64, BoxErr> {
    let id = provider.parse()?;
    let used = h.hot.cost_used(&id, OffsetDateTime::now_utc()).await?;
    Ok(used.bytes_today)
}

mod acquire_race;
mod affinity;
mod affinity_rotate;
mod authlimit;
mod customer;
mod hardening;
mod limits;
mod local;
mod phase6;
mod r4;
mod w5;
mod walk;

// --- tests ---

#[tokio::test]
async fn connect_through_a_static_lease_relays_bytes_both_ways() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let setup = Setup::new();
    let (h, provider, ip) = static_fixture(&env, &setup).await?;

    let mut r = connect_via(h.connect, "px", &setup.key).await?;
    assert_eq!(r.answer(), (200, "Connection established"));
    assert_eq!(r.header("X-ProxyX-Exit-IP"), Some(ip.to_string().as_str()));
    let session = r
        .header("X-ProxyX-Pool-Session")
        .expect("session header")
        .to_owned();
    assert!(!session.is_empty());

    assert_eq!(ping(&mut r.stream, "hello").await?, "pong:hello");
    assert_eq!(
        ping(&mut r.stream, "again").await?,
        "pong:again",
        "the tunnel stays open"
    );
    assert_eq!(
        provider.connects(),
        vec![(
            "example.test:443".to_owned(),
            format!("{PROVIDER_USER}:{PROVIDER_PASS}")
        )],
        "the provider got the target and the rendered credential, not the org key"
    );

    // the session id resolves to this org, unit and exit IP (control API correlation)
    let record = h.hot.session_get(&session).await?.expect("session record");
    assert_eq!(record.org, setup.org);
    assert_eq!(
        (record.unit.as_str(), record.ip),
        (ip.to_string().as_str(), ip)
    );
    assert_eq!(h.tunnels.count(), 1);
    assert_eq!(h.metrics.tunnels_open.get(), 1);
    assert_eq!(h.hot.org_tunnel_count(&setup.org).await?, 1);
    assert_eq!(h.connections("connect", "ok"), 1);

    drop(r);
    eventually("the tunnel to close", || tunnels_closed(&h, &setup.org)).await;
    let load = h.hot.unit_load(&setup.partition(), &ip.to_string()).await?;
    assert_eq!(load.tunnels, 0, "the unit counter is closed too");
    assert_eq!(h.metrics.tunnels_open.get(), 0);
    Ok(())
}

#[tokio::test]
async fn wrong_or_missing_key_gets_407_and_never_reaches_the_provider() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let setup = Setup::new();
    let (h, provider, _) = static_fixture(&env, &setup).await?;

    let r = connect_via(h.connect, "px", "not-a-key").await?;
    assert_eq!(r.answer(), (407, "auth_required"));
    assert!(r.header("Proxy-Authenticate").is_some());

    // no Proxy-Authorization at all
    let mut s = TcpStream::connect(h.connect).await?;
    s.write_all(b"CONNECT example.test:443 HTTP/1.1\r\n\r\n")
        .await?;
    let head = read_head(&mut s).await.expect("reply");
    assert!(head.starts_with("HTTP/1.1 407 auth_required\r\n"), "{head}");

    assert!(provider.connects().is_empty());
    assert_eq!(h.connections("connect", "auth_required"), 2);
    Ok(())
}

#[tokio::test]
async fn a_full_pod_closes_new_connections_until_one_ends() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.settings.max_connections = 1;
    let (h, _, _) = static_fixture(&env, &setup).await?;

    // the one permit is held by an open tunnel
    let mut open = connect_via(h.connect, "px", &setup.key).await?;
    assert_eq!(open.status, 200, "{}", open.reason);

    let mut second = TcpStream::connect(h.connect).await?;
    let _ = second
        .write_all(b"CONNECT example.test:443 HTTP/1.1\r\n\r\n")
        .await;
    let head = timeout(Duration::from_secs(5), read_head(&mut second)).await?;
    assert!(
        head.is_none(),
        "a full pod closes without a reply: {head:?}"
    );
    assert_eq!(h.connections("connect", "over_limit"), 1);
    // a tunnel that is already open is not touched
    assert!(open.stream.write_all(b"x").await.is_ok());

    drop(open);
    eventually("a permit to be free again", || async {
        matches!(
            connect_via(h.connect, "px", "not-a-key").await,
            Ok(r) if r.status == 407
        )
    })
    .await;
    Ok(())
}

#[tokio::test]
async fn disabled_org_key_gets_403_org_disabled_and_never_reaches_the_provider() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let setup = Setup::new();
    let (h, provider, _) = static_fixture(&env, &setup).await?;
    test_db()
        .await?
        .disable_org_keys(&setup.org, "test")
        .await?;

    let r = connect_via(h.connect, "px", &setup.key).await?;
    assert_eq!(r.answer(), (403, "org_disabled"));
    assert!(
        r.header("Proxy-Authenticate").is_none(),
        "a disabled key is not asked to retry"
    );
    let unknown = connect_via(h.connect, "px", "not-a-key").await?;
    assert_eq!(unknown.status, 407, "an unknown key stays a 407");

    assert!(provider.connects().is_empty());
    assert_eq!(h.connections("connect", "org_disabled"), 1);
    Ok(())
}

/// An org key of the probe org (one an operator registered, or
/// the old static probe key) is not a password on the probe listener or on
/// any other: only a signed token is, and only on the probe listener.
#[tokio::test]
async fn the_probe_orgs_own_key_logs_in_nowhere_and_the_secret_is_no_password() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let setup = Setup::new();
    let (h, provider, _) = static_fixture(&env, &setup).await?;

    for listener in [h.probe, h.connect] {
        let r = connect_via(listener, "px", &setup.probe_key).await?;
        assert_eq!(r.answer(), (407, "auth_required"));
        assert!(r.header("Proxy-Authenticate").is_some());
    }
    let r = connect_via(h.probe, "px", &setup.probe_secret).await?;
    assert_eq!(r.answer(), (407, "auth_required"));
    assert_eq!(h.connections("probe", "auth_required"), 2);
    assert_eq!(h.connections("connect", "auth_required"), 1);
    assert!(provider.connects().is_empty());
    Ok(())
}

/// A token of another secret, an expired one and a malformed
/// one are refused with `407`.
#[tokio::test]
async fn the_probe_listener_refuses_a_foreign_expired_or_malformed_token() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let setup = Setup::new();
    let (h, provider, _) = static_fixture(&env, &setup).await?;

    let foreign = common::probe_token::issue(&Secret::new("another"), std::time::SystemTime::now());
    let expired = common::probe_token::issue(
        &Secret::new(setup.probe_secret.clone()),
        std::time::SystemTime::now() - common::probe_token::TOKEN_TTL - Duration::from_secs(5),
    );
    for bad in [foreign.expose(), expired.expose(), "pt1.1.2", ""] {
        let r = connect_via(h.probe, "px", bad).await?;
        assert_eq!(r.answer(), (407, "auth_required"), "{bad:?}");
    }
    assert!(provider.connects().is_empty());
    Ok(())
}

/// A valid token opens the hosts of the probe targets only; any
/// other host, port or address answers `403 destination_denied` and never
/// reaches the provider.
#[tokio::test]
async fn the_probe_listener_opens_only_the_probe_target_hosts() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let setup = Setup::new();
    let (h, provider, _) = static_fixture(&env, &setup).await?;
    let token = probe_token(&setup);

    for target in [
        "other.test:443",
        "example.test:22",
        "127.0.0.1:443",
        "169.254.169.254:80",
    ] {
        let r = connect_to(h.probe, target, "px", &token).await?;
        assert_eq!(r.answer(), (403, "destination_denied"), "{target}");
    }
    assert_eq!(h.connections("probe", "destination_denied"), 4);
    assert!(provider.connects().is_empty());

    let ok = connect_to(h.probe, "www.example.test:80", "px", &token).await?;
    assert_eq!(ok.status, 200);
    // the customer listener is not narrowed
    let other = connect_to(h.connect, "other.test:443", "px", &setup.key).await?;
    assert_eq!(other.status, 200);
    Ok(())
}

#[tokio::test]
async fn an_open_route_class_is_skipped_for_the_next_provider_probed_and_closed_again() -> TestResult
{
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    // "dead" sorts before "live", so the walk tries it first
    let (dead_id, live_id) = (setup.provider.clone(), format!("{}b", setup.provider));
    setup.adapter_toml = Some(format!(
        "{}{}",
        static_adapter_toml(&dead_id, "[]"),
        static_adapter_toml(&live_id, "[]")
    ));
    let cfg = BreakerConfig {
        first_probe_after: Duration::from_millis(400),
        max_probe_after: Duration::from_millis(400),
        ..breaker(2)
    };
    setup.pacing.breaker = cfg;
    let target = stub_target().await;
    let live = stub_provider(PROVIDER_PASS, target, uniq_ip()).await;
    // the dead provider: a port nothing listens on
    let dead_addr = closed_endpoint();
    // Two dead IPs: one dead IP no longer opens the route class, the
    // failure of a second one does
    let (dead_ip, dead_ip2, live_ip) = (uniq_ip(), uniq_ip(), uniq_ip());
    let dead_entry = entry(&setup, dead_ip, dead_addr.port());
    let dead_entry2 = entry(&setup, dead_ip2, dead_addr.port());
    let mut live_entry = entry(&setup, live_ip, live.addr.port());
    live_entry.provider = live_id.parse()?;
    let h = start(
        &env,
        &setup,
        vec![
            row(&dead_entry, true),
            row(&dead_entry2, true),
            row(&live_entry, true),
        ],
    )
    .await?;
    let dead_p = setup.partition();
    let live_p = Partition {
        provider: live_id.parse()?,
        region: "fr".parse()?,
    };
    let ready_dead = || async {
        for ip in [dead_ip, dead_ip2] {
            h.ready(&dead_p, ip).await?;
        }
        Ok::<_, BoxErr>(())
    };
    ready_dead().await?;
    h.ready(&live_p, live_ip).await?;
    let exit_of = |r: &Reply| r.header("X-ProxyX-Exit-IP").map(str::to_owned);
    let skipped = || {
        h.metrics
            .breaker_skips_total
            .with_label_values(&[dead_id.as_str()])
            .get()
    };
    // a sticky key of its own for each tunnel: a key that was served by the next
    // provider stays there for a minute, and would never try the dead one
    let next = std::cell::Cell::new(0);
    let (addr, key) = (h.connect, setup.key.clone());
    let tunnel = || {
        next.set(next.get() + 1);
        let (sid, key) = (format!("px-sid-o{}", next.get()), key.clone());
        async move { connect_via(addr, &sid, &key).await }
    };

    // Each tunnel fails on the dead provider once, however many of its IPs it
    // Tries: the first leaves the route class closed, the second opens
    // it. Both are still served by the next provider.
    let r = tunnel().await?;
    assert_eq!(exit_of(&r), Some(live_ip.to_string()), "{}", r.reason);
    assert_eq!(
        h.hot.breaker_peek(&dead_p, &cfg).await?.0,
        BreakerState::Closed
    );
    ready_dead().await?;
    let r = tunnel().await?;
    assert_eq!(exit_of(&r), Some(live_ip.to_string()), "{}", r.reason);
    assert_eq!(
        h.hot.breaker_peek(&dead_p, &cfg).await?.0,
        BreakerState::Open
    );
    assert_eq!(skipped(), 0, "the two failures were real dials");

    // Open: the walk skips the route class without dialing it.
    let r = tunnel().await?;
    assert_eq!(exit_of(&r), Some(live_ip.to_string()));
    assert_eq!(skipped(), 1);
    assert_eq!(
        h.metrics
            .warm_creates_total
            .with_label_values(&[dead_id.as_str(), "breaker"])
            .get(),
        0,
        "walking past an open route class is not a session create"
    );

    // The probe is due, the provider is still dead: it fails, the route
    // class reopens and the tunnel falls back again.
    sleep(Duration::from_millis(450)).await;
    ready_dead().await?;
    let r = tunnel().await?;
    assert_eq!(exit_of(&r), Some(live_ip.to_string()));
    assert_eq!(
        h.hot.breaker_peek(&dead_p, &cfg).await?.0,
        BreakerState::Open,
        "a failed probe reopens it"
    );
    assert_eq!(skipped(), 1, "the probe was a dial, not a skip");

    // The provider comes back: the next probe passes (half-open), the one
    // after closes the route class, and the dead provider serves again.
    sleep(Duration::from_millis(450)).await;
    ready_dead().await?;
    let revived = stub_provider_on(dead_addr.listen()?, PROVIDER_PASS, target, uniq_ip());
    let r = tunnel().await?;
    assert!(
        [Some(dead_ip.to_string()), Some(dead_ip2.to_string())].contains(&exit_of(&r)),
        "the probe goes to it"
    );
    assert_eq!(
        h.hot.breaker_peek(&dead_p, &cfg).await?.0,
        BreakerState::HalfOpen
    );
    let r = tunnel().await?;
    assert!([Some(dead_ip.to_string()), Some(dead_ip2.to_string())].contains(&exit_of(&r)));
    assert_eq!(
        h.hot.breaker_peek(&dead_p, &cfg).await?,
        (BreakerState::Closed, Admit::Go),
        "two passes close it"
    );
    assert_eq!(revived.connects().len(), 2);
    Ok(())
}

#[tokio::test]
async fn probe_token_is_refused_on_the_main_listeners_and_accepted_on_the_probe_listener()
-> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let setup = Setup::new();
    let (h, _, _) = static_fixture(&env, &setup).await?;
    let token = probe_token(&setup);

    let refused = connect_via(h.connect, "px", &token).await?;
    assert_eq!(refused.answer(), (407, "auth_required"));
    let mut ok = connect_via(h.probe, "px", &token).await?;
    assert_eq!(ok.status, 200);
    assert_eq!(ping(&mut ok.stream, "probe").await?, "pong:probe");

    // the probe listener takes no org's key
    let other = connect_via(h.probe, "px", &setup.key).await?;
    assert_eq!(other.answer(), (407, "auth_required"));
    assert_eq!(h.connections("connect", "auth_required"), 1);
    assert_eq!(h.connections("probe", "auth_required"), 1);
    assert_eq!(h.connections("probe", "ok"), 1);
    Ok(())
}

#[tokio::test]
async fn options_that_widen_the_policy_or_do_not_parse_get_403_option_denied() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.kinds = r#"["static"]"#;
    let (h, provider, _) = static_fixture(&env, &setup).await?;

    for username in [
        "px-kind-rotating", // a kind the policy does not allow
        "px-cc-de",         // a region the policy does not list
        "px-ttl-1d",        // above lease_ttl
        "px-bogus-1",       // unknown key
        "bob",              // no px prefix
        "px-sid-Upper",     // outside [a-z0-9_]
    ] {
        let r = connect_via(h.connect, username, &setup.key).await?;
        assert_eq!(r.answer(), (403, "option_denied"), "{username}");
    }
    assert!(provider.connects().is_empty());
    // a narrowing option still works
    let ok = connect_via(h.connect, "px-kind-static-cc-fr", &setup.key).await?;
    assert_eq!(ok.status, 200);
    Ok(())
}

#[tokio::test]
async fn private_and_internal_targets_get_403_destination_denied_before_any_lease() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let setup = Setup::new();
    let (h, provider, ip) = static_fixture(&env, &setup).await?;

    for target in [
        "10.0.0.1:80",
        "169.254.169.254:80",
        "[::1]:443",
        "db.svc:5432",
        "localhost:80",
    ] {
        let r = connect_to(h.connect, target, "px", &setup.key).await?;
        assert_eq!(r.answer(), (403, "destination_denied"), "{target}");
    }
    assert!(provider.connects().is_empty(), "nothing was dialed");
    let load = h.hot.unit_load(&setup.partition(), &ip.to_string()).await?;
    assert_eq!((load.leases, load.tunnels), (0, 0), "no lease was taken");
    assert_eq!(h.hot.org_tunnel_count(&setup.org).await?, 0);
    Ok(())
}

#[tokio::test]
async fn target_port_outside_the_adapter_allow_list_gets_403_port_not_allowed() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.adapter_toml = Some(setup.static_adapter("[443]"));
    let (h, provider, _) = static_fixture(&env, &setup).await?;

    let r = connect_to(h.connect, "example.test:8080", "px", &setup.key).await?;
    assert_eq!(r.answer(), (403, "port_not_allowed"));
    assert!(provider.connects().is_empty());
    let ok = connect_via(h.connect, "px", &setup.key).await?;
    assert_eq!(ok.status, 200);
    Ok(())
}

#[tokio::test]
async fn org_at_max_tunnels_gets_503_org_capacity_and_other_orgs_do_not() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.extra_policies = format!(
        "\n[[policy]]\nname = \"cap\"\nscope = \"org\"\nmatch = \"{}\"\nmax_tunnels_per_org = 1\n",
        setup.org
    );
    let (h, _, _) = static_fixture(&env, &setup).await?;

    let first = connect_via(h.connect, "px", &setup.key).await?;
    assert_eq!(first.status, 200);
    let second = connect_via(h.connect, "px", &setup.key).await?;
    assert_eq!(second.answer(), (503, "org_capacity"));
    assert_eq!(h.metrics.org_capacity_refusals_total.get(), 1);
    assert_eq!(
        h.hot.org_tunnel_count(&setup.org).await?,
        1,
        "a refusal does not hold a slot"
    );

    // the probe org has no cap
    let other = connect_via(h.probe, "px", &probe_token(&setup)).await?;
    assert_eq!(other.status, 200);

    drop(first);
    eventually("the slot to free", || async {
        h.hot
            .org_tunnel_count(&setup.org)
            .await
            .is_ok_and(|n| n == 0)
    })
    .await;
    let again = connect_via(h.connect, "px", &setup.key).await?;
    assert_eq!(again.status, 200);
    Ok(())
}

#[tokio::test]
async fn empty_static_partition_with_on_empty_fail_gets_503_no_healthy_ip() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.policy = "[policy.on_empty]\nstatic = \"fail\"\n".into();
    let provider = stub_provider(PROVIDER_PASS, stub_target().await, uniq_ip()).await;
    let (h, _) = unready_unit(&env, &setup, provider.addr, true).await?;
    // the partition exists in the inventory but nothing is leasable

    let started = std::time::Instant::now();
    let r = connect_via(h.connect, "px", &setup.key).await?;
    assert_eq!(r.answer(), (503, "no_healthy_ip"));
    assert!(
        started.elapsed() < Duration::from_millis(900),
        "fail answers at once"
    );
    assert!(provider.connects().is_empty());
    assert_eq!(
        h.hot.org_tunnel_count(&setup.org).await?,
        0,
        "the org slot was released"
    );
    Ok(())
}

#[tokio::test]
async fn failed_lease_is_remembered_for_the_same_sticky_key_only() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.policy = "[policy.on_empty]\nstatic = \"fail\"\n".into();
    let provider = stub_provider(PROVIDER_PASS, stub_target().await, uniq_ip()).await;
    let (h, ip) = unready_unit(&env, &setup, provider.addr, true).await?;

    let r = connect_via(h.connect, "px-sid-a", &setup.key).await?;
    assert_eq!(r.answer(), (503, "no_healthy_ip"));
    h.ready(&setup.partition(), ip).await?;

    // the unit is leasable now, but the same key still gets the remembered answer
    let again = connect_via(h.connect, "px-sid-a", &setup.key).await?;
    assert_eq!(again.answer(), (503, "no_healthy_ip"));
    // another sticky key is not affected
    let other = connect_via(h.connect, "px-sid-b", &setup.key).await?;
    assert_eq!(other.status, 200);
    Ok(())
}

#[tokio::test]
async fn on_empty_wait_serves_a_unit_that_appears_and_times_out_with_504_otherwise() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let setup = Setup::new(); // static on_empty defaults to wait, lease_wait 1s
    let provider = stub_provider(PROVIDER_PASS, stub_target().await, uniq_ip()).await;
    let (h, ip) = unready_unit(&env, &setup, provider.addr, true).await?;

    let started = std::time::Instant::now();
    let r = connect_via(h.connect, "px-sid-w1", &setup.key).await?;
    assert_eq!(r.answer(), (504, "lease_timeout"));
    assert!(
        started.elapsed() >= Duration::from_millis(900),
        "it waited for lease_wait"
    );

    let hot = h.hot.clone();
    let partition = setup.partition();
    let late = tokio::spawn(async move {
        sleep(Duration::from_millis(300)).await;
        hot.ready_put(&partition, &UnitRecord::static_ip(ip)).await
    });
    let r = connect_via(h.connect, "px-sid-w2", &setup.key).await?;
    late.await??;
    assert_eq!(
        r.status, 200,
        "a unit that became leasable during the wait is served"
    );
    Ok(())
}

#[tokio::test]
async fn provider_rejecting_the_credential_gets_502_provider_auth() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let setup = Setup::new();
    let provider = stub_provider("some-other-password", stub_target().await, uniq_ip()).await;
    let (h, ip) = static_unit(&env, &setup, provider.addr, true).await?;

    let r = connect_via(h.connect, "px", &setup.key).await?;
    assert_eq!(r.answer(), (502, "provider_auth"));
    assert!(
        provider.connects().is_empty(),
        "the provider refused the login"
    );
    eventually("the counters to close", || async {
        let load = h.hot.unit_load(&setup.partition(), &ip.to_string()).await;
        load.is_ok_and(|l| l.tunnels == 0)
            && h.hot
                .org_tunnel_count(&setup.org)
                .await
                .is_ok_and(|n| n == 0)
    })
    .await;
    assert_eq!(h.connections("connect", "provider_auth"), 1);
    Ok(())
}

#[tokio::test]
async fn unreachable_provider_gets_502_provider_unavailable() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let setup = Setup::new();
    // an inventory entry that points at a closed port
    let dead = closed_endpoint();
    let (h, _) = static_unit(&env, &setup, dead.addr(), true).await?;

    let r = connect_via(h.connect, "px", &setup.key).await?;
    assert_eq!(r.answer(), (502, "provider_unavailable"));
    Ok(())
}

#[tokio::test]
async fn a_provider_that_accepts_and_stays_silent_is_dialed_once_and_refused_within_the_handshake_limit()
-> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let setup = Setup::new();
    let hang = TcpListener::bind("127.0.0.1:0").await?;
    let addr = hang.local_addr()?;
    let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = Arc::clone(&accepted);
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = hang.accept().await {
            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            held.push(s);
        }
    });
    let (h, _) = static_unit(&env, &setup, addr, true).await?;

    let started = std::time::Instant::now();
    let r = connect_via(h.connect, "px", &setup.key).await?;
    let took = started.elapsed();
    assert_eq!(r.answer(), (504, "provider_timeout"));
    assert_eq!(
        accepted.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "a silent provider is not dialed again"
    );
    // the default handshake limit is 3 s; three tries would take the whole 8 s budget
    assert!(took < Duration::from_millis(4500), "{took:?}");
    Ok(())
}

#[tokio::test]
async fn org_block_on_the_provider_gets_403_org_blocked() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let setup = Setup::new();
    let (h, provider, _) = static_fixture(&env, &setup).await?;
    h.hot
        .org_block_set(
            &setup.org,
            &BlockScope::Provider(setup.provider.parse()?),
            None,
        )
        .await?;

    let r = connect_via(h.connect, "px", &setup.key).await?;
    assert_eq!(r.answer(), (403, "org_blocked"));
    assert!(provider.connects().is_empty());
    Ok(())
}

#[tokio::test]
async fn static_ip_that_fails_its_exit_check_is_withdrawn_and_never_served() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.check = true;
    setup.policy = "[policy.on_empty]\nstatic = \"fail\"\n".into();
    // the provider reports another exit IP than the inventory says
    let provider = stub_provider(PROVIDER_PASS, stub_target().await, uniq_ip()).await;
    let (h, ip) = static_unit(&env, &setup, provider.addr, false).await?;

    let r = connect_via(h.connect, "px", &setup.key).await?;
    assert_eq!(r.answer(), (503, "no_healthy_ip"));
    assert_eq!(provider.checks(), 1, "the exit IP was checked once");
    assert!(
        provider.connects().is_empty(),
        "the failed IP carried no tunnel"
    );
    assert!(
        h.hot.ready_ids(&setup.partition()).await?.is_empty(),
        "{ip} left the ready set"
    );
    Ok(())
}

#[tokio::test]
async fn static_ip_with_a_matching_exit_check_is_served_and_checked_once() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.check = true;
    let target = stub_target().await;
    let ip = uniq_ip();
    let provider = stub_provider(PROVIDER_PASS, target, ip).await;
    let e = entry(&setup, ip, provider.addr.port());
    let h = start(&env, &setup, vec![row(&e, false)]).await?;
    h.ready(&setup.partition(), ip).await?;

    for _ in 0..2 {
        let mut r = connect_via(h.connect, "px", &setup.key).await?;
        assert_eq!(r.status, 200);
        assert_eq!(ping(&mut r.stream, "x").await?, "pong:x");
    }
    assert_eq!(
        provider.checks(),
        1,
        "the second tunnel reuses the check of the first"
    );
    Ok(())
}

#[tokio::test]
async fn empty_rotating_partition_creates_a_session_on_demand_and_reuses_it() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    let (provider, exit) = on_demand(&mut setup).await;
    let h = start(&env, &setup, vec![]).await?;

    let mut r = connect_via(h.connect, "px-cc-fr", &setup.key).await?;
    assert_eq!(r.status, 200, "{}", r.reason);
    assert_eq!(
        r.header("X-ProxyX-Exit-IP"),
        Some(exit.to_string().as_str())
    );
    assert_eq!(ping(&mut r.stream, "hi").await?, "pong:hi");

    let sessions = h.hot.ready_ids(&setup.partition()).await?;
    assert_eq!(sessions.len(), 1, "one session was created and made ready");
    let connects = provider.connects();
    assert_eq!(connects.len(), 1);
    let login = &connects[0].1;
    let session_id = {
        let loaded = h.loaded.borrow();
        let provider = setup.provider.parse()?;
        loaded
            .adapters
            .get(&provider)
            .ok_or("adapter")?
            .decode_session(&sessions[0])?
            .session_id
            .to_owned()
    };
    assert!(
        login.starts_with(&format!("{PROVIDER_USER}-cc-FR-sid-{session_id}-t-60:")),
        "the session id and region are in the provider credential: {login}"
    );
    assert!(
        provider.checks() >= 1,
        "the exit IP quorum ran before the session was served"
    );

    // a second tunnel of the same org takes the same session: no second create
    let mut again = connect_via(h.connect, "px-cc-fr", &setup.key).await?;
    assert_eq!(again.status, 200);
    assert_eq!(ping(&mut again.stream, "two").await?, "pong:two");
    assert_eq!(h.hot.ready_ids(&setup.partition()).await?, sessions);
    assert_eq!(provider.connects().len(), 2);
    assert_eq!(
        provider.connects()[1].1,
        *login,
        "the same credential renders again"
    );
    Ok(())
}

#[tokio::test]
async fn failed_create_gets_503_cache_empty_and_leaves_nothing_reserved() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    // a provider that rejects every login: the check answers nothing, the
    // session cannot be verified, so it is never served
    let provider = stub_provider("some-other-password", stub_target().await, uniq_ip()).await;
    setup.rotating_via(provider.addr.port());
    let h = start(&env, &setup, vec![]).await?;

    let r = connect_via(h.connect, "px-cc-fr", &setup.key).await?;
    assert_eq!(r.answer(), (503, "cache_empty"));
    assert!(h.hot.ready_ids(&setup.partition()).await?.is_empty());
    let counts = h.hot.counts(&setup.partition()).await?;
    assert_eq!(
        (counts.creating, counts.reserved),
        (0, 0),
        "reservations and in-flight creates are aborted"
    );
    assert_eq!(h.hot.org_tunnel_count(&setup.org).await?, 0);
    Ok(())
}

/// A rotating setup whose empty partition creates on demand, with the
/// provider that gives the new session `exit` as its exit IP.
async fn on_demand(setup: &mut Setup) -> (StubProvider, IpAddr) {
    let exit = uniq_ip();
    let provider = stub_provider(PROVIDER_PASS, stub_target().await, exit).await;
    setup.rotating_via(provider.addr.port());
    (provider, exit)
}

/// The session jobs in the shared `due` set that belong to `p`.
async fn session_jobs(env: &Env, p: &Partition) -> Result<Vec<SessionJob>, BoxErr> {
    let mut raw = redis::Client::open(env.redis_url.as_str())?
        .get_multiplexed_async_connection()
        .await?;
    let jobs: Vec<String> = redis::cmd("ZRANGE")
        .arg("due")
        .arg(0)
        .arg(-1)
        .query_async(&mut raw)
        .await?;
    Ok(jobs
        .iter()
        .filter_map(|j| SessionJob::parse(j))
        .filter(|j| j.partition == *p)
        .collect())
}

/// True when the exit IP is free to claim, that is no session holds it.
async fn exit_ip_is_free(h: &Harness, ip: IpAddr) -> Result<bool, BoxErr> {
    let claim = h
        .hot
        .claim_exit_ip(ip, "free-check", Duration::from_secs(60))
        .await?;
    Ok(matches!(claim, ExitIpClaim::Claimed))
}

#[tokio::test]
async fn an_on_demand_session_is_in_the_due_set_for_keepalive_and_drain() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    let (_provider, exit) = on_demand(&mut setup).await;
    let h = start(&env, &setup, vec![]).await?;

    let r = connect_via(h.connect, "px-cc-fr", &setup.key).await?;
    assert_eq!(r.status, 200, "{}", r.reason);

    let sessions = h.hot.ready_ids(&setup.partition()).await?;
    let jobs = session_jobs(&env, &setup.partition()).await?;
    assert_eq!(jobs.len(), 1, "one ready session, one job: {jobs:?}");
    let job = &jobs[0];
    assert_eq!(vec![job.session.clone()], sessions);
    assert_eq!(
        IpAddr::V4(job.ip),
        exit,
        "the job knows the verified exit IP"
    );
    assert!(job.expires > job.born, "{job:?}");
    assert_eq!(
        job.phase,
        Phase::fresh(job.born),
        "it starts in the keep phase"
    );
    Ok(())
}

#[tokio::test]
async fn an_on_demand_session_over_max_risk_is_not_served_and_one_at_it_is() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    // the default `criteria.max_risk` is 75: over it drains, at it is kept
    for (risk, served) in [(76, false), (75, true)] {
        let mut setup = Setup::new();
        let (_provider, exit) = on_demand(&mut setup).await;
        setup.scorer_risk = Some(risk);
        let h = start(&env, &setup, vec![]).await?;

        let r = connect_via(h.connect, "px-cc-fr", &setup.key).await?;
        let p = setup.partition();
        if served {
            assert_eq!(r.status, 200, "risk {risk}: {}", r.reason);
            assert_eq!(h.hot.ready_ids(&p).await?.len(), 1);
            continue;
        }
        assert_eq!(r.answer(), (503, "cache_empty"), "risk {risk}");
        assert!(h.hot.ready_ids(&p).await?.is_empty(), "never made ready");
        assert!(
            session_jobs(&env, &p).await?.is_empty(),
            "no job for a refused session"
        );
        assert!(
            exit_ip_is_free(&h, exit).await?,
            "the claim of the refused exit IP is given back"
        );
        assert_eq!(
            h.metrics
                .cache_evictions_total
                .with_label_values(&["reputation"])
                .get(),
            u64::from(crate::acquire::CREATE_TRIES)
        );
        let counts = h.hot.counts(&p).await?;
        assert_eq!((counts.creating, counts.reserved), (0, 0));
    }
    Ok(())
}

#[tokio::test]
async fn an_on_demand_session_with_no_score_follows_on_score_unavailable() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    for (value, status) in [("allow", 200), ("deny", 503)] {
        let mut setup = Setup::new();
        on_demand(&mut setup).await;
        // no scorer is on
        setup.policy = format!("on_score_unavailable = \"{value}\"\n");
        let h = start(&env, &setup, vec![]).await?;

        let r = connect_via(h.connect, "px-cc-fr", &setup.key).await?;
        assert_eq!(
            r.status, status,
            "on_score_unavailable = {value}: {}",
            r.reason
        );
        assert_eq!(
            h.hot.ready_ids(&setup.partition()).await?.len(),
            usize::from(status == 200)
        );
    }
    Ok(())
}

#[tokio::test]
async fn an_on_demand_session_blocked_by_a_probe_target_is_not_served() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    for (target, served) in [
        ("http://probe.test/blocked", false),
        ("http://probe.test/fine", true),
    ] {
        let mut setup = Setup::new();
        let (provider, _) = on_demand(&mut setup).await;
        setup.scorer_risk = Some(10);
        setup.probe_targets = vec![target];
        let h = start(&env, &setup, vec![]).await?;

        let r = connect_via(h.connect, "px-cc-fr", &setup.key).await?;
        let p = setup.partition();
        if served {
            assert_eq!(r.status, 200, "{target}: {}", r.reason);
            assert_eq!(h.hot.ready_ids(&p).await?.len(), 1);
            assert!(
                provider.checks() >= 4,
                "the quorum and three probe GETs ran"
            );
            continue;
        }
        assert_eq!(r.answer(), (503, "cache_empty"), "{target}");
        assert!(h.hot.ready_ids(&p).await?.is_empty());
        assert!(session_jobs(&env, &p).await?.is_empty());
        assert_eq!(
            h.metrics
                .cache_evictions_total
                .with_label_values(&["block"])
                .get(),
            u64::from(crate::acquire::CREATE_TRIES)
        );
    }
    Ok(())
}

/// N52: a new session whose probe answers are clean but slower than
/// `criteria.max_ttfb_ms` is served as a degraded session, as the warmer keeps
/// one, instead of being refused; while the partition holds a free degraded
/// session already (a quarter of `max_ready`, which is 2: one) it is refused as
/// before.
#[tokio::test]
async fn an_on_demand_session_that_is_clean_but_slow_is_served_as_degraded_within_the_cap()
-> TestResult {
    let Some(env) = env() else { return Ok(()) };
    for (cap_used, served) in [(false, true), (true, false)] {
        let mut setup = Setup::new();
        let (_provider, _) = on_demand(&mut setup).await;
        setup.scorer_risk = Some(10);
        setup.probe_targets = vec!["http://probe.test/slow"];
        setup.policy = "[policy.criteria]\nmax_ttfb_ms = 50\n".into();
        let h = start(&env, &setup, vec![]).await?;
        let p = setup.partition();
        if cap_used {
            // a free degraded session that only another org may lease
            let other = UnitRecord {
                owner: Some(setup.rival.clone()),
                ..UnitRecord::static_ip(uniq_ip())
            };
            h.hot.ready_put_tier(&p, &other, Tier::Degraded).await?;
        }

        let r = connect_via(h.connect, "px-cc-fr", &setup.key).await?;
        let slow_refusals = h
            .metrics
            .cache_evictions_total
            .with_label_values(&["quality"])
            .get();
        if served {
            assert_eq!(r.status, 200, "{}", r.reason);
            assert_eq!(slow_refusals, 0, "a slow session is admitted, not evicted");
            let ready = h.hot.ready_ids(&p).await?;
            assert_eq!(ready.len(), 1);
            assert_eq!(h.hot.tier(&p, &ready[0]).await?, Tier::Degraded);
            assert_eq!(session_jobs(&env, &p).await?.len(), 1);
            continue;
        }
        assert_eq!(
            r.answer(),
            (503, "cache_empty"),
            "no room for a degraded one"
        );
        assert_eq!(slow_refusals, u64::from(crate::acquire::CREATE_TRIES));
        assert!(session_jobs(&env, &p).await?.is_empty());
    }
    Ok(())
}

/// The whole open answers inside `TOTAL_BUDGET`, however the
/// time went. The first IP answers its re-check at once and its CONNECT with a
/// 403 after 2.9 s; from then on every re-check hangs (2 s) and every CONNECT
/// takes 2.9 s. The third IP starts its re-check at 7.8 s: it would run to
/// 9.8 s, near the session proxy's 10 s, but ends with the budget, so the client hears
/// `provider_timeout` at 8 s, our own answer.
#[tokio::test]
async fn an_open_that_spends_its_budget_in_slow_checks_answers_by_the_budget() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.check = true;
    // set by the first CONNECT: from then on every re-check hangs
    let connected = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut rows = Vec::new();
    let mut ips = Vec::new();
    for _ in 0..3 {
        let ip = uniq_ip();
        let connected = Arc::clone(&connected);
        let addr = serve(move |mut s| {
            let connected = Arc::clone(&connected);
            async move {
                let Some(head) = read_head(&mut s).await else {
                    return;
                };
                let (first, _) = request_and_login(&head);
                if first.starts_with("CONNECT") {
                    connected.store(true, std::sync::atomic::Ordering::Relaxed);
                    sleep(Duration::from_millis(2_900)).await;
                    respond(&mut s, "403 Forbidden", "").await;
                } else if connected.load(std::sync::atomic::Ordering::Relaxed) {
                    sleep(Duration::from_secs(60)).await;
                } else {
                    let body = format!(r#"{{"ip":"{ip}","country":"fr"}}"#);
                    respond(&mut s, "200 OK", &body).await;
                }
            }
        })
        .await;
        rows.push(row(&entry(&setup, ip, addr.port()), false));
        ips.push(ip);
    }
    let h = start(&env, &setup, rows).await?;
    let p = setup.partition();
    for ip in ips {
        h.ready(&p, ip).await?;
    }

    let started = std::time::Instant::now();
    let r = connect_via(h.connect, "px", &setup.key).await?;
    let took = started.elapsed();
    assert_eq!(r.answer(), (504, "provider_timeout"));
    assert!(
        took >= Duration::from_millis(7_900) && took < Duration::from_millis(8_300),
        "answered at the budget: {took:?}"
    );
    Ok(())
}

#[tokio::test]
async fn tunnel_bytes_are_metered_against_the_provider_budget_and_the_tunnel_stays_counted()
-> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let setup = Setup::new();
    let (h, _, ip) = static_fixture(&env, &setup).await?;
    let before = metered_bytes(&h, &setup.provider).await?;

    let mut r = connect_via(h.connect, "px", &setup.key).await?;
    assert_eq!(ping(&mut r.stream, "meter-me").await?, "pong:meter-me");
    // "meter-me" out and "pong:meter-me" back, counted by the keeper after its 5 s tick
    sleep(Duration::from_millis(5600)).await;
    assert_eq!(
        metered_bytes(&h, &setup.provider).await?,
        before + 8 + 13,
        "the open tunnel's bytes are metered"
    );
    let load = h.hot.unit_load(&setup.partition(), &ip.to_string()).await?;
    assert_eq!(load.tunnels, 1, "touching keeps the tunnel counted");

    // bytes after the last tick are metered when the tunnel ends
    assert_eq!(ping(&mut r.stream, "x").await?, "pong:x");
    drop(r);
    eventually("the rest to be metered", || async {
        metered_bytes(&h, &setup.provider)
            .await
            .is_ok_and(|n| n == before + 8 + 13 + 1 + 6)
    })
    .await;
    Ok(())
}

// --- SOCKS5 ---

async fn socks_connect(
    proxy: SocketAddr,
    username: &str,
    key: &str,
    host: &str,
    port: u16,
) -> Result<(TcpStream, [u8; 2], Option<[u8; 10]>), BoxErr> {
    let mut s = TcpStream::connect(proxy).await?;
    s.write_all(&[5, 1, 2]).await?;
    let mut sel = [0u8; 2];
    s.read_exact(&mut sel).await?;
    assert_eq!(sel, [5, 2]);
    let mut auth = vec![1, u8::try_from(username.len())?];
    auth.extend_from_slice(username.as_bytes());
    auth.push(u8::try_from(key.len())?);
    auth.extend_from_slice(key.as_bytes());
    s.write_all(&auth).await?;
    let mut status = [0u8; 2];
    s.read_exact(&mut status).await?;
    if status[1] != 0 {
        return Ok((s, status, None));
    }
    let mut req = vec![5, 1, 0, 3, u8::try_from(host.len())?];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).await?;
    Ok((s, status, Some(reply)))
}

#[tokio::test]
async fn socks5_tunnels_bytes_and_answers_refusals_with_reply_codes() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.policy = "[policy.on_empty]\nstatic = \"fail\"\n".into();
    let (h, _, ip) = static_fixture(&env, &setup).await?;

    let (mut s, auth, reply) =
        socks_connect(h.socks, "px", &setup.key, "example.test", 443).await?;
    assert_eq!(auth, [1, 0]);
    assert_eq!(reply.expect("reply")[..2], [5, 0], "success");
    assert_eq!(ping(&mut s, "socks").await?, "pong:socks");
    assert_eq!(h.connections("socks", "ok"), 1);

    // bad key: RFC 1929 failure status
    let (_, auth, reply) = socks_connect(h.socks, "px", "wrong", "example.test", 443).await?;
    assert_eq!(auth, [1, 1]);
    assert!(reply.is_none());

    // the probe org's key is not valid on the SOCKS listener
    let (_, auth, _) = socks_connect(h.socks, "px", &setup.probe_key, "example.test", 443).await?;
    assert_eq!(auth, [1, 1]);

    // not allowed by the ruleset (0x02): a private target and a widened option
    let (_, _, reply) = socks_connect(h.socks, "px", &setup.key, "10.0.0.1", 80).await?;
    assert_eq!(reply.expect("reply")[1], 0x02);
    let (_, _, reply) = socks_connect(h.socks, "px-cc-de", &setup.key, "example.test", 443).await?;
    assert_eq!(reply.expect("reply")[1], 0x02);

    // empty partition (on_empty = fail): general failure (0x01)
    h.hot
        .ready_take(&setup.partition(), &ip.to_string())
        .await?;
    let (_, _, reply) =
        socks_connect(h.socks, "px-sid-none", &setup.key, "example.test", 443).await?;
    assert_eq!(
        reply.expect("reply")[1],
        0x01,
        "no unit: general SOCKS server failure"
    );
    Ok(())
}

// --- drain and closing ---

#[tokio::test]
async fn drain_waits_for_an_open_tunnel_then_closes_it_at_the_deadline() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.settings.drain_timeout = Duration::from_millis(1500);
    let (h, _, _) = static_fixture(&env, &setup).await?;
    let mut r = connect_via(h.connect, "px", &setup.key).await?;
    assert_eq!(r.status, 200);

    h.cancel.cancel();
    let started = std::time::Instant::now();
    sleep(Duration::from_millis(500)).await;
    assert!(
        !h.task.is_finished(),
        "the gateway waits for the open tunnel"
    );
    assert_eq!(
        ping(&mut r.stream, "still-open").await?,
        "pong:still-open",
        "traffic flows while draining"
    );
    // no new connections once draining starts
    assert!(
        timeout(
            Duration::from_secs(1),
            connect_via(h.connect, "px", &setup.key)
        )
        .await
        .is_ok_and(|r| r.is_err()),
        "the listener is closed"
    );

    let result = timeout(Duration::from_secs(5), h.task).await??;
    result?;
    assert!(
        started.elapsed() >= Duration::from_millis(1400),
        "it held the tunnel until the deadline, {:?}",
        started.elapsed()
    );
    let mut rest = Vec::new();
    let n = timeout(Duration::from_secs(2), r.stream.read_to_end(&mut rest)).await??;
    assert_eq!(n, 0, "the deadline closed the tunnel");
    assert_eq!(
        h.hot.org_tunnel_count(&setup.org).await?,
        0,
        "and closed its counters"
    );
    Ok(())
}

#[tokio::test]
async fn drain_returns_as_soon_as_the_last_tunnel_ends() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.settings.drain_timeout = Duration::from_secs(30);
    let (h, _, _) = static_fixture(&env, &setup).await?;
    let r = connect_via(h.connect, "px", &setup.key).await?;
    assert_eq!(r.status, 200);

    h.cancel.cancel();
    sleep(Duration::from_millis(300)).await;
    assert!(!h.task.is_finished());
    drop(r);
    let result = timeout(Duration::from_secs(5), h.task).await??;
    result?;
    Ok(())
}

#[tokio::test]
async fn registry_closes_the_orgs_tunnels_in_a_block_scope() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let setup = Setup::new();
    let (h, _, ip) = static_fixture(&env, &setup).await?;

    let mut buf = Vec::new();
    let mut by_scope = connect_via(h.connect, "px-sid-s2", &setup.key).await?;
    assert_eq!(
        h.tunnels.close_org_scope(&setup.org, &BlockScope::Ip(ip)),
        1
    );
    let n = timeout(
        Duration::from_secs(2),
        by_scope.stream.read_to_end(&mut buf),
    )
    .await??;
    assert_eq!(n, 0);
    eventually("the counters to close", || tunnels_closed(&h, &setup.org)).await;
    Ok(())
}

/// Short keeper timing so the drain cap fits a test.
fn fast(drain_cap: Duration) -> Pacing {
    Pacing {
        keep_every: Duration::from_millis(100),
        drain_cap,
        ..Pacing::default()
    }
}

/// True when the client side sees the tunnel closed (end of stream or reset).
async fn closed_within(s: &mut TcpStream, limit: Duration) -> bool {
    let mut buf = [0u8; 64];
    matches!(timeout(limit, s.read(&mut buf)).await, Ok(Ok(0) | Err(_)))
}

#[tokio::test]
async fn tunnel_on_a_drained_static_unit_closes_at_the_drain_cap() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.pacing = fast(Duration::from_millis(800));
    let (h, _, ip) = static_fixture(&env, &setup).await?;
    let mut r = connect_via(h.connect, "px", &setup.key).await?;
    assert_eq!(r.status, 200);

    // a healthy unit is never closed by the keeper
    sleep(Duration::from_millis(1000)).await;
    assert_eq!(ping(&mut r.stream, "before").await?, "pong:before");

    h.hot
        .ready_take(&setup.partition(), &ip.to_string())
        .await?;
    let drained_at = std::time::Instant::now();
    sleep(Duration::from_millis(300)).await;
    assert_eq!(
        ping(&mut r.stream, "draining").await?,
        "pong:draining",
        "the tunnel runs on while the cap has not passed"
    );
    assert!(closed_within(&mut r.stream, Duration::from_secs(5)).await);
    let took = drained_at.elapsed();
    assert!(
        took >= Duration::from_millis(700),
        "closed at the cap, not before: {took:?}"
    );
    eventually("the counters to close", || tunnels_closed(&h, &setup.org)).await;
    Ok(())
}

#[tokio::test]
async fn a_unit_that_is_leasable_again_resets_the_drain_cap() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.pacing = fast(Duration::from_millis(800));
    let (h, _, ip) = static_fixture(&env, &setup).await?;
    let mut r = connect_via(h.connect, "px", &setup.key).await?;
    assert_eq!(r.status, 200);

    h.hot
        .ready_take(&setup.partition(), &ip.to_string())
        .await?;
    sleep(Duration::from_millis(400)).await;
    h.ready(&setup.partition(), ip).await?;
    // past the first cap deadline, but the unit came back
    sleep(Duration::from_millis(1200)).await;
    assert_eq!(ping(&mut r.stream, "back").await?, "pong:back");
    Ok(())
}

/// An org block closes the tunnels it covers at the next keeper
/// tick on every replica, not after the drain cap (600 s here: a closure at the
/// cap would never come within the test).
#[tokio::test]
async fn tunnel_under_an_org_block_closes_at_the_next_keeper_tick() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.pacing = fast(Duration::from_secs(600));
    let (h, _, _) = static_fixture(&env, &setup).await?;
    let mut other = connect_via(h.connect, "px", &setup.rival_key).await?;
    let mut r = connect_via(h.connect, "px", &setup.key).await?;
    assert_eq!((other.status, r.status), (200, 200));

    h.hot
        .org_block_set(
            &setup.org,
            &BlockScope::Provider(setup.provider.parse()?),
            None,
        )
        .await?;
    assert!(closed_within(&mut r.stream, Duration::from_secs(3)).await);
    assert_eq!(
        ping(&mut other.stream, "unaffected").await?,
        "pong:unaffected",
        "another org's tunnel on the same unit is not drained"
    );
    Ok(())
}

#[tokio::test]
async fn rotating_tunnel_bytes_are_metered_while_the_tunnel_is_open() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.pacing = fast(Duration::from_secs(600));
    on_demand(&mut setup).await;
    let h = start(&env, &setup, vec![]).await?;
    let id = setup.provider.parse()?;
    assert_eq!(metered_bytes(&h, &setup.provider).await?, 0);

    let mut r = connect_via(h.connect, "px-cc-fr", &setup.key).await?;
    assert_eq!(r.status, 200, "{}", r.reason);
    assert_eq!(ping(&mut r.stream, "hi").await?, "pong:hi");
    // "hi" out, "pong:hi" back; the keeper counts them on its next tick
    eventually("the keeper to meter the open rotating tunnel", || async {
        metered_bytes(&h, &setup.provider)
            .await
            .is_ok_and(|n| n == 2 + 7)
    })
    .await;
    let used = h.hot.cost_used(&id, OffsetDateTime::now_utc()).await?;
    assert_eq!(
        used.creates_this_hour, 1,
        "the on-demand create is metered too"
    );

    // bytes after the last tick are metered at close
    assert_eq!(ping(&mut r.stream, "x").await?, "pong:x");
    drop(r);
    eventually("the rest to be metered at close", || async {
        metered_bytes(&h, &setup.provider)
            .await
            .is_ok_and(|n| n == 2 + 7 + 1 + 6)
    })
    .await;
    Ok(())
}

#[tokio::test]
async fn after_release_drains_or_keeps_a_rotating_session_when_its_tunnel_closes() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    for (after, kept) in [("drain", false), ("reuse_same_org", true)] {
        let mut setup = Setup::new();
        setup.policy = format!("[policy.rotating]\nafter_release = \"{after}\"\n");
        on_demand(&mut setup).await;
        let h = start(&env, &setup, vec![]).await?;
        let p = setup.partition();
        let open = || connect_via(h.connect, "px-cc-fr-rot-each", &setup.key);

        // `rot-each` leases per connection: the lease ends with the tunnel
        let mut r = open().await?;
        assert_eq!(r.status, 200, "{after}: {}", r.reason);
        assert_eq!(ping(&mut r.stream, "hi").await?, "pong:hi");
        assert_eq!(h.hot.ready_ids(&p).await?.len(), 1, "{after}");
        drop(r);
        eventually("the tunnel to end", || async { h.tunnels.count() == 0 }).await;
        sleep(Duration::from_millis(200)).await;

        let ready = h.hot.ready_ids(&p).await?;
        assert_eq!(!ready.is_empty(), kept, "{after}: ready {ready:?}");
        // A drained session is gone (the stub gives every session one exit
        // IP, so a second create would be refused as a duplicate); a kept
        // one serves the org's next tunnel.
        if kept {
            let next = open().await?;
            assert_eq!(next.status, 200, "{after}");
            assert_eq!(
                h.hot.ready_ids(&p).await?,
                ready,
                "the same session is reused"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn a_static_ip_at_its_monthly_fair_use_is_leased_last_and_keeps_its_own() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.kinds = r#"["static"]"#;
    // 3000 bytes a month
    setup.policy =
        "[policy.cost]\nfair_use_gb_per_ip_month = 0.000003\n[policy.on_empty]\nstatic = \"fail\"\n"
            .into();
    setup.pacing = fast(Duration::from_secs(600));
    let (h, _, ip) = static_fixture(&env, &setup).await?;
    let exceeded = || {
        h.metrics
            .fair_use_exceeded_total
            .with_label_values(&[setup.provider.as_str()])
            .get()
    };

    let mut a = connect_via(h.connect, "px-sid-a", &setup.key).await?;
    assert_eq!(a.status, 200, "{}", a.reason);
    assert_eq!(a.header("X-ProxyX-Exit-IP"), Some(ip.to_string().as_str()));
    // the target answers each chunk of up to 1 KiB: 2 x (1000 + 1005) bytes
    let big = "x".repeat(1_000);
    for _ in 0..2 {
        assert_eq!(ping(&mut a.stream, &big).await?.len(), 1_005);
    }
    eventually("the IP to reach its fair use", || async { exceeded() == 1 }).await;

    // a new lease finds the only IP stopped and takes it all the same, the
    // stop broken as the last limit; the open tunnel and its own
    // lease are not touched
    let b = connect_via(h.connect, "px-sid-b", &setup.key).await?;
    assert_eq!(b.status, 200, "{}", b.reason);
    assert_eq!(
        h.metrics
            .lease_limit_broken_total
            .with_label_values(&["fair_use", &setup.provider])
            .get(),
        1
    );
    assert_eq!(ping(&mut a.stream, "still").await?, "pong:still");
    let a2 = connect_via(h.connect, "px-sid-a", &setup.key).await?;
    assert_eq!(a2.status, 200, "the lease it holds is renewed");
    assert_eq!(exceeded(), 1, "counted once, not at every tick");
    Ok(())
}
