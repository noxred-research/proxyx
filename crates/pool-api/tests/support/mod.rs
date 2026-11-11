//! Shared helpers of the API tests. They need the local Redis and Postgres
//! (`PROXYX_TEST_REDIS_URL`, `PROXYX_TEST_DATABASE_URL`) and skip with a
//! message when the variables are unset. Redis DB 4 is this crate's.
#![allow(dead_code)] // shared by several test binaries; each uses a part

/// Unwrap what a constructor returned, or end the test as passed when it is
/// `None`: the local services are not configured and it said so.
macro_rules! or_skip {
    ($setup:expr) => {
        match $setup {
            Some(ready) => ready,
            None => return Ok(()),
        }
    };
}

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::Secret;
use common::config::Settings;
use common::metrics::Metrics;
use common::types::{InventoryEntry, IpState, Kind, OrgId, Partition, Subtype, Target};
use parking_lot::Mutex;
use policy::{PolicyFile, PolicySet, Pool};
use provider::{AdapterFile, AdapterSet};
use proxyx_pool_api::{ApiState, TunnelControl};
use reqwest::{Method, StatusCode};
use serde_json::Value;
use store::loaded::{Loaded, ProbeTargets};
use store::{
    BlockScope, Db, Hot, LeaseLimits, LeaseOutcome, LeaseRequest, Snapshot, Transition, UnitRecord,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use verify::{CheckService, ExitIpChecker, ExitIpConfig, ServiceKind};

pub type TestResult = Result<(), Box<dyn std::error::Error>>;

pub const ADMIN: &str = "admin-secret";
pub const PROBER: &str = "prober-secret";
pub const PROBE_SECRET: &str = "probe-signing-secret";
const REDIS_DB: &str = "4";

/// Tunnels that record what the API asked to close.
#[derive(Default)]
pub struct FakeTunnels {
    pub calls: Mutex<Vec<(OrgId, BlockScope)>>,
}

impl TunnelControl for FakeTunnels {
    fn close_org_scope(&self, org: &OrgId, scope: &BlockScope) -> usize {
        self.calls.lock().push((org.clone(), scope.clone()));
        2
    }
}

/// A TCP relay in front of Redis that a test can cut and restore: the API's
/// calls fail while it is cut, as in a Redis outage.
pub struct RedisProxy {
    url: String,
    up: watch::Sender<bool>,
}

impl RedisProxy {
    async fn start(redis_url: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let (scheme, rest) = redis_url.split_once("://").ok_or("redis url")?;
        let (authority, db) = rest.split_once('/').ok_or("redis url has no db")?;
        let target = authority.to_owned();
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("{scheme}://{}/{db}", listener.local_addr()?);
        let (up, state) = watch::channel(true);
        tokio::spawn(async move {
            while let Ok((mut client, _)) = listener.accept().await {
                let mut state = state.clone();
                if !*state.borrow() {
                    continue;
                }
                let target = target.clone();
                tokio::spawn(async move {
                    let Ok(mut server) = TcpStream::connect(target).await else {
                        return;
                    };
                    tokio::select! {
                        _ = tokio::io::copy_bidirectional(&mut client, &mut server) => {}
                        _ = state.wait_for(|up| !*up) => {}
                    }
                });
            }
        });
        Ok(Self { url, up })
    }

    /// The URL a client connects through.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Drop every connection and refuse new ones.
    pub fn cut(&self) {
        self.up.send_replace(false);
    }

    pub fn restore(&self) {
        self.up.send_replace(true);
    }
}

pub struct Harness {
    pub base: String,
    pub client: reqwest::Client,
    pub db: Db,
    /// Raw SQL against the test database, on whichever backend the suite runs.
    pub raw: proxyx_db::testing::Raw,
    pub hot: Hot,
    pub loaded: watch::Receiver<Arc<Loaded>>,
    pub metrics: Arc<Metrics>,
    pub tunnels: Arc<FakeTunnels>,
    /// The provider every static test IP belongs to (unique per run).
    pub provider: String,
    pub data_dir: PathBuf,
    pub proxy: Option<RedisProxy>,
    cancel: CancellationToken,
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

fn policies_toml(provider: &str) -> String {
    format!(
        r#"
[[policy]]
name = "global"
regions = ["fr"]
min_ready = 2

[policy.block]
target_cooldown = "30m"
escalate_targets = 3
escalate_signals = 5
signal_window = "30m"
max_cooldown_share = 0.5

[policy.static]
cooldown = "15m"
quarantine_after = 3
retest_every = "6h"

[policy.criteria]
max_ttfb_ms = 3000
max_load_ms = 10000
min_success = 0.66

[policy.limits]
max_gb_per_day = 10

[[policy]]
name = "fr-web"
scope = "route_class"
match = "{provider}"
regions = ["fr"]
"#
    )
}

fn redis_url() -> Option<String> {
    let base = std::env::var("PROXYX_TEST_REDIS_URL").ok()?;
    let (scheme, rest) = base.split_once("://")?;
    let authority = rest.split('/').next().unwrap_or(rest);
    Some(format!("{scheme}://{authority}/{REDIS_DB}"))
}

/// Create the database `proxyx_api_<name>_test` empty, and return its URL.
async fn fresh_database(name: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let name = format!("proxyx_api_{name}_test");
    Ok(store::testing::backend_database(&name, true).await?)
}

pub fn uniq(prefix: &str) -> String {
    format!("{prefix}{}", &Uuid::new_v4().simple().to_string()[..10])
}

/// What a test changes in the default harness.
#[derive(Default)]
pub struct Options<'a> {
    /// Adapter TOML (`[[adapter]]` list) to load; none by default.
    pub adapters_toml: Option<&'a str>,
    /// The exit-IP check services of the API; the public default when unset.
    pub exit_ip: Option<ExitIpConfig>,
    /// Page URLs of the `fr` probe targets besides the first.
    pub extra_fr_targets: usize,
    /// Give the API its own Redis connection through a [`RedisProxy`] the test
    /// can cut, while `Harness::hot` stays direct.
    pub redis_proxy: bool,
    /// Policy TOML (`[[policy]]` tables) added to the default policies, for
    /// tests that need an org policy: the API reads one fixed set.
    pub extra_policies: &'a str,
    /// Wrong credentials per source before a `429`: the API default (20) when
    /// set; the tests that send many wrong credentials on purpose otherwise
    /// run with a limit they never reach.
    pub default_failure_limit: bool,
}

/// Start the API against a fresh database and the shared Redis. `None`
/// (after a message) when the services are not configured.
pub async fn harness(name: &str) -> Result<Option<Harness>, Box<dyn std::error::Error>> {
    harness_with(name, Options::default()).await
}

/// [`harness`] with adapters and exit-IP services of the test's choosing.
pub async fn harness_with(
    name: &str,
    options: Options<'_>,
) -> Result<Option<Harness>, Box<dyn std::error::Error>> {
    let (Some(redis), Some(database)) = (redis_url(), fresh_database(name).await?) else {
        eprintln!("SKIP: PROXYX_TEST_REDIS_URL / PROXYX_TEST_DATABASE_URL is not set");
        return Ok(None);
    };
    let db = Db::connect(&database).await?;
    db.migrate().await?;
    let raw = proxyx_db::testing::Raw::connect(&database).await?;
    let hot = Hot::connect(&redis).await?;
    let proxy = if options.redis_proxy {
        Some(RedisProxy::start(&redis).await?)
    } else {
        None
    };
    let api_hot = match &proxy {
        Some(p) => Hot::connect(&p.url).await?,
        None => hot.clone(),
    };
    let provider = uniq("oxy");

    let dir = std::env::temp_dir().join(format!("proxyx-api-{}", Uuid::new_v4()));
    std::fs::create_dir_all(dir.join("secrets"))?;
    std::fs::create_dir_all(dir.join("data"))?;
    std::fs::write(dir.join("secrets/admin-token"), format!("{ADMIN}\n"))?;
    std::fs::write(dir.join("secrets/prober-token"), PROBER)?;
    std::fs::write(dir.join("secrets/probe-key"), PROBE_SECRET)?;
    let mut fr_targets = vec!["https://fr.test/".parse()?];
    for i in 0..options.extra_fr_targets {
        fr_targets.push(format!("https://fr.test/{i}").parse()?);
    }
    let settings = Settings {
        data_dir: dir.join("data"),
        secrets_dir: dir.join("secrets"),
        admin_token_file: dir.join("secrets/admin-token"),
        probe_key_file: dir.join("secrets/probe-key"),
        ..Settings::default()
    };

    let policies = format!("{}{}", policies_toml(&provider), options.extra_policies);
    let docs = PolicyFile::parse(&policies)?.policies;
    db.put_policies(&docs, "test").await?;
    let loaded = Loaded {
        policies: PolicySet::from_docs(docs)?,
        adapters: {
            let default_adapter = format!(
                "[[adapter]]\nid = \"{provider}\"\nkind = \"static\"\nsubtype = \"isp\"\n\
                 scheme = \"http\"\ncredentials_optional = true\nuser = \"{{base_user}}\"\n\
                 pass = \"{{base_pass}}\"\n"
            );
            AdapterSet::from_configs(
                toml::from_str::<AdapterFile>(options.adapters_toml.unwrap_or(&default_adapter))?
                    .adapter,
                &|name: &str| Err(anyhow::anyhow!("no secret {name}")),
            )?
        },
        probe_targets: ProbeTargets::new(
            vec!["https://any.test/".parse()?],
            HashMap::from([("fr".to_owned(), fr_targets)]),
        ),
        snapshot: Snapshot::load(&db).await?,
        loaded_at: Instant::now(),
    };
    // The API only reads the current value, which stays after the sender drops.
    let (_, rx) = watch::channel(Arc::new(loaded));

    let metrics = Arc::new(Metrics::new("test"));
    let tunnels = Arc::new(FakeTunnels::default());
    let exit_ip = ExitIpChecker::new(options.exit_ip.unwrap_or_default(), metrics.clone());
    let mut state = ApiState::new(
        &settings,
        db.clone(),
        api_hot,
        rx.clone(),
        metrics.clone(),
        tunnels.clone(),
        exit_ip,
    )?;
    if !options.default_failure_limit {
        state = state.with_failure_limit(1_000_000);
    }
    let state = Arc::new(state);
    let cancel = CancellationToken::new();
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(proxyx_pool_api::serve_listener(
        listener,
        state,
        cancel.clone(),
    ));
    Ok(Some(Harness {
        base: format!("http://{addr}"),
        client: reqwest::Client::new(),
        db,
        raw,
        hot,
        loaded: rx,
        metrics,
        tunnels,
        provider,
        data_dir: dir.join("data"),
        proxy,
        cancel,
    }))
}

/// Send `req` with an optional JSON `body`; the answer is the status and the
/// JSON body (`Null` when empty, the text when it is not JSON).
async fn finish(mut req: reqwest::RequestBuilder, body: Option<Value>) -> (StatusCode, Value) {
    if let Some(body) = body {
        req = req.json(&body);
    }
    let resp = req.send().await.expect("request");
    let status = resp.status();
    let text = resp.text().await.expect("body");
    let json = if text.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&text).unwrap_or(Value::String(text))
    };
    (status, json)
}

impl Harness {
    /// One request; the answer is the status and the JSON body (`Null` when
    /// empty). `auth` is the whole `Authorization` value.
    pub async fn send(
        &self,
        method: Method,
        path: &str,
        auth: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut req = self.client.request(method, format!("{}{path}", self.base));
        if let Some(auth) = auth {
            req = req.header("authorization", auth);
        }
        finish(req, body).await
    }

    pub async fn admin(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        self.send(method, path, Some(&format!("Bearer {ADMIN}")), body)
            .await
    }

    /// Admin `GET`, `DELETE`, `PUT` and `POST` with a JSON body, the
    /// requests most tests make.
    pub async fn get(&self, path: &str) -> (StatusCode, Value) {
        self.admin(Method::GET, path, None).await
    }

    pub async fn delete(&self, path: &str) -> (StatusCode, Value) {
        self.admin(Method::DELETE, path, None).await
    }

    pub async fn put(&self, path: &str, body: Value) -> (StatusCode, Value) {
        self.admin(Method::PUT, path, Some(body)).await
    }

    pub async fn post(&self, path: &str, body: Value) -> (StatusCode, Value) {
        self.admin(Method::POST, path, Some(body)).await
    }

    /// `GET /v1/probe/targets` as the prober.
    pub async fn probe_targets(&self) -> (StatusCode, Value) {
        let auth = format!("Bearer {PROBER}");
        self.send(Method::GET, "/v1/probe/targets", Some(&auth), None)
            .await
    }

    /// `POST /v1/probe/results` as the prober.
    pub async fn probe_results(&self, body: Value) -> (StatusCode, Value) {
        let auth = format!("Bearer {PROBER}");
        self.send(Method::POST, "/v1/probe/results", Some(&auth), Some(body))
            .await
    }

    /// An admin request that names the person in `X-Operator`.
    pub async fn send_as_operator(
        &self,
        method: Method,
        path: &str,
        operator: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let req = self
            .client
            .request(method, format!("{}{path}", self.base))
            .bearer_auth(ADMIN)
            .header("x-operator", operator);
        finish(req, body).await
    }

    pub fn partition(&self) -> Partition {
        Partition {
            provider: self.provider.parse().expect("provider"),
            region: "fr".parse().expect("region"),
        }
    }

    pub fn entry(&self, ip: IpAddr, subtype: Subtype) -> InventoryEntry {
        InventoryEntry {
            provider: self.provider.parse().expect("provider"),
            subtype,
            plan: "test".into(),
            ip,
            host: ip.to_string(),
            port: 8000,
            region: "fr".parse().expect("region"),
            asn: None,
            credentials: None,
            box_handle: None,
            rental_end: None,
        }
    }

    /// `n` static IPs of the harness provider: in the inventory as
    /// `Available` and in the ready set.
    pub async fn seed_ips(&self, n: usize) -> Result<Vec<IpAddr>, Box<dyn std::error::Error>> {
        self.seed_ips_of(n, Subtype::Isp).await
    }

    pub async fn seed_ips_of(
        &self,
        n: usize,
        subtype: Subtype,
    ) -> Result<Vec<IpAddr>, Box<dyn std::error::Error>> {
        let mut ips = Vec::new();
        for _ in 0..n {
            let b = Uuid::new_v4();
            let ip = IpAddr::from([10, b.as_bytes()[0], b.as_bytes()[1], b.as_bytes()[2]]);
            self.db
                .upsert_inventory_entry(&self.entry(ip, subtype), "test")
                .await?;
            self.db
                .transition_ip(ip, &Transition::to(IpState::Available, "test"), "test")
                .await?;
            self.hot
                .ready_put(&self.partition(), &UnitRecord::static_ip(ip))
                .await?;
            ips.push(ip);
        }
        Ok(ips)
    }

    pub async fn state_of(&self, ip: IpAddr) -> IpState {
        self.db
            .inventory_row(ip)
            .await
            .expect("row")
            .expect("inventory ip")
            .state
    }

    /// Register an org key and return it.
    pub async fn org_key(&self, org: &OrgId) -> Result<String, Box<dyn std::error::Error>> {
        let key = uniq("key");
        self.db
            .add_org_key(org, &Secret::new(key.clone()), "test", "test")
            .await?;
        Ok(key)
    }

    /// Record a tunnel session for `org` on a unit.
    pub async fn session(
        &self,
        org: &OrgId,
        unit: &str,
        ip: IpAddr,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let id = Uuid::new_v4().simple().to_string();
        self.hot
            .session_put(
                &id,
                &store::SessionRecord {
                    org: org.clone(),
                    partition: self.partition(),
                    unit: unit.to_owned(),
                    ip,
                },
                Duration::from_secs(600),
            )
            .await?;
        Ok(id)
    }
}

/// The `error` message of an error reply.
pub fn error_of(body: &Value) -> &str {
    body["error"]
        .as_str()
        .unwrap_or_else(|| panic!("no error in {body}"))
}

pub fn org(name: &str) -> OrgId {
    name.parse().expect("org id")
}

pub fn basic(user: &str, key: &str) -> String {
    use base64::Engine as _;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{user}:{key}"))
    )
}

// --- Customer upstream stubs (shared by the upstream and backfill tests) ---

/// The shipped customer adapters without the public-address rule: the stub
/// proxies are on loopback.
pub const CUSTOMER_ADAPTERS: &str = r#"
[[adapter]]
id = "customer"
kind = "static"
subtype = "datacenter"
scheme = "http"
credentials_optional = true
user = "{base_user}"
pass = "{base_pass}"

[[adapter]]
id = "customer_socks5"
kind = "static"
subtype = "datacenter"
scheme = "socks5"
credentials_optional = true
user = "{base_user}"
pass = "{base_pass}"

[[adapter]]
id = "customer_https"
kind = "static"
subtype = "datacenter"
scheme = "https"
credentials_optional = true
user = "{base_user}"
pass = "{base_pass}"
"#;

/// IP-check services that only answer through a stub proxy.
pub fn exit_ip_config() -> ExitIpConfig {
    let svc = |kind, path: &str| CheckService {
        kind,
        url: format!("http://exit-check.test/{path}"),
    };
    ExitIpConfig {
        services: vec![
            svc(ServiceKind::Ipify, "ipify?format=json"),
            svc(ServiceKind::Cloudflare, "cloudflare"),
            svc(ServiceKind::Ipinfo, "ipinfo"),
        ],
        min_agree: 2,
        timeout: Duration::from_secs(3),
    }
}

pub fn customer_partition() -> Partition {
    Partition {
        provider: "customer".parse().expect("provider"),
        region: "fr".parse().expect("region"),
    }
}

/// Lease from the `customer@fr` partition as `org`.
pub async fn lease(
    h: &Harness,
    org: &OrgId,
    sticky: &str,
) -> Result<LeaseOutcome, Box<dyn std::error::Error>> {
    let target = Target {
        host: "example.com".into(),
        port: 443,
    };
    Ok(h.hot
        .lease_ranked(
            &LeaseRequest {
                partition: &customer_partition(),
                kind: Kind::Static,
                org,
                sticky,
                target: &target,
                tunnel: Uuid::new_v4(),
                pool: Pool::Shared,
                limits: LeaseLimits {
                    lease_ttl: Duration::from_secs(60),
                    tunnel_ttl: Duration::from_secs(60),
                    orgs_hard: None,
                    max_conns_per_ip: None,
                    provider_conns_per_ip: None,
                    rest_after_release: Duration::ZERO,
                    min_remaining: Duration::ZERO,
                    allow_create: false,
                },
            },
            &[],
            store::MAX_RANK,
        )
        .await?)
}

/// The request head of a proxied request.
pub async fn read_head(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if buf.len() > 16 * 1024 || stream.read(&mut byte).await? == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        buf.push(byte[0]);
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Answer a proxied request as an org's own upstream: `407` unless the head
/// carries `expected` as its `Proxy-Authorization`, else what the IP-check
/// services say for `exit` (country FR).
pub async fn answer_proxied(
    mut stream: TcpStream,
    head: &str,
    expected: &str,
    exit: Ipv4Addr,
) -> std::io::Result<()> {
    let mut lines = head.lines();
    let uri = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or_default();
    let authorised = lines.any(|l| {
        l.split_once(':').is_some_and(|(k, v)| {
            k.eq_ignore_ascii_case("proxy-authorization") && v.trim() == expected
        })
    });
    if !authorised {
        return stream
            .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
            .await;
    }
    let (content_type, body) = if uri.contains("/cloudflare") {
        ("text/plain", format!("ip={exit}\nloc=FR\n"))
    } else if uri.contains("/ipinfo") {
        (
            "application/json",
            format!(r#"{{"ip":"{exit}","country":"FR"}}"#),
        )
    } else {
        ("application/json", format!(r#"{{"ip":"{exit}"}}"#))
    };
    stream
        .write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await
}
