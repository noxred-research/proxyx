//! End-to-end: the real gateway and warmer roles (`proxyx_pool::roles`), run
//! in-process on the local Redis (DB 5) and a fresh Postgres database, against
//! stub upstream proxies that stand in for a provider and the IP-check
//! services. Skips with a message when the local services are not set up.
//!
//! The `migrate` tests run the built binary.

#[macro_use]
#[path = "support_pool/mod.rs"]
mod support;

use common::types::Partition;
use std::net::{IpAddr, SocketAddr};
use std::process::Command;
use std::time::Duration;

use common::Secret;
use common::config::Settings;
use serde_json::{Value, json};
use support::{
    Connected, REDIS_DB, TempDir, TestResult, Upstreams, connect_via, eventually, flush_redis,
    free_addr, services,
};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use verify::{CheckService, ExitIpConfig, ServiceKind};

const PROVIDER_USER: &str = "stub-user";
const PROVIDER_PASS: &str = "stub-pass";
const ADMIN_TOKEN: &str = "admin-token-for-tests";
const PROBER_TOKEN: &str = "prober-token-for-tests";
const ORG: &str = "e2e_org";
const TARGET_A: &str = "a.example:443";
const TARGET_B: &str = "b.example:443";

/// A key is waiting for the warmer to verify the inventory, which takes a
/// few ticks.
const READY_WITHIN: Duration = Duration::from_secs(90);

fn exit_ip_config() -> ExitIpConfig {
    let svc = |kind, path: &str| CheckService {
        kind,
        url: format!("http://ipcheck.test/{path}"),
    };
    ExitIpConfig {
        services: vec![
            svc(ServiceKind::Ipify, "ipify"),
            svc(ServiceKind::Cloudflare, "cloudflare"),
            svc(ServiceKind::Ipinfo, "ipinfo"),
        ],
        min_agree: 2,
        timeout: Duration::from_secs(5),
    }
}

/// The two roles of one run.
struct Roles {
    cancel: CancellationToken,
    gateway: JoinHandle<anyhow::Result<()>>,
    warmer: JoinHandle<anyhow::Result<()>>,
}

impl Roles {
    fn start(settings: &Settings) -> std::io::Result<Self> {
        let cancel = CancellationToken::new();
        // Separate pods in production; here the warmer needs its own ops port.
        let warmer_settings = Settings {
            ops_listen: free_addr()?,
            ..settings.clone()
        };
        let gateway = tokio::spawn(proxyx_pool::roles::gateway(
            settings.clone(),
            "e2e-gateway",
            exit_ip_config(),
            cancel.clone(),
        ));
        let warmer = tokio::spawn(proxyx_pool::roles::warmer(
            warmer_settings,
            "e2e-warmer",
            exit_ip_config(),
            cancel.clone(),
        ));
        Ok(Self {
            cancel,
            gateway,
            warmer,
        })
    }

    /// Stop both roles and require a clean exit.
    async fn stop(self) -> TestResult {
        self.cancel.cancel();
        let (gateway, warmer) = tokio::time::timeout(Duration::from_secs(60), async {
            (self.gateway.await, self.warmer.await)
        })
        .await
        .map_err(|_| "roles did not stop within 60 s")?;
        gateway??;
        warmer??;
        Ok(())
    }

    /// Resolves when either role has ended on its own, with how it ended.
    async fn exited(&mut self) -> String {
        let (role, result) = tokio::select! {
            r = &mut self.gateway => ("gateway", r),
            r = &mut self.warmer => ("warmer", r),
        };
        format!("the {role} role ended early: {result:?}")
    }

    /// Wait until the gateway's ops server is ready, or fail at once when a
    /// role dies during startup.
    async fn ready(&mut self, fx: &Fixture, http: &reqwest::Client) -> TestResult {
        tokio::select! {
            ready = fx.wait_ready(http) => ready,
            why = self.exited() => Err(why.into()),
        }
    }
}

struct Fixture {
    services: support::Services,
    settings: Settings,
    upstreams: Upstreams,
    /// Exit IPs of the two stub endpoints.
    ips: [IpAddr; 2],
    _data: TempDir,
}

impl Fixture {
    /// Data directory, secrets, a migrated database, an empty Redis DB
    /// (`redis_db`: one per test that runs roles, see [`REDIS_DB`]) and the
    /// stub provider; no role is running yet.
    async fn new(name: &str, redis_db: u8) -> Result<Option<Self>, Box<dyn std::error::Error>> {
        // RUST_LOG shows the roles' logs of a failing run.
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .try_init();
        let Some(services) = services(name, redis_db).await? else {
            return Ok(None);
        };
        store::Db::connect(&services.database_url)
            .await?
            .migrate()
            .await?;
        flush_redis(&services.redis_url).await?;

        let ips: [IpAddr; 2] = ["198.51.100.11".parse()?, "198.51.100.12".parse()?];
        let upstreams = Upstreams::start(&ips, PROVIDER_USER, PROVIDER_PASS).await?;

        let data = TempDir::new(name)?;
        data.write("secrets/stub_user", PROVIDER_USER)?;
        data.write("secrets/stub_pass", PROVIDER_PASS)?;
        data.write("secrets/admin-token", ADMIN_TOKEN)?;
        data.write("secrets/prober-token", PROBER_TOKEN)?;
        // The light probe reads a plain-HTTP page through the stub upstream
        // instead of the built-in public default.
        data.write(
            "data/probe-targets.toml",
            "global = [\"http://probe.test/\"]\n",
        )?;
        data.write(
            "data/adapters/stub.toml",
            r#"
[[adapter]]
id = "stubprov"
kind = "static"
subtype = "datacenter"
scheme = "http"
user_file = "stub_user"
pass_file = "stub_pass"
user = "{base_user}"
pass = "{base_pass}"
max_conns_per_ip = 100
"#,
        )?;
        data.write(
            "data/policies/global.toml",
            r#"
[[policy]]
name = "global"
scope = "global"
kinds = ["static"]
regions = ["fr"]
# One lease per (org, target): a block on one target moves only that target.
sticky_scope = "target"
lease_wait = "3s"

# A browser sample (5% of the new IPs by default) pins an IP for the probe
# org, so the org cap would make a customer share its own IP: no samples here.
[policy.criteria]
browser_sample = 0.0
"#,
        )?;
        let mut inventory = String::new();
        for ip in &ips {
            let port = upstreams.endpoints[ip].port();
            inventory.push_str(&format!(
                "[[entry]]\nprovider = \"stubprov\"\nsubtype = \"datacenter\"\nip = \"{ip}\"\nhost = \"127.0.0.1\"\nport = {port}\nregion = \"fr\"\n\n"
            ));
        }
        data.write("data/inventory/stubprov.toml", &inventory)?;

        let settings = Settings {
            database_url: Secret::new(services.database_url.as_str()),
            redis_url: Secret::new(services.redis_url.as_str()),
            connect_listen: free_addr()?,
            socks_listen: free_addr()?,
            probe_listen: free_addr()?,
            api_listen: free_addr()?,
            ops_listen: free_addr()?,
            data_dir: data.path().join("data"),
            secrets_dir: data.path().join("secrets"),
            admin_token_file: data.path().join("secrets/admin-token"),
            drain_timeout: Duration::from_secs(2),
            reload_every: Duration::from_secs(1),
            ..Settings::default()
        };
        Ok(Some(Self {
            services,
            settings,
            upstreams,
            ips,
            _data: data,
        }))
    }

    fn api(&self, path: &str) -> String {
        format!("http://{}{path}", self.settings.api_listen)
    }

    /// Wait until the gateway's ops server reports ready and its API is listening.
    async fn wait_ready(&self, http: &reqwest::Client) -> TestResult {
        let url = format!("http://{}/readyz", self.settings.ops_listen);
        eventually(Duration::from_secs(60), || async {
            let res = http.get(&url).send().await.ok()?;
            if !res.status().is_success() {
                return None;
            }
            drop(
                tokio::net::TcpStream::connect(self.settings.api_listen)
                    .await
                    .ok()?,
            );
            Some(())
        })
        .await
        .ok_or("the gateway never became ready")?;
        Ok(())
    }

    /// Wait until the warmer made every inventory IP leasable. It verifies
    /// the IPs concurrently, so one is leasable before the other; a test that
    /// leases while only one is, cannot tell a preference for idle IPs from
    /// the lack of a second one.
    async fn wait_inventory_ready(&self) -> TestResult {
        let hot = store::Hot::connect(&self.services.redis_url).await?;
        let partition = Partition {
            provider: "stubprov".parse()?,
            region: "fr".parse()?,
        };
        let mut want: Vec<String> = self.ips.iter().map(IpAddr::to_string).collect();
        want.sort();
        let (hot, partition, want) = (&hot, &partition, &want);
        eventually(READY_WITHIN, || async move {
            (hot.ready_ids(partition).await.ok()? == *want).then_some(())
        })
        .await
        .ok_or("the warmer did not make every inventory ip leasable")?;
        Ok(())
    }

    /// A CONNECT on the customer listener that must succeed.
    async fn tunnel(
        &self,
        key: &str,
        target: &str,
    ) -> Result<Connected, Box<dyn std::error::Error>> {
        tunnel_via(self.settings.connect_listen, key, target).await
    }

    async fn post_block(
        &self,
        http: &reqwest::Client,
        key: &str,
        session: &str,
        ip: IpAddr,
        target: &str,
    ) -> TestResult {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let res = http
            .post(self.api("/v1/block-signals"))
            .basic_auth("px", Some(key))
            .json(&json!([{
                "session": session,
                "exit_ip": ip.to_string(),
                "org": ORG,
                "target": target,
                "type": "rate_limited",
                "status": 429,
                "time": now,
            }]))
            .send()
            .await?;
        let status = res.status();
        assert!(
            status.is_success(),
            "block signal answered {status}: {}",
            res.text().await?
        );
        Ok(())
    }
}

/// A CONNECT on `listener` that must succeed, retried while the warmer
/// verifies IPs (or the prober key gets registered).
async fn tunnel_via(
    listener: SocketAddr,
    key: &str,
    target: &str,
) -> Result<Connected, Box<dyn std::error::Error>> {
    let last = parking_lot::Mutex::new(String::from("no answer"));
    let last_ref = &last;
    let got = eventually(READY_WITHIN, || async move {
        let note = match connect_via(listener, "px", key, target).await {
            Ok(c) if c.status == 200 => return Some(c),
            Ok(c) => format!("status {}", c.status),
            Err(e) => e.to_string(),
        };
        *last_ref.lock() = note;
        None
    })
    .await;
    let last = last.into_inner();
    got.ok_or_else(|| format!("no tunnel to {target} within {READY_WITHIN:?}: {last}").into())
}

fn exit_ip_of(conn: &Connected) -> Result<IpAddr, Box<dyn std::error::Error>> {
    Ok(conn
        .header("x-proxyx-exit-ip")
        .ok_or("reply has no X-ProxyX-Exit-IP")?
        .parse()?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tunnels_follow_blocks_and_survive_redis_loss_and_restart() -> TestResult {
    let fx = or_skip!(Fixture::new("lifecycle", REDIS_DB).await?);
    let http = reqwest::Client::new();
    let mut roles = Roles::start(&fx.settings)?;
    roles.ready(&fx, &http).await?;

    // An org key from the API (admin bearer); the reply is the only time the
    // key is readable.
    let created: Value = http
        .post(fx.api(&format!("/v1/orgs/{ORG}/keys")))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let key = created["key"].as_str().ok_or("no key in reply")?.to_owned();
    fx.wait_inventory_ready().await?;

    // A tunnel reaches the stub target through a stub upstream and carries the
    // reply headers.
    let mut a1 = fx.tunnel(&key, TARGET_A).await?;
    let ip_a = exit_ip_of(&a1)?;
    let session = a1
        .header("x-proxyx-pool-session")
        .ok_or("reply has no X-ProxyX-Pool-Session")?
        .to_owned();
    assert!(
        fx.ips.contains(&ip_a),
        "exit ip {ip_a} is one of the inventory ips"
    );
    assert_eq!(
        a1.echo(b"hello through proxyx").await?,
        b"hello through proxyx"
    );
    assert_eq!(
        fx.upstreams.ips_for(TARGET_A),
        [ip_a],
        "the stub upstream of that ip saw the CONNECT"
    );

    // Another target leases its own IP (one lease per org and target).
    let mut b1 = fx.tunnel(&key, TARGET_B).await?;
    let ip_b = exit_ip_of(&b1)?;
    assert_ne!(ip_a, ip_b, "an idle ip is preferred over sharing");

    // A block signal cools ip_a for target A only.
    fx.post_block(&http, &key, &session, ip_a, TARGET_A).await?;
    let mut a2 = fx.tunnel(&key, TARGET_A).await?;
    assert_eq!(exit_ip_of(&a2)?, ip_b, "target A moved off the cooled ip");
    let mut b2 = fx.tunnel(&key, TARGET_B).await?;
    assert_eq!(exit_ip_of(&b2)?, ip_b, "target B keeps its ip");
    for conn in [&mut a2, &mut b2, &mut a1, &mut b1] {
        assert_eq!(conn.echo(b"x").await?, b"x");
    }
    drop((a1, b1, a2, b2));

    // Redis loses everything: the warmer rebuilds it from Postgres, the
    // cooldown included, and tunnels work again.
    flush_redis(&fx.services.redis_url).await?;
    let a3 = fx.tunnel(&key, TARGET_A).await?;
    assert_eq!(
        exit_ip_of(&a3)?,
        ip_b,
        "the target cooldown of ip {ip_a} survived the rebuild"
    );
    let b3 = fx.tunnel(&key, TARGET_B).await?;
    assert!(fx.ips.contains(&exit_ip_of(&b3)?));
    drop((a3, b3));

    // Kill and restart both roles: the org key, inventory and cooldown come
    // back from Postgres and the tunnels keep working.
    roles.stop().await?;
    let mut roles = Roles::start(&fx.settings)?;
    roles.ready(&fx, &http).await?;
    let a4 = fx.tunnel(&key, TARGET_A).await?;
    assert_eq!(exit_ip_of(&a4)?, ip_b, "the cooldown outlives a restart");
    drop(a4);
    roles.stop().await
}

const PROBE_SECRET: &str = "vault-generated-probe-secret";

/// The probe listener takes only the short-lived token the control API
/// issues from the Vault secret (a file the gateway mounts), and opens only
/// the hosts of `probe-targets.toml`. The secret itself is not a password.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_probe_listener_takes_the_api_token_and_opens_only_the_probe_hosts() -> TestResult {
    let mut fx = or_skip!(Fixture::new("probe_token_login", REDIS_DB + 1).await?);
    fx._data.write("secrets/probe-key", PROBE_SECRET)?;
    fx._data.write(
        "data/probe-targets.toml",
        "global = [\"http://probe.test/\"]\nextra_hosts = [\"a.example\"]\n",
    )?;
    fx.settings.probe_key_file = fx._data.path().join("secrets/probe-key");
    let http = reqwest::Client::new();
    let mut roles = Roles::start(&fx.settings)?;
    roles.ready(&fx, &http).await?;

    let res = http
        .post(fx.api("/v1/probe/token"))
        .bearer_auth(PROBER_TOKEN)
        .send()
        .await?;
    assert!(res.status().is_success(), "{}", res.status());
    let body: serde_json::Value = res.json().await?;
    let token = body["token"].as_str().ok_or("no token in the reply")?;
    assert_ne!(token, PROBE_SECRET);

    let mut tunnel = tunnel_via(fx.settings.probe_listen, token, TARGET_A).await?;
    assert_eq!(tunnel.echo(b"probe").await?, b"probe");

    // the secret itself and an unsigned password are refused
    for wrong in [PROBE_SECRET, "some-other-key"] {
        let refused = connect_via(fx.settings.probe_listen, "px", wrong, TARGET_A).await?;
        assert_eq!(refused.status, 407, "{wrong}");
    }
    // a host that is not a probe target is not opened, token or not
    let denied = connect_via(fx.settings.probe_listen, "px", token, TARGET_B).await?;
    assert_eq!(denied.status, 403);
    // the token opens nothing on the customer listener
    let refused = connect_via(fx.settings.connect_listen, "px", token, TARGET_A).await?;
    assert_eq!(refused.status, 407);

    // the token endpoint is the prober's
    let res = http
        .post(fx.api("/v1/probe/token"))
        .bearer_auth("not-the-prober-token")
        .send()
        .await?;
    assert_eq!(res.status(), 401);

    roles.stop().await
}

/// `proxyx migrate pool --check` against a fresh database: it lists the pending
/// migrations and fails; after `proxyx migrate pool` it passes.
#[tokio::test]
async fn migrate_check_reports_pending_then_clean() -> TestResult {
    let services = or_skip!(services("migrate", REDIS_DB).await?);
    let run = |args: &[&str]| -> std::io::Result<std::process::Output> {
        Command::new(env!("CARGO_BIN_EXE_proxyx"))
            .args(args)
            .env("PROXYX_POOL_DATABASE_URL", &services.database_url)
            .env("PROXYX_POOL_JSON_LOGS", "false")
            .output()
    };

    let pending = run(&["migrate", "pool", "--check"])?;
    assert!(
        !pending.status.success(),
        "a fresh database has pending migrations"
    );
    let out = String::from_utf8_lossy(&pending.stdout);
    assert!(
        out.contains("pending: "),
        "lists the pending migrations: {out}"
    );

    let applied = run(&["migrate", "pool"])?;
    assert!(
        applied.status.success(),
        "{}",
        String::from_utf8_lossy(&applied.stderr)
    );

    let clean = run(&["migrate", "pool", "--check"])?;
    assert!(
        clean.status.success(),
        "{}",
        String::from_utf8_lossy(&clean.stderr)
    );
    assert!(String::from_utf8_lossy(&clean.stdout).contains("no pending migrations"));
    Ok(())
}

/// A pod whose Postgres and Redis are down must not crash-loop: liveness
/// answers, readiness says not ready, and a stop request ends it cleanly.
#[tokio::test]
async fn missing_dependencies_keep_the_role_alive_but_not_ready() -> TestResult {
    let settings = Settings {
        // Nothing listens on port 1.
        database_url: Secret::new("postgres://proxyx@127.0.0.1:1/proxyx"),
        redis_url: Secret::new("redis://127.0.0.1:1"),
        ops_listen: free_addr()?,
        drain_timeout: Duration::from_secs(1),
        ..Settings::default()
    };
    let http = reqwest::Client::new();
    let cancel = CancellationToken::new();
    let mut role = tokio::spawn(proxyx_pool::roles::gateway(
        settings.clone(),
        "e2e-down",
        exit_ip_config(),
        cancel.clone(),
    ));

    let healthz = format!("http://{}/healthz", settings.ops_listen);
    eventually(Duration::from_secs(10), || async {
        let res = http.get(&healthz).send().await.ok()?;
        res.status().is_success().then_some(())
    })
    .await
    .ok_or("/healthz never answered")?;

    // Several retries pass; the role is still up and not ready.
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(!role.is_finished(), "the role gave up instead of retrying");
    let ready = http
        .get(format!("http://{}/readyz", settings.ops_listen))
        .send()
        .await?;
    assert_eq!(
        ready.status(),
        503,
        "not ready while the dependencies are down"
    );

    cancel.cancel();
    let ended = tokio::time::timeout(Duration::from_secs(10), &mut role)
        .await
        .map_err(|_| "the role did not stop")??;
    assert!(
        ended.is_ok(),
        "a stop request during startup is a clean exit: {ended:?}"
    );
    Ok(())
}
