//! `/readyz` of the real roles (`proxyx_pool::roles`) never answers 200 before
//! the role owns every listener it serves, and a listener that cannot bind
//! ends the role with an error that names it. In-process on the local Redis
//! and a fresh database per test, on the backend `PROXYX_TEST_BACKEND` selects
//! (PostgreSQL when unset). Skips with a message when the local services are
//! not set up (`PROXYX_TEST_REDIS_URL` and the selected backend's test
//! variable). The Redis database is the one the URL names, DB 11 when it names
//! none.

use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, anyhow, bail};
use common::Secret;
use common::config::Settings;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use verify::ExitIpConfig;

type TestResult = anyhow::Result<()>;
type Role = JoinHandle<anyhow::Result<()>>;

/// No test of this binary flushes it: the roles only read and write their own
/// keys.
const REDIS_DB: &str = "11";
const WAIT: Duration = Duration::from_secs(60);
const POLL: Duration = Duration::from_millis(2);

/// A directory removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> std::io::Result<Self> {
        let dir =
            std::env::temp_dir().join(format!("proxyx-ready-{label}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir)?;
        Ok(Self(dir))
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn write(&self, rel: &str, content: &str) -> std::io::Result<()> {
        let path = self.0.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, content)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A free loopback address (bound, read and released).
fn free_addr() -> std::io::Result<SocketAddr> {
    TcpListener::bind("127.0.0.1:0")?.local_addr()
}

fn exit_ip_config() -> ExitIpConfig {
    ExitIpConfig {
        services: vec![],
        min_agree: 1,
        timeout: Duration::from_secs(2),
    }
}

/// Settings of one test: free listeners, a migrated database and a data
/// directory the gateway can load. No role is running yet.
struct Fixture {
    settings: Settings,
    _data: TempDir,
}

async fn fixture(name: &str) -> anyhow::Result<Option<Fixture>> {
    let Ok(redis) = std::env::var("PROXYX_TEST_REDIS_URL") else {
        eprintln!("SKIP: PROXYX_TEST_REDIS_URL is not set");
        return Ok(None);
    };
    let (scheme, rest) = redis
        .split_once("://")
        .ok_or_else(|| anyhow!("redis url has no scheme"))?;
    let authority = rest.split('/').next().unwrap_or(rest);
    // the database index of the URL when it names one
    let redis_db = rest
        .split_once('/')
        .map(|(_, db)| db)
        .filter(|db| !db.is_empty())
        .unwrap_or(REDIS_DB);
    let redis_url = format!("{scheme}://{authority}/{redis_db}");
    let Some(database_url) =
        store::testing::backend_database(&format!("proxyx_pool_ready_{name}_test"), true).await?
    else {
        return Ok(None);
    };
    store::Db::connect(&database_url).await?.migrate().await?;

    let data = TempDir::new(name)?;
    data.write("secrets/stub_user", "stub-user")?;
    data.write("secrets/stub_pass", "stub-pass")?;
    data.write("secrets/admin-token", "admin-token-for-tests")?;
    data.write("secrets/prober-token", "prober-token-for-tests")?;
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
sticky_scope = "target"
lease_wait = "3s"

[policy.criteria]
browser_sample = 0.0
"#,
    )?;
    // Nothing listens on the entry: no test here needs a leasable IP.
    data.write(
        "data/inventory/stubprov.toml",
        "[[entry]]\nprovider = \"stubprov\"\nsubtype = \"datacenter\"\nip = \"198.51.100.11\"\nhost = \"127.0.0.1\"\nport = 9\nregion = \"fr\"\n",
    )?;

    let settings = Settings {
        database_url: Secret::new(database_url.as_str()),
        redis_url: Secret::new(redis_url.as_str()),
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
    Ok(Some(Fixture {
        settings,
        _data: data,
    }))
}

fn spawn_gateway(settings: &Settings, cancel: &CancellationToken) -> Role {
    tokio::spawn(proxyx_pool::roles::gateway(
        settings.clone(),
        "ready-gateway",
        exit_ip_config(),
        cancel.clone(),
    ))
}

/// The status code of `/readyz` of `ops`; `None` when nothing answers.
async fn readyz(http: &reqwest::Client, ops: SocketAddr) -> Option<u16> {
    let res = http.get(format!("http://{ops}/readyz")).send().await.ok()?;
    Some(res.status().as_u16())
}

/// True when something else owns `addr`: the process cannot bind it.
fn is_owned(addr: SocketAddr) -> bool {
    matches!(
        TcpListener::bind(addr),
        Err(err) if err.kind() == std::io::ErrorKind::AddrInUse
    )
}

/// Poll `/readyz` until it answers 200 and return at once, so the caller
/// checks what the role owns at that moment. Fails when the role ends first.
async fn first_ready(http: &reqwest::Client, ops: SocketAddr, role: &mut Role) -> TestResult {
    tokio::time::timeout(WAIT, async {
        loop {
            tokio::select! {
                ended = &mut *role => bail!("the role ended before it was ready: {ended:?}"),
                () = tokio::time::sleep(POLL) => {}
            }
            if readyz(http, ops).await == Some(200) {
                return Ok(());
            }
        }
    })
    .await
    .context("the role never became ready")?
}

async fn stop(cancel: &CancellationToken, role: Role) -> TestResult {
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(30), role)
        .await
        .context("the role did not stop")??
        .context("a stop request ends the role cleanly")
}

#[tokio::test]
async fn ready_means_the_api_and_every_tunnel_listener_is_bound() -> TestResult {
    let Some(fx) = fixture("bound").await? else {
        return Ok(());
    };
    let s = &fx.settings;
    let http = reqwest::Client::new();
    for addr in [
        s.connect_listen,
        s.socks_listen,
        s.probe_listen,
        s.api_listen,
    ] {
        assert!(!is_owned(addr), "{addr} is free before the role starts");
    }
    let cancel = CancellationToken::new();
    let mut role = spawn_gateway(s, &cancel);

    first_ready(&http, s.ops_listen, &mut role).await?;
    // checked right after the first 200, not after the role settled
    for (name, addr) in [
        ("connect", s.connect_listen),
        ("socks", s.socks_listen),
        ("probe", s.probe_listen),
        ("api", s.api_listen),
    ] {
        assert!(
            is_owned(addr),
            "/readyz was 200 but the {name} listener {addr} is not bound"
        );
    }
    stop(&cancel, role).await
}

/// Occupy the listener `set` points at, start the gateway role and require
/// that `/readyz` never answers 200 and the role fails naming `expected`.
async fn occupied(name: &str, set: fn(&mut Settings, SocketAddr), what: &str) -> TestResult {
    let Some(fx) = fixture(name).await? else {
        return Ok(());
    };
    let holder = TcpListener::bind("127.0.0.1:0")?;
    let taken = holder.local_addr()?;
    let mut settings = fx.settings.clone();
    set(&mut settings, taken);
    let expected = format!("{what} {taken}");

    let http = reqwest::Client::new();
    let cancel = CancellationToken::new();
    let mut role = spawn_gateway(&settings, &cancel);
    let mut ready_seen = 0u32;
    let ended = tokio::time::timeout(WAIT, async {
        loop {
            tokio::select! {
                ended = &mut role => return ended,
                () = tokio::time::sleep(POLL) => {}
            }
            if readyz(&http, settings.ops_listen).await == Some(200) {
                ready_seen += 1;
            }
        }
    })
    .await
    .context("a role whose listener is taken must end on its own")?;

    assert_eq!(ready_seen, 0, "/readyz answered 200 with {taken} taken");
    let err = ended?.expect_err("the role must fail when it cannot bind");
    assert!(
        format!("{err:#}").contains(&expected),
        "the error does not name the listener: {err:#}"
    );
    drop(holder);
    Ok(())
}

#[tokio::test]
async fn an_occupied_api_listener_never_reports_ready() -> TestResult {
    occupied(
        "api_taken",
        |s, addr| s.api_listen = addr,
        "failed to bind the control API to",
    )
    .await
}

#[tokio::test]
async fn an_occupied_connect_listener_never_reports_ready() -> TestResult {
    occupied(
        "connect_taken",
        |s, addr| s.connect_listen = addr,
        "failed to bind the connect listener on",
    )
    .await
}

#[tokio::test]
async fn an_occupied_socks_listener_never_reports_ready() -> TestResult {
    occupied(
        "socks_taken",
        |s, addr| s.socks_listen = addr,
        "failed to bind the socks listener on",
    )
    .await
}

#[tokio::test]
async fn an_occupied_probe_listener_never_reports_ready() -> TestResult {
    occupied(
        "probe_taken",
        |s, addr| s.probe_listen = addr,
        "failed to bind the probe listener on",
    )
    .await
}

#[tokio::test]
async fn the_warmer_still_becomes_ready() -> TestResult {
    let Some(fx) = fixture("warmer").await? else {
        return Ok(());
    };
    let http = reqwest::Client::new();
    let cancel = CancellationToken::new();
    // the gateway syncs the git policies and inventory the warmer waits for
    let mut gateway = spawn_gateway(&fx.settings, &cancel);
    first_ready(&http, fx.settings.ops_listen, &mut gateway).await?;

    // separate pods in production: the warmer needs its own ops port
    let warmer_settings = Settings {
        ops_listen: free_addr()?,
        ..fx.settings.clone()
    };
    let mut warmer = tokio::spawn(proxyx_pool::roles::warmer(
        warmer_settings.clone(),
        "ready-warmer",
        exit_ip_config(),
        cancel.clone(),
    ));
    first_ready(&http, warmer_settings.ops_listen, &mut warmer).await?;

    cancel.cancel();
    let (gateway, warmer) = tokio::time::timeout(Duration::from_secs(60), async {
        (gateway.await, warmer.await)
    })
    .await
    .context("the roles did not stop")?;
    gateway??;
    warmer??;
    Ok(())
}
