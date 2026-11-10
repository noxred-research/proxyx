//! The pool gateway scenario: CONNECT tunnels, and HTTP requests over them,
//! through a gateway that leases from a stub provider.
//!
//! The gateway tunnels TCP only; it answers a plain `GET http://...` proxy
//! request with `405`. "Forward" therefore means a CONNECT to port 80 followed
//! by HTTP/1.1 requests over the tunnel.
//!
//! In spawn mode the tool builds the whole world the gateway needs: a stub
//! provider (an HTTP proxy that tunnels to local stubs), a static adapter, one
//! inventory unit that points at the stub, a policy, an org key in Postgres and
//! the unit in the Redis ready set. The warmer, which would normally verify
//! and ready units, is not needed.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::Secret;
use common::types::{InventoryEntry, IpState, OrgId, Partition, Subtype};
use store::{Db, Hot, Transition, UnitRecord};
use time::OffsetDateTime;
use tokio::net::TcpStream;

use crate::cli::{GatewayArgs, GatewayMode};
use crate::http1::{self, Conn};
use crate::load::{Connector, LoadError};
use crate::report::{Report, run_sweep};
use crate::session::{preflight, workdir};
use crate::stubs::{self, Routes};
use crate::target::{self, Spawned};

/// Target of a tunnel in `tunnel` mode. The destination rule refuses private
/// and loopback addresses, so the name must look public; the stub provider
/// ignores it and tunnels to its own stub.
pub const TUNNEL_TARGET: &str = "8.8.8.8:443";
/// Target of a tunnel in `forward` mode (the stub provider routes port 80 to
/// its HTTP origin).
pub const FORWARD_TARGET: &str = "8.8.8.8:80";

const DATABASE_NAME: &str = "proxyx_ops_bench";
const PROVIDER_ID: &str = "benchprov";
const PROVIDER_LOGIN: &str = "benchuser:benchpass";
const ORG: &str = "bench-org";
/// The org key; the shape `ak_` plus 43 URL-safe characters of a real key.
const ORG_KEY: &str = "ak_benchbenchbenchbenchbenchbenchbenchbench000";
const UNIT_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 18, 77, 1));
const STARTUP_LIMIT: Duration = Duration::from_secs(60);

/// A gateway load: one login, one target, one way to use the tunnel.
pub struct GatewayConnector {
    proxy: SocketAddr,
    proxy_authorization: String,
    authority: String,
    mode: GatewayMode,
    body: Vec<u8>,
}

impl GatewayConnector {
    pub fn new(
        proxy: SocketAddr,
        username: &str,
        password: &str,
        authority: &str,
        mode: GatewayMode,
        payload_bytes: usize,
    ) -> Self {
        Self {
            proxy,
            proxy_authorization: format!(
                "Basic {}",
                STANDARD.encode(format!("{username}:{password}"))
            ),
            authority: authority.to_owned(),
            mode,
            body: vec![b'x'; payload_bytes],
        }
    }
}

impl Connector for GatewayConnector {
    type Conn = Conn<TcpStream>;

    async fn connect(&self) -> Result<Self::Conn, LoadError> {
        let tcp =
            http1::connect_tunnel(self.proxy, &self.authority, &self.proxy_authorization).await?;
        Ok(Conn::new(tcp))
    }

    async fn exchange(&self, conn: &mut Self::Conn, close: bool) -> Result<u64, LoadError> {
        match self.mode {
            GatewayMode::Tunnel => {
                conn.write_all(&self.body).await?;
                let mut echoed = vec![0u8; self.body.len()];
                conn.read_exact_into(&mut echoed).await?;
                if echoed != self.body {
                    return Err(LoadError::protocol("the echo differs from the payload"));
                }
                Ok(2 * self.body.len() as u64)
            }
            GatewayMode::Forward => {
                let host = self.authority.split(':').next().unwrap_or(&self.authority);
                conn.post(host, &self.body, close).await
            }
        }
    }
}

/// The adapter, policy and inventory files of the spawned gateway.
pub struct DataFiles {
    pub adapter: String,
    pub policy: String,
    pub inventory: String,
}

pub fn data_files(provider_port: u16) -> DataFiles {
    DataFiles {
        adapter: format!(
            "[[adapter]]\nid = \"{PROVIDER_ID}\"\nkind = \"static\"\nsubtype = \"isp\"\n\
             user_file = \"bench_user\"\npass_file = \"bench_pass\"\n\
             user = \"{{base_user}}\"\npass = \"{{base_pass}}\"\n"
        ),
        policy: "[[policy]]\nname = \"global\"\nscope = \"global\"\nkinds = [\"static\"]\n\
                 regions = [\"fr\"]\nmin_ready = 1\nmax_ready = 2\nlease_ttl = \"10m\"\n\
                 lease_wait = \"1s\"\ncreate_deadline = \"3s\"\n"
            .to_owned(),
        inventory: format!(
            "[[entry]]\nprovider = \"{PROVIDER_ID}\"\nsubtype = \"isp\"\nplan = \"bench\"\n\
             ip = \"{UNIT_IP}\"\nhost = \"127.0.0.1\"\nport = {provider_port}\nregion = \"fr\"\n"
        ),
    }
}

/// The loopback addresses of a spawned gateway.
#[derive(Debug, Clone, Copy)]
pub struct Addrs {
    pub connect: SocketAddr,
    pub socks: SocketAddr,
    pub probe: SocketAddr,
    pub api: SocketAddr,
    pub ops: SocketAddr,
    /// Where the exit-IP check service is said to be. Nothing listens there:
    /// no check runs inside a bench, and the setting only has to be valid.
    pub dead_exit_check: SocketAddr,
}

impl Addrs {
    pub fn free() -> Result<Self> {
        Ok(Self {
            connect: target::free_addr()?,
            socks: target::free_addr()?,
            probe: target::free_addr()?,
            api: target::free_addr()?,
            ops: target::free_addr()?,
            dead_exit_check: target::free_addr()?,
        })
    }
}

/// The gateway's `pool.toml`.
pub fn pool_config(dir: &Path, database_url: &str, redis_url: &str, addrs: &Addrs) -> String {
    let Addrs {
        connect,
        socks,
        probe,
        api,
        ops,
        dead_exit_check,
    } = *addrs;
    let q = |s: &str| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""));
    let path = |p: &str| q(&dir.join(p).to_string_lossy());
    format!(
        "database_url = {db}\nredis_url = {redis}\n\
         connect_listen = {connect}\nsocks_listen = {socks}\nprobe_listen = {probe}\n\
         api_listen = {api}\nops_listen = {ops}\n\
         data_dir = {data}\nsecrets_dir = {secrets}\n\
         admin_token_file = {admin}\nprobe_key_file = {probe_key}\n\
         drain_timeout = \"2s\"\nreload_every = \"1s\"\njson_logs = false\n\
         exit_ip_services = {exit}\n",
        db = q(database_url),
        redis = q(redis_url),
        connect = q(&connect.to_string()),
        socks = q(&socks.to_string()),
        probe = q(&probe.to_string()),
        api = q(&api.to_string()),
        ops = q(&ops.to_string()),
        data = path("data"),
        secrets = path("secrets"),
        admin = path("secrets/admin-token"),
        probe_key = path("secrets/probe-key"),
        exit = q(&format!("ipinfo=http://{dead_exit_check}/json")),
    )
}

/// The database URL of the benchmark database on the server `base` names.
fn write_world(dir: &Path, files: &DataFiles) -> Result<()> {
    for (sub, name, text) in [
        ("data/adapters", "bench.toml", files.adapter.as_str()),
        ("data/policies", "global.toml", files.policy.as_str()),
        ("data/inventory", "bench.toml", files.inventory.as_str()),
        ("secrets", "bench_user", "benchuser"),
        ("secrets", "bench_pass", "benchpass"),
        ("secrets", "admin-token", "bench-admin-token"),
        ("secrets", "probe-key", "bench-probe-key"),
        ("secrets", "prober-token", "bench-prober-token"),
    ] {
        let d = dir.join(sub);
        std::fs::create_dir_all(&d)?;
        std::fs::write(d.join(name), text)?;
    }
    // the gateway reads the probe-target list from the data directory
    std::fs::write(dir.join("data/probe-targets.toml"), "")?;
    Ok(())
}

/// Create a fresh benchmark database and put the org key, the inventory unit
/// and the ready-set entry in it, the way the warmer leaves a verified unit.
async fn seed(database_url: &str, redis_url: &str, provider_port: u16) -> Result<()> {
    let url = store::testing::database(database_url, DATABASE_NAME, true)
        .await
        .context("create the benchmark database")?;
    let db = Db::connect(&url)
        .await
        .context("connect to the benchmark database")?;
    db.migrate()
        .await
        .context("migrate the benchmark database")?;
    let org: OrgId = ORG.parse().context("org id")?;
    db.add_org_key(&org, &Secret::new(ORG_KEY), "bench", "bench")
        .await?;

    let entry = InventoryEntry {
        provider: PROVIDER_ID.parse().context("provider id")?,
        subtype: Subtype::Isp,
        plan: "bench".into(),
        ip: UNIT_IP,
        host: "127.0.0.1".into(),
        port: provider_port,
        region: "fr".parse().context("region")?,
        asn: None,
        credentials: None,
        box_handle: None,
        rental_end: None,
    };
    db.upsert_inventory_entry(&entry, "bench").await?;
    db.transition_ip(
        UNIT_IP,
        &Transition::to(IpState::Available, "bench"),
        "bench",
    )
    .await?;
    db.record_check(UNIT_IP, Some(UNIT_IP), OffsetDateTime::now_utc())
        .await?;

    // The Redis database is the benchmark's own: start it empty.
    let client = redis::Client::open(redis_url).context("open Redis")?;
    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .context("connect to Redis")?;
    redis::cmd("FLUSHDB")
        .query_async::<()>(&mut conn)
        .await
        .context("flush the benchmark Redis database")?;
    let hot = Hot::connect(redis_url).await.context("connect to Redis")?;
    let partition = Partition {
        provider: entry.provider.clone(),
        region: entry.region.clone(),
    };
    hot.ready_put(&partition, &UnitRecord::static_ip(UNIT_IP))
        .await?;
    Ok(())
}

/// Run the gateway scenario as `args` describe it.
pub async fn run(args: &GatewayArgs) -> Result<Report> {
    args.validate()?;
    let authority = match args.mode {
        GatewayMode::Tunnel => TUNNEL_TARGET,
        GatewayMode::Forward => FORWARD_TARGET,
    };

    // Attach mode: the caller owns the gateway and the target.
    if let Some(pid) = args.common.pid {
        let connector = Arc::new(GatewayConnector::new(
            args.proxy.context("attach mode needs --proxy")?,
            &args.username,
            args.password
                .as_deref()
                .context("attach mode needs --password")?,
            args.target
                .as_deref()
                .context("attach mode needs --target")?,
            args.mode,
            args.common.payload_bytes,
        ));
        preflight(&*connector)
            .await
            .context("the gateway does not serve a request")?;
        let runs = run_sweep(connector, &args.common.sweep(Some(pid))).await?;
        return Ok(report(args, "attached", runs));
    }

    let binary = args
        .common
        .spawn
        .as_ref()
        .context("give --spawn or --pid")?;
    let dir = workdir(args.common.workdir.as_ref(), "gateway")?;

    // The stubs: a TCP echo and an HTTP origin behind a provider proxy.
    let echo = stubs::echo().await.context("start the echo target")?;
    let origin = stubs::http_origin(args.common.payload_bytes, None)
        .await
        .context("start the HTTP origin")?;
    let provider = stubs::provider_proxy(
        PROVIDER_LOGIN,
        Routes {
            default: echo.addr,
            port_80: Some(origin.addr),
        },
    )
    .await
    .context("start the stub provider")?;

    write_world(&dir, &data_files(provider.addr.port()))?;
    seed(&args.database_url, &args.redis_url, provider.addr.port()).await?;

    let addrs = Addrs::free()?;
    let db_url = store::testing::database(&args.database_url, DATABASE_NAME, false).await?;
    let config = dir.join("pool.toml");
    std::fs::write(&config, pool_config(&dir, &db_url, &args.redis_url, &addrs))?;
    let mut child = Spawned::start(
        binary,
        &["gateway", "--config", &config.to_string_lossy()],
        &dir,
        "gateway",
    )?;
    child
        .wait_ready(STARTUP_LIMIT, || target::http_ok(addrs.ops, "/readyz"))
        .await?;
    let pid = child.pid;

    let outcome = async {
        let connector = Arc::new(GatewayConnector::new(
            addrs.connect,
            &args.username,
            ORG_KEY,
            authority,
            args.mode,
            args.common.payload_bytes,
        ));
        preflight(&*connector).await.with_context(|| {
            format!(
                "the gateway does not serve a request; log tail:\n{}",
                child.log_tail(20)
            )
        })?;
        let runs = run_sweep(connector, &args.common.sweep(Some(pid))).await?;
        Ok::<_, anyhow::Error>(report(args, "spawned", runs))
    }
    .await;

    child.stop(Duration::from_secs(8)).await?;
    outcome
}

fn report(args: &GatewayArgs, target_kind: &str, runs: Vec<crate::report::Run>) -> Report {
    Report {
        scenario: "gateway".into(),
        mode: args.mode.name().into(),
        keepalive: args.common.keepalive,
        payload_bytes: args.common.payload_bytes,
        target_kind: target_kind.into(),
        warmup_secs: args.common.warmup.as_secs_f64(),
        runs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_tunnel_connector_echoes_through_a_stub_proxy() {
        let echo = stubs::echo().await.expect("echo");
        let provider = stubs::provider_proxy("u:p", Routes::only(echo.addr))
            .await
            .expect("provider");
        // the stub accepts the same Basic login the connector sends
        let connector = GatewayConnector::new(
            provider.addr,
            "u",
            "p",
            TUNNEL_TARGET,
            GatewayMode::Tunnel,
            100,
        );
        let mut conn = connector.connect().await.expect("connect");
        assert_eq!(
            connector.exchange(&mut conn, false).await.expect("one"),
            200
        );
        assert_eq!(
            connector.exchange(&mut conn, false).await.expect("two"),
            200
        );
    }

    #[tokio::test]
    async fn a_forward_connector_speaks_http_over_the_port_80_route() {
        let echo = stubs::echo().await.expect("echo");
        let origin = stubs::http_origin(64, None).await.expect("origin");
        let provider = stubs::provider_proxy(
            "u:p",
            Routes {
                default: echo.addr,
                port_80: Some(origin.addr),
            },
        )
        .await
        .expect("provider");
        let connector = GatewayConnector::new(
            provider.addr,
            "u",
            "p",
            FORWARD_TARGET,
            GatewayMode::Forward,
            10,
        );
        let mut conn = connector.connect().await.expect("connect");
        assert_eq!(
            connector
                .exchange(&mut conn, false)
                .await
                .expect("keep-alive"),
            74
        );
        assert_eq!(
            connector.exchange(&mut conn, true).await.expect("close"),
            74
        );
    }

    #[tokio::test]
    async fn a_wrong_login_is_a_connect_407_error_class() {
        let echo = stubs::echo().await.expect("echo");
        let provider = stubs::provider_proxy("u:p", Routes::only(echo.addr))
            .await
            .expect("provider");
        let connector = GatewayConnector::new(
            provider.addr,
            "u",
            "wrong",
            TUNNEL_TARGET,
            GatewayMode::Tunnel,
            8,
        );
        let e = connector.connect().await.err().expect("refused");
        assert_eq!(e.class, "connect_407_proxy_authentication_required");
    }

    #[test]
    fn the_generated_files_parse_as_toml_and_agree_on_the_provider() {
        let files = data_files(4242);
        for text in [&files.adapter, &files.policy, &files.inventory] {
            text.parse::<toml::Table>().expect("valid toml");
        }
        let inv: toml::Table = files.inventory.parse().expect("toml");
        let entry = &inv["entry"][0];
        assert_eq!(entry["provider"].as_str(), Some(PROVIDER_ID));
        assert_eq!(entry["port"].as_integer(), Some(4242));
        let adapter: toml::Table = files.adapter.parse().expect("toml");
        assert_eq!(adapter["adapter"][0]["id"].as_str(), Some(PROVIDER_ID));
    }

    #[test]
    fn the_pool_config_names_every_listener_and_directory() {
        let a = |p: u16| SocketAddr::from(([127, 0, 0, 1], p));
        let addrs = Addrs {
            connect: a(1),
            socks: a(2),
            probe: a(3),
            api: a(4),
            ops: a(5),
            dead_exit_check: a(6),
        };
        let text = pool_config(Path::new("/w"), "postgres://x@h/db", "redis://h/13", &addrs);
        let t: toml::Table = text.parse().expect("toml");
        assert_eq!(t["connect_listen"].as_str(), Some("127.0.0.1:1"));
        assert_eq!(t["ops_listen"].as_str(), Some("127.0.0.1:5"));
        assert_eq!(t["data_dir"].as_str(), Some("/w/data"));
        assert_eq!(t["secrets_dir"].as_str(), Some("/w/secrets"));
        assert_eq!(
            t["admin_token_file"].as_str(),
            Some("/w/secrets/admin-token")
        );
        assert_eq!(
            t["exit_ip_services"].as_str(),
            Some("ipinfo=http://127.0.0.1:6/json")
        );
    }
}
