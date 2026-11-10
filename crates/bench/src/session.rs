//! The session proxy scenario: CONNECT through `proxyx-intercept` to a local
//! TLS origin, either as a passthrough tunnel or intercepted.
//!
//! A session is a JSON document under `{prefix}:session:{id}:data` in the
//! proxy's Redis, which is what the control plane writes; the proxy reads it
//! on the first request. The load client logs in with `Basic <id>:<anything>`.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rustls::pki_types::ServerName;
use serde_json::json;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use uuid::Uuid;

use crate::cli::{SessionArgs, SessionMode};
use crate::http1::{self, Conn};
use crate::load::{Connector, LoadError};
use crate::report::{Report, run_sweep};
use crate::stubs;
use crate::target::{self, Spawned};
use crate::tls::{self, Ca};

/// The host name the load asks for. It resolves to loopback, where the origin
/// listens, and is a name (not an address) so the proxy can sign a
/// certificate for it.
pub const ORIGIN_HOST: &str = "localhost";

/// How long a session lives; far longer than any run.
const SESSION_TTL_SECS: u64 = 3600;
/// How long the spawned proxy has to start serving.
const STARTUP_LIMIT: Duration = Duration::from_secs(30);

/// Everything a session connector needs.
pub struct Plan {
    pub proxy: SocketAddr,
    pub session_id: Uuid,
    pub origin_port: u16,
    /// The DER root the client trusts: the origin's CA in passthrough mode,
    /// the proxy's CA in MITM mode.
    pub trust_der: Vec<u8>,
    pub payload_bytes: usize,
}

/// Connects through a session proxy to the origin, with a TLS session to
/// whoever terminates it, and sends `POST`s over it.
pub struct SessionConnector {
    proxy: SocketAddr,
    proxy_authorization: String,
    authority: String,
    tls: TlsConnector,
    server_name: ServerName<'static>,
    body: Vec<u8>,
}

impl SessionConnector {
    pub fn new(plan: &Plan) -> Result<Self> {
        let login = format!("{}:bench", plan.session_id);
        Ok(Self {
            proxy: plan.proxy,
            proxy_authorization: format!("Basic {}", STANDARD.encode(login)),
            authority: format!("{ORIGIN_HOST}:{}", plan.origin_port),
            tls: TlsConnector::from(tls::client_config(&plan.trust_der)?),
            server_name: tls::server_name(ORIGIN_HOST)?,
            body: vec![b'x'; plan.payload_bytes],
        })
    }
}

impl Connector for SessionConnector {
    type Conn = Conn<TlsStream<TcpStream>>;

    async fn connect(&self) -> Result<Self::Conn, LoadError> {
        let tcp =
            http1::connect_tunnel(self.proxy, &self.authority, &self.proxy_authorization).await?;
        let stream = self
            .tls
            .connect(self.server_name.clone(), tcp)
            .await
            .map_err(|e| LoadError::new("tls_handshake", e.to_string()))?;
        Ok(Conn::new(stream))
    }

    async fn exchange(&self, conn: &mut Self::Conn, close: bool) -> Result<u64, LoadError> {
        conn.post(&self.authority, &self.body, close).await
    }
}

/// Write the session of `id` into the proxy's Redis. `captured` makes the
/// proxy intercept the origin host; otherwise it only relays.
pub async fn create_session(redis_url: &str, prefix: &str, id: Uuid, captured: bool) -> Result<()> {
    let client = redis::Client::open(redis_url).context("open the session Redis")?;
    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .context("connect to the session Redis")?;
    let now_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64;
    // Far above anything a run can use, so the org rate limit never answers.
    let session = json!({
        "session_id": id,
        "org_id": "bench-org",
        "source": "bench",
        "source_id": format!("bench-{id}"),
        "agent": null,
        "captured_hosts": if captured { vec![ORIGIN_HOST] } else { Vec::new() },
        "excluded_hosts": [],
        "upstream_overrides": {},
        "inject_headers": [],
        "serialize": false,
        "expires_at_ms": now_ms + (SESSION_TTL_SECS as i64) * 1000,
        "egress_proxy": null,
        "rate_limit": { "requests_per_minute": 4_000_000_000u64, "burst": 1_000_000_000u64 },
    });
    redis::cmd("SET")
        .arg(format!("{prefix}:session:{id}:data"))
        .arg(session.to_string())
        .arg("EX")
        .arg(SESSION_TTL_SECS)
        .query_async::<()>(&mut conn)
        .await
        .context("write the session")?;
    Ok(())
}

/// Remove what a run wrote: the session and the capture stream.
async fn cleanup(redis_url: &str, prefix: &str, id: Uuid) {
    let Ok(client) = redis::Client::open(redis_url) else {
        return;
    };
    let Ok(mut conn) = client.get_multiplexed_async_connection().await else {
        return;
    };
    let _ = redis::cmd("DEL")
        .arg(format!("{prefix}:session:{id}:data"))
        .arg(format!("{prefix}:request_log"))
        .query_async::<()>(&mut conn)
        .await;
}

/// The configuration of a spawned `proxyx-intercept`.
pub fn intercept_config(
    connect: SocketAddr,
    socks: SocketAddr,
    api: SocketAddr,
    redis_url: &str,
    prefix: &str,
    ca_dir: &std::path::Path,
) -> String {
    let q = |s: &str| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""));
    format!(
        "connect_addr = {connect}\nsocks_addr = {socks}\napi_addr = {api}\nredis_url = {redis}\n\
         redis_key_prefix = {prefix}\nno_capture_hosts = []\n\n\
         [ca]\ntype = \"file\"\ncert_path = {cert}\nkey_path = {key}\n\n\
         [ratelimit]\nbackend = \"redis\"\ndefault_burst = 1000000000\ndefault_rpm = 4000000000\n\n\
         [request_log]\nstream_name = {stream}\n\n\
         [tuning]\nmax_connections = 20000\nshutdown_drain_timeout_secs = 2\n",
        connect = q(&connect.to_string()),
        socks = q(&socks.to_string()),
        api = q(&api.to_string()),
        redis = q(redis_url),
        prefix = q(prefix),
        cert = q(&ca_dir.join("ca.der").to_string_lossy()),
        key = q(&ca_dir.join("ca.key.der").to_string_lossy()),
        stream = q(&format!("{prefix}:request_log")),
    )
}

/// A directory for generated files, created if missing, as an absolute path.
pub fn workdir(given: Option<&PathBuf>, name: &str) -> Result<PathBuf> {
    let dir = match given {
        Some(d) => d.clone(),
        None => std::env::temp_dir().join(format!("proxyx-bench-{name}-{}", std::process::id())),
    };
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    // absolute, because the spawned target runs with this directory as its
    // working directory and is handed paths inside it
    std::fs::canonicalize(&dir).with_context(|| format!("resolve {}", dir.display()))
}

/// Run the session scenario as `args` describe it.
pub async fn run(args: &SessionArgs) -> Result<Report> {
    args.validate()?;
    let captured = args.mode == SessionMode::Mitm;
    let session_id = Uuid::new_v4();

    // The origin: TLS, signed by a CA of its own.
    let origin_ca = Ca::generate("proxyx-bench origin CA")?;
    let (cert, key) = origin_ca.issue_server(ORIGIN_HOST)?;
    let origin = stubs::http_origin(
        args.common.payload_bytes,
        Some(tls::server_config(cert, &key)?),
    )
    .await
    .context("start the origin")?;

    let mut spawned: Option<Spawned> = None;
    let (proxy, pid, proxy_ca_der, target_kind) = match (&args.common.spawn, args.common.pid) {
        (Some(binary), _) => {
            let dir = workdir(args.common.workdir.as_ref(), "session")?;
            let proxy_ca = Ca::generate("proxyx-bench proxy CA")?;
            proxy_ca.write_to(&dir.join("ca"))?;
            let (connect, socks, api) = (
                target::free_addr()?,
                target::free_addr()?,
                target::free_addr()?,
            );
            let config = dir.join("intercept.toml");
            std::fs::write(
                &config,
                intercept_config(
                    connect,
                    socks,
                    api,
                    &args.redis_url,
                    &args.redis_prefix,
                    &dir.join("ca"),
                ),
            )?;
            let mut child = Spawned::start(
                binary,
                &["--config", &config.to_string_lossy()],
                &dir,
                "proxyx-intercept",
            )?;
            child
                .wait_ready(STARTUP_LIMIT, || target::http_ok(api, "/health"))
                .await?;
            let pid = child.pid;
            spawned = Some(child);
            (connect, pid, Some(proxy_ca.cert_der()), "spawned")
        }
        (None, Some(pid)) => {
            let proxy = args.proxy.context("attach mode needs --proxy")?;
            let ca = match (&args.ca_der, args.mode) {
                (Some(path), SessionMode::Mitm) => {
                    Some(std::fs::read(path).with_context(|| format!("read {}", path.display()))?)
                }
                _ => None,
            };
            (proxy, pid, ca, "attached")
        }
        (None, None) => anyhow::bail!("give --spawn or --pid"),
    };

    let outcome = async {
        create_session(&args.redis_url, &args.redis_prefix, session_id, captured).await?;
        let trust_der = if captured {
            proxy_ca_der.context("no proxy CA to trust")?
        } else {
            origin_ca.cert_der()
        };
        let connector = Arc::new(SessionConnector::new(&Plan {
            proxy,
            session_id,
            origin_port: origin.addr.port(),
            trust_der,
            payload_bytes: args.common.payload_bytes,
        })?);
        preflight(&*connector)
            .await
            .with_context(|| match &spawned {
                Some(child) => format!(
                    "the session proxy does not serve a request; log tail:\n{}",
                    child.log_tail(20)
                ),
                None => "the session proxy does not serve a request".to_owned(),
            })?;
        let runs = run_sweep(connector, &args.common.sweep(Some(pid))).await?;
        Ok::<_, anyhow::Error>(Report {
            scenario: "session".into(),
            mode: args.mode.name().into(),
            keepalive: args.common.keepalive,
            payload_bytes: args.common.payload_bytes,
            target_kind: target_kind.into(),
            warmup_secs: args.common.warmup.as_secs_f64(),
            runs,
        })
    }
    .await;

    cleanup(&args.redis_url, &args.redis_prefix, session_id).await;
    if let Some(child) = spawned {
        child.stop(Duration::from_secs(5)).await?;
    }
    outcome
}

/// One request before the measured load, so a wrong setup fails with its
/// cause instead of as a column of errors.
pub async fn preflight<C: Connector>(connector: &C) -> Result<()> {
    let mut conn = connector
        .connect()
        .await
        .map_err(|e| anyhow::anyhow!("connect failed: {e}"))?;
    connector
        .exchange(&mut conn, true)
        .await
        .map_err(|e| anyhow::anyhow!("request failed: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_generated_config_has_every_listener_the_ca_files_and_the_prefix() {
        let text = intercept_config(
            "127.0.0.1:1".parse().expect("a"),
            "127.0.0.1:2".parse().expect("b"),
            "127.0.0.1:3".parse().expect("c"),
            "redis://127.0.0.1:45401/13",
            "pfx",
            std::path::Path::new("/w/ca"),
        );
        let v: toml_like::Doc = toml_like::parse(&text);
        assert_eq!(v.get("connect_addr"), Some("127.0.0.1:1"));
        assert_eq!(v.get("socks_addr"), Some("127.0.0.1:2"));
        assert_eq!(v.get("api_addr"), Some("127.0.0.1:3"));
        assert_eq!(v.get("redis_key_prefix"), Some("pfx"));
        assert_eq!(v.get("cert_path"), Some("/w/ca/ca.der"));
        assert_eq!(v.get("key_path"), Some("/w/ca/ca.key.der"));
        assert_eq!(v.get("stream_name"), Some("pfx:request_log"));
    }

    /// Just enough of a TOML reader for flat `key = "value"` lines.
    mod toml_like {
        pub struct Doc(Vec<(String, String)>);
        pub fn parse(text: &str) -> Doc {
            Doc(text
                .lines()
                .filter_map(|l| l.split_once(" = "))
                .map(|(k, v)| (k.trim().to_owned(), v.trim().trim_matches('"').to_owned()))
                .collect())
        }
        impl Doc {
            pub fn get(&self, key: &str) -> Option<&str> {
                self.0
                    .iter()
                    .find(|(k, _)| k == key)
                    .map(|(_, v)| v.as_str())
            }
        }
    }

    #[test]
    fn the_workdir_is_created_and_named_for_the_scenario() {
        let dir = workdir(None, "unit").expect("dir");
        assert!(dir.is_dir());
        assert!(dir.to_string_lossy().contains("proxyx-bench-unit-"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_relative_workdir_becomes_absolute() {
        let relative = PathBuf::from(format!("proxyx-bench-relative-{}", std::process::id()));
        let dir = workdir(Some(&relative), "unit").expect("dir");
        assert!(dir.is_absolute() && dir.is_dir());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
