//! Helpers of the end-to-end suite: stub upstream proxies, a CONNECT client,
//! a throwaway data directory and the local Redis and Postgres.
//!
//! The suite needs the local services (`PROXYX_TEST_REDIS_URL`,
//! `PROXYX_TEST_DATABASE_URL`) and skips with a message when they are unset.

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
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

pub type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Redis DB index of this crate's suite (contract: bin 5). A test that runs a
/// role and flushes Redis takes its own index above it (6, 7, ...): the tests
/// of one binary run in parallel, and a flush must not reach the Redis state
/// of a role in another test.
pub const REDIS_DB: u8 = 5;
const MAX_HEAD_BYTES: usize = 16 * 1024;

/// Local services of one test run.
#[derive(Clone)]
pub struct Services {
    pub redis_url: String,
    pub database_url: String,
}

/// The local Redis (DB `redis_db`) and a fresh Postgres database for `name`,
/// or `None` (with a message) when the environment is not set up.
pub async fn services(
    name: &str,
    redis_db: u8,
) -> Result<Option<Services>, Box<dyn std::error::Error>> {
    let (Ok(redis), Ok(pg)) = (
        std::env::var("PROXYX_TEST_REDIS_URL"),
        std::env::var("PROXYX_TEST_DATABASE_URL"),
    ) else {
        eprintln!("SKIP: PROXYX_TEST_REDIS_URL and PROXYX_TEST_DATABASE_URL are not set");
        return Ok(None);
    };
    let (scheme, rest) = redis.split_once("://").ok_or("redis url has no scheme")?;
    let authority = rest.split('/').next().unwrap_or(rest);
    let redis_url = format!("{scheme}://{authority}/{redis_db}");

    let name = format!("proxyx_bin_{name}_test");
    Ok(Some(Services {
        redis_url,
        database_url: store::testing::database(&pg, &name, true).await?,
    }))
}

/// `FLUSHDB` on the suite's Redis database: the "Redis lost its data" drill.
pub async fn flush_redis(url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut conn = redis::Client::open(url)?
        .get_multiplexed_async_connection()
        .await?;
    redis::cmd("FLUSHDB").query_async::<()>(&mut conn).await?;
    Ok(())
}

/// A directory removed on drop.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(label: &str) -> std::io::Result<Self> {
        let dir = std::env::temp_dir().join(format!("proxyx-e2e-{label}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir)?;
        Ok(Self(dir))
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    /// Write `content` to `rel` under the directory, creating parents.
    pub fn write(&self, rel: &str, content: &str) -> std::io::Result<()> {
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
pub fn free_addr() -> std::io::Result<SocketAddr> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    listener.local_addr()
}

/// A stub "provider" with one HTTP proxy endpoint per exit IP. Each endpoint
/// requires Basic credentials, tunnels any CONNECT to an echo (so no real
/// target is needed) and answers plain `GET` requests of the IP-check stub
/// services with its own IP.
pub struct Upstreams {
    pub endpoints: HashMap<IpAddr, SocketAddr>,
    /// Exit IP of the stub and the CONNECT authority, per CONNECT.
    seen: Arc<Mutex<Vec<(IpAddr, String)>>>,
    tasks: Vec<JoinHandle<()>>,
}

impl Upstreams {
    pub async fn start(
        ips: &[IpAddr],
        user: &str,
        pass: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let expected = format!(
            "Basic {}",
            base64_encode(format!("{user}:{pass}").as_bytes())
        );
        let mut endpoints = HashMap::new();
        let mut tasks = Vec::new();
        for ip in ips {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            endpoints.insert(*ip, listener.local_addr()?);
            let (ip, seen, expected) = (*ip, Arc::clone(&seen), expected.clone());
            tasks.push(tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    let (seen, expected) = (Arc::clone(&seen), expected.clone());
                    tokio::spawn(async move {
                        let _ = serve(stream, ip, &expected, &seen).await;
                    });
                }
            }));
        }
        Ok(Self {
            endpoints,
            seen,
            tasks,
        })
    }

    /// Exit IPs that carried a CONNECT to `target`, oldest first.
    pub fn ips_for(&self, target: &str) -> Vec<IpAddr> {
        let seen = self.seen.lock();
        seen.iter()
            .filter(|(_, authority)| authority == target)
            .map(|(ip, _)| *ip)
            .collect()
    }
}

impl Drop for Upstreams {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

async fn read_head(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if buf.len() > MAX_HEAD_BYTES || stream.read(&mut byte).await? == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        buf.push(byte[0]);
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

async fn serve(
    mut stream: TcpStream,
    ip: IpAddr,
    expected_auth: &str,
    seen: &Mutex<Vec<(IpAddr, String)>>,
) -> std::io::Result<()> {
    let head = read_head(&mut stream).await?;
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let (method, uri) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let authorised = lines.any(|l| {
        l.split_once(':').is_some_and(|(k, v)| {
            k.eq_ignore_ascii_case("proxy-authorization") && v.trim() == expected_auth
        })
    });
    if !authorised {
        stream
            .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
            .await?;
        return Ok(());
    }
    if method == "CONNECT" {
        seen.lock().push((ip, uri.to_owned()));
        stream
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await?;
        let mut buf = [0u8; 1024];
        loop {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                return Ok(());
            }
            stream.write_all(&buf[..n]).await?;
        }
    }
    // Plain HTTP through the proxy: the IP-check stub services.
    let (content_type, body) = if uri.contains("/cloudflare") {
        ("text/plain", format!("ip={ip}\nloc=FR\n"))
    } else if uri.contains("/ipinfo") {
        (
            "application/json",
            format!(r#"{{"ip":"{ip}","country":"FR"}}"#),
        )
    } else {
        ("application/json", format!(r#"{{"ip":"{ip}"}}"#))
    };
    let reply = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(reply.as_bytes()).await
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Reply of a CONNECT through the gateway.
pub struct Connected {
    pub status: u16,
    /// Lowercased header names.
    pub headers: HashMap<String, String>,
    pub stream: TcpStream,
}

impl Connected {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }

    /// Send `payload` and read the same number of bytes back (the stub tunnel
    /// is an echo), proving the tunnel carries data both ways.
    pub async fn echo(&mut self, payload: &[u8]) -> std::io::Result<Vec<u8>> {
        self.stream.write_all(payload).await?;
        let mut back = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(5), self.stream.read_exact(&mut back))
            .await
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
        Ok(back)
    }
}

/// `CONNECT target` through the gateway with the org key as Basic password.
pub async fn connect_via(
    gateway: SocketAddr,
    user: &str,
    key: &str,
    target: &str,
) -> std::io::Result<Connected> {
    let mut stream = TcpStream::connect(gateway).await?;
    let auth = base64_encode(format!("{user}:{key}").as_bytes());
    stream
        .write_all(
            format!(
                "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic {auth}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await?;
    let head = tokio::time::timeout(Duration::from_secs(15), read_head(&mut stream))
        .await
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| std::io::Error::other("no status line"))?;
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    Ok(Connected {
        status,
        headers,
        stream,
    })
}

/// Retry `probe` every 100 ms until it returns `Some` or `within` passes.
pub async fn eventually<T, F, Fut>(within: Duration, mut probe: F) -> Option<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Option<T>>,
{
    let deadline = tokio::time::Instant::now() + within;
    loop {
        if let Some(value) = probe().await {
            return Some(value);
        }
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
