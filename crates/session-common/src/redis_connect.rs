//! Redis connection setup: plain URLs or Sentinel-managed HA.
//!
//! URL contract:
//!
//! - `redis://` / `rediss://` — direct connection, unchanged behavior.
//! - `redis+sentinel://:pw@h1:26379,h2:26379,h3:26379/mastername` (or
//!   `rediss+sentinel://` for TLS) — ask the Sentinels for the current
//!   master address, then connect the usual `Client`/`ConnectionManager`
//!   pair to it. Only the elected master accepts writes.
//!
//! TLS uses full certificate verification everywhere: the valkey cert's
//! SANs are expected to cover the per-pod DNS names of the headless service, so
//! sentinels are dialed by DNS name, and the master address Sentinel
//! announces (a pod IP) is reverse-mapped to the matching pod DNS name
//! before connecting. The password applies to the master only; the
//! sentinels themselves run unauthenticated.
//!
//! Failover handling: a watchdog polls the Sentinels and exits the process
//! when the master moves, so Kubernetes restarts the pod and startup
//! re-resolves the new master. A failover already drops this process's
//! connections, so the restart adds no meaningful extra disruption.
//! (Ceiling: an in-process reconnect would need a sentinel-aware
//! `ConnectionManager`, which redis-rs does not provide.)

use std::time::Duration;

use anyhow::{Context, Result, bail};
use redis::aio::{ConnectionManager, ConnectionManagerConfig};

const SENTINEL_DEFAULT_PORT: u16 = 26379;
const WATCHDOG_INTERVAL: Duration = Duration::from_secs(5);

/// Bound on one connection attempt and on one command's reply. Without it a
/// blackholed Redis (packets dropped, no reset) stalls every caller for as
/// long as the OS keeps the connection, and the proxy's request path with it.
/// Blocking stream reads use their own connection, so this does not cut them.
pub const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// The `ConnectionManager` every role uses: reconnects by itself, bounded by
/// [`IO_TIMEOUT`].
async fn manager(client: redis::Client) -> Result<ConnectionManager> {
    manager_with(client, IO_TIMEOUT).await
}

async fn manager_with(client: redis::Client, timeout: Duration) -> Result<ConnectionManager> {
    let config = ConnectionManagerConfig::new()
        .set_connection_timeout(timeout)
        .set_response_timeout(timeout);
    // The manager's own connection timeout covers the TCP connect; the setup
    // exchange after it has no bound of its own, so a peer that accepts and
    // then stays silent would hang the start. Allow a few attempts, no more.
    tokio::time::timeout(
        timeout * 3,
        ConnectionManager::new_with_config(client, config),
    )
    .await
    .map_err(|_| anyhow::anyhow!("redis did not answer within {:?}", timeout * 3))?
    .map_err(Into::into)
}

struct SentinelUrl {
    /// Sentinel `host:port` pairs (DNS names in-cluster).
    hosts: Vec<String>,
    master_name: String,
    password: Option<String>,
    tls: bool,
}

impl SentinelUrl {
    fn scheme(&self) -> &'static str {
        if self.tls { "rediss" } else { "redis" }
    }
}

fn parse_sentinel_url(url: &str) -> Result<SentinelUrl> {
    let (tls, rest) = if let Some(rest) = url.strip_prefix("rediss+sentinel://") {
        (true, rest)
    } else if let Some(rest) = url.strip_prefix("redis+sentinel://") {
        (false, rest)
    } else {
        bail!("not a sentinel URL: {url}");
    };
    let (authority, master_name) = rest
        .split_once('/')
        .with_context(|| format!("sentinel URL missing master name: {url}"))?;
    if master_name.is_empty() {
        bail!("sentinel URL missing master name: {url}");
    }
    // Credentials are the composition-generated alphanumeric auth token;
    // no percent-decoding needed.
    let (password, hostpart) = match authority.rsplit_once('@') {
        Some((creds, hosts)) => (
            Some(creds.trim_start_matches(':').to_string()).filter(|p| !p.is_empty()),
            hosts,
        ),
        None => (None, authority),
    };
    let hosts = hostpart
        .split(',')
        .map(|pair| {
            if pair.is_empty() {
                bail!("sentinel URL has empty host: {url}");
            }
            Ok(if pair.contains(':') {
                pair.to_string()
            } else {
                format!("{pair}:{SENTINEL_DEFAULT_PORT}")
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(SentinelUrl {
        hosts,
        master_name: master_name.to_string(),
        password,
        tls,
    })
}

/// Ask each sentinel in turn for the current master address (`ip:port`).
async fn resolve_master(cfg: &SentinelUrl) -> Result<(String, u16)> {
    let mut last_err = None;
    for host in &cfg.hosts {
        let attempt = async {
            let client = redis::Client::open(format!("{}://{host}", cfg.scheme()))?;
            let mut conn = client.get_multiplexed_async_connection().await?;
            let addr: Vec<String> = redis::cmd("SENTINEL")
                .arg("get-master-addr-by-name")
                .arg(&cfg.master_name)
                .query_async(&mut conn)
                .await?;
            match addr.as_slice() {
                [ip, port] => Ok::<_, anyhow::Error>((ip.clone(), port.parse::<u16>()?)),
                other => bail!("unexpected sentinel reply: {other:?}"),
            }
        };
        match attempt.await {
            Ok(addr) => return Ok(addr),
            Err(e) => {
                tracing::warn!(sentinel = %host, error = %e, "sentinel query failed");
                last_err = Some(e);
            }
        }
    }
    bail!(
        "no sentinel answered for master {:?} (tried {:?}); last error: {}",
        cfg.master_name,
        cfg.hosts,
        last_err.map_or_else(|| "none".to_string(), |e| e.to_string()),
    )
}

/// Map the sentinel-announced master IP back to the pod DNS name so the
/// TLS connection verifies against the certificate's `*.<headless>` SAN.
async fn master_dns_name(cfg: &SentinelUrl, ip: &str, port: u16) -> Result<String> {
    for host in &cfg.hosts {
        let name = host.rsplit_once(':').map_or(host.as_str(), |(h, _)| h);
        let Ok(resolved) = tokio::net::lookup_host((name, port)).await else {
            continue;
        };
        for addr in resolved {
            if addr.ip().to_string() == ip {
                return Ok(name.to_string());
            }
        }
    }
    bail!("sentinel-announced master {ip}:{port} matches no known redis pod DNS name")
}

/// Connect to Redis from a plain or sentinel URL.
///
/// Returns the same `(Client, ConnectionManager)` pair call sites used to
/// build directly; for sentinel URLs both point at the currently elected
/// master and a spawned watchdog exits the process if the master moves.
pub async fn connect(url: &str) -> Result<(redis::Client, ConnectionManager)> {
    if !url.starts_with("redis+sentinel://") && !url.starts_with("rediss+sentinel://") {
        let client = redis::Client::open(url)?;
        let manager = manager(client.clone()).await?;
        return Ok((client, manager));
    }

    let cfg = parse_sentinel_url(url)?;
    let (ip, port) = resolve_master(&cfg).await?;
    // TLS certs carry DNS SANs only, so connect by name; plain mode can
    // use the announced IP directly.
    let master_host = if cfg.tls {
        master_dns_name(&cfg, &ip, port).await?
    } else {
        ip.clone()
    };
    tracing::info!(
        master = %format!("{master_host}:{port}"),
        announced = %format!("{ip}:{port}"),
        name = %cfg.master_name,
        "resolved redis master via sentinel",
    );

    let auth = cfg
        .password
        .as_deref()
        .map(|p| format!(":{p}@"))
        .unwrap_or_default();
    let client = redis::Client::open(format!("{}://{auth}{master_host}:{port}", cfg.scheme()))?;
    let manager = manager(client.clone()).await?;

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(WATCHDOG_INTERVAL).await;
            match resolve_master(&cfg).await {
                Ok(current) if current != (ip.clone(), port) => {
                    tracing::error!(
                        old = %format!("{ip}:{port}"),
                        new = %format!("{}:{}", current.0, current.1),
                        "redis sentinel failover detected; exiting for clean re-resolve",
                    );
                    std::process::exit(1);
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(error = %e, "sentinel master check failed");
                }
            }
        }
    });

    Ok((client, manager))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    /// A peer that accepts and then says nothing, like a Redis whose packets
    /// are dropped after the handshake: connecting must fail at the timeout
    /// instead of waiting for the operating system to give up.
    #[tokio::test]
    async fn a_silent_redis_fails_the_connect_at_the_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    while stream.read(&mut buf).await.unwrap_or(0) > 0 {}
                });
            }
        });
        let client = redis::Client::open(format!("redis://{addr}/")).unwrap();
        let started = Instant::now();
        let err = manager_with(client, Duration::from_millis(300))
            .await
            .err()
            .expect("a silent peer must not connect");
        assert!(err.to_string().contains("did not answer"), "{err:#}");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn a_real_redis_connects_with_the_bounds_and_answers() {
        let url = std::env::var("PROXYX_TEST_REDIS_URL")
            .unwrap_or_else(|_| "redis://127.0.0.1:45401/14".to_owned());
        let (_, mut conn) = connect(&url).await.unwrap();
        let pong: String = redis::cmd("PING").query_async(&mut conn).await.unwrap();
        assert_eq!(pong, "PONG");
    }

    #[test]
    fn the_shared_timeout_is_five_seconds() {
        assert_eq!(IO_TIMEOUT, Duration::from_secs(5));
    }
}
