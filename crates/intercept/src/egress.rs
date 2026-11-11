//! Egress connections to upstream servers with DNS caching, TCP keepalive,
//! retries and a per-upstream circuit breaker.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use base64::Engine;
use common::types::{EgressProxy, ProxyType};
use moka::sync::Cache;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::breaker::{BreakerConfig, TargetKind, UpstreamBreakers};
use crate::config::{NetworkConfig, TcpKeepaliveConfig};

/// Context on a dial error caused by name resolution, so a listener can tell
/// a DNS failure from other connect failures with `downcast_ref`.
#[derive(Debug, thiserror::Error)]
#[error("DNS lookup failed")]
pub struct DnsLookupFailed;

/// The whole connect, retries included, did not finish within
/// `network.upstream_connect_timeout_ms`.
#[derive(Debug, thiserror::Error)]
#[error("connect timed out after {0:?}")]
pub struct DialTimedOut(pub Duration);

/// The egress proxy answered, and refused the tunnel (bad credentials, target
/// not allowed, ...). The proxy is up, so this does not count against its
/// breaker.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct ProxyRefused(String);

/// The request itself was unusable (a name or credential too long for the
/// protocol); nothing was sent, so the target's health is unknown.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct RejectedLocally(String);

/// What a finished dial says about the target.
enum Verdict {
    Healthy,
    Unhealthy,
    NoInformation,
}

fn verdict(error: &anyhow::Error) -> Verdict {
    if error.is::<DnsLookupFailed>() || error.is::<RejectedLocally>() {
        Verdict::NoInformation
    } else if error.is::<ProxyRefused>() {
        Verdict::Healthy
    } else {
        Verdict::Unhealthy
    }
}

/// Bound on cached DNS entries.
const DNS_CACHE_MAX: u64 = 50_000;

/// TTL-based DNS cache backed by `moka`.
///
/// `time_to_live` matches the legacy explicit-expiry behavior; the size cap
/// guards against unbounded growth from random egress targets.
#[derive(Clone)]
struct DnsCache {
    entries: Cache<String, Vec<SocketAddr>>,
}

impl DnsCache {
    fn new(ttl: Duration) -> Self {
        Self {
            entries: Cache::builder()
                .max_capacity(DNS_CACHE_MAX)
                .time_to_live(ttl)
                .build(),
        }
    }

    /// Resolve host:port, returning all cached addresses (or freshly resolved).
    async fn resolve_all(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        let key = format!("{}:{}", host, port);

        if let Some(addrs) = self.entries.get(&key)
            && !addrs.is_empty()
        {
            return Ok(addrs);
        }

        // Miss or expired — resolve and cache.
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&key)
            .await
            .context(DnsLookupFailed)?
            .collect();
        if addrs.is_empty() {
            return Err(anyhow::anyhow!("no addresses for {}", host).context(DnsLookupFailed));
        }
        self.entries.insert(key, addrs.clone());
        Ok(addrs)
    }

    /// Invalidate the cached entry for host:port so the next attempt re-resolves.
    fn invalidate(&self, host: &str, port: u16) {
        let key = format!("{}:{}", host, port);
        self.entries.invalidate(&key);
    }
}

/// How `dial` behaves: timeout, retries and socket options.
struct DialOptions {
    connect_timeout: Duration,
    retries: u32,
    backoffs: Vec<Duration>,
    keepalive: TcpKeepaliveConfig,
}

/// Handles outbound connections to upstream servers.
#[derive(Clone)]
pub struct Egress {
    dns: DnsCache,
    options: Arc<DialOptions>,
    breakers: UpstreamBreakers,
}

impl Egress {
    pub fn new(network: &NetworkConfig, breaker: &BreakerConfig) -> Self {
        let breakers = UpstreamBreakers::new(breaker);
        breakers.publish_gauges();
        Self {
            dns: DnsCache::new(Duration::from_secs(network.dns_cache_ttl_secs)),
            options: Arc::new(DialOptions {
                connect_timeout: network.upstream_connect_timeout(),
                retries: network.egress_retries,
                backoffs: network
                    .egress_backoffs_ms
                    .iter()
                    .map(|ms| Duration::from_millis(*ms))
                    .collect(),
                keepalive: network.upstream_keepalive,
            }),
            breakers,
        }
    }

    /// The breaker table, for diagnostics.
    #[cfg(test)]
    pub(crate) fn breakers(&self) -> &UpstreamBreakers {
        &self.breakers
    }

    /// Connect to target (for CONNECT tunnels - not pooled).
    /// Tunnels are one socket per tunnel, can't be reused.
    ///
    /// `private_override` marks a session's private upstream target (it gets
    /// its own breaker kind). The dial is guarded by the target's breaker:
    /// an open breaker fails at once with [`crate::breaker::BreakerOpen`], and
    /// the dial as a whole is bounded by the connect timeout (error
    /// [`DialTimedOut`]). Only failures that show the target unreachable
    /// count against the breaker: connect and handshake errors and timeouts.
    /// A DNS lookup failure, a refusal the egress proxy answered and requests
    /// rejected locally do not.
    pub async fn connect_tunnel(
        &self,
        target: (&str, u16),
        egress_proxy: Option<&EgressProxy>,
        private_override: bool,
    ) -> Result<TcpStream> {
        let (kind, breaker_key) = match egress_proxy {
            Some(proxy) => (TargetKind::EgressProxy, proxy.address.clone()),
            None if private_override => (
                TargetKind::PrivateOverride,
                format!("{}:{}", target.0, target.1),
            ),
            None => (TargetKind::Origin, format!("{}:{}", target.0, target.1)),
        };
        let permit = self
            .breakers
            .acquire(kind, &breaker_key)
            .map_err(anyhow::Error::new)?;
        match tokio::time::timeout(
            self.options.connect_timeout,
            self.dial(target, egress_proxy),
        )
        .await
        {
            Ok(Ok(stream)) => {
                permit.success();
                Ok(stream)
            }
            Ok(Err(e)) => {
                match verdict(&e) {
                    Verdict::Healthy => permit.success(),
                    Verdict::Unhealthy => permit.failure(),
                    Verdict::NoInformation => permit.ignore(),
                }
                Err(e)
            }
            Err(_) => {
                permit.failure();
                Err(anyhow::Error::new(DialTimedOut(
                    self.options.connect_timeout,
                )))
            }
        }
    }

    /// Dial a new connection. Retries DNS+TCP and egress proxy with backoff.
    async fn dial(
        &self,
        target: (&str, u16),
        egress_proxy: Option<&EgressProxy>,
    ) -> Result<TcpStream> {
        let (host, port) = target;
        let backoffs = &self.options.backoffs;
        let mut last_err: Option<anyhow::Error> = None;
        for attempt in 0..self.options.retries {
            if attempt > 0 {
                let backoff = backoffs[(attempt as usize - 1).min(backoffs.len() - 1)];
                tracing::debug!(
                    attempt,
                    backoff_ms = backoff.as_millis() as u64,
                    %host,
                    "retrying egress connection"
                );
                tokio::time::sleep(backoff).await;
            }
            let result = match egress_proxy {
                Some(proxy) => self.connect_via_egress(proxy, host, port).await,
                None => self.dial_direct(host, port).await,
            };
            match result {
                Ok(stream) => return Ok(stream),
                Err(e) => {
                    tracing::warn!(
                        attempt,
                        %host,
                        error = %format!("{e:#}"),
                        "egress connection attempt failed"
                    );
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("egress dial: no attempts made")))
    }

    /// TCP-connect to `addr` and apply the upstream socket options.
    async fn tcp_connect(
        &self,
        addr: impl tokio::net::ToSocketAddrs,
    ) -> std::io::Result<TcpStream> {
        let stream = TcpStream::connect(addr).await?;
        crate::net::configure(&stream, &self.options.keepalive, "upstream");
        Ok(stream)
    }

    /// Resolve DNS and connect TCP directly (no upstream proxy).
    /// Iterates all resolved addresses; on full failure, invalidates the cache
    /// entry so the next attempt re-resolves.
    async fn dial_direct(&self, host: &str, port: u16) -> Result<TcpStream> {
        let addrs = self.dns.resolve_all(host, port).await?;
        let mut last_err: Option<anyhow::Error> = None;
        for addr in &addrs {
            match self.tcp_connect(addr).await {
                Ok(stream) => return Ok(stream),
                Err(e) => {
                    tracing::debug!(%addr, %host, error = %e, "address failed, trying next");
                    last_err = Some(e.into());
                }
            }
        }
        // All addresses failed — invalidate cache so next attempt re-resolves.
        self.dns.invalidate(host, port);
        Err(last_err
            .unwrap_or_else(|| anyhow::anyhow!("dial_direct: no addresses for {}:{}", host, port)))
    }

    /// Single attempt to connect through an egress proxy.
    async fn connect_via_egress(
        &self,
        proxy: &EgressProxy,
        host: &str,
        port: u16,
    ) -> Result<TcpStream> {
        let stream = self
            .tcp_connect(proxy.address.as_str())
            .await
            .with_context(|| {
                let kind = match proxy.proxy_type {
                    ProxyType::Socks5 => "SOCKS5",
                    ProxyType::Http => "HTTP",
                };
                format!("connect to {kind} proxy {}", proxy.address)
            })?;
        match proxy.proxy_type {
            ProxyType::Socks5 => {
                socks5_handshake(
                    stream,
                    host,
                    port,
                    proxy.username.as_deref(),
                    proxy.password.as_deref(),
                )
                .await
            }
            ProxyType::Http => {
                http_connect_handshake(
                    stream,
                    &proxy.address,
                    host,
                    port,
                    proxy.username.as_deref(),
                    proxy.password.as_deref(),
                )
                .await
            }
        }
    }
}

/// Ask a connected SOCKS5 proxy to open a tunnel to a target host
/// (RFC 1928 / RFC 1929).
async fn socks5_handshake(
    mut stream: TcpStream,
    target_host: &str,
    target_port: u16,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<TcpStream> {
    let wants_auth = username.is_some();
    if wants_auth {
        stream.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
    } else {
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
    }

    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp[0] != 0x05 {
        anyhow::bail!("invalid SOCKS5 greeting response: {:?}", resp);
    }
    match resp[1] {
        0x00 => {}
        0x02 => {
            let user = username.ok_or_else(|| {
                anyhow::Error::new(RejectedLocally(
                    "SOCKS5 proxy requested auth without username".into(),
                ))
            })?;
            let pass = password.unwrap_or("");
            socks5_password_auth(&mut stream, user, pass).await?;
        }
        other => {
            return Err(ProxyRefused(format!(
                "SOCKS5 proxy rejected authentication methods (method=0x{:02x})",
                other
            ))
            .into());
        }
    }

    let host_bytes = target_host.as_bytes();
    let mut req = Vec::with_capacity(4 + 1 + host_bytes.len() + 2);
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03]);
    if host_bytes.len() > 255 {
        return Err(RejectedLocally("hostname exceeds 255 bytes".into()).into());
    }
    req.push(host_bytes.len() as u8);
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&target_port.to_be_bytes());
    stream.write_all(&req).await?;

    let mut resp = [0u8; 4];
    stream.read_exact(&mut resp).await?;
    if resp[0] != 0x05 || resp[1] != 0x00 {
        return Err(ProxyRefused(format!("SOCKS5 CONNECT failed (rep=0x{:02x})", resp[1])).into());
    }
    match resp[3] {
        0x01 => {
            let mut buf = [0u8; 6];
            stream.read_exact(&mut buf).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut buf = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut buf).await?;
        }
        0x04 => {
            let mut buf = [0u8; 18];
            stream.read_exact(&mut buf).await?;
        }
        _ => anyhow::bail!("SOCKS5 unknown address type 0x{:02x}", resp[3]),
    }

    Ok(stream)
}

async fn socks5_password_auth(
    stream: &mut TcpStream,
    username: &str,
    password: &str,
) -> Result<()> {
    let user = username.as_bytes();
    let pass = password.as_bytes();
    if user.len() > 255 || pass.len() > 255 {
        return Err(RejectedLocally("SOCKS5 username/password exceeds 255 bytes".into()).into());
    }

    let mut req = Vec::with_capacity(3 + user.len() + pass.len());
    req.push(0x01);
    req.push(user.len() as u8);
    req.extend_from_slice(user);
    req.push(pass.len() as u8);
    req.extend_from_slice(pass);
    stream.write_all(&req).await?;

    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp != [0x01, 0x00] {
        return Err(ProxyRefused(format!(
            "SOCKS5 username/password authentication failed: {:?}",
            resp
        ))
        .into());
    }
    Ok(())
}

/// Ask a connected HTTP proxy to open a tunnel to a target host.
///
/// Sends a `CONNECT host:port` request with optional Basic authentication
/// and returns the tunneled stream.
async fn http_connect_handshake(
    mut stream: TcpStream,
    proxy_addr: &str,
    target_host: &str,
    target_port: u16,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<TcpStream> {
    // Format authority/Host with brackets for IPv6 literals.
    let authority = if target_host.contains(':') {
        format!("[{}]:{}", target_host, target_port)
    } else {
        format!("{}:{}", target_host, target_port)
    };

    // Build CONNECT request
    let mut request = format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n", authority, authority,);

    if let Some(user) = username {
        let credentials = match password {
            Some(pass) => format!("{}:{}", user, pass),
            None => user.to_string(),
        };
        let encoded = base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes());
        request.push_str(&format!("Proxy-Authorization: Basic {}\r\n", encoded));
    }

    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;

    // Read response headers with a buffered reader instead of one byte at a time.
    let mut reader = BufReader::new(&mut stream);
    let mut buf = Vec::with_capacity(512);
    loop {
        let n = reader
            .read_until(b'\n', &mut buf)
            .await
            .context("reading HTTP proxy response")?;
        if n == 0 {
            anyhow::bail!("HTTP proxy closed connection before response completed");
        }
        if buf.len() >= 4 && buf[buf.len() - 4..] == *b"\r\n\r\n" {
            break;
        }
        if buf.len() > 8192 {
            anyhow::bail!("HTTP proxy response headers too large");
        }
    }

    let response_str = String::from_utf8_lossy(&buf);
    let status_line = response_str
        .lines()
        .next()
        .ok_or_else(|| anyhow::anyhow!("empty response from HTTP proxy"))?;

    let status_code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("malformed status line from HTTP proxy: {}", status_line))?
        .parse()
        .with_context(|| format!("invalid status code in: {}", status_line))?;

    if status_code != 200 {
        return Err(ProxyRefused(format!(
            "HTTP proxy CONNECT failed with status {}: {}",
            status_code, status_line
        ))
        .into());
    }

    tracing::debug!(
        proxy = %proxy_addr,
        target = %authority,
        "HTTP proxy tunnel established"
    );

    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::breaker::BreakerState;
    use crate::net::test_support::keepalive_of;
    use tokio::net::TcpListener;

    fn egress(network: NetworkConfig, breaker: BreakerConfig) -> Egress {
        Egress::new(&network, &breaker)
    }

    /// One attempt, short timeout, tight breaker: failures show at once.
    fn fast_network() -> NetworkConfig {
        NetworkConfig {
            egress_retries: 1,
            upstream_connect_timeout_ms: 400,
            ..NetworkConfig::default()
        }
    }

    fn trip_after(n: u32) -> BreakerConfig {
        BreakerConfig {
            consecutive_failures: n,
            open_duration_ms: 60_000,
            max_open_duration_ms: 60_000,
            ..BreakerConfig::default()
        }
    }

    /// An address nothing listens on.
    async fn closed_addr() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap()
    }

    #[derive(Clone, Copy)]
    enum ProxyMode {
        /// Complete the handshake and open the tunnel.
        Accept,
        /// Answer with a protocol-level refusal.
        Refuse,
        /// Accept the TCP connection and never answer.
        Silent,
    }

    /// A SOCKS5 proxy without authentication. Counts accepted connections.
    async fn fake_socks5(
        mode: ProxyMode,
    ) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = accepted.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                tokio::spawn(async move {
                    if matches!(mode, ProxyMode::Silent) {
                        let mut sink = [0u8; 64];
                        while stream.read(&mut sink).await.unwrap_or(0) > 0 {}
                        return;
                    }
                    let mut greeting = [0u8; 3];
                    if stream.read_exact(&mut greeting).await.is_err() {
                        return;
                    }
                    let _ = stream.write_all(&[0x05, 0x00]).await;
                    let mut head = [0u8; 5];
                    if stream.read_exact(&mut head).await.is_err() {
                        return;
                    }
                    let mut rest = vec![0u8; head[4] as usize + 2];
                    if stream.read_exact(&mut rest).await.is_err() {
                        return;
                    }
                    let rep = if matches!(mode, ProxyMode::Refuse) {
                        0x05
                    } else {
                        0x00
                    };
                    let _ = stream
                        .write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                    let mut sink = [0u8; 64];
                    while stream.read(&mut sink).await.unwrap_or(0) > 0 {}
                });
            }
        });
        (addr, accepted)
    }

    /// An HTTP CONNECT proxy without authentication.
    async fn fake_http_proxy(mode: ProxyMode) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    if matches!(mode, ProxyMode::Silent) {
                        let mut sink = [0u8; 64];
                        while stream.read(&mut sink).await.unwrap_or(0) > 0 {}
                        return;
                    }
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        if stream.read_exact(&mut byte).await.is_err() {
                            return;
                        }
                        head.push(byte[0]);
                    }
                    let reply: &[u8] = if matches!(mode, ProxyMode::Refuse) {
                        b"HTTP/1.1 403 Forbidden\r\n\r\n"
                    } else {
                        b"HTTP/1.1 200 Connection Established\r\n\r\n"
                    };
                    let _ = stream.write_all(reply).await;
                    let mut sink = [0u8; 64];
                    while stream.read(&mut sink).await.unwrap_or(0) > 0 {}
                });
            }
        });
        addr
    }

    fn socks_proxy(address: &str) -> EgressProxy {
        EgressProxy {
            proxy_type: ProxyType::Socks5,
            address: address.to_string(),
            username: None,
            password: None,
        }
    }

    fn http_proxy(address: &str) -> EgressProxy {
        EgressProxy {
            proxy_type: ProxyType::Http,
            address: address.to_string(),
            username: None,
            password: None,
        }
    }

    #[test]
    fn network_defaults_are_the_former_constants() {
        let n = NetworkConfig::default();
        assert_eq!(n.client_header_timeout_ms, 5_000);
        assert_eq!(n.socks_handshake_timeout_ms, 5_000);
        assert_eq!(n.upstream_connect_timeout_ms, 10_000);
        assert_eq!(n.tls_handshake_timeout_ms, 10_000);
        assert_eq!(n.upstream_response_header_timeout_ms, 30_000);
        assert_eq!(n.body_idle_timeout_ms, 30_000);
        assert_eq!(n.http_keepalive_idle_timeout_ms, 30_000);
        assert_eq!(n.http_keepalive_max_requests, 0);
        assert_eq!(n.h2_settings_timeout_ms, 2_000);
        assert_eq!(n.dns_cache_ttl_secs, 60);
        assert_eq!(n.egress_retries, 3);
        assert_eq!(n.egress_backoffs_ms, vec![100, 200, 400]);
    }

    #[tokio::test]
    async fn direct_dial_sets_keepalive_from_config() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut network = fast_network();
        network.upstream_keepalive = crate::config::TcpKeepaliveConfig {
            enabled: true,
            time_secs: 47,
            interval_secs: 9,
            retries: 6,
        };
        let egress = egress(network, BreakerConfig::default());
        let stream = egress
            .connect_tunnel(("127.0.0.1", addr.port()), None, false)
            .await
            .unwrap();
        assert_eq!(
            keepalive_of(&stream),
            (true, Duration::from_secs(47), Duration::from_secs(9), 6)
        );
        assert!(stream.nodelay().unwrap());
    }

    #[tokio::test]
    async fn private_override_dial_sets_keepalive_from_config() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut network = fast_network();
        network.upstream_keepalive.time_secs = 33;
        network.upstream_keepalive.interval_secs = 11;
        network.upstream_keepalive.retries = 2;
        let egress = egress(network, BreakerConfig::default());
        let stream = egress
            .connect_tunnel(("127.0.0.1", addr.port()), None, true)
            .await
            .unwrap();
        assert_eq!(
            keepalive_of(&stream),
            (true, Duration::from_secs(33), Duration::from_secs(11), 2)
        );
    }

    #[tokio::test]
    async fn egress_proxy_dials_set_keepalive_from_config() {
        let mut network = fast_network();
        network.upstream_keepalive.time_secs = 52;
        network.upstream_keepalive.interval_secs = 13;
        network.upstream_keepalive.retries = 4;
        let expected = (true, Duration::from_secs(52), Duration::from_secs(13), 4);
        let egress = egress(network, BreakerConfig::default());

        let (socks_addr, _) = fake_socks5(ProxyMode::Accept).await;
        let via_socks = egress
            .connect_tunnel(("origin.test", 443), Some(&socks_proxy(&socks_addr)), false)
            .await
            .unwrap();
        assert_eq!(keepalive_of(&via_socks), expected);

        let http_addr = fake_http_proxy(ProxyMode::Accept).await;
        let via_http = egress
            .connect_tunnel(("origin.test", 443), Some(&http_proxy(&http_addr)), false)
            .await
            .unwrap();
        assert_eq!(keepalive_of(&via_http), expected);
    }

    #[tokio::test]
    async fn keepalive_can_be_turned_off_for_upstream_sockets() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut network = fast_network();
        network.upstream_keepalive.enabled = false;
        let egress = egress(network, BreakerConfig::default());
        let stream = egress
            .connect_tunnel(("127.0.0.1", addr.port()), None, false)
            .await
            .unwrap();
        assert!(!socket2::SockRef::from(&stream).keepalive().unwrap());
    }

    #[tokio::test]
    async fn refused_connects_open_the_breaker_and_then_fail_fast() {
        let addr = closed_addr().await;
        let egress = egress(fast_network(), trip_after(2));
        let target = ("127.0.0.1", addr.port());
        let key = format!("127.0.0.1:{}", addr.port());

        for _ in 0..2 {
            let err = egress
                .connect_tunnel(target, None, false)
                .await
                .unwrap_err();
            assert!(err.downcast_ref::<crate::breaker::BreakerOpen>().is_none());
        }
        assert_eq!(
            egress.breakers().state(TargetKind::Origin, &key),
            Some(BreakerState::Open)
        );

        // A listener appears, but the open breaker must not dial it.
        let listener = TcpListener::bind(addr).await.unwrap();
        let started = std::time::Instant::now();
        let err = egress
            .connect_tunnel(target, None, false)
            .await
            .unwrap_err();
        let open = err
            .downcast_ref::<crate::breaker::BreakerOpen>()
            .expect("breaker error");
        assert_eq!(open.kind, TargetKind::Origin);
        assert!(started.elapsed() < Duration::from_millis(100), "fails fast");
        assert!(
            tokio::time::timeout(Duration::from_millis(200), listener.accept())
                .await
                .is_err(),
            "no connection was attempted while open"
        );
    }

    #[tokio::test]
    async fn private_override_uses_its_own_breaker_kind() {
        let addr = closed_addr().await;
        let egress = egress(fast_network(), trip_after(1));
        let target = ("127.0.0.1", addr.port());
        let _ = egress.connect_tunnel(target, None, true).await.unwrap_err();
        let err = egress.connect_tunnel(target, None, true).await.unwrap_err();
        assert_eq!(
            err.downcast_ref::<crate::breaker::BreakerOpen>()
                .expect("breaker error")
                .kind,
            TargetKind::PrivateOverride
        );
        // The origin breaker for the same address is a different one.
        let err = egress
            .connect_tunnel(target, None, false)
            .await
            .unwrap_err();
        assert!(err.downcast_ref::<crate::breaker::BreakerOpen>().is_none());
    }

    #[tokio::test]
    async fn connect_timeout_is_a_counted_failure() {
        let (silent, accepted) = fake_socks5(ProxyMode::Silent).await;
        let mut network = fast_network();
        network.upstream_connect_timeout_ms = 150;
        let egress = egress(network, trip_after(1));
        let proxy = socks_proxy(&silent);

        let err = egress
            .connect_tunnel(("origin.test", 443), Some(&proxy), false)
            .await
            .unwrap_err();
        let timed_out = err.downcast_ref::<DialTimedOut>().expect("timeout error");
        assert_eq!(timed_out.0, Duration::from_millis(150));
        assert_eq!(
            egress.breakers().state(TargetKind::EgressProxy, &silent),
            Some(BreakerState::Open)
        );

        let err = egress
            .connect_tunnel(("origin.test", 443), Some(&proxy), false)
            .await
            .unwrap_err();
        assert_eq!(
            err.downcast_ref::<crate::breaker::BreakerOpen>()
                .expect("breaker error")
                .kind,
            TargetKind::EgressProxy
        );
        assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_egress_proxy_refusal_does_not_count_against_the_proxy() {
        let (refusing, _) = fake_socks5(ProxyMode::Refuse).await;
        let http_refusing = fake_http_proxy(ProxyMode::Refuse).await;
        let egress = egress(fast_network(), trip_after(1));
        for _ in 0..3 {
            let err = egress
                .connect_tunnel(("origin.test", 443), Some(&socks_proxy(&refusing)), false)
                .await
                .unwrap_err();
            assert!(
                format!("{err:#}").contains("SOCKS5 CONNECT failed"),
                "{err:#}"
            );
            let err = egress
                .connect_tunnel(
                    ("origin.test", 443),
                    Some(&http_proxy(&http_refusing)),
                    false,
                )
                .await
                .unwrap_err();
            assert!(format!("{err:#}").contains("status 403"), "{err:#}");
        }
        assert_eq!(
            egress.breakers().state(TargetKind::EgressProxy, &refusing),
            Some(BreakerState::Closed)
        );
        assert_eq!(
            egress
                .breakers()
                .state(TargetKind::EgressProxy, &http_refusing),
            Some(BreakerState::Closed)
        );
    }

    #[tokio::test]
    async fn an_oversized_hostname_is_rejected_without_a_verdict() {
        let (addr, _) = fake_socks5(ProxyMode::Accept).await;
        let egress = egress(fast_network(), trip_after(1));
        let long_host = "a".repeat(300);
        for _ in 0..3 {
            let err = egress
                .connect_tunnel((long_host.as_str(), 443), Some(&socks_proxy(&addr)), false)
                .await
                .unwrap_err();
            assert!(
                format!("{err:#}").contains("hostname exceeds 255"),
                "{err:#}"
            );
        }
        assert_ne!(
            egress.breakers().state(TargetKind::EgressProxy, &addr),
            Some(BreakerState::Open)
        );
    }

    #[tokio::test]
    async fn retries_and_backoffs_follow_the_config() {
        let addr = closed_addr().await;
        let network = NetworkConfig {
            egress_retries: 3,
            egress_backoffs_ms: vec![150],
            upstream_connect_timeout_ms: 5_000,
            ..NetworkConfig::default()
        };
        let egress = egress(
            network,
            BreakerConfig {
                enabled: false,
                ..BreakerConfig::default()
            },
        );
        let started = std::time::Instant::now();
        let _ = egress
            .connect_tunnel(("127.0.0.1", addr.port()), None, false)
            .await
            .unwrap_err();
        // Three attempts, two waits of 150 ms (the last backoff repeats).
        assert!(
            started.elapsed() >= Duration::from_millis(290),
            "took {:?}",
            started.elapsed()
        );
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[tokio::test]
    async fn disabled_breaker_keeps_dialing() {
        let addr = closed_addr().await;
        let egress = egress(
            fast_network(),
            BreakerConfig {
                enabled: false,
                consecutive_failures: 1,
                ..BreakerConfig::default()
            },
        );
        for _ in 0..4 {
            let err = egress
                .connect_tunnel(("127.0.0.1", addr.port()), None, false)
                .await
                .unwrap_err();
            assert!(err.downcast_ref::<crate::breaker::BreakerOpen>().is_none());
        }
        let listener = TcpListener::bind(addr).await.unwrap();
        egress
            .connect_tunnel(("127.0.0.1", addr.port()), None, false)
            .await
            .expect("dial succeeds once the target is back");
        drop(listener);
    }
}
