//! Upstream dial through HTTP CONNECT or SOCKS5 with per-stage timing.
//!
//! One attempt per call: the caller owns retries and uses
//! [`DialError::is_retryable`] to pick the retryable failures.
//! Every stage (`dns`, `tcp`, `handshake`) has its own timeout and
//! is recorded in `dial_duration_seconds{provider,stage}`. The `first_byte`
//! stage starts after the tunnel is open and is recorded by the gateway with
//! [`record_first_byte`].

mod destination;
mod http;
mod socks5;

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use common::Cause;
use common::config::TcpKeepalive;
use common::metrics::Metrics;
use common::types::{ProviderId, Target, UpstreamEndpoint, UpstreamScheme};
use tokio::net::{TcpSocket, TcpStream, lookup_host};
use tokio::time::{Instant, timeout};

pub use destination::is_denied_destination;

/// A step of the dial, and the `stage` label of `dial_duration_seconds`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Dns,
    Tcp,
    Handshake,
    FirstByte,
}

impl Stage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Stage::Dns => "dns",
            Stage::Tcp => "tcp",
            Stage::Handshake => "handshake",
            Stage::FirstByte => "first_byte",
        }
    }
}

/// Time limit of each stage. The defaults add up to 6 s, inside the 8 s
/// answer budget (the session proxy's own limit is 10 s).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DialTimeouts {
    /// Name resolution of the upstream host. Skipped for an IP literal.
    pub dns: Duration,
    /// TCP connect, over all resolved addresses together.
    pub tcp: Duration,
    /// HTTP CONNECT or SOCKS5 exchange, from first byte sent to tunnel open.
    pub handshake: Duration,
    /// TCP keepalive of the dialed socket; `None` turns it off.
    pub keepalive: Option<TcpKeepalive>,
}

impl Default for DialTimeouts {
    fn default() -> Self {
        Self {
            dns: Duration::from_secs(1),
            tcp: Duration::from_secs(2),
            handshake: Duration::from_secs(3),
            keepalive: DEFAULT_KEEPALIVE,
        }
    }
}

/// Why a dial failed. Never carries a credential.
#[derive(Debug, thiserror::Error)]
pub enum DialError {
    #[error("upstream {} stage timed out after {after:?}", .stage.as_str())]
    Timeout { stage: Stage, after: Duration },
    #[error("upstream DNS lookup failed: {0}")]
    Dns(io::Error),
    #[error("upstream TCP connect failed: {0}")]
    Connect(io::Error),
    #[error("upstream rejected the credential")]
    Auth,
    #[error("the upstream credential cannot be sent: {0}")]
    BadCredential(&'static str),
    #[error("upstream answered CONNECT with status {0}")]
    Status(u16),
    #[error("upstream SOCKS5 reply 0x{0:02x}")]
    SocksReply(u8),
    #[error("upstream protocol error: {0}")]
    Protocol(&'static str),
    #[error("I/O error during the upstream handshake: {0}")]
    Io(io::Error),
    #[error("target cannot be sent upstream: {0}")]
    BadTarget(&'static str),
    #[error("upstream resolves to a private or internal address")]
    DeniedAddress,
    #[error("local source address cannot be used: {0}")]
    LocalSource(&'static str),
}

impl DialError {
    /// The gateway answer for this failure.
    pub fn cause(&self) -> Cause {
        match self {
            DialError::Timeout { .. } => Cause::ProviderTimeout,
            DialError::Connect(e) if e.kind() == io::ErrorKind::TimedOut => Cause::ProviderTimeout,
            DialError::Dns(_) | DialError::Connect(_) | DialError::LocalSource(_) => {
                Cause::ProviderUnavailable
            }
            DialError::Auth | DialError::BadCredential(_) => Cause::ProviderAuth,
            DialError::Status(_)
            | DialError::SocksReply(_)
            | DialError::Protocol(_)
            | DialError::Io(_) => Cause::UpstreamError,
            // Refused before anything is sent: the target is not one we tunnel to.
            DialError::BadTarget(_) | DialError::DeniedAddress => Cause::DestinationDenied,
        }
    }

    /// True for the failures the caller may retry: a timeout
    /// before the CONNECT was sent, connection reset, end of stream and
    /// `429`. A handshake timeout is not retried: a provider that accepted
    /// the connection and stayed silent will not answer the next try either,
    /// and the retries would spend the whole answer budget on it. Login and protocol errors never retry.
    pub fn is_retryable(&self) -> bool {
        match self {
            DialError::Timeout { stage, .. } => matches!(stage, Stage::Dns | Stage::Tcp),
            DialError::Status(429) => true,
            DialError::Io(e) => matches!(
                e.kind(),
                io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::UnexpectedEof
            ),
            _ => false,
        }
    }

    /// True when the connect failed for lack of a local resource, not
    /// because of the provider: no free ephemeral port or source address
    /// (`EADDRNOTAVAIL`, `EADDRINUSE`), no file descriptor (`EMFILE`,
    /// `ENFILE`) or no socket buffer (`ENOBUFS`). The same failure would
    /// hit a healthy provider, so it never counts for the breaker.
    pub fn is_local(&self) -> bool {
        let DialError::Connect(e) = self else {
            return false;
        };
        matches!(
            e.raw_os_error(),
            Some(
                libc::EADDRNOTAVAIL
                    | libc::EADDRINUSE
                    | libc::EMFILE
                    | libc::ENFILE
                    | libc::ENOBUFS
            )
        )
    }

    /// True when the source address of a `Local` unit cannot be used: it is
    /// no bindable unicast address ([`DialError::LocalSource`]), or the
    /// socket could not take it (`EADDRNOTAVAIL`: the address is no longer
    /// assigned to an interface, or it has no free port left). Another IP
    /// of the machine may serve the same target; the provider is not at
    /// fault.
    pub fn source_unusable(&self) -> bool {
        match self {
            DialError::LocalSource(_) => true,
            DialError::Connect(e) => e.raw_os_error() == Some(libc::EADDRNOTAVAIL),
            _ => false,
        }
    }

    /// True when the failure says the provider endpoint itself cannot be
    /// reached (name, TCP connect, or a timeout before the CONNECT is sent):
    /// the breaker counts these. A handshake that times out may be waiting
    /// for a dead target, and a status or SOCKS reply is an answer, so
    /// neither counts: one org's bad target must not open a route class.
    /// A [local](Self::is_local) connect failure is our own fault and does
    /// not count either.
    pub fn provider_unreachable(&self) -> bool {
        match self {
            DialError::Connect(_) => !self.is_local(),
            DialError::Dns(_)
            | DialError::Timeout {
                stage: Stage::Dns | Stage::Tcp,
                ..
            } => true,
            _ => false,
        }
    }

    /// True when the provider accepted the connection but refused to serve
    /// it: it rejected the login (HTTP 407, SOCKS5 login failure) or dropped
    /// the connection during the handshake. A revoked or expired account
    /// looks like this, so the breaker counts it (runbook 053) next to
    /// [`Self::provider_unreachable`]. The gateway skips both for a customer's
    /// own upstream: one org's wrong login or dead host must not open a route
    /// class every org shares. A status or SOCKS reply is an answer about the
    /// target and a credential that could not be sent is our configuration:
    /// neither counts.
    pub fn provider_rejected(&self) -> bool {
        matches!(self, DialError::Auth | DialError::Io(_))
    }

    /// True when the upstream replied to the CONNECT with an HTTP status or a
    /// SOCKS reply: it is up and serving, whatever it said about the target.
    /// A route class breaker probe that gets no such reply (a timeout, a
    /// reset, a login failure) proves nothing about the provider.
    pub fn answered(&self) -> bool {
        matches!(self, DialError::Status(_) | DialError::SocksReply(_))
    }

    /// True when the provider endpoint answered but the unit (static IP or
    /// rotating session) fails the tunnel: it refuses its login, drops the
    /// connection, speaks nonsense or stays silent in the handshake. The
    /// gateway then stops leasing the unit for that target for a while;
    /// without it a sticky lease stays on a unit that fails every tunnel
    ///. A status or SOCKS reply is an answer about the target,
    /// an unreachable endpoint is the breaker's, and a local failure is no
    /// unit's fault: none of them counts.
    pub fn unit_misbehaves(&self) -> bool {
        match self {
            DialError::Auth
            | DialError::BadCredential(_)
            | DialError::Protocol(_)
            | DialError::Io(_) => true,
            DialError::Timeout { stage, .. } => *stage == Stage::Handshake,
            DialError::Dns(_)
            | DialError::Connect(_)
            | DialError::Status(_)
            | DialError::SocksReply(_)
            | DialError::BadTarget(_)
            | DialError::DeniedAddress
            | DialError::LocalSource(_) => false,
        }
    }

    /// True when another IP may get through where this one failed: the unit [misbehaves](Self::unit_misbehaves), or it relayed an
    /// HTTP status or SOCKS reply that another exit IP may not get. The
    /// failures left out are the ones another IP of the same provider repeats:
    /// an unreachable endpoint (the breaker's), a local resource limit, and a
    /// target the request names wrongly.
    pub fn ip_level(&self) -> bool {
        self.unit_misbehaves() || matches!(self, DialError::Status(_) | DialError::SocksReply(_))
    }
}

/// Record the `first_byte` stage: time from tunnel open to the first byte
/// the target sends back. Called by the gateway, which owns the relay.
pub fn record_first_byte(m: &Metrics, provider: &ProviderId, elapsed: Duration) {
    observe(m, provider, Stage::FirstByte, elapsed);
}

fn observe(m: &Metrics, provider: &ProviderId, stage: Stage, elapsed: Duration) {
    m.dial_duration_seconds
        .with_label_values(&[provider.as_str(), stage.as_str()])
        .observe(elapsed.as_secs_f64());
}

/// Open a tunnel to `target` through `up`. One attempt; no direct dial. The
/// stream is positioned right after the upstream's reply: no tunnel byte was
/// consumed. A failure is a [`DialError`]; [`DialError::cause`] gives the
/// gateway answer.
///
/// With `up.public_only` (an upstream the customer chose) the upstream host is
/// resolved here, every address it resolves to must pass
/// [`is_denied_destination`], and the connection goes to those checked
/// addresses, never to a second resolution. A public name that points at a
/// private address is refused with [`DialError::DeniedAddress`].
///
/// With `up.scheme == Local` there is no upstream: `up.host` is the local
/// source address, the target is resolved here, every address it resolves to
/// must pass [`is_denied_destination`], and the connection leaves from the
/// bound source address. No handshake follows.
pub async fn dial(
    up: &UpstreamEndpoint,
    target: &Target,
    t: &DialTimeouts,
    m: &Metrics,
) -> Result<TcpStream, DialError> {
    let source = local_source(up)?;
    let keepalive = t.keepalive;
    dial_with(up, target, t, m, resolve, move |a| {
        connect_from_with(a, source, keepalive)
    })
    .await
}

/// The source address of a `Local` endpoint; `None` for a proxy upstream.
fn local_source(up: &UpstreamEndpoint) -> Result<Option<IpAddr>, DialError> {
    if up.scheme != UpstreamScheme::Local {
        return Ok(None);
    }
    match up.host.parse::<IpAddr>() {
        Ok(ip) if ip.is_unspecified() || ip.is_multicast() => {
            Err(DialError::LocalSource("not a unicast address"))
        }
        Ok(ip) => Ok(Some(ip)),
        Err(_) => Err(DialError::LocalSource("host is not an IP literal")),
    }
}

async fn dial_with<R, Fut, C, CFut>(
    up: &UpstreamEndpoint,
    target: &Target,
    t: &DialTimeouts,
    m: &Metrics,
    resolver: R,
    connector: C,
) -> Result<TcpStream, DialError>
where
    R: FnOnce(String, u16) -> Fut,
    Fut: Future<Output = Result<Vec<SocketAddr>, DialError>>,
    C: FnOnce(Vec<SocketAddr>) -> CFut,
    CFut: Future<Output = Result<TcpStream, DialError>>,
{
    let host = target_host(target)?;
    if up.scheme == UpstreamScheme::Local {
        local_source(up)?;
        let addrs = match host.parse::<IpAddr>() {
            Ok(ip) => vec![SocketAddr::new(ip, target.port)],
            Err(_) => {
                timed(
                    m,
                    &up.provider,
                    Stage::Dns,
                    t.dns,
                    resolver(host.to_owned(), target.port),
                )
                .await?
            }
        };
        if addrs.iter().any(|a| {
            is_denied_destination(&Target {
                host: a.ip().to_string(),
                port: a.port(),
            })
        }) {
            return Err(DialError::DeniedAddress);
        }
        return timed(m, &up.provider, Stage::Tcp, t.tcp, connector(addrs)).await;
    }
    check_sendable(up, host)?;

    let addrs = match up.host.parse::<IpAddr>() {
        Ok(ip) => vec![SocketAddr::new(ip, up.port)],
        Err(_) => {
            timed(
                m,
                &up.provider,
                Stage::Dns,
                t.dns,
                resolver(up.host.clone(), up.port),
            )
            .await?
        }
    };
    if up.public_only
        && addrs.iter().any(|a| {
            is_denied_destination(&Target {
                host: a.ip().to_string(),
                port: a.port(),
            })
        })
    {
        return Err(DialError::DeniedAddress);
    }

    let mut stream = timed(m, &up.provider, Stage::Tcp, t.tcp, connector(addrs)).await?;

    let handshake = handshake(&mut stream, up, target);
    timed(m, &up.provider, Stage::Handshake, t.handshake, handshake).await?;

    Ok(stream)
}

/// Open the tunnel to `target` on a stream already connected to the proxy
/// `up` (HTTP CONNECT or SOCKS5, with `up`'s credential). The stream is left
/// right after the proxy's reply. Calling it for a `Local` endpoint is a
/// [`DialError::LocalSource`]: there is no proxy to talk to.
pub async fn handshake(
    stream: &mut TcpStream,
    up: &UpstreamEndpoint,
    target: &Target,
) -> Result<(), DialError> {
    let host = target_host(target)?;
    check_sendable(up, host)?;
    match up.scheme {
        UpstreamScheme::Http => http::connect(stream, up, host, target.port).await,
        UpstreamScheme::Socks5 => socks5::connect(stream, up, host, target.port).await,
        UpstreamScheme::Local => Err(DialError::LocalSource("no upstream proxy to talk to")),
    }
}

/// Run one stage under its limit and record its time, also when it fails or
/// times out, so a slow provider shows in the histogram.
async fn timed<T>(
    m: &Metrics,
    provider: &ProviderId,
    stage: Stage,
    limit: Duration,
    work: impl Future<Output = Result<T, DialError>>,
) -> Result<T, DialError> {
    let start = Instant::now();
    let result = timeout(limit, work)
        .await
        .unwrap_or(Err(DialError::Timeout {
            stage,
            after: limit,
        }));
    observe(m, provider, stage, start.elapsed());
    result
}

async fn resolve(host: String, port: u16) -> Result<Vec<SocketAddr>, DialError> {
    let addrs: Vec<SocketAddr> = lookup_host((host.as_str(), port))
        .await
        .map_err(DialError::Dns)?
        .collect();
    if addrs.is_empty() {
        return Err(DialError::Dns(io::Error::new(
            io::ErrorKind::NotFound,
            "no addresses",
        )));
    }
    Ok(addrs)
}

/// Try each address in order; the stage limit bounds the whole walk. Takes
/// the addresses by value, the shape `dial_with` gives a connector, so a
/// test can swap it.
///
/// With a `source`, the socket binds that local address (port chosen at
/// connect time) before it connects, and addresses of the other IP family are
/// skipped: a socket bound to an IPv4 address cannot reach an IPv6 target.
/// When no address has the source's family the failure is
/// `EADDRNOTAVAIL`, a local error that never counts against a provider.
pub async fn connect_from(
    addrs: Vec<SocketAddr>,
    source: Option<IpAddr>,
) -> Result<TcpStream, DialError> {
    connect_from_with(addrs, source, DEFAULT_KEEPALIVE).await
}

/// [`connect_from`] with the TCP keepalive timers of the caller (`None`: off).
pub async fn connect_from_with(
    addrs: Vec<SocketAddr>,
    source: Option<IpAddr>,
    keepalive: Option<TcpKeepalive>,
) -> Result<TcpStream, DialError> {
    let mut last = match source {
        Some(_) => io::Error::from_raw_os_error(libc::EADDRNOTAVAIL),
        None => io::Error::new(io::ErrorKind::NotFound, "no addresses"),
    };
    for addr in &addrs {
        let attempt = match source {
            None => TcpStream::connect(addr).await,
            Some(src) if src.is_ipv4() == addr.is_ipv4() => connect_bound(src, *addr).await,
            Some(_) => continue,
        };
        match attempt {
            Ok(stream) => {
                stream.set_nodelay(true).map_err(DialError::Connect)?;
                set_keepalive(&stream, keepalive).map_err(DialError::Connect)?;
                return Ok(stream);
            }
            Err(e) => last = e,
        }
    }
    Err(DialError::Connect(last))
}

/// Connect to `addr` from the local address `src`. `IP_BIND_ADDRESS_NO_PORT`
/// delays the port choice to connect time, so many connections from one
/// source address to different targets do not run out of ephemeral ports.
async fn connect_bound(src: IpAddr, addr: SocketAddr) -> io::Result<TcpStream> {
    let socket = if src.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    // Best effort: an old kernel without the option only loses the port sharing.
    let _ = nix::sys::socket::setsockopt(
        &socket,
        nix::sys::socket::sockopt::IpBindAddressNoPort,
        &true,
    );
    socket.bind(SocketAddr::new(src, 0))?;
    socket.connect(addr).await
}

/// Keepalive of a tunnel socket when nothing else is configured: first probe
/// after 60 s of silence, then every 15 s, dropping the peer after 4
/// unanswered probes (a peer that vanished without FIN or RST is gone after
/// 60 + 4 * 15 s).
pub const DEFAULT_KEEPALIVE: Option<TcpKeepalive> = Some(TcpKeepalive {
    time: Duration::from_secs(60),
    interval: Duration::from_secs(15),
    retries: 4,
});

/// Set TCP keepalive to `keepalive`'s timers, or turn it off with `None`. The
/// gateway sets it on the client socket it accepts, this crate on the one it
/// dials, both from the pool settings (`tcp_keepalive_*`).
pub fn set_keepalive(stream: &TcpStream, keepalive: Option<TcpKeepalive>) -> io::Result<()> {
    let sock = socket2::SockRef::from(stream);
    match keepalive {
        Some(k) => sock.set_tcp_keepalive(
            &socket2::TcpKeepalive::new()
                .with_time(k.time)
                .with_interval(k.interval)
                .with_retries(k.retries),
        ),
        None => sock.set_keepalive(false),
    }
}

/// The target host without IPv6 brackets, checked to be one token. A host
/// with whitespace or control bytes would split the CONNECT request line.
fn target_host(target: &Target) -> Result<&str, DialError> {
    let host = target
        .host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(&target.host);
    if host.is_empty() {
        return Err(DialError::BadTarget("empty host"));
    }
    if host.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return Err(DialError::BadTarget("host has whitespace or control bytes"));
    }
    Ok(host)
}

/// SOCKS5 length-prefixes host and credentials with one byte. Refuse before
/// connecting so no socket is opened for a request that cannot be sent.
fn check_sendable(up: &UpstreamEndpoint, host: &str) -> Result<(), DialError> {
    if up.scheme != UpstreamScheme::Socks5 {
        return Ok(());
    }
    if host.len() > 255 && host.parse::<IpAddr>().is_err() {
        return Err(DialError::BadTarget("host longer than 255 bytes"));
    }
    if up.username.expose().len() > 255 || up.password.expose().len() > 255 {
        return Err(DialError::BadCredential(
            "SOCKS5 limits fields to 255 bytes",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
