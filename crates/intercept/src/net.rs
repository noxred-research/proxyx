//! Socket options shared by the accept loops and the upstream dialers.

use std::io;
use std::time::Duration;

use socket2::{SockRef, TcpKeepalive};
use tokio::net::TcpStream;

use crate::config::TcpKeepaliveConfig;

/// Apply `cfg` to a connected socket: `SO_KEEPALIVE` plus the idle time,
/// probe interval and probe count, or `SO_KEEPALIVE` off when disabled.
pub fn apply_keepalive(stream: &TcpStream, cfg: &TcpKeepaliveConfig) -> io::Result<()> {
    let sock = SockRef::from(stream);
    if !cfg.enabled {
        return sock.set_keepalive(false);
    }
    sock.set_tcp_keepalive(
        &TcpKeepalive::new()
            .with_time(Duration::from_secs(cfg.time_secs))
            .with_interval(Duration::from_secs(cfg.interval_secs))
            .with_retries(cfg.retries),
    )
}

/// Disable Nagle and apply keepalive to a freshly connected or accepted
/// socket. A failure only costs the option, not the connection, so it is
/// logged and the socket is used anyway.
pub fn configure(stream: &TcpStream, cfg: &TcpKeepaliveConfig, side: &'static str) {
    if let Err(e) = stream.set_nodelay(true) {
        tracing::debug!(side, error = %e, "set TCP_NODELAY failed");
    }
    if let Err(e) = apply_keepalive(stream, cfg) {
        tracing::warn!(side, error = %e, "set TCP keepalive failed");
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use tokio::net::TcpListener;

    /// A connected pair: `(client side, accepted side)`.
    pub(crate) async fn socket_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
        (client.unwrap(), accepted.unwrap().0)
    }

    /// What the kernel reports for `stream`:
    /// `(SO_KEEPALIVE, TCP_KEEPIDLE, TCP_KEEPINTVL, TCP_KEEPCNT)`.
    pub(crate) fn keepalive_of(stream: &TcpStream) -> (bool, Duration, Duration, u32) {
        let sock = SockRef::from(stream);
        (
            sock.keepalive().unwrap(),
            sock.tcp_keepalive_time().unwrap(),
            sock.tcp_keepalive_interval().unwrap(),
            sock.tcp_keepalive_retries().unwrap(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{keepalive_of, socket_pair};
    use super::*;

    #[tokio::test]
    async fn applies_the_configured_options() {
        let (stream, _peer) = socket_pair().await;
        let cfg = TcpKeepaliveConfig {
            enabled: true,
            time_secs: 41,
            interval_secs: 7,
            retries: 5,
        };
        apply_keepalive(&stream, &cfg).unwrap();
        assert_eq!(
            keepalive_of(&stream),
            (true, Duration::from_secs(41), Duration::from_secs(7), 5)
        );
    }

    #[tokio::test]
    async fn disabled_switches_keepalive_off() {
        let (stream, _peer) = socket_pair().await;
        apply_keepalive(&stream, &TcpKeepaliveConfig::default()).unwrap();
        assert!(SockRef::from(&stream).keepalive().unwrap());
        apply_keepalive(
            &stream,
            &TcpKeepaliveConfig {
                enabled: false,
                ..TcpKeepaliveConfig::default()
            },
        )
        .unwrap();
        assert!(!SockRef::from(&stream).keepalive().unwrap());
    }

    #[tokio::test]
    async fn configure_sets_nodelay_and_keepalive() {
        let (stream, _peer) = socket_pair().await;
        configure(&stream, &TcpKeepaliveConfig::default(), "test");
        assert!(stream.nodelay().unwrap());
        assert!(SockRef::from(&stream).keepalive().unwrap());
    }
}
