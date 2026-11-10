//! TCP socket options from `[tcp.client]` and `[tcp.upstream]`.

use std::io;

use socket2::{SockRef, TcpKeepalive};
use tokio::net::TcpStream;

use crate::config::SocketOptions;

pub fn check(o: &SocketOptions, what: &str) -> Result<(), String> {
    if o.keepalive
        && (o.keepalive_time.is_zero()
            || o.keepalive_interval.is_zero()
            || o.keepalive_retries == 0)
    {
        return Err(format!(
            "{what}: keepalive_time, keepalive_interval and keepalive_retries must be above zero (or set keepalive = false)"
        ));
    }
    Ok(())
}

/// Apply the options to a connected socket.
pub fn apply(stream: &TcpStream, o: &SocketOptions) -> io::Result<()> {
    stream.set_nodelay(o.nodelay)?;
    let sock = SockRef::from(stream);
    if o.keepalive {
        sock.set_tcp_keepalive(
            &TcpKeepalive::new()
                .with_time(o.keepalive_time)
                .with_interval(o.keepalive_interval)
                .with_retries(o.keepalive_retries),
        )
    } else {
        sock.set_keepalive(false)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::net::TcpListener;

    use super::*;

    #[tokio::test]
    async fn options_reach_the_socket() {
        let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let s = TcpStream::connect(l.local_addr().expect("addr"))
            .await
            .expect("connect");
        let o = SocketOptions {
            keepalive: true,
            keepalive_time: Duration::from_secs(33),
            keepalive_interval: Duration::from_secs(7),
            keepalive_retries: 3,
            nodelay: false,
        };
        apply(&s, &o).expect("apply");
        let r = SockRef::from(&s);
        assert!(r.keepalive().expect("ka"));
        assert_eq!(r.tcp_keepalive_time().expect("t"), Duration::from_secs(33));
        assert_eq!(
            r.tcp_keepalive_interval().expect("i"),
            Duration::from_secs(7)
        );
        assert_eq!(r.tcp_keepalive_retries().expect("r"), 3);
        assert!(!s.nodelay().expect("nd"));
        apply(
            &s,
            &SocketOptions {
                keepalive: false,
                ..o
            },
        )
        .expect("off");
        assert!(!SockRef::from(&s).keepalive().expect("ka"));
    }

    #[test]
    fn enabled_keepalive_needs_positive_values() {
        let bad = SocketOptions {
            keepalive_retries: 0,
            ..SocketOptions::default()
        };
        assert!(check(&bad, "x").is_err());
        assert!(
            check(
                &SocketOptions {
                    keepalive: false,
                    ..bad
                },
                "x"
            )
            .is_ok()
        );
        assert!(check(&SocketOptions::default(), "x").is_ok());
    }
}
