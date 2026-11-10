//! Stub servers on loopback: a TCP echo, an HTTP/1.1 origin (plain or TLS)
//! and an HTTP proxy that stands in for a pool provider.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use crate::http1::Conn;

/// A running stub. Dropping it stops the accept loop; connections already
/// open end when their peer closes.
pub struct Stub {
    pub addr: SocketAddr,
    accepted: Arc<AtomicU64>,
    task: JoinHandle<()>,
}

impl Stub {
    /// Connections accepted so far.
    pub fn accepted(&self) -> u64 {
        self.accepted.load(Ordering::Relaxed)
    }
}

impl Drop for Stub {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Bind a fresh loopback port and run `handler` on every connection.
async fn serve<F, Fut>(handler: F) -> io::Result<Stub>
where
    F: Fn(TcpStream) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let accepted = Arc::new(AtomicU64::new(0));
    let counter = Arc::clone(&accepted);
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                // a transient accept error (descriptor limit): back off
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                continue;
            };
            let _ = stream.set_nodelay(true);
            counter.fetch_add(1, Ordering::Relaxed);
            tokio::spawn(handler(stream));
        }
    });
    Ok(Stub {
        addr,
        accepted,
        task,
    })
}

/// A TCP server that writes back every byte it reads.
pub async fn echo() -> io::Result<Stub> {
    serve(|stream| async move {
        let (mut reader, mut writer) = stream.into_split();
        let _ = tokio::io::copy(&mut reader, &mut writer).await;
    })
    .await
}

/// The two canned responses of the HTTP origin: keep-alive and close.
struct Canned {
    keep_alive: Vec<u8>,
    close: Vec<u8>,
}

impl Canned {
    fn new(body_bytes: usize) -> Self {
        let make = |connection: &str| {
            let mut out = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {body_bytes}\r\n{connection}\r\n"
            )
            .into_bytes();
            out.resize(out.len() + body_bytes, b'x');
            out
        };
        Self {
            keep_alive: make(""),
            close: make("Connection: close\r\n"),
        }
    }
}

/// An HTTP/1.1 origin that answers every request with `response_bytes` bytes
/// of body. With `tls` it speaks TLS first. It reads and discards request
/// bodies (`Content-Length` framing) and honours `Connection: close`.
pub async fn http_origin(
    response_bytes: usize,
    tls: Option<Arc<rustls::ServerConfig>>,
) -> io::Result<Stub> {
    let canned = Arc::new(Canned::new(response_bytes));
    let acceptor = tls.map(TlsAcceptor::from);
    serve(move |stream| {
        let canned = Arc::clone(&canned);
        let acceptor = acceptor.clone();
        async move {
            match acceptor {
                Some(acceptor) => {
                    if let Ok(tls) = acceptor.accept(stream).await {
                        http_connection(tls, &canned).await;
                    }
                }
                None => http_connection(stream, &canned).await,
            }
        }
    })
    .await
}

async fn http_connection<S: AsyncRead + AsyncWrite + Unpin>(stream: S, canned: &Canned) {
    let mut conn = Conn::new(stream);
    loop {
        let Ok(head) = conn.read_head().await else {
            return;
        };
        let (length, close) = request_framing(&head);
        if conn.skip(length).await.is_err() {
            return;
        }
        let reply = if close {
            &canned.close
        } else {
            &canned.keep_alive
        };
        if conn.write_all(reply).await.is_err() {
            return;
        }
        if close {
            let (mut stream, _) = conn.into_parts();
            let _ = stream.shutdown().await;
            return;
        }
    }
}

/// `Content-Length` and whether the request asks to close.
fn request_framing(head: &[u8]) -> (usize, bool) {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut request = httparse::Request::new(&mut headers);
    if request.parse(head).is_err() {
        return (0, true);
    }
    let mut length = 0;
    let mut close = false;
    for h in request.headers.iter() {
        let value = std::str::from_utf8(h.value).unwrap_or("");
        if h.name.eq_ignore_ascii_case("content-length") {
            length = value.trim().parse().unwrap_or(0);
        } else if h.name.eq_ignore_ascii_case("connection") && value.eq_ignore_ascii_case("close") {
            close = true;
        }
    }
    (length, close)
}

/// Where [`provider_proxy`] sends a tunnel, by the port the client asked for.
#[derive(Debug, Clone, Copy)]
pub struct Routes {
    /// Every port without a route of its own.
    pub default: SocketAddr,
    /// Tunnels to port 80, when they go elsewhere (a plain-HTTP origin).
    pub port_80: Option<SocketAddr>,
}

impl Routes {
    pub fn only(target: SocketAddr) -> Self {
        Self {
            default: target,
            port_80: None,
        }
    }

    fn for_port(&self, port: Option<u16>) -> SocketAddr {
        match (port, self.port_80) {
            (Some(80), Some(addr)) => addr,
            _ => self.default,
        }
    }
}

/// An HTTP proxy that accepts one login (`user:password`) and tunnels every
/// `CONNECT` to a stub target chosen by `routes`, whatever host the client
/// named. This is what a provider's upstream looks like to the pool gateway. A
/// request that is not a `CONNECT` is answered `405`, a wrong login `407`.
pub async fn provider_proxy(login: &str, routes: Routes) -> io::Result<Stub> {
    let expected = format!("Basic {}", STANDARD.encode(login));
    serve(move |stream| {
        let expected = expected.clone();
        async move {
            let mut conn = Conn::new(stream);
            let Ok(head) = conn.read_head().await else {
                return;
            };
            let mut headers = [httparse::EMPTY_HEADER; 64];
            let mut request = httparse::Request::new(&mut headers);
            if request.parse(&head).is_err() {
                return;
            }
            let authorized = request.headers.iter().any(|h| {
                h.name.eq_ignore_ascii_case("proxy-authorization")
                    && std::str::from_utf8(h.value).is_ok_and(|v| v.trim() == expected)
            });
            let is_connect = request.method == Some("CONNECT");
            let port = request
                .path
                .and_then(|p| p.rsplit_once(':'))
                .and_then(|(_, port)| port.parse::<u16>().ok());
            let target = routes.for_port(port);
            let (mut client, pending) = conn.into_parts();
            if !authorized {
                let _ = client
                    .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
                return;
            }
            if !is_connect {
                let _ = client
                    .write_all(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
                return;
            }
            let Ok(mut upstream) = TcpStream::connect(target).await else {
                let _ = client
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
                return;
            };
            let _ = upstream.set_nodelay(true);
            if client
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .is_err()
                || (!pending.is_empty() && upstream.write_all(&pending).await.is_err())
            {
                return;
            }
            let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
        }
    })
    .await
}

/// A plain CONNECT proxy with no login that tunnels to the host and port the
/// client names. It stands in for a session proxy in passthrough mode, where
/// the proxy only relays bytes.
pub async fn connect_proxy() -> io::Result<Stub> {
    serve(|stream| async move {
        let mut conn = Conn::new(stream);
        let Ok(head) = conn.read_head().await else {
            return;
        };
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut request = httparse::Request::new(&mut headers);
        if request.parse(&head).is_err() {
            return;
        }
        let path = request.path.unwrap_or("").to_owned();
        let (mut client, pending) = conn.into_parts();
        let upstream = match request.method {
            Some("CONNECT") => TcpStream::connect(path.as_str()).await.ok(),
            _ => None,
        };
        let Some(mut upstream) = upstream else {
            let _ = client
                .write_all(
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
            return;
        };
        let _ = upstream.set_nodelay(true);
        if client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .is_err()
            || (!pending.is_empty() && upstream.write_all(&pending).await.is_err())
        {
            return;
        }
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn the_echo_returns_what_it_was_sent() {
        let stub = echo().await.expect("echo");
        let mut s = TcpStream::connect(stub.addr).await.expect("connect");
        s.write_all(b"hello").await.expect("write");
        let mut got = [0u8; 5];
        s.read_exact(&mut got).await.expect("read");
        assert_eq!(&got, b"hello");
        assert_eq!(stub.accepted(), 1);
    }

    #[tokio::test]
    async fn the_origin_keeps_the_connection_alive_and_closes_on_request() {
        let stub = http_origin(10, None).await.expect("origin");
        let mut conn = Conn::new(TcpStream::connect(stub.addr).await.expect("connect"));
        // two requests on one connection, the second with a body
        assert_eq!(conn.post("x", b"", false).await.expect("first"), 10);
        assert_eq!(conn.post("x", b"abcdef", false).await.expect("second"), 16);
        // a close request: the stub ends the connection after the answer
        assert_eq!(conn.post("x", b"z", true).await.expect("third"), 11);
        let e = conn.read_head().await.expect_err("closed");
        assert_eq!(e.class, "read_eof");
        assert_eq!(stub.accepted(), 1);
    }

    #[tokio::test]
    async fn the_provider_proxy_checks_the_login_and_tunnels_to_its_target() {
        let target = echo().await.expect("echo");
        let provider = provider_proxy("user:pass", Routes::only(target.addr))
            .await
            .expect("provider");

        let connect = |auth: Option<&str>| {
            let auth =
                auth.map(|a| format!("Proxy-Authorization: Basic {}\r\n", STANDARD.encode(a)));
            format!(
                "CONNECT 8.8.8.8:443 HTTP/1.1\r\nHost: 8.8.8.8:443\r\n{}\r\n",
                auth.unwrap_or_default()
            )
        };

        let mut s = TcpStream::connect(provider.addr).await.expect("connect");
        s.write_all(connect(Some("user:pass")).as_bytes())
            .await
            .expect("write");
        let mut conn = Conn::new(s);
        let head = conn.read_head().await.expect("head");
        assert!(
            head.starts_with(b"HTTP/1.1 200"),
            "{}",
            String::from_utf8_lossy(&head)
        );
        let (mut s, _) = conn.into_parts();
        s.write_all(b"ping").await.expect("write");
        let mut got = [0u8; 4];
        s.read_exact(&mut got).await.expect("read");
        assert_eq!(&got, b"ping");

        for auth in [None, Some("user:wrong")] {
            let mut s = TcpStream::connect(provider.addr).await.expect("connect");
            s.write_all(connect(auth).as_bytes()).await.expect("write");
            let mut conn = Conn::new(s);
            let head = conn.read_head().await.expect("head");
            assert!(
                head.starts_with(b"HTTP/1.1 407"),
                "{}",
                String::from_utf8_lossy(&head)
            );
        }
    }
}
