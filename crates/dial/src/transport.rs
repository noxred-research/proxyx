//! Plain TCP and recursively layered TLS proxy transports.

use std::fmt;
use std::io::{self, IoSlice};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

/// An upstream tunnel over TCP or TLS, including TLS inside another tunnel.
///
/// Implements Tokio's asynchronous read/write traits. Plain TCP stays inline.
/// TLS layers and custom transports allocate. The underlying socket remains
/// available through [`Self::socket`], never for reading or writing TLS data.
pub struct ProxyStream {
    inner: Transport,
}

trait IoStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<S: AsyncRead + AsyncWrite + Send + Unpin> IoStream for S {}

enum Transport {
    Tcp(TcpStream),
    Tls(Box<TlsStream<ProxyStream>>),
    Custom(Box<dyn IoStream>),
}

impl fmt::Debug for ProxyStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyStream").finish_non_exhaustive()
    }
}

impl From<TcpStream> for ProxyStream {
    fn from(stream: TcpStream) -> Self {
        Self {
            inner: Transport::Tcp(stream),
        }
    }
}

impl ProxyStream {
    /// Wrap an arbitrary established transport or a connection-lifetime guard.
    /// Unlike conversion from TCP, this allocates one box.
    pub fn new<S: AsyncRead + AsyncWrite + Send + Unpin + 'static>(stream: S) -> Self {
        Self {
            inner: Transport::Custom(Box::new(stream)),
        }
    }

    pub(crate) fn tls(stream: TlsStream<Self>) -> Self {
        Self {
            inner: Transport::Tls(Box::new(stream)),
        }
    }

    /// The TCP socket under all TLS layers, or `None` for a custom transport.
    /// Do not bypass TLS for I/O.
    pub fn socket(&self) -> Option<&TcpStream> {
        match &self.inner {
            Transport::Tcp(stream) => Some(stream),
            Transport::Tls(stream) => stream.get_ref().0.socket(),
            Transport::Custom(_) => None,
        }
    }

    /// Local address of the underlying TCP connection.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket().ok_or_else(no_socket)?.local_addr()
    }

    /// Peer address of the underlying TCP connection.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.socket().ok_or_else(no_socket)?.peer_addr()
    }
}

fn no_socket() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "custom proxy transport has no TCP socket",
    )
}

impl AsyncRead for ProxyStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut self.get_mut().inner {
            Transport::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            Transport::Tls(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
            Transport::Custom(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ProxyStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.get_mut().inner {
            Transport::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            Transport::Tls(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
            Transport::Custom(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().inner {
            Transport::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            Transport::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
            Transport::Custom(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().inner {
            Transport::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            Transport::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
            Transport::Custom(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match &self.inner {
            Transport::Tcp(stream) => stream.is_write_vectored(),
            Transport::Tls(stream) => stream.is_write_vectored(),
            Transport::Custom(stream) => stream.is_write_vectored(),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match &mut self.get_mut().inner {
            Transport::Tcp(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
            Transport::Tls(stream) => Pin::new(stream.as_mut()).poll_write_vectored(cx, bufs),
            Transport::Custom(stream) => Pin::new(stream.as_mut()).poll_write_vectored(cx, bufs),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::{Duration, timeout};

    #[tokio::test]
    async fn custom_transport_forwards_vectored_io_flush_and_shutdown() {
        let (client, mut peer) = tokio::io::duplex(64);
        let mut stream = ProxyStream::new(client);
        assert!(stream.socket().is_none());
        assert_eq!(
            stream.local_addr().expect_err("no TCP metadata").kind(),
            io::ErrorKind::Unsupported,
        );
        timeout(Duration::from_secs(5), async {
            let written = stream
                .write_vectored(&[IoSlice::new(b"abc"), IoSlice::new(b"def")])
                .await
                .expect("vectored write");
            stream.flush().await.expect("flush");
            let mut bytes = [0; 6];
            peer.read_exact(&mut bytes[..written])
                .await
                .expect("peer read");
            assert_eq!(&bytes[..written], &b"abcdef"[..written]);
            peer.write_all(b"reply").await.expect("peer write");
            let mut reply = [0; 5];
            stream.read_exact(&mut reply).await.expect("wrapped read");
            assert_eq!(&reply, b"reply");
            stream.shutdown().await.expect("shutdown");
            assert_eq!(peer.read(&mut bytes).await.expect("EOF"), 0);
        })
        .await
        .expect("transport deadline");
    }
}
