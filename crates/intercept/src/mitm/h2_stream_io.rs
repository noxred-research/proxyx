//! Adapts an HTTP/2 bidirectional stream into [`AsyncRead`] + [`AsyncWrite`].
//!
//! When the proxy issues an RFC 8441 Extended CONNECT (`:protocol = websocket`),
//! h2 gives us a [`h2::client::SendStream`] for writing and a [`h2::RecvStream`]
//! for reading.  [`H2StreamIo`] wraps both so they can be handed directly to
//! `proxy_websocket`, which is generic over any `AsyncRead + AsyncWrite`.
//!
//! ## Flow control
//!
//! Read side: after consuming bytes from a DATA frame we release the h2
//! flow-control window so the remote end is not stalled.
//!
//! Write side: we call `reserve_capacity` before every write, then wait for
//! `poll_capacity` to grant the window; only then do we call `send_data`.  h2
//! grants capacity in chunks, so partial writes are normal — the tokio I/O
//! layer will call us again with the remaining buffer.
//!
//! Flush: h2 manages its own framing; there is nothing to flush.
//!
//! Shutdown: we send an empty DATA frame with `end_of_stream = true` to
//! half-close our send side, then return immediately.  Any h2 error at that
//! point means the stream is already done, which is fine.

use bytes::{Bytes, BytesMut};
use h2::{RecvStream, SendStream};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Bidirectional I/O adapter over an h2 Extended CONNECT stream.
pub struct H2StreamIo {
    send: SendStream<Bytes>,
    recv: RecvStream,
    /// Bytes received from a DATA frame but not yet consumed by the reader.
    read_buf: BytesMut,
    /// True once `poll_data` has returned `None` (remote END_STREAM).
    recv_eof: bool,
}

impl H2StreamIo {
    pub fn new(send: SendStream<Bytes>, recv: RecvStream) -> Self {
        Self {
            send,
            recv,
            read_buf: BytesMut::new(),
            recv_eof: false,
        }
    }
}

fn h2_to_io(e: h2::Error) -> io::Error {
    io::Error::other(e)
}

impl AsyncRead for H2StreamIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Drain the internal buffer before going to the network.
        if !self.read_buf.is_empty() {
            let to_copy = self.read_buf.len().min(buf.remaining());
            buf.put_slice(&self.read_buf[..to_copy]);
            let _ = self.read_buf.split_to(to_copy);
            return Poll::Ready(Ok(()));
        }

        if self.recv_eof {
            return Poll::Ready(Ok(())); // EOF — signal to caller
        }

        match self.recv.poll_data(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                self.recv_eof = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(h2_to_io(e))),
            Poll::Ready(Some(Ok(data))) => {
                // Release flow-control capacity *before* consuming the frame bytes
                // so the remote end can continue sending.
                let _ = self.recv.flow_control().release_capacity(data.len());

                let to_copy = data.len().min(buf.remaining());
                buf.put_slice(&data[..to_copy]);
                if data.len() > to_copy {
                    self.read_buf.extend_from_slice(&data[to_copy..]);
                }
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl AsyncWrite for H2StreamIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Ask h2 to grant us window for the full buffer.
        // poll_capacity will return Ready only when at least some capacity
        // has been granted.
        self.send.reserve_capacity(buf.len());

        match self.send.poll_capacity(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                // The send stream was reset by the remote peer.
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "h2 send stream closed by peer",
                )))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(h2_to_io(e))),
            Poll::Ready(Some(Ok(capacity))) => {
                // h2 may grant less than we asked — partial writes are expected.
                let n = capacity.min(buf.len());
                let data = Bytes::copy_from_slice(&buf[..n]);
                self.send.send_data(data, false).map_err(h2_to_io)?;
                Poll::Ready(Ok(n))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // h2 manages its own frame boundaries; nothing to flush.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Best-effort half-close: empty DATA frame with END_STREAM.
        // If the stream is already reset/closed, discard the error — we are
        // done either way.
        let _ = self.send.send_data(Bytes::new(), true);
        Poll::Ready(Ok(()))
    }
}
