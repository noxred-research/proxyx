//! A single client connection: owns a `TcpStream`, performs the handshake on
//! connect, and frames requests/responses through `limiter-proto`. Reusable
//! request/response byte buffers avoid per-call allocation. Uses std blocking
//! I/O; Rust ignores SIGPIPE by default so a broken pipe surfaces as an error.

use crate::resilience::{set_keepalive, Health};
use limiter_proto::{
    decode_consume_results, decode_create_results, decode_drain_results, decode_snapshot_results,
    encode_consume_reqs, encode_create_reqs, encode_drain_reqs, encode_snapshot_reqs, parse_frame,
    ConsumeReq, ConsumeResult, CreateReq, CreateResult, DrainResult, Frame, SnapshotResult, MAGIC,
    MAX_FRAME_BYTES, OP_CONSUME, OP_CREATE, OP_DRAIN, OP_SNAPSHOT, VERSION,
};
use limiter_proto::{decode_ping_results, encode_ping_reqs, PingResult, OP_PING};
use socket2::SockRef;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;

pub struct Connection {
    stream: TcpStream,
    req: Vec<u8>,
    resp: Vec<u8>,
    /// Set for connections the pooled client opens: every exchange reports its
    /// outcome to the circuit breaker.
    health: Option<Arc<Health>>,
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

impl Connection {
    /// Connect without timeouts or a breaker: blocks as long as the OS lets it.
    /// The pooled [`crate::Client`] uses [`Connection::connect_with`] instead.
    pub fn connect(addr: &str) -> io::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        Self::handshake(stream, None)
    }

    /// Connect under the client's [`crate::ResilienceConfig`]: bounded connect
    /// and handshake, per-exchange socket timeouts, TCP keepalive.
    pub(crate) fn connect_with(addr: &str, health: Arc<Health>) -> io::Result<Self> {
        let config = health.config;
        let mut last = None;
        let mut stream = None;
        for candidate in addr.to_socket_addrs()? {
            match TcpStream::connect_timeout(&candidate, config.connect_timeout) {
                Ok(s) => {
                    stream = Some(s);
                    break;
                }
                Err(e) => last = Some(e),
            }
        }
        let stream = stream.ok_or_else(|| {
            last.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address resolved"))
        })?;
        // The handshake shares the connect budget; exchanges get the I/O budget.
        stream.set_read_timeout(Some(config.connect_timeout))?;
        stream.set_write_timeout(Some(config.connect_timeout))?;
        if let Some(idle) = config.keepalive {
            set_keepalive(SockRef::from(&stream), idle)?;
        }
        let conn = Self::handshake(stream, Some(Arc::clone(&health)))?;
        conn.stream.set_read_timeout(Some(config.io_timeout))?;
        conn.stream.set_write_timeout(Some(config.io_timeout))?;
        Ok(conn)
    }

    fn handshake(mut stream: TcpStream, health: Option<Arc<Health>>) -> io::Result<Self> {
        stream.set_nodelay(true)?;
        let mut hello = [0u8; 5];
        hello[..4].copy_from_slice(&MAGIC);
        hello[4] = VERSION;
        stream.write_all(&hello)?;
        let mut reply = [0u8; 1];
        stream.read_exact(&mut reply)?;
        if reply[0] != VERSION {
            return Err(invalid("server rejected handshake"));
        }
        Ok(Connection {
            stream,
            req: Vec::with_capacity(4096),
            resp: Vec::with_capacity(4096),
            health,
        })
    }

    /// Report an exchange outcome to the breaker, if this connection has one.
    fn observe<T>(&self, result: io::Result<T>) -> io::Result<T> {
        if let Some(health) = &self.health {
            health.observe(&result);
        }
        result
    }

    /// Read exactly one response frame into `self.resp` and return it parsed.
    fn read_frame(&mut self) -> io::Result<Frame<'_>> {
        self.resp.resize(4, 0);
        self.stream.read_exact(&mut self.resp[..4])?;
        let frame_len =
            u32::from_be_bytes([self.resp[0], self.resp[1], self.resp[2], self.resp[3]]) as usize;
        if !(5..=MAX_FRAME_BYTES).contains(&frame_len) {
            return Err(invalid("bad response frame length"));
        }
        let total = 4 + frame_len;
        self.resp.resize(total, 0);
        self.stream.read_exact(&mut self.resp[4..total])?;
        parse_frame(&self.resp)?.ok_or_else(|| invalid("incomplete response frame"))
    }

    pub fn create(&mut self, reqs: &[CreateReq<'_>]) -> io::Result<Vec<CreateResult>> {
        let result = self.create_inner(reqs);
        self.observe(result)
    }

    fn create_inner(&mut self, reqs: &[CreateReq<'_>]) -> io::Result<Vec<CreateResult>> {
        self.req.clear();
        encode_create_reqs(&mut self.req, reqs);
        self.stream.write_all(&self.req)?;
        let frame = self.read_frame()?;
        if frame.op != OP_CREATE || frame.count != reqs.len() {
            return Err(invalid("response op/count mismatch"));
        }
        Ok(decode_create_results(frame.payload, frame.count)?)
    }

    pub fn snapshot(&mut self, handles: &[u64]) -> io::Result<Vec<SnapshotResult>> {
        let result = self.snapshot_inner(handles);
        self.observe(result)
    }

    fn snapshot_inner(&mut self, handles: &[u64]) -> io::Result<Vec<SnapshotResult>> {
        self.req.clear();
        encode_snapshot_reqs(&mut self.req, handles);
        self.stream.write_all(&self.req)?;
        let frame = self.read_frame()?;
        if frame.op != OP_SNAPSHOT || frame.count != handles.len() {
            return Err(invalid("response op/count mismatch"));
        }
        Ok(decode_snapshot_results(frame.payload, frame.count)?)
    }

    pub fn consume(&mut self, reqs: &[ConsumeReq]) -> io::Result<Vec<ConsumeResult>> {
        let result = self
            .send_consume(reqs)
            .and_then(|()| self.recv_consume(reqs.len()));
        self.observe(result)
    }

    /// Write one CONSUME frame without reading the response. Pair with
    /// `recv_consume` to let the caller control the in-flight (pipeline) window.
    pub fn send_consume(&mut self, reqs: &[ConsumeReq]) -> io::Result<()> {
        self.req.clear();
        encode_consume_reqs(&mut self.req, reqs);
        self.stream.write_all(&self.req)
    }

    /// Read one CONSUME response frame for a batch of `count` records.
    pub fn recv_consume(&mut self, count: usize) -> io::Result<Vec<ConsumeResult>> {
        let frame = self.read_frame()?;
        if frame.op != OP_CONSUME || frame.count != count {
            return Err(invalid("response op/count mismatch"));
        }
        Ok(decode_consume_results(frame.payload, frame.count)?)
    }

    /// Drain (debit up to `amount`, never denying) for a batch of records.
    pub fn drain(&mut self, reqs: &[ConsumeReq]) -> io::Result<Vec<DrainResult>> {
        let result = self.drain_inner(reqs);
        self.observe(result)
    }

    fn drain_inner(&mut self, reqs: &[ConsumeReq]) -> io::Result<Vec<DrainResult>> {
        self.req.clear();
        encode_drain_reqs(&mut self.req, reqs);
        self.stream.write_all(&self.req)?;
        let frame = self.read_frame()?;
        if frame.op != OP_DRAIN || frame.count != reqs.len() {
            return Err(invalid("response op/count mismatch"));
        }
        Ok(decode_drain_results(frame.payload, frame.count)?)
    }

    /// Liveness probe: send `token`, expect it echoed with the server's uptime.
    pub fn ping(&mut self, token: u64) -> io::Result<PingResult> {
        let result = self.ping_inner(token);
        self.observe(result)
    }

    fn ping_inner(&mut self, token: u64) -> io::Result<PingResult> {
        self.req.clear();
        encode_ping_reqs(&mut self.req, &[token]);
        self.stream.write_all(&self.req)?;
        let frame = self.read_frame()?;
        if frame.op != OP_PING || frame.count != 1 {
            return Err(invalid("response op/count mismatch"));
        }
        let result = decode_ping_results(frame.payload, frame.count)?[0];
        if result.token != token {
            return Err(invalid("ping token mismatch"));
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resilience::ResilienceConfig;
    use std::net::TcpListener;
    use std::time::Duration;

    #[test]
    fn pooled_connections_carry_keepalive_and_io_timeouts() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut hello = [0u8; 5];
            stream.read_exact(&mut hello).unwrap();
            stream.write_all(&[VERSION]).unwrap();
            std::thread::sleep(Duration::from_millis(500));
        });
        let health = Arc::new(Health::new(ResilienceConfig {
            keepalive: Some(Duration::from_secs(30)),
            io_timeout: Duration::from_millis(750),
            ..ResilienceConfig::default()
        }));
        let conn = Connection::connect_with(&addr.to_string(), health).unwrap();
        let sock = SockRef::from(&conn.stream);
        assert!(sock.keepalive().unwrap());
        assert_eq!(sock.tcp_keepalive_time().unwrap(), Duration::from_secs(30));
        assert_eq!(
            sock.tcp_keepalive_interval().unwrap(),
            Duration::from_secs(5)
        );
        assert_eq!(sock.tcp_keepalive_retries().unwrap(), 3);
        assert_eq!(
            conn.stream.read_timeout().unwrap(),
            Some(Duration::from_millis(750))
        );
        assert_eq!(
            conn.stream.write_timeout().unwrap(),
            Some(Duration::from_millis(750))
        );
    }

    #[test]
    fn keepalive_can_be_left_off() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut hello = [0u8; 5];
            stream.read_exact(&mut hello).unwrap();
            stream.write_all(&[VERSION]).unwrap();
            std::thread::sleep(Duration::from_millis(300));
        });
        let health = Arc::new(Health::new(ResilienceConfig {
            keepalive: None,
            ..ResilienceConfig::default()
        }));
        let conn = Connection::connect_with(&addr.to_string(), health).unwrap();
        assert!(!SockRef::from(&conn.stream).keepalive().unwrap());
    }
}
