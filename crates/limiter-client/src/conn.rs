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
use std::time::Instant;

pub struct Connection {
    stream: TcpStream,
    req: Vec<u8>,
    resp: Vec<u8>,
    /// Set for connections the pooled client opens: every exchange reports its
    /// outcome to the circuit breaker.
    health: Option<Arc<Health>>,
    pub(crate) last_used: Instant,
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

impl Connection {
    /// Connect without timeouts or a breaker: blocks as long as the OS lets it.
    /// The pooled [`crate::Client`] uses [`Connection::connect_with`] instead.
    pub fn connect(addr: &str) -> io::Result<Self> {
        let mut stream = TcpStream::connect(addr)?;
        Self::handshake(&mut stream)?;
        Self::new(stream, None)
    }

    /// Connect under the client's [`crate::ResilienceConfig`]: bounded connect
    /// and handshake, per-exchange socket timeouts, TCP keepalive.
    pub(crate) fn connect_with(addr: &str, health: Arc<Health>) -> io::Result<Self> {
        let stream = Self::connect_stream(addr, &health)?;
        Self::new(stream, Some(health))
    }

    fn connect_stream(addr: impl ToSocketAddrs, health: &Health) -> io::Result<TcpStream> {
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
        let mut stream = stream.ok_or_else(|| {
            last.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address resolved"))
        })?;
        // The handshake shares the connect budget; exchanges get the I/O budget.
        stream.set_read_timeout(Some(config.connect_timeout))?;
        stream.set_write_timeout(Some(config.connect_timeout))?;
        if let Some(idle) = config.keepalive {
            set_keepalive(SockRef::from(&stream), idle)?;
        }
        Self::handshake(&mut stream)?;
        stream.set_read_timeout(Some(config.io_timeout))?;
        stream.set_write_timeout(Some(config.io_timeout))?;
        Ok(stream)
    }

    fn handshake(stream: &mut TcpStream) -> io::Result<()> {
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
        Ok(())
    }

    fn new(stream: TcpStream, health: Option<Arc<Health>>) -> io::Result<Self> {
        Ok(Connection {
            stream,
            req: Vec::with_capacity(4096),
            resp: Vec::with_capacity(4096),
            health,
            last_used: Instant::now(),
        })
    }

    /// Report an exchange outcome to the breaker, if this connection has one.
    fn observe<T>(&self, result: io::Result<T>) -> io::Result<T> {
        if let Some(health) = &self.health {
            health.observe(&result);
        }
        result
    }

    /// Read one response frame.
    fn read_frame_bytes(&mut self) -> io::Result<()> {
        self.resp.resize(4, 0);
        self.stream.read_exact(&mut self.resp[..4])?;
        let frame_len =
            u32::from_be_bytes([self.resp[0], self.resp[1], self.resp[2], self.resp[3]]) as usize;
        if !(5..=MAX_FRAME_BYTES).contains(&frame_len) {
            return Err(invalid("bad response frame length"));
        }
        let total = 4 + frame_len;
        self.resp.resize(total, 0);
        self.stream.read_exact(&mut self.resp[4..total])
    }

    /// Pipeline reads never reconnect or replay pending requests.
    fn read_frame(&mut self) -> io::Result<Frame<'_>> {
        self.read_frame_bytes()?;
        parse_frame(&self.resp)?.ok_or_else(|| invalid("incomplete response frame"))
    }

    /// Never replay an exchange: a lost response may follow an applied mutation.
    fn exchange(&mut self) -> io::Result<Frame<'_>> {
        self.stream.write_all(&self.req)?;
        self.read_frame_bytes()?;
        parse_frame(&self.resp)?.ok_or_else(|| invalid("incomplete response frame"))
    }

    pub fn create(&mut self, reqs: &[CreateReq<'_>]) -> io::Result<Vec<CreateResult>> {
        let result = self.create_inner(reqs);
        self.observe(result)
    }

    fn create_inner(&mut self, reqs: &[CreateReq<'_>]) -> io::Result<Vec<CreateResult>> {
        self.req.clear();
        encode_create_reqs(&mut self.req, reqs);
        let frame = self.exchange()?;
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
        let frame = self.exchange()?;
        if frame.op != OP_SNAPSHOT || frame.count != handles.len() {
            return Err(invalid("response op/count mismatch"));
        }
        Ok(decode_snapshot_results(frame.payload, frame.count)?)
    }

    pub fn consume(&mut self, reqs: &[ConsumeReq]) -> io::Result<Vec<ConsumeResult>> {
        let result = self.consume_inner(reqs);
        self.observe(result)
    }

    fn consume_inner(&mut self, reqs: &[ConsumeReq]) -> io::Result<Vec<ConsumeResult>> {
        self.req.clear();
        encode_consume_reqs(&mut self.req, reqs);
        let frame = self.exchange()?;
        if frame.op != OP_CONSUME || frame.count != reqs.len() {
            return Err(invalid("response op/count mismatch"));
        }
        Ok(decode_consume_results(frame.payload, frame.count)?)
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
        let frame = self.exchange()?;
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
        let frame = self.exchange()?;
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
        assert_eq!(conn.stream.peer_addr().unwrap(), addr);
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

    fn assert_ping_failure(response: &'static [u8], warmup: bool, expected: io::ErrorKind) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server_listener = listener.try_clone().unwrap();
        server_listener.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            let (mut stream, _) = loop {
                match server_listener.accept() {
                    Ok(accepted) => break accepted,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "missing expected connection");
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("accept failed: {error}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let mut hello = [0; 5];
            stream.read_exact(&mut hello).unwrap();
            stream.write_all(&[VERSION]).unwrap();
            for index in 0..=usize::from(warmup) {
                let mut header = [0; 4];
                stream.read_exact(&mut header).unwrap();
                let mut request = vec![0; u32::from_be_bytes(header) as usize];
                stream.read_exact(&mut request).unwrap();
                if warmup && index == 0 {
                    let mut bytes = header.to_vec();
                    bytes.extend_from_slice(&request);
                    let frame = limiter_proto::parse_frame(&bytes).unwrap().unwrap();
                    let token =
                        limiter_proto::decode_ping_reqs(frame.payload, frame.count).unwrap()[0];
                    let mut reply = Vec::new();
                    limiter_proto::write_frame_header(&mut reply, OP_PING, 1, 16);
                    limiter_proto::push_ping_result(
                        &mut reply,
                        &PingResult {
                            token,
                            uptime_ns: 1,
                        },
                    );
                    stream.write_all(&reply).unwrap();
                } else {
                    stream.write_all(response).unwrap();
                }
            }
        });
        let client = crate::Client::connect_with(
            addr.to_string(),
            crate::ClientConfig::default(),
            ResilienceConfig {
                connect_timeout: Duration::from_millis(500),
                io_timeout: Duration::from_millis(500),
                ..ResilienceConfig::default()
            },
        );
        if warmup {
            client.ping().unwrap();
        }
        let error = client.ping().unwrap_err();
        server.join().unwrap();
        assert_eq!(error.kind(), expected);
        assert_eq!(client.stats().transport_errors, 1);
        listener.set_nonblocking(true).unwrap();
        assert!(matches!(
            listener.accept(),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock
        ));
    }

    #[test]
    fn fresh_socket_disconnect_is_not_replayed() {
        assert_ping_failure(&[], false, io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn reused_socket_disconnect_is_not_replayed() {
        assert_ping_failure(&[], true, io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn partial_response_header_is_not_replayed() {
        assert_ping_failure(&[0], true, io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn partial_response_payload_is_not_replayed() {
        assert_ping_failure(&[0, 0, 0, 5, OP_PING], true, io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn invalid_response_frame_is_not_replayed() {
        assert_ping_failure(&[0, 0, 0, 0], true, io::ErrorKind::InvalidData);
    }
}
