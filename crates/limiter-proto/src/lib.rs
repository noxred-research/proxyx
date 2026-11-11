//! Limiter wire protocol: the single source of truth shared by server, client,
//! and bench. Pure data + codec, no I/O. All integers are big-endian.
//!
//! Handshake (once per connection, after TCP connect):
//!   client -> server: `MAGIC(4) ++ VERSION(1)`
//!   server -> client: `VERSION(1)` on accept, or `REJECT(1)` then close.
//!
//! Frame (both directions): `[u32 frame_len][u8 op][u32 count][payload]`.
//! `frame_len` counts everything after itself (`1 + 4 + payload_len`). Responses
//! echo `op` and `count`; they arrive in request order on a connection.

use std::fmt;

pub const MAGIC: [u8; 4] = *b"GNDF";
pub const VERSION: u8 = 1;
/// Server's handshake reply byte on rejection (bad magic / version mismatch).
pub const REJECT: u8 = 0xFF;

pub const OP_CREATE: u8 = 1;
pub const OP_CONSUME: u8 = 2;
pub const OP_SNAPSHOT: u8 = 3;
pub const OP_DRAIN: u8 = 4;
/// Liveness probe: one record, an opaque 8-byte token the server echoes back
/// with its uptime. Added after version 1 shipped; a server that predates it
/// drops the connection on the unknown op.
pub const OP_PING: u8 = 5;

pub const ST_OK: u8 = 0;
pub const ST_STALE: u8 = 1;
pub const ST_NOTFOUND: u8 = 2;
pub const ST_FULL: u8 = 3;
pub const ST_BADREQ: u8 = 4;

pub const MAX_FRAME_BYTES: usize = 1 << 24; // 16 MiB
pub const MAX_BATCH: usize = 4096;
pub const MAX_KEY_LEN: usize = 1024;

/// Bytes in the frame header that follow `frame_len`: `op(1) + count(4)`.
const HEADER_TAIL_BYTES: usize = 5;
const CONSUME_REQ_BYTES: usize = 16; // handle(8) + amount(8)
const SNAPSHOT_REQ_BYTES: usize = 8; // handle(8)
const CREATE_REQ_FIXED_BYTES: usize = 28; // capacity(8) + refill(8) + ttl(8) + key_len(4)
pub const CONSUME_RESULT_BYTES: usize = 18; // status(1) + allowed(1) + remaining(8) + retry(8)
pub const SNAPSHOT_RESULT_BYTES: usize = 33; // status(1) + capacity(8) + refill(8) + tokens(8) + last(8)
pub const CREATE_RESULT_BYTES: usize = 9; // status(1) + handle(8)
pub const DRAIN_RESULT_BYTES: usize = 9; // status(1) + drained(8)
const PING_REQ_BYTES: usize = 8; // token(8)
pub const PING_RESULT_BYTES: usize = 16; // token(8) + uptime_ns(8)

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtoError {
    /// `frame_len` exceeds `MAX_FRAME_BYTES`.
    FrameTooLarge,
    /// `count == 0` or `count > MAX_BATCH`.
    BadCount,
    /// A CREATE record declares `key_len > MAX_KEY_LEN`.
    KeyTooLong,
    /// Payload truncated or not a whole number of records.
    Malformed,
}

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            ProtoError::FrameTooLarge => "frame exceeds MAX_FRAME_BYTES",
            ProtoError::BadCount => "frame count out of range",
            ProtoError::KeyTooLong => "create key exceeds MAX_KEY_LEN",
            ProtoError::Malformed => "malformed frame payload",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for ProtoError {}

impl From<ProtoError> for std::io::Error {
    fn from(e: ProtoError) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e)
    }
}

// --- typed records ---

/// A CREATE request record. `key` borrows the caller's buffer on decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateReq<'a> {
    pub capacity: u64,
    pub refill_rate: u64,
    pub ttl_ns: u64,
    pub key: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsumeReq {
    pub handle: u64,
    pub amount: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateResult {
    pub status: u8,
    pub handle: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrainResult {
    pub status: u8,
    pub drained: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsumeResult {
    pub status: u8,
    pub allowed: bool,
    pub remaining: u64,
    pub retry_after_ns: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PingResult {
    /// The request's token, echoed.
    pub token: u64,
    /// Server uptime in nanoseconds on its own monotonic clock.
    pub uptime_ns: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotResult {
    pub status: u8,
    pub capacity: u64,
    pub refill_rate: u64,
    pub tokens: u64,
    pub last_refill_ns: u64,
}

// --- little big-endian helpers (callers validate length first) ---

#[inline]
fn be_u32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

#[inline]
fn be_u64(b: &[u8]) -> u64 {
    u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

// --- frame parsing ---

/// A parsed frame borrowing the caller's buffer. `total_len` is the number of
/// bytes the frame occupies (header + payload), to advance the read cursor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    pub op: u8,
    pub count: usize,
    pub payload: &'a [u8],
    pub total_len: usize,
}

/// Parse one frame from the front of `buf`. Returns `Ok(None)` when `buf` does
/// not yet hold a complete frame (caller reads more). `Err` on malformed bytes;
/// the caller closes the connection.
pub fn parse_frame(buf: &[u8]) -> Result<Option<Frame<'_>>, ProtoError> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let frame_len = be_u32(&buf[0..4]) as usize;
    if frame_len > MAX_FRAME_BYTES {
        return Err(ProtoError::FrameTooLarge);
    }
    if frame_len < HEADER_TAIL_BYTES {
        return Err(ProtoError::Malformed);
    }
    let total_len = 4 + frame_len;
    if buf.len() < total_len {
        return Ok(None);
    }
    let op = buf[4];
    let count = be_u32(&buf[5..9]) as usize;
    if count == 0 || count > MAX_BATCH {
        return Err(ProtoError::BadCount);
    }
    let payload = &buf[9..total_len];
    Ok(Some(Frame {
        op,
        count,
        payload,
        total_len,
    }))
}

// --- request decoding (server side) ---

/// Zero-alloc iterator over CONSUME request records.
pub struct ConsumeReqs<'a> {
    payload: &'a [u8],
    i: usize,
    count: usize,
}

impl<'a> Iterator for ConsumeReqs<'a> {
    type Item = ConsumeReq;
    fn next(&mut self) -> Option<ConsumeReq> {
        if self.i >= self.count {
            return None;
        }
        let o = self.i * CONSUME_REQ_BYTES;
        self.i += 1;
        Some(ConsumeReq {
            handle: be_u64(&self.payload[o..o + 8]),
            amount: be_u64(&self.payload[o + 8..o + 16]),
        })
    }
}

pub fn decode_consume_reqs(payload: &[u8], count: usize) -> Result<ConsumeReqs<'_>, ProtoError> {
    if payload.len() != count * CONSUME_REQ_BYTES {
        return Err(ProtoError::Malformed);
    }
    Ok(ConsumeReqs {
        payload,
        i: 0,
        count,
    })
}

/// Zero-alloc iterator over SNAPSHOT request handles.
pub struct SnapshotReqs<'a> {
    payload: &'a [u8],
    i: usize,
    count: usize,
}

impl Iterator for SnapshotReqs<'_> {
    type Item = u64;
    fn next(&mut self) -> Option<u64> {
        if self.i >= self.count {
            return None;
        }
        let o = self.i * SNAPSHOT_REQ_BYTES;
        self.i += 1;
        Some(be_u64(&self.payload[o..o + 8]))
    }
}

pub fn decode_snapshot_reqs(payload: &[u8], count: usize) -> Result<SnapshotReqs<'_>, ProtoError> {
    if payload.len() != count * SNAPSHOT_REQ_BYTES {
        return Err(ProtoError::Malformed);
    }
    Ok(SnapshotReqs {
        payload,
        i: 0,
        count,
    })
}

/// Decode the PING request tokens.
pub fn decode_ping_reqs(payload: &[u8], count: usize) -> Result<Vec<u64>, ProtoError> {
    if payload.len() != count * PING_REQ_BYTES {
        return Err(ProtoError::Malformed);
    }
    Ok((0..count)
        .map(|i| be_u64(&payload[i * PING_REQ_BYTES..(i + 1) * PING_REQ_BYTES]))
        .collect())
}

/// Decode CREATE request records. Variable-length (key bytes) and cold path, so
/// this allocates a `Vec`. Validates each `key_len` against `MAX_KEY_LEN` and
/// that the payload is exactly consumed.
pub fn decode_create_reqs(payload: &[u8], count: usize) -> Result<Vec<CreateReq<'_>>, ProtoError> {
    let mut out = Vec::with_capacity(count);
    let mut o = 0usize;
    for _ in 0..count {
        if o + CREATE_REQ_FIXED_BYTES > payload.len() {
            return Err(ProtoError::Malformed);
        }
        let capacity = be_u64(&payload[o..o + 8]);
        let refill_rate = be_u64(&payload[o + 8..o + 16]);
        let ttl_ns = be_u64(&payload[o + 16..o + 24]);
        let key_len = be_u32(&payload[o + 24..o + 28]) as usize;
        if key_len > MAX_KEY_LEN {
            return Err(ProtoError::KeyTooLong);
        }
        o += CREATE_REQ_FIXED_BYTES;
        if o + key_len > payload.len() {
            return Err(ProtoError::Malformed);
        }
        let key = &payload[o..o + key_len];
        o += key_len;
        out.push(CreateReq {
            capacity,
            refill_rate,
            ttl_ns,
            key,
        });
    }
    if o != payload.len() {
        return Err(ProtoError::Malformed);
    }
    Ok(out)
}

// --- response decoding (client side) ---

pub fn decode_create_results(
    payload: &[u8],
    count: usize,
) -> Result<Vec<CreateResult>, ProtoError> {
    if payload.len() != count * CREATE_RESULT_BYTES {
        return Err(ProtoError::Malformed);
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let o = i * CREATE_RESULT_BYTES;
        out.push(CreateResult {
            status: payload[o],
            handle: be_u64(&payload[o + 1..o + 9]),
        });
    }
    Ok(out)
}

pub fn decode_drain_results(payload: &[u8], count: usize) -> Result<Vec<DrainResult>, ProtoError> {
    if payload.len() != count * DRAIN_RESULT_BYTES {
        return Err(ProtoError::Malformed);
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let o = i * DRAIN_RESULT_BYTES;
        out.push(DrainResult {
            status: payload[o],
            drained: be_u64(&payload[o + 1..o + 9]),
        });
    }
    Ok(out)
}

pub fn decode_consume_results(
    payload: &[u8],
    count: usize,
) -> Result<Vec<ConsumeResult>, ProtoError> {
    if payload.len() != count * CONSUME_RESULT_BYTES {
        return Err(ProtoError::Malformed);
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let o = i * CONSUME_RESULT_BYTES;
        out.push(ConsumeResult {
            status: payload[o],
            allowed: payload[o + 1] != 0,
            remaining: be_u64(&payload[o + 2..o + 10]),
            retry_after_ns: be_u64(&payload[o + 10..o + 18]),
        });
    }
    Ok(out)
}

pub fn decode_ping_results(payload: &[u8], count: usize) -> Result<Vec<PingResult>, ProtoError> {
    if payload.len() != count * PING_RESULT_BYTES {
        return Err(ProtoError::Malformed);
    }
    Ok((0..count)
        .map(|i| {
            let o = i * PING_RESULT_BYTES;
            PingResult {
                token: be_u64(&payload[o..o + 8]),
                uptime_ns: be_u64(&payload[o + 8..o + 16]),
            }
        })
        .collect())
}

pub fn decode_snapshot_results(
    payload: &[u8],
    count: usize,
) -> Result<Vec<SnapshotResult>, ProtoError> {
    if payload.len() != count * SNAPSHOT_RESULT_BYTES {
        return Err(ProtoError::Malformed);
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let o = i * SNAPSHOT_RESULT_BYTES;
        out.push(SnapshotResult {
            status: payload[o],
            capacity: be_u64(&payload[o + 1..o + 9]),
            refill_rate: be_u64(&payload[o + 9..o + 17]),
            tokens: be_u64(&payload[o + 17..o + 25]),
            last_refill_ns: be_u64(&payload[o + 25..o + 33]),
        });
    }
    Ok(out)
}

// --- encoding ---

/// Write the frame header (`frame_len`, `op`, `count`) for a payload of
/// `payload_len` bytes. Caller then appends exactly `payload_len` record bytes.
pub fn write_frame_header(buf: &mut Vec<u8>, op: u8, count: usize, payload_len: usize) {
    let frame_len = HEADER_TAIL_BYTES + payload_len;
    buf.extend_from_slice(&(frame_len as u32).to_be_bytes());
    buf.push(op);
    buf.extend_from_slice(&(count as u32).to_be_bytes());
}

pub fn push_create_result(buf: &mut Vec<u8>, r: &CreateResult) {
    buf.push(r.status);
    buf.extend_from_slice(&r.handle.to_be_bytes());
}

pub fn push_drain_result(buf: &mut Vec<u8>, r: &DrainResult) {
    buf.push(r.status);
    buf.extend_from_slice(&r.drained.to_be_bytes());
}

pub fn push_consume_result(buf: &mut Vec<u8>, r: &ConsumeResult) {
    buf.push(r.status);
    buf.push(r.allowed as u8);
    buf.extend_from_slice(&r.remaining.to_be_bytes());
    buf.extend_from_slice(&r.retry_after_ns.to_be_bytes());
}

pub fn push_snapshot_result(buf: &mut Vec<u8>, r: &SnapshotResult) {
    buf.push(r.status);
    buf.extend_from_slice(&r.capacity.to_be_bytes());
    buf.extend_from_slice(&r.refill_rate.to_be_bytes());
    buf.extend_from_slice(&r.tokens.to_be_bytes());
    buf.extend_from_slice(&r.last_refill_ns.to_be_bytes());
}

pub fn encode_create_reqs(buf: &mut Vec<u8>, reqs: &[CreateReq<'_>]) {
    let payload_len: usize = reqs
        .iter()
        .map(|r| CREATE_REQ_FIXED_BYTES + r.key.len())
        .sum();
    write_frame_header(buf, OP_CREATE, reqs.len(), payload_len);
    for r in reqs {
        buf.extend_from_slice(&r.capacity.to_be_bytes());
        buf.extend_from_slice(&r.refill_rate.to_be_bytes());
        buf.extend_from_slice(&r.ttl_ns.to_be_bytes());
        buf.extend_from_slice(&(r.key.len() as u32).to_be_bytes());
        buf.extend_from_slice(r.key);
    }
}

pub fn encode_consume_reqs(buf: &mut Vec<u8>, reqs: &[ConsumeReq]) {
    write_frame_header(buf, OP_CONSUME, reqs.len(), reqs.len() * CONSUME_REQ_BYTES);
    for r in reqs {
        buf.extend_from_slice(&r.handle.to_be_bytes());
        buf.extend_from_slice(&r.amount.to_be_bytes());
    }
}

/// DRAIN requests share the CONSUME record layout (`handle`, `amount`); only the
/// op byte differs.
pub fn encode_drain_reqs(buf: &mut Vec<u8>, reqs: &[ConsumeReq]) {
    write_frame_header(buf, OP_DRAIN, reqs.len(), reqs.len() * CONSUME_REQ_BYTES);
    for r in reqs {
        buf.extend_from_slice(&r.handle.to_be_bytes());
        buf.extend_from_slice(&r.amount.to_be_bytes());
    }
}

pub fn encode_snapshot_reqs(buf: &mut Vec<u8>, handles: &[u64]) {
    write_frame_header(
        buf,
        OP_SNAPSHOT,
        handles.len(),
        handles.len() * SNAPSHOT_REQ_BYTES,
    );
    for h in handles {
        buf.extend_from_slice(&h.to_be_bytes());
    }
}

pub fn push_ping_result(buf: &mut Vec<u8>, r: &PingResult) {
    buf.extend_from_slice(&r.token.to_be_bytes());
    buf.extend_from_slice(&r.uptime_ns.to_be_bytes());
}

pub fn encode_ping_reqs(buf: &mut Vec<u8>, tokens: &[u64]) {
    write_frame_header(buf, OP_PING, tokens.len(), tokens.len() * PING_REQ_BYTES);
    for t in tokens {
        buf.extend_from_slice(&t.to_be_bytes());
    }
}

pub fn encode_create_results(buf: &mut Vec<u8>, results: &[CreateResult]) {
    write_frame_header(
        buf,
        OP_CREATE,
        results.len(),
        results.len() * CREATE_RESULT_BYTES,
    );
    for r in results {
        push_create_result(buf, r);
    }
}

pub fn encode_drain_results(buf: &mut Vec<u8>, results: &[DrainResult]) {
    write_frame_header(
        buf,
        OP_DRAIN,
        results.len(),
        results.len() * DRAIN_RESULT_BYTES,
    );
    for r in results {
        push_drain_result(buf, r);
    }
}

pub fn encode_consume_results(buf: &mut Vec<u8>, results: &[ConsumeResult]) {
    write_frame_header(
        buf,
        OP_CONSUME,
        results.len(),
        results.len() * CONSUME_RESULT_BYTES,
    );
    for r in results {
        push_consume_result(buf, r);
    }
}

pub fn encode_snapshot_results(buf: &mut Vec<u8>, results: &[SnapshotResult]) {
    write_frame_header(
        buf,
        OP_SNAPSHOT,
        results.len(),
        results.len() * SNAPSHOT_RESULT_BYTES,
    );
    for r in results {
        push_snapshot_result(buf, r);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip_frame(buf: &[u8]) -> Frame<'_> {
        parse_frame(buf).expect("parse ok").expect("complete frame")
    }

    #[test]
    fn consume_req_roundtrip() {
        let reqs = [
            ConsumeReq {
                handle: 1,
                amount: 5,
            },
            ConsumeReq {
                handle: u64::MAX,
                amount: 0,
            },
        ];
        let mut buf = Vec::new();
        encode_consume_reqs(&mut buf, &reqs);
        let f = roundtrip_frame(&buf);
        assert_eq!(f.op, OP_CONSUME);
        assert_eq!(f.count, 2);
        assert_eq!(f.total_len, buf.len());
        let got: Vec<_> = decode_consume_reqs(f.payload, f.count).unwrap().collect();
        assert_eq!(got, reqs);
    }

    #[test]
    fn ping_roundtrip() {
        let mut buf = Vec::new();
        encode_ping_reqs(&mut buf, &[0xDEAD_BEEF]);
        let f = roundtrip_frame(&buf);
        assert_eq!(f.op, OP_PING);
        assert_eq!(decode_ping_reqs(f.payload, f.count).unwrap(), [0xDEAD_BEEF]);
        assert_eq!(
            decode_ping_reqs(&f.payload[1..], f.count),
            Err(ProtoError::Malformed)
        );

        let mut resp = Vec::new();
        write_frame_header(&mut resp, OP_PING, 1, PING_RESULT_BYTES);
        push_ping_result(
            &mut resp,
            &PingResult {
                token: 7,
                uptime_ns: 99,
            },
        );
        let f = roundtrip_frame(&resp);
        assert_eq!(
            decode_ping_results(f.payload, f.count).unwrap(),
            [PingResult {
                token: 7,
                uptime_ns: 99
            }]
        );
    }

    #[test]
    fn snapshot_req_roundtrip() {
        let handles = [7u64, 8, 9];
        let mut buf = Vec::new();
        encode_snapshot_reqs(&mut buf, &handles);
        let f = roundtrip_frame(&buf);
        assert_eq!(f.op, OP_SNAPSHOT);
        let got: Vec<_> = decode_snapshot_reqs(f.payload, f.count).unwrap().collect();
        assert_eq!(got, handles);
    }

    #[test]
    fn create_req_roundtrip() {
        let reqs = [
            CreateReq {
                capacity: 100,
                refill_rate: 5,
                ttl_ns: 0,
                key: b"user:1",
            },
            CreateReq {
                capacity: 1,
                refill_rate: 2,
                ttl_ns: 9,
                key: b"",
            },
        ];
        let mut buf = Vec::new();
        encode_create_reqs(&mut buf, &reqs);
        let f = roundtrip_frame(&buf);
        assert_eq!(f.op, OP_CREATE);
        let got = decode_create_reqs(f.payload, f.count).unwrap();
        assert_eq!(got, reqs);
    }

    #[test]
    fn consume_result_roundtrip() {
        let results = [
            ConsumeResult {
                status: ST_OK,
                allowed: true,
                remaining: 9,
                retry_after_ns: 0,
            },
            ConsumeResult {
                status: ST_STALE,
                allowed: false,
                remaining: 0,
                retry_after_ns: u64::MAX,
            },
        ];
        let mut buf = Vec::new();
        encode_consume_results(&mut buf, &results);
        let f = roundtrip_frame(&buf);
        assert_eq!(decode_consume_results(f.payload, f.count).unwrap(), results);
    }

    #[test]
    fn snapshot_result_roundtrip() {
        let results = [SnapshotResult {
            status: ST_OK,
            capacity: 10,
            refill_rate: 5,
            tokens: 3,
            last_refill_ns: 1234,
        }];
        let mut buf = Vec::new();
        encode_snapshot_results(&mut buf, &results);
        let f = roundtrip_frame(&buf);
        assert_eq!(
            decode_snapshot_results(f.payload, f.count).unwrap(),
            results
        );
    }

    #[test]
    fn create_result_roundtrip() {
        let results = [CreateResult {
            status: ST_OK,
            handle: 0xABCD_1234,
        }];
        let mut buf = Vec::new();
        encode_create_results(&mut buf, &results);
        let f = roundtrip_frame(&buf);
        assert_eq!(decode_create_results(f.payload, f.count).unwrap(), results);
    }

    #[test]
    fn drain_req_and_result_roundtrip() {
        let reqs = [
            ConsumeReq {
                handle: 9,
                amount: 500,
            },
            ConsumeReq {
                handle: 10,
                amount: 0,
            },
        ];
        let mut buf = Vec::new();
        encode_drain_reqs(&mut buf, &reqs);
        let f = roundtrip_frame(&buf);
        assert_eq!(f.op, OP_DRAIN);
        // DRAIN reuses the CONSUME record layout.
        let got: Vec<_> = decode_consume_reqs(f.payload, f.count).unwrap().collect();
        assert_eq!(got, reqs);

        let results = [
            DrainResult {
                status: ST_OK,
                drained: 500,
            },
            DrainResult {
                status: ST_STALE,
                drained: 0,
            },
        ];
        let mut rbuf = Vec::new();
        encode_drain_results(&mut rbuf, &results);
        let rf = roundtrip_frame(&rbuf);
        assert_eq!(rf.op, OP_DRAIN);
        assert_eq!(decode_drain_results(rf.payload, rf.count).unwrap(), results);
    }

    #[test]
    fn truncated_frame_returns_none() {
        let mut buf = Vec::new();
        encode_consume_reqs(
            &mut buf,
            &[ConsumeReq {
                handle: 1,
                amount: 1,
            }],
        );
        for partial in 0..buf.len() {
            // A partial buffer must parse to None (incomplete), never Err.
            assert!(parse_frame(&buf[..partial]).unwrap().is_none());
        }
    }

    #[test]
    fn count_zero_rejected() {
        let mut buf = Vec::new();
        write_frame_header(&mut buf, OP_CONSUME, 0, 0);
        assert_eq!(parse_frame(&buf), Err(ProtoError::BadCount));
    }

    #[test]
    fn count_over_max_rejected() {
        let mut buf = Vec::new();
        // Header claims a huge count but we don't supply the payload; parse must
        // reject on count before needing the body.
        write_frame_header(&mut buf, OP_CONSUME, MAX_BATCH + 1, 0);
        assert_eq!(parse_frame(&buf), Err(ProtoError::BadCount));
    }

    #[test]
    fn frame_too_large_rejected() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&((MAX_FRAME_BYTES as u32) + 1).to_be_bytes());
        assert_eq!(parse_frame(&buf), Err(ProtoError::FrameTooLarge));
    }

    #[test]
    fn key_too_long_rejected() {
        // Hand-build a CREATE frame whose key_len exceeds MAX_KEY_LEN.
        let mut payload = Vec::new();
        payload.extend_from_slice(&1u64.to_be_bytes());
        payload.extend_from_slice(&1u64.to_be_bytes());
        payload.extend_from_slice(&0u64.to_be_bytes());
        payload.extend_from_slice(&((MAX_KEY_LEN as u32) + 1).to_be_bytes());
        let mut buf = Vec::new();
        write_frame_header(&mut buf, OP_CREATE, 1, payload.len());
        buf.extend_from_slice(&payload);
        let f = roundtrip_frame(&buf);
        assert_eq!(
            decode_create_reqs(f.payload, f.count),
            Err(ProtoError::KeyTooLong)
        );
    }

    #[test]
    fn wrong_payload_size_rejected() {
        // count says 2 consume records but payload only holds one.
        let mut buf = Vec::new();
        write_frame_header(&mut buf, OP_CONSUME, 2, CONSUME_REQ_BYTES);
        buf.extend_from_slice(&[0u8; CONSUME_REQ_BYTES]);
        let f = roundtrip_frame(&buf);
        assert_eq!(
            decode_consume_reqs(f.payload, f.count).err(),
            Some(ProtoError::Malformed)
        );
    }

    #[test]
    fn two_frames_in_one_buffer() {
        let mut buf = Vec::new();
        encode_snapshot_reqs(&mut buf, &[1]);
        encode_consume_reqs(
            &mut buf,
            &[ConsumeReq {
                handle: 2,
                amount: 3,
            }],
        );
        let f1 = roundtrip_frame(&buf);
        assert_eq!(f1.op, OP_SNAPSHOT);
        let f2 = roundtrip_frame(&buf[f1.total_len..]);
        assert_eq!(f2.op, OP_CONSUME);
        assert_eq!(f1.total_len + f2.total_len, buf.len());
    }
}
