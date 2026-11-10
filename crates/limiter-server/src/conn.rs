//! Per-connection handler: handshake, then a read -> parse-frames -> dispatch ->
//! write loop. The raw `recv`/`send` helpers (EINTR/EAGAIN-correct, `MSG_NOSIGNAL`
//! on writes) are carried over from the original benchmark service.

use crate::state::Registry;
use crate::stats::Stats;
use limiter_proto::{
    decode_consume_reqs, decode_create_reqs, decode_ping_reqs, decode_snapshot_reqs, parse_frame,
    push_consume_result, push_create_result, push_drain_result, push_ping_result,
    push_snapshot_result, write_frame_header, CreateResult, Frame, PingResult, ProtoError,
    CONSUME_RESULT_BYTES, CREATE_RESULT_BYTES, DRAIN_RESULT_BYTES, MAGIC, OP_CONSUME, OP_CREATE,
    OP_DRAIN, OP_PING, OP_SNAPSHOT, PING_RESULT_BYTES, SNAPSHOT_RESULT_BYTES, ST_FULL, ST_OK,
    VERSION,
};
use std::io;
use std::net::TcpStream;
use std::os::fd::AsRawFd;
use std::sync::Arc;

// Linux: suppress SIGPIPE on send. macOS has no MSG_NOSIGNAL; Rust's runtime
// already sets SIGPIPE to SIG_IGN, so a flag of 0 is safe there.
#[cfg(target_os = "linux")]
const MSG_NOSIGNAL: i32 = 0x4000;
#[cfg(not(target_os = "linux"))]
const MSG_NOSIGNAL: i32 = 0;
const READ_CHUNK_BYTES: usize = 64 * 1024;

unsafe extern "C" {
    fn recv(fd: i32, buf: *mut u8, len: usize, flags: i32) -> isize;
    fn send(fd: i32, buf: *const u8, len: usize, flags: i32) -> isize;
}

fn recv_some(stream: &TcpStream, buf: &mut [u8]) -> io::Result<usize> {
    let fd = stream.as_raw_fd();
    loop {
        let received = unsafe { recv(fd, buf.as_mut_ptr(), buf.len(), 0) };
        if received == 0 {
            return Ok(0);
        }
        if received < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        return Ok(received as usize);
    }
}

fn recv_exact(stream: &TcpStream, mut buf: &mut [u8]) -> io::Result<()> {
    while !buf.is_empty() {
        let n = recv_some(stream, buf)?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        buf = &mut buf[n..];
    }
    Ok(())
}

fn send_all(stream: &TcpStream, mut buf: &[u8]) -> io::Result<()> {
    let fd = stream.as_raw_fd();
    while !buf.is_empty() {
        let written = unsafe { send(fd, buf.as_ptr(), buf.len(), MSG_NOSIGNAL) };
        if written == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        if written < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        buf = &buf[written as usize..];
    }
    Ok(())
}

/// Read `MAGIC ++ VERSION`; reply `VERSION` on accept, `REJECT` then close on a
/// bad handshake. Returns `Ok(false)` to signal the caller to drop the conn.
fn handshake(stream: &TcpStream) -> io::Result<bool> {
    let mut hs = [0u8; 5];
    recv_exact(stream, &mut hs)?;
    if hs[0..4] != MAGIC || hs[4] != VERSION {
        let _ = send_all(stream, &[limiter_proto::REJECT]);
        return Ok(false);
    }
    send_all(stream, &[VERSION])?;
    Ok(true)
}

/// Dispatch one request frame, appending its response frame to `resp`. Each op is
/// homogeneous within a frame; the response echoes `op` and `count`.
fn dispatch(
    reg: &Registry,
    stats: &Stats,
    frame: &Frame,
    resp: &mut Vec<u8>,
) -> Result<(), ProtoError> {
    let now = reg.now_ns();
    match frame.op {
        OP_CONSUME => {
            let reqs = decode_consume_reqs(frame.payload, frame.count)?;
            write_frame_header(
                resp,
                OP_CONSUME,
                frame.count,
                frame.count * CONSUME_RESULT_BYTES,
            );
            Stats::add(&stats.consume, frame.count as u64);
            for req in reqs {
                let r = reg.consume(now, req.handle, req.amount);
                if r.status == ST_OK && !r.allowed {
                    Stats::add(&stats.consume_denied, 1);
                }
                push_consume_result(resp, &r);
            }
        }
        OP_DRAIN => {
            // DRAIN shares the CONSUME request record layout.
            let reqs = decode_consume_reqs(frame.payload, frame.count)?;
            write_frame_header(
                resp,
                OP_DRAIN,
                frame.count,
                frame.count * DRAIN_RESULT_BYTES,
            );
            Stats::add(&stats.drain, frame.count as u64);
            for req in reqs {
                let r = reg.drain(now, req.handle, req.amount);
                push_drain_result(resp, &r);
            }
        }
        OP_SNAPSHOT => {
            let handles = decode_snapshot_reqs(frame.payload, frame.count)?;
            write_frame_header(
                resp,
                OP_SNAPSHOT,
                frame.count,
                frame.count * SNAPSHOT_RESULT_BYTES,
            );
            Stats::add(&stats.snapshot, frame.count as u64);
            for handle in handles {
                let r = reg.snapshot(now, handle);
                push_snapshot_result(resp, &r);
            }
        }
        OP_CREATE => {
            let reqs = decode_create_reqs(frame.payload, frame.count)?;
            write_frame_header(
                resp,
                OP_CREATE,
                frame.count,
                frame.count * CREATE_RESULT_BYTES,
            );
            Stats::add(&stats.create, frame.count as u64);
            for req in reqs {
                let result =
                    match reg.create(now, req.key, req.capacity, req.refill_rate, req.ttl_ns) {
                        Ok(handle) => CreateResult {
                            status: ST_OK,
                            handle,
                        },
                        Err(status) => {
                            if status == ST_FULL {
                                Stats::add(&stats.create_full, 1);
                            }
                            CreateResult { status, handle: 0 }
                        }
                    };
                push_create_result(resp, &result);
            }
        }
        OP_PING => {
            let tokens = decode_ping_reqs(frame.payload, frame.count)?;
            write_frame_header(resp, OP_PING, frame.count, frame.count * PING_RESULT_BYTES);
            Stats::add(&stats.ping, frame.count as u64);
            for token in tokens {
                push_ping_result(
                    resp,
                    &PingResult {
                        token,
                        uptime_ns: now,
                    },
                );
            }
        }
        // Unknown op: protocol violation, drop the connection.
        _ => return Err(ProtoError::Malformed),
    }
    Ok(())
}

/// Serve one connection until EOF or a protocol/IO error. Any error drops only
/// this connection; the server process keeps running.
pub fn handle_client(
    stream: TcpStream,
    registry: Arc<Registry>,
    stats: Arc<Stats>,
) -> io::Result<()> {
    let result = serve(&stream, &registry, &stats);
    if result.is_err() {
        Stats::add(&stats.connection_errors, 1);
    }
    result
}

fn serve(stream: &TcpStream, registry: &Registry, stats: &Stats) -> io::Result<()> {
    if !handshake(stream)? {
        return Ok(());
    }
    let mut buf: Vec<u8> = Vec::with_capacity(READ_CHUNK_BYTES);
    let mut chunk = vec![0u8; READ_CHUNK_BYTES];
    let mut resp: Vec<u8> = Vec::with_capacity(READ_CHUNK_BYTES);

    loop {
        let mut consumed = 0usize;
        resp.clear();
        while let Some(frame) = parse_frame(&buf[consumed..])? {
            dispatch(registry, stats, &frame, &mut resp)?;
            consumed += frame.total_len;
        }
        if consumed > 0 {
            buf.drain(0..consumed);
        }
        if !resp.is_empty() {
            send_all(stream, &resp)?;
        }
        let n = recv_some(stream, &mut chunk)?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}
