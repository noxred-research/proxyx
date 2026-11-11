//! Optional operations endpoint: `GET /healthz`, `/readyz` and `/metrics` on a
//! separate plain-HTTP port (`PROXYX_LIMITER_METRICS_ADDR`). One thread, one
//! request at a time, short socket timeouts: it must never be able to slow the
//! rate-limit hot path.

use crate::state::Registry;
use crate::stats::Stats;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

const IO_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_REQUEST_BYTES: usize = 8 * 1024;

pub fn serve(listener: TcpListener, registry: Arc<Registry>, stats: Arc<Stats>) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let _ = handle(stream, &registry, &stats);
    }
}

fn handle(mut stream: TcpStream, registry: &Registry, stats: &Stats) -> std::io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() < MAX_REQUEST_BYTES {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let head = String::from_utf8_lossy(&buf);
    let mut parts = head.lines().next().unwrap_or("").split_whitespace();
    let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let path = target.split('?').next().unwrap_or("");
    let (status, content_type, body) = route(method, path, registry, stats);
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())
}

/// Route one request; returns `(status line tail, content type, body)`.
pub fn route(
    method: &str,
    path: &str,
    registry: &Registry,
    stats: &Stats,
) -> (&'static str, &'static str, String) {
    const TEXT: &str = "text/plain; charset=utf-8";
    if method != "GET" && method != "HEAD" {
        return (
            "405 Method Not Allowed",
            TEXT,
            "method not allowed\n".into(),
        );
    }
    match path {
        "/healthz" => ("200 OK", TEXT, "ok\n".into()),
        // Ready while it can still create buckets: a full slab refuses every
        // new org, which a balancer or the operator should see.
        "/readyz" => {
            if registry.used() < registry.capacity() {
                ("200 OK", TEXT, "ready\n".into())
            } else {
                ("503 Service Unavailable", TEXT, "bucket slab full\n".into())
            }
        }
        "/metrics" => (
            "200 OK",
            "text/plain; version=0.0.4; charset=utf-8",
            render(registry, stats),
        ),
        _ => ("404 Not Found", TEXT, "not found\n".into()),
    }
}

fn family(out: &mut String, name: &str, kind: &str, help: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
}

/// Prometheus text exposition of the service state. The families are documented
/// in `docs/metrics/limiter.md`.
pub fn render(registry: &Registry, stats: &Stats) -> String {
    let mut out = String::with_capacity(2048);
    family(
        &mut out,
        "proxyx_limiter_buckets",
        "gauge",
        "Buckets currently allocated in the slab.",
    );
    let _ = writeln!(out, "proxyx_limiter_buckets {}", registry.used());
    family(
        &mut out,
        "proxyx_limiter_buckets_capacity",
        "gauge",
        "Size of the bucket slab.",
    );
    let _ = writeln!(
        out,
        "proxyx_limiter_buckets_capacity {}",
        registry.capacity()
    );
    family(
        &mut out,
        "proxyx_limiter_connections",
        "gauge",
        "Open client connections.",
    );
    let _ = writeln!(
        out,
        "proxyx_limiter_connections {}",
        Stats::get(&stats.connections)
    );
    family(
        &mut out,
        "proxyx_limiter_connections_refused_total",
        "counter",
        "Connections dropped at the connection cap.",
    );
    let _ = writeln!(
        out,
        "proxyx_limiter_connections_refused_total {}",
        Stats::get(&stats.connections_refused)
    );
    family(
        &mut out,
        "proxyx_limiter_requests_total",
        "counter",
        "Records handled, by op.",
    );
    for (op, counter) in [
        ("create", &stats.create),
        ("consume", &stats.consume),
        ("drain", &stats.drain),
        ("snapshot", &stats.snapshot),
        ("ping", &stats.ping),
    ] {
        let _ = writeln!(
            out,
            "proxyx_limiter_requests_total{{op=\"{op}\"}} {}",
            Stats::get(counter)
        );
    }
    family(
        &mut out,
        "proxyx_limiter_consume_denied_total",
        "counter",
        "Consume records answered not allowed.",
    );
    let _ = writeln!(
        out,
        "proxyx_limiter_consume_denied_total {}",
        Stats::get(&stats.consume_denied)
    );
    family(
        &mut out,
        "proxyx_limiter_create_rejected_total",
        "counter",
        "Create records refused, by reason.",
    );
    let _ = writeln!(
        out,
        "proxyx_limiter_create_rejected_total{{reason=\"full\"}} {}",
        Stats::get(&stats.create_full)
    );
    family(
        &mut out,
        "proxyx_limiter_connection_errors_total",
        "counter",
        "Connections ended by an I/O or protocol error.",
    );
    let _ = writeln!(
        out,
        "proxyx_limiter_connection_errors_total {}",
        Stats::get(&stats.connection_errors)
    );
    family(
        &mut out,
        "proxyx_limiter_uptime_seconds",
        "gauge",
        "Seconds since the service started.",
    );
    let _ = writeln!(
        out,
        "proxyx_limiter_uptime_seconds {:.3}",
        registry.now_ns() as f64 / 1e9
    );
    out
}
