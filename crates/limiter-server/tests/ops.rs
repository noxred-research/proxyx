//! Operations surface of the limiter service: PING, the HTTP endpoint, the
//! connection cap, and the client's timeouts and circuit breaker against a
//! real server and against deliberately broken peers.

use limiter_client::{
    AsyncClient, BreakerConfig, CircuitState, Client, ClientConfig, FailMode, Limits,
    ResilienceConfig,
};
use limiter_proto::{MAGIC, VERSION};
use proxyx_limiter_server::{spawn, Config};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn config(max_buckets: usize) -> Config {
    Config {
        max_buckets,
        shards: 4,
        ..Config::default()
    }
}

fn http_get(addr: SocketAddr, path: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut raw = String::new();
    stream.read_to_string(&mut raw).unwrap();
    let status = raw.split_whitespace().nth(1).unwrap().parse().unwrap();
    let body = raw.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (status, body)
}

fn metric(body: &str, series: &str) -> f64 {
    body.lines()
        .find_map(|line| line.strip_prefix(series)?.trim().parse().ok())
        .unwrap_or_else(|| panic!("series {series} missing in:\n{body}"))
}

fn limits() -> Limits {
    Limits {
        capacity: 2,
        refill_rate: 0,
        ttl_ns: 0,
    }
}

fn quick_resilience() -> ResilienceConfig {
    ResilienceConfig {
        connect_timeout: Duration::from_millis(200),
        io_timeout: Duration::from_millis(200),
        max_idle: Duration::from_secs(30),
        keepalive: Some(Duration::from_secs(30)),
        breaker: Some(BreakerConfig {
            failure_threshold: 3,
            open_duration: Duration::from_millis(300),
        }),
    }
}

/// An address nothing listens on.
fn dead_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

fn handshake(stream: &mut TcpStream) -> std::io::Result<u8> {
    let mut hello = MAGIC.to_vec();
    hello.push(VERSION);
    stream.write_all(&hello)?;
    let mut reply = [0u8; 1];
    stream.read_exact(&mut reply)?;
    Ok(reply[0])
}

fn wait_for_connections(addr: SocketAddr, expected: f64) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let (_, body) = http_get(addr, "/metrics");
        if metric(&body, "proxyx_limiter_connections ") == expected {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "connection count never became {expected}"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn assert_closed(stream: &mut TcpStream) {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut byte = [0];
    match stream.read(&mut byte) {
        Ok(0) => {}
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
        result => panic!("expected closed connection, got {result:?}"),
    }
}

#[test]
fn ping_round_trips_over_sync_and_async_clients() {
    let server = spawn("127.0.0.1:0", None, &config(16)).unwrap();
    let client = Client::connect(server.addr.to_string(), ClientConfig::default());
    let first = client.ping().unwrap();
    std::thread::sleep(Duration::from_millis(5));
    let second = client.ping().unwrap();
    assert!(second.uptime_ns > first.uptime_ns);
    assert_eq!(client.circuit_state(), CircuitState::Closed);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let client = AsyncClient::connect(server.addr.to_string(), ClientConfig::default());
        assert!(client.ping().await.unwrap().uptime_ns > 0);
    });
}

#[test]
fn sync_consume_degrades_after_idle_disconnect_and_recovers_on_next_operation() {
    let server = spawn(
        "127.0.0.1:0",
        Some("127.0.0.1:0"),
        &Config {
            idle_timeout: Duration::from_millis(200),
            ..config(16)
        },
    )
    .unwrap();
    let client = Client::connect(server.addr.to_string(), ClientConfig::default());
    let bucket = client.create(b"idle-sync", limits()).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    wait_for_connections(server.metrics_addr.unwrap(), 0.0);

    let outcome = bucket.consume(1);
    assert!(outcome.allowed);
    assert!(outcome.degraded);
    assert_eq!(outcome.remaining, 0);
    assert_eq!(client.stats().transport_errors, 1);
    assert_eq!(client.stats().circuit_opens, 0);
    assert_eq!(client.circuit_state(), CircuitState::Closed);

    let outcome = bucket.consume(1);
    assert!(outcome.allowed);
    assert!(!outcome.degraded);
    assert_eq!(outcome.remaining, 1);
    assert_eq!(client.stats().transport_errors, 1);
    assert_eq!(client.stats().circuit_opens, 0);
    assert_eq!(client.circuit_state(), CircuitState::Closed);
}

#[test]
fn async_consume_degrades_after_idle_disconnect_and_recovers_on_next_operation() {
    let server = spawn(
        "127.0.0.1:0",
        Some("127.0.0.1:0"),
        &Config {
            idle_timeout: Duration::from_millis(200),
            ..config(16)
        },
    )
    .unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let client = AsyncClient::connect(server.addr.to_string(), ClientConfig::default());
        let bucket = client.create(b"idle-async", limits()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        wait_for_connections(server.metrics_addr.unwrap(), 0.0);

        let outcome = tokio::time::timeout(Duration::from_secs(2), bucket.consume(1))
            .await
            .unwrap();
        assert!(outcome.allowed);
        assert!(outcome.degraded);
        assert_eq!(outcome.remaining, 0);
        assert_eq!(client.stats().transport_errors, 1);
        assert_eq!(client.stats().circuit_opens, 0);
        assert_eq!(client.circuit_state(), CircuitState::Closed);

        let outcome = tokio::time::timeout(Duration::from_secs(2), bucket.consume(1))
            .await
            .unwrap();
        assert!(outcome.allowed);
        assert!(!outcome.degraded);
        assert_eq!(outcome.remaining, 1);
        assert_eq!(client.stats().transport_errors, 1);
        assert_eq!(client.stats().circuit_opens, 0);
        assert_eq!(client.circuit_state(), CircuitState::Closed);
    });
}

#[test]
fn http_endpoint_serves_health_readiness_and_metrics() {
    let server = spawn("127.0.0.1:0", Some("127.0.0.1:0"), &config(2)).unwrap();
    let ops = server.metrics_addr.unwrap();
    assert_eq!(http_get(ops, "/healthz"), (200, "ok\n".into()));
    assert_eq!(http_get(ops, "/readyz").0, 200);
    assert_eq!(http_get(ops, "/nope").0, 404);

    let client = Client::connect(server.addr.to_string(), ClientConfig::default());
    let a = client.create(b"a", limits()).unwrap();
    assert!(a.consume(1).allowed);
    assert!(a.consume(1).allowed);
    assert!(!a.consume(1).allowed, "capacity 2, no refill");
    client.create(b"b", limits()).unwrap();
    assert!(client.create(b"c", limits()).is_err(), "slab of 2 is full");

    let (status, body) = http_get(ops, "/metrics");
    assert_eq!(status, 200);
    assert_eq!(metric(&body, "proxyx_limiter_buckets "), 2.0);
    assert_eq!(metric(&body, "proxyx_limiter_buckets_capacity "), 2.0);
    assert_eq!(
        metric(&body, "proxyx_limiter_requests_total{op=\"consume\"} "),
        3.0
    );
    assert_eq!(
        metric(&body, "proxyx_limiter_requests_total{op=\"create\"} "),
        3.0
    );
    assert_eq!(metric(&body, "proxyx_limiter_consume_denied_total "), 1.0);
    assert_eq!(
        metric(
            &body,
            "proxyx_limiter_create_rejected_total{reason=\"full\"} "
        ),
        1.0
    );
    // The failed create dropped the pooled connection; at most one is open.
    assert!(metric(&body, "proxyx_limiter_connections ") <= 1.0);
    assert!(metric(&body, "proxyx_limiter_uptime_seconds ") > 0.0);
    // Full slab: the service cannot admit new orgs, so it reports not ready.
    assert_eq!(http_get(ops, "/readyz").0, 503);
    assert_eq!(http_get(ops, "/healthz").0, 200);
}

#[test]
fn connection_cap_drops_excess_connections() {
    let server = spawn(
        "127.0.0.1:0",
        Some("127.0.0.1:0"),
        &Config {
            max_connections: 2,
            ..config(16)
        },
    )
    .unwrap();
    // Complete a handshake on every admitted connection before checking the cap.
    let mut held = Vec::new();
    for _ in 0..2 {
        let mut stream = TcpStream::connect(server.addr).unwrap();
        assert_eq!(handshake(&mut stream).unwrap(), VERSION);
        held.push(stream);
    }
    let mut third = TcpStream::connect(server.addr).unwrap();
    third
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    assert!(
        handshake(&mut third).is_err(),
        "third connection is dropped"
    );

    let (_, body) = http_get(server.metrics_addr.unwrap(), "/metrics");
    assert_eq!(metric(&body, "proxyx_limiter_connections "), 2.0);
    assert_eq!(
        metric(&body, "proxyx_limiter_connections_refused_total "),
        1.0
    );

    // Closing one frees a slot.
    drop(held.pop());
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let mut again = TcpStream::connect(server.addr).unwrap();
        again
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        if handshake(&mut again).is_ok() {
            break;
        }
        assert!(Instant::now() < deadline, "slot never freed");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn idle_handshakes_close_and_release_admission_slots() {
    for prefix in [&[][..], &MAGIC[..2]] {
        let server = spawn(
            "127.0.0.1:0",
            Some("127.0.0.1:0"),
            &Config {
                max_connections: 1,
                handshake_timeout: Duration::from_millis(150),
                idle_timeout: Duration::from_secs(5),
                keepalive: None,
                ..config(16)
            },
        )
        .unwrap();
        let ops = server.metrics_addr.unwrap();
        let mut idle = TcpStream::connect(server.addr).unwrap();
        idle.write_all(prefix).unwrap();
        wait_for_connections(ops, 1.0);
        assert_closed(&mut idle);
        wait_for_connections(ops, 0.0);

        let mut replacement = TcpStream::connect(server.addr).unwrap();
        replacement
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        assert_eq!(handshake(&mut replacement).unwrap(), VERSION);
    }
}

#[test]
fn handshake_progress_does_not_extend_absolute_deadline() {
    let server = spawn(
        "127.0.0.1:0",
        Some("127.0.0.1:0"),
        &Config {
            max_connections: 1,
            handshake_timeout: Duration::from_millis(250),
            idle_timeout: Duration::from_secs(5),
            keepalive: None,
            ..config(16)
        },
    )
    .unwrap();
    let mut stream = TcpStream::connect(server.addr).unwrap();
    wait_for_connections(server.metrics_addr.unwrap(), 1.0);
    let mut writer = stream.try_clone().unwrap();
    let trickle = std::thread::spawn(move || {
        let mut hello = MAGIC.to_vec();
        hello.push(VERSION);
        for byte in hello {
            if writer.write_all(&[byte]).is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    });
    // Each gap is below the handshake budget, but the whole hello exceeds it.
    assert_closed(&mut stream);
    trickle.join().unwrap();
    wait_for_connections(server.metrics_addr.unwrap(), 0.0);
    let mut replacement = TcpStream::connect(server.addr).unwrap();
    replacement
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    assert_eq!(handshake(&mut replacement).unwrap(), VERSION);
}

#[test]
fn idle_established_connections_and_partial_frames_release_admission_slots() {
    let mut frame = Vec::new();
    limiter_proto::encode_ping_reqs(&mut frame, &[7]);
    for prefix in [&[][..], &frame[..2], &frame[..10]] {
        let server = spawn(
            "127.0.0.1:0",
            Some("127.0.0.1:0"),
            &Config {
                max_connections: 1,
                handshake_timeout: Duration::from_secs(1),
                idle_timeout: Duration::from_millis(150),
                keepalive: None,
                ..config(16)
            },
        )
        .unwrap();
        let ops = server.metrics_addr.unwrap();
        let mut idle = TcpStream::connect(server.addr).unwrap();
        idle.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        assert_eq!(handshake(&mut idle).unwrap(), VERSION);
        idle.write_all(prefix).unwrap();
        wait_for_connections(ops, 1.0);
        assert_closed(&mut idle);
        wait_for_connections(ops, 0.0);

        let mut replacement = TcpStream::connect(server.addr).unwrap();
        replacement
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        assert_eq!(handshake(&mut replacement).unwrap(), VERSION);
    }
}

#[test]
fn frame_read_progress_refreshes_idle_timeout() {
    let server = spawn(
        "127.0.0.1:0",
        None,
        &Config {
            handshake_timeout: Duration::from_secs(1),
            idle_timeout: Duration::from_millis(250),
            ..config(16)
        },
    )
    .unwrap();
    let mut stream = TcpStream::connect(server.addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    assert_eq!(handshake(&mut stream).unwrap(), VERSION);
    let mut request = Vec::new();
    limiter_proto::encode_ping_reqs(&mut request, &[42]);
    // Total frame time exceeds the idle timeout; every read still progresses.
    for chunk in request.chunks(4) {
        stream.write_all(chunk).unwrap();
        std::thread::sleep(Duration::from_millis(100));
    }
    let mut response = [0u8; 4 + 5 + limiter_proto::PING_RESULT_BYTES];
    stream.read_exact(&mut response).unwrap();
    let frame = limiter_proto::parse_frame(&response).unwrap().unwrap();
    assert_eq!(frame.op, limiter_proto::OP_PING);
    let results = limiter_proto::decode_ping_results(frame.payload, frame.count).unwrap();
    assert_eq!(results[0].token, 42);
}

#[test]
fn breaker_opens_on_a_dead_service_and_recovers_when_it_returns() {
    let addr = dead_addr();
    let client = Client::connect_with(
        addr.to_string(),
        ClientConfig {
            pool_size: 2,
            fail_mode: FailMode::Closed,
        },
        quick_resilience(),
    );
    for _ in 0..3 {
        assert!(client.ping().is_err());
    }
    assert_eq!(client.circuit_state(), CircuitState::Open);
    let before = client.stats();
    assert_eq!(before.transport_errors, 3);
    assert_eq!(before.circuit_opens, 1);

    // Open: fail fast without a dial.
    let started = Instant::now();
    assert!(client.ping().is_err());
    assert!(started.elapsed() < Duration::from_millis(50));
    assert_eq!(client.stats().circuit_rejections, 1);
    assert_eq!(client.stats().transport_errors, 3, "no network attempt");

    // The service comes back on the same address; after the open period the
    // half-open probe succeeds and closes the circuit.
    let _server = spawn(&addr.to_string(), None, &config(16)).unwrap();
    std::thread::sleep(Duration::from_millis(350));
    assert!(client.ping().is_ok());
    assert_eq!(client.circuit_state(), CircuitState::Closed);
}

#[derive(Debug, Clone, Copy)]
enum OnConsume {
    /// Close the connection (a crashed service).
    Hangup,
    /// Read the request and never answer (a wedged service).
    Silence,
    /// Send one response byte and close; replay could double-charge the bucket.
    PartialResponse,
    /// Deny on the CREATE connection, but allow on a new connection.
    RejectReuse,
}

#[derive(Default)]
struct StubCounts {
    connections: AtomicUsize,
    consumes: AtomicUsize,
    reused_consumes: AtomicUsize,
}

/// A stand-in service that handshakes and answers CREATE, and misbehaves on CONSUME.
fn stub_service(on_consume: OnConsume) -> SocketAddr {
    counted_stub_service(on_consume).0
}

fn counted_stub_service(on_consume: OnConsume) -> (SocketAddr, Arc<StubCounts>) {
    use limiter_proto::{
        encode_consume_results, encode_create_results, parse_frame, ConsumeResult, CreateResult,
        OP_CONSUME, OP_CREATE, ST_OK,
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let counts = Arc::new(StubCounts::default());
    let service_counts = counts.clone();
    listener.set_nonblocking(true).unwrap();
    std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            let mut stream = match listener.accept() {
                Ok((stream, _)) => stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2));
                    continue;
                }
                Err(error) => panic!("stub accept failed: {error}"),
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            service_counts.connections.fetch_add(1, Ordering::Relaxed);
            let counts = service_counts.clone();
            std::thread::spawn(move || {
                let mut hello = [0u8; 5];
                if stream.read_exact(&mut hello).is_err() || stream.write_all(&[VERSION]).is_err() {
                    return;
                }
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let mut created = false;
                loop {
                    let n = match stream.read(&mut chunk) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    buf.extend_from_slice(&chunk[..n]);
                    while let Ok(Some(frame)) = parse_frame(&buf) {
                        let total = frame.total_len;
                        match frame.op {
                            OP_CREATE => {
                                created = true;
                                let mut resp = Vec::new();
                                let results = vec![
                                    CreateResult {
                                        status: ST_OK,
                                        handle: 1
                                    };
                                    frame.count
                                ];
                                encode_create_results(&mut resp, &results);
                                if stream.write_all(&resp).is_err() {
                                    return;
                                }
                            }
                            OP_CONSUME => {
                                counts.consumes.fetch_add(1, Ordering::Relaxed);
                                if created {
                                    counts.reused_consumes.fetch_add(1, Ordering::Relaxed);
                                }
                                match on_consume {
                                    OnConsume::Hangup => return,
                                    OnConsume::Silence => {}
                                    OnConsume::PartialResponse => {
                                        stream.write_all(&[0]).unwrap();
                                        return;
                                    }
                                    OnConsume::RejectReuse => {
                                        let mut resp = Vec::new();
                                        let results = vec![
                                            ConsumeResult {
                                                status: ST_OK,
                                                allowed: !created,
                                                remaining: 1,
                                                retry_after_ns: 0,
                                            };
                                            frame.count
                                        ];
                                        encode_consume_results(&mut resp, &results);
                                        if stream.write_all(&resp).is_err() {
                                            return;
                                        }
                                    }
                                }
                            }
                            _ => return,
                        }
                        buf.drain(..total);
                    }
                }
            });
        }
    });
    (addr, counts)
}

#[test]
fn sync_checkout_drops_expired_connections_before_the_server_idle_timeout() {
    let (addr, counts) = counted_stub_service(OnConsume::RejectReuse);
    let client = Client::connect_with(
        addr.to_string(),
        ClientConfig {
            pool_size: 1,
            fail_mode: FailMode::Closed,
        },
        ResilienceConfig {
            max_idle: Duration::from_millis(50),
            ..quick_resilience()
        },
    );
    let bucket = client.create(b"idle-sync", limits()).unwrap();
    // The stub keeps idle sockets open for two seconds, well past this checkout.
    std::thread::sleep(Duration::from_millis(100));

    let outcome = bucket.consume(1);
    assert!(outcome.allowed, "the stub denies CONSUME on the old socket");
    assert!(!outcome.degraded);
    assert_eq!(counts.connections.load(Ordering::Relaxed), 2);
    assert_eq!(counts.consumes.load(Ordering::Relaxed), 1);
    assert_eq!(counts.reused_consumes.load(Ordering::Relaxed), 0);
    assert_eq!(client.stats().transport_errors, 0);
    assert_eq!(client.stats().circuit_opens, 0);
    assert_eq!(client.circuit_state(), CircuitState::Closed);
}

#[test]
fn async_checkout_drops_expired_connections_before_the_server_idle_timeout() {
    let (addr, counts) = counted_stub_service(OnConsume::RejectReuse);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let client = AsyncClient::connect_with(
            addr.to_string(),
            ClientConfig {
                pool_size: 1,
                fail_mode: FailMode::Closed,
            },
            ResilienceConfig {
                max_idle: Duration::from_millis(50),
                ..quick_resilience()
            },
        );
        let bucket = client.create(b"idle-async", limits()).await.unwrap();
        // The stub keeps idle sockets open for two seconds, well past this checkout.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let outcome = tokio::time::timeout(Duration::from_secs(1), bucket.consume(1))
            .await
            .unwrap();
        assert!(outcome.allowed, "the stub denies CONSUME on the old socket");
        assert!(!outcome.degraded);
        assert_eq!(counts.connections.load(Ordering::Relaxed), 2);
        assert_eq!(counts.consumes.load(Ordering::Relaxed), 1);
        assert_eq!(counts.reused_consumes.load(Ordering::Relaxed), 0);
        assert_eq!(client.stats().transport_errors, 0);
        assert_eq!(client.stats().circuit_opens, 0);
        assert_eq!(client.circuit_state(), CircuitState::Closed);
    });
}

#[test]
fn sync_ambiguous_disconnect_is_not_replayed() {
    for (on_consume, max_idle, expected_connections, expected_consumes) in [
        (OnConsume::Hangup, Duration::from_secs(30), 1, 1),
        (OnConsume::PartialResponse, Duration::from_secs(30), 1, 1),
        (OnConsume::Hangup, Duration::ZERO, 2, 1),
    ] {
        let (addr, counts) = counted_stub_service(on_consume);
        let client = Client::connect_with(
            addr.to_string(),
            ClientConfig {
                pool_size: 1,
                fail_mode: FailMode::Closed,
            },
            ResilienceConfig {
                max_idle,
                ..quick_resilience()
            },
        );
        let bucket = client.create(b"retry-sync", limits()).unwrap();
        let outcome = bucket.consume(1);
        assert!(outcome.degraded, "{on_consume:?}, max_idle={max_idle:?}");
        assert!(!outcome.allowed);
        assert_eq!(
            counts.connections.load(Ordering::Relaxed),
            expected_connections,
            "{on_consume:?}, max_idle={max_idle:?}"
        );
        assert_eq!(
            counts.consumes.load(Ordering::Relaxed),
            expected_consumes,
            "{on_consume:?}, max_idle={max_idle:?}"
        );
        assert_eq!(
            counts.reused_consumes.load(Ordering::Relaxed),
            usize::from(!max_idle.is_zero())
        );
        assert_eq!(client.stats().transport_errors, 1);
        assert_eq!(client.stats().degraded, 1);
        assert_eq!(client.stats().circuit_opens, 0);
        assert_eq!(client.circuit_state(), CircuitState::Closed);
    }
}

#[test]
fn async_ambiguous_disconnect_is_not_replayed() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        for (on_consume, max_idle, expected_connections, expected_consumes) in [
            (OnConsume::Hangup, Duration::from_secs(30), 1, 1),
            (OnConsume::PartialResponse, Duration::from_secs(30), 1, 1),
            (OnConsume::Hangup, Duration::ZERO, 2, 1),
        ] {
            let (addr, counts) = counted_stub_service(on_consume);
            let client = AsyncClient::connect_with(
                addr.to_string(),
                ClientConfig {
                    pool_size: 1,
                    fail_mode: FailMode::Closed,
                },
                ResilienceConfig {
                    max_idle,
                    ..quick_resilience()
                },
            );
            let bucket = client.create(b"retry-async", limits()).await.unwrap();
            let outcome = tokio::time::timeout(Duration::from_secs(1), bucket.consume(1))
                .await
                .unwrap();
            assert!(outcome.degraded, "{on_consume:?}, max_idle={max_idle:?}");
            assert!(!outcome.allowed);
            assert_eq!(
                counts.connections.load(Ordering::Relaxed),
                expected_connections,
                "{on_consume:?}, max_idle={max_idle:?}"
            );
            assert_eq!(
                counts.consumes.load(Ordering::Relaxed),
                expected_consumes,
                "{on_consume:?}, max_idle={max_idle:?}"
            );
            assert_eq!(
                counts.reused_consumes.load(Ordering::Relaxed),
                usize::from(!max_idle.is_zero())
            );
            assert_eq!(client.stats().transport_errors, 1);
            assert_eq!(client.stats().degraded, 1);
            assert_eq!(client.stats().circuit_opens, 0);
            assert_eq!(client.circuit_state(), CircuitState::Closed);
        }
    });
}

#[test]
fn consume_degrades_by_fail_mode_and_then_fails_fast_without_dialing() {
    for (mode, allowed) in [(FailMode::Open, true), (FailMode::Closed, false)] {
        let addr = stub_service(OnConsume::Hangup);
        let client = Client::connect_with(
            addr.to_string(),
            ClientConfig {
                pool_size: 1,
                fail_mode: mode,
            },
            quick_resilience(),
        );
        let bucket = client.create(b"org", limits()).unwrap();
        for _ in 0..3 {
            let outcome = bucket.consume(1);
            assert!(outcome.degraded);
            assert_eq!(outcome.allowed, allowed);
        }
        assert_eq!(client.circuit_state(), CircuitState::Open);
        let errors = client.stats().transport_errors;

        let started = Instant::now();
        let outcome = bucket.consume(1);
        assert!(outcome.degraded);
        assert_eq!(outcome.allowed, allowed);
        assert!(started.elapsed() < Duration::from_millis(50));
        let stats = client.stats();
        assert_eq!(stats.transport_errors, errors, "open circuit does not dial");
        assert_eq!(stats.circuit_rejections, 1);
        assert_eq!(stats.degraded, 4);
    }
}

#[test]
fn async_consume_on_a_wedged_service_is_bounded_by_the_io_timeout() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        for (mode, allowed) in [(FailMode::Open, true), (FailMode::Closed, false)] {
            let addr = stub_service(OnConsume::Silence);
            let client = AsyncClient::connect_with(
                addr.to_string(),
                ClientConfig {
                    pool_size: 1,
                    fail_mode: mode,
                },
                quick_resilience(),
            );
            let bucket = client.create(b"org", limits()).await.unwrap();
            let started = Instant::now();
            let outcome = bucket.consume(1).await;
            assert!(outcome.degraded);
            assert_eq!(outcome.allowed, allowed);
            assert!(started.elapsed() < Duration::from_secs(1));
            assert_eq!(client.stats().transport_errors, 1);
            for _ in 0..2 {
                bucket.consume(1).await;
            }
            assert_eq!(client.circuit_state(), CircuitState::Open);
            let started = Instant::now();
            assert!(bucket.consume(1).await.degraded);
            assert!(started.elapsed() < Duration::from_millis(50));
            assert_eq!(client.stats().circuit_rejections, 1);
        }
    });
}

#[test]
fn blackholed_handshake_is_bounded_by_the_connect_timeout() {
    // Accepts the TCP connection but never answers the handshake.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let _hold = std::thread::spawn(move || {
        let held: Vec<_> = listener.incoming().take(4).collect();
        std::thread::sleep(Duration::from_secs(2));
        drop(held);
    });
    let client = Client::connect_with(
        addr.to_string(),
        ClientConfig::default(),
        quick_resilience(),
    );
    let started = Instant::now();
    assert!(client.ping().is_err());
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(client.stats().transport_errors, 1);
}
