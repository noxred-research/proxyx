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
    let handshake = |stream: &mut TcpStream| -> std::io::Result<u8> {
        let mut hello = MAGIC.to_vec();
        hello.push(VERSION);
        stream.write_all(&hello)?;
        let mut reply = [0u8; 1];
        stream.read_exact(&mut reply)?;
        Ok(reply[0])
    };
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

#[derive(Clone, Copy)]
enum OnConsume {
    /// Close the connection (a crashed service).
    Hangup,
    /// Read the request and never answer (a wedged service).
    Silence,
}

/// A stand-in service that handshakes and answers CREATE, and misbehaves on CONSUME.
fn stub_service(on_consume: OnConsume) -> SocketAddr {
    use limiter_proto::{
        encode_create_results, parse_frame, CreateResult, OP_CONSUME, OP_CREATE, ST_OK,
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            std::thread::spawn(move || {
                let mut hello = [0u8; 5];
                if stream.read_exact(&mut hello).is_err() || stream.write_all(&[VERSION]).is_err() {
                    return;
                }
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
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
                            OP_CONSUME => match on_consume {
                                OnConsume::Hangup => return,
                                OnConsume::Silence => {}
                            },
                            _ => return,
                        }
                        buf.drain(..total);
                    }
                }
            });
        }
    });
    addr
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
