// Test harness of the rate-limit service: a failed setup step should abort the test loudly.
#![allow(clippy::unwrap_used)]

//! Async-client end-to-end: drives the real `limiter-server` binary through the
//! tokio-based `AsyncClient`.

use limiter_client::{AsyncClient, ClientConfig, FailMode, Limits};
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};

struct Server {
    child: Child,
    addr: String,
}

impl Server {
    fn start() -> Server {
        let mut child = Command::new(env!("CARGO_BIN_EXE_proxyx"))
            .args(["limiter", "127.0.0.1:0"])
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn server");
        let stdout = child.stdout.take().expect("server stdout");
        let mut line = String::new();
        BufReader::new(stdout)
            .read_line(&mut line)
            .expect("read READY line");
        assert!(line.starts_with("READY "), "unexpected: {line:?}");
        let addr = line.split_whitespace().nth(1).expect("addr").to_string();
        Server { child, addr }
    }

    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.kill();
    }
}

fn limits(capacity: u64) -> Limits {
    Limits {
        capacity,
        refill_rate: 0,
        ttl_ns: 0,
    }
}

#[tokio::test]
async fn async_create_consume_deny_snapshot() {
    let server = Server::start();
    let client = AsyncClient::connect(server.addr.clone(), ClientConfig::default());
    let bucket = client.create(b"user:1", limits(5)).await.unwrap();

    for _ in 0..5 {
        assert!(bucket.consume(1).await.allowed);
    }
    let denied = bucket.consume(1).await;
    assert!(!denied.allowed);
    assert!(!denied.degraded);

    let snap = bucket.snapshot().await.unwrap();
    assert_eq!(snap.capacity, 5);
    assert_eq!(snap.tokens, 0);
}

#[tokio::test]
async fn async_fail_open_when_server_down() {
    let mut server = Server::start();
    let client = AsyncClient::connect(
        server.addr.clone(),
        ClientConfig {
            pool_size: 4,
            fail_mode: FailMode::Open,
        },
    );
    let bucket = client.create(b"fo", limits(5)).await.unwrap();
    assert!(bucket.consume(1).await.allowed);

    server.kill();
    let degraded = bucket.consume(1).await;
    assert!(degraded.allowed);
    assert!(degraded.degraded);
}

#[tokio::test]
async fn async_drain_debits_up_to_available() {
    let server = Server::start();
    let client = AsyncClient::connect(server.addr.clone(), ClientConfig::default());
    // tpm-style bucket: gate input via consume, account output via drain.
    let bucket = client.create(b"tpm:model", limits(100)).await.unwrap();
    assert!(bucket.consume(60).await.allowed); // 40 left
    assert_eq!(bucket.drain(50).await.unwrap(), 40); // drains only what remains
    assert_eq!(bucket.drain(10).await.unwrap(), 0); // empty
    assert_eq!(bucket.snapshot().await.unwrap().tokens, 0);
}
