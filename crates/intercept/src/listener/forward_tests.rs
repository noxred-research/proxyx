use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::AtomicI64;
use std::time::Duration;

use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use uuid::Uuid;

use super::handle_client;
use crate::config::CaConfig;
use crate::context::{ProxyContext, ProxySettings};
use crate::health::testkit::{GatedProducer, fake_redis};
use crate::pipeline::{RequestLogConfig, RequestLogWriter};
use crate::ratelimit::{RateLimitError, RateLimiter};
use crate::state::{LocalSession, ProxyState};

const DEADLINE: Duration = Duration::from_secs(5);

struct AllowAll;

impl RateLimiter for AllowAll {
    fn acquire<'a>(
        &'a self,
        _org_id: &'a str,
        _limits: Option<&'a common::types::RateLimitSettings>,
    ) -> Pin<Box<dyn Future<Output = Result<Duration, RateLimitError>> + Send + 'a>> {
        Box::pin(async { Ok(Duration::ZERO) })
    }
}

async fn context(session_ids: [Uuid; 2]) -> (Arc<ProxyContext>, std::path::PathBuf) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let redis_client = redis::Client::open(fake_redis().await).unwrap();
    let redis = redis::aio::ConnectionManager::new(redis_client)
        .await
        .unwrap();
    let state = ProxyState::new("forward-test".into(), redis, Vec::new(), "test".into());
    for session_id in session_ids {
        state.sessions.insert(
            session_id,
            LocalSession {
                session_id,
                org_id: Arc::from("test-org"),
                source: "test".into(),
                source_id: session_id.to_string(),
                agent: None,
                captured_hosts: Vec::new(),
                excluded_hosts: Vec::new(),
                upstream_overrides: Arc::from([]),
                inject_headers: Arc::from([]),
                serialize: false,
                serial_lock: None,
                expires_at_ms: Arc::new(AtomicI64::new(i64::MAX)),
                egress_proxy: None,
                insecure_upstream_tls: false,
                rate_limit: None,
            },
        );
    }
    let ca_dir = std::env::temp_dir().join(format!("proxyx-forward-test-{}", Uuid::new_v4()));
    let ca = crate::ca::load(&CaConfig::Generate {
        data_dir: ca_dir.clone(),
    })
    .unwrap();
    let (producer, _gate) = GatedProducer::new(true);
    let pipeline = Arc::new(RequestLogWriter::new(
        RequestLogConfig::default(),
        Box::new(producer),
    ));
    let ctx = ProxyContext::new(
        state,
        ca,
        Arc::new(AllowAll),
        pipeline,
        ProxySettings::default(),
    )
    .unwrap();
    (Arc::new(ctx), ca_dir)
}

async fn client(ctx: Arc<ProxyContext>) -> (TcpStream, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handler = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        handle_client(stream, peer, ctx).await.unwrap();
    });
    (TcpStream::connect(addr).await.unwrap(), handler)
}

async fn read_response(client: &mut TcpStream) -> String {
    let mut response = Vec::new();
    timeout(DEADLINE, client.read_to_end(&mut response))
        .await
        .expect("proxy must close the client after one response")
        .unwrap();
    String::from_utf8(response).unwrap()
}

async fn origin(listener: TcpListener, path: &str, body: &[u8]) {
    let (mut stream, _) = timeout(DEADLINE, listener.accept()).await.unwrap().unwrap();
    let mut head = Vec::new();
    timeout(DEADLINE, async {
        while !head.ends_with(b"\r\n\r\n") {
            head.push(stream.read_u8().await.unwrap());
        }
    })
    .await
    .unwrap();
    let head = String::from_utf8(head).unwrap();
    assert!(head.lines().next().unwrap().contains(path), "{head}");
    assert!(
        !head.to_ascii_lowercase().contains("proxy-authorization"),
        "{head}"
    );
    assert!(
        !head.to_ascii_lowercase().contains("proxy-connection"),
        "{head}"
    );
    let mut received_body = vec![0; body.len()];
    timeout(DEADLINE, stream.read_exact(&mut received_body))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received_body, body);
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok")
        .await
        .unwrap();
    let mut extra = Vec::new();
    timeout(DEADLINE, stream.read_to_end(&mut extra))
        .await
        .expect("proxy must close the origin after one exchange")
        .unwrap();
    assert!(
        extra.is_empty(),
        "origin received pipelined data: {extra:?}"
    );
}

async fn assert_forward_isolated(body_headers: &str, body: &'static [u8]) {
    let first_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let first_addr = first_listener.local_addr().unwrap();
    let second_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let second_addr = second_listener.local_addr().unwrap();
    let session_ids = [Uuid::new_v4(), Uuid::new_v4()];
    let (ctx, ca_dir) = context(session_ids).await;
    let auth = session_ids
        .map(|id| base64::engine::general_purpose::STANDARD.encode(format!("{id}:secret")));
    let first_request = format!(
        "POST http://{first_addr}/first HTTP/1.1\r\nHost: {first_addr}\r\nProxy-Authorization: Basic {}\r\nProxy-Connection: keep-alive\r\n{body_headers}\r\n",
        auth[0],
    );
    let second_request = format!(
        "GET http://{second_addr}/second HTTP/1.1\r\nHost: {second_addr}\r\npRoXy-AuThOrIzAtIoN: Basic {}\r\nProxy-Connection: keep-alive\r\n\r\n",
        auth[1],
    );
    let mut pipeline = first_request.into_bytes();
    pipeline.extend_from_slice(body);
    pipeline.extend_from_slice(second_request.as_bytes());
    let first_origin = tokio::spawn(async move {
        origin(first_listener, "/first", body).await;
    });
    let (mut first_client, first_handler) = client(ctx.clone()).await;
    first_client.write_all(&pipeline).await.unwrap();
    let response = read_response(&mut first_client).await;
    assert!(response.starts_with("HTTP/1.1 200 "), "{response}");
    assert!(response.contains("Connection: close\r\n"), "{response}");
    assert!(response.ends_with("\r\n\r\nok"), "{response}");
    timeout(DEADLINE, first_origin).await.unwrap().unwrap();
    timeout(DEADLINE, first_handler).await.unwrap().unwrap();
    assert!(
        timeout(Duration::from_millis(100), second_listener.accept())
            .await
            .is_err(),
        "pipelined request must not connect to another authority",
    );

    // A retry uses a fresh handler: missing credentials cannot inherit the
    // first request's session, and valid credentials route to the second origin.
    let (mut unauthenticated, rejected_handler) = client(ctx.clone()).await;
    unauthenticated
        .write_all(
            format!("GET http://{second_addr}/second HTTP/1.1\r\nHost: {second_addr}\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let rejected = read_response(&mut unauthenticated).await;
    assert!(rejected.starts_with("HTTP/1.1 407 "), "{rejected}");
    timeout(DEADLINE, rejected_handler).await.unwrap().unwrap();
    assert!(
        timeout(Duration::from_millis(100), second_listener.accept())
            .await
            .is_err(),
        "unauthenticated retry must not dial the origin",
    );
    let second_origin = tokio::spawn(async move {
        origin(second_listener, "/second", &[]).await;
    });
    let (mut retry_client, retry_handler) = client(ctx.clone()).await;
    retry_client
        .write_all(second_request.as_bytes())
        .await
        .unwrap();
    let response = read_response(&mut retry_client).await;
    assert!(response.starts_with("HTTP/1.1 200 "), "{response}");
    assert!(response.contains("Connection: close\r\n"), "{response}");
    timeout(DEADLINE, second_origin).await.unwrap().unwrap();
    timeout(DEADLINE, retry_handler).await.unwrap().unwrap();
    ctx.pipeline.flush_and_close(DEADLINE).await;
    std::fs::remove_dir_all(ca_dir).unwrap();
}

#[tokio::test]
async fn uncaptured_forward_pipeline_closes_before_second_authority_and_reauthenticates_retry() {
    assert_forward_isolated("", &[]).await;
}

#[tokio::test]
async fn uncaptured_forward_content_length_overflow_does_not_forward_next_request() {
    assert_forward_isolated("Content-Length: 5\r\n", b"hello").await;
}

#[tokio::test]
async fn uncaptured_forward_chunked_overflow_does_not_forward_next_request() {
    assert_forward_isolated("Transfer-Encoding: chunked\r\n", b"5\r\nhello\r\n0\r\n\r\n").await;
}
