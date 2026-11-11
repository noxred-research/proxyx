//! Classic HTTP/2 CONNECT over TLS: authentication, policy and flow-controlled relay.
#![allow(clippy::unwrap_used)]

mod common;
#[path = "common/tls_fixture.rs"]
mod tls_fixture;

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use common::Edge;
use h2::client::SendRequest;
use http::{Request, StatusCode};
use tls_fixture::TlsFixture;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const ALLOW: &str = "[[rule]]\naction = \"allow\"\nallow_internal = true\n";

async fn echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0; 8192];
                loop {
                    match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if socket.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

async fn client(
    fixture: &TlsFixture,
    edge: &Edge,
) -> (SendRequest<Bytes>, tokio::task::JoinHandle<()>) {
    let tls = fixture.connect(edge.addr("main"), &[b"h2"]).await;
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
    let (client, connection) = h2::client::handshake(tls).await.unwrap();
    let task = tokio::spawn(async move {
        let _ = connection.await;
    });
    (client, task)
}

async fn request(
    client: &SendRequest<Bytes>,
    target: SocketAddr,
    auth: Option<&str>,
) -> (http::Response<h2::RecvStream>, h2::SendStream<Bytes>) {
    let mut builder = Request::builder().method("CONNECT").uri(target.to_string());
    if let Some(value) = auth {
        builder = builder.header("proxy-authorization", value);
    }
    let req = builder.body(()).unwrap();
    let mut ready = client.clone().ready().await.unwrap();
    let (response, send) = ready.send_request(req, false).unwrap();
    let response = tokio::time::timeout(Duration::from_secs(3), response)
        .await
        .unwrap()
        .unwrap();
    (response, send)
}

async fn send_all(mut send: h2::SendStream<Bytes>, data: Vec<u8>) {
    let mut offset = 0;
    while offset < data.len() {
        send.reserve_capacity((data.len() - offset).min(16384));
        let capacity = std::future::poll_fn(|cx| send.poll_capacity(cx))
            .await
            .unwrap()
            .unwrap();
        let n = capacity.min(data.len() - offset).min(16384);
        if n == 0 {
            continue;
        }
        send.send_data(Bytes::copy_from_slice(&data[offset..offset + n]), false)
            .unwrap();
        offset += n;
    }
    send.send_data(Bytes::new(), true).unwrap();
}

async fn receive(mut recv: h2::RecvStream) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut data = Vec::new();
        while let Some(chunk) = recv.data().await {
            let chunk = chunk.unwrap();
            data.extend_from_slice(&chunk);
            recv.flow_control().release_capacity(chunk.len()).unwrap();
        }
        data
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn h2_connect_relays_more_than_flow_window_and_preserves_half_close() {
    let fixture = TlsFixture::new();
    let edge = Edge::start(&format!("{}\n{ALLOW}", fixture.listener("http", "none"))).await;
    let origin = echo().await;
    let (client, driver) = client(&fixture, &edge).await;
    let (response, send) = request(&client, origin, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let payload = (0..256 * 1024).map(|i| (i % 251) as u8).collect::<Vec<_>>();
    let expected = payload.clone();
    let (_, received) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(send_all(send, payload), receive(response.into_body()))
    })
    .await
    .unwrap();
    assert_eq!(received, expected);
    driver.abort();
    edge.server.shutdown(Duration::from_millis(20)).await;
}

#[tokio::test]
async fn h2_connect_challenges_auth_and_charges_concurrent_user_limits() {
    let fixture = TlsFixture::new();
    let config = format!(
        "{}\n{ALLOW}\n[[user]]\nname = \"alice\"\npassword = \"pw\"\nmax_connections = 1\n",
        fixture.listener("auto", "users")
    );
    let edge = Edge::start(&config).await;
    let origin = echo().await;
    let (client, driver) = client(&fixture, &edge).await;
    let (missing, _) = request(&client, origin, None).await;
    assert_eq!(missing.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
    assert!(missing.headers().contains_key("proxy-authenticate"));
    let (bad, _) = request(&client, origin, Some("Basic YWxpY2U6YmFk")).await;
    assert_eq!(bad.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
    let (first, send) = request(&client, origin, Some("Basic YWxpY2U6cHc=")).await;
    assert_eq!(first.status(), StatusCode::OK);
    let (second, _) = request(&client, origin, Some("Basic YWxpY2U6cHc=")).await;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    send_all(send, b"single slot".to_vec()).await;
    assert_eq!(receive(first.into_body()).await, b"single slot");
    driver.abort();
    edge.server.shutdown(Duration::from_millis(20)).await;
}

#[tokio::test]
async fn h2_connect_checks_internal_destination_and_request_acl() {
    let fixture = TlsFixture::new();
    let edge = Edge::start(&format!(
        "{}\n[[rule]]\naction = \"allow\"\n",
        fixture.listener("http", "none")
    ))
    .await;
    let origin = echo().await;
    let (client, driver) = client(&fixture, &edge).await;
    let (denied, _) = request(&client, origin, None).await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    driver.abort();
    edge.server.shutdown(Duration::from_millis(20)).await;

    let edge = Edge::start(&format!(
        "{}\n[[rule]]\naction = \"deny\"\n",
        fixture.listener("http", "none")
    ))
    .await;
    let (client, driver) = self::client(&fixture, &edge).await;
    assert_eq!(
        request(&client, origin, None).await.0.status(),
        StatusCode::FORBIDDEN
    );
    driver.abort();
    edge.server.shutdown(Duration::from_millis(20)).await;
}

#[tokio::test]
async fn h2_rejects_forward_requests_and_bounds_idle_tunnels() {
    let fixture = TlsFixture::new();
    let edge = Edge::start(&format!(
        "{}\n{ALLOW}\n[timeouts]\nidle = \"80ms\"\n",
        fixture.listener("http", "none")
    ))
    .await;
    let origin = echo().await;
    let (client, driver) = client(&fixture, &edge).await;
    let mut ready = client.clone().ready().await.unwrap();
    let (response, _) = ready
        .send_request(
            Request::builder()
                .method("GET")
                .uri("https://example.test/")
                .body(())
                .unwrap(),
            true,
        )
        .unwrap();
    assert_eq!(
        response.await.unwrap().status(),
        StatusCode::METHOD_NOT_ALLOWED
    );
    let (response, _send) = request(&client, origin, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let mut recv = response.into_body();
    let closed = tokio::time::timeout(Duration::from_secs(2), recv.data())
        .await
        .unwrap();
    assert!(closed.is_none() || closed.unwrap().is_err());
    driver.abort();
    edge.server.shutdown(Duration::from_millis(20)).await;
}

#[tokio::test]
async fn h2_connect_rejects_trailing_headers_on_tunnel_stream() {
    let fixture = TlsFixture::new();
    let edge = Edge::start(&format!("{}\n{ALLOW}", fixture.listener("http", "none"))).await;
    let origin = echo().await;
    let (client, driver) = client(&fixture, &edge).await;
    let (response, mut send) = request(&client, origin, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let mut trailers = http::HeaderMap::new();
    trailers.insert(
        "x-trailer",
        http::HeaderValue::from_static("not tunnel data"),
    );
    send.send_trailers(trailers).unwrap();
    let mut recv = response.into_body();
    let error = tokio::time::timeout(Duration::from_secs(3), recv.data())
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(error.reason(), Some(h2::Reason::PROTOCOL_ERROR));
    driver.abort();
    edge.server.shutdown(Duration::from_millis(20)).await;
}

#[tokio::test]
async fn h2_rejections_log_once_and_count_listener_failures() {
    let fixture = TlsFixture::new();
    let edge = Edge::start(&format!(
        "{}\n{ALLOW}\n[[user]]\nname = \"alice\"\npassword = \"pw\"\n[[rule]]\nstage = \"post_auth\"\naction = \"deny\"\n",
        fixture.listener("http", "users")
    )).await;
    let origin = echo().await;
    let (client, driver) = client(&fixture, &edge).await;
    assert_eq!(
        request(&client, origin, None).await.0.status(),
        StatusCode::PROXY_AUTHENTICATION_REQUIRED
    );
    assert_eq!(
        request(&client, origin, Some("Basic YWxpY2U6YmFk"))
            .await
            .0
            .status(),
        StatusCode::PROXY_AUTHENTICATION_REQUIRED
    );
    assert_eq!(
        request(&client, origin, Some("Basic YWxpY2U6cHc="))
            .await
            .0
            .status(),
        StatusCode::FORBIDDEN
    );

    let mut ready = client.clone().ready().await.unwrap();
    let (unsupported, _) = ready
        .send_request(
            Request::builder()
                .method("GET")
                .uri("https://example.test/")
                .body(())
                .unwrap(),
            true,
        )
        .unwrap();
    assert_eq!(
        unsupported.await.unwrap().status(),
        StatusCode::METHOD_NOT_ALLOWED
    );
    let authority_only = http::Uri::builder()
        .authority("example.test")
        .build()
        .unwrap();
    let mut ready = client.clone().ready().await.unwrap();
    let (malformed, _) = ready
        .send_request(
            Request::builder()
                .method("CONNECT")
                .uri(authority_only)
                .body(())
                .unwrap(),
            false,
        )
        .unwrap();
    assert_eq!(malformed.await.unwrap().status(), StatusCode::BAD_REQUEST);

    let metrics = &edge.server.shared.metrics;
    assert_eq!(
        metrics
            .requests_total
            .with_label_values(&["main", "connect", "auth_required"])
            .get(),
        2
    );
    assert_eq!(
        metrics
            .requests_total
            .with_label_values(&["main", "connect", "denied"])
            .get(),
        1
    );
    assert_eq!(
        metrics
            .requests_total
            .with_label_values(&["main", "connect", "bad_request"])
            .get(),
        1
    );
    assert_eq!(
        metrics
            .requests_total
            .with_label_values(&["main", "http", "bad_request"])
            .get(),
        1
    );
    let ops = proxyx_edge::ops::serve(edge.server.clone(), "127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let response = common::via_proxy(
        ops,
        "GET /stats HTTP/1.1\r\nHost: ops\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(response.status, 200);
    let snapshot: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    let listener = snapshot["listeners"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == "main")
        .unwrap();
    assert_eq!(listener["failures"], 5);
    driver.abort();
    edge.server.shutdown(Duration::from_millis(20)).await;
}

#[tokio::test]
async fn h2_cancelled_active_stream_is_accounted_once() {
    let fixture = TlsFixture::new();
    let edge = Edge::start(&format!("{}\n{ALLOW}", fixture.listener("http", "none"))).await;
    let origin = echo().await;
    let (client, driver) = client(&fixture, &edge).await;
    let (response, _send) = request(&client, origin, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    driver.abort();
    edge.server.shutdown(Duration::from_secs(1)).await;
    let requests = &edge.server.shared.metrics.requests_total;
    assert_eq!(
        requests
            .with_label_values(&["main", "connect", "connect_error"])
            .get(),
        1
    );
    assert_eq!(
        requests.with_label_values(&["main", "connect", "ok"]).get(),
        0
    );
}
