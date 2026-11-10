//! `MobileBoxClient::rotate` against a local stub HTTP server.

use std::time::Duration;

use common::Secret;
use proxyx_provider::{Adapter, AdapterFile, AdapterSet, MobileBoxClient, ProviderError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A `mobile_box` adapter whose `[adapter.rotate]` table holds `call`.
fn load(call: &str) -> Result<Adapter, ProviderError> {
    let toml = format!(
        "[[adapter]]\nid = \"box\"\nkind = \"static\"\nsubtype = \"mobile_box\"\nhost = \"box.example.com\"\n[adapter.rotate]\n{call}\n"
    );
    let file: AdapterFile = toml::from_str(&toml).expect("parse");
    let secrets = |name: &str| -> anyhow::Result<Secret> {
        match name {
            "box_token" => Ok(Secret::new("tok-123")),
            other => anyhow::bail!("no secret {other}"),
        }
    };
    let set = AdapterSet::from_configs(file.adapter, &secrets)?;
    Ok(set
        .get(&"box".parse().expect("id"))
        .expect("adapter")
        .clone())
}

fn adapter(call: &str) -> Adapter {
    load(call).expect("load")
}

async fn rotate(a: &Adapter, handle: &str) -> Result<(), ProviderError> {
    MobileBoxClient::new()
        .expect("client")
        .rotate(a, handle)
        .await
}

/// A full HTTP answer: `status` is the status line text and any extra headers.
fn answer(status: &str) -> String {
    format!("HTTP/1.1 {status}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
}

async fn bind() -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    (listener, port)
}

/// Accepts one connection, answers `reply`, returns the raw request.
async fn stub(reply: String) -> (u16, tokio::task::JoinHandle<String>) {
    let (listener, port) = bind().await;
    let task = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("accept");
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let n = sock.read(&mut chunk).await.expect("read");
            buf.extend_from_slice(&chunk[..n]);
            let text = String::from_utf8_lossy(&buf);
            if let Some((head, body)) = text.split_once("\r\n\r\n") {
                let want = head
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                    })
                    .unwrap_or(0);
                if body.len() >= want || n == 0 {
                    break;
                }
            } else if n == 0 {
                break;
            }
        }
        sock.write_all(reply.as_bytes()).await.expect("write");
        sock.shutdown().await.ok();
        String::from_utf8_lossy(&buf).into_owned()
    });
    (port, task)
}

#[tokio::test]
async fn rotate_sends_the_configured_call() {
    let (port, request) = stub(answer("200 OK")).await;
    let a = adapter(&format!(
        r#"
        method = "POST"
        url = "http://127.0.0.1:{port}/api/v1/modems/{{handle}}/rotate?x=1"
        bearer_file = "box_token"
        body = '{{"action":"changeip","modem":"{{handle}}"}}'
        timeout = "2s"
        "#
    ));
    rotate(&a, "modem-7").await.expect("rotate");
    let req = request.await.expect("stub");
    let lower = req.to_ascii_lowercase();
    assert!(
        req.starts_with("POST /api/v1/modems/modem-7/rotate?x=1 HTTP/1.1"),
        "{req}"
    );
    assert!(lower.contains("authorization: bearer tok-123"), "{req}");
    assert!(lower.contains("content-type: application/json"), "{req}");
    assert!(
        req.ends_with(r#"{"action":"changeip","modem":"modem-7"}"#),
        "{req}"
    );
}

#[tokio::test]
async fn rotate_without_a_token_or_body_sends_a_bare_get() {
    let (port, request) = stub(answer("200 OK")).await;
    let a = adapter(&format!(
        "method = \"GET\"\nurl = \"http://127.0.0.1:{port}/rotate/{{handle}}\""
    ));
    rotate(&a, "3").await.expect("rotate");
    let req = request.await.expect("stub").to_ascii_lowercase();
    assert!(req.starts_with("get /rotate/3 http/1.1"), "{req}");
    assert!(!req.contains("authorization"), "{req}");
}

#[tokio::test]
async fn rotate_maps_answers_to_errors() {
    type Check = fn(&ProviderError) -> bool;
    let cases: [(String, Check); 3] = [
        (answer("429 Too Many Requests"), |e| {
            matches!(e, ProviderError::RotateRateLimited)
        }),
        (answer("500 Internal Server Error"), |e| {
            matches!(e, ProviderError::RotateStatus(500))
        }),
        // a redirect is an answer, not something to follow
        (
            answer("302 Found\r\nlocation: http://169.254.169.254/"),
            |e| matches!(e, ProviderError::RotateStatus(302)),
        ),
    ];
    for (reply, is_expected) in cases {
        let (port, _request) = stub(reply).await;
        let a = adapter(&format!(
            "method = \"POST\"\nurl = \"http://127.0.0.1:{port}/r/{{handle}}\""
        ));
        let err = rotate(&a, "1").await.expect_err("fails");
        assert!(is_expected(&err), "{err:?}");
    }
}

#[tokio::test]
async fn rotate_transport_error_does_not_show_the_url() {
    // a port nothing listens on, with a credential in the query string
    let (_, port) = bind().await;
    let a = adapter(&format!(
        "method = \"GET\"\nurl = \"http://127.0.0.1:{port}/r/{{handle}}?key=s3cret\""
    ));
    let err = rotate(&a, "1").await.expect_err("refused");
    assert!(matches!(err, ProviderError::RotateTransport(_)), "{err:?}");
    assert!(!err.to_string().contains("s3cret"), "{err}");
}

#[tokio::test]
async fn rotate_times_out_on_a_silent_box() {
    let (listener, port) = bind().await;
    let hold = tokio::spawn(async move {
        let (_sock, _) = listener.accept().await.expect("accept");
        tokio::time::sleep(Duration::from_secs(5)).await;
    });
    let a = adapter(&format!(
        "method = \"POST\"\nurl = \"http://127.0.0.1:{port}/r/{{handle}}\"\ntimeout = \"1s\""
    ));
    let started = std::time::Instant::now();
    let err = rotate(&a, "1").await.expect_err("times out");
    assert!(matches!(err, ProviderError::RotateTimeout), "{err:?}");
    assert!(started.elapsed() < Duration::from_secs(4));
    hold.abort();
}

#[tokio::test]
async fn rotate_refuses_a_hostile_handle_without_sending() {
    // nothing listens: a request would fail with a transport error instead
    let a = adapter("method = \"POST\"\nurl = \"http://127.0.0.1:9/r/{handle}\"");
    for bad in [
        "",
        "a/b",
        "..",
        "a b",
        "a?x=1",
        "a#b",
        "a\r\nb",
        &"a".repeat(65),
    ] {
        let err = rotate(&a, bad).await.expect_err("refused");
        assert!(matches!(err, ProviderError::BadHandle), "{bad:?}: {err:?}");
    }
}

#[test]
fn rotate_call_is_checked_at_load() {
    let is_config = |call: &str| matches!(load(call), Err(ProviderError::Config { .. }));
    // the handle cannot choose the host
    assert!(is_config(
        "method = \"POST\"\nurl = \"http://{handle}.example.com/r\""
    ));
    assert!(is_config(
        "method = \"POST\"\nurl = \"ftp://example.com/r/{handle}\""
    ));
    assert!(is_config(
        "method = \"POST\"\nurl = \"http://example.com/r\"\ntimeout = \"0s\""
    ));
    assert!(load("method = \"PUT\"\nurl = \"https://example.com/r/{handle}\"").is_ok());
}
