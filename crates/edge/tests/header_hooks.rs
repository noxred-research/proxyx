#![allow(clippy::unwrap_used)]
mod common;

use common::{Edge, get, http_origin};

#[tokio::test]
async fn named_acl_scopes_request_and_response_header_edits() {
    let origin = http_origin("127.0.0.1:0").await;
    let edge = Edge::start(
        r#"
[[listener]]
name = "main"
listen = "127.0.0.1:0"
auth = "none"
[[http.header_rule]]
rule = "special"
request_headers_set = { X-Scoped = "request" }
response_headers_set = { X-Scoped = "response" }
[[rule]]
name = "special"
action = "allow"
allow_internal = true
when = { domain = ["origin.test"] }
[[rule]]
name = "ordinary"
action = "allow"
allow_internal = true
"#,
    )
    .await;
    let scoped = get(
        edge.addr("main"),
        &format!("origin.test:{}", origin.port()),
        "/headers",
        None,
    )
    .await;
    assert_eq!(scoped.status, 200);
    assert!(scoped.text().contains("X-Scoped: request"));
    assert_eq!(scoped.header("x-scoped"), Some("response"));
    let ordinary = get(
        edge.addr("main"),
        &format!("origin2.test:{}", origin.port()),
        "/headers",
        None,
    )
    .await;
    assert_eq!(ordinary.status, 200);
    assert!(!ordinary.text().contains("X-Scoped"));
    assert_eq!(ordinary.header("x-scoped"), None);
    edge.server
        .shutdown(std::time::Duration::from_secs(1))
        .await;
}
