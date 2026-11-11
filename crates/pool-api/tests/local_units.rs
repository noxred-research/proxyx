//! `scheme = "local"` at the API: the machine's own addresses are operator
//! inventory, never something a customer picks. Needs the local Postgres and
//! Redis like the other API tests (they skip with a message when unset).

#[macro_use]
mod support;

use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use support::{CUSTOMER_ADAPTERS, Options, TestResult, harness_with, org, uniq};

const LOCAL_ADAPTER: &str = r#"
[[adapter]]
id = "local"
kind = "static"
subtype = "datacenter"
scheme = "local"
"#;

fn local_entry(ip: &str, host: &str) -> Value {
    json!({
        "provider": "local", "subtype": "datacenter", "ip": ip, "host": host,
        "port": 0, "region": "fr", "plan": "box"
    })
}

/// The customer upstream route offers `http` and `socks5` only: `local` would
/// make the gateway dial from a local address the customer names.
#[tokio::test]
async fn a_customer_cannot_choose_the_local_scheme() -> TestResult {
    let adapters = format!("{CUSTOMER_ADAPTERS}{LOCAL_ADAPTER}");
    let h = or_skip!(
        harness_with(
            "upstream_local_refused",
            Options {
                adapters_toml: Some(&adapters),
                ..Options::default()
            },
        )
        .await?
    );
    let acme = org(&uniq("acme"));
    let path = format!("/v1/orgs/{acme}/upstream");
    for host in ["127.0.0.2", "10.0.0.5", "8.8.8.8", "proxy.example.com"] {
        let body = json!({"scheme": "local", "host": host, "port": 3128, "region": "fr"});
        let (status, out) = h.put(&path, body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{host}: {out}");
    }
    // no row exists for the org afterwards
    let (status, _) = h.admin(Method::GET, &path, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (_, list) = h.get("/v1/inventory?provider=local").await;
    assert!(list["items"].as_array().expect("items").is_empty());
    Ok(())
}

/// An inventory entry of a `local` adapter has no upstream port (any value
/// is stored as given, `0` included) and a bindable IP literal as host; no
/// credentials, since there is no login.
#[tokio::test]
async fn local_inventory_entries_need_a_bindable_host_and_take_no_credentials() -> TestResult {
    let h = or_skip!(
        harness_with(
            "inventory_local",
            Options {
                adapters_toml: Some(LOCAL_ADAPTER),
                ..Options::default()
            },
        )
        .await?
    );
    let path = "/v1/inventory/local";
    let with = |key: &str, value: Value| {
        let mut e = local_entry("203.0.113.40", "10.0.0.5");
        e[key] = value;
        e
    };
    for (what, entry) in [
        ("name as host", with("host", json!("proxy.example.com"))),
        ("localhost", with("host", json!("localhost"))),
        ("wildcard host", with("host", json!("0.0.0.0"))),
        ("multicast host", with("host", json!("224.0.0.1"))),
        ("host with a port", with("host", json!("10.0.0.5:80"))),
        ("credentials", with("credentials", json!("local-login"))),
        ("other subtype", with("subtype", json!("isp"))),
        ("private exit ip", with("ip", json!("10.0.0.5"))),
    ] {
        let (status, out) = h.put(path, json!({ "entries": [entry] })).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{what}: {out}");
    }
    let (_, list) = h.get("/v1/inventory?provider=local").await;
    assert!(list["items"].as_array().expect("items").is_empty());

    // port 0, an IPv6 source, and a host that is not the exit IP (1:1 NAT)
    let entries = json!({ "entries": [
        local_entry("203.0.113.40", "10.0.0.5"),
        local_entry("203.0.113.41", "203.0.113.41"),
        local_entry("2001:db8::7", "2001:db8::7"),
    ]});
    let (status, out) = h.put(path, entries).await;
    assert_eq!(status, StatusCode::OK, "{out}");
    assert_eq!(out["added"].as_array().expect("added").len(), 3);
    let (_, list) = h.get("/v1/inventory?provider=local").await;
    let items = list["items"].as_array().expect("items");
    let nat = items
        .iter()
        .find(|i| i["ip"] == "203.0.113.40")
        .expect("nat entry");
    assert_eq!(
        (nat["host"].as_str(), nat["port"].as_u64()),
        (Some("10.0.0.5"), Some(0))
    );

    // another provider keeps the plain rule: its entries need a port
    let mut other = local_entry("203.0.113.50", "h.example");
    other["provider"] = json!("elsewhere");
    let (status, out) = h
        .put("/v1/inventory/elsewhere", json!({ "entries": [other] }))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{out}");
    Ok(())
}
