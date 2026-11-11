//! Endpoint exports and live-session control with real Postgres and Valkey.

#[macro_use]
mod support;

use std::collections::HashSet;
use std::time::Duration;

use common::Secret;
use policy::InboundOptions;
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use store::AffinityRecord;
use support::{ADMIN, TestResult, harness, org, uniq};

const TTL: Duration = Duration::from_secs(60);

fn request(provider: &str) -> Value {
    json!({"gateway_host":"gateway.example", "http_port":8080, "kind":"static",
        "country":"FR", "provider":provider, "rotation":"sticky", "ttl":"1s"})
}

#[tokio::test]
async fn all_session_routes_require_admin_bearer() -> TestResult {
    let h = or_skip!(harness("sessions_auth").await?);
    for (method, suffix, body) in [
        (Method::POST, "endpoints", Some(request(&h.provider))),
        (Method::GET, "sessions", None),
        (Method::DELETE, "sessions/example", None),
    ] {
        let (status, _) = h
            .send(method, &format!("/v1/orgs/example/{suffix}"), None, body)
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    Ok(())
}

#[tokio::test]
async fn endpoint_generator_returns_ten_thousand_unique_policy_checked_sticky_urls() -> TestResult {
    let h = or_skip!(harness("sessions_export").await?);
    let org = org(&uniq("export"));
    let known_key = h.org_key(&org).await?;
    let mut body = request(&h.provider);
    body["count"] = json!(10000);
    body["strict"] = json!(true);
    let response = h
        .client
        .post(format!("{}/v1/orgs/{org}/endpoints", h.base))
        .bearer_auth(ADMIN)
        .json(&body)
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let value: Value = response.json().await?;
    assert_eq!(value["count"], 10000);
    assert!(
        !value.to_string().contains(&known_key),
        "stored org key must never be reconstructed"
    );
    let endpoints = value["endpoints"].as_array().expect("endpoints");
    assert_eq!(endpoints.len(), 10000);
    let mut ids = HashSet::with_capacity(10000);
    for endpoint in endpoints {
        let sid = endpoint["sid"].as_str().expect("sid");
        assert!(ids.insert(sid));
        let username = endpoint["username"].as_str().expect("username");
        let options = InboundOptions::parse(username).expect("gateway options");
        assert_eq!(options.sid.as_deref(), Some(sid));
        let url = endpoint["url"].as_str().expect("url");
        assert_eq!(url, format!("http://{username}@gateway.example:8080"));
    }
    assert!(
        h.hot.affinity_sessions(&org).await?.is_empty(),
        "generation does not reserve or store credentials"
    );
    let rows = h.db.audit_for(org.as_str(), 10).await?;
    assert!(
        rows.iter()
            .any(|row| row.action == "endpoints.generate" && row.detail["status"] == 201)
    );
    assert!(
        rows.iter()
            .all(|row| !row.detail.to_string().contains(&known_key))
    );
    Ok(())
}

#[tokio::test]
async fn explicit_keys_are_org_checked_and_exports_are_real_csv_and_txt() -> TestResult {
    let h = or_skip!(harness("sessions_formats").await?);
    let org = org(&uniq("formats"));
    let key = format!("{}:@/,%\"", uniq("secret"));
    h.db.add_org_key(&org, &Secret::new(key.clone()), "test", "test")
        .await?;
    let other = support::org(&uniq("different"));
    let other_key = h.org_key(&other).await?;
    let mut body = request(&h.provider);
    body["org_key"] = json!(other_key);
    let (status, value) = h
        .post(&format!("/v1/orgs/{org}/endpoints"), body.clone())
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(!value.to_string().contains(&other_key));
    body["org_key"] = json!(key);
    body["count"] = json!(2);
    for (format, content_type) in [
        ("csv", "text/csv; charset=utf-8"),
        ("txt", "text/plain; charset=utf-8"),
    ] {
        body["format"] = json!(format);
        body["style"] = json!("socks5");
        body["socks5_port"] = json!(1080);
        let response = h
            .client
            .post(format!("{}/v1/orgs/{org}/endpoints", h.base))
            .bearer_auth(ADMIN)
            .json(&body)
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(response.headers()["content-type"], content_type);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let text = response.text().await?;
        assert!(text.contains("socks5://"));
        assert!(text.contains("%3A%40%2F%2C%25%22@gateway.example:1080"));
        assert!(!text.contains(&key));
        assert_eq!(text.lines().count(), if format == "csv" { 3 } else { 2 });
        if format == "csv" {
            assert!(text.starts_with("sid,username,url\r\n"));
        }
    }
    body["format"] = json!("json");
    body["rotation"] = json!("each");
    let (status, value) = h.post(&format!("/v1/orgs/{org}/endpoints"), body).await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(value["endpoints"][0]["sid"].is_null());
    assert!(
        !value["endpoints"][0]["username"]
            .as_str()
            .expect("username")
            .contains("-sid-")
    );
    let rows = h.db.audit_for(org.as_str(), 20).await?;
    assert!(rows.iter().all(|row| !row.detail.to_string().contains(&key)
        && !row.detail.to_string().contains(&other_key)));
    assert!(
        rows.iter()
            .any(|row| row.action == "endpoints.generate" && row.detail["status"] == 403)
    );
    Ok(())
}

#[tokio::test]
async fn sessions_expose_only_requested_org_and_delete_rotates_only_its_sid() -> TestResult {
    let h = or_skip!(harness("sessions_live").await?);
    let owner = org(&uniq("owner"));
    let outsider = org(&uniq("outsider"));
    let ips = h.seed_ips(2).await?;
    let p = h.partition();
    let record = AffinityRecord {
        sticky: "sid:scan1".into(),
        partition: p.clone(),
        unit: ips[0].to_string(),
        ip: ips[0],
        created_at_ms: 0,
        last_seen_ms: 0,
        bytes: 0,
    };
    h.hot
        .lease_pin(
            &p,
            &owner,
            &record.sticky,
            &record.unit,
            Duration::from_secs(60),
        )
        .await?;
    h.hot
        .affinity_touch(&owner, &record, Duration::from_secs(60), Some(3), false)
        .await?;
    h.hot
        .affinity_add_bytes(&owner, &record.sticky, 1024, TTL)
        .await?;
    let (status, value) = h.get(&format!("/v1/orgs/{owner}/sessions")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["sessions"][0]["sid"], "scan1");
    assert_eq!(value["sessions"][0]["provider"], h.provider);
    assert_eq!(value["sessions"][0]["region"], "fr");
    assert_eq!(value["sessions"][0]["exit_ip"], ips[0].to_string());
    assert_eq!(value["sessions"][0]["bytes"], 1024);
    assert!(value["sessions"][0]["age_seconds"].as_u64().is_some());
    assert_eq!(value["affinity"]["entries"], 1);
    assert_eq!(value["affinity"]["misses"], 1);
    let (status, value) = h.get(&format!("/v1/orgs/{outsider}/sessions")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(value["sessions"].as_array().expect("sessions").is_empty());
    let (status, _) = h
        .delete(&format!("/v1/orgs/{outsider}/sessions/scan1"))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(h.hot.affinity_sessions(&owner).await?.len(), 1);
    let (status, value) = h.delete(&format!("/v1/orgs/{owner}/sessions/scan1")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["rotated"], true);
    assert!(h.hot.affinity_sessions(&owner).await?.is_empty());
    assert_eq!(
        h.hot
            .affinity_rotation_skip(&owner, "sid:scan1", &p)
            .await?,
        Some(record.unit)
    );
    let (status, _) = h.delete(&format!("/v1/orgs/{owner}/sessions/scan1")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let rows = h.db.audit_for(owner.as_str(), 10).await?;
    assert!(rows.iter().any(|row| row.action == "sessions.list"));
    assert!(
        rows.iter()
            .any(|row| row.action == "sessions.rotate" && row.detail["status"] == 200)
    );
    assert!(
        rows.iter()
            .any(|row| row.action == "sessions.rotate" && row.detail["status"] == 404)
    );
    Ok(())
}

#[tokio::test]
async fn bad_options_and_unknown_or_incompatible_provider_are_rejected_and_audited() -> TestResult {
    let h = or_skip!(harness("sessions_validation").await?);
    let owner = org(&uniq("validation"));
    let path = format!("/v1/orgs/{owner}/endpoints");
    for patch in [
        json!({"count":0}),
        json!({"count":10001}),
        json!({"gateway_host":"http://example.com"}),
        json!({"http_port":0}),
        json!({"provider":"not_configured"}),
        json!({"ttl":"0s"}),
        json!({"kind":"rotating"}),
        json!({"unknown":"field"}),
    ] {
        let mut body = request(&h.provider);
        body.as_object_mut()
            .expect("body")
            .extend(patch.as_object().expect("patch").clone());
        let (status, _) = h.post(&path, body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    let mut denied = request(&h.provider);
    denied["country"] = json!("de");
    let (status, _) = h.post(&path, denied).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let rows = h.db.audit_for(owner.as_str(), 20).await?;
    assert_eq!(
        rows.iter()
            .filter(|row| row.action == "endpoints.generate")
            .count(),
        9
    );
    Ok(())
}

#[tokio::test]
async fn route_rate_limit_is_per_org_shared_across_routes_and_audits_refusals() -> TestResult {
    let h = or_skip!(harness("sessions_rate").await?);
    let owner = org(&uniq("ratelimit"));
    let path = format!("/v1/orgs/{owner}/sessions");
    for _ in 0..60 {
        assert_eq!(h.get(&path).await.0, StatusCode::OK);
    }
    let response = h
        .client
        .post(format!("{}/v1/orgs/{owner}/endpoints", h.base))
        .bearer_auth(ADMIN)
        .json(&request(&h.provider))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(response.headers()["retry-after"].to_str()?.parse::<u64>()? > 0);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(
        h.delete(&format!("/v1/orgs/{owner}/sessions/missing"))
            .await
            .0,
        StatusCode::TOO_MANY_REQUESTS
    );
    let other = org(&uniq("free"));
    assert_eq!(
        h.get(&format!("/v1/orgs/{other}/sessions")).await.0,
        StatusCode::OK
    );
    let rows = h.db.audit_for(owner.as_str(), 100).await?;
    assert_eq!(
        rows.iter()
            .filter(|row| row.detail["status"] == 429)
            .count(),
        2
    );
    Ok(())
}
