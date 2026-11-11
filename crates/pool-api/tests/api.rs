//! Control API against real Postgres and Redis (skipped when unset).

#[macro_use]
mod support;

use std::net::IpAddr;

use common::types::{IpState, SignalSource, SignalType, Subtype, Target, Tier};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use store::{BlockScope, SampleJob};
use support::*;

fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

fn target(host: &str) -> Target {
    Target {
        host: host.to_owned(),
        port: 0,
    }
}

// --- credentials ---

#[tokio::test]
async fn every_route_refuses_a_missing_or_wrong_credential() -> TestResult {
    let h = or_skip!(harness("auth").await?);
    let admin_routes = [
        (Method::GET, "/v1/inventory"),
        (Method::GET, "/v1/inventory/replacements"),
        (Method::PUT, "/v1/inventory/oxy"),
        (Method::POST, "/v1/ips/203.0.113.1/block"),
        (Method::GET, "/v1/policies"),
        (Method::PUT, "/v1/policies"),
        (Method::PUT, "/v1/orgs/acme/cache-policy"),
        (Method::POST, "/v1/orgs/acme/keys"),
        (Method::DELETE, "/v1/orgs/acme/keys"),
        (Method::GET, "/v1/orgs/acme/upstream"),
        (Method::PUT, "/v1/orgs/acme/upstream"),
        (Method::DELETE, "/v1/orgs/acme/upstream"),
        (Method::POST, "/v1/orgs/acme/upstream/validate"),
        (Method::POST, "/v1/orgs/acme/upstream/rotate-secret"),
        (Method::POST, "/v1/org-blocks"),
        (Method::GET, "/v1/org-blocks"),
        (
            Method::DELETE,
            "/v1/org-blocks/6f0c1f3e-7c64-4a59-9f3c-0a6b8c0e8d11",
        ),
    ];
    let wrong_bearer = format!("Bearer {PROBER}");
    for (method, path) in &admin_routes {
        for auth in [
            None,
            Some("Bearer nope"),
            Some(wrong_bearer.as_str()),
            Some("Basic YTpi"),
        ] {
            let (status, body) = h.send(method.clone(), path, auth, Some(json!({}))).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {path} {auth:?}");
            assert_eq!(error_of(&body), "unauthorized");
        }
    }
    for (method, path) in [
        (Method::GET, "/v1/probe/targets"),
        (Method::POST, "/v1/probe/results"),
        (Method::POST, "/v1/probe/token"),
    ] {
        let admin = format!("Bearer {ADMIN}");
        for auth in [None, Some("Bearer nope"), Some(admin.as_str())] {
            let (status, _) = h.send(method.clone(), path, auth, Some(json!({}))).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {path} {auth:?}");
        }
    }
    let admin = format!("Bearer {ADMIN}");
    for auth in [None, Some(admin.as_str()), Some("Basic YTpi")] {
        let (status, _) = h
            .send(Method::POST, "/v1/block-signals", auth, Some(json!([])))
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "block-signals {auth:?}");
    }
    // The right tokens pass authentication.
    let (status, _) = h.get("/v1/inventory").await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = h.probe_targets().await;
    assert_eq!(status, StatusCode::OK);
    Ok(())
}

// --- inventory ---

fn entry_json(provider: &str, ip: &str) -> Value {
    json!({
        "provider": provider, "subtype": "isp", "ip": ip, "host": "h.example",
        "port": 8001, "region": "fr", "plan": "p", "rental_end": "2027-01-01"
    })
}

#[tokio::test]
async fn inventory_put_list_retire_and_replacement_report() -> TestResult {
    let h = or_skip!(harness("inventory").await?);
    let p = h.provider.clone();
    let path = format!("/v1/inventory/{p}");

    let body =
        json!({ "entries": [entry_json(&p, "203.0.113.10"), entry_json(&p, "203.0.113.11")] });
    let (status, out) = h.put(&path, body).await;
    assert_eq!(status, StatusCode::OK, "{out}");
    assert_eq!(out["added"].as_array().expect("added").len(), 2);

    let (_, list) = h.get(&format!("/v1/inventory?provider={p}")).await;
    let items = list["items"].as_array().expect("items");
    assert_eq!(items.len(), 2);
    assert!(
        items
            .iter()
            .all(|i| i["state"] == "candidate" && i["region"] == "fr")
    );
    let (status, bad) = h.get("/v1/inventory?state=bogus").await;
    assert_eq!(
        (status, error_of(&bad).contains("ip state")),
        (StatusCode::BAD_REQUEST, true)
    );

    // validation
    let other = json!({ "entries": [entry_json("someone_else", "203.0.113.12")] });
    let (status, out) = h.put(&path, other).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{out}");
    let mut rotating = entry_json(&p, "203.0.113.12");
    rotating["subtype"] = json!("residential");
    let (status, out) = h.put(&path, json!({ "entries": [rotating] })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{out}");
    assert!(error_of(&out).contains("not a static"), "{out}");
    let (status, out) = h.put(&path, json!({ "entries": 5 })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{out}");
    error_of(&out);
    let (status, _) = h
        .put("/v1/inventory/Bad_Id", json!({ "entries": [] }))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // leaving an IP out retires it and withdraws it from the ready set
    let gone: IpAddr = "203.0.113.11".parse()?;
    h.hot
        .ready_put(&h.partition(), &store::UnitRecord::static_ip(gone))
        .await?;
    let keep = json!({ "entries": [entry_json(&p, "203.0.113.10")] });
    let (status, out) = h.put(&path, keep).await;
    assert_eq!(status, StatusCode::OK, "{out}");
    assert_eq!(out["retired"], json!(["203.0.113.11"]));
    assert!(
        !h.hot
            .ready_ids(&h.partition())
            .await?
            .contains(&gone.to_string())
    );
    let (_, retired) = h
        .get(&format!("/v1/inventory?provider={p}&state=retired"))
        .await;
    assert_eq!(retired["items"][0]["ip"], "203.0.113.11");

    // replacement report: scores per service, blocks per target, rental end
    let kept: IpAddr = "203.0.113.10".parse()?;
    h.db.transition_ip(
        kept,
        &store::Transition::to(IpState::ReplaceRequested, "test"),
        "test",
    )
    .await?;
    for (source, risk) in [("fraud_score", 90u8), ("abuse_confidence", 80)] {
        h.db.record_score(&store::ScoreRow {
            ip: kept,
            source: source.into(),
            risk,
            flags: vec!["tor".into()],
            checked_at: time::OffsetDateTime::now_utc(),
        })
        .await?;
    }
    h.db.record_block(
        kept,
        None,
        SignalSource::Operator,
        SignalType::Forbidden,
        None,
    )
    .await?;
    let until = time::OffsetDateTime::now_utc() + std::time::Duration::from_secs(600);
    h.db.record_block(
        kept,
        Some("x.test"),
        SignalSource::Probe,
        SignalType::Challenge,
        Some(until),
    )
    .await?;
    let (status, report) = h.get("/v1/inventory/replacements").await;
    assert_eq!(status, StatusCode::OK);
    let items = report["items"].as_array().expect("items");
    assert_eq!(items.len(), 1, "{report}");
    let item = &items[0];
    assert_eq!(item["ip"], "203.0.113.10");
    assert_eq!(item["plan"], "p");
    assert_eq!(item["rental_end"], "2027-01-01");
    assert_eq!(item["scores"].as_array().expect("scores").len(), 2);
    assert_eq!(item["blocks_by_target"], json!({ "*": 1, "x.test": 1 }));
    Ok(())
}

// --- policies ---

#[tokio::test]
async fn policy_writes_are_checked_as_a_set_before_they_are_stored() -> TestResult {
    let h = or_skip!(harness("policies").await?);
    h.seed_ips(1).await?; // a policy needs a region some adapter can serve
    let (_, list) = h.get("/v1/policies").await;
    assert_eq!(list["items"].as_array().expect("items").len(), 2);

    // min_ready above max_ready: refused, version unchanged
    let bad = json!({ "policies": [{ "name": "global", "regions": ["fr"], "min_ready": 50, "max_ready": 10 }] });
    let (status, out) = h.put("/v1/policies", bad).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{out}");
    assert_eq!(h.db.policy_versions("global", "global").await?.len(), 1);

    // valid change: a new version by the named operator
    let good = json!({ "policies": [{ "name": "global", "regions": ["fr"], "min_ready": 3 }] });
    let (status, out) = h
        .send_as_operator(Method::PUT, "/v1/policies", "ana@example.com", Some(good))
        .await;
    assert_eq!(status, StatusCode::OK, "{out}");
    assert_eq!(out["stored"], json!(["global/global"]));
    let versions = h.db.policy_versions("global", "global").await?;
    assert_eq!(
        (versions[0].version, versions[0].actor.as_str()),
        (2, "ana@example.com")
    );

    // an unknown field and an empty list are refused
    let (status, _) = h
        .put(
            "/v1/policies",
            json!({ "policies": [{ "name": "x", "bogus": 1 }] }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = h.put("/v1/policies", json!({ "policies": [] })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn org_cache_policy_cannot_exceed_a_ceiling_or_name_another_scope() -> TestResult {
    let h = or_skip!(harness("cachepolicy").await?);
    h.seed_ips(1).await?;
    let path = "/v1/orgs/acme/cache-policy";
    // the global ceiling is 10 GB/day
    let (status, out) = h
        .put(
            path,
            json!({ "min_ready": 4, "cost": { "max_gb_per_day": 99 } }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{out}");
    assert!(error_of(&out).contains("ceiling"), "{out}");
    assert!(
        h.db.current_policies()
            .await?
            .iter()
            .all(|r| r.scope != "org"),
        "a refused policy is not stored"
    );

    let ok = json!({ "cost": { "max_gb_per_day": 8 } });
    let (status, out) = h.put(path, ok.clone()).await;
    assert_eq!(status, StatusCode::OK, "{out}");
    assert_eq!(out["stored"], json!(["org/org-acme"]));
    let (_, again) = h.put(path, ok).await;
    assert_eq!(again["unchanged"], 1, "{again}");

    for body in [
        json!({ "scope": "global" }),
        json!({ "match": "other" }),
        json!({ "bogus": 1 }),
        json!(5),
    ] {
        let (status, out) = h.put(path, body.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {out}");
    }
    let (status, _) = h.put("/v1/orgs/BAD/cache-policy", json!({})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    Ok(())
}

// --- org keys ---

#[tokio::test]
async fn key_creation_requires_json_content_type_only_when_a_body_is_present() -> TestResult {
    let h = or_skip!(harness("key_content_type").await?);
    let url = format!("{}/v1/orgs/acme/keys", h.base);
    for content_type in [None, Some("text/plain")] {
        let mut request = h.client.post(&url).bearer_auth(ADMIN).body("{}");
        if let Some(value) = content_type {
            request = request.header("content-type", value);
        }
        let response = request.send().await?;
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        let body: Value = response.json().await?;
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("Content-Type")
        );
    }
    let response = h.client.post(&url).bearer_auth(ADMIN).send().await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let response = h
        .client
        .post(&url)
        .bearer_auth(ADMIN)
        .header("content-type", "application/vnd.example+json")
        .body(r#"{"label":"json"}"#)
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    Ok(())
}

#[tokio::test]
async fn a_new_org_key_is_returned_once_and_only_its_hash_is_stored() -> TestResult {
    let h = or_skip!(harness("keys").await?);
    let resp = h
        .client
        .post(format!("{}/v1/orgs/acme/keys", h.base))
        .bearer_auth(ADMIN)
        .json(&json!({ "label": "ci" }))
        .send()
        .await?;
    assert_eq!(resp.status(), StatusCode::CREATED);
    assert_eq!(resp.headers()["cache-control"], "no-store");
    let body: Value = resp.json().await?;
    let key = body["key"].as_str().expect("key").to_owned();
    assert!(key.starts_with("ak_") && key.len() >= 40, "{key}");
    assert_eq!(
        h.db.verify_org_key(&key).await?,
        store::KeyStatus::Enabled(org("acme"))
    );

    let stored = h
        .raw
        .int(
            "SELECT count(*) FROM org_keys WHERE org = 'acme' AND key_hash = ?",
            &[(&store::hash_org_key(&key)[..]).into()],
        )
        .await?;
    assert_eq!(stored, 1);
    let plaintext = h
        .raw
        .int(
            "SELECT count(*) FROM org_keys WHERE label = ? OR key_hash = ?",
            &[key.as_str().into(), key.as_bytes().into()],
        )
        .await?;
    assert_eq!(plaintext, 0, "the key itself is nowhere in the table");

    let (_, second) = h.admin(Method::POST, "/v1/orgs/acme/keys", None).await;
    assert_ne!(second["key"], body["key"], "every call mints a fresh key");

    let (status, _) = h.admin(Method::POST, "/v1/orgs/BAD/keys", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let long = "x".repeat(200);
    let (status, _) = h.post("/v1/orgs/acme/keys", json!({ "label": long })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, out) = h.delete("/v1/orgs/acme/keys").await;
    assert_eq!((status, &out["disabled"]), (StatusCode::OK, &json!(2)));
    assert_eq!(
        h.db.verify_org_key(&key).await?,
        store::KeyStatus::Disabled,
        "a disabled key stops working"
    );
    Ok(())
}

// --- org blocks ---

#[tokio::test]
async fn org_block_caches_drains_the_scope_and_lifts_only_when_no_block_remains() -> TestResult {
    let h = or_skip!(harness("orgblocks").await?);
    let acme = org(&uniq("acme"));
    let new_block = |ttl: Option<&str>| {
        let mut b =
            json!({ "org": acme, "scope": "ip", "value": "203.0.113.9", "reason": "abuse" });
        if let Some(ttl) = ttl {
            b["ttl"] = json!(ttl);
        }
        b
    };

    let (status, first) = h.post("/v1/org-blocks", new_block(Some("1h"))).await;
    assert_eq!(status, StatusCode::CREATED, "{first}");
    assert_eq!(
        first["drained"], 2,
        "the open tunnels in scope were asked to close"
    );
    let left = first["expires_at"].as_i64().expect("expiry") - now();
    assert!((3_590..=3_610).contains(&left), "{left}");
    let calls = h.tunnels.calls.lock().clone();
    assert_eq!(
        calls,
        vec![(acme.clone(), BlockScope::Ip("203.0.113.9".parse()?))]
    );
    assert_eq!(
        h.hot.org_blocks(&acme).await?,
        vec!["ip:203.0.113.9".to_owned()]
    );

    let (_, listed) = h.get(&format!("/v1/org-blocks?org={acme}")).await;
    assert_eq!(listed["items"].as_array().expect("items").len(), 1);
    let (_, none) = h.get("/v1/org-blocks?org=someone_else").await;
    assert!(none["items"].as_array().expect("items").is_empty());

    // validation: nothing is stored or drained
    let before = h.tunnels.calls.lock().len();
    for body in [
        json!({ "org": acme, "scope": "ip", "value": "203.0.113.9", "reason": "" }),
        json!({ "org": acme, "scope": "zone", "value": "x", "reason": "r" }),
        json!({ "org": acme, "scope": "ip", "value": "not-an-ip", "reason": "r" }),
        json!({ "org": acme, "scope": "ip", "value": "203.0.113.9", "reason": "r", "ttl": "0s" }),
        json!({ "org": acme, "scope": "ip", "value": "203.0.113.9", "reason": "r", "ttl": "soon" }),
        json!({ "scope": "ip", "value": "203.0.113.9", "reason": "r" }),
        json!({ "org": acme, "scope": "ip", "value": "203.0.113.9", "reason": "r", "extra": 1 }),
    ] {
        let (status, out) = h.post("/v1/org-blocks", body.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {out}");
        error_of(&out);
    }
    assert_eq!(h.tunnels.calls.lock().len(), before);

    // two blocks of one scope: the cache field stays until the last is lifted
    let (_, second) = h.post("/v1/org-blocks", new_block(None)).await;
    let (first_id, second_id) = (
        first["id"].as_str().expect("id"),
        second["id"].as_str().expect("id"),
    );
    let (status, _) = h.delete(&format!("/v1/org-blocks/{first_id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        h.hot.org_blocks(&acme).await?.len(),
        1,
        "the second block still holds"
    );
    let (status, _) = h.delete(&format!("/v1/org-blocks/{second_id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(h.hot.org_blocks(&acme).await?.is_empty());
    let (status, _) = h.delete(&format!("/v1/org-blocks/{second_id}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "already lifted");
    let (status, _) = h.delete("/v1/org-blocks/nope").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    Ok(())
}

// --- block signals ---

fn event(session: &str, ip: IpAddr, target: &str, ty: &str) -> Value {
    json!({ "session": session, "exit_ip": ip, "org": "ignored", "target": target,
            "type": ty, "status": 429, "time": now() })
}

/// A batch with one `ty` event of the session per host in `hosts` (port 443).
fn events(session: &str, ip: IpAddr, ty: &str, hosts: &[&str]) -> Value {
    hosts
        .iter()
        .map(|host| event(session, ip, &format!("{host}:443"), ty))
        .collect()
}

async fn post_signals(h: &Harness, key: &str, events: Value) -> (StatusCode, Value) {
    h.send(
        Method::POST,
        "/v1/block-signals",
        Some(&basic("px-kind-static-cc-fr", key)),
        Some(events),
    )
    .await
}

fn count(h: &Harness, source: &str, ty: &str, scope: &str) -> u64 {
    h.metrics
        .block_signals_total
        .with_label_values(&[source, ty, scope])
        .get()
}

#[tokio::test]
async fn a_client_signal_cools_only_its_target() -> TestResult {
    let h = or_skip!(harness("sig_target").await?);
    let (acme, p) = (org(&uniq("acme")), h.partition());
    let key = h.org_key(&acme).await?;
    let ips = h.seed_ips(3).await?;
    let session = h.session(&acme, &ips[0].to_string(), ips[0]).await?;

    let (status, out) = post_signals(
        &h,
        &key,
        events(&session, ips[0], "rate_limited", &["a.test"]),
    )
    .await;
    assert_eq!(
        (status, &out),
        (StatusCode::OK, &json!({ "accepted": 1, "ignored": 0 }))
    );
    assert!(h.hot.is_cooled(&p, ips[0], &target("a.test")).await?);
    assert!(
        !h.hot.is_cooled(&p, ips[0], &target("b.test")).await?,
        "other targets keep the ip"
    );
    assert_eq!(h.state_of(ips[0]).await, IpState::Available);
    assert!(h.hot.ready_ids(&p).await?.contains(&ips[0].to_string()));
    assert_eq!(count(&h, "client", "rate_limited", "target"), 1);

    // the cooldown is also in Postgres, so a Redis loss rebuilds it
    let since = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
    let blocks = h.db.blocks_since(ips[0], since).await?;
    assert!(blocks.iter().any(|b| b.target.as_deref() == Some("a.test")));
    Ok(())
}

#[tokio::test]
async fn a_batch_with_one_invalid_event_applies_none_of_the_others() -> TestResult {
    let h = or_skip!(harness("sig_batch").await?);
    let (acme, p) = (org(&uniq("acme")), h.partition());
    let key = h.org_key(&acme).await?;
    let ips = h.seed_ips(1).await?;
    let session = h.session(&acme, &ips[0].to_string(), ips[0]).await?;

    let batch = json!([
        event(&session, ips[0], "a.test:443", "reset"),
        event(&session, ips[0], "a b:443", "reset"),
    ]);
    let (status, _) = post_signals(&h, &key, batch).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        !h.hot.is_cooled(&p, ips[0], &target("a.test")).await?,
        "a retry of the batch must not count the first event twice"
    );
    assert_eq!(count(&h, "client", "reset", "target"), 0);
    Ok(())
}

#[tokio::test]
async fn signals_for_sessions_of_another_org_or_ip_are_ignored() -> TestResult {
    let h = or_skip!(harness("sig_org").await?);
    let (acme, other, p) = (org(&uniq("acme")), org(&uniq("other")), h.partition());
    let key = h.org_key(&acme).await?;
    let ips = h.seed_ips(2).await?;
    let theirs = h.session(&other, &ips[0].to_string(), ips[0]).await?;
    let mine = h.session(&acme, &ips[1].to_string(), ips[1]).await?;

    let events = json!([
        event(&theirs, ips[0], "a.test:443", "forbidden"),
        event("unknown-session", ips[0], "a.test:443", "forbidden"),
        event(&mine, ips[0], "a.test:443", "forbidden"),
    ]);
    let (status, out) = post_signals(&h, &key, events).await;
    assert_eq!(
        (status, &out),
        (StatusCode::OK, &json!({ "accepted": 0, "ignored": 3 }))
    );
    assert_eq!(
        h.metrics.block_signals_ignored_total.get(),
        3,
        "dropped signals are counted"
    );
    for ip in &ips {
        assert!(!h.hot.is_cooled(&p, *ip, &target("a.test")).await?, "{ip}");
    }
    Ok(())
}

#[tokio::test]
async fn three_distinct_targets_take_a_static_ip_out_of_leasing() -> TestResult {
    let h = or_skip!(harness("sig_escalate").await?);
    let (acme, p) = (org(&uniq("acme")), h.partition());
    let key = h.org_key(&acme).await?;
    let ips = h.seed_ips(3).await?;
    let session = h.session(&acme, &ips[0].to_string(), ips[0]).await?;

    let two = events(&session, ips[0], "challenge", &["a.test", "b.test"]);
    post_signals(&h, &key, two).await;
    assert_eq!(
        h.state_of(ips[0]).await,
        IpState::Available,
        "two targets are not enough"
    );

    let (status, _) =
        post_signals(&h, &key, events(&session, ips[0], "challenge", &["c.test"])).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h.state_of(ips[0]).await, IpState::Cooldown);
    assert!(!h.hot.ready_ids(&p).await?.contains(&ips[0].to_string()));
    let row = h.db.inventory_row(ips[0]).await?.expect("row");
    let left =
        (row.cooldown_until.expect("deadline") - time::OffsetDateTime::now_utc()).whole_seconds();
    assert!(
        (880..=900).contains(&left),
        "the policy cooldown (15 min), not the target one: {left}"
    );
    assert_eq!(
        (
            count(&h, "client", "challenge", "target"),
            count(&h, "client", "challenge", "ip")
        ),
        (2, 1)
    );
    assert!(
        h.hot.ready_ids(&p).await?.contains(&ips[1].to_string()),
        "other ips keep serving"
    );
    Ok(())
}

#[tokio::test]
async fn five_signals_on_one_target_escalate_too() -> TestResult {
    let h = or_skip!(harness("sig_count").await?);
    let acme = org(&uniq("acme"));
    let key = h.org_key(&acme).await?;
    let ips = h.seed_ips(3).await?;
    let session = h.session(&acme, &ips[0].to_string(), ips[0]).await?;

    let four: Vec<Value> = (0..4)
        .map(|_| event(&session, ips[0], "a.test:443", "rate_limited"))
        .collect();
    post_signals(&h, &key, json!(four)).await;
    assert_eq!(h.state_of(ips[0]).await, IpState::Available);
    post_signals(
        &h,
        &key,
        events(&session, ips[0], "rate_limited", &["a.test"]),
    )
    .await;
    assert_eq!(h.state_of(ips[0]).await, IpState::Cooldown);
    Ok(())
}

/// A slow IP is still leasable, so blocks still take it out of leasing.
#[tokio::test]
async fn blocks_take_a_degraded_ip_out_of_leasing_too() -> TestResult {
    let h = or_skip!(harness("sig_degraded").await?);
    let (acme, p) = (org(&uniq("acme")), h.partition());
    let key = h.org_key(&acme).await?;
    let ips = h.seed_ips(3).await?;
    h.db.transition_ip(
        ips[0],
        &store::Transition::to(IpState::Degraded, "test"),
        "test",
    )
    .await?;
    h.hot
        .set_tier(&p, &ips[0].to_string(), Tier::Degraded)
        .await?;
    let session = h.session(&acme, &ips[0].to_string(), ips[0]).await?;

    let three = events(
        &session,
        ips[0],
        "challenge",
        &["a.test", "b.test", "c.test"],
    );
    post_signals(&h, &key, three).await;
    assert_eq!(h.state_of(ips[0]).await, IpState::Cooldown);
    assert!(!h.hot.ready_ids(&p).await?.contains(&ips[0].to_string()));
    Ok(())
}

#[tokio::test]
async fn the_pool_guard_stops_escalation_but_keeps_the_target_cooldown() -> TestResult {
    let h = or_skip!(harness("sig_guard").await?);
    let (acme, p) = (org(&uniq("acme")), h.partition());
    let key = h.org_key(&acme).await?;
    let ips = h.seed_ips(2).await?;
    // half of the partition is already cooled
    h.db.transition_ip(
        ips[1],
        &store::Transition::to(IpState::Cooldown, "test")
            .cooldown_until(time::OffsetDateTime::now_utc() + std::time::Duration::from_secs(600)),
        "test",
    )
    .await?;
    h.hot.ready_take(&p, &ips[1].to_string()).await?;
    let session = h.session(&acme, &ips[0].to_string(), ips[0]).await?;

    let three = events(
        &session,
        ips[0],
        "forbidden",
        &["a.test", "b.test", "c.test"],
    );
    let (status, _) = post_signals(&h, &key, three).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        h.state_of(ips[0]).await,
        IpState::Available,
        "the last healthy ip is not cooled"
    );
    assert!(h.hot.ready_ids(&p).await?.contains(&ips[0].to_string()));
    for host in ["a.test", "b.test", "c.test"] {
        assert!(h.hot.is_cooled(&p, ips[0], &target(host)).await?, "{host}");
    }
    assert_eq!(count(&h, "client", "forbidden", "pool_guard"), 1);
    assert_eq!(count(&h, "client", "forbidden", "ip"), 0);
    Ok(())
}

#[tokio::test]
async fn a_rotating_session_is_drained_on_escalation() -> TestResult {
    // the adapter of the session's partition says it is rotating
    let rotating = r#"
[[adapter]]
id = "rot"
kind = "rotating"
subtype = "residential"
host = "127.0.0.1"
port = 9
credentials_optional = true
user = "u{opts}"

[[adapter.option]]
name = "sid"
to = "user"
frag = "-s-{v}"
charset = "alnum"
len = 12

[[adapter.option]]
name = "country"
to = "user"
frag = "-c-{v}"
"#;
    let h = or_skip!(
        harness_with(
            "sig_rotating",
            Options {
                adapters_toml: Some(rotating),
                ..Options::default()
            },
        )
        .await?
    );
    let acme = org(&uniq("acme"));
    let p = common::types::Partition {
        provider: "rot".parse()?,
        region: "fr".parse()?,
    };
    let key = h.org_key(&acme).await?;
    let ip: IpAddr = "198.51.100.7".parse()?;
    let unit = uniq("sess");
    h.hot
        .ready_put(
            &p,
            &store::UnitRecord {
                id: unit.clone(),
                ip,
                expires_at: None,
                ttl: None,
                owner: None,
            },
        )
        .await?;
    let session = uniq("sid");
    h.hot
        .session_put(
            &session,
            &store::SessionRecord {
                org: acme.clone(),
                partition: p.clone(),
                unit: unit.clone(),
                ip,
            },
            std::time::Duration::from_secs(600),
        )
        .await?;

    let three = events(&session, ip, "challenge", &["a.test", "b.test", "c.test"]);
    post_signals(&h, &key, three).await;
    assert!(
        !h.hot.ready_ids(&p).await?.contains(&unit),
        "the session no longer takes leases"
    );
    assert_eq!(
        h.metrics
            .cache_evictions_total
            .with_label_values(&["block"])
            .get(),
        1
    );
    assert!(h.hot.is_cooled(&p, ip, &target("a.test")).await?);
    Ok(())
}

#[tokio::test]
async fn repeated_ip_wide_blocks_within_an_hour_quarantine_the_ip() -> TestResult {
    let h = or_skip!(harness("sig_quarantine").await?);
    let (acme, p) = (org(&uniq("acme")), h.partition());
    let key = h.org_key(&acme).await?;
    let ips = h.seed_ips(4).await?;
    let ip = ips[0];
    let session = h.session(&acme, &ip.to_string(), ip).await?;
    let three = events(&session, ip, "forbidden", &["a.test", "b.test", "c.test"]);
    post_signals(&h, &key, three).await;
    assert_eq!(h.state_of(ip).await, IpState::Cooldown);

    // while it rests, late signals from older tunnels do not count again
    post_signals(&h, &key, events(&session, ip, "forbidden", &["d.test"])).await;
    assert_eq!(h.state_of(ip).await, IpState::Cooldown);

    // retest passes, it returns, and is blocked again: second block, still a cooldown
    for round in 2..=3 {
        h.db.transition_ip(
            ip,
            &store::Transition::to(IpState::Available, "retest"),
            "test",
        )
        .await?;
        h.hot
            .ready_put(&p, &store::UnitRecord::static_ip(ip))
            .await?;
        // each round is another batch (a batch sent again is not counted twice)
        let mut again = event(&session, ip, "e.test:443", "forbidden");
        again["time"] = json!(now() - round);
        post_signals(&h, &key, json!([again])).await;
        let want = if round == 3 {
            IpState::Quarantined
        } else {
            IpState::Cooldown
        };
        assert_eq!(h.state_of(ip).await, want, "block number {round}");
    }
    let row = h.db.inventory_row(ip).await?.expect("row");
    assert!(
        row.retest_at.is_some(),
        "a quarantined ip has a retest time"
    );
    assert!(!h.hot.ready_ids(&p).await?.contains(&ip.to_string()));
    Ok(())
}

#[tokio::test]
async fn signal_requests_are_authenticated_and_validated() -> TestResult {
    let h = or_skip!(harness("sig_input").await?);
    let acme = org(&uniq("acme"));
    let key = h.org_key(&acme).await?;
    let ips = h.seed_ips(1).await?;
    let session = h.session(&acme, &ips[0].to_string(), ips[0]).await?;
    let ok_event = event(&session, ips[0], "a.test:443", "reset");

    let (status, _) = h
        .send(Method::POST, "/v1/block-signals", None, Some(json!([])))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = post_signals(&h, "not-a-key", json!([ok_event.clone()])).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    h.db.disable_org_keys(&acme, "test").await?;
    let (status, out) = post_signals(&h, &key, json!([ok_event.clone()])).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "a disabled key is refused");
    assert_eq!(out["error"], "org_disabled");
    let key = h.org_key(&acme).await?;

    let bad_type = json!([{ "session": session, "exit_ip": ips[0], "target": "a.test:443", "type": "melted", "time": now() }]);
    let bad_ip = json!([{ "session": session, "exit_ip": "999.1.1.1", "target": "a.test:443", "type": "reset", "time": now() }]);
    let bad_target = json!([{ "session": session, "exit_ip": ips[0], "target": "a b:443", "type": "reset", "time": now() }]);
    for body in [json!({ "not": "an array" }), bad_type, bad_ip, bad_target] {
        let (status, out) = post_signals(&h, &key, body.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {out}");
        error_of(&out);
    }
    let too_many = Value::Array(vec![ok_event.clone(); 501]);
    let (status, _) = post_signals(&h, &key, too_many).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, out) = post_signals(&h, &key, json!([])).await;
    assert_eq!(
        (status, &out),
        (StatusCode::OK, &json!({ "accepted": 0, "ignored": 0 }))
    );
    let mut stale = ok_event;
    stale["time"] = json!(now() - 7_200);
    let (_, out) = post_signals(&h, &key, json!([stale])).await;
    assert_eq!(
        out["ignored"], 1,
        "an event from two hours ago says nothing about the ip now"
    );
    Ok(())
}

// --- operator reports ---

#[tokio::test]
async fn an_operator_report_cools_a_target_or_the_whole_ip() -> TestResult {
    let h = or_skip!(harness("operator").await?);
    let p = h.partition();
    let ips = h.seed_ips(3).await?;
    let box_ip = h.seed_ips_of(1, Subtype::MobileBox).await?[0];

    let path = |ip: IpAddr| format!("/v1/ips/{ip}/block");
    let (status, out) = h
        .post(
            &path(ips[0]),
            json!({ "target": "a.test:443", "type": "rate_limited" }),
        )
        .await;
    assert_eq!(
        (status, &out["scope"]),
        (StatusCode::OK, &json!("target")),
        "{out}"
    );
    assert!(h.hot.is_cooled(&p, ips[0], &target("a.test")).await?);
    assert_eq!(count(&h, "operator", "rate_limited", "target"), 1);

    let (_, out) = h.post(&path(ips[1]), json!({})).await;
    assert_eq!(out["scope"], "ip", "{out}");
    assert_eq!(h.state_of(ips[1]).await, IpState::Cooldown);
    assert!(!h.hot.ready_ids(&p).await?.contains(&ips[1].to_string()));

    // a SIM box is also flagged for a reset
    h.post(&path(box_ip), json!({})).await;
    assert_eq!(h.state_of(box_ip).await, IpState::Cooldown);
    let audit = h.db.audit_for(&box_ip.to_string(), 10).await?;
    assert!(
        audit.iter().any(|a| a.action == "ip.rotate_requested"),
        "{audit:?}"
    );

    let (status, _) = h.post(&path("203.0.113.250".parse()?), json!({})).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "an unknown ip needs a session"
    );
    let (status, _) = h.post("/v1/ips/not-an-ip/block", json!({})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = h.post(&path(ips[2]), json!({ "bogus": 1 })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    Ok(())
}

// --- prober ---

fn run(outcome: &str, ttfb: u32, load: u32) -> Value {
    json!({ "target": "https://t.test/", "run": 1, "outcome": outcome, "status": 200,
            "ttfb_ms": ttfb, "dom_content_loaded_ms": load, "load_ms": load })
}

fn results(h: &Harness, kind: &str, job: Option<&str>, runs: Vec<Value>) -> Value {
    json!({ "job_id": job, "kind": kind, "route_class": "fr-web", "provider": h.provider,
            "region": "fr", "country": "fr", "session": "sid1",
            "started_at": "2026-10-15T10:00:00Z", "results": runs })
}

#[tokio::test]
async fn probe_targets_list_route_classes_with_pages_and_pending_samples() -> TestResult {
    let h = or_skip!(harness("probe_targets").await?);
    // global pages, then the country's, from the loaded probe targets
    h.hot
        .sample_put(
            &SampleJob {
                job_id: "job1".into(),
                route_class: "fr-web".into(),
                provider: h.provider.parse()?,
                region: "fr".parse()?,
                sid: Some("cand1".into()),
                targets: vec!["https://fr.test/".into()],
            },
            std::time::Duration::from_secs(60),
        )
        .await?;
    let (_, out) = h.probe_targets().await;
    assert_eq!(
        out["route_classes"],
        json!([{ "route_class": "fr-web", "provider": h.provider,
                 "regions": [{ "region": "fr", "country": "fr",
                               "targets": ["https://any.test/", "https://fr.test/"] }] }])
    );
    let sample = out["samples"]
        .as_array()
        .expect("samples")
        .iter()
        .find(|s| s["job_id"] == "job1")
        .expect("job1");
    assert_eq!(
        (&sample["sid"], &sample["country"]),
        (&json!("cand1"), &json!("fr"))
    );

    // the result ends the listing
    let done = results(&h, "sample", Some("job1"), vec![run("ok", 100, 800)]);
    let (status, _) = h.probe_results(done).await;
    assert_eq!(status, StatusCode::OK);
    let (_, out) = h.probe_targets().await;
    assert!(
        out["samples"]
            .as_array()
            .expect("samples")
            .iter()
            .all(|s| s["job_id"] != "job1")
    );
    Ok(())
}

/// A provider without a route-class policy is probed as a class of its
/// own, also when other providers have one.
#[tokio::test]
async fn every_provider_is_probed_when_only_some_have_a_route_class_policy() -> TestResult {
    let adapters: String = ["rc_a", "rc_b"]
        .iter()
        .map(|id| {
            format!(
                "[[adapter]]\nid = \"{id}\"\nkind = \"static\"\nsubtype = \"isp\"\n\
                 scheme = \"http\"\ncredentials_optional = true\nuser = \"{{base_user}}\"\n\
                 pass = \"{{base_pass}}\"\n"
            )
        })
        .collect();
    let h = or_skip!(
        harness_with(
            "probe_all_providers",
            Options {
                adapters_toml: Some(&adapters),
                extra_policies: "\n[[policy]]\nname = \"rc-a\"\nscope = \"route_class\"\nmatch = \"rc_a\"\nregions = [\"fr\"]\n",
                ..Options::default()
            },
        )
        .await?
    );
    let (_, out) = h.probe_targets().await;
    let mut classes: Vec<(String, String)> = out["route_classes"]
        .as_array()
        .expect("route classes")
        .iter()
        .map(|c| {
            (
                c["route_class"].as_str().expect("name").to_owned(),
                c["provider"].as_str().expect("provider").to_owned(),
            )
        })
        .filter(|(_, provider)| provider.starts_with("rc_"))
        .collect();
    classes.sort();
    assert_eq!(
        classes,
        [
            ("rc-a".to_owned(), "rc_a".to_owned()),
            ("rc_b".to_owned(), "rc_b".to_owned())
        ]
    );
    Ok(())
}

#[tokio::test]
async fn a_failed_canary_drains_the_route_class_and_a_passing_one_resumes_warming() -> TestResult {
    let h = or_skip!(harness("probe_canary").await?);
    let p = h.partition();
    let ips = h.seed_ips(2).await?;
    let sess_ip: IpAddr = "198.51.100.8".parse()?;
    h.hot
        .ready_put(
            &p,
            &store::UnitRecord {
                id: uniq("sess"),
                ip: sess_ip,
                expires_at: None,
                ttl: None,
                owner: None,
            },
        )
        .await?;
    assert_eq!(h.hot.ready_ids(&p).await?.len(), 3);

    // 1 of 3 runs is good (min_success 0.66): the canary fails
    let failing = results(
        &h,
        "canary",
        None,
        vec![
            run("ok", 100, 800),
            run("timeout", 0, 0),
            run("blocked", 100, 800),
        ],
    );
    let (status, out) = h.probe_results(failing).await;
    assert_eq!(status, StatusCode::OK, "{out}");
    assert_eq!(out["verdict"]["ok"], false);
    assert_eq!(out["drained"], 3);
    assert!(
        h.hot.ready_ids(&p).await?.is_empty(),
        "nothing of the route class takes leases"
    );
    for ip in &ips {
        assert_eq!(h.state_of(*ip).await, IpState::Cooldown, "{ip}");
    }
    assert!(h.hot.warm_paused(&p).await?, "warming is paused");
    let verdict = h
        .hot
        .verdict_get(&format!("canary:{}", p.tag()))
        .await?
        .expect("verdict");
    assert!(
        !verdict.ok && verdict.detail.contains("1 of 3"),
        "{verdict:?}"
    );
    assert_eq!(count(&h, "canary", "challenge", "route_class"), 1);

    // the next canary passes: warming resumes (cooled IPs wait for their retest)
    let passing = results(
        &h,
        "canary",
        None,
        vec![
            run("ok", 100, 800),
            run("ok", 200, 900),
            run("ok", 300, 1000),
        ],
    );
    let (_, out) = h.probe_results(passing).await;
    assert_eq!(
        (out["verdict"]["ok"].clone(), out["drained"].clone()),
        (json!(true), json!(0))
    );
    assert!(!h.hot.warm_paused(&p).await?);
    assert_eq!(h.state_of(ips[0]).await, IpState::Cooldown);
    Ok(())
}

/// A canary whose pages loaded but over the load limit moves the route
/// class to the degraded tier and keeps leasing; a canary that sees blocks
/// still drains it, degraded units included.
#[tokio::test]
async fn a_slow_canary_degrades_the_route_class_and_a_blocked_one_still_drains_it() -> TestResult {
    let h = or_skip!(harness("probe_canary_slow").await?);
    let p = h.partition();
    let ips = h.seed_ips(2).await?;
    let sess = uniq("sess");
    h.hot
        .ready_put(
            &p,
            &store::UnitRecord {
                id: sess.clone(),
                ip: "198.51.100.9".parse()?,
                expires_at: None,
                ttl: None,
                owner: None,
            },
        )
        .await?;

    // all runs loaded, all over max_load_ms (10 s): slow, not bad
    let slow = results(
        &h,
        "canary",
        None,
        vec![
            run("ok", 100, 12_000),
            run("ok", 100, 12_000),
            run("ok", 100, 12_000),
        ],
    );
    let (status, out) = h.probe_results(slow).await;
    assert_eq!(status, StatusCode::OK, "{out}");
    assert_eq!(
        (out["verdict"]["ok"].clone(), out["verdict"]["slow"].clone()),
        (json!(false), json!(true))
    );
    assert_eq!(
        (out["drained"].clone(), out["degraded"].clone()),
        (json!(0), json!(3))
    );
    assert_eq!(h.hot.ready_ids(&p).await?.len(), 3, "still leasable");
    for ip in &ips {
        assert_eq!(h.state_of(*ip).await, IpState::Degraded, "{ip}");
        assert_eq!(h.hot.tier(&p, &ip.to_string()).await?, Tier::Degraded);
    }
    assert_eq!(h.hot.tier(&p, &sess).await?, Tier::Degraded);
    assert!(!h.hot.warm_paused(&p).await?, "warming goes on");

    // blocks are not slowness: the class is drained, the degraded IPs cool
    let blocked = results(
        &h,
        "canary",
        None,
        vec![
            run("ok", 100, 12_000),
            run("blocked", 100, 800),
            run("blocked", 100, 800),
        ],
    );
    let (_, out) = h.probe_results(blocked).await;
    assert_eq!(
        (out["verdict"]["slow"].clone(), out["drained"].clone()),
        (json!(false), json!(3))
    );
    for ip in &ips {
        assert_eq!(h.state_of(*ip).await, IpState::Cooldown, "{ip}");
    }
    assert!(h.hot.warm_paused(&p).await?);
    Ok(())
}

/// A canary that passes at full speed returns the units a slow canary
/// degraded to normal, and a slow canary with one error drains the class.
#[tokio::test]
async fn a_fast_canary_promotes_a_degraded_route_class_and_an_error_drains_it() -> TestResult {
    let h = or_skip!(harness("probe_canary_promote").await?);
    let p = h.partition();
    let ips = h.seed_ips(2).await?;
    let sess = uniq("sess");
    h.hot
        .ready_put(
            &p,
            &store::UnitRecord {
                id: sess.clone(),
                ip: "198.51.100.9".parse()?,
                expires_at: None,
                ttl: None,
                owner: None,
            },
        )
        .await?;
    let slow = || {
        results(
            &h,
            "canary",
            None,
            vec![
                run("ok", 100, 12_000),
                run("ok", 100, 12_000),
                run("ok", 100, 12_000),
            ],
        )
    };
    let fast = || {
        results(
            &h,
            "canary",
            None,
            vec![
                run("ok", 100, 800),
                run("ok", 100, 800),
                run("ok", 100, 800),
            ],
        )
    };

    let (_, out) = h.probe_results(slow()).await;
    assert_eq!(out["degraded"], 3, "{out}");
    let (_, out) = h.probe_results(fast()).await;
    assert_eq!(
        (out["verdict"]["ok"].clone(), out["promoted"].clone()),
        (json!(true), json!(3)),
        "{out}"
    );
    for ip in &ips {
        assert_eq!(h.state_of(*ip).await, IpState::Available, "{ip}");
        assert_eq!(h.hot.tier(&p, &ip.to_string()).await?, Tier::Normal);
    }
    assert_eq!(h.hot.tier(&p, &sess).await?, Tier::Normal);
    assert_eq!(h.hot.ready_ids(&p).await?.len(), 3, "leasable throughout");

    // two slow pages and one error: not slowness, the class drains
    let mixed = results(
        &h,
        "canary",
        None,
        vec![
            run("ok", 100, 12_000),
            run("ok", 100, 12_000),
            run("error", 0, 0),
        ],
    );
    let (_, out) = h.probe_results(mixed).await;
    assert_eq!(
        (out["verdict"]["slow"].clone(), out["drained"].clone()),
        (json!(false), json!(3)),
        "{out}"
    );
    assert!(h.hot.warm_paused(&p).await?);
    Ok(())
}

#[tokio::test]
async fn a_sample_result_becomes_a_verdict_and_touches_nothing_else() -> TestResult {
    let h = or_skip!(harness("probe_sample").await?);
    let p = h.partition();
    let ips = h.seed_ips(1).await?;

    // one run over max_load_ms: only 1 of 2 is good, below 0.66
    let slow = results(
        &h,
        "sample",
        Some("jobslow"),
        vec![run("ok", 100, 800), run("ok", 100, 10_001)],
    );
    let (status, out) = h.probe_results(slow).await;
    assert_eq!(status, StatusCode::OK, "{out}");
    assert_eq!(out["verdict"]["ok"], false);
    let verdict = h.hot.verdict_get("jobslow").await?.expect("verdict");
    assert!(
        !verdict.ok && (verdict.success_ratio - 0.5).abs() < 1e-9,
        "{verdict:?}"
    );
    assert!(
        !h.hot.warm_paused(&p).await?,
        "a sample never pauses warming"
    );
    assert_eq!(h.state_of(ips[0]).await, IpState::Available);
    assert!(h.hot.ready_ids(&p).await?.contains(&ips[0].to_string()));

    let fast = results(
        &h,
        "sample",
        Some("jobfast"),
        vec![run("ok", 100, 800), run("ok", 100, 10_000)],
    );
    h.probe_results(fast).await;
    assert!(
        h.hot.verdict_get("jobfast").await?.expect("verdict").ok,
        "the limit itself is allowed"
    );

    // validation
    for (label, body) in [
        (
            "sample without a job",
            results(&h, "sample", None, vec![run("ok", 1, 1)]),
        ),
        ("no runs", results(&h, "canary", None, vec![])),
        (
            "unknown outcome",
            results(&h, "canary", None, vec![run("exploded", 1, 1)]),
        ),
        (
            "unknown kind",
            results(&h, "weekly", None, vec![run("ok", 1, 1)]),
        ),
        (
            "a job id that names another verdict key",
            results(&h, "sample", Some("canary:fr"), vec![run("ok", 1, 1)]),
        ),
    ] {
        let (status, out) = h.probe_results(body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{label}: {out}");
        error_of(&out);
    }
    Ok(())
}

#[tokio::test]
async fn the_prober_gets_at_most_100_targets_per_region_and_per_sample() -> TestResult {
    let h = or_skip!(
        harness_with(
            "probe_cap",
            Options {
                extra_fr_targets: 150,
                ..Options::default()
            },
        )
        .await?
    );
    h.hot
        .sample_put(
            &SampleJob {
                job_id: "jobbig".into(),
                route_class: "fr-web".into(),
                provider: h.provider.parse()?,
                region: "fr".parse()?,
                sid: None,
                targets: (0..150).map(|i| format!("https://s.test/{i}")).collect(),
            },
            std::time::Duration::from_secs(60),
        )
        .await?;
    let (_, out) = h.probe_targets().await;
    let region_targets = &out["route_classes"][0]["regions"][0]["targets"];
    assert_eq!(region_targets.as_array().expect("targets").len(), 100);
    let sample = out["samples"]
        .as_array()
        .expect("samples")
        .iter()
        .find(|s| s["job_id"] == "jobbig")
        .expect("jobbig");
    assert_eq!(sample["targets"].as_array().expect("targets").len(), 100);
    Ok(())
}

#[tokio::test]
async fn a_body_over_the_limit_is_refused_with_413_and_a_json_error() -> TestResult {
    let h = or_skip!(harness("body_limit").await?);
    let body = json!({ "policies": [], "pad": "x".repeat(5 * 1024 * 1024) });
    let (status, out) = h.put("/v1/policies", body).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{out}");
    error_of(&out);
    Ok(())
}

// --- regressions ---

/// api D1: a huge `ttl` used to panic in `now + ttl` and abort the process.
#[tokio::test]
async fn an_org_block_ttl_past_the_cap_is_a_400_and_the_api_keeps_serving() -> TestResult {
    let h = or_skip!(harness("block_ttl").await?);
    let acme = org(&uniq("acme"));
    for ttl in ["367d", "3000000d", "99999999999d", "18446744073709551615s"] {
        let body =
            json!({ "org": acme, "scope": "pool", "value": "shared", "reason": "x", "ttl": ttl });
        let (status, out) = h.post("/v1/org-blocks", body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{ttl}: {out}");
    }
    let body =
        json!({ "org": acme, "scope": "pool", "value": "shared", "reason": "x", "ttl": "366d" });
    let (status, out) = h.post("/v1/org-blocks", body).await;
    assert_eq!(status, StatusCode::CREATED, "{out}");
    Ok(())
}

/// api D2: a second, shorter block of one org and scope used to overwrite the
/// cache expiry of the first, lifting the first block when the short one ended.
#[tokio::test]
async fn a_short_block_does_not_shorten_a_permanent_one_of_the_same_scope() -> TestResult {
    let h = or_skip!(harness("block_overwrite").await?);
    let acme = org(&uniq("acme"));
    let new_block = |reason: &str, ttl: Option<&str>| {
        let mut b = json!({ "org": acme, "scope": "pool", "value": "shared", "reason": reason });
        if let Some(ttl) = ttl {
            b["ttl"] = json!(ttl);
        }
        b
    };
    let (_, permanent) = h.post("/v1/org-blocks", new_block("permanent", None)).await;
    let (status, short) = h
        .post("/v1/org-blocks", new_block("short", Some("1s")))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{short}");
    tokio::time::sleep(std::time::Duration::from_millis(1_500)).await;
    assert_eq!(
        h.hot.org_blocks(&acme).await?,
        vec!["pool:shared".to_owned()],
        "the permanent block still holds after the short one ended"
    );

    // Lifting the permanent block leaves the expired one: nothing is blocked.
    let id = permanent["id"].as_str().expect("id");
    let (status, _) = h.delete(&format!("/v1/org-blocks/{id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(h.hot.org_blocks(&acme).await?.is_empty());
    Ok(())
}

/// api D3: a set the gateway cannot load (a current `global` row and a second
/// row of the same name in another scope) must be refused before the commit.
#[tokio::test]
async fn a_put_that_would_leave_two_policies_of_one_name_is_refused() -> TestResult {
    let h = or_skip!(harness("policy_shadow").await?);
    let (_, before) = h.get("/v1/policies").await;
    let body = json!({ "policies": [
        { "name": "global", "scope": "org", "match": "shadowo", "min_ready": 2 },
        { "name": "globalx", "scope": "global", "regions": ["fr"], "min_ready": 2 },
    ] });
    let (status, out) = h.put("/v1/policies", body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{out}");
    let (_, after) = h.get("/v1/policies").await;
    assert_eq!(before, after, "nothing was stored");

    // The set that is left would also have two global policies.
    let body =
        json!({ "policies": [{ "name": "globaltwo", "scope": "global", "regions": ["fr"] }] });
    let (status, out) = h.put("/v1/policies", body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{out}");
    Ok(())
}

/// api D4: NUL bytes and oversized strings reach Postgres as a `503`.
#[tokio::test]
async fn nul_bytes_and_oversized_strings_are_400_not_503() -> TestResult {
    let h = or_skip!(harness("text_limits").await?);
    let acme = org(&uniq("acme"));
    let p = h.provider.clone();
    let (status, out) = h
        .post(
            &format!("/v1/orgs/{acme}/keys"),
            json!({ "label": "a\u{0}b" }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "label: {out}");
    let (status, out) = h
        .post(
            "/v1/org-blocks",
            json!({ "org": acme, "scope": "pool", "value": "shared", "reason": "a\u{0}b" }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "reason: {out}");
    let mut entry = entry_json(&p, "203.0.113.30");
    entry["plan"] = json!("a\u{0}b");
    let (status, out) = h
        .put(&format!("/v1/inventory/{p}"), json!({ "entries": [entry] }))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "plan: {out}");
    let (status, out) = h
        .put(
            &format!("/v1/orgs/{acme}/cache-policy"),
            json!({ "name": "n".repeat(3_900_000) }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "name: {out}");
    let (status, out) = h
        .put(
            &format!("/v1/orgs/{acme}/cache-policy"),
            json!({ "name": "a\u{0}b" }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "name NUL: {out}");
    Ok(())
}

/// api D10: serde fills a struct from an array.
#[tokio::test]
async fn a_json_array_is_not_a_body() -> TestResult {
    let h = or_skip!(harness("array_body").await?);
    let acme = org(&uniq("acme"));
    for body in [json!([]), json!(["viaseq"])] {
        let (status, out) = h.post(&format!("/v1/orgs/{acme}/keys"), body.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {out}");
    }
    let (status, out) = h
        .post("/v1/org-blocks", json!([acme, "pool", "shared", "r"]))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{out}");
    let (status, _) = h
        .post(&format!("/v1/orgs/{acme}/keys"), json!({ "label": "ok" }))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    Ok(())
}

/// api D11: an org block change that the cache refused is not stored (a retry
/// would duplicate a block, or the lift would be committed but not enforced).
#[tokio::test]
async fn a_cache_failure_leaves_no_half_applied_org_block() -> TestResult {
    let h = or_skip!(
        harness_with(
            "block_cache",
            Options {
                redis_proxy: true,
                ..Options::default()
            },
        )
        .await?
    );
    let proxy = h.proxy.as_ref().expect("proxy");
    let acme = org(&uniq("acme"));
    let block = json!({ "org": acme, "scope": "ip", "value": "203.0.113.9", "reason": "abuse" });

    proxy.cut();
    let (status, out) = h.post("/v1/org-blocks", block.clone()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{out}");
    let stored =
        h.db.active_org_blocks(time::OffsetDateTime::now_utc())
            .await?;
    assert!(
        stored.iter().all(|b| b.org != acme),
        "the 503 means nothing was applied"
    );
    proxy.restore();

    // A retry works and makes one block.
    let mut created = None;
    for _ in 0..50 {
        let (status, out) = h.post("/v1/org-blocks", block.clone()).await;
        if status == StatusCode::CREATED {
            created = Some(out);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    let created = created.ok_or("the API never reconnected")?;
    let id = created["id"].as_str().expect("id").to_owned();
    assert_eq!(
        h.hot.org_blocks(&acme).await?,
        vec!["ip:203.0.113.9".to_owned()]
    );

    // Lift while the cache is out: the 503 means nothing was applied.
    proxy.cut();
    let (status, _) = h.delete(&format!("/v1/org-blocks/{id}")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    proxy.restore();
    assert_eq!(h.hot.org_blocks(&acme).await?.len(), 1);

    // The same request again lifts it.
    let mut answer = StatusCode::SERVICE_UNAVAILABLE;
    for _ in 0..50 {
        (answer, _) = h.delete(&format!("/v1/org-blocks/{id}")).await;
        if answer != StatusCode::SERVICE_UNAVAILABLE {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    assert_eq!(answer, StatusCode::OK);
    assert!(h.hot.org_blocks(&acme).await?.is_empty());
    Ok(())
}

/// api D12: free-form inventory fields that the warmer and the gateway read.
#[tokio::test]
async fn inventory_entries_with_unusable_fields_are_refused_and_nothing_is_stored() -> TestResult {
    let h = or_skip!(harness("inventory_valid").await?);
    let p = h.provider.clone();
    let path = format!("/v1/inventory/{p}");
    let with = |key: &str, value: Value| {
        let mut e = entry_json(&p, "203.0.113.40");
        e[key] = value;
        e
    };
    for (what, entry) in [
        ("unspecified ip", with("ip", json!("0.0.0.0"))),
        ("loopback ip", with("ip", json!("127.0.0.1"))),
        ("private ip", with("ip", json!("10.0.0.1"))),
        ("ula ip", with("ip", json!("fd00::1"))),
        ("empty host", with("host", json!(""))),
        ("url as host", with("host", json!("http://x"))),
        ("long host", with("host", json!("h".repeat(10_000)))),
        ("port zero", with("port", json!(0))),
        (
            "path as credentials",
            with("credentials", json!("../../etc/passwd")),
        ),
        ("bad rental_end", with("rental_end", json!("not-a-date"))),
        (
            "impossible rental_end",
            with("rental_end", json!("2027-02-30")),
        ),
        ("long plan", with("plan", json!("p".repeat(1_000)))),
    ] {
        let (status, out) = h.put(&path, json!({ "entries": [entry] })).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{what}: {out}");
    }
    let (_, list) = h.get(&format!("/v1/inventory?provider={p}")).await;
    assert!(list["items"].as_array().expect("items").is_empty());

    let mut good = entry_json(&p, "203.0.113.40");
    good["credentials"] = json!("oxy-203-0-113-40");
    let (status, out) = h.put(&path, json!({ "entries": [good] })).await;
    assert_eq!(status, StatusCode::OK, "{out}");
    Ok(())
}

/// api D14: the ready-set withdrawal after a bulk retire is best effort and
/// bounded: with Redis out the committed change still answers 200 in time.
#[tokio::test]
async fn retiring_many_ips_while_redis_is_down_still_answers_200_in_time() -> TestResult {
    let h = or_skip!(
        harness_with(
            "retire_redis_down",
            Options {
                redis_proxy: true,
                ..Options::default()
            },
        )
        .await?
    );
    let p = h.provider.clone();
    let path = format!("/v1/inventory/{p}");
    let entries: Vec<Value> = (1..=12)
        .map(|n| entry_json(&p, &format!("203.0.113.{}", 100 + n)))
        .collect();
    let (status, out) = h.put(&path, json!({ "entries": entries })).await;
    assert_eq!(status, StatusCode::OK, "{out}");

    h.proxy.as_ref().expect("proxy").cut();
    let started = std::time::Instant::now();
    let (status, out) = h
        .put(&path, json!({ "entries": [entries[0].clone()] }))
        .await;
    assert_eq!(status, StatusCode::OK, "{out}");
    assert_eq!(out["retired"].as_array().expect("retired").len(), 11);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(10),
        "{:?}",
        started.elapsed()
    );
    Ok(())
}

/// rotating D13: a `min_remaining` that no session of a short-lived provider
/// can satisfy must be refused like any other invalid policy.
#[tokio::test]
async fn a_policy_no_session_of_a_short_lived_provider_can_satisfy_is_refused() -> TestResult {
    let short_lived = r#"
[[adapter]]
id = "rot"
kind = "rotating"
subtype = "residential"
host = "127.0.0.1"
port = 9
credentials_optional = true
user = "u{opts}"
max_session_minutes = 3

[[adapter.option]]
name = "sid"
to = "user"
frag = "-s-{v}"
charset = "alnum"
len = 12

[[adapter.option]]
name = "country"
to = "user"
frag = "-c-{v}"
"#;
    let h = or_skip!(
        harness_with(
            "policy_life",
            Options {
                adapters_toml: Some(short_lived),
                ..Options::default()
            },
        )
        .await?
    );
    // The default `min_remaining` (5 m) is above the shortest 3 m session.
    let doc = json!({ "policies": [{ "name": "global", "regions": ["fr"], "min_ready": 3 }] });
    let (status, out) = h.put("/v1/policies", doc).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{out}");
    assert!(error_of(&out).contains("min_remaining"), "{out}");
    assert_eq!(h.db.policy_versions("global", "global").await?.len(), 1);

    let doc = json!({ "policies": [{
        "name": "global", "regions": ["fr"], "min_ready": 3,
        "rotating": { "min_remaining": "30s" },
    }] });
    let (status, out) = h.put("/v1/policies", doc).await;
    assert_eq!(status, StatusCode::OK, "{out}");
    Ok(())
}

/// warmer D-W10: a result for a route class that does not exist writes nothing.
#[tokio::test]
async fn probe_results_for_an_unknown_provider_or_region_are_refused() -> TestResult {
    let h = or_skip!(harness("probe_unknown").await?);
    let run = json!({ "outcome": "ok", "status": 200, "ttfb_ms": 10.0, "load_ms": 20.0 });
    for (provider, region, expected) in [
        ("nothere", "fr", StatusCode::NOT_FOUND),
        (h.provider.as_str(), "us", StatusCode::BAD_REQUEST),
    ] {
        let body =
            json!({ "kind": "canary", "provider": provider, "region": region, "results": [run] });
        let (status, out) = h.probe_results(body).await;
        assert_eq!(status, expected, "{provider}/{region}: {out}");
    }
    assert!(h.hot.verdict_get("canary:nothere:fr").await?.is_none());
    let body =
        json!({ "kind": "canary", "provider": h.provider, "region": "fr", "results": [run] });
    let (status, out) = h.probe_results(body).await;
    assert_eq!(status, StatusCode::OK, "{out}");
    Ok(())
}
