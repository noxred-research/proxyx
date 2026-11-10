//! Regression tests of the operations and control API areas.

#[macro_use]
mod support;

use reqwest::{Method, StatusCode, header};
use serde_json::{Value, json};
use support::*;

/// A key body over the limit answered plain text.
#[tokio::test]
async fn an_oversized_key_body_is_a_413_with_a_json_error() -> TestResult {
    let h = or_skip!(harness("ops_413").await?);
    let resp = h
        .client
        .post(format!("{}/v1/orgs/acme/keys", h.base))
        .bearer_auth(ADMIN)
        .header(header::CONTENT_TYPE, "application/json")
        .body(vec![b'a'; 4 * 1024 * 1024 + 10])
        .send()
        .await?;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let content_type = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    assert!(
        content_type.starts_with("application/json"),
        "{content_type}"
    );
    let body: Value = resp.json().await?;
    error_of(&body);
    Ok(())
}

/// Framework errors were plain text or empty.
#[tokio::test]
async fn path_route_and_method_errors_are_json() -> TestResult {
    let h = or_skip!(harness("ops_framework").await?);
    let send = |method: Method, path: &str| {
        let req = h
            .client
            .request(method, format!("{}{path}", h.base))
            .bearer_auth(ADMIN);
        async move { req.send().await }
    };

    let resp = send(Method::POST, "/v1/orgs/%ff%fe/keys").await?;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: Value = resp.json().await?;
    error_of(&body);

    let resp = send(Method::GET, "/v1/nowhere").await?;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body: Value = resp.json().await?;
    error_of(&body);

    let resp = send(Method::PATCH, "/v1/policies").await?;
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert!(resp.headers().contains_key(header::ALLOW), "Allow is kept");
    let body: Value = resp.json().await?;
    error_of(&body);

    let resp = send(Method::GET, "/v1/org-blocks?org=%ff").await?;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: Value = resp.json().await?;
    error_of(&body);
    Ok(())
}

/// The operator block route ignored `X-Operator`.
#[tokio::test]
async fn the_operator_block_route_records_and_validates_x_operator() -> TestResult {
    let h = or_skip!(harness("ops_operator").await?);
    let ip = h.seed_ips(1).await?[0];
    let path = format!("/v1/ips/{ip}/block");

    let (status, out) = h
        .send_as_operator(Method::POST, &path, "ana@example.com", Some(json!({})))
        .await;
    assert_eq!(status, StatusCode::OK, "{out}");
    let audit = h.db.audit_for(&ip.to_string(), 20).await?;
    assert!(
        audit
            .iter()
            .any(|a| a.actor == "ana@example.com" && a.action == "ip.block_reported"),
        "the operator is named: {audit:?}"
    );

    let (status, out) = h
        .send_as_operator(Method::POST, &path, "bad actor", Some(json!({})))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{out}");
    Ok(())
}

/// Wrong credentials were never throttled on the control API.
#[tokio::test]
async fn a_source_with_twenty_wrong_credentials_is_refused_with_429() -> TestResult {
    let h = or_skip!(
        harness_with(
            "ops_bruteforce",
            Options {
                default_failure_limit: true,
                ..Options::default()
            },
        )
        .await?
    );
    let acme = org("acme");
    let good = h.org_key(&acme).await?;
    let failures = |reason: &str| {
        h.metrics
            .auth_failures_total
            .with_label_values(&[reason])
            .get()
    };

    for i in 0..20 {
        let (status, _) = h
            .send(
                Method::POST,
                "/v1/block-signals",
                Some(&basic("px", &format!("wrong{i}"))),
                Some(json!([])),
            )
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "attempt {i}");
    }
    assert_eq!(failures("unknown_key"), 20);

    // The 21st is refused without a lookup, and so is the right key.
    for key in ["wrong-again", good.as_str()] {
        let (status, out) = h
            .send(
                Method::POST,
                "/v1/block-signals",
                Some(&basic("px", key)),
                Some(json!([])),
            )
            .await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{out}");
        error_of(&out);
    }
    assert_eq!(failures("source_limited"), 2);

    // A wrong admin bearer from the same source is limited too; the right
    // admin token is not (its check is in memory and it is the operator).
    let (status, _) = h
        .send(Method::GET, "/v1/inventory", Some("Bearer nope"), None)
        .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    let (status, _) = h.get("/v1/inventory").await;
    assert_eq!(status, StatusCode::OK);
    Ok(())
}

/// Admin side: the bearer token is counted on its own, so wrong
/// admin tokens alone reach the limit.
#[tokio::test]
async fn twenty_wrong_admin_tokens_are_throttled() -> TestResult {
    let h = or_skip!(
        harness_with(
            "ops_bruteforce_admin",
            Options {
                default_failure_limit: true,
                ..Options::default()
            },
        )
        .await?
    );
    for i in 0..20 {
        let (status, _) = h
            .send(
                Method::GET,
                "/v1/inventory",
                Some(&format!("Bearer w{i}")),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "attempt {i}");
    }
    let (status, _) = h
        .send(Method::GET, "/v1/inventory", Some("Bearer w21"), None)
        .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    Ok(())
}

/// Wrong org keys sent at once were all looked up, because the
/// limiter counted a failure only after its lookup. Counted first, exactly
/// twenty reach Postgres and the rest are `429` without a lookup.
#[tokio::test]
async fn a_burst_of_wrong_keys_is_limited_before_the_lookups_return() -> TestResult {
    let h = or_skip!(
        harness_with(
            "ops_burst",
            Options {
                default_failure_limit: true,
                ..Options::default()
            },
        )
        .await?
    );
    if h.raw.backend() != proxyx_db::Backend::Postgres {
        eprintln!("SKIP: the test holds a PostgreSQL table lock and reads pg_stat_activity");
        return Ok(());
    }
    let proxyx_db::Pool::Postgres(pg) = h.raw.pool().clone() else {
        return Ok(());
    };
    let acme = org("acme");
    let good = h.org_key(&acme).await?;
    let request = |key: String| {
        h.client
            .post(format!("{}/v1/block-signals", h.base))
            .header(header::AUTHORIZATION, basic("px", &key))
            .json(&json!([]))
            .send()
    };

    // The lookups block on a table lock while the whole burst arrives, which
    // is what a slow Postgres does to a real one. Returns the statuses and the
    // most org key lookups that were waiting on Postgres at once.
    let burst = |keys: Vec<String>| async {
        let mut lock = pg.begin().await?;
        sqlx::query("LOCK TABLE org_keys IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *lock)
            .await?;
        let tasks: Vec<_> = keys
            .into_iter()
            .map(|key| tokio::spawn(request(key)))
            .collect();
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity
             WHERE wait_event_type = 'Lock' AND query ILIKE '%FROM org_keys WHERE key_hash%'",
        )
        .fetch_one(&pg)
        .await?;
        lock.commit().await?;
        let mut statuses = Vec::new();
        for task in tasks {
            statuses.push(task.await??.status());
        }
        Ok::<_, Box<dyn std::error::Error>>((statuses, waiting))
    };

    // right keys in a burst wait for their turn: none is refused
    let (right, waiting) = burst(vec![good.clone(); 40]).await?;
    assert!(right.iter().all(|s| *s == StatusCode::OK), "{right:?}");
    assert_eq!(waiting, 1, "one lookup at a time, the rest wait their turn");

    let (statuses, waiting) = burst((0..60).map(|i| format!("wrong{i}")).collect()).await?;
    assert_eq!(waiting, 1, "one lookup at a time, the rest wait their turn");
    let count = |status: StatusCode| statuses.iter().filter(|s| **s == status).count();
    assert_eq!(count(StatusCode::UNAUTHORIZED), 20, "{statuses:?}");
    assert_eq!(count(StatusCode::TOO_MANY_REQUESTS), 40, "{statuses:?}");
    Ok(())
}

/// The prober's tokens for the probe listener come from the
/// control API, signed with the probe secret, and only the prober gets one.
#[tokio::test]
async fn the_prober_gets_a_signed_short_lived_probe_token() -> TestResult {
    let h = or_skip!(harness("ops_probe_token").await?);
    let secret = common::Secret::new(PROBE_SECRET);

    let (status, out) = h
        .send(
            Method::POST,
            "/v1/probe/token",
            Some(&format!("Bearer {PROBER}")),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{out}");
    let token = out["token"].as_str().ok_or("no token")?;
    let now = std::time::SystemTime::now();
    assert!(common::probe_token::verify(&secret, token, now));
    assert_eq!(
        out["expires_in_s"],
        common::probe_token::TOKEN_TTL.as_secs()
    );
    let later = now + common::probe_token::TOKEN_TTL + std::time::Duration::from_secs(2);
    assert!(!common::probe_token::verify(&secret, token, later));

    for auth in [None, Some(format!("Bearer {ADMIN}"))] {
        let (status, _) = h
            .send(Method::POST, "/v1/probe/token", auth.as_deref(), None)
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    Ok(())
}

/// The `429` named no time to retry at.
#[tokio::test]
async fn the_429_carries_retry_after() -> TestResult {
    let h = or_skip!(
        harness_with(
            "ops_retry_after",
            Options {
                default_failure_limit: true,
                ..Options::default()
            },
        )
        .await?
    );
    for i in 0..20 {
        let resp = h
            .client
            .get(format!("{}/v1/inventory", h.base))
            .bearer_auth(format!("wrong{i}"))
            .send()
            .await?;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "attempt {i}");
        assert!(!resp.headers().contains_key(header::RETRY_AFTER));
    }
    let resp = h
        .client
        .get(format!("{}/v1/inventory", h.base))
        .bearer_auth("wrong-again")
        .send()
        .await?;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let seconds: u64 = resp
        .headers()
        .get(header::RETRY_AFTER)
        .ok_or("no Retry-After")?
        .to_str()?
        .parse()?;
    assert!((1..=60).contains(&seconds), "{seconds}");
    Ok(())
}

/// Deleting the API override of a policy git defines was refused
/// 400 (the set without it has no `global`), though git's version returns.
#[tokio::test]
async fn deleting_the_override_of_a_git_defined_global_is_allowed() -> TestResult {
    let h = or_skip!(harness("ops_delete_global").await?);
    // the harness stored `global` as actor `test`: an API-written policy
    let path = "/v1/policies/global/global";

    // git defines no `global`: nothing comes back, the set would have none
    let (status, out) = h.delete(path).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{out}");

    std::fs::create_dir_all(h.data_dir.join("policies"))?;
    std::fs::write(
        h.data_dir.join("policies/global.toml"),
        "[[policy]]\nname = \"global\"\nregions = [\"fr\"]\nmin_ready = 5\n",
    )?;
    let (status, out) = h.delete(path).await;
    assert_eq!(status, StatusCode::OK, "{out}");
    assert_eq!(out["written_by"], "test");
    Ok(())
}

/// `PUT /v1/policies` accepted policies no adapter can serve.
#[tokio::test]
async fn a_policy_no_adapter_can_serve_is_refused() -> TestResult {
    let h = or_skip!(harness("ops_servable").await?);
    h.seed_ips(1).await?; // an `fr` static IP of the only adapter

    for (what, doc) in [
        (
            "kinds with no adapter",
            json!({ "name": "global", "regions": ["fr"], "kinds": ["rotating"] }),
        ),
        (
            "a region without inventory",
            json!({ "name": "global", "regions": ["de"] }),
        ),
    ] {
        let (status, out) = h.put("/v1/policies", json!({ "policies": [doc] })).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{what}: {out}");
        assert!(error_of(&out).contains("cannot be served"), "{what}: {out}");
    }
    assert_eq!(h.db.policy_versions("global", "global").await?.len(), 1);

    // The same two mistakes in an org policy.
    for body in [
        json!({ "kinds": ["rotating"] }),
        json!({ "regions": ["de"] }),
    ] {
        let (status, out) = h.put("/v1/orgs/acme/cache-policy", body.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {out}");
    }

    // A list where one region can be served passes.
    let ok = json!({ "policies": [{ "name": "global", "regions": ["de", "fr"], "min_ready": 3 }] });
    let (status, out) = h.put("/v1/policies", ok).await;
    assert_eq!(status, StatusCode::OK, "{out}");
    Ok(())
}

/// An API-written route_class policy could not be deleted and blocked
/// the git one for the same provider.
#[tokio::test]
async fn an_api_written_policy_can_be_deleted_and_a_git_written_one_cannot() -> TestResult {
    let Some(h) = harness_with(
        "ops_delete",
        Options {
            adapters_toml: Some(
                "[[adapter]]\nid = \"alt_isp\"\nkind = \"static\"\nsubtype = \"isp\"\n\
                 scheme = \"http\"\ncredentials_optional = true\nuser = \"{base_user}\"\n\
                 pass = \"{base_pass}\"\n",
            ),
            ..Options::default()
        },
    )
    .await?
    else {
        return Ok(());
    };
    // an `fr` IP of the one adapter the API-written route_class is for
    let mut entry = h.entry("10.9.9.9".parse()?, common::types::Subtype::Isp);
    entry.provider = "alt_isp".parse()?;
    h.db.upsert_inventory_entry(&entry, "test").await?;
    let route = json!({ "name": "api-rc", "scope": "route_class", "match": "alt_isp",
                        "regions": ["fr"], "min_ready": 3 });
    let (status, out) = h
        .send_as_operator(
            Method::PUT,
            "/v1/policies",
            "ana@example.com",
            Some(json!({ "policies": [route] })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{out}");

    let (status, out) = h
        .send_as_operator(
            Method::DELETE,
            "/v1/policies/route_class/api-rc",
            "ben@example.com",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{out}");
    assert_eq!(out["written_by"], "ana@example.com");
    let (_, list) = h.get("/v1/policies").await;
    assert!(
        list["items"]
            .as_array()
            .ok_or("items")?
            .iter()
            .all(|p| p["name"] != "api-rc"),
        "{list}"
    );
    assert_eq!(
        h.db.policy_versions("route_class", "api-rc").await?.len(),
        1,
        "history stays"
    );
    let audit = h.db.audit_for("route_class/api-rc", 10).await?;
    assert!(
        audit
            .iter()
            .any(|a| a.actor == "ben@example.com" && a.action == "policy.deactivate"),
        "{audit:?}"
    );

    // gone: a second delete is a 404; a bad scope a 400
    let (status, _) = h.delete("/v1/policies/route_class/api-rc").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = h.delete("/v1/policies/planet/x").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // a policy git wrote is git's to remove
    h.db.put_policies(
        &[serde_json::from_value(json!({
            "name": "from-git", "scope": "org", "match": "gitorg", "min_ready": 4
        }))?],
        "gitops",
    )
    .await?;
    let (status, out) = h.delete("/v1/policies/org/from-git").await;
    assert_eq!(status, StatusCode::CONFLICT, "{out}");
    Ok(())
}
