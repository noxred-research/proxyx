//! Mutating tools: capability gating, dry runs, the propose/apply workflow, approval, secret
//! handling and the audit log.

mod common;

use common::*;
use proxyx_mcp::audit;
use proxyx_mcp::store::Store;
use serde_json::{Value, json};

fn audit_text(fx: &Fixture) -> String {
    std::fs::read_to_string(fx.audit_path()).unwrap_or_default()
}

#[tokio::test]
async fn read_only_server_refuses_every_mutation_and_touches_nothing() {
    let fx = Fixture::start().await;
    let server = fx.read_only();
    let listed = ask(&server, modern(1, "tools/list", json!({}))).await;
    assert!(
        !tool_names(&listed).contains(&"set_org_rate_limit".to_owned()),
        "not listed when its capability is off"
    );
    for (tool, args) in [
        (
            "create_session",
            json!({"captured_hosts": ["*.example.com"]}),
        ),
        ("create_org_key", json!({"org": "acme"})),
        (
            "set_org_rate_limit",
            json!({"org": "acme", "requests_per_minute": 1, "burst": 1}),
        ),
        (
            "put_policy",
            json!({"toml": "[[policy]]\nname = \"x\"\nscope = \"org\"\nmatch = \"acme\""}),
        ),
        (
            "create_org_block",
            json!({"org": "acme", "scope": "pool", "value": "shared", "reason": "x"}),
        ),
        (
            "put_inventory",
            json!({"provider": "isp1", "entries": [{"ip": "203.0.113.5"}]}),
        ),
    ] {
        let error = tool_err(&server, tool, args).await;
        let text = error.to_string();
        assert!(
            text.contains("refused") && text.contains("capability"),
            "{tool}: {text}"
        );
    }
    // propose works without the capability and says it cannot be applied here
    let proposal = tool_ok(
        &server,
        "propose_config_change",
        json!({"action": "set_org_rate_limit", "arguments": {"org": "acme", "requests_per_minute": 3000, "burst": 500}}),
    )
    .await;
    assert_eq!(proposal["status"], "proposed");
    assert_eq!(proposal["can_apply_here"], false);
    assert_eq!(proposal["diff"]["requests_per_minute"]["from"], 6000);
    assert_eq!(proposal["diff"]["requests_per_minute"]["to"], 3000);
    let id = proposal["change_id"]
        .as_str()
        .expect("change id")
        .to_owned();
    let applied = tool_err(&server, "apply_config_change", json!({"change_id": id})).await;
    assert!(applied.to_string().contains("not allowed"), "{applied}");
    assert!(
        fx.pool.log.mutations().is_empty() && fx.control.log.mutations().is_empty(),
        "nothing reached a backend"
    );
    // the refusals are in the audit log
    let log = audit_text(&fx);
    assert!(log.contains("\"outcome\":\"refused\""));
}

#[tokio::test]
async fn capabilities_are_independent() {
    let fx = Fixture::start().await;
    let server = fx.server("capabilities = [\"org_limits\"]", "");
    let ok = tool_ok(
        &server,
        "set_org_rate_limit",
        json!({"org": "acme", "requests_per_minute": 1200, "burst": 100}),
    )
    .await;
    assert_eq!(ok["status"], "applied");
    assert_eq!(
        fx.control.log.calls("PUT", "/rpc/orgs/acme/rate-limit")[0].body,
        json!({"requests_per_minute": 1200, "burst": 100})
    );
    let other = tool_err(
        &server,
        "create_org_block",
        json!({"org": "acme", "scope": "pool", "value": "shared", "reason": "x"}),
    )
    .await;
    assert!(other.to_string().contains("org_blocks"));
}

#[tokio::test]
async fn dry_run_and_forced_dry_run_change_nothing() {
    let fx = Fixture::start().await;
    let server = fx.admin();
    let preview = tool_ok(
        &server,
        "set_org_rate_limit",
        json!({"org": "acme", "requests_per_minute": 10, "burst": 5, "dry_run": true}),
    )
    .await;
    assert_eq!(preview["status"], "dry_run");
    assert_eq!(preview["diff"]["burst"]["to"], 5);
    assert_eq!(preview["would_call"][0], "PUT /rpc/orgs/{org}/rate-limit");
    assert!(fx.control.log.mutations().is_empty());

    let forced = fx.server("profile = \"admin\"\nforce_dry_run = true", "");
    let still = tool_ok(
        &forced,
        "create_org_block",
        json!({"org": "acme", "scope": "provider", "value": "p2", "reason": "test"}),
    )
    .await;
    assert_eq!(still["status"], "dry_run");
    assert_eq!(still["forced_by_server"], true);
    assert!(fx.pool.log.mutations().is_empty());
    assert_eq!(
        audit_text(&fx).matches("\"outcome\":\"dry_run\"").count(),
        2
    );
}

#[tokio::test]
async fn validation_rejects_bad_input_before_any_backend_call() {
    let fx = Fixture::start().await;
    let server = fx.admin();
    for (tool, args, needle) in [
        (
            "create_org_block",
            json!({"org": "acme", "scope": "ip", "value": "not-an-ip", "reason": "x"}),
            "does not fit scope",
        ),
        (
            "create_org_block",
            json!({"org": "acme", "scope": "pool", "value": "shared", "reason": "x", "ttl": "forever"}),
            "must match",
        ),
        (
            "set_customer_upstream",
            json!({"org": "acme", "scheme": "http", "host": "10.0.0.5", "port": 3128, "region": "fr"}),
            "public routable",
        ),
        (
            "set_org_egress_proxy",
            json!({"org": "acme", "proxy_type": "socks5", "address": "nohost"}),
            "must match",
        ),
        (
            "create_session",
            json!({"captured_hosts": ["a/b"]}),
            "not a host pattern",
        ),
        (
            "create_session",
            json!({"captured_hosts": ["a.example"], "ttl_secs": 86400}),
            "above this server's limit",
        ),
        (
            "put_inventory",
            json!({"provider": "isp1", "entries": [{"provider": "isp1", "ip": "10.1.1.1", "host": "h", "port": 1}]}),
            "not a public address",
        ),
        (
            "put_policy",
            json!({"toml": "[[policy]]\nname = \"x\"\nscope = \"org\"\nmatch = \"acme\"\nregions = []"}),
            "invalid",
        ),
    ] {
        let error = tool_err(&server, tool, args).await;
        assert!(
            error.to_string().contains(needle),
            "{tool}: expected {needle:?} in {error}"
        );
    }
    assert!(fx.pool.log.mutations().is_empty() && fx.control.log.mutations().is_empty());
}

#[tokio::test]
async fn secrets_go_to_a_private_file_unless_revealing_once_is_enabled() {
    let fx = Fixture::start().await;
    let server = fx.admin();
    let created = tool_ok(
        &server,
        "create_org_key",
        json!({"org": "acme", "label": "ci"}),
    )
    .await;
    let text = created.to_string();
    assert!(
        !text.contains(NEW_ORG_KEY),
        "the key is not in the result: {text}"
    );
    assert!(created["result"].get("revealed_once").is_none());
    let file = created["result"]["secret_file"]
        .as_str()
        .expect("secret file");
    assert!(
        std::fs::read_to_string(file)
            .expect("file")
            .contains(NEW_ORG_KEY)
    );
    assert_eq!(
        created["result"]["key_fingerprint"]
            .as_str()
            .expect("fingerprint")
            .len(),
        12
    );
    assert_eq!(
        fx.pool.log.calls("POST", "/v1/orgs/acme/keys")[0]
            .operator
            .as_deref(),
        Some("mcp-test")
    );

    let session = tool_ok(
        &server,
        "create_session",
        json!({"captured_hosts": ["*.example.com"], "ttl_secs": 300, "source_id": "run-9"}),
    )
    .await;
    let text = session.to_string();
    assert!(
        !text.contains("password@") && !text.contains(SESSION_PROXY_URL),
        "the proxy URL is a credential: {text}"
    );
    assert!(session["result"]["secret_file"].is_string());
    assert_eq!(session["result"]["session_id"], SESSION_ID);
    let env = std::fs::read_to_string(session["result"]["secret_file"].as_str().expect("file"))
        .expect("env file");
    assert!(env.contains(&format!("HTTPS_PROXY={SESSION_PROXY_URL}")));
    let body = &fx.control.log.calls("POST", "/rpc/sessions")[0].body;
    assert_eq!(
        (
            body["org_id"].as_str(),
            body["source_id"].as_str(),
            body["ttl_secs"].as_u64()
        ),
        (Some("acme"), Some("run-9"), Some(300))
    );
    let registered = tool_ok(&server, "list_sessions", json!({})).await;
    assert_eq!(registered["sessions"][0]["session_id"], SESSION_ID);
    assert!(!registered.to_string().contains("password"));

    // the log has neither secret
    let log = audit_text(&fx);
    for secret in [
        NEW_ORG_KEY,
        SESSION_PROXY_URL,
        ADMIN,
        SERVICE_KEY,
        "0f6d3a4e-5b1c-4d52-9a0e-7c1b2e8d4f10:password",
    ] {
        assert!(!log.contains(secret), "{secret} leaked into the audit log");
    }

    let revealing = fx.server("profile = \"admin\"\nreveal_secrets_once = true", "");
    let shown = tool_ok(&revealing, "create_org_key", json!({"org": "acme"})).await;
    assert_eq!(
        shown["result"]["revealed_once"]["key"], NEW_ORG_KEY,
        "shown once in the creating call"
    );
    assert!(shown["result"].get("secret_file").is_none());
    assert!(
        !audit_text(&fx).contains(NEW_ORG_KEY),
        "even a revealed key never reaches the audit log"
    );
    // and it cannot be read back afterwards
    let log = tool_ok(&revealing, "list_changes", json!({})).await;
    assert!(!log.to_string().contains(NEW_ORG_KEY));
    let resource = ask(
        &revealing,
        modern(2, "resources/read", json!({"uri": "proxyx://audit/recent"})),
    )
    .await;
    assert!(!resource.to_string().contains(NEW_ORG_KEY));
}

#[tokio::test]
async fn logins_are_passed_by_reference_and_never_stored_or_echoed() {
    let fx = Fixture::start().await;
    let server = fx.admin();
    let inline = tool_err(
        &server,
        "set_customer_upstream",
        json!({"org": "acme", "scheme": "http", "host": "proxy.example.net", "port": 3128, "region": "fr", "username": "u", "password": "inline-pass"}),
    )
    .await;
    assert!(inline.to_string().contains("inline secrets are disabled"));
    let unknown = tool_err(&server, "set_customer_upstream", json!({"org": "acme", "scheme": "http", "host": "proxy.example.net", "port": 3128, "region": "fr", "credential_ref": "nope"})).await;
    assert!(
        unknown.to_string().contains("upstream-main"),
        "lists the references that exist"
    );

    let args = json!({"org": "acme", "scheme": "http", "host": "proxy.example.net", "port": 3128, "region": "fr", "credential_ref": "upstream-main"});
    let done = tool_ok(&server, "set_customer_upstream", args.clone()).await;
    assert_eq!(done["status"], "applied");
    let sent = &fx.pool.log.calls("PUT", "/v1/orgs/acme/upstream")[0].body;
    assert_eq!(
        sent["password"], UPSTREAM_PASSWORD,
        "the backend gets the secret from the file"
    );
    assert_eq!(sent["username"], "svc-user");
    assert!(!done.to_string().contains(UPSTREAM_PASSWORD));
    assert!(!audit_text(&fx).contains(UPSTREAM_PASSWORD));
    let shown = tool_ok(&server, "get_customer_upstream", json!({"org": "acme"})).await;
    assert_eq!(shown["has_login"], true);

    let valid = tool_ok(
        &server,
        "validate_customer_upstream",
        json!({"org": "acme"}),
    )
    .await;
    assert_eq!(valid["result"]["valid"], true);
    let diff = tool_ok(&server, "set_customer_upstream", json!({"org": "acme", "scheme": "http", "host": "bad.example.net", "port": 3128, "region": "fr", "dry_run": true})).await;
    assert_eq!(diff["diff"]["host"]["from"], "proxy.example.net");
    tool_ok(&server, "set_customer_upstream", json!({"org": "acme", "scheme": "http", "host": "bad.example.net", "port": 3128, "region": "fr"})).await;
    let invalid = tool_ok(
        &server,
        "validate_customer_upstream",
        json!({"org": "acme"}),
    )
    .await;
    assert_eq!(invalid["result"]["valid"], false);
    assert_eq!(invalid["result"]["reason"], "refused");

    // egress proxy through the control plane, also by reference
    tool_ok(&server, "set_org_egress_proxy", json!({"org": "acme", "proxy_type": "socks5", "address": "egress.example.net:1080", "credential_ref": "upstream-main"})).await;
    assert_eq!(
        fx.control.log.calls("PUT", "/rpc/orgs/acme/proxy")[0].body["password"],
        UPSTREAM_PASSWORD
    );
    assert!(!audit_text(&fx).contains(UPSTREAM_PASSWORD));
}

#[tokio::test]
async fn approval_flow_pending_approve_apply_once() {
    let fx = Fixture::start().await;
    let server = fx.server("profile = \"admin\"\napproval = \"all\"", "");
    let held = tool_ok(&server, "create_org_block", json!({"org": "acme", "scope": "provider", "value": "p2", "reason": "abuse report 1234", "ttl": "2h"})).await;
    assert_eq!(held["status"], "pending_approval");
    let id = held["change_id"].as_str().expect("id").to_owned();
    assert_eq!(held["approve_with"], format!("proxyx mcp approve {id}"));
    assert_eq!(held["diff"]["creates"]["scope"], "provider");
    assert!(fx.pool.log.mutations().is_empty(), "held, not applied");
    let pending = tool_ok(&server, "list_changes", json!({"status": "proposed"})).await;
    assert_eq!(pending["changes"][0]["change_id"], id.as_str());
    assert_eq!(pending["changes"][0]["approval_required"], true);

    let early = tool_err(&server, "apply_config_change", json!({"change_id": id})).await;
    assert!(early.to_string().contains("approval"), "{early}");
    assert!(fx.pool.log.mutations().is_empty());

    // the operator approves out of band, as `proxyx mcp approve` does
    let store = Store::open(fx.state_dir()).expect("store");
    store
        .approve(&id, "alice", Some("checked"))
        .expect("approve");

    let dry = tool_ok(
        &server,
        "apply_config_change",
        json!({"change_id": id, "dry_run": true}),
    )
    .await;
    assert_eq!(dry["status"], "dry_run");
    assert!(fx.pool.log.mutations().is_empty());
    let applied = tool_ok(&server, "apply_config_change", json!({"change_id": id})).await;
    assert_eq!(applied["status"], "applied");
    assert_eq!(fx.pool.log.calls("POST", "/v1/org-blocks").len(), 1);
    assert_eq!(
        fx.pool.log.calls("POST", "/v1/org-blocks")[0].body["reason"],
        "abuse report 1234"
    );
    let again = tool_err(&server, "apply_config_change", json!({"change_id": id})).await;
    assert!(again.to_string().contains("already applied"));
    assert_eq!(
        fx.pool.log.calls("POST", "/v1/org-blocks").len(),
        1,
        "a change applies once"
    );

    let log = audit_text(&fx);
    assert!(
        log.contains("\"phase\":\"intent\""),
        "the intent is recorded before the call"
    );
    assert!(log.contains(&id));
    assert_eq!(
        audit::verify(&fx.audit_path()).expect("verify").broken,
        None
    );
}

#[tokio::test]
async fn rejected_and_edited_changes_do_not_apply_and_listed_mode_is_selective() {
    let fx = Fixture::start().await;
    let server = fx.server(
        "profile = \"admin\"\napproval = \"listed\"\napproval_tools = [\"put_*\", \"delete_*\"]",
        "",
    );
    // not listed: runs directly
    let direct = tool_ok(
        &server,
        "create_org_block",
        json!({"org": "acme", "scope": "pool", "value": "shared", "reason": "direct"}),
    )
    .await;
    assert_eq!(direct["status"], "applied");
    // listed: held
    let held = tool_ok(&server, "put_org_policy", json!({"org": "acme", "toml": "[[policy]]\nname = \"acme-limits\"\nmax_tunnels_per_org = 7"})).await;
    assert_eq!(held["status"], "pending_approval");
    let id = held["change_id"].as_str().expect("id").to_owned();
    let store = Store::open(fx.state_dir()).expect("store");
    store.reject(&id, "bob", Some("too broad")).expect("reject");
    let refused = tool_err(&server, "apply_config_change", json!({"change_id": id})).await;
    assert!(refused.to_string().contains("rejected by bob"));
    assert!(
        fx.pool
            .log
            .calls("PUT", "/v1/orgs/acme/cache-policy")
            .is_empty()
    );

    // an edited change file is refused even when approved
    let held = tool_ok(&server, "put_org_policy", json!({"org": "acme", "toml": "[[policy]]\nname = \"acme-limits\"\nmax_tunnels_per_org = 7"})).await;
    let id = held["change_id"].as_str().expect("id").to_owned();
    store.approve(&id, "alice", None).expect("approve");
    let path = fx.state_dir().join("changes").join(format!("{id}.json"));
    let text = std::fs::read_to_string(&path).expect("read").replace(
        "\"max_tunnels_per_org\": 7",
        "\"max_tunnels_per_org\": 7000",
    );
    std::fs::write(&path, text).expect("tamper");
    let tampered = tool_err(&server, "apply_config_change", json!({"change_id": id})).await;
    assert!(tampered.to_string().contains("edited"), "{tampered}");
    assert!(
        fx.pool
            .log
            .calls("PUT", "/v1/orgs/acme/cache-policy")
            .is_empty()
    );
}

#[tokio::test]
async fn confirm_tool_needs_the_separate_token() {
    let fx = Fixture::start().await;
    let cfg = format!(
        "confirm_token_file = \"{}/confirm-token\"",
        fx.dir.display()
    );
    let server = fx.server(
        &format!("profile = \"admin\"\napproval = \"all\"\n{cfg}"),
        "",
    );
    let listed = ask(&server, modern(1, "tools/list", json!({}))).await;
    assert!(tool_names(&listed).contains(&"confirm_change".to_owned()));
    let held = tool_ok(&server, "disable_org_keys", json!({"org": "acme"})).await;
    let id = held["change_id"].as_str().expect("id").to_owned();
    let wrong = tool_err(
        &server,
        "confirm_change",
        json!({"change_id": id, "token": "guess"}),
    )
    .await;
    assert!(wrong.to_string().contains("token is wrong"));
    for secret_token in [ADMIN, SERVICE_KEY, HTTP_TOKEN] {
        let error = tool_err(
            &server,
            "confirm_change",
            json!({"change_id": id, "token": secret_token}),
        )
        .await;
        assert!(
            error.to_string().contains("token is wrong"),
            "other credentials are not the confirm token"
        );
    }
    assert!(
        tool_err(&server, "apply_config_change", json!({"change_id": id}))
            .await
            .to_string()
            .contains("approval")
    );
    let ok = tool_ok(
        &server,
        "confirm_change",
        json!({"change_id": id, "token": CONFIRM_TOKEN}),
    )
    .await;
    assert_eq!(ok["status"], "approved");
    assert!(
        !audit_text(&fx).contains(CONFIRM_TOKEN),
        "the confirmation token is redacted in the audit log"
    );
    let applied = tool_ok(&server, "apply_config_change", json!({"change_id": id})).await;
    assert_eq!(applied["result"]["disabled"], 2);
    assert_eq!(fx.pool.log.calls("DELETE", "/v1/orgs/acme/keys").len(), 1);
}

#[tokio::test]
async fn policy_changes_are_validated_diffed_and_applied() {
    let fx = Fixture::start().await;
    let server = fx.admin();
    let proposal = tool_ok(
        &server,
        "propose_config_change",
        json!({"action": "put_org_policy", "arguments": {"org": "acme", "toml": "[[policy]]\nname = \"acme-limits\"\nmax_tunnels_per_org = 50\n[policy.limits]\norg_max_gb_per_day = 20\n"}}),
    )
    .await;
    assert_eq!(proposal["status"], "proposed");
    assert_eq!(proposal["diff"][0]["policy"], "org/acme-limits");
    assert_eq!(proposal["diff"][0]["new"], true);
    let paths: Vec<&str> = proposal["diff"][0]["changes"]
        .as_array()
        .expect("changes")
        .iter()
        .filter_map(|c| c["path"].as_str())
        .collect();
    assert!(
        paths.contains(&"max_tunnels_per_org") && paths.contains(&"limits.org_max_gb_per_day"),
        "{paths:?}"
    );
    assert!(fx.pool.log.mutations().is_empty());
    let id = proposal["change_id"].as_str().expect("id");
    let applied = tool_ok(&server, "apply_config_change", json!({"change_id": id})).await;
    assert_eq!(applied["status"], "applied");
    let sent = &fx.pool.log.calls("PUT", "/v1/orgs/acme/cache-policy")[0].body;
    assert_eq!(sent["scope"], "org");
    assert_eq!(sent["match"], "acme");
    assert_eq!(sent["max_tunnels_per_org"], 50);
    let stored = tool_ok(&server, "list_policies", json!({"name": "acme-limits"})).await;
    assert_eq!(stored["items"][0]["doc"]["max_tunnels_per_org"], 50);

    // a global policy written by git is flagged as an override
    let override_ = tool_ok(
        &server,
        "put_policy",
        json!({"policies": [{"name": "global", "scope": "global", "kinds": ["rotating"], "providers": ["p1"], "regions": ["fr"], "min_ready": 4}], "dry_run": true}),
    )
    .await;
    assert!(
        override_["warnings"]
            .as_array()
            .expect("warnings")
            .iter()
            .any(|w| w.as_str().unwrap_or("").contains("written by git"))
    );
    let deleted = tool_err(
        &server,
        "delete_policy",
        json!({"scope": "global", "name": "global"}),
    )
    .await;
    assert!(deleted.to_string().contains("git wrote this policy"));
    tool_ok(
        &server,
        "delete_policy",
        json!({"scope": "org", "name": "acme-limits"}),
    )
    .await;
    assert_eq!(
        fx.pool
            .log
            .calls("DELETE", "/v1/policies/org/acme-limits")
            .len(),
        1
    );
}

#[tokio::test]
async fn org_scope_and_engagement_limit_what_can_change() {
    let fx = Fixture::start().await;
    let server = fx.server(
        "profile = \"admin\"",
        "[scope]\nengagement = \"SOW-42\"\nallowed_orgs = [\"acme\"]",
    );
    let outside = tool_err(
        &server,
        "create_org_block",
        json!({"org": "other", "scope": "pool", "value": "shared", "reason": "x"}),
    )
    .await;
    assert!(
        outside
            .to_string()
            .contains("outside this server's authorized scope")
    );
    let shared = tool_err(&server, "put_inventory", json!({"provider": "isp1", "entries": [{"provider": "isp1", "ip": "203.0.113.50", "host": "h.example", "port": 1}]})).await;
    assert!(
        shared.to_string().contains("scoped to specific orgs"),
        "{shared}"
    );
    let global = tool_err(
        &server,
        "put_policy",
        json!({"policies": [{"name": "g2", "scope": "global", "regions": ["fr"]}]}),
    )
    .await;
    assert!(global.to_string().contains("scoped to specific orgs"));
    let read_outside = tool_err(&server, "get_org", json!({"org": "other"})).await;
    assert!(read_outside.to_string().contains("outside"));
    let inside = tool_ok(
        &server,
        "create_org_block",
        json!({"org": "acme", "scope": "pool", "value": "shared", "reason": "x"}),
    )
    .await;
    assert_eq!(inside["status"], "applied");
    assert!(audit_text(&fx).contains("\"engagement\":\"SOW-42\""));

    let expired = fx.server(
        "profile = \"admin\"",
        "[scope]\nexpires = \"2020-01-01T00:00:00Z\"",
    );
    let late = tool_err(
        &expired,
        "create_org_block",
        json!({"org": "acme", "scope": "pool", "value": "shared", "reason": "x"}),
    )
    .await;
    assert!(late.to_string().contains("expired"));
    let required = fx.server("profile = \"admin\"", "[scope]\nrequire_engagement = true");
    assert!(
        tool_err(
            &required,
            "create_org_block",
            json!({"org": "acme", "scope": "pool", "value": "shared", "reason": "x"})
        )
        .await
        .to_string()
        .contains("engagement")
    );
}

#[tokio::test]
async fn block_signals_use_the_org_key_route_or_the_operator_route() {
    let fx = Fixture::start().await;
    let server = fx.admin();
    let org_key = tool_ok(&server, "report_block_signal", json!({"exit_ip": "203.0.113.50", "target": "example.com:443", "type": "rate_limited", "session": "5f0a7c9e2b1d4c6f8a3e0b7d9c2a1f48"})).await;
    assert_eq!(org_key["result"]["route"], "org_key");
    assert_eq!(org_key["result"]["accepted"], 1);
    let sent = &fx.pool.log.calls("POST", "/v1/block-signals")[0];
    assert!(
        sent.authorization
            .as_deref()
            .is_some_and(|a| a.starts_with("Basic "))
    );
    assert_eq!(sent.body[0]["type"], "rate_limited");
    assert_eq!(sent.body[0]["target"], "example.com:443");
    let operator = tool_ok(
        &server,
        "report_block_signal",
        json!({"exit_ip": "203.0.113.51", "target": "example.com", "type": "forbidden"}),
    )
    .await;
    assert_eq!(operator["result"]["route"], "operator");
    assert_eq!(
        fx.pool.log.calls("POST", "/v1/ips/203.0.113.51/block")[0].body["target"],
        "example.com"
    );
    assert!(!audit_text(&fx).contains(ORG_KEY));
}

#[tokio::test]
async fn sessions_can_be_extended_and_ended_and_inventory_diffed() {
    let fx = Fixture::start().await;
    let server = fx.admin();
    let extended = tool_ok(
        &server,
        "extend_session",
        json!({"session_id": SESSION_ID, "additional_secs": 300}),
    )
    .await;
    assert_eq!(extended["status"], "applied");
    assert_eq!(
        fx.control
            .log
            .calls("PATCH", &format!("/rpc/sessions/{SESSION_ID}"))[0]
            .body,
        json!({"additional_secs": 300})
    );
    let both = tool_err(
        &server,
        "extend_session",
        json!({"session_id": SESSION_ID, "additional_secs": 1, "new_ttl_secs": 1}),
    )
    .await;
    assert!(both.to_string().contains("not both"));
    let too_long = tool_err(
        &server,
        "extend_session",
        json!({"session_id": SESSION_ID, "additional_secs": 7200}),
    )
    .await;
    assert!(too_long.to_string().contains("above this server's limit"));
    let ended = tool_ok(&server, "end_session", json!({"session_id": SESSION_ID})).await;
    assert_eq!(ended["result"]["released"], true);

    let diff = tool_ok(
        &server,
        "put_inventory",
        json!({"provider": "isp1", "dry_run": true, "entries": [
            {"provider": "isp1", "ip": "203.0.113.10", "host": "isp.example", "port": 8001},
            {"provider": "isp1", "ip": "203.0.113.99", "host": "isp.example", "port": 8001}
        ]}),
    )
    .await;
    assert_eq!(diff["diff"]["added"], json!(["203.0.113.99"]));
    assert_eq!(diff["diff"]["retired"], json!(["203.0.113.11"]));
    assert_eq!(diff["diff"]["unchanged"], 1);
    let empty = tool_err(
        &server,
        "put_inventory",
        json!({"provider": "isp1", "entries": []}),
    )
    .await;
    assert!(empty.to_string().contains("entries"));
}

#[tokio::test]
async fn mutation_budget_is_enforced_but_dry_runs_are_free() {
    let fx = Fixture::start().await;
    let server = fx.server(
        "profile = \"admin\"",
        "[limits]\nmax_mutations_per_hour = 2",
    );
    for _ in 0..5 {
        tool_ok(
            &server,
            "set_org_rate_limit",
            json!({"org": "acme", "requests_per_minute": 1, "burst": 1, "dry_run": true}),
        )
        .await;
    }
    tool_ok(
        &server,
        "set_org_rate_limit",
        json!({"org": "acme", "requests_per_minute": 1, "burst": 1}),
    )
    .await;
    tool_ok(
        &server,
        "set_org_rate_limit",
        json!({"org": "acme", "requests_per_minute": 2, "burst": 2}),
    )
    .await;
    let third = tool_err(
        &server,
        "set_org_rate_limit",
        json!({"org": "acme", "requests_per_minute": 3, "burst": 3}),
    )
    .await;
    assert!(third.to_string().contains("mutations in an hour"));
    assert_eq!(
        fx.control
            .log
            .calls("PUT", "/rpc/orgs/acme/rate-limit")
            .len(),
        2
    );
}

#[tokio::test]
async fn audit_log_records_every_call_with_caller_and_a_valid_chain() {
    let fx = Fixture::start().await;
    let server = fx.admin();
    let frames = converse(
        &server,
        &[
            call(1, "health", json!({})),
            call(2, "explain_refusal", json!({"code": "cache_empty"})),
            call(
                3,
                "create_org_block",
                json!({"org": "acme", "scope": "pool", "value": "shared", "reason": "audit test"}),
            ),
            call(4, "list_inventory", json!({"state": "bogus"})),
        ],
    )
    .await;
    assert_eq!(frames.len(), 4);
    let entries: Vec<Value> = audit_text(&fx)
        .lines()
        .map(|l| serde_json::from_str(l).expect("jsonl"))
        .collect();
    let results: Vec<&Value> = entries.iter().filter(|e| e["phase"] == "result").collect();
    assert_eq!(results.len(), 4);
    for entry in &entries {
        assert_eq!(entry["caller"]["transport"], "stdio");
        assert_eq!(entry["caller"]["client_name"], "conformance-client");
        assert_eq!(entry["caller"]["client_version"], "1.2.3");
    }
    let by_tool = |tool: &str| {
        results
            .iter()
            .find(|e| e["tool"] == tool)
            .copied()
            .unwrap_or_else(|| panic!("{tool}"))
    };
    assert_eq!(by_tool("health")["outcome"], "ok");
    assert_eq!(
        by_tool("create_org_block")["arguments"]["reason"],
        "audit test"
    );
    assert_eq!(by_tool("list_inventory")["outcome"], "error");
    assert!(
        by_tool("list_inventory")["detail"]
            .as_str()
            .expect("detail")
            .contains("invalid arguments")
    );
    assert!(
        entries
            .iter()
            .any(|e| e["phase"] == "intent" && e["tool"] == "create_org_block")
    );
    let report = audit::verify(&fx.audit_path()).expect("verify");
    assert_eq!(report.broken, None);
    assert!(report.entries >= 5);
    // an unknown tool is a protocol error and is not a tool call
    let unknown = ask(&server, call(5, "nope", json!({}))).await;
    assert_eq!(unknown["error"]["code"], -32602);
}
