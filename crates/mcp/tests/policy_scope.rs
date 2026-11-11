//! Policy previews respect organization scope before backend reads and merged validation.

mod common;

use common::*;
use serde_json::json;

#[tokio::test]
async fn unauthorized_org_preview_is_rejected_before_backend_access() {
    let fx = Fixture::start().await;
    let server = fx.server("", "[scope]\nallowed_orgs = [\"acme\"]");
    let error = tool_err(
        &server,
        "validate_policy",
        json!({
            "org": "other",
            "policies": [{"name": "draft", "scope": "org", "match": "acme"}]
        }),
    )
    .await;

    assert_eq!(error["error"]["kind"], "refused");
    assert!(error.to_string().contains("authorized scope"));
    assert!(fx.pool.log.all().is_empty());
    assert!(fx.control.log.all().is_empty());
}

#[tokio::test]
async fn unauthorized_input_org_target_is_rejected_before_backend_access() {
    let fx = Fixture::start().await;
    let server = fx.server("", "[scope]\nallowed_orgs = [\"acme\"]");
    for input in [
        json!({
            "org": "acme",
            "policies": [{"name": "draft", "scope": "org", "match": "other"}]
        }),
        json!({
            "toml": "[[policy]]\nname = \"draft\"\nscope = \"org\"\nmatch = \"other\"\n"
        }),
    ] {
        let error = tool_err(&server, "validate_policy", input).await;
        assert_eq!(error["error"]["kind"], "refused");
        assert!(error.to_string().contains("authorized scope"));
    }
    assert!(fx.pool.log.all().is_empty());
    assert!(fx.control.log.all().is_empty());
}

#[tokio::test]
async fn whole_set_validation_errors_do_not_disclose_unauthorized_policies() {
    let fx = Fixture::start().await;
    fx.pool_state.lock().expect("pool").policies.extend([
        json!({
            "scope": "org", "name": "private-policy-name",
            "doc": {"name": "private-policy-name", "scope": "org", "match": "other", "regions": []}
        }),
        json!({
            "scope": "org", "name": "private-malformed-policy",
            "doc": {"name": "private-malformed-policy", "scope": "org", "match": "other", "private_unknown_field": true}
        }),
        json!({
            "scope": "global", "name": "private-mislabeled-policy",
            "doc": {"name": "private-mislabeled-policy", "scope": "org", "match": "other", "regions": []}
        }),
    ]);
    let server = fx.server("", "[scope]\nallowed_orgs = [\"acme\"]");
    let result = tool_ok(
        &server,
        "validate_policy",
        json!({
            "org": "acme",
            "policies": [{"name": "visible-invalid-policy", "scope": "org", "match": "acme", "regions": []}]
        }),
    )
    .await;

    assert_eq!(result["valid"], false);
    assert_eq!(result["merged_with_stored_policies"], true);
    assert!(
        result["error"]
            .as_str()
            .expect("error")
            .contains("visible-invalid-policy")
    );
    let text = result.to_string();
    for hidden in [
        "private-policy-name",
        "private-malformed-policy",
        "private_unknown_field",
        "private-mislabeled-policy",
    ] {
        assert!(!text.contains(hidden), "unauthorized policy leaked: {text}");
    }
    assert!(fx.pool.log.mutations().is_empty());
}

#[tokio::test]
async fn scoped_validation_keeps_shared_and_authorized_policies() {
    let fx = Fixture::start().await;
    fx.pool_state.lock().expect("pool").policies.extend([
        json!({
            "scope": "org", "name": "allowed-policy",
            "doc": {"name": "allowed-policy", "scope": "org", "match": "acme", "max_tunnels_per_org": 37}
        }),
        json!({
            "scope": "route_class", "name": "shared-provider-policy",
            "doc": {"name": "shared-provider-policy", "scope": "route_class", "match": "p1", "regions": []}
        }),
    ]);
    let server = fx.server("", "[scope]\nallowed_orgs = [\"acme\"]");
    let input = json!({"org": "acme", "policies": [global_policy()["doc"].clone()]});
    let invalid = tool_ok(&server, "validate_policy", input.clone()).await;
    assert_eq!(invalid["valid"], false);
    assert!(
        invalid["error"]
            .as_str()
            .expect("error")
            .contains("shared-provider-policy")
    );

    fx.pool_state.lock().expect("pool").policies[2]["doc"]["regions"] = json!(["de"]);
    let valid = tool_ok(&server, "validate_policy", input).await;
    assert_eq!(valid["valid"], true);
    assert_eq!(valid["merged_with_stored_policies"], true);
    assert_eq!(valid["effective_preview"]["max_tunnels_per_org"], 37);
    assert_eq!(valid["effective_preview"]["regions"], json!(["fr", "de"]));
    assert!(fx.pool.log.mutations().is_empty());
}

#[tokio::test]
async fn selector_preview_ignores_unauthorized_invalid_policies() {
    let fx = Fixture::start().await;
    fx.pool_state.lock().expect("pool").policies.push(json!({
        "scope": "org", "name": "private-selector-policy",
        "doc": {"name": "private-selector-policy", "scope": "org", "match": "other", "regions": []}
    }));
    let server = fx.server("", "[scope]\nallowed_orgs = [\"acme\"]");
    let result = tool_ok(
        &server,
        "explain_selector",
        json!({"org": "acme", "username": "px-kind-rotating-cc-fr-sid-scan42"}),
    )
    .await;

    assert_eq!(result["policy_check"]["checked"], true);
    assert!(!result.to_string().contains("private-selector-policy"));
    assert!(fx.pool.log.mutations().is_empty());
}
