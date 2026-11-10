//! The real binary: stdio JSON-RPC lines against fakes, and the operator commands.

mod common;

use std::process::Stdio;

use common::*;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

fn binary() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_proxyx-mcp"));
    command
        .env_remove("PROXYX_MCP_CONFIG")
        .env("RUST_LOG", "warn");
    command
}

#[tokio::test]
async fn stdio_session_transcript() {
    let fx = Fixture::start().await;
    let config = write_file(&fx.dir, "mcp.toml", &fx.config_text("", ""));
    let mut child = binary()
        .arg("--config")
        .arg(&config)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn proxyx-mcp");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut lines = BufReader::new(child.stdout.take().expect("stdout")).lines();
    let requests = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"demo","version":"1"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"explain_refusal","arguments":{"text":"HTTP/1.1 503 cache_empty"}}}),
        json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"pool_capacity","arguments":{}}}),
        json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"create_org_block","arguments":{"org":"acme","scope":"pool","value":"shared","reason":"demo"}}}),
    ];
    let mut transcript = Vec::new();
    for request in &requests {
        stdin
            .write_all(format!("{request}\n").as_bytes())
            .await
            .expect("write");
        transcript.push(format!(">>> {request}"));
        if request.get("id").is_some() {
            let line = tokio::time::timeout(std::time::Duration::from_secs(20), lines.next_line())
                .await
                .expect("reply in time")
                .expect("read")
                .expect("a line");
            let reply: Value = serde_json::from_str(&line).expect("stdout carries only JSON");
            assert_eq!(reply["id"], request["id"]);
            let shown = if request["id"] == 2 {
                let names: Vec<&str> = reply["result"]["tools"]
                    .as_array()
                    .expect("tools")
                    .iter()
                    .filter_map(|t| t["name"].as_str())
                    .collect();
                format!(
                    "<<< {{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{{\"tools\":[{} tools: {}]}}}}",
                    names.len(),
                    names.join(", ")
                )
            } else if request["id"] == 4 {
                format!(
                    "<<< {{\"jsonrpc\":\"2.0\",\"id\":4,\"result\":{{... \"isError\":{}, \"structuredContent\":{{\"status\":{}, \"providers\":[...]}}}}}}",
                    reply["result"]["isError"], reply["result"]["structuredContent"]["status"]
                )
            } else {
                format!("<<< {line}")
            };
            transcript.push(shown);
            if request["id"] == 5 {
                assert_eq!(
                    reply["result"]["isError"], true,
                    "a read-only server refuses the mutation"
                );
                assert!(
                    reply["result"]["content"][0]["text"]
                        .as_str()
                        .expect("text")
                        .contains("capability")
                );
            }
        }
    }
    drop(stdin);
    let status = tokio::time::timeout(std::time::Duration::from_secs(20), child.wait())
        .await
        .expect("exit in time")
        .expect("wait");
    assert!(status.success(), "exits 0 when stdin closes");
    println!(
        "--- stdio transcript ---\n{}\n--- end ---",
        transcript.join("\n")
    );
}

#[tokio::test]
async fn operator_commands_approve_reject_check_and_audit() {
    let fx = Fixture::start().await;
    let config = write_file(
        &fx.dir,
        "mcp.toml",
        &fx.config_text("profile = \"admin\"\napproval = \"all\"", ""),
    );
    let server = fx.server("profile = \"admin\"\napproval = \"all\"", "");
    let held = tool_ok(
        &server,
        "set_org_rate_limit",
        json!({"org": "acme", "requests_per_minute": 100, "burst": 10}),
    )
    .await;
    let id = held["change_id"].as_str().expect("id").to_owned();

    let run = |args: Vec<&str>| {
        let mut command = binary();
        command
            .arg("--config")
            .arg(&config)
            .args(args)
            .stdin(Stdio::null());
        async move { command.output().await.expect("run") }
    };
    let pending = run(vec!["pending"]).await;
    let text = String::from_utf8_lossy(&pending.stdout).to_string();
    assert!(text.contains(&id) && text.contains("proposed"), "{text}");
    let approved = run(vec!["approve", &id, "--yes", "--by", "alice"]).await;
    assert!(
        approved.status.success(),
        "{}",
        String::from_utf8_lossy(&approved.stderr)
    );
    let out = String::from_utf8_lossy(&approved.stdout).to_string();
    assert!(
        out.contains("\"requests_per_minute\"") && out.contains("approved"),
        "the diff is shown before approval: {out}"
    );
    let applied = tool_ok(&server, "apply_config_change", json!({"change_id": id})).await;
    assert_eq!(applied["status"], "applied");
    let again = run(vec!["approve", &id, "--yes"]).await;
    assert!(
        !again.status.success(),
        "an applied change cannot be approved again"
    );
    assert!(
        !run(vec!["approve", "chg_nothex", "--yes"])
            .await
            .status
            .success()
    );

    let check = run(vec!["check"]).await;
    let report: Value = serde_json::from_slice(&check.stdout).expect("check prints JSON");
    assert_eq!(report["pool_api"]["ok"], true);
    assert_eq!(report["control_api"]["ok"], true);
    assert_eq!(report["roles"]["overall"], "ok");
    assert!(!String::from_utf8_lossy(&check.stdout).contains(ADMIN));

    let verified = run(vec!["audit", "--verify"]).await;
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );
    let tools = run(vec!["tools"]).await;
    let list: Value = serde_json::from_slice(&tools.stdout).expect("tools JSON");
    assert!(
        list["tools"]
            .as_array()
            .expect("tools")
            .iter()
            .any(|t| t["tool"] == "set_org_rate_limit" && t["listed"] == true)
    );
}

#[tokio::test]
async fn http_transport_needs_a_token_file() {
    let fx = Fixture::start().await;
    let text = fx.config_text("", "").replace(
        &format!("token_file = \"{}/http-token\"", fx.dir.display()),
        "",
    );
    let config = write_file(&fx.dir, "mcp-notoken.toml", &text);
    let output = binary()
        .arg("--config")
        .arg(&config)
        .args(["--transport", "http"])
        .stdin(Stdio::null())
        .output()
        .await
        .expect("run");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("token_file"));
}
