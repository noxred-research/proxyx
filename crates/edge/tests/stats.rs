//! Statistics use live runtime state and existing metric samples.
#![allow(clippy::unwrap_used)]

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::*;
use serde_json::Value;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

async fn stats_response(ops: SocketAddr, path: &str, accept: Option<&str>) -> Resp {
    let mut stream = TcpStream::connect(ops).await.unwrap();
    let accept = accept
        .map(|value| format!("Accept: {value}\r\n"))
        .unwrap_or_default();
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: ops\r\n{accept}Connection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    read_response(&mut stream, false).await
}

async fn start_ops(edge: &Edge) -> SocketAddr {
    proxyx_edge::ops::serve(edge.server.clone(), "127.0.0.1:0".parse().unwrap())
        .await
        .unwrap()
}

async fn stats_json(ops: SocketAddr) -> Value {
    let response = stats_response(ops, "/stats", None).await;
    assert_eq!(response.status, 200, "{response:?}");
    assert_eq!(response.header("content-type"), Some("application/json"));
    serde_json::from_slice(&response.body).unwrap()
}

fn row<'a>(snapshot: &'a Value, section: &str, kind: &str, name: &str) -> &'a Value {
    snapshot[section]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["kind"] == kind && row["name"] == name)
        .unwrap_or_else(|| panic!("missing {section}/{kind}/{name}: {snapshot}"))
}

#[tokio::test]
async fn stats_lists_idle_configuration_and_escapes_csv_names_without_creating_metrics() {
    let edge = Edge::start(&format!(
        r#"{OPEN}
[[listener]]
name = "quiet,\"stats\"\r\nline"
listen = "127.0.0.1:0"
auth = "none"
[[pool]]
name = "local"
addresses = ["127.0.0.1", "127.0.0.2"]
[[parent]]
name = "unused"
type = "http"
address = "127.0.0.1:9"
[health]
interval = "0"
"#
    ))
    .await;
    let ops = start_ops(&edge).await;
    let before = edge.server.shared.metrics.render();
    let snapshot = stats_json(ops).await;
    assert_eq!(snapshot["listeners"].as_array().unwrap().len(), 2);
    assert_eq!(snapshot["pools"].as_array().unwrap().len(), 1);
    assert_eq!(snapshot["nodes"].as_array().unwrap().len(), 3);
    for section in ["listeners", "pools", "nodes"] {
        for row in snapshot[section].as_array().unwrap() {
            assert_eq!(row["state"], "up");
            assert_eq!(row["active"], 0);
            assert_eq!(row["total_connections"], 0);
            assert_eq!(row["failures"], 0);
            assert!(row["latency_seconds"].is_null());
        }
    }
    let query = stats_response(ops, "/stats?format=csv", None).await;
    let accept = stats_response(ops, "/stats", Some("application/json, text/csv; q=0.8")).await;
    assert_eq!(query.status, 200);
    assert_eq!(
        query.header("content-type"),
        Some("text/csv; charset=utf-8")
    );
    assert_eq!(query.header("vary"), Some("Accept"));
    assert_eq!(query.body, accept.body);
    let csv = query.text();
    assert!(
        csv.starts_with(
            "kind,name,pool,state,active,total_connections,failures,latency_seconds\r\n"
        )
    );
    assert!(
        csv.contains("listener,\"quiet,\"\"stats\"\"\r\nline\",,up,0,0,0,\r\n"),
        "{csv:?}"
    );
    assert!(csv.contains("pool,local,,up,0,0,0,\r\n"));
    assert!(csv.contains("egress,127.0.0.2,local,up,0,0,0,\r\n"));
    assert!(csv.contains("parent,unused,,up,0,0,0,\r\n"));
    assert_eq!(before, edge.server.shared.metrics.render());
    let explicit_json = stats_response(ops, "/stats?format=json", Some("text/csv")).await;
    assert_eq!(
        explicit_json.header("content-type"),
        Some("application/json")
    );
    let not_acceptable = stats_response(ops, "/stats", Some("text/csv; q=0")).await;
    assert_eq!(
        not_acceptable.header("content-type"),
        Some("application/json")
    );
    assert_eq!(
        stats_response(ops, "/stats?format=xml", None).await.status,
        400
    );
    edge.server.shutdown(Duration::from_secs(1)).await;
    let stopped = stats_json(ops).await;
    assert_eq!(
        row(&stopped, "listeners", "listener", "main")["state"],
        "stopping"
    );
}

#[tokio::test]
async fn stats_returns_empty_pool_and_node_arrays_without_egress_configuration() {
    let edge = Edge::start(OPEN).await;
    let ops = start_ops(&edge).await;
    let snapshot = stats_json(ops).await;
    assert_eq!(snapshot["pools"], serde_json::json!([]));
    assert_eq!(snapshot["nodes"], serde_json::json!([]));
    assert_eq!(row(&snapshot, "listeners", "listener", "main")["active"], 0);
    edge.server.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn stats_reports_live_connections_failed_requests_and_successful_connect_latency() {
    let banner = banner_origin("127.0.0.1:0").await;
    let edge = Edge::start(&format!(
        "{OPEN}\n[[pool]]\nname = \"local\"\naddresses = [\"127.0.0.1\"]\n[server]\ndefault_pool = \"local\"\n"
    ))
    .await;
    let ops = start_ops(&edge).await;
    let mut live = tunnel(
        edge.addr("main"),
        &format!("origin.test:{}", banner.port()),
        None,
    )
    .await
    .unwrap();
    assert_eq!(read_line(&mut live).await, "ip:127.0.0.1");
    let snapshot = stats_json(ops).await;
    for (section, kind, name) in [
        ("listeners", "listener", "main"),
        ("pools", "pool", "local"),
        ("nodes", "egress", "127.0.0.1"),
    ] {
        let row = row(&snapshot, section, kind, name);
        assert_eq!(row["active"], 1, "{snapshot}");
        assert_eq!(row["total_connections"], 1, "{snapshot}");
        assert_eq!(row["failures"], 0);
    }
    assert!(row(&snapshot, "listeners", "listener", "main")["latency_seconds"].is_null());
    for (section, kind, name) in [("pools", "pool", "local"), ("nodes", "egress", "127.0.0.1")] {
        let latency = row(&snapshot, section, kind, name)["latency_seconds"]
            .as_f64()
            .unwrap();
        assert!(latency.is_finite() && latency >= 0.0);
    }
    let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let closed = reserved.local_addr().unwrap();
    drop(reserved);
    let failed = get(
        edge.addr("main"),
        &format!("origin.test:{}", closed.port()),
        "/ip",
        None,
    )
    .await;
    assert!(failed.status >= 500, "{failed:?}");
    drop(live);
    let snapshot = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let snapshot = stats_json(ops).await;
            if row(&snapshot, "listeners", "listener", "main")["active"] == 0
                && row(&snapshot, "listeners", "listener", "main")["failures"] == 1
            {
                break snapshot;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let listener = row(&snapshot, "listeners", "listener", "main");
    assert_eq!(listener["total_connections"], 2);
    let pool = row(&snapshot, "pools", "pool", "local");
    assert_eq!(pool["active"], 0);
    assert_eq!(pool["total_connections"], 2);
    assert_eq!(pool["failures"], 1);
    let csv = stats_response(ops, "/stats?format=csv", None).await.text();
    assert!(csv.contains("listener,main,local,up,0,2,1,\r\n"), "{csv}");
    assert!(csv.contains("pool,local,,up,0,2,1,"), "{csv}");
    edge.server.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn stats_reports_parent_failure_state_and_live_healthy_parent_activity_in_json_and_csv() {
    let origin = banner_origin("127.0.0.1:0").await;
    let healthy = Edge::start(OPEN).await;
    let denied =
        Edge::start("[[listener]]\nname = \"main\"\nlisten = \"127.0.0.1:0\"\nauth = \"none\"\n")
            .await;
    let edge = Edge::start(&format!(
        r#"{OPEN}
[server]
default_route = "parent"
[breaker.parent]
failure_threshold = 1
open_duration = "1h"
[health]
interval = "0"
[[parent]]
name = "failed"
type = "http"
address = "{}"
[[parent]]
name = "healthy"
type = "http"
address = "{}"
priority = 1
"#,
        denied.addr("main"),
        healthy.addr("main"),
    ))
    .await;
    let ops = start_ops(&edge).await;
    let mut live = tunnel(
        edge.addr("main"),
        &format!("origin.test:{}", origin.port()),
        None,
    )
    .await
    .unwrap();
    assert_eq!(read_line(&mut live).await, "ip:127.0.0.1");
    let snapshot = stats_json(ops).await;
    let failed = row(&snapshot, "nodes", "parent", "failed");
    assert_eq!(failed["state"], "open");
    assert_eq!(failed["active"], 0);
    assert_eq!(failed["total_connections"], 1);
    assert_eq!(failed["failures"], 1);
    assert!(failed["latency_seconds"].is_null());
    let healthy_row = row(&snapshot, "nodes", "parent", "healthy");
    assert_eq!(healthy_row["state"], "up");
    assert_eq!(healthy_row["active"], 1);
    assert_eq!(healthy_row["total_connections"], 1);
    assert_eq!(healthy_row["failures"], 0);
    assert!(healthy_row["latency_seconds"].as_f64().unwrap() >= 0.0);
    let csv = stats_response(ops, "/stats", Some("text/csv")).await.text();
    assert!(csv.contains("parent,failed,,open,0,1,1,\r\n"), "{csv}");
    assert!(csv.contains("parent,healthy,,up,1,1,0,"), "{csv}");
    drop(live);
    edge.server.shutdown(Duration::from_secs(1)).await;
    healthy.server.shutdown(Duration::from_secs(1)).await;
    denied.server.shutdown(Duration::from_secs(1)).await;
}
