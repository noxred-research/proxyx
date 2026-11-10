//! Microbenchmark of the control plane's traffic query lowering: the filter
//! tree a caller sends becomes the `WHERE` clause and bind list that go to
//! ClickHouse.
//!
//! This is the only bench file that links `proxyx-control` (OpenSSL, through
//! rdkafka). The session proxy's BoringSSL lives in `intercept_micro`.

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use proxyx_control::query::{TrafficQuery, lower_for_bench};
use serde_json::json;

fn query(value: serde_json::Value) -> TrafficQuery {
    serde_json::from_value(value).expect("a valid query")
}

fn lowering(c: &mut Criterion) {
    let simple = query(json!({
        "org_id": "org-1",
        "branches": [{ "host": { "op": "exact", "value": "api.example.com" } }],
        "limit": 100,
    }));
    let typical = query(json!({
        "org_id": "org-1",
        "branches": [{
            "source_id": ["run-42"],
            "host": { "op": "contains", "value": "example.com" },
            "method": { "op": "any", "filters": [
                { "op": "exact", "value": "POST" }, { "op": "exact", "value": "PUT" }
            ]},
            "path": { "op": "regex_match", "value": "^/v[0-9]+/items/[0-9a-f-]{36}$" },
            "status_code": { "op": "gte", "value": 400 },
            "duration_ms": { "op": "all", "filters": [
                { "op": "gt", "value": 250 }, { "op": "lt", "value": 5000 }
            ]},
        }],
        "order": "desc",
        "limit": 100,
    }));
    let heavy = query(json!({
        "org_id": "org-1",
        "branches": [
            {
                "source_id": ["run-1", "run-2", "run-3"],
                "request_body": { "op": "contains", "value": "password" },
                "response_body": { "op": "all", "filters": [
                    { "op": "contains", "value": "error" },
                    { "op": "not", "filter": { "op": "contains", "value": "retry" } },
                    { "op": "length", "value": { "op": "gt", "value": 1024 } }
                ]},
                "request_sends_cookies": true,
                "request_header": { "key": "x-api-key", "value": "k_live_123" },
            },
            {
                "host": { "op": "regex_match", "value": "(?i)^(api|auth)\\.example\\.(com|org)$" },
                "mime_type": { "op": "exact", "value": "application/json" },
                "response_size": { "op": "gte", "value": 1048576 },
                "correlation_id": { "op": "is_present" },
            },
            {
                "account_id": { "op": "exact", "value": "acct-7" },
                "tool_call_id": { "op": "any", "filters": [
                    { "op": "exact", "value": "call-1" }, { "op": "exact", "value": "call-2" }
                ]},
                "response_sets_cookies": true,
            },
        ],
        "limit": 500,
    }));

    let mut g = c.benchmark_group("query_lowering");
    for (name, q) in [
        ("simple", &simple),
        ("typical", &typical),
        ("heavy_three_branches", &heavy),
    ] {
        let (sql, _) = lower_for_bench(q);
        // throughput in bytes of the SQL fragment produced
        g.throughput(Throughput::Bytes(sql.len() as u64));
        g.bench_function(name, |b| {
            b.iter(|| black_box(lower_for_bench(black_box(q))));
        });
    }
    g.finish();
}

fn parsing(c: &mut Criterion) {
    let text = json!({
        "org_id": "org-1",
        "branches": [{
            "source_id": ["run-42"],
            "host": { "op": "contains", "value": "example.com" },
            "status_code": { "op": "gte", "value": 400 },
        }],
        "limit": 100,
    })
    .to_string();
    let mut g = c.benchmark_group("query_parse");
    g.throughput(Throughput::Bytes(text.len() as u64));
    g.bench_function("json_to_query", |b| {
        b.iter(|| black_box(serde_json::from_str::<TrafficQuery>(black_box(&text))));
    });
    g.finish();
}

criterion_group!(benches, lowering, parsing);
criterion_main!(benches);
