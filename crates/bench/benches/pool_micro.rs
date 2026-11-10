//! Microbenchmarks of the pool gateway's per-connection work: parsing the
//! `px` username, rendering an adapter recipe and the destination rule.
//!
//! None of these crates links a TLS library, so this file may be built next to
//! the limiter benches. The session proxy and control plane have their own
//! bench files (`intercept_micro`, `control_micro`): BoringSSL and OpenSSL must
//! not meet in one binary.

use std::hint::black_box;

use common::Secret;
use common::types::{InventoryEntry, Region, Subtype, Target};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use policy::InboundOptions;
use provider::{AdapterFile, AdapterSet, UnitSpec};

const ROTATING_ADAPTER: &str = include_str!("../../../data/adapters/oxylabs_res.toml");
const STATIC_ADAPTER: &str = include_str!("../../../data/adapters/oxylabs_isp.toml");

fn username_parse(c: &mut Criterion) {
    let mut g = c.benchmark_group("username_parse");
    for (name, username) in [
        ("bare", "px"),
        ("region", "px-kind-rotating-cc-fr"),
        (
            "full",
            "px-kind-rotating-cc-fr-city-paris-sid-scan42-ttl-30m-prov-oxylabs_res",
        ),
        (
            "sticky_static",
            "px-kind-static-prov-oxylabs_isp-sid-job_17-ttl-1h",
        ),
        // the refusal paths are as hot as the accepting ones under a scan
        ("refused_repeated_key", "px-cc-fr-cc-de"),
        ("refused_uppercase", "px-cc-FR"),
    ] {
        g.throughput(Throughput::Bytes(username.len() as u64));
        g.bench_function(name, |b| {
            b.iter(|| black_box(InboundOptions::parse(black_box(username))));
        });
    }
    g.finish();
}

fn adapters() -> AdapterSet {
    let mut configs = toml::from_str::<AdapterFile>(ROTATING_ADAPTER)
        .expect("rotating adapter")
        .adapter;
    configs.extend(
        toml::from_str::<AdapterFile>(STATIC_ADAPTER)
            .expect("static adapter")
            .adapter,
    );
    AdapterSet::from_configs(configs, &|name: &str| match name {
        "oxylabs_res_user" | "oxylabs_isp_user" => Ok(Secret::new("acct")),
        "oxylabs_res_pass" | "oxylabs_isp_pass" => Ok(Secret::new("s3cret-pass")),
        other => Err(anyhow::anyhow!("no secret {other}")),
    })
    .expect("adapter set")
}

fn recipe_render(c: &mut Criterion) {
    let set = adapters();
    let rotating = set
        .get(&"oxylabs_res".parse().expect("id"))
        .expect("oxylabs_res");
    let isp = set
        .get(&"oxylabs_isp".parse().expect("id"))
        .expect("oxylabs_isp");
    let country = Region::new("fr", None).expect("region");
    let city = Region::new("fr", Some("paris")).expect("region");
    let entry = InventoryEntry {
        provider: "oxylabs_isp".parse().expect("id"),
        subtype: Subtype::Isp,
        plan: "bench".into(),
        ip: "203.0.113.10".parse().expect("ip"),
        host: "isp.oxylabs.io".into(),
        port: 8001,
        region: country.clone(),
        asn: None,
        credentials: None,
        box_handle: None,
        rental_end: None,
    };

    let mut g = c.benchmark_group("recipe_render");
    g.throughput(Throughput::Elements(1));
    g.bench_function("rotating_country", |b| {
        b.iter(|| {
            black_box(rotating.recipe(&UnitSpec::Rotating {
                session_id: "Ab3dEf6hIj9kLm2n",
                ttl_minutes: 1440,
                region: &country,
                strict: false,
            }))
        });
    });
    g.bench_function("rotating_city_strict", |b| {
        b.iter(|| {
            black_box(rotating.recipe(&UnitSpec::Rotating {
                session_id: "Ab3dEf6hIj9kLm2n",
                ttl_minutes: 1440,
                region: &city,
                strict: true,
            }))
        });
    });
    g.bench_function("static_inventory_entry", |b| {
        b.iter(|| {
            black_box(isp.recipe(&UnitSpec::Static {
                entry: &entry,
                credentials: None,
            }))
        });
    });
    g.finish();
}

fn destination_denial(c: &mut Criterion) {
    let target = |host: &str, port: u16| Target {
        host: host.to_owned(),
        port,
    };
    let mut g = c.benchmark_group("destination_denial");
    g.throughput(Throughput::Elements(1));
    for (name, t) in [
        ("public_name", target("www.example.com", 443)),
        ("public_ip", target("93.184.216.34", 443)),
        ("private_ip", target("10.1.2.3", 443)),
        ("metadata_ip", target("169.254.169.254", 80)),
        ("loopback_v6", target("[::1]", 8080)),
        ("decimal_ip_spelling", target("2130706433", 80)),
        ("internal_suffix", target("db.prod.svc.cluster.local", 5432)),
    ] {
        g.bench_function(name, |b| {
            b.iter(|| black_box(dial::is_denied_destination(black_box(&t))));
        });
    }
    g.finish();
}

criterion_group!(benches, username_parse, recipe_render, destination_denial);
criterion_main!(benches);
