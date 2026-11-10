//! Microbenchmarks of the session proxy's per-request work: header rewrite,
//! origin-form conversion, request-target parsing, WebSocket framing and leaf
//! certificate issue.
//!
//! This is the only bench file that links `proxyx-intercept` (BoringSSL). The
//! control plane's OpenSSL lives in `control_micro`.

use std::hint::black_box;

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use proxyx_bench::tls::Ca;
use proxyx_intercept::bench_support as bs;

/// What a client sends to a proxy for a plain-HTTP request: absolute-form
/// target, the session credential and a browser's usual headers.
fn proxy_request_head() -> Vec<u8> {
    concat!(
        "GET http://api.example.com/v1/items?page=2&sort=name HTTP/1.1\r\n",
        "Host: api.example.com\r\n",
        "Proxy-Authorization: Basic MDE5MmY1YjAtMDAwMC03MDAwLTgwMDAtMDAwMDAwMDAwMDAxOnB3\r\n",
        "Proxy-Connection: keep-alive\r\n",
        "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36\r\n",
        "Accept: application/json, text/plain, */*\r\n",
        "Accept-Language: en-US,en;q=0.9\r\n",
        "Accept-Encoding: gzip, deflate, br\r\n",
        "Cookie: session=4f9c2d1e8a7b; theme=dark; consent=1\r\n",
        "Cache-Control: no-cache\r\n",
        "\r\n"
    )
    .as_bytes()
    .to_vec()
}

fn header_rewrite(c: &mut Criterion) {
    let head = proxy_request_head();
    let inject = vec![
        ("X-Org-Trace".to_owned(), "bench".to_owned()),
        (
            "Authorization".to_owned(),
            "Bearer injected-token-value".to_owned(),
        ),
    ];
    let mut g = c.benchmark_group("mitm_header_rewrite");
    g.throughput(Throughput::Bytes(head.len() as u64));
    g.bench_function("rewrite_with_injection", |b| {
        b.iter(|| {
            black_box(bs::rewrite_request_head(
                black_box(&head),
                black_box(&inject),
            ))
        });
    });
    g.bench_function("strip_hop_by_hop_only", |b| {
        b.iter(|| black_box(bs::strip_hop_by_hop(black_box(&head))));
    });
    for (name, line) in [
        (
            "absolute_form",
            &b"GET http://api.example.com/v1/items?page=2 HTTP/1.1"[..],
        ),
        ("already_origin_form", &b"GET /v1/items?page=2 HTTP/1.1"[..]),
    ] {
        g.throughput(Throughput::Bytes(line.len() as u64));
        g.bench_function(format!("origin_form_{name}"), |b| {
            b.iter(|| black_box(bs::origin_form_request_line(black_box(line))));
        });
    }
    g.finish();
}

fn target_parse(c: &mut Criterion) {
    let mut g = c.benchmark_group("request_target_parse");
    g.throughput(Throughput::Elements(1));
    g.bench_function("connect_authority", |b| {
        b.iter(|| {
            black_box(bs::parse_connect_authority(black_box(
                "api.example.com:443",
            )))
        });
    });
    g.bench_function("forward_url", |b| {
        b.iter(|| {
            black_box(bs::parse_forward_url(black_box(
                "http://api.example.com:8080/v1/items?page=2&sort=name",
            )))
        });
    });
    g.finish();
}

/// A masked client-to-server text frame of `len` payload bytes.
fn masked_text_frame(len: usize) -> Vec<u8> {
    let mut frame = vec![0x81u8];
    match len {
        0..=125 => frame.push(0x80 | len as u8),
        126..=65535 => {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        }
        _ => {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }
    }
    frame.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]);
    frame.extend((0..len).map(|i| (i % 251) as u8));
    frame
}

fn websocket_frames(c: &mut Criterion) {
    let mut g = c.benchmark_group("websocket_frame");
    for len in [16usize, 1024, 65_536] {
        let frame = masked_text_frame(len);
        // the parser reads the header only, whatever the payload size: count
        // frames, not bytes
        g.throughput(Throughput::Elements(1));
        g.bench_function(format!("parse_header_{len}"), |b| {
            b.iter(|| black_box(bs::parse_ws_frame_header(black_box(&frame))));
        });
    }
    for len in [1024usize, 65_536] {
        let mut payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        g.throughput(Throughput::Bytes(len as u64));
        g.bench_function(format!("unmask_{len}"), |b| {
            b.iter(|| bs::ws_unmask(black_box(&mut payload), [0x12, 0x34, 0x56, 0x78]));
        });
    }
    // a 3-fragment message of 4 KiB, capture cap 512 KiB
    let fragment = vec![b'a'; 4096];
    g.throughput(Throughput::Bytes(3 * fragment.len() as u64));
    g.bench_function("reassemble_three_fragments", |b| {
        b.iter_batched(
            || bs::WsReassembler::new(512 * 1024),
            |mut r| {
                let _ = r.feed(&fragment, 0x1, false);
                let _ = r.feed(&fragment, 0x0, false);
                black_box(r.feed(&fragment, 0x0, true))
            },
            BatchSize::SmallInput,
        );
    });
    g.finish();
}

fn leaf_certificates(c: &mut Criterion) {
    let ca = Ca::generate("bench ca").expect("ca");
    let proxy_ca = bs::BenchCa::from_der(&ca.cert_der(), &ca.key_der()).expect("proxy ca");
    let mut g = c.benchmark_group("mitm_leaf_certificate");
    g.throughput(Throughput::Elements(1));
    proxy_ca.leaf("cached.example.com").expect("warm the cache");
    g.bench_function("cache_hit", |b| {
        b.iter(|| black_box(proxy_ca.leaf(black_box("cached.example.com"))));
    });
    // Every call a new name: key generation plus signing. A cache that fills
    // evicts, which is part of the real cost.
    let mut n = 0u64;
    g.sample_size(30);
    g.bench_function("issue_new_host", |b| {
        b.iter(|| {
            n += 1;
            black_box(proxy_ca.leaf(&format!("host{n}.example.com")))
        });
    });
    g.finish();
}

criterion_group!(
    benches,
    header_rewrite,
    target_parse,
    websocket_frames,
    leaf_certificates
);
criterion_main!(benches);
