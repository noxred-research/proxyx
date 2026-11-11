# Benchmarks

ProxyX has two kinds of benchmark: criterion microbenchmarks that time the small functions a connection
runs through, and a load tool, `proxyx-bench`, that pushes real tunnels through the pool gateway and the
session proxy and reports throughput, latency, and the CPU and memory of the process under test. Both live in
the `proxyx-bench` crate (`crates/bench`). The limiter service has its own throughput tool,
`limiter-bench` (`crates/limiter-bench`), which is unchanged and described at the end.

Every number on this page was measured on one host on 2026-11-10 and is labelled `this host`. Read the
[methodology](#methodology) before comparing them with anything: the host was shared and busy, the load runs
over loopback, and the load tool runs on the same machine as the process it measures.

- [What is measured](#what-is-measured)
- [Methodology](#methodology)
- [Commands](#commands)
- [Microbenchmark results](#microbenchmark-results)
- [The load tool](#the-load-tool)
- [End-to-end results, release build](#end-to-end-results-release-build)
- [End-to-end results, debug build](#end-to-end-results-debug-build)
- [Reading the numbers](#reading-the-numbers)
- [Limiter throughput](#limiter-throughput)
- [Smoke run in CI](#smoke-run-in-ci)

## What is measured

### Microbenchmarks

One bench file per linked-artifact family. The session proxy links BoringSSL and the control plane links
OpenSSL (through rdkafka); the two export the same C symbols, so no binary may hold both, and the two benches
that need them are behind features of the crate (see [Commands](#commands)).

| File | Group | What it times |
|---|---|---|
| `pool_micro` | `username_parse` | `InboundOptions::parse`: the `px-...` username grammar of [gateway.md](gateway.md#username-grammar), for a bare name, a region, a full option set, a sticky static name and two refusals. |
| `pool_micro` | `recipe_render` | `Adapter::recipe`: the shipped `oxylabs_res` adapter for a rotating country and a strict rotating city lease, and the shipped `oxylabs_isp` adapter for an inventory entry ([providers.md](providers.md#the-deterministic-recipe)). |
| `pool_micro` | `destination_denial` | `is_denied_destination`: the rule that refuses private, loopback, link-local and internal targets ([gateway.md](gateway.md#denied-destinations)), for public and denied names and for IP spellings. |
| `limiter_micro` | `token_bucket` | `TokenBucket::consume` in process, allowed and denied. |
| `limiter_micro` | `limiter_loopback` | The limiter client against a real `proxyx-limiter-server` started in the bench process on loopback: one consume per round trip through the pooled client, and batches of 1, 32 and 256 consumes by handle on one connection. |
| `intercept_micro` | `mitm_header_rewrite` | The session proxy's request-head rewrite: origin-form request line, `Proxy-Authorization` and `Proxy-Connection` dropped, headers injected; and the origin-form conversion alone. |
| `intercept_micro` | `request_target_parse` | The CONNECT authority and the plain-HTTP absolute URL parsers of the listeners. |
| `intercept_micro` | `websocket_frame` | Frame header parse, payload unmask (1 KiB and 64 KiB) and reassembly of a three-fragment message. |
| `intercept_micro` | `mitm_leaf_certificate` | The certificate authority that signs interception certificates: a cache hit, and a new host name (key generation and signing). |
| `control_micro` | `query_lowering` | The traffic query DSL of the control API ([control-api.md](control-api.md)) lowered to the `WHERE` clause and bind list that go to ClickHouse: a one-filter query, a typical filtered query and a three-branch query with regex, body, header and cookie filters. |
| `control_micro` | `query_parse` | The JSON of a query read into the query type. |

Where a function is private to its crate, the bench reaches it through a small `#[doc(hidden)]` module
(`proxyx_intercept::bench_support`, `proxyx_control::query::lower_for_bench`) that wraps the function and
changes no behaviour. Every group has a throughput annotation: bytes for things that read a byte string,
elements for a single decision.

### The load tool

| Scenario | Mode | What one request is |
|---|---|---|
| `gateway` | `tunnel` | `CONNECT 8.8.8.8:443` through the pool gateway with the `px` username and an org key, then the payload written through the tunnel and read back from an echo. |
| `gateway` | `forward` | `CONNECT 8.8.8.8:80`, then an HTTP/1.1 `POST` with the payload and a response with a body of the payload size, over the tunnel. |
| `session` | `passthrough` | `CONNECT localhost:<port>` through `proxyx-intercept` for a session that captures nothing, TLS to a stub origin through the tunnel, then an HTTP/1.1 `POST` of the payload and a response of the payload size. |
| `session` | `mitm` | The same, for a session that captures the host: the proxy terminates TLS with a certificate of its own CA (which the load client trusts), reads the exchange, sends the capture to the Redis stream and dials the origin. |

The gateway never forwards a plain `GET http://...` request: it answers `405` (see
[gateway.md](gateway.md#protocols)), so "forward" is HTTP carried over a CONNECT tunnel to port 80. The
destination rule refuses loopback and private targets, so the load asks for `8.8.8.8` and the stub provider,
which tunnels every request to its own stubs whatever host was asked, makes it reach a local server.

## Methodology

**Host.** Measured on one workstation, on 2026-11-10. It is the machine the other work of this repository was
done on, so it was busy.

| | |
|---|---|
| CPU | AMD Ryzen 9 9950X, 16 cores, 32 threads, one socket, one NUMA node; maximum 5.76 GHz; L3 64 MiB; governor `performance` |
| Memory | 187.8 GiB (`MemTotal` 196955064 kB) |
| Kernel | Linux 7.2.15-200.fc44.x86_64 (Fedora 44) |
| Toolchain | rustc 1.97.1 (8bab26f4f 2026-07-14) |
| Release profile | the workspace's `[profile.release]`: `lto = true`, `codegen-units = 1`, `panic = "abort"` |
| Services | Postgres on `127.0.0.1:45400`, Valkey on `127.0.0.1:45401` (database 13), both local |

**The host was not quiet.** Other builds and tools ran all the time. The one-minute load average read by
`uptime` was 142.79 at the start of the release end-to-end run and 114.02 at its end, and 115.62 to 129.61 for
the debug run (32 hardware threads). The microbenchmarks ran at a load average of 29 to 152. Treat every
absolute number as a lower bound that a quiet machine with the same CPU would beat, expect tail latencies
(p99, max) to be inflated by scheduling delay, and rely on the ratios between rows more than on one row. To
reproduce a number, run on a host with nothing else on it.

**Loopback.** Client, proxy and stub servers share one machine and one kernel network stack. There is no NIC,
no wire latency and no packet loss, the client and the stubs take CPU that a real deployment would not
spend on the same machine, and a loopback connect is far cheaper than a connect across a network. The
numbers show how much work the process does per request, not what a deployment's clients would see.

**What is timed.** A request is complete when its whole response is read. Latency is from the start of the
request to that moment; with `--keepalive=false` it includes opening the tunnel (the CONNECT, and the TLS
handshake in the session scenarios). `req/s` counts completed requests; `MB/s` counts application bytes, the
request body plus the response body, per second (1 MB = 10^6 bytes). Percentiles come from an HdrHistogram
with microsecond resolution and three significant digits.

**Target CPU and memory.** The tool reads `/proc/<pid>/stat` (user and system ticks, 100 per second) at the
start and the end of each concurrency level, and `/proc/<pid>/status` every 100 ms. `Target CPU s` is CPU
seconds the target used during the level (all threads), `Target CPU %` is that over the level's wall time as a
percentage of one core, and `Peak RSS` is the process's `VmHWM`, the peak since the process started, so it
only grows from one level to the next and includes the warmup.

**Warmup and sweep.** Each run starts the target fresh, sends one request as a check, runs the first
concurrency level for 2 s (release) or 1 s (debug) and drops the result (1 s for the tunnel-per-request and 64 KiB
runs), then runs the levels in order. The
levels were 1, 8, 32, 128 and 512 workers for the release keep-alive runs and 1, 8, 32 and 128 for debug. Each
keep-alive level ran 5 s (release) or 3 s (debug). Runs with a tunnel per request ran 10000 requests at
8, 32 and 128 workers (release; 8 and 32 for debug), not a duration: a new loopback connection per request
would use up the client's ephemeral ports in a few seconds.

**Debug versus release.** The debug rows use debug builds of the target and of the load tool, so they show a
build that is useful for development and not what to deploy. Release rows use release builds of both.

**Payload.** 1 KiB bodies unless the heading says 64 KiB.

**Not measured.** Throughput over a real network, TLS to a real origin, many distinct origins (the MITM runs
use one host, so every request finds its certificate in the cache), HTTP/2 to the origin, or more than one core
of load generator. The gateway's lease and exit-IP work runs once per tunnel, against one unit that is
always healthy.

## Commands

Build once, release for numbers:

```sh
export CARGO_TARGET_DIR=/path/to/target        # optional
cargo build --release -p proxyx-bench -p proxyx -p proxyx-intercept
```

Microbenchmarks (criterion; results land in `$CARGO_TARGET_DIR/criterion`, the profile is the `bench`
profile, which inherits `release`):

```sh
cargo bench -p proxyx-bench                                       # pool_micro and limiter_micro
cargo bench -p proxyx-bench --features intercept-bench --bench intercept_micro
cargo bench -p proxyx-bench --features control-bench   --bench control_micro
cargo bench -p proxyx-bench --bench pool_micro -- --quick         # a few seconds per bench
cargo bench -p proxyx-bench -- --test                             # default benches once, no timing
```

Run `intercept-bench` and `control-bench` separately to keep their BoringSSL and OpenSSL measurement paths isolated. Each benchmark has `required-features`, so a plain `cargo bench -p proxyx-bench` runs only the first two files. Enabling both features built all four executables in the local check; that build-only result is not proof that combining both TLS stacks in one executable is safe.

Load tool, with the services this repository's tests use (Postgres on 45400, Valkey on 45401):

```sh
B=${CARGO_TARGET_DIR:-target}/release

# pool gateway: spawn it with a generated configuration, sweep the concurrency
$B/proxyx-bench gateway --mode tunnel  --spawn $B/proxyx --concurrency 1,8,32,128,512 --duration 5s --warmup 2s
$B/proxyx-bench gateway --mode forward --spawn $B/proxyx --concurrency 32 --duration 5s --payload-bytes 65536

# session proxy
$B/proxyx-bench session --mode passthrough --spawn $B/proxyx-intercept --concurrency 1,8,32,128,512 --duration 5s
$B/proxyx-bench session --mode mitm        --spawn $B/proxyx-intercept --concurrency 8 --requests 10000 --keepalive=false

# machine-readable
$B/proxyx-bench session --mode mitm --spawn $B/proxyx-intercept --duration 5s --json > mitm.json
```

The numbers below came from exactly these commands with the flags in the table headings, through a small
script that ran them in a fixed order and wrote one JSON file per run.

## Microbenchmark results

Criterion, release (`bench`) profile, default sampling (3 s warmup, 100 samples), one run per bench, on
2026-11-10. `Median` is criterion's median estimate; the interval is its 95 % bootstrap interval of the
median. The host was loaded (see [Methodology](#methodology)), so the intervals show noise inside the run
only; two runs on this host would differ by more than the intervals in places.

| Group | Benchmark | Median | 95% interval of the median | Throughput |
|---|---|---|---|---|
| destination_denial | decimal_ip_spelling | 25.6 ns | 25.6 ns to 25.7 ns | 39.01 M elem/s |
| destination_denial | internal_suffix | 36.7 ns | 36.5 ns to 36.8 ns | 27.27 M elem/s |
| destination_denial | loopback_v6 | 25.7 ns | 25.6 ns to 25.8 ns | 38.92 M elem/s |
| destination_denial | metadata_ip | 18.8 ns | 18.3 ns to 20.4 ns | 53.23 M elem/s |
| destination_denial | private_ip | 12.2 ns | 12.2 ns to 12.2 ns | 81.98 M elem/s |
| destination_denial | public_ip | 15.4 ns | 15.4 ns to 15.4 ns | 64.93 M elem/s |
| destination_denial | public_name | 35.7 ns | 35.3 ns to 36.4 ns | 28.02 M elem/s |
| limiter_loopback | client_consume_round_trip | 6.50 us | 6.44 us to 6.64 us | 0.15 M elem/s |
| limiter_loopback | connection_consume_batch_1 | 6.42 us | 6.37 us to 6.54 us | 0.16 M elem/s |
| limiter_loopback | connection_consume_batch_256 | 9.19 us | 8.98 us to 9.26 us | 27.86 M elem/s |
| limiter_loopback | connection_consume_batch_32 | 6.87 us | 6.74 us to 6.96 us | 4.66 M elem/s |
| mitm_header_rewrite | origin_form_absolute_form | 31.8 ns | 30.6 ns to 33.0 ns | 1,531 MiB/s |
| mitm_header_rewrite | origin_form_already_origin_form | 13.6 ns | 13.0 ns to 14.6 ns | 2,032 MiB/s |
| mitm_header_rewrite | rewrite_with_injection | 327.9 ns | 319.8 ns to 337.1 ns | 1,454 MiB/s |
| mitm_header_rewrite | strip_hop_by_hop_only | 333.4 ns | 329.9 ns to 339.2 ns | 1,430 MiB/s |
| mitm_leaf_certificate | cache_hit | 52.3 ns | 51.8 ns to 53.0 ns | 19.11 M elem/s |
| mitm_leaf_certificate | issue_new_host | 53.34 us | 52.16 us to 54.20 us | 0.02 M elem/s |
| query_lowering | heavy_three_branches | 1.87 us | 1.74 us to 1.94 us | 410 MiB/s |
| query_lowering | simple | 85.5 ns | 81.7 ns to 88.8 ns | 257 MiB/s |
| query_lowering | typical | 684.4 ns | 623.9 ns to 739.8 ns | 251 MiB/s |
| query_parse | json_to_query | 393.0 ns | 382.2 ns to 404.7 ns | 374 MiB/s |
| recipe_render | rotating_city_strict | 758.7 ns | 725.5 ns to 782.2 ns | 1.32 M elem/s |
| recipe_render | rotating_country | 415.1 ns | 410.0 ns to 425.7 ns | 2.41 M elem/s |
| recipe_render | static_inventory_entry | 206.1 ns | 194.2 ns to 215.7 ns | 4.85 M elem/s |
| request_target_parse | connect_authority | 21.2 ns | 20.2 ns to 22.3 ns | 47.07 M elem/s |
| request_target_parse | forward_url | 32.8 ns | 32.1 ns to 33.2 ns | 30.52 M elem/s |
| token_bucket | consume_allowed | 9.9 ns | 9.8 ns to 9.9 ns | 101.32 M elem/s |
| token_bucket | consume_denied | 9.3 ns | 9.3 ns to 9.4 ns | 107.05 M elem/s |
| username_parse | bare | 15.0 ns | 14.9 ns to 15.2 ns | 127 MiB/s |
| username_parse | full | 272.3 ns | 258.6 ns to 284.2 ns | 242 MiB/s |
| username_parse | refused_repeated_key | 49.2 ns | 47.4 ns to 50.6 ns | 272 MiB/s |
| username_parse | refused_uppercase | 32.4 ns | 31.9 ns to 33.0 ns | 235 MiB/s |
| username_parse | region | 74.3 ns | 72.4 ns to 75.4 ns | 282 MiB/s |
| username_parse | sticky_static | 171.8 ns | 166.2 ns to 179.3 ns | 272 MiB/s |
| websocket_frame | parse_header_1024 | 2.4 ns | 2.0 ns to 2.6 ns | 421.41 M elem/s |
| websocket_frame | parse_header_16 | 1.7 ns | 1.7 ns to 1.7 ns | 583.65 M elem/s |
| websocket_frame | parse_header_65536 | 1.8 ns | 1.8 ns to 1.8 ns | 556.88 M elem/s |
| websocket_frame | reassemble_three_fragments | 154.8 ns | 153.8 ns to 156.1 ns | 75,680 MiB/s |
| websocket_frame | unmask_1024 | 73.3 ns | 72.7 ns to 75.0 ns | 13,328 MiB/s |
| websocket_frame | unmask_65536 | 4.30 us | 4.22 us to 4.38 us | 14,542 MiB/s |

### Debug profile, where noted

The same code in the unoptimized `dev` profile, for `pool_micro` and `limiter_micro` only, with `--quick`
(`cargo bench --profile dev -p proxyx-bench --bench pool_micro --bench limiter_micro -- --quick`), 2026-11-10,
load average about 86. These are for scale: a debug build runs these functions between 1.7 and about 30 times slower,
which is why every number to rely on is a release number.

| Group | Benchmark | Median | 95% interval of the median | Throughput |
|---|---|---|---|---|
| destination_denial | decimal_ip_spelling | 721.4 ns | 711.6 ns to 731.3 ns | 1.39 M elem/s |
| destination_denial | internal_suffix | 829.0 ns | 821.2 ns to 836.8 ns | 1.21 M elem/s |
| destination_denial | loopback_v6 | 393.2 ns | 392.4 ns to 394.0 ns | 2.54 M elem/s |
| destination_denial | metadata_ip | 258.9 ns | 257.9 ns to 260.0 ns | 3.86 M elem/s |
| destination_denial | private_ip | 241.1 ns | 236.8 ns to 245.4 ns | 4.15 M elem/s |
| destination_denial | public_ip | 270.8 ns | 269.2 ns to 272.4 ns | 3.69 M elem/s |
| destination_denial | public_name | 943.1 ns | 933.2 ns to 953.0 ns | 1.06 M elem/s |
| limiter_loopback | client_consume_round_trip | 11.20 us | 11.05 us to 11.34 us | 0.09 M elem/s |
| limiter_loopback | connection_consume_batch_1 | 10.46 us | 10.43 us to 10.49 us | 0.10 M elem/s |
| limiter_loopback | connection_consume_batch_256 | 82.85 us | 81.39 us to 84.31 us | 3.09 M elem/s |
| limiter_loopback | connection_consume_batch_32 | 19.24 us | 18.80 us to 19.68 us | 1.66 M elem/s |
| recipe_render | rotating_city_strict | 5.83 us | 5.74 us to 5.92 us | 0.17 M elem/s |
| recipe_render | rotating_country | 5.47 us | 5.36 us to 5.59 us | 0.18 M elem/s |
| recipe_render | static_inventory_entry | 2.05 us | 2.03 us to 2.07 us | 0.49 M elem/s |
| token_bucket | consume_allowed | 24.2 ns | 24.2 ns to 24.2 ns | 41.28 M elem/s |
| token_bucket | consume_denied | 20.5 ns | 20.2 ns to 20.8 ns | 48.85 M elem/s |
| username_parse | bare | 178.7 ns | 178.3 ns to 179.2 ns | 11 MiB/s |
| username_parse | full | 2.61 us | 2.57 us to 2.66 us | 25 MiB/s |
| username_parse | refused_repeated_key | 510.8 ns | 500.8 ns to 520.7 ns | 26 MiB/s |
| username_parse | refused_uppercase | 300.2 ns | 297.2 ns to 303.2 ns | 25 MiB/s |
| username_parse | region | 809.7 ns | 806.0 ns to 813.3 ns | 26 MiB/s |
| username_parse | sticky_static | 1.92 us | 1.87 us to 1.97 us | 24 MiB/s |

## The load tool

```text
proxyx-bench gateway [--mode tunnel|forward] [common flags] [--spawn <proxyx> | --pid <pid> --proxy <addr> --password <key> --target <host:port>]
proxyx-bench session [--mode passthrough|mitm] [common flags] [--spawn <proxyx-intercept> | --pid <pid> --proxy <addr> [--ca-der <file>]]
```

Common flags:

| Flag | Default | Meaning |
|---|---|---|
| `--concurrency LIST` | `16` | Concurrent workers. A comma list is a sweep: each level runs in turn against the same target. 1 to 20000. |
| `--duration T` | `5s` when `--requests` is not given | How long each level runs: `500ms`, `5s`, `2m`, `1h` or bare seconds. |
| `--requests N` | none | Requests each level runs (failed ones count). With `--duration` too, whichever ends first stops the level. |
| `--payload-bytes N` | `1024` | Bytes in every request body and every response body. 1 to 64 MiB. |
| `--keepalive[=BOOL]` | `true` | `true` reuses each tunnel for many requests. `--keepalive=false` opens one tunnel per request. |
| `--timeout T` | `10s` | Limit for one connect or one request; a longer one is a `timeout` error. |
| `--warmup T` | `0s` | Run the first level this long first and drop the result. |
| `--json` | off | Print the report as JSON. |
| `--spawn PATH` | | Start this binary as the target and stop it afterwards. |
| `--pid PID` | | Sample an already running target instead (attach mode). |
| `--workdir DIR` | a fresh directory under the temporary directory | Where generated configuration, the CA and the target's log go. |

`--spawn` and `--pid` exclude each other, and one is required.

**Spawn mode** builds everything the target needs:

- Gateway (`--spawn` a `proxyx` binary; flags `--database-url`, `--redis-url`, `--username`). It starts a stub
  provider (an HTTP proxy that checks one login and tunnels to local stubs), a TCP echo and an HTTP origin;
  writes an adapter, a policy, one inventory entry that points at the stub and the secret files under the
  work directory; drops and rebuilds the Postgres database `proxyx_ops_bench` on the server of `--database-url`
  (default `postgres://postgres@127.0.0.1:45400/postgres`), registers an org key, moves the unit to
  `available`, **flushes the Redis database of `--redis-url`** (default `redis://127.0.0.1:45401/13`, which
  nothing else may use) and puts the unit in the ready set. This is what the warmer would leave behind, so no
  warmer runs. It then starts `proxyx gateway --config <generated pool.toml>`, waits for `/readyz`, sends one
  request to prove the path works, and runs the sweep. The load logs in with `--username` (default
  `px-kind-static-cc-fr`) and the generated key.
- Session proxy (`--spawn` a `proxyx-intercept` binary; flags `--redis-url`, `--redis-prefix`). It generates
  two certificate authorities, one for the TLS stub origin and one for the proxy to sign with
  (`ca.der` and `ca.key.der` in the work directory, loaded by the proxy's `file` CA mode; the private key is written with mode `0600`), writes a proxy
  configuration with the rate limit raised far above any load, starts the proxy, waits for `/health`,
  writes a session into Redis under `<prefix>:session:<id>:data` the way the control plane does
  ([session-proxy.md](session-proxy.md)), and sends one request to prove the path works. In `passthrough` the
  session captures no host and the client trusts the origin's CA; in `mitm` it captures `localhost` and the
  client trusts the proxy's CA. The generated benchmark session sets `insecure_upstream_tls = true` in MITM mode because the local stub origin uses a fresh private CA; it does not change the proxy's global verification setting. These runs do not measure upstream certificate verification. The session and the capture stream are removed afterwards.

**Attach mode** (`--pid`) leaves setup to you: the tool samples the process and sends the load, and starts
only the stubs it needs itself. For the gateway you give `--proxy`, `--password` (the org key) and
`--target`, a `host:port` that your setup makes reach an echo (`tunnel`) or an HTTP/1.1 origin (`forward`). For
the session proxy you give `--proxy`, the same `--redis-url` and `--redis-prefix` as the proxy, and for
`--mode mitm` the proxy's CA as `--ca-der`.

**Output.** A table (or `--json`) with one row per concurrency level: requests, errors, requests per second,
MB per second, latency p50, p95, p99 and max (and in JSON min, mean and a separate connect-latency summary),
and the target's CPU seconds, CPU percent of one core, resident set and peak resident set. Errors are counted
by class, for example `connect_503_cache_empty` (the pool gateway's cause code is the reason phrase),
`connect_407_...`, `tls_handshake`, `http_status_502`, `read_reset`, `timeout`; one example message per class
is printed. The exit status is 0 when every request succeeded, 1 when any request failed or none completed,
and 2 for a usage or startup failure.

**Bounds.** At most 20000 workers and 64 MiB of payload; every operation has `--timeout`; the target is killed
if it does not stop within the grace period; nothing is left running when the tool exits normally.

## End-to-end results, release build

Release builds of `proxyx`, `proxyx-intercept` and `proxyx-bench`, on 2026-11-10, host load average 142.79
at the start and 114.02 at the end. Every row had 0 errors. `Target` columns describe the gateway
(`proxyx gateway`, which also runs the control API and the ops server) or the session proxy process.

### gateway tunnel, keep-alive, 1 KiB bodies

| Concurrency | Requests | Errors | req/s | MB/s | p50 ms | p95 ms | p99 ms | max ms | Target CPU s | Target CPU % of one core | Peak RSS MiB |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 145170 | 0 | 29,033 | 59.5 | 0.03 | 0.04 | 0.07 | 5.07 | 1.04 | 21 | 28.5 |
| 8 | 166456 | 0 | 33,288 | 68.2 | 0.19 | 0.50 | 1.79 | 11.68 | 1.05 | 21 | 29.3 |
| 32 | 221881 | 0 | 44,348 | 90.8 | 0.59 | 1.48 | 3.06 | 37.18 | 1.28 | 26 | 31.9 |
| 128 | 216663 | 0 | 43,208 | 88.5 | 2.36 | 7.09 | 10.08 | 65.28 | 2.05 | 41 | 37.2 |
| 512 | 217652 | 0 | 43,271 | 88.6 | 9.48 | 22.72 | 31.92 | 1234.94 | 3.79 | 75 | 55.1 |

### gateway tunnel, new tunnel per request, 1 KiB bodies

| Concurrency | Requests | Errors | req/s | MB/s | p50 ms | p95 ms | p99 ms | max ms | Target CPU s | Target CPU % of one core | Peak RSS MiB |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 8 | 10000 | 0 | 1,620 | 3.3 | 4.50 | 9.49 | 13.31 | 23.68 | 2.86 | 46 | 38.1 |
| 32 | 10000 | 0 | 2,250 | 4.6 | 12.81 | 25.54 | 34.17 | 103.68 | 2.63 | 59 | 53.1 |
| 128 | 10000 | 0 | 3,520 | 7.2 | 30.86 | 69.06 | 130.11 | 137.98 | 2.72 | 96 | 75.8 |

### gateway tunnel, keep-alive, 64 KiB bodies

| Concurrency | Requests | Errors | req/s | MB/s | p50 ms | p95 ms | p99 ms | max ms | Target CPU s | Target CPU % of one core | Peak RSS MiB |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 32 | 45201 | 0 | 9,017 | 1,181.9 | 2.90 | 8.07 | 12.05 | 30.38 | 2.32 | 46 | 33.1 |

### gateway forward, keep-alive, 1 KiB bodies

| Concurrency | Requests | Errors | req/s | MB/s | p50 ms | p95 ms | p99 ms | max ms | Target CPU s | Target CPU % of one core | Peak RSS MiB |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 134536 | 0 | 26,906 | 55.1 | 0.03 | 0.04 | 0.07 | 4.74 | 1.00 | 20 | 29.4 |
| 8 | 165821 | 0 | 33,153 | 67.9 | 0.18 | 0.52 | 1.89 | 9.18 | 1.00 | 20 | 30.0 |
| 32 | 165501 | 0 | 33,074 | 67.7 | 0.84 | 2.13 | 3.91 | 39.65 | 1.00 | 20 | 32.9 |
| 128 | 189022 | 0 | 37,712 | 77.2 | 2.76 | 7.63 | 10.70 | 88.77 | 1.97 | 39 | 38.5 |
| 512 | 247497 | 0 | 49,069 | 100.5 | 7.93 | 19.17 | 28.18 | 2160.64 | 4.19 | 83 | 57.1 |

### gateway forward, new tunnel per request, 1 KiB bodies

| Concurrency | Requests | Errors | req/s | MB/s | p50 ms | p95 ms | p99 ms | max ms | Target CPU s | Target CPU % of one core | Peak RSS MiB |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 8 | 10000 | 0 | 1,375 | 2.8 | 5.43 | 10.11 | 13.14 | 23.15 | 2.98 | 41 | 37.6 |
| 32 | 10000 | 0 | 2,682 | 5.5 | 10.18 | 22.78 | 28.53 | 97.09 | 2.50 | 67 | 55.3 |
| 128 | 10000 | 0 | 3,173 | 6.5 | 34.66 | 84.61 | 109.50 | 132.48 | 2.65 | 84 | 75.2 |

### gateway forward, keep-alive, 64 KiB bodies

| Concurrency | Requests | Errors | req/s | MB/s | p50 ms | p95 ms | p99 ms | max ms | Target CPU s | Target CPU % of one core | Peak RSS MiB |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 32 | 40950 | 0 | 8,181 | 1,072.3 | 3.38 | 8.41 | 11.68 | 23.90 | 1.97 | 39 | 32.3 |

### session passthrough, keep-alive, 1 KiB bodies

| Concurrency | Requests | Errors | req/s | MB/s | p50 ms | p95 ms | p99 ms | max ms | Target CPU s | Target CPU % of one core | Peak RSS MiB |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 179139 | 0 | 35,825 | 73.4 | 0.03 | 0.03 | 0.05 | 6.71 | 1.30 | 26 | 23.7 |
| 8 | 254653 | 0 | 50,915 | 104.3 | 0.10 | 0.26 | 1.22 | 10.29 | 1.44 | 29 | 24.1 |
| 32 | 274133 | 0 | 54,792 | 112.2 | 0.45 | 1.22 | 2.58 | 23.57 | 1.42 | 28 | 25.5 |
| 128 | 357587 | 0 | 71,371 | 146.2 | 1.40 | 4.24 | 6.54 | 54.24 | 2.29 | 46 | 29.2 |
| 512 | 310829 | 0 | 61,572 | 126.1 | 6.13 | 16.53 | 24.78 | 1134.59 | 3.79 | 75 | 42.6 |

### session passthrough, new tunnel per request, 1 KiB bodies

| Concurrency | Requests | Errors | req/s | MB/s | p50 ms | p95 ms | p99 ms | max ms | Target CPU s | Target CPU % of one core | Peak RSS MiB |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 8 | 10000 | 0 | 3,257 | 6.7 | 2.28 | 4.09 | 6.14 | 11.67 | 0.87 | 28 | 29.8 |
| 32 | 10000 | 0 | 4,763 | 9.8 | 5.47 | 12.70 | 23.50 | 126.33 | 1.24 | 59 | 39.3 |
| 128 | 10000 | 0 | 4,593 | 9.4 | 24.80 | 45.82 | 109.82 | 220.54 | 1.47 | 68 | 64.5 |

### session passthrough, keep-alive, 64 KiB bodies

| Concurrency | Requests | Errors | req/s | MB/s | p50 ms | p95 ms | p99 ms | max ms | Target CPU s | Target CPU % of one core | Peak RSS MiB |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 32 | 63355 | 0 | 12,655 | 1,658.7 | 2.01 | 6.01 | 9.35 | 45.15 | 3.03 | 61 | 25.7 |

### session mitm, keep-alive, 1 KiB bodies

| Concurrency | Requests | Errors | req/s | MB/s | p50 ms | p95 ms | p99 ms | max ms | Target CPU s | Target CPU % of one core | Peak RSS MiB |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 49891 | 0 | 9,978 | 20.4 | 0.08 | 0.14 | 0.66 | 100.16 | 1.93 | 39 | 29.7 |
| 8 | 83042 | 0 | 16,605 | 34.0 | 0.25 | 1.22 | 5.49 | 22.21 | 3.05 | 61 | 36.6 |
| 32 | 70152 | 0 | 13,999 | 28.7 | 0.86 | 9.95 | 19.89 | 74.30 | 2.77 | 55 | 52.1 |
| 128 | 65738 | 0 | 13,104 | 26.8 | 6.54 | 26.13 | 32.49 | 127.04 | 3.61 | 72 | 70.9 |
| 512 | 74368 | 0 | 14,723 | 30.2 | 31.33 | 53.12 | 80.51 | 2064.38 | 5.20 | 103 | 123.4 |

### session mitm, new tunnel per request, 1 KiB bodies

| Concurrency | Requests | Errors | req/s | MB/s | p50 ms | p95 ms | p99 ms | max ms | Target CPU s | Target CPU % of one core | Peak RSS MiB |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 8 | 10000 | 0 | 1,555 | 3.2 | 4.29 | 10.79 | 15.34 | 66.50 | 6.91 | 107 | 35.3 |
| 32 | 10000 | 0 | 3,607 | 7.4 | 7.93 | 16.07 | 22.61 | 43.94 | 6.07 | 219 | 222.3 |
| 128 | 10000 | 0 | 6,061 | 12.4 | 19.74 | 32.32 | 43.36 | 58.14 | 5.89 | 357 | 488.2 |

### session mitm, keep-alive, 64 KiB bodies

| Concurrency | Requests | Errors | req/s | MB/s | p50 ms | p95 ms | p99 ms | max ms | Target CPU s | Target CPU % of one core | Peak RSS MiB |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 32 | 15872 | 0 | 3,154 | 413.4 | 4.21 | 45.95 | 80.83 | 122.11 | 4.71 | 94 | 671.5 |

## End-to-end results, debug build

Debug builds of the target and of the tool, on 2026-11-10, host load average 115.62 at the start and 129.61 at
the end. Fewer and shorter levels (see [Methodology](#methodology)). Every row had 0 errors.

### Debug: gateway tunnel, keep-alive, 1 KiB bodies

| Concurrency | Requests | Errors | req/s | MB/s | p50 ms | p95 ms | p99 ms | max ms | Target CPU s | Target CPU % of one core | Peak RSS MiB |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 31675 | 0 | 10,558 | 21.6 | 0.09 | 0.13 | 0.24 | 9.28 | 0.99 | 33 | 71.1 |
| 8 | 44368 | 0 | 14,740 | 30.2 | 0.39 | 1.49 | 3.17 | 25.71 | 1.21 | 40 | 72.2 |
| 32 | 69409 | 0 | 22,985 | 47.1 | 1.10 | 2.87 | 5.33 | 116.80 | 1.55 | 51 | 81.6 |
| 128 | 79301 | 0 | 25,537 | 52.3 | 4.04 | 9.28 | 13.41 | 228.74 | 2.13 | 69 | 88.2 |

### Debug: gateway tunnel, new tunnel per request, 1 KiB bodies

| Concurrency | Requests | Errors | req/s | MB/s | p50 ms | p95 ms | p99 ms | max ms | Target CPU s | Target CPU % of one core | Peak RSS MiB |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 8 | 10000 | 0 | 459 | 0.9 | 15.54 | 33.79 | 47.13 | 98.37 | 25.29 | 116 | 85.1 |
| 32 | 10000 | 0 | 1,494 | 3.1 | 18.96 | 38.75 | 55.26 | 125.69 | 15.49 | 231 | 104.0 |

### Debug: gateway tunnel, keep-alive, 64 KiB bodies

| Concurrency | Requests | Errors | req/s | MB/s | p50 ms | p95 ms | p99 ms | max ms | Target CPU s | Target CPU % of one core | Peak RSS MiB |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 32 | 25778 | 0 | 8,487 | 1,112.4 | 3.24 | 7.39 | 10.60 | 33.05 | 2.29 | 75 | 80.6 |

### Debug: gateway forward, keep-alive, 1 KiB bodies

| Concurrency | Requests | Errors | req/s | MB/s | p50 ms | p95 ms | p99 ms | max ms | Target CPU s | Target CPU % of one core | Peak RSS MiB |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 41786 | 0 | 13,926 | 28.5 | 0.07 | 0.07 | 0.10 | 6.41 | 0.78 | 26 | 70.3 |
| 8 | 35268 | 0 | 11,725 | 24.0 | 0.59 | 1.43 | 2.86 | 11.20 | 0.97 | 32 | 72.4 |
| 32 | 51998 | 0 | 17,207 | 35.2 | 1.54 | 3.69 | 5.97 | 84.35 | 1.32 | 44 | 80.5 |
| 128 | 67583 | 0 | 21,800 | 44.6 | 4.70 | 11.81 | 17.84 | 194.69 | 2.07 | 67 | 88.3 |

### Debug: gateway forward, new tunnel per request, 1 KiB bodies

| Concurrency | Requests | Errors | req/s | MB/s | p50 ms | p95 ms | p99 ms | max ms | Target CPU s | Target CPU % of one core | Peak RSS MiB |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 8 | 10000 | 0 | 550 | 1.1 | 13.09 | 26.94 | 37.63 | 84.09 | 22.89 | 126 | 84.9 |
| 32 | 10000 | 0 | 1,179 | 2.4 | 24.67 | 48.86 | 60.54 | 81.86 | 16.10 | 190 | 104.5 |

### Debug: gateway forward, keep-alive, 64 KiB bodies

| Concurrency | Requests | Errors | req/s | MB/s | p50 ms | p95 ms | p99 ms | max ms | Target CPU s | Target CPU % of one core | Peak RSS MiB |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 32 | 19413 | 0 | 6,395 | 838.2 | 4.29 | 10.02 | 14.96 | 38.24 | 1.90 | 63 | 80.9 |

### Debug: session passthrough, keep-alive, 1 KiB bodies

| Concurrency | Requests | Errors | req/s | MB/s | p50 ms | p95 ms | p99 ms | max ms | Target CPU s | Target CPU % of one core | Peak RSS MiB |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 23892 | 0 | 7,959 | 16.3 | 0.11 | 0.20 | 0.36 | 4.92 | 0.76 | 25 | 52.0 |
| 8 | 43068 | 0 | 14,332 | 29.4 | 0.43 | 1.27 | 2.85 | 18.40 | 1.09 | 36 | 53.0 |
| 32 | 68392 | 0 | 22,619 | 46.3 | 1.17 | 3.07 | 4.43 | 47.45 | 1.29 | 43 | 57.4 |
| 128 | 83254 | 0 | 27,009 | 55.3 | 3.76 | 9.65 | 13.25 | 142.34 | 1.68 | 54 | 64.1 |

### Debug: session passthrough, new tunnel per request, 1 KiB bodies

| Concurrency | Requests | Errors | req/s | MB/s | p50 ms | p95 ms | p99 ms | max ms | Target CPU s | Target CPU % of one core | Peak RSS MiB |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 8 | 10000 | 0 | 823 | 1.7 | 8.21 | 20.37 | 30.27 | 67.84 | 6.24 | 51 | 62.6 |
| 32 | 10000 | 0 | 1,472 | 3.0 | 17.90 | 43.97 | 68.35 | 198.40 | 4.54 | 67 | 78.3 |

### Debug: session passthrough, keep-alive, 64 KiB bodies

| Concurrency | Requests | Errors | req/s | MB/s | p50 ms | p95 ms | p99 ms | max ms | Target CPU s | Target CPU % of one core | Peak RSS MiB |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 32 | 11910 | 0 | 3,931 | 515.3 | 7.21 | 16.18 | 22.43 | 44.26 | 1.13 | 37 | 56.7 |

### Debug: session mitm, keep-alive, 1 KiB bodies

| Concurrency | Requests | Errors | req/s | MB/s | p50 ms | p95 ms | p99 ms | max ms | Target CPU s | Target CPU % of one core | Peak RSS MiB |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 4107 | 0 | 1,368 | 2.8 | 0.62 | 1.27 | 2.62 | 6.50 | 1.86 | 62 | 58.5 |
| 8 | 9259 | 0 | 3,073 | 6.3 | 1.72 | 5.78 | 23.77 | 52.86 | 3.43 | 114 | 67.4 |
| 32 | 12800 | 0 | 4,167 | 8.5 | 3.21 | 34.75 | 59.81 | 104.00 | 4.02 | 131 | 78.0 |
| 128 | 10531 | 0 | 3,304 | 6.8 | 16.69 | 93.25 | 155.78 | 208.77 | 3.87 | 121 | 98.6 |

### Debug: session mitm, new tunnel per request, 1 KiB bodies

| Concurrency | Requests | Errors | req/s | MB/s | p50 ms | p95 ms | p99 ms | max ms | Target CPU s | Target CPU % of one core | Peak RSS MiB |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 8 | 10000 | 0 | 337 | 0.7 | 20.82 | 48.06 | 67.39 | 118.72 | 37.60 | 127 | 72.1 |
| 32 | 10000 | 0 | 1,094 | 2.2 | 25.97 | 55.55 | 70.33 | 121.15 | 30.69 | 336 | 304.4 |

### Debug: session mitm, keep-alive, 64 KiB bodies

| Concurrency | Requests | Errors | req/s | MB/s | p50 ms | p95 ms | p99 ms | max ms | Target CPU s | Target CPU % of one core | Peak RSS MiB |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 32 | 4801 | 0 | 1,559 | 204.4 | 8.81 | 90.62 | 159.10 | 243.84 | 4.23 | 137 | 593.0 |

## Reading the numbers

These come from the release tables above, on this host and under its load.

- **The functions on the hot path are cheap.** In the release microbenchmarks the full `px` username parses in
  272.3 ns, the destination rule answers in 12.2 to 36.7 ns, rendering a rotating adapter recipe takes
  415.1 to 758.7 ns, a token-bucket consume 9.9 ns, and the request-head rewrite of the MITM path 327.9 ns for a
  roughly 500-byte head. A new interception certificate costs 53.34 us once per host name; a cached one
  52.3 ns. A limiter consume over loopback costs 6.50 us per round trip, and a batch of 256 consumes on one
  connection takes 9.19 us (27.86 M consumes per second).
- **Throughput stops growing early and latency takes the rest.** For keep-alive 1 KiB requests the gateway
  tunnel goes from 29,033 req/s with one worker to 44,348 with 32, and stays there (43,208 at 128 and 43,271 at
  512 workers) while p50 latency rises from 0.59 ms to 9.48 ms: more workers only queue. Session passthrough
  peaks at 71,371 req/s (128 workers); session MITM peaks at 16,605 req/s (8 workers) and sits between 13,104
  and 14,723 req/s from 32 workers up.
- **These runs do not find the targets' CPU ceilings.** At 128 workers the gateway used 41 % of one core and the
  passthrough session proxy 46 %, while their throughput had stopped growing. The load tool, the stub servers and
  the other work on the host took the rest. Use the CPU columns to compare what a request costs the target
  (for example 1.05 CPU s for 166,456 gateway requests at 8 workers), and not as a statement of capacity.
- **Interception costs about a third of passthrough on small requests.** At 8 workers with 1 KiB bodies and
  keep-alive, MITM served 16,605 req/s against 50,915 for passthrough, at 3.05 against 1.44 target CPU
  seconds over a run of the same length.
- **A tunnel per request is 10 to 20 times slower than reuse.** At 8 workers the gateway tunnel falls
  from 33,288 to 1,620 req/s, session passthrough from 50,915 to 3,257 and session MITM from 16,605 to
  1,555. Each of these requests pays the CONNECT, for the gateway the whole open pipeline (key check, policy
  narrowing, lease, dial through the provider and the provider's CONNECT), and for the session proxy the
  session lookup, the upstream dial and the TLS handshake.
- **Large bodies cost MITM the most.** With 64 KiB bodies at 32 workers the gateway tunnel moved 1,181.9 MB/s
  and passthrough 1,658.7 MB/s; MITM moved 413.4 MB/s, about a quarter of passthrough, and its peak resident set
  reached 671.5 MiB against 25.7 MiB for passthrough (in MITM mode the proxy reads and captures every body).
  Size the memory of a session proxy that intercepts large bodies with this in mind.
- **Debug builds are slow where the code does real work.** For the gateway, a tunnel per request at 8 workers
  ran at 459 req/s in the debug build against 1,620 in release, and used 25.29 CPU s against 2.86 for the same
  10000 requests.

## Limiter throughput

`limiter-bench` (`crates/limiter-bench`) is the load tool of the rate-limit service: client threads each hold a
persistent connection to a running `proxyx limiter`, create a working set of buckets, then run pipelined
consumes by handle, and it prints one `METRIC` line per workload (uniform, Zipf-skewed, concurrent, rate-limited)
with operations per second and p99 latency.

```sh
proxyx limiter 127.0.0.1:39091 &
limiter-bench 127.0.0.1:39091 1000000 32 32 all 1      # addr, ops, clients, batch, workloads, pipeline depth
```

The `all` selection runs uniform, Zipf-skewed and concurrent workloads. Run the rate-limited workload separately with `openloop_rate_limited`, for example `limiter-bench 127.0.0.1:39091 100000 4 32 openloop_rate_limited 1`.

The arguments are positional and every one is optional: `ADDR` (default `127.0.0.1:39091`), `OPS` (consumes per workload, default 1000000), `CLIENTS` (connections, one thread each, 1 to 4096, default 32), `BATCH` (consumes per frame, 1 to 4096, default 32), `WORKLOAD` (`all`, `uniform`, `zipfian`, `concurrent` or `openloop_rate_limited`, default `all`) and `PIPELINE_DEPTH` (frames in flight per connection, 1 to 1024, default 1). `OPS` must be at least `CLIENTS`, because each client runs `OPS / CLIENTS` consumes. `--help` prints this usage. A value that is not an integer in range, an unknown workload or an extra argument is a usage error (exit status 2, nothing is run); a limiter that cannot be reached is exit status 1.

It measures the service under sustained multi-client load. The `limiter_loopback` group above measures one
operation's cost from a single caller. The two answer different questions and neither replaces the other.

## Smoke run in CI

`ci/bench-smoke.sh` is a short bounded pass over every path above. It builds the three binaries (`PROFILE=debug`,
the default, or `PROFILE=release`; it honours `CARGO_TARGET_DIR`), then runs the gateway tunnel and forward loads,
the session passthrough and MITM loads (each `SMOKE_SECONDS`, default 3, at `SMOKE_CONCURRENCY`, default 8),
runs the load tool's integration tests against the real session proxy, and runs every microbenchmark once
(`cargo bench -- --test` in release, `cargo test --benches` in debug; the intercept and control benches each
in their own invocation). It prints the JSON summary of each run and exits nonzero on a startup failure, on any
request error, or when a microbenchmark does not run.

```sh
ci/bench-smoke.sh
PROFILE=release ci/bench-smoke.sh
PROXYX_BENCH_REDIS_URL=redis://127.0.0.1:45401/13 PROXYX_BENCH_DATABASE_URL=postgres://postgres@127.0.0.1:45400/postgres ci/bench-smoke.sh
```
