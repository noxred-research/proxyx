<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/banner-dark.svg">
  <img alt="ProxyX: open-source Rust proxy platform for pools, sessions and traffic capture" src="docs/assets/banner-light.svg" width="100%">
</picture>

**Next-generation AI/LLM-native proxy for authorized security research.**

An open-source Rust proxy platform for pools, sessions and traffic capture.

Lease pooled residential, ISP, datacenter and mobile IPs through one gateway, and route, inspect and record the traffic of authorized sessions, on infrastructure you control.

[![License: AGPL-3.0-only](https://img.shields.io/badge/license-AGPL--3.0--only-blue)](LICENSE) [![CI](https://github.com/noxred-research/proxyx/actions/workflows/ci.yml/badge.svg?branch=main&event=push)](https://github.com/noxred-research/proxyx/actions/workflows/ci.yml) [![Version 0.2.0](https://img.shields.io/badge/version-0.2.0-informational)](CHANGELOG.md) [![Rust 1.99.0](https://img.shields.io/badge/rust-1.99.0-orange?logo=rust)](rust-toolchain.toml) [![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)](CONTRIBUTING.md) [![Security policy](https://img.shields.io/badge/security-policy-informational?logo=github)](SECURITY.md)

[What it is](#what-is-proxyx) · [Features](#features) · [Architecture](#architecture) · [Quick start](#quick-start) · [Roles](#roles) · [Configuration](#configuration) · [Integrations](#integrations) · [Observability](#observability) · [Responsible use](#responsible-use-and-security) · [Docs](#documentation)

</div>

> [!IMPORTANT]
> **Authorized use only.** ProxyX is built for operating proxy infrastructure you own or are permitted to operate, and for inspecting traffic whose owner has consented. It is not for evading a site's protections, for abusing third-party services, or for intercepting anyone else's traffic. See [Responsible use and security](#responsible-use-and-security).

> **Status:** pre-1.0 (0.2.0). Interfaces, configuration keys and database schemas can still change between minor versions, and the [changelog](CHANGELOG.md) lists what changed. The distribution is this repository and tagged source releases; no prebuilt binaries, images or crates.io packages are published, so build them from source or with the provided [Dockerfile](docker/Dockerfile).

## What is ProxyX

ProxyX is one Rust workspace that builds two binaries and covers three jobs that usually need three separate products:

1. **A pool gateway.** Clients speak plain HTTP CONNECT or SOCKS5 to it. The username carries options (`px-kind-rotating-cc-fr-sid-scan42`) and an org key is the password. The gateway leases a unit from a pool of upstream IPs (rotating residential sessions, rented static ISP or datacenter IPs, SIM boxes, or an org's own upstream), dials it, and relays bytes. Policy decides which units an org may use, and breakers, cooldowns and budgets decide when to stop.
2. **A session proxy.** An authenticated, per-session proxy with TLS interception. A session names the hosts to capture, headers to inject, private routes for logical hosts, a browser TLS profile and a rate limit. Captured HTTP and WebSocket exchanges are published to a broker.
3. **A control plane.** REST and GraphQL APIs that create sessions and org API keys, ingest captures into ClickHouse (or OpenSearch / Elasticsearch), query them with a typed filter DSL and export traffic views to object storage.

A small in-memory rate-limit service completes the set. A background warmer and verifier keeps the pools healthy and checks every exit IP before it is used.

## Features

| Capability | What you get |
|---|---|
| **Pool gateway** | HTTP CONNECT and SOCKS5 ingress; org-key authentication with a brute-force limiter; a username grammar for kind, country, city, provider, lease time, sticky key and rotation; per-org tunnel and byte budgets; org blocks; fair-use accounting per static IP; graceful drain |
| **Provider adapters** | Declarative TOML templates that turn the gateway's options into each provider's username and password format. Residential and ISP examples ship in [`data/adapters`](data/adapters); you bring your own accounts |
| **Static inventory and customer upstreams** | Rented IPs and SIM boxes described in TOML, plus an org's own upstream proxy, validated at write time and fenced to that org |
| **Warmer and verifier** | Pre-creates rotating sessions, keeps them alive, re-checks static IPs, rotates SIM boxes, scores reputation with the scorers you configure, and replaces IPs that go bad |
| **Policies** | Layered documents (global, route class, org) for regions, ready-pool sizes, lease and rest times, block rules, spend and limits |
| **Session proxy** | Per-session credentials, captured and excluded host patterns, TLS interception for HTTP/1.1, HTTP/2 and WebSocket, header injection, private upstream overrides, egress chaining, browser-grade upstream TLS profiles, per-org rate limits |
| **Capture pipeline** | Protobuf envelopes on Redis Streams, Apache Kafka (or a Kafka-compatible broker) or RabbitMQ quorum queues, at-least-once delivery with per-source ordering and acks after the store write, a batching ClickHouse ingester with a circuit breaker |
| **Capture stores** | ClickHouse by default, or OpenSearch / Elasticsearch 8 behind the same query API; the OpenSearch store writes idempotently (a capture is never stored twice) and has its own index templates, see [capture-stores.md](docs/capture-stores.md) |
| **Databases** | PostgreSQL by default, or MariaDB 10.6+, or SQLite for a single host, selected by the scheme of `database_url` for the pool and the control plane; the same migrations and the same behavior on each, pinned by a cross-backend contract test, see [databases.md](docs/databases.md) |
| **Shared backends** | Every storage family (SQL database, object store, Redis or Valkey, ClickHouse, OpenSearch / Elasticsearch, Kafka or RabbitMQ) can share one instance with other products without collisions: a PostgreSQL schema per plane (`database_schema`), a key prefix (`redis_key_prefix`), a ClickHouse database, an index prefix, an object prefix (`traffic_views_prefix`) and S3 profiles for RustFS, MinIO, edge and compatible stores; ProxyX never touches objects outside its own namespace. Support matrix and tests in [backends.md](docs/backends.md) |
| **Control plane** | Session lifecycle with reference counting, org management, API keys, a typed query DSL over captures and WebSocket messages, GraphQL, Parquet exports with signed download URLs |
| **Capture correlation** | A client that runs many sessions over one control-plane session appends a sticky key to the session username (`<session-uuid>-sid-<key>`); each captured exchange carries it as `correlation_id`, so captures can be attributed per session. See [session-proxy.md](docs/session-proxy.md#sticky-key) |
| **Edge proxy** | `proxyx edge`: a database-less HTTP, CONNECT and SOCKS4/5 proxy over a host's own IP addresses with egress pools (round robin, random, least connections, sticky sessions), login options, ordered default-deny rules, bandwidth and connection limits, parent proxies with circuit breakers and health checks, and a `local` provider scheme so the pool gateway can lease the same addresses; see [edge-proxy.md](docs/edge-proxy.md) |
| **Rate-limit service** | An in-memory token-bucket daemon with a binary TCP protocol, used by the session proxy as an alternative to Redis |
| **AI/LLM-native** | An MCP server (`proxyx mcp`, stdio and streamable HTTP) lets AI agents monitor health, capacity, breakers and refusals, explain failures, search captured traffic, and, only when an operator enables capabilities, manage sessions, blocks, limits and policies through validated, approvable, audited changes. Optional passive capture analysis (`[analysis]`, off by default) works inside operator-listed sources and origins: authentication flows, sensitive-data findings with masked previews, natural-language traffic queries, API schema drafts and cursor-based capture feeds, all with evidence references. Optional LLM tools for any chat-completions compatible endpoint cover traffic summaries, block-page classification and policy drafts. See [docs/ai.md](docs/ai.md) |
| **Observability** | Prometheus metrics for every role, `/healthz` and `/readyz`, OpenTelemetry traces, optional Sentry, [runbooks](docs/runbooks/README.md) for every alert |

## Architecture

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/architecture-dark.svg">
    <img alt="ProxyX architecture: clients, pool gateway with provider adapters, session proxy, control plane and capture pipeline, state stores and platform services" src="docs/assets/architecture-light.svg" width="900">
  </picture>
</p>

```mermaid
flowchart LR
    C[Clients: curl, browsers, crawlers] -->|CONNECT / SOCKS5<br/>org key| G[proxyx gateway]
    G -->|lease + dial| U[(Upstream providers<br/>static IPs, customer upstreams)]
    W[proxyx warmer] -->|create, check, rotate| U
    G <--> R[(Valkey / Redis<br/>hot state)]
    W <--> R
    G <--> P[(PostgreSQL<br/>policies, inventory, keys)]
    W <--> P

    A[API clients] -->|"POST /rpc/sessions<br/>Bearer pxk_..."| CP[proxyx control api]
    CP <--> P2[(PostgreSQL)]
    CP --> R2[(Valkey / Redis<br/>sessions)]
    C2[Session clients] -->|"session id as username"| I[proxyx-intercept]
    I --> R2
    I -.->|egress chaining| G
    I --> L[proxyx limiter]
    I -->|captures| B[[Redis Streams / Kafka / RabbitMQ]]
    B --> IN[proxyx control ingester]
    IN --> CH[(ClickHouse)]
    CP -->|queries, exports| CH
```

The gateway and the session proxy are independent: the session proxy can reach the internet directly, through any HTTP or SOCKS5 proxy, or through the pool gateway. See [architecture](docs/architecture.md) for the data flows, the state each component keeps and the failure behavior.

## Quick start

### With Docker Compose

```
docker compose -f docker/docker-compose.yml up -d --build --wait
```

This builds one image with both binaries and starts PostgreSQL 18, Valkey 9, ClickHouse, the gateway, the warmer, the control API, the ingester, the session proxy and the limiter, with migrations applied and secrets and a development CA generated into volumes. Everything listens on `127.0.0.1`. The compose file is for development, not for production.

Initialization creates secret files with a private umask and retains existing credentials. If CA generation was interrupted, initialization refuses an incomplete CA instead of silently replacing it: restore all four CA files from the same backup before restarting. Keep the generated CA out of personal and system trust stores.

### From source

```
git clone https://github.com/noxred-research/proxyx.git && cd proxyx
cargo build --release          # target/release/proxyx and target/release/proxyx-intercept
```

You need the pinned Rust toolchain (see [`rust-toolchain.toml`](rust-toolchain.toml); `rustup` installs it), CMake, a C/C++ compiler and Clang (BoringSSL and librdkafka build from source), and `perl`. The protobuf compiler is vendored.

Start PostgreSQL, a Redis-compatible server and (for the session flow) ClickHouse, then use the files in [`examples/`](examples/) as a starting point. When running both planes, give the pool and the control plane separate databases (PostgreSQL by default; see [docs/databases.md](docs/databases.md) for MariaDB and SQLite):

```
export PROXYX_POOL_DATABASE_URL=postgres://proxyx:proxyx@localhost:5432/proxyx_pool
export PROXYX_POOL_REDIS_URL=redis://localhost:6379/1
export PROXYX_POOL_DATA_DIR=$PWD/data PROXYX_POOL_SECRETS_DIR=$PWD/secrets
export PROXYX_POOL_ADMIN_TOKEN_FILE=$PWD/secrets/admin-token

umask 077
mkdir -p secrets
for f in admin-token prober-token probe-key; do openssl rand -hex 32 > secrets/$f; done

target/release/proxyx migrate pool
target/release/proxyx gateway        # CONNECT 8080, SOCKS5 1080, API 8081, ops 8888
```

The gateway loads every adapter in `data/adapters`, and an adapter that names a secret file fails the load when the file is missing. Keep only the adapters you have credentials for in your data directory; the Compose stack mounts only the two that need none.

### Route traffic through the pool

Create an org key and register your own upstream proxy for the org. The admin token authorizes the `/v1` routes. With the Compose stack, read it from the gateway container:

```
ADMIN=$(docker compose -f docker/docker-compose.yml exec -T gateway cat /etc/proxyx/secrets/admin-token)
API=http://localhost:8081

# An org key. The reply is the only time the key can be read.
curl -sS -X POST "$API/v1/orgs/acme/keys" -H "Authorization: Bearer $ADMIN" \
  -H 'content-type: application/json' -d '{"label":"quickstart"}'
# {"org":"acme","key":"ak_..."}

# The org's own upstream: a public HTTP proxy you operate, exiting in France.
curl -sS -X PUT "$API/v1/orgs/acme/upstream" -H "Authorization: Bearer $ADMIN" \
  -H 'content-type: application/json' \
  -d '{"scheme":"http","host":"proxy.example.net","port":3128,"region":"fr","username":"u","password":"p"}'
curl -sS -X POST "$API/v1/orgs/acme/upstream/validate" -H "Authorization: Bearer $ADMIN"
```

Then use the key as the proxy password. The username selects options; the region must be one of the regions the effective policy allows (the shipped policy allows `fr` and `de`):

```
KEY=ak_...
curl -x "http://px-cc-fr:$KEY@localhost:8080" https://echo.example.test/
curl -x "socks5h://px-cc-fr:$KEY@localhost:1080" https://echo.example.test/
```

With a provider adapter and inventory in place instead of a customer upstream, the same username selects pool units: `px-kind-rotating-cc-fr-sid-scan42` pins a rotating session to the sticky key `scan42`. The full grammar, the refusal codes and the control API are in [gateway](docs/gateway.md); adapters and inventory are in [providers](docs/providers.md).

### Capture a session

The session flow uses the control plane and the session proxy. Create an API key, create a session with it, and send traffic through the returned `proxy_url`:

```
COMPOSE="docker compose -f docker/docker-compose.yml"
PXK=$($COMPOSE exec -T control-api proxyx control keys create --kind service --org acme --name quickstart)

curl -sS -X POST http://localhost:9000/rpc/sessions \
  -H "Authorization: Bearer $PXK" -H 'content-type: application/json' \
  -d '{"org_id":"acme","source":"demo","source_id":"run-1","captured_hosts":["example.org"],
       "excluded_hosts":[],"inject_headers":[],"serialize":false,"ttl_secs":600}' | tee session.json
# {"session_id":"…","proxy_url":"http://<session-id>:password@localhost:8443","ca_cert_pem":"-----BEGIN CERTIFICATE-----…",…}

jq -r .ca_cert_pem session.json > ca.pem
curl --proxy "$(jq -r .proxy_url session.json)" --cacert ca.pem https://example.org/
```

The session's UUID is its credential; the password is ignored. The proxy intercepts `example.org` with a certificate signed by the CA in `ca.pem`, relays the request and publishes the exchange to the capture stream. The ingester writes it to ClickHouse, and the query routes return it. Binaries from a source build use `proxyx control keys create ...` and `proxyx-intercept` directly. See [session proxy](docs/session-proxy.md) and [control API](docs/control-api.md).

## Roles

One `proxyx` binary runs one role per process, and `proxyx-intercept` runs the session proxy. They are separate binaries because the session proxy's upstream TLS stack (BoringSSL, for browser-grade fingerprints) and the control plane's Kafka client (OpenSSL) export the same symbols and cannot share a process.

| Command | Role | Listens on | Needs |
|---|---|---|---|
| `proxyx gateway` | Pool gateway: CONNECT and SOCKS5 ingress, leasing, `/v1` control API | 8080, 1080, 8082 (probe), 8081 (API), 8888 (ops) | PostgreSQL, MariaDB or SQLite; Redis |
| `proxyx warmer` | Pool maintenance: warming, keepalive, quality checks, sweeper | 8888 (ops) | PostgreSQL, MariaDB or SQLite; Redis |
| `proxyx migrate pool` | Apply (or `--check`) the pool schema | none | PostgreSQL, MariaDB or SQLite |
| `proxyx-intercept` | Session proxy: routing, TLS interception, capture | 8443 (CONNECT), 1080 (SOCKS5), 8888 (admin) | Redis; optionally the limiter |
| `proxyx control api` | Sessions, orgs, query, export and GraphQL API | 9000 | PostgreSQL, MariaDB or SQLite; Redis; ClickHouse or OpenSearch/Elasticsearch |
| `proxyx control ingester` | Consume captures, write the capture store, close sessions | 9001 (health) | PostgreSQL, MariaDB or SQLite; ClickHouse or OpenSearch/Elasticsearch; the broker |
| `proxyx control keys create\|list\|disable` | Manage API keys (`pxk_...`) | none | PostgreSQL, MariaDB or SQLite |
| `proxyx control schema export\|validate\|manifest` | GraphQL schema tooling | none | none |
| `proxyx migrate control` | Apply (or `--check`) relational, capture-store and broker schemas | none | Selected SQL database, capture store and broker, according to `--target` |
| `proxyx edge --config FILE [--check]` | Self-hosted multi-IP forward proxy: HTTP, CONNECT, SOCKS4/5, rules, limits, parents | your listeners, ops listener | one TOML file, no database |
| `proxyx limiter [ADDR]` | In-memory rate-limit service | 39091 | none |

[Operations](docs/operations.md) covers the deploy order, migrations, health and readiness, draining and scaling.

## Configuration

The pool, session proxy and control plane read TOML and their `PROXYX_POOL_*`, `PROXYX_INTERCEPT_*` or `PROXYX_CONTROL_*` environment variables; an explicit `--config FILE` takes precedence. The edge reads its required TOML file only. The limiter reads `PROXYX_LIMITER_*` environment variables and an optional listen address; it has no configuration file. [`docs/configuration.md`](docs/configuration.md) lists every key with its default and environment variable, and [`examples/`](examples/) has minimal working files. Provider adapters, policies and the static inventory are versioned TOML data under `data_dir`: see [providers](docs/providers.md) and [policies](docs/policies.md).

## Integrations

ProxyX is one of three open-source tools for authorized security research from [noxred-research](https://github.com/noxred-research). Each runs on its own, each keeps its own safety rules, and none relaxes another's. All three expose an MCP server, so one agent can operate them together.

### crawlx

[crawlx](https://github.com/noxred-research/crawlx) is a crawler for authorized security research, and ProxyX is an egress option for it. crawlx's `--proxy` flag takes an HTTP proxy URL, which the pool gateway is:

```
crawlx crawl https://app.example.org --mode static \
  --proxy "http://px-cc-fr-rot-sticky-sid-scan42:$KEY@proxyx-gateway:8080"
```

The sticky key keeps a scan on one exit IP; a different `sid` gets another. crawlx's scope, robots and egress policy still apply to every request it makes, and the gateway refuses private, loopback, link-local and metadata destinations. A client that sees the `X-ProxyX-Pool-Session` and `X-ProxyX-Exit-IP` headers of the CONNECT response can report a blocked target with `POST /v1/block-signals` (HTTP Basic, the org key as password) so the pool cools that IP for that target; see [gateway](docs/gateway.md#control-api). SOCKS5 replies carry no headers, so SOCKS5 clients cannot name a session.

### BrowserX

[BrowserX](https://github.com/noxred-research/browserx) ([browserx.dev](https://browserx.dev)) runs browser sessions for authorized security research. Its sessions can egress through the ProxyX pool gateway: BrowserX renders a sticky proxy username per session from a `{session}` template, for example `px-kind-rotating-cc-fr-sid-{session}`, so each browser session keeps its own exit IP, and the gateway's [username grammar](docs/gateway.md#username-grammar) applies unchanged.

The session proxy has a matching option for capture work. A client that runs many sessions over one control-plane session can append its own key to the session username, `<session-uuid>-sid-<key>`. The key never selects a session or changes routing; each captured exchange carries it as `correlation_id`, and an MCP analysis scope (`open_analysis_scope` with `correlation_ids`) can narrow an agent to the captures of one key. The key format, its limits and what it does not do are in [session-proxy.md](docs/session-proxy.md#sticky-key).

## Observability

- Every role serves Prometheus metrics at `/metrics` (the gateway and warmer on the ops port 8888, the session proxy on its admin port, the control plane on its API and ingester health ports, the edge proxy on `server.ops_listen`, the limiter on `PROXYX_LIMITER_METRICS_ADDR`). The metrics are catalogued in [`docs/metrics/`](docs/metrics/pool.md) ([pool](docs/metrics/pool.md), [session proxy](docs/metrics/session-proxy.md), [edge](docs/metrics/edge.md), [limiter](docs/metrics/limiter.md)), and [monitoring](docs/monitoring.md) covers the shipped alert rules and dashboard.
- The gateway and warmer answer `/healthz` (the process is up) and `/readyz` (dependencies are connected, the first snapshot is loaded and every listener is bound; `503 draining` after a stop request). The session proxy and the control plane answer `/health/live` and `/health/ready`.
- Logs are structured with `tracing`; set `RUST_LOG` for the filter and `json_logs` (pool) or `PROXYX_LOG_JSON` (session proxy and control plane) for JSON. `OTEL_ENABLED=true` exports OTLP traces, and a Sentry DSN turns on error reporting.
- [Runbooks](docs/runbooks/README.md) describe diagnosis and mitigation for each pool alert.

## Responsible use and security

ProxyX is infrastructure that can route traffic through third-party IP addresses and decrypt TLS. Use it only where you have the right to:

- **Pool addresses and provider accounts.** Operate pools from providers whose terms allow your use, and bring your own accounts. The shipped adapters are examples of the adapter format, not endorsements or bundled services.
- **Interception.** TLS interception is for traffic whose owner has consented: your own applications and test environments, and users who have been told and agreed. The proxy only intercepts hosts a session lists, never the hosts in `no_capture_hosts`, and clients must install the session's CA to be intercepted at all. Do not use it to read other people's traffic.
- **Captured data.** Captures contain request and response bodies and headers, including credentials a client sends. Store them as sensitive data, restrict access by org, and set retention to what you need.
- **Targets.** Do not use ProxyX to evade a site's protections, to attack or overload third parties, or for anything unlawful where you operate.

The gateway enforces a deny-first destination rule (private, loopback, link-local, CGNAT, metadata and cluster-internal names are refused), caps and budgets per org, and records an audit trail of operator changes. Those controls reduce harm; they do not replace authorization. Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## Documentation

| Page | Contents |
|---|---|
| [architecture.md](docs/architecture.md) | Components, data flows, state stores, failure behavior |
| [configuration.md](docs/configuration.md) | Every configuration key and environment variable |
| [gateway.md](docs/gateway.md) | Pool gateway protocols, authentication, username grammar, cause codes, control API |
| [providers.md](docs/providers.md) | Adapter schema, inventory, customer upstreams, mobile boxes, verification |
| [policies.md](docs/policies.md) | Policy document format and precedence |
| [session-proxy.md](docs/session-proxy.md) | Sessions, routing, interception, CA, TLS profiles, rate limits, [sticky keys](docs/session-proxy.md#sticky-key) for capture correlation |
| [control-api.md](docs/control-api.md) | REST and GraphQL APIs, query DSL, authentication, exports |
| [capture-pipeline.md](docs/capture-pipeline.md) | Broker, ClickHouse schema, delivery semantics |
| [capture-stores.md](docs/capture-stores.md) | ClickHouse versus OpenSearch / Elasticsearch: setup, schema, query differences, retention |
| [backends.md](docs/backends.md) | Support matrix of every backend family, why each exists, how to share instances, how each is tested |
| [databases.md](docs/databases.md) | PostgreSQL, MariaDB and SQLite: URLs, choosing, migrations, per-backend differences and limits |
| [edge-proxy.md](docs/edge-proxy.md) | The self-hosted multi-IP forward proxy: listeners, egress pools, users, rules, limits, parents, logs |
| [mcp.md](docs/mcp.md), [ai.md](docs/ai.md) | MCP server, tool catalog, approval and audit; AI/LLM-assisted operations and responsible use |
| [operations.md](docs/operations.md) | Deploy order, migrations, health, drain, scaling, backups, Compose profiles, VPN egress sidecar |
| [doctor.md](docs/doctor.md) | `proxyx doctor` and `proxyx assess pool` self-checks |
| [monitoring.md](docs/monitoring.md), [runbooks/](docs/runbooks/README.md) | Alert rules, dashboard and the runbook for each alert |
| [metrics/](docs/metrics/pool.md) | Metric catalogues |
| [benchmarks.md](docs/benchmarks.md) | Microbenchmarks and the load tool |

The full index is [docs/README.md](docs/README.md).

The Python [prober](prober/README.md) is an optional sidecar that measures candidate IPs with a real browser through the gateway's probe listener.

## Getting help

- **Documentation:** [docs/README.md](docs/README.md); operators start with [operations](docs/operations.md) and the [runbooks](docs/runbooks/README.md).
- **Bugs and feature requests:** open an issue with the matching form. Include the version or commit and a minimal reproduction, and remove credentials, keys and captured traffic first.
- **Questions:** use the question form after searching the docs and closed issues.
- **Security:** report vulnerabilities privately as described in [SECURITY.md](SECURITY.md), never in a public issue.
- **Conduct concerns:** [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Contributing

Issues and pull requests are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) for the checks, coding standards and review flow, and follow the [Code of Conduct](CODE_OF_CONDUCT.md). CI runs only on self-hosted runners: the `workflow-lint` check (`ci/check-self-hosted-only.py`) fails any job without the `self-hosted` label. Maintainers update dependencies and container base images by hand.

## Support the project

If ProxyX saves you time, a star helps others find it.

[![Star ProxyX on GitHub](https://img.shields.io/badge/star-proxyx-yellow?logo=github&style=social)](https://github.com/noxred-research/proxyx)

## License

ProxyX is licensed under the [GNU Affero General Public License v3.0 only](LICENSE) (`AGPL-3.0-only`). If you run a modified version as a network service, the license requires you to offer its source to the users of that service. Third-party material is listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

ProxyX is built and intended for authorized security research and testing only (see [Responsible use and security](#responsible-use-and-security)); this is a project policy and does not change the license.

### Project owners

ProxyX is owned and maintained by:

- [Noxtica](https://noxtica.com)
- [NoxRed Security Research](https://noxred.ai)
- [ProxyX](https://proxyx.dev)
- [Kaan Keskin](https://www.linkedin.com/in/keskinkaan/)
- [Onur Yalcin](https://www.linkedin.com/in/imonuryalcin/)
