# ProxyX documentation

Start with the [README](../README.md) for what ProxyX is and a quick start, then use this index.

## Concepts

| Page | Contents |
|---|---|
| [architecture.md](architecture.md) | The three planes (pool, session, control), request paths, state stores, failure behavior, crate layout |
| [edge-proxy.md](edge-proxy.md) | The self-hosted multi-IP proxy (`proxyx edge`): installing on a multi-IP host, listeners, egress pools, users, rules, limits, parents, logs |
| [capture-pipeline.md](capture-pipeline.md) | Capture flow from the session proxy through the broker and ingester into ClickHouse, delivery semantics, schema |

## Reference

| Page | Contents |
|---|---|
| [configuration.md](configuration.md) | Every configuration key, environment variable and default for the pool, session proxy, control plane, limiter and edge proxy |
| [gateway.md](gateway.md) | Pool gateway protocols, authentication, username grammar, cause codes and the `/v1` control API |
| [providers.md](providers.md) | Provider adapter schema, shipped adapters, static inventory, customer upstreams, mobile boxes, verification |
| [policies.md](policies.md) | Policy document format, scopes and precedence |
| [session-proxy.md](session-proxy.md) | Sessions, routing, interception, CA, TLS profiles, rate limits, the error header |
| [ai.md](ai.md) | AI/LLM-native overview: monitoring, management, dynamic configuration, LLM-assisted operations, responsible use |
| [mcp.md](mcp.md) | MCP server: client setup, tool catalog, safety model, approval, audit log |
| [control-api.md](control-api.md) | REST routes, GraphQL, query DSL, authentication modes and API keys, exports |
| [metrics/pool.md](metrics/pool.md), [metrics/session-proxy.md](metrics/session-proxy.md), [metrics/edge.md](metrics/edge.md) | Metric catalogues |

## Operations

| Page | Contents |
|---|---|
| [backends.md](backends.md) | Support matrix of every backend family (relational, object store, Redis and Valkey, ClickHouse, OpenSearch and Elasticsearch, Kafka and RabbitMQ), why each exists and how to share instances |
| [databases.md](databases.md) | PostgreSQL, MariaDB and SQLite: URLs, choosing a backend, migrations, differences and limits |
| [operations.md](operations.md) | Deploy order, migrations, health and readiness, drain, scaling, backups, rotation |
| [doctor.md](doctor.md) | `proxyx doctor` (role self-check: configuration, dependencies, CA, secrets, ports) and `proxyx assess pool` (pool health findings): usage, check tables, thresholds, exit codes, JSON |
| [monitoring.md](monitoring.md) | What to scrape, Prometheus rules and tests, the Grafana dashboard, Alertmanager routing, the alert table |
| [benchmarks.md](benchmarks.md) | Microbenchmarks and the `proxyx-bench` load tool: methodology, commands and measured numbers |
| [runbooks/](runbooks/README.md) | Diagnosis and mitigation for each alert |

## Elsewhere in the repository

- [`examples/`](../examples/): minimal working configuration files (`edge.toml` and a loopback `edge-loopback.toml` for the edge proxy).
- [`deploy/systemd/`](../deploy/systemd/): a hardened unit for `proxyx edge`.
- [`deploy/monitoring/`](../deploy/monitoring/): Prometheus rules and tests, a Grafana dashboard, Alertmanager and scrape examples.
- [`data/`](../data/): shipped provider adapters, the global policy and probe targets.
- [`docker/`](../docker/): the image, the development Compose stack and the VPN egress sidecar.
- [`prober/`](../prober/README.md): the optional browser prober.
