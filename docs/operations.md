# Operations

This page covers deploying and running ProxyX: what to deploy, in which order, how schemas change, how to check health, how to stop a process without cutting traffic, and how to scale. The commands use the `proxyx` binary; run them as containers, as Kubernetes workloads or as systemd services, whichever you operate. [`docker/docker-compose.yml`](../docker/docker-compose.yml) is a working single-host reference for the wiring. Alert-driven procedures are in the [runbooks](runbooks/README.md).

## What to run

| Workload | Command | Replicas | State |
|---|---|---|---|
| Pool gateway | `proxyx gateway` | 2 or more behind a TCP load balancer | stateless; database + Redis |
| Pool warmer | `proxyx warmer` | 2 for availability (partition locks share the work) | stateless; database + Redis |
| Session proxy | `proxyx-intercept` | any number behind a TCP load balancer | stateless; Redis |
| Control API | `proxyx control api` | any number | stateless; database, Redis, ClickHouse |
| Ingester | `proxyx control ingester` | any number (one consumer group) | stateless; broker, ClickHouse, database |
| Limiter | `proxyx limiter ADDR` | one per session-proxy fleet (or per node) | in memory; a restart resets every bucket |
| Migrations | `proxyx migrate pool`, `proxyx migrate control` | one-shot job | database, ClickHouse or OpenSearch |

Backing services: PostgreSQL (two databases, see below), Redis or Valkey (always: sessions, rate limits, pool state; also the capture stream unless you choose Kafka or RabbitMQ), ClickHouse (or OpenSearch / Elasticsearch 8, see [capture-stores.md](capture-stores.md)), and optionally a Kafka-compatible broker (Redpanda) when you do not use Redis Streams for captures.

### Datastore layout

- **Two relational databases.** The pool plane and the control plane each keep their own migration history. Give them separate databases (for example `proxyx_pool` and `proxyx_control`) on one server, or separate SQLite files.
- **Choosing the relational backend.** The scheme of `database_url` selects PostgreSQL (default), MariaDB 10.6 or newer, or SQLite ([databases.md](databases.md) lists the differences). PostgreSQL and MariaDB serve any number of gateways, warmers, control APIs and ingesters on any number of hosts. **SQLite is one host only**: every ProxyX process that uses the file must run on that host, on a local disk, because SQLite is a file and a second host cannot share it safely (a file on a network filesystem is not safe at all). ProxyX logs a warning at every start on SQLite but cannot see the other hosts, so do not scale `gateway`, `warmer` or `control api` across hosts on SQLite. On SQLite writes also queue behind one writer; for a busy pool prefer PostgreSQL or MariaDB. Pick the backend before you have data: there is no copy between backends (see [databases.md](databases.md#choosing)).
- **Two Redis scopes.** Pool hot state (leases, ready sets) and session state (sessions, rate-limit buckets, the capture stream) are unrelated. Use two instances, or at least two database numbers (`redis://host:6379/1` for the pool), and keep a distinct `redis_key_prefix` per environment on a shared instance.
- **Redis persistence.** The pool's hot state is rebuilt from the database. The session proxy's capture stream is the only durable hand-off between the proxy and the ingester: if you use Redis Streams, enable persistence (AOF) on that instance, or use Redpanda. See [capture-pipeline.md](capture-pipeline.md).
- **ClickHouse.** The shipped DDL creates `Replicated*` tables with a tiered storage policy. The `http_captures` table keeps three days on the local volume, moves older parts to a volume named `cold`, and deletes rows after twelve months. A cluster therefore needs ClickHouse Keeper (or ZooKeeper) and a storage policy named `tiered` with a volume named `cold`. A single node has neither, so set `PROXYX_CONTROL_CLICKHOUSE__LOCAL_SINGLE_NODE=1` for `proxyx migrate control` to rewrite the DDL to plain engines without the tiering.

## Deploy order

Bring the system up in this order. Each step must succeed before the next starts.

1. **Datastores.** The relational database (PostgreSQL, MariaDB or SQLite), Redis, ClickHouse and, if used, the broker.
2. **Secrets.** Pool: `admin-token`, `prober-token`, `probe-key` and provider and scorer secrets in `secrets_dir`. Control: the database and ClickHouse credentials, and the CA certificate (and, for the session proxy, key) that both sides share.
3. **Migrations.** `proxyx migrate pool` and `proxyx migrate control` (see below).
4. **Pool gateway**, then **warmer**. The gateway copies the policy and inventory files under `data_dir` into the database at start, so start it first. It refuses to start when the open-file limit is below `2 x max_connections + 512`.
5. **Limiter**, then **session proxy** (when `ratelimit.backend = "limiter"`).
6. **Control API** and **ingester**.
7. **Self-check**: `proxyx doctor` before the first start and after a configuration change (see below).
8. **Smoke check**: `/readyz` on the gateway and warmer, `/health/ready` on the session proxy and the control API, `/health` on the ingester, a CONNECT through the gateway, a session created and a capture queried.

Every serving role retries its dependency connections with jittered backoff and never gives up while it runs, so the order is not brittle: a role that starts before its database waits and its `/readyz` stays `503 starting`. Only `/healthz` (liveness) answers throughout, so an orchestrator can tell a waiting process from a dead one.

## Self-check and assessment

- **`proxyx doctor`** validates the configuration of each role the way the role loads it and probes what the role needs, without starting anything: the database, Redis or Valkey (including the clock difference against Redis `TIME`), ClickHouse, the broker, the CA certificate (present, parses, expiry), adapter and provider secret files, the open-file limit, listener ports and DNS. It prints a pass/warn/fail table, `--json` prints the same as JSON, and the exit code is non-zero when a check fails. `proxyx-intercept doctor` does the same for the session proxy, which cannot share a process with the control plane's TLS stack. See [doctor.md](doctor.md).
- **`proxyx assess pool`** reads the database, Redis and the gateway's ops port and reports capacity against `min_ready` per partition, breaker states, exit-IP check freshness, reputation scores, block-signal rates, lease use, rental days left and budget use, each as OK, WARN or CRIT. It exits non-zero on CRIT.

## Monitoring and benchmarks

[monitoring.md](monitoring.md) describes the shipped Prometheus rules (every runbook has a rule), the Grafana dashboard and the Alertmanager example in [`deploy/monitoring`](../deploy/monitoring). [benchmarks.md](benchmarks.md) describes the microbenchmarks and the load tool `proxyx-bench`, and records the numbers measured on the reference host. `ci/bench-smoke.sh` is destructive for its target services: it flushes the Redis database named by `--redis-url` (13 by default) and rebuilds the Postgres database `proxyx_ops_bench`, so never point it at a real deployment.

## Timeouts, keepalive and breakers

Defaults are the values the code used before they became configurable; see [configuration.md](configuration.md) for the keys.

| Layer | Behaviour |
|---|---|
| Gateway sockets | TCP keepalive (60 s, then every 15 s, 4 probes) on client and upstream sockets; `handshake_timeout` 10 s, `first_byte_timeout` 3 s, `tunnel_idle_timeout` 10 m. |
| Gateway providers | A shared breaker per route class in Redis: five failures in 60 s open it, probes after 5 s doubling to 5 m, three passes close it ([runbook 004](runbooks/004-provider-breaker-open.md)). |
| Session proxy upstreams | A breaker per egress proxy, private override target and origin: when open, a connection is refused at once with `X-ProxyX-Error: upstream_unavailable` instead of dialing. Gauge `proxyx_intercept_upstream_breaker_state{target_kind}`. |
| Session proxy sockets | TCP keepalive, HTTP keepalive idle time and request cap, connect, TLS handshake and response timeouts are all configuration. |
| Redis clients | Connect and response bounded at 5 s. A blackholed Redis fails requests after 5 s and flips session proxy readiness; it does not hang them. |
| Limiter client | 1 s connect and exchange timeouts, keepalive, and a breaker (5 failures, 2 s open). While it is open, `failopen_policy` applies at once: `grant_tokens` lets traffic through, `deny` answers `429`. |
| Limiter service | One thread per connection, capped by `PROXYX_LIMITER_MAX_CONNECTIONS` (4096); TCP keepalive on accepted sockets. |
| Control API | `[http]` limits: a request still running after `request_timeout_secs` (60) gets `504`; more than `max_in_flight` (1024) concurrent requests get `503` with `Retry-After: 1`; each credential (the `Authorization` header, else the client address) has a token bucket of `per_key_rps` (100) with burst `per_key_burst` (200), `429` with `Retry-After` when empty. Health and metrics routes are exempt. Refusals count in `proxyx_control_api_refusals_total{reason}`. |

Known gap: TCP keepalive cannot be set on Redis sockets with the pinned client library; Redis calls are bounded by timeouts instead.

## Migrations

Schemas are **forward-only**. Migrations are embedded in the binary; a release never edits a migration it has shipped and only adds new ones. There is no automatic down-migration, so a rollback of the binary runs against the newer schema. To make that safe, each release keeps schema changes backward compatible with the previous release (add before you use, remove one release later).

```
proxyx migrate pool --check            # list pending migrations, exit 1 if any
proxyx migrate pool                    # apply
proxyx migrate control --check         # pending database and ClickHouse migrations, exit 1 if any
proxyx migrate control                 # apply: the database, the capture store, and the Kafka topic or RabbitMQ queues of broker_kind
proxyx migrate control --target database      # (alias: postgres) or: clickhouse, opensearch, broker, all (default: the database plus the configured capture store)
```

- Run migrations as a one-shot job before rolling the new version out, never from the serving processes. The serving roles do not apply migrations at start. The only start-time check is the OpenSearch ingester's: it refuses to run unless its index templates exist at this build's schema version.
- `migrate pool` has its own 60 second connect timeout and fails instead of waiting.
- ClickHouse migrations are SQL files applied in name order and recorded in a `_ch_migrations` table, so each runs once. They create and alter tables and materialized views.
- `migrate pool` and `migrate control` work the same on PostgreSQL, MariaDB and SQLite: each backend has its own migration directory with the same versions, so `--check` lists the same names. Concurrent runs are safe on all three (advisory lock, `GET_LOCK`, a lock file next to the SQLite database).
- Take a database backup before a release that adds migrations (for SQLite, copy the file with `sqlite3 FILE ".backup COPY"` while the roles run, or stop them first).

## Health and readiness

| Role | Liveness | Readiness | Metrics |
|---|---|---|---|
| Gateway, warmer | `GET :8888/healthz` (200 from the first moment) | `GET :8888/readyz`: `503 starting` until connected and loaded; `503` after three consecutive failed Redis checks; `503 draining` after a stop request | `GET :8888/metrics` |
| Session proxy | `GET :8888/health/live` (admin port): `200` while the process runs | `GET :8888/health/ready` (and `/health`): `200` only when Redis answers, the capture pipeline is not backed up or stalled, every listener runs and the proxy is not draining; the JSON body lists each check | `GET :8888/metrics` |
| Control API | `GET :9000/health/live` | `GET :9000/health/ready` (and `/health`, `/rpc/health`): `200` only when the database (`SELECT 1`) and Redis (`PING`) answer within 2 s, else `503`; the capture store is not probed (use `GET :9000/health/store`, which is `503` when the store is unreachable) | `GET :9000/metrics` |
| Ingester | `GET :9001/health`: 503 once the consumer task has exited, while the broker connection is down (Kafka, RabbitMQ) or while the capture store's circuit breaker is open | same | `GET :9001/metrics` |
| Limiter | `GET /healthz` on the operations port (`PROXYX_LIMITER_METRICS_ADDR`, off by default); the `PING` op of the data protocol; the process also prints `READY <addr> max_buckets=<n>` on stdout once listening | `GET /readyz`: `503` when the bucket slab is full | `GET /metrics` on the same port, see [metrics/limiter.md](metrics/limiter.md) |
| MCP server | `GET /healthz` | `GET /readyz`: `503` naming an unreachable backend, `503 draining` after a stop request | none |
| Edge proxy | `GET /healthz` | `GET /readyz`: `503` when no healthy egress path remains | `GET /metrics` |

Use `/readyz` for the gateway's Service or load-balancer health check so that a draining replica stops receiving new tunnels, and use `/healthz` for restarts so a replica that is waiting for a dependency is not killed.

## Stopping and draining

Send SIGTERM (an orchestrator's normal stop) or Ctrl-C.

- **Gateway.** `/readyz` turns `503 draining` at once so the balancer stops sending new connections. Open tunnels keep running for up to `drain_timeout` (default 300 s), then they are closed and the process stops, with 15 s of margin for listener close and flush. The ops server stays up through the drain, so you can watch the open-tunnel gauges fall. Give the workload a termination grace period of at least `drain_timeout` plus 15 s, plus any pre-stop delay your load balancer needs to notice the failed readiness check.
- **Warmer.** Stops its loops and releases the partition locks, giving in-flight creates and resets 10 s to finish.
- **Session proxy.** `/health/ready` turns `503` (check `draining`) at once, then it stops accepting, waits up to `shutdown_drain_timeout_secs` (default 300) for tunnels, then flushes the capture buffer (up to 30 s). The admin port stays up until the drain ends, so you can watch `proxyx_intercept_connections_active` fall. Size the grace period to cover both. [`deploy/systemd`](../deploy/systemd) has a unit for every role with `TimeoutStopSec` sized this way.
- **Ingester.** Stops consuming and flushes the ClickHouse buffer (up to 30 s).
- **Limiter.** Exits with status 0 at once; its state is not durable by design. Every org starts with a full bucket again after a restart, so a restart briefly admits more than the limit.

A drain after a unit is removed from service works the same way inside the gateway: a rotating session taken out of the ready set, a static IP taken out of leasing, or an org block closes the affected tunnels after a bounded time (ten minutes at most), on every replica.

Release builds abort on panic. A process that dies is restarted by the supervisor; configure restarts (`restart: unless-stopped`, a Deployment, `Restart=always`) for every role.

## Upgrades and rollback

1. Read the [changelog](../CHANGELOG.md) for configuration and schema changes.
2. Back up the database.
3. Run `proxyx migrate pool --check` and `proxyx migrate control --check` with the new binary to see what is pending, then run the migrations.
4. Roll the workloads one replica at a time: warmer and gateway (the gateway drains), then session proxy, control API and ingester. Verify `/readyz` and the dashboards between steps.
5. To roll back, redeploy the previous image against the already-migrated schema. This is supported for one release back, because schema changes are backward compatible. Do not restore an older database over newer data unless you are prepared to lose what was written since the backup.

A gateway that restarts with a different `data_dir` tree than the one stored does not overwrite the stored policies while a gateway that runs the stored tree is alive, so a rolling update or a drifted config cannot make replicas fight; once none of them runs the stored tree, the newer one applies it (this is how a rollback of policy files takes effect).

## Scaling

- **Gateway.** Throughput is bounded by file descriptors (two per tunnel) and by upstream bandwidth, not CPU. Scale replicas for more tunnels; each enforces its own `max_connections`, while per-org caps and leases are shared through Redis. Raise `max_pending_per_ip` if many clients arrive from one NAT address.
- **Warmer.** More replicas share partitions through the Redis locks, and extra replicas are standby. Scale for availability rather than throughput.
- **Session proxy.** Stateless apart from Redis; scale replicas behind a TCP balancer. Per-org rate limits are enforced through Redis or the limiter, so they hold across replicas. Capture volume is bounded by the broker and ClickHouse, not by the proxy: when the ingester falls behind, backpressure slows tunnels.
- **Ingester.** Add replicas to share a Redis consumer group (or Kafka partitions; the topic's partition count is fixed at creation, so size it for your target parallelism). With RabbitMQ the unit of parallelism is a partition queue with one active consumer, so more replicas than `rabbitmq.partitions` add nothing but failover; the partition count is fixed too.
- **ClickHouse.** Wide body columns make merges memory-heavy. Keep the ingester's `clickhouse.bulk_size` large so parts stay few and big, and watch the table's insert-delay settings (`parts_to_delay_insert`). When the ingester's buffer reaches `clickhouse.max_buffer_bytes` it stops reading, and the broker holds the backlog.
- **Limiter.** One process handles very high request rates; its `PROXYX_LIMITER_MAX_BUCKETS` must exceed the number of active orgs.

## Backups and retention

- **The relational database** (PostgreSQL, MariaDB or SQLite) holds everything that is hard to rebuild: org keys (hashes), policies, inventory, customer upstream logins, audit rows, API keys, session lifecycle and export jobs. Back it up and test restores.
- **Redis** (pool) needs no backup. **Redis** (sessions and stream) needs persistence only to the extent you cannot lose captures between the proxy and the ingester.
- **ClickHouse** holds captures. The default table retention is twelve months; change it with a new ClickHouse migration, and apply your own data-protection rules to bodies and headers.
- **Exports** (Parquet in object storage) expire `traffic_views_ttl_secs` after completion (default 24 hours); the control API's reaper deletes the object and the job row.

## Secrets and rotation

| Secret | Rotate by |
|---|---|
| Org key (`ak_...`) | Create a new key with `POST /v1/orgs/{org}/keys`, move clients over, then `DELETE /v1/orgs/{org}/keys` to disable all keys of the org. Keys are stored as SHA-256 only and cannot be read back. |
| Pool admin token, prober token | Replace the file and restart the gateway: tokens are read at start. |
| Probe key | Replace the file and restart the gateways (and the prober, which asks for a fresh token). |
| Provider logins | Replace the secret file and let the next reload pick it up (an unreadable secret keeps the previous adapters and sets `config_reload_failed`), or restart. |
| Customer upstream login | `POST /v1/orgs/{org}/upstream/rotate-secret`: the new login is checked through the upstream before it replaces the old one. |
| Control API key (`pxk_...`) | Create a new one with `proxyx control keys create`, disable the old one with `proxyx control keys disable ID`; the change takes effect within the 30 second key cache window. |
| MITM CA | Generate a new CA, give the same key material to the session proxy and the certificate to the control plane, restart both, and have clients trust the new certificate. Sessions created earlier hold the old certificate in their response only; clients fetch the current one from `GET /rpc/certificate`. |

Never put secrets into configuration files that you commit; use `secrets_dir` files and environment variables from your secret store.

## Security hardening checklist

- Terminate nothing in front of the gateway's tunnel listeners except a TCP load balancer; use PROXY-protocol-aware limits or raise `max_pending_per_ip` for NATed clients.
- Expose the `/v1` API (8081), the ops port (8888) and the control API only on a private network. The admin token, the control API keys and the session proxy admin port are not meant for the public internet.
- Run in `auth_mode = "keys"` unless an authenticating gateway fronts the control API, and then set `env` to anything but `dev` and fill `internal_allowed_cidrs`.
- Use the `file` or `env` CA mode with one CA shared between the session proxy and the control plane; keep the CA key readable by the session proxy only.
- Run the containers as the non-root user the image defines and drop capabilities.
