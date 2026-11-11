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

Limiter clients do not replay a failed exchange. If the server consumed tokens but the response was lost, even EOF before the first response byte cannot prove that the consume did not happen. The client reports the configured fail policy with `degraded = true`; a later operation uses a fresh connection. Pooled connections expire after 30 seconds of idleness by default, before the service's default 60-second idle timeout. Keep the client's `max_idle` below a shorter server idle timeout.

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
- **Redis** (pool) needs no backup: when it comes back empty, a warmer notices the missing seed marker and rebuilds the ready sets from the database (log line `redis was empty, rebuilt it from postgres`). Leases and sticky sessions that lived only in Redis are gone, so clients reconnect. **Redis** (sessions and stream) holds the live session records as well as the capture stream. Enable AOF persistence on it: after a crash of a Redis without persistence the session proxy answers `407` for sessions that were live, and the captures not yet ingested are lost. A session already in a proxy's local cache keeps working through a short outage; one that is not cached is refused until Redis is back.
- **ClickHouse** holds captures. The default table retention is twelve months; change it with a new ClickHouse migration, and apply your own data-protection rules to bodies and headers.
- **Exports** (Parquet in object storage) expire `traffic_views_ttl_secs` after completion (default 24 hours); the control API's reaper deletes the object and the job row.

Restoring the pool database from a PostgreSQL dump:

```sh
pg_dump -Fc -f pool.dump proxyx_pool                   # the roles keep running
createdb proxyx_pool_restored && pg_restore --no-owner -d proxyx_pool_restored pool.dump
proxyx migrate pool --check                            # with database_url pointing at the restored database: nothing pending
```

Stop the gateways and warmers, empty the pool Redis (`FLUSHDB` on its database; never copy hot-state keys back from before the restore), point `database_url` at the restored database and start the roles. The warmer rebuilds Redis from the database, and keys, policies and inventory are the ones of the backup: an org key or inventory change made after the backup is not in the restored database, and its holder is refused (`407`) until you create it again. For SQLite, `sqlite3 FILE ".backup COPY"` takes the same consistent copy while the roles run.

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

## Docker Compose profiles

[`docker/docker-compose.yml`](../docker/docker-compose.yml) starts PostgreSQL, Valkey, ClickHouse and every role. Profiles swap one dependency each, and they combine: the relational database (`mariadb` or `sqlite`, with its env file), the capture store (`opensearch`) and the captures-log broker (`kafka` or `rabbitmq`) are independent choices.

| Choice | Command |
|---|---|
| MariaDB | `docker compose --env-file docker/db-mariadb.env -f docker/docker-compose.yml --profile mariadb up -d --build --wait` |
| SQLite | `docker compose --env-file docker/db-sqlite.env -f docker/docker-compose.yml --profile sqlite up -d --build --wait` |
| OpenSearch captures | `PROXYX_CAPTURE_STORE=opensearch docker compose -f docker/docker-compose.yml --profile opensearch up -d --build --wait` |
| Kafka broker | `PROXYX_BROKER=kafka docker compose -f docker/docker-compose.yml --profile kafka up -d --build --wait` |
| RabbitMQ broker | `PROXYX_BROKER=rabbitmq docker compose -f docker/docker-compose.yml --profile rabbitmq up -d --build --wait` |

Combine them by repeating `--profile` and setting both variables, for example `--env-file docker/db-mariadb.env --profile mariadb --profile opensearch --profile kafka` with `PROXYX_CAPTURE_STORE=opensearch PROXYX_BROKER=kafka`. Selecting a profile without its variable starts the server but leaves the roles on the default (ClickHouse, Redis Streams), and the reverse (a variable without its profile) leaves the roles pointing at a host that does not exist. The session proxy and the control plane read the same `PROXYX_BROKER`, so they cannot disagree.

Every datastore keeps its data in a named volume. `docker compose down` keeps the volumes: keys, sessions' captured rows, the dev CA and the secrets survive, and `init` and the migrations rerun as no-ops. `docker compose down -v` removes them. Valkey has no volume, so the session state and rate-limit buckets it held are gone after `down`; the warmer rebuilds the pool's ready sets from the database. After a datastore restart the roles reconnect on their own, and the ingester's `/health` answers `503 broker connection down` until its Kafka or RabbitMQ consumer has rejoined (seconds to a minute).

The host disk matters for OpenSearch: above 95 % use it marks every index read-only and the ingester's bulk writes fail with HTTP 429. Free space, or set `cluster.routing.allocation.disk.threshold_enabled=false` on the throwaway node.

Every host port is bound to `127.0.0.1`. The compose file has no port variables; to move a port, add an override file with `ports: !override ["127.0.0.1:NEW:CONTAINER"]` for that service and pass it with a second `-f`.

## VPN egress sidecar

[`docker/Dockerfile.egress`](../docker/Dockerfile.egress) builds a container that brings up one VPN tunnel (WireGuard, OpenVPN or Tailscale) and serves a SOCKS5 proxy (`microsocks`) that leaves through it. Point a static inventory entry of the `vpn-pool` adapter at the sidecar ([providers](providers.md#local-egress-sidecars-vpn-pool)). Run it with `--cap-add NET_ADMIN --device /dev/net/tun` and no published port beyond the networks that need it: the SOCKS port listens on `0.0.0.0` inside the container.

| Variable | Meaning |
|---|---|
| `VPN_TYPE` | `wireguard`, `openvpn` or `tailscale`. Required. |
| `VPN_CONFIG` | Path of the WireGuard or OpenVPN config inside the container. WireGuard names the interface after the file (`wg0.conf` gives `wg0`). |
| `TAILSCALE_AUTH_KEY`, `TAILSCALE_ARGS` | Pre-auth key, and extra `tailscale up` flags such as `--login-server=URL` (Headscale) or `--exit-node=IP`. `tailscale up` is bounded to 60 seconds. |
| `SOCKS_PORT`, `SOCKS_USER`, `SOCKS_PASS` | SOCKS5 port (1080) and optional login. Set both of the login variables or neither; the container refuses to start with one. |
| `HEALTH_HOST` | Address pinged through the tunnel before the proxy starts (default `1.1.1.1`). Choose an address that only answers inside the VPN, such as the tunnel's own gateway, so a leaked route cannot pass the check. |

Behavior to rely on:

- The proxy starts only after the ping through the tunnel succeeds. A bad config, an unreachable VPN server or control plane, or a rejected key makes the container exit non-zero with the reason on stderr; no SOCKS port is opened.
- The container supervises the tunnel. If the OpenVPN or `tailscaled` process dies, the WireGuard interface disappears or `microsocks` exits, the container exits (code 1) instead of serving over its direct route. Run it with `restart: unless-stopped` so a new tunnel comes up.
- `docker stop` runs the shutdown trap: it stops `microsocks`, takes the tunnel down and exits (143) within a few seconds.
- A WireGuard config that routes everything (`AllowedIPs = 0.0.0.0/0`) makes `wg-quick` set `net.ipv4.conf.all.src_valid_mark`, which a container can only get at start: add `--sysctl net.ipv4.conf.all.src_valid_mark=1` (Compose `sysctls`).
- Tailscale runs with a kernel TUN device, so the SOCKS proxy reaches tailnet addresses and an exit node. Joining needs a reachable control plane and a valid auth key, and `--login-server` selects a self-hosted Headscale.
- The SOCKS login and the keys reach the container as environment variables or mounted files, which `docker inspect` shows to anyone with Docker access. Mount the config read-only with mode `0600` and use a key that is reusable only if you need it to be.
