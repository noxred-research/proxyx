# Doctor and assess

Two commands answer two different questions.

- `proxyx doctor` (and `proxyx-intercept doctor`) asks: *would this role start and work here?* It loads
  the role's configuration the way the role loads it, then probes what the role needs (Postgres, Redis,
  brokers, ClickHouse, CA files, secret files, open-files limit, listener ports, DNS). It starts nothing
  and writes nothing. Run it before a deploy, in an init container, or when a role will not come up.
- `proxyx assess pool` asks: *is the running pool healthy?* It reads Postgres, Redis and the gateway's ops
  server and judges capacity, leases, breakers, exit-IP check freshness, reputation, block signals, rentals
  and budget. Run it by hand, from cron, or after an incident.

Both print a table for people and JSON for machines (`--json`), and both exit non-zero when something is
wrong.

- [Doctor](#doctor)
- [Check reference](#check-reference)
- [Doctor JSON](#doctor-json)
- [Assess pool](#assess-pool)
- [Assess JSON](#assess-json)

## Doctor

```sh
proxyx doctor --role gateway --config /etc/proxyx/pool.toml
proxyx doctor --role control --config control=/etc/proxyx/control.toml --json
proxyx doctor                      # every role that has a configuration here
proxyx-intercept doctor --config /etc/proxyx/intercept.toml
```

| Option | Meaning |
|---|---|
| `--role` | `pool` (gateway and warmer together), `gateway`, `warmer`, `control` (API and ingester together), `ingester`, `limiter`, `intercept`, `edge`, or `all` (default). |
| `--config [ROLE=]PATH` | The role's configuration file. A bare `PATH` applies to the one role you selected; with `--role all` write `ROLE=PATH` (`pool`, `control`, `edge`, `intercept`; repeat for several). A role without a file reads its default file and environment, exactly as it does when it starts. |
| `--json` | Print the report as JSON instead of a table. |
| `--strict` | A warning counts as a failure. |
| `--timeout` | Bound on every probe (`5s`, `1m`; default `5s`). A host that does not answer cannot hold the doctor longer than this. |
| `--skip-listeners` | Do not try to bind the listener ports. Use it where the role already runs: its ports are in use then, and the doctor would report that as a failure. |
| `--limiter-addr` | Listen address of the limiter to check (`proxyx limiter [ADDR]`; default `0.0.0.0:39091`). |

`proxyx-intercept doctor` takes `--json`, `--strict`, `--timeout` and `--skip-listeners`, and the global
`--config`. `proxyx-intercept` with no subcommand still runs the proxy.

### Which roles `--role all` checks

A role is checked when it has an explicit `--config`, or a default file exists (`/etc/proxyx/pool.toml`,
`control.toml` or `/etc/proxyx/control.toml`, `/etc/proxyx/edge.toml`, `intercept.toml` or
`/etc/proxyx/intercept.toml`), or its marker variable is set (`PROXYX_POOL_DATABASE_URL`,
`PROXYX_CONTROL_DATABASE_URL`, `PROXYX_INTERCEPT_REDIS_URL` or `PROXYX_INTERCEPT_CONNECT_ADDR`, any
`PROXYX_LIMITER_*` tuning variable, or `--limiter-addr`). When none is found the report is one failing
`config.found`.

### The session proxy

The session proxy links BoringSSL and cannot share a process with the control plane's OpenSSL, so
`proxyx doctor --role intercept` runs `proxyx-intercept doctor --json` (next to the `proxyx` executable, else
on `PATH`) and merges its checks into the report under `intercept.`. If that binary is not installed, the
check is skipped under `--role all` and fails when you named the role.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Every check passed or was skipped. |
| `1` | At least one check failed. With `--strict`, a warning also gives `1`. |
| `2` | No failure, at least one warning. |

A failed `config.load` ends that role's list: nothing else can be judged without the configuration. A
mistake in a configuration file is reported with the file and the key (`max_connection` is an unknown key in
`/etc/proxyx/pool.toml`, `api_addr` has an invalid value in `control.toml`), as the role itself would report it
at start.

Ids in `proxyx doctor` start with the role (`gateway.redis.reachable`, `control.ca.expiry`), so a report that
covers several roles keeps their checks apart. `proxyx-intercept doctor` prints ids without a prefix.

## Check reference

Status columns: **fail** stops the role from starting or working, **warn** is worth an operator's look.

### Pool: gateway, warmer, pool

| Check | What it looks at | Status |
|---|---|---|
| `config.load` | `Settings` loaded from the default file, `PROXYX_POOL_*` and the `--config` file; unknown keys, wrong types and invalid values (`reload_every`, `max_connections`, `probe_org`, scorer URLs, ...). | fail on any error |
| `config.exit_ip_services` | `exit_ip_services` parses and has a service that reports the country. | fail |
| `postgres.reachable` | Connect and `SELECT 1` within `--timeout`; latency of both. The check ids keep the `postgres.` prefix on every backend (PostgreSQL, MariaDB or SQLite, by the URL scheme); the message names the backend. The URL's password is never printed. | fail on error or timeout, or an unsupported scheme; warn when `SELECT 1` takes over 250 ms |
| `postgres.version` | Server version. | PostgreSQL: warn below 13. MariaDB: fail below 10.6 or when the server is not MariaDB. SQLite: warn below 3.40 |
| `postgres.migrations` | `_sqlx_migrations` exists and lists applied migrations. | fail when missing or empty |
| `postgres.pending` | The embedded migrations that are not applied yet. | fail, naming them |
| `redis.reachable` | `PING`, server and version (Redis or Valkey), latency. | fail on error or timeout |
| `redis.clock_skew` | The server's `TIME` against this host, with half the round trip forgiven. | warn from 1 s, fail from 5 s |
| `redis.memory_policy` | `maxmemory` and `maxmemory-policy`. | warn when a limit is set with a policy that evicts keys |
| `redis.persistence` | AOF and RDB save points (read with `INFO` and `CONFIG GET save`; managed servers that refuse `CONFIG` are not judged). | warn when none is on and the data cannot be rebuilt (not for the pool, whose state is rebuilt from Postgres) |
| `dns.postgres`, `dns.redis` | The host names in the two URLs resolve. Not run for IP literals. | fail |
| `data.dir` | `data_dir` exists. | fail |
| `data.adapters` | `adapters/*.toml` load together, with their secret files (the same load the roles do). | fail, with the adapter named |
| `data.policies` | `policies/*.toml` merge and fit the adapters' session life. No files: policies live in Postgres only. | fail; skip when there are no files |
| `data.inventory` | Every `credentials` file an inventory entry names exists in `secrets_dir` and is not empty. | fail; skip without an inventory directory |
| `secrets.dir` | `secrets_dir` exists. | fail |
| `secrets.permissions` | No file in `secrets_dir` is readable by everyone. | warn, naming the files |
| `secrets.admin_token` | `admin_token_file` exists, is non-empty, not readable by everyone. Required for the gateway. | fail when missing or empty; warn on permissions; skip for the warmer when missing |
| `secrets.probe_key` | `probe_key_file`, same rules. Optional: without it there is no prober. | warn on permissions; skip when missing |
| `listen.distinct` | No two listeners of the role share a port. | fail |
| `listen.connect`, `listen.socks`, `listen.probe`, `listen.api` | The listener can be bound now. Gateway only. | fail when in use or not permitted; skip with `--skip-listeners` |
| `listen.ops` | The ops listener can be bound. | as above |
| `system.open_files` | Soft limit of open files against `2 x max_connections + 512`, the same need the gateway checks at start (`/proc/self/limits`). Gateway only. | fail, with the `ulimit` or `LimitNOFILE` to set |

### Control plane: control, ingester

| Check | What it looks at | Status |
|---|---|---|
| `config.load` | `ControlConfig` from the default file, `PROXYX_CONTROL_*` and `--config`. | fail |
| `config.capture_store` | The section the chosen backend needs exists (`[clickhouse]`, or `[capture_store.opensearch]`). | fail |
| `config.broker` | `broker_kind = "kafka"` has a `[kafka]` section (or the deprecated `[redpanda]`), `broker_kind = "rabbitmq"` has a `[rabbitmq]` section. | fail |
| `postgres.*`, `redis.*`, `dns.*` | As for the pool. `postgres.pending` uses the control plane's own migrations. Redis persistence is judged when captures go through a Redis stream. | as above |
| `clickhouse.ping` | `GET /ping` answers `Ok.`. | fail when unreachable or not HTTP 200; warn on another body |
| `opensearch.ping` | `GET /` of the cluster answers (401 and 403 count: the doctor sends no credentials). | fail |
| `redis.stream` | The capture stream (`request_log_stream`): whether it exists and how full it is against `request_log_max_stream_len`. A stream that does not exist yet passes: the first writer creates it. | warn at 90% of the cap |
| `broker.reachable` | TCP connect to each broker of `kafka.brokers`, or to the host of `rabbitmq.url`. | pass when all answer, warn when some do, fail when none |
| `ca.mode` | `ca.type = "generate"` is for development. | warn |
| `ca.cert`, `ca.expiry` | The CA certificate is present and parses (PEM), and its validity window. See [CA material](#ca-material). | |
| `listen.api`, `listen.ingester_health` | The listeners can be bound. The ingester role does not bind the API. | fail |

### Limiter

| Check | What it looks at | Status |
|---|---|---|
| `config.max_buckets`, `config.shards`, `config.reaper_ms`, `config.max_connections`, `config.idle_timeout_ms` | The limiter silently uses its default for a value that is not a positive integer; the doctor says so. | warn |
| `config.tcp_keepalive_secs` | A non-negative integer; `0` disables keepalive. Invalid values use the default. | warn |
| `listen.limiter`, `listen.metrics` | The data listener and optional `PROXYX_LIMITER_METRICS_ADDR` parse and can be bound; `--skip-listeners` skips binding, not address validation. | fail |
| `listen.distinct` | Data and metrics listeners must not collide, even with `--skip-listeners`. | fail |
| `system.open_files` | At least 1024 descriptors (one per client connection). | fail |

### Edge

| Check | What it looks at | Status |
|---|---|---|
| `config.load` | `proxyx edge --check`: references resolve, local addresses are assigned and bindable, password hashes are supported. | fail, with the file and the key |

### Session proxy (`proxyx-intercept doctor`)

| Check | What it looks at | Status |
|---|---|---|
| `config.load` | `Config` from the default file, `PROXYX_INTERCEPT_*` and `--config`. | fail |
| `config.valid`, `config.broker`, `config.ratelimit`, `config.tuning` | Values the proxy would trip over later: a Kafka or RabbitMQ broker without its section, a limiter address that is not `host:port`, a zero `tuning.max_connections` or channel capacity. | fail |
| `listen.distinct` | Two listeners on one port. | fail |
| `redis.reachable`, `redis.clock_skew`, `redis.memory_policy`, `redis.persistence`, `dns.redis` | As for the pool; the session proxy's Redis holds sessions and, by default, the capture stream, so missing persistence warns when captures go through it. | as above |
| `redis.stream` | The capture stream `request_log.stream_name` against `request_log.max_stream_len`. | warn at 90% of the cap |
| `broker.reachable` | The Kafka brokers or the RabbitMQ host, when `broker_kind` is `kafka` or `rabbitmq`. | as above |
| `ratelimit.limiter` | TCP connect to `ratelimit.limiter_addr`, when `ratelimit.backend = "limiter"`. | fail with `failopen_policy = "deny"`; warn otherwise, because the proxy then keeps serving without limits |
| `ca.mode`, `ca.cert`, `ca.expiry`, `ca.key` | The CA that signs interception certificates. | |
| `system.open_files` | `2 x tuning.max_connections + 512`. | fail |
| `listen.connect`, `listen.http`, `listen.socks`, `listen.api` | The listeners can be bound. | fail |

### CA material

For the session proxy: `ca.type = "file"` reads DER files (`cert_path`, `key_path`), `env` reads
`PROXYX_INTERCEPT_CA_CERT` and `PROXYX_INTERCEPT_CA_KEY` (PEM, or base64 of the DER), `generate` reads
`ca.der` and `ca.key.der` in `data_dir` if they exist. For the control plane: a PEM certificate from a file
or `PROXYX_CONTROL_CA_CERT`, or the shared `ca.der`. The doctor reads the material in the encoding the
role expects: a PEM file where raw DER is read is a failure.

| Check | Status |
|---|---|
| `ca.cert`: the material is present, decodes and is an X.509 certificate. | fail otherwise; warn when it is not a CA certificate (`basicConstraints CA:TRUE`) |
| `ca.expiry`: days left in the validity window. | pass at 30 days or more; warn below 30; fail below 7, when expired, and when the certificate is not valid yet |
| `ca.key`: when the role holds the key (the session proxy; the control plane's `generate` mode when `ca.key.der` exists), it is a PKCS#8 key and is the certificate's. | fail when it does not parse or does not match |

## Doctor JSON

`--json` prints one document. Schema 1 changes only when a field is removed or changes meaning; new fields
can be added.

```json
{
  "schema": 1,
  "subject": "gateway",
  "strict": false,
  "overall": "warn",
  "exit_code": 2,
  "summary": { "pass": 14, "warn": 1, "fail": 0, "skip": 2 },
  "checks": [
    { "id": "gateway.redis.reachable", "status": "pass",
      "message": "127.0.0.1:6379/1 answers PING (redis 7.2.4)", "elapsed_ms": 2 },
    { "id": "gateway.secrets.probe_key", "status": "warn",
      "message": "probe key file /etc/proxyx/secrets/probe-key is readable by everyone (mode 644)",
      "hint": "chmod 600 /etc/proxyx/secrets/probe-key (or 640 with a group)" }
  ]
}
```

| Field | Meaning |
|---|---|
| `schema` | Document version, `1`. |
| `subject` | The role selected with `--role`, or `all`; `intercept` for `proxyx-intercept doctor`. |
| `strict` | Whether `--strict` was given. |
| `overall` | `pass`, `warn` or `fail`. With `--strict` a warning makes it `fail`. A run of only passes and skips is `pass`. |
| `exit_code` | The process exit code. |
| `summary` | Counts by status. |
| `checks[].id` | Stable dotted id. |
| `checks[].status` | `pass`, `warn`, `fail` or `skip`. |
| `checks[].message` | What was found, in one line. |
| `checks[].hint` | What to do; present on warnings and failures. |
| `checks[].elapsed_ms` | Time of a check that talks to the network. |

## Assess pool

```sh
proxyx assess pool --config /etc/proxyx/pool.toml
proxyx assess pool --json --window 30m --ops-url http://gateway-0:8888
```

It reads the same configuration as the gateway (`--config`, the default file, `PROXYX_POOL_*`), connects to
Postgres and Redis, loads the policies, adapters and inventory the way the roles do (without syncing git
data into Postgres), reads the state with read calls only, and asks the gateway's ops server. It takes no
lease and creates nothing.

| Option | Meaning |
|---|---|
| `--config` | Pool configuration file. |
| `--json` | Print JSON instead of the table. |
| `--strict` | A WARN counts as CRIT. |
| `--window` | How far back block signals are counted (`30m`, `1h`, `1d`; default `1h`). |
| `--ops-url` | Ops server of a gateway. Default: the configured `ops_listen` on this host (a wildcard address means loopback). |
| `--no-gateway` | Do not ask the gateway. |
| `--timeout` | Bound on each HTTP request to the gateway (default `5s`). |

Exit codes are those of the doctor: `0` all OK, `1` a CRIT (or a WARN with `--strict`), `2` only WARNs. When
Postgres, Redis or the pool configuration cannot be read, the command stops with the error and exits `1`.

### Findings

Each section holds findings of one kind, each `OK`, `WARN` or `CRIT`. A section with nothing to judge says so
in one `OK` line.

| Section | Subject | OK | WARN | CRIT |
|---|---|---|---|---|
| `capacity` | each partition (provider, region, kind) | ready at or above `min_ready` | ready below `min_ready` but not below the low watermark; or warming paused by a failed canary | ready below the low watermark, or none while `min_ready` is above 0 |
| `leases` | each partition | under 80% of the leasable units leased | 80% or more leased; or the busiest static IP at its tunnel limit | 95% or more leased; or the busiest static IP at twice its limit |
| `breakers` | each provider (worst of its partitions) | closed | open or half-open | not used |
| `checks` | each provider with static IPs | every IP checked within 3 x `static.recheck_every` | some IPs older than that | half or more older than that |
| `inventory` | each provider with static IPs | under 20% of the IPs out of rotation (cooldown, quarantine, offline, replacement requested) | 20% or more; or any IP with a replacement requested | 50% or more |
| `reputation` | pool, and each provider | fewer than 10% of the scored IPs above `criteria.max_risk` | 10% or more | 30% or more |
| `blocks` | pool | fewer than 20% of the static IPs got a block signal in the window | 20% or more | 50% or more |
| `rentals` | each provider with dated IPs | every rental ends in 30 days or more | one ends in under 30 days | one ends in under 14 days, or has ended |
| `budget` | each rotating provider | under 80% of the daily traffic and hourly create limits | 80% or more (the warmer only keeps `min_ready`) | 90% or more (100% stops creates) |
| `gateway` | the ops URL | `/readyz` answers 200 | not reachable from here; the last configuration reload rejected; the snapshot older than 5 reload intervals | `/readyz` not 200; the gateway reports Postgres or Redis down |

How the numbers are read:

- **Ready.** For a rotating partition, the free ready sessions. For a static partition, every IP in a state
  that can be leased (available, degraded, leased): the figure the pool's cache gauges and the low-watermark
  alert use. `min_ready` and the low watermark come from the effective policy of the provider and region.
- **Leases.** Units with a lease or an open tunnel, from Redis, against the leasable units. The tunnel limit
  of a static IP is the policy's `max_conns_per_ip`, or 80% of the adapter's `max_conns_per_ip`; the busiest of
  at most 500 units per partition is read.
- **Checks.** The age of an IP's last exit-IP check, or of its current state when it was never checked. Retired,
  offline and replacement-requested IPs are not expected to be checked.
- **Reputation.** The highest risk among the newest check of each reputation service, per IP, against the
  provider policy's `criteria.max_risk`. The pool line also gives the median, 90th percentile and worst risk
  of every scored IP, rotating exits included.
- **Blocks.** Distinct IPs with at least one signal (any type, target or IP-wide) inside `--window`, against the
  static IPs that are not retired. The message gives the signals by type.
- **Rentals.** Days from today to `rental_end` of the non-retired static IPs, soonest first.
- **Budget.** The larger of the day's traffic against `cost.max_gb_per_day` and the hour's creates against
  `cost.max_creates_per_hour`, as the warmer meters them.
- **Gateway.** `/readyz` and the gauges `postgres_down`, `redis_down`, `config_reload_failed` and
  `snapshot_age_seconds` of `/metrics` (see [metrics/pool.md](metrics/pool.md)). A gateway that cannot be
  reached from this host is a WARN, since the command often runs where the ops port is not open; use
  `--no-gateway` to leave it out. The control API is not used: everything it would show is read from Postgres
  and Redis.

The thresholds are the defaults of the command; they are not configuration. Pair a finding with its runbook:
capacity with [003](runbooks/003-cache-below-low-watermark.md), breakers with
[004](runbooks/004-provider-breaker-open.md), budget with [005](runbooks/005-provider-budget-at-90-percent.md),
rentals with [006](runbooks/006-static-ip-rental-ending.md), replacements with
[009](runbooks/009-ip-replace-requested.md).

## Assess JSON

Schema 1; fields can be added, not removed.

```json
{
  "schema": 1,
  "target": "pool",
  "generated_at": 1800000000,
  "strict": false,
  "overall": "warn",
  "exit_code": 2,
  "summary": { "ok": 9, "warn": 1, "crit": 0 },
  "sections": [
    { "name": "capacity", "findings": [
      { "level": "ok", "subject": "res_pass_suffix@fr (rotating)",
        "message": "12 ready, min_ready 10, low watermark 5" } ] },
    { "name": "breakers", "findings": [
      { "level": "warn", "subject": "res_pass_suffix",
        "message": "breaker open: the provider failed repeatedly and is skipped" } ] }
  ]
}
```

| Field | Meaning |
|---|---|
| `generated_at` | Unix seconds when the state was read. |
| `overall` | `ok`, `warn` or `crit`; with `strict`, a warning gives `crit`. |
| `sections[].name` | `capacity`, `leases`, `breakers`, `checks`, `inventory`, `reputation`, `blocks`, `rentals`, `budget`, `gateway`, always in this order. |
| `sections[].findings[]` | `level` (`ok`, `warn`, `crit`), `subject` and a one-line `message`. |
