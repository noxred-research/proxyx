# Configuration reference

Every ProxyX process reads its configuration from a TOML file, from environment variables, or from both. This page lists every key, its environment variable and its default for the five configurable components:

| Component | Command | Environment prefix | Default file |
|---|---|---|---|
| Pool gateway and warmer | `proxyx gateway`, `proxyx warmer`, `proxyx migrate pool` | `PROXYX_POOL_` | `/etc/proxyx/pool.toml` |
| Session proxy | `proxyx-intercept` | `PROXYX_INTERCEPT_` | `./intercept.toml`, else `/etc/proxyx/intercept.toml` |
| Control plane | `proxyx control ...`, `proxyx migrate control` | `PROXYX_CONTROL_` | `./control.toml`, else `/etc/proxyx/control.toml` |
| Limiter | `proxyx limiter [ADDR]` | `PROXYX_LIMITER_` | none (environment only) |
| Edge proxy | `proxyx edge` | none (one TOML file) | none: `--config FILE` is required |

Minimal working files are in [`examples/`](../examples/).

## How values are resolved

From lowest to highest priority:

1. The default configuration file of the component (see the table above).
2. Environment variables with the component prefix. A double underscore nests: `sentry.dsn` is `PROXYX_POOL_SENTRY__DSN`, `clickhouse.url` is `PROXYX_CONTROL_CLICKHOUSE__URL`.
3. The file named by `--config FILE` (`-c FILE`). It overrides both of the above.

A few rules apply to all components:

- A `--config` file that does not exist is an error. A wrong mount path never silently starts the process on defaults.
- Durations of the pool gateway are plain seconds or `30s`, `5m`, `2h`. Durations of the session proxy and control plane are integer seconds or milliseconds as the key name says (`_secs`, `_ms`).
- Secrets are never part of a pool configuration file. Provider logins, the admin token and scorer keys are files in `secrets_dir`; see [Pool gateway](#pool-gateway-and-warmer).
- The pool gateway refuses a configuration **file** that contains an unknown key (a typo such as `max_connection`) and refuses values that would fail later (a zero timeout, a pending limit above `max_connections`). Unknown `PROXYX_POOL_*` environment variables are ignored, because orchestrators inject variables with that prefix.

## Database URLs

`database_url` of the pool (`PROXYX_POOL_DATABASE_URL`) and of the control plane (`PROXYX_CONTROL_DATABASE_URL`) name the relational database, and the **scheme selects the backend**. The two planes may use different backends; each needs its own database (PostgreSQL, MariaDB) or file (SQLite).

| Scheme | Backend | Example |
|---|---|---|
| `postgres://`, `postgresql://` | PostgreSQL 13 or newer (default) | `postgres://proxyx:secret@db.internal:5432/proxyx_pool` |
| `mariadb://`, `mysql://` | MariaDB 10.6 or newer (MySQL itself is not supported) | `mariadb://proxyx:secret@db.internal:3306/proxyx_pool` |
| `sqlite://` | SQLite 3.40 or newer, one host | `sqlite:///var/lib/proxyx/pool.db?mode=rwc` |

- Any other scheme, or none, is refused at start: a typo never falls back to another database.
- Percent-encode special characters in a user name or password (`@` as `%40`, `/` as `%2F`).
- A SQLite URL names a file: `sqlite:///absolute/path.db?mode=rwc` (three slashes, then the absolute path) or `sqlite://relative.db?mode=rwc`. `mode=rwc` creates the file when it is missing. `sqlite::memory:` is refused. Start the roles that share the file on one host only; see [databases.md](databases.md#sqlite).
- Connection options of the driver go in the query string (`?sslmode=require` for PostgreSQL, `?ssl-mode=required` for MariaDB). TLS to the database uses rustls.
- The URL is a secret: it appears in no log line or error message (`proxyx doctor` prints `host:port/database` only).
- `proxyx migrate pool` and `proxyx migrate control` apply the schema of whichever backend the URL names, and `--check` reports the pending migrations of that backend; see [operations.md](operations.md#migrations).

## Pool gateway and warmer

The gateway and the warmer read the same settings. The warmer ignores the listener keys it does not serve. Provider adapters, policies and the static inventory are not settings: they are versioned data under `data_dir` (see [providers](providers.md) and [policies](policies.md)).

| Key | Environment variable | Default | Meaning |
|---|---|---|---|
| `database_url` | `PROXYX_POOL_DATABASE_URL` | `postgres://proxyx@localhost/proxyx` | The relational database, the source of truth: org keys, policies, inventory, scores, blocks, audit. The scheme selects the backend: `postgres://` (default), `mariadb://` or `mysql://` (MariaDB 10.6 or newer), `sqlite://PATH?mode=rwc` (one host only). See [databases.md](databases.md). |
| `redis_url` | `PROXYX_POOL_REDIS_URL` | `redis://localhost:6379` | Redis or Valkey for hot state (leases, ready sets, counters, cooldowns, breakers). Loss of this state is accepted and rebuilt from the database. Keep it separate from the session proxy's Redis, or use another database number (`redis://host:6379/1`). |
| `connect_listen` | `PROXYX_POOL_CONNECT_LISTEN` | `0.0.0.0:8080` | HTTP CONNECT listener. |
| `socks_listen` | `PROXYX_POOL_SOCKS_LISTEN` | `0.0.0.0:1080` | SOCKS5 listener. |
| `probe_listen` | `PROXYX_POOL_PROBE_LISTEN` | `0.0.0.0:8082` | CONNECT listener for the prober's browsers. It accepts only signed probe tokens. |
| `api_listen` | `PROXYX_POOL_API_LISTEN` | `0.0.0.0:8081` | Control API (`/v1/...`). |
| `ops_listen` | `PROXYX_POOL_OPS_LISTEN` | `0.0.0.0:8888` | `/healthz`, `/readyz`, `/metrics`. |
| `data_dir` | `PROXYX_POOL_DATA_DIR` | `/etc/proxyx/data` | Directory with `adapters/*.toml`, `policies/*.toml`, `inventory/*.toml` and `probe-targets.toml`. |
| `secrets_dir` | `PROXYX_POOL_SECRETS_DIR` | `/etc/proxyx/secrets` | Directory of secret files. Adapters (`user_file`, `pass_file`), inventory entries (`credentials`) and the scorers name a file in it. A name with `..` or a leading `/` is refused; an empty or missing file is an error. One trailing newline is trimmed. |
| `admin_token_file` | `PROXYX_POOL_ADMIN_TOKEN_FILE` | `/etc/proxyx/secrets/admin-token` | Bearer token for the mutating `/v1` routes. |
| `probe_key_file` | `PROXYX_POOL_PROBE_KEY_FILE` | `/etc/proxyx/secrets/probe-key` | Secret that signs short-lived probe tokens (`POST /v1/probe/token`). Mounted into the gateway only. Read once at start: rotating it takes a restart. A missing file means there is no prober: no token is issued and the probe listener refuses every login. |
| `probe_org` | `PROXYX_POOL_PROBE_ORG` | `proxyx-probe` | Org id that probe tokens log in as. The policy of the prober's route classes applies to it. Must match `[a-z0-9_-]{1,64}`. |
| `drain_timeout` | `PROXYX_POOL_DRAIN_TIMEOUT` | `300s` | How long a stopping process keeps open tunnels. Must be above zero. Give the orchestrator a termination grace period longer than this plus 15 s. |
| `reload_every` | `PROXYX_POOL_RELOAD_EVERY` | `30s` | Interval of the policy and inventory snapshot reload. At least one second. |
| `max_connections` | `PROXYX_POOL_MAX_CONNECTIONS` | `10000` | Most tunnels at once across the CONNECT, SOCKS5 and probe listeners. A connection over the cap is closed at accept. The gateway refuses to start when `ulimit -n` is below `2 x max_connections + 512`. Must be above zero. |
| `max_pending_connections` | `PROXYX_POOL_MAX_PENDING_CONNECTIONS` | `max_connections / 2` (at least 1) | Most connections that have not authenticated yet, across all listeners. Between 1 and `max_connections`. |
| `max_pending_per_ip` | `PROXYX_POOL_MAX_PENDING_PER_IP` | a quarter of the pending limit, at least 16, at most the pending limit | Most unauthenticated connections of one source (an IPv4 address or an IPv6 /64). Raise it for clients behind one NAT or a load balancer without PROXY protocol. |
| `tunnel_idle_timeout` | `PROXYX_POOL_TUNNEL_IDLE_TIMEOUT` | `10m` | A tunnel with no byte in either direction for this long is closed. Must be above zero. |
| `exit_ip_services` | `PROXYX_POOL_EXIT_IP_SERVICES` | unset (public services) | Comma list of `kind=url` that replaces the public exit-IP check services, for an isolated environment. It needs at least one of `cloudflare`, `ipinfo`, `ifconfig_co`, because only those report the exit country. |
| `ipqs_base_url` | `PROXYX_POOL_IPQS_BASE_URL` | `https://ipqualityscore.com` | Origin of the IPQS reputation API. |
| `abuseipdb_base_url` | `PROXYX_POOL_ABUSEIPDB_BASE_URL` | `https://api.abuseipdb.com` | Origin of the AbuseIPDB reputation API. |
| `scamalytics_base_url` | `PROXYX_POOL_SCAMALYTICS_BASE_URL` | `https://api12.scamalytics.com` | Origin of the Scamalytics API. |
| `scamalytics_customer` | `PROXYX_POOL_SCAMALYTICS_CUSTOMER` | unset | Scamalytics account name. Required when the `scamalytics_api_key` secret exists. |
| `json_logs` | `PROXYX_POOL_JSON_LOGS` | `true` | JSON log lines; plain text when false. |
| `sentry.dsn` | `PROXYX_POOL_SENTRY__DSN` | unset (off) | Sentry DSN. A malformed DSN is refused at start. |
| `sentry.environment` | `PROXYX_POOL_SENTRY__ENVIRONMENT` | `development` | Environment tag of events. |
| `sentry.release` | `PROXYX_POOL_SENTRY__RELEASE` | crate version | Release tag of events. |
| `sentry.sample_rate` | `PROXYX_POOL_SENTRY__SAMPLE_RATE` | `1.0` | Share of error events sent, 0.0 to 1.0. |
| `sentry.traces_sample_rate` | `PROXYX_POOL_SENTRY__TRACES_SAMPLE_RATE` | `0.0` | Share of transactions sent, 0.0 to 1.0. Traces go to OpenTelemetry. |

The base URLs must be `http://` or `https://` origins. Only a benchmark or an isolated environment with a stand-in service changes them.

### Secret files

| File in `secrets_dir` | Needed by | Purpose |
|---|---|---|
| `admin-token` (path from `admin_token_file`) | gateway | Bearer token of the operator routes of the control API. |
| `prober-token` | gateway | Bearer token of the prober, for `/v1/probe/*`. A separate secret from the admin token. |
| `probe-key` (path from `probe_key_file`) | gateway | HMAC key for probe tokens. |
| `ipqs_api_key`, `abuseipdb_api_key`, `scamalytics_api_key` | gateway, warmer | Each file that exists turns on that reputation scorer. With no file, no scorer runs. |
| files named by adapters and inventory entries | gateway, warmer | Provider logins. A missing or empty file fails the whole adapter load. |

### Environment outside the settings

| Variable | Default | Meaning |
|---|---|---|
| `SERVICE_NAME` | `proxyx-gateway`, `proxyx-warmer`, `proxyx-migrate` | The `service` label of metrics, the trace service name and the Sentry tag. |
| `RUST_LOG` | `info` | Log filter. |
| `OTEL_ENABLED` | `false` | `1`, `true`, `yes` or `on` turns on OTLP trace export. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://localhost:4317` | OTLP gRPC endpoint. |
| `OTEL_TRACES_SAMPLER_ARG` | `0.1` | Trace sampling ratio. |
| `ENVIRONMENT` | `dev` | Deployment environment tag of traces. |

## Session proxy

`proxyx-intercept` reads `PROXYX_INTERCEPT_*` variables and the file `./intercept.toml`, else `/etc/proxyx/intercept.toml`, then `--config`.

### Top-level keys

| Key | Environment variable | Default | Meaning |
|---|---|---|---|
| `id` | `PROXYX_INTERCEPT_ID` | random UUID | Proxy id recorded on every capture (`proxy_id`). |
| `connect_addr` | `PROXYX_INTERCEPT_CONNECT_ADDR` | **required** | HTTP CONNECT listener (also handles absolute-URI forward requests). The built-in default value is `0.0.0.0:8443`, but a file or environment that omits it fails to load, so always set it. |
| `http_addr` | `PROXYX_INTERCEPT_HTTP_ADDR` | unset (off) | Optional second HTTP forward proxy listener. |
| `socks_addr` | `PROXYX_INTERCEPT_SOCKS_ADDR` | `0.0.0.0:1080` | SOCKS5 listener. |
| `api_addr` | `PROXYX_INTERCEPT_API_ADDR` | `0.0.0.0:8888` | Admin server: `/health/live`, `/health/ready` (alias `/health`), `/metrics`, and the profiling routes when enabled. |
| `redis_url` | `PROXYX_INTERCEPT_REDIS_URL` | `redis://127.0.0.1:6379` | Redis for sessions, the rate-limit state and, by default, the capture stream. Accepts `redis://`, `rediss://` and the Sentinel forms `redis+sentinel://:pw@h1:26379,h2:26379/mastername` and `rediss+sentinel://`. With Sentinel the process exits when the master moves, so the supervisor restarts it. |
| `redis_key_prefix` | `PROXYX_INTERCEPT_REDIS_KEY_PREFIX` | `proxyx` | Prefix of every Redis key and channel. Must equal the control plane's `redis_key_prefix`. Change it to isolate deployments on one Redis. |
| `no_capture_hosts` | `PROXYX_INTERCEPT_NO_CAPTURE_HOSTS` | empty | Host patterns that are never captured, even when a session asks for them. A comma-separated string in the environment, a list in a file. Patterns: exact host, `*.suffix` (also matches the bare suffix), `*`. |
| `broker_kind` | `PROXYX_INTERCEPT_BROKER_KIND` | `redis_stream` | Capture log broker: `redis_stream`, `kafka` (`[kafka]`) or `rabbitmq` (`[rabbitmq]`). `redpanda` is a deprecated alias of `kafka`. Redis is still required for sessions and rate limits whichever you pick. |

### `[ratelimit]`

Per-org request rate limits. See [session-proxy.md](session-proxy.md#rate-limiting).

| Key | Environment variable | Default | Meaning |
|---|---|---|---|
| `backend` | `PROXYX_INTERCEPT_RATELIMIT__BACKEND` | `redis` | `redis` (Lua token bucket) or `limiter` (the `proxyx limiter` service). |
| `limiter_addr` | `PROXYX_INTERCEPT_RATELIMIT__LIMITER_ADDR` | `127.0.0.1:39091` | Limiter address, used only with `backend = "limiter"`. |
| `default_burst` | `PROXYX_INTERCEPT_RATELIMIT__DEFAULT_BURST` | `1000` | Burst of an org without its own setting. |
| `default_rpm` | `PROXYX_INTERCEPT_RATELIMIT__DEFAULT_RPM` | `6000` | Requests per minute of an org without its own setting. |
| `refill_threshold_pct` | `PROXYX_INTERCEPT_RATELIMIT__REFILL_THRESHOLD_PCT` | `0.25` | The local bucket refills from the backend when its tokens fall below this share of the maximum. |
| `rate_limit_max_wait_ms` | `PROXYX_INTERCEPT_RATELIMIT__RATE_LIMIT_MAX_WAIT_MS` | `1000` | Longest a request waits for a token before it is refused with 429. |
| `limiter_connect_timeout_ms` | `PROXYX_INTERCEPT_RATELIMIT__LIMITER_CONNECT_TIMEOUT_MS` | `1000` | `limiter` backend: connect budget of one limiter connection. Must be above 0. |
| `limiter_io_timeout_ms` | `PROXYX_INTERCEPT_RATELIMIT__LIMITER_IO_TIMEOUT_MS` | `1000` | `limiter` backend: budget of one request/response exchange. Must be above 0. |
| `limiter_keepalive_secs` | `PROXYX_INTERCEPT_RATELIMIT__LIMITER_KEEPALIVE_SECS` | `30` | `limiter` backend: idle seconds before the first TCP keepalive probe. `0` turns keepalive off. |
| `limiter_breaker_failures` | `PROXYX_INTERCEPT_RATELIMIT__LIMITER_BREAKER_FAILURES` | `5` | `limiter` backend: consecutive transport failures that open the limiter client's circuit breaker. `0` turns it off. |
| `limiter_breaker_open_ms` | `PROXYX_INTERCEPT_RATELIMIT__LIMITER_BREAKER_OPEN_MS` | `2000` | `limiter` backend: how long that breaker stays open before one probe. Must be above 0 while the breaker is on. |
| `failopen_policy` | `PROXYX_INTERCEPT_RATELIMIT__FAILOPEN_POLICY` | `{ type = "grant_tokens", value = <default_burst> }` | Behaviour when the backend fails. `{ type = "deny" }` refuses requests with 429. `grant_tokens` fails open for the org's local bucket after the first backend error. In a file: `failopen_policy = { type = "deny" }`. |

### `[request_log]`

| Key | Environment variable | Default | Meaning |
|---|---|---|---|
| `stream_name` | `PROXYX_INTERCEPT_REQUEST_LOG__STREAM_NAME` | `proxyx:request_log` | Redis stream that receives captures. Must equal the control plane's `request_log_stream`. |
| `channel_capacity` | `PROXYX_INTERCEPT_REQUEST_LOG__CHANNEL_CAPACITY` | `256` | Size of the in-process queue, and the largest batch handed to the producer. A full queue blocks the tunnel (backpressure). |
| `max_stream_len` | `PROXYX_INTERCEPT_REQUEST_LOG__MAX_STREAM_LEN` | `1000000` | Approximate `MAXLEN ~` of the Redis stream. `0` disables trimming. |

### `[tuning]`

| Key | Environment variable | Default | Meaning |
|---|---|---|---|
| `max_body_capture` | `PROXYX_INTERCEPT_TUNING__MAX_BODY_CAPTURE` | `524288` | Largest request or response body (and WebSocket payload) kept in a capture, in bytes. Larger bodies are truncated and flagged. |
| `max_header_capture` | `PROXYX_INTERCEPT_TUNING__MAX_HEADER_CAPTURE` | `512` | Largest header value kept, in bytes. |
| `exchange_channel_capacity` | `PROXYX_INTERCEPT_TUNING__EXCHANGE_CHANNEL_CAPACITY` | `8` | Per-tunnel queue between the interception path and the capture publisher. |
| `max_connections` | `PROXYX_INTERCEPT_TUNING__MAX_CONNECTIONS` | `10000` | Most concurrent connections across all listeners. |
| `shutdown_drain_timeout_secs` | `PROXYX_INTERCEPT_TUNING__SHUTDOWN_DRAIN_TIMEOUT_SECS` | `300` | How long a stopping proxy waits for tunnels before forcing exit. The capture buffer is then flushed for up to 30 s more, so the termination grace period has to cover both. |

### `[capture_store.opensearch]`

Required when `capture_store.backend = "opensearch"`. OpenSearch 2.x or Elasticsearch 8. The full description, the schema and the query differences are in [capture-stores.md](capture-stores.md).

| Key | Environment variable | Default | Meaning |
|---|---|---|---|
| `url` | `PROXYX_CONTROL_CAPTURE_STORE__OPENSEARCH__URL` | required | `http://` or `https://` URL of the cluster or a coordinating node. |
| `username`, `password` | `..__USERNAME`, `..__PASSWORD` | unset | Basic authentication. |
| `api_key` | `..__API_KEY` | unset | Elasticsearch API key (`Authorization: ApiKey`). Exclusive with `username`. |
| `ca_cert` | `..__CA_CERT` | unset | PEM file with the CA of the server certificate. |
| `index_prefix` | `..__INDEX_PREFIX` | `proxyx` | Prefix of indices and templates. |
| `rollover` | `..__ROLLOVER` | `daily` | `daily` or `weekly` index per UTC period of the capture time. |
| `number_of_shards`, `number_of_replicas` | `..__NUMBER_OF_SHARDS`, `..__NUMBER_OF_REPLICAS` | `1`, `1` | Template settings. |
| `refresh_interval` | `..__REFRESH_INTERVAL` | `5s` | Template setting; how long a write takes to become searchable. |
| `index_settings` | table in the file | empty | Extra template settings by full name, for example `"index.lifecycle.name"` (ILM) or `"index.plugins.index_state_management.policy_id"` (ISM). |
| `request_timeout_secs`, `bulk_timeout_secs` | `..__REQUEST_TIMEOUT_SECS`, `..__BULK_TIMEOUT_SECS` | `30`, `120` | Timeouts of searches and admin calls, and of one `_bulk` request. |
| `max_bulk_bytes` | `..__MAX_BULK_BYTES` | `10485760` | Largest `_bulk` request body. |
| `connect_timeout_secs` | `..__CONNECT_TIMEOUT_SECS` | `10` | Timeout of establishing a connection (TCP and TLS). |
| `pool_idle_timeout_secs` | `..__POOL_IDLE_TIMEOUT_SECS` | `90` | An idle pooled connection is closed after this long; `0` keeps it until the server closes it. |
| `pool_max_idle_per_host` | `..__POOL_MAX_IDLE_PER_HOST` | `32` | Idle connections kept per host. |
| `tcp_keepalive_secs` | `..__TCP_KEEPALIVE_SECS` | `60` | TCP keepalive interval; `0` disables it. |
| `max_retries`, `retry_initial_backoff_ms`, `retry_max_backoff_ms` | `..__MAX_RETRIES` and so on | `3`, `200`, `5000` | In-place retries of a `_bulk` request after a transient failure, with exponential backoff and jitter. `0` disables the in-place retry. |
| `bulk_size`, `flush_interval_secs`, `max_buffer_bytes`, `circuit_breaker_threshold`, `circuit_breaker_reset_secs` | `..__BULK_SIZE` and so on | as `[clickhouse]` | Batching, backpressure and circuit breaker, with the same meaning as the ClickHouse keys. |

### `[ca]`

The CA that signs the leaf certificates of intercepted TLS connections. The `type` key selects the mode.

| `type` | Keys | Meaning |
|---|---|---|
| `generate` (default, `data_dir = "data"`) | `data_dir` | Loads `ca.der` and `ca.key.der` from `data_dir`, or creates them (ECDSA P-256, ten years). Development only. |
| `file` | `cert_path`, `key_path` | DER files. |
| `env` | none | `PROXYX_INTERCEPT_CA_CERT` and `PROXYX_INTERCEPT_CA_KEY`: base64 DER, or PEM. |

Clients trust the certificate that the control plane serves, so the control plane's `[ca]` must publish the same CA. See [session-proxy.md](session-proxy.md#ca-and-client-trust).

### `[sentry]`

`dsn`, `environment`, `release`, `sample_rate` (default `1.0`) and `traces_sample_rate` (default `0.0`), with the same meaning as for the pool gateway. Variables: `PROXYX_INTERCEPT_SENTRY__DSN` and so on.

### `[kafka]`

Required when `broker_kind = "kafka"`; shared with the control plane (same table in `control.toml`). `[redpanda]` / `PROXYX_*_REDPANDA__*` is a deprecated alias of this section, accepted for one more release; setting both is an error. See [capture-pipeline.md](capture-pipeline.md#apache-kafka-and-kafka-compatible-brokers-kafka).

| Key | Default | Meaning |
|---|---|---|
| `brokers` | required | Comma-separated bootstrap list, `host:port`. |
| `topic` | required | Capture topic. |
| `partitions` | `12` | Partition count. Permanent: `migrate` fails when the topic exists with another count. |
| `replication_factor` | `3` | Replication factor at topic creation. Use `1` on a single-node cluster. |
| `retention_ms` | `604800000` | `retention.ms` of a topic that `migrate` creates (seven days). An existing topic is not altered; a different value is reported. |
| `client_id_prefix` | `proxyx` | Prefix of the Kafka `client.id`. |
| `compression` | `none` | Producer compression: `none`, `gzip`, `lz4`, `snappy` or `zstd`. |
| `acks` | `all` | Only `all` is accepted: the producer always waits for every in-sync replica. |
| `linger_ms` | `0` | Time to coalesce concurrent publish calls into one request; useful for the control API, not for the session proxy. |
| `batch_bytes` | `1048576` | Largest produce request; 16 KiB to 100 MiB. Keep within the broker's `message.max.bytes`. |
| `tls.ca_cert`, `tls.client_cert`, `tls.client_key` | unset | PEM file paths; the client pair enables mutual TLS. |
| `sasl.mechanism`, `sasl.username`, `sasl.password` | unset | `PLAIN`, `SCRAM-SHA-256` or `SCRAM-SHA-512`. With `tls` the consumer uses `sasl_ssl`, without it `sasl_plaintext`. |

### `[rabbitmq]`

Required when `broker_kind = "rabbitmq"`; shared with the control plane. See [capture-pipeline.md](capture-pipeline.md#rabbitmq-rabbitmq).

| Key | Default | Meaning |
|---|---|---|
| `url` | required | `amqp://user:pass@host:5672/%2f` or `amqps://...` for TLS; the path is the vhost. |
| `username`, `password` | unset | Override the credentials of the URL. |
| `exchange` | `proxyx.captures` | Direct exchange; the queues are `<exchange>.p00` and so on, the dead-letter queue `<exchange>.dead`. |
| `queue_prefix` | the exchange name | Prefix of the queue names. |
| `partitions` | `12` | Partition queues, 1 to 1000. Permanent: it decides which queue a key goes to. |
| `quorum_group_size` | `3` | Replicas of each quorum queue at declaration (`x-quorum-initial-group-size`); `1` on a single node. |
| `delivery_limit` | `20` | Redeliveries before a message is dead-lettered. |
| `message_ttl_ms` | `604800000` | Queue message TTL; expired messages are dead-lettered. `0` disables it. |
| `prefetch` | `500` | Unacked messages per queue consumer; keep it at least the ingester's `bulk_size`. |
| `heartbeat_secs` | `30` | AMQP heartbeat. |
| `connect_timeout_secs` | `10` | Timeout of establishing a connection. |
| `confirm_timeout_secs` | `30` | Wait for the publisher confirms of one chunk. |
| `reconnect_initial_backoff_ms`, `reconnect_max_backoff_ms` | `500`, `30000` | Exponential reconnect backoff. |
| `client_name_prefix` | `proxyx` | Prefix of the connection name (`<prefix>-proxy`, `-api`, `-ingester`). |
| `tls.ca_cert`, `tls.client_cert`, `tls.client_key` | unset | PEM files; requires `amqps://`. The client key is PKCS#8. |

### Other variables

| Variable | Meaning |
|---|---|
| `PROXYX_INTERCEPT_PROFILING` | `1` or `true` adds `GET /debug/pprof/profile?seconds=N` and `GET /debug/stalls` to the admin server. |
| `PROXYX_LOG_JSON` | `1` or `true` emits JSON logs (default text). |
| `RUST_LOG`, `OTEL_ENABLED`, `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_TRACES_SAMPLER_ARG`, `ENVIRONMENT` | As for the pool gateway. |

## Control plane

`proxyx control api`, `proxyx control ingester`, `proxyx control keys` and `proxyx migrate control` read `PROXYX_CONTROL_*` variables and `./control.toml`, else `/etc/proxyx/control.toml`, then `--config`.

| Key | Environment variable | Default | Meaning |
|---|---|---|---|
| `env` | `PROXYX_CONTROL_ENV` | `dev` | Environment name (`dev`, `staging`, `prod`). Outside `dev`, the CIDR check of `trusted_headers` mode is enforced. |
| `debug` | `PROXYX_CONTROL_DEBUG` | `false` | Enables development conveniences. |
| `auth_mode` | `PROXYX_CONTROL_AUTH_MODE` | `keys` | `keys`: `Authorization: Bearer pxk_...` checked against the `api_keys` table. `trusted_headers`: `x-proxyx-*` principal headers set by an authenticating gateway in front of the API. See [control-api.md](control-api.md#authentication). |
| `http.request_timeout_secs` | `PROXYX_CONTROL_HTTP__REQUEST_TIMEOUT_SECS` | `60` | Deadline of one API request; past it the API answers `504`. `0` disables. |
| `http.max_in_flight` | `PROXYX_CONTROL_HTTP__MAX_IN_FLIGHT` | `1024` | Requests served at once; more get `503` with `Retry-After: 1`. `0` disables. |
| `http.per_key_rps` | `PROXYX_CONTROL_HTTP__PER_KEY_RPS` | `100` | Sustained requests per second per credential (or client address); over it `429` with `Retry-After`. `0` disables. |
| `http.per_key_burst` | `PROXYX_CONTROL_HTTP__PER_KEY_BURST` | `200` | Burst of `per_key_rps`. |
| `internal_allowed_cidrs` | `PROXYX_CONTROL_INTERNAL_ALLOWED_CIDRS` | empty | Comma-separated CIDR allowlist for `/rpc/*` in `trusted_headers` mode, matched against the `X-Forwarded-For` client. Enforced outside `env = "dev"`. |
| `database_url` | `PROXYX_CONTROL_DATABASE_URL` | empty | Database URL (orgs, session lifecycle, export jobs, API keys). Required. The scheme selects the backend as for the pool: `postgres://`, `mariadb://` or `mysql://`, `sqlite://PATH?mode=rwc`. The pool and the control plane may use different backends but need separate databases or files. See [databases.md](databases.md). |
| `api_addr` | `PROXYX_CONTROL_API_ADDR` | `0.0.0.0:9000` | API listener. |
| `ingester_health_addr` | `PROXYX_CONTROL_INGESTER_HEALTH_ADDR` | `0.0.0.0:9001` | Ingester health and metrics listener. |
| `redis_url` | `PROXYX_CONTROL_REDIS_URL` | `redis://127.0.0.1:6379` | Redis for sessions and the capture stream. Required by the API and the Redis-stream ingester; optional for a Kafka or RabbitMQ ingester. The same URL forms as the session proxy. |
| `redis_key_prefix` | `PROXYX_CONTROL_REDIS_KEY_PREFIX` | `proxyx` | Prefix of keys, streams and channels. Must equal the session proxy's. |
| `request_log_stream` | `PROXYX_CONTROL_REQUEST_LOG_STREAM` | `proxyx:request_log` | Capture stream name. |
| `request_log_max_stream_len` | `PROXYX_CONTROL_REQUEST_LOG_MAX_STREAM_LEN` | `1000000` | Approximate stream cap used when the control plane publishes (`SessionEnd`). Match the session proxy's value. |
| `consumer_group` | `PROXYX_CONTROL_CONSUMER_GROUP` | `proxyx_control` | Redis consumer group of the ingester. |
| `broker_kind` | `PROXYX_CONTROL_BROKER_KIND` | `redis_stream` | `redis_stream`, `kafka` or `rabbitmq`; must match the session proxy. `redpanda` is a deprecated alias of `kafka`. |
| `kafka` | `PROXYX_CONTROL_KAFKA__*` | unset | The `[kafka]` table above. Required for `kafka`. |
| `rabbitmq` | `PROXYX_CONTROL_RABBITMQ__*` | unset | The `[rabbitmq]` table above. Required for `rabbitmq`. |
| `session_default_ttl_secs` | `PROXYX_CONTROL_SESSION_DEFAULT_TTL_SECS` | `600` | TTL of a session created without one. |
| `capture_store.backend` | `PROXYX_CONTROL_CAPTURE_STORE__BACKEND` | `clickhouse` | Where captures are stored and queried: `clickhouse` (`[clickhouse]`) or `opensearch` (`[capture_store.opensearch]`, also Elasticsearch 8). See [capture-stores.md](capture-stores.md). |
| `session_lifecycle_writes` | `PROXYX_CONTROL_SESSION_LIFECYCLE_WRITES` | `true` | Whether the ingester marks `session_lifecycle` rows `closed` after its capture-store flush. Turn it off on an ingester whose store does not serve reads. |
| `default_rate_limit_rpm` | `PROXYX_CONTROL_DEFAULT_RATE_LIMIT_RPM` | `0` | Requests per minute for sessions of orgs without a row. `0` means unlimited. |
| `default_rate_limit_burst` | `PROXYX_CONTROL_DEFAULT_RATE_LIMIT_BURST` | `0` | Burst for such sessions. `0` means unlimited. |
| `proxy_public_host` | `PROXYX_CONTROL_PROXY_PUBLIC_HOST` | `localhost:8443` | Public `host:port` of the session proxy's CONNECT listener, put into `proxy_url`. |
| `proxy_public_host_socks5` | `PROXYX_CONTROL_PROXY_PUBLIC_HOST_SOCKS5` | `localhost:1080` | Public `host:port` of its SOCKS5 listener. |
| `correlation_id_header` | `PROXYX_CONTROL_CORRELATION_ID_HEADER` | `X-ProxyX-Agent` | Request header stored as `correlation_id`. Case-insensitive. Unset disables extraction. |
| `parent_correlation_id_header` | `PROXYX_CONTROL_PARENT_CORRELATION_ID_HEADER` | `X-ProxyX-Parent-Agent` | Request header stored as `parent_correlation_id`. |
| `account_id_header` | `PROXYX_CONTROL_ACCOUNT_ID_HEADER` | `X-ProxyX-Account` | Request header stored as `account_id`. |
| `tool_call_id_header` | `PROXYX_CONTROL_TOOL_CALL_ID_HEADER` | `X-ProxyX-Tool` | Request header stored as `tool_call_id`. |
| `sentry.*` | `PROXYX_CONTROL_SENTRY__*` | off | As for the session proxy. |

### `[clickhouse]`

Required when `capture_store.backend` is `clickhouse` (the default; the section has no default values). Used by the API, the ingester and `migrate control`. Not needed with the `opensearch` backend.

| Key | Environment variable | Default | Meaning |
|---|---|---|---|
| `url` | `PROXYX_CONTROL_CLICKHOUSE__URL` | required | HTTP URL, for example `http://clickhouse:8123`. |
| `database` | `PROXYX_CONTROL_CLICKHOUSE__DATABASE` | server default | Database. |
| `user`, `password` | `PROXYX_CONTROL_CLICKHOUSE__USER`, `..__PASSWORD` | unset | Credentials. |
| `table` | `PROXYX_CONTROL_CLICKHOUSE__TABLE` | `http_captures` | Capture table. |
| `bulk_size` | `PROXYX_CONTROL_CLICKHOUSE__BULK_SIZE` | `500` | Rows per insert. Larger batches make fewer, larger parts. |
| `flush_interval_secs` | `PROXYX_CONTROL_CLICKHOUSE__FLUSH_INTERVAL_SECS` | `5` | Longest a row waits before a flush. |
| `max_buffer_bytes` | `PROXYX_CONTROL_CLICKHOUSE__MAX_BUFFER_BYTES` | `268435456` | Soft cap on buffered payload bytes. At the cap the flusher refuses new rows and the backpressure reaches the consumer. Rows are never dropped. |
| `circuit_breaker_threshold` | `PROXYX_CONTROL_CLICKHOUSE__CIRCUIT_BREAKER_THRESHOLD` | `5` | Consecutive failed flushes that open the breaker. |
| `circuit_breaker_reset_secs` | `PROXYX_CONTROL_CLICKHOUSE__CIRCUIT_BREAKER_RESET_SECS` | `60` | Time before a half-open attempt. |
| `local_single_node` | `PROXYX_CONTROL_CLICKHOUSE__LOCAL_SINGLE_NODE` | unset | When the variable is set to any value, `migrate control` rewrites `Replicated*` engines to their plain form, drops the tiered-storage policy and volume moves, and skips `SYSTEM SYNC REPLICA`. Single-node development only. |

### `[ca]`

The CA certificate that session responses return (and `GET /rpc/certificate`). The control plane never signs anything with it.

| `type` | Keys | Meaning |
|---|---|---|
| `generate` (default, `data_dir = "data"`) | `data_dir` | Shares `ca.der` and `ca.key.der` in `data_dir` with the session proxy: whichever process starts first creates them (the file is created exclusively, so a concurrent start never overwrites it) and the other loads them. The control plane serves the certificate as PEM. Both processes must see the same `data_dir`. Development only. |
| `file` | `cert_path` | PEM file. |
| `env` | none | `PROXYX_CONTROL_CA_CERT`: the PEM string. Use the same CA as the session proxy. |

### Traffic view exports

Exports exist only with the ClickHouse capture store; with `opensearch` they answer `501` and these keys are ignored.

| Key | Environment variable | Default | Meaning |
|---|---|---|---|
| `traffic_views_backend` | `PROXYX_CONTROL_TRAFFIC_VIEWS_BACKEND` | `s3` | `s3` (ClickHouse writes with `s3()`; downloads are CloudFront-signed URLs) or `azure` (Azure Blob Storage through `azureBlobStorage()`; downloads are user-delegation SAS URLs). |
| `traffic_views_bucket` | `PROXYX_CONTROL_TRAFFIC_VIEWS_BUCKET` | empty | S3 bucket, or blob container for `azure`. |
| `traffic_views_azure_account` | `PROXYX_CONTROL_TRAFFIC_VIEWS_AZURE_ACCOUNT` | empty | Storage account name. Required for `azure`. |
| `traffic_views_s3_region` | `PROXYX_CONTROL_TRAFFIC_VIEWS_S3_REGION` | `us-east-1` | AWS region of the bucket. |
| `traffic_views_ttl_secs` | `PROXYX_CONTROL_TRAFFIC_VIEWS_TTL_SECS` | `86400` | How long a completed export is kept, counted from completion. The reaper then deletes the object and the job row. |
| `cloudfront_domain` | `PROXYX_CONTROL_CLOUDFRONT_DOMAIN` | empty | CloudFront distribution domain for signed download URLs. Required for signed URLs. |
| `cloudfront_key_pair_id` | `PROXYX_CONTROL_CLOUDFRONT_KEY_PAIR_ID` | empty | CloudFront key pair id. |
| `cloudfront_private_key` | `PROXYX_CONTROL_CLOUDFRONT_PRIVATE_KEY` | empty | RSA private key (PEM, PKCS#1 or PKCS#8) for URL signing. |
| `export_preferred_block_size_bytes` | `PROXYX_CONTROL_EXPORT_PREFERRED_BLOCK_SIZE_BYTES` | `33554432` | ClickHouse reader block size during export; keeps memory bounded on wide body columns. |
| `export_max_block_size` | `PROXYX_CONTROL_EXPORT_MAX_BLOCK_SIZE` | `5000` | Maximum rows per block during export. |
| `export_row_group_size_bytes` | `PROXYX_CONTROL_EXPORT_ROW_GROUP_SIZE_BYTES` | `134217728` | Target Parquet row group size in bytes. |
| `export_row_group_size` | `PROXYX_CONTROL_EXPORT_ROW_GROUP_SIZE` | `10000` | Target Parquet row group size in rows. |

### Other variables

| Variable | Meaning |
|---|---|
| `PROXYX_SCHEMA_ROUTING_URL` | Routing URL written into the manifest by `proxyx control schema manifest` (default `http://localhost:9000/graphql`). |
| `PROVENANCE_ID` | Version of the manifest when `--version` is not given. |
| `PROXYX_LOG_JSON`, `RUST_LOG`, `OTEL_*`, `ENVIRONMENT` | As for the session proxy. |

## Limiter

`proxyx limiter [ADDR]` takes the listen address as its only argument (default `127.0.0.1:39091`). It reads no file. Its state is in memory and is discarded on exit.

| Variable | Default | Meaning |
|---|---|---|
| `PROXYX_LIMITER_MAX_BUCKETS` | `1048576` | Capacity of the bucket slab. |
| `PROXYX_LIMITER_SHARDS` | `256` | Number of shards of the name index. |
| `PROXYX_LIMITER_REAPER_MS` | `1000` | Interval of the TTL reaper, in milliseconds. |
| `PROXYX_LIMITER_MAX_CONNECTIONS` | `4096` | Open connections the service accepts. It runs one thread per connection, so the cap bounds threads and memory. A connection above it is closed at once and counted in `proxyx_limiter_connections_refused_total`. |
| `PROXYX_LIMITER_TCP_KEEPALIVE_SECS` | `60` | Idle time before the first TCP keepalive probe on accepted sockets. Probes then repeat every sixth of that time (at least 1 s), and the peer is dropped after 3 unanswered probes, so a client host that vanished does not hold a thread forever. `0` turns keepalive off. |
| `PROXYX_LIMITER_METRICS_ADDR` | empty (off) | Address of the plain-HTTP operations port with `/healthz`, `/readyz` and `/metrics` (for example `127.0.0.1:39092`). See [metrics/limiter.md](metrics/limiter.md). |

A value that is not a positive integer falls back to the default (for `PROXYX_LIMITER_TCP_KEEPALIVE_SECS`, `0` is valid and means off).

The data protocol also has a `PING` op: the service echoes an 8-byte token with its uptime. The client library exposes it as `ping()`; use it for a liveness check that goes through the real protocol (`/healthz` only proves the process runs).

### Limiter client resilience

The session proxy talks to the limiter through a pooled client (`backend = "limiter"`). The client never waits unbounded on a dead or blackholed service:

| Behaviour | Default | Effect |
|---|---|---|
| Connect and handshake timeout | 1 s | A connect that does not finish counts as a transport failure. |
| Exchange timeout | 1 s | One request/response on an open connection. On timeout the connection is dropped. |
| TCP keepalive | 30 s idle, 3 probes | Detects a peer that vanished without a FIN. |
| Circuit breaker | opens after 5 consecutive transport failures, stays open 2 s, then lets one probe through | While open, no connection is attempted: `consume` returns at once the answer of the fail policy (`failopen_policy`: `grant_tokens` allows, `deny` rejects with the same `429`), and `create` fails. A `FULL` or `STALE` reply counts as a success, because the service answered. |

The fail policy still decides what a degraded `consume` means; the breaker only removes the wait. Library users set these through `limiter_client::ResilienceConfig` and `Client::connect_with` / `AsyncClient::connect_with`, and read `stats()` and `circuit_state()` for diagnostics.

## Edge proxy

`proxyx edge --config FILE` reads one TOML file and nothing else: no environment variables, no default path, no database. The file is parsed strictly: an unknown key anywhere (a typo in a rule included) is an error. `proxyx edge --check --config FILE` validates it, including that every local address is assigned to the host and bindable, and exits. SIGHUP reloads it (see [edge-proxy.md](edge-proxy.md#operating-it)). Durations are `500ms`, `30s`, `5m`, `2h`, `1d` or integer seconds. A complete commented file is [`examples/edge.toml`](../examples/edge.toml); [edge-proxy.md](edge-proxy.md) explains the behavior.

### `[server]`

| Key | Default | Meaning |
|---|---|---|
| `ops_listen` | none | `/metrics`, `/healthz` (live) and `/readyz` (listeners bound, config loaded, an egress path is healthy) address; absent: no ops listener. Needs a restart to change. |
| `max_connections` | `10000` | Client connections served at once over all listeners; more are closed at accept. |
| `max_connections_per_src` | `0` | Connections of one source address (the PROXY protocol address when there is one); `0` is unlimited. |
| `default_pool` | none | Pool used when no egress rule, login option, user or listener names one; absent: the operating system picks the source address. |
| `default_route` | `direct` | Route when no `[[route]]` matches: `direct`, `parent`, `parent_or_direct`. |
| `utc_offset` | `+00:00` | Zone of `time` conditions, `+HH:MM` or `-HH:MM`. |
| `shutdown_grace` | `30s` | How long SIGTERM waits for open tunnels. |

### `[timeouts]`

| Key | Default | Meaning |
|---|---|---|
| `handshake` | `30s` | Reading the first request and the login. |
| `connect` | `10s` | Name resolution plus connecting to the target or parent, over all attempts. |
| `idle` | `10m` | A tunnel with no byte in either direction this long is closed (also a UDP association). |
| `keepalive` | `60s` | A client connection waiting for its next HTTP request. |
| `response_header` | `60s` | Waiting for the target's response head after the request was sent. |
| `total` | `0` | Longest one request, tunnel or UDP association may last; `0` is no limit. Every other timeout must be above zero. |

### `[tcp.client]` and `[tcp.upstream]`

Socket options of connections accepted from clients and of connections to targets and parents.

| Key | Default | Meaning |
|---|---|---|
| `keepalive` | `true` | TCP keepalive. |
| `keepalive_time` | `60s` | Idle time before the first probe. |
| `keepalive_interval` | `15s` | Time between probes. |
| `keepalive_retries` | `4` | Unanswered probes after which the connection is dropped. |
| `nodelay` | `true` | `TCP_NODELAY`. |

With `keepalive = true` the time, interval and retries must be above zero.

### `[breaker.parent]` and `[breaker.egress]`

Circuit breakers, one per parent and one per explicitly listed egress address; see [edge-proxy.md](edge-proxy.md#circuit-breakers-and-health-checks).

| Key | Default | Meaning |
|---|---|---|
| `failure_threshold` | `3` | Failures in a row that open the breaker. |
| `open_duration` | `30s` | How long it stays open before probes pass. |
| `half_open_probes` | `1` | Requests let through at once while half open. |
| `success_threshold` | `1` | Good probe results that close it. |

### `[health]`

| Key | Default | Meaning |
|---|---|---|
| `interval` | `10s` | Time between rounds of active checks of parents and egress addresses; `0` turns them off. |
| `timeout` | `5s` | One probe. |
| `parent_target` | none | `host:port` a probe opens a tunnel to through each parent; absent: the probe only connects to the parent. |
| `unhealthy_threshold` | `2` | Failed probes in a row that take a parent out. |
| `healthy_threshold` | `1` | Good probes in a row that bring it back. |

### `[dns]`

| Key | Default | Meaning |
|---|---|---|
| `nameservers` | `[]` | Resolvers to ask; empty: the system configuration (`/etc/resolv.conf`). |
| `cache_size` | `4096` | Cached answers. |
| `timeout` | `5s` | Per query. |
| `attempts` | `2` | Tries per query. |
| `min_ttl`, `max_ttl` | `30s`, `1h` | Bounds on how long an answer is cached. |
| `ip_version` | `prefer_ipv4` | `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only`. |
| `hosts` | `{}` | Fixed answers: `"name" = ["127.0.0.1", "::1"]`. |

### `[log]` and `[access_log]`

| Key | Default | Meaning |
|---|---|---|
| `log.level` | `info` | `tracing` filter; `RUST_LOG` overrides it. |
| `log.json` | `true` | JSON lines on stderr; `false` for text. |
| `access_log.output` | `off` | `off`, `stdout`, `stderr` or a file path (created `0640`, reopened on SIGHUP). |
| `access_log.format` | `squid` | `squid`, `combined`, `json`. |

### `[http]` (header policy)

| Key | Default | Meaning |
|---|---|---|
| `forwarded_for` | `delete` | `delete`, `off`, `truncate`, `on`, `transparent`. |
| `via` | `false` | Add `Via: 1.1 <proxy_name>` to requests and responses. |
| `proxy_name` | `proxyx` | Name in `Via`. |
| `request_headers_remove`, `response_headers_remove` | `[]` | Header names to drop. |
| `request_headers_set`, `response_headers_set` | `{}` | Headers set to a fixed value. |
| `max_header_bytes` | `32768` | Largest request or response head. |
| `client_max_requests` | `1000` | Requests served on one client connection before `Connection: close`; `0` is no limit. |
| `parent_keepalive` | `true` | Reuse connections to HTTP parents for bodyless requests. |
| `parent_idle_timeout` | `30s` | How long an idle parent connection is kept. |
| `parent_max_idle` | `64` | Idle parent connections kept in all (4 per key). |

### `[auth]`

| Key | Default | Meaning |
|---|---|---|
| `realm` | `proxyx` | `Proxy-Authenticate` realm. |
| `users_file` | none | htpasswd-style `user:hash` file. |
| `login_options` | `false` | Read `-sid-`, `-pool-` and `-ip-` pairs off the end of the login. |
| `fail_limit`, `fail_window` | `20`, `60s` | Failed logins per source (an IPv6 /64) before it is refused with `429`; `0` turns it off. |

### `[[listener]]`

| Key | Default | Meaning |
|---|---|---|
| `name` | required | Unique name used by rules and users. |
| `listen` | required | Socket address; port `0` picks a free port. |
| `protocol` | `auto` | `auto` (HTTP and SOCKS), `http`, `socks`. |
| `auth` | `users` | `users` requires a login, `none` relies on the rules. |
| `pool` | none | Default egress pool of the listener. |
| `proxy_protocol` | `off` | `off`, `optional`, `required`. |
| `trusted_proxies` | `[]` | Peers whose PROXY header is believed; required when `proxy_protocol` is not `off`. |
| `udp` | `false` | Serve SOCKS5 UDP ASSOCIATE. |
| `max_connections` | `0` | Connections of this listener; `0` is unlimited. |

### `[[pool]]`

| Key | Default | Meaning |
|---|---|---|
| `name` | required | Letters, digits, `_`, `-`; with `login_options`, a name used in `allowed_pools` must be `[a-z0-9_]`. |
| `addresses` | `[]` | Local addresses (each checked to be assigned and bindable). |
| `interface` | none | Add every usable address of this interface. |
| `ipv4`, `ipv6` | `true` | Families taken from `interface`. |
| `exclude` | `[]` | Networks left out of the interface's addresses. |
| `prefixes` | `[]` | Routed networks to draw addresses from, one per IP family, not mixed with `addresses` of that family. |
| `strategy` | `round_robin` | `first`, `round_robin`, `random`, `least_connections`, `sticky`. |

### `[[user]]`

| Key | Default | Meaning |
|---|---|---|
| `name` | required | No spaces, control characters or `:`. |
| `password` / `password_hash` | one required unless the user is in `users_file` | Plaintext, or bcrypt / `$apr1$` / `$1$` / `$5$` / `$6$` / argon2 / `{SHA}`. |
| `groups` | `[]` | For `group` conditions. |
| `pool` | none | The user's egress pool. |
| `allowed_pools` | `[]` | Pools selectable with `-pool-<name>`. |
| `allow_ip_select` | `false` | May use `-ip-<n>`. |
| `allowed_listeners` | `[]` | Listeners the user may log in on; empty is all. |
| `max_connections` | none | Simultaneous requests and tunnels of the user. |
| `socks4` | `false` | Accept the user on SOCKS4 by user id alone. |

### `[[rule]]`, `[[egress]]`, `[[route]]`, `[[limit]]`

All four have an optional `name` and a `when = { ... }` table with the conditions `src`, `dst`, `domain`, `port`, `method`, `protocol`, `user`, `group`, `listener`, `time`, `authenticated` and `not` (see [edge-proxy.md](edge-proxy.md#access-rules-and-the-destination-check)).

| Table | Other keys |
|---|---|
| `[[rule]]` | `action` (`allow` or `deny`, required), `allow_internal` (default `false`, allow rules only). First match wins; no match denies. |
| `[[egress]]` | exactly one of `pool` and `address`. First match wins. |
| `[[route]]` | `route` (`direct`, `parent`, `parent_or_direct`, required), `parents` (names). First match wins. |
| `[[limit]]` | `scope` (`user` default, `src`, `rule`), `bandwidth_down`, `bandwidth_up` (bytes per second or `"10Mbit/s"`, `"512KiB"`, `"2MB"`), `max_connections`, `request_rate` (`"100/min"`; `/s`, `/m`, `/h`). At least one limit key; every matching table applies. |

### `[[parent]]`

| Key | Default | Meaning |
|---|---|---|
| `name` | required | Slug (`[a-z0-9_-]`, at most 48). |
| `type` | required | `http` or `socks5`. |
| `address` | required | `host:port` or `[v6]:port`. |
| `username`, `password` | none | Set together. |
| `weight` | `1` | Share inside the priority tier. |
| `priority` | `0` | Lower tiers first. |
| `pool` | none | Pool for the connection to the parent (default: the request's pool). |
| `send_proxy_protocol` | `off` | `v1` or `v2` header with the client address. |

## Session proxy network options

These keys belong to `proxyx-intercept` (see [Session proxy](#session-proxy) above for the others and [session-proxy.md](session-proxy.md) for behavior). Each is a table in `intercept.toml` and an environment variable with `__` for nesting: `[network] upstream_connect_timeout_ms = 5000` is `PROXYX_INTERCEPT_NETWORK__UPSTREAM_CONNECT_TIMEOUT_MS=5000`. The defaults are the values that were fixed in the code before these keys existed. A zero timeout, a zero retry count or an empty backoff list is rejected at startup with an error that names the key.

### `[network]`

| Key | Environment variable (`PROXYX_INTERCEPT_NETWORK__…`) | Default | Meaning |
|---|---|---|---|
| `client_header_timeout_ms` | `CLIENT_HEADER_TIMEOUT_MS` | `5000` | Time a client has to send a complete CONNECT or HTTP request head. Also the time the SOCKS5 listener gives itself to answer a failed tunnel. |
| `socks_handshake_timeout_ms` | `SOCKS_HANDSHAKE_TIMEOUT_MS` | `5000` | Time for the SOCKS5 greeting, authentication and request, and for sniffing the first bytes of a tunnel. |
| `upstream_connect_timeout_ms` | `UPSTREAM_CONNECT_TIMEOUT_MS` | `10000` | Time for one upstream connect, all retries and the egress proxy handshake included. A timeout counts against the target's circuit breaker. |
| `tls_handshake_timeout_ms` | `TLS_HANDSHAKE_TIMEOUT_MS` | `10000` | Time for one TLS handshake, on the client side or the upstream side, including the WebSocket fallback dial. |
| `upstream_response_header_timeout_ms` | `UPSTREAM_RESPONSE_HEADER_TIMEOUT_MS` | `30000` | Time the upstream has to send response headers on an intercepted request; then the client gets `504`. |
| `body_idle_timeout_ms` | `BODY_IDLE_TIMEOUT_MS` | `30000` | Longest wait for the next bytes of a body. An idle limit, not a total one. |
| `http_keepalive_idle_timeout_ms` | `HTTP_KEEPALIVE_IDLE_TIMEOUT_MS` | `30000` | How long an intercepted client connection may sit idle between two requests before the proxy closes it. |
| `http_keepalive_max_requests` | `HTTP_KEEPALIVE_MAX_REQUESTS` | `0` | Requests served on one intercepted client connection before the proxy closes it, announced with `Connection: close` on the last response. `0` means no limit. |
| `h2_settings_timeout_ms` | `H2_SETTINGS_TIMEOUT_MS` | `2000` | Wait for the upstream's reply to the HTTP/2 round trip that precedes a WebSocket upgrade. |
| `dns_cache_ttl_secs` | `DNS_CACHE_TTL_SECS` | `60` | Lifetime of a cached DNS answer for direct dials. |
| `egress_retries` | `EGRESS_RETRIES` | `3` | Attempts for one upstream connect, the first one included. |
| `egress_backoffs_ms` | `EGRESS_BACKOFFS_MS` | `[100, 200, 400]` | Pauses between attempts; the last value repeats when there are more attempts than values. In the environment: `[100,200,400]`. |

### `[network.client_keepalive]` and `[network.upstream_keepalive]`

TCP keepalive on the sockets the proxy accepts from clients (`client_keepalive`) and on the sockets it dials: direct dials, egress proxy dials and private override dials (`upstream_keepalive`). It detects a peer that vanished without closing, which would otherwise hold a connection slot for as long as the tunnel stays open. Both tables take the same keys; the environment variables are `PROXYX_INTERCEPT_NETWORK__CLIENT_KEEPALIVE__ENABLED` and so on.

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | `false` switches `SO_KEEPALIVE` off on that side. |
| `time_secs` | `60` | Idle time before the first probe (`TCP_KEEPIDLE`). Must be above 0. |
| `interval_secs` | `20` | Time between probes (`TCP_KEEPINTVL`). Must be above 0. |
| `retries` | `3` | Unanswered probes before the connection is dropped (`TCP_KEEPCNT`). Must be above 0. |

`TCP_NODELAY` is set on all of these sockets and is not configurable.

### `[breaker]` (session proxy)

Per-upstream circuit breaker; how it works and what counts as a failure is in [session-proxy.md](session-proxy.md#upstream-circuit-breaker). Environment variables are `PROXYX_INTERCEPT_BREAKER__<KEY>`.

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | `false` disables the breaker; the other keys are then not validated. |
| `consecutive_failures` | `5` | Failed dials in a row that open a closed breaker. |
| `failure_rate_pct` | `90` | Failure share over `rate_window_ms` that opens a closed breaker, once `rate_min_calls` dials were seen. `0` turns the rate rule off. At most 100. |
| `rate_min_calls` | `20` | Dials in the window before the rate rule applies. |
| `rate_window_ms` | `60000` | Length of the rolling window of the rate rule. |
| `open_duration_ms` | `30000` | How long the breaker stays open the first time it trips. |
| `open_backoff_factor` | `2.0` | Each trip without a close in between multiplies the open period by this. At least 1.0. |
| `max_open_duration_ms` | `300000` | Upper bound of the open period. Not below `open_duration_ms`. |
| `half_open_max_probes` | `1` | Probe dials allowed at the same time while half-open. |
| `success_threshold` | `2` | Successful probes that close a half-open breaker. |
| `max_targets` | `10000` | Most targets tracked at once. |
| `idle_ttl_ms` | `900000` | A target idle this long is forgotten and starts closed again. Not below `max_open_duration_ms`. |

### `[health]` (session proxy)

Readiness checks behind `GET /health/ready`; see [session-proxy.md](session-proxy.md#health-and-readiness). Environment variables are `PROXYX_INTERCEPT_HEALTH__<KEY>`.

| Key | Default | Meaning |
|---|---|---|
| `check_interval_ms` | `2000` | Period of the Redis ping and of the capture pipeline sample. |
| `redis_timeout_ms` | `1000` | Time one Redis `PING` may take. |
| `redis_failure_threshold` | `3` | Consecutive failed pings that make the `redis` check fail. |
| `capture_stall_fraction` | `0.9` | The capture queue counts as full at this share of `request_log.channel_capacity`. In (0, 1]. |
| `capture_stall_window_ms` | `30000` | How long the queue has to stay full before `capture_pipeline` fails. |
| `capture_publish_stale_ms` | `60000` | Captures are queued or in flight but nothing was published for this long: `capture_pipeline` fails. |
| `drain_notice_ms` | `0` | Pause between going not-ready and closing the listeners on shutdown. |
