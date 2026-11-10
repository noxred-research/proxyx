# ProxyX limiter metrics

The rate-limit service (`proxyx limiter`) serves these on an optional plain-HTTP port: set `PROXYX_LIMITER_METRICS_ADDR` (for example `127.0.0.1:39092`). The port is off by default, because the data protocol on the limiter address has no HTTP. The same port serves `GET /healthz` (always `200` while the process runs) and `GET /readyz` (`503 bucket slab full` when no slot is left, otherwise `200`).

The families are hand-rendered in `crates/limiter-server/src/http.rs`, not registered in the shared registry, and carry no `service` label: add one in your scrape config. Labels use closed sets only.

Client-side signals (timeouts, circuit breaker, fail-open) are on the session proxy, see [session-proxy.md](session-proxy.md).

### `proxyx_limiter_buckets`
- **Type:** gauge
- **Labels:** none
- **Source:** state, `Registry::used` at scrape time
- **Meaning:** Token buckets currently allocated in the slab: one per org with live traffic. Buckets free themselves after their TTL of idleness.
- **Query:** `proxyx_limiter_buckets / proxyx_limiter_buckets_capacity`

### `proxyx_limiter_buckets_capacity`
- **Type:** gauge
- **Labels:** none
- **Source:** state, `PROXYX_LIMITER_MAX_BUCKETS` rounded up to a power of two
- **Meaning:** Size of the slab. When `proxyx_limiter_buckets` reaches it, new orgs cannot be created, and the session proxy applies its fail policy to them.
- **Query:** `proxyx_limiter_buckets_capacity`

### `proxyx_limiter_connections`
- **Type:** gauge
- **Labels:** none
- **Source:** state, accept loop
- **Meaning:** Open client connections. The service runs one thread per connection and drops connections above `PROXYX_LIMITER_MAX_CONNECTIONS`.
- **Query:** `proxyx_limiter_connections`

### `proxyx_limiter_connections_refused_total`
- **Type:** counter
- **Labels:** none
- **Source:** event, accept loop
- **Meaning:** Connections accepted and closed at once because the connection cap was reached. Raise `PROXYX_LIMITER_MAX_CONNECTIONS` when it grows: each session proxy replica keeps up to 16 pooled connections.
- **Query:** `rate(proxyx_limiter_connections_refused_total[5m])`

### `proxyx_limiter_requests_total`
- **Type:** counter
- **Labels:** `op` (create, consume, drain, snapshot, ping)
- **Source:** event, `crates/limiter-server/src/conn.rs` dispatch
- **Meaning:** Records handled, not frames: a frame batches up to 4096 records of one op. `consume` is the hot path, one per proxied exchange of an org that uses the limiter backend.
- **Query:** `sum by (op) (rate(proxyx_limiter_requests_total[5m]))`

### `proxyx_limiter_consume_denied_total`
- **Type:** counter
- **Labels:** none
- **Source:** event, `consume` records answered not allowed
- **Meaning:** Consume records that found too few tokens. This is rate limiting working as designed, not an error. The session proxy retries within `rate_limit_max_wait_ms` before it answers `429`.
- **Query:** `rate(proxyx_limiter_consume_denied_total[5m]) / rate(proxyx_limiter_requests_total{op="consume"}[5m])`

### `proxyx_limiter_create_rejected_total`
- **Type:** counter
- **Labels:** `reason` (full)
- **Source:** event, `create` records
- **Meaning:** Create records refused because the slab was full. Any increase means orgs are running without a limit or are denied, by the session proxy's fail policy.
- **Query:** `increase(proxyx_limiter_create_rejected_total[5m])`

### `proxyx_limiter_connection_errors_total`
- **Type:** counter
- **Labels:** none
- **Source:** event, end of a connection thread
- **Meaning:** Connections that ended on an I/O error or a protocol violation (bad frame, unknown op) rather than a clean close. A reset by a restarting client counts here too.
- **Query:** `rate(proxyx_limiter_connection_errors_total[5m])`

### `proxyx_limiter_uptime_seconds`
- **Type:** gauge
- **Labels:** none
- **Source:** state, monotonic clock since start
- **Meaning:** Seconds since the process started. A drop to zero is a restart, which also reset every bucket: each org starts with a full bucket again.
- **Query:** `resets(proxyx_limiter_uptime_seconds[1h])`
