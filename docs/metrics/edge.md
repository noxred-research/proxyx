# ProxyX edge metrics

All families are defined in `crates/edge/src/metrics.rs` (`Metrics::new()`, one instance per process). `proxyx edge` serves them on `/metrics` of `server.ops_listen` as `text/plain; version=0.0.4; charset=utf-8`; the same listener answers `/healthz` (always `ok` while the process runs) and `/readyz` (`503` once the process is shutting down). Without `server.ops_listen` nothing is served. Every series carries the constant label `service="proxyx-edge"`. Names follow `proxyx_edge_<noun>_<unit>`. Labels are closed sets: configured listener, pool and parent names and fixed words. Client addresses, users, hosts, session ids and egress addresses are never labels; the access log carries them. A test (`metrics_md_matches_the_registry_and_forbids_identity_labels`) keeps this file and the registry equal, names and labels.

## Connections and requests

### `proxyx_edge_connections_total`
- **Type:** counter
- **Labels:** `listener`, `outcome` (accepted, over_limit, proxy_protocol_error, tls_error)
- **Source:** event, `crates/edge/src/server.rs`, once per accepted TCP connection
- **Meaning:** Client connections by listener and outcome. `over_limit` is a connection closed at accept because `server.max_connections`, the listener's `max_connections` or `server.max_connections_per_src` is reached; `proxy_protocol_error` is a missing, invalid or untrusted required PROXY header. `tls_error` is a failed or timed-out listener TLS handshake; no proxy credentials are accepted on that transport.
- **Query:** `sum by (listener, outcome) (rate(proxyx_edge_connections_total{outcome!="accepted"}[5m]))`

### `proxyx_edge_connections_open`
- **Type:** gauge
- **Labels:** `listener`
- **Source:** state, `crates/edge/src/server.rs`
- **Meaning:** Client connections being served now (a keep-alive HTTP connection counts while it is open, a tunnel while it relays).
- **Query:** `sum by (listener) (proxyx_edge_connections_open)`

### `proxyx_edge_requests_total`
- **Type:** counter
- **Labels:** `listener`, `protocol` (http, connect, socks4, socks5, udp), `result` (ok, auth_required, denied, bad_request, dns_error, connect_error, parent_error, timeout, limited, internal)
- **Source:** event, `crates/edge/src/conn.rs` (`Shared::log`), once per request when it ends: an HTTP request, a CONNECT, a SOCKS command, a UDP association. A tunnel counts when it closes.
- **Meaning:** Requests by listener, protocol and result. `denied` is an access rule, the destination denial or a login option the user may not use; `auth_required` is a missing or wrong proxy login; `limited` is a connection or rate limit; `dns_error`, `connect_error`, `timeout` and `parent_error` say where reaching the target failed.
- **Query:** `sum by (result) (rate(proxyx_edge_requests_total{result!="ok"}[5m]))`

### `proxyx_edge_bytes_total`
- **Type:** counter
- **Labels:** `listener`, `direction` (up, down)
- **Source:** event, `crates/edge/src/conn.rs` (`Shared::log`), added when a request ends
- **Meaning:** Payload bytes passed. `up` is client to target, `down` target to client. For HTTP the count is the message bodies (chunk framing included for chunked bodies), for tunnels every byte relayed.
- **Query:** `sum by (listener, direction) (rate(proxyx_edge_bytes_total[5m]))`

## Authentication, rules and limits

### `proxyx_edge_auth_failures_total`
- **Type:** counter
- **Labels:** `listener`, `reason` (missing, invalid, blocked, option_denied, listener_denied)
- **Source:** event, `crates/edge/src/conn.rs` (`authenticate`)
- **Meaning:** Logins that did not pass. `missing` is a client that has not sent credentials yet (a normal first step for most HTTP clients); `invalid` an unknown user or a wrong password (the two are not told apart); `blocked` a source past `auth.fail_limit` failures in `auth.fail_window`; `option_denied` a login option (`-pool-`, `-ip-`) the user may not use; `listener_denied` a user that may not log in on this listener.
- **Query:** `sum by (listener, reason) (rate(proxyx_edge_auth_failures_total{reason!="missing"}[5m]))`

### `proxyx_edge_acl_decisions_total`
- **Type:** counter
- **Labels:** `action` (allow, deny)
- **Source:** event, `crates/edge/src/conn.rs` (`check`, lifecycle and command-stage checks)
- **Meaning:** Access-rule decisions across normal requests and every configured pre-negotiation, post-authentication, BIND and UDP stage. One request may contribute several decisions. An absent optional stage contributes none; `deny` includes a configured stage's default deny when no rule matches.
- **Query:** `rate(proxyx_edge_acl_decisions_total{action="deny"}[5m])`

### `proxyx_edge_destination_denied_total`
- **Type:** counter
- **Labels:** none
- **Source:** event, `crates/edge/src/conn.rs` (`check`)
- **Meaning:** Requests refused with `403 destination_denied`: the target is a private, loopback, link-local, metadata or internal name, or resolves to such an address, and the deciding rule has no `allow_internal = true`.
- **Query:** `rate(proxyx_edge_destination_denied_total[5m])`

### `proxyx_edge_limit_rejections_total`
- **Type:** counter
- **Labels:** `kind` (global, listener, per_src, user, limit_connections, limit_rate)
- **Source:** event, `crates/edge/src/server.rs` and `crates/edge/src/conn.rs`
- **Meaning:** Connections or requests refused by a limit: `global` (`server.max_connections`), `listener` (the listener's `max_connections`), `per_src` (`server.max_connections_per_src`), `user` (the user's `max_connections`), `limit_connections` and `limit_rate` (a `[[limit]]` rule).
- **Query:** `sum by (kind) (rate(proxyx_edge_limit_rejections_total[5m]))`

## Egress, parents and DNS

### `proxyx_edge_egress_connections_total`
- **Type:** counter
- **Labels:** `pool` (a configured pool, the generated pool of an egress rule with a fixed address, or none when the operating system picked the source address), `outcome` (ok, failed, no_address, unavailable)
- **Source:** event, `crates/edge/src/connect.rs`, once per connect to a target or parent
- **Meaning:** Connection attempts by egress pool. `no_address` means the pool has no address of the destination's IP family (an IPv6 destination with an IPv4-only pool) or the login asked for an address (`-ip-<n>`) that does not exist; `unavailable` means every address of the family is out of service (breaker open or failed active check).
- **Query:** `sum by (pool, outcome) (rate(proxyx_edge_egress_connections_total[5m]))`

### `proxyx_edge_connect_duration_seconds`
- **Type:** histogram (buckets 5 ms to 10 s)
- **Labels:** `pool`
- **Source:** event, `crates/edge/src/connect.rs`, for successful connects only
- **Meaning:** Time from the start of the connect (including parent selection, TCP connect and a parent handshake) to an open stream.
- **Query:** `histogram_quantile(0.95, sum by (le, pool) (rate(proxyx_edge_connect_duration_seconds_bucket[5m])))`

### `proxyx_edge_egress_addresses`
- **Type:** gauge
- **Labels:** `pool`, `state` (total, open, half_open, unhealthy, prefixes)
- **Source:** state, read at scrape time from the running configuration
- **Meaning:** Addresses of each pool: `total` (the explicitly listed or discovered ones), `open` (shut out by the circuit breaker after connects from them failed), `half_open` (the breaker lets probe connections through), `unhealthy` (failed the active check: no longer assigned to an interface or not bindable), and `prefixes` (the number of routed networks addresses are drawn from). A pool whose addresses are all `open` or `unhealthy` answers `503 egress_unavailable`.
- **Query:** `proxyx_edge_egress_addresses{state=~"open|unhealthy"} > 0`

### `proxyx_edge_parent_requests_total`
- **Type:** counter
- **Labels:** `parent`, `outcome` (ok, failed)
- **Source:** event, `crates/edge/src/connect.rs`
- **Meaning:** Connections made through each parent proxy and whether the connect and handshake worked. Failed attempts move to the next path within `selector.connect_retries` and `selector.forward_timeout` and count towards the parent's existing circuit breaker. Node `max_fails`/`fail_timeout` override that breaker's settings; local egress failures do not count against a parent. A successful first hop alone does not prove a complete chain is healthy.
- **Query:** `sum by (parent, outcome) (rate(proxyx_edge_parent_requests_total[5m]))`

### `proxyx_edge_parent_up`
- **Type:** gauge
- **Labels:** `parent`
- **Source:** state, read at scrape time
- **Meaning:** 1 while the parent can take requests, 0 while it is out of use: its circuit breaker is open (and its `open_duration` has not passed) or it fails its active health probes.
- **Query:** `proxyx_edge_parent_up == 0`

### `proxyx_edge_dns_lookups_total`
- **Type:** counter
- **Labels:** `result` (ok, error)
- **Source:** event, `crates/edge/src/conn.rs` and `crates/edge/src/connect.rs`
- **Meaning:** Name resolutions for targets and parents. IP literals are not counted; answers from the cache and from `dns.hosts` count as ok.
- **Query:** `rate(proxyx_edge_dns_lookups_total{result="error"}[5m])`

## Circuit breakers, health checks and connection reuse

### `proxyx_edge_breaker_transitions_total`
- **Type:** counter
- **Labels:** `kind` (parent, egress), `state` (closed, half_open, open)
- **Source:** event, `crates/edge/src/breaker.rs`, when a breaker enters a state
- **Meaning:** Circuit breaker transitions, summed over every breaker of the kind (one per parent, one per explicitly listed egress address). `open` is entered after `failure_threshold` failures in a row (`[breaker.parent]`, `[breaker.egress]`) or after a failed half-open probe; `half_open` when the first request is let through after `open_duration`; `closed` after `success_threshold` good probe results. The counters live in the registry, so they survive a configuration reload.
- **Query:** `sum by (kind) (increase(proxyx_edge_breaker_transitions_total{state="open"}[15m]))`

### `proxyx_edge_parent_breaker_state`
- **Type:** gauge
- **Labels:** `parent`
- **Source:** state, read at scrape time
- **Meaning:** Breaker of each parent: 0 closed, 1 half open (probes may pass, or `open_duration` has passed since it opened), 2 open.
- **Query:** `proxyx_edge_parent_breaker_state == 2`

### `proxyx_edge_parent_healthy`
- **Type:** gauge
- **Labels:** `parent`
- **Source:** state, read at scrape time
- **Meaning:** 1 while the parent passes its active health probes (`[health]`): `unhealthy_threshold` failed probes in a row set it to 0, `healthy_threshold` good ones back to 1. Independent of the breaker; a parent is used only while both are good (`proxyx_edge_parent_up`).
- **Query:** `proxyx_edge_parent_healthy == 0`

### `proxyx_edge_health_checks_total`
- **Type:** counter
- **Labels:** `kind` (parent, egress, chain), `result` (ok, failed)
- **Source:** event, `crates/edge/src/health.rs`, every `health.interval`
- **Meaning:** Active probes. Parent probes use configured TCP, HTTP status/body or operator command checks, or the legacy TCP/CONNECT probe. Chain probes traverse every selected hop to a representative target. Egress checks verify listed addresses and routed prefixes remain assigned and bindable. Probe duration feeds latency selection; unmeasured nodes do not acquire fictitious zero latency.
- **Query:** `sum by (kind) (rate(proxyx_edge_health_checks_total{result="failed"}[5m]))`

### `proxyx_edge_parent_conn_reuse_total`
- **Type:** counter
- **Labels:** `outcome` (reused, new)
- **Source:** event, `crates/edge/src/connect.rs`
- **Meaning:** Plain HTTP requests without a body that go to an HTTP parent: `reused` took an idle keep-alive connection to the parent, `new` opened one. Requests with a body, tunnels and SOCKS parents never reuse. Switch reuse off with `http.parent_keepalive = false`.
- **Query:** `rate(proxyx_edge_parent_conn_reuse_total{outcome="reused"}[5m]) / ignoring(outcome) sum(rate(proxyx_edge_parent_conn_reuse_total[5m]))`

## Operations

### `proxyx_edge_config_reloads_total`
- **Type:** counter
- **Labels:** `result` (ok, failed)
- **Source:** event, `crates/edge/src/server.rs` (`Server::reload`), one per SIGHUP
- **Meaning:** Configuration reloads. A failed reload keeps the running configuration and logs the reason.
- **Query:** `increase(proxyx_edge_config_reloads_total{result="failed"}[15m]) > 0`

### `proxyx_edge_access_log_dropped_total`
- **Type:** counter
- **Labels:** none
- **Source:** state, copied from the access log writer at scrape time
- **Meaning:** Access log lines dropped because the writer thread fell behind (the log disk is slow) or failed to write. A request never waits for the log.
- **Query:** `rate(proxyx_edge_access_log_dropped_total[5m]) > 0`

### `proxyx_edge_udp_associations_open`
- **Type:** gauge
- **Labels:** `listener`
- **Source:** state, `crates/edge/src/udp.rs`
- **Meaning:** SOCKS5 UDP associations open now.
- **Query:** `sum by (listener) (proxyx_edge_udp_associations_open)`

## Runtime statistics

`GET /stats` shares the ops listener but does not create Prometheus families or client-identity
labels. JSON contains `listeners`, `pools` and `nodes` arrays, including configured zero-traffic
entries. Each row has `kind`, `name`, `pool`, `state`, `active`, `total_connections`, `failures`
and `latency_seconds`. Request `?format=csv` or `Accept: text/csv` for CSV; explicit format wins,
and an unknown format returns `400`. CSV uses the same columns, CRLF records and quoted-field escaping.

Node states are `up`, `half_open`, `open` or `unhealthy`; listener states include `unbound` and
`stopping`, and pools report `up`/`down`. Listener failure counts combine rejected connections
and failed requests. Pool aggregates reuse existing metrics; node activity comes from runtime
counters. Unknown latency is JSON `null` or an empty CSV cell, not zero. Listener latency is
not measured. Snapshots are observational, not an atomic transaction across counters.
Addresses drawn from a routed prefix are not individually listed.

The endpoint exposes configured node identities and local addresses. Bind the ops listener
to loopback or a protected management network; it is not a public dashboard or authenticated API.
