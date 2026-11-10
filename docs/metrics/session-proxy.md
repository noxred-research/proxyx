# ProxyX session proxy and control plane metrics

All metrics are defined in `crates/session-common/src/metrics.rs` on one process-wide registry. Each process serves them at `/metrics`: the session proxy (`proxyx-intercept`) on its HTTP address, the control API (`proxyx control api`) on its HTTP port, and the ingester (`proxyx control ingester`) on its health server (port 9001 by default). Every series carries a `service` label from `SERVICE_NAME`. If a scrape target supplies a conflicting `service` label and `honorLabels` is false, Prometheus preserves the metric's value as `exported_service`.

Labels use closed sets only, so they never carry hosts, URLs, ids, or raw paths.

## Proxy

### `proxyx_intercept_connections_total`
- **Type:** counter
- **Labels:** `outcome` (ok, rejected, backend_unavailable, upstream_error, upstream_timeout, upstream_unavailable, error), `listener` (connect, http, socks5)
- **Source:** event, `crates/intercept/src/listener/{connect,http,socks}.rs` accept loops
- **Meaning:** One per client connection when its handler finishes. `error` means the handler returned an error, including a broken SOCKS5 handshake. The other non-`ok` values mean the proxy sent the client an error reply: `rejected` for a failed authentication, a missing session, or a routing denial; `backend_unavailable` when the session backend failed or timed out; `upstream_error` when the upstream connect failed; `upstream_timeout` when it hit the connect timeout (`network.upstream_connect_timeout_ms`, 10 s); `upstream_unavailable` when the target's circuit breaker was open and the dial failed fast. The `socks5` listener always replies SOCKS `0x00` and sends these errors in band, as an HTTP response with an `X-ProxyX-Error` header to the client's first request. Upstream connect failures that happen before any request is read are counted only here.
- **Query:** `sum by (outcome) (rate(proxyx_intercept_connections_total[5m]))`

### `proxyx_intercept_requests_total`
- **Type:** counter
- **Labels:** `protocol` (http, https, websocket), `status_class` (1xx, 2xx, 3xx, 4xx, 5xx, error)
- **Source:** event, `crates/intercept/src/mitm/mod.rs` `UpstreamRequest`, used in `proxy_http_keepalive`, `proxy_h1_to_h2`, and `run_h1_fallback_ws_upgrade`
- **Meaning:** One per request the MITM path forwards upstream. `status_class` comes from the upstream response status. `error` means no usable response headers arrived because of an I/O error, a timeout, a malformed response, or a failed fallback dial. A WebSocket upgrade counts once as `websocket`. A successful upgrade is `1xx` (101, including H2 Extended CONNECT 200), and a rejected one carries the upstream status. `protocol` is the client-facing scheme. Not counted: raw `copy_bidirectional` tunnels (see `connections_total`), and requests the proxy answers itself without forwarding them, such as a 429 rate limit or a 400/500/502 before the upstream send.
- **Query:** `sum by (status_class) (rate(proxyx_intercept_requests_total[5m]))`

### `proxyx_intercept_upstream_duration_seconds`
- **Type:** histogram (0.01 to 30 s, 11 buckets)
- **Labels:** `protocol` (http, https, websocket)
- **Source:** event, `crates/intercept/src/mitm/mod.rs` `UpstreamRequest::response`
- **Meaning:** Time from starting to forward a request upstream (headers plus request body) until the upstream response headers arrive. For HTTP/2 it includes waiting for a stream slot. For the H1 WebSocket fallback it excludes the dial. Only requests that got a response are observed; `error` requests are not.
- **Query:** `histogram_quantile(0.95, sum by (le, protocol) (rate(proxyx_intercept_upstream_duration_seconds_bucket[5m])))`

### `proxyx_intercept_capture_buffer_depth`
- **Type:** gauge
- **Labels:** none
- **Source:** state, `crates/intercept/src/pipeline.rs` `RequestLogWriter::send`/`send_ws` (after enqueue) and `drain_task` (after dequeue)
- **Meaning:** Number of captures (HTTP exchanges and WS messages) waiting in the request log writer channel ahead of `publish_with_retry`. When it sits near the channel capacity (`channel_capacity`, default 256), the broker is slow and MITM connections are being backpressured. Per-connection exchange channels are not included.
- **Query:** `max(proxyx_intercept_capture_buffer_depth)`
- **Stall log:** `capture batch publish stalled` fires once per publish attempt after 5 seconds. `source_ids` lists distinct crawl/scan IDs in the in-flight batch; `records`, `max_record_attempt`, and `capture_buffer_depth` show its size, highest per-record attempt number, and queued work. Publishing continues after the warning. The gauge excludes the in-flight batch.
- **Break:** A full buffer with no published captures blocks proxied traffic even while the session proxy reports healthy; stop starting new crawls and scans until publishing recovers.

### `proxyx_intercept_overhead_seconds`
- **Type:** histogram (0.001 to 10 s, 12 buckets)
- **Labels:** `protocol` (http, https, websocket; same as `requests_total`), `phase` (request, response, lock_wait, ratelimit_wait, capture_wait)
- **Source:** event, `crates/intercept/src/mitm/mod.rs` `observe_overhead`, called from `proxy_http_keepalive`, `proxy_h1_to_h2`, and `run_h1_fallback_ws_upgrade`, and from `crates/intercept/src/mitm/websocket.rs` `acquire_rate_limit`
- **Meaning:** Time the proxy itself adds to one MITM exchange. Body streaming is never included.
  - `request`: from reading the client request headers to starting to forward the request upstream. Excludes the serial-lock wait and the rate-limit wait (both have their own phase). On HTTP/2 it also excludes reading the buffered request body, and for an Extended CONNECT it excludes the SETTINGS ping.
  - `response`: from receiving the upstream response headers to writing them to the client. For an HTTP/2 WebSocket upgrade it runs until the translated 101 has been flushed.
  - `lock_wait`: time spent acquiring the per-session serial lock. Observed only for sessions that use the lock.
  - `ratelimit_wait`: time spent waiting for a per-session rate-limit token, a deliberate policy delay bounded by `rate_limit_max_wait_ms`. Observed only for sessions with a rate limit, including the wait before a 429. For WebSockets it is per client-to-server message (`protocol=websocket`).
  - `capture_wait`: time `exchange_tx.send` blocks on the per-connection capture channel, which is backpressure from the publisher.

  | Path | request | response | lock_wait | ratelimit_wait | capture_wait |
  |---|---|---|---|---|---|
  | `proxy_http_keepalive` (H1 upstream and plaintext, including H1 WS upgrade) | yes | yes | yes | yes | yes |
  | `proxy_h1_to_h2` (H2 upstream) | yes | yes | yes | yes | yes |
  | `proxy_h1_to_h2` Extended CONNECT (WS over H2) | yes | yes | yes | no: the upgrade request is not rate-limited | yes |
  | `run_h1_fallback_ws_upgrade` (WS over a fresh H1 dial) | no: spans the SETTINGS ping and the new dial | yes | no: recorded by the H2 loop before falling back | no | yes |
  | `websocket::proxy_websocket` (messages after an upgrade) | no | no | no | yes, per client-to-server message | no |

  Requests the proxy answers itself (429, or the 502 for an unsupported or uncapturable upgrade) record no `response` phase.
- **Query:** `histogram_quantile(0.99, sum by (le, phase) (rate(proxyx_intercept_overhead_seconds_bucket[5m])))`

### `proxyx_intercept_tls_handshake_seconds`
- **Type:** histogram (0.005 to 10 s, 11 buckets)
- **Labels:** `side` (client, upstream)
- **Source:** event, `crates/intercept/src/mitm/mod.rs` `MitmHandler::intercept` (client accept, upstream connect) and its H1 fallback dialer (upstream)
- **Meaning:** Duration of MITM TLS handshakes. `client` is the proxy accepting TLS from the client using a minted certificate. `upstream` is the proxy's BoringSSL connect to the origin. Only successful handshakes are observed; failures show up as `error` in `connections_total` or `requests_total`. Raw tunnels and plain-HTTP upstreams do no TLS handshake here.
- **Query:** `histogram_quantile(0.95, sum by (le, side) (rate(proxyx_intercept_tls_handshake_seconds_bucket[5m])))`

### `proxyx_intercept_captures_published_total`
- **Type:** counter
- **Labels:** none
- **Source:** event, `crates/intercept/src/pipeline.rs` `publish_with_retry`
- **Meaning:** Captures that were published to the broker.
- **Query:** `rate(proxyx_intercept_captures_published_total[5m])`

### `proxyx_intercept_captures_dropped_total`
- **Type:** counter
- **Labels:** none
- **Source:** event, `crates/intercept/src/pipeline.rs` `publish_with_retry`
- **Meaning:** Captures that were lost after every publish attempt failed. Any increase means captured data was lost.
- **Query:** `increase(proxyx_intercept_captures_dropped_total[15m]) > 0`

### `proxyx_intercept_upstream_breaker_state`
- **Type:** gauge
- **Labels:** `target_kind` (egress_proxy, private_override, origin)
- **Source:** state, `crates/intercept/src/breaker.rs`, updated on every breaker transition and when a breaker leaves the table
- **Meaning:** The worst circuit breaker state among the tracked targets of that kind: 0 when all are closed, 1 when at least one is open, 2 when none is open but at least one is half-open. Targets are the egress proxy address, a session's private override target, and the origin `host:port`. A breaker that was evicted for idleness no longer counts. The series are 0 from startup. With `breaker.enabled = false` they stay 0.
- **Query:** `max by (target_kind) (proxyx_intercept_upstream_breaker_state == 1)`

### `proxyx_intercept_upstream_breaker_transitions_total`
- **Type:** counter
- **Labels:** `target_kind` (egress_proxy, private_override, origin), `to` (open, half_open, closed)
- **Source:** event, `crates/intercept/src/breaker.rs`
- **Meaning:** Breaker state changes, labelled with the state entered. A breaker that trips and recovers counts `open`, `half_open`, `closed` once each; a failed probe counts `open` again. Many `open` transitions with few `closed` ones mean targets that keep failing their probes.
- **Query:** `sum by (target_kind, to) (increase(proxyx_intercept_upstream_breaker_transitions_total[15m]))`

### `proxyx_intercept_upstream_breaker_rejected_total`
- **Type:** counter
- **Labels:** `target_kind` (egress_proxy, private_override, origin)
- **Source:** event, `crates/intercept/src/breaker.rs` `UpstreamBreakers::acquire`
- **Meaning:** Dials refused without connecting because the target's breaker was open, or half-open with every probe slot taken. Each one is answered to the client as `upstream_unavailable` (see `connections_total`). Dials that failed for real are in `connections_total` as `upstream_error` or `upstream_timeout`, not here.
- **Query:** `sum by (target_kind) (rate(proxyx_intercept_upstream_breaker_rejected_total[5m]))`

### `proxyx_intercept_ready`
- **Type:** gauge
- **Labels:** none
- **Source:** state, `crates/intercept/src/health.rs` `Readiness::report`
- **Meaning:** 1 while `/health/ready` answers 200, 0 while it answers 503. It is 0 before the three listeners are bound, while any readiness check fails, and from the shutdown signal on.
- **Query:** `min(proxyx_intercept_ready) == 0`

### `proxyx_intercept_readiness_check`
- **Type:** gauge
- **Labels:** `check` (redis, capture_pipeline, listeners)
- **Source:** state, `crates/intercept/src/health.rs`
- **Meaning:** Result of one readiness check: 1 passing, 0 failing. `redis`: the periodic `PING` failed `health.redis_failure_threshold` times in a row. `capture_pipeline`: the capture queue stayed above `health.capture_stall_fraction` of its capacity for longer than `health.capture_stall_window_ms`, or nothing was published for `health.capture_publish_stale_ms` while captures were queued or in flight. `listeners`: an accept loop is not bound or has exited.
- **Query:** `min by (check) (proxyx_intercept_readiness_check) == 0`

### `proxyx_intercept_draining`
- **Type:** gauge
- **Labels:** none
- **Source:** state, `crates/intercept/src/health.rs` `Readiness::set_draining`
- **Meaning:** 1 from the moment the proxy receives the shutdown signal until the process exits. The admin port keeps serving `/metrics` and `/health/live` during the drain, so this series is visible while connections wind down.
- **Query:** `max(proxyx_intercept_draining) == 1`

### `proxyx_intercept_connections_active`
- **Type:** gauge
- **Labels:** none
- **Source:** state, `crates/intercept/src/context.rs` `ProxyContext::admit` and the drop of its `ConnSlot`
- **Meaning:** Client connections that hold a connection slot: accepted on any listener and not yet finished. It is capped by `tuning.max_connections`.
- **Query:** `max(proxyx_intercept_connections_active) / <tuning.max_connections>`

### `proxyx_intercept_connection_limit_refusals_total`
- **Type:** counter
- **Labels:** none
- **Source:** event, `crates/intercept/src/context.rs` `ProxyContext::admit`
- **Meaning:** Client connections closed right after accept because `tuning.max_connections` slots were taken. The proxy never queues them: the CONNECT and HTTP listeners try to send a `503` with `X-ProxyX-Error: connection_limit`, the SOCKS5 listener just closes. Any sustained rate means the limit is too low for the load or connections are leaking.
- **Query:** `rate(proxyx_intercept_connection_limit_refusals_total[5m]) > 0`

### `proxyx_intercept_ratelimit_backend_errors_total`
- **Type:** counter
- **Labels:** `backend` (redis, limiter)
- **Source:** event, `crates/intercept/src/ratelimit.rs`
- **Meaning:** Calls to the rate-limit backend that failed. `redis`: a token refill failed after its retry. `limiter`: a bucket create failed, or a consume got no answer from the limiter (timeout, connection error, or the limiter client's own breaker being open). Whether the request is let through depends on `ratelimit.failopen_policy`; see `ratelimit_failopen_total`.
- **Query:** `sum by (backend) (rate(proxyx_intercept_ratelimit_backend_errors_total[5m]))`

### `proxyx_intercept_ratelimit_failopen_total`
- **Type:** counter
- **Labels:** `backend` (redis, limiter)
- **Source:** event, `crates/intercept/src/ratelimit.rs`
- **Meaning:** Requests admitted without a rate-limit verdict because the backend failed and `ratelimit.failopen_policy` is `grant_tokens` (the default). With the `redis` backend an org's local bucket stays fail-open after its first error, and every request it admits counts here. Traffic is then unlimited for that org on this proxy.
- **Query:** `sum by (backend) (rate(proxyx_intercept_ratelimit_failopen_total[5m])) > 0`

## Ingester

### `proxyx_ingester_messages_total`
- **Type:** counter
- **Labels:** `outcome` (ok, error)
- **Source:** event, `crates/control/src/consumer.rs`
- **Meaning:** Messages consumed from the captures log. `error` means the protobuf envelope failed to decode; such a message is acked and skipped.
- **Query:** `sum by (outcome) (rate(proxyx_ingester_messages_total[5m]))`

### `proxyx_ingester_flush_duration_seconds`
- **Type:** histogram (0.005 to 30 s, 12 buckets)
- **Labels:** `table` (http_captures, ws_messages), `outcome` (ok, error)
- **Source:** event, `crates/control/src/pipeline/batch_handler.rs` `Flusher::try_flush`
- **Meaning:** Duration of one capture store batch write (a ClickHouse insert, or all the `_bulk` requests of a flush including in-place retries). `error` means the write failed for some rows and they were requeued. Flushes skipped while the circuit is open, and empty flushes, are not observed.
- **Query:** `sum by (table, outcome) (rate(proxyx_ingester_flush_duration_seconds_count[5m]))`

### `proxyx_ingester_rows_dropped_total`
- **Type:** counter
- **Labels:** `table` (http_captures, ws_messages)
- **Source:** event, `crates/control/src/pipeline/batch_handler.rs` `Flusher::try_flush`
- **Meaning:** Rows dropped from a batch because writing that row failed. They are acked and lost by policy, not retried, so any non-zero rate means captures are being lost.
- **Query:** `sum by (table) (rate(proxyx_ingester_rows_dropped_total[5m]))`

### `proxyx_ingester_store_retries_total`
- **Type:** counter
- **Labels:** `table` (http_captures, ws_messages)
- **Source:** event, `crates/control/src/capture_store/opensearch/sink.rs` `BulkWriter::write`
- **Meaning:** In-place retries of an OpenSearch / Elasticsearch `_bulk` request after a transient failure (connection error, timeout, HTTP `429` or `5xx`, or items answered `429`/`5xx`). One count is one retry round of one request. Always 0 with the ClickHouse store, which retries only through the flush loop. A rising rate with a flat flush error rate means the cluster is shedding load but recovering within the retry budget; when the budget runs out, the flush fails and counts toward the circuit breaker.
- **Query:** `sum by (table) (rate(proxyx_ingester_store_retries_total[5m]))`

### `proxyx_ingester_circuit_open`
- **Type:** gauge (0 or 1)
- **Labels:** `table` (http_captures, ws_messages)
- **Source:** state, `crates/control/src/pipeline/batch_handler.rs`: `Flusher::open_circuit` sets 1, `Flusher::record_success` sets 0, and `BatchHandler::new` initializes 0
- **Meaning:** 1 once consecutive flush failures open the circuit breaker. It stays 1 until the next successful flush, which means it also covers the half-open retry after the reset window, while no writes reach the capture store.
- **Query:** `max by (table) (proxyx_ingester_circuit_open) == 1`

### `proxyx_broker_publish_records_total`
- **Type:** counter
- **Labels:** `broker` (redis_stream, kafka, rabbitmq), `outcome` (published, failed, not_sent)
- **Source:** event, `crates/session-common/src/log/instrument.rs`; emitted by every process that publishes to the captures log (session proxy, control API)
- **Meaning:** Records handed to the broker, per outcome. `failed` consumes a retry attempt of the proxy's writer, `not_sent` does not (a record blocked behind a failed one of the same key). Kafka counts a record `published` when its produce request was acknowledged by all in-sync replicas, RabbitMQ when its publisher confirm arrived.
- **Query:** `sum by (broker, outcome) (rate(proxyx_broker_publish_records_total[5m]))`

### `proxyx_broker_publish_duration_seconds`
- **Type:** histogram (0.001 to 5 s, 12 buckets)
- **Labels:** `broker`
- **Source:** event, `crates/session-common/src/log/instrument.rs`
- **Meaning:** Duration of one batch publish call: all records of a drain round up to the last confirm.
- **Query:** `histogram_quantile(0.99, sum by (le, broker) (rate(proxyx_broker_publish_duration_seconds_bucket[5m])))`

### `proxyx_broker_consumed_total`
- **Type:** counter
- **Labels:** `broker`
- **Source:** event, `crates/session-common/src/log/instrument.rs`; emitted by the ingester
- **Meaning:** Messages received from the captures log, before they are decoded. A redelivery counts again.
- **Query:** `sum by (broker) (rate(proxyx_broker_consumed_total[5m]))`

### `proxyx_broker_acks_total`
- **Type:** counter
- **Labels:** `broker`, `outcome` (ok, error, rejected)
- **Source:** event, `crates/session-common/src/log/instrument.rs`
- **Meaning:** Acknowledgements of consumed messages, which follow the capture store's flush. `error` means the broker refused or lost the ack (a lost RabbitMQ connection, a revoked Kafka partition): the message is redelivered. `rejected` counts malformed envelopes that were dead-lettered (RabbitMQ only; the other brokers ack them as `ok`).
- **Query:** `sum by (broker, outcome) (rate(proxyx_broker_acks_total[5m]))`

### `proxyx_broker_connected`
- **Type:** gauge (0 or 1)
- **Labels:** `broker` (kafka, rabbitmq), `role` (producer, consumer)
- **Source:** state, `crates/session-common/src/log/instrument.rs` `ConnState`; set by the Kafka producer and group consumer and by the RabbitMQ producer and consumer
- **Meaning:** 1 while the connection works. The consumers also feed the ingester's `/health` with it. Kafka's consumer is assumed up at start and goes down when librdkafka reports every broker unreachable; the producers go down on a failed request and up on a successful one.
- **Query:** `min by (broker, role) (proxyx_broker_connected) == 0`

### `proxyx_broker_reconnects_total`
- **Type:** counter
- **Labels:** `broker` (kafka, rabbitmq), `role` (producer, consumer)
- **Source:** event, `crates/session-common/src/log/instrument.rs` `ConnState`
- **Meaning:** Connections that came back after a loss, counted when the state goes from down to up again; the first connect is not counted. A steady rate is a flapping broker or network.
- **Query:** `sum by (broker, role) (increase(proxyx_broker_reconnects_total[1h]))`

### `proxyx_capture_commit_lag_seconds`
- **Type:** histogram (0.1 to 600 s, 12 buckets)
- **Labels:** `table` (http_captures, ws_messages)
- **Source:** event, `crates/control/src/pipeline/batch_handler.rs` `Flusher::try_flush` (after `insert.end()` succeeds), with per-table `FlushTarget::completed_at`
- **Meaning:** End-to-end delay from a capture completing at the proxy to its row committing in ClickHouse. Observed once per committed row. HTTP rows measure from `timestamp + duration_ms`, and WS messages from `timestamp`. Negative values from clock skew are clamped to 0. Rows from a failed or requeued insert are observed only when a later insert commits them. Poison rows are never observed.
- **Query:** `histogram_quantile(0.95, sum by (le, table) (rate(proxyx_capture_commit_lag_seconds_bucket[5m])))`

## API

### `proxyx_control_api_refusals_total`
- **Type:** counter
- **Labels:** `reason` (rate_limited, over_capacity, timeout)
- **Source:** event, `crates/control/src/server/limits.rs` `enforce`
- **Meaning:** Control API requests refused by the `[http]` request limits: `rate_limited` is a credential over its token bucket (`429`), `over_capacity` is the in-flight cap (`503`), `timeout` is a request past `request_timeout_secs` (`504`). Health and metrics routes are never refused.
- **Query:** `sum by (reason) (rate(proxyx_control_api_refusals_total[5m]))`

### `proxyx_control_api_requests_total`
- **Type:** counter
- **Labels:** `route` (axum route template, e.g. `/rpc/sessions/{session_id}`, or `unmatched`), `status_class` (1xx, 2xx, 3xx, 4xx, 5xx)
- **Source:** event, `crates/control/src/server/mod.rs` `request_metrics`
- **Meaning:** API HTTP requests completed. `route` comes from `MatchedPath`, so it is a template and never a raw path. Not counted: `/metrics`, `/health`, `/health/live`, `/health/ready`, and `/rpc/health`.
- **Query:** `sum by (route) (rate(proxyx_control_api_requests_total{status_class="5xx"}[5m]))`

### `proxyx_control_api_request_duration_seconds`
- **Type:** histogram (0.001 to 10 s, 12 buckets)
- **Labels:** `route` (as above)
- **Source:** event, `crates/control/src/server/mod.rs` `request_metrics`
- **Meaning:** Wall time from the middleware receiving the request until the handler returns its response. Excludes the same probe routes as `api_requests_total`.
- **Query:** `histogram_quantile(0.95, sum by (le, route) (rate(proxyx_control_api_request_duration_seconds_bucket[5m])))`
