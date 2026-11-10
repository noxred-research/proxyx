# Monitoring

ProxyX ships Prometheus rules, a Grafana dashboard and an Alertmanager example in [`deploy/monitoring/`](../deploy/monitoring/). This page says what is scraped, how to load the files, what each alert means, and how to test them. Metric definitions are in the catalogues: [pool](metrics/pool.md), [session proxy and control plane](metrics/session-proxy.md), [limiter](metrics/limiter.md) and [edge](metrics/edge.md). Operators who get paged start at the [runbooks](runbooks/README.md).

| File | Contents |
|---|---|
| `prometheus-rules.yml` | 21 recording rules and 74 alerts, in groups per role |
| `prometheus-rules.test.yml` | `promtool` unit tests with synthetic series |
| `prometheus.example.yml` | Scrape jobs for every role, the rule file and the Alertmanager |
| `alertmanager.example.yml` | Routing by severity, inhibition, placeholder receivers |
| `grafana/proxyx-overview.json` | One dashboard with a row per role |
| `contract-metrics.txt` | Metric names the rules may use before their catalogue lists them |

## What is scraped

The rules select on the job name, so use these names (or edit the rules). Every ProxyX series also carries a `service` label set by the process; if a scrape target supplies its own `service` label and `honor_labels` is false, Prometheus keeps the metric's value as `exported_service`. The limiter's series carry no `service` label.

| Role | Job | Default port | Path | Notes |
|---|---|---|---|---|
| Pool gateway | `proxyx-gateway` | 8888 | `/metrics` | `PROXYX_POOL_OPS_LISTEN`. Scrape every replica. |
| Pool warmer | `proxyx-warmer` | 8888 | `/metrics` | Same ops port as the gateway. Partitions are owned by one warmer at a time, so scrape all of them. |
| Prober | `proxyx-prober` | 8081 | `/metrics` | Optional. Not the gateway's API port, although both default to 8081. |
| Session proxy | `proxyx-intercept` | 8888 | `/metrics` | Admin listener (`api_addr`). Unauthenticated: keep it private. |
| Control API | `proxyx-control-api` | 9000 | `/metrics` | `PROXYX_CONTROL_API_ADDR`. |
| Ingester | `proxyx-ingester` | 9001 | `/metrics` | `PROXYX_CONTROL_INGESTER_HEALTH_ADDR`. |
| Limiter | `proxyx-limiter` | none | `/metrics` | Only when `PROXYX_LIMITER_METRICS_ADDR` is set, for example `127.0.0.1:39092`. |
| Edge proxy | `proxyx-edge` | none | `/metrics` | Only when `server.ops_listen` is set. |

Health and readiness endpoints are in [operations](operations.md#health-and-readiness). Prometheus only reads `/metrics`; use `/readyz` for load balancer checks.

## Loading the files

**Prometheus.** Copy `prometheus-rules.yml` next to your configuration and list it under `rule_files`. Load the whole file: several alerts read the recording rules (`proxyx:...`) in the same file, and they never fire without them. `prometheus.example.yml` shows the scrape jobs. Check the files before you reload:

```sh
promtool check rules deploy/monitoring/prometheus-rules.yml
promtool check config deploy/monitoring/prometheus.example.yml
```

Each alert has a `runbook_url` annotation. It points at the file on the project's `main` branch; replace the prefix if you keep the runbooks elsewhere. The recording group evaluates every 30 seconds.

**Alertmanager.** `alertmanager.example.yml` routes `severity="critical"` to a pager receiver and `severity="warning"` to a chat receiver, and inhibits alerts that a down target, a down database or an open breaker already explains. The receivers are placeholders; set your own. Check it with `amtool check-config deploy/monitoring/alertmanager.example.yml`.

**Grafana.** Import `grafana/proxyx-overview.json` (Dashboards, New, Import) or provision it from a file. It has the template variables `DS_PROMETHEUS` (pick your Prometheus data source), `service` (pool role, applied to the pool panels) and `instance`. The rows are the pool gateway, the warmer and cache, the session proxy, the control API and ingester, the limiter and the edge proxy. Panels for a role you do not run stay empty.

## Alert reference

Severities follow the runbooks. `critical` means a person should act now: capacity, durability or the pool's dependencies are at risk. `warning` means look at it in working hours, or it is an early signal of a critical alert. Neither implies a particular notification integration. The alerts that have a runbook link to it. The others carry a first step in the table; their `runbook_url` points at the section of this page.

### Scrape targets and readiness

Every role has a down alert based on `up`. The session proxy also exports its readiness: `proxyx_intercept_ready` (1 ready), `proxyx_intercept_readiness_check{check}` (1 ok, 0 failing; `check` is `redis`, `capture_pipeline` or `listeners`) and `proxyx_intercept_draining`. A draining proxy is not ready on purpose, so `ProxyXInterceptNotReady` skips it, and `ProxyXInterceptDrainingTooLong` catches a drain that does not end.

| Alert | Severity | Fires when | Runbook or first step |
|---|---|---|---|
| `ProxyXGatewayDown` | critical | `up` is 0 for a gateway for 2 minutes. | [014](runbooks/014-deploy-and-rollback.md) |
| `ProxyXWarmerDown` | critical | `up` is 0 for a warmer for 2 minutes. | [003](runbooks/003-cache-below-low-watermark.md) |
| `ProxyXInterceptDown` | critical | `up` is 0 for a session proxy for 2 minutes. | Check the process and its admin listener (`GET :8888/health`). A listener that failed to bind leaves the process running, so also read its log. |
| `ProxyXControlAPIDown` | critical | `up` is 0 for the control API for 2 minutes. | Check the process, then `GET :9000/health/ready`: Postgres and Redis must answer. |
| `ProxyXIngesterDown` | critical | `up` is 0 for an ingester for 2 minutes. | Check the process and `GET :9001/health`, which is 503 once the consumer task has exited. Captures wait in the broker until it runs again. |
| `ProxyXLimiterDown` | critical | `up` is 0 for the limiter for 2 minutes. | Restart it and check `PROXYX_LIMITER_METRICS_ADDR` if it is up but not scraped. Session proxies deny or fail open by their fail-open policy; a restarted limiter starts with full buckets. |
| `ProxyXEdgeDown` | critical | `up` is 0 for an edge proxy for 2 minutes. | Check the process and that `server.ops_listen` is set; without it nothing is served. |
| `ProxyXProberScrapeDown` | warning | `up` is 0 for the prober for 15 minutes. | [012](runbooks/012-prober-not-reporting.md) |
| `ProxyXInterceptNotReady` | critical | `proxyx_intercept_ready` is 0 for 5 minutes and the proxy is not draining. | Read `proxyx_intercept_readiness_check{check}`: `redis`, `capture_pipeline` or `listeners` names the failing part. A proxy that is not ready should be out of the balancer. |
| `ProxyXInterceptReadinessCheckFailing` | warning | One readiness check is 0 for 5 minutes. | `redis`: check Redis. `capture_pipeline`: check the broker and the capture buffer. `listeners`: a listener failed to bind or exited. |
| `ProxyXInterceptDrainingTooLong` | warning | `proxyx_intercept_draining` is 1 for 15 minutes. | The drain waits up to `shutdown_drain_timeout_secs` (300 by default) and then flushes captures for up to 30 seconds. A longer drain means tunnels that do not end or a capture buffer that does not empty. Check the supervisor's stop timeout. |

### Pool gateway

Most gateway alerts come from the runbooks. The extra ones watch refusals, the connection caps, key scanning and the control API. Every pool series carries `service` (`proxyx-gateway` or `proxyx-warmer`); the alerts group by `service` and `instance` where a single replica matters.

| Alert | Severity | Fires when | Runbook or first step |
|---|---|---|---|
| `ProxyXRedisDown` | critical | `proxyx_pool_redis_down` is 1 for 5 minutes. | [001](runbooks/001-redis-down.md) |
| `ProxyXPostgresDown` | critical | `proxyx_pool_postgres_down` is 1 for 10 minutes. | [002](runbooks/002-postgres-down.md) |
| `ProxyXConfigRejected` | critical | `proxyx_pool_config_reload_failed` is 1 for a source for 5 minutes. | [007](runbooks/007-config-reload-rejected.md) |
| `ProxyXSnapshotStale` | warning | The loaded snapshot is older than 300 seconds for 5 minutes. Reloads run every 30 seconds by default. | [014](runbooks/014-deploy-and-rollback.md) |
| `ProxyXLeaseLimitBroken` | warning | 10 or more leases past `max_conns` or `fair_use` in 10 minutes, held for 30 minutes. | [013](runbooks/013-lease-limit-broken.md) |
| `ProxyXBlockSignalsDropped` | warning | At least 10 ignored client block signals in 30 minutes and more than half of all client signals, held for 10 minutes. | [011](runbooks/011-block-signals-dropped.md) |
| `ProxyXGatewayNoCapacity` | warning | Tunnels refused with `cache_empty` or `no_healthy_ip` for 5 minutes. | [003](runbooks/003-cache-below-low-watermark.md) |
| `ProxyXGatewayProviderUnavailable` | warning | Tunnels refused with `provider_unavailable`, `provider_auth` or `provider_timeout` for 10 minutes. | [004](runbooks/004-provider-breaker-open.md) |
| `ProxyXGatewayConnectionCap` | warning | A gateway closes connections at accept (`over_limit`) for 5 minutes. | `max_connections` or the pending-connection caps are full. Check for a client that opens connections without logging in, then raise `PROXYX_POOL_MAX_CONNECTIONS` if the load is real. |
| `ProxyXGatewaySourceLimited` | warning | More than 1 login per second is refused as `source_limited` for 10 minutes. | A scan or a client that cycles keys. Find the source in the gateway log. Behind a load balancer without PROXY protocol every customer shares one source, so check the caveats in the pool metrics page. |
| `ProxyXGatewayDialSlow` | warning | The p95 of the dns, tcp or handshake dial stage is over 5 seconds for 15 minutes. | [004](runbooks/004-provider-breaker-open.md) |
| `ProxyXPoolAPIErrors` | warning | More than 5% of pool control API requests are 5xx for 10 minutes. | [002](runbooks/002-postgres-down.md) |
| `ProxyXPoolAPISlow` | warning | The p95 of a pool control API route is over 5 seconds for 10 minutes. | Check PostgreSQL latency, then the route name in the alert. |

### Pool warmer and cache

Inventory gauges are shared state: every warmer replica reports the same IPs. The alerts take the `max` across replicas before they add or divide, so a second replica does not double the numbers. The provider breaker gauge of the pool reads 0 closed, 1 half-open, 2 open.

| Alert | Severity | Fires when | Runbook or first step |
|---|---|---|---|
| `ProxyXCacheLow` | critical | `proxyx_pool_cache_low{tier="all"}` is 1. The warmer already applies the `low_for` delay. | [003](runbooks/003-cache-below-low-watermark.md) |
| `ProxyXCacheBelowMinReady` | warning | Ready units are below `min_ready` for 15 minutes. | [003](runbooks/003-cache-below-low-watermark.md) |
| `ProxyXProviderBreakerOpen` | critical | A provider breaker is open (state 2) for 5 minutes. | [004](runbooks/004-provider-breaker-open.md) |
| `ProxyXBudgetNearLimit` | critical | The cost budget ratio is 0.9 or more for 5 minutes. | [005](runbooks/005-provider-budget-at-90-percent.md) |
| `ProxyXRentalEnding` | critical | A dated rental ends in under 14 days. | [006](runbooks/006-static-ip-rental-ending.md) |
| `ProxyXSweeperRising` | critical | 3 or more reclaims in 15 minutes, held for 30 minutes. | [008](runbooks/008-sweeper-reclaim-rate-rising.md) |
| `ProxyXIPReplaceRequested` | critical | An IP is in `replace_requested` for 5 minutes. | [009](runbooks/009-ip-replace-requested.md) |
| `ProxyXPoolCooled` | warning | Half or more of a provider's usable static IPs are in cooldown or quarantine for 10 minutes. | [010](runbooks/010-pool-cooled.md) |
| `ProxyXWarmCreatesFailing` | warning | More than half of the session creates of a provider fail for 15 minutes. | [004](runbooks/004-provider-breaker-open.md) |
| `ProxyXRotateFailing` | warning | More than half of the SIM box resets of a provider time out or fail over an hour, held for 30 minutes. | [009](runbooks/009-ip-replace-requested.md) |
| `ProxyXIPChecksFailing` | warning | Calls to an IP-check or reputation service fail for 30 minutes. | Check the service status and the key file for that check. Exit-IP and reputation verdicts degrade meanwhile. |

### Prober

The prober is optional. If you run none, drop `ProxyXProberMissing`, `ProxyXProberSilent`, `ProxyXProberBlocked` and `ProxyXProberScrapeDown`: the missing-series alert fires 3 hours after the rules load.

| Alert | Severity | Fires when | Runbook or first step |
|---|---|---|---|
| `ProxyXProberBlocked` | critical | Probe jobs ended as `credentials_rejected` or `results_lost` for 10 minutes. | [012](runbooks/012-prober-not-reporting.md) |
| `ProxyXProberSilent` | warning | No canary result posted for 3 hours. | [012](runbooks/012-prober-not-reporting.md) |
| `ProxyXProberMissing` | warning | The canary timestamp series is absent for 3 hours. | [012](runbooks/012-prober-not-reporting.md) |

### Session proxy

The upstream breaker gauge `proxyx_intercept_upstream_breaker_state{target_kind}` reads 0 closed, 1 open, 2 half_open, and the value is the worst state among the tracked targets of that kind. `target_kind` is `egress_proxy`, `private_override` or `origin`. Do not confuse it with the pool's provider breaker, where 2 is open.

| Alert | Severity | Fires when | Runbook or first step |
|---|---|---|---|
| `ProxyXInterceptBreakerOpen` | warning | An upstream breaker is open (value 1) for 5 minutes. | The label `target_kind` says what is broken: `egress_proxy` is the proxy the session uses, `private_override` a configured private target, `origin` the site itself. Test that target from the proxy host. Note that for this gauge 1 is open and 2 is half_open, the reverse of the pool provider breaker. |
| `ProxyXInterceptBreakerFlapping` | warning | A breaker opened 5 or more times in 30 minutes. | The target recovers and fails again. Check its health and the breaker thresholds. |
| `ProxyXInterceptBreakerRejecting` | warning | The breaker fails requests fast for 5 minutes. | Same as an open breaker. The rejected requests are the cost, so check which sessions send to that target. |
| `ProxyXInterceptUpstreamErrors` | warning | More than 5% of forwarded requests end in `error`, or more than 5% of connections end in `upstream_error` or `upstream_timeout`, for 10 minutes. | Split by `outcome` in `proxyx_intercept_connections_total` and by target. A broken egress proxy and an unreachable site look the same. |
| `ProxyXInterceptUpstream5xx` | warning | More than 10% of upstream responses are 5xx for 15 minutes. | The status comes from the sites. Check whether one target dominates before blaming the proxy. |
| `ProxyXInterceptOverheadHigh` | warning | The p99 of the proxy's own overhead (request, response and capture_wait phases) is over 250 ms for 15 minutes. | Look at `proxyx_intercept_overhead_seconds` by `phase`. A high `capture_wait` means the capture pipeline backpressures the proxy. |
| `ProxyXInterceptUpstreamSlow` | warning | The p99 time to upstream response headers is over 10 seconds for 15 minutes (not WebSocket). | Check the egress proxy or pool gateway latency, then the target. |
| `ProxyXInterceptConnectionLimit` | warning | The proxy refuses connections at `tuning.max_connections` for 5 minutes. | Scale out or raise the limit. Check for leaked connections: `proxyx_intercept_connections_active`. |
| `ProxyXRatelimitBackendErrors` | warning | Rate-limit calls to the `redis` or `limiter` backend fail for 5 minutes. | Check that backend. Orgs are denied or let through by `failopen_policy`. |
| `ProxyXRatelimitFailOpen` | warning | Requests pass without a rate-limit decision because the backend failed, for 5 minutes. | Rate limits are not enforced meanwhile. Fix the backend. |

### Capture pipeline

Captures flow from the session proxy through the broker and the ingester into the capture store (see [capture pipeline](capture-pipeline.md)). The session proxy alerts cover the first hop; the ingester alerts below cover the rest. A full buffer blocks proxied traffic even while the proxy reports healthy.

| Alert | Severity | Fires when | Runbook or first step |
|---|---|---|---|
| `ProxyXCaptureBufferStalled` | critical | The capture buffer is not empty and nothing was published for 5 minutes. | Look for the `capture batch publish stalled` log line, then the broker. Stop starting new crawls and scans until publishing recovers. |
| `ProxyXCaptureBufferHigh` | warning | The capture buffer holds more than 192 captures for 10 minutes. | The broker is slow. The threshold is 75% of the default `channel_capacity` of 256; scale it if you changed that. |
| `ProxyXCapturesDropped` | critical | Any capture was dropped in 15 minutes. | Captures are lost after every publish attempt failed. Fix the broker, then check the ingester. |

### Control API and ingester

The control API and the ingester share one metric registry layout with the session proxy (see [session proxy metrics](metrics/session-proxy.md)).

| Alert | Severity | Fires when | Runbook or first step |
|---|---|---|---|
| `ProxyXControlAPIErrors` | warning | More than 5% of control API requests are 5xx for 10 minutes. | Check `GET :9000/health/ready` (Postgres and Redis), then the route label of the 5xx series. |
| `ProxyXControlAPISlow` | warning | The p95 of a control API route is over 5 seconds for 10 minutes. | Exports and large searches are slow by nature; check the route first. |
| `ProxyXIngesterCircuitOpen` | critical | The ingester circuit for a table is open for 2 minutes. | Consecutive flush failures opened it. Check the capture store (ClickHouse or OpenSearch). It closes after the next successful flush. |
| `ProxyXIngesterFlushFailing` | warning | More than 20% of batch writes to a table fail for 10 minutes. | Check the capture store. A circuit alert usually follows. |
| `ProxyXIngesterRowsDropped` | critical | Any row was dropped in 15 minutes. | These rows are acked and lost. Find the failing write in the ingester log (a poison row or a store that rejects data). |
| `ProxyXIngesterDecodeErrors` | warning | Messages fail to decode for 10 minutes. | The producer and the ingester run incompatible versions, or the topic holds foreign data. Such messages are acked and skipped. |
| `ProxyXCaptureCommitLagHigh` | warning | The p95 delay from capture to committed row is over 120 seconds for 10 minutes. | The ingester falls behind or the store is slow. Check flush duration and circuits. |

### Limiter

The limiter serves metrics only when `PROXYX_LIMITER_METRICS_ADDR` is set (see [limiter metrics](metrics/limiter.md)). Its series carry no `service` label; the example scrape config adds one. `ProxyXRatelimitBackendErrors` and `ProxyXRatelimitFailOpen` (session proxy section) link here: with `ratelimit.backend = "limiter"` the limiter is their usual cause.

| Alert | Severity | Fires when | Runbook or first step |
|---|---|---|---|
| `ProxyXLimiterBucketsNearCapacity` | warning | Buckets are over 90% of the capacity for 10 minutes. | Raise `PROXYX_LIMITER_MAX_BUCKETS` and restart in a quiet period; a restart resets every bucket. |
| `ProxyXLimiterRejectingBuckets` | critical | The slab is full and creates are rejected for 5 minutes. | Orgs are denied or let through by `failopen_policy`. Raise `PROXYX_LIMITER_MAX_BUCKETS`. |
| `ProxyXLimiterConnectionsRefused` | warning | The limiter closes connections at `PROXYX_LIMITER_MAX_CONNECTIONS` for 5 minutes. | Raise the cap. Each session proxy replica keeps up to 16 pooled connections. |
| `ProxyXLimiterRestarted` | warning | The limiter's uptime is under 5 minutes. | Every bucket restarted full. Expect a short burst above the configured rates; find out why it restarted. |

### Edge proxy

These read the families in [edge metrics](metrics/edge.md). The edge proxy serves metrics only when `server.ops_listen` is set. Its `/readyz` answers 503 when no healthy egress path exists.

| Alert | Severity | Fires when | Runbook or first step |
|---|---|---|---|
| `ProxyXEdgeParentDown` | warning | A parent proxy takes no requests for 5 minutes (`proxyx_edge_parent_up` is 0): its circuit breaker is open or it fails its health probes. | Test the parent from the host. The breaker tries it again after `open_duration`; see `[breaker.parent]` and `[health]` in the edge configuration. |
| `ProxyXEdgeParentUnhealthy` | warning | `proxyx_edge_parent_healthy` is 0 for 5 minutes: the parent failed `unhealthy_threshold` active probes in a row. | Check the parent and `health.parent_target`. This is independent of the breaker. |
| `ProxyXEdgeEgressAddressesOut` | warning | Egress addresses are `open` (breaker) or `unhealthy` (failed active check) for 10 minutes. | `open`: connects from those addresses fail, so check routing and the egress network. `unhealthy`: the address left the host or is not bindable; check the interface configuration. |
| `ProxyXEdgeEgressUnavailable` | critical | Connects fail with `unavailable` for 5 minutes: every address of the destination's family is out of service. `/readyz` answers 503 while no healthy egress path exists. | Fix the addresses first; see `ProxyXEdgeEgressAddressesOut`. |
| `ProxyXEdgeEgressCheckFailing` | warning | An active egress check failed in the last 15 minutes. | An address left the host or became unbindable, or a prefix is no longer routed here. |
| `ProxyXEdgeBreakerFlapping` | warning | Parent or egress breakers opened 5 or more times in 30 minutes. | A target recovers and fails again. Check its health and the `[breaker.parent]` and `[breaker.egress]` thresholds. |
| `ProxyXEdgeConfigReloadFailed` | warning | A reload (SIGHUP) failed in the last 15 minutes. | The old configuration keeps running. The log names the reason. |
| `ProxyXEdgeAccessLogDropping` | warning | Access log lines are dropped for 5 minutes. | The log disk is slow or failing. Requests do not wait for the log. |
| `ProxyXEdgeConnectionCap` | warning | A listener closes connections over its limit for 10 minutes. | Check `proxyx_edge_limit_rejections_total` for which limit (`global`, `listener`, `per_src`). |
| `ProxyXEdgeAuthFailures` | warning | More than 5 failed logins per second (invalid or blocked) for 10 minutes. | A scan or a misconfigured client. The access log names the source. |
| `ProxyXEdgeRequestFailures` | warning | More than 25% of requests fail to reach their target for 15 minutes. | Split by `result` in `proxyx_edge_requests_total`: DNS, connect, parent or timeout. |
| `ProxyXEdgeEgressFailures` | warning | More than 25% of connects of an egress pool fail or find no address for 15 minutes. | Split by `outcome`. `no_address` means a pool without an address of the destination's IP family. |

## Recording rules

The rules file also defines these series. Dashboards do not need them (every panel reads raw metrics); alerts do.

| Series | Meaning |
|---|---|
| `proxyx:pool_connections_refused:ratio_rate5m` | Share of gateway connections answered with a refusal cause (not `ok`, `bad_request` or `over_limit`). |
| `proxyx:pool_dial_duration_seconds:p95_rate5m` | p95 dial time by provider and stage. |
| `proxyx:pool_api_requests_5xx:ratio_rate5m` | Share of 5xx answers of the pool control API. |
| `proxyx:pool_api_request_duration_seconds:p95_rate5m` | p95 pool control API latency by route. |
| `proxyx:pool_warm_creates_failed:ratio_rate15m` | Share of failed session creates by provider (`ok` and `failed` only). |
| `proxyx:pool_rotate_failed:ratio_rate1h` | Share of SIM box resets that time out or fail, by provider. |
| `proxyx:intercept_requests_error:ratio_rate5m` | Share of forwarded requests with no usable response (`status_class="error"`). |
| `proxyx:intercept_requests_5xx:ratio_rate5m` | Share of 5xx upstream responses. |
| `proxyx:intercept_connections_upstream_failed:ratio_rate5m` | Share of connections that end in `upstream_error` or `upstream_timeout`. |
| `proxyx:intercept_upstream_duration_seconds:p50_rate5m`, `proxyx:intercept_upstream_duration_seconds:p95_rate5m`, `proxyx:intercept_upstream_duration_seconds:p99_rate5m` | Upstream latency quantiles by protocol. |
| `proxyx:intercept_overhead_seconds:p99_rate5m` | p99 proxy overhead by phase. |
| `proxyx:control_api_requests_5xx:ratio_rate5m` | Share of 5xx answers of the control API. |
| `proxyx:control_api_request_duration_seconds:p95_rate5m` | p95 control API latency by route. |
| `proxyx:ingester_flush_failed:ratio_rate5m` | Share of failed capture store writes by table. |
| `proxyx:capture_commit_lag_seconds:p95_rate5m` | p95 delay from capture to committed row by table. |
| `proxyx:limiter_buckets:used_ratio` | Buckets in use over the slab capacity. |
| `proxyx:limiter_consume_denied:ratio_rate5m` | Share of consume records the limiter denied. |
| `proxyx:edge_requests_failed:ratio_rate5m` | Share of edge requests that end in a DNS, connect, parent, timeout or internal failure. |
| `proxyx:edge_egress_failed:ratio_rate5m` | Share of failed egress connects by pool. |

## Service level suggestions

Starting points. Adjust them to your traffic, and treat a first month of data as a calibration, not a target.

- **Gateway availability.** Keep `proxyx:pool_connections_refused:ratio_rate5m` under 0.5% over 30 days. It counts refusals with a cause (`cache_empty`, `no_healthy_ip`, `provider_*` and so on) and leaves out `bad_request` and `over_limit`.
- **Session proxy errors.** Keep `proxyx:intercept_requests_error:ratio_rate5m` under 1% over 30 days. Remember that unreachable sites count too; use a per-target view for customer-facing numbers.
- **Proxy overhead.** Keep the p99 of the `request`, `response` and `capture_wait` phases of `proxyx_intercept_overhead_seconds` under 250 ms, which is the alert threshold. `lock_wait` and `ratelimit_wait` are deliberate delays, so leave them out.
- **Capture durability.** Zero. Any increase of `proxyx_intercept_captures_dropped_total` or `proxyx_ingester_rows_dropped_total` is data loss. Keep the p95 of `proxyx_capture_commit_lag_seconds` under 60 seconds in normal operation; the alert fires at 120.
- **Cache health.** Keep every provider's ready units at or above `min_ready` for 99% of the time, using `ProxyXCacheBelowMinReady` as the signal.
- **Limiter headroom.** Keep `proxyx:limiter_buckets:used_ratio` under 0.8 so a traffic peak does not reach the 0.9 alert.

## Contract metrics

The session proxy readiness, breaker, connection and rate-limit signals are named by agreement between the code and these rules. `deploy/monitoring/contract-metrics.txt` lists them for the checker, so the rules can use a name before its catalogue entry exists. Once a name is in `docs/metrics/`, remove it from that file. The limiter families are already documented in [limiter metrics](metrics/limiter.md).

| Metric | Type | Labels |
|---|---|---|
| `proxyx_intercept_upstream_breaker_state` | gauge | `target_kind` (`egress_proxy`, `private_override`, `origin`); 0 closed, 1 open, 2 half_open, worst state of that kind |
| `proxyx_intercept_upstream_breaker_transitions_total` | counter | `target_kind`, `to` (`open`, `half_open`, `closed`) |
| `proxyx_intercept_upstream_breaker_rejected_total` | counter | `target_kind` |
| `proxyx_intercept_ready` | gauge | none; 0 or 1 |
| `proxyx_intercept_readiness_check` | gauge | `check` (`redis`, `capture_pipeline`, `listeners`); 1 ok, 0 failing |
| `proxyx_intercept_draining` | gauge | none; 0 or 1 |
| `proxyx_intercept_connections_active` | gauge | none |
| `proxyx_intercept_connection_limit_refusals_total` | counter | none |
| `proxyx_intercept_ratelimit_backend_errors_total` | counter | `backend` (`redis`, `limiter`) |
| `proxyx_intercept_ratelimit_failopen_total` | counter | `backend` |

## Testing the assets

Run from the repository root. `promtool` and `amtool` come from the Prometheus and Alertmanager release tarballs; any recent release works.

```sh
promtool check rules deploy/monitoring/prometheus-rules.yml
promtool test rules deploy/monitoring/prometheus-rules.test.yml
promtool check config deploy/monitoring/prometheus.example.yml
amtool check-config deploy/monitoring/alertmanager.example.yml
python3 ci/check-alert-metrics.py
```

`prometheus-rules.test.yml` feeds synthetic series and states which alerts fire at which time, and which stay silent: a provider breaker open (and half-open, which does not fire), Redis and PostgreSQL down, a cache below its low watermark (only for `tier="all"`), a session proxy not ready (but not while draining), an open upstream breaker (but not half_open), a stalled capture buffer (but not while publishing), a limiter near capacity, an open ingester circuit, scrape targets that are down, and more. Add a case there whenever you add or change an alert.

`ci/check-alert-metrics.py` needs PyYAML. It fails when:

- a metric used in a rule expression, a dashboard panel or a dashboard variable query is not documented in `docs/metrics/*.md`, not listed in `contract-metrics.txt`, not a recording rule of the rules file, and not the built-in `up`;
- a runbook `docs/runbooks/NNN-*.md` is not the `runbook_url` of at least one alert;
- an alert lacks `severity` (`critical` or `warning`), `role`, `summary`, `description` or `runbook_url`, or its `runbook_url` points at a file or an anchor of this page that does not exist;
- an alert is missing from this page;
- the dashboard JSON does not parse, or reuses a panel id.
