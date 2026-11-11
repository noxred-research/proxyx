# ProxyX metrics

All families are defined in `crates/pool-common/src/metrics.rs` (`Metrics::new(service)`, one instance per process, injected into the crates that record). The gateway and the warmer each serve their registry on `/metrics` of the ops port (8888) as `text/plain; version=0.0.4; charset=utf-8` (`common::metrics::CONTENT_TYPE`); `render()` does no I/O. Every series carries the constant label `service`: `proxyx-gateway` or `proxyx-warmer`, the value of `SERVICE_NAME` (unset: the role's name, `crates/pool/src/cli.rs`). If a scrape target also supplies a conflicting `service` label and `honorLabels` is false, Prometheus preserves the metric's value as `exported_service` and uses the target's value for `service`. Align alert selectors and grouping with the actual scrape configuration. Names follow `proxyx_pool_<noun>[_<unit>]`; labels are closed sets and never hold an org, host, IP or session id. A family that has no sample yet is absent from the scrape until its first label set is recorded, except plain counters and gauges, which scrape as 0. The prober (Python) has its own families, listed last.

## Gateway (tunnels)

### `proxyx_pool_connections_total`
- **Type:** counter
- **Labels:** `listener` (connect, socks, probe), `outcome` (ok, bad_request, over_limit, or a cause code: auth_required, org_disabled, option_denied, org_blocked, port_not_allowed, destination_denied, org_capacity, org_budget, cache_empty, no_healthy_ip, cache_unavailable, lease_timeout, provider_unavailable, provider_auth, provider_timeout, upstream_error), `provider` (the provider that served the tunnel; none for a refusal and for connections that never got a lease: bad_request, over_limit, auth_required, org_disabled)
- **Source:** event, `crates/gateway` (`gateway.rs` open pipeline and `listener.rs` handlers), once per connection when it is answered: `ok` as soon as the tunnel is open (not when it ends), otherwise the refusal
- **Meaning:** Connections by listener and outcome. `bad_request` is a head or handshake that did not parse or time out, including a socket that sent no first byte within 3 s; `over_limit` is a connection closed unanswered because the pod already runs `max_connections` connections, or `max_pending_connections` connections that have not authenticated yet, or the connection's source (an IPv4 address, an IPv6 /64) already has `max_pending_per_ip` of them (default: a quarter of the pending pool, at least 16, so at least four sources are needed to fill it); any other outcome except `ok` is the answer the client saw (`common::Cause::code`).
- **Query:** `sum by (outcome) (rate(proxyx_pool_connections_total{outcome!="ok"}[5m]))`

### `proxyx_pool_auth_failures_total`
- **Type:** counter
- **Labels:** `reason` (unknown_key, source_limited)
- **Source:** event, `crates/gateway/src/auth.rs`, once per login refused for its key: `unknown_key` when the org key is not registered (answered by Postgres or by the 5 s memory of unknown keys), `source_limited` when the connection's source (an IPv4 address, an IPv6 /64) already caused 20 unknown-key lookups in the last 60 s in the bucket of this key (16 buckets, by the first byte of the key's SHA-256) and the key has no verified entry in this pod, so it is refused without a lookup
- **Meaning:** Wrong-key traffic. A steady `unknown_key` rate is a misconfigured or revoked client; `source_limited` is a scan or a client that keeps cycling keys, held to 20 Postgres lookups per source and bucket per minute, 320 per source in all (fixed 60 s window from the first counted failure of the bucket; the limit is per pod, in memory, 10,000 sources at most). A limited source keeps working with every key this pod verified before (up to an hour after its last check, also while Postgres is down). The one cost: a valid key this pod has never verified (new org, pod restarted, idle over an hour) is refused with `407` from a source whose bucket for that key is limited, until the window ends, then works; a source only becomes limited by its own wrong keys. When a session proxy serves many orgs from one source address, a wrong proxy password consumes lookups only in that key's bucket. Without another org's key, a client cannot identify its bucket, so targeting that org's first key verification requires failures across all 16 buckets. A wrong key repeated within 5 s costs no charge, and disabled orgs are not counted here (`org_disabled` in `connections_total`). Neither the source nor the key is in a label.
- **Caveats:** (1) The limit is per connection source. Behind SNAT or a load balancer without PROXY protocol every customer shares one source address, so one hostile client that fails lookups in every bucket can make every new, never-verified key fail with `407` for up to 60 s (verified keys keep working); `max_pending_per_ip` counts a source in the same way. The session proxy connects to the gateway directly, so the source is the session proxy's own address. (2) The source table holds 10,000 sources: a scan from more addresses evicts limited sources, which then start a fresh window, so a wide scan can exceed 320 lookups per source per minute in total. Neither is fixed in code; both are the documented limits of an in-memory, per-pod defence.
- **Query:** `sum by (reason) (rate(proxyx_pool_auth_failures_total[5m]))`

### `proxyx_pool_tunnels_open`
- **Type:** gauge
- **Labels:** none
- **Source:** state, `crates/gateway` (incremented when a tunnel opens, decremented when it closes)
- **Meaning:** Tunnels open now in this pod. During a drain it falls to 0 before the pod exits.
- **Query:** `sum by (pod) (proxyx_pool_tunnels_open)`

### `proxyx_pool_dial_duration_seconds`
- **Type:** histogram (buckets 5 ms to 8 s)
- **Labels:** `provider` (configured adapter id), `stage` (dns, tcp, handshake, first_byte)
- **Source:** event, `crates/dial/src/lib.rs` (`dns`, `tcp`, `handshake`, also when the stage fails or times out); `dial::record_first_byte` from `crates/gateway` (`first_byte`)
- **Meaning:** Upstream dial time per stage. `handshake` includes TLS to an HTTPS proxy plus CONNECT under one shared budget. A slow provider shows in `handshake`, a slow target in `first_byte`. Rotating dial races record each attempted upstream, including completed failures, not a new metric family.
- **Query:** `histogram_quantile(0.95, sum by (le, provider, stage) (rate(proxyx_pool_dial_duration_seconds_bucket[5m])))`

### `proxyx_pool_org_capacity_refusals_total`
- **Type:** counter
- **Labels:** none
- **Source:** event, `crates/gateway` when `max_tunnels_per_org` refuses a tunnel
- **Meaning:** Tunnels refused with `org_capacity`: the org's open tunnels in total reached `max_tunnels_per_org` of its global or org policy, or its open tunnels on one provider reached the `max_tunnels_per_org` of that provider's route class. A route-class cap counts only the org's tunnels on that provider, whatever it has on the others.
- **Query:** `rate(proxyx_pool_org_capacity_refusals_total[5m])`

### `proxyx_pool_org_budget_refusals_total`
- **Type:** counter
- **Labels:** none
- **Source:** event, `crates/gateway` when an org used `limits.org_max_gb_per_day` and a new tunnel is refused
- **Meaning:** Tunnels refused with `org_budget`. Open tunnels are not cut. The org is in the gateway log, never in a label.
- **Query:** `rate(proxyx_pool_org_budget_refusals_total[5m])`

## Control API

### `proxyx_pool_api_requests_total`
- **Type:** counter
- **Labels:** `route` (the matched route template, or unmatched; never the raw path), `status_class` (1xx, 2xx, 3xx, 4xx, 5xx, other)
- **Source:** event, `crates/pool-api` request middleware, once per answered `/v1` request; the ops routes (`/healthz`, `/readyz`, `/metrics`) are not counted
- **Meaning:** Control API requests by route and status class. `other` is a status outside 100 to 599. Routes include `/v1/orgs/{org}/endpoints`, `/v1/orgs/{org}/sessions` and `/v1/orgs/{org}/sessions/{sid}`. Templates never expose orgs, session ids, generated URLs or keys as labels. Per-org affinity entries, hits, misses, evictions and rotations are Redis/API statistics, not Prometheus labels.
- **Query:** `sum by (route, status_class) (rate(proxyx_pool_api_requests_total{status_class=~"4xx|5xx"}[5m]))`

### `proxyx_pool_api_request_duration_seconds`
- **Type:** histogram (buckets 1 ms to 10 s)
- **Labels:** `route` (matched route template, or unmatched)
- **Source:** event, `crates/pool-api` request middleware, time from request received to response ready
- **Meaning:** Control API request duration by route.
- **Query:** `histogram_quantile(0.95, sum by (le, route) (rate(proxyx_pool_api_request_duration_seconds_bucket[5m])))`

## Cache (leases, sessions, ready units)

### `proxyx_pool_cache_ready`
- **Type:** gauge
- **Labels:** `kind` (static, rotating), `provider`, `tier` (normal, degraded)
- **Source:** state, `crates/warmer` partition loops, from the Redis ready set each cycle (the `tier` field of each unit) and, for static IPs, the inventory state
- **Meaning:** Units that can be leased now, by tier. A degraded unit is leasable but slow (clean answers over the TTFB or load limit); the gateway leases it only when no normal unit is left. The sum over `tier` is every leasable unit.
- **Break:** `sum by (kind, provider) (cache_ready)` below `proxyx_pool_cache_low_watermark` for the policy's `low_for` (default 2 minutes) means the cache-low alert fires. The warmer applies `low_for` and exports the result as `proxyx_pool_cache_low{tier="all"}`, which the alert reads.
- **Query:** `sum by (kind, provider) (proxyx_pool_cache_ready) < max by (kind, provider) (proxyx_pool_cache_low_watermark)`

### `proxyx_pool_cache_min_ready`
- **Type:** gauge
- **Labels:** `kind` (static, rotating), `provider`
- **Source:** state, `crates/warmer`, from the effective policy each cycle
- **Meaning:** Effective `min_ready` of the provider, so an alert can compare it with `cache_ready`.
- **Query:** `sum by (kind, provider) (proxyx_pool_cache_min_ready)`

### `proxyx_pool_cache_low_watermark`
- **Type:** gauge
- **Labels:** `kind` (static, rotating), `provider`
- **Source:** state, `crates/warmer`, from the effective policy each cycle (`capacity.low_watermark`, summed over the provider's regions, like `cache_min_ready`)
- **Meaning:** Level below which the provider's cache counts as low. Unset in policy, it is half of `min_ready`.
- **Query:** `sum by (kind, provider) (proxyx_pool_cache_low_watermark)`

### `proxyx_pool_cache_low`
- **Type:** gauge
- **Labels:** `kind` (static, rotating), `provider`, `tier` (all, normal)
- **Source:** state, `crates/warmer` gauges tick; the warmer times how long the leasable units have stayed below `cache_low_watermark` (in memory, per kind, provider and tier; a warmer restart restarts the clock)
- **Meaning:** 1 when the units have been below `cache_low_watermark` for at least the policy's `capacity.low_for` (default 2 minutes), else 0. `tier="all"` counts normal and degraded units together: nothing is left to serve. `tier="normal"` counts the normal tier alone: 1 while `all` is 0 means the cache serves on degraded units. A reading at or above the watermark resets the clock; a provider that leaves the gauges loses its series.
- **Break:** `tier="all"` at 1 means the cache-low alert fires (the alert needs no `for:` delay of its own: the delay is already in the metric).
- **Query:** `max by (kind, provider) (proxyx_pool_cache_low{tier="all"}) == 1`

### `proxyx_pool_cache_sessions`
- **Type:** gauge
- **Labels:** `kind` (rotating), `state` (creating, ready, leased, draining)
- **Source:** state, `crates/warmer`, counted from the session registry each cycle
- **Meaning:** Rotating sessions by lifecycle state. `creating` includes verification during session creation, so there is no separate `verifying` state. `draining` is a session taken out of leasing that keeps serving its open tunnels until they end or the drain cap passes. An expired session goes straight to draining and its record is then dropped; `expired` is not an observable state.
- **Query:** `sum by (state) (proxyx_pool_cache_sessions)`

### `proxyx_pool_cache_leases_total`
- **Type:** counter
- **Labels:** `kind` (static, rotating, none), `outcome` (hit, shared, created, or the cause code of a failed walk), `provider` (the provider that served the tunnel; none for a failed walk)
- **Source:** event, `crates/gateway` after each lease call
- **Meaning:** Lease attempts. `hit` renewed the org's lease, `shared` joined a busy unit, `created` waited for a new session. A failed walk is counted under the first kind of the request and `provider="none"`; `none` is the kind of a request that names none (a validated policy always names one, so it should stay 0). The provider label shows how the tunnels split across providers: the walk keeps the providers in priority order, so the first one serves until it has no normal unit within its limits left.
- **Query:** `sum by (provider) (rate(proxyx_pool_cache_leases_total{outcome=~"hit|shared|created"}[5m]))`

### `proxyx_pool_lease_limit_broken_total`
- **Type:** counter
- **Labels:** `limit` (rest, orgs_hard, max_conns, fair_use), `provider` (the provider whose unit was leased)
- **Source:** event, `crates/gateway` after a lease that broke a limit
- **Meaning:** Last-resort leases: no unit of any provider was left within the limits, so the lease took one that breaks a soft limit instead of stalling the org. The walk asks every provider for a normal unit within the limits first, then for a degraded one within them, and only then breaks a limit, in this order over all providers: rest (`rest_after_release`, the 30 s rest between orgs), then `orgs_hard`, then `max_conns_per_ip`, then `fair_use` (the monthly fair-use stop), a normal unit before a degraded one; the first provider in priority order breaks a tie. Breaking `max_conns_per_ip` has a ceiling: a unit that holds twice the limit in open tunnels (or the provider's own limit per IP, `max_conns_per_ip` of the adapter, when that is lower) is not leased at all, and with every unit at its ceiling the lease waits (`lease_timeout`). A unit that failed a tunnel at IP level a moment ago (10 s, doubling on each failure up to 5 minutes, cleared when it serves a tunnel) goes after all of these, whatever its tier or limit, so a failing IP is the last resort and does not take the new sticky keys. The labels name the limit that was broken and the provider whose unit was taken. A steady rate means the pools are too small for their traffic.
- **Break:** `limit` `max_conns` or `fair_use` rising by at least 10 per 10 minutes for 30 minutes on one provider fires `ProxyXLeaseLimitBroken` (warning, runbook 013): the pool is too small for the load. `rest` and `orgs_hard` are not alerted.
- **Query:** `sum by (limit, provider) (rate(proxyx_pool_lease_limit_broken_total[5m]))`

### `proxyx_pool_cache_evictions_total`
- **Type:** counter
- **Labels:** `cause` (ready_ttl, max_age, keepalive, ip_changed, stability, reputation, quality, block, duplicate, retired, moved, not_leasable)
- **Source:** event, `crates/warmer` when a session or IP leaves the ready set (`ip_changed` also from the static IP recheck, when an IP's exit changed), and `crates/gateway` when an on-demand session is refused by the admission checks (`reputation`, `quality`, `block`) and when a rotating session's exit IP changed on the tunnel path (`ip_changed`)
- **Meaning:** Why units were removed from rotation.
- **Query:** `sum by (cause) (rate(proxyx_pool_cache_evictions_total[1h]))`

### `proxyx_pool_sweeper_reclaimed_total`
- **Type:** counter
- **Labels:** `kind` (session, reservation, lease)
- **Source:** event, `crates/warmer` sweeper
- **Meaning:** Stuck state reclaimed after a crash or a lost message: expired creates and reservations, ready ids whose record is gone, and per-connection leases past their expiry (the gateway releases those with the tunnel, so one that expired was leaked by a gateway that died). An expired sticky lease (`sid`, org or target scope) is normal traffic and is not counted. Counts what any script dropped (a gauge read, a lease call or the sweep itself; the sweep reports the book), so reading the pool never hides a leak from it. A steady rate means something leaks.
- **Query:** `sum by (kind) (increase(proxyx_pool_sweeper_reclaimed_total[15m]))`

## Inventory (static IPs and SIM boxes)

### `proxyx_pool_inventory_ips`
- **Type:** gauge
- **Labels:** `provider`, `state` (candidate, available, leased, degraded, cooldown, quarantined, rotating, offline, replace_requested, retired)
- **Source:** state, `crates/warmer` inventory loop, counted from Postgres; `leased` is filled from the Redis lease counts (the Postgres row stays `available` or `degraded`), and a leased unit leaves the count of its row's state
- **Meaning:** Static IPs by state; the states add up to the shared inventory. `degraded` is leasable but slow. Customer upstreams (rows owned by an org) are not counted, here or in `cache_ready`, `cache_min_ready`, `cache_low_watermark` and `cache_low` of static providers: they are no part of the pool, and one tenant's upstream would otherwise page the cache and pool alerts.
- **Query:** `sum by (provider, state) (proxyx_pool_inventory_ips)`

### `proxyx_pool_inventory_rental_days_left`
- **Type:** gauge
- **Labels:** `provider`
- **Source:** state, `crates/warmer` inventory loop, from `rental_end`; the series disappears when the provider has no dated, non-retired IP
- **Meaning:** Fewest rental days left among the provider's IPs.
- **Break:** a value under 14 means an IP's rental ends soon: the `ProxyXRentalEnding` alert and runbook 006 use 14 days, the time a manual renewal or replacement takes.
- **Query:** `min by (provider) (proxyx_pool_inventory_rental_days_left)`

### `proxyx_pool_rotate_total`
- **Type:** counter
- **Labels:** `provider`, `outcome` (changed, unchanged, timeout, error)
- **Source:** event, `crates/warmer` SIM box reset loop (`crates/provider/src/rotate.rs` call)
- **Meaning:** SIM box resets by result.
- **Query:** `sum by (provider, outcome) (rate(proxyx_pool_rotate_total[1h]))`

### `proxyx_pool_replace_reports_total`
- **Type:** counter
- **Labels:** `provider`
- **Source:** event, `crates/warmer` when the replacement rule emits its log event
- **Meaning:** Replacement report events: IPs the operator should ask the provider to replace.
- **Query:** `sum by (provider) (increase(proxyx_pool_replace_reports_total[24h]))`

### `proxyx_pool_fair_use_exceeded_total`
- **Type:** counter
- **Labels:** `provider`
- **Source:** event, `crates/gateway` relay metering when a static IP's traffic in the UTC month reaches `cost.fair_use_gb_per_ip_month`
- **Meaning:** Static IPs that used up their monthly fair-use traffic. The IP gets no new lease until the next UTC month while another IP of the partition is within its limits; with none left it is leased as the last resort (`lease_limit_broken_total{limit="fair_use"}`); leases it holds go on. At 80% the gateway logs a warning.
- **Query:** `sum by (provider) (increase(proxyx_pool_fair_use_exceeded_total[30d]))`

## Blocks and checks

### `proxyx_pool_block_signals_total`
- **Type:** counter
- **Labels:** `source` (probe, canary, operator, client), `type` (rate_limited, challenge, forbidden, reset), `scope` (target, ip, pool_guard, route_class)
- **Source:** event, `crates/pool-api` (`/v1` block signals, and `/v1/probe/results` for `route_class` after a blocked canary or probe run) and `crates/warmer` light probe
- **Meaning:** Block signals received, with the scope they resulted in.
- **Query:** `sum by (source, scope) (rate(proxyx_pool_block_signals_total[15m]))`

### `proxyx_pool_block_signals_ignored_total`
- **Type:** counter
- **Labels:** none
- **Source:** event, `crates/pool-api` `POST /v1/block-signals`, once per event of a session proxy batch that was not applied (the `ignored` count of the reply)
- **Meaning:** Block-signal events from the session proxy that were dropped: older than an hour, for a session the gateway no longer knows (expired, or Redis was wiped), for a session of another org, or with an exit IP other than the one the gateway reported. A few are normal (a block page seen as a session ends); a steady flow means the session proxy's detector and the gateway disagree, and blocked IPs stay in leasing. The `ProxyXBlockSignalsDropped` warning reads it.
- **Query:** `sum(increase(proxyx_pool_block_signals_ignored_total[15m]))`

### `proxyx_pool_check_failures_total`
- **Type:** counter
- **Labels:** `check` (ip_json, trace_lines, ip_country_json, ip_country_iso_json, provider_echo, fraud_score, abuse_confidence, proxy_risk)
- **Source:** event, `crates/verify` (`exit_ip.rs`, `reputation.rs`) when a check call fails
- **Meaning:** Failed calls to IP-check and reputation services. The label is `check`, not `service`, because every series already carries the constant `service` label. A reputation scorer is on when its key file exists in the secrets directory (`fraud_score_api_key`, `abuse_confidence_api_key`, `proxy_risk_api_key`); `proxy_risk` also needs the setting `proxy_risk_customer` (`PROXYX_POOL_PROXY_RISK_CUSTOMER`, its account name) and fails the start without it. Put its key file in the secrets directory to turn it on. `PROXYX_POOL_PROXY_RISK_BASE_URL` (default: the service's EU node) points it elsewhere, like the other two origins.
- **Query:** `sum by (check) (rate(proxyx_pool_check_failures_total[15m]))`

## Warmer (provider cost and health)

### `proxyx_pool_warm_creates_total`
- **Type:** counter
- **Labels:** `provider`, `outcome` (ok, failed, budget, breaker)
- **Source:** event, `crates/warmer` rotating refill loop (all outcomes), and `crates/gateway` on-demand creates (`breaker`: a create refused because the route class breaker is open)
- **Meaning:** Session creates tried, and those skipped for budget or an open breaker. A tunnel request that only walks past an open route class is `breaker_skips_total`, not a create.
- **Query:** `sum by (provider, outcome) (rate(proxyx_pool_warm_creates_total[15m]))`

### `proxyx_pool_breaker_skips_total`
- **Type:** counter
- **Labels:** `provider`
- **Source:** event, `crates/gateway` candidate walk, once per route class passed over for an open breaker
- **Meaning:** Route classes the gateway skipped on a tunnel request because their breaker is open and no probe is due. The request goes on to the next partition, so a rising value with requests still served means one route class is open and another serves; every request failing with `provider_unavailable` means all candidates are open.
- **Query:** `sum by (provider) (rate(proxyx_pool_breaker_skips_total[5m]))`

### `proxyx_pool_provider_breaker_state`
- **Type:** gauge
- **Labels:** `provider`
- **Source:** state, `crates/warmer` gauges tick; the breaker of each route class (provider and region) lives in Redis (`breaker:{provider:region}`), written by warmer creates and gateway dials
- **Meaning:** The worst state among the route classes of the provider: 0 closed, 1 half-open, 2 open.
- **Break:** 2 for more than 5 minutes means the provider cannot create sessions.
- **Query:** `max by (provider) (proxyx_pool_provider_breaker_state) == 2`

### `proxyx_pool_cost_used_ratio`
- **Type:** gauge
- **Labels:** `provider`
- **Source:** state, `crates/warmer` cost meter
- **Meaning:** Share of the cost budget (`[policy.cost]`) used in the current window, capped at 1 (`Metrics::set_cost_used_ratio`): a window that spent past its limit still reads 1, never more. 1 stops new creates. A create is charged its exit check (24 KiB) before it runs, so the ratio reaches about 1 before creates halt. The series of a provider that left the policy is removed, like its `provider_breaker_state` and `cache_*` series.
- **Query:** `max by (provider) (proxyx_pool_cost_used_ratio) > 0.8`

## State and configuration

### `proxyx_pool_redis_down`
- **Type:** gauge
- **Labels:** none
- **Source:** state, `crates/pool-api` ops server (a Redis ping every 5 s and on every `/readyz`), and failing Redis calls of `crates/warmer`
- **Meaning:** 1 while the last Redis ping or call failed; the ping clears it within 5 s of Redis answering again, whether or not `/readyz` is probed. It starts at 1 and stays until the first successful ping, so a pod that starts while Redis is down reads as down. The gateway then refuses new leases with `cache_unavailable` and keeps open tunnels.
- **Query:** `max(proxyx_pool_redis_down) == 1`

### `proxyx_pool_postgres_down`
- **Type:** gauge
- **Labels:** none
- **Source:** state, `crates/store/src/loaded.rs` reload loop
- **Meaning:** 1 while the last Postgres query failed; it starts at 1 until the first snapshot loads. Processes keep the last good snapshot.
- **Query:** `max(proxyx_pool_postgres_down) == 1`

### `proxyx_pool_config_reload_failed`
- **Type:** gauge
- **Labels:** `source` (policies, inventory, adapters, probe_targets)
- **Source:** state, `crates/store/src/loaded.rs` reload loop
- **Meaning:** 1 when the last reload of that source failed and the previous version is still in use.
- **Break:** logs name the file and the rule that failed.
- **Query:** `max by (source) (proxyx_pool_config_reload_failed) == 1`

### `proxyx_pool_snapshot_age_seconds`
- **Type:** gauge
- **Labels:** none
- **Source:** state, `crates/store/src/loaded.rs`
- **Meaning:** Seconds since the policy and inventory snapshot was loaded.
- **Break:** well above `reload_every` (30 s) means reloads are stuck.
- **Query:** `max(proxyx_pool_snapshot_age_seconds) > 300`

## Prober (Python process `proxyx-prober`)

Defined in `prober/src/proxyx_prober/metrics.py` with `prometheus_client` and served on `/metrics` of the prober's metrics port (8081 by default). The standalone prober runs a local headless browser through a browser-automation library. The `service` label is the prober's `SERVICE_NAME`. These families are not in the Rust registry, so the registry/doc test stops at this heading.

| Name | Type | Labels | Meaning |
|---|---|---|---|
| `proxyx_pool_probe_jobs_total` | counter | `kind` (canary, sample), `outcome` (posted, results_lost, dropped_old, queue_full, pool_failure, credentials_rejected) | Probe jobs by how they ended. `credentials_rejected`: the browsers have no working login for the probe listener, because the control API gave no probe token (`POST /v1/probe/token` failed) or the listener answered the login with `407` (the token expired, or the gateway processes do not share the probe secret); nothing is reported, because the route was never reached, and the prober pauses and retries with a new token. `pool_failure`: browser setup or execution failed; the job is retried after a pause. `results_lost`: the measurements were taken but the control API took none. |
| `proxyx_pool_probe_last_posted_timestamp_seconds` | gauge | `kind` (canary, sample) | Unix time the prober last posted results to the control API. The canary series starts at the prober's start, so a prober that never posts still ages. |

Alerts: `ProxyXProberBlocked` (`credentials_rejected` or `results_lost` jobs, 10 minutes; critical), `ProxyXProberSilent` (no canary result for 3 hours, the canary interval being 1 hour; warning) and `ProxyXProberMissing` (the gauge has no series for 3 hours: the prober is down or not scraped; warning); see runbook 012.
