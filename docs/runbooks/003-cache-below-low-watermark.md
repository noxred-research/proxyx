# Cache below the low watermark

## Symptom
`ProxyXCacheLow` (critical): `proxyx_pool_cache_low{tier="all"} == 1` for a provider and kind. The warmer sets this after leasable normal and degraded units remain below the effective `low_watermark` for `low_for` (default 2 minutes). A warmer restart restarts this timer. No additional alert delay is required.

The default watermark is half of `min_ready`, summed over the provider's regions. `tier="normal"` at 1 while `tier="all"` is 0 means degraded capacity still serves; it is not the all-capacity alert.

## Impact
New tunnels fail with `cache_empty` or `no_healthy_ip` when capacity runs out. Rotating requests may wait for a new create according to the policy's `on_empty` behavior. Slow, degraded units remain leasable after normal units.

## Diagnosis
```promql
proxyx_pool_cache_low{provider="<provider>"}
sum by (kind, provider) (proxyx_pool_cache_ready)
max by (kind, provider) (proxyx_pool_cache_low_watermark)
max by (provider, state) (proxyx_pool_inventory_ips)
sum by (provider, outcome) (rate(proxyx_pool_warm_creates_total[15m]))
sum by (cause) (rate(proxyx_pool_cache_evictions_total[1h]))
```

For static inventory, use [operator access](README.md#operator-access):

```sh
curl --fail-with-body -sS -H "Authorization: Bearer $TOKEN" \
  "$API/v1/inventory?provider=<provider>" \
  | jq -r '.items[] | [.ip, .state, .state_since] | @tsv'
```

## Mitigation
1. For static IPs, identify which states removed capacity:
   - `cooldown` or `quarantined`: use [010: pool cooled](010-pool-cooled.md). Retests continue even when a failed canary pauses rotating warming. Provider-wide upstream refusals or exit-IP disagreement while at least half the route class rests do not count toward quarantine; outage retests use breaker probe spacing instead of the full static cooldown.
   - `degraded`: still leasable. Clean but slow checks demote an IP; a later full-speed check restores it. A slow-only canary degrades the route class, while a blocked or errored canary drains it. A passing canary restores the degraded class.
   - `replace_requested`: follow [009: IP replacement requested](009-ip-replace-requested.md).
   - `candidate` or `offline`: inspect warmer checks, provider reachability, and any SIM-box health. These states continue to be checked during a canary pause.
2. If inventory is genuinely too small, rent capacity and update the provider's complete inventory document or its files under `PROXYX_POOL_DATA_DIR/inventory`. Omitted entries are retired; do not accidentally replace a provider list with only the new IP.
3. For rotating capacity, `outcome="breaker"` points to [004](004-provider-breaker-open.md); `outcome="budget"` points to [005](005-provider-budget-at-90-percent.md). Inspect warmer errors for `failed` creates, admission rejections, or misconfigured adapters. Fix Redis failures using [001](001-redis-down.md).
4. If the intended capacity changed, update `low_watermark` in the policy source under `PROXYX_POOL_DATA_DIR/policies` or through the control API. It must not exceed `min_ready`. Do not lower it only to silence a genuine shortage.

## Verification
`proxyx_pool_cache_low{tier="all"}` returns to 0. Ready capacity reaches the effective watermark, and `proxyx_pool_connections_total` stops accumulating `cache_empty` and `no_healthy_ip` outcomes.

## Escalation
If the warmer is healthy, the breaker is closed, and no creates run, inspect partition ownership and warmer logs. Partition locks expire; a controlled warmer restart can recover a stuck worker. For provider supply exhaustion, escalate with region, requested capacity, and create errors. Document any temporary capacity reduction.

## Alert
Rules: `ProxyXWarmerDown` (critical), `ProxyXGatewayNoCapacity` (warning), `ProxyXCacheLow` (critical), `ProxyXCacheBelowMinReady` (warning) in [`deploy/monitoring/prometheus-rules.yml`](../../deploy/monitoring/prometheus-rules.yml); see [monitoring](../monitoring.md#alert-reference).
