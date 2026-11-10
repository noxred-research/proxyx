# Block signals dropped

## Symptom
`ProxyXBlockSignalsDropped` (warning): for 10 minutes, the preceding 30-minute window contains at least 10 ignored events, and ignored events exceed half of all client block-signal events. Compare `proxyx_pool_block_signals_ignored_total` with applied `proxyx_pool_block_signals_total{source="client"}`. `POST /v1/block-signals` can return HTTP 200 with `{"accepted": n, "ignored": m}` even when some events were ignored.

## Impact
An ignored event cools no IP. The reporting session proxy or other client may continue receiving blocked pages until another probe, canary, or operator reports the IP. Ignored-event counts are not the same as authentication failures or a rejected whole batch.

## Diagnosis
```promql
sum(increase(proxyx_pool_block_signals_ignored_total[30m]))
sum by (source, scope) (increase(proxyx_pool_block_signals_total[30m]))
max(proxyx_pool_redis_down)
```

An event is ignored if it is older than an hour, its session no longer exists in Redis, it belongs to another org, its exit IP differs from the gateway's session record, or its provider adapter is no longer loaded. Inspect event timestamps, session identifiers, and the `X-ProxyX-Exit-IP` reported for that session without putting raw customer identifiers in metric labels.

The endpoint authenticates with HTTP Basic and the org key as password, not the admin bearer token. Compare `accepted` and `ignored` from successful replies; a 401, 429, invalid batch, or 5xx needs its own request-level investigation.

## Mitigation
1. If Redis was recently lost or rebuilt, allow clients to reopen tunnels and obtain current sessions; use [001](001-redis-down.md).
2. With healthy Redis, compare the client's session lifetime with policy `rotating.ready_ttl` and `rotating.max_age`. Stop replaying stale batches and use the actual exit IP from the gateway's response for the matching session.
3. Check clocks and timestamp units on the reporting client. The event field is Unix seconds; old events are intentionally ignored.
4. Verify the sending org matches the session owner and that the route's provider still has a loaded adapter. Fix mismatched session ownership or configuration rather than bypassing validation.
5. If urgent containment is needed, an authorized operator can call `POST /v1/ips/{ip}/block` using [operator access](README.md#operator-access). A rotating IP also needs its current session identifier; an inventory IP can be looked up directly.

## Verification
Over the next 30-minute window, ignored events fall below 10 or below half of all client events. For the latter comparison, use ignored / (ignored + applied), not ignored / applied. Confirm successful current-session reports return nonzero `accepted` counts and no unexpected ignores.

## Escalation
Preserve redacted request/reply samples, event age, configured session lifetimes, recent Redis-loss times, and affected org ownership evidence. The API returns aggregate counts, not a reason for each event; do not claim a per-event cause from the reply alone. Genuine widespread cooling belongs in [010](010-pool-cooled.md).

## Alert
Rules: `ProxyXBlockSignalsDropped` (warning) in [`deploy/monitoring/prometheus-rules.yml`](../../deploy/monitoring/prometheus-rules.yml); see [monitoring](../monitoring.md#alert-reference).
