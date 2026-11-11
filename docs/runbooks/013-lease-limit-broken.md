# Lease limit broken

## Symptom
`ProxyXLeaseLimitBroken` (warning): `proxyx_pool_lease_limit_broken_total{limit=~"max_conns|fair_use"}` increases by at least 10 in a 10-minute window, with that condition persisting for 30 minutes on one provider. The other soft-limit labels, `rest` and `orgs_hard`, are not part of this alert.

## Impact
The gateway makes a last-resort lease instead of stalling an org when no provider has a unit within its soft limits. `max_conns` increases load and block risk on an IP; `fair_use` can cause provider throttling or extra charges.

Breaking `max_conns_per_ip` still has a hard ceiling: the lower of twice the policy limit and the adapter's provider limit. Units at that ceiling are not leased; if every unit is there, requests wait and can fail with `lease_timeout`.

## Diagnosis
```promql
sum by (limit, provider) (increase(proxyx_pool_lease_limit_broken_total[30m]))
max by (provider, state) (proxyx_pool_inventory_ips)
sum by (provider) (increase(proxyx_pool_fair_use_exceeded_total[30d]))
```

Check whether the pool is undersized, IPs were cooled or removed, or the first-priority provider carries demand while fallback capacity is also constrained. The walk tries normal then degraded units within limits before breaking any limit. Soft limits break in order: `rest`, `orgs_hard`, `max_conns`, then `fair_use`; normal units precede degraded ones within a break pass.

## Mitigation
1. Recover cooled or quarantined capacity using [010](010-pool-cooled.md), and handle replacement requests using [009](009-ip-replace-requested.md). For low cache, use [003](003-cache-below-low-watermark.md).
2. For `max_conns` on an otherwise healthy pool, add inventory or reduce demand. Raise policy `max_conns_per_ip` only after confirming the provider's supported limit. When unset, the policy uses 80 percent of the adapter's limit. Keep the adapter's hard ceiling accurate.
3. Adding a fallback provider does not imply equal load balancing: providers are walked in policy priority order, and later providers serve when earlier ones cannot meet the current pass's constraints.
4. For `fair_use`, compare `cost.fair_use_gb_per_ip_month` with the purchased plan and actual provider accounting. Add IPs, use approved alternative providers, or correct an understated allowance. Monthly usage resets at the start of the UTC month; do not clear counters to avoid the allowance.
5. If a deliberate load test fills the pool, stop or reduce that test before changing production policy. One short burst should not sustain the 30-minute alert hold.

## Verification
```promql
sum by (limit, provider) (increase(proxyx_pool_lease_limit_broken_total{limit=~"max_conns|fair_use"}[10m])) < 10
```

Check that throughput remains healthy and `lease_timeout` refusals do not replace the soft-limit breaks. Tune this starting alert threshold to observed operating load, not merely to silence sustained pressure.

## Escalation
If breaks continue while inventory appears available, inspect target-specific cooldowns and recently failed IPs. IP-level failures rank a unit behind other choices for 10 seconds, doubling up to 5 minutes until a successful tunnel clears the penalty. For one affected org, inspect its policy and route-class caps through `GET /v1/policies` using [operator access](README.md#operator-access). Provide provider/limit breakdowns and concurrency evidence.

## Alert
Rules: `ProxyXLeaseLimitBroken` (warning) in [`deploy/monitoring/prometheus-rules.yml`](../../deploy/monitoring/prometheus-rules.yml); see [monitoring](../monitoring.md#alert-reference).
