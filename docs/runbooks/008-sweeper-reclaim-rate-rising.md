# Sweeper reclaim rate rising

## Symptom
`ProxyXSweeperRising` (critical): `increase(proxyx_pool_sweeper_reclaimed_total[15m]) >= 3` persists for 30 minutes for `kind="session"`, `reservation`, or `lease`. The warmer logs `sweeper reclaimed stuck state` with `partition`, `kind`, and `count`.

The 15-minute measurement window is shorter than the alert's 30-minute hold, so one deployment burst should not sustain the alert. Treat this threshold as an operational starting point to tune against observed churn, not a universal capacity limit.

## Impact
The sweeper reclaims state that no live operation owns, normally every 30 seconds. Capacity remains unavailable until its deadline expires. `session` includes creates beyond twice `create_deadline` and ready IDs without a unit record; `reservation` includes reservations beyond 120 seconds; `lease` includes expired per-connection leases not released by a gateway. Normal sticky-lease expiry is not counted.

Clients can see `lease_timeout`, `cache_empty`, or reduced capacity while leaked state waits for reclamation. Reclaims performed by lease scripts or gauge reads also contribute; this counter does not count only the sweep loop itself.

## Diagnosis
```promql
sum by (kind) (increase(proxyx_pool_sweeper_reclaimed_total[15m]))
sum by (provider, outcome) (rate(proxyx_pool_warm_creates_total[15m]))
histogram_quantile(0.95, sum by (le, provider, stage) (rate(proxyx_pool_dial_duration_seconds_bucket[5m])))
max(proxyx_pool_redis_down)
```

Check process crashes, memory exhaustion, forced restarts, host loss, Redis failovers, and provider latency at the time reclaims increased. Use `kubectl describe pod <pod>` and workload logs, or systemd status and journal logs, according to the [operator access guide](README.md#operator-access).

## Mitigation
1. For `session`, investigate warmer restarts and slow or failing provider creates. Use [004](004-provider-breaker-open.md) for provider failures.
2. For `reservation`, inspect gateways that stopped between reserving and finishing a create.
3. For `lease`, inspect gateways killed with open tunnels. Normal sticky session expiry alone is not a leak.
4. Fix crash loops, memory limits, premature service termination, or Redis instability. Allow the configured `PROXYX_POOL_DRAIN_TIMEOUT` plus shutdown margin before a supervisor sends a forced kill. On Kubernetes, include any pre-stop delay in `terminationGracePeriodSeconds`; on systemd, size `TimeoutStopSec` accordingly.
5. Let the sweeper reclaim abandoned state. Do not delete reservation or lease keys manually. After empty-cache recovery, allow the warmer to finish rebuilding from PostgreSQL; see [001](001-redis-down.md).

## Verification
For a full measurement window:

```promql
sum by (kind) (increase(proxyx_pool_sweeper_reclaimed_total[15m])) < 3
```

Confirm that unplanned restarts stopped and the ready cache recovered. A one-time recovery burst should age out without recurring.

## Escalation
Sustained reclaims with stable processes and a healthy provider need investigation as a state leak. Preserve timestamped sweeper lines, partition values, kind counts, process termination reasons, and recent deploy details. A concentration in one partition narrows the investigation to one provider/region.

## Alert
Rules: `ProxyXSweeperRising` (critical) in [`deploy/monitoring/prometheus-rules.yml`](../../deploy/monitoring/prometheus-rules.yml); see [monitoring](../monitoring.md#alert-reference).
