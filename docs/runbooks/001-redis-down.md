# Redis down

## Symptom
`ProxyXRedisDown` (critical): `proxyx_pool_redis_down == 1` on a gateway or warmer for more than 5 minutes. New CONNECT/SOCKS5 connections fail with `cache_unavailable`. Gateway logs include `redis call failed` or `redis call timed out`; warmer logs may include `failed to reconcile the partition`, `failed to sweep the partition`, or `failed to check the redis seed marker`.

## Impact
Redis holds leases, ready sets, sessions, per-IP tunnel counters, cooldowns, and cost meters. The gateway refuses new leases while Redis is unavailable; already open tunnels continue. The warmer cannot refill or sweep the cache. PostgreSQL still holds durable inventory, policies, org keys, and audit records.

## Diagnosis
Use the [operator access guide](README.md#operator-access) to inspect gateway and warmer logs. Check Redis service health, memory, persistence, failover events, and connectivity from both roles. Common causes include a stopped process, memory exhaustion, storage errors, blocked TCP port 6379, or changed credentials.

```promql
max by (service) (proxyx_pool_redis_down)
sum(rate(proxyx_pool_connections_total{outcome="cache_unavailable"}[5m]))
```

If `proxyx_pool_redis_down` is 0 but clients see `lease_timeout`, investigate lease pressure instead. Redis may be answering while leases wait for capacity; clients that generate a new sticky `sid` for every request can amplify that pressure.

## Mitigation
1. Restore Redis availability before restarting healthy ProxyX processes. Resolve memory, disk, failover, or network failures at the Redis service.
2. Confirm `PROXYX_POOL_REDIS_URL` in the gateway and warmer matches the active Redis endpoint and credentials. For `rediss://`, check certificate trust and hostname validation without logging the URL or password.
3. If connection settings changed, restart the affected roles using the commands in the operator access guide. Avoid restarting all gateways unnecessarily, because that closes client tunnels after their drain period.
4. If Redis returns empty, let the warmer rebuild it from PostgreSQL. It detects the missing seed marker and retries rebuilding, logging `failed to rebuild redis from postgres, retrying` if the rebuild fails. Lost leases and rotating sessions require clients to reconnect. Do not copy stale hot-state keys back into the recovered cache.

## Verification
For 10 minutes, both roles report `proxyx_pool_redis_down == 0`, and the rate of `cache_unavailable` refusals is 0. Confirm readiness on port 8888 and that the warmer refills the ready cache.

## Escalation
If Redis answers but ProxyX still reports failures, collect timestamped errors from one affected process, endpoint reachability results, and TLS errors with secrets removed. Escalate to the Redis operator. Sustained reclaim activity after recovery belongs in [008: sweeper reclaim rate rising](008-sweeper-reclaim-rate-rising.md).

## Alert
Rules: `ProxyXRedisDown` (critical) in [`deploy/monitoring/prometheus-rules.yml`](../../deploy/monitoring/prometheus-rules.yml); see [monitoring](../monitoring.md#alert-reference).
