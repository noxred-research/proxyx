# PostgreSQL down

## Symptom
`ProxyXPostgresDown` (critical): `proxyx_pool_postgres_down == 1` for more than 10 minutes. Gateway or warmer logs include `configuration reload failed, keeping the last good one`, `failed to read the inventory for gauges`, or `failed to read the inventory, keeping the last state`. `proxyx_pool_snapshot_age_seconds` rises beyond the normal reload interval, which defaults to 30 seconds.

A connectivity failure is not a rejected configuration. Do not expect `ProxyXConfigRejected` to identify a database outage.

## Impact
Processes with a loaded snapshot retain the last good policies, inventory, and org-block state and can continue leasing from Redis. Configuration changes and inventory state persistence stop. Database-backed control API operations fail, and inventory gauges and replacement decisions become stale. A fresh process cannot finish its initial snapshot load.

## Diagnosis
Inspect database health, primary selection, available connections, disk space, transaction logs, and connectivity from the gateway and warmer. Check the configured `PROXYX_POOL_DATABASE_URL` without exposing its password. A failover, blocked TCP port 5432, changed credentials, or database connection exhaustion can produce these symptoms.

```promql
max by (service) (proxyx_pool_postgres_down)
max(proxyx_pool_snapshot_age_seconds)
```

Use the [operator access guide](README.md#operator-access) for process logs and API access. Check whether failures affect all replicas or only one host.

## Mitigation
1. Restore database connectivity or resolve the database resource failure. Follow the database service's own recovery procedure for disk exhaustion or failed failover.
2. If the connection URL or credential changed, update the gateway and warmer settings and restart only affected roles after connectivity returns.
3. Preserve healthy processes serving their last good snapshot during the outage. Do not repeatedly submit configuration writes: failed writes are not queued for later application.
4. After a backup restore, reconcile the durable inventory with the intended configuration. Redis may describe newer state than the restored database. Restart the warmer if reconciliation remains stuck, and let lease TTLs and the sweeper reclaim abandoned state rather than deleting keys manually.

## Verification
```promql
max by (service) (proxyx_pool_postgres_down) == 0
max(proxyx_pool_snapshot_age_seconds) < 60
```

Adjust the snapshot-age expectation if `PROXYX_POOL_RELOAD_EVERY` is not its 30-second default. Confirm a successful control API read:

```sh
curl --fail-with-body -sS -H "Authorization: Bearer $TOKEN" "$API/v1/inventory"
```

## Escalation
Provide database connection errors, service health, failover events, and the time of the last successful snapshot to the database operator. If connectivity is restored but reloads still fail validation, use [007: configuration reload rejected](007-config-reload-rejected.md).

## Alert
Rules: `ProxyXPostgresDown` (critical), `ProxyXPoolAPIErrors` (warning) in [`deploy/monitoring/prometheus-rules.yml`](../../deploy/monitoring/prometheus-rules.yml); see [monitoring](../monitoring.md#alert-reference).
