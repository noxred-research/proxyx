# Deploy and rollback with forward-only migrations

## Symptom
A deployment fails migration checks, a newly started gateway never becomes ready, or an older image cannot load the current snapshot after an image rollback. Logs can include `configuration reload failed, keeping the last good one`, `failed to load the snapshot`, or a migration recorded in the database but missing from the binary's embedded migration set.

There is no dedicated deployment alert. Inspect readiness and `proxyx_pool_postgres_down`, `proxyx_pool_snapshot_age_seconds`, and `proxyx_pool_config_reload_failed`. An incompatible stored state is not necessarily classified as a configuration rejection; a zero rejection gauge does not prove compatibility.

## Impact
ProxyX migrations move forward. An old binary can reject a schema, migration history, or stored value written by a newer release. A running process may retain a frozen last-good snapshot; a fresh incompatible process cannot finish loading. Redis leases can mask this while some new connections still succeed.

A concrete compatibility boundary is `crates/store/migrations/20261019000001_degraded_state.sql`: it allows `degraded` inventory state. Code that cannot parse that state is not a safe rollback target after a new warmer or probe result writes it.

## Diagnosis
1. Identify the exact current and proposed image versions for every writer and reader: gateways, warmers, and any prober involved in state transitions. Inspect the embedded pool migrations in `crates/store/migrations` and the control migration implementation in `crates/control/src/migrations.rs`.
2. Check database connectivity and inspect migration output before changing images. Do not interpret every migration error as a failed database service.
3. Run checks using the release binary and its normal environment/configuration:

```sh
proxyx migrate pool --check
proxyx migrate control --check
```

The pool check lists pending migrations and exits nonzero when any remain. It is read-only and does not prove that an older binary understands newer stored values, nor that the database contains no migrations unknown to that binary. Check compatibility separately.

## Mitigation
### Deploy forward
1. Preserve a tested recovery path and current backups for each affected durable store. Review release schema and state changes before allowing new writers to run. Coordinate incompatible reader/writer changes; do not run an old gateway beside a warmer that writes states the gateway cannot parse.
2. Apply pool migrations with the new release binary, then check again:

```sh
proxyx migrate pool
proxyx migrate pool --check
```

3. If the release changes the control plane stores, use its corresponding command and check. The default control target covers PostgreSQL, ClickHouse, and broker setup where supported; use the deployment's normal configuration:

```sh
proxyx migrate control
proxyx migrate control --check
```

4. Start the intended gateway and warmer release through the normal supervisor. On Kubernetes, set approved images and inspect `kubectl -n <namespace> rollout status deployment/<deployment>`. On systemd, install the approved binary and restart the configured `proxyx-gateway` and `proxyx-warmer` units. These unit/deployment names are examples, not installed resources provided by the CLI.
5. Respect `PROXYX_POOL_DRAIN_TIMEOUT` and supervisor shutdown margins so replacing gateways can finish open tunnels rather than forcing them closed early.

### Roll an image back
1. Prefer a fixed newer image when the older binary is incompatible with the migrated database.
2. Roll back only to a version demonstrated to read the current schema, migration history, and stored values. Check application parsers as well as migration SQL. A successful `--check` alone is insufficient.
3. Stop incompatible writers before any coordinated recovery that requires them stopped. Preserve compatible serving processes where safe; avoid a mixed fleet that keeps writing unreadable state.
4. Do not delete rows from `_sqlx_migrations`, undo constraints by hand, or relabel current data merely to make an old image start. Such changes hide migration history and are not an image rollback. If no compatible image exists, restore the compatible release or perform an explicitly planned database recovery with the database operator, including the consistency impact on Redis and other stores.

## Verification
Check each role, not only a load-balanced endpoint:

```sh
curl --fail-with-body -sS http://127.0.0.1:8888/healthz
curl --fail-with-body -sS http://127.0.0.1:8888/readyz
curl --fail-with-body -sS http://127.0.0.1:8888/metrics
proxyx migrate pool --check
proxyx migrate control --check
```

Use [operator access](README.md#operator-access) for remote endpoints. Confirm successful inventory reads, a fresh snapshot, successful representative tunnels, resumed warming, and no repeated snapshot-load errors. Observe `proxyx_pool_tunnels_open` during gateway drain. Liveness alone is insufficient: `/healthz` answers during startup, while `/readyz` can still report `starting` or `draining`.

## Escalation
Provide release versions, embedded/applied migration versions, exact migration and snapshot-load errors, readiness state, and which writers remain active. Escalate schema compatibility or recovery decisions to the database and release operators. For invalid source input rather than release incompatibility, use [007](007-config-reload-rejected.md).

## Alert
Rules: `ProxyXGatewayDown` (critical), `ProxyXSnapshotStale` (warning) in [`deploy/monitoring/prometheus-rules.yml`](../../deploy/monitoring/prometheus-rules.yml); see [monitoring](../monitoring.md#alert-reference).
