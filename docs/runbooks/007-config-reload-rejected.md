# Configuration reload rejected

## Symptom
`ProxyXConfigRejected` (critical): `proxyx_pool_config_reload_failed{source="<source>"} == 1` for 5 minutes. Sources are `adapters`, `probe_targets`, `policies`, and `inventory`. Logs identify the source and validation failure; reload failures can include `configuration reload failed, keeping the last good one` or `configuration reload timed out, keeping the last good one`.

## Impact
The process retains its previous good configuration, so the proposed change has no effect. A fresh process with invalid initial configuration cannot finish loading and become ready. A rolling deployment can stall while old replicas continue serving.

## Diagnosis
Inspect gateway and warmer logs using the [operator access guide](README.md#operator-access). Correlate the first error with changes to `PROXYX_POOL_DATA_DIR`, credential files under `PROXYX_POOL_SECRETS_DIR`, or control API writes.

Check for unknown fields, duplicate entries, invalid rental dates, missing credential files, adapter values outside a declared charset, `min_ready` above `max_ready`, `low_watermark` above `min_ready`, and policy values above their ceilings.

```promql
max by (source) (proxyx_pool_config_reload_failed)
max(proxyx_pool_snapshot_age_seconds)
max(proxyx_pool_postgres_down)
```

A failed database connection is not proof of invalid input; investigate it using [002](002-postgres-down.md).

## Mitigation
1. Fix or revert only the offending source document or credential file. Preserve the last known good data and record what changed.
2. For source configuration, update the files mounted or installed at `PROXYX_POOL_DATA_DIR`. The default reload interval is 30 seconds. Do not depend on a particular configuration delivery controller to restart processes.
3. For an emergency API change, resend the last good document to `PUT /v1/policies` or `PUT /v1/inventory/{provider}`, as appropriate. The inventory route replaces that provider's complete list; do not send only the changed entry.
4. If a rollout is stuck, restore valid input before restarting or replacing more replicas. A restart with the same invalid initial state does not fix it.
5. If logs show a timeout rather than a parse or validation error, inspect database latency and availability before changing valid policy values.

## Verification
```promql
max by (source) (proxyx_pool_config_reload_failed) == 0
max(proxyx_pool_snapshot_age_seconds) < 60
```

Adjust snapshot age for a non-default reload interval. Check `/readyz` on port 8888 for every role and confirm the intended configuration through the control API. A clean log alone is insufficient if the source was never reloaded.

## Escalation
Collect the exact validation error, source name, redacted document diff, and whether a process already had a good snapshot. If normal logs hide the cause, enable `RUST_LOG=debug` on one controlled instance and inspect the error chain without publishing credential values. Deployment compatibility failures belong in [014](014-deploy-and-rollback.md).

## Alert
Rules: `ProxyXConfigRejected` (critical) in [`deploy/monitoring/prometheus-rules.yml`](../../deploy/monitoring/prometheus-rules.yml); see [monitoring](../monitoring.md#alert-reference).
