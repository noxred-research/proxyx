# Static IP replacement requested

## Symptom
`ProxyXIPReplaceRequested` (critical): `proxyx_pool_inventory_ips{state="replace_requested"} > 0` for 5 minutes. The warmer emits `pool_replacement_report` for each IP, then repeats the report once per 24 hours while replacement remains pending. The report contains provider, plan, IP, port, state age, reasons, scores, block evidence, probes, and rental end.

## Impact
The IP is no longer leased and does not meet ready-capacity targets. Replacing a rented IP requires provider/operator action; ProxyX cannot repair its reputation. Several pending replacements can trigger [003](003-cache-below-low-watermark.md).

## Diagnosis
Use [operator access](README.md#operator-access) to retrieve replacement evidence:

```sh
curl --fail-with-body -sS -H "Authorization: Bearer $TOKEN" \
  "$API/v1/inventory/replacements" | jq
```

Match the records with warmer `pool_replacement_report` logs. Reasons can include consecutive high-risk checks from enough independent scorers, a high blocked-target share across consecutive probes, excessive quarantine duration, or exhausted SIM-box reset attempts. Policy keys include `replace_after_checks`, `replace_min_sources`, `replace_blocked_share`, `replace_quarantine_for`, and `rotate_attempts`.

A route-class-wide blocked outage while the pool guard is active does not count toward the blocked-share replacement rule. Avoid replacing a whole pool for a transient provider or target failure.

## Mitigation
1. Ask the provider to replace the affected IP and record the new IP, host, port, plan, and rental date. Preserve the evidence needed for the replacement request.
2. Update the complete inventory for that provider through `PUT /v1/inventory/{provider}`, or edit its source under `PROXYX_POOL_DATA_DIR/inventory`. Remove the old entry and add the new one with the required routing and credential fields.
3. Do not submit only the new entry if other inventory must remain: this API replaces the provider list, and omitted entries are retired.
4. Allow the next reload and warmer checks. The old entry becomes `retired`; the replacement begins as `candidate` and must pass exit-IP, country, reputation, and quality checks before leasing.
5. If replacement is deferred, leave the IP in `replace_requested`. Do not force it back into service just to silence the alert; daily reports continue while it awaits action.

## Verification
```sh
curl --fail-with-body -sS -H "Authorization: Bearer $TOKEN" \
  "$API/v1/inventory?provider=<provider>" \
  | jq -r '.items[] | [.ip, .state] | @tsv'
```

The replacement reaches `available` or `leased`, the old entry is `retired`, and no unintended replacement requests remain:

```promql
max by (provider) (proxyx_pool_inventory_ips{state="replace_requested"}) == 0
```

## Escalation
A replacement stuck in `candidate` needs warmer check results: country mismatch, exit-IP disagreement, high risk, and connection failures. Request another IP if the replacement is unsuitable. An inventory update that never loads belongs in [007](007-config-reload-rejected.md); share the redacted entry and exact error with the operator.

## Alert
Rules: `ProxyXIPReplaceRequested` (critical), `ProxyXRotateFailing` (warning) in [`deploy/monitoring/prometheus-rules.yml`](../../deploy/monitoring/prometheus-rules.yml); see [monitoring](../monitoring.md#alert-reference).
