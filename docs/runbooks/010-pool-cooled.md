# Pool cooled

## Symptom
`ProxyXPoolCooled` (warning): at least half of a provider's usable static IPs stay in `cooldown` or `quarantined` for 10 minutes. The alert condition divides those states by `available + leased + degraded + cooldown + quarantined` from `proxyx_pool_inventory_ips`. `proxyx_pool_block_signals_total{scope="pool_guard"}` may increase.

The suggested alert threshold is 0.5. The policy's `block.max_cooldown_share` defaults to 0.5 but can differ; changing the guard does not automatically change an external alert rule.

## Impact
Cooled and quarantined IPs are not leased until recovery. The pool guard stops further IP-wide escalation when too much of the class rests; subsequent signals cool only their own target. This protects remaining capacity from a flood of block signals, but shortages can still trigger [003](003-cache-below-low-watermark.md).

## Diagnosis
```promql
sum by (source, type, scope) (rate(proxyx_pool_block_signals_total[30m]))
max by (provider, state) (proxyx_pool_inventory_ips{provider="<provider>"})
```

Use [operator access](README.md#operator-access) to inspect state ages and retest times:

```sh
curl --fail-with-body -sS -H "Authorization: Bearer $TOKEN" \
  "$API/v1/inventory?provider=<provider>" \
  | jq -r '.items[] | select(.state=="cooldown" or .state=="quarantined") | [.ip, .state, .state_since, .cooldown_until, .retest_at] | @tsv'
```

Distinguish genuine target blocks from an invalid probe target, a faulty client detector, or a provider outage. Provider-wide connection refusals or exit-IP disagreement while at least half the route class rests do not increase quarantine counts; outage retests use breaker probe spacing rather than the full static cooldown.

## Mitigation
1. For `source="client"`, inspect the reporting client's target and block evidence. Reduce traffic to a genuinely blocking target. An authorized operator can use `POST /v1/org-blocks` to stop a specific org/scope; it also asks matching open tunnels to close.
2. For `probe` or `canary`, check the configured pages in `PROXYX_POOL_DATA_DIR/probe-targets.toml`. Fix stale targets or broad challenge pages rather than treating every IP as individually bad.
3. For `operator`, inspect the audit record of `POST /v1/ips/{ip}/block` before undoing a deliberate intervention.
4. Inspect warmer cooldown, quarantine, and retest logs. Static retests continue during a canary pause; default cooldown is 15 minutes, with retest timing controlled by policy.
5. If observed traffic shows the policy is too sensitive, review `block.escalate_targets`, `block.escalate_signals`, `block.signal_window`, and `static.cooldown`. Do not widen `block.max_cooldown_share` merely to hide the symptom.

## Verification
```promql
sum by (provider) (max by (provider, state) (proxyx_pool_inventory_ips{state=~"cooldown|quarantined"}))
  / sum by (provider) (max by (provider, state) (proxyx_pool_inventory_ips{state=~"available|leased|degraded|cooldown|quarantined"})) < 0.5
```

Confirm the guard signal rate falls and recovered IPs serve traffic. `degraded` units count as usable; an IP with open leases is counted once as `leased`.

## Escalation
For IPs that progress to `replace_requested`, use [009](009-ip-replace-requested.md). Persistent cooling at normal load needs source/type/target evidence and provider reachability results. For ignored client reports, use [011](011-block-signals-dropped.md).

## Alert
Rules: `ProxyXPoolCooled` (warning) in [`deploy/monitoring/prometheus-rules.yml`](../../deploy/monitoring/prometheus-rules.yml); see [monitoring](../monitoring.md#alert-reference).
