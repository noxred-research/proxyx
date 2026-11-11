# Provider cost budget at 90 percent

## Symptom
`ProxyXBudgetNearLimit` (critical): `proxyx_pool_cost_used_ratio{provider="<provider>"} >= 0.9` for 5 minutes. The ratio is the larger of daily traffic use and hourly create use against `cost.max_gb_per_day` and `cost.max_creates_per_hour`. It is capped at 1, even if actual use exceeds a limit.

## Impact
At 80 percent the warmer limits refill to `min_ready`, with one create at a time per region. Different regions can still create concurrently. At 100 percent, no new sessions are created until the relevant UTC hour or day resets. Existing cache capacity continues to serve; exhaustion can trigger [003](003-cache-below-low-watermark.md). An on-demand create may log `provider budget is used up, not creating a session`.

## Diagnosis
```promql
max by (provider) (proxyx_pool_cost_used_ratio)
sum by (cause) (rate(proxyx_pool_cache_evictions_total[1h]))
sum by (provider, outcome) (rate(proxyx_pool_warm_creates_total[1h]))
proxyx_pool_cache_sessions
```

Compare the current policy to expected traffic and the provider invoice. Include probe and keepalive traffic: the meter counts gateway and warmer bytes, and the provider's billing can differ. Inspect warmer logs for repeated eviction/create cycles involving keepalive, changed exit IPs, stability, quality, or reputation failures.

## Mitigation
1. Fix churn before adding creates. Replacing sessions that immediately fail again only consumes more budget.
2. If demand is legitimate and extra cost is approved, raise `max_gb_per_day` or `max_creates_per_hour` under `[policy.cost]` in the policy source, or submit an approved policy document to `PUT /v1/policies`. Keep the values within the configured ceilings; otherwise the configuration is rejected.
3. Wait for the default 30-second reload interval, or the configured `PROXYX_POOL_RELOAD_EVERY`, and confirm that the new policy loaded. Record emergency API changes in the source configuration; a later edit to the same source policy supersedes them.
4. If spending must remain capped, reduce demand or wait for the UTC window reset. Do not clear Redis meter keys to bypass the limit.

## Verification
```promql
max by (provider) (proxyx_pool_cost_used_ratio) < 0.9
sum by (provider) (rate(proxyx_pool_warm_creates_total{outcome="budget"}[5m]))
```

Budget refusals stop increasing when creates are allowed again. Check ready capacity and successful creates as well as the ratio.

## Escalation
A ratio that remains 1 after the relevant reset requires policy and meter investigation. A zero limit is exhausted immediately. Use [operator access](README.md#operator-access) to read `GET /v1/policies`; configuration failures belong in [007](007-config-reload-rejected.md). Escalate unexpected spend with traffic, churn, configured limits, and billing evidence, not secret-bearing logs.

## Alert
Rules: `ProxyXBudgetNearLimit` (critical) in [`deploy/monitoring/prometheus-rules.yml`](../../deploy/monitoring/prometheus-rules.yml); see [monitoring](../monitoring.md#alert-reference).
