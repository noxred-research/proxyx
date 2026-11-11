# Provider breaker open

## Symptom
`ProxyXProviderBreakerOpen` (critical): `proxyx_pool_provider_breaker_state{provider="<provider>"} == 2` for 5 minutes. Warmer creates accumulate `outcome="breaker"`; gateway walks can increase `proxyx_pool_breaker_skips_total` without attempting a create.

## Impact
The affected provider/region route class stops normal creates and dials until a recovery probe is due. Policy fallback can serve through another allowed provider or kind. Without fallback, the cache drains and tunnels fail; see [003: cache below the low watermark](003-cache-below-low-watermark.md).

## Diagnosis
The breaker opens after 5 provider failures in 60 seconds. Warmer create failures and gateway tunnels that fail on the provider contribute; a retry successfully served by another IP of the same provider does not charge a provider failure. An IP rejected by admission checks does not itself make the provider unavailable.

Inspect warmer logs for `session create failed` and `session create is misconfigured`, and distinguish expired credentials, provider refusal, connection timeout, and admission rejection.

```promql
max by (provider) (proxyx_pool_provider_breaker_state)
sum by (provider) (rate(proxyx_pool_breaker_skips_total[5m]))
histogram_quantile(0.95, sum by (le, provider, stage) (rate(proxyx_pool_dial_duration_seconds_bucket[5m])))
sum by (outcome) (rate(proxyx_pool_connections_total{outcome=~"provider_.*|upstream_error"}[5m]))
```

## Mitigation
1. For `provider_auth` or HTTP 407, check the provider account and credential files named by the adapter. Correct expired or mismatched credentials; restart affected roles if the credential is read at startup.
2. For timeouts or unavailability, check the provider status and account limits. Test DNS and TCP reachability from the affected gateway and warmer. Inspect local firewall and egress policy rather than assuming every public destination is allowed.
3. Let the breaker probe automatically after the provider recovers. Its first wait is 5 seconds; repeated failures double the delay up to 5 minutes. Three successful probes close it. Probes require work or traffic, so allow for idle route classes.
4. If immediate retry is necessary after a confirmed repair, an authorized Redis operator can remove only the affected route class's breaker hash and failure set. These keys are shared across all gateways and warmers; restarting a process does not reset them. Do not flush Redis or delete a provider-wide wildcard.

```sh
redis-cli -u "$PROXYX_POOL_REDIS_URL" DEL \
  'breaker:{<provider>:<region>}' 'breaker:{<provider>:<region>}:fails'
```

Run this from a trusted administrative host with the existing Redis credential available. The command exposes the URL to the process argument list; use your Redis client's protected credential mechanism where required.

## Verification
```promql
max by (provider) (proxyx_pool_provider_breaker_state) == 0
sum by (outcome) (rate(proxyx_pool_warm_creates_total{provider="<provider>"}[15m]))
```

Successful creates resume without sustained `breaker` or `failed` outcomes. Check that successful connections use the repaired provider rather than only fallback capacity.

## Escalation
A repeatedly reopening breaker needs provider errors, affected regions, and dial latency evidence. Misconfigured adapter recipes or option charsets belong in [007](007-config-reload-rejected.md). For a prolonged outage, remove the provider from the policy's allowed `providers` list only after confirming that fallback capacity can carry the load.

## Alert
Rules: `ProxyXGatewayProviderUnavailable` (warning), `ProxyXGatewayDialSlow` (warning), `ProxyXProviderBreakerOpen` (critical), `ProxyXWarmCreatesFailing` (warning) in [`deploy/monitoring/prometheus-rules.yml`](../../deploy/monitoring/prometheus-rules.yml); see [monitoring](../monitoring.md#alert-reference).
