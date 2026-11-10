# Prober not reporting

## Symptom
- `ProxyXProberBlocked` (critical): jobs with `outcome="credentials_rejected"` or `outcome="results_lost"` increased over 30 minutes, with the condition persisting for 10 minutes.
- `ProxyXProberSilent` (warning): `time() - proxyx_pool_probe_last_posted_timestamp_seconds{kind="canary"}` exceeds 3 hours. The default canary interval is 1 hour; the timestamp starts at process startup, so a process that never posts can still become silent.
- `ProxyXProberMissing` (warning): the canary timestamp series is absent for 3 hours. This covers a stopped or unscraped prober; the silence expression cannot fire without a series.

## Impact
Missing reports remove canary and browser-sample verdicts. Broken route classes may not be drained, and sampled candidates remain unjudged. Customer tunnels are not directly interrupted by the prober stopping. Failed probe authentication is deliberately not posted as a failed route verdict: it says nothing about the provider's health.

## Diagnosis
```promql
sum by (outcome) (increase(proxyx_pool_probe_jobs_total[1h]))
time() - max(proxyx_pool_probe_last_posted_timestamp_seconds{kind="canary"})
absent(proxyx_pool_probe_last_posted_timestamp_seconds{kind="canary"})
```

Inspect the `python -m proxyx_prober` process or its supervisor logs. Relevant messages include `probe token unavailable`, `probe token refused`, `probe results lost`, and `probe targets unavailable`.

- `credentials_rejected`: the control API could not issue a token, or the probe CONNECT listener returned 407. Tokens last 30 minutes; gateway replicas must share the signing secret.
- `results_lost`: the control API accepted none of a measured job's results. Check HTTP status, API reachability, and the prober bearer token.
- `pool_failure`: browser startup, connection, or execution failed. Check the standalone browser installation and resource availability; this outcome name does not require a separate browser service.
- Silent or missing without those outcomes: inspect the prober process, target list, and Prometheus scrape target.

## Mitigation
1. Check `PROXYX_PROBER_API_URL` and `PROXYX_PROBER_API_TOKEN_FILE`. The latter must contain the bearer token configured as `prober-token` under the gateway's `PROXYX_POOL_SECRETS_DIR`. The admin token does not authorize `/v1/probe/*`.
2. Check `PROXYX_PROBER_PROXY_URL` points to the gateway's probe listener, default port 8082, and that the prober can reach both that port and the control API on 8081.
3. For `probe token unavailable`, verify every gateway has a readable `PROXYX_POOL_PROBE_KEY_FILE` (default `/etc/proxyx/secrets/probe-key`). The gateway reads this signing secret at startup. The prober does not need or mount it.
4. For `probe token refused`, compare protected checksums of that file across gateway replicas. Complete any partial credential rollout and restart stale replicas. Do not expose the secret itself in logs or reports.
5. Restore a stopped prober or its browser runtime. For a missing series with a running process, check its metrics endpoint (default port 8081) and scrape configuration. This is a different process from the gateway API even though both default to 8081.

### Probe signing-secret rotation
Distribute the new `PROXYX_POOL_PROBE_KEY_FILE` securely to all gateways, then restart them in a coordinated rollout. Old tokens stop working on gateways using the new secret; mixed old/new replicas can briefly reject each other's tokens. The prober fetches a fresh token on its next attempt. This secret signs restricted probe tokens and is not an org key.

### A probe page needs another host
The listener permits configured target hosts and `extra_hosts` from `PROXYX_POOL_DATA_DIR/probe-targets.toml`, on ports 80 and 443. If a redirect or asset host fails with `destination_denied`, add only the required host to `extra_hosts` and let configuration reload. Subdomains are included. Confirm the refusal using `proxyx_pool_connections_total{listener="probe",outcome="destination_denied"}`.

## Verification
```promql
sum by (outcome) (increase(proxyx_pool_probe_jobs_total{outcome=~"credentials_rejected|results_lost"}[30m])) == 0
time() - max(proxyx_pool_probe_last_posted_timestamp_seconds{kind="canary"}) < 3600
```

Allow old errors to age out of the window and wait for the next scheduled canary. Confirm the timestamp series is present, jobs post results, and no auth failures are being misreported as unhealthy routes.

## Escalation
Provide job outcomes, redacted HTTP errors, target-list availability, listener reachability, scrape status, browser startup errors, and whether gateway signing-secret checksums match. Persistent 407s with valid fresh tokens usually require checking the particular gateway serving the probe listener against the gateway that signed the token.

## Alert
Rules: `ProxyXProberScrapeDown` (warning), `ProxyXProberBlocked` (critical), `ProxyXProberSilent` (warning), `ProxyXProberMissing` (warning) in [`deploy/monitoring/prometheus-rules.yml`](../../deploy/monitoring/prometheus-rules.yml); see [monitoring](../monitoring.md#alert-reference).
