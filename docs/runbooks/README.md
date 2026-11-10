# ProxyX pool runbooks

These runbooks cover the pool gateway, warmer, control API, and standalone prober. Metric definitions are in [pool metrics](../metrics/pool.md); session proxy and control plane metrics are in [session proxy metrics](../metrics/session-proxy.md).

Prometheus rules for these alerts, with `promtool` tests, a Grafana dashboard and an Alertmanager example, are in [`deploy/monitoring/`](../../deploy/monitoring/); see [monitoring](../monitoring.md). Each runbook also states the intended alert condition and duration in prose. Route severities according to your operational policy; `critical` and `warning` do not imply a particular notification integration. Other alerts in the rules (session proxy, ingester, limiter, edge) are listed in the monitoring page. The deploy/rollback procedure has no dedicated alert.

| Runbook | Alert name | Severity | Summary |
|---|---|---|---|
| [001: Redis down](001-redis-down.md) | `ProxyXRedisDown` | critical | Restore hot-state availability while preserving healthy tunnels. |
| [002: PostgreSQL down](002-postgres-down.md) | `ProxyXPostgresDown` | critical | Restore durable storage and resume fresh snapshots and control writes. |
| [003: Cache below the low watermark](003-cache-below-low-watermark.md) | `ProxyXCacheLow` | critical | Find lost static or rotating capacity and restore ready units. |
| [004: Provider breaker open](004-provider-breaker-open.md) | `ProxyXProviderBreakerOpen` | critical | Repair provider failures and recover shared route-class breakers. |
| [005: Provider budget at 90 percent](005-provider-budget-at-90-percent.md) | `ProxyXBudgetNearLimit` | critical | Diagnose session churn or demand before changing approved cost limits. |
| [006: Static IP rental ending](006-static-ip-rental-ending.md) | `ProxyXRentalEnding` | critical | Renew or replace dated rentals before capacity expires. |
| [007: Configuration reload rejected](007-config-reload-rejected.md) | `ProxyXConfigRejected` | critical | Restore valid source files or API documents without losing the last good snapshot. |
| [008: Sweeper reclaim rate rising](008-sweeper-reclaim-rate-rising.md) | `ProxyXSweeperRising` | critical | Find crashes or unfinished work behind sustained abandoned-state cleanup. |
| [009: IP replacement requested](009-ip-replace-requested.md) | `ProxyXIPReplaceRequested` | critical | Use replacement evidence to obtain and verify a new provider IP. |
| [010: Pool cooled](010-pool-cooled.md) | `ProxyXPoolCooled` | warning | Distinguish real blocks, bad targets, and provider-wide outages. |
| [011: Block signals dropped](011-block-signals-dropped.md) | `ProxyXBlockSignalsDropped` | warning | Reconcile stale or mismatched client reports with live gateway sessions. |
| [012: Prober not reporting](012-prober-not-reporting.md) | `ProxyXProberBlocked` | critical | Restore probe authentication or delivery of measured results. |
| [012: Prober not reporting](012-prober-not-reporting.md) | `ProxyXProberSilent` | warning | Recover a running prober that has stopped posting canaries. |
| [012: Prober not reporting](012-prober-not-reporting.md) | `ProxyXProberMissing` | warning | Restore the prober process or its missing scrape target. |
| [013: Lease limit broken](013-lease-limit-broken.md) | `ProxyXLeaseLimitBroken` | warning | Relieve sustained last-resort concurrency or fair-use leases. |
| [014: Deploy and rollback](014-deploy-and-rollback.md) | None; operational procedure | not applicable | Deploy forward-only migrations and reject unsafe image rollback targets. |

## Operator access

All endpoint ports below are defaults; use the addresses configured for your deployment. The pool control API listens on port **8081** (`PROXYX_POOL_API_LISTEN`). Each gateway and warmer serves unauthenticated ops endpoints on port **8888** (`PROXYX_POOL_OPS_LISTEN`): `/healthz`, `/readyz`, and `/metrics`. The CONNECT probe listener is a separate port, **8082**.

`/healthz` can answer while the process is still starting. `/readyz` reports startup, drain, and dependency readiness; inspect every replica rather than relying on one load-balanced check. Keep control and ops listeners on trusted networks or behind appropriate access controls.

### Control API authentication

Inventory, policy, org-key, org-block, customer-upstream, and operator IP-block routes require an admin bearer token. Its configured file is `PROXYX_POOL_ADMIN_TOKEN_FILE`, default `/etc/proxyx/secrets/admin-token`. Obtain authorized access to that file through your deployment's credential procedure. Do not put credentials in a repository, log, or incident report.

From a trusted operator shell where that file is available:

```sh
API=http://127.0.0.1:8081
TOKEN=$(cat "${PROXYX_POOL_ADMIN_TOKEN_FILE:-/etc/proxyx/secrets/admin-token}")
curl --fail-with-body -sS -H "Authorization: Bearer $TOKEN" "$API/v1/inventory"
```

Mutating requests can include `X-Operator: <operator-id>` for the audit trail. A valid operator ID has 1–64 characters from letters, digits, `-`, `_`, `.`, and `@`. Use a meaningful approved identifier rather than assuming any shell username is valid.

The other authentication schemes are separate:

- `/v1/probe/targets`, `/v1/probe/results`, and `/v1/probe/token` use the prober bearer token, read from `prober-token` under `PROXYX_POOL_SECRETS_DIR` by the gateway.
- `POST /v1/block-signals` uses HTTP Basic with the org key as the password. An admin bearer token is not a substitute.

Use `GET /v1/inventory`, `GET /v1/inventory/replacements`, and `GET /v1/policies` for diagnosis. `PUT /v1/inventory/{provider}` replaces the provider's full entry list, using a JSON body with an `entries` array. Omitted entries are retired. `PUT /v1/policies` accepts an approved policy document; do not assume inventory API responses can be submitted as policy input.

### Kubernetes example

Substitute the verified namespace, deployment, pod, and container names used in your installation. These examples do not require a particular operator or deployment controller.

```sh
kubectl -n <namespace> get pods
kubectl -n <namespace> describe pod <pod>
kubectl -n <namespace> logs deployment/proxyx-gateway --since=30m
kubectl -n <namespace> logs deployment/proxyx-warmer --since=30m
kubectl -n <namespace> port-forward deployment/proxyx-gateway 8081:8081 8888:8888
```

Run port forwarding in a separate terminal, run API/ops commands locally, and stop the forward with Ctrl-C when finished. Port forwarding grants network access, not permission to read the admin-token file. Inspect warmer ops separately, using another free local port if necessary.

After a configuration or credential repair that needs a process restart:

```sh
kubectl -n <namespace> rollout restart deployment/proxyx-gateway
kubectl -n <namespace> rollout restart deployment/proxyx-warmer
kubectl -n <namespace> rollout status deployment/proxyx-gateway
kubectl -n <namespace> rollout status deployment/proxyx-warmer
```

### systemd example

For host installations, configure separate units that run `proxyx gateway` and `proxyx warmer`. The CLI does not install these units. Adapt these example unit names to your host:

```sh
systemctl status proxyx-gateway proxyx-warmer
journalctl -u proxyx-gateway -u proxyx-warmer --since '30 minutes ago'
sudo systemctl restart proxyx-gateway
sudo systemctl restart proxyx-warmer
```

Run commands only for the affected role; a gateway restart drains and eventually closes client tunnels. Set the supervisor's stop timeout to cover `PROXYX_POOL_DRAIN_TIMEOUT` plus shutdown margin. Environment and connection-string changes normally require a restart; source data reloads use `PROXYX_POOL_RELOAD_EVERY`, default 30 seconds.

### Source configuration and metrics

Source documents live under `PROXYX_POOL_DATA_DIR`, default `/etc/proxyx/data`, in `adapters`, `policies`, and `inventory`, with `probe-targets.toml` alongside them. Credentials are files under `PROXYX_POOL_SECRETS_DIR`. Changes to a source policy can supersede an emergency API version of that same policy; reconcile both before closing the incident.

PromQL examples assume target labels retain their metric meaning. Deduplicate shared inventory gauges across replicas before summing states; replica copies are not extra IPs. Check your scrape labels and warmer partition ownership before summing capacity. Histogram `_bucket` and `_count` series belong to their documented metric family. Some labeled families are absent before their first event, so an absent series is not always a zero reading.

After using the admin credential, clear the shell value:

```sh
unset TOKEN
```
