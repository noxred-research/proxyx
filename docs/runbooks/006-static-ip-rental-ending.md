# Static IP rental ending

## Symptom
`ProxyXRentalEnding` (critical): `proxyx_pool_inventory_rental_days_left{provider="<provider>"} < 14`. The gauge shows the fewest days remaining among the provider's dated, non-retired IPs.

## Impact
There may be no immediate failure. If the provider ends a rental, tunnels and checks for that IP fail and usable capacity shrinks. Enough expired rentals can trigger [003: cache below the low watermark](003-cache-below-low-watermark.md). ProxyX does not renew provider rentals.

## Diagnosis
Set up [operator access](README.md#operator-access), then list the dated entries:

```sh
curl --fail-with-body -sS -H "Authorization: Bearer $TOKEN" \
  "$API/v1/inventory?provider=<provider>" \
  | jq -r '.items | sort_by(.rental_end) | .[] | [.ip, .port, .state, .rental_end] | @tsv'
```

Compare `rental_end` with the provider's actual rental record. A negative gauge means a recorded end date has already passed.

## Mitigation
1. Renew the rental with the provider, or arrange replacement capacity before retiring the old IP.
2. Check whether renewal changed the IP, endpoint, or port. The inventory is keyed by IP; do not assume that a provider's port-to-IP mapping stays unchanged.
3. Update `rental_end = "YYYY-MM-DD"` and any changed endpoint fields in the inventory source under `PROXYX_POOL_DATA_DIR/inventory`. Source edits sync on the next reload when their content changes. Alternatively, use `PUT /v1/inventory/{provider}` with the complete approved provider list.
4. If not renewing, omit the old entry from that complete list or remove it from the source inventory. Its state becomes retired; existing tunnels drain. Ensure the remaining capacity still meets the policy, or add replacements first.

## Verification
```promql
min by (provider) (proxyx_pool_inventory_rental_days_left)
```

Every dated active rental should have at least 14 days left, unless a documented replacement plan intentionally leaves a shorter interval. An inventory API read shows the new date and expected state. If no dated non-retired IP remains, the provider's gauge disappears rather than reporting a renewed date.

## Escalation
An unchanged gauge after an edit can indicate `proxyx_pool_config_reload_failed{source="inventory"} == 1`; use [007](007-config-reload-rejected.md). Invalid calendar dates are rejected. For failing or unsuitable replacement IPs, follow [009](009-ip-replace-requested.md) and provide the provider with the affected rental identifiers.

## Alert
Rules: `ProxyXRentalEnding` (critical) in [`deploy/monitoring/prometheus-rules.yml`](../../deploy/monitoring/prometheus-rules.yml); see [monitoring](../monitoring.md#alert-reference).
