# AI/LLM-native ProxyX

ProxyX is a next-generation AI/LLM-native proxy for authorized security research. That means three things: an AI agent can watch the system, an agent can steer it within limits an operator sets, and the explanations an agent needs are part of the product instead of knowledge in a wiki. It does not mean a model sits in the data path. Tunnels, leases, policies and captures are decided by deterministic code; models read, explain, draft and, when allowed, ask for changes.

The interface is a [Model Context Protocol](https://modelcontextprotocol.io) server, `proxyx mcp`; setup, the tool catalog and the safety model are in [mcp.md](mcp.md).

- [What an agent can do](#what-an-agent-can-do)
- [Monitoring](#monitoring)
- [Management](#management)
- [Dynamic configuration](#dynamic-configuration)
- [LLM-assisted operations](#llm-assisted-operations)
- [Typical sessions](#typical-sessions)
- [Responsible use](#responsible-use)
- [Design notes](#design-notes)

## What an agent can do

| Need | Tools |
|---|---|
| Is the platform healthy? | `health`, `assess`, `pool_capacity`, `breaker_states` |
| What is failing, and why? | `recent_refusals`, `explain_refusal`, `explain_selector`, `diagnose`, `block_signal_rates` |
| What did the traffic look like? | `search_traffic`, `count_traffic`, `get_capture`, `search_ws`, `get_ws_conversation`, `summarize_traffic` |
| Is a target blocking us? | `classify_block_page`, `block_signal_rates`, `report_block_signal` |
| Run a piece of work | `create_session`, `extend_session`, `end_session`, `session_status` |
| Steer egress | `set_org_egress_proxy`, `set_customer_upstream`, `create_org_block`, `set_org_rate_limit`, `list_pool_sessions`, `rotate_pool_session`, `generate_pool_endpoints` |
| Change configuration | `validate_policy`, `suggest_policy`, `propose_config_change`, `apply_config_change` |
| Understand the rules | resources `proxyx://docs/...`, prompts `triage_blocks`, `capacity_review`, `session_debug` |

The agents and clients that use these tools hold the credentials of the MCP server's configuration and no others; an operator decides, per capability, what may change.

## Monitoring

Monitoring works from the roles' ops ports (`/healthz`, `/readyz`, `/metrics`), which need no credentials, so it can be switched on with nothing but URLs.

- **Health.** `health` probes liveness and readiness of every role, with latency and the `/readyz` reason (`starting`, `draining`, `redis unavailable`).
- **Capacity.** `pool_capacity` compares ready units (normal and degraded) with `min_ready` and the low watermark for every provider and kind, and adds cost used, breaker state, rental days left and inventory by state. Verdicts: `ok`, `degraded_only`, `below_min`, `below_watermark`, `empty`.
- **Breakers.** `breaker_states` reads the pool's route-class breakers, and finds every other breaker gauge by name in the roles' metrics: session-proxy upstream breakers and edge parent breakers appear as soon as those roles export them, without this server knowing their code.
- **Refusals and blocks.** `recent_refusals` ranks refusals by cause with rates, and attaches the meaning and next steps of each cause; `block_signal_rates` shows what targets are doing to the exit IPs and how the pool reacted (`target`, `ip`, `pool_guard`, `route_class`).
- **Rates.** A counter total says little about now. The server scrapes in the background (`metrics.sample_interval_secs`) and reports increases over a window; before it has two scrapes a tool says so and shows totals.
- **Assessment.** `assess` runs every check above in one call and grades it `pass`, `warn` or `fail`. Each warn or fail carries the evidence, concrete remediation steps and the [runbook](runbooks/README.md) to follow; the result lists the runbooks to open and the checks it could not run and why. Thresholds are in the tool's note: pool-side refusals warn at 2% and fail at 10% of connections (at least 20), dial and API p95 latency warn at 2 s / 1 s and fail at 5 s, cost warns at 80% and fails at 90%, rentals warn at 14 days and fail at 3. They are defaults chosen to match the runbooks, not service-level commitments.
- **Timeouts and keepalive.** `effective_config` shows the effective policy for an org and provider (lease ttl and wait, create deadline, rotating keepalive and the interval that is actually in force, session life, cooldowns, block rules, quality criteria), the gateway's built-in dial, handshake, idle and keepalive timings, and the MCP server's own limits. The built-in values come from the documentation and are labelled so: the roles do not expose their environment.
- **Traffic.** `search_traffic` takes the control plane's [query language](control-api.md#query-language); the server checks a query before sending it and explains what is wrong (unknown field, bad operator, invalid RE2) so the model fixes it in one round trip.
- **Explanations.** `explain_refusal` covers all gateway cause codes and the session proxy's `X-ProxyX-Error` values; `explain_selector` runs a proxy username through the gateway's own grammar and, with an org, its effective policy.

Captured content is hostile by default: a response body can say "ignore your instructions". Everything captured is marked untrusted, truncated, stripped of credential headers, and the tool descriptions and server instructions tell the model to treat it as data.

## Management

Mutations are the dangerous half, so they are opt-in and layered. The server is read-only until an operator enables capabilities (`sessions`, `org_keys`, `org_limits`, `egress`, `org_blocks`, `signals`, `policy`, `inventory`, `pool_sessions`), can be confined to listed orgs and an engagement window, can hold every change for a human, and records every call in a hash-chained audit log. A tool that is not allowed is not listed. Secrets never travel through the model: a created org key or session proxy URL goes to a private file (or is shown once if the operator allows), and logins are passed by reference to the operator's credential files. The full list is in [mcp.md](mcp.md#safety-model).

Typical management calls: open a capture session for a crawl and extend it while the crawl runs; block an org from a provider after an abuse report, with the reason recorded; cap an org's rate; chain an org's session traffic through an egress proxy; set an org's own upstream and validate it; report a block signal so the pool cools the IP; disable an org's keys.

## Dynamic configuration

ProxyX is configured by policy documents, inventory and org settings that the running system re-reads. An agent changes them through a two-step workflow:

1. `propose_config_change` validates the change and returns a diff against the current state. Policy documents are parsed and merged by the gateway's own `proxyx-policy` crate, so strict fields, durations, ceilings and required regions are checked with the real rules, against the policies already stored. Hosts, ids and addresses are checked with the gateway's rules. The change is stored under a `change_id`.
2. `apply_config_change` applies it once, after re-validating against the state at that moment and, when required, after an operator approved exactly that change (`proxyx mcp approve <change_id>`).

Git remains the source of truth for `global` and `route_class` policies: the diff warns when a change is an emergency override that git replaces when it next changes that policy.

## LLM-assisted operations

Nothing needs a model. The statistics, rules and explanations above work without one. When an operator configures an OpenAI-compatible endpoint (OpenAI, an Anthropic-compatible gateway, Ollama, vLLM), three tools use it for the part only a model does:

| Tool | Without the model | With the model |
|---|---|---|
| `summarize_traffic` | Counts by host, method and status, error and rate-limit shares, slowest and largest exchanges, block-page suspects | A short narrative and the next tools to try |
| `classify_block_page` | Rules for 429, challenge markers (Cloudflare, reCAPTCHA, hCaptcha, `/sorry/`, ...) and plain 403 | The model decides pages the rules cannot (confidence under 0.9); the answer feeds `report_block_signal` |
| `suggest_policy` | not listed | A policy draft for a natural-language request |

The model is held to a contract. It is asked for JSON that matches a schema (`json_schema`, with a `json_object` fallback), at temperature 0, with a timeout and a size cap. The answer is validated against the same schema, and a mismatch is an error. A policy draft is parsed and merged by `proxyx-policy` before it is returned, with the validation result and the effective policy it would produce. Nothing is applied: a draft becomes a change only when someone calls `propose_config_change`, and applying it needs the `policy` capability and, if configured, approval. A block classification reports a signal only when the caller asks (`report`) and the server has the `signals` capability, because a wrong report cools a healthy IP. Captured content is given to the model inside `<untrusted_data>` tags with a system prompt that says it is data; the output schema, not the prompt, is what limits an injected instruction.

## Typical sessions

**"Tunnels are failing with cache_empty."** The agent calls `assess`: the finding says provider `p1` is below its low watermark with an open breaker and points to runbooks 003 and 004. `breaker_states` shows the create outcomes (`failed` rising); `effective_config` shows the policy's `create_deadline`. The agent reports the evidence and the runbook steps. Changing the provider's order in the policy is a `propose_config_change` the operator approves.

**"The crawl gets 403s."** `search_traffic` on the crawl's `source_id` with `status_code >= 400`, `classify_block_page` on two captures (challenge, 0.9), `block_signal_rates` (rate-limited signals rising on one target). The agent suggests slowing the crawl and a sticky key per target, and offers `report_block_signal` for the IPs involved.

**"Why is `px-kind-rotating-cc-fr-city-paris-sid-a-b` refused?"** `explain_selector`: `pairs`: a value never contains `-`; the sticky key `a-b` must be `a_b`.

**"Give acme a daily byte budget."** `suggest_policy` drafts it, `validate_policy` merges it with the stored set, `propose_config_change` shows the diff, the operator approves, `apply_config_change` stores it.

## Responsible use

ProxyX is for infrastructure you own or are permitted to operate and for traffic whose owner has consented. An AI agent makes it easier to do a lot quickly, which is why the defaults are conservative.

- Record the authorization: set `scope.engagement` to its reference and `scope.expires` to its end; every audit entry carries the engagement, and mutations stop when it lapses.
- Give an agent the smallest capability set the task needs, use `allowed_orgs`, and keep `approval = "all"` for anything that touches shared resources or secrets.
- Treat captured traffic as data from a third party. It can contain personal data and, deliberately, instructions aimed at your agent. Keep `limits.max_body_bytes` small and do not send captured content to an LLM endpoint you do not control.
- A block signal, an org block and a policy change affect real traffic and shared IPs. Prefer `dry_run` and a proposal first.
- Do not use the tools to evade a site's protections, to attack services you are not authorized to test, or to intercept anyone else's traffic. See [Responsible use](../README.md#responsible-use-and-security) and [SECURITY.md](../SECURITY.md).

## Design notes

- **Wraps, does not fork, the control surfaces.** The server calls the APIs and ops ports operators already use, so a role needs no change to be monitored, and what an agent can do is bounded by credentials that already have an owner. Two reuse points: the gateway's cause codes come from `proxyx-pool-common`, and username and policy grammar from `proxyx-policy`, so explanations cannot drift from behaviour; a test also fails when the catalogue of metric families differs from [metrics/pool.md](metrics/pool.md) and [metrics/session-proxy.md](metrics/session-proxy.md).
- **Stateless protocol, explicit handles.** The server keeps no per-connection state. State that spans calls (changes, sessions) is named by an id the model carries.
- **Evidence before verdicts.** `diagnose` and `assess` return findings with their evidence and what they could not check, so a wrong threshold or a missing scrape is visible rather than hidden in a verdict.
- **The same conventions as crawlx.** crawlx, the sibling crawler, exposes an MCP server with stdio framing, schema-validated arguments, tool errors as results and an advisory-only model. ProxyX's server follows those conventions and adds HTTP, capabilities and approval because it can change shared infrastructure.
