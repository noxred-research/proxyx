# AI/LLM-native ProxyX

ProxyX is a next-generation AI/LLM-native proxy for authorized security research. That means three things: an AI agent can watch the system, an agent can steer it within limits an operator sets, and the explanations an agent needs are part of the product instead of knowledge in a wiki. It does not mean a model sits in the data path. Tunnels, leases, policies and captures are decided by deterministic code; models read, explain, draft and, when allowed, ask for changes.

The interface is a [Model Context Protocol](https://modelcontextprotocol.io) server, `proxyx mcp`; setup, the tool catalog and the safety model are in [mcp.md](mcp.md).

- [What an agent can do](#what-an-agent-can-do)
- [Monitoring](#monitoring)
- [Management](#management)
- [Dynamic configuration](#dynamic-configuration)
- [LLM-assisted operations](#llm-assisted-operations)
- [Passive capture analysis](#passive-capture-analysis)
- [Roadmap](#roadmap)
- [Typical sessions](#typical-sessions)
- [Responsible use](#responsible-use)
- [Design notes](#design-notes)

## What an agent can do

| Need | Tools |
|---|---|
| Is the platform healthy? | `health`, `assess`, `pool_capacity`, `breaker_states` |
| What is failing, and why? | `recent_refusals`, `explain_refusal`, `explain_selector`, `diagnose`, `block_signal_rates` |
| What did the traffic look like? | `search_traffic`, `count_traffic`, `get_capture`, `search_ws`, `get_ws_conversation`, `summarize_traffic` |
| How does the application authenticate, and what leaks? | `open_analysis_scope`, `analyze_auth_flows`, `scan_sensitive_data` |
| What is its API? | `infer_api_schema`, `get_api_schema_draft` |
| Ask a traffic question in plain language | `draft_traffic_query`, `run_traffic_query` |
| Follow new captures | `open_capture_feed`, `read_capture_feed`, `close_capture_feed` |
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

Nothing needs a model. The statistics, rules and explanations above work without one. When an operator configures a chat-completions compatible endpoint (a hosted service, a gateway or a local inference server), three tools use it for the part only a model does:

| Tool | Without the model | With the model |
|---|---|---|
| `summarize_traffic` | Counts by host, method and status, error and rate-limit shares, slowest and largest exchanges, block-page suspects | A short narrative and the next tools to try |
| `classify_block_page` | Structural rules: status, challenge headers, redirect targets, page title, forms and challenge widgets. It names a subtype and its evidence, tells an authorization answer, a maintenance page or a proxy-made refusal from a block, and abstains on a page that only talks about a CAPTCHA | The model judges only pages the rules cannot (a weak verdict or an abstention). Its number is labelled `self_reported` and never makes a classification reportable |
| `suggest_policy` | not listed | A policy draft for a natural-language request |

The model is held to a contract. It is asked for JSON that matches a schema (`json_schema`, with a `json_object` fallback), at temperature 0, with a timeout and a size cap. The answer is validated against the same schema, and a mismatch is an error. A policy draft is parsed and merged by `proxyx-policy` before it is returned, with the validation result and the effective policy it would produce. Nothing is applied: a draft becomes a change only when someone calls `propose_config_change`, and applying it needs the `policy` capability and, if configured, approval. A block classification never writes: it returns the arguments of a separate `report_block_signal` call and whether the evidence (repeated equivalent observations, `analysis.blocks.min_observations`) is enough. That call needs the `signals` capability and, with `[analysis]` enabled, an operator's approval, because a wrong report cools a healthy IP. Captured content is given to the model inside `<untrusted_data>` tags with a system prompt that says it is data; the output schema, not the prompt, is what limits an injected instruction.

The transport is bounded too: the endpoint's certificate and host name are verified (a private CA is trusted with `llm.ca_file`, see [mcp.md](mcp.md#llm-assisted-tools)), a redirect is never followed so the key and the prompt stay with the configured origin, and a slow, hanging or oversized (above 2 MiB) response is an `llm_error`.

## Passive capture analysis

The analysis tools turn stored captures into evidence-bearing findings: how an application authenticates, where sensitive data sits, what its API looks like, and which captures answer a question asked in plain language. They are passive: they read captures the control plane already stored and never send a request to a target. They are off until an operator enables `[analysis]` and names the capture sources and origins an agent may analyse.

### The shared boundary

Every analysis starts from a **scope handle** (`open_analysis_scope`): one org, named `source_id`s and origins, all inside `analysis.allowed_source_ids` and `analysis.allowed_origins`, until an expiry that never outlives the engagement. The server intersects the scope into **every OR branch** of every query after the query is built, so a branch cannot escape it, and it checks every returned capture against the scope again; anything outside is counted (`coverage.out_of_scope_dropped`) and never shown. An unknown, expired or other-org scope, a source outside the scope or a lapsed engagement is refused before any capture is fetched or any model is called.

A scope can also be limited to opaque client-supplied correlation keys (`correlation_ids`: 1 to 64 characters of `[A-Za-z0-9_-]`, up to 32), such as the sticky key a client puts in its session proxy credential ([session-proxy.md](session-proxy.md#sticky-key)). The keys narrow the scope and never widen it: every OR branch gets a `correlation_id` filter, every returned capture is checked against it, and WebSocket messages, which have no correlation id, are refused for such a scope.

**The ceiling applies without a scope handle too.** While `[analysis]` is enabled, `search_traffic`, `count_traffic`, `get_capture` (and the `proxyx://captures/{org}/{id}` resource), `search_ws`, `get_ws_conversation` and `summarize_traffic` are confined to `analysis.allowed_source_ids` and `analysis.allowed_origins` in the same way: the query is intersected with them, a branch that names another source is refused, a capture outside them is refused, and returned items outside them are withheld and counted (`withheld_outside_analysis_scope`). Read the ceiling as: nothing outside what an operator allowed for analysis is reachable through any capture tool. With analysis off these tools are unchanged.

Results share one envelope: `scope`, `coverage` (`sampled`, `complete`, `truncated`, `cursor`, `observed_at`, bodies by availability, notes, and a statement that ingestion lags so a short result does not mean there was no traffic), `evidence` (an id, the capture, the side, a location and a keyed digest, never a value) and the detector version. Credential values become **keyed HMAC fingerprints** at once: the key is the operator's file, the engagement and the org are mixed in, so equal values link inside one engagement and nowhere else, and no raw value reaches a result, the in-memory registry, the audit log or a model. Results are kept in memory for `analysis.retention_secs` and can be fetched again (`get_analysis_result`) or deleted early (`delete_analysis_result`).

Limits are the operator's: `max_captures`, `max_input_bytes` (headers and bodies read), `max_body_bytes` per body, `deadline_secs` as one absolute deadline over fetching and model calls, and `max_result_bytes` of `[limits]` as the one output ceiling for tools and resources alike. `analysis_capabilities` shows the effective, non-secret values.

A model is optional everywhere. `use_llm` needs `[llm]` and `analysis.allow_external_llm = true`; without that setting nothing is sent and the result says `refused`. With `[analysis]` enabled the same grant covers `summarize_traffic` (which then needs a `scope_id` with `use_llm`), `suggest_policy` and the model path of `classify_block_page`, and every disclosure is recorded in the audit log before it is made: no record, no disclosure. The model only adds wording to local results: it sees names, attribute lists, graph edges, masked locations and sanitized schema summaries, never credential or personal values; every evidence id it cites is checked against the ones the analysis produced (an invented id rejects the whole answer, the local result stands), and a model failure leaves the local result intact. Each model call writes an audit record of the endpoint alias, model id, prompt version, input and output sizes, duration, attempts and evidence ids, never the prompt. One total prompt budget (`analysis.max_total_prompt_chars`, at most `llm.max_input_chars`) covers all fragments of a prompt.

### Authentication and session flows (`analyze_auth_flows`)

Needs `analysis.auth.enabled` and `analysis.auth.fingerprint_key_file`. It reads `Authorization` schemes, cookies and their attributes (`Secure`, `HttpOnly`, `SameSite`, domain and path, so same-name cookies for different scopes stay separate), `Set-Cookie` issue, replacement and deletion, API-key and CSRF headers and fields, token members in JSON and form bodies, and credentials in a URL. The result lists `mechanisms`, `cookie_findings`, `flow_edges` (`issued_then_sent`, `replaced_by`, `cleared_by`, `reused_across_origins`, `sent_without_observed_issue`) and `hypotheses` (observations, such as a double-submit CSRF pattern, plus optional model suggestions). A JWT-shaped value is decoded locally only for its structure (algorithm, whether `exp` and `iat` exist, a lifetime class, optional claim names with `include_jwt_claim_names`) and is always reported `verified: false`: a decoded claim is attacker-controlled input, not an identity. A cut or oversized body makes the result incomplete and says so. Findings are observations, not claims of exploitability, and a confidence never authorizes a replay.

### Sensitive data (`scan_sensitive_data`)

A local detector registry reads normalized JSON, form, XML and text and reports `credential`, `personal_data` and `candidate` findings with a severity, the detector version, the evidence basis (`pattern`, `checksum`, `field_name`, `entropy_heuristic`, `custom_rule`), a location, a masked preview (`preview_chars`, 0 by default: only the length) and a fingerprint. A finding never carries the value. Location changes severity: a credential in a URL is raised, a password submitted in a form is lowered. Unsupported content types, compressed bodies that are not readable and oversized bodies are explicit coverage loss. `custom_rules_file` is the operator's only way to add detectors; a model cannot. There is no search by discovered value and no linking across engagements.

### Natural-language queries (`draft_traffic_query`, `run_traffic_query`)

The drafter compiles a question into the capture [query language](control-api.md#query-language) with fixed templates (status codes and classes, methods, hosts, paths, cookies, durations, sizes, content types, headers, body text, `source_id`, correlation ids, `or` as a new branch). A phrase it does not understand is listed under `unsupported_clauses` and the draft is not executable; it is never guessed or dropped. The language has no time field, so “the last hour” is always unsupported: it is never simulated with a newest-N sample. With `use_llm` a model may propose branches for what the templates cannot express; its branches pass the same validator and the same scope intersection, and an invalid or out-of-scope proposal is discarded. A draft names its cost: body and payload filters are `expensive`, a regular expression adds work, and each needs the operator's `allow_body_scan` and `allow_regex`. `run_traffic_query` takes the draft's `query_digest` and re-checks the draft's expiry, the scope and the operator's settings before it searches or counts; drafting runs nothing. A count is made by the server over the captures the scope admits (up to `analysis.max_captures`, with `coverage` saying whether it is complete), because the store's own count cannot be checked against the scope; counts are HTTP only. The same cost gate applies to the `branches` argument of every other analysis tool. Generated filters use only `contains`, `exact`, integer comparisons and `any`/`all`, which mean the same in both capture stores ([capture-stores.md](capture-stores.md#differences-that-are-not-rejected) lists the remaining case-folding differences of `contains`); the host and source constraints of a scope are only a pruning hint for the store, and the server checks every returned capture against the scope itself.

### API drafts (`infer_api_schema`, `get_api_schema_draft`)

The inferencer groups captures by origin, method and path template and merges the JSON shapes it saw per status code and content type into an OpenAPI 3.1 document per origin. A path segment that is a plain word (letters, a version such as `v1`, a file name) stays literal, so `me` and `123` are different routes; anything else (digits, a UUID, a token, an address) is shown as a parameter even when one value was seen, because identifier-like values are never printed. JSON keys and query parameter names that are not plain identifiers (a map keyed by user, email or token) are collapsed into one `additionalProperties` shape or left out, and the same rule turns such names into `*` in finding locations and evidence. A property seen in every sample is `x-proxyx-observed-required`, never `required`; types that conflict stay a union with a note; an empty array leaves its item type unknown; a cut, oversized or non-allowed body leaves the schema unknown and is counted in `diagnostics`; unobserved routes, statuses, authorization requirements and examples are never invented. Every route and property carries evidence ids. `proxyx://analysis/{org}/{draft_id}/openapi` serves the document through the same gate. A model may only name operations (`operationId`, `summary`) of routes the draft already has. The document is untrusted data and not permission to call anything.

### Capture feeds (`open_capture_feed`, `read_capture_feed`, `close_capture_feed`)

A feed is a polled view of stored captures that arrive after it opened: it keeps the scope-constrained query and two cursors, never a capture. It starts from the control plane's `/rpc/sequence` position, reads ascending up to the newest stored position, returns stable ids (a duplicate write is dropped by id) and a `next_cursor` that only moves forward, and re-checks the scope on every poll (an ended scope or engagement closes the feed). Polls closer than `analysis.feeds.min_poll_interval_ms` are refused, pages are capped by `max_page_rows`, bodies need `analysis.feeds.include_bodies`, and `proxyx://feeds/{org}/{feed_id}` reads the next page through the same path. Captures go through the same cleaning as `get_capture`. A feed is not a live stream and does not claim exactly-once or event-time order: ingestion lags, a late capture can sort before the cursor, a store that no longer holds the cursor is reported as a possible retention gap, and feeds live in server memory, so a restart ends them.

### Block-page classification

See [LLM-assisted operations](#llm-assisted-operations). The rules are versioned (`detector_version`) and measured on the published synthetic fixtures (`crates/mcp/tests/fixtures/block_pages.json`, split by site and template and by time, with a confusion matrix and abstention printed by the test). The precision table the classifier publishes (`analysis.blocks.min_calibrated_precision` gates reporting on it) is recomputed from those fixtures and the test fails if a rule change lowers it. It is a regression guard on fixtures that someone wrote, not a field accuracy: calibrate against your own labelled responses before relying on it.

### Safety properties

- No evasion: nothing here solves a challenge, rotates identity after a denial, tunes stealth or weakens a protection; a block recommendation is to pause, slow down or check authorization.
- Captured text, headers, schema descriptions and model output are untrusted data and never become a tool name, a command, a credential or a grant.
- Models advise and never authorize: scope, limits, evidence and approval are deterministic code.
- Every call is audited; analyses add an `evidence` record (ids and digests, never content) and model calls a `model` record.

## Roadmap

These designs are documented, not implemented. Each needs enforcement that does not exist yet and is deliberately not exposed.

- **Capture baseline comparison and anomaly explanations.** Immutable, redacted aggregate baselines of an operator-chosen cohort and a deterministic comparison (new hosts and routes, status, size and duration shifts), with `insufficient_evidence` for small or mismatched cohorts. Needs a persistent analysis store with its own capability.
- **Least-privilege egress policy drafting and simulation.** A reviewable restrictive policy from an operator-owned authorization record and observed dependencies, where observed traffic is never permission and unexpected third parties are listed, not allowed. Needs destination-side parsers to validate against and the authorization record.
- **Cross-project investigation context.** A first piece exists: a client can put an opaque sticky key in its proxy username, captures carry it as `correlation_id`, and an analysis scope can be limited to it, which joins one client session to its captures without passing a proxy credential through a model. Joining crawl runs and browser actions into one investigation view across the products' servers, each keeping its own scope, still needs agreed wire contracts with the sibling projects.
- **Agent-safe captured-request replay.** Out of scope until destination enforcement exists end to end: exact allowed origins and methods, connect-time address checks, credential references, single consumption and delivery-unknown semantics. It is not offered in any reduced form.

## Typical sessions

**"Tunnels are failing with cache_empty."** The agent calls `assess`: the finding says provider `p1` is below its low watermark with an open breaker and points to runbooks 003 and 004. `breaker_states` shows the create outcomes (`failed` rising); `effective_config` shows the policy's `create_deadline`. The agent reports the evidence and the runbook steps. Changing the provider's order in the policy is a `propose_config_change` the operator approves.

**"The crawl gets 403s."** `search_traffic` on the crawl's `source_id` with `status_code >= 400`, `classify_block_page` on two captures (challenge, 0.9), `block_signal_rates` (rate-limited signals rising on one target). The agent suggests slowing the crawl and a sticky key per target, and offers `report_block_signal` for the IPs involved.

**"Why is `px-kind-rotating-cc-fr-city-paris-sid-a-b` refused?"** `explain_selector`: `pairs`: a value never contains `-`; the sticky key `a-b` must be `a_b`.

**"What does this app do for auth, and does it leak anything?"** `open_analysis_scope` on the run's `source_id`, then `analyze_auth_flows` (a session cookie issued at login, rotated on refresh and cleared at logout, no `HttpOnly` on a tracking cookie) and `scan_sensitive_data` (an access key in a response, an email in a JSON member), each finding with the capture and the location that show it, and none carrying a value.

**"Which requests failed with 401 or 403?"** `draft_traffic_query` shows the branches with the scope applied and their cost before `run_traffic_query` searches.

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
- **Scope before data.** An analysis reads only what a scope handle, derived from operator-owned settings, allows, and every query and every returned capture is checked against it; a model never sees an unauthorized capture, because nothing is fetched until the scope passes.
- **Evidence before verdicts.** `diagnose` and `assess` return findings with their evidence and what they could not check, so a wrong threshold or a missing scrape is visible rather than hidden in a verdict.
- **The same conventions as crawlx.** crawlx, the sibling crawler, exposes an MCP server with stdio framing, schema-validated arguments, tool errors as results and an advisory-only model. ProxyX's server follows those conventions and adds HTTP, capabilities and approval because it can change shared infrastructure.
