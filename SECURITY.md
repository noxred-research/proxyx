# Security policy

We take the security of ProxyX and of the people who run it seriously. This page says which versions are supported, how to report a vulnerability, what you can expect from us, and what is in and out of scope.

> **Intended use.** ProxyX is infrastructure for operating proxy pools and for inspecting traffic whose owner has consented. Use it only on systems and traffic you own or are authorized to handle. See [Responsible use](#responsible-use).

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |
| Earlier than 0.1.0 | No |

ProxyX is pre-1.0. Only the latest 0.1.x release receives security fixes. The distribution is the source repository and tagged source releases. No binaries, container images, hosted service or crates.io packages are published, so there are no other artifacts to patch. The [Dockerfile](docker/Dockerfile) and [Compose file](docker/docker-compose.yml) in this repository are for development: do not expose the Compose stack to a network you do not control.

### Automated security checks

The [security workflow](.github/workflows/security.yml) checks locked dependencies against current Rust advisories, scans all fetched Git history with gitleaks and audits workflow configuration with zizmor on main-branch pushes, weekly and on manual dispatch. [CodeQL](.github/workflows/codeql.yml) analyzes Rust and GitHub Actions on authorized pull requests, main-branch pushes, weekly and on manual dispatch; analysis and upload are disabled while the repository is private. These checks use a code-owner authorization gate and do not replace manual review. Repository fork-workflow restrictions, required code-owner review and private vulnerability reporting must be configured separately by a maintainer.

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion for a suspected vulnerability.** Report it privately through GitHub private vulnerability reporting for `noxred-research/proxyx`:

1. Open <https://github.com/noxred-research/proxyx/security/advisories/new>, or go to the repository's **Security** tab and choose **Report a vulnerability**.
2. Describe the affected component (gateway, warmer, session proxy, control plane, limiter, prober) and the version or commit, the impact, and steps or a proof of concept that reproduce the problem. A minimal reproduction against a local deployment is ideal.
3. Do not include live credentials, real personal data or captured third-party traffic in the report.

If the private reporting option is not offered on the repository, open a public issue that asks for a private channel and contains no technical details.

## What to expect

These are commitments for good-faith reports of issues in scope. Times are in business days.

| Step | Target |
| --- | --- |
| Acknowledge receipt | within 3 days |
| Initial assessment: confirmed, needs more information, or not a vulnerability | within 10 days |
| Status updates while the report is open | at least every 14 days |
| Fix or mitigation, and a coordinated disclosure date | within 90 days of the initial assessment; sooner for actively exploited issues |

We will keep you informed, agree on a disclosure date with you, and credit you in the published advisory unless you ask to remain anonymous. This project does not run a bug bounty. If we cannot meet a target we will tell you why.

## Safe harbor

We consider security research carried out in good faith under this policy to be authorized, and we will not pursue or support legal action against you for it. Good faith means that you:

- test only against your own deployment of ProxyX, never against someone else's systems or data, and never against production data you do not own;
- make a reasonable effort to avoid privacy violations, data destruction and interruption or degradation of services;
- access only as much data as needed to demonstrate the issue, and stop and report if you encounter personal data or credentials;
- give us a reasonable time to fix the issue before you disclose it, and do not disclose it publicly until we have agreed a date or the 90-day target has passed without a response;
- do not use social engineering, physical attacks, denial of service or spam.

This safe harbor covers the ProxyX project only. It does not authorize testing of upstream proxy providers, of third-party systems that a ProxyX deployment is pointed at, of the services of GitHub or other platforms, or of anyone else's deployment; those have their own terms. If you are unsure whether an activity is covered, ask first, privately.

## Scope

**In scope:** code in this repository, its build and CI configuration, and the deployment files under `docker/`. Findings that bypass a control described below are in scope even when they need a particular configuration. Examples:

- **Authentication and authorization.**
  - A way to open a tunnel, call a `/v1` route, or call a control API route without a valid credential.
  - Acting as another org: a key or session of one org reaching another org's units, sessions, captures, exports or API keys.
  - Bypassing the brute-force limiters or the key caches so that a revoked or disabled credential keeps working past its documented window.
- **Destination controls.** A way to make the gateway or the session proxy dial a private, loopback, link-local, carrier-grade NAT, cloud metadata or cluster-internal address that the destination rules refuse, including through DNS rebinding, redirects of a customer upstream, alternative IP spellings or IPv6 embeddings.
- **Customer upstreams.** Writing, validating or dialing an org's upstream in a way that reaches a non-public address, leaks the stored login, or lets another org lease that upstream.
- **TLS interception scope.** Intercepting a host that a session did not list, or one that `no_capture_hosts` excludes; signing with a CA other than the one configured; leaking CA private key material.
- **Secret handling.** Leakage of org keys, API keys, provider logins, probe secrets, session ids or the admin token into logs, metrics, error reports, traces, API responses or captures beyond what the documentation states.
- **Capture integrity.** Reading captures across orgs, forging or injecting captures, or bypassing the query layer's org scoping (REST, GraphQL, exports and signed URLs).
- **Resource limits.** Bypassing per-org tunnel, byte, rate or budget limits, or a pre-authentication amplification that defeats the connection caps.
- **Supply chain.** Weaknesses in the build, container, workflow or dependency configuration.

**Out of scope:**

- vulnerabilities in third-party dependencies that have no ProxyX-specific exploit path (report those upstream; dependency advisories are checked by `cargo deny`);
- findings that require an operator to deliberately grant a credential, role or network position to an attacker;
- the behavior of upstream providers and of the sites reached through ProxyX, and content they serve;
- denial of service by volume against a deployment that does not use the limits and resource settings the documentation tells operators to configure;
- the development defaults of `docker/docker-compose.yml` (default passwords, no TLS to datastores, single instances, a self-generated CA);
- issues that appear only when the documented hardening steps in [operations](docs/operations.md#security-hardening-checklist) are skipped, such as exposing the admin API or the ops port to the public internet;
- missing hardening that is documented as a known limitation in the [changelog](CHANGELOG.md);
- reports from automated scanners without a demonstrated impact, and social engineering of maintainers;
- abuse of ProxyX by third parties against systems you operate. We cannot act on deployments we do not run; report that activity to the operator or hosting provider concerned.

## What ProxyX handles

Knowing what a deployment holds helps you judge impact and protect it.

- **Org keys (`ak_...`) and control API keys (`pxk_...`)** are stored as SHA-256 hashes only and are shown once at creation.
- **Provider logins and scorer keys** are files in a secrets directory, never part of configuration files or the database. Customer upstream logins are stored in Postgres and are never returned by the API.
- **Egress proxy passwords of orgs** are stored in Postgres and are write-only through the control API: reads return `<redacted>`.
- **Session credentials** are session UUIDs. Possession of the id is the whole secret of a session proxy credential, so treat `proxy_url` as a secret.
- **The MITM CA key** can sign certificates for any host. Whoever holds it can impersonate sites to clients that trust its certificate. Keep it readable by the session proxy only, and do not install its certificate in trust stores that are not under test.
- **Captured traffic** includes request and response headers and bodies, which can hold credentials and personal data. Operators decide what is captured, by org, and for how long it is retained.

## Responsible use

ProxyX routes traffic through third-party IP addresses and can terminate TLS. Use it only where you have the right to do so: with proxy provider accounts whose terms allow your use, and, for interception, with the consent of the owner of the traffic (your own applications and test environments, or users who have been informed and agreed). Do not use it to evade a site's protections, to attack or overload third parties, to read other people's traffic or for anything unlawful where you operate. This is the project's intended-use policy and a condition of support and community participation; the [AGPL-3.0-only](LICENSE) license itself is unchanged.

The project enforces parts of this in code: the gateway refuses non-public destinations, enforces per-org budgets and records an audit trail of operator changes, and the session proxy intercepts only the hosts a session lists. These controls reduce harm; they do not verify that you are authorized. Misuse of ProxyX is not covered by this policy, is not covered by the safe harbor above, and is your responsibility.

## Disclosure

After a fix is released, the advisory is published through GitHub Security Advisories with credit to the reporter unless the reporter asks to remain anonymous.
