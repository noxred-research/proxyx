//! The MCP server's TOML configuration (`examples/mcp.toml`).
//!
//! Defaults are the safest setting: no mutating capability, no approval bypass, no secret in
//! any output, loopback bind. Credentials are never configuration values: every one is read
//! from a file named here, and the files are read once when the server starts.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, bail, ensure};
use proxyx_client::Secret;
use serde::{Deserialize, Serialize};

/// Where the configuration is looked up when `--config` is not given.
pub const DEFAULT_PATHS: [&str; 2] = ["./mcp.toml", "/etc/proxyx/mcp.toml"];

/// Default bind address of the HTTP transport.
pub const DEFAULT_BIND: &str = "127.0.0.1:8765";

/// A mutating capability. A tool that changes ProxyX needs its capability enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Create, extend and end capture sessions.
    Sessions,
    /// Create and disable org keys.
    OrgKeys,
    /// Set org rate limits.
    OrgLimits,
    /// Set and clear an org's egress proxy and customer upstream.
    Egress,
    /// Create and lift org blocks.
    OrgBlocks,
    /// Report block signals.
    Signals,
    /// Write and delete policies.
    Policy,
    /// Replace a provider's static inventory.
    Inventory,
    /// Rotate sticky pool sessions of an org.
    PoolSessions,
}

impl Capability {
    pub const ALL: [Capability; 9] = [
        Capability::Sessions,
        Capability::OrgKeys,
        Capability::OrgLimits,
        Capability::Egress,
        Capability::OrgBlocks,
        Capability::Signals,
        Capability::Policy,
        Capability::Inventory,
        Capability::PoolSessions,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Capability::Sessions => "sessions",
            Capability::OrgKeys => "org_keys",
            Capability::OrgLimits => "org_limits",
            Capability::Egress => "egress",
            Capability::OrgBlocks => "org_blocks",
            Capability::Signals => "signals",
            Capability::Policy => "policy",
            Capability::Inventory => "inventory",
            Capability::PoolSessions => "pool_sessions",
        }
    }
}

/// A named bundle of capabilities.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    /// Observe only. The default.
    #[default]
    ReadOnly,
    /// Run sessions and react to blocks: sessions, org blocks, block signals.
    Operator,
    /// Everything, including policy, inventory, keys and egress.
    Admin,
}

impl Profile {
    pub fn capabilities(self) -> Vec<Capability> {
        match self {
            Profile::ReadOnly => Vec::new(),
            Profile::Operator => vec![
                Capability::Sessions,
                Capability::OrgBlocks,
                Capability::Signals,
            ],
            Profile::Admin => Capability::ALL.to_vec(),
        }
    }
}

/// How approval applies to mutations.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMode {
    /// A mutation runs as soon as its capability allows it.
    #[default]
    Off,
    /// Every mutation waits for an operator.
    All,
    /// Only the tools in `approval_tools` wait.
    Listed,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub http: HttpConfig,
    pub endpoints: Endpoints,
    pub safety: Safety,
    pub scope: Scope,
    pub limits: Limits,
    pub audit: AuditConfig,
    pub metrics: MetricsConfig,
    pub llm: Option<LlmConfig>,
    /// Passive analysis of captured traffic. Off unless an operator enables it.
    pub analysis: AnalysisConfig,
    /// Named credentials a tool can reference (`credential_ref`) instead of taking a secret as
    /// an argument.
    pub credentials: BTreeMap<String, CredentialFiles>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HttpConfig {
    pub bind: String,
    pub path: String,
    /// Bearer token the HTTP transport requires. Required to serve HTTP.
    pub token_file: Option<PathBuf>,
    /// Origins allowed to call the endpoint, besides loopback origins on a loopback bind.
    pub allowed_origins: Vec<String>,
    pub max_body_bytes: usize,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            bind: DEFAULT_BIND.to_owned(),
            path: "/mcp".to_owned(),
            token_file: None,
            allowed_origins: Vec::new(),
            max_body_bytes: 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Endpoints {
    pub pool: Option<PoolEndpoint>,
    pub control: Option<ControlEndpoint>,
    /// Health and metrics targets: one per running role.
    pub roles: Vec<RoleEndpoint>,
}

/// The pool gateway's control API (`/v1`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolEndpoint {
    pub url: String,
    pub admin_token_file: PathBuf,
    /// Written to `X-Operator` so the gateway's audit trail names this server (1 to 64 of
    /// `[A-Za-z0-9-_.@]`).
    #[serde(default = "default_operator")]
    pub operator: String,
    /// An org key. When set, block signals can go through the org-key route.
    #[serde(default)]
    pub org_key_file: Option<PathBuf>,
}

fn default_operator() -> String {
    "proxyx-mcp".to_owned()
}

/// The session control plane (`/rpc`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlEndpoint {
    pub url: String,
    /// A `pxk_` service key.
    pub key_file: PathBuf,
    /// The org the service key is bound to; the default of every `org` argument.
    pub org: String,
}

/// What a role is, which decides its health and metrics paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RoleKind {
    Gateway,
    Warmer,
    ControlApi,
    Ingester,
    Intercept,
}

impl RoleKind {
    pub const fn defaults(self) -> RolePaths {
        match self {
            RoleKind::Gateway | RoleKind::Warmer => RolePaths {
                live: "/healthz",
                ready: Some("/readyz"),
                metrics: "/metrics",
            },
            RoleKind::ControlApi => RolePaths {
                live: "/health/live",
                ready: Some("/health/ready"),
                metrics: "/metrics",
            },
            RoleKind::Ingester => RolePaths {
                live: "/health",
                ready: None,
                metrics: "/metrics",
            },
            RoleKind::Intercept => RolePaths {
                live: "/health",
                ready: None,
                metrics: "/metrics",
            },
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RolePaths {
    pub live: &'static str,
    pub ready: Option<&'static str>,
    pub metrics: &'static str,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleEndpoint {
    pub name: String,
    pub kind: RoleKind,
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Safety {
    pub profile: Profile,
    /// When set, replaces the capabilities of the profile.
    pub capabilities: Option<Vec<Capability>>,
    /// When non-empty, only these tools can be listed or called. A trailing `*` matches a
    /// prefix.
    pub allow_tools: Vec<String>,
    pub deny_tools: Vec<String>,
    pub approval: ApprovalMode,
    pub approval_tools: Vec<String>,
    pub approval_ttl_secs: u64,
    /// Show a secret in the result of the call that creates it, once, and nowhere else. When
    /// false the secret is written to a `0600` file under `state_dir/secrets` instead.
    pub reveal_secrets_once: bool,
    /// Treat every mutation as a dry run.
    pub force_dry_run: bool,
    /// Enables the `confirm_change` tool: a separate token an operator (not the model) holds.
    pub confirm_token_file: Option<PathBuf>,
    /// Pending changes, written secrets and the session registry live here.
    pub state_dir: Option<PathBuf>,
}

impl Default for Safety {
    fn default() -> Self {
        Self {
            profile: Profile::ReadOnly,
            capabilities: None,
            allow_tools: Vec::new(),
            deny_tools: Vec::new(),
            approval: ApprovalMode::Off,
            approval_tools: Vec::new(),
            approval_ttl_secs: 86_400,
            reveal_secrets_once: false,
            force_dry_run: false,
            confirm_token_file: None,
            state_dir: None,
        }
    }
}

impl Safety {
    /// The enabled capabilities, sorted.
    pub fn enabled(&self) -> Vec<Capability> {
        let mut caps = self
            .capabilities
            .clone()
            .unwrap_or_else(|| self.profile.capabilities());
        caps.sort();
        caps.dedup();
        caps
    }
}

/// The engagement the work is authorized under. Recorded in every audit entry; mutations are
/// refused outside it.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Scope {
    /// A reference to the written authorization (ticket, statement of work). Free text.
    pub engagement: Option<String>,
    /// RFC 3339. Mutations are refused from this moment on.
    pub expires: Option<String>,
    /// Refuse every mutation unless `engagement` is set.
    pub require_engagement: bool,
    /// When non-empty, tools can only act on these orgs.
    pub allowed_orgs: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    /// Most rows a list result carries.
    pub max_rows: usize,
    /// Most bytes of one captured body in a result.
    pub max_body_bytes: usize,
    /// Most bytes of text in one tool result.
    pub max_result_bytes: usize,
    /// Timeout of one backend request.
    pub request_timeout_secs: u64,
    pub max_calls_per_minute: u32,
    pub max_mutations_per_hour: u32,
    /// Longest session an agent can ask for.
    pub max_session_ttl_secs: u32,
    /// Accept a secret as a tool argument. Off: use `credential_ref`.
    pub allow_inline_secrets: bool,
    /// Most requests served at once per transport.
    pub max_in_flight: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_rows: 100,
            max_body_bytes: 4096,
            max_result_bytes: 256 * 1024,
            request_timeout_secs: 20,
            max_calls_per_minute: 240,
            max_mutations_per_hour: 120,
            max_session_ttl_secs: 3600,
            allow_inline_secrets: false,
            max_in_flight: 16,
        }
    }
}

impl Limits {
    pub fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.request_timeout_secs.max(1))
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AuditConfig {
    /// Append-only JSONL. Default `state_dir/audit.jsonl`.
    pub path: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct MetricsConfig {
    /// Seconds between background scrapes that feed the rate calculations; 0 disables.
    pub sample_interval_secs: u64,
    /// Scrapes kept per role.
    pub history: usize,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            sample_interval_secs: 30,
            history: 120,
        }
    }
}

/// A chat-completions compatible endpoint.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LlmConfig {
    /// Base URL (`https://host/v1`) or the full `.../chat/completions` URL.
    pub endpoint: String,
    pub model: String,
    #[serde(default)]
    pub api_key_file: Option<PathBuf>,
    /// PEM file of extra root certificates to trust, for an endpoint behind a private CA.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    #[serde(default = "default_llm_timeout")]
    pub timeout_secs: u64,
    /// Most characters of captured content sent to the model.
    #[serde(default = "default_llm_input")]
    pub max_input_chars: usize,
    #[serde(default = "default_llm_output")]
    pub max_output_tokens: u32,
    /// A name for this endpoint in audit records. Defaults to the endpoint's host.
    #[serde(default)]
    pub alias: Option<String>,
}

fn default_llm_timeout() -> u64 {
    60
}
fn default_llm_input() -> usize {
    24_000
}
fn default_llm_output() -> u32 {
    1024
}

/// Operator-owned settings of the passive capture-analysis tools. Nothing here can be widened by
/// a tool argument or a model answer.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AnalysisConfig {
    /// Master switch. Off: no analysis tool is listed.
    pub enabled: bool,
    /// Capture sources an analysis scope may name. Required when enabled.
    pub allowed_source_ids: Vec<String>,
    /// Origins an analysis scope may cover: `host`, `*.suffix`, optionally with a scheme and a
    /// port (`https://api.example.com:8443`). Required when enabled.
    pub allowed_origins: Vec<String>,
    /// Allow analysis tools to send sanitized evidence to the `[llm]` endpoint.
    pub allow_external_llm: bool,
    /// Most captures one analysis reads.
    pub max_captures: usize,
    /// Most bytes of capture content (headers and bodies) one analysis reads.
    pub max_input_bytes: usize,
    /// Most bytes of one body an analysis fetches.
    pub max_body_bytes: usize,
    /// Most characters of all content in the prompts of one analysis.
    pub max_total_prompt_chars: usize,
    /// One absolute deadline for an analysis, fetching and model calls together.
    pub deadline_secs: u64,
    /// How long scopes, findings, drafts and feeds are kept in memory.
    pub retention_secs: u64,
    pub auth: AuthAnalysisConfig,
    pub sensitive: SensitiveAnalysisConfig,
    pub query: QueryAnalysisConfig,
    pub openapi: OpenApiAnalysisConfig,
    pub blocks: BlocksAnalysisConfig,
    pub feeds: FeedsAnalysisConfig,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_source_ids: Vec::new(),
            allowed_origins: Vec::new(),
            allow_external_llm: false,
            max_captures: 500,
            max_input_bytes: 256 * 1024,
            max_body_bytes: 16 * 1024,
            max_total_prompt_chars: 24_000,
            deadline_secs: 60,
            retention_secs: 86_400,
            auth: AuthAnalysisConfig::default(),
            sensitive: SensitiveAnalysisConfig::default(),
            query: QueryAnalysisConfig::default(),
            openapi: OpenApiAnalysisConfig::default(),
            blocks: BlocksAnalysisConfig::default(),
            feeds: FeedsAnalysisConfig::default(),
        }
    }
}

/// `[analysis.auth]`: authentication and session-flow discovery.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AuthAnalysisConfig {
    /// Off by default: it needs `fingerprint_key_file`.
    pub enabled: bool,
    /// Most distinct credential values tracked in one analysis.
    pub max_token_candidates: usize,
    /// The operator-held key that turns credential values into fingerprints. Fingerprints only
    /// link within one engagement: the engagement is mixed into every fingerprint.
    pub fingerprint_key_file: Option<PathBuf>,
    /// Report the claim names of a decoded JWT (never values).
    pub include_jwt_claim_names: bool,
}

impl Default for AuthAnalysisConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_token_candidates: 200,
            fingerprint_key_file: None,
            include_jwt_claim_names: false,
        }
    }
}

/// `[analysis.sensitive]`: sensitive-data findings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SensitiveAnalysisConfig {
    pub enabled: bool,
    /// Which finding categories to report: `credential`, `personal_data`, `candidate`.
    pub categories: Vec<String>,
    /// Shannon entropy (bits per character) a high-entropy candidate needs.
    pub min_entropy: f64,
    pub max_findings: usize,
    /// Characters of a match shown in `masked_preview`. 0 shows only the length.
    pub preview_chars: usize,
    /// Extra detectors (TOML `[[rule]]` tables: name, category, severity, pattern). Operator
    /// owned: a model never supplies rules.
    pub custom_rules_file: Option<PathBuf>,
    /// Keep findings for at most this long. Never longer than `analysis.retention_secs`.
    pub retention_secs: Option<u64>,
}

impl Default for SensitiveAnalysisConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            categories: vec![
                "credential".to_owned(),
                "personal_data".to_owned(),
                "candidate".to_owned(),
            ],
            min_entropy: 4.0,
            max_findings: 200,
            preview_chars: 0,
            custom_rules_file: None,
            retention_secs: None,
        }
    }
}

/// `[analysis.query]`: natural-language query drafts.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct QueryAnalysisConfig {
    pub enabled: bool,
    pub max_branches: usize,
    /// Let a draft filter on bodies or payloads (reads the wide columns: the slowest queries).
    pub allow_body_scan: bool,
    /// Let a draft use regular expressions.
    pub allow_regex: bool,
    pub max_regex_bytes: usize,
    pub draft_ttl_secs: u64,
}

impl Default for QueryAnalysisConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_branches: 16,
            allow_body_scan: false,
            allow_regex: false,
            max_regex_bytes: 1000,
            draft_ttl_secs: 600,
        }
    }
}

/// `[analysis.openapi]`: API schema drafts inferred from captures.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct OpenApiAnalysisConfig {
    pub enabled: bool,
    pub max_routes: usize,
    pub max_schema_depth: usize,
    pub max_properties: usize,
    /// `none`: a draft carries no example values. No other value exists yet.
    pub examples: String,
    pub allowed_content_types: Vec<String>,
}

impl Default for OpenApiAnalysisConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_routes: 200,
            max_schema_depth: 12,
            max_properties: 200,
            examples: "none".to_owned(),
            allowed_content_types: vec!["application/json".to_owned()],
        }
    }
}

/// `[analysis.blocks]`: evidence-calibrated block-page classification.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct BlocksAnalysisConfig {
    /// Equivalent observations a classification needs before it is eligible for reporting.
    pub min_observations: usize,
    /// A subtype whose measured precision on the published fixtures is below this is never
    /// eligible for reporting.
    pub min_calibrated_precision: Option<f64>,
    /// Let the model judge pages the rules cannot.
    pub allow_model: bool,
    /// The version of the labelled fixture set the operator calibrated against; echoed in results.
    pub fixture_version: Option<String>,
    /// With `[analysis]` enabled, `report_block_signal` waits for an operator's approval.
    pub report_requires_approval: bool,
}

impl Default for BlocksAnalysisConfig {
    fn default() -> Self {
        Self {
            min_observations: 2,
            min_calibrated_precision: None,
            allow_model: true,
            fixture_version: None,
            report_requires_approval: true,
        }
    }
}

/// `[analysis.feeds]`: cursor-based capture feeds.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct FeedsAnalysisConfig {
    pub enabled: bool,
    pub max_feeds: usize,
    pub ttl_secs: u64,
    pub min_poll_interval_ms: u64,
    pub max_page_rows: usize,
    /// Let a feed carry bodies.
    pub include_bodies: bool,
}

impl Default for FeedsAnalysisConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_feeds: 16,
            ttl_secs: 3600,
            min_poll_interval_ms: 1000,
            max_page_rows: 100,
            include_bodies: false,
        }
    }
}

/// Files that hold the username and password a tool may use by name.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialFiles {
    #[serde(default)]
    pub username: Option<String>,
    pub password_file: PathBuf,
}

impl Config {
    /// Read `path`, or the first of [`DEFAULT_PATHS`] that exists, or the defaults.
    ///
    /// # Errors
    /// When a named or found file cannot be read or does not parse, or fails validation.
    pub fn load(path: Option<&Path>) -> anyhow::Result<(Self, Option<PathBuf>)> {
        let from_env = std::env::var_os("PROXYX_MCP_CONFIG")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from);
        let found = match path.map(Path::to_path_buf).or(from_env) {
            Some(path) => Some(path),
            None => DEFAULT_PATHS
                .iter()
                .map(PathBuf::from)
                .find(|candidate| candidate.is_file()),
        };
        let Some(found) = found else {
            let config = Self::default();
            config.validate()?;
            return Ok((config, None));
        };
        let text = std::fs::read_to_string(&found)
            .with_context(|| format!("cannot read {}", found.display()))?;
        let config = Self::parse(&text).with_context(|| format!("{}", found.display()))?;
        Ok((config, Some(found)))
    }

    /// Parse and validate TOML text.
    ///
    /// # Errors
    /// On a syntax error, an unknown key or a value `validate` refuses.
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let config: Self = toml::from_str(text).context("invalid configuration")?;
        config.validate()?;
        Ok(config)
    }

    /// Check the values that serde cannot.
    ///
    /// # Errors
    /// With the first problem found.
    pub fn validate(&self) -> anyhow::Result<()> {
        if let Some(pool) = &self.endpoints.pool {
            check_url("endpoints.pool.url", &pool.url)?;
            ensure!(
                is_operator(&pool.operator),
                "endpoints.pool.operator must be 1 to 64 characters of [A-Za-z0-9-_.@]"
            );
        }
        if let Some(control) = &self.endpoints.control {
            check_url("endpoints.control.url", &control.url)?;
            ensure!(
                is_org_id(&control.org),
                "endpoints.control.org must be 1 to 64 characters of [a-z0-9_-]"
            );
        }
        let mut names = std::collections::BTreeSet::new();
        for role in &self.endpoints.roles {
            check_url(&format!("endpoints.roles[{}].url", role.name), &role.url)?;
            ensure!(
                !role.name.is_empty()
                    && role
                        .name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
                "role names are 1 or more of [A-Za-z0-9_-]: {:?}",
                role.name
            );
            ensure!(
                names.insert(&role.name),
                "duplicate role name {:?}",
                role.name
            );
        }
        for org in &self.scope.allowed_orgs {
            ensure!(is_org_id(org), "scope.allowed_orgs: invalid org id {org:?}");
        }
        if let Some(expires) = &self.scope.expires {
            time::OffsetDateTime::parse(expires, &time::format_description::well_known::Rfc3339)
                .with_context(|| format!("scope.expires {expires:?} is not an RFC 3339 time"))?;
        }
        ensure!(
            self.limits.max_rows >= 1,
            "limits.max_rows must be at least 1"
        );
        ensure!(
            self.limits.max_result_bytes >= 1024,
            "limits.max_result_bytes must be at least 1024"
        );
        ensure!(
            self.limits.max_in_flight >= 1,
            "limits.max_in_flight must be at least 1"
        );
        ensure!(
            self.http.path.starts_with('/') && self.http.path.len() > 1,
            "http.path must start with / and name a path"
        );
        self.http
            .bind
            .parse::<std::net::SocketAddr>()
            .with_context(|| format!("http.bind {:?} is not a socket address", self.http.bind))?;
        if self.safety.approval == ApprovalMode::Listed {
            ensure!(
                !self.safety.approval_tools.is_empty(),
                "safety.approval = \"listed\" needs safety.approval_tools"
            );
        }
        ensure!(
            self.safety.approval_ttl_secs >= 60,
            "safety.approval_ttl_secs must be at least 60"
        );
        for (name, files) in &self.credentials {
            ensure!(
                !name.is_empty()
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
                "credential names are 1 or more of [A-Za-z0-9_-]: {name:?}"
            );
            if let Some(username) = &files.username {
                ensure!(
                    !username.is_empty() && username.len() <= 255 && !username.contains('\0'),
                    "credentials.{name}.username must be 1 to 255 bytes without NUL"
                );
            }
        }
        if let Some(llm) = &self.llm {
            check_url("llm.endpoint", &llm.endpoint)?;
            ensure!(!llm.model.trim().is_empty(), "llm.model must not be empty");
            ensure!(llm.timeout_secs >= 1, "llm.timeout_secs must be at least 1");
            if let Some(alias) = &llm.alias {
                ensure!(
                    is_operator(alias),
                    "llm.alias must be 1 to 64 characters of [A-Za-z0-9-_.@]"
                );
            }
        }
        self.analysis.validate()?;
        Ok(())
    }

    /// Where pending changes, written secrets and the session registry live.
    pub fn state_dir(&self) -> PathBuf {
        self.safety.state_dir.clone().unwrap_or_else(|| {
            std::env::var_os("XDG_STATE_HOME")
                .map(PathBuf::from)
                .or_else(|| {
                    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state"))
                })
                .unwrap_or_else(|| PathBuf::from("."))
                .join("proxyx-mcp")
        })
    }

    /// The audit log path.
    pub fn audit_path(&self) -> PathBuf {
        self.audit
            .path
            .clone()
            .unwrap_or_else(|| self.state_dir().join("audit.jsonl"))
    }
}

fn check_url(field: &str, text: &str) -> anyhow::Result<()> {
    let url = reqwest::Url::parse(text)
        .map_err(|error| anyhow::anyhow!("{field}: not a URL ({error})"))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        bail!("{field} must be an absolute http or https URL");
    }
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "{field} must not carry credentials; put them in a *_file setting"
    );
    Ok(())
}

/// `[A-Za-z0-9-_.@]{1,64}`: what the pool control API accepts as `X-Operator`.
pub fn is_operator(text: &str) -> bool {
    (1..=64).contains(&text.len())
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'@'))
}

/// `[a-z0-9_-]{1,64}`: an org id.
pub fn is_org_id(text: &str) -> bool {
    (1..=64).contains(&text.len())
        && text
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// `[a-z0-9_-]{1,48}`: a provider id.
pub fn is_provider_id(text: &str) -> bool {
    (1..=48).contains(&text.len())
        && text
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

impl AnalysisConfig {
    /// Check the values that serde cannot.
    ///
    /// # Errors
    /// With the first problem found.
    pub fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            self.max_captures >= 1 && self.max_captures <= 5000,
            "analysis.max_captures must be 1 to 5000"
        );
        ensure!(
            self.max_input_bytes >= 1024,
            "analysis.max_input_bytes must be at least 1024"
        );
        ensure!(
            self.max_body_bytes >= 1,
            "analysis.max_body_bytes must be at least 1"
        );
        ensure!(
            self.max_total_prompt_chars >= 256,
            "analysis.max_total_prompt_chars must be at least 256"
        );
        ensure!(
            self.deadline_secs >= 1,
            "analysis.deadline_secs must be at least 1"
        );
        ensure!(
            self.retention_secs >= 1,
            "analysis.retention_secs must be at least 1"
        );
        for source in &self.allowed_source_ids {
            ensure!(
                is_source_id(source),
                "analysis.allowed_source_ids: invalid source id {source:?} (1 to 128 of [A-Za-z0-9._:-])"
            );
        }
        for origin in &self.allowed_origins {
            crate::analysis::OriginPattern::parse(origin).map_err(|error| {
                anyhow::anyhow!("analysis.allowed_origins: {origin:?}: {error}")
            })?;
        }
        ensure!(
            self.allowed_origins.len() <= 64,
            "analysis.allowed_origins lists at most 64 origins"
        );
        if self.enabled {
            ensure!(
                !self.allowed_source_ids.is_empty(),
                "analysis.enabled needs analysis.allowed_source_ids: an analysis reads only sources an operator named"
            );
            ensure!(
                !self.allowed_origins.is_empty(),
                "analysis.enabled needs analysis.allowed_origins: an analysis covers only origins an operator named"
            );
        }
        if self.auth.enabled {
            ensure!(
                self.auth.fingerprint_key_file.is_some(),
                "analysis.auth.enabled needs analysis.auth.fingerprint_key_file"
            );
        }
        ensure!(
            self.auth.max_token_candidates >= 1,
            "analysis.auth.max_token_candidates must be at least 1"
        );
        for category in &self.sensitive.categories {
            ensure!(
                matches!(
                    category.as_str(),
                    "credential" | "personal_data" | "candidate"
                ),
                "analysis.sensitive.categories: {category:?} is not credential, personal_data or candidate"
            );
        }
        ensure!(
            self.sensitive.min_entropy > 0.0 && self.sensitive.min_entropy <= 8.0,
            "analysis.sensitive.min_entropy must be above 0 and at most 8"
        );
        ensure!(
            self.sensitive.max_findings >= 1,
            "analysis.sensitive.max_findings must be at least 1"
        );
        ensure!(
            self.sensitive.preview_chars <= 8,
            "analysis.sensitive.preview_chars is at most 8"
        );
        ensure!(
            self.sensitive.retention_secs.is_none_or(|secs| secs >= 1),
            "analysis.sensitive.retention_secs must be at least 1"
        );
        ensure!(
            (1..=64).contains(&self.query.max_branches),
            "analysis.query.max_branches must be 1 to 64"
        );
        ensure!(
            (1..=1000).contains(&self.query.max_regex_bytes),
            "analysis.query.max_regex_bytes must be 1 to 1000"
        );
        ensure!(
            self.query.draft_ttl_secs >= 1,
            "analysis.query.draft_ttl_secs must be at least 1"
        );
        ensure!(
            self.openapi.max_routes >= 1,
            "analysis.openapi.max_routes must be at least 1"
        );
        ensure!(
            (1..=32).contains(&self.openapi.max_schema_depth),
            "analysis.openapi.max_schema_depth must be 1 to 32"
        );
        ensure!(
            self.openapi.max_properties >= 1,
            "analysis.openapi.max_properties must be at least 1"
        );
        ensure!(
            self.openapi.examples == "none",
            "analysis.openapi.examples must be \"none\" (no other value exists)"
        );
        ensure!(
            !self.openapi.allowed_content_types.is_empty(),
            "analysis.openapi.allowed_content_types must not be empty"
        );
        ensure!(
            self.blocks.min_observations >= 1,
            "analysis.blocks.min_observations must be at least 1"
        );
        if let Some(precision) = self.blocks.min_calibrated_precision {
            ensure!(
                (0.0..=1.0).contains(&precision),
                "analysis.blocks.min_calibrated_precision must be between 0 and 1"
            );
        }
        ensure!(
            (1..=64).contains(&self.feeds.max_feeds),
            "analysis.feeds.max_feeds must be 1 to 64"
        );
        ensure!(
            self.feeds.ttl_secs >= 1,
            "analysis.feeds.ttl_secs must be at least 1"
        );
        ensure!(
            (1..=1000).contains(&self.feeds.max_page_rows),
            "analysis.feeds.max_page_rows must be 1 to 1000"
        );
        Ok(())
    }
}

/// `[A-Za-z0-9._:-]{1,128}`: a capture source id.
pub fn is_source_id(text: &str) -> bool {
    (1..=128).contains(&text.len())
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

/// Read a credential file: trimmed, non-empty. Warns when others can read it.
///
/// # Errors
/// When the file is missing, unreadable or empty. The error names the file, never its content.
pub fn read_secret(path: &Path) -> anyhow::Result<Secret> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read secret file {}", path.display()))?;
    let value = text.trim();
    ensure!(!value.is_empty(), "secret file {} is empty", path.display());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if let Ok(meta) = std::fs::metadata(path)
            && meta.permissions().mode() & 0o077 != 0
        {
            tracing::warn!(
                file = %path.display(),
                "secret file is readable by group or others; restrict it to the owner"
            );
        }
    }
    Ok(Secret::new(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_read_only_and_valid() {
        let config = Config::default();
        config.validate().expect("defaults validate");
        assert!(config.safety.enabled().is_empty());
        assert!(!config.safety.reveal_secrets_once);
        assert_eq!(config.http.bind, DEFAULT_BIND);
    }

    #[test]
    fn profiles_expand_and_explicit_capabilities_win() {
        let mut safety = Safety {
            profile: Profile::Operator,
            ..Safety::default()
        };
        assert_eq!(
            safety.enabled(),
            vec![
                Capability::Sessions,
                Capability::OrgBlocks,
                Capability::Signals
            ]
        );
        safety.capabilities = Some(vec![Capability::Policy]);
        assert_eq!(safety.enabled(), vec![Capability::Policy]);
        safety.profile = Profile::Admin;
        safety.capabilities = None;
        assert_eq!(safety.enabled().len(), Capability::ALL.len());
    }

    #[test]
    fn the_shipped_example_parses_and_is_read_only() {
        let config =
            Config::parse(include_str!("../../../examples/mcp.toml")).expect("example parses");
        assert!(config.safety.enabled().is_empty());
        assert_eq!(config.endpoints.roles.len(), 5);
        assert!(config.llm.is_none());
        assert!(!config.safety.reveal_secrets_once && !config.limits.allow_inline_secrets);
    }

    #[test]
    fn unknown_keys_and_bad_values_are_refused() {
        assert!(Config::parse("[safety]\nprofle = \"admin\"").is_err());
        assert!(
            Config::parse("[endpoints.pool]\nurl = \"ftp://x\"\nadmin_token_file = \"/t\"")
                .is_err()
        );
        assert!(
            Config::parse("[endpoints.pool]\nurl = \"http://u:p@x\"\nadmin_token_file = \"/t\"")
                .is_err()
        );
        assert!(Config::parse("[safety]\napproval = \"listed\"").is_err());
        assert!(Config::parse("[scope]\nexpires = \"tomorrow\"").is_err());
        assert!(Config::parse("[http]\nbind = \"not-an-address\"").is_err());
    }

    #[test]
    fn id_checks_match_the_gateway_rules() {
        assert!(is_org_id("acme-1_x"));
        assert!(!is_org_id("Acme"));
        assert!(!is_org_id(""));
        assert!(is_operator("proxyx-mcp"));
        assert!(!is_operator("with space"));
        assert!(is_provider_id("isp_static_port"));
    }
}
