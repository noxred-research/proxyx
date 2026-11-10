//! The gate every tool call passes: which tools exist for this server, whether a mutation may
//! run, and how often calls may be made.
//!
//! Defaults fail closed: a read-only profile enables no mutating capability, and a mutation
//! also needs an unexpired engagement when the configuration requires one, an org inside the
//! allowed scope, and room in the hourly mutation budget.

use std::collections::{BTreeSet, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::config::{ApprovalMode, Capability, Config};

/// Why a call was refused. The text is shown to the model, so it says how to fix it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal(pub String);

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refusal {}

/// The enforcement state of one server.
#[derive(Debug)]
pub struct Gate {
    enabled: BTreeSet<Capability>,
    allow: Vec<String>,
    deny: Vec<String>,
    approval: ApprovalMode,
    approval_tools: Vec<String>,
    force_dry_run: bool,
    engagement: Option<String>,
    require_engagement: bool,
    expires: Option<OffsetDateTime>,
    allowed_orgs: Vec<String>,
    max_calls_per_minute: u32,
    max_mutations_per_hour: u32,
    calls: Mutex<VecDeque<Instant>>,
    mutations: Mutex<VecDeque<Instant>>,
}

/// True when `name` matches `pattern`: equal, or `pattern` ends in `*` and is a prefix.
pub fn glob(pattern: &str, name: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => pattern == name,
    }
}

fn admit(window: &Mutex<VecDeque<Instant>>, span: Duration, limit: u32) -> bool {
    let mut window = window
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let now = Instant::now();
    while window
        .front()
        .is_some_and(|at| now.duration_since(*at) >= span)
    {
        window.pop_front();
    }
    if window.len() >= limit as usize {
        return false;
    }
    window.push_back(now);
    true
}

impl Gate {
    pub fn new(config: &Config) -> Self {
        let expires = config
            .scope
            .expires
            .as_deref()
            .and_then(|text| OffsetDateTime::parse(text, &Rfc3339).ok());
        Self {
            enabled: config.safety.enabled().into_iter().collect(),
            allow: config.safety.allow_tools.clone(),
            deny: config.safety.deny_tools.clone(),
            approval: config.safety.approval,
            approval_tools: config.safety.approval_tools.clone(),
            force_dry_run: config.safety.force_dry_run,
            engagement: config.scope.engagement.clone(),
            require_engagement: config.scope.require_engagement,
            expires,
            allowed_orgs: config.scope.allowed_orgs.clone(),
            max_calls_per_minute: config.limits.max_calls_per_minute,
            max_mutations_per_hour: config.limits.max_mutations_per_hour,
            calls: Mutex::new(VecDeque::new()),
            mutations: Mutex::new(VecDeque::new()),
        }
    }

    pub fn enabled(&self) -> &BTreeSet<Capability> {
        &self.enabled
    }

    pub fn has(&self, capability: Capability) -> bool {
        self.enabled.contains(&capability)
    }

    /// The tool passes the allow and deny lists.
    pub fn tool_allowed(&self, name: &str) -> bool {
        if self.deny.iter().any(|pattern| glob(pattern, name)) {
            return false;
        }
        self.allow.is_empty() || self.allow.iter().any(|pattern| glob(pattern, name))
    }

    pub fn force_dry_run(&self) -> bool {
        self.force_dry_run
    }

    /// Whether `tool` needs an operator's approval before it runs.
    pub fn approval_required(&self, tool: &str) -> bool {
        match self.approval {
            ApprovalMode::Off => false,
            ApprovalMode::All => true,
            ApprovalMode::Listed => self
                .approval_tools
                .iter()
                .any(|pattern| glob(pattern, tool)),
        }
    }

    pub fn engagement(&self) -> Option<&str> {
        self.engagement.as_deref()
    }

    /// Count one call against the per-minute budget.
    ///
    /// # Errors
    /// [`Refusal`] when the budget is spent.
    pub fn admit_call(&self) -> Result<(), Refusal> {
        if admit(
            &self.calls,
            Duration::from_secs(60),
            self.max_calls_per_minute,
        ) {
            Ok(())
        } else {
            Err(Refusal(format!(
                "rate limit: more than {} tool calls in a minute; wait and retry",
                self.max_calls_per_minute
            )))
        }
    }

    /// The org scope check, for read and write tools alike.
    ///
    /// # Errors
    /// [`Refusal`] when `org` is outside `scope.allowed_orgs`.
    pub fn check_org(&self, org: &str) -> Result<(), Refusal> {
        if self.allowed_orgs.is_empty() || self.allowed_orgs.iter().any(|allowed| allowed == org) {
            Ok(())
        } else {
            Err(Refusal(format!(
                "org {org:?} is outside this server's authorized scope (scope.allowed_orgs)"
            )))
        }
    }

    /// Everything a mutation needs before it may even be prepared: capability, engagement,
    /// scope and budget. Called with the capability of the tool and the org it acts on.
    ///
    /// # Errors
    /// [`Refusal`] naming what is missing.
    pub fn check_mutation(&self, capability: Capability, org: Option<&str>) -> Result<(), Refusal> {
        self.check_applicable(capability, org)?;
        self.admit_mutation()
    }

    /// Count one mutation against the hourly budget. Dry runs and previews do not count.
    ///
    /// # Errors
    /// [`Refusal`] when the budget is spent.
    pub fn admit_mutation(&self) -> Result<(), Refusal> {
        if admit(
            &self.mutations,
            Duration::from_secs(3600),
            self.max_mutations_per_hour,
        ) {
            Ok(())
        } else {
            Err(Refusal(format!(
                "rate limit: more than {} mutations in an hour",
                self.max_mutations_per_hour
            )))
        }
    }

    /// True when the server is not limited to specific orgs, so changes to shared resources
    /// (global policies, inventory, operator block signals) are within its scope.
    pub fn unscoped(&self) -> bool {
        self.allowed_orgs.is_empty()
    }

    /// Capability, engagement and scope only (no budget): used when a proposal is prepared.
    ///
    /// # Errors
    /// [`Refusal`] naming what is missing.
    pub fn check_applicable(
        &self,
        capability: Capability,
        org: Option<&str>,
    ) -> Result<(), Refusal> {
        if !self.has(capability) {
            return Err(Refusal(format!(
                "this server is not allowed to {}: capability `{}` is not enabled (profile or safety.capabilities in the server configuration). An operator enables it; the model cannot.",
                describe(capability),
                capability.as_str()
            )));
        }
        if self.require_engagement && self.engagement.is_none() {
            return Err(Refusal(
                "mutations need an engagement: set scope.engagement to the reference of the written authorization".into(),
            ));
        }
        if let Some(expires) = self.expires
            && OffsetDateTime::now_utc() >= expires
        {
            return Err(Refusal(format!(
                "the engagement authorization expired at {}",
                expires.format(&Rfc3339).unwrap_or_default()
            )));
        }
        if let Some(org) = org {
            self.check_org(org)?;
        }
        Ok(())
    }
}

fn describe(capability: Capability) -> &'static str {
    match capability {
        Capability::Sessions => "create, extend or end sessions",
        Capability::OrgKeys => "create or disable org keys",
        Capability::OrgLimits => "change org rate limits",
        Capability::Egress => "change egress proxies or customer upstreams",
        Capability::OrgBlocks => "create or lift org blocks",
        Capability::Signals => "report block signals",
        Capability::Policy => "write or delete policies",
        Capability::Inventory => "replace static inventory",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gate(toml: &str) -> Gate {
        Gate::new(&Config::parse(toml).expect("config"))
    }

    #[test]
    fn read_only_refuses_every_mutation() {
        let gate = gate("");
        for capability in Capability::ALL {
            let refusal = gate.check_mutation(capability, None).expect_err("refused");
            assert!(refusal.0.contains(capability.as_str()));
        }
    }

    #[test]
    fn capability_engagement_scope_and_expiry() {
        let gate = gate(
            "[safety]\nprofile = \"operator\"\n[scope]\nrequire_engagement = true\nallowed_orgs = [\"acme\"]",
        );
        assert!(
            gate.check_mutation(Capability::Sessions, Some("acme"))
                .is_err(),
            "no engagement"
        );
        let gate = self::gate(
            "[safety]\nprofile = \"operator\"\n[scope]\nengagement = \"SOW-1\"\nallowed_orgs = [\"acme\"]",
        );
        assert!(
            gate.check_mutation(Capability::Sessions, Some("acme"))
                .is_ok()
        );
        assert!(
            gate.check_mutation(Capability::Sessions, Some("other"))
                .is_err()
        );
        assert!(
            gate.check_mutation(Capability::Policy, Some("acme"))
                .is_err()
        );
        let expired = self::gate(
            "[safety]\nprofile = \"admin\"\n[scope]\nexpires = \"2020-01-01T00:00:00Z\"",
        );
        assert!(
            expired
                .check_mutation(Capability::Policy, None)
                .expect_err("expired")
                .0
                .contains("expired")
        );
    }

    #[test]
    fn allow_and_deny_lists_use_prefix_globs() {
        let gate = gate(
            "[safety]\nallow_tools = [\"list_*\", \"health\"]\ndeny_tools = [\"list_secrets\"]",
        );
        assert!(gate.tool_allowed("list_policies"));
        assert!(gate.tool_allowed("health"));
        assert!(!gate.tool_allowed("create_session"));
        assert!(!gate.tool_allowed("list_secrets"));
    }

    #[test]
    fn budgets_are_enforced() {
        let gate = gate(
            "[safety]\nprofile = \"admin\"\n[limits]\nmax_mutations_per_hour = 2\nmax_calls_per_minute = 3",
        );
        assert!(gate.check_mutation(Capability::Policy, None).is_ok());
        assert!(gate.check_mutation(Capability::Policy, None).is_ok());
        assert!(gate.check_mutation(Capability::Policy, None).is_err());
        for _ in 0..3 {
            assert!(gate.admit_call().is_ok());
        }
        assert!(gate.admit_call().is_err());
    }

    #[test]
    fn approval_modes() {
        let off = gate("");
        assert!(!off.approval_required("put_policy"));
        let all = gate("[safety]\napproval = \"all\"");
        assert!(all.approval_required("anything"));
        let listed = gate("[safety]\napproval = \"listed\"\napproval_tools = [\"put_*\"]");
        assert!(listed.approval_required("put_policy"));
        assert!(!listed.approval_required("create_session"));
    }
}
