//! Session caching policy and inbound username options.
//!
//! # Policy file format
//!
//! A file is a list of `[[policy]]` tables. Every field but `name` is
//! optional and an unknown field is an error. Durations are seconds or
//! `30s`, `5m`, `2h`, `1d`, at most `366d`. `data/policies/global.toml` spells out every
//! default.
//!
//! ```toml
//! [[policy]]
//! name = "fr-web"                  # unique across all files
//! scope = "route_class"            # global (default) | route_class | org
//! match = "isp_static_port"            # provider id (route_class) or org id (org)
//! kinds = ["static", "rotating"]   # preference order
//! providers = ["isp_static_port"]      # priority order; unset: every configured provider
//! regions = ["fr/paris", "fr"]     # fallback order; required after merging
//! pool = "shared"                  # only "shared": "private" is refused (use a customer upstream)
//! min_ready = 10                   # per region; static: healthy IPs
//! max_ready = 20                   # unset: 2 x the region's min_ready
//! low_watermark = 5                # unset: half the region's min_ready
//! low_for = "2m"                   # ready below low_watermark this long: cache_low alert
//! lease_ttl = "10m"
//! lease_wait = "3s"
//! create_deadline = "6s"
//! orgs_hard = 2                    # unset: no cap on orgs per IP or session
//! max_conns_per_ip = 40            # unset: 80% of the provider limit
//! rest_after_release = "30s"       # these three are soft limits: with no unit left within
//!                                  # them the lease breaks rest, orgs_hard, max_conns, in that order
//! max_tunnels_per_org = 200        # unset: no cap; in a route_class: the org's tunnels on that provider
//! max_sticky_entries_per_org = 10000 # unset: no cap; scopes can only lower it
//! sticky_scope = "org"             # org | target | connection
//! on_score_unavailable = "allow"   # allow | deny
//!
//! [policy.min_ready_by_region]     # exact region, else country, else min_ready
//! "fr/paris" = 20
//!
//! [policy.criteria]
//! max_risk = 75
//! max_ttfb_ms = 3000
//! max_load_ms = 10000
//! min_success = 0.66
//! browser_sample = 0.05
//! verdict_max_age = "24h"
//!
//! [policy.on_empty]                # static default wait, rotating default create
//! static = "wait"                  # wait | fail
//! rotating = "create"              # create | wait | fail
//!
//! [policy.dial]
//! race = 1                        # concurrent candidate dials, from 1 through 16
//!
//! [policy.block]
//! target_cooldown = "30m"
//! escalate_targets = 3
//! escalate_signals = 5
//! signal_window = "30m"
//! max_cooldown_share = 0.5
//!
//! [policy.static]                  # also: [policy.mobile_box]
//! cooldown = "15m"
//!
//! [policy.rotating]
//! headroom = 0                     # extra ready sessions per lease per minute (the floor)
//! headroom_auto = false            # true: also cover lease rate x measured create time
//!
//! [policy.cost]                    # checked against [policy.limits]
//! max_gb_per_day = 5
//!
//! [policy.limits]                  # ceilings; a lower scope can only lower them
//! max_gb_per_day = 20
//! org_max_gb_per_day = 50          # per org and day; new tunnels get 503 org_budget
//! ```
//!
//! # Precedence
//!
//! `global` < `route_class` < `org`, field by field: a field that a more
//! specific policy sets replaces the value of a less specific one, a field it
//! leaves out keeps it. Lists (`kinds`, `providers`, `regions`) are replaced as
//! a whole; `min_ready_by_region` merges per region. `limits` and
//! `max_sticky_entries_per_org` are ceilings: the lowest value in the chain
//! wins, and a `cost` value above its ceiling makes the whole set invalid
//! ([`PolicySet::from_docs`]).
//!
//! # Several providers
//!
//! `providers` is a priority order. The gateway walks it with the tiers and the
//! soft limits applied across all providers: a normal unit within its limits of
//! any provider goes first (the first provider in the list on a tie), then a
//! degraded one within them, and only then does a lease break `rest_after_release`,
//! `orgs_hard`, `max_conns_per_ip` or the fair-use stop (that order, a normal unit
//! before a degraded one). A sticky key whose lease moved to a later provider
//! stays there for a minute before it may go back to an earlier one. A route
//! class's `max_tunnels_per_org` counts the org's tunnels on that provider only;
//! the global or org value caps the org's tunnels in total.
//!
//! # Inbound options
//!
//! [`InboundOptions::parse`] reads the proxy username, and
//! [`EffectivePolicy::narrow`] turns it into a [`LeaseRequest`].
//! `px-strict-true` requests strict lease selection; omitted or `false` keeps
//! the default lease behaviour.

mod doc;
mod effective;
mod error;
mod inbound;
mod set;

pub use doc::{
    AfterRelease, BlockDoc, CostDoc, CriteriaDoc, DialDoc, LimitsDoc, MobileBoxDoc, OnEmpty,
    OnEmptyDoc, OnScoreUnavailable, PolicyDoc, PolicyFile, Pool, RotatingDoc, Scope, StabilityDoc,
    StaticDoc,
};
pub use effective::{
    BlockRules, Capacity, Cost, Criteria, DialRules, EffectivePolicy, Limits, MobileBoxRules,
    OnEmptyByKind, ReadyTarget, RotatingRules, Stability, StaticRules,
};
pub use error::PolicyError;
pub use inbound::{InboundOptions, LeaseRequest, MAX_USERNAME_LEN, StickyKeySource};
pub use set::PolicySet;
