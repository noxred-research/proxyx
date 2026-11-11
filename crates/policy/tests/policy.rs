use std::path::Path;
use std::time::Duration;

use common::types::{Kind, OrgId, ProviderId, Region};
use proxyx_policy::{EffectivePolicy, OnEmpty, PolicyDoc, PolicyError, PolicyFile, PolicySet};

fn org(s: &str) -> OrgId {
    s.parse().expect("test org")
}

fn provider(s: &str) -> ProviderId {
    s.parse().expect("test provider")
}

fn region(s: &str) -> Region {
    s.parse().expect("test region")
}

fn docs(text: &str) -> Vec<PolicyDoc> {
    PolicyFile::parse(text).expect("parse").policies
}

fn set(text: &str) -> Result<PolicySet, PolicyError> {
    PolicySet::from_docs(docs(text))
}

fn ok(text: &str) -> PolicySet {
    set(text).expect("valid set")
}

/// The global effective policy of `text`, for org `a`.
fn eff(text: &str) -> EffectivePolicy {
    ok(text).effective(&org("a"), None).clone()
}

fn err(text: &str) -> PolicyError {
    match set(text) {
        Ok(_) => panic!("expected an error for:\n{text}"),
        Err(e) => e,
    }
}

fn invalid_field(text: &str) -> &'static str {
    match err(text) {
        PolicyError::Invalid { field, .. } => field,
        e => panic!("expected Invalid for:\n{text}\ngot {e}"),
    }
}

fn ceiling_field(text: &str) -> &'static str {
    match err(text) {
        PolicyError::AboveCeiling { field, .. } => field,
        e => panic!("expected AboveCeiling for:\n{text}\ngot {e}"),
    }
}

fn rejected_at_parse(text: &str) -> bool {
    matches!(PolicyFile::parse(text), Err(PolicyError::Toml(_)))
}

/// The key of the last `key = value` line of `body`.
fn key(body: &str) -> &str {
    body.lines()
        .last()
        .and_then(|l| l.split(' ').next())
        .expect("a key")
}

/// `(min_ready, max_ready, low_watermark)` of `region` under `p`.
fn target(p: &EffectivePolicy, r: &str) -> (u32, u32, u32) {
    let t = p.capacity.target(&region(r));
    (t.min_ready, t.max_ready, t.low_watermark)
}

const GLOBAL: &str = "[[policy]]\nname = \"global\"\nregions = [\"fr\"]\n";

fn global_with(extra: &str) -> String {
    format!("{GLOBAL}{extra}\n")
}

fn org_doc(name: &str, id: &str, body: &str) -> String {
    format!("\n[[policy]]\nname = \"{name}\"\nscope = \"org\"\nmatch = \"{id}\"\n{body}\n")
}

fn rc_doc(name: &str, id: &str, body: &str) -> String {
    format!("\n[[policy]]\nname = \"{name}\"\nscope = \"route_class\"\nmatch = \"{id}\"\n{body}\n")
}

/// `base` plus the org policy `o` of org `acme`.
fn with_org(base: &str, body: &str) -> String {
    format!("{base}{}", org_doc("o", "acme", body))
}

#[test]
fn defaults_are_the_proposal_values() {
    let p = eff(GLOBAL);
    assert_eq!(p.kinds, [Kind::Static, Kind::Rotating]);
    assert!(p.providers.is_empty());
    assert_eq!(p.capacity.min_ready, 10);
    assert_eq!(target(&p, "fr"), (10, 20, 5));
    assert_eq!(p.capacity.low_for, Duration::from_secs(120));
    assert_eq!(p.cost.max_gb_per_day, 5.0);
    assert_eq!(p.cost.max_creates_per_hour, 600);
    assert_eq!(p.cost.fair_use_gb_per_ip_month, 80.0);
    assert_eq!(p.on_empty.static_ips, OnEmpty::Wait);
    assert_eq!(p.on_empty.rotating, OnEmpty::Create);
    assert_eq!(p.lease_ttl, Duration::from_secs(600));
    assert_eq!(p.lease_wait, Duration::from_secs(3));
    assert_eq!(p.create_deadline, Duration::from_secs(6));
    assert_eq!(p.orgs_hard, None);
    assert_eq!(p.max_tunnels_per_org, None);
    assert_eq!(p.max_sticky_entries_per_org, None);
    assert_eq!(p.dial.race, 1);
    assert_eq!(p.criteria.max_risk, 75);
    assert_eq!(p.criteria.min_success, 0.66);
    assert_eq!(p.criteria.browser_sample, 0.05);
    assert_eq!(p.rotating.keepalive, Duration::from_secs(30));
    assert_eq!(
        (
            p.rotating.stability.changes_per_hour,
            p.rotating.stability.drops_per_hour
        ),
        (2, 3)
    );
}

#[test]
fn shipped_global_policy_equals_the_schema_defaults() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/policies");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .expect("data/policies exists")
        .map(|entry| entry.expect("dir entry").path())
        .filter(|path| path.extension().is_some_and(|e| e == "toml"))
        .collect();
    files.sort();
    let shipped_docs = files
        .iter()
        .flat_map(|path| docs(&std::fs::read_to_string(path).expect("read policy file")))
        .collect();
    let shipped = PolicySet::from_docs(shipped_docs).expect("data/policies loads");
    let defaults = ok("[[policy]]\nname = \"g\"\nregions = [\"fr\", \"de\"]\n");
    assert_eq!(
        shipped.effective(&org("acme"), None),
        defaults.effective(&org("acme"), None)
    );
}

#[test]
fn duration_formats() {
    let p = eff(&global_with(
        "lease_ttl = \"2h\"\nlease_wait = 7\ncreate_deadline = \"90s\"\nlow_for = \"5m\"\n",
    ));
    assert_eq!(p.lease_ttl, Duration::from_secs(7_200));
    assert_eq!(p.lease_wait, Duration::from_secs(7));
    assert_eq!(p.create_deadline, Duration::from_secs(90));
    assert_eq!(p.capacity.low_for, Duration::from_secs(300));
    assert!(rejected_at_parse(&global_with("lease_ttl = \"5x\"")));

    // 366 days is the longest accepted duration
    let p = eff(&global_with("lease_ttl = \"366d\""));
    assert_eq!(p.lease_ttl, Duration::from_secs(366 * 86_400));
    for body in ["lease_ttl = \"367d\"", "rotating.max_age = 99999999999"] {
        assert!(rejected_at_parse(&global_with(body)), "{body}");
    }
}

/// One field, as a TOML value for the global, route-class and org policy.
/// Values use single quotes (TOML literal strings) to stay short.
struct Case {
    field: &'static str,
    get: fn(&EffectivePolicy) -> String,
    values: [&'static str; 3],
}

/// `case!(toml.key, g, r, o)` reads `p.toml.key`; `case!("key", path, g, r, o)`
/// names the TOML key apart from the field path; `case!(static.key, ..)` is
/// the `[policy.static]` table, which the policy keeps in `static_ips`.
macro_rules! case {
    ($field:literal, $($path:ident).+, $g:literal, $r:literal, $o:literal) => {
        Case {
            field: $field,
            get: |p| format!("{:?}", p.$($path).+),
            values: [$g, $r, $o],
        }
    };
    (static.$f:ident, $g:literal, $r:literal, $o:literal) => {
        Case {
            field: concat!("static.", stringify!($f)),
            get: |p| format!("{:?}", p.static_ips.$f),
            values: [$g, $r, $o],
        }
    };
    ($($path:ident).+, $g:literal, $r:literal, $o:literal) => {
        Case {
            field: stringify!($($path).+),
            get: |p| format!("{:?}", p.$($path).+),
            values: [$g, $r, $o],
        }
    };
}

impl Case {
    fn layer(&self, i: usize) -> String {
        format!("{} = {}", self.field, self.values[i])
    }

    /// A global policy that sets only this field (and `regions`, unless it is the field).
    fn global(&self, i: usize) -> String {
        let regions = if self.field == "regions" {
            ""
        } else {
            "regions = ['fr']\n"
        };
        format!("[[policy]]\nname = 'g'\n{regions}{}\n", self.layer(i))
    }
}

fn cases() -> Vec<Case> {
    vec![
        case!(
            kinds,
            "['static']",
            "['rotating']",
            "['rotating', 'static']"
        ),
        case!(providers, "['a']", "['b']", "['c']"),
        case!(regions, "['fr']", "['de']", "['us']"),
        case!("min_ready", capacity.min_ready, "5", "6", "7"),
        case!(
            "on_empty.static",
            on_empty.static_ips,
            "'wait'",
            "'fail'",
            "'wait'"
        ),
        case!("max_ready", capacity.max_ready, "30", "40", "50"),
        case!("low_watermark", capacity.low_watermark, "1", "2", "3"),
        case!("low_for", capacity.low_for, "'1m'", "'2m'", "'3m'"),
        case!(criteria.max_risk, "60", "65", "70"),
        case!(criteria.max_ttfb_ms, "1000", "2000", "4000"),
        case!(criteria.max_load_ms, "5000", "6000", "7000"),
        case!(criteria.min_success, "0.5", "0.6", "0.7"),
        case!(criteria.browser_sample, "0.1", "0.2", "0.3"),
        case!(criteria.verdict_max_age, "'1h'", "'2h'", "'3h'"),
        case!(on_score_unavailable, "'allow'", "'deny'", "'allow'"),
        case!(lease_ttl, "'1m'", "'2m'", "'3m'"),
        case!(on_empty.rotating, "'wait'", "'fail'", "'create'"),
        case!(lease_wait, "'1s'", "'2s'", "'4s'"),
        case!(create_deadline, "'1s'", "'2s'", "'4s'"),
        case!(orgs_hard, "1", "2", "3"),
        case!(max_conns_per_ip, "10", "20", "30"),
        case!(rest_after_release, "'1s'", "'2s'", "'3s'"),
        case!(max_tunnels_per_org, "10", "20", "30"),
        case!(sticky_scope, "'org'", "'target'", "'connection'"),
        case!(dial.race, "2", "4", "16"),
        case!(block.target_cooldown, "'1m'", "'2m'", "'3m'"),
        case!(block.escalate_targets, "4", "5", "6"),
        case!(block.escalate_signals, "7", "8", "9"),
        case!(block.signal_window, "'1m'", "'2m'", "'3m'"),
        case!(block.max_cooldown_share, "0.3", "0.4", "0.6"),
        case!(static.cooldown, "'1m'", "'2m'", "'3m'"),
        case!(static.quarantine_after, "4", "5", "6"),
        case!(static.retest_every, "'1h'", "'2h'", "'3h'"),
        case!(static.recheck_every, "'1m'", "'2m'", "'3m'"),
        case!(static.replace_after_checks, "4", "5", "6"),
        case!(static.replace_min_sources, "3", "4", "5"),
        case!(static.replace_blocked_share, "0.3", "0.4", "0.7"),
        case!(static.replace_quarantine_for, "'1h'", "'2h'", "'3h'"),
        case!(mobile_box.rotate_attempts, "4", "5", "6"),
        case!(mobile_box.rotate_timeout, "'1m'", "'2m'", "'3m'"),
        case!(mobile_box.rotate_min_interval, "'1s'", "'2s'", "'3s'"),
        case!(mobile_box.rotate_per_hour, "7", "8", "9"),
        case!(mobile_box.drain_wait, "'1s'", "'2s'", "'3s'"),
        case!(mobile_box.offline_after, "'1s'", "'2s'", "'3s'"),
        case!(rotating.ready_ttl, "'1m'", "'2m'", "'3m'"),
        case!(rotating.max_age, "'1h'", "'2h'", "'3h'"),
        case!(rotating.min_remaining, "'1m'", "'2m'", "'3m'"),
        case!(
            rotating.after_release,
            "'drain'",
            "'reuse_same_org'",
            "'drain'"
        ),
        case!(rotating.refill_concurrency, "3", "4", "5"),
        case!(rotating.refill_rate, "11", "12", "13"),
        case!(rotating.headroom, "1", "2", "3"),
        case!(rotating.headroom_auto, "true", "false", "true"),
        case!(rotating.keepalive, "'10s'", "'20s'", "'40s'"),
        case!(rotating.recheck_every, "'1m'", "'2m'", "'3m'"),
        case!(rotating.stability.changes_per_hour, "4", "5", "6"),
        case!(rotating.stability.drops_per_hour, "7", "8", "9"),
        case!(cost.max_gb_per_day, "1", "2", "3"),
        case!(cost.max_creates_per_hour, "100", "200", "300"),
    ]
}

#[test]
fn every_field_follows_global_route_class_org() {
    for case in cases() {
        let get = |s: &PolicySet, org_id: &str, prov: Option<&str>| {
            (case.get)(s.effective(&org(org_id), prov.map(provider).as_ref()))
        };
        let [g, r, o] = [0, 1, 2].map(|i| get(&ok(&case.global(i)), "acme", None));
        assert_ne!(g, r, "{}: test data must differ", case.field);
        assert_ne!(r, o, "{}: test data must differ", case.field);

        let stack = |org_body: &str| {
            ok(&format!(
                "{}{}{}",
                case.global(0),
                rc_doc("rc", "p", &case.layer(1)),
                org_doc("o", "acme", org_body),
            ))
        };
        let s = stack(&case.layer(2));
        let f = case.field;
        for (org_id, prov, want, what) in [
            ("acme", Some("p"), &o, "org over route class"),
            ("acme", None, &o, "org over global"),
            ("other", Some("p"), &r, "route class over global"),
            ("other", Some("unlisted"), &g, "provider without policy"),
            ("other", None, &g, "global"),
        ] {
            assert_eq!(&get(&s, org_id, prov), want, "{f}: {what}");
        }

        // An org policy that leaves this field out keeps the inherited value.
        let s = stack(if f == "sticky_scope" {
            "max_tunnels_per_org = 7"
        } else {
            "sticky_scope = \"connection\""
        });
        for (prov, want, what) in [(Some("p"), &r, "the route class"), (None, &g, "global")] {
            assert_eq!(
                &get(&s, "acme", prov),
                want,
                "{f}: unset org field falls through to {what}"
            );
        }
    }
}

#[test]
fn min_ready_by_region_merges_per_region() {
    let s = ok(&format!(
        "{}{}{}",
        global_with(
            "min_ready = 10\n[policy.min_ready_by_region]\nfr = 12\n\"fr/paris\" = 15\nde = 4"
        ),
        rc_doc("rc", "p", "[policy.min_ready_by_region]\nde = 6"),
        org_doc(
            "o",
            "acme",
            "[policy.min_ready_by_region]\n\"fr/paris\" = 18"
        ),
    ));
    let min = |o: &str, p: Option<&str>, r: &str| {
        s.effective(&org(o), p.map(provider).as_ref())
            .capacity
            .target(&region(r))
            .min_ready
    };
    // exact region, then country, then policy value
    assert_eq!(min("x", None, "fr/paris"), 15);
    assert_eq!(min("x", None, "fr/lyon"), 12);
    assert_eq!(min("x", None, "fr"), 12);
    assert_eq!(min("x", None, "us"), 10);
    // route class overrides one region and keeps the others
    assert_eq!(min("x", Some("p"), "de"), 6);
    assert_eq!(min("x", Some("p"), "fr"), 12);
    // org overrides one region and keeps the inherited rest
    assert_eq!(min("acme", Some("p"), "fr/paris"), 18);
    assert_eq!(min("acme", Some("p"), "de"), 6);
    assert_eq!(min("acme", Some("p"), "fr/lyon"), 12);
}

#[test]
fn ready_target_follows_the_regions_min_ready() {
    let p = eff(&global_with(
        "min_ready = 10\n[policy.min_ready_by_region]\n\"fr/paris\" = 30",
    ));
    assert_eq!(target(&p, "fr/paris"), (30, 60, 15));
    assert_eq!(target(&p, "de"), (10, 20, 5));

    let p = eff(&global_with(
        "min_ready = 10\nmax_ready = 40\nlow_watermark = 4",
    ));
    assert_eq!(target(&p, "fr"), (10, 40, 4));
}

#[test]
fn org_cannot_exceed_a_ceiling() {
    let global = global_with(
        "[policy.limits]\nmax_gb_per_day = 10\nmax_creates_per_hour = 100\nfair_use_gb_per_ip_month = 50",
    );
    // at the ceiling is fine
    let s = ok(&with_org(&global, "cost.max_gb_per_day = 10"));
    assert_eq!(s.effective(&org("acme"), None).cost.max_gb_per_day, 10.0);

    for body in [
        "cost.max_gb_per_day = 10.5",
        "cost.max_creates_per_hour = 101",
    ] {
        let PolicyError::AboveCeiling { field, context, .. } = err(&with_org(&global, body)) else {
            panic!("{body}: expected AboveCeiling");
        };
        assert_eq!(field, key(body));
        assert_eq!(context, "global + o");
    }

    // a cost above its own ceiling is refused at global level too
    assert_eq!(
        ceiling_field(&global_with(
            "cost.max_creates_per_hour = 700\n[policy.limits]\nmax_creates_per_hour = 600"
        )),
        "cost.max_creates_per_hour"
    );
}

#[test]
fn fair_use_is_set_by_global_or_route_class_never_by_an_org() {
    let global = global_with("[policy.cost]\nfair_use_gb_per_ip_month = 80");
    let s = ok(&format!(
        "{global}{}",
        rc_doc("rc", "p", "cost.fair_use_gb_per_ip_month = 40")
    ));
    let fair_use = |prov: Option<&str>| {
        s.effective(&org("acme"), prov.map(provider).as_ref())
            .cost
            .fair_use_gb_per_ip_month
    };
    assert_eq!(fair_use(None), 80.0);
    assert_eq!(fair_use(Some("p")), 40.0);

    for body in [
        "cost.fair_use_gb_per_ip_month = 1",
        "limits.fair_use_gb_per_ip_month = 1",
    ] {
        let PolicyError::Scope { name, reason } = err(&with_org(&global, body)) else {
            panic!("{body}: expected a scope error");
        };
        assert_eq!(name, "o");
        assert!(reason.contains("fair_use_gb_per_ip_month"), "{reason}");
    }
}

#[test]
fn an_org_cannot_raise_a_ceiling_but_can_lower_it() {
    let global = global_with("[policy.limits]\nmax_gb_per_day = 10");
    // raising the ceiling in the org policy does not help the cost value
    assert_eq!(
        ceiling_field(&with_org(
            &global,
            "cost.max_gb_per_day = 20\n[policy.limits]\nmax_gb_per_day = 50"
        )),
        "cost.max_gb_per_day"
    );
    // lowering it clamps the default cost for that org only
    let s = ok(&with_org(&global, "[policy.limits]\nmax_gb_per_day = 2"));
    let acme = s.effective(&org("acme"), None);
    assert_eq!(acme.cost.max_gb_per_day, 2.0);
    assert_eq!(acme.limits.max_gb_per_day, Some(2.0));
    assert_eq!(s.effective(&org("other"), None).cost.max_gb_per_day, 5.0);
}

#[test]
fn the_org_budget_is_off_unset_and_only_ever_tightens() {
    let none = ok(&global_with(""));
    assert_eq!(
        none.effective(&org("acme"), None).limits.org_max_gb_per_day,
        None
    );

    let global = global_with("[policy.limits]\norg_max_gb_per_day = 10");
    let s = ok(&format!(
        "{global}{}{}",
        org_doc("lower", "acme", "[policy.limits]\norg_max_gb_per_day = 2"),
        org_doc("higher", "big", "[policy.limits]\norg_max_gb_per_day = 50"),
    ));
    let budget = |o: &str| s.effective(&org(o), None).limits.org_max_gb_per_day;
    assert_eq!(budget("acme"), Some(2.0), "an org lowers its budget");
    assert_eq!(budget("big"), Some(10.0), "an org cannot raise it");
    assert_eq!(
        budget("other"),
        Some(10.0),
        "the global value applies to the rest"
    );

    assert_eq!(
        invalid_field(&global_with("[policy.limits]\norg_max_gb_per_day = -1")),
        "limits.org_max_gb_per_day"
    );
}

#[test]
fn sticky_entry_ceiling_only_tightens_across_all_scopes() {
    for global in [None, Some(100)] {
        for route_class in [None, Some(50), Some(200)] {
            for org_limit in [None, Some(25), Some(300)] {
                let body = |limit: Option<u32>| {
                    limit
                        .map(|n| format!("max_sticky_entries_per_org = {n}"))
                        .unwrap_or_default()
                };
                let s = ok(&format!(
                    "{}{}{}",
                    global_with(&body(global)),
                    rc_doc("rc", "p", &body(route_class)),
                    org_doc("o", "acme", &body(org_limit)),
                ));
                for (org_id, provider_id, want) in [
                    ("acme", Some("p"), [global, route_class, org_limit]),
                    ("acme", None, [global, None, org_limit]),
                    ("other", Some("p"), [global, route_class, None]),
                    ("other", None, [global, None, None]),
                ] {
                    assert_eq!(
                        s.effective(&org(org_id), provider_id.map(provider).as_ref())
                            .max_sticky_entries_per_org,
                        want.into_iter().flatten().min(),
                        "global={global:?}, route_class={route_class:?}, org={org_limit:?}, \
                         lookup={org_id}/{provider_id:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn dial_race_and_sticky_entry_ceiling_accept_positive_bounds() {
    for race in [1, 16] {
        let p = eff(&global_with(&format!(
            "max_sticky_entries_per_org = 1\ndial.race = {race}"
        )));
        assert_eq!(p.dial.race, race);
        assert_eq!(p.max_sticky_entries_per_org, Some(1));
    }
    let p = eff(&global_with(&format!(
        "max_sticky_entries_per_org = {}",
        u32::MAX
    )));
    assert_eq!(p.max_sticky_entries_per_org, Some(u32::MAX));
}

#[test]
fn dial_race_and_sticky_entry_ceiling_reject_wrong_types() {
    for body in [
        "dial.race = -1",
        "dial.race = 1.5",
        "dial.race = '2'",
        "dial.race = true",
        "dial.races = 2",
        "max_sticky_entries_per_org = -1",
        "max_sticky_entries_per_org = 1.5",
        "max_sticky_entries_per_org = '2'",
        "max_sticky_entries_per_org = true",
        "max_sticky_entries_per_org = 4294967296",
    ] {
        assert!(rejected_at_parse(&global_with(body)), "{body}");
    }
}

#[test]
fn a_route_class_ceiling_binds_the_org_that_uses_that_provider() {
    let global = global_with("[policy.limits]\nmax_gb_per_day = 10");
    let org8 = org_doc("o", "acme", "cost.max_gb_per_day = 8");
    // 8 is under the global ceiling but over the route-class ceiling
    let text = format!(
        "{global}{}{org8}",
        rc_doc("rc", "p", "[policy.limits]\nmax_gb_per_day = 4")
    );
    assert_eq!(ceiling_field(&text), "cost.max_gb_per_day");
    // without the route class the same org value is fine
    ok(&format!("{global}{org8}"));
}

#[test]
fn ready_bounds_are_checked() {
    assert_eq!(
        invalid_field(&global_with("min_ready = 30\nmax_ready = 20")),
        "min_ready"
    );
    // only visible after merging: the org raises min_ready past the global max_ready
    assert_eq!(
        invalid_field(&with_org(&global_with("max_ready = 20"), "min_ready = 25")),
        "min_ready"
    );
    // a per-region override counts too
    assert_eq!(
        invalid_field(&global_with(
            "max_ready = 20\n[policy.min_ready_by_region]\nfr = 21"
        )),
        "min_ready"
    );
    // equal is fine
    ok(&global_with("min_ready = 20\nmax_ready = 20"));

    assert_eq!(
        invalid_field(&global_with("min_ready = 4\nlow_watermark = 5")),
        "low_watermark"
    );
}

#[test]
fn duplicate_policies_are_refused() {
    let two = |a: String, b: String| format!("{GLOBAL}{a}{b}");
    let dup_org = two(org_doc("a", "acme", ""), org_doc("b", "acme", ""));
    assert!(matches!(err(&dup_org), PolicyError::Duplicate { key, .. } if key == "acme"));

    let dup_rc = two(rc_doc("a", "p", ""), rc_doc("b", "p", ""));
    assert!(matches!(err(&dup_rc), PolicyError::Duplicate { key, .. } if key == "p"));

    let dup_global = format!("{GLOBAL}\n[[policy]]\nname = \"second\"\nregions = [\"de\"]\n");
    assert!(matches!(err(&dup_global), PolicyError::Duplicate { .. }));

    let dup_name = two(org_doc("same", "a", ""), org_doc("same", "b", ""));
    assert!(matches!(err(&dup_name), PolicyError::DuplicateName(n) if n == "same"));

    // an org and a route class may share an id: they are different scopes
    ok(&two(org_doc("a", "x", ""), rc_doc("b", "x", "")));
}

#[test]
fn unknown_fields_are_rejected() {
    for text in [
        "[[policy]]\nname = \"g\"\nregions = [\"fr\"]\nmin_redy = 3\n",
        "[[policy]]\nname = \"g\"\nregions = [\"fr\"]\n[policy.criteria]\nmax_rsik = 3\n",
        "[[policy]]\nname = \"g\"\nregions = [\"fr\"]\n[policy.rotating.stability]\nflaps = 3\n",
        "[[policy]]\nname = \"g\"\nregions = [\"fr\"]\n[policy.on_empty]\nmobile = \"wait\"\n",
        "[[polcy]]\nname = \"g\"\n",
        "bogus = 1\n",
    ] {
        assert!(rejected_at_parse(text), "{text}");
    }
    // the same for a document that arrives as JSON from the API
    assert!(serde_json::from_str::<PolicyDoc>(r#"{"name":"o","min_redy":3}"#).is_err());
}

#[test]
fn scope_and_match_must_agree() {
    for body in [
        "scope = \"global\"\nmatch = \"acme\"",
        "scope = \"org\"",
        "scope = \"route_class\"",
        "scope = \"org\"\nmatch = \"Not An Org\"",
    ] {
        let text = format!("{GLOBAL}\n[[policy]]\nname = \"x\"\n{body}\n");
        assert!(matches!(err(&text), PolicyError::Scope { .. }), "{body}");
    }
    assert!(matches!(
        err("[[policy]]\nname = \"\"\nregions = [\"fr\"]\n"),
        PolicyError::Scope { .. }
    ));
}

#[test]
fn regions_are_required_after_merging() {
    // a route class cannot supply them for the providers it does not cover
    let rc_only = format!(
        "[[policy]]\nname = \"g\"\n{}",
        rc_doc("rc", "p", "regions = [\"fr\"]")
    );
    for text in [
        "[[policy]]\nname = \"g\"\n",
        "[[policy]]\nname = \"g\"\nregions = []\n",
        &rc_only,
    ] {
        assert_eq!(invalid_field(text), "regions", "{text}");
    }
    assert!(rejected_at_parse(
        "[[policy]]\nname = \"g\"\nregions = [\"france\"]\n"
    ));
}

#[test]
fn list_fields_reject_empty_and_repeated_entries() {
    for body in [
        "kinds = []",
        "kinds = [\"static\", \"static\"]",
        "providers = []",
        "providers = [\"a\", \"a\"]",
        "regions = [\"fr\", \"fr\"]",
    ] {
        let text = if key(body) == "regions" {
            format!("[[policy]]\nname = \"g\"\n{body}\n")
        } else {
            global_with(body)
        };
        assert_eq!(invalid_field(&text), key(body), "{body}");
    }
}

#[test]
fn out_of_range_values_are_refused() {
    for body in [
        "pool = \"private\"",
        "on_empty.static = \"create\"",
        "criteria.max_risk = 101",
        "criteria.min_success = 1.5",
        "criteria.browser_sample = -0.1",
        "criteria.max_ttfb_ms = 0",
        "lease_ttl = 0",
        "create_deadline = \"0s\"",
        "orgs_hard = 0",
        "max_tunnels_per_org = 0",
        "max_sticky_entries_per_org = 0",
        "dial.race = 0",
        "dial.race = 17",
        "block.max_cooldown_share = 0",
        "static.replace_blocked_share = 1.01",
        "static.quarantine_after = 0",
        "rotating.keepalive = 0",
        "rotating.refill_concurrency = 0",
        "rotating.max_age = \"4m\"\nrotating.min_remaining = \"5m\"",
        "cost.max_gb_per_day = -1",
    ] {
        assert_eq!(invalid_field(&global_with(body)), key(body), "{body}");
    }
    // zero is meaningful for these
    ok(&global_with(
        "lease_wait = 0\nrest_after_release = 0\nrotating.headroom = 0\nmin_ready = 0",
    ));
}

#[test]
fn an_error_names_the_merged_policies() {
    let e = err(&[
        global_with("max_ready = 20"),
        rc_doc("fr-web", "p", ""),
        org_doc("acme-cap", "acme", "min_ready = 25"),
    ]
    .concat());
    let msg = e.to_string();
    assert!(
        msg.contains("global + acme-cap") || msg.contains("global + fr-web + acme-cap"),
        "{msg}"
    );
    assert!(msg.contains("min_ready"), "{msg}");
}

#[test]
fn provider_rules_with_derived_defaults() {
    // tunnels per IP: 80% of the provider limit unless the policy sets it
    let p = eff(GLOBAL);
    assert_eq!(p.conns_per_ip(100), 80);
    assert_eq!(p.conns_per_ip(1), 1);
    assert_eq!(
        eff(&global_with("max_conns_per_ip = 7")).conns_per_ip(100),
        7
    );

    // session life: 80% of the provider maximum unless set, never above it
    for (body, provider_max, want) in [
        ("", 1_000, 800),
        ("rotating.max_age = \"1h\"", 86_400, 3_600),
        ("rotating.max_age = \"2h\"", 86_400, 7_200),
        // a 3 minute provider session lives at most 3 minutes
        ("rotating.max_age = \"2h\"", 180, 180),
    ] {
        let p = eff(&global_with(body));
        assert_eq!(
            p.rotating.max_age_for(Duration::from_secs(provider_max)),
            Duration::from_secs(want),
            "{body} on {provider_max}s"
        );
    }
}

#[test]
fn min_remaining_must_leave_a_session_leasable_for_the_provider_life() {
    let check = |text: &str, minutes: u64| {
        ok(text).check_session_life(&provider("p"), Duration::from_secs(minutes * 60))
    };
    // default min_remaining 5m: a 3 minute adapter has no leasable session
    let e = check(GLOBAL, 3).expect_err("5m min_remaining on a 3m session");
    assert!(matches!(&e, PolicyError::Invalid { field, .. } if *field == "rotating.min_remaining"));
    assert!(e.to_string().contains("provider p"), "{e}");
    // 80% of a 6 minute life is 3m50s: still short of 5m
    assert!(check(GLOBAL, 6).is_err());
    assert!(check(GLOBAL, 20).is_ok());
    let short = global_with("rotating.min_remaining = \"30s\"");
    assert!(check(&short, 3).is_ok());
    // an explicit max_age counts, clamped to the provider life
    assert!(check(&global_with("rotating.max_age = \"6m\""), 1_440).is_err());
    // a route-class and an org policy are checked too
    let rc = [
        short.clone(),
        rc_doc("rc", "p", "rotating.min_remaining = \"15m\""),
    ]
    .concat();
    assert!(check(&rc, 20).is_err());
    let orgp = with_org(&short, "rotating.min_remaining = \"15m\"");
    let e = check(&orgp, 20).expect_err("org policy too");
    assert!(e.to_string().contains("acme"), "{e}");
}

#[test]
fn a_document_survives_the_json_round_trip_the_store_uses() {
    let text = "[[policy]]\nname = \"g\"\nregions = [\"fr/paris\", \"de\"]\nlease_ttl = \"5m\"\nmin_ready = 3\non_empty.static = \"fail\"\n\
                criteria.min_success = 0.5\nrotating.keepalive = \"45s\"\nrotating.stability.drops_per_hour = 9\n\
                max_sticky_entries_per_org = 100\ndial.race = 4\n\
                limits.max_gb_per_day = 9\n[policy.min_ready_by_region]\n\"fr/paris\" = 2\n";
    let original = docs(text).remove(0);
    let json = serde_json::to_string(&original).expect("serialize");
    let back: PolicyDoc = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, original);
    let effective = |d| {
        PolicySet::from_docs(vec![d])
            .expect("valid")
            .effective(&org("a"), None)
            .clone()
    };
    assert_eq!(effective(back), effective(original));
}

#[test]
fn syntax_errors_name_their_cause_once() {
    let syntax = PolicyFile::parse("lease_ttl = ").expect_err("bad syntax");
    // the message holds the cause, so a `source` would print it twice under `{:#}`
    assert!(std::error::Error::source(&syntax).is_none(), "{syntax}");
}
