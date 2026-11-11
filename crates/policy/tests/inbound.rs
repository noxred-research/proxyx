use std::time::Duration;

use common::Cause;
use common::types::{Kind, OrgId, ProviderId, Region, Rotation, StickyScope};
use proxyx_policy::{
    EffectivePolicy, InboundOptions, LeaseRequest, MAX_USERNAME_LEN, PolicyFile, PolicySet,
    StickyKeySource,
};

fn region(s: &str) -> Region {
    s.parse().expect("test region")
}

fn provider(s: &str) -> ProviderId {
    s.parse().expect("test provider")
}

#[test]
fn bare_prefix_means_no_options() {
    assert_eq!(InboundOptions::parse("px"), Ok(InboundOptions::default()));
}

#[test]
fn every_key_parses() {
    let o = InboundOptions::parse(
        "px-kind-rotating-cc-fr-city-paris-prov-oxy_res-ttl-5m-sid-scan_42-rot-sticky-strict-true",
    )
    .expect("valid");
    assert_eq!(o.kind, Some(Kind::Rotating));
    assert_eq!(o.region, Some(region("fr/paris")));
    assert_eq!(o.provider, Some(provider("oxy_res")));
    assert_eq!(o.ttl, Some(Duration::from_secs(300)));
    assert_eq!(o.sid.as_deref(), Some("scan_42"));
    assert_eq!(o.rotation, Some(Rotation::Sticky));
    assert_eq!(o.strict, Some(true));
}

#[test]
fn proposal_example_and_key_order_independence() {
    let a = InboundOptions::parse("px-kind-rotating-cc-fr-sid-scan42").expect("valid");
    let b = InboundOptions::parse("px-sid-scan42-cc-fr-kind-rotating").expect("valid");
    assert_eq!(a, b);
    assert_eq!(a.region, Some(region("fr")));
}

#[test]
fn strict_accepts_only_explicit_lowercase_booleans() {
    for (value, want) in [("true", true), ("false", false)] {
        let o = InboundOptions::parse(&format!("px-strict-{value}")).expect("valid");
        assert_eq!(o.strict, Some(want));
    }
    for username in [
        "px-strict",
        "px-strict-",
        "px-strict-1",
        "px-strict-0",
        "px-strict-yes",
        "px-strict-TRUE",
        "px-strict-False",
        "px-strict-true-strict-false",
        "px-strict-false-strict-false",
    ] {
        assert_eq!(
            InboundOptions::parse(username),
            Err(Cause::OptionDenied),
            "{username}"
        );
    }
}

#[test]
fn ttl_accepts_plain_seconds_and_units() {
    for (v, secs) in [("600", 600), ("30s", 30), ("2h", 7_200)] {
        let o = InboundOptions::parse(&format!("px-ttl-{v}")).expect("valid");
        assert_eq!(o.ttl, Some(Duration::from_secs(secs)), "{v}");
    }
}

#[test]
fn username_length_limit_is_128_bytes() {
    let sid = |n: usize| format!("px-sid-{}", "a".repeat(n));
    let ok = sid(MAX_USERNAME_LEN - "px-sid-".len());
    assert_eq!(ok.len(), MAX_USERNAME_LEN);
    assert!(InboundOptions::parse(&ok).is_ok());
    assert_eq!(
        InboundOptions::parse(&format!("{ok}a")),
        Err(Cause::OptionDenied)
    );
}

#[test]
fn malformed_usernames_are_refused() {
    let cases = [
        // missing or wrong prefix
        "",
        "kind-rotating",
        "proxyx",
        "proxyx-kind-static",
        "ARGO",
        "-px",
        // unknown key
        "px-color-red",
        "px-kind-static-region-fr",
        // bad charset: uppercase, space, dot, plus, non-ASCII
        "px-sid-Scan",
        "px-kind-ROTATING",
        // The grammar is lowercase only, `cc` included
        "px-cc-US",
        "px-sid-a b",
        "px-sid-a.b",
        "px-sid-a+b",
        "px-sid-é",
        // repeated key
        "px-kind-static-kind-rotating",
        "px-cc-fr-cc-de",
        "px-sid-a-sid-a",
        // `-` inside a value shifts the pairs
        "px-sid-a-b",
        "px-sid-a-b-cc-fr",
        "px-sid-a-b-c-d",
        // key without value, empty value, empty pair
        "px-kind",
        "px-kind-",
        "px-",
        "px--kind-static",
        "px-kind-static-",
        // bad values
        "px-kind-residential",
        "px-cc-fra",
        "px-cc-f1",
        "px-cc-fr-city-pa_ris-city-x",
        "px-ttl-0",
        "px-ttl-0s",
        "px-ttl-soon",
        "px-ttl-5x",
        "px-rot-never",
        "px-prov-has-dash",
        // city needs cc; sid contradicts rot-each
        "px-city-paris",
        "px-sid-x-rot-each",
    ];
    for username in cases {
        assert_eq!(
            InboundOptions::parse(username),
            Err(Cause::OptionDenied),
            "{username:?}"
        );
    }
}

fn policy_of(body: &str) -> EffectivePolicy {
    let docs = PolicyFile::parse(&format!("[[policy]]\nname = \"g\"\n{body}\n"))
        .expect("parse")
        .policies;
    PolicySet::from_docs(docs)
        .expect("valid")
        .effective(&"acme".parse::<OrgId>().expect("org"), None)
        .clone()
}

fn policy(extra: &str) -> EffectivePolicy {
    policy_of(&format!(
        "regions = [\"fr/paris\", \"fr\", \"de\"]\n{extra}"
    ))
}

fn opts(username: &str) -> InboundOptions {
    InboundOptions::parse(username).expect("valid username")
}

/// `pick` of the request `username` narrows `p` to.
fn narrowed<T>(
    p: &EffectivePolicy,
    username: &str,
    pick: fn(LeaseRequest) -> T,
) -> Result<T, Cause> {
    p.narrow(&opts(username)).map(pick)
}

fn denied(p: &EffectivePolicy, username: &str) {
    assert_eq!(
        p.narrow(&opts(username)),
        Err(Cause::OptionDenied),
        "{username}"
    );
}

#[test]
fn no_options_leaves_the_whole_policy() {
    let p = policy(
        "kinds = [\"rotating\", \"static\"]\nproviders = [\"a\", \"b\"]\nsticky_scope = \"target\"\n",
    );
    assert_eq!(
        p.narrow(&opts("px")),
        Ok(LeaseRequest {
            kinds: vec![Kind::Rotating, Kind::Static],
            providers: vec![provider("a"), provider("b")],
            regions: vec![region("fr/paris"), region("fr"), region("de")],
            ttl: Duration::from_secs(600),
            sticky: StickyKeySource::Scope(StickyScope::Target),
            rotation: Rotation::Sticky,
            strict: false,
        })
    );
}

#[test]
fn kind_inside_policy_narrows_and_outside_is_denied() {
    let both = policy("");
    assert_eq!(
        narrowed(&both, "px-kind-rotating", |r| r.kinds),
        Ok(vec![Kind::Rotating])
    );
    let static_only = policy("kinds = [\"static\"]\n");
    assert_eq!(
        narrowed(&static_only, "px-kind-static", |r| r.kinds),
        Ok(vec![Kind::Static])
    );
    denied(&static_only, "px-kind-rotating");
}

#[test]
fn provider_inside_policy_narrows_and_outside_is_denied() {
    let p = policy("providers = [\"a\", \"b\"]\n");
    assert_eq!(
        narrowed(&p, "px-prov-b", |r| r.providers),
        Ok(vec![provider("b")])
    );
    denied(&p, "px-prov-c");

    // any provider may be named when the policy lists none
    let any = policy("");
    assert_eq!(
        narrowed(&any, "px-prov-c", |r| r.providers),
        Ok(vec![provider("c")])
    );
}

#[test]
fn region_must_be_covered_by_a_policy_region() {
    let p = policy("");
    // exact city, whole country, and a city under a country entry
    for (username, want) in [
        ("px-cc-fr-city-paris", "fr/paris"),
        ("px-cc-fr", "fr"),
        ("px-cc-fr-city-lyon", "fr/lyon"),
    ] {
        assert_eq!(
            narrowed(&p, username, |r| r.regions),
            Ok(vec![region(want)]),
            "{username}"
        );
    }
    denied(&p, "px-cc-us");

    // a policy limited to one city does not cover the country or another city
    let city_only = policy_of("regions = [\"fr/paris\"]");
    assert_eq!(
        narrowed(&city_only, "px-cc-fr-city-paris", |r| r.regions),
        Ok(vec![region("fr/paris")])
    );
    denied(&city_only, "px-cc-fr");
    denied(&city_only, "px-cc-fr-city-lyon");
}

#[test]
fn ttl_may_shorten_but_not_extend_the_lease() {
    let p = policy("");
    assert_eq!(
        narrowed(&p, "px-ttl-5m", |r| r.ttl),
        Ok(Duration::from_secs(300))
    );
    assert_eq!(
        narrowed(&p, "px-ttl-10m", |r| r.ttl),
        Ok(Duration::from_secs(600))
    );
    denied(&p, "px-ttl-601");
    denied(&p, "px-ttl-1h");
}

#[test]
fn sid_and_rotation_set_the_lease_key() {
    let p = policy("");
    let r = p.narrow(&opts("px-sid-scan42")).expect("narrow");
    assert_eq!(r.sticky, StickyKeySource::Sid("scan42".into()));
    assert_eq!(r.rotation, Rotation::Sticky);
    let r = p.narrow(&opts("px-rot-each")).expect("narrow");
    assert_eq!(r.sticky, StickyKeySource::Scope(StickyScope::Org));
    assert_eq!(r.rotation, Rotation::Each);
}

#[test]
fn strict_is_forwarded_and_defaults_to_false() {
    let p = policy("");
    for (username, want) in [
        ("px", false),
        ("px-strict-true", true),
        ("px-strict-false", false),
        ("px-rot-each-strict-true", true),
        ("px-sid-scan42-strict-true", true),
    ] {
        assert_eq!(narrowed(&p, username, |r| r.strict), Ok(want), "{username}");
    }
}
