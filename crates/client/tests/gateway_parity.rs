//! The client's grammar and cause table must track the gateway crates: what the gateway
//! accepts the client accepts, and what the gateway refuses the client refuses.

use std::time::Duration;

use common::types::{Kind as PoolKind, Rotation as PoolRotation};
use proxyx_client::gateway::{Cause, Kind, PoolSelector, Rotation};

fn kind_of(kind: PoolKind) -> Kind {
    match kind {
        PoolKind::Static => Kind::Static,
        PoolKind::Rotating => Kind::Rotating,
    }
}

fn rotation_of(rotation: PoolRotation) -> Rotation {
    match rotation {
        PoolRotation::Sticky => Rotation::Sticky,
        PoolRotation::Each => Rotation::Each,
    }
}

/// Both sides accept with the same fields, or both refuse.
fn agree(username: &str) -> bool {
    let server = policy::InboundOptions::parse(username);
    let client = PoolSelector::parse(username);
    match (server, client) {
        (Ok(server), Ok(client)) => {
            assert_eq!(server.kind.map(kind_of), client.get_kind(), "{username:?}");
            assert_eq!(
                server.region.as_ref().map(|r| r.country()),
                client.get_country(),
                "{username:?}"
            );
            assert_eq!(
                server.region.as_ref().and_then(|r| r.city()),
                client.get_city(),
                "{username:?}"
            );
            assert_eq!(
                server.provider.as_ref().map(|p| p.as_str()),
                client.get_provider(),
                "{username:?}"
            );
            assert_eq!(server.ttl, client.get_ttl(), "{username:?}");
            assert_eq!(server.sid.as_deref(), client.get_sid(), "{username:?}");
            assert_eq!(
                server.rotation.map(rotation_of),
                client.get_rotation(),
                "{username:?}"
            );
            assert_eq!(server.strict, client.get_strict(), "{username:?}");
            // what the client renders is what the gateway reads
            let rendered = client.username().expect("a parsed selector renders");
            let again = policy::InboundOptions::parse(&rendered)
                .expect("the gateway accepts the rendering");
            assert_eq!(again.ttl, server.ttl, "{username:?} -> {rendered:?}");
            assert_eq!(again.sid, server.sid, "{username:?} -> {rendered:?}");
            assert_eq!(again.strict, server.strict, "{username:?} -> {rendered:?}");
            true
        }
        (Err(_), Err(_)) => false,
        (server, client) => {
            panic!("disagreement on {username:?}: gateway {server:?}, client {client:?}")
        }
    }
}

#[test]
fn table_of_usernames() {
    let accepted = [
        "px",
        "px-kind-static",
        "px-kind-rotating",
        "px-cc-fr",
        "px-cc-fr-city-paris",
        "px-city-paris-cc-fr",
        "px-prov-isp_static_port",
        "px-ttl-30",
        "px-ttl-30s",
        "px-ttl-5m",
        "px-ttl-2h",
        "px-ttl-1d",
        "px-ttl-007s",
        "px-sid-scan42",
        "px-sid-a_b_c",
        "px-sid-0",
        "px-rot-sticky",
        "px-rot-each",
        "px-sid-x-rot-sticky",
        "px-kind-rotating-cc-fr-sid-scan42",
        "px-kind-static-cc-de-city-berlin-prov-dc_one-ttl-10m-sid-k1-rot-sticky",
        "px-cc-fr-city-paris_15",
        "px-strict-true",
        "px-strict-false",
        "px-kind-rotating-cc-fr-sid-s1-ttl-20m-strict-true",
    ];
    let refused = [
        "",
        "p",
        "pxx",
        "PX",
        "px-",
        "px--",
        "px-kind",
        "px-kind-",
        "px-kind-static-",
        "px-kind-static-cc",
        "px-kind-Static",
        "px-kind-fast",
        "px-kind-static-kind-static",
        "px-kind-static-kind-rotating",
        "px-cc-FR",
        "px-cc-fra",
        "px-cc-f",
        "px-cc-f1",
        "px-cc-_a",
        "px-cc-fr-cc-de",
        "px-city-paris",
        "px-cc-fr-city-pa-ris",
        "px-cc-fr-city-Paris",
        "px-cc-fr-city-paris-city-lyon",
        "px-prov-oxy-isp",
        "px-prov-Oxy",
        "px-ttl-0",
        "px-ttl-0s",
        "px-ttl-s",
        "px-ttl-5x",
        "px-ttl-5M",
        "px-ttl-99999999999999999999",
        "px-ttl-99999999999999999d",
        "px-ttl-5m-ttl-5m",
        "px-sid-a-b",
        "px-sid-A",
        "px-sid-a-sid-b",
        "px-sid-a-rot-each",
        "px-rot-each-sid-a",
        "px-rot-fast",
        "px-rot-Sticky",
        "px-unknown-x",
        "px-Kind-static",
        "px-kind-static-extra",
        "px-sid-a b",
        "px-sid-é",
        "xx-kind-static",
        " px",
        "px ",
        "px-strict",
        "px-strict-yes",
        "px-strict-True",
        "px-strict-1",
        "px-strict-true-strict-false",
    ];
    for username in accepted {
        assert!(agree(username), "the gateway should accept {username:?}");
    }
    for username in refused {
        assert!(!agree(username), "the gateway should refuse {username:?}");
    }
    let at_limit = format!("px-sid-{}", "a".repeat(128 - "px-sid-".len()));
    assert_eq!(at_limit.len(), 128);
    assert!(agree(&at_limit));
    assert!(!agree(&format!("{at_limit}a")));
    let long_city = format!("px-cc-fr-city-{}", "a".repeat(48));
    assert!(agree(&long_city));
    assert!(!agree(&format!("{long_city}a")));
    let long_prov = format!("px-prov-{}", "a".repeat(49));
    assert!(!agree(&long_prov));
}

/// Small deterministic generator: no extra dependency, reproducible failures.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % n as u64).expect("fits")
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len())]
    }
}

const KEYS: &[&str] = &[
    "kind", "cc", "city", "prov", "ttl", "sid", "rot", "strict", "x", "", "Kind",
];
const VALUES: &[&str] = &[
    "static",
    "rotating",
    "fr",
    "FR",
    "fra",
    "f1",
    "paris",
    "pa_ris",
    "Paris",
    "oxy_isp",
    "5m",
    "30",
    "30s",
    "2h",
    "1d",
    "0",
    "0s",
    "5x",
    "007",
    "a",
    "scan42",
    "each",
    "sticky",
    "",
    "a-b",
    "é",
    "99999999999999999999",
    "true",
    "false",
    "True",
];

#[test]
fn random_usernames_agree() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let (mut accepted, mut refused) = (0u32, 0u32);
    for _ in 0..30_000 {
        let mut name = String::from(if rng.below(40) == 0 { "pp" } else { "px" });
        for _ in 0..rng.below(7) {
            name.push('-');
            name.push_str(rng.pick(KEYS));
            if rng.below(12) != 0 {
                name.push('-');
                name.push_str(rng.pick(VALUES));
            }
        }
        if agree(&name) {
            accepted += 1;
        } else {
            refused += 1;
        }
    }
    // the generator must exercise both outcomes
    assert!(accepted > 500, "accepted {accepted}");
    assert!(refused > 500, "refused {refused}");
}

/// Whatever the builder refuses, the gateway refuses in its naive rendering; whatever it
/// renders, the gateway accepts with the same fields.
#[test]
fn builder_agrees_with_the_gateway() {
    let mut rng = Rng(0xD1B5_4A32_D192_ED03);
    let ccs = ["fr", "de", "FR", "fra", "f1", ""];
    let cities = ["paris", "pa_ris", "pa-ris", "Paris", "", "x"];
    let provs = ["oxy_isp", "oxy-isp", "", "A"];
    let sids = ["scan42", "a-b", "", "S", "a_b"];
    let ttls = [0u64, 1, 59, 60, 90, 3_600, 7_200, 86_400, 172_800];
    let (mut rendered, mut denied) = (0u32, 0u32);
    for _ in 0..20_000 {
        let mut selector = PoolSelector::new();
        let mut naive = String::from("px");
        if rng.below(2) == 0 {
            let kind = if rng.below(2) == 0 {
                Kind::Static
            } else {
                Kind::Rotating
            };
            selector = selector.kind(kind);
            naive.push_str(&format!("-kind-{}", kind.as_str()));
        }
        if rng.below(2) == 0 {
            let v = rng.pick(&ccs);
            selector = selector.country(v);
            naive.push_str(&format!("-cc-{v}"));
        }
        if rng.below(2) == 0 {
            let v = rng.pick(&cities);
            selector = selector.city(v);
            naive.push_str(&format!("-city-{v}"));
        }
        if rng.below(2) == 0 {
            let v = rng.pick(&provs);
            selector = selector.provider(v);
            naive.push_str(&format!("-prov-{v}"));
        }
        if rng.below(2) == 0 {
            let secs = ttls[rng.below(ttls.len())];
            selector = selector.ttl(Duration::from_secs(secs));
            naive.push_str(&format!("-ttl-{secs}s"));
        }
        if rng.below(2) == 0 {
            let v = rng.pick(&sids);
            selector = selector.sid(v);
            naive.push_str(&format!("-sid-{v}"));
        }
        if rng.below(2) == 0 {
            let rotation = if rng.below(2) == 0 {
                Rotation::Sticky
            } else {
                Rotation::Each
            };
            selector = selector.rotation(rotation);
            naive.push_str(&format!("-rot-{}", rotation.as_str()));
        }
        match selector.username() {
            Ok(name) => {
                rendered += 1;
                let server = policy::InboundOptions::parse(&name)
                    .unwrap_or_else(|c| panic!("gateway refused {name:?}: {c}"));
                assert_eq!(server.kind.map(kind_of), selector.get_kind(), "{name}");
                assert_eq!(
                    server.region.as_ref().map(|r| r.country()),
                    selector.get_country(),
                    "{name}"
                );
                assert_eq!(
                    server.region.as_ref().and_then(|r| r.city()),
                    selector.get_city(),
                    "{name}"
                );
                assert_eq!(
                    server.provider.as_ref().map(|p| p.as_str()),
                    selector.get_provider(),
                    "{name}"
                );
                assert_eq!(server.ttl, selector.get_ttl(), "{name}");
                assert_eq!(server.sid.as_deref(), selector.get_sid(), "{name}");
                assert_eq!(
                    server.rotation.map(rotation_of),
                    selector.get_rotation(),
                    "{name}"
                );
            }
            Err(error) => {
                denied += 1;
                assert!(
                    policy::InboundOptions::parse(&naive).is_err(),
                    "builder refused ({error}) but the gateway accepts {naive:?}"
                );
            }
        }
    }
    assert!(rendered > 500, "rendered {rendered}");
    assert!(denied > 500, "denied {denied}");
}

#[test]
fn causes_match_the_gateway_table() {
    assert_eq!(Cause::ALL.len(), common::Cause::ALL.len());
    for server in common::Cause::ALL {
        let client = Cause::from_code(server.code())
            .unwrap_or_else(|| panic!("client lacks cause {server}"));
        assert_eq!(client.code(), server.code());
        assert_eq!(client.status(), server.status(), "{server}");
    }
    for client in Cause::ALL {
        assert!(
            common::Cause::from_code(client.code()).is_some(),
            "gateway lacks cause {client}"
        );
    }
}

#[test]
fn username_limit_matches_the_gateway() {
    assert_eq!(
        proxyx_client::gateway::MAX_USERNAME_LEN,
        policy::MAX_USERNAME_LEN
    );
}
