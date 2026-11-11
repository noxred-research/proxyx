//! Parent selectors must choose the exit observed by a real loopback origin.
#![allow(clippy::unwrap_used)]

mod common;

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use common::*;
use proxyx_edge::breaker::Transitions;
use proxyx_edge::config::{Config, HashKey, Strategy};
use proxyx_edge::egress::PickKey;
use proxyx_edge::parent::{Parents, Selector};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpSocket;
use tokio::time::timeout;

const EXITS: [&str; 2] = ["127.0.0.3", "127.0.0.4"];

fn key() -> PickKey<'static> {
    PickKey {
        session: Some("base"),
        user: Some("alice"),
        client: ip("127.0.0.5"),
        target_host: "origin.test",
    }
}

async fn parent(source: &str) -> Edge {
    // Parents resolve CONNECT destinations themselves. Install the same bounded
    // host sample used to find a distinguishing target-host key below.
    let hosts = (0..128)
        .map(|n| format!("\"selector{n}.test\"=['127.0.0.1']\n"))
        .collect::<String>();
    Edge::start(&format!(
        "{hosts}\n{OPEN}\n[[pool]]\nname='out'\naddresses=['{source}']\n\
         [server]\ndefault_pool='out'\n[health]\ninterval='0'\n"
    ))
    .await
}

fn node(name: &str, address: SocketAddr, weight: u32) -> String {
    let weight = if weight == 1 {
        String::new()
    } else {
        format!("weight={weight}\n")
    };
    format!("[[parent]]\nname='{name}'\ntype='http'\naddress='{address}'\n{weight}")
}

struct Reference {
    parents: Parents,
    selector: Selector,
}

impl Reference {
    fn new(selector: &str, nodes: &str) -> Self {
        let cfg = Config::parse(&format!("[selector]\n{selector}\n{nodes}")).unwrap();
        let parents = Parents::build(
            &cfg.parents,
            cfg.breaker.parent,
            &cfg.health,
            &Transitions::detached(),
        )
        .unwrap();
        Self {
            parents,
            selector: Selector::new(cfg.selector),
        }
    }

    fn pick(&self, key: &PickKey<'_>) -> usize {
        self.selector.choose(&self.parents, &[], &[], key).unwrap()
    }
}

struct Fixture {
    edge: Edge,
    upstreams: Vec<Edge>,
    reference: Reference,
    selector: String,
    nodes: String,
    other_user: String,
    other_host: String,
}

impl Fixture {
    async fn new(selector: &str) -> Self {
        Self::weighted(selector, [1, 1]).await
    }

    async fn weighted(selector: &str, weights: [u32; 2]) -> Self {
        let a = parent(EXITS[0]).await;
        let b = parent(EXITS[1]).await;
        let nodes = format!(
            "{}{}",
            node("p0", a.addr("main"), weights[0]),
            node("p1", b.addr("main"), weights[1]),
        );
        let reference = Reference::new(selector, &nodes);
        let cfg = &reference.selector.cfg;
        let hashes_user = matches!(cfg.strategy, Strategy::Userhash | Strategy::Sticky)
            || matches!(cfg.strategy, Strategy::Hash | Strategy::Carp)
                && cfg.hash_key == HashKey::User;
        // Choose two known users that really distinguish the selected field. Two
        // arbitrary names can legitimately collide when only two parents exist.
        let other_user = if hashes_user {
            let base = PickKey {
                session: None,
                ..key()
            };
            let chosen = reference.pick(&base);
            (0..128)
                .map(|n| format!("user{n}"))
                .find(|user| {
                    reference.pick(&PickKey {
                        user: Some(user),
                        ..base
                    }) != chosen
                })
                .expect("user sample spans both parents")
        } else {
            "bob".to_owned()
        };
        let hashes_host = matches!(cfg.strategy, Strategy::Hash | Strategy::Carp)
            && cfg.hash_key == HashKey::TargetHost;
        let other_host = if hashes_host {
            let chosen = reference.pick(&key());
            (0..128)
                .map(|n| format!("selector{n}.test"))
                .find(|host| {
                    reference.pick(&PickKey {
                        target_host: host,
                        ..key()
                    }) != chosen
                })
                .expect("host sample spans both parents")
        } else {
            "selector0.test".to_owned()
        };
        let text = Self::config(selector, &nodes, &other_user, &other_host);
        let edge = Edge::start(&text).await;
        Self {
            edge,
            upstreams: vec![a, b],
            reference,
            selector: selector.to_owned(),
            nodes,
            other_user,
            other_host,
        }
    }

    fn config(selector: &str, nodes: &str, other_user: &str, other_host: &str) -> String {
        // BASE ends in [dns.hosts], so this adds one local name without DNS.
        format!(
            "\"{other_host}\"=['127.0.0.1']\n\
             [auth]\nlogin_options=true\n\
             [[listener]]\nname='main'\nlisten='127.0.0.1:0'\n\
             [[listener]]\nname='anonymous'\nlisten='127.0.0.1:0'\nauth='none'\n\
             [[user]]\nname='alice'\npassword='pw'\n\
             [[user]]\nname='{other_user}'\npassword='pw'\n\
             [[rule]]\naction='allow'\nallow_internal=true\n\
             [server]\ndefault_route='parent'\n\
             [health]\ninterval='0'\ntimeout='1s'\n\
             [selector]\n{selector}\nconnect_retries=0\nforward_timeout='3s'\n{nodes}"
        )
    }

    async fn observed(&self, origin: SocketAddr, key: &PickKey<'_>) -> IpAddr {
        timeout(Duration::from_secs(5), async {
            let target = format!("{}:{}", key.target_host, origin.port());
            let username = key.user.map(|user| match key.session {
                Some(sid) => format!("{user}-sid-{sid}"),
                None => user.to_owned(),
            });
            assert!(key.session.is_none() || username.is_some());
            let auth = username.as_deref().map(|user| (user, "pw"));
            let listener = if key.user.is_some() {
                "main"
            } else {
                "anonymous"
            };
            let proxy = self.edge.addr(listener);
            let response = if key.client == ip("127.0.0.1") {
                get(proxy, &target, "/ip", auth).await
            } else {
                let socket = TcpSocket::new_v4().unwrap();
                socket.bind(SocketAddr::new(key.client, 0)).unwrap();
                let mut stream = socket.connect(proxy).await.unwrap();
                let authorization = auth.map(|(u, p)| basic(u, p)).unwrap_or_default();
                stream
                    .write_all(
                        format!(
                            "GET http://{target}/ip HTTP/1.1\r\nHost: {target}\r\n\
                             {authorization}Connection: close\r\n\r\n"
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
                read_response(&mut stream, false).await
            };
            assert_eq!(response.status, 200, "{key:?}: {response:?}");
            response.text().parse().unwrap()
        })
        .await
        .expect("parent selection completes within its request budget")
    }

    async fn check(&self, origin: SocketAddr, key: &PickKey<'_>) -> IpAddr {
        let expected = ip(EXITS[self.reference.pick(key)]);
        let actual = self.observed(origin, key).await;
        assert_eq!(actual, expected, "network exit for {key:?}");
        actual
    }

    async fn shutdown(self) {
        self.edge.server.shutdown(Duration::from_millis(100)).await;
        for upstream in self.upstreams {
            upstream.server.shutdown(Duration::from_millis(100)).await;
        }
    }
}

#[tokio::test]
async fn fifo_and_round_robin_select_the_observed_parent_exit() {
    let origin = http_origin("127.0.0.1:0").await;
    let key = PickKey {
        session: None,
        user: None,
        client: ip("127.0.0.1"),
        ..key()
    };
    for (strategy, cycle) in [("fifo", vec![EXITS[0]]), ("round_robin", EXITS.to_vec())] {
        let fixture = Fixture::new(&format!("strategy='{strategy}'")).await;
        for n in 0..8 {
            assert_eq!(
                fixture.check(origin, &key).await,
                ip(cycle[n % cycle.len()])
            );
        }
        fixture.shutdown().await;
    }
}

#[tokio::test]
async fn random_reaches_both_real_parents_in_a_bounded_sample() {
    let origin = http_origin("127.0.0.1:0").await;
    let fixture = Fixture::new("strategy='random'").await;
    let key = PickKey {
        client: ip("127.0.0.1"),
        ..key()
    };
    let mut seen = HashSet::new();
    // Equal default weights: the chance of missing either parent is 2^-39.
    // Do not require exact counts or a tightly balanced random distribution.
    for _ in 0..40 {
        let actual = fixture.observed(origin, &key).await;
        assert!(EXITS.iter().any(|exit| actual == ip(exit)), "{actual}");
        seen.insert(actual);
    }
    assert_eq!(seen.len(), 2, "random selected only {seen:?}");
    fixture.shutdown().await;
}

#[tokio::test]
async fn least_connections_counts_a_live_connect_tunnel() {
    let origin = banner_origin("127.0.0.1:0").await;
    let fixture = Fixture::new("strategy='least_connections'").await;
    let target = format!("origin.test:{}", origin.port());
    let proxy = fixture.edge.addr("main");
    let mut first = timeout(
        Duration::from_secs(5),
        tunnel(proxy, &target, Some(("alice", "pw"))),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(read_line(&mut first).await, format!("ip:{}", EXITS[0]));
    // Keep the first transport open: this is real active-parent load, not a
    // synthetic ParentUse counter or a completed HTTP request.
    let mut second = timeout(
        Duration::from_secs(5),
        tunnel(proxy, &target, Some(("alice", "pw"))),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(read_line(&mut second).await, format!("ip:{}", EXITS[1]));
    first.write_all(b"still-open\n").await.unwrap();
    assert_eq!(read_line(&mut first).await, "still-open");
    second.write_all(b"also-open\n").await.unwrap();
    assert_eq!(read_line(&mut second).await, "also-open");
    drop((first, second));
    fixture.shutdown().await;
}

async fn affinity_case(fixture: &Fixture, origin: SocketAddr, field: HashKey) {
    let base = key();
    let chosen = fixture.reference.pick(&base);
    let sessions: Vec<_> = (0..128).map(|n| format!("sid{n}")).collect();
    let alternate = match field {
        HashKey::ClientIp => (5..=9)
            .map(|last| PickKey {
                client: IpAddr::from([127, 0, 0, last]),
                ..base
            })
            .find(|key| fixture.reference.pick(key) != chosen)
            .expect("bound source addresses span both parents"),
        HashKey::TargetHost => PickKey {
            target_host: &fixture.other_host,
            ..base
        },
        HashKey::User => PickKey {
            user: Some(&fixture.other_user),
            ..base
        },
        HashKey::SessionId => sessions
            .iter()
            .map(|sid| PickKey {
                session: Some(sid),
                ..base
            })
            .find(|key| fixture.reference.pick(key) != chosen)
            .expect("explicit session sample spans both parents"),
    };
    assert_ne!(fixture.reference.pick(&alternate), chosen, "{field:?}");
    let mut seen = HashSet::new();
    for selected in [base, alternate] {
        let exit = fixture.check(origin, &selected).await;
        seen.insert(exit);
        assert_eq!(fixture.check(origin, &selected).await, exit);
        // Change every unrelated attribute, including the decorated login.
        // The origin must still see the exit dictated by the selected field.
        for source in ["127.0.0.6", "127.0.0.7", "127.0.0.8", "127.0.0.9"] {
            let changed = PickKey {
                client: if field == HashKey::ClientIp {
                    selected.client
                } else {
                    ip(source)
                },
                target_host: if field == HashKey::TargetHost {
                    selected.target_host
                } else {
                    "origin2.test"
                },
                user: if field == HashKey::User {
                    selected.user
                } else {
                    Some(&fixture.other_user)
                },
                session: if field == HashKey::SessionId {
                    selected.session
                } else {
                    Some("unrelated")
                },
            };
            assert_eq!(
                fixture.check(origin, &changed).await,
                exit,
                "{field:?}: {changed:?}"
            );
        }
    }
    assert_eq!(seen.len(), 2, "{field:?} did not reach both parents");
}

#[tokio::test]
async fn hash_routes_by_client_ip_target_host_user_and_explicit_session_id() {
    let origin = http_origin("127.0.0.1:0").await;
    for (name, field) in [
        ("client_ip", HashKey::ClientIp),
        ("target_host", HashKey::TargetHost),
        ("user", HashKey::User),
        ("session_id", HashKey::SessionId),
    ] {
        let fixture = Fixture::new(&format!("strategy='hash'\nhash_key='{name}'")).await;
        affinity_case(&fixture, origin, field).await;
        fixture.shutdown().await;
    }
}

#[tokio::test]
async fn userhash_and_sourcehash_override_the_configured_hash_key() {
    let origin = http_origin("127.0.0.1:0").await;
    for (strategy, field) in [
        ("userhash", HashKey::User),
        ("sourcehash", HashKey::ClientIp),
    ] {
        let fixture = Fixture::new(&format!("strategy='{strategy}'\nhash_key='target_host'")).await;
        affinity_case(&fixture, origin, field).await;
        fixture.shutdown().await;
    }
}

#[tokio::test]
async fn carp_routes_each_configured_hash_key_to_the_reference_named_parent() {
    let origin = http_origin("127.0.0.1:0").await;
    for (name, field) in [
        ("client_ip", HashKey::ClientIp),
        ("target_host", HashKey::TargetHost),
        ("user", HashKey::User),
        ("session_id", HashKey::SessionId),
    ] {
        let fixture = Fixture::new(&format!("strategy='carp'\nhash_key='{name}'")).await;
        affinity_case(&fixture, origin, field).await;
        fixture.shutdown().await;
    }
}

#[tokio::test]
async fn sticky_prefers_explicit_sid_then_authenticated_user_then_client_ip() {
    let origin = http_origin("127.0.0.1:0").await;
    let fixture = Fixture::new("strategy='sticky'\nhash_key='target_host'").await;
    affinity_case(&fixture, origin, HashKey::SessionId).await;

    let mut user_exits = HashSet::new();
    for user in ["alice", fixture.other_user.as_str()] {
        let base = PickKey {
            session: None,
            user: Some(user),
            ..key()
        };
        let exit = fixture.check(origin, &base).await;
        user_exits.insert(exit);
        for source in 5..=9 {
            let changed = PickKey {
                client: IpAddr::from([127, 0, 0, source]),
                target_host: "origin3.test",
                ..base
            };
            assert_eq!(fixture.check(origin, &changed).await, exit);
        }
    }
    assert_eq!(
        user_exits.len(),
        2,
        "distinct authenticated users must exercise both parents"
    );

    let mut anonymous_exits = HashSet::new();
    for source in 5..=9 {
        let base = PickKey {
            session: None,
            user: None,
            client: IpAddr::from([127, 0, 0, source]),
            ..key()
        };
        let exit = fixture.check(origin, &base).await;
        anonymous_exits.insert(exit);
        let changed = PickKey {
            target_host: "origin2.test",
            ..base
        };
        assert_eq!(fixture.check(origin, &changed).await, exit);
    }
    assert_eq!(
        anonymous_exits.len(),
        2,
        "anonymous source sample must exercise both parents"
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn weighted_carp_parent_addition_remaps_live_requests_only_to_the_added_parent() {
    let origin = http_origin("127.0.0.1:0").await;
    let mut fixture = Fixture::weighted("strategy='carp'\nhash_key='session_id'", [3, 1]).await;
    let sessions: Vec<_> = (0..32).map(|n| format!("membership{n}")).collect();
    let mut before = Vec::new();
    for session in &sessions {
        before.push(
            fixture
                .check(
                    origin,
                    &PickKey {
                        session: Some(session),
                        ..key()
                    },
                )
                .await,
        );
    }

    let added_exit = ip("127.0.0.10");
    let added = parent("127.0.0.10").await;
    let nodes = format!("{}{}", fixture.nodes, node("p2", added.addr("main"), 2));
    let expanded = Reference::new(&fixture.selector, &nodes);
    fixture.edge.rewrite(&Fixture::config(
        &fixture.selector,
        &nodes,
        &fixture.other_user,
        &fixture.other_host,
    ));
    fixture.edge.server.reload().await.unwrap();
    fixture.upstreams.push(added);

    let exits = [ip(EXITS[0]), ip(EXITS[1]), added_exit];
    let mut moved = 0;
    let mut retained = 0;
    for (session, old_exit) in sessions.iter().zip(before) {
        let key = PickKey {
            session: Some(session),
            ..key()
        };
        let actual = fixture.observed(origin, &key).await;
        assert_eq!(actual, exits[expanded.pick(&key)], "{session}");
        if actual == old_exit {
            retained += 1;
        } else {
            moved += 1;
            assert_eq!(
                actual, added_exit,
                "existing parents must not exchange keys"
            );
        }
    }
    // This is a live remapping check, not another statistical 1/N unit test.
    assert!(
        moved > 0 && retained > 0,
        "moved={moved}, retained={retained}"
    );
    fixture.shutdown().await;
}
