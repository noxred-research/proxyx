//! Real loopback parents exercise selection, chaining, probes and durable affinity.
#![allow(clippy::unwrap_used)]

mod common;

use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;

use common::*;
use proxyx_edge::breaker::{BreakerState, Transitions};
use proxyx_edge::config::{BreakerConfig, Config, HashKey, HealthConfig, SelectorConfig, Strategy};
use proxyx_edge::egress::PickKey;
use proxyx_edge::parent::{ParentUse, Parents, Selector};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn key() -> PickKey<'static> {
    PickKey {
        session: Some("sid-a"),
        user: Some("alice"),
        client: ip("198.51.100.1"),
        target_host: "origin.test",
    }
}

fn parents(count: usize) -> Parents {
    let text = (0..count)
        .map(|n| {
            format!(
                "[[parent]]\nname='p{n}'\ntype='http'\naddress='127.0.0.1:{}'\n",
                10000 + n
            )
        })
        .collect::<String>();
    let cfg = Config::parse(&text).unwrap();
    Parents::build(
        &cfg.parents,
        BreakerConfig::default(),
        &HealthConfig::default(),
        &Transitions::detached(),
    )
    .unwrap()
}

fn selector(strategy: Strategy) -> Selector {
    Selector::new(SelectorConfig {
        strategy,
        ..SelectorConfig::default()
    })
}

#[test]
fn fifo_round_robin_least_connections_and_all_hash_keys() {
    let p = parents(3);
    let fifo = selector(Strategy::Fifo);
    for _ in 0..12 {
        assert_eq!(fifo.choose(&p, &[], &[], &key()), Some(0));
    }
    assert_eq!(fifo.choose(&p, &[], &[0], &key()), Some(1));
    let rr = selector(Strategy::RoundRobin);
    let actual: Vec<_> = (0..6)
        .map(|_| rr.choose(&p, &[], &[], &key()).unwrap())
        .collect();
    assert_eq!(actual, [0, 1, 2, 0, 1, 2]);
    let held = ParentUse::new(vec![p.get(0).unwrap().clone()]);
    assert_eq!(
        selector(Strategy::LeastConnections).choose(&p, &[], &[], &key()),
        Some(1)
    );
    drop(held);
    for hash_key in [
        HashKey::ClientIp,
        HashKey::TargetHost,
        HashKey::User,
        HashKey::SessionId,
    ] {
        let s = Selector::new(SelectorConfig {
            strategy: Strategy::Hash,
            hash_key,
            ..SelectorConfig::default()
        });
        let chosen = s.choose(&p, &[], &[], &key());
        assert_eq!(s.choose(&p, &[], &[], &key()), chosen);
    }
    for strategy in [
        Strategy::Userhash,
        Strategy::Sourcehash,
        Strategy::Sticky,
        Strategy::Carp,
    ] {
        let s = selector(strategy);
        assert_eq!(
            s.choose(&p, &[], &[], &key()),
            s.choose(&p, &[], &[], &key())
        );
    }
}

#[test]
fn userhash_and_sourcehash_ignore_unrelated_context() {
    let p = parents(5);
    let changed = PickKey {
        session: Some("new"),
        target_host: "different.test",
        ..key()
    };
    for strategy in [Strategy::Userhash, Strategy::Sourcehash] {
        let s = selector(strategy);
        assert_eq!(
            s.choose(&p, &[], &[], &key()),
            s.choose(&p, &[], &[], &changed)
        );
    }
}

#[test]
fn weighted_carp_membership_change_moves_only_removed_parent_keys() {
    let p = parents(5);
    let expanded = parents(6);
    let s = Selector::new(SelectorConfig {
        strategy: Strategy::Carp,
        hash_key: HashKey::SessionId,
        ..SelectorConfig::default()
    });
    let mut removed = 0;
    let mut added = 0;
    for n in 0..10000 {
        let session = format!("session-{n}");
        let key = PickKey {
            session: Some(&session),
            ..key()
        };
        let before = s.choose(&p, &[], &[], &key).unwrap();
        let after = s.choose(&p, &[], &[2], &key).unwrap();
        let after_add = s.choose(&expanded, &[], &[], &key).unwrap();
        if after_add != before {
            added += 1;
            assert_eq!(after_add, 5);
        }
        if before == 2 {
            removed += 1;
            assert_ne!(after, 2);
        } else {
            assert_eq!(after, before);
        }
    }
    assert!(
        (1700..2300).contains(&removed),
        "removed {removed} of 10000 keys"
    );
    assert!(
        (1400..1900).contains(&added),
        "added parent received {added} of 10000 keys"
    );
}

#[tokio::test]
async fn latency_tolerance_switch_cancellation_and_idle_do_not_refresh_from_probes() {
    let p = parents(2);
    p.get(0).unwrap().record_latency(Duration::from_millis(100));
    p.get(1).unwrap().record_latency(Duration::from_millis(120));
    let s = Selector::new(SelectorConfig {
        strategy: Strategy::Latency,
        tolerance_ms: 50,
        interrupt_on_switch: true,
        idle_timeout: Duration::from_millis(30),
        ..SelectorConfig::default()
    });
    assert_eq!(s.choose(&p, &[], &[], &key()), Some(0));
    let token = s.token().unwrap();
    p.get(1).unwrap().record_latency(Duration::from_millis(70));
    s.refresh(&p, &[]);
    assert!(!token.is_cancelled());
    assert_eq!(s.choose(&p, &[], &[], &key()), Some(0));
    p.get(1).unwrap().record_latency(Duration::from_millis(10));
    s.refresh(&p, &[]);
    assert!(token.is_cancelled());
    assert_eq!(s.choose(&p, &[], &[], &key()), Some(1));
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert!(s.idle());
    s.choose_probe(&p, &[], &key());
    assert!(
        s.idle(),
        "background probes must not create client activity"
    );
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn parent(source: &str) -> Edge {
    Edge::start(&format!("{OPEN}\n[[pool]]\nname='out'\naddresses=['{source}']\n[server]\ndefault_pool='out'\n[health]\ninterval='0'\n")).await
}

fn node(name: &str, kind: &str, address: SocketAddr, extra: &str) -> String {
    format!("[[parent]]\nname='{name}'\ntype='{kind}'\naddress='{address}'\n{extra}\n")
}

fn child(selector: &str, nodes: &str) -> String {
    format!(
        "{OPEN}\n[server]\ndefault_route='parent'\n[health]\ninterval='0'\ntimeout='1s'\n[selector]\n{selector}\n{nodes}"
    )
}

#[tokio::test]
async fn race_uses_first_success_and_backup_recovers_after_fail_timeout() {
    let origin = http_origin("127.0.0.1:0").await;
    let a = parent("127.0.0.3").await;
    let b = parent("127.0.0.4").await;
    let dead: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
    let race = Edge::start(&child(
        "strategy='race'\nrace_width=2",
        &format!(
            "{}{}",
            node("dead", "http", dead, "max_fails=1"),
            node("live", "http", b.addr("main"), "")
        ),
    ))
    .await;
    let target = format!("origin.test:{}", origin.port());
    assert_eq!(
        get_ip(race.addr("main"), &target, None).await,
        ip("127.0.0.4")
    );
    let primary = a.addr("main");
    let backup_cfg = child(
        "strategy='fifo'",
        &format!(
            "{}{}",
            node(
                "primary",
                "http",
                primary,
                "max_fails=1\nfail_timeout='50ms'"
            ),
            node("backup", "http", b.addr("main"), "backup=true")
        ),
    );
    let backup = Edge::start(&format!("{backup_cfg}\n[http]\nparent_keepalive=false\n")).await;
    assert_eq!(
        get_ip(backup.addr("main"), &target, None).await,
        ip("127.0.0.3")
    );
    a.server.shutdown(Duration::from_millis(100)).await;
    assert_eq!(
        get_ip(backup.addr("main"), &target, None).await,
        ip("127.0.0.4")
    );
    let returned=Edge::start(&format!("[[listener]]\nname='main'\nlisten='{primary}'\nauth='none'\n[[rule]]\naction='allow'\nallow_internal=true\n[[pool]]\nname='out'\naddresses=['127.0.0.3']\n[server]\ndefault_pool='out'\n")).await;
    tokio::time::sleep(Duration::from_millis(70)).await;
    assert_eq!(
        get_ip(backup.addr("main"), &target, None).await,
        ip("127.0.0.3")
    );
    drop(returned);
}

#[tokio::test]
async fn http_socks5_socks4_chain_reaches_origin_and_reports_broken_second_hop() {
    let origin = banner_origin("127.0.0.1:0").await;
    let first = parent("127.0.0.2").await;
    let middle = parent("127.0.0.3").await;
    let last = parent("127.0.0.4").await;
    let nodes = format!(
        "{}{}{}",
        node("first", "http", first.addr("main"), ""),
        node("middle", "socks5", middle.addr("main"), "max_fails=1"),
        node("last", "socks4", last.addr("main"), "")
    );
    let chain = "[[chain]]\nname='route'\nhops=[{parents=['first']},{parents=['middle']},{parents=['last']}]\n[[route]]\nroute='parent'\nchain='route'\n";
    let edge = Edge::start(&format!("{}\n{chain}", child("strategy='fifo'", &nodes))).await;
    let target = format!("origin.test:{}", origin.port());
    let mut tunnel = tunnel(edge.addr("main"), &target, None).await.unwrap();
    assert_eq!(read_line(&mut tunnel).await, "ip:127.0.0.4");
    tunnel.write_all(b"chain-ok\n").await.unwrap();
    assert_eq!(read_line(&mut tunnel).await, "chain-ok");
    drop(tunnel);
    middle.server.shutdown(Duration::from_millis(100)).await;
    assert!(
        common::tunnel(edge.addr("main"), &target, None)
            .await
            .is_err()
    );
    let state = edge.server.shared.state();
    assert_eq!(
        state
            .parents
            .get(state.parents.index_of("middle").unwrap())
            .unwrap()
            .state(),
        BreakerState::Open
    );
}

#[tokio::test]
async fn http_keepalive_retains_parent_chain_despite_round_robin() {
    let origin = http_origin("127.0.0.1:0").await;
    let first = parent("127.0.0.3").await;
    let second = parent("127.0.0.4").await;
    let nodes = format!(
        "{}{}",
        node("a", "http", first.addr("main"), ""),
        node("b", "http", second.addr("main"), "")
    );
    let edge = Edge::start(&child("strategy='round_robin'", &nodes)).await;
    let mut stream = TcpStream::connect(edge.addr("main")).await.unwrap();
    let mut addresses = HashSet::new();
    for _ in 0..4 {
        stream
            .write_all(
                format!(
                    "GET http://origin.test:{}/ip HTTP/1.1\r\nHost: origin.test\r\n\r\n",
                    origin.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let response = read_response(&mut stream, false).await;
        assert_eq!(response.status, 200);
        addresses.insert(response.text());
    }
    assert_eq!(addresses.len(), 1);
}

#[tokio::test]
async fn bounded_http_substring_and_end_to_end_chain_probe_detect_failure() {
    let origin = http_origin("127.0.0.1:0").await;
    let first = parent("127.0.0.3").await;
    let nodes = node(
        "one",
        "http",
        first.addr("main"),
        &format!(
            "probe={{type='http',url='http://origin.test:{}/ip',status=200,body_contains='127.0.0.3',max_body_bytes=64}}",
            origin.port()
        ),
    );
    let edge = Edge::start(&child("strategy='latency'", &nodes)).await;
    let state = edge.server.shared.state();
    proxyx_edge::health::round(&edge.server.shared, &state).await;
    assert!(state.parents.get(0).unwrap().health.is_healthy());
    assert!(state.parents.get(0).unwrap().latency().is_some());
    let dead = free_port();
    let chain = format!(
        "[[chain]]\nname='broken'\nhops=[{{parents=['one']}}]\nprobe={{type='tcp',target='127.0.0.1:{dead}'}}\n[[route]]\nroute='parent'\nchain='broken'\n"
    );
    let edge = Edge::start(&format!(
        "{}\n{chain}",
        child(
            "strategy='fifo'",
            &node("one", "http", first.addr("main"), "")
        )
    ))
    .await;
    let state = edge.server.shared.state();
    proxyx_edge::health::round(&edge.server.shared, &state).await;
    proxyx_edge::health::round(&edge.server.shared, &state).await;
    assert!(!state.chains[0].health.is_healthy());
    let _recovered = banner_origin(&format!("127.0.0.1:{dead}")).await;
    proxyx_edge::health::round(&edge.server.shared, &state).await;
    assert!(state.chains[0].health.is_healthy());
}

fn sticky_config(addresses: &str, extra: &str) -> String {
    format!(
        "[[listener]]\nname='main'\nlisten='127.0.0.1:0'\n[auth]\nlogin_options=true\n[[user]]\nname='alice'\npassword='pw'\n[[rule]]\naction='allow'\nallow_internal=true\n[[pool]]\nname='out'\naddresses=[{addresses}]\nstrategy='round_robin'\n[server]\ndefault_pool='out'\n[selector]\nstrategy='sticky'\n[health]\ninterval='0'\n{extra}"
    )
}

#[tokio::test]
async fn stick_claim_survives_reload_and_address_reordering() {
    let origin = http_origin("127.0.0.1:0").await;
    let edge = Edge::start(&sticky_config("'127.0.0.2','127.0.0.3'", "")).await;
    let target = format!("origin.test:{}", origin.port());
    let auth = Some(("alice-sid-persistent", "pw"));
    let before = get_ip(edge.addr("main"), &target, auth).await;
    let old = edge.server.shared.state().stick.clone();
    edge.rewrite(&sticky_config("'127.0.0.3','127.0.0.2'", ""));
    edge.server.reload().await.unwrap();
    assert!(std::sync::Arc::ptr_eq(
        &old,
        &edge.server.shared.state().stick
    ));
    assert_eq!(get_ip(edge.addr("main"), &target, auth).await, before);
}

struct RedisProcess(std::process::Child);
impl Drop for RedisProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn redis_server() -> (Option<RedisProcess>, String) {
    if let Ok(url) = std::env::var("PROXYX_TEST_REDIS_URL") {
        return (None, url);
    }
    let port = free_port();
    let process = std::process::Command::new("redis-server")
        .args([
            "--bind",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--save",
            "",
            "--appendonly",
            "no",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("redis-server is required for Redis affinity integration tests");
    let guard = RedisProcess(process);
    let url = format!("redis://127.0.0.1:{port}/");
    let client = redis::Client::open(url.as_str()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(mut connection) = client.get_multiplexed_async_connection().await
                && redis::cmd("PING")
                    .query_async::<String>(&mut connection)
                    .await
                    .is_ok()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    (Some(guard), url)
}

#[tokio::test]
async fn redis_shares_atomic_claims_across_replicas_and_never_refreshes_ttl() {
    let (_redis, url) = redis_server().await;
    let origin = http_origin("127.0.0.1:0").await;
    let prefix = format!("edge-test:{}:{}", std::process::id(), free_port());
    let config = format!(
        "[stick]\nttl='5s'\n[stick.redis]\nurl='{url}'\nkey_prefix='{prefix}'\nttl='2s'\ntimeout='1s'\n"
    );
    let a = Edge::start(&sticky_config("'127.0.0.2','127.0.0.3'", &config)).await;
    let b = Edge::start(&sticky_config("'127.0.0.3','127.0.0.2'", &config)).await;
    let target = format!("origin.test:{}", origin.port());
    let auth = Some(("alice-sid-shared", "pw"));
    let (a_ip, b_ip) = tokio::join!(
        get_ip(a.addr("main"), &target, auth),
        get_ip(b.addr("main"), &target, auth)
    );
    assert_eq!(a_ip, b_ip);
    let mut connection = redis::Client::open(url)
        .unwrap()
        .get_multiplexed_async_connection()
        .await
        .unwrap();
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg(format!("{prefix}:claim:*"))
        .query_async(&mut connection)
        .await
        .unwrap();
    assert_eq!(keys.len(), 1);
    let before: i64 = redis::cmd("PTTL")
        .arg(&keys[0])
        .query_async(&mut connection)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(get_ip(b.addr("main"), &target, auth).await, a_ip);
    let after: i64 = redis::cmd("PTTL")
        .arg(&keys[0])
        .query_async(&mut connection)
        .await
        .unwrap();
    assert!(
        after > 0 && after < before - 50,
        "before={before} after={after}"
    );
}

#[tokio::test]
async fn redis_outage_fails_closed_instead_of_creating_local_mapping() {
    let address = format!("redis://127.0.0.1:{}/", free_port());
    let origin = http_origin("127.0.0.1:0").await;
    let edge = Edge::start(&sticky_config(
        "'127.0.0.2','127.0.0.3'",
        &format!("[stick.redis]\nurl='{address}'\ntimeout='50ms'"),
    ))
    .await;
    let response = get(
        edge.addr("main"),
        &format!("origin.test:{}", origin.port()),
        "/ip",
        Some(("alice-sid-no-local", "pw")),
    )
    .await;
    assert_ne!(response.status, 200);
    assert!(edge.server.shared.state().stick.is_empty());
}

#[tokio::test]
async fn monitored_latency_switch_closes_existing_tunnel() {
    let origin = banner_origin("127.0.0.1:0").await;
    let a = parent("127.0.0.3").await;
    let b = parent("127.0.0.4").await;
    let edge = Edge::start(&child(
        "strategy='latency'\ntolerance_ms=0\ninterrupt_on_switch=true",
        &format!(
            "{}{}",
            node("a", "http", a.addr("main"), ""),
            node("b", "http", b.addr("main"), "")
        ),
    ))
    .await;
    let state = edge.server.shared.state();
    state
        .parents
        .get(0)
        .unwrap()
        .record_latency(Duration::from_millis(1));
    state
        .parents
        .get(1)
        .unwrap()
        .record_latency(Duration::from_secs(1));
    let mut client = tunnel(
        edge.addr("main"),
        &format!("origin.test:{}", origin.port()),
        None,
    )
    .await
    .unwrap();
    read_line(&mut client).await;
    state
        .parents
        .get(0)
        .unwrap()
        .record_latency(Duration::from_secs(2));
    state
        .parents
        .get(1)
        .unwrap()
        .record_latency(Duration::from_millis(1));
    state.selector.refresh(&state.parents, &[]);
    let mut byte = [0];
    let read = tokio::time::timeout(Duration::from_secs(1), client.read(&mut byte))
        .await
        .unwrap();
    assert!(matches!(read, Ok(0) | Err(_)));
}

#[tokio::test]
async fn command_probe_timeout_kills_child_and_reports_failure() {
    let parent = parent("127.0.0.3").await;
    let edge = Edge::start(&child(
        "strategy='fifo'",
        &node(
            "p",
            "http",
            parent.addr("main"),
            "probe={type='command',command=['sleep','30']}",
        ),
    ))
    .await;
    let state = edge.server.shared.state();
    let pid_file = edge.dir.join("probe.pid");
    let mut config = state.cfg.parents[0].clone();
    config.probe = Some(proxyx_edge::config::ProbeConfig::Command {
        command: vec![
            "sh".to_owned(),
            "-c".to_owned(),
            format!(
                "printf '%s' \"$$\" > '{}'; exec sleep 30",
                pid_file.display()
            ),
        ],
    });
    let probed = std::sync::Arc::new(
        proxyx_edge::parent::Parent::from_config(
            &config,
            state.cfg.breaker.parent,
            &state.cfg.health,
            &Transitions::detached(),
        )
        .unwrap(),
    );
    let start = tokio::time::Instant::now();
    assert!(
        proxyx_edge::connect::probe_parent(&state, &probed, None, Duration::from_millis(500))
            .await
            .is_err()
    );
    assert!(start.elapsed() < Duration::from_secs(1));
    let pid = std::fs::read_to_string(pid_file).unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while std::path::Path::new(&format!("/proc/{pid}")).exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("timed-out child must be killed and reaped");
}

#[test]
fn named_hashes_match_explicit_hash_keys_and_carp_respects_weights() {
    let p = parents(4);
    for (strategy, hash_key) in [
        (Strategy::Userhash, HashKey::User),
        (Strategy::Sourcehash, HashKey::ClientIp),
    ] {
        let alias = selector(strategy);
        let explicit = Selector::new(SelectorConfig {
            strategy: Strategy::Hash,
            hash_key,
            ..SelectorConfig::default()
        });
        assert_eq!(
            alias.choose(&p, &[], &[], &key()),
            explicit.choose(&p, &[], &[], &key())
        );
    }
    let cfg = Config::parse("[[parent]]\nname='heavy'\ntype='http'\naddress='127.0.0.1:1'\nweight=3\n[[parent]]\nname='light'\ntype='http'\naddress='127.0.0.1:2'\n").unwrap();
    let p = Parents::build(
        &cfg.parents,
        BreakerConfig::default(),
        &HealthConfig::default(),
        &Transitions::detached(),
    )
    .unwrap();
    let s = Selector::new(SelectorConfig {
        strategy: Strategy::Carp,
        hash_key: HashKey::SessionId,
        ..SelectorConfig::default()
    });
    let mut heavy = 0;
    for n in 0..10000 {
        let session = format!("weight-{n}");
        let key = PickKey {
            session: Some(&session),
            ..key()
        };
        if s.choose(&p, &[], &[], &key) == Some(0) {
            heavy += 1;
        }
    }
    assert!(
        (7100..7900).contains(&heavy),
        "weighted CARP chose heavy node {heavy} times"
    );
}

#[tokio::test]
async fn race_drops_slow_handshake_transport_after_fast_success() {
    let origin = banner_origin("127.0.0.1:0").await;
    let upstream = parent("127.0.0.3").await;
    let delayed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let delayed_addr = delayed.local_addr().unwrap();
    let target = upstream.addr("main");
    let relay = tokio::spawn(async move {
        loop {
            let Ok((mut inbound, _)) = delayed.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut outbound = TcpStream::connect(target).await.unwrap();
                tokio::time::sleep(Duration::from_millis(500)).await;
                let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
            });
        }
    });
    let nodes = format!(
        "{}{}",
        node("slow", "http", delayed_addr, ""),
        node("fast", "http", upstream.addr("main"), "")
    );
    let edge = Edge::start(&child("strategy='race'\nrace_width=2", &nodes)).await;
    let started = tokio::time::Instant::now();
    let mut client = tunnel(
        edge.addr("main"),
        &format!("origin.test:{}", origin.port()),
        None,
    )
    .await
    .unwrap();
    assert_eq!(read_line(&mut client).await, "ip:127.0.0.3");
    assert!(started.elapsed() < Duration::from_millis(400));
    let state = edge.server.shared.state();
    assert_eq!(state.parents.get(0).unwrap().stats().active, 0);
    assert_eq!(
        state.parents.get(0).unwrap().stats().failures,
        0,
        "canceled races are not failures"
    );
    relay.abort();
}

#[tokio::test]
async fn sticky_hop_does_not_disable_later_round_robin_hop() {
    let origin = http_origin("127.0.0.1:0").await;
    let entry = parent("127.0.0.2").await;
    let a = parent("127.0.0.3").await;
    let b = parent("127.0.0.4").await;
    let nodes = format!(
        "{}{}{}",
        node("entry", "http", entry.addr("main"), ""),
        node("a", "http", a.addr("main"), ""),
        node("b", "http", b.addr("main"), "")
    );
    let chain = "[[chain]]\nname='mixed'\nhops=[{parents=['entry'],selector={strategy='sticky'}},{parents=['a','b'],selector={strategy='round_robin'}}]\n[[route]]\nroute='parent'\nchain='mixed'\n";
    let edge = Edge::start(&format!("{}\n{chain}", child("strategy='fifo'", &nodes))).await;
    let target = format!("origin.test:{}", origin.port());
    let mut seen = HashSet::new();
    for _ in 0..4 {
        seen.insert(get_ip(edge.addr("main"), &target, None).await);
    }
    assert_eq!(seen, HashSet::from([ip("127.0.0.3"), ip("127.0.0.4")]));
}

#[tokio::test]
async fn http_probe_substring_must_fit_inside_explicit_body_bound() {
    let origin = http_origin("127.0.0.1:0").await;
    let upstream = parent("127.0.0.3").await;
    let nodes = node(
        "p",
        "http",
        upstream.addr("main"),
        &format!(
            "probe={{type='http',url='http://origin.test:{}/ip',status=200,body_contains='0.3',max_body_bytes=3}}",
            origin.port()
        ),
    );
    let edge = Edge::start(&child("strategy='fifo'", &nodes)).await;
    let state = edge.server.shared.state();
    assert!(
        proxyx_edge::connect::probe_parent(
            &state,
            state.parents.get(0).unwrap(),
            None,
            Duration::from_secs(1)
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn redis_namespace_capacity_and_exact_parent_egress_mapping_are_atomic() {
    use proxyx_edge::stick::{Mapping, StickMap};
    let (_process, url) = redis_server().await;
    let prefix = format!("edge-capacity:{}:{}", std::process::id(), free_port());
    let cfg = Config::parse(&format!("[stick]\ncapacity=2\nttl='2s'\n[stick.redis]\nurl='{url}'\nkey_prefix='{prefix}'\ntimeout='1s'\n")).unwrap();
    let a = StickMap::new(&cfg.stick).unwrap();
    let b = StickMap::new(&cfg.stick).unwrap();
    let first = Mapping {
        parents: vec!["one".to_owned(), "two".to_owned()],
        egress: Some(ip("127.0.0.2")),
    };
    let second = Mapping {
        parents: vec!["other".to_owned()],
        egress: Some(ip("127.0.0.3")),
    };
    let (claim_a, claim_b) = tokio::join!(
        a.claim("same", first.clone(), |_| true),
        b.claim("same", second.clone(), |_| true)
    );
    assert_eq!(
        claim_a.unwrap(),
        claim_b.unwrap(),
        "claim must bind parent path and egress as one value"
    );
    a.claim("two", first.clone(), |_| true).await.unwrap();
    b.claim("three", second.clone(), |_| true).await.unwrap();
    let mut connection = redis::Client::open(url)
        .unwrap()
        .get_multiplexed_async_connection()
        .await
        .unwrap();
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg(format!("{prefix}:claim:*"))
        .query_async(&mut connection)
        .await
        .unwrap();
    assert_eq!(keys.len(), 2);
    let indexed: usize = redis::cmd("ZCARD")
        .arg(format!("{prefix}:expiry"))
        .query_async(&mut connection)
        .await
        .unwrap();
    assert_eq!(indexed, 2);
    assert_eq!(
        a.claim("three", first.clone(), |value| value == &first)
            .await
            .unwrap(),
        first
    );
    for key in keys {
        let _: i64 = redis::cmd("DEL")
            .arg(key)
            .query_async(&mut connection)
            .await
            .unwrap();
    }
    let _: i64 = redis::cmd("DEL")
        .arg(format!("{prefix}:expiry"))
        .query_async(&mut connection)
        .await
        .unwrap();
}

#[test]
fn backup_and_default_parents_follow_primary_tiers() {
    let cfg = Config::parse("[[parent]]\nname='primary'\ntype='http'\naddress='127.0.0.1:1'\nmax_fails=1\n[[parent]]\nname='backup'\ntype='http'\naddress='127.0.0.1:2'\nbackup=true\nmax_fails=1\n[[parent]]\nname='last'\ntype='http'\naddress='127.0.0.1:3'\ndefault=true\n").unwrap();
    let p = Parents::build(
        &cfg.parents,
        BreakerConfig::default(),
        &HealthConfig::default(),
        &Transitions::detached(),
    )
    .unwrap();
    let s = selector(Strategy::Fifo);
    assert_eq!(s.choose(&p, &[], &[], &key()), Some(0));
    p.get(0).unwrap().report(false);
    assert_eq!(s.choose(&p, &[], &[], &key()), Some(1));
    p.get(1).unwrap().report(false);
    assert_eq!(s.choose(&p, &[], &[], &key()), Some(2));
}

#[tokio::test]
async fn repeated_http_auth_failures_open_parent_breaker_without_tcp_success_reset() {
    let origin = http_origin("127.0.0.1:0").await;
    let upstream = Edge::start("[[listener]]\nname='main'\nlisten='127.0.0.1:0'\n[[user]]\nname='relay'\npassword='correct'\n[[rule]]\naction='allow'\nallow_internal=true\n").await;
    let edge = Edge::start(&child(
        "strategy='fifo'",
        &node(
            "p",
            "http",
            upstream.addr("main"),
            "username='relay'\npassword='wrong'\nmax_fails=2",
        ),
    ))
    .await;
    let target = format!("origin.test:{}", origin.port());
    for _ in 0..2 {
        assert_eq!(
            get(edge.addr("main"), &target, "/ip", None).await.status,
            502
        );
    }
    let state = edge.server.shared.state();
    assert_eq!(state.parents.get(0).unwrap().state(), BreakerState::Open);
    assert_eq!(
        get(edge.addr("main"), &target, "/ip", None).await.status,
        503
    );
}

#[tokio::test]
async fn latency_active_probes_pause_after_client_idle_and_resume_on_request() {
    let upstream = parent("127.0.0.3").await;
    let origin = http_origin("127.0.0.1:0").await;
    let edge = Edge::start(&child(
        "strategy='latency'\nidle_timeout='200ms'",
        &node("p", "http", upstream.addr("main"), ""),
    ))
    .await;
    let state = edge.server.shared.state();
    tokio::time::sleep(Duration::from_millis(250)).await;
    state
        .parents
        .get(0)
        .unwrap()
        .record_latency(Duration::from_secs(5));
    proxyx_edge::health::round(&edge.server.shared, &state).await;
    assert_eq!(
        state.parents.get(0).unwrap().latency(),
        Some(Duration::from_secs(5))
    );
    assert_eq!(
        get_ip(
            edge.addr("main"),
            &format!("origin.test:{}", origin.port()),
            None
        )
        .await,
        ip("127.0.0.3")
    );
    assert!(!state.selector.idle());
    proxyx_edge::health::round(&edge.server.shared, &state).await;
    assert!(state.parents.get(0).unwrap().latency().unwrap() < Duration::from_secs(5));
}

#[tokio::test]
async fn latency_warms_unmeasured_parents_from_live_dials() {
    let a = parent("127.0.0.3").await;
    let b = parent("127.0.0.4").await;
    let origin = http_origin("127.0.0.1:0").await;
    let edge = Edge::start(&child(
        "strategy='latency'",
        &format!(
            "{}{}",
            node("a", "http", a.addr("main"), ""),
            node("b", "http", b.addr("main"), "")
        ),
    ))
    .await;
    let target = format!("origin.test:{}", origin.port());
    let first = get_ip(edge.addr("main"), &target, None).await;
    let second = get_ip(edge.addr("main"), &target, None).await;
    assert_ne!(
        first, second,
        "unmeasured parents need one live dial before latency comparison"
    );
    let state = edge.server.shared.state();
    assert!(
        state
            .parents
            .all()
            .iter()
            .all(|parent| parent.latency().is_some())
    );
}

#[tokio::test]
async fn redis_manager_recovers_after_its_transparent_bridge_disconnects() {
    use proxyx_edge::stick::{Mapping, StickMap};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use tokio_util::sync::CancellationToken;

    let (_process, url) = redis_server().await;
    let client = redis::Client::open(url.as_str()).unwrap();
    let (host, port) = match &client.get_connection_info().addr {
        redis::ConnectionAddr::Tcp(host, port) => (host.clone(), *port),
        _ => panic!("Redis reconnect regression requires a plaintext TCP PROXYX_TEST_REDIS_URL"),
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (scheme, rest) = url.split_once("://").unwrap();
    let (authority, suffix) = rest.split_once('/').unwrap_or((rest, ""));
    let auth = authority
        .rsplit_once('@')
        .map_or(String::new(), |(auth, _)| format!("{auth}@"));
    let bridge_url = format!("{scheme}://{auth}{address}/{suffix}");
    let online = Arc::new(AtomicBool::new(true));
    let active = Arc::new(AtomicUsize::new(0));
    let generation = Arc::new(parking_lot::Mutex::new(CancellationToken::new()));
    let stop = CancellationToken::new();

    struct Active(Arc<AtomicUsize>);
    impl Drop for Active {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }
    struct Bridge {
        task: tokio::task::JoinHandle<()>,
        stop: CancellationToken,
    }
    impl Drop for Bridge {
        fn drop(&mut self) {
            self.stop.cancel();
            self.task.abort();
        }
    }
    let task = {
        let online = Arc::clone(&online);
        let active = Arc::clone(&active);
        let generation = Arc::clone(&generation);
        let stop = stop.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut inbound, _)) = listener.accept().await else {
                    return;
                };
                if !online.load(Ordering::SeqCst) {
                    continue;
                }
                let cut = generation.lock().clone();
                let host = host.clone();
                let stop = stop.clone();
                active.fetch_add(1, Ordering::SeqCst);
                let guard = Active(Arc::clone(&active));
                tokio::spawn(async move {
                    let _guard = guard;
                    let outbound = tokio::select! {
                        result = TcpStream::connect((host.as_str(), port)) => result,
                        () = cut.cancelled() => return,
                        () = stop.cancelled() => return,
                    };
                    let Ok(mut outbound) = outbound else {
                        return;
                    };
                    tokio::select! {
                        _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound) => {}
                        () = cut.cancelled() => {}
                        () = stop.cancelled() => {}
                    }
                });
            }
        })
    };
    let _bridge = Bridge { task, stop };
    let prefix = format!("edge-reconnect:{}:{}", std::process::id(), free_port());
    // A generous claim timeout: the disconnected claim below fails on the cut
    // connection, not on this timer, and a loaded CI host can take well over
    // 200 ms for the first claim through the bridge.
    let cfg = Config::parse(&format!(
        "[stick]\nttl='30s'\n[stick.redis]\nurl={}\nkey_prefix='{prefix}'\ntimeout='2s'\n",
        serde_json::to_string(&bridge_url).unwrap()
    ))
    .unwrap();
    let map = StickMap::new(&cfg.stick).unwrap();
    let original = Mapping {
        parents: vec!["original".to_owned()],
        egress: Some(ip("127.0.0.2")),
    };
    let changed = Mapping {
        parents: vec!["changed".to_owned()],
        egress: Some(ip("127.0.0.3")),
    };
    assert_eq!(
        map.claim("shared", original.clone(), |_| true)
            .await
            .unwrap(),
        original
    );
    online.store(false, Ordering::SeqCst);
    generation.lock().cancel();
    tokio::time::timeout(Duration::from_secs(2), async {
        while active.load(Ordering::SeqCst) != 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        map.claim("shared", changed.clone(), |_| true)
            .await
            .is_err(),
        "disconnected Redis must fail closed"
    );
    *generation.lock() = CancellationToken::new();
    online.store(true, Ordering::SeqCst);
    let recovered = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(value) = map.claim("shared", changed.clone(), |_| true).await {
                break value;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("connection manager must reconnect without reload");
    assert_eq!(recovered, original);
    let mut connection = client.get_multiplexed_async_connection().await.unwrap();
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg(format!("{prefix}:*"))
        .query_async(&mut connection)
        .await
        .unwrap();
    let _: i64 = redis::cmd("DEL")
        .arg(keys)
        .query_async(&mut connection)
        .await
        .unwrap();
}

#[test]
fn late_dial_to_old_latency_choice_receives_canceled_generation() {
    let p = parents(2);
    p.get(0).unwrap().record_latency(Duration::from_millis(1));
    p.get(1).unwrap().record_latency(Duration::from_millis(100));
    let selector = Selector::new(SelectorConfig {
        strategy: Strategy::Latency,
        interrupt_on_switch: true,
        tolerance_ms: 0,
        ..SelectorConfig::default()
    });
    assert_eq!(selector.choose(&p, &[], &[], &key()), Some(0));
    p.get(0).unwrap().record_latency(Duration::from_millis(100));
    p.get(1).unwrap().record_latency(Duration::from_millis(1));
    selector.refresh(&p, &[]);
    assert!(selector.token_for(0).unwrap().is_cancelled());
    assert!(!selector.token_for(1).unwrap().is_cancelled());
}

#[tokio::test]
async fn broken_second_hop_uses_its_backup_without_opening_reachable_first_hop() {
    let first = parent("127.0.0.2").await;
    let backup = parent("127.0.0.4").await;
    let origin = http_origin("127.0.0.1:0").await;
    let dead: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
    let nodes = format!(
        "{}{}{}",
        node("entry", "http", first.addr("main"), "max_fails=1"),
        node("dead", "http", dead, "max_fails=1"),
        node("backup", "http", backup.addr("main"), "backup=true")
    );
    let chain = "[[chain]]\nname='backup-hop'\nhops=[{parents=['entry']},{parents=['dead','backup']}]\n[[route]]\nroute='parent'\nchain='backup-hop'\n";
    let edge = Edge::start(&format!("{}\n{chain}", child("strategy='fifo'", &nodes))).await;
    assert_eq!(
        get_ip(
            edge.addr("main"),
            &format!("origin.test:{}", origin.port()),
            None
        )
        .await,
        ip("127.0.0.4")
    );
    let state = edge.server.shared.state();
    assert_eq!(
        state
            .parents
            .get(state.parents.index_of("entry").unwrap())
            .unwrap()
            .state(),
        BreakerState::Closed
    );
    assert_eq!(
        state
            .parents
            .get(state.parents.index_of("dead").unwrap())
            .unwrap()
            .state(),
        BreakerState::Open
    );
}

#[tokio::test]
async fn sticky_explicit_egress_skips_incompatible_first_parent_dns_family() {
    let upstream = parent("127.0.0.3").await;
    let origin = http_origin("127.0.0.1:0").await;
    let edge = Edge::start(OPEN).await;
    let nodes = node("p", "http", upstream.addr("main"), "pool='source'").replace(
        &format!("address='{}'", upstream.addr("main")),
        &format!("address='parent.test:{}'", upstream.addr("main").port()),
    );
    let config = format!(
        "{BASE}\n\"parent.test\"=['::1','127.0.0.1']\n{}\n[[pool]]\nname='source'\naddresses=['127.0.0.2']\n",
        child("strategy='sticky'", &nodes)
    );
    std::fs::write(&edge.path, config).unwrap();
    edge.server.reload().await.unwrap();
    assert_eq!(
        get_ip(
            edge.addr("main"),
            &format!("origin.test:{}", origin.port()),
            None
        )
        .await,
        ip("127.0.0.3")
    );
    assert_eq!(edge.server.shared.state().stick.len(), 1);
}
