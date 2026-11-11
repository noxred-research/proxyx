//! Selection policies, passive failure recovery, and real loopback source addresses.
#![allow(clippy::unwrap_used)]

mod common;

use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;

use common::{Edge, OPEN, get_ip, http_origin, ip};
use proxyx_edge::breaker::{BreakerState, Transitions};
use proxyx_edge::config::{BreakerConfig, Config, HashKey, Strategy};
use proxyx_edge::egress::{Family, PickError, PickKey, Pool};

fn key() -> PickKey<'static> {
    PickKey {
        session: Some("session-a"),
        user: Some("alice"),
        client: ip("198.51.100.10"),
        target_host: "origin.test",
    }
}

fn configured(options: &str) -> Pool {
    let cfg = Config::parse(&format!(
        "[[pool]]\nname = 'p'\naddresses = ['127.0.0.2', '127.0.0.3']\n{options}\n"
    ))
    .unwrap();
    Pool::from_config(
        &cfg.pools[0],
        BreakerConfig::default(),
        &Transitions::detached(),
    )
    .unwrap()
}

fn pick(pool: &Pool, key: &PickKey<'_>) -> IpAddr {
    pool.pick(Family::V4, key, None, &[]).unwrap().ip()
}

#[test]
fn schema_accepts_every_selector_and_explicit_hash_key() {
    for name in [
        "first",
        "fifo",
        "round_robin",
        "random",
        "least_connections",
        "sticky",
        "hash",
        "userhash",
        "sourcehash",
        "carp",
        "race",
        "latency",
    ] {
        let cfg = Config::parse(&format!("[[pool]]\nname = 'p'\nstrategy = '{name}'\n")).unwrap();
        assert_eq!(cfg.pools[0].hash_key, HashKey::ClientIp);
        assert_eq!(cfg.pools[0].latency_tolerance, Duration::from_millis(50));
        assert_eq!(cfg.pools[0].race_width, 2);
        assert!(cfg.pools[0].max_fails.is_none());
        assert!(cfg.pools[0].fail_timeout.is_none());
    }
    for (name, expected) in [
        ("client_ip", HashKey::ClientIp),
        ("target_host", HashKey::TargetHost),
        ("user", HashKey::User),
        ("session_id", HashKey::SessionId),
    ] {
        let cfg = Config::parse(&format!(
            "[[pool]]\nname = 'p'\nhash_key = '{name}'\nmax_fails = 2\nfail_timeout = '80ms'\nlatency_tolerance = '5ms'\n"
        )).unwrap();
        assert_eq!(cfg.pools[0].hash_key, expected);
        assert_eq!(cfg.pools[0].max_fails, Some(2));
        assert_eq!(cfg.pools[0].fail_timeout, Some(Duration::from_millis(80)));
        assert_eq!(cfg.pools[0].latency_tolerance, Duration::from_millis(5));
    }
}

#[test]
fn invalid_failure_overrides_and_duplicate_backups_are_rejected() {
    for options in [
        "max_fails = 0",
        "fail_timeout = '0s'",
        "race_width = 0",
        "backup_addresses = ['127.0.0.2']",
        "backup_addresses = ['127.0.0.4', '127.0.0.4']",
    ] {
        let cfg = Config::parse(&format!(
            "[[pool]]\nname = 'p'\naddresses = ['127.0.0.2']\n{options}\n"
        ))
        .unwrap();
        assert!(
            Pool::from_config(
                &cfg.pools[0],
                BreakerConfig::default(),
                &Transitions::detached()
            )
            .is_err(),
            "{options}"
        );
    }
}

#[test]
fn fifo_keeps_configuration_order_instead_of_rotating() {
    let pool = configured("strategy = 'fifo'");
    assert_eq!(pool.strategy(), Strategy::Fifo);
    for _ in 0..4 {
        assert_eq!(pick(&pool, &key()), ip("127.0.0.2"));
    }
    assert_eq!(
        pool.pick(Family::V4, &key(), None, &[ip("127.0.0.2")])
            .unwrap()
            .ip(),
        ip("127.0.0.3")
    );
}

#[tokio::test]
async fn failure_threshold_opens_then_fail_timeout_allows_primary_recovery() {
    let pool = configured(
        "strategy = 'fifo'\nmax_fails = 2\nfail_timeout = '40ms'\nbackup_addresses = ['127.0.0.4']",
    );
    let mut first = pool.pick(Family::V4, &key(), None, &[]).unwrap();
    first.report(false);
    first.report(false); // A settled attempt cannot count twice.
    assert_eq!(pool.snapshots()[0].failures, 1);
    drop(first);
    assert_eq!(pick(&pool, &key()), ip("127.0.0.2"));
    let mut second = pool.pick(Family::V4, &key(), None, &[]).unwrap();
    second.report(false);
    drop(second);
    assert_eq!(pool.snapshots()[0].state, BreakerState::Open);
    assert_eq!(pick(&pool, &key()), ip("127.0.0.3"));
    for _ in 0..2 {
        let mut other = pool.pick(Family::V4, &key(), None, &[]).unwrap();
        other.report(false);
    }
    assert_eq!(pick(&pool, &key()), ip("127.0.0.4"));
    tokio::time::sleep(Duration::from_millis(60)).await;
    let mut recovered = pool.pick(Family::V4, &key(), None, &[]).unwrap();
    assert_eq!(recovered.ip(), ip("127.0.0.2"));
    recovered.report(true);
    drop(recovered);
    assert_eq!(pool.snapshots()[0].state, BreakerState::Closed);
    assert_eq!(pick(&pool, &key()), ip("127.0.0.2"));
}

#[test]
fn hash_key_uses_only_its_selected_attribute() {
    let original = key();
    for selected in [
        HashKey::ClientIp,
        HashKey::TargetHost,
        HashKey::User,
        HashKey::SessionId,
    ] {
        let mut changed = original;
        changed.client = ip("203.0.113.7");
        changed.target_host = "elsewhere.test";
        changed.user = Some("bob");
        changed.session = Some("session-b");
        match selected {
            HashKey::ClientIp => changed.client = original.client,
            HashKey::TargetHost => changed.target_host = original.target_host,
            HashKey::User => changed.user = original.user,
            HashKey::SessionId => changed.session = original.session,
        }
        assert_eq!(original.hash_bytes(selected), changed.hash_bytes(selected));
    }
    let mut normalized = original;
    normalized.target_host = "ORIGIN.TEST.";
    assert_eq!(
        original.hash_bytes(HashKey::TargetHost),
        normalized.hash_bytes(HashKey::TargetHost)
    );
    let anonymous = PickKey {
        user: None,
        session: None,
        ..original
    };
    assert_eq!(
        anonymous.hash_bytes(HashKey::User),
        anonymous.hash_bytes(HashKey::ClientIp)
    );
    assert_eq!(
        anonymous.hash_bytes(HashKey::SessionId),
        anonymous.hash_bytes(HashKey::ClientIp)
    );
}

#[test]
fn each_configured_hash_source_spreads_keys_and_preserves_affinity() {
    for source in ["client_ip", "target_host", "user", "session_id"] {
        let pool = configured(&format!("strategy = 'hash'\nhash_key = '{source}'"));
        let mut seen = HashSet::new();
        for n in 1..80 {
            let value = format!("value-{n}.test");
            let mut k = key();
            match source {
                "client_ip" => k.client = IpAddr::from([198, 51, 100, n]),
                "target_host" => k.target_host = &value,
                "user" => k.user = Some(&value),
                "session_id" => k.session = Some(&value),
                _ => unreachable!(),
            }
            let chosen = pick(&pool, &k);
            assert_eq!(chosen, pick(&pool, &k));
            seen.insert(chosen);
        }
        assert_eq!(seen.len(), 2, "{source}");
    }
}

#[test]
fn named_hash_aliases_ignore_unrelated_fields() {
    for (strategy, selected) in [
        ("userhash", HashKey::User),
        ("sourcehash", HashKey::ClientIp),
    ] {
        let pool = configured(&format!(
            "strategy = '{strategy}'\nhash_key = 'target_host'"
        ));
        let original = key();
        let changed = PickKey {
            session: Some("different"),
            target_host: "different.test",
            user: if selected == HashKey::User {
                original.user
            } else {
                Some("different")
            },
            client: if selected == HashKey::ClientIp {
                original.client
            } else {
                ip("203.0.113.1")
            },
        };
        assert_eq!(pick(&pool, &original), pick(&pool, &changed));
    }
}

#[test]
fn carp_remaps_only_keys_from_a_removed_address() {
    let full = configured("strategy = 'carp'\nhash_key = 'session_id'");
    let cfg = Config::parse(
        "[[pool]]\nname='p'\naddresses=['127.0.0.2']\nstrategy='carp'\nhash_key='session_id'",
    )
    .unwrap();
    let reduced = Pool::from_config(
        &cfg.pools[0],
        BreakerConfig::default(),
        &Transitions::detached(),
    )
    .unwrap();
    let mut moved = 0;
    for n in 0..100 {
        let sid = format!("session-{n}");
        let k = PickKey {
            session: Some(&sid),
            ..key()
        };
        let before = pick(&full, &k);
        let after = pick(&reduced, &k);
        if before == ip("127.0.0.2") {
            assert_eq!(before, after);
        } else {
            moved += 1;
        }
    }
    assert!(moved > 20 && moved < 80, "{moved}");
}

#[test]
fn race_candidates_hold_leases_and_exclude_backup_family_and_avoid() {
    let pool = configured("strategy = 'race'\nbackup_addresses = ['127.0.0.4']");
    let candidates = pool.candidates(Family::V4, &key(), None, &[]).unwrap();
    assert_eq!(
        candidates
            .iter()
            .map(|lease| lease.ip())
            .collect::<Vec<_>>(),
        vec![ip("127.0.0.2"), ip("127.0.0.3")]
    );
    assert_eq!(pool.active(), 2);
    drop(candidates);
    assert_eq!(pool.active(), 0);
    assert!(pool.snapshots().iter().all(|a| a.attempts == 0));
    let candidates = pool
        .candidates(Family::V4, &key(), None, &[ip("127.0.0.2")])
        .unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].ip(), ip("127.0.0.3"));
    drop(candidates);
    let pinned = pool.candidates(Family::V4, &key(), Some(2), &[]).unwrap();
    assert_eq!(pinned.len(), 1);
    assert_eq!(pool.index_of(pinned[0].ip()), Some(2));
    assert_eq!(pool.index_of(ip("192.0.2.1")), None);
    assert_eq!(
        pool.candidates(Family::V6, &key(), None, &[]).unwrap_err(),
        PickError::NoAddressOfFamily
    );
    assert_eq!(
        pool.candidates(Family::V6, &key(), Some(1), &[])
            .unwrap_err(),
        PickError::BadIndex
    );
}

#[tokio::test]
async fn dropping_race_losers_releases_half_open_probe_reservations() {
    let pool = configured("strategy = 'race'\nmax_fails = 1\nfail_timeout = '20ms'");
    for mut lease in pool.candidates(Family::V4, &key(), None, &[]).unwrap() {
        lease.report(false);
    }
    assert_eq!(
        pool.candidates(Family::V4, &key(), None, &[]).unwrap_err(),
        PickError::Unavailable
    );
    tokio::time::sleep(Duration::from_millis(30)).await;
    let probes = pool.candidates(Family::V4, &key(), None, &[]).unwrap();
    assert_eq!(probes.len(), 2);
    assert_eq!(
        pool.candidates(Family::V4, &key(), None, &[]).unwrap_err(),
        PickError::Unavailable
    );
    drop(probes);
    assert_eq!(
        pool.candidates(Family::V4, &key(), None, &[])
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn latency_warms_nodes_then_retains_choice_within_tolerance() {
    let pool = configured("strategy = 'latency'\nlatency_tolerance = '10ms'");
    let mut first = pool.pick(Family::V4, &key(), None, &[]).unwrap();
    assert_eq!(first.ip(), ip("127.0.0.2"));
    first.report_latency(Duration::from_millis(100));
    first.report(true);
    drop(first);
    let mut second = pool.pick(Family::V4, &key(), None, &[]).unwrap();
    assert_eq!(second.ip(), ip("127.0.0.3"));
    second.report_latency(Duration::from_millis(120));
    second.report(true);
    drop(second);
    assert_eq!(pick(&pool, &key()), ip("127.0.0.2"));
    assert!(pool.record_latency(ip("127.0.0.3"), Duration::from_millis(70)));
    // Mean 95ms improves by only 5ms, so the previous 100ms node stays selected.
    assert_eq!(pick(&pool, &key()), ip("127.0.0.2"));
    assert!(pool.record_latency(ip("127.0.0.3"), Duration::from_millis(20)));
    assert_eq!(pick(&pool, &key()), ip("127.0.0.3"));
    assert!(!pool.record_latency(ip("192.0.2.9"), Duration::from_millis(1)));
    let snapshots = pool.snapshots();
    assert_eq!(snapshots[0].attempts, 1);
    assert_eq!(snapshots[0].failures, 0);
    assert_eq!(snapshots[0].latency, Some(Duration::from_millis(100)));
}

#[tokio::test]
async fn fifo_and_race_dial_real_loopback_source_addresses() {
    let origin = http_origin("127.0.0.1:0").await;
    for strategy in ["fifo", "race"] {
        let edge = Edge::start(&format!(
            "{OPEN}\n[[pool]]\nname='p'\naddresses=['127.0.0.2','127.0.0.3']\nbackup_addresses=['127.0.0.4']\nstrategy='{strategy}'\n[server]\ndefault_pool='p'\n"
        )).await;
        let target = format!("origin.test:{}", origin.port());
        for _ in 0..3 {
            let actual = get_ip(edge.addr("main"), &target, None).await;
            if strategy == "fifo" {
                assert_eq!(actual, ip("127.0.0.2"));
            } else {
                assert!([ip("127.0.0.2"), ip("127.0.0.3")].contains(&actual));
            }
        }
    }
}

#[tokio::test]
async fn target_host_hash_reaches_origin_from_its_selected_address() {
    let origin = http_origin("127.0.0.1:0").await;
    let pool = configured("strategy='hash'\nhash_key='target_host'");
    let edge = Edge::start(&format!(
        "{OPEN}\n[[pool]]\nname='p'\naddresses=['127.0.0.2','127.0.0.3']\nstrategy='hash'\nhash_key='target_host'\n[server]\ndefault_pool='p'\n"
    )).await;
    for host in ["origin.test", "origin2.test", "origin3.test"] {
        let expected = pick(
            &pool,
            &PickKey {
                target_host: host,
                ..key()
            },
        );
        let target = format!("{host}:{}", origin.port());
        assert_eq!(get_ip(edge.addr("main"), &target, None).await, expected);
        assert_eq!(get_ip(edge.addr("main"), &target, None).await, expected);
    }
}

#[test]
fn latency_rejects_prefixes_without_persistent_per_address_measurements() {
    let cfg =
        Config::parse("[[pool]]\nname='p'\nprefixes=['127.0.2.0/24']\nstrategy='latency'").unwrap();
    let error = Pool::from_config(
        &cfg.pools[0],
        BreakerConfig::default(),
        &Transitions::detached(),
    )
    .unwrap_err();
    assert!(error.contains("latency selection requires persistent addresses"));
}

#[tokio::test]
async fn loopback_backup_exits_after_failed_primary_recovers() {
    let origin = http_origin("127.0.0.1:0").await;
    let edge = Edge::start(&format!(
        "{OPEN}\n[[pool]]\nname='p'\naddresses=['127.0.0.2']\nbackup_addresses=['127.0.0.3']\nstrategy='fifo'\nmax_fails=1\nfail_timeout='200ms'\n[server]\ndefault_pool='p'\n"
    )).await;
    let target = format!("origin.test:{}", origin.port());
    assert_eq!(
        get_ip(edge.addr("main"), &target, None).await,
        ip("127.0.0.2")
    );
    let state = edge.server.shared.state();
    let pool = &state.pools["p"];
    let mut failed = pool.pick(Family::V4, &key(), Some(1), &[]).unwrap();
    failed.report(false);
    drop(failed);
    assert_eq!(
        get_ip(edge.addr("main"), &target, None).await,
        ip("127.0.0.3")
    );
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(
        get_ip(edge.addr("main"), &target, None).await,
        ip("127.0.0.2")
    );
}

#[tokio::test]
async fn loopback_latency_selection_uses_data_and_respects_failed_nodes() {
    let origin = http_origin("127.0.0.1:0").await;
    let edge = Edge::start(&format!(
        "{OPEN}\n[[pool]]\nname='p'\naddresses=['127.0.0.2','127.0.0.3']\nstrategy='latency'\nlatency_tolerance='0ms'\nmax_fails=1\n[server]\ndefault_pool='p'\n"
    )).await;
    let state = edge.server.shared.state();
    let pool = &state.pools["p"];
    pool.record_latency(ip("127.0.0.2"), Duration::from_secs(100));
    pool.record_latency(ip("127.0.0.3"), Duration::from_micros(1));
    let target = format!("origin.test:{}", origin.port());
    assert_eq!(
        get_ip(edge.addr("main"), &target, None).await,
        ip("127.0.0.3")
    );
    let mut failed = pool.pick(Family::V4, &key(), Some(2), &[]).unwrap();
    failed.report(false);
    drop(failed);
    assert_eq!(
        get_ip(edge.addr("main"), &target, None).await,
        ip("127.0.0.2")
    );
}

#[test]
fn race_width_limits_live_candidate_leases_and_allows_next_batch() {
    for width in [1, 2, 3, 8] {
        let cfg = Config::parse(&format!(
            "[[pool]]\nname='p'\naddresses=['127.0.0.2','127.0.0.3','127.0.0.4']\nstrategy='race'\nrace_width={width}"
        )).unwrap();
        let pool = Pool::from_config(
            &cfg.pools[0],
            BreakerConfig::default(),
            &Transitions::detached(),
        )
        .unwrap();
        let first = pool.candidates(Family::V4, &key(), None, &[]).unwrap();
        assert_eq!(first.len(), width.min(3));
        assert_eq!(pool.active(), first.len());
        let avoid = first.iter().map(|lease| lease.ip()).collect::<Vec<_>>();
        drop(first);
        if width < 3 {
            let next = pool.candidates(Family::V4, &key(), None, &avoid).unwrap();
            assert!(next.iter().all(|lease| !avoid.contains(&lease.ip())));
            assert_eq!(next.len(), width.min(3 - width));
        }
        assert_eq!(pool.active(), 0);
    }
}
