//! R1 and R1b: no org is stalled while a unit can serve it, and a
//! failed IP is left out for another. Same stubs and skip rule as the parent
//! module.

use super::*;

/// R1b: an IP that answers the CONNECT with a status, or with no HTTP at all,
/// fails that IP and not the tunnel: another IP serves it. The failed IP is
/// cooled for the target, not withdrawn, and the breaker stays closed.
#[tokio::test]
async fn an_ip_level_dial_failure_is_retried_on_another_ip_without_withdrawing_the_failed_one()
-> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let good = stub_provider(PROVIDER_PASS, stub_target().await, uniq_ip()).await;
    let dead = closed_endpoint();
    let status = stub_provider(PROVIDER_PASS, dead.addr(), uniq_ip()).await;
    let garbage = serve(|mut s| async move {
        if read_head(&mut s).await.is_some() {
            let _ = s.write_all(b"not http at all\r\n\r\n").await;
        }
    })
    .await;
    for (what, bad) in [("a status", status.addr), ("no HTTP", garbage)] {
        let mut setup = Setup::new();
        setup.pacing.breaker = breaker(1000);
        // "198.18" sorts before "198.19": the failing IP is leased first
        let (bad_ip, good_ip) = (
            IpAddr::from([198, 18, 11, 1]),
            IpAddr::from([198, 19, 11, 1]),
        );
        let h = start(
            &env,
            &setup,
            vec![
                row(&entry(&setup, bad_ip, bad.port()), true),
                row(&entry(&setup, good_ip, good.addr.port()), true),
            ],
        )
        .await?;
        let p = setup.partition();
        for ip in [bad_ip, good_ip] {
            h.ready(&p, ip).await?;
        }
        let r = connect_via(h.connect, "px-sid-r1b", &setup.key).await?;
        assert_eq!(r.status, 200, "{what}: {}", r.reason);
        assert_eq!(
            r.header("X-ProxyX-Exit-IP"),
            Some(good_ip.to_string().as_str()),
            "{what}"
        );
        assert!(
            h.hot.is_ready(&p, &bad_ip.to_string()).await?,
            "{what}: the failed IP is cooled, not withdrawn"
        );
        assert_eq!(
            h.hot.breaker_peek(&p, &breaker(1000)).await?.0,
            BreakerState::Closed,
            "{what}"
        );
    }
    Ok(())
}

/// The only IP rests after the org that held it last; another org is not
/// stalled by it: it takes the IP, and the rest broken is counted.
#[tokio::test]
async fn an_org_is_not_stalled_by_the_rest_of_the_only_ip_and_the_broken_limit_is_counted()
-> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.kinds = r#"["static"]"#;
    setup.policy = "sticky_scope = \"connection\"\n".into();
    let (h, _, ip) = static_fixture(&env, &setup).await?;
    let p = setup.partition();
    let broken = |limit| {
        h.metrics
            .lease_limit_broken_total
            .with_label_values(&[limit, &setup.provider])
            .get()
    };

    let a = connect_via(h.connect, "px", &setup.key).await?;
    assert_eq!(a.status, 200, "{}", a.reason);
    drop(a);
    // the unit has no lease and no tunnel: it rests for the 30 s default
    eventually("the unit to be free", || async {
        tunnels_closed(&h, &setup.org).await
            && h.hot
                .unit_load(&p, &ip.to_string())
                .await
                .is_ok_and(|l| l.leases == 0)
    })
    .await;
    assert_eq!(broken("rest"), 0);

    let started = std::time::Instant::now();
    let b = connect_via(h.connect, "px", &setup.rival_key).await?;
    assert_eq!(b.status, 200, "{}", b.reason);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "served at once, not after the lease wait"
    );
    assert_eq!(broken("rest"), 1);
    Ok(())
}

/// A TCP proxy in front of Redis. It notes when each lease script goes by
/// (`leases`), and with a `stall` withholds every reply of Redis for that long
/// after one does: the script runs, but whoever called it hears nothing in
/// time, as when Redis is slow under a burst.
struct RedisTap {
    url: String,
    leases: Arc<Mutex<Vec<std::time::Instant>>>,
}

async fn tap_redis(redis_url: &str, stall: Duration) -> Result<RedisTap, BoxErr> {
    let (scheme, rest) = redis_url.split_once("://").ok_or("redis url")?;
    let (authority, db) = rest.split_once('/').unwrap_or((rest, ""));
    let upstream = authority.to_owned();
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("{scheme}://{}/{db}", listener.local_addr()?);
    let leases: Arc<Mutex<Vec<std::time::Instant>>> = Arc::default();
    let hold: Arc<Mutex<Option<std::time::Instant>>> = Arc::default();
    let noted = Arc::clone(&leases);
    tokio::spawn(async move {
        let needle = br#""mode":"lease""#;
        while let Ok((client, _)) = listener.accept().await {
            let Ok(server) = TcpStream::connect(&upstream).await else {
                continue;
            };
            let (mut from_client, mut to_client) = client.into_split();
            let (mut from_server, mut to_server) = server.into_split();
            let (noted, hold_up) = (Arc::clone(&noted), Arc::clone(&hold));
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                while let Ok(n) = from_client.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    if buf[..n].windows(needle.len()).any(|w| w == needle) {
                        let now = std::time::Instant::now();
                        noted.lock().push(now);
                        if !stall.is_zero() {
                            *hold_up.lock() = Some(now + stall);
                        }
                    }
                    if to_server.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
            let hold_down = Arc::clone(&hold);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                while let Ok(n) = from_server.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    let until = *hold_down.lock();
                    if let Some(until) = until {
                        tokio::time::sleep_until(tokio::time::Instant::from_std(until)).await;
                    }
                    if to_client.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    Ok(RedisTap { url, leases })
}

fn tapped(tap: &RedisTap) -> Env {
    Env {
        redis_url: tap.url.clone(),
    }
}

/// A lease call that runs out of time may have run in Redis
/// all the same. A per-connection lease nobody will ever release would hold
/// its unit for the whole `lease_ttl`, so the failed call releases it.
#[tokio::test]
async fn a_lease_call_that_times_out_leaves_no_per_connection_lease() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.policy = "sticky_scope = \"connection\"\n".into();
    let tap = tap_redis(&env.redis_url, Duration::from_millis(2500)).await?;
    let (h, _, _) = static_fixture(&tapped(&tap), &setup).await?;

    let raw = redis::Client::open(env.redis_url.as_str())?
        .get_multiplexed_async_connection()
        .await?;
    let pattern = format!("lease:{{{}}}:{}:conn:*", setup.partition().tag(), setup.org);
    let count = |mut raw: redis::aio::MultiplexedConnection, pattern: String| async move {
        redis::cmd("KEYS")
            .arg(pattern)
            .query_async::<Vec<String>>(&mut raw)
            .await
            .map_or(0, |keys| keys.len())
    };
    let seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop = CancellationToken::new();
    let watcher = tokio::spawn({
        let (raw, pattern, seen, stop) = (raw.clone(), pattern.clone(), seen.clone(), stop.clone());
        async move {
            while !stop.is_cancelled() {
                if count(raw.clone(), pattern.clone()).await > 0 {
                    seen.store(true, std::sync::atomic::Ordering::Relaxed);
                }
                sleep(Duration::from_millis(20)).await;
            }
        }
    });

    let r = connect_via(h.connect, "px", &setup.key).await?;
    assert_eq!(r.answer(), (504, "lease_timeout"));
    eventually("the lease of the failed call to be released", || {
        let (raw, pattern) = (raw.clone(), pattern.clone());
        async move { count(raw, pattern).await == 0 }
    })
    .await;
    stop.cancel();
    watcher.await?;
    assert!(
        seen.load(std::sync::atomic::Ordering::Relaxed),
        "the call that timed out did take the lease"
    );
    Ok(())
}

/// A walk whose budget is spent leases nothing more. Three
/// static units each hold the dial for 2.9 s and answer `403` (the unit is
/// left out and the next is tried); the budget is gone when the walk comes
/// back to the rotating partition that needed a create.
#[tokio::test]
async fn a_walk_past_its_budget_takes_no_more_leases() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    let rotating = Setup::new();
    // the rotating partition is tried first and is empty: it asks for a create
    setup.kinds = r#"["rotating", "static"]"#;
    let dead = closed_endpoint();
    setup.adapter_toml = Some(format!(
        "{}\n{}",
        setup.static_adapter("[]"),
        rotating.rotating_adapter(dead.port())
    ));
    let slow = serve(|mut s| async move {
        if read_head(&mut s).await.is_some() {
            sleep(Duration::from_millis(2_900)).await;
            respond(&mut s, "403 Forbidden", "").await;
        }
    })
    .await;
    let ips = [uniq_ip(), uniq_ip(), uniq_ip()];
    let rows = ips
        .iter()
        .map(|ip| row(&entry(&setup, *ip, slow.port()), true))
        .collect();
    let tap = tap_redis(&env.redis_url, Duration::ZERO).await?;
    let h = start(&tapped(&tap), &setup, rows).await?;
    for ip in ips {
        h.ready(&setup.partition(), ip).await?;
    }

    let started = std::time::Instant::now();
    let r = connect_via(h.connect, "px", &setup.key).await?;
    assert_ne!(r.status, 200, "{}", r.reason);
    assert!(
        started.elapsed() >= Duration::from_millis(7_900),
        "the walk spent its budget"
    );
    let after_budget = tap
        .leases
        .lock()
        .iter()
        .filter(|at| at.duration_since(started) > Duration::from_secs(7))
        .count();
    assert_eq!(after_budget, 0, "no lease after the budget");
    Ok(())
}

/// The bytes a client pipelines behind its CONNECT are metered,
/// and a tunnel that ends before the first keeper tick still records its
/// traffic for the load-spreading tie-break.
#[tokio::test]
async fn pipelined_bytes_and_short_tunnels_are_metered() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let setup = Setup::new();
    let (h, _, ip) = static_fixture(&env, &setup).await?;
    let before = metered_bytes(&h, &setup.provider).await?;

    let auth = STANDARD.encode(format!("px:{}", setup.key));
    let mut s = TcpStream::connect(h.connect).await?;
    // the CONNECT and the first bytes of the tunnel in one write
    s.write_all(
        format!(
            "CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\nProxy-Authorization: Basic {auth}\r\n\r\nabc"
        )
        .as_bytes(),
    )
    .await?;
    let head = timeout(Duration::from_secs(5), read_head(&mut s))
        .await?
        .ok_or("no reply head")?;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let mut reply = [0u8; 8];
    timeout(Duration::from_secs(5), s.read_exact(&mut reply)).await??;
    assert_eq!(&reply, b"pong:abc");
    drop(s);

    // 3 bytes out (the pipelined ones) and 8 back, all before one keeper tick
    eventually("the pipelined bytes to be metered", || async {
        metered_bytes(&h, &setup.provider)
            .await
            .is_ok_and(|n| n == before + 3 + 8)
    })
    .await;
    let mut raw = redis::Client::open(env.redis_url.as_str())?
        .get_multiplexed_async_connection()
        .await?;
    let traffic: std::collections::HashMap<String, u64> = redis::cmd("HGETALL")
        .arg(format!("traf:{{{}}}:{ip}", setup.partition().tag()))
        .query_async(&mut raw)
        .await?;
    assert_eq!(
        traffic.values().sum::<u64>(),
        3 + 8,
        "the short tunnel recorded its traffic on the unit"
    );
    Ok(())
}
