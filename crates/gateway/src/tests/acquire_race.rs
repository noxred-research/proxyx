use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

async fn ready_session(
    h: &Harness,
    setup: &Setup,
    sid: &str,
    ip: IpAddr,
) -> Result<String, BoxErr> {
    let id = {
        let loaded = h.loaded.borrow();
        let adapter = loaded
            .adapters
            .get(&setup.partition().provider)
            .ok_or("adapter missing")?;
        adapter.encode_session(sid, adapter.session_life(), false)?
    };
    h.hot
        .ready_put(
            &setup.partition(),
            &UnitRecord {
                id: id.clone(),
                ip,
                expires_at: Some(OffsetDateTime::now_utc() + time::Duration::minutes(30)),
                ttl: Some(Duration::from_secs(3600)),
                owner: None,
            },
        )
        .await?;
    Ok(id)
}

fn session_from_login(login: &str) -> &str {
    login
        .split_once("-sid-")
        .map(|(_, rest)| rest.split('-').next().unwrap_or_default())
        .unwrap_or_default()
}

#[tokio::test]
async fn race_returns_before_slow_dials_and_releases_loser_leases_and_counters() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    let target = stub_target().await;
    let fast_sid = "Fast00000001";
    let slow_sid = "Slow00000001";
    let fast_ip = uniq_ip();
    let slow_ip = uniq_ip();
    let starts = Arc::new(tokio::sync::Barrier::new(2));
    let canceled = Arc::new(AtomicUsize::new(0));
    let addr = serve({
        let starts = Arc::clone(&starts);
        let canceled = Arc::clone(&canceled);
        move |mut stream| {
            let starts = Arc::clone(&starts);
            let canceled = Arc::clone(&canceled);
            async move {
                let Some(head) = read_head(&mut stream).await else {
                    return;
                };
                let (request, login) = request_and_login(&head);
                let fast = session_from_login(&login) == fast_sid;
                if !request.starts_with("CONNECT ") {
                    let ip = if fast { fast_ip } else { slow_ip };
                    respond(
                        &mut stream,
                        "200 OK",
                        &format!(r#"{{"ip":"{ip}","country":"fr"}}"#),
                    )
                    .await;
                    return;
                }
                starts.wait().await;
                if fast {
                    if let Ok(upstream) = TcpStream::connect(target).await {
                        splice(stream, upstream).await;
                    }
                } else {
                    let mut byte = [0];
                    if matches!(stream.read(&mut byte).await, Ok(0) | Err(_)) {
                        canceled.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
    })
    .await;
    setup.rotating_via(addr.port());
    setup.policy = "[policy.dial]\nrace = 2\n".into();
    setup.pacing = fast(Duration::from_secs(600));
    let h = start(&env, &setup, vec![]).await?;
    let fast_id = ready_session(&h, &setup, fast_sid, fast_ip).await?;
    let slow_id = ready_session(&h, &setup, slow_sid, slow_ip).await?;
    let mut reply = timeout(
        Duration::from_secs(2),
        connect_via(h.connect, "px-rot-each", &setup.key),
    )
    .await??;
    assert_eq!(reply.status, 200, "{}", reply.reason);
    assert_eq!(
        reply.header("X-ProxyX-Exit-IP"),
        Some(fast_ip.to_string().as_str())
    );
    assert_eq!(ping(&mut reply.stream, "first").await?, "pong:first");
    eventually("slow race dial cancellation", || async {
        canceled.load(Ordering::Relaxed) == 1
    })
    .await;
    eventually("loser lease and counter release", || async {
        h.hot
            .unit_load(&setup.partition(), &slow_id)
            .await
            .is_ok_and(|l| l.leases == 0 && l.tunnels == 0)
    })
    .await;
    assert_eq!(
        h.hot.org_tunnel_count(&setup.org).await?,
        1,
        "race counts one client tunnel"
    );
    sleep(Duration::from_millis(250)).await;
    assert_eq!(
        h.hot.unit_load(&setup.partition(), &fast_id).await?.tunnels,
        1,
        "loser cleanup cannot fence the winner's keeper"
    );
    assert_eq!(ping(&mut reply.stream, "kept").await?, "pong:kept");
    drop(reply);
    eventually("winner lease release", || async {
        h.hot
            .unit_load(&setup.partition(), &fast_id)
            .await
            .is_ok_and(|l| l.leases == 0 && l.tunnels == 0)
            && tunnels_closed(&h, &setup.org).await
    })
    .await;
    Ok(())
}

#[tokio::test]
async fn three_failed_race_dials_charge_the_breaker_exactly_once() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    let attempts = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let addr = serve({
        let attempts = Arc::clone(&attempts);
        move |mut stream| {
            let attempts = Arc::clone(&attempts);
            let barrier = Arc::clone(&barrier);
            async move {
                let Some(head) = read_head(&mut stream).await else {
                    return;
                };
                if head.starts_with("CONNECT ") {
                    attempts.fetch_add(1, Ordering::Relaxed);
                    barrier.wait().await;
                }
                respond(&mut stream, "407 Proxy Authentication Required", "").await;
            }
        }
    })
    .await;
    setup.rotating_via(addr.port());
    setup.check = false;
    setup.policy = "[policy.dial]\nrace = 3\n[policy.on_empty]\nrotating = \"fail\"\n".into();
    let cfg = breaker(2);
    setup.pacing.breaker = cfg;
    let h = start(&env, &setup, vec![]).await?;
    let mut ids = Vec::new();
    for sid in ["Fail00000001", "Fail00000002", "Fail00000003"] {
        ids.push(ready_session(&h, &setup, sid, uniq_ip()).await?);
    }
    let reply = timeout(
        Duration::from_secs(3),
        connect_via(h.connect, "px-rot-each", &setup.key),
    )
    .await??;
    assert_ne!(reply.status, 200);
    assert_eq!(attempts.load(Ordering::Relaxed), 3);
    assert_eq!(
        h.hot.breaker_peek(&setup.partition(), &cfg).await?.0,
        BreakerState::Closed,
        "three race failures are not three failed tunnels"
    );
    assert_eq!(
        h.hot.breaker_failure(&setup.partition(), &cfg).await?,
        BreakerState::Open,
        "one further failure reaches the threshold of two"
    );
    for id in ids {
        let load = h.hot.unit_load(&setup.partition(), &id).await?;
        assert_eq!((load.leases, load.tunnels), (0, 0));
    }
    assert_eq!(h.hot.org_tunnel_count(&setup.org).await?, 0);
    Ok(())
}

#[tokio::test]
async fn create_race_cancels_slow_provider_checks_without_leaking_reservations() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    let target = stub_target().await;
    let sessions = Arc::new(Mutex::new(HashMap::<String, IpAddr>::new()));
    let started = Arc::new(AtomicUsize::new(0));
    let canceled = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let addr = serve({
        let sessions = Arc::clone(&sessions);
        let started = Arc::clone(&started);
        let canceled = Arc::clone(&canceled);
        move |mut stream| {
            let sessions = Arc::clone(&sessions);
            let started = Arc::clone(&started);
            let canceled = Arc::clone(&canceled);
            let barrier = Arc::clone(&barrier);
            async move {
                let Some(head) = read_head(&mut stream).await else {
                    return;
                };
                let (request, login) = request_and_login(&head);
                if request.starts_with("CONNECT ") {
                    if let Ok(upstream) = TcpStream::connect(target).await {
                        splice(stream, upstream).await;
                    }
                    return;
                }
                let sid = session_from_login(&login).to_owned();
                let (ip, first) = {
                    let mut sessions = sessions.lock();
                    let fresh = !sessions.contains_key(&sid);
                    (*sessions.entry(sid).or_insert_with(uniq_ip), fresh)
                };
                if first {
                    let index = started.fetch_add(1, Ordering::Relaxed);
                    barrier.wait().await;
                    if index == 0 {
                        let mut byte = [0];
                        if matches!(stream.read(&mut byte).await, Ok(0) | Err(_)) {
                            canceled.fetch_add(1, Ordering::Relaxed);
                        }
                        return;
                    }
                }
                respond(
                    &mut stream,
                    "200 OK",
                    &format!(r#"{{"ip":"{ip}","country":"fr"}}"#),
                )
                .await;
            }
        }
    })
    .await;
    setup.rotating_via(addr.port());
    setup.policy = "[policy.dial]\nrace = 2\n".into();
    let h = start(&env, &setup, vec![]).await?;
    let mut reply = timeout(
        Duration::from_secs(2),
        connect_via(h.connect, "px-rot-each", &setup.key),
    )
    .await??;
    assert_eq!(reply.status, 200, "{}", reply.reason);
    assert_eq!(
        started.load(Ordering::Relaxed),
        2,
        "two independent sessions were created concurrently"
    );
    assert_eq!(ping(&mut reply.stream, "created").await?, "pong:created");
    eventually("slow create socket cancellation", || async {
        canceled.load(Ordering::Relaxed) == 1
    })
    .await;
    eventually("canceled create accounting", || async {
        h.hot
            .counts(&setup.partition())
            .await
            .is_ok_and(|c| c.creating == 0 && c.reserved == 0)
    })
    .await;
    assert_eq!(h.hot.ready_ids(&setup.partition()).await?.len(), 1);
    assert_eq!(
        session_jobs(&env, &setup.partition()).await?.len(),
        1,
        "only the committed session has a warmer job"
    );
    Ok(())
}

#[tokio::test]
async fn client_ttl_and_strict_survive_create_reuse_and_session_jobs() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    let (provider, _) = on_demand(&mut setup).await;
    setup.adapter_toml = Some(format!(
        "{}\n[[adapter.option]]\nname = \"strict\"\nto = \"user\"\nfrag = \"-locked\"\n",
        setup.rotating_adapter(provider.addr.port())
    ));
    setup.policy = "[policy.dial]\nrace = 3\n".into();
    let h = start(&env, &setup, vec![]).await?;
    let default_id = ready_session(&h, &setup, "Warm00000001", uniq_ip()).await?;
    for _ in 0..2 {
        let mut reply =
            connect_via(h.connect, "px-sid-options-ttl-7m-strict-true", &setup.key).await?;
        assert_eq!(reply.status, 200, "{}", reply.reason);
        assert_eq!(ping(&mut reply.stream, "options").await?, "pong:options");
    }
    let mut ids = h.hot.ready_ids(&setup.partition()).await?;
    assert_eq!(
        ids.len(),
        2,
        "client options do not reuse the incompatible warmed recipe"
    );
    ids.retain(|id| *id != default_id);
    assert_eq!(
        ids.len(),
        1,
        "sticky requests create only one compatible session"
    );
    {
        let loaded = h.loaded.borrow();
        let adapter = loaded
            .adapters
            .get(&setup.partition().provider)
            .ok_or("adapter missing")?;
        let recipe = adapter.decode_session(&ids[0])?;
        assert_eq!(recipe.ttl, Duration::from_secs(420));
        assert!(recipe.strict);
    }
    let connects = provider.connects();
    assert_eq!(connects.len(), 2);
    assert_eq!(
        connects[0].1, connects[1].1,
        "recipe identity survives reuse"
    );
    assert!(connects[0].1.contains("-t-7-locked:"), "{}", connects[0].1);
    let jobs = session_jobs(&env, &setup.partition()).await?;
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].session, ids[0]);
    assert!(
        jobs[0].expires - jobs[0].born <= 420,
        "job cannot outlive provider TTL"
    );
    Ok(())
}
