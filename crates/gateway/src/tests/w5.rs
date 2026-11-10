//! Regression tests of route-class caps, regions and lease limits. Same
//! stubs and skip rule as the parent module.

use super::*;

/// One dead static IP leaves leasing at its first failed tunnel
/// and never opens the route class; the tunnel itself is served by another IP.
#[tokio::test]
async fn one_dead_static_ip_leaves_leasing_without_opening_the_route_class() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    let cfg = breaker(2);
    setup.pacing.breaker = cfg;
    let live = stub_provider(PROVIDER_PASS, stub_target().await, uniq_ip()).await;
    let dead_addr = closed_addr().await;
    // "198.18" sorts before "198.19": the dead IP is leased first
    let dead_ip = IpAddr::from([198, 18, 7, 7]);
    let live_ip = IpAddr::from([198, 19, 7, 7]);
    let h = start(
        &env,
        &setup,
        vec![
            row(&entry(&setup, dead_ip, dead_addr.port()), true),
            row(&entry(&setup, live_ip, live.addr.port()), true),
        ],
    )
    .await?;
    let p = setup.partition();
    for ip in [dead_ip, live_ip] {
        h.ready(&p, ip).await?;
    }
    for i in 0..6 {
        let host = format!("t{i}.example.test:443");
        let r = connect_to(h.connect, &host, "px", &setup.key).await?;
        assert_eq!(r.status, 200, "tunnel {i}: {}", r.reason);
        assert_eq!(
            r.header("X-ProxyX-Exit-IP"),
            Some(live_ip.to_string().as_str())
        );
    }
    assert_eq!(h.hot.breaker_peek(&p, &cfg).await?.0, BreakerState::Closed);
    assert!(!h.hot.is_ready(&p, &dead_ip.to_string()).await?);
    Ok(())
}

/// `n` static IPs whose provider port nothing listens on, in the ready set.
async fn dead_class(
    env: &Env,
    setup: &Setup,
    n: u8,
) -> Result<(Harness, Vec<(IpAddr, SocketAddr)>), BoxErr> {
    let mut dead = Vec::new();
    for i in 0..n {
        dead.push((IpAddr::from([198, 18, 8, i + 1]), closed_addr().await));
    }
    let rows = dead
        .iter()
        .map(|(ip, addr)| row(&entry(setup, *ip, addr.port()), true))
        .collect();
    let h = start(env, setup, rows).await?;
    for (ip, _) in &dead {
        h.ready(&setup.partition(), *ip).await?;
    }
    Ok((h, dead))
}

/// When the whole route class fails (the provider blipped), the IPs
/// are not withdrawn one by one for the 60 s rest: after the blip the class
/// serves at once. Only the first failed IP of a burst is taken for a bad one.
#[tokio::test]
async fn a_provider_wide_dial_failure_withdraws_no_more_than_one_ip_and_recovers_at_once()
-> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.pacing.breaker = breaker(1000);
    let (h, dead) = dead_class(&env, &setup, 6).await?;
    let p = setup.partition();

    for i in 0..6 {
        let r = connect_via(h.connect, &format!("px-sid-blip{i}"), &setup.key).await?;
        assert_eq!(r.status, 502, "tunnel {i}: {}", r.reason);
    }
    let ready = h.hot.ready_ids(&p).await?;
    assert!(
        ready.len() >= 5,
        "a provider-wide failure withdrew {} of 6 IPs: {ready:?}",
        6 - ready.len()
    );

    // the provider is back on every port: the next tunnel is served
    let target = stub_target().await;
    let revived: Vec<StubProvider> = {
        let mut v = Vec::new();
        for (ip, addr) in &dead {
            v.push(stub_provider_on(
                TcpListener::bind(addr).await?,
                PROVIDER_PASS,
                target,
                *ip,
            ));
        }
        v
    };
    let r = connect_via(h.connect, "px-sid-after", &setup.key).await?;
    assert_eq!(r.status, 200, "{}", r.reason);
    assert_eq!(revived.iter().map(|s| s.connects().len()).sum::<usize>(), 1);
    Ok(())
}

/// After a second IP of the class failed within the window (the provider
/// is at fault, nothing more is withdrawn) the tunnel still tries one other
/// IP: a healthy one serves it. It tries one only: with a third IP failing
/// too, the tunnel answers with the cause and never reaches the healthy IP.
#[tokio::test]
async fn a_provider_wide_dial_failure_still_tries_one_other_ip() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let target = stub_target().await;
    let bad = stub_provider("some-other-password", target, uniq_ip()).await;
    let good = stub_provider(PROVIDER_PASS, target, uniq_ip()).await;
    let good_ip = IpAddr::from([198, 19, 10, 1]);
    for (n_bad, status) in [(2u8, 200), (3, 502)] {
        let mut setup = Setup::new();
        setup.pacing.breaker = breaker(1000);
        // "198.18" sorts before "198.19": the failing IPs are leased first
        let bad_ips: Vec<IpAddr> = (1..=n_bad)
            .map(|i| IpAddr::from([198, 18, 10, i]))
            .collect();
        let mut rows: Vec<_> = bad_ips
            .iter()
            .map(|ip| row(&entry(&setup, *ip, bad.addr.port()), true))
            .collect();
        rows.push(row(&entry(&setup, good_ip, good.addr.port()), true));
        let h = start(&env, &setup, rows).await?;
        let p = setup.partition();
        for ip in bad_ips.iter().chain([&good_ip]) {
            h.ready(&p, *ip).await?;
        }
        let r = connect_via(h.connect, "px-sid-n31", &setup.key).await?;
        assert_eq!(r.status, status, "{n_bad} failing IPs: {}", r.reason);
        if status == 200 {
            assert_eq!(
                r.header("X-ProxyX-Exit-IP"),
                Some(good_ip.to_string().as_str())
            );
        } else {
            assert_eq!(r.answer(), (502, "provider_auth"));
        }
        assert_eq!(
            h.hot.ready_ids(&p).await?.len(),
            usize::from(n_bad),
            "only the first failed IP is withdrawn"
        );
    }
    assert_eq!(good.connects().len(), 1, "only the 200 case reached it");
    Ok(())
}

/// A client tunnel that fails on several IPs charges the route class
/// breaker once, so it takes `failures_to_open` failed tunnels to open it.
#[tokio::test]
async fn a_failed_tunnel_charges_the_breaker_once_however_many_ips_it_tried() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    let cfg = breaker(3);
    setup.pacing.breaker = cfg;
    let (h, _dead) = dead_class(&env, &setup, 8).await?;
    let p = setup.partition();

    for i in 0..2 {
        let r = connect_via(h.connect, &format!("px-sid-f{i}"), &setup.key).await?;
        assert_eq!(r.status, 502, "tunnel {i}: {}", r.reason);
        assert_eq!(
            h.hot.breaker_peek(&p, &cfg).await?.0,
            BreakerState::Closed,
            "{} failed tunnel(s) are fewer than {}",
            i + 1,
            cfg.failures_to_open
        );
    }
    let r = connect_via(h.connect, "px-sid-f2", &setup.key).await?;
    assert_eq!(r.status, 502, "{}", r.reason);
    assert_eq!(h.hot.breaker_peek(&p, &cfg).await?.0, BreakerState::Open);
    Ok(())
}

/// Cool `ip` of `p` for `host:443` for a minute, as block signals do.
async fn cool_for(h: &Harness, p: &Partition, ip: IpAddr, host: &str) -> TestResult {
    let target = common::types::Target {
        host: host.into(),
        port: 443,
    };
    h.hot
        .cool_target(p, ip, &target, Duration::from_secs(60))
        .await?;
    Ok(())
}

/// N2-2: the answer for target A (every IP cooled for it) is remembered per
/// target, so the same sticky key is still served for target B.
#[tokio::test]
async fn a_failed_lease_for_one_target_does_not_refuse_another_target() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let setup = Setup::new();
    let provider = stub_provider(PROVIDER_PASS, stub_target().await, uniq_ip()).await;
    let (h, ip) = static_unit(&env, &setup, provider.addr, true).await?;
    cool_for(&h, &setup.partition(), ip, "a.example.test").await?;

    let a = connect_to(h.connect, "a.example.test:443", "px", &setup.key).await?;
    assert_eq!(a.answer(), (503, "no_healthy_ip"));
    let b = connect_to(h.connect, "b.example.test:443", "px", &setup.key).await?;
    assert_eq!(b.status, 200, "{}", b.reason);
    // and A is still answered from the memo
    let again = connect_to(h.connect, "a.example.test:443", "px", &setup.key).await?;
    assert_eq!(again.answer(), (503, "no_healthy_ip"));
    Ok(())
}

/// A session proxy session is `px-sid-<hash>`, one sticky key each, so an org
/// with many sessions used to take every IP. Two orgs on four IPs now hold
/// two each, and never share one.
#[tokio::test]
async fn orgs_with_many_sid_sessions_each_hold_their_share_of_the_ips() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let setup = Setup::new();
    let provider = stub_provider(PROVIDER_PASS, stub_target().await, uniq_ip()).await;
    let ips: Vec<IpAddr> = (1..=4).map(|i| IpAddr::from([198, 18, 9, i])).collect();
    let rows = ips
        .iter()
        .map(|ip| row(&entry(&setup, *ip, provider.addr.port()), true))
        .collect();
    let h = start(&env, &setup, rows).await?;
    for ip in &ips {
        h.ready(&setup.partition(), *ip).await?;
    }
    let mut exits: [std::collections::BTreeSet<String>; 2] = Default::default();
    for session in 0..8 {
        for (i, key) in [&setup.key, &setup.rival_key].into_iter().enumerate() {
            let r = connect_via(h.connect, &format!("px-sid-s{session}"), key).await?;
            assert_eq!(r.status, 200, "{}", r.reason);
            exits[i].insert(r.header("X-ProxyX-Exit-IP").unwrap_or_default().to_owned());
        }
    }
    assert_eq!(
        [exits[0].len(), exits[1].len()],
        [2, 2],
        "each org holds half of the pool: {exits:?}"
    );
    assert!(exits[0].is_disjoint(&exits[1]), "no shared IP: {exits:?}");
    Ok(())
}

/// N2-3: one refused tunnel counts once in `org_budget_refusals_total`,
/// however many candidate partitions it was refused on.
#[tokio::test]
async fn a_tunnel_refused_by_the_org_budget_on_two_partitions_counts_one_refusal() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.policy = "[policy.limits]\norg_max_gb_per_day = 0.000001\n".to_owned();
    let second = format!("{}b", setup.provider);
    setup.adapter_toml = Some(format!(
        "{}{}",
        static_adapter_toml(&setup.provider, "[]"),
        static_adapter_toml(&second, "[]")
    ));
    let provider = stub_provider(PROVIDER_PASS, stub_target().await, uniq_ip()).await;
    let (ip, ip2) = (uniq_ip(), uniq_ip());
    let mut e2 = entry(&setup, ip2, provider.addr.port());
    e2.provider = second.parse()?;
    let h = start(
        &env,
        &setup,
        vec![
            row(&entry(&setup, ip, provider.addr.port()), true),
            row(&e2, true),
        ],
    )
    .await?;
    h.ready(&setup.partition(), ip).await?;
    let p2 = Partition {
        provider: second.parse()?,
        region: "fr".parse()?,
    };
    h.ready(&p2, ip2).await?;
    h.hot
        .org_cost_add(&setup.org, 5_000, OffsetDateTime::now_utc())
        .await?;

    let r = connect_via(h.connect, "px", &setup.key).await?;
    assert_eq!(r.answer(), (503, "org_budget"));
    assert_eq!(h.connections("connect", "org_budget"), 1);
    assert_eq!(h.metrics.org_budget_refusals_total.get(), 1);
    Ok(())
}

/// A pool cooled for the target by block signals, and a static route
/// class whose IPs a failed canary put in cooldown, answer at once with the
/// cause instead of after `lease_wait`.
#[tokio::test]
async fn cooled_and_drained_static_pools_answer_at_once() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let setup = Setup::new(); // static on_empty = wait, lease_wait 1s
    let provider = stub_provider(PROVIDER_PASS, stub_target().await, uniq_ip()).await;
    let (h, ip) = static_unit(&env, &setup, provider.addr, true).await?;
    let p = setup.partition();

    cool_for(&h, &p, ip, "blocked.example.test").await?;
    let started = std::time::Instant::now();
    let r = connect_to(h.connect, "blocked.example.test:443", "px", &setup.key).await?;
    assert_eq!(r.answer(), (503, "no_healthy_ip"));
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "{:?}",
        started.elapsed()
    );

    // a route class the canary drained: every IP in cooldown, none ready
    let drained = Setup::new();
    let ip2 = uniq_ip();
    let mut cooled = row(&entry(&drained, ip2, provider.addr.port()), true);
    cooled.state = IpState::Cooldown;
    let h2 = start(&env, &drained, vec![cooled]).await?;
    let started = std::time::Instant::now();
    let r = connect_via(h2.connect, "px", &drained.key).await?;
    assert_eq!(r.answer(), (503, "no_healthy_ip"));
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "{:?}",
        started.elapsed()
    );
    Ok(())
}

/// The cap of a route class applies to `px` without `prov-`, the way
/// the session proxy's user connects.
#[tokio::test]
async fn a_route_class_cap_applies_without_naming_the_provider() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.extra_policies = format!(
        "\n[[policy]]\nname = \"rc\"\nscope = \"route_class\"\nmatch = \"{}\"\nmax_tunnels_per_org = 1\n",
        setup.provider
    );
    let (h, _, _) = static_fixture(&env, &setup).await?;

    let first = connect_via(h.connect, "px", &setup.key).await?;
    assert_eq!(first.status, 200, "{}", first.reason);
    let second = connect_via(h.connect, "px-sid-two", &setup.key).await?;
    assert_eq!(second.answer(), (503, "org_capacity"));
    assert_eq!(
        h.hot.org_tunnel_count(&setup.org).await?,
        1,
        "a refusal does not hold a slot"
    );
    Ok(())
}

/// The regions of a route class apply to `px` without `prov-`. The
/// global policy lists `fr`; the route class moves the provider to `de`, where
/// the only IP is, and refuses the region it replaced.
#[tokio::test]
async fn route_class_regions_apply_without_naming_the_provider() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.extra_policies = format!(
        "\n[[policy]]\nname = \"rc\"\nscope = \"route_class\"\nmatch = \"{}\"\nregions = [\"de\"]\n",
        setup.provider
    );
    let provider = stub_provider(PROVIDER_PASS, stub_target().await, uniq_ip()).await;
    let ip = uniq_ip();
    let mut e = entry(&setup, ip, provider.addr.port());
    e.region = "de".parse()?;
    let h = start(&env, &setup, vec![row(&e, true)]).await?;
    let p = Partition {
        provider: setup.provider.parse()?,
        region: "de".parse()?,
    };
    h.ready(&p, ip).await?;

    let served = connect_via(h.connect, "px", &setup.key).await?;
    assert_eq!(served.status, 200, "{}", served.reason);
    assert_eq!(provider.connects().len(), 1);

    let refused = connect_via(h.connect, "px-cc-fr", &setup.key).await?;
    assert_eq!(refused.answer(), (403, "option_denied"));
    let narrowed = connect_via(h.connect, "px-cc-de", &setup.key).await?;
    assert_eq!(narrowed.status, 200, "{}", narrowed.reason);
    Ok(())
}

/// The `lease_ttl` of a route class bounds the `ttl` option of `px`
/// without `prov-`. The global policy allows 10 minutes; the route class 1.
#[tokio::test]
async fn route_class_lease_ttl_bounds_the_ttl_option_without_the_provider() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.extra_policies = format!(
        "\n[[policy]]\nname = \"rc\"\nscope = \"route_class\"\nmatch = \"{}\"\nlease_ttl = \"1m\"\n",
        setup.provider
    );
    let (h, provider, _) = static_fixture(&env, &setup).await?;

    let too_long = connect_via(h.connect, "px-ttl-5m", &setup.key).await?;
    assert_eq!(too_long.answer(), (403, "option_denied"));
    assert!(provider.connects().is_empty());

    let within = connect_via(h.connect, "px-sid-short-ttl-1m", &setup.key).await?;
    assert_eq!(within.status, 200, "{}", within.reason);
    Ok(())
}

/// A half-open probe whose dial got no answer (a provider that
/// accepts and stays silent) is not a pass: the route class does not close on
/// a provider that cannot serve.
#[tokio::test]
async fn a_half_open_probe_that_gets_no_answer_does_not_close_the_route_class() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    let cfg = BreakerConfig {
        failures_to_open: 1,
        window: Duration::from_secs(60),
        first_probe_after: Duration::from_millis(300),
        max_probe_after: Duration::from_millis(300),
        passes_to_close: 1,
    };
    setup.pacing.breaker = cfg;
    let silent = serve(|mut s| async move {
        read_head(&mut s).await;
        sleep(Duration::from_secs(30)).await;
    })
    .await;
    let (h, _) = static_unit(&env, &setup, silent, true).await?;
    let p = setup.partition();
    h.hot.breaker_failure(&p, &cfg).await?;
    assert_eq!(h.hot.breaker_peek(&p, &cfg).await?.0, BreakerState::Open);
    sleep(Duration::from_millis(400)).await;

    let r = connect_via(h.connect, "px", &setup.key).await?;
    assert_eq!(r.answer(), (504, "provider_timeout"));
    assert_eq!(
        h.hot.breaker_peek(&p, &cfg).await?.0,
        BreakerState::HalfOpen,
        "the probe got no answer: it is neither a pass nor a failure"
    );
    Ok(())
}
