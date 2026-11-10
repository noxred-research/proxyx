//! D1-D3, D6, D7 and NEW-1: the walk over several providers applies
//! the tiers and the soft limits across them, keeps a lease young, counts a
//! route-class cap on its own provider, charges the breaker only for a tunnel
//! that no IP of the failing provider served, and labels what it counts with
//! the provider. Same stubs and skip rule as the parent module.

use super::*;

/// Two static providers in priority order (`setup.provider`, then the same
/// id with `b`), one IP each, both ready.
struct Pair {
    h: Harness,
    ip_a: IpAddr,
    ip_b: IpAddr,
    pa: Partition,
    pb: Partition,
    a: String,
    b: String,
}

async fn pair(env: &Env, setup: &mut Setup) -> Result<Pair, BoxErr> {
    let b = format!("{}b", setup.provider);
    let a = setup.provider.clone();
    setup.adapter_toml = Some(format!(
        "{}{}",
        static_adapter_toml(&a, "[]"),
        static_adapter_toml(&b, "[]")
    ));
    let target = stub_target().await;
    let stub_a = stub_provider(PROVIDER_PASS, target, uniq_ip()).await;
    let stub_b = stub_provider(PROVIDER_PASS, target, uniq_ip()).await;
    let (ip_a, ip_b) = (uniq_ip(), uniq_ip());
    let mut entry_b = entry(setup, ip_b, stub_b.addr.port());
    entry_b.provider = b.parse()?;
    let h = start(
        env,
        setup,
        vec![
            row(&entry(setup, ip_a, stub_a.addr.port()), true),
            row(&entry_b, true),
        ],
    )
    .await?;
    let pa = setup.partition();
    let pb = Partition {
        provider: b.parse()?,
        region: "fr".parse()?,
    };
    h.ready(&pa, ip_a).await?;
    h.ready(&pb, ip_b).await?;
    Ok(Pair {
        h,
        ip_a,
        ip_b,
        pa,
        pb,
        a,
        b,
    })
}

fn exit_of(r: &Reply) -> Option<String> {
    r.header("X-ProxyX-Exit-IP").map(str::to_owned)
}

/// A degraded unit of the first provider gives way to a normal one of the
/// next; with both degraded the first provider serves again.
#[tokio::test]
async fn a_degraded_provider_gives_way_to_a_normal_one() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    let t = pair(&env, &mut setup).await?;
    t.h.hot
        .set_tier(&t.pa, &t.ip_a.to_string(), Tier::Degraded)
        .await?;

    let r = connect_via(t.h.connect, "px-sid-d1", &setup.key).await?;
    assert_eq!(exit_of(&r), Some(t.ip_b.to_string()), "{}", r.reason);
    // the provider label names who served it
    assert_eq!(
        t.h.metrics
            .cache_leases_total
            .with_label_values(&["static", "hit", &t.b])
            .get(),
        1
    );
    assert_eq!(
        t.h.metrics
            .cache_leases_total
            .with_label_values(&["static", "hit", &t.a])
            .get(),
        0
    );
    let served = |provider: &str| {
        t.h.metrics
            .connections_total
            .with_label_values(&["connect", "ok", provider])
            .get()
    };
    assert_eq!(
        (served(&t.b), served(&t.a)),
        (1, 0),
        "connections_total carries the provider"
    );

    t.h.hot
        .set_tier(&t.pb, &t.ip_b.to_string(), Tier::Degraded)
        .await?;
    let r = connect_via(t.h.connect, "px-sid-d1b", &setup.key).await?;
    assert_eq!(exit_of(&r), Some(t.ip_a.to_string()), "{}", r.reason);
    Ok(())
}

/// A provider whose only IP is at `max_conns_per_ip` gives way to a
/// provider within its limits, and no limit is counted as broken; with both
/// full, the first provider breaks it.
#[tokio::test]
async fn a_provider_at_its_limit_gives_way_before_any_limit_breaks() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.policy = "max_conns_per_ip = 1\n".into();
    let t = pair(&env, &mut setup).await?;
    let broken = |provider: &str| {
        t.h.metrics
            .lease_limit_broken_total
            .with_label_values(&["max_conns", provider])
            .get()
    };

    let first = connect_via(t.h.connect, "px-sid-d2a", &setup.key).await?;
    assert_eq!(
        exit_of(&first),
        Some(t.ip_a.to_string()),
        "{}",
        first.reason
    );
    let second = connect_via(t.h.connect, "px-sid-d2b", &setup.key).await?;
    assert_eq!(
        exit_of(&second),
        Some(t.ip_b.to_string()),
        "{}",
        second.reason
    );
    assert_eq!((broken(&t.a), broken(&t.b)), (0, 0));

    let third = connect_via(t.h.connect, "px-sid-d2c", &setup.key).await?;
    assert_eq!(
        exit_of(&third),
        Some(t.ip_a.to_string()),
        "{}",
        third.reason
    );
    assert_eq!((broken(&t.a), broken(&t.b)), (1, 0));
    drop((first, second, third));
    Ok(())
}

/// A sticky key that moved to the second provider stays there until its
/// lease is older than the dwell, and only then goes back to the first.
#[tokio::test]
async fn a_lease_on_a_lower_priority_provider_stays_until_the_dwell_has_passed() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    let t = pair(&env, &mut setup).await?;
    // the first provider is out of service when the key first connects
    t.h.hot.ready_take(&t.pa, &t.ip_a.to_string()).await?;
    let sid = "px-sid-d3";

    let r = connect_via(t.h.connect, sid, &setup.key).await?;
    assert_eq!(exit_of(&r), Some(t.ip_b.to_string()), "{}", r.reason);
    drop(r);

    // it is back, but the key stays where it works
    t.h.ready(&t.pa, t.ip_a).await?;
    let r = connect_via(t.h.connect, sid, &setup.key).await?;
    assert_eq!(exit_of(&r), Some(t.ip_b.to_string()), "{}", r.reason);
    drop(r);

    // an older lease moves back; so does another key at once
    let mut raw = redis::Client::open(env.redis_url.as_str())?
        .get_multiplexed_async_connection()
        .await?;
    let since = format!("since:{{{}}}:{}:sid:d3", t.pb.tag(), setup.org);
    let gone: i64 = redis::AsyncCommands::del(&mut raw, &since).await?;
    assert_eq!(gone, 1, "{since} marks a young lease");
    let r = connect_via(t.h.connect, sid, &setup.key).await?;
    assert_eq!(exit_of(&r), Some(t.ip_a.to_string()), "{}", r.reason);
    let other = connect_via(t.h.connect, "px-sid-d3new", &setup.key).await?;
    assert_eq!(
        exit_of(&other),
        Some(t.ip_a.to_string()),
        "{}",
        other.reason
    );
    Ok(())
}

/// The cap of a route class is compared with the org's tunnels on that
/// provider, not with its total. Two tunnels on the first provider do not
/// count against the second one's cap of 2.
#[tokio::test]
async fn a_route_class_cap_counts_the_tunnels_on_its_own_provider() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.extra_policies = format!(
        "\n[[policy]]\nname = \"rc-a\"\nscope = \"route_class\"\nmatch = \"{a}\"\nmax_tunnels_per_org = 3\n\
         \n[[policy]]\nname = \"rc-b\"\nscope = \"route_class\"\nmatch = \"{a}b\"\nmax_tunnels_per_org = 2\n",
        a = setup.provider
    );
    let t = pair(&env, &mut setup).await?;
    let one = connect_via(t.h.connect, "px-sid-d6a", &setup.key).await?;
    let two = connect_via(t.h.connect, "px-sid-d6b", &setup.key).await?;
    assert_eq!(exit_of(&one), Some(t.ip_a.to_string()), "{}", one.reason);
    assert_eq!(exit_of(&two), Some(t.ip_a.to_string()), "{}", two.reason);

    // the first provider is out: the second serves, with 3 tunnels in all
    t.h.hot.ready_take(&t.pa, &t.ip_a.to_string()).await?;
    let three = connect_via(t.h.connect, "px-sid-d6c", &setup.key).await?;
    assert_eq!(three.status, 200, "{}", three.reason);
    assert_eq!(exit_of(&three), Some(t.ip_b.to_string()));
    // the second provider's own cap is 2: its second tunnel is served, the
    // third refused, and the refusal holds no place
    let four = connect_via(t.h.connect, "px-sid-d6d", &setup.key).await?;
    assert_eq!(exit_of(&four), Some(t.ip_b.to_string()), "{}", four.reason);
    let five = connect_via(t.h.connect, "px-sid-d6e", &setup.key).await?;
    assert_eq!(five.answer(), (503, "org_capacity"));
    drop((one, two, three, four));
    Ok(())
}

/// NEW-1: a tunnel that an IP of the same provider finally served does not
/// charge the breaker of the route class for the IP that failed it; a tunnel
/// that ends refused does.
#[tokio::test]
async fn a_served_tunnel_does_not_charge_the_breaker_and_a_refused_one_does() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let target = stub_target().await;
    let good = stub_provider(PROVIDER_PASS, target, uniq_ip()).await;
    // refuses the login: the provider rejected it
    let rejecting = stub_provider("another-password", target, uniq_ip()).await;
    // "198.18" sorts before "198.19": the failing IP is leased first
    let (bad_ip, bad_ip2, good_ip) = (
        IpAddr::from([198, 18, 21, 1]),
        IpAddr::from([198, 18, 21, 2]),
        IpAddr::from([198, 19, 21, 1]),
    );

    let mut s = Setup::new();
    s.pacing.breaker = breaker(1);
    let h = start(
        &env,
        &s,
        vec![
            row(&entry(&s, bad_ip, rejecting.addr.port()), true),
            row(&entry(&s, good_ip, good.addr.port()), true),
        ],
    )
    .await?;
    let p = s.partition();
    for ip in [bad_ip, good_ip] {
        h.ready(&p, ip).await?;
    }
    let r = connect_via(h.connect, "px-sid-n1", &s.key).await?;
    assert_eq!(exit_of(&r), Some(good_ip.to_string()), "{}", r.reason);
    assert_eq!(
        h.hot.breaker_peek(&p, &breaker(1)).await?.0,
        BreakerState::Closed,
        "served: the provider answered"
    );

    // every IP rejects the login: the tunnel is refused and charges it
    let mut s = Setup::new();
    s.pacing.breaker = breaker(1);
    let h = start(
        &env,
        &s,
        vec![
            row(&entry(&s, bad_ip, rejecting.addr.port()), true),
            row(&entry(&s, bad_ip2, rejecting.addr.port()), true),
        ],
    )
    .await?;
    let p = s.partition();
    for ip in [bad_ip, bad_ip2] {
        h.ready(&p, ip).await?;
    }
    let r = connect_via(h.connect, "px-sid-n1b", &s.key).await?;
    assert_eq!(r.answer(), (502, "provider_auth"));
    assert_eq!(
        h.hot.breaker_peek(&p, &breaker(1)).await?.0,
        BreakerState::Open,
        "refused: charged once"
    );
    Ok(())
}

/// A provider that answers 403 to every CONNECT, and counts them.
async fn refusing_provider() -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = Arc::clone(&count);
    let addr = serve(move |mut s| {
        let seen = Arc::clone(&seen);
        async move {
            if read_head(&mut s).await.is_some() {
                seen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                respond(&mut s, "403 Forbidden", "").await;
            }
        }
    })
    .await;
    (addr, count)
}

/// R1 (attractor): 4 of 10 IPs answer 403 to every CONNECT. A failed
/// attempt gives its lease back, so a failing IP holds the fewest leases and
/// was the least-loaded pick of every new sticky key and of the retry. Now it
/// goes last for a while after each failure: of 40 new keys, each with a
/// target of its own (the cooldown is per target), nearly all are served and
/// the refusing IPs see few CONNECTs.
#[tokio::test]
async fn ips_that_refuse_do_not_attract_new_sticky_keys() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let target = stub_target().await;
    let setup = Setup::new();
    let mut rows = Vec::new();
    let mut ips = Vec::new();
    let mut refusing = Vec::new();
    let mut working = Vec::new();
    for n in 0..10 {
        let ip = uniq_ip();
        let port = if n < 4 {
            let (addr, count) = refusing_provider().await;
            refusing.push(count);
            addr.port()
        } else {
            let provider = stub_provider(PROVIDER_PASS, target, ip).await;
            let port = provider.addr.port();
            working.push(provider);
            port
        };
        rows.push(row(&entry(&setup, ip, port), true));
        ips.push(ip);
    }
    let h = start(&env, &setup, rows).await?;
    let p = setup.partition();
    for ip in ips {
        h.ready(&p, ip).await?;
    }

    let mut served = 0;
    for i in 0..40 {
        let r = connect_to(
            h.connect,
            &format!("at{i}.example.test:443"),
            &format!("px-sid-at{i}"),
            &setup.key,
        )
        .await?;
        served += usize::from(r.status == 200);
    }
    let refused: usize = refusing
        .iter()
        .map(|n| n.load(std::sync::atomic::Ordering::Relaxed))
        .sum();
    let accepted: usize = working.iter().map(|w| w.connects().len()).sum();
    assert!(served >= 38, "{served} of 40 served");
    assert!(
        refused <= 8,
        "the refusing IPs saw {refused} of {} CONNECTs",
        refused + accepted
    );
    Ok(())
}

/// A tunnel that failed on the first provider and was served by the second
/// leaves no dwell key on the first. Its lease there never settled, so once
/// the first provider works again the key goes back to it at once instead of
/// a minute later.
#[tokio::test]
async fn a_failed_attempt_does_not_make_the_lease_young_on_the_failing_provider() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    let (a, b) = (setup.provider.clone(), format!("{}b", setup.provider));
    setup.adapter_toml = Some(format!(
        "{}{}",
        static_adapter_toml(&a, "[]"),
        static_adapter_toml(&b, "[]")
    ));
    let target = stub_target().await;
    // the first provider rejects the login: its IP fails the tunnel
    let stub_a = stub_provider("another-password", target, uniq_ip()).await;
    let stub_b = stub_provider(PROVIDER_PASS, target, uniq_ip()).await;
    let (ip_a, ip_b) = (uniq_ip(), uniq_ip());
    let mut entry_b = entry(&setup, ip_b, stub_b.addr.port());
    entry_b.provider = b.parse()?;
    let h = start(
        &env,
        &setup,
        vec![
            row(&entry(&setup, ip_a, stub_a.addr.port()), true),
            row(&entry_b, true),
        ],
    )
    .await?;
    let (pa, pb) = (
        setup.partition(),
        Partition {
            provider: b.parse()?,
            region: "fr".parse()?,
        },
    );
    h.ready(&pa, ip_a).await?;
    h.ready(&pb, ip_b).await?;

    let r = connect_via(h.connect, "px-sid-d3f", &setup.key).await?;
    assert_eq!(exit_of(&r), Some(ip_b.to_string()), "{}", r.reason);
    let sticky = store::sid_sticky("d3f");
    assert!(
        !h.hot.lease_is_young(&pa, &setup.org, &sticky).await?,
        "the failed provider holds no young lease"
    );
    assert!(
        h.hot.lease_is_young(&pb, &setup.org, &sticky).await?,
        "the serving one does"
    );
    Ok(())
}

/// Regions are candidate partitions of their own, so the walk asks the
/// second region for a unit within the limits before the first breaks one.
/// Regions ["us", "ca"], `max_conns_per_ip` 1: the second tunnel goes to the
/// idle CA IP and no limit is counted as broken; the third breaks it on US.
#[tokio::test]
async fn the_next_region_serves_before_the_first_breaks_a_limit() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.regions = r#"["us", "ca"]"#;
    setup.policy = "max_conns_per_ip = 1\n".into();
    let target = stub_target().await;
    let stub_us = stub_provider(PROVIDER_PASS, target, uniq_ip()).await;
    let stub_ca = stub_provider(PROVIDER_PASS, target, uniq_ip()).await;
    let (ip_us, ip_ca) = (uniq_ip(), uniq_ip());
    let mut entry_us = entry(&setup, ip_us, stub_us.addr.port());
    entry_us.region = "us".parse()?;
    let mut entry_ca = entry(&setup, ip_ca, stub_ca.addr.port());
    entry_ca.region = "ca".parse()?;
    let h = start(
        &env,
        &setup,
        vec![row(&entry_us, true), row(&entry_ca, true)],
    )
    .await?;
    let partition = |region: &str| -> Result<Partition, BoxErr> {
        Ok(Partition {
            provider: setup.provider.parse()?,
            region: region.parse()?,
        })
    };
    h.ready(&partition("us")?, ip_us).await?;
    h.ready(&partition("ca")?, ip_ca).await?;

    let first = connect_via(h.connect, "px-sid-s2a", &setup.key).await?;
    assert_eq!(exit_of(&first), Some(ip_us.to_string()), "{}", first.reason);
    let second = connect_via(h.connect, "px-sid-s2b", &setup.key).await?;
    assert_eq!(
        exit_of(&second),
        Some(ip_ca.to_string()),
        "{}",
        second.reason
    );
    let broken = |limit: &str| {
        h.metrics
            .lease_limit_broken_total
            .with_label_values(&[limit, &setup.provider])
            .get()
    };
    assert_eq!(broken("max_conns"), 0);
    // both are full now: the third breaks the limit on the first region
    let third = connect_via(h.connect, "px-sid-s2c", &setup.key).await?;
    assert_eq!(exit_of(&third), Some(ip_us.to_string()), "{}", third.reason);
    assert_eq!(broken("max_conns"), 1);
    drop((first, second, third));
    Ok(())
}
