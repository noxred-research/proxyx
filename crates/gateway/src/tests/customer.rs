//! Org-owned units (customer upstreams) through the gateway: the owner's
//! stored login, isolation between orgs, fail-closed pinning, and the
//! public-address rule at dial. Same stubs and skip rule as the parent module.

use super::*;

fn login(user: &str, pass: &str) -> store::CustomerLogin {
    store::CustomerLogin {
        username: Secret::new(user),
        password: Secret::new(pass),
    }
}

/// A leasable unit of `setup`'s provider owned by `owner`.
async fn owned_unit(h: &Harness, setup: &Setup, ip: IpAddr, owner: &OrgId) -> Result<(), BoxErr> {
    h.hot
        .ready_put(
            &setup.partition(),
            &UnitRecord {
                owner: Some(owner.clone()),
                ..UnitRecord::static_ip(ip)
            },
        )
        .await?;
    Ok(())
}

fn owned_row(setup: &Setup, ip: IpAddr, port: u16, owner: &OrgId) -> InventoryRow {
    let mut r = row(&entry(setup, ip, port), true);
    r.owner = Some(owner.clone());
    r
}

#[tokio::test]
async fn a_customer_unit_dials_with_the_login_of_its_owner_and_no_other_org_reaches_it()
-> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.kinds = r#"["static"]"#;
    setup.policy = "[policy.on_empty]\nstatic = \"fail\"\n".into();
    setup
        .customer_logins
        .insert(setup.org.clone(), login("provuser-cust", "cust-pass"));
    let provider = stub_provider("cust-pass", stub_target().await, uniq_ip()).await;
    let ip = uniq_ip();
    let h = start(
        &env,
        &setup,
        vec![owned_row(&setup, ip, provider.addr.port(), &setup.org)],
    )
    .await?;
    owned_unit(&h, &setup, ip, &setup.org).await?;

    // The owner is served, with its own login, not the adapter's base one.
    let mut r = connect_via(h.connect, "px", &setup.key).await?;
    assert_eq!(r.status, 200, "{}", r.reason);
    assert_eq!(ping(&mut r.stream, "hi").await?, "pong:hi");
    assert_eq!(
        provider.connects(),
        vec![(
            "example.test:443".to_owned(),
            "provuser-cust:cust-pass".to_owned()
        )]
    );

    // Another org with a valid key never reaches the owner's upstream.
    let rival = connect_via(h.connect, "px", &setup.rival_key).await?;
    assert_eq!(rival.answer(), (503, "no_healthy_ip"));
    assert_eq!(
        provider.connects().len(),
        1,
        "the rival was never dialled through it"
    );
    Ok(())
}

#[tokio::test]
async fn an_org_with_its_own_upstream_fails_closed_instead_of_using_a_shared_provider() -> TestResult
{
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.kinds = r#"["static"]"#;
    setup.policy = "[policy.on_empty]\nstatic = \"fail\"\n".into();
    let shared = Setup::new();
    setup.adapter_toml = Some(format!(
        "{}\n{}",
        setup.static_adapter("[]"),
        shared.static_adapter("[]")
    ));
    let target = stub_target().await;
    let mine = stub_provider(PROVIDER_PASS, target, uniq_ip()).await;
    let shared_provider = stub_provider(PROVIDER_PASS, target, uniq_ip()).await;

    // The org's own unit is not validated yet (a candidate: not in the ready
    // set). A shared provider has a healthy unit.
    let (own_ip, shared_ip) = (uniq_ip(), uniq_ip());
    let mut own = owned_row(&setup, own_ip, mine.addr.port(), &setup.org);
    own.state = IpState::Candidate;
    let shared_row = row(
        &entry(&shared, shared_ip, shared_provider.addr.port()),
        true,
    );
    let h = start(&env, &setup, vec![own, shared_row]).await?;
    h.ready(&shared.partition(), shared_ip).await?;

    // The owner is refused: its traffic must leave through its own upstream.
    let owner = connect_via(h.connect, "px", &setup.key).await?;
    assert_eq!(owner.answer(), (503, "no_healthy_ip"));
    assert!(shared_provider.connects().is_empty());
    assert!(mine.connects().is_empty());

    // Everyone else is served by the shared provider as before.
    let mut rival = connect_via(h.connect, "px", &setup.rival_key).await?;
    assert_eq!(rival.status, 200, "{}", rival.reason);
    assert_eq!(ping(&mut rival.stream, "hi").await?, "pong:hi");
    assert_eq!(shared_provider.connects().len(), 1);
    assert!(
        mine.connects().is_empty(),
        "the owned unit is nobody else's"
    );
    Ok(())
}

#[tokio::test]
async fn a_customer_unit_with_a_non_public_host_is_refused_at_dial() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.kinds = r#"["static"]"#;
    setup.policy = "[policy.on_empty]\nstatic = \"fail\"\n".into();
    setup.adapter_toml = Some(format!(
        "{}public_only = true\n",
        setup.static_adapter("[]")
    ));
    let ip = uniq_ip();
    let mut unit = owned_row(&setup, ip, 3128, &setup.org);
    // the row says the upstream is a cluster address: the adapter refuses it
    // when the endpoint is rendered, before any socket is opened
    unit.entry.host = "10.0.0.5".into();
    let h = start(&env, &setup, vec![unit]).await?;
    owned_unit(&h, &setup, ip, &setup.org).await?;

    let r = connect_via(h.connect, "px", &setup.key).await?;
    assert_eq!(r.answer(), (502, "provider_unavailable"));
    Ok(())
}

/// The upstream refuses the customer's login, so the unit is cooled and
/// answers `provider_auth` at once. The customer fixes the login; the next
/// snapshot reload makes the cooldown forgotten and the tunnel succeeds
/// without waiting out the 10 s that would otherwise remain.
#[tokio::test]
async fn a_changed_customer_login_is_used_after_the_snapshot_reload_not_after_the_cooldown()
-> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.kinds = r#"["static"]"#;
    setup.policy = "[policy.on_empty]\nstatic = \"fail\"\n".into();
    setup
        .customer_logins
        .insert(setup.org.clone(), login("provuser-cust", "wrong-pass"));
    let provider = stub_provider("cust-pass", stub_target().await, uniq_ip()).await;
    let ip = uniq_ip();
    let row_of_the_unit = owned_row(&setup, ip, provider.addr.port(), &setup.org);
    let h = start(&env, &setup, vec![row_of_the_unit.clone()]).await?;
    owned_unit(&h, &setup, ip, &setup.org).await?;

    let refused = connect_via(h.connect, "px", &setup.key).await?;
    assert_eq!(refused.answer(), (502, "provider_auth"));
    // The refused dial took the unit out of leasing (this adapter is not
    // `public_only`, which a loopback stub needs) and the warmer would put it
    // back at its next retest. The cooldown of the failed tunnel stays.
    owned_unit(&h, &setup, ip, &setup.org).await?;
    let cooled = connect_via(h.connect, "px", &setup.key).await?;
    assert_eq!(
        cooled.answer(),
        (502, "provider_auth"),
        "the unit stays cooled with its cause until the login changes"
    );

    // The customer saves a working login; the next reload carries it.
    setup
        .customer_logins
        .insert(setup.org.clone(), login("provuser-cust", "cust-pass"));
    h.reload(loaded_for(&setup, vec![row_of_the_unit])?);

    let started = std::time::Instant::now();
    let served = loop {
        let r = connect_via(h.connect, "px", &setup.key).await?;
        if r.status == 200 || started.elapsed() > Duration::from_secs(5) {
            break r;
        }
        sleep(Duration::from_millis(100)).await;
    };
    assert_eq!(served.status, 200, "{}", served.reason);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "served after {:?}: it waited out the cooldown",
        started.elapsed()
    );
    Ok(())
}
