//! Regression tests of gateway defects found in end-to-end testing. Same
//! stubs and skip rule as the parent module.

use std::net::Ipv4Addr;

use super::*;

/// How the stub provider answers a CONNECT.
#[derive(Clone, Copy)]
enum Connect {
    /// Tunnel to the target.
    Tunnel,
    /// Refuse with this status line, for example `407 Proxy Authentication Required`.
    Status(&'static str),
}

/// The exit IP a session gets: stable per login, different per session.
fn exit_for(login: &str) -> IpAddr {
    let hash = login
        .bytes()
        .fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
            (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
        })
        .to_be_bytes();
    IpAddr::V4(Ipv4Addr::new(198, 18, hash[0], hash[1].max(1)))
}

/// A provider that answers exit-IP checks (after `check_delay`) with a
/// per-session exit IP and handles CONNECT as `connect` says. It accepts any
/// login. Returns its port.
async fn session_provider(target: SocketAddr, connect: Connect, check_delay: Duration) -> u16 {
    serve(move |mut s| async move {
        let Some(head) = read_head(&mut s).await else {
            return;
        };
        let (first, login) = request_and_login(&head);
        if first.starts_with("CONNECT") {
            match connect {
                Connect::Status(line) => respond(&mut s, line, "").await,
                Connect::Tunnel => {
                    if let Ok(upstream) = TcpStream::connect(target).await {
                        splice(s, upstream).await;
                    }
                }
            }
            return;
        }
        sleep(check_delay).await;
        let body = format!(r#"{{"ip":"{}","country":"fr"}}"#, exit_for(&login));
        respond(&mut s, "200 OK", &body).await;
    })
    .await
    .port()
}

/// A rotating setup that creates on demand in front of `session_provider`.
async fn rotating_setup(connect: Connect, check_delay: Duration) -> Setup {
    let mut setup = Setup::new();
    let port = session_provider(stub_target().await, connect, check_delay).await;
    setup.rotating_via(port);
    setup
}

/// After a tunnel failed on the unit its sticky lease is bound to, the
/// next tunnel of the same key moves to another unit instead of failing the
/// same way until `lease_ttl`.
#[tokio::test]
async fn the_sticky_lease_leaves_a_unit_that_fails_its_tunnels() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let setup = Setup::new();
    let target = stub_target().await;
    let bad = stub_provider("some-other-password", target, uniq_ip()).await;
    let good = stub_provider(PROVIDER_PASS, target, uniq_ip()).await;
    let (bad_ip, good_ip) = (uniq_ip(), uniq_ip());
    let h = start(
        &env,
        &setup,
        vec![
            row(&entry(&setup, bad_ip, bad.addr.port()), true),
            row(&entry(&setup, good_ip, good.addr.port()), true),
        ],
    )
    .await?;
    let p = setup.partition();
    // the org's lease binds to the unit that refuses the login
    h.ready(&p, bad_ip).await?;
    let r = connect_via(h.connect, "px", &setup.key).await?;
    assert_eq!(r.answer(), (502, "provider_auth"));

    h.ready(&p, good_ip).await?;
    let r = connect_via(h.connect, "px", &setup.key).await?;
    assert_eq!(r.status, 200, "{}", r.reason);
    assert_eq!(
        r.header("X-ProxyX-Exit-IP"),
        Some(good_ip.to_string().as_str()),
        "the same sticky key is served by the healthy unit"
    );
    Ok(())
}

/// A provider that refuses the login opens the route class breaker, as
/// runbook 053 says. Each tunnel goes to another target: a failing unit is
/// skipped per target, so every failure is a real dial.
#[tokio::test]
async fn a_refused_provider_login_opens_the_route_class_breaker() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.pacing.breaker = breaker(2);
    let provider = stub_provider("some-other-password", stub_target().await, uniq_ip()).await;
    // two IPs: a refused login on one IP leaves the route class closed (it is
    // that IP's); two failed tunnels open it
    let (ip1, ip2) = (uniq_ip(), uniq_ip());
    let h = start(
        &env,
        &setup,
        vec![
            row(&entry(&setup, ip1, provider.addr.port()), true),
            row(&entry(&setup, ip2, provider.addr.port()), true),
        ],
    )
    .await?;
    let p = setup.partition();
    for ip in [ip1, ip2] {
        h.ready(&p, ip).await?;
    }
    let r = connect_to(h.connect, "a.example.test:443", "px", &setup.key).await?;
    assert_eq!(r.answer(), (502, "provider_auth"));
    assert_eq!(
        h.hot.breaker_peek(&p, &breaker(2)).await?.0,
        BreakerState::Closed,
        "one failed tunnel is one failure, however many IPs it tried"
    );
    let r = connect_to(h.connect, "b.example.test:443", "px", &setup.key).await?;
    assert_eq!(r.answer(), (502, "provider_auth"));
    assert_eq!(
        h.hot.breaker_peek(&p, &breaker(2)).await?.0,
        BreakerState::Open
    );
    let r = connect_to(h.connect, "c.example.test:443", "px", &setup.key).await?;
    assert_eq!(r.answer(), (502, "provider_unavailable"));
    Ok(())
}

/// A session made on demand whose dial fails answers with the dial cause,
/// not `cache_empty`.
#[tokio::test]
async fn a_dial_failure_after_an_on_demand_create_keeps_its_cause() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let setup = rotating_setup(
        Connect::Status("407 Proxy Authentication Required"),
        Duration::ZERO,
    )
    .await;
    let h = start(&env, &setup, vec![]).await?;

    let r = connect_via(h.connect, "px-cc-fr", &setup.key).await?;
    assert_eq!(r.answer(), (502, "provider_auth"));
    assert_eq!(h.connections("connect", "provider_auth"), 1);
    assert_eq!(h.connections("connect", "cache_empty"), 0);
    Ok(())
}

/// A rotating session that exits from another IP is withdrawn and counted
/// as an `ip_changed` eviction.
#[tokio::test]
async fn a_rotating_session_that_changed_its_exit_ip_is_an_ip_changed_eviction() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let setup = rotating_setup(Connect::Tunnel, Duration::ZERO).await;
    let h = start(&env, &setup, vec![]).await?;
    let p = setup.partition();
    // the ready session says one IP, the provider exits from another
    let now = OffsetDateTime::now_utc();
    h.hot
        .ready_put(
            &p,
            &UnitRecord {
                id: "stalesession".into(),
                ip: uniq_ip(),
                expires_at: Some(now + time::Duration::hours(1)),
                ttl: Some(Duration::from_secs(3700)),
                owner: None,
            },
        )
        .await?;

    let r = connect_via(h.connect, "px-cc-fr", &setup.key).await?;
    assert_eq!(r.status, 200, "{}", r.reason);
    assert!(
        !h.hot
            .ready_ids(&p)
            .await?
            .contains(&"stalesession".to_owned()),
        "the session was withdrawn"
    );
    let changed = h
        .metrics
        .cache_evictions_total
        .with_label_values(&["ip_changed"])
        .get();
    assert_eq!(changed, 1);
    Ok(())
}

/// A burst on a cold pool waits for the creates in flight and shares what
/// they make, instead of answering `cache_empty` at once.
#[tokio::test]
async fn a_burst_on_a_cold_pool_waits_for_the_creates_in_flight() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    // max_ready is 2: two creates run, each takes 500 ms; the rest must wait
    let setup = rotating_setup(Connect::Tunnel, Duration::from_millis(500)).await;
    let h = start(&env, &setup, vec![]).await?;

    let mut tasks = Vec::new();
    for i in 0..6 {
        let (addr, key) = (h.connect, setup.key.clone());
        tasks.push(tokio::spawn(async move {
            let user = format!("px-cc-fr-sid-burst{i}");
            connect_via(addr, &user, &key)
                .await
                .map(|r| (r.status, r.reason.clone()))
                .map_err(|e| e.to_string())
        }));
    }
    for task in tasks {
        let (status, reason) = task.await?.map_err(BoxErr::from)?;
        assert_eq!((status, reason.as_str()), (200, "Connection established"));
    }
    assert!(h.hot.ready_ids(&setup.partition()).await?.len() <= 2);
    Ok(())
}

/// On-demand creates go through the breaker: failed creates open it, an
/// open one refuses the next request without another provider call. A tunnel
/// charges the route class once, however many creates it tried.
#[tokio::test]
async fn on_demand_creates_open_and_obey_the_route_class_breaker() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.pacing.breaker = breaker(2);
    // a provider nothing listens on
    let dead = closed_endpoint();
    setup.rotating_via(dead.port());
    let h = start(&env, &setup, vec![]).await?;
    let p = setup.partition();

    let r = connect_via(h.connect, "px-cc-fr-sid-one", &setup.key).await?;
    assert_eq!(r.answer(), (503, "cache_empty"));
    assert_eq!(
        h.hot.breaker_peek(&p, &breaker(2)).await?.0,
        BreakerState::Closed,
        "the two failed creates of one tunnel are one failure"
    );
    let r = connect_via(h.connect, "px-cc-fr-sid-two", &setup.key).await?;
    // the second failed tunnel opens it when it ends
    assert_eq!(r.answer(), (503, "cache_empty"));
    assert_eq!(
        h.hot.breaker_peek(&p, &breaker(2)).await?.0,
        BreakerState::Open,
        "two failed tunnels opened it"
    );
    let r = connect_via(h.connect, "px-cc-fr-sid-three", &setup.key).await?;
    assert_eq!(r.answer(), (502, "provider_unavailable"));
    Ok(())
}

/// A session the gateway creates lives no longer than the provider
/// keeps it, whatever `max_age` says.
#[tokio::test]
async fn an_on_demand_session_never_outlives_the_provider_session_life() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = rotating_setup(Connect::Tunnel, Duration::ZERO).await;
    setup.adapter_toml = setup
        .adapter_toml
        .map(|toml| toml.replace("max_session_minutes = 60", "max_session_minutes = 3"));
    setup.policy = "[policy.rotating]\nmax_age = \"2h\"\nmin_remaining = \"30s\"\n".into();
    let h = start(&env, &setup, vec![]).await?;

    let r = connect_via(h.connect, "px-cc-fr", &setup.key).await?;
    assert_eq!(r.status, 200, "{}", r.reason);
    let jobs = session_jobs(&env, &setup.partition()).await?;
    assert_eq!(jobs.len(), 1, "{jobs:?}");
    let life = jobs[0].expires - jobs[0].born;
    assert!(
        life <= 180,
        "the session job lives {life} s, provider keeps 180 s"
    );
    Ok(())
}

/// N-1: when a provider-wide failure has cooled every unit of the partition
/// for the target (and `max_ready` leaves no room for another session), the
/// client hears the failure at once. It used to wait out `create_deadline`
/// and then get `cache_empty`.
#[tokio::test]
async fn a_pool_cooled_by_a_provider_wide_failure_answers_with_that_failure_at_once() -> TestResult
{
    let Some(env) = env() else { return Ok(()) };
    // max_ready is 2: two sessions fail the tunnel, the third request finds
    // both cooled and no room to create
    let setup = rotating_setup(
        Connect::Status("407 Proxy Authentication Required"),
        Duration::ZERO,
    )
    .await;
    let h = start(&env, &setup, vec![]).await?;

    for sid in ["n1a", "n1b"] {
        let user = format!("px-cc-fr-sid-{sid}");
        let r = connect_via(h.connect, &user, &setup.key).await?;
        assert_eq!(r.answer(), (502, "provider_auth"), "{sid}");
    }
    assert_eq!(h.hot.ready_ids(&setup.partition()).await?.len(), 2);

    let started = std::time::Instant::now();
    let r = connect_via(h.connect, "px-cc-fr-sid-n1c", &setup.key).await?;
    assert_eq!(r.answer(), (502, "provider_auth"));
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "answered after {:?}: it waited for creates that cannot start",
        started.elapsed()
    );
    assert_eq!(h.connections("connect", "cache_empty"), 0);
    Ok(())
}

/// N-1, static: the only unit refused the login a moment ago, so the next
/// tunnel to the same target is refused with that cause, not `lease_timeout`
/// after `lease_wait`.
#[tokio::test]
async fn a_static_unit_cooled_by_a_failed_tunnel_answers_with_the_failure_not_lease_timeout()
-> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let setup = Setup::new(); // static on_empty defaults to wait, lease_wait 1s
    let provider = stub_provider("some-other-password", stub_target().await, uniq_ip()).await;
    let (h, _) = static_unit(&env, &setup, provider.addr, true).await?;

    let r = connect_via(h.connect, "px-sid-c1", &setup.key).await?;
    assert_eq!(r.answer(), (502, "provider_auth"));

    // The refused unit left leasing, so the next tunnel finds
    // no unit: it waits for one, as `on_empty = wait` says, and times out.
    let r = connect_via(h.connect, "px-sid-c2", &setup.key).await?;
    assert_eq!(r.answer(), (504, "lease_timeout"));
    Ok(())
}

/// Observation (inventory D12): a client that resets the connection before
/// its head is a peer that left, like one that closes cleanly, not a bad request.
#[tokio::test]
async fn a_reset_before_the_head_is_not_a_bad_request_but_garbage_is() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let setup = Setup::new();
    let (h, _, _) = static_fixture(&env, &setup).await?;

    let reset = TcpStream::connect(h.connect).await?;
    socket2::SockRef::from(&reset).set_linger(Some(Duration::ZERO))?;
    drop(reset);
    drop(TcpStream::connect(h.connect).await?);

    let mut garbage = TcpStream::connect(h.connect).await?;
    garbage.write_all(b"GET / HTTP/1.1\r\n\r\n").await?;
    let mut sink = Vec::new();
    sleep(Duration::from_millis(200)).await;
    garbage.read_to_end(&mut sink).await?;
    assert_eq!(
        h.connections("connect", "bad_request"),
        1,
        "only the garbage head counts"
    );
    Ok(())
}

async fn raw_http(proxy: SocketAddr, request: &[u8]) -> Result<Vec<u8>, BoxErr> {
    let mut client = TcpStream::connect(proxy).await?;
    client.write_all(request).await?;
    let mut response = Vec::new();
    timeout(Duration::from_secs(12), client.read_to_end(&mut response)).await??;
    Ok(response)
}

#[tokio::test]
async fn probe_http_pages_use_leased_tunnels_and_never_forward_a_second_request() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.probe_targets = vec!["http://page.stub/"];
    let seen: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
    let captured = Arc::clone(&seen);
    let target = serve(move |mut socket| {
        let captured = Arc::clone(&captured);
        async move {
            let Some(head) = read_head(&mut socket).await else {
                return;
            };
            let mut request = head.as_bytes().to_vec();
            let n = if head.contains("Transfer-Encoding: chunked\r\n") {
                b"4\r\nbody\r\n0\r\n\r\n".len()
            } else if head.contains("Content-Length: 4\r\n") {
                4
            } else {
                0
            };
            let mut body = vec![0; n];
            if socket.read_exact(&mut body).await.is_err() {
                return;
            }
            request.extend_from_slice(&body);
            // A raw relay would deliver the next authority and its credentials
            // here. The HTTP bridge must not forward even one extra byte.
            let mut extra = [0; 1024];
            if let Ok(Ok(n)) = timeout(Duration::from_millis(100), socket.read(&mut extra)).await {
                request.extend_from_slice(&extra[..n]);
            }
            captured.lock().push(request);
            respond(
                &mut socket,
                "200 OK",
                "<!doctype html><title>probe page</title>",
            )
            .await;
        }
    })
    .await;
    let (h, provider, ip) = unit_for(&env, &setup, target).await?;
    let token = probe_token(&setup);
    let auth = STANDARD.encode(format!("px:{token}"));
    let later_auth = STANDARD.encode("px:later-secret");
    let later = format!(
        "GET http://other.stub/private HTTP/1.1\r\nHost: other.stub\r\n\
         Proxy-Authorization: Basic {later_auth}\r\n\r\n",
    );
    for (method, framing, body, pipelined) in [
        ("GET", "", "", false),
        ("GET", "", "", true),
        ("POST", "Content-Length: 4\r\n", "body", true),
        (
            "POST",
            "Transfer-Encoding: chunked\r\nTrailer: Proxy-Authorization\r\n",
            "4;extension=discard\r\nbody\r\n0\r\nProxy-Authorization: trailer-secret\r\n\r\n",
            true,
        ),
    ] {
        let request = format!(
            "{method} http://page.stub/ HTTP/1.1\r\nHost: page.stub\r\n\
             Proxy-Authorization: Basic {auth}\r\n\
             Connection: keep-alive, X-Remove\r\nX-Remove: hop-secret\r\n\
             Proxy-Connection: keep-alive\r\n{framing}\r\n{body}{}",
            if pipelined { later.as_str() } else { "" },
        );
        let response = String::from_utf8(raw_http(h.probe, request.as_bytes()).await?)?;
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("<!doctype html><title>probe page</title>"));
        assert!(response.contains(&format!("X-ProxyX-Exit-IP: {ip}\r\n")));
        assert!(response.contains("Connection: close\r\n"));
        let session = response
            .lines()
            .find_map(|line| line.strip_prefix("X-ProxyX-Pool-Session: "))
            .ok_or("missing session correlation")?;
        assert_eq!(
            h.hot
                .session_get(session)
                .await?
                .ok_or("missing session record")?
                .org,
            setup.probe_org
        );

        let request = seen.lock().last().expect("origin received request").clone();
        let request = String::from_utf8(request)?;
        assert!(request.starts_with(&format!("{method} / HTTP/1.1\r\n")));
        assert!(request.contains("Host: page.stub\r\n"));
        assert!(request.contains("Connection: close\r\n"));
        for forbidden in [
            "Proxy-Authorization",
            "Proxy-Connection",
            "X-Remove",
            "hop-secret",
            "other.stub",
            "trailer-secret",
            auth.as_str(),
            later_auth.as_str(),
        ] {
            assert!(!request.contains(forbidden), "origin received {forbidden}");
        }
        let expected_body = if framing.starts_with("Transfer-Encoding") {
            "4\r\nbody\r\n0\r\n\r\n"
        } else {
            body
        };
        assert_eq!(
            request.split_once("\r\n\r\n").expect("head").1,
            expected_body
        );
    }
    assert_eq!(provider.connects().len(), 4);
    assert!(provider.connects().iter().all(|(target, login)| {
        target == "page.stub:80" && login == &format!("{PROVIDER_USER}:{PROVIDER_PASS}")
    }));
    eventually("HTTP probe tunnels close", || {
        tunnels_closed(&h, &setup.probe_org)
    })
    .await;
    assert!(metered_bytes(&h, &setup.provider).await? > 0);
    assert_eq!(h.connections("probe", "ok"), 4);
    Ok(())
}

#[tokio::test]
async fn absolute_http_keeps_probe_auth_destination_rules_and_public_405() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.probe_targets = vec!["http://page.stub/", "http://127.0.0.1/"];
    let (h, provider, _) = static_fixture(&env, &setup).await?;
    let token = probe_token(&setup);
    for (url, host) in [
        ("http://other.stub/", "other.stub"),
        ("http://page.stub:22/", "page.stub:22"),
        ("http://127.0.0.1/", "127.0.0.1"),
        ("http://169.254.169.254/", "169.254.169.254"),
    ] {
        let auth = STANDARD.encode(format!("px:{token}"));
        let request = format!(
            "GET {url} HTTP/1.1\r\nHost: {host}\r\nProxy-Authorization: Basic {auth}\r\n\r\n",
        );
        let response = raw_http(h.probe, request.as_bytes()).await?;
        assert!(
            response.starts_with(b"HTTP/1.1 403 destination_denied\r\n"),
            "{url}"
        );
    }
    for key in [
        setup.key.as_str(),
        setup.probe_key.as_str(),
        setup.probe_secret.as_str(),
        "invalid-token",
    ] {
        let auth = STANDARD.encode(format!("px:{key}"));
        let request = format!(
            "GET http://page.stub/ HTTP/1.1\r\nHost: page.stub\r\nProxy-Authorization: Basic {auth}\r\n\r\n",
        );
        let response = raw_http(h.probe, request.as_bytes()).await?;
        assert!(response.starts_with(b"HTTP/1.1 407 auth_required\r\n"));
    }
    let response = raw_http(
        h.probe,
        b"GET http://page.stub/ HTTP/1.1\r\nHost: page.stub\r\n\r\n",
    )
    .await?;
    assert!(response.starts_with(b"HTTP/1.1 407 auth_required\r\n"));
    for listener in [h.connect, h.probe] {
        let auth = STANDARD.encode(format!("px:{token}"));
        let request = format!(
            "GET http://page.stub/ HTTP/1.1\r\nHost: other.stub\r\nProxy-Authorization: Basic {auth}\r\n\r\n",
        );
        let response = raw_http(listener, request.as_bytes()).await?;
        let expected = if listener == h.connect {
            &b"HTTP/1.1 405 Method Not Allowed\r\n"[..]
        } else {
            &b"HTTP/1.1 400 Bad Request\r\n"[..]
        };
        assert!(response.starts_with(expected));
    }
    for framing in [
        "Content-Length: 0\r\nContent-Length: 1\r\n",
        "Content-Length: 0\r\nTransfer-Encoding: chunked\r\n",
        "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n",
        "Content-Length: +1\r\n",
    ] {
        let auth = STANDARD.encode(format!("px:{token}"));
        let request = format!(
            "POST http://page.stub/ HTTP/1.1\r\nHost: page.stub\r\n\
             Proxy-Authorization: Basic {auth}\r\n{framing}\r\n",
        );
        let response = raw_http(h.probe, request.as_bytes()).await?;
        assert!(response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
    }
    assert!(provider.connects().is_empty());
    Ok(())
}
