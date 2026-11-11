//! Tests of the tunnel time limits (idle, half-close, stuck write) and of the
//! pre-auth pool. Same stubs and skip rule as the parent
//! module.

use super::*;

/// A target that reads until the client side ends, then sends `ticks` bytes
/// 200 ms apart, then holds the connection open without a byte.
async fn lingering_target(ticks: usize) -> SocketAddr {
    serve(move |mut s| async move {
        let mut buf = [0u8; 1024];
        while matches!(s.read(&mut buf).await, Ok(n) if n > 0) {}
        for _ in 0..ticks {
            sleep(Duration::from_millis(200)).await;
            if s.write_all(b"t").await.is_err() {
                return;
            }
        }
        sleep(Duration::from_secs(600)).await;
    })
    .await
}

/// A target that never reads and sends one byte every 100 ms.
async fn deaf_target() -> SocketAddr {
    serve(|mut s| async move {
        while s.write_all(b"t").await.is_ok() {
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
}

#[tokio::test]
async fn an_idle_tunnel_is_closed_after_the_idle_limit_and_returns_counters_and_permit()
-> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.settings.tunnel_idle_timeout = Duration::from_millis(800);
    setup.settings.max_connections = 1;
    let (h, _, ip) = static_fixture(&env, &setup).await?;

    let mut r = connect_via(h.connect, "px", &setup.key).await?;
    assert_eq!(r.status, 200, "{}", r.reason);
    assert_eq!(h.metrics.tunnels_open.get(), 1);

    // a byte moves the limit: the tunnel outlives its first 800 ms
    sleep(Duration::from_millis(500)).await;
    assert_eq!(ping(&mut r.stream, "alive").await?, "pong:alive");
    sleep(Duration::from_millis(500)).await;
    assert_eq!(
        ping(&mut r.stream, "still").await?,
        "pong:still",
        "500 ms after a byte is inside the limit"
    );

    let last_byte = std::time::Instant::now();
    assert!(
        closed_within(&mut r.stream, Duration::from_secs(5)).await,
        "no byte for the idle limit closes the tunnel"
    );
    assert!(
        last_byte.elapsed() >= Duration::from_millis(700),
        "closed at the limit, not before: {:?}",
        last_byte.elapsed()
    );
    eventually("the counters to close", || tunnels_closed(&h, &setup.org)).await;
    assert_eq!(h.metrics.tunnels_open.get(), 0);
    let load = h.hot.unit_load(&setup.partition(), &ip.to_string()).await?;
    assert_eq!(load.tunnels, 0, "the unit counter is closed too");

    // max_connections is 1: this only works when the permit came back
    eventually_served("the connection permit to come back", &h, &setup.key).await;
    Ok(())
}

#[tokio::test]
async fn a_tunnel_whose_client_ended_closes_after_the_linger_unless_the_target_still_sends()
-> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.pacing.half_close_linger = Duration::from_millis(700);
    // idle stays at ten minutes: only the linger can close this tunnel
    let (h, _, _) = unit_for(&env, &setup, lingering_target(5).await).await?;

    let mut r = connect_via(h.connect, "px", &setup.key).await?;
    assert_eq!(r.status, 200, "{}", r.reason);
    r.stream.shutdown().await?;
    let ended = std::time::Instant::now();

    // the target answers five bytes 200 ms apart: each one is inside the linger
    let mut got = [0u8; 5];
    timeout(Duration::from_secs(5), r.stream.read_exact(&mut got)).await??;
    assert_eq!(&got, b"ttttt", "the tunnel stays up while bytes flow");
    assert!(ended.elapsed() >= Duration::from_millis(900));
    assert_eq!(h.tunnels.count(), 1);

    // then nothing: the linger closes it
    assert!(closed_within(&mut r.stream, Duration::from_secs(5)).await);
    assert!(
        ended.elapsed() >= Duration::from_millis(1_500),
        "the linger counts from the last byte: {:?}",
        ended.elapsed()
    );
    eventually("the counters to close", || tunnels_closed(&h, &setup.org)).await;
    Ok(())
}

#[tokio::test]
async fn a_write_that_cannot_progress_ends_the_tunnel_even_while_the_target_sends() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.settings.tunnel_idle_timeout = Duration::from_millis(800);
    let (h, _, _) = unit_for(&env, &setup, deaf_target().await).await?;

    let mut r = connect_via(h.connect, "px", &setup.key).await?;
    assert_eq!(r.status, 200, "{}", r.reason);

    // fill every buffer on the way to the target that never reads
    let chunk = vec![0u8; 64 * 1024];
    let mut stuck = false;
    for _ in 0..4_096 {
        if timeout(Duration::from_millis(300), r.stream.write_all(&chunk))
            .await
            .is_err()
        {
            stuck = true;
            break;
        }
    }
    assert!(stuck, "the buffers never filled");
    let stuck_at = std::time::Instant::now();

    // the target's one byte per 100 ms keeps the other direction busy, so only
    // the write limit can end this tunnel
    eventually("the stuck write to end the tunnel", || {
        tunnels_closed(&h, &setup.org)
    })
    .await;
    assert!(
        stuck_at.elapsed() < Duration::from_secs(5),
        "{:?}",
        stuck_at.elapsed()
    );
    assert_eq!(h.metrics.tunnels_open.get(), 0);
    Ok(())
}

#[tokio::test]
async fn a_full_pre_auth_pool_closes_new_connections_but_not_an_authenticated_connect() -> TestResult
{
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.settings.max_connections = 10;
    setup.settings.max_pending_connections = Some(3);
    let (h, _, _) = static_fixture(&env, &setup).await?;

    // `slow` is a legitimate client that is mid-handshake; two silent ones
    // follow. The listener accepts in order, so the pool of 3 is full when
    // the fourth connection arrives.
    let slow = TcpStream::connect(h.connect).await?;
    let silent1 = TcpStream::connect(h.connect).await?;
    let mut silent2 = TcpStream::connect(h.connect).await?;
    let mut refused = TcpStream::connect(h.connect).await?;
    assert!(
        closed_within(&mut refused, Duration::from_secs(2)).await,
        "a connection over the pre-auth limit is closed at once"
    );
    assert_eq!(h.connections("connect", "over_limit"), 1);

    // the handshake that started before the pool filled up still completes
    let mut ok = connect_on(slow, "example.test:443", "px", &setup.key).await?;
    assert_eq!(ok.answer(), (200, "Connection established"));
    assert_eq!(ping(&mut ok.stream, "hello").await?, "pong:hello");

    // it gave its slot back on authentication: one more connection fits
    let second = connect_via(h.connect, "px", &setup.key).await?;
    assert_eq!(second.status, 200, "{}", second.reason);
    assert_eq!(h.connections("connect", "over_limit"), 1);
    assert_eq!(ping(&mut ok.stream, "again").await?, "pong:again");

    // the silent clients were never answered and still hold their slots
    let mut buf = [0u8; 1];
    assert!(
        timeout(Duration::from_millis(100), silent2.read(&mut buf))
            .await
            .is_err()
    );
    drop(silent1);
    drop(silent2);
    eventually_served(
        "the slots of the silent clients to come back",
        &h,
        &setup.key,
    )
    .await;
    Ok(())
}

#[tokio::test]
async fn one_source_cannot_take_more_than_its_share_of_the_pre_auth_pool() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.settings.max_connections = 100;
    setup.settings.max_pending_per_ip = Some(2);
    let (h, _, _) = static_fixture(&env, &setup).await?;

    // two silent sockets from 127.0.0.1 fill its share of a pool of 50
    let silent1 = TcpStream::connect(h.connect).await?;
    let silent2 = TcpStream::connect(h.connect).await?;
    let mut third = TcpStream::connect(h.connect).await?;
    assert!(
        closed_within(&mut third, Duration::from_secs(2)).await,
        "a third pre-auth connection of one source is closed at once"
    );
    assert_eq!(h.connections("connect", "over_limit"), 1);

    // another source is not affected. Only Linux answers for all of
    // 127.0.0.0/8; where 127.0.0.2 cannot be bound the test ends here.
    let socket = tokio::net::TcpSocket::new_v4()?;
    if socket.bind("127.0.0.2:0".parse()?).is_err() {
        eprintln!("skipping: cannot bind 127.0.0.2");
        return Ok(());
    }
    let other = socket.connect(h.connect).await?;
    let mut ok = connect_on(other, "example.test:443", "px", &setup.key).await?;
    assert_eq!(ok.answer(), (200, "Connection established"));
    assert_eq!(ping(&mut ok.stream, "hello").await?, "pong:hello");
    assert_eq!(h.connections("connect", "over_limit"), 1);

    // the share comes back when its sockets end
    drop(silent1);
    drop(silent2);
    eventually_served(
        "the share of the silent source to come back",
        &h,
        &setup.key,
    )
    .await;
    Ok(())
}

#[tokio::test]
async fn a_socket_that_sends_nothing_is_closed_after_the_first_byte_deadline_and_gives_its_slot_back()
-> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.settings.max_connections = 10;
    setup.settings.max_pending_connections = Some(1);
    let (h, _, _) = static_fixture(&env, &setup).await?;

    let mut silent = TcpStream::connect(h.connect).await?;
    let started = std::time::Instant::now();
    let mut refused = TcpStream::connect(h.connect).await?;
    assert!(
        closed_within(&mut refused, Duration::from_secs(2)).await,
        "the one pre-auth slot is held by the silent socket"
    );
    assert_eq!(h.connections("connect", "over_limit"), 1);

    assert!(
        closed_within(&mut silent, Duration::from_secs(4)).await,
        "a socket without a first byte is closed well before the 10 s handshake limit"
    );
    assert!(
        started.elapsed() >= Duration::from_millis(2_500),
        "closed at the first-byte deadline, not before: {:?}",
        started.elapsed()
    );
    assert_eq!(h.connections("connect", "bad_request"), 1);

    let again = connect_via(h.connect, "px", &setup.key).await?;
    assert_eq!(again.status, 200, "{}", again.reason);
    Ok(())
}

#[tokio::test]
async fn a_session_id_resolves_while_its_tunnel_is_open_and_lapses_after_it_closed() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.pacing.keep_every = Duration::from_millis(100);
    setup.pacing.session_ttl = Duration::from_millis(1_500);
    let (h, _, _) = static_fixture(&env, &setup).await?;

    let r = connect_via(h.connect, "px", &setup.key).await?;
    assert_eq!(r.status, 200, "{}", r.reason);
    let session = r
        .header("X-ProxyX-Pool-Session")
        .expect("session header")
        .to_owned();

    // older than the TTL, so only the keeper's refresh keeps it
    sleep(Duration::from_millis(2_500)).await;
    assert!(
        h.hot.session_get(&session).await?.is_some(),
        "a session of an open tunnel does not expire"
    );

    drop(r);
    eventually("the tunnel to close", || tunnels_closed(&h, &setup.org)).await;
    eventually("the session record to lapse", || async {
        matches!(h.hot.session_get(&session).await, Ok(None))
    })
    .await;
    Ok(())
}
