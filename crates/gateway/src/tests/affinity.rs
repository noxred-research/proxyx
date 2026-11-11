//! Live tunnel affinity indexing, metering and eviction through the gateway.

use super::*;

#[tokio::test]
async fn sticky_tunnels_publish_live_affinity_and_meter_their_bytes() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.pacing.keep_every = Duration::from_millis(100);
    let (h, _, ip) = static_fixture(&env, &setup).await?;
    let mut reply = connect_via(h.connect, "px-sid-metered", &setup.key).await?;
    assert_eq!(reply.status, 200, "{}", reply.reason);
    let sticky = store::sid_sticky("metered");
    let sessions = h.hot.affinity_sessions(&setup.org).await?;
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].sticky, sticky);
    assert_eq!(sessions[0].ip, ip);
    assert_eq!(sessions[0].partition, setup.partition());

    assert_eq!(ping(&mut reply.stream, "affinity").await?, "pong:affinity");
    eventually("sticky session bytes to be metered", || async {
        h.hot
            .affinity_sessions(&setup.org)
            .await
            .is_ok_and(|rows| rows.len() == 1 && rows[0].bytes >= 21)
    })
    .await;
    drop(reply);
    eventually("sticky tunnel to close", || tunnels_closed(&h, &setup.org)).await;
    assert_eq!(h.hot.affinity_sessions(&setup.org).await?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn per_connection_rotation_does_not_fill_the_affinity_table() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let setup = Setup::new();
    let (h, _, _) = static_fixture(&env, &setup).await?;
    let reply = connect_via(h.connect, "px-rot-each", &setup.key).await?;
    assert_eq!(reply.status, 200, "{}", reply.reason);
    assert!(h.hot.affinity_sessions(&setup.org).await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn sticky_entry_cap_evicts_the_least_recently_used_key() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    setup.policy = "max_sticky_entries_per_org = 2".to_owned();
    let (h, _, _) = static_fixture(&env, &setup).await?;
    for sid in ["old", "keep", "keep", "new"] {
        let reply = connect_via(h.connect, &format!("px-sid-{sid}"), &setup.key).await?;
        assert_eq!(reply.status, 200, "{}", reply.reason);
        drop(reply);
        eventually("affinity test tunnel to close", || {
            tunnels_closed(&h, &setup.org)
        })
        .await;
        sleep(Duration::from_millis(2)).await;
    }
    let rows = h.hot.affinity_sessions(&setup.org).await?;
    assert_eq!(rows.len(), 2);
    assert!(
        rows.iter()
            .any(|row| row.sticky == store::sid_sticky("keep"))
    );
    assert!(
        rows.iter()
            .any(|row| row.sticky == store::sid_sticky("new"))
    );
    assert!(
        !rows
            .iter()
            .any(|row| row.sticky == store::sid_sticky("old"))
    );
    Ok(())
}
