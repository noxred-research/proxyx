//! Forced rotation must influence the next real gateway lease, not only its index.

use super::*;

#[tokio::test]
async fn forced_rotation_excludes_the_previous_static_unit_at_the_gateway() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let setup = Setup::new();
    let provider = stub_provider(PROVIDER_PASS, stub_target().await, uniq_ip()).await;
    let first_ip = uniq_ip();
    let second_ip = uniq_ip();
    let first = entry(&setup, first_ip, provider.addr.port());
    let second = entry(&setup, second_ip, provider.addr.port());
    let h = start(&env, &setup, vec![row(&first, true), row(&second, true)]).await?;
    h.ready(&setup.partition(), first_ip).await?;
    h.ready(&setup.partition(), second_ip).await?;

    let mut before = connect_via(h.connect, "px-sid-rotate", &setup.key).await?;
    assert_eq!(before.status, 200, "{}", before.reason);
    let old_ip = before
        .header("X-ProxyX-Exit-IP")
        .ok_or("exit header")?
        .to_owned();
    assert!(
        h.hot
            .affinity_rotate(&setup.org, &store::sid_sticky("rotate"))
            .await?
    );
    let mut after = connect_via(h.connect, "px-sid-rotate", &setup.key).await?;
    assert_eq!(after.status, 200, "{}", after.reason);
    assert_ne!(after.header("X-ProxyX-Exit-IP"), Some(old_ip.as_str()));
    assert_eq!(ping(&mut before.stream, "old").await?, "pong:old");
    assert_eq!(ping(&mut after.stream, "new").await?, "pong:new");
    Ok(())
}
