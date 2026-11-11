//! Tests of the per-source limit on wrong org keys. Same stubs and
//! skip rule as the parent module.

use super::*;
use crate::auth::{FAILURES_PER_WINDOW, keys_in_bucket};

fn failures(h: &Harness, reason: &str) -> u64 {
    h.metrics
        .auth_failures_total
        .with_label_values(&[reason])
        .get()
}

#[tokio::test]
async fn a_source_cycling_wrong_keys_is_limited_but_its_valid_key_still_tunnels() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let setup = Setup::new();
    let (h, provider, _) = static_fixture(&env, &setup).await?;

    // the valid key is known to the pod before the scan starts
    let mut first = connect_via(h.connect, "px", &setup.key).await?;
    assert_eq!(first.status, 200, "{}", first.reason);
    assert_eq!(ping(&mut first.stream, "before").await?, "pong:before");

    let limit = FAILURES_PER_WINDOW as usize;
    let extra = 30;
    for (i, key) in keys_in_bucket(0, "wrong-", limit + extra)
        .into_iter()
        .enumerate()
    {
        let r = connect_via(h.connect, "px", &key).await?;
        assert_eq!(r.answer(), (407, "auth_required"), "attempt {i}");
        assert!(r.header("Proxy-Authenticate").is_some());
    }
    assert_eq!(failures(&h, "unknown_key"), limit as u64);
    assert_eq!(failures(&h, "source_limited"), extra as u64);
    assert_eq!(
        h.connections("connect", "auth_required"),
        (limit + extra) as u64
    );

    // the same source, now limited, keeps working with the valid key on both
    // listeners that accept it
    let mut again = connect_via(h.connect, "px", &setup.key).await?;
    assert_eq!(again.status, 200, "{}", again.reason);
    assert_eq!(ping(&mut again.stream, "during").await?, "pong:during");
    let (mut s, auth, reply) =
        socks_connect(h.socks, "px", &setup.key, "example.test", 443).await?;
    assert_eq!(auth, [1, 0]);
    assert_eq!(reply.expect("reply")[..2], [5, 0]);
    assert_eq!(ping(&mut s, "socks").await?, "pong:socks");

    // SOCKS5 wrong keys of the limited source get the auth failure status too
    let wrong_socks = keys_in_bucket(0, "wrong-socks", 1).remove(0);
    let (_, auth, reply) = socks_connect(h.socks, "px", &wrong_socks, "example.test", 443).await?;
    assert_eq!(auth, [1, 1]);
    assert!(reply.is_none());
    assert_eq!(failures(&h, "source_limited"), extra as u64 + 1);

    assert_eq!(provider.connects().len(), 3, "only the valid logins dialed");
    Ok(())
}

#[tokio::test]
async fn a_repeated_wrong_key_is_counted_but_never_limits_its_source() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let setup = Setup::new();
    let (h, _, _) = static_fixture(&env, &setup).await?;

    let attempts = FAILURES_PER_WINDOW as usize * 3;
    for _ in 0..attempts {
        let r = connect_via(h.connect, "px", "revoked-key").await?;
        assert_eq!(r.status, 407);
    }
    assert_eq!(failures(&h, "unknown_key"), attempts as u64);
    assert_eq!(failures(&h, "source_limited"), 0);

    // a key never seen before is still looked up
    let r = connect_via(h.connect, "px", &setup.rival_key).await?;
    assert_eq!(r.status, 200, "{}", r.reason);
    Ok(())
}
