//! Tests of the org budget. Same stubs and skip rule as the parent
//! module.

use super::*;

#[tokio::test]
async fn an_org_over_its_daily_budget_gets_503_org_budget_for_new_tunnels() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    // 1,000 bytes
    setup.policy = "[policy.limits]\norg_max_gb_per_day = 0.000001\n".to_owned();
    let (h, provider, _) = static_fixture(&env, &setup).await?;

    let mut first = connect_via(h.connect, "px", &setup.key).await?;
    assert_eq!(first.status, 200, "an org under its budget opens tunnels");
    ping(&mut first.stream, &"x".repeat(900)).await?;
    // both directions count: 900 + 905 bytes pass the 1,000 byte budget
    drop(first);
    eventually("the org meter to pass the budget", || async {
        h.hot
            .org_cost_used(&setup.org, OffsetDateTime::now_utc())
            .await
            .is_ok_and(|used| used >= 1_000)
    })
    .await;

    let refused = connect_via(h.connect, "px", &setup.key).await?;
    assert_eq!(refused.answer(), (503, "org_budget"));
    assert_eq!(h.metrics.org_budget_refusals_total.get(), 1);
    assert_eq!(h.connections("connect", "org_budget"), 1);
    assert_eq!(
        provider.connects().len(),
        1,
        "the refusal never reached the provider"
    );
    Ok(())
}
