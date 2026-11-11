//! `scheme = "local"` units through the whole gateway: the adapter renders
//! the entry, the dial binds its host as the source address and connects
//! straight to the target. The destination rule refuses loopback and private
//! targets, so no in-process target can answer; what these tests run is the
//! part that needs no network: the dial fails at the socket, and the failure
//! must be classified as a local one. The tunnel that does leave from the
//! chosen source is covered by the `dial` tests (`connect_from` against a
//! loopback listener) and the `verify` tests (the exit-IP check from a bound
//! address). Same stubs and skip rule as the parent module.

use super::*;

/// A public literal: the destination rule lets it through, the dial never
/// gets as far as the network in these tests.
const TARGET: &str = "8.8.8.8:443";

/// A static `local` adapter named `id`.
fn local_adapter_toml(id: &str) -> String {
    format!(
        "[[adapter]]\nid = \"{id}\"\nkind = \"static\"\nsubtype = \"isp\"\nscheme = \"local\"\n"
    )
}

/// An inventory entry of the `local` adapter: its `host` is the source
/// address the dial binds, its `port` is unused.
fn local_entry(setup: &Setup, ip: IpAddr, source: &str) -> InventoryEntry {
    InventoryEntry {
        host: source.to_owned(),
        port: 0,
        ..entry(setup, ip, 0)
    }
}

/// A gateway with one ready `local` unit that binds `source`, and a breaker
/// that opens on its first failure.
async fn local_unit(
    env: &Env,
    setup: &mut Setup,
    source: &str,
) -> Result<(Harness, IpAddr), BoxErr> {
    setup.adapter_toml = Some(local_adapter_toml(&setup.provider));
    setup.pacing.breaker = breaker(1);
    let ip = uniq_ip();
    let h = start(env, setup, vec![row(&local_entry(setup, ip, source), true)]).await?;
    h.ready(&setup.partition(), ip).await?;
    Ok((h, ip))
}

/// A source address no interface owns cannot be bound: that is the unit's
/// fault (it is withdrawn from this target for a while) and the machine's, not
/// a provider's, so the route class breaker never hears of it.
#[tokio::test]
async fn a_local_unit_with_an_unassigned_source_fails_the_tunnel_and_never_opens_the_breaker()
-> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    // 203.0.113.0/24 is documentation space: no interface owns 203.0.113.77
    let (h, _) = local_unit(&env, &mut setup, "203.0.113.77").await?;

    for target in [TARGET, "8.8.4.4:443"] {
        let r = connect_to(h.connect, target, "px", &setup.key).await?;
        assert_eq!(r.status / 100, 5, "{target}: {} {}", r.status, r.reason);
        assert_eq!(
            h.hot.breaker_peek(&setup.partition(), &breaker(1)).await?.0,
            BreakerState::Closed,
            "{target}: a local failure is no provider failure"
        );
    }
    Ok(())
}

/// The unit's source is fine; what fails is the way to the target (the
/// kernel refuses 127.0.0.2 as the source of a packet to a public address,
/// as it refuses a dead route): the unit stays leasable and the breaker stays
/// closed, whereas a proxy upstream failing the same connect is withdrawn and
/// opens the breaker.
#[tokio::test]
async fn a_local_unit_whose_way_to_the_target_fails_stays_leasable_and_charges_nobody() -> TestResult
{
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    let (h, _) = local_unit(&env, &mut setup, "127.0.0.2").await?;

    for round in 0..3 {
        let r = connect_via_target(&h, &setup, TARGET).await?;
        assert_eq!(
            r.answer(),
            (502, "provider_unavailable"),
            "round {round}: a real dial each time, not a lease_timeout of a withdrawn unit"
        );
        assert_eq!(
            h.hot.breaker_peek(&setup.partition(), &breaker(1)).await?.0,
            BreakerState::Closed,
            "round {round}"
        );
    }
    Ok(())
}

async fn connect_via_target(h: &Harness, setup: &Setup, target: &str) -> Result<Reply, BoxErr> {
    connect_to(h.connect, target, "px", &setup.key).await
}

/// The same refusal of an unusable source for a host that is no IP literal:
/// the entry is refused when the adapter renders it, so the tunnel fails
/// without a dial and the unit is not a provider failure either.
#[tokio::test]
async fn a_local_entry_whose_host_is_no_ip_literal_never_dials_and_charges_nobody() -> TestResult {
    let Some(env) = env() else { return Ok(()) };
    let mut setup = Setup::new();
    let (h, _) = local_unit(&env, &mut setup, "not-an-ip.example").await?;

    let r = connect_via_target(&h, &setup, TARGET).await?;
    assert_eq!(r.status / 100, 5, "{} {}", r.status, r.reason);
    assert_eq!(
        h.hot.breaker_peek(&setup.partition(), &breaker(1)).await?.0,
        BreakerState::Closed
    );
    Ok(())
}
