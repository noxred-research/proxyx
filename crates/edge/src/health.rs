//! Active health checks, run in the background every `health.interval`.
//!
//! * Parents: a probe connects to each parent from its egress pool and, with
//!   `health.parent_target`, opens a tunnel to that `host:port` through it
//!   (HTTP CONNECT or SOCKS5 CONNECT). `unhealthy_threshold` failed probes in
//!   a row take the parent out of use, `healthy_threshold` good ones bring it
//!   back. The circuit breaker is a separate signal, fed by real requests.
//! * Egress addresses: each address of each pool is checked to be still
//!   assigned to a local interface and bindable, each prefix to be still routed
//!   to this host. A failed check takes the address out of the rotation until
//!   it passes again.
//!
//! The checks read the running configuration at every round, so a reload
//! changes what is checked; the verdicts of a reloaded configuration start
//! healthy and are re-established by the next round.

use std::sync::Arc;
use std::time::Duration;

use common::types::Target;
use tokio::task::JoinSet;

use crate::conn::Shared;
use crate::connect;
use crate::parent::split_host_port;
use crate::state::State;

pub async fn run(shared: Arc<Shared>) {
    loop {
        let state = shared.state();
        let interval = state.cfg.health.interval;
        if !interval.is_zero() {
            round(&shared, &state).await;
        }
        shared.parent_conns.reap();
        let wait = if interval.is_zero() {
            Duration::from_secs(5)
        } else {
            interval
        };
        tokio::select! {
            () = tokio::time::sleep(wait) => {}
            () = shared.shutdown.cancelled() => return,
        }
    }
}

/// One round of checks over everything in the running configuration.
pub async fn round(shared: &Arc<Shared>, state: &Arc<State>) {
    let m = &shared.metrics;

    for pool in state.all_pools() {
        let p = Arc::clone(&pool);
        let Ok(r) = tokio::task::spawn_blocking(move || p.recheck()).await else {
            continue;
        };
        m.health_checks_total
            .with_label_values(&["egress", "ok"])
            .inc_by(r.ok as u64);
        m.health_checks_total
            .with_label_values(&["egress", "failed"])
            .inc_by(r.failed as u64);
        for (what, healthy) in r.changed {
            if healthy {
                tracing::info!(pool = pool.name(), address = %what, "egress address is usable again");
            } else {
                tracing::warn!(pool = pool.name(), address = %what, "egress address is no longer assigned or bindable: out of rotation");
            }
        }
    }

    let target = state
        .cfg
        .health
        .parent_target
        .as_deref()
        .and_then(split_host_port)
        .map(|(host, port)| Target { host, port });
    let budget = state.cfg.health.timeout;
    let mut set = JoinSet::new();
    for (index, parent) in state.parents.all().iter().enumerate() {
        let root_used = state.cfg.server.default_route != crate::config::Route::Direct
            || state.cfg.routes.iter().any(|route| {
                route.chain.is_none()
                    && route.route != crate::config::Route::Direct
                    && (route.parents.is_empty() || route.parents.contains(&parent.name))
            });
        let root_active = root_used
            && (state.selector.cfg.strategy != crate::config::Strategy::Latency
                || !state.selector.idle());
        let referenced = state
            .chains
            .iter()
            .any(|chain| chain.hops.iter().any(|hop| hop.parents.contains(&index)));
        let active_chain = state.chains.iter().any(|chain| {
            chain.hops.iter().any(|hop| {
                hop.parents.contains(&index)
                    && (hop.selector.cfg.strategy != crate::config::Strategy::Latency
                        || !hop.selector.idle())
            })
        });
        if !root_active && (root_used || referenced) && !active_chain {
            continue;
        }
        let (state, parent, target) = (Arc::clone(state), Arc::clone(parent), target.clone());
        set.spawn(async move {
            let started = tokio::time::Instant::now();
            let r = connect::probe_parent(&state, &parent, target.as_ref(), budget).await;
            if r.is_ok() {
                parent.record_latency(started.elapsed());
            }
            (parent, r)
        });
    }
    while let Some(done) = set.join_next().await {
        let Ok((parent, result)) = done else { continue };
        let ok = result.is_ok();
        m.health_checks_total
            .with_label_values(&["parent", if ok { "ok" } else { "failed" }])
            .inc();
        match parent.health.observe(ok) {
            Some(false) => {
                let why = result.err().map(|e| e.to_string()).unwrap_or_default();
                tracing::warn!(parent = %parent.name, reason = %why, "parent failed its health checks: out of use");
            }
            Some(true) => tracing::info!(parent = %parent.name, "parent is healthy again"),
            None => {}
        }
    }
    let mut chains = JoinSet::new();
    for (index, chain) in state.chains.iter().enumerate() {
        if chain.probe.is_none()
            || (chain
                .hops
                .iter()
                .any(|hop| hop.selector.cfg.strategy == crate::config::Strategy::Latency)
                && chain.hops.iter().all(|hop| hop.selector.idle()))
        {
            continue;
        }
        let state = Arc::clone(state);
        chains.spawn(async move {
            let result = connect::probe_chain(&state, &state.chains[index], budget).await;
            (index, result)
        });
    }
    while let Some(done) = chains.join_next().await {
        let Ok((index, result)) = done else {
            continue;
        };
        let chain = &state.chains[index];
        let ok = result.is_ok();
        m.health_checks_total
            .with_label_values(&["chain", if ok { "ok" } else { "failed" }])
            .inc();
        if let Some(healthy) = chain.health.observe(ok) {
            tracing::info!(chain=%chain.name, healthy, "chain health changed");
        }
    }
    state.selector.refresh(&state.parents, &[]);
    for chain in &state.chains {
        for hop in &chain.hops {
            hop.selector.refresh(&state.parents, &hop.parents);
        }
    }
}
