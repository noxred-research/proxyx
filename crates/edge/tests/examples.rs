//! The shipped example files stay valid.
#![allow(clippy::unwrap_used)]

use std::path::PathBuf;

fn example(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples")
        .join(name)
}

#[test]
fn the_multi_ip_example_parses() {
    let cfg = proxyx_edge::Config::load(&example("edge.toml")).unwrap();
    assert_eq!(cfg.listeners.len(), 2);
    assert_eq!(cfg.pools.len(), 3);
    assert!(cfg.rules.len() >= 3 && !cfg.limits.is_empty() && !cfg.egress.is_empty());
}

#[test]
fn the_loopback_example_passes_check_on_any_linux_host() {
    let report = proxyx_edge::check(&example("edge-loopback.toml")).unwrap();
    assert_eq!(report.pools[0].1.len(), 3);
    assert_eq!(report.users, 1);
}
