//! The exit-IP check services of this process.
//!
//! The default is the public list in [`ExitIpConfig::default`]. A benchmark
//! or an isolated environment with a stub provider replaces it with
//! `Settings::exit_ip_services` (`PROXYX_POOL_EXIT_IP_SERVICES`), a comma list
//! of `kind=url`.
//!
//! The exit country that the warmer checks against a static IP's region comes
//! from the `trace_lines` (`loc=`), `ip_country_json` and `ip_country_iso_json` kinds. The
//! provider's own echo (`echo_url`) and the `ip_json` kind return the IP only, so a list
//! without one of the three is refused:
//! every exit would fail its region check.

use anyhow::Context as _;
use verify::{CheckService, ExitIpConfig, ServiceKind};

/// The check configuration for `raw` (`Settings::exit_ip_services`): the
/// default when unset, otherwise only the listed services.
///
/// Fails when an item is not `kind=url`, the kind is unknown, the URL is not an
/// http(s) URL, the list is empty, or no service in it reports a country.
pub fn config(raw: Option<&str>) -> anyhow::Result<ExitIpConfig> {
    let mut cfg = ExitIpConfig::default();
    let Some(raw) = raw else {
        return Ok(cfg);
    };
    cfg.services = raw
        .split(',')
        .map(|item| service(item.trim()))
        .collect::<anyhow::Result<_>>()
        .context("failed to parse exit_ip_services")?;
    anyhow::ensure!(
        cfg.services.iter().any(|s| reports_country(s.kind)),
        "exit_ip_services needs one of trace_lines, ip_country_json or ip_country_iso_json: \
         only they report the exit country that is checked against the region"
    );
    Ok(cfg)
}

fn reports_country(kind: ServiceKind) -> bool {
    matches!(
        kind,
        ServiceKind::TraceLines | ServiceKind::IpCountryJson | ServiceKind::IpCountryIsoJson
    )
}

fn service(item: &str) -> anyhow::Result<CheckService> {
    let (kind, url) = item
        .split_once('=')
        .with_context(|| format!("{item:?} is not kind=url"))?;
    let kind = match kind {
        "ip_json" => ServiceKind::IpJson,
        "trace_lines" => ServiceKind::TraceLines,
        "ip_country_json" => ServiceKind::IpCountryJson,
        "ip_country_iso_json" => ServiceKind::IpCountryIsoJson,
        other => anyhow::bail!("unknown service kind {other:?}"),
    };
    anyhow::ensure!(
        url.starts_with("http://") || url.starts_with("https://"),
        "the url of {} must be http or https",
        kind.name()
    );
    Ok(CheckService {
        kind,
        url: url.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_keeps_the_public_default() {
        let cfg = config(None).expect("default");
        assert_eq!(cfg.services, ExitIpConfig::default().services);
    }

    #[test]
    fn a_list_replaces_the_default_in_order_and_keeps_query_strings() {
        let cfg = config(Some(
            "ip_json=http://stub:1/ip?format=json, trace_lines=http://stub:1/trace",
        ))
        .expect("list");
        let got: Vec<_> = cfg
            .services
            .iter()
            .map(|s| (s.kind, s.url.as_str()))
            .collect();
        assert_eq!(
            got,
            [
                (ServiceKind::IpJson, "http://stub:1/ip?format=json"),
                (ServiceKind::TraceLines, "http://stub:1/trace"),
            ]
        );
        assert_eq!(cfg.min_agree, ExitIpConfig::default().min_agree);
    }

    #[test]
    fn bad_items_are_startup_errors() {
        for bad in [
            "",
            "ip_json",
            "nosuch=http://x/",
            "ip_json=ftp://x/",
            "ip_json=http://x/,",
        ] {
            assert!(config(Some(bad)).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn a_list_without_a_country_source_is_refused() {
        // ip_json and the provider echo give the IP only:
        // every exit would fail its region check and be quarantined.
        let err =
            config(Some("ip_json=https://ip.example.test/?format=json")).expect_err("no country");
        assert!(format!("{err:#}").contains("trace_lines"), "{err:#}");
        for ok in [
            "ip_json=http://x/,trace_lines=https://trace.example.test/trace",
            "ip_country_json=http://x/",
            "ip_country_iso_json=http://x/",
        ] {
            config(Some(ok)).unwrap_or_else(|e| panic!("{ok}: {e:#}"));
        }
    }

    #[test]
    fn the_default_list_reports_a_country() {
        let cfg = ExitIpConfig::default();
        assert!(cfg.services.iter().any(|s| reports_country(s.kind)));
    }
}
