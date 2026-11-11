//! Name resolution: a caching resolver with configurable nameservers, an IP
//! family preference and fixed host records.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use anyhow::Context as _;
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{LookupIpStrategy, NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;

use crate::config::{DnsConfig, IpVersion};

#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("no address for {0}")]
    NoAddress(String),
    #[error("DNS lookup of {host} failed: {reason}")]
    Lookup { host: String, reason: String },
    #[error("DNS lookup of {0} timed out")]
    Timeout(String),
}

pub struct Resolver {
    inner: TokioResolver,
    hosts: HashMap<String, Vec<IpAddr>>,
    ip_version: IpVersion,
    timeout: Duration,
}

impl Resolver {
    pub fn new(c: &DnsConfig) -> anyhow::Result<Self> {
        let mut builder = if c.nameservers.is_empty() {
            TokioResolver::builder_tokio().context("read the system resolver configuration")?
        } else {
            let servers = c
                .nameservers
                .iter()
                .map(|ip| NameServerConfig::udp_and_tcp(*ip))
                .collect();
            TokioResolver::builder_with_config(
                ResolverConfig::from_name_servers(servers),
                TokioRuntimeProvider::default(),
            )
        };
        let o: &mut ResolverOpts = builder.options_mut();
        o.cache_size = c.cache_size;
        o.timeout = c.timeout;
        o.attempts = c.attempts.max(1);
        o.ip_strategy = match c.ip_version {
            IpVersion::PreferIpv4 => LookupIpStrategy::Ipv4AndIpv6,
            IpVersion::PreferIpv6 => LookupIpStrategy::Ipv6AndIpv4,
            IpVersion::Ipv4Only => LookupIpStrategy::Ipv4Only,
            IpVersion::Ipv6Only => LookupIpStrategy::Ipv6Only,
        };
        o.positive_min_ttl = Some(c.min_ttl);
        o.positive_max_ttl = Some(c.max_ttl);
        let hosts = c
            .hosts
            .iter()
            .map(|(k, v)| (k.trim_end_matches('.').to_ascii_lowercase(), v.clone()))
            .collect();
        Ok(Self {
            inner: builder.build().context("build the DNS resolver")?,
            hosts,
            ip_version: c.ip_version,
            timeout: c.timeout.saturating_mul(c.attempts.max(1) as u32 + 1),
        })
    }

    /// Addresses of `host`, preferred family first. An IP literal answers
    /// itself; a fixed host record answers without DNS.
    pub async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        let host = host.trim_end_matches('.');
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let key = host.to_ascii_lowercase();
        let mut out: Vec<IpAddr> = match self.hosts.get(&key) {
            Some(fixed) => fixed.clone(),
            None => {
                let lookup = tokio::time::timeout(self.timeout, self.inner.lookup_ip(key.as_str()))
                    .await
                    .map_err(|_| DnsError::Timeout(key.clone()))?
                    .map_err(|e| DnsError::Lookup {
                        host: key.clone(),
                        reason: e.to_string(),
                    })?;
                lookup.iter().collect()
            }
        };
        match self.ip_version {
            IpVersion::Ipv4Only => out.retain(IpAddr::is_ipv4),
            IpVersion::Ipv6Only => out.retain(IpAddr::is_ipv6),
            IpVersion::PreferIpv4 => out.sort_by_key(|ip| ip.is_ipv6()),
            IpVersion::PreferIpv6 => out.sort_by_key(|ip| ip.is_ipv4()),
        }
        if out.is_empty() {
            return Err(DnsError::NoAddress(key));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn resolver(toml: &str) -> Resolver {
        let c = Config::parse(toml).expect("parse");
        // fixed nameserver so the test does not read /etc/resolv.conf
        let mut dns = c.dns;
        if dns.nameservers.is_empty() {
            dns.nameservers = vec!["127.0.0.1".parse().expect("ip")];
        }
        Resolver::new(&dns).expect("resolver")
    }

    #[tokio::test]
    async fn literals_and_fixed_hosts_never_touch_the_network() {
        let r = resolver(
            "[dns.hosts]\n\"Echo.Test\" = [\"::1\", \"127.0.0.2\"]\n\"v6only.test\" = [\"::1\"]\n",
        );
        assert_eq!(
            r.resolve("203.0.113.5").await.expect("lit"),
            vec!["203.0.113.5".parse::<IpAddr>().expect("ip")]
        );
        assert_eq!(r.resolve("::1").await.expect("lit").len(), 1);
        // case-insensitive, trailing dot ignored, preferred family first
        let got = r.resolve("echo.test.").await.expect("fixed");
        assert_eq!(
            got,
            vec![
                "127.0.0.2".parse::<IpAddr>().expect("ip"),
                "::1".parse().expect("ip")
            ]
        );
    }

    #[tokio::test]
    async fn family_policy_filters_and_orders() {
        let r = resolver(
            "[dns]\nip_version = \"prefer_ipv6\"\n[dns.hosts]\n\"a.test\" = [\"127.0.0.2\", \"::1\"]\n",
        );
        assert!(r.resolve("a.test").await.expect("fixed")[0].is_ipv6());
        let r =
            resolver("[dns]\nip_version = \"ipv4_only\"\n[dns.hosts]\n\"a.test\" = [\"::1\"]\n");
        assert!(matches!(
            r.resolve("a.test").await,
            Err(DnsError::NoAddress(_))
        ));
    }
}
