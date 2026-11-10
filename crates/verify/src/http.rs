//! HTTP clients that go through an upstream proxy, or straight out of a local
//! source address, and bounded body reads.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use common::types::{Target, UpstreamEndpoint, UpstreamScheme};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::{Client, ClientBuilder, Proxy, Response, Url, redirect::Policy};

const USER_AGENT: &str = concat!("proxyx-verify/", env!("CARGO_PKG_VERSION"));

/// A client cannot be built from the upstream or settings. Carries no host or
/// credential.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("upstream address is not a valid proxy url")]
    BadUpstream,
    #[error("upstream name did not resolve")]
    Resolve,
    #[error("upstream resolves to a private or internal address")]
    DeniedAddress,
    #[error("cannot build http client: {0}")]
    Build(reqwest::Error),
}

impl From<reqwest::Error> for ClientError {
    fn from(e: reqwest::Error) -> Self {
        Self::Build(e.without_url())
    }
}

/// A client whose every request goes through `up`. HTTP upstreams get
/// `Proxy-Authorization` (CONNECT for https targets); SOCKS5 upstreams use
/// RFC 1929 and resolve names at the proxy (`socks5h`). Redirects are never
/// followed: callers decide. With `fresh_connections` each request opens a new
/// connection, so timings include the tunnel setup.
///
/// With `up.public_only` (an upstream the customer chose) the upstream host
/// is resolved here, once, every address must pass the destination rule and
/// the client connects to the checked address, never to a second resolution
/// of the name (DNS rebinding), like `dial` does.
///
/// A `Local` upstream is no proxy: see [`local_client`].
pub(crate) async fn upstream_client(
    up: &UpstreamEndpoint,
    timeout: Duration,
    fresh_connections: bool,
) -> Result<Client, ClientError> {
    if up.scheme == UpstreamScheme::Local {
        return local_client(up, timeout, fresh_connections);
    }
    let checked = public_address(up, timeout).await?;
    let proxy = Proxy::all(proxy_url(up, checked).ok_or(ClientError::BadUpstream)?)?;
    let mut builder = base_builder(timeout).proxy(proxy);
    if fresh_connections {
        builder = builder.pool_max_idle_per_host(0);
    }
    Ok(builder.build()?)
}

/// A client with no proxy that binds `up.host` (the local source address of a
/// `Local` unit) to every socket it opens, so a request leaves from, and shows
/// the exit IP of, that address. A name is resolved through [`LocalResolver`]
/// (public addresses of the source's IP family only); redirects are never
/// followed.
fn local_client(
    up: &UpstreamEndpoint,
    timeout: Duration,
    fresh_connections: bool,
) -> Result<Client, ClientError> {
    let source = up
        .host
        .parse::<IpAddr>()
        .ok()
        .filter(|ip| !ip.is_unspecified() && !ip.is_multicast())
        .ok_or(ClientError::BadUpstream)?;
    let mut builder = base_builder(timeout)
        .local_address(source)
        .dns_resolver(Arc::new(LocalResolver { source }));
    if fresh_connections {
        builder = builder.pool_max_idle_per_host(0);
    }
    Ok(builder.build()?)
}

/// Name resolution for a client bound to `source`. Without it the client
/// would connect to an address of the other IP family from the default
/// route (the exit IP check would then see another IP), and a name that
/// points at a private or internal address (DNS rebinding, a redirect to an
/// internal name) would reach the machine's own network. IP literals in a URL
/// do not pass through a resolver: the callers' URLs are the operator's.
struct LocalResolver {
    source: IpAddr,
}

impl Resolve for LocalResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let source = self.source;
        Box::pin(async move {
            let found = tokio::net::lookup_host((name.as_str(), 0)).await?;
            let usable: Vec<SocketAddr> = found
                .filter(|a| a.is_ipv4() == source.is_ipv4())
                .filter(|a| {
                    !dial::is_denied_destination(&Target {
                        host: a.ip().to_string(),
                        port: 0,
                    })
                })
                .collect();
            if usable.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "no public address of the source's IP family",
                )
                .into());
            }
            Ok(Box::new(usable.into_iter()) as Addrs)
        })
    }
}

/// The address a `public_only` upstream is connected to, after every address
/// of its host passed the destination rule. `None` for any other upstream.
async fn public_address(
    up: &UpstreamEndpoint,
    timeout: Duration,
) -> Result<Option<IpAddr>, ClientError> {
    if !up.public_only {
        return Ok(None);
    }
    let addrs: Vec<IpAddr> = match up.host.parse::<IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => tokio::time::timeout(
            timeout,
            tokio::net::lookup_host((up.host.as_str(), up.port)),
        )
        .await
        .map_err(|_| ClientError::Resolve)?
        .map_err(|_| ClientError::Resolve)?
        .map(|a| a.ip())
        .collect(),
    };
    let Some(first) = addrs.first().copied() else {
        return Err(ClientError::Resolve);
    };
    if addrs.iter().any(|ip| {
        dial::is_denied_destination(&Target {
            host: ip.to_string(),
            port: up.port,
        })
    }) {
        return Err(ClientError::DeniedAddress);
    }
    Ok(Some(first))
}

/// The proxy url of `up`: its host, or `address` (the checked one) instead.
fn proxy_url(up: &UpstreamEndpoint, address: Option<IpAddr>) -> Option<Url> {
    let scheme = match up.scheme {
        UpstreamScheme::Http => "http",
        UpstreamScheme::Socks5 => "socks5h",
        // no proxy to point at: `local_client` handles it
        UpstreamScheme::Local => return None,
    };
    let mut url = Url::parse(&format!("{scheme}://localhost")).ok()?;
    // An IPv6 literal is stored without brackets; the url needs it as an IP host.
    match address.map_or_else(|| up.host.parse::<IpAddr>(), Ok) {
        Ok(ip) => url.set_ip_host(ip).ok()?,
        Err(_) => url.set_host(Some(&up.host)).ok()?,
    }
    url.set_port(Some(up.port)).ok()?;
    if !up.username.is_empty() {
        url.set_username(up.username.expose()).ok()?;
    }
    if !up.password.is_empty() {
        url.set_password(Some(up.password.expose())).ok()?;
    }
    Some(url)
}

/// A direct (no proxy) client for the reputation APIs. Their URLs and headers
/// carry the API key, so redirects are never followed.
pub(crate) fn direct_client(timeout: Duration) -> Result<Client, ClientError> {
    Ok(base_builder(timeout).build()?)
}

fn base_builder(timeout: Duration) -> ClientBuilder {
    Client::builder()
        .no_proxy()
        .timeout(timeout)
        .redirect(Policy::none())
        .user_agent(USER_AGENT)
}

/// Read at most `limit` bytes of the body, then stop (the rest is never
/// downloaded).
pub(crate) async fn read_capped(
    resp: &mut Response,
    limit: usize,
) -> Result<Vec<u8>, reqwest::Error> {
    let mut buf = Vec::with_capacity(limit.min(4096));
    while buf.len() < limit {
        let Some(chunk) = resp.chunk().await? else {
            break;
        };
        let take = chunk.len().min(limit - buf.len());
        buf.extend_from_slice(&chunk[..take]);
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Stub, upstream};

    #[tokio::test]
    async fn an_ipv6_upstream_builds_a_client_as_well_as_a_name_or_an_ipv4_one() {
        let mut up = upstream(&Stub::hanging());
        for host in ["::1", "2001:db8::1", "127.0.0.1", "proxy.example.com"] {
            up.host = host.to_owned();
            assert!(
                upstream_client(&up, Duration::from_secs(1), false)
                    .await
                    .is_ok(),
                "{host}"
            );
        }
    }

    /// A customer's upstream is checked like `dial` checks it,
    /// before any request goes through it: a name that resolves to a private
    /// address (here `localhost`) and private literals are refused, and the
    /// same hosts are fine for an upstream that is not `public_only`.
    #[tokio::test]
    async fn a_public_only_upstream_that_resolves_to_a_private_address_gets_no_client() {
        let mut up = upstream(&Stub::hanging());
        up.public_only = true;
        for host in [
            "localhost",
            "127.0.0.1",
            "10.1.2.3",
            "::1",
            "169.254.169.254",
        ] {
            up.host = host.to_owned();
            let err = upstream_client(&up, Duration::from_secs(1), false)
                .await
                .expect_err(host);
            assert!(matches!(err, ClientError::DeniedAddress), "{host}: {err}");
        }
        up.public_only = false;
        up.host = "localhost".to_owned();
        assert!(
            upstream_client(&up, Duration::from_secs(1), false)
                .await
                .is_ok()
        );
    }

    /// The client connects to the address that passed the check, not to a
    /// second resolution of the name.
    #[tokio::test]
    async fn the_proxy_url_of_a_checked_upstream_names_the_checked_address() {
        let mut up = upstream(&Stub::hanging());
        up.host = "proxy.customer.example".to_owned();
        let named = proxy_url(&up, None).expect("url");
        assert_eq!(named.host_str(), Some("proxy.customer.example"));
        let pinned = proxy_url(&up, Some("8.8.8.8".parse().expect("ip"))).expect("url");
        assert_eq!(pinned.host_str(), Some("8.8.8.8"));
        assert_eq!(pinned.username(), named.username());
    }
}

#[cfg(test)]
mod local_tests {
    use super::*;
    use crate::testutil::{local_upstream, peer_echo};

    async fn body_from(source: &str, fresh: bool) -> String {
        let echo = peer_echo();
        let client = upstream_client(&local_upstream(source), Duration::from_secs(5), fresh)
            .await
            .expect("client");
        client
            .get(format!("http://{echo}/"))
            .send()
            .await
            .expect("request")
            .text()
            .await
            .expect("body")
    }

    /// The request leaves from the unit's own address: the server sees it as
    /// the peer, with no proxy in between.
    #[tokio::test]
    async fn a_local_client_connects_from_the_bound_source_address() {
        for (source, fresh) in [("127.0.0.2", false), ("127.0.0.3", true)] {
            let body = body_from(source, fresh).await;
            assert!(body.contains(&format!(r#""ip":"{source}""#)), "{body}");
        }
    }

    /// An endpoint that is no unicast IP literal gets no client; the address
    /// would otherwise be a name resolved at connect time or the wildcard.
    #[tokio::test]
    async fn a_local_upstream_without_a_unicast_ip_literal_gets_no_client() {
        for host in ["localhost", "", "0.0.0.0", "::", "224.0.0.1", "ff02::1"] {
            let err = upstream_client(&local_upstream(host), Duration::from_secs(1), false)
                .await
                .expect_err(host);
            assert!(matches!(err, ClientError::BadUpstream), "{host}: {err}");
        }
    }

    /// A name that resolves only to private addresses is not connected to,
    /// whatever the target port serves (`localhost` is 127.0.0.1 and ::1).
    #[tokio::test]
    async fn a_local_client_refuses_names_that_resolve_to_internal_addresses() {
        let echo = peer_echo();
        let client = upstream_client(&local_upstream("127.0.0.2"), Duration::from_secs(5), false)
            .await
            .expect("client");
        let err = client
            .get(format!("http://localhost:{}/", echo.port()))
            .send()
            .await
            .expect_err("denied");
        assert!(err.is_connect(), "{err:?}");
    }
}
