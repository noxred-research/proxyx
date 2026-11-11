//! Bounded parent and chain probes over the same established transports as live traffic.

use super::*;

struct HttpTarget {
    target: Target,
    authority: String,
    path: String,
    tls: bool,
}

fn http_target(url: &str) -> Result<HttpTarget, String> {
    let uri = url
        .parse::<axum::http::Uri>()
        .map_err(|e| format!("probe URL: {e}"))?;
    let tls = match uri.scheme_str() {
        Some("http") => false,
        Some("https") => true,
        _ => return Err("probe URL must use http:// or https://".to_owned()),
    };
    let authority = uri
        .authority()
        .ok_or_else(|| "probe URL has no authority".to_owned())?;
    if authority.as_str().contains('@') {
        return Err("probe URL cannot contain credentials".to_owned());
    }
    let host = uri
        .host()
        .ok_or_else(|| "probe URL has no host".to_owned())?
        .trim_start_matches('[')
        .trim_end_matches(']');
    if host.is_empty() {
        return Err("probe URL has no host".to_owned());
    }
    Ok(HttpTarget {
        target: Target {
            host: host.to_owned(),
            port: uri.port_u16().unwrap_or(if tls { 443 } else { 80 }),
        },
        authority: authority.to_string(),
        path: uri.path_and_query().map_or("/", |p| p.as_str()).to_owned(),
        tls,
    })
}

pub fn check_probe(probe: &ProbeConfig) -> anyhow::Result<()> {
    match probe {
        ProbeConfig::Tcp { target } => {
            if split_host_port(target).is_none() {
                anyhow::bail!("probe target {target:?} is not host:port");
            }
        }
        ProbeConfig::Http {
            url,
            status,
            body_contains,
            max_body_bytes,
        } => {
            http_target(url).map_err(anyhow::Error::msg)?;
            if !(100..=599).contains(status) {
                anyhow::bail!("probe HTTP status must be between 100 and 599");
            }
            if *max_body_bytes == 0 || *max_body_bytes > 16 * 1024 * 1024 {
                anyhow::bail!("probe max_body_bytes must be between 1 and 16777216");
            }
            if body_contains
                .as_ref()
                .is_some_and(|s| s.len() > *max_body_bytes)
            {
                anyhow::bail!("probe body_contains exceeds max_body_bytes");
            }
        }
        ProbeConfig::Command { command } => {
            if command.first().is_none_or(String::is_empty) {
                anyhow::bail!("probe command needs an executable");
            }
        }
    }
    Ok(())
}

pub(in crate::connect) fn probe_key(host: &str) -> PickKey<'_> {
    PickKey {
        session: None,
        user: None,
        client: [0, 0, 0, 0].into(),
        target_host: host,
    }
}

/// Probe bypasses the chain verdict so a failed chain can recover.
pub async fn probe_chain(
    state: &State,
    chain: &Chain,
    budget: Duration,
) -> Result<(), ConnectError> {
    let Some(probe) = &chain.probe else {
        return Ok(());
    };
    let key = probe_key("");
    let parents = chain
        .hops
        .iter()
        .map(|hop| {
            hop.selector
                .choose_probe(&state.parents, &hop.parents, &key)
                .or_else(|| hop.parents.first().copied())
                .and_then(|i| state.parents.get(i).cloned())
                .ok_or(ConnectError::NoParent)
        })
        .collect::<Result<Vec<_>, _>>()?;
    execute_probe(state, &parents, probe, budget).await
}

pub(in crate::connect) async fn execute_probe(
    state: &State,
    parents: &[Arc<Parent>],
    probe: &ProbeConfig,
    budget: Duration,
) -> Result<(), ConnectError> {
    let work = async {
        if let ProbeConfig::Command { command } = probe {
            let executable = command.first().ok_or(ConnectError::NoParent)?;
            let mut process = tokio::process::Command::new(executable);
            process
                .args(&command[1..])
                .kill_on_drop(true)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .env(
                    "PROXYX_PARENT_CHAIN",
                    parents
                        .iter()
                        .map(|p| p.name.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                );
            let status = process.status().await.map_err(ConnectError::Connect)?;
            if !status.success() {
                return Err(ConnectError::Connect(io::Error::other(format!(
                    "probe command exited {status}"
                ))));
            }
            return Ok(());
        }
        let http = if let ProbeConfig::Http { url, .. } = probe {
            Some(http_target(url).map_err(|e| ConnectError::Connect(io::Error::other(e)))?)
        } else {
            None
        };
        let target = if let Some(http) = &http {
            http.target.clone()
        } else if let ProbeConfig::Tcp { target } = probe {
            let (host, port) = split_host_port(target).ok_or(ConnectError::NoParent)?;
            Target { host, port }
        } else {
            return Err(ConnectError::NoParent);
        };
        let first = parents.first().ok_or(ConnectError::NoParent)?;
        let addrs = state.resolver.resolve(&first.host).await?;
        let own = first.pool.as_ref().and_then(|n| state.pools.get(n));
        let default = state.default_pool();
        let key = probe_key(&target.host);
        let (tcp, _lease, _) = connect_ips(
            &addrs,
            first.port,
            own.or(default.as_ref()),
            &key,
            None,
            budget,
            &state.cfg.tcp.upstream,
        )
        .await?;
        let mut stream: ProxyStream = tcp.into();
        for (hop, parent) in parents.iter().enumerate() {
            let target = parents.get(hop + 1).map_or_else(
                || target.clone(),
                |p| Target {
                    host: p.host.clone(),
                    port: p.port,
                },
            );
            stream = handshake(stream, parent, &target).await?;
        }
        if let Some(http) = http {
            if http.tls {
                let mut endpoint = first.endpoint().clone();
                endpoint.host = http.target.host.clone();
                endpoint.port = http.target.port;
                endpoint.scheme = common::types::UpstreamScheme::Https;
                stream = dial::proxy_transport(stream, &endpoint)
                    .await
                    .map_err(|e| parent_error(first, e))?;
            }
            stream.write_all(format!("GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n",http.path,http.authority).as_bytes())
                .await.map_err(ConnectError::Connect)?;
            let mut pipe = crate::wire::Pipe::new(stream);
            let response = crate::wire::read_response_head(&mut pipe, 16384, budget)
                .await
                .map_err(|e| {
                    ConnectError::Connect(io::Error::other(format!("probe response: {e:?}")))
                })?;
            if let ProbeConfig::Http {
                status,
                body_contains,
                max_body_bytes,
                ..
            } = probe
            {
                if response.status != *status {
                    return Err(ConnectError::Connect(io::Error::other(format!(
                        "probe HTTP status {}, expected {status}",
                        response.status
                    ))));
                }
                if let Some(needle) = body_contains {
                    let framing =
                        crate::wire::response_framing(response.status, false, &response.headers)
                            .map_err(|e| ConnectError::Connect(io::Error::other(e)))?;
                    let (stream, prefix) = pipe.into_parts();
                    let mut input = std::io::Cursor::new(prefix).chain(stream);
                    let body = bounded_body(&mut input, framing, *max_body_bytes)
                        .await
                        .map_err(ConnectError::Connect)?;
                    if !needle.is_empty()
                        && !body
                            .windows(needle.len())
                            .any(|window| window == needle.as_bytes())
                    {
                        return Err(ConnectError::Connect(io::Error::other(
                            "probe body substring not found within bound",
                        )));
                    }
                }
            }
        }
        Ok(())
    };
    timeout(budget, work)
        .await
        .unwrap_or(Err(ConnectError::Timeout))
}

async fn line<R: AsyncRead + Unpin>(input: &mut R) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    loop {
        if line.len() >= 1024 {
            return Err(io::Error::other("probe chunk line too long"));
        }
        line.push(input.read_u8().await?);
        if line.ends_with(b"\r\n") {
            line.truncate(line.len() - 2);
            return Ok(line);
        }
    }
}

async fn bounded_body<R: AsyncRead + Unpin>(
    input: &mut R,
    framing: crate::wire::Framing,
    max: usize,
) -> io::Result<Vec<u8>> {
    use crate::wire::Framing;
    let mut body = Vec::with_capacity(max.min(8192));
    if framing == Framing::Chunked {
        while body.len() < max {
            let size = line(input).await?;
            let size = size
                .split(|b| *b == b';')
                .next()
                .ok_or_else(|| io::Error::other("probe chunk has no size"))?;
            let size = std::str::from_utf8(size).map_err(io::Error::other)?;
            let size = u64::from_str_radix(size.trim(), 16).map_err(io::Error::other)?;
            if size == 0 {
                break;
            }
            let remaining = max - body.len();
            let read = usize::try_from(size).unwrap_or(usize::MAX).min(remaining);
            let start = body.len();
            body.resize(start + read, 0);
            input.read_exact(&mut body[start..]).await?;
            if size > read as u64 {
                break;
            }
            let mut crlf = [0; 2];
            input.read_exact(&mut crlf).await?;
            if crlf != *b"\r\n" {
                return Err(io::Error::other("probe chunk has no CRLF"));
            }
        }
    } else {
        let limit = match framing {
            Framing::None => 0,
            Framing::Length(n) => n.min(max as u64),
            _ => max as u64,
        };
        input.take(limit).read_to_end(&mut body).await?;
    }
    Ok(body)
}
