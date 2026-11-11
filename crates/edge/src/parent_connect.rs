//! Parent selection, chain handshakes and connection-lifetime accounting.

use super::*;

/// Poll a bounded set of dials together; dropping losers closes their sockets.
pub(super) async fn first_success<F, T>(futures: Vec<F>) -> Result<T, ConnectError>
where
    F: Future<Output = Result<T, ConnectError>>,
{
    let mut pending: Vec<_> = futures.into_iter().map(|f| Some(Box::pin(f))).collect();
    let mut last = None;
    poll_fn(move |cx| {
        let mut active = false;
        for slot in &mut pending {
            let Some(future) = slot.as_mut() else {
                continue;
            };
            match future.as_mut().poll(cx) {
                Poll::Ready(Ok(value)) => return Poll::Ready(Ok(value)),
                Poll::Ready(Err(error)) => {
                    last = Some(error);
                    *slot = None;
                }
                Poll::Pending => active = true,
            }
        }
        if active {
            Poll::Pending
        } else {
            Poll::Ready(Err(last.take().unwrap_or(ConnectError::NoParent)))
        }
    })
    .await
}

fn parent_error(parent: &Parent, error: impl std::fmt::Display) -> ConnectError {
    ConnectError::Parent {
        name: parent.name.clone(),
        reason: error.to_string(),
    }
}

pub(super) async fn handshake(
    stream: ProxyStream,
    parent: &Parent,
    target: &Target,
) -> Result<ProxyStream, ConnectError> {
    handshake_classified(stream, parent, target)
        .await
        .map_err(|(error, _)| error)
}

/// A proxy that answered "next hop unreachable" is not itself a failed node.
async fn handshake_classified(
    stream: ProxyStream,
    parent: &Parent,
    target: &Target,
) -> Result<ProxyStream, (ConnectError, bool)> {
    if parent.kind != ParentKind::Socks4 {
        return dial::handshake(stream, parent.endpoint(), target)
            .await
            .map_err(|error| {
                let downstream = matches!(
                    &error,
                    DialError::Status(502..=504) | DialError::SocksReply(3..=6)
                );
                (parent_error(parent, error), downstream)
            });
    }
    let mut stream = stream;
    let user = parent.endpoint().username.expose();
    if user.as_bytes().contains(&0) || target.host.as_bytes().contains(&0) {
        return Err((
            parent_error(parent, "SOCKS4 user or target contains NUL"),
            false,
        ));
    }
    let address = target.host.parse::<std::net::Ipv4Addr>().ok();
    let mut request = Vec::with_capacity(10 + user.len() + target.host.len());
    request.extend_from_slice(&[4, 1]);
    request.extend_from_slice(&target.port.to_be_bytes());
    request.extend_from_slice(&address.map_or([0, 0, 0, 1], |a| a.octets()));
    request.extend_from_slice(user.as_bytes());
    request.push(0);
    if address.is_none() {
        request.extend_from_slice(target.host.as_bytes());
        request.push(0);
    }
    stream
        .write_all(&request)
        .await
        .map_err(|e| (parent_error(parent, e), false))?;
    let mut reply = [0; 8];
    stream
        .read_exact(&mut reply)
        .await
        .map_err(|e| (parent_error(parent, e), false))?;
    if reply[0] != 0 || reply[1] != 90 {
        return Err((
            parent_error(parent, format!("SOCKS4 CONNECT refused ({})", reply[1])),
            reply[0] == 0 && reply[1] == 91,
        ));
    }
    Ok(stream)
}

fn sticky_key(plan: &Plan<'_>, namespace: &str) -> String {
    use base64::Engine as _;
    use sha2::{Digest as _, Sha256};
    let key = plan.key.hash_bytes(if plan.key.session.is_some() {
        HashKey::SessionId
    } else if plan.key.user.is_some() {
        HashKey::User
    } else {
        HashKey::ClientIp
    });
    let mut hash = Sha256::new();
    hash.update(namespace.as_bytes());
    hash.update(key);
    if let Some(user) = plan.key.user {
        hash.update(u64::try_from(user.len()).unwrap_or(u64::MAX).to_be_bytes());
        hash.update(user.as_bytes());
    }
    hash.update(
        u64::try_from(plan.index.unwrap_or(0))
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    hash.update(pool_label(plan.pool).as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash.finalize())
}

pub(super) async fn direct_index(
    state: &State,
    plan: &Plan<'_>,
) -> Result<Option<usize>, ConnectError> {
    let Some(pool) = plan.pool else {
        return Ok(plan.index);
    };
    if state.cfg.selector.strategy != Strategy::Sticky && pool.strategy() != Strategy::Sticky {
        return Ok(plan.index);
    }
    let mut candidate = None;
    let mut error = ConnectError::NoAddressOfFamily;
    for &ip in plan.ips {
        match pool.pick(Family::of(ip), &plan.key, plan.index, &[]) {
            Ok(lease) => {
                candidate = Some(lease.ip());
                break;
            }
            Err(PickError::BadIndex) => error = ConnectError::BadIndex,
            Err(PickError::Unavailable) => error = ConnectError::EgressUnavailable,
            Err(PickError::NoAddressOfFamily) => {}
        }
    }
    let ip = candidate.ok_or(error)?;
    // Routed prefixes are deterministic by key but have no finite explicit index to replicate.
    if pool.index_of(ip).is_none() {
        return Ok(plan.index);
    }
    let mapping = state
        .stick
        .claim(
            &sticky_key(plan, "direct"),
            Mapping {
                parents: Vec::new(),
                egress: Some(ip),
            },
            |mapping| {
                mapping.parents.is_empty()
                    && mapping.egress.is_some_and(|ip| {
                        plan.ips
                            .iter()
                            .any(|target| Family::of(*target) == Family::of(ip))
                            && pool.index_of(ip).is_some_and(|index| {
                                (plan.index.is_none() || plan.index == Some(index))
                                    && pool
                                        .pick(Family::of(ip), &plan.key, Some(index), &[])
                                        .is_ok()
                            })
                    })
            },
        )
        .await
        .map_err(ConnectError::Stick)?;
    Ok(mapping.egress.and_then(|ip| pool.index_of(ip)))
}

/// Claims include an exact egress IP for explicit-address pools, not unbounded prefixes.
async fn claim_path(
    state: &State,
    plan: &Plan<'_>,
    namespace: &str,
    path: &[usize],
    allowed: &[Vec<usize>],
    excluded: &[usize],
) -> Result<(Vec<usize>, Option<usize>), ConnectError> {
    let first = path
        .first()
        .and_then(|&i| state.parents.get(i))
        .ok_or(ConnectError::NoParent)?;
    let pool = first
        .pool
        .as_ref()
        .and_then(|n| state.pools.get(n))
        .or(plan.pool);
    let egress = if let Some(pool) = pool {
        let addrs = state.resolver.resolve(&first.host).await?;
        let mut selected = None;
        let mut error = ConnectError::NoAddressOfFamily;
        for ip in addrs {
            match pool.pick(Family::of(ip), &plan.key, plan.index, &[]) {
                Ok(lease) => {
                    selected = Some(lease);
                    break;
                }
                Err(PickError::NoAddressOfFamily) => {}
                Err(PickError::Unavailable) => error = ConnectError::EgressUnavailable,
                Err(PickError::BadIndex) => error = ConnectError::BadIndex,
            }
        }
        let lease = selected.ok_or(error)?;
        pool.index_of(lease.ip()).map(|_| lease.ip())
    } else {
        None
    };
    let proposal = Mapping {
        parents: path
            .iter()
            .filter_map(|&i| state.parents.get(i).map(|p| p.name.clone()))
            .collect(),
        egress,
    };
    let mapping = state
        .stick
        .claim(&sticky_key(plan, namespace), proposal, |mapping| {
            mapping.parents.len() == allowed.len()
                && mapping.parents.iter().enumerate().all(|(hop, name)| {
                    state.parents.index_of(name).is_some_and(|i| {
                        !excluded.contains(&i)
                            && (allowed[hop].is_empty() || allowed[hop].contains(&i))
                            && state.parents.get(i).is_some_and(|p| !p.is_down())
                    })
                })
                && mapping.egress.is_none_or(|ip| {
                    let pool = mapping
                        .parents
                        .first()
                        .and_then(|name| state.parents.index_of(name))
                        .and_then(|i| state.parents.get(i))
                        .and_then(|p| p.pool.as_ref())
                        .and_then(|name| state.pools.get(name))
                        .or(plan.pool);
                    pool.is_some_and(|pool| {
                        pool.index_of(ip).is_some_and(|index| {
                            (plan.index.is_none() || plan.index == Some(index))
                                && pool
                                    .pick(Family::of(ip), &plan.key, Some(index), &[])
                                    .is_ok()
                        })
                    })
                })
        })
        .await
        .map_err(ConnectError::Stick)?;
    let path = mapping
        .parents
        .iter()
        .map(|name| state.parents.index_of(name).ok_or(ConnectError::NoParent))
        .collect::<Result<Vec<_>, _>>()?;
    let pool = path
        .first()
        .and_then(|&i| state.parents.get(i))
        .and_then(|p| p.pool.as_ref())
        .and_then(|name| state.pools.get(name))
        .or(plan.pool);
    let index = mapping
        .egress
        .and_then(|ip| pool.and_then(|pool| pool.index_of(ip)))
        .or(plan.index);
    Ok((path, index))
}

fn pinned_path(
    state: &State,
    plan: &Plan<'_>,
    groups: &[Vec<usize>],
) -> Result<Option<Vec<usize>>, ConnectError> {
    let Some(names) = plan.pinned.filter(|p| !p.is_empty()) else {
        return Ok(None);
    };
    if names.len() != groups.len() {
        return Err(ConnectError::NoParent);
    }
    names
        .iter()
        .enumerate()
        .map(|(hop, name)| {
            let index = state.parents.index_of(name).ok_or(ConnectError::NoParent)?;
            if !groups[hop].is_empty() && !groups[hop].contains(&index) {
                return Err(ConnectError::NoParent);
            }
            if state.parents.get(index).is_none_or(|p| p.is_down()) {
                return Err(ConnectError::NoParent);
            }
            Ok(index)
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

pub(super) async fn connect_group(
    state: &State,
    metrics: &Metrics,
    idle: &ParentConns,
    budget: Duration,
    plan: &Plan<'_>,
    selector: &Selector,
) -> Result<Upstream, ConnectError> {
    let groups = vec![plan.parents.to_vec()];
    let pinned = pinned_path(state, plan, &groups)?;
    let mut tried = Vec::new();
    let mut last = ConnectError::NoParent;
    for _ in 0..=selector.cfg.connect_retries {
        let Some(index) = pinned
            .as_ref()
            .and_then(|p| p.first().copied())
            .or_else(|| selector.choose(&state.parents, plan.parents, &tried, &plan.key))
        else {
            break;
        };
        let mut candidates = vec![index];
        if pinned.is_none() && selector.cfg.strategy == Strategy::Race {
            candidates.extend(
                state
                    .parents
                    .candidates(plan.parents, &tried)
                    .into_iter()
                    .filter(|i| *i != index)
                    .take(selector.cfg.race_width.saturating_sub(1)),
            );
        }
        let mut index_override = plan.index;
        if pinned.is_none() && selector.cfg.strategy == Strategy::Sticky {
            let mut names: Vec<_> = plan
                .parents
                .iter()
                .filter_map(|&i| state.parents.get(i).map(|p| p.name.as_str()))
                .collect();
            names.sort_unstable();
            let namespace = format!("parents:{names:?}");
            let (path, index) =
                claim_path(state, plan, &namespace, &candidates[..1], &groups, &tried).await?;
            candidates = path;
            index_override = index;
        }
        let local_plan = Plan {
            index: index_override,
            ..*plan
        };
        let result = first_success(
            candidates
                .iter()
                .filter_map(|&i| state.parents.get(i))
                .map(|parent| via_parent(state, metrics, idle, budget, &local_plan, parent))
                .collect(),
        )
        .await;
        match result {
            Ok(mut up) => {
                if !up.reused {
                    let parents = up.parent.iter().cloned().collect();
                    let switch = up
                        .parent
                        .as_ref()
                        .and_then(|parent| state.parents.index_of(&parent.name))
                        .and_then(|index| selector.token_for(index));
                    up.stream = monitored(up.stream, parents, switch.into_iter().collect());
                }
                return Ok(up);
            }
            Err(error) => last = error,
        }
        if pinned.is_some() {
            break;
        }
        tried.extend(candidates);
    }
    Err(last)
}

pub(super) async fn connect_chain(
    state: &State,
    metrics: &Metrics,
    idle: &ParentConns,
    budget: Duration,
    plan: &Plan<'_>,
    chain: &Chain,
) -> Result<Upstream, ConnectError> {
    if !chain.health.is_healthy() {
        return Err(ConnectError::NoParent);
    }
    let groups: Vec<_> = chain.hops.iter().map(|h| h.parents.clone()).collect();
    let pinned = pinned_path(state, plan, &groups)?;
    let retries = chain
        .hops
        .iter()
        .map(|h| h.selector.cfg.connect_retries)
        .max()
        .unwrap_or(0);
    let mut excluded = Vec::new();
    let mut last = ConnectError::NoParent;
    for _ in 0..=retries {
        let mut paths = vec![Vec::with_capacity(chain.hops.len())];
        if let Some(path) = &pinned {
            paths = vec![path.clone()];
        } else {
            for hop in &chain.hops {
                let Some(index) =
                    hop.selector
                        .choose(&state.parents, &hop.parents, &excluded, &plan.key)
                else {
                    return Err(last);
                };
                let mut candidates = vec![index];
                if hop.selector.cfg.strategy == Strategy::Race {
                    candidates.extend(
                        state
                            .parents
                            .candidates(&hop.parents, &excluded)
                            .into_iter()
                            .filter(|i| *i != index)
                            .take(hop.selector.cfg.race_width.saturating_sub(1)),
                    );
                }
                let mut next = Vec::new();
                for path in &paths {
                    for &index in &candidates {
                        if next.len() == 64 {
                            break;
                        }
                        let mut path = path.clone();
                        path.push(index);
                        next.push(path);
                    }
                }
                paths = next;
            }
        }
        let mut index = plan.index;
        if pinned.is_none() {
            for (hop_index, hop) in chain.hops.iter().enumerate() {
                if hop.selector.cfg.strategy != Strategy::Sticky {
                    continue;
                }
                let namespace = format!("chain:{}:hop:{hop_index}", chain.name);
                let selected = paths[0][hop_index];
                let selected = if hop_index == 0 {
                    let (claimed, claimed_index) = claim_path(
                        state,
                        plan,
                        &namespace,
                        &[selected],
                        std::slice::from_ref(&hop.parents),
                        &excluded,
                    )
                    .await?;
                    index = claimed_index;
                    claimed[0]
                } else {
                    let parent = state.parents.get(selected).ok_or(ConnectError::NoParent)?;
                    let mapping = state
                        .stick
                        .claim(
                            &sticky_key(plan, &namespace),
                            Mapping {
                                parents: vec![parent.name.clone()],
                                egress: None,
                            },
                            |mapping| {
                                mapping.egress.is_none()
                                    && mapping.parents.len() == 1
                                    && state.parents.index_of(&mapping.parents[0]).is_some_and(
                                        |i| {
                                            hop.parents.contains(&i)
                                                && !excluded.contains(&i)
                                                && state
                                                    .parents
                                                    .get(i)
                                                    .is_some_and(|p| !p.is_down())
                                        },
                                    )
                            },
                        )
                        .await
                        .map_err(ConnectError::Stick)?;
                    state
                        .parents
                        .index_of(&mapping.parents[0])
                        .ok_or(ConnectError::NoParent)?
                };
                for path in &mut paths {
                    path[hop_index] = selected;
                }
            }
        }
        let local_plan = Plan { index, ..*plan };
        let result = first_success(
            paths
                .iter()
                .map(|path| via_path(state, metrics, idle, budget, &local_plan, path))
                .collect(),
        )
        .await;
        match result {
            Ok(mut up) => {
                if !up.reused {
                    let parents = up
                        .chain
                        .iter()
                        .filter_map(|name| state.parents.index_of(name))
                        .filter_map(|i| state.parents.get(i).cloned())
                        .collect();
                    let tokens = chain
                        .hops
                        .iter()
                        .zip(&up.chain)
                        .filter_map(|(hop, name)| {
                            state
                                .parents
                                .index_of(name)
                                .and_then(|index| hop.selector.token_for(index))
                        })
                        .collect();
                    up.stream = monitored(up.stream, parents, tokens);
                }
                return Ok(up);
            }
            Err(error) => {
                if let ConnectError::Parent { name, .. } = &error
                    && let Some(index) = state.parents.index_of(name)
                {
                    excluded.push(index);
                }
                last = error;
            }
        }
        if pinned.is_some() {
            break;
        }
    }
    Err(last)
}

async fn via_path(
    state: &State,
    metrics: &Metrics,
    idle: &ParentConns,
    budget: Duration,
    plan: &Plan<'_>,
    indexes: &[usize],
) -> Result<Upstream, ConnectError> {
    let parents = indexes
        .iter()
        .map(|&i| state.parents.get(i).cloned().ok_or(ConnectError::NoParent))
        .collect::<Result<Vec<_>, _>>()?;
    let first = parents.first().ok_or(ConnectError::NoParent)?;
    let last = parents.last().ok_or(ConnectError::NoParent)?;
    let pool = first
        .pool
        .as_ref()
        .and_then(|n| state.pools.get(n))
        .or(plan.pool);
    let http_proxy =
        plan.mode == Mode::Http && matches!(last.kind, ParentKind::Http | ParentKind::Https);
    let names: Vec<_> = parents.iter().map(|p| p.name.clone()).collect();
    let reuse_key = (http_proxy
        && plan.reuse
        && state.cfg.http.parent_keepalive
        && parents
            .iter()
            .all(|p| p.send_proxy_protocol == SendProxyProtocol::Off))
    .then(|| parent_reuse_key(state, plan, &parents, pool));
    if let Some(key) = &reuse_key {
        if let Some((stream, lease, peer, bound_addr)) = idle.take(key) {
            let attempts = parents
                .iter()
                .map(|parent| Attempt::start(parent).ok_or(ConnectError::NoParent))
                .collect::<Result<Vec<_>, _>>()?;
            for (hop, attempt) in attempts.into_iter().enumerate() {
                if hop + 1 == parents.len() {
                    attempt.defer_http(true);
                } else {
                    attempt.finish(true);
                }
            }
            metrics
                .parent_conn_reuse_total
                .with_label_values(&["reused"])
                .inc();
            return Ok(Upstream {
                stream,
                bound_addr,
                chain: names,
                lease,
                parent: Some(Arc::clone(last)),
                peer,
                http_proxy,
                reuse_key,
                reused: true,
            });
        }
        metrics
            .parent_conn_reuse_total
            .with_label_values(&["new"])
            .inc();
    }
    let mut in_flight = Arc::clone(first);
    let work = async {
        let first_attempt = Attempt::start(first).ok_or(ConnectError::NoParent)?;
        let addrs = match state.resolver.resolve(&first.host).await {
            Ok(addrs) => addrs,
            Err(error) => {
                first_attempt.finish(false);
                return Err(parent_error(first, error));
            }
        };
        let tcp = connect_ips(
            &addrs,
            first.port,
            pool,
            &plan.key,
            plan.index,
            budget,
            &state.cfg.tcp.upstream,
        )
        .await;
        let (tcp, lease, peer) = match tcp {
            Ok(value) => value,
            Err(error) => {
                if matches!(
                    error,
                    ConnectError::NoAddressOfFamily
                        | ConnectError::EgressUnavailable
                        | ConnectError::BadIndex
                ) {
                    drop(first_attempt);
                } else {
                    first_attempt.finish(false);
                }
                return Err(parent_error(first, error));
            }
        };
        let bound_addr = tcp.local_addr().ok();
        let mut stream: ProxyStream = tcp.into();
        let mut first_attempt = Some(first_attempt);
        for (hop, parent) in parents.iter().enumerate() {
            in_flight = Arc::clone(parent);
            let attempt = if hop == 0 {
                first_attempt.take()
            } else {
                Attempt::start(parent)
            }
            .ok_or(ConnectError::NoParent)?;
            if parent.send_proxy_protocol != SendProxyProtocol::Off {
                let dst = if hop == 0 {
                    SocketAddr::new(peer, parent.port)
                } else {
                    let ips = state.resolver.resolve(&parent.host).await?;
                    SocketAddr::new(
                        *ips.first().ok_or(ConnectError::NoAddressOfFamily)?,
                        parent.port,
                    )
                };
                let header = match parent.send_proxy_protocol {
                    SendProxyProtocol::V1 => proxy_protocol::encode_v1(plan.client, dst),
                    _ => proxy_protocol::encode_v2(plan.client, dst),
                };
                if let Err(error) = stream.write_all(&header).await {
                    attempt.finish(false);
                    return Err(parent_error(parent, error));
                }
            }
            let target = match parents.get(hop + 1) {
                Some(next) => Target {
                    host: next.host.clone(),
                    port: next.port,
                },
                None => plan.target()?,
            };
            let result = if hop + 1 == parents.len() && http_proxy {
                dial::proxy_transport(stream, parent.endpoint())
                    .await
                    .map_err(|e| (parent_error(parent, e), false))
            } else {
                handshake_classified(stream, parent, &target).await
            };
            match result {
                Ok(next) => {
                    if hop + 1 == parents.len() && http_proxy {
                        attempt.defer_http(false);
                    } else {
                        attempt.finish(true);
                    }
                    stream = next;
                }
                Err((error, downstream)) => {
                    if downstream && let Some(next) = parents.get(hop + 1) {
                        attempt.finish(true);
                        next.failed_attempt();
                        return Err(parent_error(next, error));
                    }
                    attempt.finish(false);
                    return Err(error);
                }
            }
            metrics
                .parent_requests_total
                .with_label_values(&[&parent.name, "ok"])
                .inc();
        }
        Ok(Upstream {
            stream,
            bound_addr,
            chain: names,
            lease,
            parent: Some(Arc::clone(last)),
            peer,
            http_proxy,
            reuse_key,
            reused: false,
        })
    };
    match timeout(budget, work).await {
        Ok(result) => result,
        Err(_) => {
            in_flight.failed_attempt();
            Err(parent_error(&in_flight, "connect timed out"))
        }
    }
}

struct MonitoredStream {
    stream: ProxyStream,
    parents: ParentUse,
    switches: Vec<Pin<Box<tokio_util::sync::WaitForCancellationFutureOwned>>>,
    failed: bool,
}

impl MonitoredStream {
    fn interrupted(&mut self, cx: &mut Context<'_>) -> bool {
        self.switches
            .iter_mut()
            .any(|stop| stop.as_mut().poll(cx).is_ready())
    }
    fn observe<T>(&mut self, result: &Poll<io::Result<T>>) {
        if !self.failed
            && matches!(result,Poll::Ready(Err(e)) if e.kind()!=io::ErrorKind::WouldBlock)
        {
            self.failed = true;
            self.parents.failed();
        }
    }
}

impl AsyncRead for MonitoredStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.interrupted(cx) {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::ConnectionAborted)));
        }
        let result = Pin::new(&mut this.stream).poll_read(cx, buf);
        this.observe(&result);
        result
    }
}
impl AsyncWrite for MonitoredStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.interrupted(cx) {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::ConnectionAborted)));
        }
        let result = Pin::new(&mut this.stream).poll_write(cx, buf);
        this.observe(&result);
        result
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.interrupted(cx) {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::ConnectionAborted)));
        }
        let result = Pin::new(&mut this.stream).poll_flush(cx);
        this.observe(&result);
        result
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

fn monitored(
    stream: ProxyStream,
    parents: Vec<Arc<Parent>>,
    tokens: Vec<tokio_util::sync::CancellationToken>,
) -> ProxyStream {
    ProxyStream::new(MonitoredStream {
        stream,
        parents: ParentUse::new(parents),
        switches: tokens
            .into_iter()
            .map(|token| Box::pin(token.cancelled_owned()))
            .collect(),
        failed: false,
    })
}

#[path = "parent_probe.rs"]
mod probe;
pub use probe::{check_probe, probe_chain};
pub(super) use probe::{execute_probe, probe_key};
