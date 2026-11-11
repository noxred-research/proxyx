//! What every request goes through, whatever its wire protocol: login,
//! access rules, destination check, limits, egress choice, connect.
//!
//! The protocol modules (`http`, `socks`) parse their wire format, call
//! [`authenticate`] and [`open`], and turn a [`Refusal`] into their own
//! error reply.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::SystemTime;

use common::types::Target;
use parking_lot::RwLock;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::accesslog::{AccessLog, AccessRecord};
use crate::acl::{Clock, Proto, Req};
use crate::auth::{AuthError, FailLimiter, Login};
use crate::config::{Action, ListenerAuth};
use crate::connect::{self, ConnectError, Mode, ParentConns, Plan};
use crate::egress::{Lease, PickKey};
use crate::limits::{Admission, ConnCounters, CountGuard, Reject};
use crate::metrics::Metrics;
use crate::parent::Parent;
use crate::state::{EgressError, ListenerRt, State};

/// Process-wide state shared by every connection.
pub struct Shared {
    state: RwLock<Arc<State>>,
    pub metrics: Arc<Metrics>,
    pub conns: Arc<ConnCounters>,
    /// Idle keep-alive connections to HTTP parents.
    pub parent_conns: ParentConns,
    access_log: RwLock<Arc<AccessLog>>,
    fail: RwLock<Arc<FailLimiter>>,
    pub shutdown: CancellationToken,
    pub tracker: TaskTracker,
}

impl Shared {
    pub fn new(state: Arc<State>, access_log: AccessLog, metrics: Arc<Metrics>) -> Arc<Self> {
        let fail = FailLimiter::new(state.cfg.auth.fail_limit, state.cfg.auth.fail_window);
        let conns = ParentConns::default();
        conns.configure(
            state.cfg.http.parent_idle_timeout,
            state.cfg.http.parent_max_idle,
        );
        Arc::new(Self {
            state: RwLock::new(state),
            metrics,
            conns: Arc::new(ConnCounters::default()),
            parent_conns: conns,
            access_log: RwLock::new(Arc::new(access_log)),
            fail: RwLock::new(Arc::new(fail)),
            shutdown: CancellationToken::new(),
            tracker: TaskTracker::new(),
        })
    }

    pub fn state(&self) -> Arc<State> {
        Arc::clone(&self.state.read())
    }

    pub fn set_state(&self, new: Arc<State>) {
        let old = self.state();
        if old.cfg.auth.fail_limit != new.cfg.auth.fail_limit
            || old.cfg.auth.fail_window != new.cfg.auth.fail_window
        {
            *self.fail.write() = Arc::new(FailLimiter::new(
                new.cfg.auth.fail_limit,
                new.cfg.auth.fail_window,
            ));
        }
        self.parent_conns.configure(
            new.cfg.http.parent_idle_timeout,
            new.cfg.http.parent_max_idle,
        );
        *self.state.write() = new;
    }

    pub fn access_log(&self) -> Arc<AccessLog> {
        Arc::clone(&self.access_log.read())
    }

    pub fn set_access_log(&self, log: AccessLog) {
        *self.access_log.write() = Arc::new(log);
    }

    pub fn fail_limiter(&self) -> Arc<FailLimiter> {
        Arc::clone(&self.fail.read())
    }

    /// Write one access log line and count the bytes.
    pub fn log(&self, rec: AccessRecord) {
        self.metrics
            .requests_total
            .with_label_values(&[&rec.listener, rec.protocol, rec.result])
            .inc();
        if rec.bytes_up != 0 {
            self.metrics
                .bytes_total
                .with_label_values(&[&rec.listener, "up"])
                .inc_by(rec.bytes_up);
        }
        if rec.bytes_down != 0 {
            self.metrics
                .bytes_total
                .with_label_values(&[&rec.listener, "down"])
                .inc_by(rec.bytes_down);
        }
        self.access_log().log(rec);
    }
}

/// Why a request was not served.
#[derive(Debug)]
pub enum RefusalKind {
    /// An access rule denied it (or none allowed it).
    Forbidden,
    /// The destination is private or internal.
    DestinationDenied,
    /// The login asks for an option the user may not use.
    OptionDenied,
    LimitConnections,
    LimitRate,
    Dns(String),
    Connect(ConnectError),
    Internal,
}

#[derive(Debug)]
pub struct Refusal {
    pub kind: RefusalKind,
    pub rule: Option<String>,
}

impl Refusal {
    fn of(kind: RefusalKind) -> Self {
        Self { kind, rule: None }
    }

    pub fn status(&self) -> u16 {
        match &self.kind {
            RefusalKind::Forbidden | RefusalKind::DestinationDenied | RefusalKind::OptionDenied => {
                403
            }
            RefusalKind::LimitConnections | RefusalKind::LimitRate => 429,
            RefusalKind::Dns(_) => 502,
            RefusalKind::Connect(ConnectError::Timeout) => 504,
            RefusalKind::Connect(ConnectError::NoParent | ConnectError::EgressUnavailable) => 503,
            RefusalKind::Connect(ConnectError::BadIndex) => 403,
            RefusalKind::Connect(_) => 502,
            RefusalKind::Internal => 500,
        }
    }

    /// The closed word used as the metric and log `result`.
    pub fn result(&self) -> &'static str {
        match &self.kind {
            RefusalKind::Forbidden | RefusalKind::DestinationDenied | RefusalKind::OptionDenied => {
                "denied"
            }
            RefusalKind::LimitConnections | RefusalKind::LimitRate => "limited",
            RefusalKind::Dns(_) => "dns_error",
            RefusalKind::Connect(ConnectError::Timeout) => "timeout",
            RefusalKind::Connect(ConnectError::Parent { .. } | ConnectError::NoParent) => {
                "parent_error"
            }
            RefusalKind::Connect(_) => "connect_error",
            RefusalKind::Internal => "internal",
        }
    }

    /// Machine-readable word for the `X-ProxyX-Error` header.
    pub fn code(&self) -> &'static str {
        match &self.kind {
            RefusalKind::Forbidden => "forbidden",
            RefusalKind::DestinationDenied => "destination_denied",
            RefusalKind::OptionDenied => "option_denied",
            RefusalKind::LimitConnections => "too_many_connections",
            RefusalKind::LimitRate => "rate_limited",
            RefusalKind::Dns(_) => "dns_error",
            RefusalKind::Connect(ConnectError::Timeout) => "connect_timeout",
            RefusalKind::Connect(ConnectError::NoParent) => "no_parent",
            RefusalKind::Connect(ConnectError::Parent { .. }) => "parent_error",
            RefusalKind::Connect(ConnectError::BadIndex) => "option_denied",
            RefusalKind::Connect(ConnectError::NoAddressOfFamily) => "no_egress_address",
            RefusalKind::Connect(ConnectError::EgressUnavailable) => "egress_unavailable",
            RefusalKind::Connect(_) => "connect_failed",
            RefusalKind::Internal => "internal",
        }
    }

    /// SOCKS5 reply code (RFC 1928 6).
    pub fn socks5_reply(&self) -> u8 {
        match &self.kind {
            RefusalKind::Forbidden
            | RefusalKind::DestinationDenied
            | RefusalKind::OptionDenied
            | RefusalKind::LimitConnections
            | RefusalKind::LimitRate => 0x02,
            RefusalKind::Dns(_) => 0x04,
            RefusalKind::Connect(ConnectError::Connect(e)) => match e.kind() {
                std::io::ErrorKind::ConnectionRefused => 0x05,
                std::io::ErrorKind::NetworkUnreachable => 0x03,
                std::io::ErrorKind::TimedOut => 0x06,
                _ => 0x04,
            },
            RefusalKind::Connect(ConnectError::Timeout) => 0x06,
            RefusalKind::Connect(ConnectError::BadIndex) => 0x02,
            RefusalKind::Connect(ConnectError::EgressUnavailable) => 0x03,
            RefusalKind::Connect(_) | RefusalKind::Internal => 0x01,
        }
    }

    /// A short reason for the response body and the log.
    pub fn message(&self) -> String {
        match &self.kind {
            RefusalKind::Forbidden => "request not allowed by the access rules".into(),
            RefusalKind::DestinationDenied => "destination is private or internal".into(),
            RefusalKind::OptionDenied => "login option not allowed for this user".into(),
            RefusalKind::LimitConnections => "too many connections".into(),
            RefusalKind::LimitRate => "request rate limit exceeded".into(),
            RefusalKind::Dns(e) => e.clone(),
            RefusalKind::Connect(e) => e.to_string(),
            RefusalKind::Internal => "internal error".into(),
        }
    }
}

/// Why a login did not pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginFailure {
    /// No credentials were sent (the client has not tried yet).
    Missing,
    /// The source failed too many logins recently.
    Blocked,
    Invalid,
    OptionDenied,
    ListenerDenied,
}

impl LoginFailure {
    fn reason(self) -> &'static str {
        match self {
            LoginFailure::Missing => "missing",
            LoginFailure::Blocked => "blocked",
            LoginFailure::Invalid => "invalid",
            LoginFailure::OptionDenied => "option_denied",
            LoginFailure::ListenerDenied => "listener_denied",
        }
    }
}

/// Check the credentials a client sent on `listener`. `None` login for a
/// listener without authentication. Counts failures per source.
pub async fn authenticate(
    shared: &Shared,
    state: &State,
    listener: &ListenerRt,
    client: IpAddr,
    creds: Option<(&str, &str)>,
) -> Result<Option<Login>, LoginFailure> {
    if listener.cfg.auth == ListenerAuth::None {
        return Ok(None);
    }
    let Some((user, pass)) = creds else {
        return Err(LoginFailure::Missing);
    };
    let fail = shared.fail_limiter();
    if fail.blocked(client) {
        count_failure(shared, listener, LoginFailure::Blocked);
        return Err(LoginFailure::Blocked);
    }
    match state.users.verify(user, pass, &listener.cfg.name).await {
        Ok(l) => Ok(Some(l)),
        Err(e) => {
            let f = match e {
                AuthError::Invalid => {
                    fail.record(client);
                    LoginFailure::Invalid
                }
                AuthError::OptionDenied => LoginFailure::OptionDenied,
                AuthError::ListenerDenied => LoginFailure::ListenerDenied,
            };
            count_failure(shared, listener, f);
            Err(f)
        }
    }
}

/// SOCKS4: the user id is the whole login.
pub fn authenticate_userid(
    shared: &Shared,
    state: &State,
    listener: &ListenerRt,
    client: IpAddr,
    userid: &str,
) -> Result<Option<Login>, LoginFailure> {
    if listener.cfg.auth == ListenerAuth::None {
        return Ok(None);
    }
    let fail = shared.fail_limiter();
    if fail.blocked(client) {
        count_failure(shared, listener, LoginFailure::Blocked);
        return Err(LoginFailure::Blocked);
    }
    state
        .users
        .verify_userid(userid, &listener.cfg.name)
        .map(Some)
        .map_err(|e| {
            let f = match e {
                AuthError::Invalid => {
                    fail.record(client);
                    LoginFailure::Invalid
                }
                AuthError::OptionDenied => LoginFailure::OptionDenied,
                AuthError::ListenerDenied => LoginFailure::ListenerDenied,
            };
            count_failure(shared, listener, f);
            f
        })
}

fn count_failure(shared: &Shared, listener: &ListenerRt, f: LoginFailure) {
    shared
        .metrics
        .auth_failures_total
        .with_label_values(&[&listener.cfg.name, f.reason()])
        .inc();
}

/// A request to serve.
pub struct ReqCtx<'a> {
    pub shared: &'a Arc<Shared>,
    pub state: &'a Arc<State>,
    pub listener: &'a ListenerRt,
    pub client: SocketAddr,
    pub proto: Proto,
    pub method: &'a str,
    /// Lowercase, no brackets, no trailing dot.
    pub host: &'a str,
    pub port: u16,
    pub login: Option<&'a Login>,
    pub mode: Mode,
    /// The request is bodyless: a connection to an HTTP parent may be reused.
    pub reuse: bool,
}

impl ReqCtx<'_> {
    pub fn user(&self) -> Option<&str> {
        self.login.map(|l| l.user.name.as_str())
    }

    pub fn req<'b>(&'b self, ips: &'b [IpAddr]) -> Req<'b> {
        Req {
            src: self.client.ip(),
            listener: &self.listener.cfg.name,
            proto: self.proto,
            method: self.method,
            host: self.host,
            port: self.port,
            dst_ips: ips,
            user: self.user(),
            groups: self.login.map_or(&[], |l| l.user.groups.as_slice()),
            clock: Clock::at(SystemTime::now(), self.state.utc_offset_secs),
        }
    }

    /// An access record with the fields every outcome has; the caller adds the rest.
    pub fn record(
        &self,
        started: SystemTime,
        elapsed: std::time::Duration,
        status: u16,
        result: &'static str,
    ) -> AccessRecord {
        let url = if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        };
        AccessRecord {
            time: started,
            elapsed,
            client: self.client,
            listener: self.listener.cfg.name.clone(),
            protocol: self.proto.as_str(),
            user: self.user().map(str::to_owned),
            method: self.method.to_owned(),
            url,
            host: self.host.to_owned(),
            port: self.port,
            status,
            bytes_up: 0,
            bytes_down: 0,
            egress: None,
            pool: None,
            target_ip: None,
            parent: None,
            result,
            rule: None,
            referer: None,
            user_agent: None,
            mime: None,
            session: self.login.and_then(|l| l.options.sid.clone()),
        }
    }
}

/// What a request holds for as long as it runs: its limits and its slot on the
/// local address and the user's connection count.
pub struct Held {
    pub admission: Admission,
    lease: Option<Lease>,
    _user_slot: Option<CountGuard<String>>,
}

impl Held {
    /// Hand the local address slot to an idle connection filed for reuse.
    pub fn take_lease(&mut self) -> Option<Lease> {
        self.lease.take()
    }
}

/// A request that passed every check, with its upstream connection.
pub struct Opened {
    pub stream: dial::ProxyStream,
    pub bound_addr: Option<SocketAddr>,
    pub chain: Vec<String>,
    pub held: Held,
    pub rule: Option<String>,
    pub pool: Option<String>,
    /// Local source address of the connection.
    pub egress: Option<IpAddr>,
    /// Address the stream is connected to (the parent's, via a parent).
    pub peer: IpAddr,
    /// Approved numeric target for an absolute-form request sent to an HTTP parent.
    pub destination: SocketAddr,
    pub parent: Option<Arc<Parent>>,
    /// The stream speaks to an HTTP proxy.
    pub http_proxy: bool,
    /// Filing key when the stream may go back to the idle pool of parent connections.
    pub reuse_key: Option<String>,
    /// The stream came from the idle pool and may have gone stale.
    pub reused: bool,
}

/// The outcome of the access rules and the destination check.
pub struct Checked {
    /// Resolved destination addresses individually approved by the ACL (never empty).
    pub ips: Vec<IpAddr>,
    pub rule: Option<String>,
}

/// Evaluate an early lifecycle stage without destination data or any connection side effect.
pub fn check_stage(
    shared: &Arc<Shared>,
    state: &Arc<State>,
    listener: &ListenerRt,
    client: SocketAddr,
    login: Option<&Login>,
    stage: crate::acl::RuleStage,
    proto: Proto,
) -> Result<(), Refusal> {
    if !matches!(
        stage,
        crate::acl::RuleStage::PreNegotiation | crate::acl::RuleStage::PostAuth
    ) {
        return Err(Refusal::of(RefusalKind::Internal));
    }
    if !state.rules.has_stage(stage) {
        return Ok(());
    }
    let req = Req {
        src: client.ip(),
        listener: &listener.cfg.name,
        proto,
        method: "",
        host: "",
        port: 0,
        dst_ips: &[],
        user: login.map(|l| l.user.name.as_str()),
        groups: login.map_or(&[], |l| l.user.groups.as_slice()),
        clock: Clock::at(SystemTime::now(), state.utc_offset_secs),
    };
    let verdict = state.rules.evaluate_stage(stage, &req);
    enforce_verdict(shared, &verdict)
}

fn enforce_verdict(shared: &Shared, verdict: &crate::acl::Verdict) -> Result<(), Refusal> {
    let allowed = verdict.action == Action::Allow;
    shared
        .metrics
        .acl_decisions_total
        .with_label_values(&[if allowed { "allow" } else { "deny" }])
        .inc();
    if allowed {
        Ok(())
    } else {
        Err(Refusal {
            kind: RefusalKind::Forbidden,
            rule: verdict.rule.clone(),
        })
    }
}

fn check_destination_stage(
    c: &ReqCtx<'_>,
    checked: &mut Checked,
    stage: crate::acl::RuleStage,
) -> Result<(), Refusal> {
    if stage != crate::acl::RuleStage::Request && !c.state.rules.has_stage(stage) {
        return Ok(());
    }
    let mut refusal = None;
    let mut first_rule = None;
    let mut allowed = false;
    checked.ips.retain(|ip| {
        let verdict = c
            .state
            .rules
            .evaluate_stage(stage, &c.req(std::slice::from_ref(ip)));
        let result = enforce_verdict(c.shared, &verdict).and_then(|()| {
            if !verdict.allow_internal
                && [c.host.to_owned(), ip.to_string()]
                    .into_iter()
                    .any(|host| dial::is_denied_destination(&Target { host, port: c.port }))
            {
                c.shared.metrics.destination_denied_total.inc();
                return Err(Refusal {
                    kind: RefusalKind::DestinationDenied,
                    rule: verdict.rule.clone(),
                });
            }
            Ok(())
        });
        match result {
            Ok(()) => {
                if !allowed {
                    first_rule = verdict.rule;
                    allowed = true;
                }
                true
            }
            Err(error) => {
                if refusal.is_none() {
                    refusal = Some(error);
                }
                false
            }
        }
    });
    if !allowed {
        return Err(refusal.unwrap_or_else(|| Refusal::of(RefusalKind::Forbidden)));
    }
    checked.rule = first_rule;
    Ok(())
}

/// Resolve the destination, run the access rules and refuse private and
/// internal destinations (unless the deciding rule opts out). Nothing is
/// connected and no limit is charged.
pub async fn check(c: &ReqCtx<'_>) -> Result<Checked, Refusal> {
    if !c.state.uses_dst {
        let verdict = c.state.rules.evaluate(&c.req(&[]));
        if verdict.action == Action::Deny {
            enforce_verdict(c.shared, &verdict)?;
        }
        if !verdict.allow_internal
            && dial::is_denied_destination(&Target {
                host: c.host.to_owned(),
                port: c.port,
            })
        {
            c.shared.metrics.destination_denied_total.inc();
            return Err(Refusal {
                kind: RefusalKind::DestinationDenied,
                rule: verdict.rule,
            });
        }
    }
    let ips = match c.host.parse::<IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => resolve(c).await?,
    };
    let mut checked = Checked { ips, rule: None };
    check_destination_stage(c, &mut checked, crate::acl::RuleStage::Request)?;
    if c.proto == Proto::Udp {
        check_destination_stage(c, &mut checked, crate::acl::RuleStage::Udp)?;
    }
    Ok(checked)
}

pub(crate) fn admit(c: &ReqCtx<'_>, ips: &[IpAddr], rule: Option<&str>) -> Result<Held, Refusal> {
    let metrics = &c.shared.metrics;
    let deny = |kind| Refusal {
        kind,
        rule: rule.map(str::to_owned),
    };
    let user_slot = match c
        .login
        .and_then(|l| l.user.max_connections.map(|m| (&l.user.name, m)))
    {
        Some((name, max)) => Some(
            c.shared
                .conns
                .per_user
                .acquire(name.clone(), max)
                .ok_or_else(|| {
                    metrics
                        .limit_rejections_total
                        .with_label_values(&["user"])
                        .inc();
                    deny(RefusalKind::LimitConnections)
                })?,
        ),
        None => None,
    };
    let admission = c.state.limits.admit(&c.req(ips)).map_err(|r| {
        let (kind, label) = match r {
            Reject::Connections => (RefusalKind::LimitConnections, "limit_connections"),
            Reject::Rate => (RefusalKind::LimitRate, "limit_rate"),
        };
        metrics
            .limit_rejections_total
            .with_label_values(&[label])
            .inc();
        deny(kind)
    })?;
    Ok(Held {
        admission,
        lease: None,
        _user_slot: user_slot,
    })
}

/// Run the pipeline up to and including the connect.
pub async fn open(c: &ReqCtx<'_>) -> Result<Opened, Refusal> {
    open_pinned(c, None).await
}

/// HTTP keep-alive requests retain the parent chain selected for the client connection.
pub async fn open_pinned(c: &ReqCtx<'_>, pinned: Option<&[String]>) -> Result<Opened, Refusal> {
    let state = c.state;
    let metrics = &c.shared.metrics;
    let Checked { ips, rule } = check(c).await?;
    let deny = |kind| Refusal {
        kind,
        rule: rule.clone(),
    };
    let destination = SocketAddr::new(
        *ips.first().ok_or_else(|| deny(RefusalKind::Forbidden))?,
        c.port,
    );

    let mut held = admit(c, &ips, rule.as_deref())?;

    // Egress and route.
    let req = c.req(&ips);
    let pick = state
        .egress_for(&req, c.login, c.listener)
        .map_err(|EgressError::UnknownPool(_)| deny(RefusalKind::OptionDenied))?;
    let (route, parents, chain) = state.route_for(&req);
    let key = PickKey {
        session: c.login.and_then(|l| l.options.sid.as_deref()),
        user: c.user(),
        client: c.client.ip(),
        target_host: c.host,
    };
    let plan = Plan {
        port: c.port,
        ips: &ips,
        pool: pick.pool.as_ref(),
        index: pick.index,
        key,
        route,
        parents,
        chain,
        pinned,
        mode: c.mode,
        client: c.client,
        reuse: c.reuse,
    };
    let upstream = connect::connect(
        state,
        metrics,
        &c.shared.parent_conns,
        state.cfg.timeouts.connect,
        &plan,
    )
    .await
    .map_err(|e| deny(RefusalKind::Connect(e)))?;
    let egress = upstream.local_ip();
    held.lease = upstream.lease;
    Ok(Opened {
        egress,
        bound_addr: upstream.bound_addr,
        chain: upstream.chain,
        peer: upstream.peer,
        destination,
        parent: upstream.parent,
        http_proxy: upstream.http_proxy,
        reuse_key: upstream.reuse_key,
        reused: upstream.reused,
        stream: upstream.stream,
        held,
        rule,
        pool: pick.pool.map(|p| p.name().to_owned()),
    })
}

/// A checked BIND listener. Its guards remain held until the reverse tunnel ends.
pub struct Bound {
    pub listener: tokio::net::TcpListener,
    pub held: Held,
    pub rule: Option<String>,
    pub pool: Option<String>,
    pub egress: Option<IpAddr>,
    /// Pinned addresses permitted to connect to the BIND listener.
    pub expected_ips: Vec<IpAddr>,
}

/// Check and reserve a BIND request without connecting to the requested peer.
pub async fn bind_prepare(c: &ReqCtx<'_>) -> Result<Bound, Refusal> {
    let mut checked = check(c).await?;
    for ip in &mut checked.ips {
        if let IpAddr::V6(v6) = ip
            && let Some(v4) = v6.to_ipv4_mapped()
        {
            *ip = IpAddr::V4(v4);
        }
    }
    check_destination_stage(c, &mut checked, crate::acl::RuleStage::Bind)?;
    let deny = |kind| Refusal {
        kind,
        rule: checked.rule.clone(),
    };
    if checked.ips.iter().any(|ip| ip.is_unspecified()) {
        return Err(deny(RefusalKind::DestinationDenied));
    }
    let req = c.req(&checked.ips);
    if c.state.route_for(&req).0 != crate::config::Route::Direct {
        return Err(deny(RefusalKind::OptionDenied));
    }
    let mut held = admit(c, &checked.ips, checked.rule.as_deref())?;
    let pick = c
        .state
        .egress_for(&req, c.login, c.listener)
        .map_err(|EgressError::UnknownPool(_)| deny(RefusalKind::OptionDenied))?;
    let key = PickKey {
        session: c.login.and_then(|l| l.options.sid.as_deref()),
        user: c.user(),
        client: c.client.ip(),
        target_host: c.host,
    };
    let mut last = ConnectError::NoAddressOfFamily;
    for peer in &checked.ips {
        let family = crate::egress::Family::of(*peer);
        let mut lease = match &pick.pool {
            Some(pool) => match pool.pick(family, &key, pick.index, &[]) {
                Ok(lease) => Some(lease),
                Err(crate::egress::PickError::BadIndex) => {
                    return Err(deny(RefusalKind::Connect(ConnectError::BadIndex)));
                }
                Err(crate::egress::PickError::NoAddressOfFamily) => continue,
                Err(crate::egress::PickError::Unavailable) => {
                    last = ConnectError::EgressUnavailable;
                    continue;
                }
            },
            None => None,
        };
        let local = lease.as_ref().map_or_else(
            || {
                let configured = c.listener.cfg.listen.ip();
                if crate::egress::Family::of(configured) == family {
                    configured
                } else {
                    match family {
                        crate::egress::Family::V4 => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                        crate::egress::Family::V6 => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                    }
                }
            },
            Lease::ip,
        );
        match tokio::net::TcpListener::bind(SocketAddr::new(local, 0)).await {
            Ok(listener) => {
                if let Some(lease) = &mut lease {
                    lease.report(true);
                }
                held.lease = lease;
                return Ok(Bound {
                    listener,
                    held,
                    rule: checked.rule,
                    pool: pick.pool.as_ref().map(|p| p.name().to_owned()),
                    egress: (!local.is_unspecified()).then_some(local),
                    expected_ips: checked.ips,
                });
            }
            Err(error) => {
                if let Some(lease) = &mut lease {
                    lease.report(false);
                }
                last = ConnectError::Connect(error);
            }
        }
    }
    Err(deny(RefusalKind::Connect(last)))
}

async fn resolve(c: &ReqCtx<'_>) -> Result<Vec<IpAddr>, Refusal> {
    match c.state.resolver.resolve(c.host).await {
        Ok(ips) => {
            c.shared
                .metrics
                .dns_lookups_total
                .with_label_values(&["ok"])
                .inc();
            Ok(ips)
        }
        Err(e) => {
            c.shared
                .metrics
                .dns_lookups_total
                .with_label_values(&["error"])
                .inc();
            Err(Refusal::of(RefusalKind::Dns(e.to_string())))
        }
    }
}
