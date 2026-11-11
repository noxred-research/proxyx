//! Customer upstream routes against the real API, local Postgres and Redis,
//! a stub HTTP proxy (the org's own upstream) and the stub IP-check services
//! it answers for.

#[macro_use]
mod support;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use common::types::{IpState, OrgId};
use parking_lot::Mutex;
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use store::LeaseOutcome;
use support::{
    CUSTOMER_ADAPTERS, Harness, Options, TestResult, answer_proxied, basic, exit_ip_config,
    harness_with, lease, org, read_head, uniq,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;

const EXIT: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);

/// The org's own upstream: a loopback HTTP proxy that wants one Basic login
/// (changeable) and answers the IP-check services with `EXIT`, country FR.
struct Stub {
    addr: SocketAddr,
    login: Arc<Mutex<(String, String)>>,
    requests: Arc<AtomicUsize>,
    open: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl Stub {
    async fn start(user: &str, pass: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let login = Arc::new(Mutex::new((user.to_owned(), pass.to_owned())));
        let requests = Arc::new(AtomicUsize::new(0));
        let (open, gate) = watch::channel(true);
        let (shared, count) = (Arc::clone(&login), Arc::clone(&requests));
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let (shared, count, gate) = (Arc::clone(&shared), Arc::clone(&count), gate.clone());
                tokio::spawn(async move {
                    let _ = serve(stream, &shared, &count, gate).await;
                });
            }
        });
        Ok(Self {
            addr,
            login,
            requests,
            open,
            task,
        })
    }

    fn accept_password(&self, pass: &str) {
        self.login.lock().1 = pass.to_owned();
    }

    /// Stop answering until [`Stub::release`]: requests are counted, then wait.
    fn hold(&self) {
        self.open.send_replace(false);
    }

    fn release(&self) {
        self.open.send_replace(true);
    }

    /// Wait until a request beyond the first `seen` reached the stub.
    async fn request_after(&self, seen: usize) -> TestResult {
        tokio::time::timeout(Duration::from_secs(5), async {
            while self.requests() <= seen {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .map_err(|_| "the check never reached the upstream")?;
        Ok(())
    }

    fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

impl Drop for Stub {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(
    mut stream: TcpStream,
    login: &Mutex<(String, String)>,
    requests: &AtomicUsize,
    mut open: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let head = read_head(&mut stream).await?;
    requests.fetch_add(1, Ordering::SeqCst);
    // A held stub keeps the request unanswered: the check is in flight.
    let _ = open.wait_for(|open| *open).await;
    let (user, pass) = login.lock().clone();
    answer_proxied(stream, &head, &basic(&user, &pass), EXIT).await
}

async fn start(name: &str) -> Result<Option<Harness>, Box<dyn std::error::Error>> {
    harness_with(
        name,
        Options {
            adapters_toml: Some(CUSTOMER_ADAPTERS),
            exit_ip: Some(exit_ip_config()),
            ..Options::default()
        },
    )
    .await
}

fn upstream_body(stub: &Stub, user: &str, pass: &str) -> Value {
    json!({
        "scheme": "http",
        "host": "127.0.0.1",
        "port": stub.addr.port(),
        "region": "fr",
        "username": user,
        "password": pass,
    })
}

async fn put_upstream(h: &Harness, org: &OrgId, body: Value) -> (StatusCode, Value) {
    h.put(&format!("/v1/orgs/{org}/upstream"), body).await
}

async fn call(h: &Harness, method: Method, org: &OrgId, tail: &str) -> (StatusCode, Value) {
    h.admin(method, &format!("/v1/orgs/{org}/upstream{tail}"), None)
        .await
}

async fn rotate(h: &Harness, org: &OrgId, password: &str) -> (StatusCode, Value) {
    h.post(
        &format!("/v1/orgs/{org}/upstream/rotate-secret"),
        json!({ "password": password }),
    )
    .await
}
fn audit_actions(rows: &[store::AuditRow]) -> Vec<&str> {
    rows.iter().map(|r| r.action.as_str()).collect()
}

#[tokio::test]
async fn set_creates_a_candidate_nobody_can_lease_and_never_returns_the_login() -> TestResult {
    let h = or_skip!(start("upstream_set").await?);
    let stub = Stub::start("svc", "hunter2-pass").await?;
    let acme = org(&uniq("acme"));

    let (status, body) = put_upstream(&h, &acme, upstream_body(&stub, "svc", "hunter2-pass")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "candidate");
    assert_eq!(body["leasable"], false);
    assert_eq!(body["scheme"], "http");
    assert_eq!(body["provider"], "customer");
    assert_eq!(body["has_login"], true);
    assert_eq!(body["set_by"], "admin");

    // Not leasable before validation, not even by its owner; the stub was not dialled.
    assert_eq!(lease(&h, &acme, "s").await?, LeaseOutcome::Empty);
    assert_eq!(stub.requests(), 0, "set never dials");

    // No reply, GET or inventory listing carries the login.
    let (status, got) = call(&h, Method::GET, &acme, "").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(got["set_by"], body["set_by"]);
    let (_, list) = h.get("/v1/inventory").await;
    for reply in [body.to_string(), got.to_string(), list.to_string()] {
        assert!(
            !reply.contains("hunter2-pass") && !reply.contains("\"svc\""),
            "{reply}"
        );
    }
    let owned = &list["items"][0];
    assert_eq!(owned["owner"], acme.as_str());

    let rows = h.db.audit_for(acme.as_str(), 10).await?;
    assert_eq!(audit_actions(&rows), ["customer.set"]);
    let detail = serde_json::to_string(&rows[0].detail)?;
    assert!(
        !detail.contains("hunter2-pass") && !detail.contains("svc"),
        "{detail}"
    );
    Ok(())
}

#[tokio::test]
async fn validate_dials_through_the_upstream_and_only_a_pass_makes_it_leasable() -> TestResult {
    let h = or_skip!(start("upstream_validate").await?);
    let stub = Stub::start("svc", "right").await?;
    let (acme, other) = (org(&uniq("acme")), org(&uniq("other")));

    // A wrong login: the quorum fails, nothing changes, the failure is audited.
    put_upstream(&h, &acme, upstream_body(&stub, "svc", "wrong")).await;
    let (status, body) = call(&h, Method::POST, &acme, "/validate").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["valid"], false);
    assert_eq!(body["reason"], "unverified");
    assert!(stub.requests() > 0, "validate dialled the upstream");
    let (_, now) = call(&h, Method::GET, &acme, "").await;
    assert_eq!(now["state"], "candidate");
    assert_eq!(lease(&h, &acme, "s").await?, LeaseOutcome::Empty);

    // The right login: available, with the exit IP the quorum saw.
    put_upstream(&h, &acme, upstream_body(&stub, "svc", "right")).await;
    let (status, body) = call(&h, Method::POST, &acme, "/validate").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["valid"], true);
    assert_eq!(body["state"], "available");
    assert_eq!(body["exit_ip"], EXIT.to_string());
    assert_eq!(body["country"], "fr");

    // Two-org isolation: the owner leases it; another org never does.
    let owner = lease(&h, &acme, "s").await?;
    let LeaseOutcome::Free(grant) = &owner else {
        return Err(format!("owner should get the unit: {owner:?}").into());
    };
    assert_eq!(
        grant.ip.to_string(),
        EXIT.to_string(),
        "the reported exit IP"
    );
    assert_eq!(lease(&h, &other, "s").await?, LeaseOutcome::Empty);

    let rows = h.db.audit_for(acme.as_str(), 20).await?;
    let validations: Vec<_> = rows
        .iter()
        .filter(|r| r.action == "customer.validate")
        .map(|r| r.detail["ok"].as_bool())
        .collect();
    assert_eq!(validations, [Some(true), Some(false)], "newest first");
    Ok(())
}

/// api D5: a hung upstream is `timeout`, not `unverified` like a wrong login.
#[tokio::test]
async fn validate_tells_a_hung_upstream_from_a_wrong_login() -> TestResult {
    let h = or_skip!(start("upstream_hung").await?);
    let stub = Stub::start("svc", "right").await?;
    let acme = org(&uniq("acme"));
    put_upstream(&h, &acme, upstream_body(&stub, "svc", "right")).await;
    stub.hold();
    let (status, body) = call(&h, Method::POST, &acme, "/validate").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["reason"], "timeout", "{body}");
    stub.release();
    let (_, now) = call(&h, Method::GET, &acme, "").await;
    assert_eq!(now["state"], "candidate", "a failed check changes nothing");
    Ok(())
}

/// api D4: a NUL byte in the login reached Postgres as a `503`.
#[tokio::test]
async fn a_login_with_a_nul_byte_is_a_400() -> TestResult {
    let h = or_skip!(start("upstream_nul").await?);
    let stub = Stub::start("svc", "pw").await?;
    let acme = org(&uniq("acme"));
    let mut body = upstream_body(&stub, "svc", "pw");
    body["username"] = json!("u\u{0}x");
    let (status, out) = put_upstream(&h, &acme, body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{out}");
    Ok(())
}

#[tokio::test]
async fn validate_refuses_a_region_the_exit_country_does_not_match() -> TestResult {
    let h = or_skip!(start("upstream_country").await?);
    let stub = Stub::start("svc", "pw").await?;
    let acme = org(&uniq("acme"));
    let mut body = upstream_body(&stub, "svc", "pw");
    body["region"] = json!("de");
    put_upstream(&h, &acme, body).await;

    let (status, body) = call(&h, Method::POST, &acme, "/validate").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["reason"], "country_mismatch");
    let (_, now) = call(&h, Method::GET, &acme, "").await;
    assert_eq!(now["state"], "candidate");
    Ok(())
}

#[tokio::test]
async fn clear_retires_the_unit_withdraws_it_and_deletes_the_login() -> TestResult {
    let h = or_skip!(start("upstream_clear").await?);
    let stub = Stub::start("svc", "pw").await?;
    let acme = org(&uniq("acme"));
    let (_, set) = put_upstream(&h, &acme, upstream_body(&stub, "svc", "pw")).await;
    let unit: std::net::IpAddr = set["unit"].as_str().ok_or("unit key")?.parse()?;
    call(&h, Method::POST, &acme, "/validate").await;
    assert!(matches!(
        lease(&h, &acme, "s").await?,
        LeaseOutcome::Free(_)
    ));

    let (status, body) = call(&h, Method::DELETE, &acme, "").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "retired");

    // New tunnels are refused at once; the row is retired and the login gone.
    assert_eq!(lease(&h, &acme, "fresh").await?, LeaseOutcome::Empty);
    let row =
        h.db.inventory_row(unit)
            .await?
            .ok_or("row stays for the audit trail")?;
    assert_eq!(row.state, IpState::Retired);
    assert!(h.db.customer_login(&acme).await?.is_none());
    let (status, _) = call(&h, Method::GET, &acme, "").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = call(&h, Method::DELETE, &acme, "").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "nothing left to clear");

    let rows = h.db.audit_for(acme.as_str(), 20).await?;
    for want in ["customer.set", "customer.validate", "customer.clear"] {
        assert!(audit_actions(&rows).contains(&want), "{want}");
    }
    Ok(())
}

/// The check reaches the old upstream, a PUT replaces it, then the check's
/// result comes back. The stub holds the check so the order is fixed.
#[tokio::test]
async fn a_validation_that_began_before_a_put_does_not_approve_the_replacement() -> TestResult {
    let h = or_skip!(start("upstream_validate_race").await?);
    let stub = Stub::start("svc", "pw").await?;
    let acme = org(&uniq("acme"));
    put_upstream(&h, &acme, upstream_body(&stub, "svc", "pw")).await;

    stub.hold();
    let seen = stub.requests();
    let (validated, put) = tokio::join!(call(&h, Method::POST, &acme, "/validate"), async {
        stub.request_after(seen).await?;
        let replaced = put_upstream(&h, &acme, upstream_body(&stub, "svc", "other")).await;
        stub.release();
        Ok::<_, Box<dyn std::error::Error>>(replaced)
    });
    let (status, body) = put?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = validated;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    let (_, now) = call(&h, Method::GET, &acme, "").await;
    assert_eq!(now["state"], "candidate", "the replacement is not approved");
    assert_eq!(now["exit_ip"], Value::Null);
    assert_eq!(lease(&h, &acme, "s").await?, LeaseOutcome::Empty);

    // Validating the replacement is a new check and passes with its own login.
    stub.accept_password("other");
    let (status, body) = call(&h, Method::POST, &acme, "/validate").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    Ok(())
}

/// A new login checked against the old upstream must not overwrite the login
/// of an upstream that replaced it during the check.
#[tokio::test]
async fn a_rotation_checked_against_an_old_upstream_does_not_overwrite_the_replacement()
-> TestResult {
    let h = or_skip!(start("upstream_rotate_race").await?);
    let stub = Stub::start("svc", "old-pass").await?;
    let acme = org(&uniq("acme"));
    put_upstream(&h, &acme, upstream_body(&stub, "svc", "old-pass")).await;
    call(&h, Method::POST, &acme, "/validate").await;

    stub.accept_password("new-pass");
    stub.hold();
    let seen = stub.requests();
    let (rotated, put) = tokio::join!(rotate(&h, &acme, "new-pass"), async {
        stub.request_after(seen).await?;
        let replaced =
            put_upstream(&h, &acme, upstream_body(&stub, "svc", "replacement-pass")).await;
        stub.release();
        Ok::<_, Box<dyn std::error::Error>>(replaced)
    });
    let (status, body) = put?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = rotated;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    let kept = h.db.customer_login(&acme).await?.ok_or("login")?;
    assert_eq!(kept.password.expose(), "replacement-pass");
    let rotations =
        h.db.audit_for(acme.as_str(), 20)
            .await?
            .into_iter()
            .filter(|r| r.action == "customer.rotate")
            .count();
    assert_eq!(rotations, 0, "a refused rotation is not recorded as done");
    Ok(())
}

#[tokio::test]
async fn rotate_secret_stores_only_a_login_that_works() -> TestResult {
    let h = or_skip!(start("upstream_rotate").await?);
    let stub = Stub::start("svc", "old-pass").await?;
    let acme = org(&uniq("acme"));
    put_upstream(&h, &acme, upstream_body(&stub, "svc", "old-pass")).await;
    call(&h, Method::POST, &acme, "/validate").await;

    // The upstream's password changed to "new-pass"; a mistyped one is refused
    // and the stored one stays.
    stub.accept_password("new-pass");
    let (status, body) = rotate(&h, &acme, "typo-pass").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(
        (body["rotated"].clone(), body["reason"].clone()),
        (json!(false), json!("unverified"))
    );
    let kept = h.db.customer_login(&acme).await?.ok_or("login")?;
    assert_eq!(kept.password.expose(), "old-pass");

    let (status, body) = rotate(&h, &acme, "new-pass").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let stored = h.db.customer_login(&acme).await?.ok_or("login")?;
    assert_eq!(
        (stored.username.expose(), stored.password.expose()),
        ("svc", "new-pass"),
        "the username stays when none is sent"
    );
    assert!(!body.to_string().contains("new-pass"));

    // A rotation of an org without an upstream is a 404; an empty password a 400.
    let nobody = org(&uniq("nobody"));
    let (status, _) = h
        .post(
            &format!("/v1/orgs/{nobody}/upstream/rotate-secret"),
            json!({ "password": "x" }),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = h
        .post(
            &format!("/v1/orgs/{acme}/upstream/rotate-secret"),
            json!({ "password": "" }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let rows = h.db.audit_for(acme.as_str(), 20).await?;
    let rotations: Vec<_> = rows
        .iter()
        .filter(|r| r.action == "customer.rotate")
        .map(|r| r.detail.get("ok").and_then(Value::as_bool))
        .collect();
    assert_eq!(
        rotations,
        [None, Some(false)],
        "the failed attempt is audited too"
    );
    let all = serde_json::to_string(&rows.iter().map(|r| &r.detail).collect::<Vec<_>>())?;
    assert!(!all.contains("pass"), "{all}");
    Ok(())
}

#[tokio::test]
async fn one_org_cannot_see_change_or_take_another_orgs_upstream() -> TestResult {
    let h = or_skip!(start("upstream_isolation").await?);
    let stub = Stub::start("svc", "pw").await?;
    let (acme, rival) = (org(&uniq("acme")), org(&uniq("rival")));
    put_upstream(&h, &acme, upstream_body(&stub, "svc", "pw")).await;
    call(&h, Method::POST, &acme, "/validate").await;

    // The rival has no upstream: every route says so, and acme's is untouched.
    for (method, tail) in [
        (Method::GET, ""),
        (Method::DELETE, ""),
        (Method::POST, "/validate"),
    ] {
        let (status, _) = call(&h, method.clone(), &rival, tail).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {tail}");
    }
    // The same upstream address under another org is another unit: both
    // work, and neither can lease or clear the other's.
    let (status, body) = put_upstream(&h, &rival, upstream_body(&stub, "svc", "pw")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, mine) = call(&h, Method::GET, &acme, "").await;
    assert_eq!(mine["state"], "available");
    assert_ne!(mine["unit"], body["unit"]);
    assert_eq!(
        lease(&h, &rival, "s").await?,
        LeaseOutcome::Empty,
        "not validated yet"
    );
    call(&h, Method::POST, &rival, "/validate").await;
    let (mine_lease, rival_lease) = (lease(&h, &acme, "s").await?, lease(&h, &rival, "s").await?);
    let (LeaseOutcome::Free(mine_lease), LeaseOutcome::Free(rival_lease)) =
        (&mine_lease, &rival_lease)
    else {
        return Err(format!("both orgs get a free unit: {mine_lease:?} {rival_lease:?}").into());
    };
    assert_eq!(mine_lease.unit, mine["unit"].as_str().ok_or("unit")?);
    assert_eq!(rival_lease.unit, body["unit"].as_str().ok_or("unit")?);
    // Clearing the rival's leaves acme's untouched.
    call(&h, Method::DELETE, &rival, "").await;
    let (_, mine) = call(&h, Method::GET, &acme, "").await;
    assert_eq!(mine["state"], "available");
    assert_eq!(lease(&h, &rival, "fresh").await?, LeaseOutcome::Empty);
    Ok(())
}

#[tokio::test]
async fn setting_again_replaces_the_unit_and_requires_a_new_validation() -> TestResult {
    let h = or_skip!(start("upstream_replace").await?);
    let stub = Stub::start("svc", "pw").await?;
    let acme = org(&uniq("acme"));
    put_upstream(&h, &acme, upstream_body(&stub, "svc", "pw")).await;
    call(&h, Method::POST, &acme, "/validate").await;
    assert!(matches!(
        lease(&h, &acme, "s").await?,
        LeaseOutcome::Free(_)
    ));

    // A second PUT (even the same address) resets the unit: nothing leases it
    // until it is validated again.
    let (status, body) = put_upstream(&h, &acme, upstream_body(&stub, "svc", "pw")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "candidate");
    assert_eq!(lease(&h, &acme, "fresh").await?, LeaseOutcome::Empty);
    call(&h, Method::POST, &acme, "/validate").await;
    // the earlier lease of "s" still holds the unit, so "fresh" shares it
    assert!(matches!(
        lease(&h, &acme, "fresh").await?,
        LeaseOutcome::Shared(_)
    ));
    Ok(())
}

#[tokio::test]
async fn bad_requests_are_refused_before_anything_is_stored() -> TestResult {
    let h = or_skip!(start("upstream_bad").await?);
    let acme = org(&uniq("acme"));
    let good = json!({
        "scheme": "http", "host": "127.0.0.1", "port": 3128, "region": "fr",
        "username": "u", "password": "p",
    });
    let with = |key: &str, value: Value| {
        let mut body = good.clone();
        body[key] = value;
        body
    };
    for (what, body) in [
        ("unknown scheme", with("scheme", json!("ftp"))),
        ("port zero", with("port", json!(0))),
        (
            "url as host",
            with("host", json!("http://proxy.example.com")),
        ),
        (
            "host with a port",
            with("host", json!("proxy.example.com:3128")),
        ),
        ("empty host", with("host", json!(""))),
        ("bad region", with("region", json!("france"))),
        ("password alone", {
            let mut b = good.clone();
            b.as_object_mut().ok_or("object")?.remove("username");
            b
        }),
        ("empty password", with("password", json!(""))),
        ("unknown field", with("proxy_type", json!("http"))),
    ] {
        let (status, body) = put_upstream(&h, &acme, body).await;
        assert!(
            status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY,
            "{what}: {status} {body}"
        );
    }
    let (status, _) = call(&h, Method::GET, &acme, "").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "nothing was stored");

    for (scheme, provider) in [("socks5", "customer_socks5"), ("https", "customer_https")] {
        let mut configured = good.clone();
        configured["scheme"] = json!(scheme);
        let (status, body) = put_upstream(&h, &acme, configured).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            (body["scheme"].clone(), body["provider"].clone()),
            (json!(scheme), json!(provider))
        );
    }
    Ok(())
}

/// The shipped `customer` adapters carry the public-address rule.
#[tokio::test]
async fn private_loopback_and_cluster_addresses_are_refused_at_write() -> TestResult {
    let shipped = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/adapters/customer.toml"),
    )?;
    let h = or_skip!(
        harness_with(
            "upstream_public",
            Options {
                adapters_toml: Some(&shipped),
                exit_ip: Some(exit_ip_config()),
                ..Options::default()
            },
        )
        .await?
    );
    let acme = org(&uniq("acme"));
    for host in [
        "127.0.0.1",
        "10.0.0.5",
        "172.16.4.4",
        "192.168.1.1",
        "100.64.0.1",
        "169.254.169.254",
        "::1",
        "[fd00::1]",
        "localhost",
        "egress.egress.svc",
        "egress.egress.svc.cluster.local",
        "proxy.internal",
    ] {
        for scheme in ["http", "socks5"] {
            let (status, body) = put_upstream(
                &h,
                &acme,
                json!({"scheme": scheme, "host": host, "port": 3128, "region": "fr"}),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{scheme} {host}: {body}");
            assert!(
                body["error"].as_str().is_some_and(|e| e.contains("public")),
                "{host}: {body}"
            );
        }
    }
    let (status, _) = call(&h, Method::GET, &acme, "").await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a refused address stores nothing"
    );

    // A public address is accepted (set does not dial); it stays a candidate.
    let (status, body) = put_upstream(
        &h,
        &acme,
        json!({"scheme": "http", "host": "8.8.8.8", "port": 3128, "region": "us"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "candidate");
    assert_eq!(body["has_login"], false);
    Ok(())
}

/// Org policies the API sees from the start: one lists providers without
/// `customer`, one lists it, and an org with none lists no providers.
const ORG_POLICIES: &str = r#"
[[policy]]
name = "org-warnexcl"
scope = "org"
match = "warnexcl"
providers = ["oxylabs_isp"]

[[policy]]
name = "org-warnallow"
scope = "org"
match = "warnallow"
providers = ["oxylabs_isp", "customer"]
"#;

/// PUT then validate the upstream of the org `name` on a harness of its own
/// and return both replies.
async fn put_and_validate(
    db: &str,
    name: &str,
) -> Result<Option<(Value, Value)>, Box<dyn std::error::Error>> {
    let Some(h) = harness_with(
        db,
        Options {
            adapters_toml: Some(CUSTOMER_ADAPTERS),
            exit_ip: Some(exit_ip_config()),
            extra_policies: ORG_POLICIES,
            ..Options::default()
        },
    )
    .await?
    else {
        return Ok(None);
    };
    let stub = Stub::start("svc", "pw").await?;
    let org = org(name);
    let (status, put) = put_upstream(&h, &org, upstream_body(&stub, "svc", "pw")).await;
    assert_eq!(status, StatusCode::OK, "{put}");
    let (status, validate) = call(&h, Method::POST, &org, "/validate").await;
    assert_eq!(status, StatusCode::OK, "{validate}");
    assert_eq!(validate["valid"], true, "{validate}");
    Ok(Some((put, validate)))
}

/// api D13: the org is pinned to its unit, so a cache policy that lists
/// providers without `customer` makes every tunnel fail with `no_healthy_ip`
/// although the check passed; both replies say so.
#[tokio::test]
async fn put_and_validate_warn_when_the_org_policy_leaves_the_provider_out() -> TestResult {
    let (put, validate) = or_skip!(put_and_validate("upstream_warn", "warnexcl").await?);
    for (reply, body) in [("put", &put), ("validate", &validate)] {
        assert!(
            body["warning"]
                .as_str()
                .is_some_and(|w| w.contains("customer")),
            "{reply} carries a warning naming the provider: {body}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn put_and_validate_do_not_warn_when_the_org_policy_lists_the_provider() -> TestResult {
    let (put, validate) = or_skip!(put_and_validate("upstream_nowarn_listed", "warnallow").await?);
    for (reply, body) in [("put", &put), ("validate", &validate)] {
        assert!(body.get("warning").is_none(), "{reply}: {body}");
    }
    Ok(())
}

#[tokio::test]
async fn put_and_validate_do_not_warn_when_the_org_policy_lists_no_providers() -> TestResult {
    let (put, validate) = or_skip!(put_and_validate("upstream_nowarn_unset", "warnfree").await?);
    for (reply, body) in [("put", &put), ("validate", &validate)] {
        assert!(body.get("warning").is_none(), "{reply}: {body}");
    }
    Ok(())
}
