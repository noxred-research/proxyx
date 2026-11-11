//! Golden, refusal and load tests for the adapters. The shipped files in
//! `data/adapters` and the extra providers in `tests/fixtures` are rendered
//! byte for byte.

use std::path::{Path, PathBuf};
use std::time::Duration;

use common::Secret;
use common::types::{InventoryEntry, ProviderId, Region, Subtype, UpstreamScheme};
use proxyx_provider::{
    Adapter, AdapterFile, AdapterSet, ProviderError, SessionMode, UnitSpec, ensure_public_address,
};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn secrets(name: &str) -> anyhow::Result<Secret> {
    let value = match name {
        "isp_static_port_user" => "acme",
        "isp_static_port_pass" => "pw-isp",
        "res_user_suffix_user" => "resu",
        "res_user_suffix_pass" => "resp",
        "res_pass_suffix_user" => "ipu",
        "res_pass_suffix_pass" => "ipp",
        "res_numeric_session_user" => "webuser",
        "res_numeric_session_pass" => "webpass",
        "res_zone_user" => "acct-example-zone-residential",
        "res_zone_pass" => "zonepass",
        "res_zone_full_user" => "acct-hl_abc-zone-res1",
        "res_zone_full_pass" => "bdrp",
        "isp_zone_ip_user" => "acct-hl_abc-zone-isp1",
        "isp_zone_ip_pass" => "bdip",
        "res_user_prefix_user" => "dec",
        "res_user_prefix_pass" => "decp",
        "res_package_key_pass" => "pkgkey",
        _ => anyhow::bail!("no secret {name}"),
    };
    Ok(Secret::new(value))
}

fn shipped() -> AdapterSet {
    AdapterSet::load(&root().join("../../data/adapters"), secrets).expect("shipped adapters load")
}

fn fixtures() -> AdapterSet {
    AdapterSet::load(&root().join("tests/fixtures"), secrets).expect("fixtures load")
}

fn id(s: &str) -> ProviderId {
    s.parse().expect("provider id")
}

fn get<'a>(set: &'a AdapterSet, name: &str) -> &'a Adapter {
    set.get(&id(name)).expect("adapter present")
}

fn shipped_adapter(name: &str) -> Adapter {
    get(&shipped(), name).clone()
}

fn fixture_adapter(name: &str) -> Adapter {
    get(&fixtures(), name).clone()
}

/// A shipped adapter file loaded with one secret replaced.
fn load_shipped_with_secret(
    file: &str,
    secret: &str,
    value: &str,
) -> Result<AdapterSet, ProviderError> {
    let text =
        std::fs::read_to_string(root().join("../../data/adapters").join(file)).expect("read");
    let parsed: AdapterFile = toml::from_str(&text).expect("parse");
    AdapterSet::from_configs(parsed.adapter, &|name: &str| {
        if name == secret {
            Ok(Secret::new(value))
        } else {
            secrets(name)
        }
    })
}

fn region(s: &str) -> Region {
    s.parse().expect("region")
}

/// An inventory entry at `203.0.113.10`.
fn entry(provider: &str, subtype: Subtype, host: &str, port: u16, cc: &str) -> InventoryEntry {
    InventoryEntry {
        provider: id(provider),
        subtype,
        plan: String::new(),
        ip: "203.0.113.10".parse().expect("ip"),
        host: host.to_owned(),
        port,
        region: region(cc),
        asn: None,
        credentials: None,
        box_handle: None,
        rental_end: None,
    }
}

fn static_spec(entry: &InventoryEntry) -> UnitSpec<'_> {
    UnitSpec::Static {
        entry,
        credentials: None,
    }
}

fn login_spec<'a>(entry: &'a InventoryEntry, user: &str, pass: &str) -> UnitSpec<'a> {
    UnitSpec::Static {
        entry,
        credentials: Some((Secret::new(user), Secret::new(pass))),
    }
}

/// `(username, password, host, port)` of a rendered endpoint.
fn render(a: &Adapter, spec: &UnitSpec<'_>) -> (String, String, String, u16) {
    let up = a.recipe(spec).expect("recipe");
    (
        up.username.expose().to_owned(),
        up.password.expose().to_owned(),
        up.host,
        up.port,
    )
}

fn assert_endpoint(
    a: &Adapter,
    spec: &UnitSpec<'_>,
    user: &str,
    pass: &str,
    host: &str,
    port: u16,
) {
    assert_eq!(
        render(a, spec),
        (user.to_owned(), pass.to_owned(), host.to_owned(), port)
    );
}

fn rotating<'a>(sid: &'a str, ttl: u32, region: &'a Region, strict: bool) -> UnitSpec<'a> {
    UnitSpec::Rotating {
        session_id: sid,
        ttl: Duration::from_secs(u64::from(ttl) * 60),
        region,
        strict,
    }
}

/// The option an adapter refuses `spec` for.
fn refused(a: &Adapter, spec: &UnitSpec<'_>) -> &'static str {
    match a.recipe(spec).expect_err("recipe must refuse") {
        ProviderError::OptionRefused { option, .. } => option,
        other => panic!("expected OptionRefused, got {other:?}"),
    }
}

fn is_mismatch(a: &Adapter, spec: &UnitSpec<'_>) -> bool {
    matches!(a.recipe(spec), Err(ProviderError::SpecMismatch { .. }))
}

fn is_not_public(a: &Adapter, spec: &UnitSpec<'_>) -> bool {
    matches!(a.recipe(spec), Err(ProviderError::NotPublic))
}

#[test]
fn shipped_adapters_load() {
    let set = shipped();
    let ids: Vec<_> = set.iter().map(|a| a.id().to_string()).collect();
    assert_eq!(
        ids,
        [
            "customer",
            "customer_https",
            "customer_socks5",
            "isp_static_port",
            "local",
            "res_numeric_rotating_http",
            "res_numeric_rotating_socks5",
            "res_numeric_sticky_http",
            "res_numeric_sticky_socks5",
            "res_pass_suffix",
            "res_user_suffix",
            "res_zone",
            "vpn-pool"
        ]
    );
}

#[test]
fn isp_static_port_uses_the_port_of_each_inventory_entry() {
    let a = shipped_adapter("isp_static_port");
    for port in [8001, 8003, 8010] {
        let e = entry(
            "isp_static_port",
            Subtype::Isp,
            "isp.oxylabs.io", // wire-compat: shipped gateway host
            port,
            "nl",
        );
        let spec = static_spec(&e);
        assert_endpoint(&a, &spec, "acme", "pw-isp", "isp.oxylabs.io", port); // wire-compat: shipped gateway host
        let up = a.recipe(&spec).expect("recipe");
        assert_eq!(up.scheme, UpstreamScheme::Http);
        assert_eq!(up.provider, id("isp_static_port"));
    }
}

#[test]
fn isp_static_port_entry_credentials_replace_the_base_credentials() {
    let e = entry(
        "isp_static_port",
        Subtype::Isp,
        "isp.oxylabs.io", // wire-compat: shipped gateway host
        8002,
        "nl",
    );
    let spec = login_spec(&e, "other", "otherpw");
    assert_endpoint(
        &shipped_adapter("isp_static_port"),
        &spec,
        "other",
        "otherpw",
        "isp.oxylabs.io", // wire-compat: shipped gateway host
        8002,
    );
}

#[test]
fn isp_rotating_pool_takes_the_country() {
    let e = entry(
        "isp_rotating_pool",
        Subtype::Isp,
        "rotating.isp.example.net",
        8001,
        "de",
    );
    let spec = static_spec(&e);
    assert_endpoint(
        &fixture_adapter("isp_rotating_pool"),
        &spec,
        "user-acme-country-DE",
        "pw-isp",
        "rotating.isp.example.net",
        8000,
    );
}

#[test]
fn res_user_suffix_golden() {
    let a = shipped_adapter("res_user_suffix");
    let fr = region("fr");
    let sid = "abcd1234abcd1234";
    assert_endpoint(
        &a,
        &rotating(sid, 30, &fr, false),
        "customer-resu-cc-FR-sessid-abcd1234abcd1234-sesstime-30",
        "resp",
        "pr.oxylabs.io", // wire-compat: shipped gateway host
        7777,
    );
    // strict swaps the session key, never adds a second one
    assert_eq!(
        render(&a, &rotating(sid, 30, &fr, true)).0,
        "customer-resu-cc-FR-sessid_oneip-abcd1234abcd1234-sesstime-30"
    );
    let paris = region("fr/paris");
    assert_eq!(
        render(&a, &rotating(sid, 10, &paris, false)).0,
        "customer-resu-cc-FR-city-paris-sessid-abcd1234abcd1234-sesstime-10"
    );
    assert_eq!(a.session_id_len(), Some(16));
}

#[test]
fn res_user_suffix_allows_only_80_and_443() {
    let a = shipped_adapter("res_user_suffix");
    assert!(a.port_allowed(80));
    assert!(a.port_allowed(443));
    assert!(!a.port_allowed(8080));
    assert!(!a.port_allowed(22));
    // no list: every port
    assert!(shipped_adapter("isp_static_port").port_allowed(8080));
}

#[test]
fn res_pass_suffix_puts_the_options_in_the_password() {
    let a = shipped_adapter("res_pass_suffix");
    let br = region("br");
    assert_endpoint(
        &a,
        &rotating("sgn34f3e", 10, &br, false),
        "ipu",
        "ipp_country-br_session-sgn34f3e_lifetime-600s",
        "geo.iproyal.com", // wire-compat: shipped gateway host
        12321,
    );
    assert_eq!(
        render(&a, &rotating("sgn34f3e", 30, &br, true)).1,
        "ipp_country-br_session-sgn34f3e_lifetime-1800s_killswitch-1"
    );
    assert_eq!(a.session_id_len(), Some(8));
}

#[test]
fn res_zone_full_golden() {
    let res = fixture_adapter("res_zone_full");
    let us = region("us");
    assert_endpoint(
        &res,
        &rotating("scan42", 10, &us, false),
        "acct-hl_abc-zone-res1-country-us-session-scan42",
        "bdrp",
        "zone-gw.example.net",
        33335,
    );
    assert_eq!(
        render(&res, &rotating("scan42", 10, &us, true)).0,
        "acct-hl_abc-zone-res1-country-us-session-scan42-const"
    );

    let mut e = entry("isp_zone_ip", Subtype::Isp, "203.0.113.7", 24000, "us");
    e.ip = "203.0.113.7".parse().expect("ip");
    assert_endpoint(
        &fixture_adapter("isp_zone_ip"),
        &static_spec(&e),
        "acct-hl_abc-zone-isp1-ip-203.0.113.7",
        "bdip",
        "zone-gw.example.net",
        33335,
    );
}

#[test]
fn res_zone_full_session_id_with_a_dash_is_refused() {
    let us = region("us");
    let a = fixture_adapter("res_zone_full");
    assert_eq!(refused(&a, &rotating("scan-42", 10, &us, false)), "sid");
}

#[test]
fn user_prefix_duration_golden() {
    let a = fixture_adapter("res_user_prefix");
    let au = region("us/austin");
    assert_endpoint(
        &a,
        &rotating("random123", 60, &au, false),
        "user-dec-country-us-city-austin-session-random123-sessionduration-60",
        "decp",
        "gw.example.net",
        7000,
    );
    assert_eq!(
        render(&a, &rotating("random123", 60, &au, true)).0,
        "user-dec-country-us-city-austin-session_iplock-random123-sessionduration-60"
    );
}

#[test]
fn package_key_golden_and_no_strict_mode() {
    let a = fixture_adapter("res_package_key");
    let fr = region("fr");
    assert_endpoint(
        &a,
        &rotating("job_1", 30, &fr, false),
        "country-fr-session-job_1-rotate-timed_1800",
        "pkgkey",
        "package.example.net",
        1337,
    );
    assert!(is_mismatch(&a, &rotating("job_1", 30, &fr, true)));
    // 33 characters: over the session id limit of 32
    assert_eq!(
        refused(&a, &rotating(&"a".repeat(33), 30, &fr, false)),
        "sid"
    );
    assert!(a.recipe(&rotating(&"a".repeat(32), 30, &fr, false)).is_ok());
}

#[test]
fn customer_takes_host_and_login_from_the_entry() {
    let a = shipped_adapter("customer");
    let mut e = entry("customer", Subtype::Datacenter, "8.8.8.8", 3128, "us");
    assert_endpoint(&a, &static_spec(&e), "", "", "8.8.8.8", 3128);
    e.host = "proxy.example.com".to_owned();
    assert_endpoint(
        &a,
        &login_spec(&e, "u1", "p1"),
        "u1",
        "p1",
        "proxy.example.com",
        3128,
    );
}

#[test]
fn customer_refuses_non_public_addresses() {
    let a = shipped_adapter("customer");
    for host in [
        "10.0.0.5",
        "172.16.4.4",
        "192.168.1.1",
        "127.0.0.1",
        "100.64.0.1",
        "169.254.169.254",
        "0.0.0.0",
        "::1",
        "[fd00::1]",
        "fe80::1",
        "localhost",
        "proxy.internal",
        "egress.egress.svc",
        "egress.egress.svc.cluster.local",
        "singlelabel",
    ] {
        let e = entry("customer", Subtype::Datacenter, host, 3128, "us");
        assert!(is_not_public(&a, &static_spec(&e)), "{host} accepted");
        assert!(matches!(
            ensure_public_address(host),
            Err(ProviderError::NotPublic)
        ));
    }
    assert!(ensure_public_address("1.1.1.1").is_ok());
    assert!(ensure_public_address("proxy.example.com").is_ok());
}

#[test]
fn customer_adapter_with_a_private_gateway_is_refused_at_load() {
    let toml = r#"
        [[adapter]]
        id = "customer"
        kind = "static"
        subtype = "datacenter"
        public_only = true
        host = "10.1.2.3"
    "#;
    let file: AdapterFile = toml::from_str(toml).expect("parse");
    let r = AdapterSet::from_configs(file.adapter, &secrets);
    assert!(matches!(r, Err(ProviderError::NotPublic)), "{r:?}");
}

#[test]
fn vpn_pool_dials_cluster_services_over_socks5() {
    let a = shipped_adapter("vpn-pool");
    assert!(!a.public_only(), "cluster-internal upstreams are the point");
    let e = entry(
        "vpn-pool",
        Subtype::Datacenter,
        "egress-fr.egress.svc",
        1080,
        "fr",
    );
    let spec = static_spec(&e);
    assert_endpoint(&a, &spec, "", "", "egress-fr.egress.svc", 1080);
    let up = a.recipe(&spec).expect("recipe");
    assert_eq!(up.scheme, UpstreamScheme::Socks5);

    // the release login replaces the empty one
    for host in [
        "egress-fr.egress.svc",
        "egress-fr.egress.svc.cluster.local",
        "10.43.12.7",
    ] {
        let e = entry("vpn-pool", Subtype::Datacenter, host, 1080, "fr");
        assert_endpoint(
            &a,
            &login_spec(&e, "socks", "s3cret"),
            "socks",
            "s3cret",
            host,
            1080,
        );
    }
    // the same hosts are refused for a customer upstream
    let customer = shipped_adapter("customer");
    assert!(customer.public_only());
    let e = entry(
        "customer",
        Subtype::Datacenter,
        "egress-fr.egress.svc",
        1080,
        "fr",
    );
    assert!(is_not_public(&customer, &static_spec(&e)));
}

#[test]
fn customer_socks5_dials_over_socks5_with_the_org_login() {
    let a = shipped_adapter("customer_socks5");
    assert!(a.public_only());
    let e = entry(
        "customer_socks5",
        Subtype::Datacenter,
        "proxy.example.com",
        1080,
        "us",
    );
    let spec = login_spec(&e, "u1", "p1");
    assert_endpoint(&a, &spec, "u1", "p1", "proxy.example.com", 1080);
    assert_eq!(
        a.recipe(&spec).expect("recipe").scheme,
        UpstreamScheme::Socks5
    );
}

#[test]
fn local_binds_the_host_of_each_entry_and_sends_no_login() {
    let a = shipped_adapter("local");
    assert!(!a.public_only());
    assert_eq!(a.scheme(), UpstreamScheme::Local);
    for host in [
        "127.0.0.2",
        "203.0.113.10",
        "10.0.0.5",
        "2001:db8::5",
        "::1",
    ] {
        // the port of an entry is not used, whatever it says
        for port in [0, 3128] {
            let e = entry("local", Subtype::Datacenter, host, port, "fr");
            let up = a.recipe(&static_spec(&e)).expect("recipe");
            assert_eq!(up.scheme, UpstreamScheme::Local, "{host}");
            assert_eq!(up.host, host);
            assert_eq!(up.port, 0);
            assert!(up.username.is_empty() && up.password.is_empty());
            assert!(!up.public_only);
        }
    }
    // the exit IP of the entry is not the bound address (1:1 NAT): the
    // endpoint still names the bound address
    let nat = entry("local", Subtype::Datacenter, "10.0.0.5", 0, "de");
    assert_ne!(nat.ip.to_string(), nat.host);
    assert_eq!(
        a.recipe(&static_spec(&nat)).expect("recipe").host,
        "10.0.0.5"
    );
    // an IPv6 literal is normalised the way a socket address prints it
    let e = entry("local", Subtype::Datacenter, "2001:DB8:0::5", 0, "fr");
    assert_eq!(
        a.recipe(&static_spec(&e)).expect("recipe").host,
        "2001:db8::5"
    );
}

#[test]
fn local_refuses_what_a_socket_cannot_bind_and_every_credential() {
    let a = shipped_adapter("local");
    for host in [
        "proxy.example.com",
        "localhost",
        "",
        "0.0.0.0",
        "::",
        "224.0.0.1",
        "ff02::1",
        "fe80::1",
        "255.255.255.255",
        "[::1]",
        "127.0.0.1:80",
    ] {
        let e = entry("local", Subtype::Datacenter, host, 0, "fr");
        assert_eq!(refused(&a, &static_spec(&e)), "host", "{host:?}");
    }
    let e = entry("local", Subtype::Datacenter, "127.0.0.2", 0, "fr");
    // no login: neither a parsed pair nor a credentials file name
    assert!(is_mismatch(&a, &login_spec(&e, "u", "p")));
    let mut named = e.clone();
    named.credentials = Some("login".to_owned());
    assert!(is_mismatch(&a, &static_spec(&named)));
    // the spec must fit the adapter like for any other
    assert!(is_mismatch(&a, &rotating("sid", 10, &region("fr"), false)));
    let isp = entry("local", Subtype::Isp, "127.0.0.2", 0, "fr");
    assert!(is_mismatch(&a, &static_spec(&isp)));
    let other = entry("customer", Subtype::Datacenter, "127.0.0.2", 0, "fr");
    assert!(is_mismatch(&a, &static_spec(&other)));
}

#[test]
fn local_keeps_the_target_port_allow_list_and_limits() {
    let file: AdapterFile = toml::from_str(
        "[[adapter]]\nid = \"lan\"\nkind = \"static\"\nsubtype = \"isp\"\nscheme = \"local\"\n\
         allowed_ports = [80, 443]\nmax_conns_per_ip = 50\necho_url = \"http://echo.example.com/ip\"\n",
    )
    .expect("parse");
    let set = AdapterSet::from_configs(file.adapter, &secrets).expect("loads");
    let a = get(&set, "lan");
    assert!(a.port_allowed(80) && a.port_allowed(443) && !a.port_allowed(25));
    assert_eq!(a.max_conns_per_ip(), Some(50));
    assert_eq!(a.echo_url(), Some("http://echo.example.com/ip"));
    let e = entry("lan", Subtype::Isp, "127.0.0.2", 0, "fr");
    assert_eq!(
        a.recipe(&static_spec(&e)).expect("recipe").host,
        "127.0.0.2"
    );
}

#[test]
fn local_adapter_files_that_describe_a_proxy_are_refused_at_load() {
    let head = "[[adapter]]\nid = \"x\"\nkind = \"static\"\nscheme = \"local\"\n";
    let load = |subtype: &str, extra: &str| {
        let file: AdapterFile =
            toml::from_str(&format!("{head}subtype = \"{subtype}\"\n{extra}")).expect("parse");
        AdapterSet::from_configs(file.adapter, &secrets).map(|_| ())
    };
    assert!(load("datacenter", "").is_ok());
    assert!(load("isp", "").is_ok());
    // a template and `credentials_optional` are harmless: no login is rendered
    assert!(
        load(
            "datacenter",
            "credentials_optional = true\nuser = \"{base_user}\"\n"
        )
        .is_ok()
    );

    for (extra, key) in [
        ("host = \"127.0.0.2\"\n", "host"),
        ("port = 1080\n", "port"),
        ("user_file = \"res_user_prefix_user\"\n", "user_file"),
        ("pass_file = \"res_user_prefix_pass\"\n", "pass_file"),
        ("public_only = true\n", "public_only"),
        (
            "[[adapter.option]]\nname = \"country\"\nto = \"user\"\nfrag = \"-c-{v}\"\n",
            "option",
        ),
    ] {
        let reason = config_error(&format!("{head}subtype = \"datacenter\"\n{extra}"));
        assert!(
            reason.contains("local") && reason.contains(key),
            "{key}: {reason}"
        );
    }
    // only a plain static subtype: no rotating kind, no SIM box
    let reason = config_error(
        "[[adapter]]\nid = \"x\"\nkind = \"rotating\"\nsubtype = \"residential\"\nscheme = \"local\"\nhost = \"a\"\nport = 1\n",
    );
    assert!(reason.contains("local"), "{reason}");
    let reason = config_error(&format!(
        "{head}subtype = \"mobile_box\"\n[adapter.rotate]\nmethod = \"POST\"\nurl = \"http://a.example.com/r\"\n"
    ));
    assert!(reason.contains("local"), "{reason}");
    let reason = config_error(&format!("{head}subtype = \"mobile_box\"\n"));
    assert!(reason.contains("local"), "{reason}");
}

#[test]
fn refuses_values_outside_charset_and_length() {
    let a = shipped_adapter("res_user_suffix");
    let fr = region("fr");
    // dot, dash, space, injection, non-ASCII: refused, never escaped
    for bad in [
        "abcd.234abcd1234",
        "abcd-234abcd1234",
        "abcd 234abcd1234",
        "abcd1234abcd123\n",
        "abcd1234abcd12é4",
    ] {
        assert_eq!(
            refused(&a, &rotating(bad, 10, &fr, false)),
            "sid",
            "{bad:?}"
        );
    }
    // exactly 16 characters: 15, 17 and none refused
    for len in [0, 15, 17] {
        let sid = "a".repeat(len);
        assert_eq!(refused(&a, &rotating(&sid, 10, &fr, false)), "sid", "{len}");
    }
    assert!(a.recipe(&rotating(&"a".repeat(16), 10, &fr, false)).is_ok());

    let ip = shipped_adapter("res_pass_suffix");
    let br = region("br");
    for bad in ["abcdefghi", "abcdefg_"] {
        assert_eq!(refused(&ip, &rotating(bad, 10, &br, false)), "sid", "{bad}");
    }
}

#[test]
fn refuses_durations_above_the_provider_maximum() {
    let a = shipped_adapter("res_user_suffix");
    let fr = region("fr");
    let sid = "abcd1234abcd1234";
    assert!(a.recipe(&rotating(sid, 30, &fr, false)).is_ok());
    assert_eq!(refused(&a, &rotating(sid, 31, &fr, false)), "ttl");
    assert_eq!(refused(&a, &rotating(sid, 0, &fr, false)), "ttl");
}

#[test]
fn refuses_a_city_the_provider_cannot_express() {
    let paris = region("fr/paris");
    let a = shipped_adapter("res_pass_suffix");
    assert_eq!(
        refused(&a, &rotating("abcdefgh", 10, &paris, false)),
        "city"
    );
}

#[test]
fn refuses_specs_of_the_wrong_kind_provider_or_subtype() {
    let fr = region("fr");
    let isp = shipped_adapter("isp_static_port");
    assert!(is_mismatch(
        &isp,
        &rotating("abcd1234abcd1234", 10, &fr, false)
    ));
    let wrong = [
        // a static spec for a rotating adapter
        ("res_user_suffix", "res_user_suffix", Subtype::Isp),
        // an entry of another provider
        ("isp_static_port", "customer", Subtype::Isp),
        // an entry of another subtype
        ("isp_static_port", "isp_static_port", Subtype::Datacenter),
    ];
    for (adapter, provider, subtype) in wrong {
        let e = entry(provider, subtype, "isp.oxylabs.io", 8001, "nl"); // wire-compat: shipped gateway host
        assert!(
            is_mismatch(&shipped_adapter(adapter), &static_spec(&e)),
            "{adapter} took {provider} {subtype:?}"
        );
    }
}

#[test]
fn base_username_with_a_provider_separator_is_refused_at_load() {
    let err = load_shipped_with_secret(
        "res_user_suffix.toml",
        "res_user_suffix_user",
        "acme-sessid-evil",
    )
    .expect_err("separator refused");
    assert!(
        matches!(err, ProviderError::SeparatorInBase { .. }),
        "{err:?}"
    );
    assert!(
        !err.to_string().contains("acme"),
        "error leaks the base: {err}"
    );
}

#[test]
fn entry_credentials_with_a_separator_or_colon_are_refused_at_recipe() {
    let a = fixture_adapter("isp_zone_ip");
    let e = entry("isp_zone_ip", Subtype::Isp, "203.0.113.7", 24000, "us");
    assert!(matches!(
        a.recipe(&login_spec(&e, "zone-ip-1.2.3.4", "p")),
        Err(ProviderError::SeparatorInBase { .. })
    ));
    for user in ["a:b", "a\r\nb"] {
        assert!(matches!(
            a.recipe(&login_spec(&e, user, "p")),
            Err(ProviderError::BadChar { field: "username" })
        ));
    }
}

#[test]
fn fields_cap_at_255_bytes() {
    let build = |user_len: usize| {
        load_shipped_with_secret(
            "isp_static_port.toml",
            "isp_static_port_user",
            &"u".repeat(user_len),
        )
        .expect("load")
    };
    let e = entry(
        "isp_static_port",
        Subtype::Isp,
        "isp.oxylabs.io", // wire-compat: shipped gateway host
        8001,
        "nl",
    );
    let spec = static_spec(&e);
    // the username is sent as is: no prefix
    let ok = build(255);
    assert_eq!(
        get(&ok, "isp_static_port")
            .recipe(&spec)
            .expect("255")
            .username
            .expose()
            .len(),
        255
    );
    let over = build(256);
    assert!(matches!(
        get(&over, "isp_static_port").recipe(&spec),
        Err(ProviderError::FieldTooLong {
            field: "username",
            len: 256
        })
    ));
}

#[test]
fn debug_output_never_shows_credentials() {
    let a = shipped_adapter("res_pass_suffix");
    let br = region("br");
    let up = a
        .recipe(&rotating("sgn34f3e", 10, &br, false))
        .expect("recipe");
    let shown = format!("{up:?}");
    assert!(shown.contains("geo.iproyal.com"), "{shown}"); // wire-compat: shipped gateway host
    for secret in ["ipp", "ipu", "sgn34f3e", "lifetime"] {
        assert!(!shown.contains(secret), "{secret} in {shown}");
    }
    assert!(shown.contains("***"));
    // the adapter holds the base credentials and must not print them either
    let shown = format!("{a:?}");
    assert!(!shown.contains("ipp") && !shown.contains("ipu"), "{shown}");
}

#[test]
fn load_failures() {
    // missing directory
    let missing = AdapterSet::load(&root().join("tests/no-such-dir"), secrets)
        .expect_err("missing directory");
    assert!(
        matches!(&missing, ProviderError::Io { .. })
            && std::error::Error::source(&missing).is_none(),
        "{missing:?}"
    );
    // duplicate id across files
    assert!(matches!(
        AdapterSet::load(&root().join("tests/fixtures/dup"), secrets),
        Err(ProviderError::DuplicateId(d)) if d.as_str() == "twin"
    ));
    // missing secret file
    let err = AdapterSet::load(&root().join("../../data/adapters"), |n| {
        if n == "res_pass_suffix_pass" {
            anyhow::bail!("not mounted");
        }
        secrets(n)
    })
    .expect_err("missing secret");
    assert!(
        matches!(&err, ProviderError::Secret { name, .. } if name == "res_pass_suffix_pass"),
        "{err:?}"
    );
    // the cause is in the message and not also a `source`, so `{:#}` shows it once
    assert_eq!(
        format!("{err:#}").matches("not mounted").count(),
        1,
        "{err:#}"
    );
    assert!(std::error::Error::source(&err).is_none(), "{err:?}");
}

fn config_error(toml: &str) -> String {
    let file: AdapterFile = toml::from_str(toml).expect("parse");
    match AdapterSet::from_configs(file.adapter, &secrets) {
        Err(ProviderError::Config { reason, .. }) => reason,
        other => panic!("expected Config error, got {other:?}"),
    }
}

#[test]
fn broken_adapter_files_are_refused_at_load() {
    let head = r#"[[adapter]]
        id = "x"
        kind = "rotating"
        subtype = "residential"
        host = "gw.example.com"
        port = 1
        user_file = "res_user_prefix_user"
        pass_file = "res_user_prefix_pass"
    "#;
    let opt = |name: &str, to: &str, frag: &str| {
        format!("[[adapter.option]]\nname = \"{name}\"\nto = \"{to}\"\nfrag = \"{frag}\"\n")
    };
    let country = opt("country", "user", "-c-{v}");
    let sid = opt("sid", "user", "-s-{v}");

    // a kind that does not match the subtype
    assert!(
        config_error("[[adapter]]\nid = \"x\"\nkind = \"rotating\"\nsubtype = \"isp\"")
            .contains("subtype")
    );
    // rotating adapters need country and sid
    assert!(config_error(&format!("{head}{country}")).contains("sid"));
    // a fragment must hold {v} exactly once
    assert!(config_error(&format!("{head}{country}{}", opt("sid", "user", "-s-"))).contains("{v}"));
    // options write into a field whose template has a slot
    assert!(
        config_error(&format!("{head}{country}{}", opt("sid", "host", "{v}."))).contains("opts")
    );
    // no session options on a static adapter
    assert!(
        config_error(&format!(
            "[[adapter]]\nid = \"x\"\nkind = \"static\"\nsubtype = \"isp\"\n{sid}"
        ))
        .contains("sessions")
    );
    // a username fragment cannot hold the Basic auth separator
    assert!(
        config_error(&format!("{head}{}{sid}", opt("country", "user", "-c:{v}"))).contains(':')
    );
    // a rotating adapter has no gateway without a host
    assert!(
        config_error(&format!(
            "{}{country}{sid}",
            head.replace("host = \"gw.example.com\"", "")
        ))
        .contains("host")
    );
    // mobile_box needs rotate; others must not have it
    assert!(
        config_error("[[adapter]]\nid = \"x\"\nkind = \"static\"\nsubtype = \"mobile_box\"")
            .contains("rotate")
    );
    assert!(config_error(
        "[[adapter]]\nid = \"x\"\nkind = \"static\"\nsubtype = \"isp\"\n[adapter.rotate]\nmethod = \"POST\"\nurl = \"http://a.example.com/r\""
    )
    .contains("mobile_box"));
    // an unknown key is a typo, not a setting
    let typo: Result<AdapterFile, _> = toml::from_str(
        "[[adapter]]\nid = \"x\"\nkind = \"static\"\nsubtype = \"isp\"\nhots = \"a\"",
    );
    assert!(typo.is_err());
    // an empty file is fine
    assert!(
        toml::from_str::<AdapterFile>("")
            .expect("empty")
            .adapter
            .is_empty()
    );
}

fn rotating_seconds<'a>(
    sid: &'a str,
    seconds: u64,
    region: &'a Region,
    strict: bool,
) -> UnitSpec<'a> {
    UnitSpec::Rotating {
        session_id: sid,
        ttl: Duration::from_secs(seconds),
        region,
        strict,
    }
}

#[test]
fn res_pass_suffix_seconds_and_seven_day_bounds_are_exact() {
    let adapter = shipped_adapter("res_pass_suffix");
    let br = region("br");
    for seconds in [1, 59, 60, 61, 604_800] {
        assert_eq!(
            render(&adapter, &rotating_seconds("sgn34f3e", seconds, &br, false)).1,
            format!("ipp_country-br_session-sgn34f3e_lifetime-{seconds}s"),
        );
    }
    assert_eq!(
        refused(&adapter, &rotating_seconds("sgn34f3e", 0, &br, false)),
        "ttl"
    );
    assert_eq!(
        refused(&adapter, &rotating_seconds("sgn34f3e", 604_801, &br, false)),
        "ttl"
    );
}

#[test]
fn minute_provider_rounds_up_without_exceeding_thirty_minutes() {
    let adapter = shipped_adapter("res_user_suffix");
    let fr = region("fr");
    let sid = "abcd1234abcd1234";
    for (seconds, minutes) in [(1, 1), (59, 1), (60, 1), (61, 2), (1800, 30)] {
        assert_eq!(
            render(&adapter, &rotating_seconds(sid, seconds, &fr, false)).0,
            format!("customer-resu-cc-FR-sessid-{sid}-sesstime-{minutes}"),
        );
        assert_eq!(
            adapter
                .normalize_session_ttl(Duration::from_secs(seconds))
                .expect("normalize"),
            Duration::from_secs(minutes * 60),
        );
    }
    assert_eq!(
        refused(&adapter, &rotating_seconds(sid, 1801, &fr, false)),
        "ttl"
    );
    let fractional = UnitSpec::Rotating {
        session_id: sid,
        ttl: Duration::from_millis(1500),
        region: &fr,
        strict: false,
    };
    assert_eq!(refused(&adapter, &fractional), "ttl");
}

#[test]
fn res_numeric_sticky_http_and_socks5_golden() {
    let us = region("us/los_angeles");
    for (id, scheme, port) in [
        ("res_numeric_sticky_http", UpstreamScheme::Http, 80),
        ("res_numeric_sticky_socks5", UpstreamScheme::Socks5, 1080),
    ] {
        let adapter = shipped_adapter(id);
        let spec = rotating_seconds("1234567890123456", 61, &us, false);
        assert_endpoint(
            &adapter,
            &spec,
            "webuser-us-city_los_angeles-1234567890123456",
            "webpass",
            "p.webshare.io", // wire-compat: shipped gateway host
            port,
        );
        assert_eq!(adapter.recipe(&spec).expect("recipe").scheme, scheme);
        assert_eq!(adapter.session_mode(), SessionMode::Sticky);
        assert_eq!(adapter.session_id_alphabet(), b"0123456789");
        assert_eq!(adapter.session_id_len(), Some(16));
        assert!(is_mismatch(
            &adapter,
            &rotating_seconds("1234567890123456", 61, &us, true)
        ));
        assert_eq!(
            refused(
                &adapter,
                &rotating_seconds("abcdef1234567890", 61, &us, false)
            ),
            "sid"
        );
        assert_eq!(
            refused(
                &adapter,
                &rotating_seconds("1234567890123456", 61, &region("us/city2"), false)
            ),
            "city",
        );
        assert!(
            adapter
                .recipe(&rotating("1234567890123456", 1440, &us, false))
                .is_ok()
        );
        assert_eq!(
            refused(&adapter, &rotating("1234567890123456", 1441, &us, false)),
            "ttl"
        );
    }
}

#[test]
fn numeric_session_per_request_http_and_socks5_golden() {
    let us = region("us");
    for (id, scheme, port) in [
        ("res_numeric_rotating_http", UpstreamScheme::Http, 80),
        ("res_numeric_rotating_socks5", UpstreamScheme::Socks5, 1080),
    ] {
        let adapter = shipped_adapter(id);
        let spec = rotating_seconds("localTracking1", 30, &us, false);
        assert_endpoint(
            &adapter,
            &spec,
            "webuser-us-rotate",
            "webpass",
            "p.webshare.io", // wire-compat: shipped gateway host
            port,
        );
        assert_eq!(adapter.recipe(&spec).expect("recipe").scheme, scheme);
        assert_eq!(adapter.session_mode(), SessionMode::PerRequest);
        assert_eq!(
            render(&adapter, &spec),
            render(&adapter, &rotating_seconds("differentId", 60, &us, false)),
        );
        assert_eq!(
            render(
                &adapter,
                &rotating_seconds("localTracking1", 30, &region("us/houston"), false)
            )
            .0,
            "webuser-us-city_houston-rotate",
        );
        assert!(is_mismatch(
            &adapter,
            &rotating_seconds("localTracking1", 30, &us, true)
        ));
    }
}

#[test]
fn zone_full_username_golden() {
    let adapter = shipped_adapter("res_zone");
    let us = region("us/sanfrancisco");
    assert_endpoint(
        &adapter,
        &rotating_seconds("scan42", 61, &us, true),
        "acct-example-zone-residential-country-us-city-sanfrancisco-session-scan42-const",
        "zonepass",
        "brd.superproxy.io", // wire-compat: shipped gateway host
        33335,
    );
    assert_eq!(
        render(&adapter, &rotating("scan42", 10, &region("us"), false)).0,
        "acct-example-zone-residential-country-us-session-scan42",
    );
    assert_eq!(
        refused(&adapter, &rotating("scan-42", 10, &us, false)),
        "sid"
    );
}

#[test]
fn https_adapter_preserves_tls_transport_and_public_address_rules() {
    let adapter = shipped_adapter("customer_https");
    let public = entry(
        "customer_https",
        Subtype::Datacenter,
        "proxy.example.com",
        443,
        "us",
    );
    let endpoint = adapter
        .recipe(&login_spec(&public, "tlsuser", "tlspass"))
        .expect("recipe");
    assert_eq!(endpoint.scheme, UpstreamScheme::Https);
    assert_endpoint(
        &adapter,
        &login_spec(&public, "tlsuser", "tlspass"),
        "tlsuser",
        "tlspass",
        "proxy.example.com",
        443,
    );
    let private = entry(
        "customer_https",
        Subtype::Datacenter,
        "127.0.0.1",
        443,
        "us",
    );
    assert!(is_not_public(&adapter, &static_spec(&private)));
}

#[test]
fn session_identity_roundtrips_normalized_lifetime_and_strictness() {
    let adapter = shipped_adapter("res_user_suffix");
    let sid = "abcd1234abcd1234";
    let encoded = adapter
        .encode_session(sid, Duration::from_secs(61), true)
        .expect("encode");
    assert_eq!(encoded, "abcd1234abcd1234~120~1");
    let decoded = adapter.decode_session(&encoded).expect("decode");
    assert_eq!(decoded.session_id, sid);
    assert_eq!(decoded.ttl, Duration::from_secs(120));
    assert!(decoded.strict);
    let fr = region("fr");
    assert_eq!(
        render(
            &adapter,
            &UnitSpec::Rotating {
                session_id: decoded.session_id,
                ttl: decoded.ttl,
                region: &fr,
                strict: decoded.strict,
            }
        ),
        render(&adapter, &rotating_seconds(sid, 61, &fr, true)),
    );
    let legacy = adapter.decode_session(sid).expect("legacy");
    assert_eq!(legacy.ttl, adapter.session_life());
    assert!(!legacy.strict);
    let seconds = shipped_adapter("res_pass_suffix");
    let encoded = seconds
        .encode_session("12345678", Duration::from_secs(1), false)
        .expect("seconds");
    assert_eq!(encoded, "12345678~1~0");
    assert_eq!(
        seconds.decode_session(&encoded).expect("decode").ttl,
        Duration::from_secs(1)
    );
}

#[test]
fn session_identity_refuses_malformed_or_unsupported_inputs() {
    let adapter = shipped_adapter("res_user_suffix");
    for bad in [
        "abcd1234abcd1234~",
        "abcd1234abcd1234~60",
        "abcd1234abcd1234~0~0",
        "abcd1234abcd1234~61~0",
        "abcd1234abcd1234~60~2",
        "abcd1234abcd1234~60~0~extra",
        "abcd1234abcd1234~no~0",
        "abcd1234abcd1234~18446744073709551615~0",
        "abcd1234abcd1234~1801~0",
        "bad-sid~60~0",
    ] {
        assert!(adapter.decode_session(bad).is_err(), "{bad}");
    }
    assert!(
        adapter
            .encode_session("bad~sid", Duration::from_secs(60), false)
            .is_err()
    );
    assert!(
        adapter
            .encode_session("abcd1234abcd1234", Duration::ZERO, false)
            .is_err()
    );
    let numeric = shipped_adapter("res_numeric_sticky_http");
    assert!(
        numeric
            .encode_session("1234567890123456", Duration::from_secs(60), true)
            .is_err()
    );
    assert!(numeric.decode_session("1234567890123456~60~1").is_err());
    assert!(
        shipped_adapter("customer")
            .decode_session("12345678")
            .is_err()
    );
}

#[test]
fn per_request_session_options_and_static_session_mode_are_refused() {
    let text = std::fs::read_to_string(root().join("../../data/adapters/res_numeric_session.toml"))
        .expect("read");
    let file: AdapterFile = toml::from_str(&text).expect("parse");
    let sticky = file
        .adapter
        .iter()
        .find(|c| c.id.as_str() == "res_numeric_sticky_http")
        .expect("sticky");
    let mut config = sticky.clone();
    config.session_mode = SessionMode::PerRequest;
    assert!(matches!(
        AdapterSet::from_configs(vec![config], &secrets),
        Err(ProviderError::Config { .. })
    ));
    assert!(config_error(
        "[[adapter]]\nid = \"x\"\nkind = \"static\"\nsubtype = \"isp\"\nsession_mode = \"per_request\""
    ).contains("session_mode"));
}

#[test]
fn lifetime_option_maximum_applies_without_an_explicit_adapter_cap() {
    let adapter = fixture_adapter("res_package_key");
    assert_eq!(
        adapter
            .normalize_session_ttl(Duration::from_secs(604_800))
            .expect("option maximum"),
        Duration::from_secs(604_800),
    );
    assert!(
        adapter
            .normalize_session_ttl(Duration::from_secs(604_801))
            .is_err()
    );
    assert!(
        adapter
            .normalize_session_ttl(Duration::from_secs(u64::MAX))
            .is_err()
    );
    let minutes = fixture_adapter("res_user_prefix");
    assert_eq!(
        minutes
            .normalize_session_ttl(Duration::from_secs(61))
            .expect("round"),
        Duration::from_secs(120),
    );
    assert!(
        minutes
            .normalize_session_ttl(Duration::from_secs(1440 * 60 + 1))
            .is_err()
    );
}

#[test]
fn adapter_unknown_transport_names_are_not_coerced_to_http() {
    let result = toml::from_str::<AdapterFile>(
        "[[adapter]]\nid = \"x\"\nkind = \"static\"\nsubtype = \"isp\"\nscheme = \"httpps\"",
    );
    assert!(result.is_err());
}
