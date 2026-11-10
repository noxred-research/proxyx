//! Golden, refusal and load tests for the adapters. The shipped files in
//! `data/adapters` and the extra providers in `tests/fixtures` are rendered
//! byte for byte.

use std::path::{Path, PathBuf};

use common::Secret;
use common::types::{InventoryEntry, ProviderId, Region, Subtype, UpstreamScheme};
use proxyx_provider::{
    Adapter, AdapterFile, AdapterSet, ProviderError, UnitSpec, ensure_public_address,
};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn secrets(name: &str) -> anyhow::Result<Secret> {
    let value = match name {
        "oxylabs_isp_user" => "acme",
        "oxylabs_isp_pass" => "pw-isp",
        "oxylabs_res_user" => "resu",
        "oxylabs_res_pass" => "resp",
        "iproyal_res_user" => "ipu",
        "iproyal_res_pass" => "ipp",
        "bd_res_user" => "brd-customer-hl_abc-zone-res1",
        "bd_res_pass" => "bdrp",
        "bd_isp_user" => "brd-customer-hl_abc-zone-isp1",
        "bd_isp_pass" => "bdip",
        "decodo_user" => "dec",
        "decodo_pass" => "decp",
        "soax_package_key" => "pkgkey",
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
        ttl_minutes: ttl,
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
            "customer_socks5",
            "iproyal_res",
            "local",
            "oxylabs_isp",
            "oxylabs_res",
            "vpn-pool"
        ]
    );
}

#[test]
fn oxylabs_isp_uses_the_port_of_each_inventory_entry() {
    let a = shipped_adapter("oxylabs_isp");
    for port in [8001, 8003, 8010] {
        let e = entry("oxylabs_isp", Subtype::Isp, "isp.oxylabs.io", port, "nl");
        let spec = static_spec(&e);
        assert_endpoint(&a, &spec, "acme", "pw-isp", "isp.oxylabs.io", port);
        let up = a.recipe(&spec).expect("recipe");
        assert_eq!(up.scheme, UpstreamScheme::Http);
        assert_eq!(up.provider, id("oxylabs_isp"));
    }
}

#[test]
fn oxylabs_isp_entry_credentials_replace_the_base_credentials() {
    let e = entry("oxylabs_isp", Subtype::Isp, "isp.oxylabs.io", 8002, "nl");
    let spec = login_spec(&e, "other", "otherpw");
    assert_endpoint(
        &shipped_adapter("oxylabs_isp"),
        &spec,
        "other",
        "otherpw",
        "isp.oxylabs.io",
        8002,
    );
}

#[test]
fn oxylabs_port_8000_takes_the_country() {
    let e = entry(
        "oxylabs_isp_pool",
        Subtype::Isp,
        "disp.oxylabs.io",
        8001,
        "de",
    );
    let spec = static_spec(&e);
    assert_endpoint(
        &fixture_adapter("oxylabs_isp_pool"),
        &spec,
        "user-acme-country-DE",
        "pw-isp",
        "disp.oxylabs.io",
        8000,
    );
}

#[test]
fn oxylabs_residential_golden() {
    let a = shipped_adapter("oxylabs_res");
    let fr = region("fr");
    let sid = "abcd1234abcd1234";
    assert_endpoint(
        &a,
        &rotating(sid, 30, &fr, false),
        "customer-resu-cc-FR-sessid-abcd1234abcd1234-sesstime-30",
        "resp",
        "pr.oxylabs.io",
        7777,
    );
    // strict swaps the session key, never adds a second one
    assert_eq!(
        render(&a, &rotating(sid, 1440, &fr, true)).0,
        "customer-resu-cc-FR-sessid_oneip-abcd1234abcd1234-sesstime-1440"
    );
    let paris = region("fr/paris");
    assert_eq!(
        render(&a, &rotating(sid, 10, &paris, false)).0,
        "customer-resu-cc-FR-city-paris-sessid-abcd1234abcd1234-sesstime-10"
    );
    assert_eq!(a.session_id_len(), Some(16));
}

#[test]
fn oxylabs_residential_allows_only_80_and_443() {
    let a = shipped_adapter("oxylabs_res");
    assert!(a.port_allowed(80));
    assert!(a.port_allowed(443));
    assert!(!a.port_allowed(8080));
    assert!(!a.port_allowed(22));
    // no list: every port
    assert!(shipped_adapter("oxylabs_isp").port_allowed(8080));
}

#[test]
fn iproyal_puts_the_options_in_the_password() {
    let a = shipped_adapter("iproyal_res");
    let br = region("br");
    assert_endpoint(
        &a,
        &rotating("sgn34f3e", 10, &br, false),
        "ipu",
        "ipp_country-br_session-sgn34f3e_lifetime-10m",
        "geo.iproyal.com",
        12321,
    );
    assert_eq!(
        render(&a, &rotating("sgn34f3e", 30, &br, true)).1,
        "ipp_country-br_session-sgn34f3e_lifetime-30m_killswitch-1"
    );
    assert_eq!(a.session_id_len(), Some(8));
}

#[test]
fn bright_data_golden() {
    let res = fixture_adapter("brightdata_res");
    let us = region("us");
    assert_endpoint(
        &res,
        &rotating("scan42", 10, &us, false),
        "brd-customer-hl_abc-zone-res1-country-us-session-scan42",
        "bdrp",
        "brd.superproxy.io",
        33335,
    );
    assert_eq!(
        render(&res, &rotating("scan42", 10, &us, true)).0,
        "brd-customer-hl_abc-zone-res1-country-us-session-scan42-const"
    );

    let mut e = entry("brightdata_isp", Subtype::Isp, "203.0.113.7", 24000, "us");
    e.ip = "203.0.113.7".parse().expect("ip");
    assert_endpoint(
        &fixture_adapter("brightdata_isp"),
        &static_spec(&e),
        "brd-customer-hl_abc-zone-isp1-ip-203.0.113.7",
        "bdip",
        "brd.superproxy.io",
        33335,
    );
}

#[test]
fn bright_data_session_id_with_a_dash_is_refused() {
    let us = region("us");
    let a = fixture_adapter("brightdata_res");
    assert_eq!(refused(&a, &rotating("scan-42", 10, &us, false)), "sid");
}

#[test]
fn decodo_golden() {
    let a = fixture_adapter("decodo_res");
    let au = region("us/austin");
    assert_endpoint(
        &a,
        &rotating("random123", 60, &au, false),
        "user-dec-country-us-city-austin-session-random123-sessionduration-60",
        "decp",
        "gate.decodo.com",
        7000,
    );
    assert_eq!(
        render(&a, &rotating("random123", 60, &au, true)).0,
        "user-dec-country-us-city-austin-session_iplock-random123-sessionduration-60"
    );
}

#[test]
fn soax_golden_and_no_strict_mode() {
    let a = fixture_adapter("soax_res");
    let fr = region("fr");
    assert_endpoint(
        &a,
        &rotating("job_1", 30, &fr, false),
        "country-fr-session-job_1-rotate-timed_1800",
        "pkgkey",
        "proxy.soax.com",
        1337,
    );
    assert!(is_mismatch(&a, &rotating("job_1", 30, &fr, true)));
    // 33 characters: over the SOAX limit of 32
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
        ("user_file = \"decodo_user\"\n", "user_file"),
        ("pass_file = \"decodo_pass\"\n", "pass_file"),
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
    let a = shipped_adapter("oxylabs_res");
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

    let ip = shipped_adapter("iproyal_res");
    let br = region("br");
    for bad in ["abcdefghi", "abcdefg_"] {
        assert_eq!(refused(&ip, &rotating(bad, 10, &br, false)), "sid", "{bad}");
    }
}

#[test]
fn refuses_durations_above_the_provider_maximum() {
    let a = shipped_adapter("oxylabs_res");
    let fr = region("fr");
    let sid = "abcd1234abcd1234";
    assert!(a.recipe(&rotating(sid, 1440, &fr, false)).is_ok());
    assert_eq!(refused(&a, &rotating(sid, 1441, &fr, false)), "ttl");
    assert_eq!(refused(&a, &rotating(sid, 0, &fr, false)), "ttl");
}

#[test]
fn refuses_a_city_the_provider_cannot_express() {
    let paris = region("fr/paris");
    let a = shipped_adapter("iproyal_res");
    assert_eq!(
        refused(&a, &rotating("abcdefgh", 10, &paris, false)),
        "city"
    );
}

#[test]
fn refuses_specs_of_the_wrong_kind_provider_or_subtype() {
    let fr = region("fr");
    let isp = shipped_adapter("oxylabs_isp");
    assert!(is_mismatch(
        &isp,
        &rotating("abcd1234abcd1234", 10, &fr, false)
    ));
    let wrong = [
        // a static spec for a rotating adapter
        ("oxylabs_res", "oxylabs_res", Subtype::Isp),
        // an entry of another provider
        ("oxylabs_isp", "customer", Subtype::Isp),
        // an entry of another subtype
        ("oxylabs_isp", "oxylabs_isp", Subtype::Datacenter),
    ];
    for (adapter, provider, subtype) in wrong {
        let e = entry(provider, subtype, "isp.oxylabs.io", 8001, "nl");
        assert!(
            is_mismatch(&shipped_adapter(adapter), &static_spec(&e)),
            "{adapter} took {provider} {subtype:?}"
        );
    }
}

#[test]
fn base_username_with_a_provider_separator_is_refused_at_load() {
    let err = load_shipped_with_secret("oxylabs_res.toml", "oxylabs_res_user", "acme-sessid-evil")
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
    let a = fixture_adapter("brightdata_isp");
    let e = entry("brightdata_isp", Subtype::Isp, "203.0.113.7", 24000, "us");
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
            "oxylabs_isp.toml",
            "oxylabs_isp_user",
            &"u".repeat(user_len),
        )
        .expect("load")
    };
    let e = entry("oxylabs_isp", Subtype::Isp, "isp.oxylabs.io", 8001, "nl");
    let spec = static_spec(&e);
    // the username is sent as is: no prefix
    let ok = build(255);
    assert_eq!(
        get(&ok, "oxylabs_isp")
            .recipe(&spec)
            .expect("255")
            .username
            .expose()
            .len(),
        255
    );
    let over = build(256);
    assert!(matches!(
        get(&over, "oxylabs_isp").recipe(&spec),
        Err(ProviderError::FieldTooLong {
            field: "username",
            len: 256
        })
    ));
}

#[test]
fn debug_output_never_shows_credentials() {
    let a = shipped_adapter("iproyal_res");
    let br = region("br");
    let up = a
        .recipe(&rotating("sgn34f3e", 10, &br, false))
        .expect("recipe");
    let shown = format!("{up:?}");
    assert!(shown.contains("geo.iproyal.com"), "{shown}");
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
        if n == "iproyal_res_pass" {
            anyhow::bail!("not mounted");
        }
        secrets(n)
    })
    .expect_err("missing secret");
    assert!(
        matches!(&err, ProviderError::Secret { name, .. } if name == "iproyal_res_pass"),
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
        user_file = "decodo_user"
        pass_file = "decodo_pass"
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
