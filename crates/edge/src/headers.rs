//! Header policy for forwarded HTTP: hop-by-hop stripping, `X-Forwarded-For`
//! and `Via` handling, operator removals and replacements.

use std::collections::HashSet;
use std::net::IpAddr;

use anyhow::bail;

use crate::config::{Action, ForwardedFor, HeaderRuleConfig, HttpConfig, RuleConfig, RuleStage};

/// One header as read from the wire (value bytes are not necessarily UTF-8).
pub type Header = (String, Vec<u8>);

/// Headers that belong to one connection, not to the message (RFC 9110 7.6.1).
const HOP_BY_HOP: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "upgrade",
];

fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

fn check_value(v: &str) -> bool {
    !v.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
}

/// Reject connection options that would remove routing, framing or proxy metadata.
pub(crate) fn validate_request_connection(h: &[Header]) -> Result<(), &'static str> {
    let has_upgrade = h.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("upgrade") && !value.trim_ascii().is_empty()
    });
    for (_, value) in h
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
    {
        if !value.is_ascii() {
            return Err("Connection options must be ASCII");
        }
        for token in value.split(|b| *b == b',').map(<[u8]>::trim_ascii) {
            if [
                b"content-length".as_slice(),
                b"transfer-encoding",
                b"host",
                b"te",
                b"trailer",
            ]
            .iter()
            .any(|name| token.eq_ignore_ascii_case(name))
                || token
                    .get(..6)
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"proxy-"))
            {
                return Err("Connection must not nominate routing, framing or proxy headers");
            }
            if token.eq_ignore_ascii_case(b"upgrade") && !has_upgrade {
                return Err("Connection upgrade requires an Upgrade header");
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct HeaderPolicy {
    xff: ForwardedFor,
    via: Option<String>,
    req_remove: HashSet<String>,
    req_set: Vec<(String, String)>,
    resp_remove: HashSet<String>,
    resp_set: Vec<(String, String)>,
    rules: Vec<RuleEdits>,
}

#[derive(Debug, Clone)]
struct RuleEdits {
    rule: String,
    request_remove: Vec<String>,
    request_set: Vec<Header>,
    response_remove: Vec<String>,
    response_set: Vec<Header>,
}

fn check_edit_name(name: &str) -> anyhow::Result<()> {
    if !is_token(name)
        || HOP_BY_HOP.iter().any(|h| name.eq_ignore_ascii_case(h))
        || ["host", "content-length", "transfer-encoding"]
            .iter()
            .any(|h| name.eq_ignore_ascii_case(h))
    {
        bail!("http.header_rule: cannot rewrite routing, framing or connection header {name:?}");
    }
    Ok(())
}

impl RuleEdits {
    fn compile(c: &HeaderRuleConfig) -> anyhow::Result<Self> {
        for name in c
            .request_headers_remove
            .iter()
            .chain(&c.response_headers_remove)
            .chain(c.request_headers_set.keys())
            .chain(c.response_headers_set.keys())
        {
            check_edit_name(name)?;
        }
        let sets = |values: &std::collections::BTreeMap<String, String>| {
            values
                .iter()
                .map(|(name, value)| {
                    if !check_value(value) {
                        bail!("http.header_rule: invalid header value for {name:?}");
                    }
                    Ok((name.clone(), value.as_bytes().to_vec()))
                })
                .collect::<anyhow::Result<Vec<Header>>>()
        };
        Ok(Self {
            rule: c.rule.clone(),
            request_remove: c.request_headers_remove.clone(),
            request_set: sets(&c.request_headers_set)?,
            response_remove: c.response_headers_remove.clone(),
            response_set: sets(&c.response_headers_set)?,
        })
    }
}

/// Every scoped policy names exactly one allow rule; ambiguous references fail closed.
pub fn validate_rules(c: &HttpConfig, rules: &[RuleConfig]) -> anyhow::Result<()> {
    let mut seen = HashSet::new();
    for policy in &c.header_rules {
        let mut matching = rules
            .iter()
            .filter(|rule| rule.name.as_deref() == Some(&policy.rule));
        let valid = matching
            .next()
            .is_some_and(|rule| rule.action == Action::Allow && rule.stage == RuleStage::Request)
            && matching.next().is_none();
        if policy.rule.is_empty() || !valid || !seen.insert(&policy.rule) {
            bail!(
                "http.header_rule: {:?} must name one unique request-stage allow rule",
                policy.rule
            );
        }
    }
    Ok(())
}

fn apply_edits(h: &mut Vec<Header>, remove: &[String], set: &[Header]) {
    h.retain(|(name, _)| {
        !remove.iter().any(|other| name.eq_ignore_ascii_case(other))
            && !set
                .iter()
                .any(|(other, _)| name.eq_ignore_ascii_case(other))
    });
    h.extend_from_slice(set);
}

impl HeaderPolicy {
    pub fn compile(c: &HttpConfig) -> anyhow::Result<Self> {
        let names = |what: &str, list: &[String]| -> anyhow::Result<HashSet<String>> {
            list.iter()
                .map(|n| {
                    if is_token(n) {
                        Ok(n.to_ascii_lowercase())
                    } else {
                        bail!("http.{what}: {n:?} is not a header name")
                    }
                })
                .collect()
        };
        let sets = |what: &str, m: &std::collections::BTreeMap<String, String>| {
            m.iter()
                .map(|(k, v)| {
                    if !is_token(k) || !check_value(v) {
                        bail!("http.{what}: bad header {k:?}");
                    }
                    Ok((k.clone(), v.clone()))
                })
                .collect::<anyhow::Result<Vec<_>>>()
        };
        if c.via && (!is_token(&c.proxy_name) || c.proxy_name.contains(' ')) {
            bail!("http.proxy_name must be a token");
        }
        Ok(Self {
            xff: c.forwarded_for,
            via: c.via.then(|| format!("1.1 {}", c.proxy_name)),
            req_remove: names("request_headers_remove", &c.request_headers_remove)?,
            req_set: sets("request_headers_set", &c.request_headers_set)?,
            resp_remove: names("response_headers_remove", &c.response_headers_remove)?,
            resp_set: sets("response_headers_set", &c.response_headers_set)?,
            rules: c
                .header_rules
                .iter()
                .map(RuleEdits::compile)
                .collect::<anyhow::Result<_>>()?,
        })
    }

    /// Rewrite the headers of a request about to go to the target (or a
    /// parent). With `upgrade` the `Connection`/`Upgrade` pair stays, for a
    /// WebSocket handshake.
    pub fn apply_request(&self, h: &mut Vec<Header>, client: IpAddr, upgrade: bool) {
        strip_hop_by_hop(h, upgrade);
        h.retain(|(n, _)| !n.eq_ignore_ascii_case("proxy-authorization"));
        let old_xff: Vec<Vec<u8>> = h
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("x-forwarded-for"))
            .map(|(_, v)| v.clone())
            .collect();
        match self.xff {
            ForwardedFor::Transparent => {}
            ForwardedFor::Delete => {
                remove(h, &["x-forwarded-for", "forwarded", "x-real-ip"]);
            }
            ForwardedFor::Off => {
                remove(h, &["x-forwarded-for", "forwarded", "x-real-ip"]);
                h.push(("X-Forwarded-For".to_owned(), b"unknown".to_vec()));
            }
            ForwardedFor::Truncate => {
                remove(h, &["x-forwarded-for"]);
                h.push((
                    "X-Forwarded-For".to_owned(),
                    client.to_string().into_bytes(),
                ));
            }
            ForwardedFor::On => {
                remove(h, &["x-forwarded-for"]);
                let mut v = old_xff.join(&b", "[..]);
                if !v.is_empty() {
                    v.extend_from_slice(b", ");
                }
                v.extend_from_slice(client.to_string().as_bytes());
                h.push(("X-Forwarded-For".to_owned(), v));
            }
        }
        if let Some(via) = &self.via {
            append_via(h, via);
        }
        for n in &self.req_remove {
            h.retain(|(k, _)| !k.eq_ignore_ascii_case(n));
        }
        for (k, v) in &self.req_set {
            h.retain(|(n, _)| !n.eq_ignore_ascii_case(k));
            h.push((k.clone(), v.clone().into_bytes()));
        }
    }

    /// Rewrite the headers of a response before it goes to the client.
    pub fn apply_response(&self, h: &mut Vec<Header>, upgrade: bool) {
        strip_hop_by_hop(h, upgrade);
        if let Some(via) = &self.via {
            append_via(h, via);
        }
        for n in &self.resp_remove {
            h.retain(|(k, _)| !k.eq_ignore_ascii_case(n));
        }
        for (k, v) in &self.resp_set {
            h.retain(|(n, _)| !n.eq_ignore_ascii_case(k));
            h.push((k.clone(), v.clone().into_bytes()));
        }
    }

    /// Apply request edits for the access rule that authorized this request.
    pub fn apply_rule_request(&self, h: &mut Vec<Header>, rule: Option<&str>) {
        if let Some(edits) = self
            .rules
            .iter()
            .find(|edits| Some(edits.rule.as_str()) == rule)
        {
            apply_edits(h, &edits.request_remove, &edits.request_set);
        }
    }

    /// Apply response edits for the access rule that authorized this request.
    pub fn apply_rule_response(&self, h: &mut Vec<Header>, rule: Option<&str>) {
        if let Some(edits) = self
            .rules
            .iter()
            .find(|edits| Some(edits.rule.as_str()) == rule)
        {
            apply_edits(h, &edits.response_remove, &edits.response_set);
        }
    }
}

fn remove(h: &mut Vec<Header>, names: &[&str]) {
    h.retain(|(n, _)| !names.iter().any(|x| n.eq_ignore_ascii_case(x)));
}

fn append_via(h: &mut Vec<Header>, via: &str) {
    let mut value: Vec<u8> = Vec::new();
    h.retain(|(n, v)| {
        if n.eq_ignore_ascii_case("via") {
            if !value.is_empty() {
                value.extend_from_slice(b", ");
            }
            value.extend_from_slice(v);
            false
        } else {
            true
        }
    });
    if !value.is_empty() {
        value.extend_from_slice(b", ");
    }
    value.extend_from_slice(via.as_bytes());
    h.push(("Via".to_owned(), value));
}

/// Remove the hop-by-hop headers and every header the `Connection` header names.
fn strip_hop_by_hop(h: &mut Vec<Header>, keep_upgrade: bool) {
    let named: Vec<String> = h
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, v)| {
            String::from_utf8_lossy(v)
                .split(',')
                .map(|t| t.trim().to_ascii_lowercase())
                .filter(|t| !t.is_empty())
                .collect::<Vec<_>>()
        })
        .collect();
    h.retain(|(n, _)| {
        let l = n.to_ascii_lowercase();
        if keep_upgrade && l == "upgrade" {
            return true;
        }
        !HOP_BY_HOP.contains(&l.as_str()) && !named.contains(&l)
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn policy(toml: &str) -> HeaderPolicy {
        HeaderPolicy::compile(&Config::parse(toml).expect("parse").http).expect("policy")
    }

    fn hdrs(list: &[(&str, &str)]) -> Vec<Header> {
        list.iter()
            .map(|(k, v)| ((*k).to_owned(), v.as_bytes().to_vec()))
            .collect()
    }

    fn get<'a>(h: &'a [Header], name: &str) -> Vec<&'a [u8]> {
        h.iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_slice())
            .collect()
    }

    const CLIENT: &str = "198.51.100.9";

    fn client() -> IpAddr {
        CLIENT.parse().expect("ip")
    }

    #[test]
    fn connection_options_reject_routing_framing_and_proxy_headers() {
        for token in [
            "content-length",
            "CoNtEnT-LeNgTh",
            "TRANSFER-ENCODING",
            "Host",
            "tE",
            "Trailer",
            "Proxy-Authorization",
            "proxy-authenticate",
            "PROXY-CONNECTION",
            "pRoXy-Custom",
            "\u{a0}content-length",
        ] {
            let value = format!("keep-alive, \t{token}\t, X-Hop");
            let h = hdrs(&[
                ("Connection", "keep-alive"),
                ("cOnNeCtIoN", &value),
                ("Upgrade", "echo"),
            ]);
            assert!(validate_request_connection(&h).is_err(), "{token}");
        }
    }

    #[test]
    fn connection_upgrade_requires_an_actual_upgrade_header() {
        for upgrade in [None, Some(""), Some(" \t")] {
            let mut h = hdrs(&[
                ("Connection", "keep-alive"),
                ("CONNECTION", "X-Hop, UpGrAdE"),
            ]);
            if let Some(value) = upgrade {
                h.push(("Upgrade".to_owned(), value.as_bytes().to_vec()));
            }
            assert!(validate_request_connection(&h).is_err(), "{upgrade:?}");
        }
    }

    #[test]
    fn connection_options_allow_custom_headers_and_arbitrary_upgrades() {
        for h in [
            hdrs(&[]),
            hdrs(&[("Connection", "keep-alive, X-Hop")]),
            hdrs(&[
                ("Connection", "keep-alive"),
                ("cOnNeCtIoN", "X-Hop, UpGrAdE"),
                ("uPgRaDe", "echo"),
            ]),
        ] {
            assert_eq!(validate_request_connection(&h), Ok(()));
        }
    }

    #[test]
    fn hop_by_hop_and_connection_named_headers_go() {
        let p = policy("");
        let mut h = hdrs(&[
            ("Host", "a.test"),
            ("Connection", "keep-alive, X-Secret"),
            ("X-Secret", "1"),
            ("Keep-Alive", "timeout=5"),
            ("Proxy-Authorization", "Basic abc"),
            ("Proxy-Connection", "keep-alive"),
            ("TE", "trailers"),
            ("Upgrade", "websocket"),
            ("Accept", "*/*"),
        ]);
        p.apply_request(&mut h, client(), false);
        let names: Vec<&str> = h.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["Host", "Accept"]);
    }

    #[test]
    fn upgrade_survives_for_a_websocket_handshake() {
        let p = policy("");
        let mut h = hdrs(&[("Connection", "Upgrade"), ("Upgrade", "websocket")]);
        p.apply_request(&mut h, client(), true);
        assert_eq!(get(&h, "upgrade"), vec![&b"websocket"[..]]);
        assert!(
            get(&h, "connection").is_empty(),
            "the caller writes Connection itself"
        );
    }

    #[test]
    fn forwarded_for_modes() {
        let run = |mode: &str, list: &[(&str, &str)]| {
            let p = policy(&format!("[http]\nforwarded_for = \"{mode}\"\n"));
            let mut h = hdrs(list);
            p.apply_request(&mut h, client(), false);
            h
        };
        let with = [
            ("X-Forwarded-For", "1.1.1.1, 2.2.2.2"),
            ("X-Real-IP", "1.1.1.1"),
            ("Forwarded", "for=1.1.1.1"),
        ];
        let h = run("delete", &with);
        assert!(h.is_empty());
        let h = run("off", &with);
        assert_eq!(get(&h, "x-forwarded-for"), vec![&b"unknown"[..]]);
        assert!(get(&h, "x-real-ip").is_empty());
        let h = run("truncate", &with);
        assert_eq!(get(&h, "x-forwarded-for"), vec![CLIENT.as_bytes()]);
        let h = run("on", &with);
        assert_eq!(
            get(&h, "x-forwarded-for"),
            vec![format!("1.1.1.1, 2.2.2.2, {CLIENT}").as_bytes()]
        );
        let h = run("transparent", &with);
        assert_eq!(h.len(), 3);
        assert_eq!(get(&h, "x-forwarded-for"), vec![&b"1.1.1.1, 2.2.2.2"[..]]);
    }

    #[test]
    fn via_is_appended_when_on_only() {
        let off = policy("");
        let mut h = hdrs(&[("Via", "1.0 up")]);
        off.apply_request(&mut h, client(), false);
        assert_eq!(get(&h, "via"), vec![&b"1.0 up"[..]]);
        let on = policy("[http]\nvia = true\nproxy_name = \"edge1\"\n");
        let mut h = hdrs(&[("Via", "1.0 up")]);
        on.apply_request(&mut h, client(), false);
        assert_eq!(get(&h, "via"), vec![&b"1.0 up, 1.1 edge1"[..]]);
        let mut r = hdrs(&[]);
        on.apply_response(&mut r, false);
        assert_eq!(get(&r, "via"), vec![&b"1.1 edge1"[..]]);
    }

    #[test]
    fn operator_removals_and_replacements_win() {
        let p = policy(
            "[http]\nrequest_headers_remove = [\"Referer\", \"x-trace\"]\nresponse_headers_remove = [\"Server\"]\n[http.request_headers_set]\n\"User-Agent\" = \"curl/8\"\n[http.response_headers_set]\n\"X-Served-By\" = \"edge\"\n",
        );
        let mut h = hdrs(&[
            ("referer", "x"),
            ("X-Trace", "1"),
            ("user-agent", "Mozilla"),
            ("Accept", "*/*"),
        ]);
        p.apply_request(&mut h, client(), false);
        assert!(get(&h, "referer").is_empty() && get(&h, "x-trace").is_empty());
        assert_eq!(get(&h, "user-agent"), vec![&b"curl/8"[..]]);
        let mut r = hdrs(&[
            ("Server", "nginx"),
            ("Connection", "close"),
            ("Keep-Alive", "x"),
            ("Content-Length", "3"),
        ]);
        p.apply_response(&mut r, false);
        assert!(get(&r, "server").is_empty() && get(&r, "connection").is_empty());
        assert_eq!(get(&r, "content-length"), vec![&b"3"[..]]);
        assert_eq!(get(&r, "x-served-by"), vec![&b"edge"[..]]);
    }

    #[test]
    fn bad_names_and_values_are_refused() {
        for bad in [
            "[http]\nrequest_headers_remove = [\"bad name\"]\n",
            "[http.request_headers_set]\n\"X-A\" = \"a\\r\\nX-B: b\"\n",
            "[http.request_headers_set]\n\"X A\" = \"a\"\n",
        ] {
            assert!(
                HeaderPolicy::compile(&Config::parse(bad).expect("parse").http).is_err(),
                "{bad}"
            );
        }
    }
}

#[cfg(test)]
mod scoped_tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn scoped_edits_only_touch_the_deciding_rule() {
        let cfg = Config::parse(
            r#"
[[http.header_rule]]
rule = "staff"
request_headers_remove = ["X-Secret"]
request_headers_set = { X-Mode = "staff" }
response_headers_remove = ["Server"]
response_headers_set = { X-Policy = "scoped" }
[[rule]]
name = "staff"
action = "allow"
"#,
        )
        .expect("config");
        validate_rules(&cfg.http, &cfg.rules).expect("valid rule");
        let policy = HeaderPolicy::compile(&cfg.http).expect("policy");
        let original = vec![("X-Secret".to_owned(), b"secret".to_vec())];
        let mut request = original.clone();
        policy.apply_rule_request(&mut request, Some("other"));
        assert_eq!(request, original);
        policy.apply_rule_request(&mut request, Some("staff"));
        assert_eq!(request, vec![("X-Mode".to_owned(), b"staff".to_vec())]);
        let mut response = vec![("Server".to_owned(), b"origin".to_vec())];
        policy.apply_rule_response(&mut response, Some("staff"));
        assert_eq!(response, vec![("X-Policy".to_owned(), b"scoped".to_vec())]);
    }

    #[test]
    fn scoped_edits_refuse_framing_routing_and_injection() {
        for name in [
            "Host",
            "Content-Length",
            "Transfer-Encoding",
            "Connection",
            "Proxy-Authorization",
        ] {
            let cfg = Config::parse(&format!(
                "[[http.header_rule]]\nrule='staff'\nrequest_headers_set={{'{name}'='bad'}}"
            ))
            .expect("config");
            assert!(HeaderPolicy::compile(&cfg.http).is_err(), "{name}");
        }
        let cfg = Config::parse(
            "[[http.header_rule]]\nrule='staff'\nresponse_headers_set={X-Test=\"a\\r\\nInjected: yes\"}",
        )
        .expect("config");
        assert!(HeaderPolicy::compile(&cfg.http).is_err());
    }

    #[test]
    fn scoped_edits_require_unique_named_allow_rule() {
        for rules in [
            "",
            "[[rule]]\nname='staff'\naction='deny'",
            "[[rule]]\nname='staff'\naction='allow'\nstage='post_auth'",
            "[[rule]]\nname='staff'\naction='allow'\n[[rule]]\nname='staff'\naction='allow'",
        ] {
            let cfg = Config::parse(&format!(
                "[[http.header_rule]]\nrule='staff'\nresponse_headers_set={{X-Test='yes'}}\n{rules}"
            ))
            .expect("config");
            assert!(validate_rules(&cfg.http, &cfg.rules).is_err());
        }
    }
}
