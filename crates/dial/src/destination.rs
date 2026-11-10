//! Destination rule: refuse targets that point inside a
//! network before any lease is taken.
//!
//! ProxyX never dials a target itself, but a provider could reach private
//! ranges from its side. The rule covers IP literals in every spelling a
//! resolver accepts (dotted, bracketed IPv6, IPv4-mapped, NAT64, 6to4,
//! decimal/hex/octal/short IPv4) and names that are clearly internal.
//! It cannot see through a public name that resolves to a private address
//! (for example `127.0.0.1.nip.io`); that stays with the provider.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use common::types::Target;

/// Suffixes that only exist inside a network: Kubernetes (`svc`,
/// `cluster.local`), mDNS, cloud and corporate resolvers.
const INTERNAL_SUFFIXES: [&str; 8] = [
    ".svc",
    ".cluster.local",
    ".local",
    ".localhost",
    ".localdomain",
    ".internal",
    ".lan",
    ".home.arpa",
];

/// Azure wire server and instance metadata helper. It is a public address,
/// so no range rule catches it.
const AZURE_WIRESERVER: Ipv4Addr = Ipv4Addr::new(168, 63, 129, 16);

/// True when the gateway must answer `403 destination_denied`.
pub fn is_denied_destination(target: &Target) -> bool {
    let host = target.host.trim();
    // `[::1]` and `[::1]%eth0` forms; a zone id never changes the address.
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.split_once(']').map(|(inner, _)| inner))
        .unwrap_or(host);
    let host = host.split_once('%').map_or(host, |(addr, _zone)| addr);
    let host = host.trim_end_matches('.');
    if host.is_empty() {
        return true;
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v4) => denied_v4(v4),
            IpAddr::V6(v6) => denied_v6(v6),
        };
    }
    if let Some(v4) = parse_legacy_ipv4(host) {
        return denied_v4(v4);
    }
    denied_name(host)
}

fn denied_v4(ip: Ipv4Addr) -> bool {
    if ip == AZURE_WIRESERVER {
        return true;
    }
    match ip.octets() {
        // "this network", private, loopback
        [0 | 10 | 127, ..] => true,
        // CGNAT 100.64/10
        [100, 64..=127, ..] => true,
        // link-local, includes 169.254.169.254 metadata
        [169, 254, ..] => true,
        [172, 16..=31, ..] => true,
        // IETF protocol assignments, TEST-NET-1
        [192, 0, 0 | 2, _] => true,
        [192, 168, ..] => true,
        // benchmarking
        [198, 18 | 19, ..] => true,
        // TEST-NET-2 and TEST-NET-3
        [198, 51, 100, _] | [203, 0, 113, _] => true,
        // multicast, reserved and broadcast
        [224..=255, ..] => true,
        _ => false,
    }
}

fn v4_from_segments(hi: u16, lo: u16) -> Ipv4Addr {
    let [a, b] = hi.to_be_bytes();
    let [c, d] = lo.to_be_bytes();
    Ipv4Addr::new(a, b, c, d)
}

fn denied_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    let low32 = v4_from_segments(s[6], s[7]);
    let high_zero = s[..5].iter().all(|&x| x == 0);

    // ::/96 holds `::`, `::1` and the deprecated IPv4-compatible form.
    if high_zero && s[5] == 0 {
        return true;
    }
    // IPv4-translated (SIIT) ::ffff:0:a.b.c.d embeds the IPv4 target too.
    if s[..4].iter().all(|&x| x == 0) && s[4] == 0xffff && s[5] == 0 {
        return denied_v4(low32);
    }
    // IPv4-mapped ::ffff:a.b.c.d
    if high_zero && s[5] == 0xffff {
        return denied_v4(low32);
    }
    // NAT64 64:ff9b::/96 embeds the IPv4 target; 64:ff9b:1::/48 is local-use.
    if s[0] == 0x0064 && s[1] == 0xff9b {
        return s[2] != 0 || s[3..6].iter().any(|&x| x != 0) || denied_v4(low32);
    }
    // 6to4 2002::/16 embeds the IPv4 target in bits 16..48.
    if s[0] == 0x2002 {
        return denied_v4(v4_from_segments(s[1], s[2]));
    }
    // ULA fc00::/7 (AWS metadata fd00:ec2::254), link-local fe80::/10,
    // deprecated site-local fec0::/10, multicast ff00::/8.
    if s[0] & 0xfe00 == 0xfc00
        || s[0] & 0xffc0 == 0xfe80
        || s[0] & 0xffc0 == 0xfec0
        || s[0] & 0xff00 == 0xff00
    {
        return true;
    }
    // Teredo 2001::/32 tunnels IPv4 and embeds the client's (inverted)
    // address; nothing public is reached that way. Documentation
    // 2001:db8::/32 and discard-only 100::/64.
    (s[0] == 0x2001 && (s[1] == 0 || s[1] == 0x0db8))
        || (s[0] == 0x0100 && s[1..4].iter().all(|&x| x == 0))
}

/// Names that cannot be public: no dot at all, an internal-only suffix (or
/// the bare zone), or a last label that is a number. A name ending in a
/// number is no valid host: it is a malformed or out-of-range IPv4 spelling
/// (`256.1.1.1`, `08.8.8.8`, `0x.1`) that the legacy parser refused.
fn denied_name(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    if host == "localhost" || !host.contains('.') {
        return true;
    }
    let last = host.rsplit('.').next().unwrap_or_default();
    let numeric = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let hex = |s: &str| {
        s.strip_prefix("0x")
            .is_some_and(|h| h.bytes().all(|b| b.is_ascii_hexdigit()))
    };
    if numeric(last) || hex(last) {
        return true;
    }
    // `.home.arpa` also denies the zone `home.arpa` itself.
    INTERNAL_SUFFIXES
        .iter()
        .any(|s| host.ends_with(s) || host == s[1..])
}

/// `inet_aton` spellings that a resolver turns into an IPv4 address:
/// `2130706433`, `0x7f000001`, `017700000001`, `127.1`, `0x7f.0.0.1`.
/// Returns `None` for anything that is not entirely numeric in that grammar,
/// so ordinary hostnames never match.
fn parse_legacy_ipv4(host: &str) -> Option<Ipv4Addr> {
    let mut nums = [0u64; 4];
    let mut n = 0;
    for part in host.split('.') {
        if n == nums.len() {
            return None;
        }
        nums[n] = parse_legacy_number(part)?;
        n += 1;
    }
    let (head, last) = nums[..n].split_at(n - 1);
    if head.iter().any(|&h| h > 255) {
        return None;
    }
    let last = last[0];
    // The last part fills every remaining byte.
    if last >= 1u64 << (8 * (5 - n)) {
        return None;
    }
    let mut value = last;
    for (i, h) in head.iter().enumerate() {
        value |= h << (8 * (3 - i));
    }
    u32::try_from(value).ok().map(Ipv4Addr::from)
}

fn parse_legacy_number(part: &str) -> Option<u64> {
    let (digits, radix) =
        if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
            (hex, 16)
        } else if part.len() > 1 && part.starts_with('0') {
            (&part[1..], 8)
        } else {
            (part, 10)
        };
    // `from_str_radix` accepts a leading `+`; the resolver grammar does not.
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(digits, radix).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn denied(host: &str) -> bool {
        is_denied_destination(&Target {
            host: host.to_owned(),
            port: 443,
        })
    }

    fn assert_denied(hosts: &[&str]) {
        for host in hosts {
            assert!(denied(host), "{host:?} must be denied");
        }
    }

    fn assert_allowed(hosts: &[&str]) {
        for host in hosts {
            assert!(!denied(host), "{host:?} must be allowed");
        }
    }

    #[test]
    fn ipv4_ranges_deny_at_both_edges() {
        assert_denied(&[
            "0.0.0.0",
            "0.255.255.255",
            "10.0.0.1",
            "10.255.255.255",
            "100.64.0.0",
            "100.127.255.255",
            "127.0.0.1",
            "127.255.255.254",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.192",
            "192.0.2.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.19.255.255",
            "198.51.100.7",
            "203.0.113.7",
            "224.0.0.1",
            "239.255.255.255",
            "240.0.0.1",
            "255.255.255.255",
            "168.63.129.16",
        ]);
    }

    #[test]
    fn ipv4_just_outside_the_ranges_is_allowed() {
        assert_allowed(&[
            "1.1.1.1",
            "8.8.8.8",
            "9.255.255.255",
            "11.0.0.0",
            "100.63.255.255",
            "100.128.0.0",
            "126.255.255.255",
            "128.0.0.1",
            "169.253.255.255",
            "169.255.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "192.0.1.1",
            "192.0.3.1",
            "192.167.255.255",
            "192.169.0.0",
            "198.17.255.255",
            "198.20.0.0",
            "198.51.101.1",
            "203.0.112.255",
            "223.255.255.255",
            "168.63.129.15",
            "168.63.129.17",
        ]);
    }

    #[test]
    fn ipv6_literals_in_all_forms() {
        assert_denied(&[
            "::",
            "::1",
            "[::1]",
            "[::1]:8080",
            "0:0:0:0:0:0:0:1",
            "::2",
            "::ffff:127.0.0.1",
            "::ffff:7f00:1",
            "[::ffff:10.1.2.3]",
            "::ffff:169.254.169.254",
            "64:ff9b::a00:1",
            "64:ff9b:1::1",
            "2002:7f00:1::1",
            "2002:a9fe:a9fe::1",
            "fc00::1",
            "fd00:ec2::254",
            "fdff::1",
            "fe80::1",
            "febf::1",
            "fec0::1",
            "fe80::1%eth0",
            "[fe80::1%25eth0]",
            "ff02::1",
            "2001:db8::1",
            "100::1",
        ]);
        assert_allowed(&[
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
            "::ffff:8.8.8.8",
            "[::ffff:808:808]",
            "64:ff9b::808:808",
            "2002:808:808::1",
            "2001:db9::1",
            "fbff::1",
            "fe00::1",
            "100:0:0:1::1",
        ]);
    }

    #[test]
    fn legacy_ipv4_spellings_are_resolved_before_the_check() {
        assert_denied(&[
            "2130706433",
            "0x7f000001",
            "0X7F000001",
            "017700000001",
            "127.1",
            "127.0.1",
            "0x7f.0.0.1",
            "0177.0.0.01",
            "10.1",
            "167772161",
            "2852039166",
        ]);
        // 8.8.8.8 spelled as one number, and not-numbers that look close.
        assert_allowed(&[
            "134744072",
            "0x8080808",
            "example.com",
            "add.bad.com",
            "0x.com",
        ]);
    }

    #[test]
    fn internal_names_are_denied_case_insensitively() {
        assert_denied(&[
            "localhost",
            "LocalHost",
            "localhost.",
            "app.localhost",
            "redis.default.svc",
            "redis.default.svc.cluster.local",
            "Kubernetes.Default.Svc.Cluster.Local.",
            "printer.local",
            "metadata.google.internal",
            "db.localdomain",
            "nas.lan",
            "router.home.arpa",
            "redis",
            "metadata",
            "",
            "  ",
        ]);
    }

    #[test]
    fn public_names_are_allowed() {
        assert_allowed(&[
            "example.com",
            "www.example.co.uk",
            "svc.example.com",
            "local.example.com",
            "localhost.example.com",
            "internal.example.org",
            "xn--bcher-kva.example",
            "8.8.8.8",
            "[2606:4700:4700::1111]",
        ]);
    }

    /// Translated and tunnelled spellings of internal addresses,
    /// the bare `home.arpa` zone and numeric hosts the legacy parser refuses.
    #[test]
    fn previously_found_rule_gaps_are_closed() {
        assert_denied(&[
            "[::ffff:0:7f00:1]",
            "::ffff:0:a00:1",
            "[2001:0:7f00:1::1]",
            "2001::1",
            "home.arpa",
            "HOME.ARPA.",
            "08.8.8.8",
            "0x.1",
            "256.1.1.1",
            "1.1.1.256",
            "example.0x1f",
        ]);
        assert_allowed(&[
            "[::ffff:0:808:808]",
            "2001:1::1",
            "home.arpa.example.com",
            "1.example.com",
            "0x.com",
        ]);
    }
}
