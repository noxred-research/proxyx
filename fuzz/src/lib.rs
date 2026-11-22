//! Fuzz target bodies. Each function takes raw bytes and must never panic; the invariants
//! below are asserted here so a violation is a crash the fuzzer records. The
//! `fuzz_targets/*.rs` binaries are thin wrappers: libFuzzer entry points under
//! `cfg(fuzzing)`, stdin readers otherwise (crash replay on stable).

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use proxyx_edge::auth::{split_login, LoginOptions};
use proxyx_edge::http::parse_basic_value;
use proxyx_edge::password::{self, PasswordError};
use proxyx_pool_api::fuzzing as pool_api;
use std::io::Read as _;

/// Runs `target` once over everything on stdin (the non-libFuzzer entry point).
pub fn run_stdin(target: fn(&[u8])) {
    let mut data = Vec::new();
    if std::io::stdin().read_to_end(&mut data).is_ok() {
        target(&data);
    }
}

/// `htpasswd_parse`: an htpasswd body either loads or fails with the number of the line that
/// is wrong, and an error never repeats a hash. A body that loads lists distinct users with
/// supported hashes and loads again, unchanged, from its own listing.
pub fn htpasswd_parse(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    match password::parse_htpasswd(text) {
        Ok(entries) => {
            let mut listing = String::new();
            let mut seen = std::collections::HashSet::new();
            for (user, hash) in &entries {
                assert!(
                    !user.is_empty() && !user.contains(':'),
                    "user name `{user}` cannot be written back"
                );
                assert!(
                    !user.chars().any(|c| c.is_whitespace() || c.is_control()),
                    "user name `{user}` holds whitespace or a control character"
                );
                assert!(seen.insert(user.as_str()), "user `{user}` listed twice");
                assert!(
                    password::is_supported(hash),
                    "a loaded hash is not supported for `{user}`"
                );
                listing.push_str(user);
                listing.push(':');
                listing.push_str(hash);
                listing.push('\n');
            }
            let again = password::parse_htpasswd(&listing)
                .unwrap_or_else(|e| panic!("own listing is refused: {e}"));
            assert_eq!(again, entries, "listing changed on a second load");
        }
        Err(PasswordError::File { line, reason }) => {
            assert!(
                (1..=text.lines().count()).contains(&line),
                "error names line {line} of {}",
                text.lines().count()
            );
            // The reason is one of a fixed set of texts, so a hash or a user name from the
            // file can never reach the message.
            const REASONS: [&str; 7] = [
                "missing ':' separator",
                "empty user name",
                "user name contains whitespace or control characters",
                "empty hash",
                "unsupported hash format",
                "malformed hash",
                "duplicate user",
            ];
            assert!(
                REASONS.contains(&reason.as_str()),
                "error reason `{reason}` is not a fixed text"
            );
        }
        Err(other) => panic!("parse_htpasswd answered `{other}`, not a line error"),
    }
}

/// Whether verifying `hash` costs little: the fuzzer must not spend its time in a bcrypt of
/// cost 31, a sha-crypt of 999,999,999 rounds or an argon2 of gigabytes. The cost lives in
/// the text of the hash, so it is read from the text.
fn cheap(hash: &str) -> bool {
    let number_after = |text: &str, key: &str| -> Option<u64> {
        let rest = &text[text.find(key)? + key.len()..];
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        digits.parse().ok()
    };
    if let Some(rest) = ["$2a$", "$2b$", "$2x$", "$2y$"]
        .iter()
        .find_map(|p| hash.strip_prefix(p))
    {
        return rest
            .get(..2)
            .and_then(|c| c.parse::<u32>().ok())
            .is_none_or(|c| c <= 5);
    }
    if hash.starts_with("$5$") || hash.starts_with("$6$") {
        return !hash.contains("rounds=")
            || number_after(hash, "rounds=").is_some_and(|r| r <= 2000);
    }
    if hash.starts_with("$argon2") {
        return number_after(hash, "m=").is_some_and(|m| m <= 1024)
            && number_after(hash, "t=").is_some_and(|t| t <= 3)
            && number_after(hash, "p=").is_some_and(|p| p <= 4);
    }
    true
}

/// `password_verify`: `hash`, a NUL byte, then the password. A hash that passes
/// `is_supported` always verifies to an answer (a login never fails on a hash startup
/// accepted), any other hash is an error, and the answer does not change between two checks.
pub fn password_verify(data: &[u8]) {
    let Some(split) = data.iter().position(|b| *b == 0) else {
        return;
    };
    let (Ok(hash), Ok(pass)) = (
        std::str::from_utf8(&data[..split]),
        std::str::from_utf8(&data[split + 1..]),
    ) else {
        return;
    };
    let supported = password::is_supported(hash);
    assert_eq!(
        password::is_legacy_sha1(hash),
        hash.starts_with("{SHA}"),
        "legacy format test"
    );
    if !cheap(hash) {
        return;
    }
    let first = password::verify(hash, pass);
    assert_eq!(
        first.is_ok(),
        supported,
        "is_supported({supported}) and verify disagree for `{hash}`: {first:?}"
    );
    if let Ok(answer) = first {
        let second = password::verify(hash, pass);
        assert_eq!(
            second.ok(),
            Some(answer),
            "verify changed its answer for `{hash}`"
        );
    }
}

/// `basic_header`: the value of a `Proxy-Authorization` header. An accepted value names a
/// user without `:` and writes back to a value that parses to the same pair.
pub fn basic_header(data: &[u8]) {
    let Ok(value) = std::str::from_utf8(data) else {
        return;
    };
    let Some((user, pass)) = parse_basic_value(value) else {
        return;
    };
    assert!(!user.contains(':'), "user `{user}` holds a colon");
    let written = format!("Basic {}", STANDARD.encode(format!("{user}:{pass}")));
    assert_eq!(
        parse_basic_value(&written),
        Some((user, pass)),
        "credentials changed across a re-encode"
    );
}

/// `login_split`: a login name with option pairs on its right end. The name is a prefix of
/// the login, what follows it is exactly the option pairs, and the name splits no further:
/// `Users::build` relies on that to refuse a user name that reads as options.
pub fn login_split(data: &[u8]) {
    let Ok(login) = std::str::from_utf8(data) else {
        return;
    };
    let Some((name, options)) = split_login(login) else {
        return;
    };
    assert!(
        login.starts_with(name),
        "name `{name}` is not a prefix of `{login}`"
    );
    let rest = &login[name.len()..];
    let pairs = [
        options.sid.is_some(),
        options.pool.is_some(),
        options.ip.is_some(),
    ]
    .into_iter()
    .filter(|set| *set)
    .count();
    assert_eq!(
        rest.is_empty(),
        pairs == 0,
        "rest `{rest}` with {pairs} options"
    );
    assert!(
        rest.is_empty() || rest.starts_with('-'),
        "rest `{rest}` has no dash"
    );
    assert_eq!(
        rest.matches('-').count(),
        pairs * 2,
        "rest `{rest}` with {pairs} options"
    );
    assert_ne!(options.ip, Some(0), "ip option 0 is accepted");
    assert_eq!(
        split_login(name),
        Some((name, LoginOptions::default())),
        "name `{name}` of `{login}` splits further"
    );
}

/// `pool_api_body`: the first byte picks a control API route, the rest is its request body.
/// Every route answers the same way twice and never panics, whatever the body holds.
pub fn pool_api_body(data: &[u8]) {
    let Some((route, body)) = data.split_first() else {
        return;
    };
    let first = pool_api::request_body(*route, body);
    assert_eq!(
        pool_api::request_body(*route, body),
        first,
        "route {} answers differently twice",
        route % pool_api::BODY_ROUTES
    );
}

/// `pool_api_endpoint`: an endpoint-generation body. The URL of an accepted request parses
/// back into the username and the credential it was built from, so a client-supplied value
/// cannot change the host or the shape of an exported URL.
pub fn pool_api_endpoint(data: &[u8]) {
    let Ok((username, endpoint, key)) = pool_api::endpoint(data) else {
        return;
    };
    let parsed = url::Url::parse(&endpoint)
        .unwrap_or_else(|e| panic!("exported url `{endpoint}` does not parse: {e}"));
    assert!(
        matches!(parsed.scheme(), "http" | "socks5"),
        "scheme of `{endpoint}`"
    );
    assert!(parsed.host_str().is_some(), "no host in `{endpoint}`");
    assert!(
        parsed.path().is_empty() || parsed.path() == "/",
        "path in `{endpoint}`"
    );
    assert!(
        parsed.query().is_none() && parsed.fragment().is_none(),
        "query or fragment in `{endpoint}`"
    );
    assert_eq!(parsed.username(), username, "username of `{endpoint}`");
    match key {
        Some(key) => {
            let decoded = percent_encoding::percent_decode_str(parsed.password().unwrap_or(""))
                .decode_utf8()
                .unwrap_or_else(|e| panic!("credential of `{endpoint}` is not UTF-8: {e}"));
            assert_eq!(decoded, key, "credential of `{endpoint}`");
        }
        None => assert!(parsed.password().is_none(), "password in `{endpoint}`"),
    }
}
