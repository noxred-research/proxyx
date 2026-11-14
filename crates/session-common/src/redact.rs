//! Credentials in URLs the process logs or prints.
//!
//! A connection URL may carry a password (`redis://user:secret@host/0`, the
//! documented ACL form, `amqp://user:secret@host`, `http://user:secret@ch:8123`)
//! or a token in the query. Anything that names a URL in a log line, an error
//! or a report goes through [`url`] first.

/// Placeholder that replaces a secret.
const MASK: &str = "***";

/// Query parameters whose value is a secret when the name contains one of these.
const SECRET_PARAMS: [&str; 9] = [
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "key",
    "auth",
    "sig",
    "credential",
];

/// `url` with its credentials masked: the password of the user info
/// (`user:secret@` becomes `user:***@`), a user info without a colon
/// (`token@`, which may itself be the secret) and the value of a query
/// parameter named like a secret (`password`, `token`, `api_key`, ...).
/// Scheme, host, port, path and the other parameters stay, so the result still
/// says where the process connects. Also accepts a Sentinel URL with several
/// hosts (`redis+sentinel://:secret@h1:26379,h2:26379/master`) and text that is
/// not a URL (returned unchanged).
pub fn url(url: &str) -> String {
    let (scheme, rest) = match url.split_once("://") {
        Some((scheme, rest)) => (Some(scheme), rest),
        None => (None, url),
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(authority_end);

    let mut out = String::with_capacity(url.len());
    if let Some(scheme) = scheme {
        out.push_str(scheme);
        out.push_str("://");
    }
    match authority.rsplit_once('@') {
        Some((userinfo, hosts)) => {
            match userinfo.split_once(':') {
                Some((user, _)) => {
                    out.push_str(user);
                    out.push(':');
                    out.push_str(MASK);
                }
                None => out.push_str(MASK),
            }
            out.push('@');
            out.push_str(hosts);
        }
        None => out.push_str(authority),
    }
    push_tail(&mut out, tail);
    out
}

/// The path, query and fragment, with secret query values masked.
fn push_tail(out: &mut String, tail: &str) {
    let Some((path, query)) = tail.split_once('?') else {
        out.push_str(tail);
        return;
    };
    out.push_str(path);
    out.push('?');
    let (query, fragment) = match query.split_once('#') {
        Some((query, fragment)) => (query, Some(fragment)),
        None => (query, None),
    };
    for (index, pair) in query.split('&').enumerate() {
        if index > 0 {
            out.push('&');
        }
        match pair.split_once('=') {
            Some((name, _)) if is_secret_param(name) => {
                out.push_str(name);
                out.push('=');
                out.push_str(MASK);
            }
            _ => out.push_str(pair),
        }
    }
    if let Some(fragment) = fragment {
        out.push('#');
        out.push_str(fragment);
    }
}

fn is_secret_param(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    SECRET_PARAMS.iter().any(|secret| name.contains(secret))
}

#[cfg(test)]
mod tests {
    use super::url;

    #[test]
    fn the_password_of_the_user_info_is_masked() {
        for (input, expected) in [
            (
                "redis://px:s3cret@127.0.0.1:6379/0",
                "redis://px:***@127.0.0.1:6379/0",
            ),
            ("rediss://:s3cret@cache:6380", "rediss://:***@cache:6380"),
            ("amqp://u:p%40ss@mq:5672/%2f", "amqp://u:***@mq:5672/%2f"),
            (
                "http://default:s3cret@ch:8123",
                "http://default:***@ch:8123",
            ),
            (
                "postgres://u:s3cret@db/proxyx",
                "postgres://u:***@db/proxyx",
            ),
            // a password that contains `@` and `:`
            ("redis://u:a@b:c@host/1", "redis://u:***@host/1"),
            // a user info without a colon can be the secret itself
            ("https://tok3n@search:9200", "https://***@search:9200"),
        ] {
            assert_eq!(url(input), expected);
        }
    }

    #[test]
    fn a_sentinel_url_with_several_hosts_keeps_the_hosts() {
        assert_eq!(
            url("redis+sentinel://:s3cret@h1:26379,h2:26379/mymaster"),
            "redis+sentinel://:***@h1:26379,h2:26379/mymaster"
        );
    }

    #[test]
    fn secret_query_parameters_are_masked_and_the_others_stay() {
        assert_eq!(
            url("redis://host/0?password=s3cret&timeout=5&API_KEY=k#frag"),
            "redis://host/0?password=***&timeout=5&API_KEY=***#frag"
        );
        assert_eq!(url("http://h:9200/?a=1&b"), "http://h:9200/?a=1&b");
    }

    #[test]
    fn a_url_without_credentials_and_plain_text_are_unchanged() {
        for input in [
            "redis://127.0.0.1:6379/0",
            "http://clickhouse:8123",
            "unix:///run/redis.sock",
            "host:6379",
            "",
        ] {
            assert_eq!(url(input), input);
        }
    }

    #[test]
    fn no_secret_survives_in_any_part() {
        let out = url("redis://user:hunter2@h/0?token=hunter2&x=1");
        assert!(!out.contains("hunter2"), "{out}");
    }
}
