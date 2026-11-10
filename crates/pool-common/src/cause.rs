//! Cause codes the gateway puts in a refusal status line.
//!
//! the session proxy prints the upstream status line in its dial error
//! (`services/session proxy/crates/proxy/src/listener/connect.rs:289-294`), so the
//! reason phrase carries a short, stable code: `HTTP/1.1 503 cache_empty`.

use std::fmt;

/// Why the gateway refused or failed a tunnel. Every variant is a terminal
/// answer: the gateway never falls back to a direct dial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Cause {
    /// Missing or unknown org key.
    AuthRequired,
    /// The org key exists but an operator disabled it.
    OrgDisabled,
    /// A username option widens the policy or is malformed.
    OptionDenied,
    /// An operator block stops this org in the requested scope.
    OrgBlocked,
    /// The provider does not allow the target port.
    PortNotAllowed,
    /// The target is a private, loopback, link-local, metadata or cluster address.
    DestinationDenied,
    /// The org reached `max_tunnels_per_org`.
    OrgCapacity,
    /// The org used its `limits.org_max_gb_per_day` for the day.
    OrgBudget,
    /// No session or IP could be leased and `on_empty` is `create` or `fail`.
    CacheEmpty,
    /// A static partition has no healthy IP.
    NoHealthyIp,
    /// Redis is unreachable; new leases are refused, open tunnels go on.
    CacheUnavailable,
    /// `on_empty = wait` ran out of `lease_wait`.
    LeaseTimeout,
    /// The provider refused the connection or is in an open breaker.
    ProviderUnavailable,
    /// The provider rejected the rendered credential.
    ProviderAuth,
    /// The provider did not answer in time.
    ProviderTimeout,
    /// The provider answered the CONNECT with an unexpected status.
    UpstreamError,
}

impl Cause {
    /// All variants, for metric pre-registration and tests.
    pub const ALL: [Cause; 16] = [
        Cause::AuthRequired,
        Cause::OrgDisabled,
        Cause::OptionDenied,
        Cause::OrgBlocked,
        Cause::PortNotAllowed,
        Cause::DestinationDenied,
        Cause::OrgCapacity,
        Cause::OrgBudget,
        Cause::CacheEmpty,
        Cause::NoHealthyIp,
        Cause::CacheUnavailable,
        Cause::LeaseTimeout,
        Cause::ProviderUnavailable,
        Cause::ProviderAuth,
        Cause::ProviderTimeout,
        Cause::UpstreamError,
    ];

    /// HTTP status the CONNECT listener answers with.
    pub const fn status(self) -> u16 {
        match self {
            Cause::AuthRequired => 407,
            Cause::OptionDenied
            | Cause::OrgDisabled
            | Cause::OrgBlocked
            | Cause::PortNotAllowed
            | Cause::DestinationDenied => 403,
            Cause::OrgCapacity
            | Cause::OrgBudget
            | Cause::CacheEmpty
            | Cause::NoHealthyIp
            | Cause::CacheUnavailable => 503,
            Cause::LeaseTimeout | Cause::ProviderTimeout => 504,
            Cause::ProviderUnavailable | Cause::ProviderAuth | Cause::UpstreamError => 502,
        }
    }

    /// The reason phrase and metric label.
    pub const fn code(self) -> &'static str {
        match self {
            Cause::AuthRequired => "auth_required",
            Cause::OptionDenied => "option_denied",
            Cause::OrgDisabled => "org_disabled",
            Cause::OrgBlocked => "org_blocked",
            Cause::PortNotAllowed => "port_not_allowed",
            Cause::OrgBudget => "org_budget",
            Cause::DestinationDenied => "destination_denied",
            Cause::OrgCapacity => "org_capacity",
            Cause::CacheEmpty => "cache_empty",
            Cause::NoHealthyIp => "no_healthy_ip",
            Cause::CacheUnavailable => "cache_unavailable",
            Cause::LeaseTimeout => "lease_timeout",
            Cause::ProviderUnavailable => "provider_unavailable",
            Cause::ProviderAuth => "provider_auth",
            Cause::ProviderTimeout => "provider_timeout",
            Cause::UpstreamError => "upstream_error",
        }
    }

    /// The cause with this [`Cause::code`], if there is one.
    pub fn from_code(code: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|cause| cause.code() == code)
    }

    /// SOCKS5 reply code (RFC 1928 section 6) for the same refusal.
    pub const fn socks5_reply(self) -> u8 {
        match self {
            // connection not allowed by ruleset
            Cause::AuthRequired
            | Cause::OptionDenied
            | Cause::OrgDisabled
            | Cause::OrgBlocked
            | Cause::PortNotAllowed
            | Cause::DestinationDenied => 0x02,
            // TTL expired is the closest code for a timeout
            Cause::LeaseTimeout | Cause::ProviderTimeout => 0x06,
            // general SOCKS server failure
            _ => 0x01,
        }
    }
}

impl fmt::Display for Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.status(), self.code())
    }
}

impl std::error::Error for Cause {}

#[cfg(test)]
mod tests {
    use super::Cause;
    use std::collections::HashSet;

    #[test]
    fn codes_are_unique_lowercase_tokens() {
        let codes: HashSet<_> = Cause::ALL.iter().map(|c| c.code()).collect();
        assert_eq!(codes.len(), Cause::ALL.len());
        for code in codes {
            assert!(
                code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "{code}"
            );
        }
    }

    #[test]
    fn from_code_reads_back_every_code() {
        for cause in Cause::ALL {
            assert_eq!(Cause::from_code(cause.code()), Some(cause));
        }
        assert_eq!(Cause::from_code("1"), None);
        assert_eq!(Cause::from_code(""), None);
    }
}
