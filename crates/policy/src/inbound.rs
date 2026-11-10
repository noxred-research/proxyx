//! Inbound session options.
//!
//! a client sends `px` plus `-key-value` pairs as the proxy username, for
//! example `px-kind-rotating-cc-fr-sid-scan42`. Values use `[a-z0-9_]` and
//! never contain `-`, so a split on `-` is unambiguous. Anything that does not
//! parse is refused with [`Cause::OptionDenied`]; nothing is escaped or
//! repaired.

use std::time::Duration;

use common::Cause;
use common::config::humantime_secs;
use common::types::{Kind, ProviderId, Region, Rotation, StickyScope};

use crate::effective::EffectivePolicy;

/// Longest accepted username in bytes.
pub const MAX_USERNAME_LEN: usize = 128;

/// Options a caller asked for. Not yet checked against a policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InboundOptions {
    pub kind: Option<Kind>,
    /// `cc` with the optional `city`.
    pub region: Option<Region>,
    pub provider: Option<ProviderId>,
    /// Lease idle time.
    pub ttl: Option<Duration>,
    /// Sticky key chosen by the caller.
    pub sid: Option<String>,
    pub rotation: Option<Rotation>,
}

fn set<T>(slot: &mut Option<T>, value: T) -> Result<(), Cause> {
    if slot.replace(value).is_some() {
        Err(Cause::OptionDenied)
    } else {
        Ok(())
    }
}

fn is_value(v: &str) -> bool {
    !v.is_empty()
        && v.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

impl InboundOptions {
    /// Parse the proxy username. [`Cause::OptionDenied`] for a missing `px`
    /// prefix, a username over [`MAX_USERNAME_LEN`] bytes, a character outside
    /// `[a-z0-9_-]`, an unknown or repeated key, a key without a value (this
    /// includes a `-` inside a value), a bad value, `city` without `cc`, or
    /// `sid` together with `rot-each`.
    pub fn parse(username: &str) -> Result<Self, Cause> {
        if username.len() > MAX_USERNAME_LEN {
            return Err(Cause::OptionDenied);
        }
        let mut parts = username.split('-');
        if parts.next() != Some("px") {
            return Err(Cause::OptionDenied);
        }
        let parts: Vec<&str> = parts.collect();
        if !parts.len().is_multiple_of(2) {
            return Err(Cause::OptionDenied);
        }

        let mut out = Self::default();
        let (mut cc, mut city) = (None, None);
        for pair in parts.chunks_exact(2) {
            let (key, value) = (pair[0], pair[1]);
            if !is_value(value) {
                return Err(Cause::OptionDenied);
            }
            match key {
                "kind" => set(
                    &mut out.kind,
                    value.parse().map_err(|_| Cause::OptionDenied)?,
                )?,
                "cc" => set(&mut cc, value)?,
                "city" => set(&mut city, value)?,
                "prov" => set(
                    &mut out.provider,
                    value.parse().map_err(|_| Cause::OptionDenied)?,
                )?,
                "ttl" => {
                    let ttl = humantime_secs::parse(value).map_err(|_| Cause::OptionDenied)?;
                    if ttl.is_zero() {
                        return Err(Cause::OptionDenied);
                    }
                    set(&mut out.ttl, ttl)?;
                }
                "sid" => set(&mut out.sid, value.to_owned())?,
                "rot" => set(
                    &mut out.rotation,
                    match value {
                        "sticky" => Rotation::Sticky,
                        "each" => Rotation::Each,
                        _ => return Err(Cause::OptionDenied),
                    },
                )?,
                _ => return Err(Cause::OptionDenied),
            }
        }

        out.region = match (cc, city) {
            (Some(cc), city) => Some(Region::new(cc, city).map_err(|_| Cause::OptionDenied)?),
            (None, Some(_)) => return Err(Cause::OptionDenied),
            (None, None) => None,
        };
        if out.sid.is_some() && out.rotation == Some(Rotation::Each) {
            return Err(Cause::OptionDenied);
        }
        Ok(out)
    }
}

/// What the lease key is bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StickyKeySource {
    /// The caller's `sid`.
    Sid(String),
    /// The policy's sticky scope.
    Scope(StickyScope),
}

/// A policy narrowed by the caller's options: what the lease may use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseRequest {
    /// Kinds to try, in order.
    pub kinds: Vec<Kind>,
    /// Providers to try, in order. Empty: every configured provider.
    pub providers: Vec<ProviderId>,
    /// Regions to try, in order.
    pub regions: Vec<Region>,
    /// Lease idle time.
    pub ttl: Duration,
    pub sticky: StickyKeySource,
    pub rotation: Rotation,
}

impl EffectivePolicy {
    /// Narrow the policy by the caller's options. Without options the whole
    /// policy is the request. An option may only select from what the policy
    /// allows: a kind in `kinds`, a provider in `providers` (any, when the
    /// policy lists none), a region that one policy region covers (`fr/paris`
    /// is covered by `fr` or `fr/paris`; `fr` only by `fr`), and a `ttl` up to
    /// `lease_ttl`. An option that asks for more is [`Cause::OptionDenied`].
    pub fn narrow(&self, opts: &InboundOptions) -> Result<LeaseRequest, Cause> {
        let kinds = match opts.kind {
            Some(k) if self.kinds.contains(&k) => vec![k],
            Some(_) => return Err(Cause::OptionDenied),
            None => self.kinds.clone(),
        };
        let providers = match &opts.provider {
            Some(p) if self.providers.is_empty() || self.providers.contains(p) => vec![p.clone()],
            Some(_) => return Err(Cause::OptionDenied),
            None => self.providers.clone(),
        };
        let regions = match &opts.region {
            Some(want) if self.regions.iter().any(|allowed| want.satisfies(allowed)) => {
                vec![want.clone()]
            }
            Some(_) => return Err(Cause::OptionDenied),
            None => self.regions.clone(),
        };
        let ttl = match opts.ttl {
            Some(t) if t <= self.lease_ttl => t,
            Some(_) => return Err(Cause::OptionDenied),
            None => self.lease_ttl,
        };
        Ok(LeaseRequest {
            kinds,
            providers,
            regions,
            ttl,
            sticky: match &opts.sid {
                Some(sid) => StickyKeySource::Sid(sid.clone()),
                None => StickyKeySource::Scope(self.sticky_scope),
            },
            rotation: opts.rotation.unwrap_or_default(),
        })
    }
}
