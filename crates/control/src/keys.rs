//! Native API keys of the control plane.
//!
//! A key is `pxk_` followed by the base64url (no padding) of 32 random bytes.
//! Only its SHA-256 is stored (`api_keys`). Callers present it as
//! `Authorization: Bearer <key>`. Each key has a kind:
//!
//! | Kind | Principal | Scope |
//! |---|---|---|
//! | `service` | [`Principal::Service`] | `/rpc/*` of its org |
//! | `user` | [`Principal::User`] | `/graphql` of its org |
//! | `admin` | [`Principal::User`] with the `superadmin` role | `/graphql` of every org |
//!
//! Verified keys are cached for [`FRESH_FOR`]; an unknown key is remembered for
//! [`UNKNOWN_FOR`] so a flood of bad keys costs one Postgres lookup each per
//! window, not one per request. Disabling a key takes effect everywhere within
//! [`FRESH_FOR`].

use std::time::Duration;

use crate::db::Db;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use moka::future::Cache;
use rand::RngCore as _;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::auth::{Principal, ServicePrincipal, UserPrincipal};

/// Prefix of every key; lets secret scanners recognise leaked keys.
pub const KEY_PREFIX: &str = "pxk_";
/// How long a verified key is trusted without asking Postgres again.
pub const FRESH_FOR: Duration = Duration::from_secs(30);
/// How long an unknown key is refused from memory.
pub const UNKNOWN_FOR: Duration = Duration::from_secs(5);
const MAX_CACHED: u64 = 10_000;
/// Namespace of the stable user ids derived from key names.
const USER_NAMESPACE: Uuid = Uuid::from_u128(0x5f0c_8f6e_3d4b_4d2e_9a61_7c1b_2e8d_4f10);

/// What a key may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum KeyKind {
    /// Org-scoped integration client of `/rpc/*` (sessions, traffic, orgs).
    Service,
    /// Org-scoped user of `/graphql`.
    User,
    /// Cross-org operator of `/graphql`.
    Admin,
}

impl KeyKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Service => "service",
            Self::User => "user",
            Self::Admin => "admin",
        }
    }

    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "service" => Some(Self::Service),
            "user" => Some(Self::User),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }
}

/// One stored key, without its secret.
#[derive(Debug, Clone, serde::Serialize)]
pub struct KeyInfo {
    pub id: String,
    pub kind: &'static str,
    pub org_id: Option<String>,
    pub name: String,
    pub disabled: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
}

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("{0}")]
    Invalid(&'static str),
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

/// Database-backed key store with a small verification cache.
#[derive(Clone)]
pub struct KeyStore {
    db: Db,
    verified: Cache<[u8; 32], Principal>,
    unknown: Cache<[u8; 32], ()>,
}

impl KeyStore {
    pub fn new(db: Db) -> Self {
        Self {
            db,
            verified: Cache::builder()
                .max_capacity(MAX_CACHED)
                .time_to_live(FRESH_FOR)
                .build(),
            unknown: Cache::builder()
                .max_capacity(MAX_CACHED)
                .time_to_live(UNKNOWN_FOR)
                .build(),
        }
    }

    /// Create a key and return it. This is the only time the key is readable.
    pub async fn create(
        &self,
        kind: KeyKind,
        org_id: Option<&str>,
        name: &str,
    ) -> Result<String, KeyError> {
        let org_id = org_id.map(str::trim).filter(|org| !org.is_empty());
        match (kind, org_id) {
            (KeyKind::Admin, Some(_)) => {
                return Err(KeyError::Invalid("an admin key is not bound to an org"));
            }
            (KeyKind::Service | KeyKind::User, None) => {
                return Err(KeyError::Invalid("service and user keys need an org"));
            }
            _ => {}
        }
        if name.is_empty()
            || name.len() > 64
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._@-".contains(&b))
        {
            return Err(KeyError::Invalid(
                "name must be 1-64 characters of [A-Za-z0-9._@-]",
            ));
        }
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        let key = format!("{KEY_PREFIX}{}", URL_SAFE_NO_PAD.encode(secret));
        self.db
            .insert_key(hash(&key).as_slice(), kind.as_str(), org_id, name)
            .await?;
        Ok(key)
    }

    /// Every key of `org_id` (or every key when `None`), newest first.
    pub async fn list(&self, org_id: Option<&str>) -> Result<Vec<KeyInfo>, KeyError> {
        let rows = self.db.list_keys(org_id).await?;
        Ok(rows
            .into_iter()
            .map(|row| KeyInfo {
                id: key_id(&row.key_hash),
                kind: KeyKind::parse(&row.kind).map_or("unknown", KeyKind::as_str),
                created_at: row.created_at(),
                org_id: row.org_id,
                name: row.name,
                disabled: row.disabled,
            })
            .collect())
    }

    /// Disable the key whose id (see [`KeyInfo::id`]) is `id`. Returns whether a
    /// live key was disabled.
    pub async fn disable(&self, id: &str) -> Result<bool, KeyError> {
        Ok(self.db.disable_key(id).await?)
    }

    /// The principal of a bearer key, `Ok(None)` when the key is unknown or
    /// disabled. Database errors are returned so the caller can answer 503
    /// rather than 401.
    pub async fn authenticate(&self, key: &str) -> Result<Option<Principal>, KeyError> {
        if !key.starts_with(KEY_PREFIX) || key.len() > 128 {
            return Ok(None);
        }
        let digest = hash(key);
        if let Some(principal) = self.verified.get(&digest).await {
            return Ok(Some(principal));
        }
        if self.unknown.get(&digest).await.is_some() {
            return Ok(None);
        }
        let row = self.db.enabled_key(digest.as_slice()).await?;
        let principal = row.and_then(|(kind, org_id, name)| principal(&kind, org_id, name));
        match &principal {
            Some(found) => self.verified.insert(digest, found.clone()).await,
            None => self.unknown.insert(digest, ()).await,
        }
        Ok(principal)
    }
}

fn principal(kind: &str, org_id: Option<String>, name: String) -> Option<Principal> {
    match (KeyKind::parse(kind)?, org_id) {
        (KeyKind::Service, Some(org_id)) => Some(Principal::Service(ServicePrincipal {
            org_id,
            service_name: name,
        })),
        (KeyKind::User, Some(org_id)) => Some(Principal::User(UserPrincipal {
            org_id: Some(org_id),
            user_id: Uuid::new_v5(&USER_NAMESPACE, name.as_bytes()),
            system_roles: Vec::new(),
        })),
        (KeyKind::Admin, None) => Some(Principal::User(UserPrincipal {
            org_id: None,
            user_id: Uuid::new_v5(&USER_NAMESPACE, name.as_bytes()),
            system_roles: vec!["superadmin".to_owned()],
        })),
        _ => None,
    }
}

fn hash(key: &str) -> [u8; 32] {
    Sha256::digest(key.as_bytes()).into()
}

/// Public identifier of a key: the hex of the first 8 bytes of its hash.
fn key_id(hash: &[u8]) -> String {
    hash.iter()
        .take(8)
        .fold(String::with_capacity(16), |mut out, byte| {
            use std::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// The bearer token of an `Authorization` header value, if any.
pub fn bearer(value: &str) -> Option<&str> {
    let (scheme, token) = value.trim().split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| token.trim())
        .filter(|token| !token.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_map_to_the_documented_principals() {
        let service = principal("service", Some("acme".into()), "crawler".into());
        assert!(matches!(
            service,
            Some(Principal::Service(ServicePrincipal { ref org_id, ref service_name }))
                if org_id == "acme" && service_name == "crawler"
        ));
        let Some(Principal::User(user)) = principal("user", Some("acme".into()), "ana".into())
        else {
            panic!("user key must give a user principal");
        };
        assert_eq!(user.org_id.as_deref(), Some("acme"));
        assert!(!user.is_superadmin());
        let Some(Principal::User(admin)) = principal("admin", None, "ops".into()) else {
            panic!("admin key must give a user principal");
        };
        assert!(admin.is_superadmin());
        assert_eq!(admin.org_id, None);
    }

    #[test]
    fn rows_that_break_the_scope_rule_grant_nothing() {
        assert!(principal("admin", Some("acme".into()), "ops".into()).is_none());
        assert!(principal("service", None, "crawler".into()).is_none());
        assert!(principal("root", None, "x".into()).is_none());
    }

    #[test]
    fn user_ids_are_stable_per_key_name() {
        let a = principal("user", Some("acme".into()), "ana".into());
        let b = principal("user", Some("other".into()), "ana".into());
        match (a, b) {
            (Some(Principal::User(a)), Some(Principal::User(b))) => {
                assert_eq!(a.user_id, b.user_id)
            }
            _ => panic!("user keys must give user principals"),
        }
    }

    #[test]
    fn bearer_parsing_is_scheme_insensitive_and_rejects_empty_tokens() {
        assert_eq!(bearer("Bearer pxk_abc"), Some("pxk_abc"));
        assert_eq!(bearer("bearer   pxk_abc "), Some("pxk_abc"));
        assert_eq!(bearer("Basic abc"), None);
        assert_eq!(bearer("Bearer "), None);
        assert_eq!(bearer("pxk_abc"), None);
    }

    #[test]
    fn key_ids_are_the_hex_of_the_first_eight_hash_bytes() {
        let digest = hash("pxk_example");
        let id = key_id(&digest);
        assert_eq!(id.len(), 16);
        assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(id, key_id(&digest[..8]));
    }
}
