//! Users, logins and login options.
//!
//! Users come from `[[user]]` tables and an htpasswd-style file. A login is
//! `user` or, with `login_options`, `user-sid-<id>-pool-<name>-ip-<n>`: the
//! option pairs are read off the right end of the name, so a user name may
//! hold dashes (`team-a`). Plaintext passwords are compared in constant time;
//! hashes are verified on a blocking thread and a successful check is
//! cached for a few minutes, so per-request HTTP Basic auth stays cheap.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use anyhow::{Context as _, bail};
use common::Secret;
use moka::sync::Cache;
use rand::RngCore as _;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use tokio::sync::Semaphore;

use crate::config::UserConfig;
use crate::password;

/// How a user proves the password.
#[derive(Debug, Clone)]
enum Credential {
    Plain(Secret),
    Hash(String),
}

/// A user and what the user may do.
#[derive(Debug, Clone)]
pub struct User {
    pub name: String,
    cred: Credential,
    pub groups: Vec<String>,
    pub pool: Option<String>,
    pub allowed_pools: Vec<String>,
    pub allow_ip_select: bool,
    pub allowed_listeners: Vec<String>,
    pub max_connections: Option<usize>,
    pub socks4: bool,
}

/// Options carried by the login name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoginOptions {
    pub sid: Option<String>,
    pub pool: Option<String>,
    /// 1-based position in the pool.
    pub ip: Option<usize>,
}

/// An accepted login.
#[derive(Debug, Clone)]
pub struct Login {
    pub user: Arc<User>,
    pub options: LoginOptions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    /// Unknown user or wrong password (never says which).
    Invalid,
    /// The login is right but asks for something the user may not have.
    OptionDenied,
    /// The user may not log in on this listener.
    ListenerDenied,
}

fn is_value(v: &str) -> bool {
    !v.is_empty()
        && v.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Split `name-key-value-...` into the user name and its options. `None`
/// when an option repeats or its value is no good (`ip` must be a positive
/// number): the login is then refused, never repaired.
pub fn split_login(login: &str) -> Option<(&str, LoginOptions)> {
    let parts: Vec<&str> = login.split('-').collect();
    let mut end = parts.len();
    let mut opts = LoginOptions::default();
    while end >= 3 {
        let (key, value) = (parts[end - 2], parts[end - 1]);
        if !matches!(key, "sid" | "pool" | "ip") {
            break;
        }
        if !is_value(value) {
            // `x-sid-Bad` is a user name with dashes, unless the value is
            // plainly a malformed option; the caller looks the whole name up.
            break;
        }
        match key {
            "sid" => {
                if opts.sid.replace(value.to_owned()).is_some() {
                    return None;
                }
            }
            "pool" => {
                if opts.pool.replace(value.to_owned()).is_some() {
                    return None;
                }
            }
            _ => {
                let n: usize = value.parse().ok().filter(|&n| n > 0)?;
                if opts.ip.replace(n).is_some() {
                    return None;
                }
            }
        }
        end -= 2;
    }
    // Byte length of the name part: the parts joined back with their dashes.
    let name_len: usize =
        parts[..end].iter().map(|p| p.len()).sum::<usize>() + end.saturating_sub(1);
    Some((&login[..name_len], opts))
}

pub struct Users {
    by_name: HashMap<String, Arc<User>>,
    login_options: bool,
    /// Successful hash checks: sha256(salt, user, password).
    verified: Cache<[u8; 32], ()>,
    salt: [u8; 16],
    /// Bounds the password checks running at once.
    cpu: Semaphore,
    dummy_hash: Option<String>,
}

impl Users {
    pub fn empty() -> Self {
        Self::build(&[], None, false).unwrap_or_else(|_| unreachable!("empty user set builds"))
    }

    /// Build the user set from `[[user]]` tables and an optional htpasswd file.
    pub fn build(
        users: &[UserConfig],
        file: Option<&Path>,
        login_options: bool,
    ) -> anyhow::Result<Self> {
        let mut hashes: HashMap<String, String> = HashMap::new();
        if let Some(path) = file {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("read users file {}", path.display()))?;
            for (name, hash) in password::parse_htpasswd(&text)
                .with_context(|| format!("users file {}", path.display()))?
            {
                hashes.insert(name, hash);
            }
        }
        let mut by_name: HashMap<String, Arc<User>> = HashMap::new();
        let mut need_dummy = false;
        for u in users {
            if u.name.is_empty() || u.name.bytes().any(|b| b <= b' ' || b == b':' || b == 0x7f) {
                bail!(
                    "user {:?}: the name must be non-empty, without spaces, control characters or ':'",
                    u.name
                );
            }
            if by_name.contains_key(&u.name) {
                bail!("user {:?} is defined twice", u.name);
            }
            let cred = match (&u.password, &u.password_hash, hashes.remove(&u.name)) {
                (Some(_), Some(_), _) => {
                    bail!("user {:?}: set password or password_hash, not both", u.name)
                }
                (Some(p), None, None) => Credential::Plain(p.clone()),
                (None, Some(h), None) => Credential::Hash(h.clone()),
                (None, None, Some(h)) => Credential::Hash(h),
                (None, None, None) => bail!(
                    "user {:?} has no password: set password or password_hash, or list it in users_file",
                    u.name
                ),
                (_, _, Some(_)) => bail!(
                    "user {:?} is in the users file and also has a password in the config",
                    u.name
                ),
            };
            if let Credential::Hash(h) = &cred {
                if !password::is_supported(h) {
                    bail!("user {:?}: unsupported password hash format", u.name);
                }
                need_dummy = true;
            }
            by_name.insert(
                u.name.clone(),
                Arc::new(User {
                    name: u.name.clone(),
                    cred,
                    groups: u.groups.clone(),
                    pool: u.pool.clone(),
                    allowed_pools: u.allowed_pools.clone(),
                    allow_ip_select: u.allow_ip_select,
                    allowed_listeners: u.allowed_listeners.clone(),
                    max_connections: u.max_connections,
                    socks4: u.socks4,
                }),
            );
        }
        // Users that only appear in the file: default settings.
        for (name, hash) in hashes {
            if by_name.contains_key(&name) {
                continue;
            }
            need_dummy = true;
            by_name.insert(
                name.clone(),
                Arc::new(User {
                    name,
                    cred: Credential::Hash(hash),
                    groups: Vec::new(),
                    pool: None,
                    allowed_pools: Vec::new(),
                    allow_ip_select: false,
                    allowed_listeners: Vec::new(),
                    max_connections: None,
                    socks4: false,
                }),
            );
        }
        if login_options {
            for name in by_name.keys() {
                match split_login(name) {
                    Some((n, o)) if n == name && o == LoginOptions::default() => {}
                    _ => bail!(
                        "user {name:?} ends in option pairs (-sid-x, -pool-x, -ip-n): login_options would read them as options"
                    ),
                }
            }
        }
        let mut salt = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt);
        let dummy_hash = need_dummy
            .then(|| pwhash::bcrypt::hash("proxyx-edge-dummy").ok())
            .flatten();
        Ok(Self {
            by_name,
            login_options,
            verified: Cache::builder()
                .max_capacity(10_000)
                .time_to_live(Duration::from_secs(300))
                .build(),
            salt,
            cpu: Semaphore::new(4),
            dummy_hash,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }

    pub fn names(&self) -> Vec<&str> {
        self.by_name.keys().map(String::as_str).collect()
    }

    pub fn groups(&self) -> Vec<&str> {
        let mut g: Vec<&str> = self
            .by_name
            .values()
            .flat_map(|u| u.groups.iter().map(String::as_str))
            .collect();
        g.sort_unstable();
        g.dedup();
        g
    }

    pub fn get(&self, name: &str) -> Option<&Arc<User>> {
        self.by_name.get(name)
    }

    /// Resolve a login name into a user and options. Does not check the password.
    fn lookup(&self, login: &str) -> Option<(Arc<User>, LoginOptions)> {
        if self.login_options
            && let Some((name, opts)) = split_login(login)
            && let Some(u) = self.by_name.get(name)
        {
            return Some((Arc::clone(u), opts));
        }
        self.by_name
            .get(login)
            .map(|u| (Arc::clone(u), LoginOptions::default()))
    }

    /// Check a Basic or RFC 1929 login.
    pub async fn verify(
        &self,
        login: &str,
        pass: &str,
        listener: &str,
    ) -> Result<Login, AuthError> {
        let Some((user, options)) = self.lookup(login) else {
            self.burn(pass).await;
            return Err(AuthError::Invalid);
        };
        if !self.password_ok(&user, pass).await {
            return Err(AuthError::Invalid);
        }
        check_access(&user, &options, listener)?;
        Ok(Login { user, options })
    }

    /// SOCKS4 carries a user id and no password: only users that opted in with `socks4 = true`.
    pub fn verify_userid(&self, userid: &str, listener: &str) -> Result<Login, AuthError> {
        let (user, options) = self.lookup(userid).ok_or(AuthError::Invalid)?;
        if !user.socks4 {
            return Err(AuthError::Invalid);
        }
        check_access(&user, &options, listener)?;
        Ok(Login { user, options })
    }

    async fn password_ok(&self, user: &Arc<User>, pass: &str) -> bool {
        match &user.cred {
            Credential::Plain(p) => p.expose().as_bytes().ct_eq(pass.as_bytes()).into(),
            Credential::Hash(h) => {
                let key = self.cache_key(&user.name, pass);
                if self.verified.contains_key(&key) {
                    return true;
                }
                let ok = self.check_hash(h.clone(), pass.to_owned()).await;
                if ok {
                    self.verified.insert(key, ());
                }
                ok
            }
        }
    }

    fn cache_key(&self, user: &str, pass: &str) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.salt);
        h.update(user.as_bytes());
        h.update([0]);
        h.update(pass.as_bytes());
        h.finalize().into()
    }

    async fn check_hash(&self, hash: String, pass: String) -> bool {
        let Ok(_permit) = self.cpu.acquire().await else {
            return false;
        };
        tokio::task::spawn_blocking(move || password::verify(&hash, &pass).unwrap_or(false))
            .await
            .unwrap_or(false)
    }

    /// Spend the time of one hash check on an unknown user, so the answer
    /// time does not tell a real name from a made-up one.
    async fn burn(&self, pass: &str) {
        if let Some(h) = &self.dummy_hash {
            let _ = self.check_hash(h.clone(), pass.to_owned()).await;
        }
    }
}

fn check_access(user: &User, o: &LoginOptions, listener: &str) -> Result<(), AuthError> {
    if !user.allowed_listeners.is_empty() && !user.allowed_listeners.iter().any(|l| l == listener) {
        return Err(AuthError::ListenerDenied);
    }
    if let Some(p) = &o.pool
        && !user.allowed_pools.iter().any(|a| a == p)
    {
        return Err(AuthError::OptionDenied);
    }
    if o.ip.is_some() && !user.allow_ip_select {
        return Err(AuthError::OptionDenied);
    }
    Ok(())
}

/// Failed logins per source: past the limit a source is refused for the rest of the window.
pub struct FailLimiter {
    limit: u32,
    seen: Cache<IpAddr, Arc<AtomicU32>>,
}

impl FailLimiter {
    pub fn new(limit: u32, window: Duration) -> Self {
        Self {
            limit,
            seen: Cache::builder()
                .max_capacity(100_000)
                .time_to_live(window)
                .build(),
        }
    }

    /// An IPv6 source counts by its /64.
    fn key(ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V6(v6) => {
                let mut o = v6.octets();
                o[8..].fill(0);
                IpAddr::V6(o.into())
            }
            v4 => v4,
        }
    }

    pub fn blocked(&self, ip: IpAddr) -> bool {
        self.limit != 0
            && self
                .seen
                .get(&Self::key(ip))
                .is_some_and(|c| c.load(Ordering::Relaxed) >= self.limit)
    }

    pub fn record(&self, ip: IpAddr) {
        if self.limit == 0 {
            return;
        }
        self.seen
            .get_with(Self::key(ip), || Arc::new(AtomicU32::new(0)))
            .fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn users(toml: &str, options: bool) -> Users {
        let c = Config::parse(toml).expect("parse");
        Users::build(&c.users, None, options).expect("users")
    }

    #[test]
    fn login_options_come_off_the_right_end() {
        let (n, o) = split_login("alice-sid-abc123-pool-eu-ip-2").expect("split");
        assert_eq!(n, "alice");
        assert_eq!(o.sid.as_deref(), Some("abc123"));
        assert_eq!(o.pool.as_deref(), Some("eu"));
        assert_eq!(o.ip, Some(2));
        let (n, o) = split_login("team-a-sid-x").expect("split");
        assert_eq!((n, o.sid.as_deref()), ("team-a", Some("x")));
        let (n, o) = split_login("plain").expect("split");
        assert_eq!((n, o), ("plain", LoginOptions::default()));
        // a name that merely looks like an option stays whole
        let (n, o) = split_login("sid-x").expect("split");
        assert_eq!((n, o), ("sid-x", LoginOptions::default()));
        let (n, _) = split_login("a-sid-Bad").expect("split");
        assert_eq!(n, "a-sid-Bad");
        assert!(split_login("a-sid-x-sid-y").is_none(), "repeated option");
        assert!(split_login("a-ip-0").is_none());
        assert!(split_login("a-ip-x").is_none(), "ip needs a number");
    }

    #[tokio::test]
    async fn plain_users_and_options_are_checked() {
        let u = users(
            r#"
            [[user]]
            name = "alice"
            password = "pw"
            allowed_pools = ["eu"]
            allow_ip_select = true
            [[user]]
            name = "bob"
            password = "pw2"
        "#,
            true,
        );
        let l = u
            .verify("alice-sid-s1-pool-eu-ip-3", "pw", "main")
            .await
            .expect("login");
        assert_eq!(l.user.name, "alice");
        assert_eq!(l.options.ip, Some(3));
        assert_eq!(
            u.verify("alice", "wrong", "main").await.err(),
            Some(AuthError::Invalid)
        );
        assert_eq!(
            u.verify("nobody", "pw", "main").await.err(),
            Some(AuthError::Invalid)
        );
        assert_eq!(
            u.verify("alice-pool-us", "pw", "main").await.err(),
            Some(AuthError::OptionDenied)
        );
        assert_eq!(
            u.verify("bob-ip-1", "pw2", "main").await.err(),
            Some(AuthError::OptionDenied)
        );
        // options off: the whole string is the name
        let off = users("[[user]]\nname = \"alice\"\npassword = \"pw\"\n", false);
        assert_eq!(
            off.verify("alice-sid-x", "pw", "main").await.err(),
            Some(AuthError::Invalid)
        );
    }

    #[tokio::test]
    async fn listener_restriction_and_socks4_opt_in() {
        let u = users(
            r#"
            [[user]]
            name = "alice"
            password = "pw"
            allowed_listeners = ["main"]
            socks4 = true
            [[user]]
            name = "bob"
            password = "pw"
        "#,
            false,
        );
        assert!(u.verify("alice", "pw", "main").await.is_ok());
        assert_eq!(
            u.verify("alice", "pw", "other").await.err(),
            Some(AuthError::ListenerDenied)
        );
        assert!(u.verify_userid("alice", "main").is_ok());
        assert_eq!(
            u.verify_userid("bob", "main").err(),
            Some(AuthError::Invalid)
        );
        assert_eq!(
            u.verify_userid("ghost", "main").err(),
            Some(AuthError::Invalid)
        );
    }

    #[tokio::test]
    async fn hashed_users_verify_and_cache() {
        let hash = pwhash::bcrypt::hash_with(
            pwhash::bcrypt::BcryptSetup {
                cost: Some(4),
                ..Default::default()
            },
            "hunter2",
        )
        .expect("hash");
        let u = users(
            &format!("[[user]]\nname = \"carol\"\npassword_hash = \"{hash}\"\n"),
            false,
        );
        assert!(u.verify("carol", "hunter2", "main").await.is_ok());
        assert_eq!(
            u.verify("carol", "hunter3", "main").await.err(),
            Some(AuthError::Invalid)
        );
        // second success comes from the cache
        assert!(u.verify("carol", "hunter2", "main").await.is_ok());
        u.verified.run_pending_tasks();
        assert_eq!(u.verified.entry_count(), 1);
    }

    #[test]
    fn build_refuses_ambiguous_and_incomplete_users() {
        let build =
            |t: &str, o: bool| Users::build(&Config::parse(t).expect("parse").users, None, o).err();
        assert!(
            build("[[user]]\nname = \"a\"\n", false).is_some(),
            "no password"
        );
        assert!(
            build(
                "[[user]]\nname = \"a\"\npassword = \"x\"\npassword_hash = \"{SHA}x\"\n",
                false
            )
            .is_some()
        );
        assert!(build("[[user]]\nname = \"a\"\npassword = \"x\"\n[[user]]\nname = \"a\"\npassword = \"y\"\n", false).is_some());
        assert!(build("[[user]]\nname = \"a:b\"\npassword = \"x\"\n", false).is_some());
        assert!(build("[[user]]\nname = \"a\"\npassword_hash = \"plain\"\n", false).is_some());
        assert!(
            build("[[user]]\nname = \"a-sid-x\"\npassword = \"x\"\n", true).is_some(),
            "name that reads as an option"
        );
        assert!(build("[[user]]\nname = \"a-sid-x\"\npassword = \"x\"\n", false).is_none());
    }

    #[test]
    fn users_file_merges_with_user_tables() {
        let hash = pwhash::bcrypt::hash_with(
            pwhash::bcrypt::BcryptSetup {
                cost: Some(4),
                ..Default::default()
            },
            "pw",
        )
        .expect("hash");
        let path =
            std::env::temp_dir().join(format!("edge-auth-users-{}.htpasswd", std::process::id()));
        std::fs::write(&path, format!("# users\nfile_only:{hash}\nboth:{hash}\n")).expect("write");
        let cfg =
            Config::parse("[[user]]\nname = \"both\"\ngroups = [\"staff\"]\n").expect("parse");
        let u = Users::build(&cfg.users, Some(&path), false).expect("users");
        assert_eq!(
            u.get("both").map(|u| u.groups.clone()),
            Some(vec!["staff".to_owned()])
        );
        assert!(u.get("file_only").is_some());
        assert_eq!(u.groups(), vec!["staff"]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_fail_limiter_blocks_a_source_after_its_limit() {
        let l = FailLimiter::new(3, Duration::from_secs(60));
        let a: IpAddr = "203.0.113.5".parse().expect("ip");
        for _ in 0..2 {
            l.record(a);
        }
        assert!(!l.blocked(a));
        l.record(a);
        assert!(l.blocked(a));
        assert!(!l.blocked("203.0.113.6".parse().expect("ip")));
        // an IPv6 source counts by /64
        let v6a: IpAddr = "2001:db8::1".parse().expect("ip");
        let v6b: IpAddr = "2001:db8::ffff".parse().expect("ip");
        for _ in 0..3 {
            l.record(v6a);
        }
        assert!(l.blocked(v6b));
        assert!(
            !FailLimiter::new(0, Duration::from_secs(1)).blocked(a),
            "limit 0 is off"
        );
    }
}
