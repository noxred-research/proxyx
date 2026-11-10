//! Proxy environment and CA bundle helpers.
//!
//! A captured session intercepts TLS with a per-deployment CA, so a client must trust that CA
//! for captured hosts and keep trusting the public roots for the hosts the proxy only
//! tunnels. [`ca_bundle_pem`] joins the session CA and the system roots into one PEM file and
//! [`ProxyEnv`] names that file in the variables most HTTP stacks read.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use uuid::Uuid;

use crate::error::{Error, Result};

const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
const END: &str = "-----END CERTIFICATE-----";

/// Environment variables that route a process through a session proxy and trust its CA.
///
/// Sets `HTTP_PROXY`, `HTTPS_PROXY`, their lowercase twins, and `SSL_CERT_FILE` plus
/// `REQUESTS_CA_BUNDLE` pointing at the CA bundle. The proxy URL carries the session id, so
/// `Debug` hides the values.
#[derive(Clone, Default)]
pub struct ProxyEnv(Vec<(&'static str, String)>);

impl ProxyEnv {
    /// The variables for `proxy_url` and the CA bundle at `ca_bundle`.
    pub fn new(proxy_url: &str, ca_bundle: &Path) -> Self {
        let bundle = ca_bundle.to_string_lossy().into_owned();
        Self(vec![
            ("HTTP_PROXY", proxy_url.to_owned()),
            ("HTTPS_PROXY", proxy_url.to_owned()),
            ("http_proxy", proxy_url.to_owned()),
            ("https_proxy", proxy_url.to_owned()),
            ("SSL_CERT_FILE", bundle.clone()),
            ("REQUESTS_CA_BUNDLE", bundle),
        ])
    }

    /// No variables: traffic goes direct. What a passthrough provider returns.
    pub fn empty() -> Self {
        Self(Vec::new())
    }

    /// True when no variable is set.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Name and value pairs, for `Command::envs`.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(name, value)| (*name, value.as_str()))
    }

    /// Owned copy as a map.
    pub fn to_map(&self) -> HashMap<String, String> {
        self.iter()
            .map(|(name, value)| (name.to_owned(), value.to_owned()))
            .collect()
    }
}

impl<'a> IntoIterator for &'a ProxyEnv {
    type Item = (&'a str, &'a str);
    type IntoIter = Box<dyn Iterator<Item = (&'a str, &'a str)> + 'a>;

    fn into_iter(self) -> Self::IntoIter {
        Box::new(self.iter())
    }
}

impl std::fmt::Debug for ProxyEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.0.iter().map(|(name, _)| *name))
            .finish()
    }
}

/// Chromium arguments that select the proxy: `--proxy-server=<url>`.
///
/// The URL is passed as given, userinfo included. Chromium ignores credentials in
/// `--proxy-server` and does not authenticate SOCKS5, so a driver such as Playwright takes the
/// server, username and password separately instead.
pub fn browser_args(proxy_url: &str) -> Vec<String> {
    vec![format!("--proxy-server={proxy_url}")]
}

/// Join the session CA and `system_roots_pem` into one PEM bundle, session CA first.
///
/// Fails when `session_ca_pem` holds no certificate: a bundle without it would not trust the
/// intercepted hosts.
pub fn join_ca_bundle(session_ca_pem: &str, system_roots_pem: &str) -> Result<String> {
    let session = session_ca_pem.trim();
    if !session.contains(BEGIN) || !session.contains(END) {
        return Err(Error::CaBundle(
            "the session CA is not a PEM certificate".into(),
        ));
    }
    let mut bundle = String::with_capacity(session.len() + system_roots_pem.len() + 2);
    bundle.push_str(session);
    bundle.push('\n');
    bundle.push_str(system_roots_pem);
    if !bundle.ends_with('\n') {
        bundle.push('\n');
    }
    Ok(bundle)
}

/// The system trust roots as PEM. Blocking: reads the OS certificate store.
///
/// Fails when the store yields no certificate, since a bundle without public roots would break
/// TLS to every host the proxy tunnels untouched.
pub fn system_roots_pem() -> Result<String> {
    let loaded = rustls_native_certs::load_native_certs();
    if loaded.certs.is_empty() {
        let detail = loaded
            .errors
            .first()
            .map_or_else(|| "none found".to_owned(), ToString::to_string);
        return Err(Error::CaBundle(format!(
            "no system root certificates: {detail}"
        )));
    }
    let mut pem = String::new();
    for cert in &loaded.certs {
        let encoded = STANDARD.encode(cert.as_ref());
        pem.push_str(BEGIN);
        pem.push('\n');
        for line in encoded.as_bytes().chunks(64) {
            // base64 output is ASCII, so each chunk is valid UTF-8
            pem.push_str(&String::from_utf8_lossy(line));
            pem.push('\n');
        }
        pem.push_str(END);
        pem.push('\n');
    }
    Ok(pem)
}

/// The session CA followed by the system roots, as one PEM string. Blocking.
pub fn ca_bundle_pem(session_ca_pem: &str) -> Result<String> {
    join_ca_bundle(session_ca_pem, &system_roots_pem()?)
}

/// Write [`ca_bundle_pem`] to `path`, replacing any file there. Blocking.
pub fn write_ca_bundle(session_ca_pem: &str, path: &Path) -> Result<()> {
    std::fs::write(path, ca_bundle_pem(session_ca_pem)?)?;
    Ok(())
}

/// A CA bundle in a private temp file, deleted on drop.
#[derive(Debug)]
pub struct TempCaBundle {
    path: PathBuf,
}

impl TempCaBundle {
    /// Write the bundle for `session_ca_pem` to a new file in the temp dir. Blocking.
    pub fn create(session_ca_pem: &str) -> Result<Self> {
        let pem = ca_bundle_pem(session_ca_pem)?;
        Self::create_with(&pem)
    }

    pub(crate) fn create_with(pem: &str) -> Result<Self> {
        use std::io::Write as _;
        let mut name = String::from("proxyx-ca-");
        // writing to a String cannot fail
        let _ = write!(name, "{}.pem", Uuid::new_v4().simple());
        let path = std::env::temp_dir().join(name);
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(&path)?;
        // from here the guard owns the file, so a failed write still removes it
        let bundle = Self { path };
        file.write_all(pem.as_bytes())?;
        Ok(bundle)
    }

    /// Location of the bundle.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempCaBundle {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CA: &str = "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n";
    const ROOT: &str = "-----BEGIN CERTIFICATE-----\nREVG\n-----END CERTIFICATE-----\n";

    #[test]
    fn env_names_proxy_and_bundle() {
        let env = ProxyEnv::new("http://id:password@proxy:8443", Path::new("/tmp/ca.pem"));
        let map = env.to_map();
        for name in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
            assert_eq!(map[name], "http://id:password@proxy:8443", "{name}");
        }
        for name in ["SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"] {
            assert_eq!(map[name], "/tmp/ca.pem", "{name}");
        }
        assert_eq!(map.len(), 6);
    }

    #[test]
    fn env_debug_hides_values() {
        let env = ProxyEnv::new(
            "http://secretid:password@proxy:8443",
            Path::new("/tmp/ca.pem"),
        );
        let text = format!("{env:?}");
        assert!(!text.contains("secretid"));
        assert!(text.contains("HTTPS_PROXY"));
        assert!(ProxyEnv::empty().is_empty());
    }

    #[test]
    fn browser_args_select_the_proxy() {
        assert_eq!(
            browser_args("http://id:password@h:8443"),
            ["--proxy-server=http://id:password@h:8443"]
        );
    }

    #[test]
    fn bundle_puts_the_session_ca_first() {
        let bundle = join_ca_bundle(CA, ROOT).expect("bundle");
        assert!(bundle.starts_with(CA.trim()));
        assert!(bundle.ends_with(ROOT));
        assert_eq!(bundle.matches(BEGIN).count(), 2);
    }

    #[test]
    fn bundle_refuses_a_session_ca_without_a_certificate() {
        assert!(matches!(join_ca_bundle("", ROOT), Err(Error::CaBundle(_))));
        assert!(matches!(
            join_ca_bundle("garbage", ROOT),
            Err(Error::CaBundle(_))
        ));
    }

    #[test]
    fn temp_bundle_is_removed_on_drop() {
        let bundle = TempCaBundle::create_with("pem\n").expect("temp bundle");
        let path = bundle.path().to_path_buf();
        assert_eq!(std::fs::read_to_string(&path).expect("read"), "pem\n");
        drop(bundle);
        assert!(!path.exists());
    }
}
