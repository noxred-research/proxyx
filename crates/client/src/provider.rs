//! A provider-neutral view of a proxy session, with a passthrough that captures nothing.
//!
//! Code that only needs "a proxy for this work unit" takes a [`ProxyProvider`] and calls
//! [`ProxyProvider::acquire`]. [`SessionsProvider`] gives a captured session from the control
//! plane; [`PassthroughProvider`] gives no proxy at all, for local runs where nothing records
//! traffic.

use async_trait::async_trait;

use crate::env::ProxyEnv;
use crate::error::Result;
use crate::sessions::{CreateSessionRequest, Session, SessionOptions, SessionsClient};

/// What a caller needs from a proxy session, whichever provider made it.
#[async_trait]
pub trait ProxyHandle: Send + Sync {
    /// HTTP proxy URL, or `None` when traffic goes direct. Contains the credential.
    fn proxy_url(&self) -> Option<&str>;

    /// SOCKS5 proxy URL, or `None`. Contains the credential.
    fn proxy_url_socks5(&self) -> Option<&str>;

    /// PEM of the CA to trust for intercepted hosts, or `None`.
    fn ca_cert_pem(&self) -> Option<&str>;

    /// Environment for a child process: proxy variables and a CA bundle. Empty for a direct
    /// handle.
    async fn proxy_env(&self) -> Result<ProxyEnv>;

    /// Chromium arguments. Empty for a direct handle.
    fn browser_args(&self) -> Vec<String>;

    /// Release the session. Idempotent.
    async fn end(&self) -> Result<()>;
}

/// Makes proxy handles for work units.
#[async_trait]
pub trait ProxyProvider: Send + Sync {
    /// A handle for `request`.
    async fn acquire(&self, request: CreateSessionRequest) -> Result<Box<dyn ProxyHandle>>;
}

#[async_trait]
impl ProxyHandle for Session {
    fn proxy_url(&self) -> Option<&str> {
        Some(Session::proxy_url(self))
    }

    fn proxy_url_socks5(&self) -> Option<&str> {
        Some(Session::proxy_url_socks5(self))
    }

    fn ca_cert_pem(&self) -> Option<&str> {
        Some(Session::ca_cert_pem(self))
    }

    async fn proxy_env(&self) -> Result<ProxyEnv> {
        Session::proxy_env(self).await
    }

    fn browser_args(&self) -> Vec<String> {
        Session::browser_args(self)
    }

    async fn end(&self) -> Result<()> {
        Session::end(self).await.map(|_| ())
    }
}

/// Provider of captured sessions from the control plane.
#[derive(Debug, Clone)]
pub struct SessionsProvider {
    client: SessionsClient,
    options: SessionOptions,
}

impl SessionsProvider {
    /// A provider that opens sessions with the default keepalive.
    pub fn new(client: SessionsClient) -> Self {
        Self {
            client,
            options: SessionOptions::default(),
        }
    }

    /// Open sessions with other options.
    #[must_use]
    pub fn with_options(mut self, options: SessionOptions) -> Self {
        self.options = options;
        self
    }
}

#[async_trait]
impl ProxyProvider for SessionsProvider {
    async fn acquire(&self, request: CreateSessionRequest) -> Result<Box<dyn ProxyHandle>> {
        Ok(Box::new(
            self.client.open_session_with(request, self.options).await?,
        ))
    }
}

/// Provider with no proxy: every handle is direct and nothing is captured.
#[derive(Debug, Clone, Copy, Default)]
pub struct PassthroughProvider;

/// The handle of [`PassthroughProvider`].
#[derive(Debug, Clone, Copy, Default)]
pub struct PassthroughHandle;

#[async_trait]
impl ProxyHandle for PassthroughHandle {
    fn proxy_url(&self) -> Option<&str> {
        None
    }

    fn proxy_url_socks5(&self) -> Option<&str> {
        None
    }

    fn ca_cert_pem(&self) -> Option<&str> {
        None
    }

    async fn proxy_env(&self) -> Result<ProxyEnv> {
        Ok(ProxyEnv::empty())
    }

    fn browser_args(&self) -> Vec<String> {
        Vec::new()
    }

    async fn end(&self) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl ProxyProvider for PassthroughProvider {
    async fn acquire(&self, _request: CreateSessionRequest) -> Result<Box<dyn ProxyHandle>> {
        Ok(Box::new(PassthroughHandle))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn passthrough_is_direct() {
        let handle = PassthroughProvider
            .acquire(CreateSessionRequest::new("o", "s", "i"))
            .await
            .expect("handle");
        assert_eq!(handle.proxy_url(), None);
        assert_eq!(handle.proxy_url_socks5(), None);
        assert_eq!(handle.ca_cert_pem(), None);
        assert!(handle.proxy_env().await.expect("env").is_empty());
        assert!(handle.browser_args().is_empty());
        handle.end().await.expect("end");
        handle.end().await.expect("end twice");
    }
}
