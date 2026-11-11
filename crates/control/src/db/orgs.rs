//! Orgs: rate limits and the egress proxy of an org.

use sqlx::FromRow;

use crate::db::DbResult;
use crate::session::OrgRow;

instances!("impls/orgs.rs");

/// The settings columns of an org the GraphQL surface shows.
#[derive(FromRow)]
pub struct OrgSettingsRow {
    pub rate_limit_rpm: Option<i32>,
    pub rate_limit_burst: Option<i32>,
    pub proxy_type: Option<String>,
    pub proxy_address: Option<String>,
}

/// Everything [`Db::set_org_settings`] writes for an org.
#[derive(Debug, Clone, Copy)]
pub struct OrgSettingsWrite<'a> {
    pub id: &'a str,
    pub rpm: Option<i32>,
    pub burst: Option<i32>,
    pub proxy_type: Option<&'a str>,
    pub proxy_address: Option<&'a str>,
    pub proxy_username: Option<&'a str>,
    pub proxy_password: Option<&'a str>,
}

/// The four proxy columns: type, address, username, password.
pub type ProxyColumns = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

delegate! {
    /// The org row, if the org exists.
    pub(crate) async fn org(&self, id: &str) -> DbResult<Option<OrgRow>>;

    /// Insert an org with its rate limits. Fails when the id exists.
    pub async fn create_org(&self, id: &str, rpm: Option<i32>, burst: Option<i32>) -> DbResult<()>;

    /// Delete an org; the number of rows removed.
    pub async fn delete_org(&self, id: &str) -> DbResult<u64>;

    /// The rate limits of an org (`None`: no such org).
    pub async fn org_rate_limit(&self, id: &str) -> DbResult<Option<(Option<i32>, Option<i32>)>>;

    /// Set the rate limits of an org, creating the org when it is new.
    pub async fn set_org_rate_limit(&self, id: &str, rpm: Option<i32>, burst: Option<i32>) -> DbResult<()>;

    /// The proxy columns of an org (`None`: no such org).
    pub async fn org_proxy(&self, id: &str) -> DbResult<Option<ProxyColumns>>;

    /// Set the proxy of an org, creating the org when it is new.
    pub async fn set_org_proxy(
        &self,
        id: &str,
        proxy_type: &str,
        address: &str,
        username: Option<&str>,
        password: Option<&str>,
    ) -> DbResult<()>;

    /// Clear the proxy of an org; the number of orgs found (0: no such org).
    pub async fn clear_org_proxy(&self, id: &str) -> DbResult<u64>;

    /// The rate limits and the proxy type and address of an org.
    pub async fn org_settings(&self, id: &str) -> DbResult<Option<OrgSettingsRow>>;

    /// Set the rate limits and the proxy of an org, creating the org when it is new.
    pub async fn set_org_settings(&self, settings: &OrgSettingsWrite<'_>) -> DbResult<()>;
}
