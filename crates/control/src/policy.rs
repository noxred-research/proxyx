use crate::auth::{ServicePrincipal, UserPrincipal};

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("access denied")]
    Forbidden,
}

pub fn require_user_org(principal: &UserPrincipal, org_id: &str) -> Result<(), PolicyError> {
    if principal.is_superadmin() || principal.org_id.as_deref() == Some(org_id) {
        Ok(())
    } else {
        Err(PolicyError::Forbidden)
    }
}

/// Resolve the effective org scope for a user principal.
///
/// - Superadmins (no `org_id` on principal, or `is_superadmin()`) may query
///   any org. When `requested_org_id` is `None` they get cross-org access
///   (returns `None`).
/// - Regular users are scoped to their own org; they cannot request a
///   different org.
pub fn resolve_user_org(
    principal: &UserPrincipal,
    requested_org_id: Option<String>,
) -> Result<Option<String>, PolicyError> {
    match (&principal.org_id, requested_org_id) {
        // Superadmin without org — cross-org or scoped to requested org.
        (None, req) => Ok(req),
        // User with org + superadmin role — cross-org or scoped to requested org.
        (Some(_), req) if principal.is_superadmin() => Ok(req.or_else(|| principal.org_id.clone())),
        // Regular user — must use own org, cannot override.
        (Some(own), None) => Ok(Some(own.clone())),
        (Some(own), Some(req)) if req == *own => Ok(Some(req)),
        _ => Err(PolicyError::Forbidden),
    }
}

pub fn require_superuser(principal: &UserPrincipal) -> Result<(), PolicyError> {
    if principal.is_superadmin() {
        Ok(())
    } else {
        Err(PolicyError::Forbidden)
    }
}

pub fn resolve_service_org(
    principal: &ServicePrincipal,
    requested_org_id: Option<String>,
) -> Result<String, PolicyError> {
    let org_id = requested_org_id.unwrap_or_else(|| principal.org_id.clone());
    require_service_org(principal, &org_id)?;
    Ok(org_id)
}

pub fn require_service_org(principal: &ServicePrincipal, org_id: &str) -> Result<(), PolicyError> {
    if principal.org_id == org_id {
        Ok(())
    } else {
        Err(PolicyError::Forbidden)
    }
}
