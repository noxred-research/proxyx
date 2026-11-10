use axum::http::HeaderMap;
use uuid::Uuid;

pub const PRINCIPAL_TYPE_HEADER: &str = "x-proxyx-principal-type";
pub const SERVICE_NAME_HEADER: &str = "x-proxyx-service-name";
pub const ORG_ID_HEADER: &str = "x-proxyx-org-id";
pub const USER_ID_HEADER: &str = "x-proxyx-user-id";
pub const SYSTEM_ROLES_HEADER: &str = "x-proxyx-system-roles";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserPrincipal {
    pub org_id: Option<String>,
    pub user_id: Uuid,
    pub system_roles: Vec<String>,
}

impl UserPrincipal {
    pub fn is_superadmin(&self) -> bool {
        self.system_roles
            .iter()
            .any(|role| role.eq_ignore_ascii_case("superadmin"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServicePrincipal {
    pub org_id: String,
    pub service_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Principal {
    User(UserPrincipal),
    Service(ServicePrincipal),
}

#[derive(Debug, thiserror::Error)]
pub enum PrincipalError {
    #[error("missing principal type header")]
    MissingPrincipalType,
    #[error("unsupported principal type `{0}`")]
    UnsupportedPrincipalType(String),
    #[error("missing required principal header `{0}`")]
    MissingHeader(&'static str),
    #[error("malformed user id")]
    MalformedUserId,
}

pub fn principal_from_headers(headers: &HeaderMap) -> Result<Principal, PrincipalError> {
    let principal_type = header_value(headers, PRINCIPAL_TYPE_HEADER)?;
    match principal_type.to_ascii_lowercase().as_str() {
        "user" => Ok(Principal::User(user_from_headers(headers)?)),
        "superadmin" => {
            let mut user = user_from_headers(headers)?;
            // Ensure the superadmin role is present when principal type is superadmin
            if !user.is_superadmin() {
                user.system_roles.push("superadmin".to_string());
            }
            Ok(Principal::User(user))
        }
        "service" => Ok(Principal::Service(service_from_headers(headers)?)),
        other => Err(PrincipalError::UnsupportedPrincipalType(other.to_string())),
    }
}

pub fn user_from_headers(headers: &HeaderMap) -> Result<UserPrincipal, PrincipalError> {
    let user_id = header_value(headers, USER_ID_HEADER)?
        .parse::<Uuid>()
        .map_err(|_| PrincipalError::MalformedUserId)?;
    let org_id = optional_header_value(headers, ORG_ID_HEADER).filter(|v| !v.trim().is_empty());
    let system_roles = optional_header_value(headers, SYSTEM_ROLES_HEADER)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|role| !role.is_empty())
        .map(str::to_string)
        .collect();
    Ok(UserPrincipal {
        org_id,
        user_id,
        system_roles,
    })
}

pub fn service_from_headers(headers: &HeaderMap) -> Result<ServicePrincipal, PrincipalError> {
    let org_id = header_value(headers, ORG_ID_HEADER)?;
    let service_name = header_value(headers, SERVICE_NAME_HEADER)?;
    Ok(ServicePrincipal {
        org_id,
        service_name,
    })
}

fn header_value(headers: &HeaderMap, name: &'static str) -> Result<String, PrincipalError> {
    optional_header_value(headers, name).ok_or(PrincipalError::MissingHeader(name))
}

fn optional_header_value(headers: &HeaderMap, name: &'static str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}
