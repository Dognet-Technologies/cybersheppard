// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - Permission Helpers
// ============================================================================

use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    Json,
};
use serde_json::json;
use crate::middleware::auth::AuthUser;

/// User roles in the system
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserRole {
    Admin,
    TeamLeader,
    User,
}

impl UserRole {
    pub fn from_str(role: &str) -> Option<Self> {
        match role.to_lowercase().as_str() {
            "admin" => Some(UserRole::Admin),
            "teamleader" | "team_leader" => Some(UserRole::TeamLeader),
            "user" => Some(UserRole::User),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            UserRole::Admin => "admin",
            UserRole::TeamLeader => "teamLeader",
            UserRole::User => "user",
        }
    }
}

/// Permission checker
pub struct Permissions;

impl Permissions {
    /// Check if user is admin
    pub fn is_admin(user: &AuthUser) -> bool {
        user.role == "admin"
    }

    /// Check if user is admin or team leader
    pub fn is_admin_or_team_leader(user: &AuthUser) -> bool {
        user.role == "admin" || user.role == "teamLeader"
    }

    /// Check if user can manage users
    pub fn can_manage_users(user: &AuthUser) -> bool {
        // Admin can manage all users
        // TeamLeader can manage team members (checked at query level)
        user.role == "admin" || user.role == "teamLeader"
    }

    /// Check if user can manage system settings
    pub fn can_manage_system_settings(user: &AuthUser) -> bool {
        user.role == "admin"
    }

    /// Check if user can install/uninstall plugins
    pub fn can_manage_plugins(user: &AuthUser) -> bool {
        user.role == "admin"
    }

    /// Check if user can configure plugins
    pub fn can_configure_plugins(user: &AuthUser) -> bool {
        user.role == "admin" || user.role == "teamLeader"
    }

    /// Check if user can view plugins
    pub fn can_view_plugins(user: &AuthUser) -> bool {
        true // All authenticated users
    }

    /// Check if user can create/edit/delete resources
    pub fn can_manage_resources(user: &AuthUser) -> bool {
        user.role == "admin" || user.role == "teamLeader"
    }

    /// Check if user can execute scans
    pub fn can_execute_scans(user: &AuthUser) -> bool {
        true // All authenticated users
    }

    /// Check if user can view audit logs
    pub fn can_view_audit_logs(user: &AuthUser) -> bool {
        user.role == "admin" || user.role == "teamLeader"
    }

    /// Check if user can manage integrations
    pub fn can_manage_integrations(user: &AuthUser) -> bool {
        user.role == "admin" || user.role == "teamLeader"
    }

    /// Check if user can generate API keys
    pub fn can_generate_api_keys(user: &AuthUser) -> bool {
        true // All users can generate their own API keys
    }

    /// Check if user can view all API keys
    pub fn can_view_all_api_keys(user: &AuthUser) -> bool {
        user.role == "admin"
    }

    /// Check if user can view team API keys
    pub fn can_view_team_api_keys(user: &AuthUser) -> bool {
        user.role == "admin" || user.role == "teamLeader"
    }
}

// ============================================================================
// Role-gated extractors
// ============================================================================
// Questi estrattori applicano l'autorizzazione in modo DICHIARATIVO: basta
// usarli nella firma di un handler (es. `AdminUser(user): AdminUser`) perché
// la route richieda quel ruolo. Se il ruolo non è sufficiente, l'handler non
// viene mai eseguito e si risponde 403. Riutilizzano l'estrazione di AuthUser
// (popolato da auth_middleware), quindi l'assenza di autenticazione dà 401.

fn forbidden(msg: &str) -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::FORBIDDEN, Json(json!({ "error": msg })))
}

/// Estrattore che richiede ruolo `admin`.
pub struct AdminUser(pub AuthUser);

#[async_trait]
impl<S> FromRequestParts<S> for AdminUser
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, Json<serde_json::Value>);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let user = AuthUser::from_request_parts(parts, state).await?;
        if Permissions::is_admin(&user) {
            Ok(AdminUser(user))
        } else {
            Err(forbidden("Admin access required"))
        }
    }
}

/// Estrattore che richiede ruolo `admin` oppure `teamLeader`.
pub struct ManagerUser(pub AuthUser);

#[async_trait]
impl<S> FromRequestParts<S> for ManagerUser
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, Json<serde_json::Value>);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let user = AuthUser::from_request_parts(parts, state).await?;
        if Permissions::is_admin_or_team_leader(&user) {
            Ok(ManagerUser(user))
        } else {
            Err(forbidden("Admin or team leader access required"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_role_from_str() {
        assert_eq!(UserRole::from_str("admin"), Some(UserRole::Admin));
        assert_eq!(UserRole::from_str("teamLeader"), Some(UserRole::TeamLeader));
        assert_eq!(UserRole::from_str("team_leader"), Some(UserRole::TeamLeader));
        assert_eq!(UserRole::from_str("user"), Some(UserRole::User));
        assert_eq!(UserRole::from_str("invalid"), None);
    }

    #[test]
    fn test_admin_permissions() {
        let admin = AuthUser {
            user_id: 1,
            username: "admin".to_string(),
            role: "admin".to_string(),
            mcp_key_scope: None,
        };

        assert!(Permissions::is_admin(&admin));
        assert!(Permissions::is_admin_or_team_leader(&admin));
        assert!(Permissions::can_manage_users(&admin));
        assert!(Permissions::can_manage_system_settings(&admin));
        assert!(Permissions::can_manage_plugins(&admin));
    }

    #[test]
    fn test_team_leader_permissions() {
        let team_leader = AuthUser {
            user_id: 2,
            username: "leader".to_string(),
            role: "teamLeader".to_string(),
            mcp_key_scope: None,
        };

        assert!(!Permissions::is_admin(&team_leader));
        assert!(Permissions::is_admin_or_team_leader(&team_leader));
        assert!(Permissions::can_manage_users(&team_leader));
        assert!(!Permissions::can_manage_system_settings(&team_leader));
        assert!(!Permissions::can_manage_plugins(&team_leader));
        assert!(Permissions::can_configure_plugins(&team_leader));
    }

    #[test]
    fn test_user_permissions() {
        let user = AuthUser {
            user_id: 3,
            username: "user".to_string(),
            role: "user".to_string(),
            mcp_key_scope: None,
        };

        assert!(!Permissions::is_admin(&user));
        assert!(!Permissions::is_admin_or_team_leader(&user));
        assert!(!Permissions::can_manage_users(&user));
        assert!(!Permissions::can_manage_system_settings(&user));
        assert!(!Permissions::can_manage_plugins(&user));
        assert!(!Permissions::can_configure_plugins(&user));
        assert!(Permissions::can_view_plugins(&user));
        assert!(Permissions::can_execute_scans(&user));
    }

    // ------------------------------------------------------------------
    // Estrattori role-gated: provano l'autorizzazione effettiva (200 vs 403)
    // ------------------------------------------------------------------

    fn parts_with_role(role: &str) -> axum::http::request::Parts {
        let mut req = axum::http::Request::builder().body(()).unwrap();
        req.extensions_mut().insert(AuthUser {
            user_id: 1,
            username: "u".to_string(),
            role: role.to_string(),
            mcp_key_scope: None,
        });
        req.into_parts().0
    }

    #[tokio::test]
    async fn admin_extractor_allows_admin_only() {
        let mut p = parts_with_role("admin");
        assert!(AdminUser::from_request_parts(&mut p, &()).await.is_ok());

        for role in ["teamLeader", "user"] {
            let mut p = parts_with_role(role);
            assert!(
                AdminUser::from_request_parts(&mut p, &()).await.is_err(),
                "role {role} must NOT pass AdminUser"
            );
        }
    }

    #[tokio::test]
    async fn manager_extractor_allows_admin_and_team_leader() {
        for role in ["admin", "teamLeader"] {
            let mut p = parts_with_role(role);
            assert!(
                ManagerUser::from_request_parts(&mut p, &()).await.is_ok(),
                "role {role} must pass ManagerUser"
            );
        }
        let mut p = parts_with_role("user");
        assert!(ManagerUser::from_request_parts(&mut p, &()).await.is_err());
    }

    #[tokio::test]
    async fn extractor_rejects_unauthenticated() {
        // Parts senza AuthUser nelle extensions => 401 (via AuthUser).
        let mut parts = axum::http::Request::builder().body(()).unwrap().into_parts().0;
        assert!(AdminUser::from_request_parts(&mut parts, &()).await.is_err());
    }
}
