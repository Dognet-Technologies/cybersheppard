// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - Permission Helpers
// ============================================================================

use axum::{
    http::StatusCode,
    extract::State,
};
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

/// Middleware to require admin role
pub fn require_admin(user: AuthUser) -> Result<AuthUser, StatusCode> {
    if Permissions::is_admin(&user) {
        Ok(user)
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

/// Middleware to require admin or team leader role
pub fn require_admin_or_team_leader(user: AuthUser) -> Result<AuthUser, StatusCode> {
    if Permissions::is_admin_or_team_leader(&user) {
        Ok(user)
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

/// Middleware to require any authenticated user
pub fn require_authenticated(user: AuthUser) -> Result<AuthUser, StatusCode> {
    Ok(user)
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
}
