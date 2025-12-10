// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - Authentication Middleware
// ============================================================================

use axum::{
    async_trait,
    extract::{FromRequestParts, Request, State},
    http::{request::Parts, HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use crate::utils::jwt::{extract_bearer_token, validate_access_token, Claims};
use crate::AppState;

/// Extension type for adding user claims to requests
#[derive(Clone, Debug)]
pub struct AuthUser {
    pub user_id: i32,
    pub username: String,
    pub role: String,
}

impl From<Claims> for AuthUser {
    fn from(claims: Claims) -> Self {
        Self {
            user_id: claims.sub,
            username: claims.username,
            role: claims.role,
        }
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, Json<serde_json::Value>);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthUser>()
            .cloned()
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({
                        "error": "Unauthorized - Authentication required"
                    })),
                )
            })
    }
}

/// Authentication middleware - validates JWT tokens
pub async fn auth_middleware(
    State(_state): State<AppState>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    // Extract Authorization header
    let auth_header = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                axum::Json(json!({
                    "error": "Missing Authorization header"
                })),
            )
        })?;

    // Extract Bearer token
    let token = extract_bearer_token(auth_header).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({
                "error": "Invalid Authorization header format"
            })),
        )
    })?;

    // Validate token
    let claims = validate_access_token(&token).map_err(|e| {
        (
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({
                "error": e.to_string()
            })),
        )
    })?;

    // Add user info to request extensions
    let auth_user: AuthUser = claims.into();
    request.extensions_mut().insert(auth_user);

    Ok(next.run(request).await)
}

/// Role-based authorization check (helper function)
pub fn check_role(auth_user: &AuthUser, required_role: &str) -> Result<(), StatusCode> {
    if auth_user.role != required_role && auth_user.role != "admin" {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(())
}

/// Admin-only middleware
pub async fn require_admin(
    request: Request,
    next: Next,
) -> Result<Response, impl IntoResponse> {
    // Extract user from extensions
    let auth_user = request
        .extensions()
        .get::<AuthUser>()
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                axum::Json(json!({
                    "error": "Authentication required"
                })),
            )
        })?
        .clone();

    // Check if admin
    if auth_user.role != "admin" {
        return Err((
            StatusCode::FORBIDDEN,
            axum::Json(json!({
                "error": "Admin access required"
            })),
        ));
    }

    Ok(next.run(request).await)
}
