// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - CSRF Protection Middleware
// ============================================================================

use axum::{
    extract::{Request, State},
    http::{HeaderMap, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use crate::middleware::auth::AuthUser;
use crate::AppState;

/// CSRF middleware - validates CSRF tokens for state-changing operations
pub async fn csrf_middleware(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, impl IntoResponse> {
    let method = request.method().clone();

    // Only check CSRF for state-changing methods
    if !matches!(method, Method::POST | Method::PUT | Method::PATCH | Method::DELETE) {
        return Ok(next.run(request).await);
    }

    // API-key authenticated clients (mcp_key_scope set — e.g. the MCP server)
    // carry a bearer credential, not a cookie session, so they have no CSRF
    // token and don't need one. CSRF protects cookie-based browser sessions.
    if request
        .extensions()
        .get::<AuthUser>()
        .map(|u| u.mcp_key_scope.is_some())
        .unwrap_or(false)
    {
        return Ok(next.run(request).await);
    }

    // Extract user from extensions (must be authenticated first)
    let auth_user = request.extensions().get::<AuthUser>().ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({
                "error": "Authentication required for CSRF validation"
            })),
        )
    })?;

    // Extract CSRF token from header
    let csrf_token = headers
        .get("X-CSRF-Token")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::FORBIDDEN,
                axum::Json(json!({
                    "error": "Missing CSRF token"
                })),
            )
        })?;

    // Validate CSRF token against database
    let is_valid = validate_csrf_token(&state.pg_pool, auth_user.user_id, csrf_token)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({
                    "error": "Failed to validate CSRF token"
                })),
            )
        })?;

    if !is_valid {
        return Err((
            StatusCode::FORBIDDEN,
            axum::Json(json!({
                "error": "Invalid or expired CSRF token"
            })),
        ));
    }

    Ok(next.run(request).await)
}

/// Generate a new CSRF token for a user
pub async fn generate_csrf_token(
    pool: &PgPool,
    user_id: i32,
) -> Result<String, sqlx::Error> {
    let token = Uuid::new_v4().to_string();

    sqlx::query!(
        r#"
        INSERT INTO csrf_tokens (user_id, token, expires_at)
        VALUES ($1, $2, NOW() + INTERVAL '1 hour')
        ON CONFLICT (user_id)
        DO UPDATE SET
            token = EXCLUDED.token,
            expires_at = EXCLUDED.expires_at,
            created_at = NOW()
        "#,
        user_id,
        token
    )
    .execute(pool)
    .await?;

    Ok(token)
}

/// Validate a CSRF token
async fn validate_csrf_token(
    pool: &PgPool,
    user_id: i32,
    token: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        r#"
        SELECT COUNT(*) as count
        FROM csrf_tokens
        WHERE user_id = $1
        AND token = $2
        AND expires_at > NOW()
        "#,
        user_id,
        token
    )
    .fetch_one(pool)
    .await?;

    Ok(result.count.unwrap_or(0) > 0)
}

/// Revoke a CSRF token
pub async fn revoke_csrf_token(pool: &PgPool, user_id: i32) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        DELETE FROM csrf_tokens
        WHERE user_id = $1
        "#,
        user_id
    )
    .execute(pool)
    .await?;

    Ok(())
}
