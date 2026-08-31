// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - Authentication API
// ============================================================================

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::middleware::auth::AuthUser;
use crate::middleware::csrf::{generate_csrf_token, revoke_csrf_token};
use crate::utils::auth::{
    hash_password, validate_email, validate_password_strength, validate_username,
    verify_password,
};
use crate::utils::jwt::{
    generate_access_token, generate_refresh_token, validate_refresh_token,
};
use crate::AppState;

// ============================================================================
// DTOs (Data Transfer Objects)
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub csrf_token: String,
    pub user: UserInfo,
}

#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub id: i32,
    pub username: String,
    pub email: String,
    pub role: String,
}

#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

// ============================================================================
// Routes
// ============================================================================

/// Public auth routes (no authentication required)
pub fn routes() -> Router<crate::AppState> {
    Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/refresh", post(refresh_token))
}

/// Protected auth routes (require authentication)
pub fn protected_routes() -> Router<crate::AppState> {
    Router::new()
        .route("/logout", post(logout))
        .route("/me", get(get_current_user))
}

// ============================================================================
// Handlers
// ============================================================================

/// Register a new user
async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    // Validate input
    validate_username(&payload.username).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse { error: e }),
        )
    })?;

    if !validate_email(&payload.email) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid email format".to_string(),
            }),
        ));
    }

    validate_password_strength(&payload.password).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse { error: e }),
        )
    })?;

    // Check if username already exists
    let existing_user = sqlx::query!(
        "SELECT id FROM users WHERE username = $1",
        payload.username
    )
    .fetch_optional(&state.pg_pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Database error: {}", e),
            }),
        )
    })?;

    if existing_user.is_some() {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "Username already exists".to_string(),
            }),
        ));
    }

    // Check if email already exists
    let existing_email = sqlx::query!(
        "SELECT id FROM users WHERE email = $1",
        payload.email
    )
    .fetch_optional(&state.pg_pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Database error: {}", e),
            }),
        )
    })?;

    if existing_email.is_some() {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "Email already exists".to_string(),
            }),
        ));
    }

    // Hash password
    let password_hash = hash_password(&payload.password).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to hash password: {}", e),
            }),
        )
    })?;

    // Create user (first user is admin, others are viewers)
    let user_count = sqlx::query!("SELECT COUNT(*) as count FROM users")
        .fetch_one(&state.pg_pool)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Database error: {}", e),
                }),
            )
        })?;

    let role = if user_count.count.unwrap_or(0) == 0 {
        "admin"
    } else {
        "viewer"
    };

    let user = sqlx::query!(
        r#"
        INSERT INTO users (username, email, password_hash, role, is_active)
        VALUES ($1, $2, $3, $4, true)
        RETURNING id, username, email, role
        "#,
        payload.username,
        payload.email,
        password_hash,
        role
    )
    .fetch_one(&state.pg_pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to create user: {}", e),
            }),
        )
    })?;

    // Generate tokens
    let access_token = generate_access_token(user.id, &user.username, &user.role).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to generate access token: {}", e),
            }),
        )
    })?;

    let refresh_token = generate_refresh_token(user.id, &user.username, &user.role).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to generate refresh token: {}", e),
            }),
        )
    })?;

    // Store refresh token in database
    store_refresh_token(&state.pg_pool, user.id, &refresh_token)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to store refresh token: {}", e),
                }),
            )
        })?;

    // Generate CSRF token
    let csrf_token = generate_csrf_token(&state.pg_pool, user.id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to generate CSRF token: {}", e),
                }),
            )
        })?;

    // Log registration
    log_audit(&state.pg_pool, user.id, "register", "User registered successfully")
        .await
        .ok();

    Ok((
        StatusCode::CREATED,
        Json(AuthResponse {
            access_token,
            refresh_token,
            csrf_token,
            user: UserInfo {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role,
            },
        }),
    ))
}

/// Login with username and password
async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    // Find user by username
    let user = sqlx::query!(
        r#"
        SELECT id, username, email, password_hash, role, is_active
        FROM users
        WHERE username = $1
        "#,
        payload.username
    )
    .fetch_optional(&state.pg_pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Database error: {}", e),
            }),
        )
    })?
    .ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid username or password".to_string(),
            }),
        )
    })?;

    // Check if user is active
    if !user.is_active.unwrap_or(true) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Account is disabled".to_string(),
            }),
        ));
    }

    // Verify password
    let password_valid = verify_password(&payload.password, &user.password_hash).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Password verification failed: {}", e),
            }),
        )
    })?;

    if !password_valid {
        log_audit(&state.pg_pool, user.id, "login_failed", "Invalid password attempt")
            .await
            .ok();

        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid username or password".to_string(),
            }),
        ));
    }

    // Generate tokens
    let access_token = generate_access_token(user.id, &user.username, &user.role).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to generate access token: {}", e),
            }),
        )
    })?;

    let refresh_token = generate_refresh_token(user.id, &user.username, &user.role).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to generate refresh token: {}", e),
            }),
        )
    })?;

    // Store refresh token
    store_refresh_token(&state.pg_pool, user.id, &refresh_token)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to store refresh token: {}", e),
                }),
            )
        })?;

    // Generate CSRF token
    let csrf_token = generate_csrf_token(&state.pg_pool, user.id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to generate CSRF token: {}", e),
                }),
            )
        })?;

    // Log successful login
    log_audit(&state.pg_pool, user.id, "login", "User logged in successfully")
        .await
        .ok();

    Ok(Json(AuthResponse {
        access_token,
        refresh_token,
        csrf_token,
        user: UserInfo {
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role,
        },
    }))
}

/// Logout (revoke tokens)
async fn logout(
    State(state): State<AppState>,
    auth_user: AuthUser,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    // Revoke refresh tokens
    sqlx::query!(
        "DELETE FROM refresh_tokens WHERE user_id = $1",
        auth_user.user_id
    )
    .execute(&state.pg_pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to revoke tokens: {}", e),
            }),
        )
    })?;

    // Revoke CSRF token
    revoke_csrf_token(&state.pg_pool, auth_user.user_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to revoke CSRF token: {}", e),
                }),
            )
        })?;

    // Log logout
    log_audit(&state.pg_pool, auth_user.user_id, "logout", "User logged out")
        .await
        .ok();

    Ok(Json(MessageResponse {
        message: "Logged out successfully".to_string(),
    }))
}

/// Refresh access token using refresh token
async fn refresh_token(
    State(state): State<AppState>,
    Json(payload): Json<RefreshTokenRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    // Validate refresh token
    let claims = validate_refresh_token(&payload.refresh_token).map_err(|e| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: format!("Invalid refresh token: {}", e),
            }),
        )
    })?;

    // Check if refresh token exists in database
    let token_exists = sqlx::query!(
        r#"
        SELECT COUNT(*) as count
        FROM refresh_tokens
        WHERE user_id = $1
        AND token = $2
        AND expires_at > NOW()
        "#,
        claims.sub,
        payload.refresh_token
    )
    .fetch_one(&state.pg_pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Database error: {}", e),
            }),
        )
    })?;

    if token_exists.count.unwrap_or(0) == 0 {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Refresh token not found or expired".to_string(),
            }),
        ));
    }

    // Get user info
    let user = sqlx::query!(
        r#"
        SELECT id, username, email, role, is_active
        FROM users
        WHERE id = $1
        "#,
        claims.sub
    )
    .fetch_one(&state.pg_pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Database error: {}", e),
            }),
        )
    })?;

    if !user.is_active.unwrap_or(true) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Account is disabled".to_string(),
            }),
        ));
    }

    // Generate new access token
    let access_token = generate_access_token(user.id, &user.username, &user.role).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to generate access token: {}", e),
            }),
        )
    })?;

    // Generate new refresh token
    let new_refresh_token =
        generate_refresh_token(user.id, &user.username, &user.role).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to generate refresh token: {}", e),
                }),
            )
        })?;

    // Store new refresh token and delete old one
    store_refresh_token(&state.pg_pool, user.id, &new_refresh_token)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to store refresh token: {}", e),
                }),
            )
        })?;

    // Get CSRF token (or generate new one)
    let csrf_token = generate_csrf_token(&state.pg_pool, user.id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to generate CSRF token: {}", e),
                }),
            )
        })?;

    Ok(Json(AuthResponse {
        access_token,
        refresh_token: new_refresh_token,
        csrf_token,
        user: UserInfo {
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role,
        },
    }))
}

/// Get current user info (requires authentication)
async fn get_current_user(
    State(state): State<AppState>,
    auth_user: AuthUser,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let user = sqlx::query!(
        r#"
        SELECT id, username, email, role, created_at
        FROM users
        WHERE id = $1
        "#,
        auth_user.user_id
    )
    .fetch_one(&state.pg_pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Database error: {}", e),
            }),
        )
    })?;

    Ok(Json(UserInfo {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
    }))
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Store a refresh token in the database
async fn store_refresh_token(
    pool: &PgPool,
    user_id: i32,
    token: &str,
) -> Result<(), sqlx::Error> {
    // Delete old refresh tokens for this user
    sqlx::query!("DELETE FROM refresh_tokens WHERE user_id = $1", user_id)
        .execute(pool)
        .await?;

    // Store new refresh token
    sqlx::query!(
        r#"
        INSERT INTO refresh_tokens (user_id, token, expires_at)
        VALUES ($1, $2, NOW() + INTERVAL '7 days')
        "#,
        user_id,
        token
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// Log an audit event
async fn log_audit(
    pool: &PgPool,
    user_id: i32,
    action: &str,
    details: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        INSERT INTO audit_logs (user_id, action, details, ip_address)
        VALUES ($1, $2, $3, '0.0.0.0')
        "#,
        user_id,
        action,
        serde_json::json!({"message": details})
    )
    .execute(pool)
    .await?;

    Ok(())
}
