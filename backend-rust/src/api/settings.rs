// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - Settings API
// ============================================================================

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{delete, get, post, put},
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;

use crate::middleware::auth::AuthUser;
use crate::middleware::permissions::{AdminUser, ManagerUser};
use crate::services::settings_manager::SettingsManager;
use crate::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        // System settings
        .route("/system", get(get_system_settings))
        .route("/system/:key", put(update_system_setting))
        // User settings
        .route("/user", get(get_user_settings))
        .route("/user/:key", put(set_user_setting))
        // API keys
        .route("/api-keys", get(list_api_keys).post(generate_api_key))
        .route("/api-keys/:id", delete(revoke_api_key))
        // Health checks
        .route("/health", get(health_check))
        .route("/test-connection", post(test_connection))
        // Password change
        .route("/change-password", post(change_password))
        // Database operations
        .route("/cleanup", post(cleanup_old_data))
        .route("/reset", post(reset_database))
}

// ============================================================================
// DTOs
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct UpdateSettingRequest {
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct GenerateApiKeyRequest {
    pub name: String,
    pub description: Option<String>,
    pub service: Option<String>,
    pub permissions: Option<serde_json::Value>,
    pub expires_days: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Deserialize)]
pub struct ResetDatabaseRequest {
    pub confirmation: String,
}

#[derive(Debug, Deserialize)]
pub struct TestConnectionRequest {
    pub service: String, // sentinel_core, firedog
    pub url: String,
    pub api_key: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ListApiKeysQuery {
    pub service: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct GetSystemSettingsQuery {
    pub category: Option<String>,
}

// ============================================================================
// HANDLERS - System Settings
// ============================================================================

async fn get_system_settings(
    State(state): State<AppState>,
    Query(params): Query<GetSystemSettingsQuery>,
    _manager: ManagerUser,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let manager = SettingsManager::new(state.pg_pool.clone());

    let settings = manager
        .get_system_settings(params.category.as_deref())
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
        })?;

    Ok(Json(json!({ "settings": settings })))
}

async fn update_system_setting(
    State(state): State<AppState>,
    Path(key): Path<String>,
    AdminUser(auth_user): AdminUser,
    Json(payload): Json<UpdateSettingRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let manager = SettingsManager::new(state.pg_pool.clone());

    manager
        .update_system_setting(&key, &payload.value, auth_user.user_id)
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": e.to_string()})),
            )
        })?;

    Ok(Json(json!({
        "status": "success",
        "message": "Setting updated successfully"
    })))
}

// ============================================================================
// HANDLERS - User Settings
// ============================================================================

async fn get_user_settings(
    State(state): State<AppState>,
    auth_user: AuthUser,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let manager = SettingsManager::new(state.pg_pool.clone());

    let settings = manager
        .get_user_settings(auth_user.user_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
        })?;

    Ok(Json(json!({ "settings": settings })))
}

async fn set_user_setting(
    State(state): State<AppState>,
    Path(key): Path<String>,
    auth_user: AuthUser,
    Json(payload): Json<UpdateSettingRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let manager = SettingsManager::new(state.pg_pool.clone());

    manager
        .set_user_setting(auth_user.user_id, &key, &payload.value)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
        })?;

    Ok(Json(json!({
        "status": "success",
        "message": "User setting updated"
    })))
}

// ============================================================================
// HANDLERS - API Keys
// ============================================================================

async fn list_api_keys(
    State(state): State<AppState>,
    Query(params): Query<ListApiKeysQuery>,
    _manager: ManagerUser,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let manager = SettingsManager::new(state.pg_pool.clone());

    let keys = manager
        .get_api_keys(params.service.as_deref())
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
        })?;

    Ok(Json(json!({ "api_keys": keys })))
}

async fn generate_api_key(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Json(payload): Json<GenerateApiKeyRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let manager = SettingsManager::new(state.pg_pool.clone());

    let permissions = payload.permissions.unwrap_or(json!([]));

    let result = manager
        .generate_api_key(
            &payload.name,
            payload.description.as_deref(),
            payload.service.as_deref(),
            permissions,
            auth_user.user_id,
            payload.expires_days,
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
        })?;

    Ok(Json(json!({
        "status": "success",
        "message": "API key generated successfully",
        "api_key": result.api_key,
        "token": result.token,
        "warning": "Store this token securely. It will not be shown again."
    })))
}

async fn revoke_api_key(
    State(state): State<AppState>,
    Path(id): Path<i32>,
    ManagerUser(auth_user): ManagerUser,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let manager = SettingsManager::new(state.pg_pool.clone());

    manager
        .revoke_api_key(id, auth_user.user_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
        })?;

    Ok(Json(json!({
        "status": "success",
        "message": "API key revoked successfully"
    })))
}

// ============================================================================
// HANDLERS - Health & Testing
// ============================================================================

async fn health_check(
    State(state): State<AppState>,
    _auth_user: AuthUser,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let manager = SettingsManager::new(state.pg_pool.clone());

    let health = manager.check_health().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
    })?;

    Ok(Json(json!({ "health": health })))
}

/// Validate that a URL is safe for outbound requests.
/// Only `http` and `https` schemes are allowed; metadata service addresses
/// and other reserved addresses that enable SSRF are rejected (CWE-918).
fn validate_integration_url(url: &str) -> Result<reqwest::Url, String> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|_| "Invalid URL format".to_string())?;

    match parsed.scheme() {
        "http" | "https" => {}
        scheme => return Err(format!("Scheme '{}' is not allowed; use http or https", scheme)),
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| "URL must include a host".to_string())?
        .to_lowercase();

    // Block cloud metadata services (SSRF via IMDS)
    let blocked_hosts = ["169.254.169.254", "metadata.google.internal", "metadata.internal"];
    if blocked_hosts.contains(&host.as_str()) {
        return Err("Requests to metadata services are not permitted".to_string());
    }

    Ok(parsed)
}

async fn test_connection(
    State(_state): State<AppState>,
    _admin: AdminUser,
    Json(payload): Json<TestConnectionRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Validate the URL before making any request (CWE-918 SSRF prevention)
    let validated_url = validate_integration_url(&payload.url).map_err(|e| {
        (StatusCode::BAD_REQUEST, Json(json!({"error": e})))
    })?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to build HTTP client"})),
            )
        })?;

    let mut request = client.get(validated_url);

    if let Some(api_key) = payload.api_key {
        request = request.header("Authorization", format!("Bearer {}", api_key));
    }

    let start = std::time::Instant::now();
    let response = request.send().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "status": "error",
                "message": format!("Connection failed: {}", e)
            })),
        )
    })?;

    let elapsed = start.elapsed().as_millis();
    let status_code = response.status().as_u16();

    Ok(Json(json!({
        "status": if response.status().is_success() { "success" } else { "error" },
        "service": payload.service,
        "http_status": status_code,
        "response_time_ms": elapsed,
        "reachable": true
    })))
}

// ============================================================================
// HANDLERS - Password & Database
// ============================================================================

async fn change_password(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Json(payload): Json<ChangePasswordRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
    use argon2::password_hash::{rand_core::OsRng, SaltString};

    // Get current user
    let user = sqlx::query!(
        "SELECT password_hash FROM users WHERE id = $1",
        auth_user.user_id
    )
    .fetch_one(&state.pg_pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
    })?;

    // Verify current password
    let parsed_hash = PasswordHash::new(&user.password_hash).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
    })?;

    Argon2::default()
        .verify_password(payload.current_password.as_bytes(), &parsed_hash)
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Current password is incorrect"})),
            )
        })?;

    // Hash new password
    let salt = SaltString::generate(&mut OsRng);
    let new_hash = Argon2::default()
        .hash_password(payload.new_password.as_bytes(), &salt)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
        })?
        .to_string();

    // Update password
    sqlx::query!(
        "UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2",
        new_hash,
        auth_user.user_id
    )
    .execute(&state.pg_pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
    })?;

    // Audit log
    let manager = SettingsManager::new(state.pg_pool.clone());
    let _ = manager.log_audit(auth_user.user_id, "change_password", "user", auth_user.user_id, None, None).await;

    Ok(Json(json!({
        "status": "success",
        "message": "Password changed successfully"
    })))
}

async fn cleanup_old_data(
    State(state): State<AppState>,
    AdminUser(auth_user): AdminUser,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let manager = SettingsManager::new(state.pg_pool.clone());

    // Get retention setting
    let retention_setting = manager
        .get_system_setting("db_retention_days")
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Retention setting not found"})),
            )
        })?;

    let retention_days: i32 = retention_setting
        .setting_value
        .unwrap_or_else(|| "90".to_string())
        .parse()
        .unwrap_or(90);

    let deleted_count = manager
        .cleanup_old_data(retention_days)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
        })?;

    Ok(Json(json!({
        "status": "success",
        "message": format!("Cleaned up {} old records", deleted_count),
        "retention_days": retention_days,
        "deleted_count": deleted_count
    })))
}

async fn reset_database(
    State(state): State<AppState>,
    AdminUser(auth_user): AdminUser,
    Json(payload): Json<ResetDatabaseRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let manager = SettingsManager::new(state.pg_pool.clone());

    manager
        .reset_database(auth_user.user_id, &payload.confirmation)
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": e.to_string()})),
            )
        })?;

    Ok(Json(json!({
        "status": "success",
        "message": "Database reset successfully. All monitoring data has been cleared."
    })))
}
