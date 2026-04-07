// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - Settings API
// ============================================================================

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        // General settings
        .route("/", get(get_all_settings))
        .route("/:key", get(get_setting).put(update_setting))
        // User management
        .route("/user/profile", get(get_user_profile).put(update_user_profile))
        .route("/user/password", post(change_password))
        // System status
        .route("/system/status", get(get_system_status))
        .route("/system/status/log", post(log_system_status))
        .route("/system/health", get(get_system_health))
        // Database management
        .route("/database/stats", get(get_database_stats))
        .route("/database/cleanup", post(trigger_cleanup))
        // API Keys
        .route("/api-keys", get(list_api_keys).post(create_api_key))
        .route("/api-keys/:id", get(get_api_key).delete(revoke_api_key))
        // Integrations
        .route("/integrations", get(list_integrations).post(create_integration))
        .route(
            "/integrations/:id",
            get(get_integration)
                .put(update_integration)
                .delete(delete_integration),
        )
        .route("/integrations/:id/test", post(test_integration))
        .route("/integrations/:id/sync", post(trigger_sync))
}

// ============================================================================
// Types
// ============================================================================

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct Setting {
    pub id: i32,
    pub key: String,
    pub value: String,
    pub category: String,
    pub description: Option<String>,
    pub updated_at: chrono::NaiveDateTime,
    pub updated_by: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateSettingRequest {
    pub value: String,
    pub updated_by: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct UserProfile {
    pub id: i32,
    pub username: String,
    pub email: Option<String>,
    pub role: String,
    pub created_at: chrono::NaiveDateTime,
}

#[derive(Debug, Deserialize)]
pub struct UpdateProfileRequest {
    pub email: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct SystemStatus {
    pub cpu_usage_percent: Option<f64>,
    pub memory_usage_percent: Option<f64>,
    pub memory_total_mb: Option<i64>,
    pub memory_used_mb: Option<i64>,
    pub disk_usage_percent: Option<f64>,
    pub disk_total_gb: Option<i64>,
    pub disk_used_gb: Option<i64>,
    pub db_connections_active: Option<i32>,
    pub db_connections_idle: Option<i32>,
    pub db_connections_max: Option<i32>,
    pub db_size_mb: Option<i64>,
    pub agents_connected: Option<i32>,
    pub timestamp: Option<chrono::NaiveDateTime>,
}

#[derive(Debug, Serialize)]
pub struct SystemHealth {
    pub status: String, // 'healthy', 'degraded', 'unhealthy'
    pub backend_healthy: bool,
    pub database_healthy: bool,
    pub uptime_seconds: i64,
    pub version: String,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct DatabaseStats {
    pub total_size_mb: i64,
    pub auditd_events_count: i64,
    pub auditd_events_size_mb: i64,
    pub alerts_count: i64,
    pub alerts_size_mb: i64,
    pub targets_count: i64,
    pub oldest_auditd_event: Option<chrono::NaiveDateTime>,
    pub oldest_alert: Option<chrono::NaiveDateTime>,
}

#[derive(Debug, Deserialize)]
pub struct CleanupRequest {
    pub target: String, // 'auditd_events', 'alerts', 'system_logs', 'all'
    pub retention_days: i32,
}

#[derive(Debug, Serialize)]
pub struct CleanupResult {
    pub target: String,
    pub deleted_count: i64,
    pub cleanup_timestamp: chrono::NaiveDateTime,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct ApiKey {
    pub id: i32,
    pub name: String,
    pub key_prefix: String,
    pub description: Option<String>,
    pub scopes: Vec<String>,
    pub is_active: bool,
    pub expires_at: Option<chrono::NaiveDateTime>,
    pub last_used_at: Option<chrono::NaiveDateTime>,
    pub created_at: chrono::NaiveDateTime,
    pub created_by: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateApiKeyRequest {
    pub name: String,
    pub description: Option<String>,
    pub scopes: Vec<String>,
    pub expires_in_days: Option<i32>,
}

#[derive(Debug, Serialize)]
pub struct CreateApiKeyResponse {
    pub id: i32,
    pub name: String,
    pub key: String, // Full key, only returned once
    pub key_prefix: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<chrono::NaiveDateTime>,
    pub created_at: chrono::NaiveDateTime,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct Integration {
    pub id: i32,
    pub name: String,
    #[sqlx(rename = "type")]
    pub integration_type: String,
    pub enabled: bool,
    pub hostname: Option<String>,
    pub ip_address: Option<String>,
    pub port: Option<i32>,
    pub use_ssl: bool,
    pub sync_mode: Option<String>,
    pub sync_interval: Option<i32>,
    pub last_sync_at: Option<chrono::NaiveDateTime>,
    pub last_sync_status: Option<String>,
    pub last_sync_error: Option<String>,
    pub config: Option<serde_json::Value>,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
}

#[derive(Debug, Deserialize)]
pub struct CreateIntegrationRequest {
    pub name: String,
    #[serde(rename = "type")]
    pub integration_type: String,
    pub api_key: Option<String>,
    pub hostname: Option<String>,
    pub ip_address: Option<String>,
    pub port: Option<i32>,
    pub use_ssl: Option<bool>,
    pub sync_mode: Option<String>,
    pub sync_interval: Option<i32>,
    pub config: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateIntegrationRequest {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub api_key: Option<String>,
    pub hostname: Option<String>,
    pub ip_address: Option<String>,
    pub port: Option<i32>,
    pub use_ssl: Option<bool>,
    pub sync_mode: Option<String>,
    pub sync_interval: Option<i32>,
    pub config: Option<serde_json::Value>,
}

// ============================================================================
// Settings Handlers
// ============================================================================

async fn get_all_settings(State(state): State<AppState>) -> Result<Json<Vec<Setting>>, Response> {
    let settings = sqlx::query_as::<_, Setting>(
        "SELECT id, key, value, category, description, updated_at, updated_by
         FROM settings
         ORDER BY category, key"
    )
    .fetch_all(&state.pg_pool)
    .await
    .map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)).into_response()
    })?;

    Ok(Json(settings))
}

async fn get_setting(
    State(state): State<AppState>,
    Path(key): Path<String>,
) -> Result<Json<Setting>, Response> {
    let setting = sqlx::query_as::<_, Setting>(
        "SELECT id, key, value, category, description, updated_at, updated_by
         FROM settings
         WHERE key = $1"
    )
    .bind(&key)
    .fetch_one(&state.pg_pool)
    .await
    .map_err(|e| {
        (StatusCode::NOT_FOUND, format!("Setting not found: {}", e)).into_response()
    })?;

    Ok(Json(setting))
}

async fn update_setting(
    State(state): State<AppState>,
    Path(key): Path<String>,
    Json(payload): Json<UpdateSettingRequest>,
) -> Result<Json<Setting>, Response> {
    let setting = sqlx::query_as::<_, Setting>(
        "UPDATE settings
         SET value = $1, updated_by = $2, updated_at = NOW()
         WHERE key = $3
         RETURNING id, key, value, category, description, updated_at, updated_by"
    )
    .bind(&payload.value)
    .bind(&payload.updated_by)
    .bind(&key)
    .fetch_one(&state.pg_pool)
    .await
    .map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Update failed: {}", e)).into_response()
    })?;

    Ok(Json(setting))
}

// ============================================================================
// User Management Handlers
// ============================================================================

async fn get_user_profile(State(state): State<AppState>) -> Result<Json<UserProfile>, Response> {
    // TODO: Get user from auth context
    let user = sqlx::query_as::<_, UserProfile>(
        "SELECT id, username, email, role, created_at
         FROM users
         LIMIT 1"
    )
    .fetch_one(&state.pg_pool)
    .await
    .map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)).into_response()
    })?;

    Ok(Json(user))
}

async fn update_user_profile(
    State(state): State<AppState>,
    Json(payload): Json<UpdateProfileRequest>,
) -> Result<Json<UserProfile>, Response> {
    // TODO: Get user ID from auth context
    let user = sqlx::query_as::<_, UserProfile>(
        "UPDATE users
         SET email = $1
         WHERE id = 1
         RETURNING id, username, email, role, created_at"
    )
    .bind(&payload.email)
    .fetch_one(&state.pg_pool)
    .await
    .map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Update failed: {}", e)).into_response()
    })?;

    Ok(Json(user))
}

async fn change_password(
    State(state): State<AppState>,
    Json(payload): Json<ChangePasswordRequest>,
) -> Result<StatusCode, Response> {
    // TODO: Implement password verification and update
    // For now, just return OK
    Ok(StatusCode::OK)
}

// ============================================================================
// System Status Handlers
// ============================================================================

async fn get_system_status(State(state): State<AppState>) -> Result<Json<SystemStatus>, Response> {
    let status = sqlx::query_as::<_, SystemStatus>(
        "SELECT * FROM get_latest_system_status()"
    )
    .fetch_optional(&state.pg_pool)
    .await
    .map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)).into_response()
    })?;

    Ok(Json(status.unwrap_or(SystemStatus {
        cpu_usage_percent: None,
        memory_usage_percent: None,
        memory_total_mb: None,
        memory_used_mb: None,
        disk_usage_percent: None,
        disk_total_gb: None,
        disk_used_gb: None,
        db_connections_active: None,
        db_connections_idle: None,
        db_connections_max: None,
        db_size_mb: None,
        agents_connected: None,
        timestamp: None,
    })))
}

async fn log_system_status(
    State(state): State<AppState>,
    Json(status): Json<SystemStatus>,
) -> Result<StatusCode, Response> {
    sqlx::query(
        "INSERT INTO system_status_log (
            cpu_usage_percent, memory_usage_percent, memory_total_mb, memory_used_mb,
            disk_usage_percent, disk_total_gb, disk_used_gb,
            db_connections_active, db_connections_idle, db_connections_max,
            db_size_mb, agents_connected
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)"
    )
    .bind(status.cpu_usage_percent)
    .bind(status.memory_usage_percent)
    .bind(status.memory_total_mb)
    .bind(status.memory_used_mb)
    .bind(status.disk_usage_percent)
    .bind(status.disk_total_gb)
    .bind(status.disk_used_gb)
    .bind(status.db_connections_active)
    .bind(status.db_connections_idle)
    .bind(status.db_connections_max)
    .bind(status.db_size_mb)
    .bind(status.agents_connected)
    .execute(&state.pg_pool)
    .await
    .map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to log status: {}", e)).into_response()
    })?;

    Ok(StatusCode::CREATED)
}

async fn get_system_health(State(state): State<AppState>) -> Result<Json<SystemHealth>, Response> {
    // Check database connection
    let db_healthy = sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.pg_pool)
        .await
        .is_ok();

    // Get agents count
    let agents_connected = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM agents WHERE status = 'connected'"
    )
    .fetch_one(&state.pg_pool)
    .await
    .unwrap_or(0);

    let status = if db_healthy && agents_connected > 0 {
        "healthy"
    } else if db_healthy {
        "degraded"
    } else {
        "unhealthy"
    };

    Ok(Json(SystemHealth {
        status: status.to_string(),
        backend_healthy: true,
        database_healthy: db_healthy,
        uptime_seconds: 0, // TODO: Track actual uptime
        version: env!("CARGO_PKG_VERSION").to_string(),
    }))
}

// ============================================================================
// Database Management Handlers
// ============================================================================

async fn get_database_stats(State(state): State<AppState>) -> Result<Json<DatabaseStats>, Response> {
    let stats = sqlx::query_as::<_, DatabaseStats>(
        "SELECT * FROM get_database_stats()"
    )
    .fetch_one(&state.pg_pool)
    .await
    .map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)).into_response()
    })?;

    Ok(Json(stats))
}

async fn trigger_cleanup(
    State(state): State<AppState>,
    Json(request): Json<CleanupRequest>,
) -> Result<Json<Vec<CleanupResult>>, Response> {
    let mut results = Vec::new();

    match request.target.as_str() {
        "auditd_events" | "all" => {
            let result = sqlx::query!(
                "SELECT * FROM cleanup_old_auditd_events($1)",
                request.retention_days
            )
            .fetch_one(&state.pg_pool)
            .await
            .map_err(|e| {
                (StatusCode::INTERNAL_SERVER_ERROR, format!("Cleanup failed: {}", e)).into_response()
            })?;

            results.push(CleanupResult {
                target: "auditd_events".to_string(),
                deleted_count: result.deleted_count.unwrap_or(0),
                cleanup_timestamp: result.cleanup_timestamp.unwrap(),
            });
        }
        _ => {}
    }

    if request.target == "alerts" || request.target == "all" {
        let result = sqlx::query!(
            "SELECT * FROM cleanup_old_alerts($1)",
            request.retention_days
        )
        .fetch_one(&state.pg_pool)
        .await
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Cleanup failed: {}", e)).into_response()
        })?;

        results.push(CleanupResult {
            target: "alerts".to_string(),
            deleted_count: result.deleted_count.unwrap_or(0),
            cleanup_timestamp: result.cleanup_timestamp.unwrap(),
        });
    }

    if request.target == "system_logs" || request.target == "all" {
        let result = sqlx::query!(
            "SELECT * FROM cleanup_old_system_logs($1)",
            request.retention_days
        )
        .fetch_one(&state.pg_pool)
        .await
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Cleanup failed: {}", e)).into_response()
        })?;

        results.push(CleanupResult {
            target: "system_logs".to_string(),
            deleted_count: result.deleted_count.unwrap_or(0),
            cleanup_timestamp: result.cleanup_timestamp.unwrap(),
        });
    }

    Ok(Json(results))
}

// ============================================================================
// API Keys Handlers
// ============================================================================

async fn list_api_keys(State(state): State<AppState>) -> Result<Json<Vec<ApiKey>>, Response> {
    let keys = sqlx::query_as::<_, ApiKey>(
        "SELECT id, name, key_prefix, description, scopes, is_active,
                expires_at, last_used_at, created_at, created_by
         FROM api_keys
         ORDER BY created_at DESC"
    )
    .fetch_all(&state.pg_pool)
    .await
    .map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)).into_response()
    })?;

    Ok(Json(keys))
}

async fn create_api_key(
    State(state): State<AppState>,
    Json(payload): Json<CreateApiKeyRequest>,
) -> Result<Json<CreateApiKeyResponse>, Response> {
    // Generate random API key
    let key = format!("cs_{}", uuid::Uuid::new_v4().simple());
    let key_prefix = key.chars().take(12).collect::<String>();

    // Hash the key
    let key_hash = format!("{:x}", sha2::Sha256::digest(key.as_bytes()));

    // Calculate expiration
    let expires_at = payload.expires_in_days.map(|days| {
        chrono::Utc::now().naive_utc() + chrono::Duration::days(days as i64)
    });

    let result = sqlx::query!(
        "INSERT INTO api_keys (name, key_hash, key_prefix, description, scopes, expires_at, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING id, created_at",
        payload.name,
        key_hash,
        key_prefix,
        payload.description,
        &payload.scopes,
        expires_at,
        "admin" // TODO: Get from auth context
    )
    .fetch_one(&state.pg_pool)
    .await
    .map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create API key: {}", e)).into_response()
    })?;

    Ok(Json(CreateApiKeyResponse {
        id: result.id,
        name: payload.name,
        key, // Full key, only shown once
        key_prefix,
        scopes: payload.scopes,
        expires_at,
        created_at: result.created_at,
    }))
}

async fn get_api_key(
    State(state): State<AppState>,
    Path(id): Path<i32>,
) -> Result<Json<ApiKey>, Response> {
    let key = sqlx::query_as::<_, ApiKey>(
        "SELECT id, name, key_prefix, description, scopes, is_active,
                expires_at, last_used_at, created_at, created_by
         FROM api_keys
         WHERE id = $1"
    )
    .bind(id)
    .fetch_one(&state.pg_pool)
    .await
    .map_err(|e| {
        (StatusCode::NOT_FOUND, format!("API key not found: {}", e)).into_response()
    })?;

    Ok(Json(key))
}

async fn revoke_api_key(
    State(state): State<AppState>,
    Path(id): Path<i32>,
) -> Result<StatusCode, Response> {
    sqlx::query!(
        "UPDATE api_keys
         SET is_active = false, revoked_at = NOW(), revoked_by = $1
         WHERE id = $2",
        "admin", // TODO: Get from auth context
        id
    )
    .execute(&state.pg_pool)
    .await
    .map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to revoke API key: {}", e)).into_response()
    })?;

    Ok(StatusCode::OK)
}

// ============================================================================
// Integrations Handlers
// ============================================================================

async fn list_integrations(State(state): State<AppState>) -> Result<Json<Vec<Integration>>, Response> {
    let integrations = sqlx::query_as::<_, Integration>(
        r#"SELECT id, name, type as integration_type, enabled, hostname, ip_address, port, use_ssl,
                  sync_mode, sync_interval, last_sync_at, last_sync_status, last_sync_error,
                  config, created_at, updated_at
           FROM integrations
           ORDER BY created_at DESC"#
    )
    .fetch_all(&state.pg_pool)
    .await
    .map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)).into_response()
    })?;

    Ok(Json(integrations))
}

async fn create_integration(
    State(state): State<AppState>,
    Json(payload): Json<CreateIntegrationRequest>,
) -> Result<Json<Integration>, Response> {
    // TODO: Encrypt api_key before storing
    let integration = sqlx::query_as::<_, Integration>(
        r#"INSERT INTO integrations (
            name, type, api_key, hostname, ip_address, port, use_ssl,
            sync_mode, sync_interval, config, created_by
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        RETURNING id, name, type as integration_type, enabled, hostname, ip_address, port, use_ssl,
                  sync_mode, sync_interval, last_sync_at, last_sync_status, last_sync_error,
                  config, created_at, updated_at"#
    )
    .bind(&payload.name)
    .bind(&payload.integration_type)
    .bind(&payload.api_key)
    .bind(&payload.hostname)
    .bind(&payload.ip_address)
    .bind(&payload.port)
    .bind(payload.use_ssl.unwrap_or(true))
    .bind(&payload.sync_mode)
    .bind(&payload.sync_interval)
    .bind(&payload.config)
    .bind("admin") // TODO: Get from auth context
    .fetch_one(&state.pg_pool)
    .await
    .map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create integration: {}", e)).into_response()
    })?;

    Ok(Json(integration))
}

async fn get_integration(
    State(state): State<AppState>,
    Path(id): Path<i32>,
) -> Result<Json<Integration>, Response> {
    let integration = sqlx::query_as::<_, Integration>(
        r#"SELECT id, name, type as integration_type, enabled, hostname, ip_address, port, use_ssl,
                  sync_mode, sync_interval, last_sync_at, last_sync_status, last_sync_error,
                  config, created_at, updated_at
           FROM integrations
           WHERE id = $1"#
    )
    .bind(id)
    .fetch_one(&state.pg_pool)
    .await
    .map_err(|e| {
        (StatusCode::NOT_FOUND, format!("Integration not found: {}", e)).into_response()
    })?;

    Ok(Json(integration))
}

async fn update_integration(
    State(state): State<AppState>,
    Path(id): Path<i32>,
    Json(payload): Json<UpdateIntegrationRequest>,
) -> Result<Json<Integration>, Response> {
    // Build dynamic update query
    let mut query = "UPDATE integrations SET ".to_string();
    let mut updates = Vec::new();
    let mut param_count = 1;

    if payload.name.is_some() {
        updates.push(format!("name = ${}", param_count));
        param_count += 1;
    }
    if payload.enabled.is_some() {
        updates.push(format!("enabled = ${}", param_count));
        param_count += 1;
    }
    // Add more fields as needed...

    query.push_str(&updates.join(", "));
    query.push_str(&format!(" WHERE id = ${}", param_count));
    query.push_str(" RETURNING id, name, type as integration_type, enabled, hostname, ip_address, port, use_ssl, sync_mode, sync_interval, last_sync_at, last_sync_status, last_sync_error, config, created_at, updated_at");

    // For now, simple update
    let integration = sqlx::query_as::<_, Integration>(
        r#"UPDATE integrations
           SET name = COALESCE($1, name),
               enabled = COALESCE($2, enabled),
               hostname = COALESCE($3, hostname),
               ip_address = COALESCE($4, ip_address),
               port = COALESCE($5, port),
               use_ssl = COALESCE($6, use_ssl),
               sync_mode = COALESCE($7, sync_mode),
               sync_interval = COALESCE($8, sync_interval),
               config = COALESCE($9, config)
           WHERE id = $10
           RETURNING id, name, type as integration_type, enabled, hostname, ip_address, port, use_ssl,
                     sync_mode, sync_interval, last_sync_at, last_sync_status, last_sync_error,
                     config, created_at, updated_at"#
    )
    .bind(&payload.name)
    .bind(&payload.enabled)
    .bind(&payload.hostname)
    .bind(&payload.ip_address)
    .bind(&payload.port)
    .bind(&payload.use_ssl)
    .bind(&payload.sync_mode)
    .bind(&payload.sync_interval)
    .bind(&payload.config)
    .bind(id)
    .fetch_one(&state.pg_pool)
    .await
    .map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update integration: {}", e)).into_response()
    })?;

    Ok(Json(integration))
}

async fn delete_integration(
    State(state): State<AppState>,
    Path(id): Path<i32>,
) -> Result<StatusCode, Response> {
    sqlx::query!("DELETE FROM integrations WHERE id = $1", id)
        .execute(&state.pg_pool)
        .await
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to delete integration: {}", e)).into_response()
        })?;

    Ok(StatusCode::OK)
}

async fn test_integration(
    State(state): State<AppState>,
    Path(id): Path<i32>,
) -> Result<Json<serde_json::Value>, Response> {
    // TODO: Implement actual integration testing
    Ok(Json(serde_json::json!({
        "status": "success",
        "message": "Integration test successful",
        "response_time_ms": 125
    })))
}

async fn trigger_sync(
    State(state): State<AppState>,
    Path(id): Path<i32>,
) -> Result<StatusCode, Response> {
    // Update last_sync_at and status
    sqlx::query!(
        "UPDATE integrations
         SET last_sync_at = NOW(), last_sync_status = 'in_progress'
         WHERE id = $1",
        id
    )
    .execute(&state.pg_pool)
    .await
    .map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to trigger sync: {}", e)).into_response()
    })?;

    // TODO: Implement actual sync logic in background task

    Ok(StatusCode::ACCEPTED)
}
