// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - Hardening API
// ============================================================================
// Rust backend integration with Django Hardening Engine

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use reqwest::Client;
use chrono::{DateTime, Utc};
use crate::AppState;

pub fn routes() -> Router<crate::AppState> {
    Router::new()
        .route("/models", get(list_models))
        .route("/models/:model_path", get(get_model))
        .route("/apply", post(apply_hardening))
        .route("/validate", post(validate_model))
        .route("/history/:target_id", get(hardening_history))
        .route("/rollback", post(rollback_hardening))
        .route("/backups", get(list_backups))
        .route("/test-connection", post(test_ssh_connection))
}

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Deserialize)]
struct ApplyHardeningRequest {
    target_id: i32,
    model_path: String,
    skip_backup: Option<bool>,
}

#[derive(Serialize, Deserialize)]
struct ApplyHardeningResponse {
    success: bool,
    steps_completed: i32,
    steps_failed: i32,
    backup_path: Option<String>,
    duration_seconds: Option<f64>,
    log: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Deserialize)]
struct RollbackRequest {
    target_id: i32,
    backup_tarball: String,
    selective_files: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
struct RollbackResponse {
    success: bool,
    files_restored: i32,
    files_failed: i32,
    log: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Deserialize)]
struct ValidateModelRequest {
    model_path: String,
}

#[derive(Serialize, Deserialize)]
struct ValidationResponse {
    is_valid: bool,
    errors: Vec<String>,
    summary: ValidationSummary,
}

#[derive(Serialize, Deserialize)]
struct ValidationSummary {
    total: usize,
    critical: usize,
    errors: usize,
    warnings: usize,
    is_safe: bool,
}

#[derive(Deserialize)]
struct TestConnectionRequest {
    target_id: i32,
}

#[derive(Serialize, Deserialize)]
struct TestConnectionResponse {
    success: bool,
    hostname: Option<String>,
    os_info: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Get Django hardening engine URL from environment
fn get_django_url() -> String {
    std::env::var("DJANGO_HARDENING_URL")
        .unwrap_or_else(|_| "http://localhost:8001".to_string())
}

/// Get target SSH info from database
async fn get_target_ssh_info(
    pool: &sqlx::PgPool,
    target_id: i32,
) -> Result<(String, i32, String, String), (StatusCode, Json<serde_json::Value>)> {
    // Query target info with SSH key path from ssh_keys table
    let target = sqlx::query!(
        r#"
        SELECT
            t.ip_address::text,
            t.ssh_port,
            t.ssh_username,
            COALESCE(k.private_key_path, '/opt/cybersheppard/keys/default_ed25519') as key_path
        FROM targets t
        LEFT JOIN ssh_keys k ON t.ssh_key_id = k.id
        WHERE t.id = $1 AND t.is_active = true
        "#,
        target_id
    )
    .fetch_one(pool)
    .await
    .map_err(|_| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "Target not found or inactive"
            }))
        )
    })?;

    Ok((
        target.ip_address.unwrap_or_default(),
        target.ssh_port.unwrap_or(22),
        target.ssh_username.unwrap_or_else(|| "microcyber".to_string()),
        target.key_path.unwrap_or_else(|| "/opt/cybersheppard/keys/default_ed25519".to_string()),
    ))
}

/// Save hardening application result to database
async fn save_hardening_result(
    pool: &sqlx::PgPool,
    target_id: i32,
    model_path: &str,
    result: &ApplyHardeningResponse,
) -> Result<i64, sqlx::Error> {
    let log_json = serde_json::to_value(&result.log).unwrap_or(serde_json::json!([]));

    sqlx::query!(
        r#"
        INSERT INTO hardening_applications
        (target_id, model_path, success, steps_completed, steps_failed,
         backup_path, duration_seconds, result_log, applied_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
        RETURNING id
        "#,
        target_id,
        model_path,
        result.success,
        result.steps_completed,
        result.steps_failed,
        result.backup_path.as_ref(),
        result.duration_seconds,
        log_json
    )
    .fetch_one(pool)
    .await
    .map(|row| row.id)
}

// ============================================================================
// API Handlers
// ============================================================================

/// List all available hardening models
async fn list_models(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let client = Client::new();
    let django_url = get_django_url();

    match client
        .get(format!("{}/api/hardening/models", django_url))
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status();
            match resp.text().await {
                Ok(body) => (StatusCode::from_u16(status.as_u16()).unwrap(), body).into_response(),
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": format!("Failed to read response: {}", e)
                    }))
                ).into_response()
            }
        }
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": format!("Django hardening engine unavailable: {}", e)
            }))
        ).into_response()
    }
}

/// Get specific model details
async fn get_model(
    State(state): State<AppState>,
    Path(model_path): Path<String>,
) -> impl IntoResponse {
    let client = Client::new();
    let django_url = get_django_url();

    match client
        .get(format!("{}/api/hardening/models/{}", django_url, model_path))
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status();
            match resp.text().await {
                Ok(body) => (StatusCode::from_u16(status.as_u16()).unwrap(), body).into_response(),
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": format!("Failed to read response: {}", e)
                    }))
                ).into_response()
            }
        }
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": format!("Django hardening engine unavailable: {}", e)
            }))
        ).into_response()
    }
}

/// Apply hardening model to target
async fn apply_hardening(
    State(state): State<AppState>,
    Json(payload): Json<ApplyHardeningRequest>,
) -> impl IntoResponse {
    // Get target SSH info
    let (target_ip, ssh_port, username, ssh_key_path) = match get_target_ssh_info(&state.pg_pool, payload.target_id).await {
        Ok(info) => info,
        Err(err) => return err.into_response(),
    };

    // Call Django hardening engine
    let client = Client::new();
    let django_url = get_django_url();

    let django_payload = serde_json::json!({
        "target_ip": target_ip,
        "model_path": payload.model_path,
        "ssh_key_path": ssh_key_path,
        "ssh_port": ssh_port,
        "username": username,
        "skip_backup": payload.skip_backup.unwrap_or(false)
    });

    match client
        .post(format!("{}/api/hardening/apply", django_url))
        .json(&django_payload)
        .send()
        .await
    {
        Ok(resp) => {
            match resp.json::<ApplyHardeningResponse>().await {
                Ok(result) => {
                    // Save result to database
                    if let Err(e) = save_hardening_result(
                        &state.pg_pool,
                        payload.target_id,
                        &payload.model_path,
                        &result
                    ).await {
                        tracing::error!("Failed to save hardening result to database: {}", e);
                    }

                    let status_code = if result.success {
                        StatusCode::OK
                    } else {
                        StatusCode::INTERNAL_SERVER_ERROR
                    };

                    (status_code, Json(result)).into_response()
                }
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": format!("Failed to parse Django response: {}", e)
                    }))
                ).into_response()
            }
        }
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": format!("Django hardening engine unavailable: {}", e)
            }))
        ).into_response()
    }
}

/// Validate hardening model
async fn validate_model(
    State(state): State<AppState>,
    Json(payload): Json<ValidateModelRequest>,
) -> impl IntoResponse {
    let client = Client::new();
    let django_url = get_django_url();

    match client
        .post(format!("{}/api/hardening/validate", django_url))
        .json(&serde_json::json!({ "model_path": payload.model_path }))
        .send()
        .await
    {
        Ok(resp) => {
            match resp.json::<ValidationResponse>().await {
                Ok(result) => (StatusCode::OK, Json(result)).into_response(),
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": format!("Failed to parse validation response: {}", e)
                    }))
                ).into_response()
            }
        }
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": format!("Django hardening engine unavailable: {}", e)
            }))
        ).into_response()
    }
}

/// Get hardening history for a target
async fn hardening_history(
    State(state): State<AppState>,
    Path(target_id): Path<i32>,
) -> impl IntoResponse {
    match sqlx::query!(
        r#"
        SELECT id, model_path, success, steps_completed, steps_failed,
               backup_path, duration_seconds, result_log, applied_at
        FROM hardening_applications
        WHERE target_id = $1
        ORDER BY applied_at DESC
        LIMIT 50
        "#,
        target_id
    )
    .fetch_all(&state.pg_pool)
    .await
    {
        Ok(records) => {
            let history: Vec<serde_json::Value> = records
                .iter()
                .map(|r| serde_json::json!({
                    "id": r.id,
                    "model_path": r.model_path,
                    "success": r.success,
                    "steps_completed": r.steps_completed,
                    "steps_failed": r.steps_failed,
                    "backup_path": r.backup_path,
                    "duration_seconds": r.duration_seconds,
                    "applied_at": r.applied_at,
                    "log": r.result_log
                }))
                .collect();

            (StatusCode::OK, Json(serde_json::json!({
                "target_id": target_id,
                "history": history
            }))).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("Database error: {}", e)
            }))
        ).into_response()
    }
}

/// Rollback hardening changes
async fn rollback_hardening(
    State(state): State<AppState>,
    Json(payload): Json<RollbackRequest>,
) -> impl IntoResponse {
    // Get target SSH info
    let (target_ip, ssh_port, username, ssh_key_path) = match get_target_ssh_info(&state.pg_pool, payload.target_id).await {
        Ok(info) => info,
        Err(err) => return err.into_response(),
    };

    // Call Django hardening engine
    let client = Client::new();
    let django_url = get_django_url();

    let django_payload = serde_json::json!({
        "backup_tarball": payload.backup_tarball,
        "target_ip": target_ip,
        "ssh_key_path": ssh_key_path,
        "ssh_port": ssh_port,
        "username": username,
        "selective_files": payload.selective_files
    });

    match client
        .post(format!("{}/api/hardening/rollback", django_url))
        .json(&django_payload)
        .send()
        .await
    {
        Ok(resp) => {
            match resp.json::<RollbackResponse>().await {
                Ok(result) => {
                    let status_code = if result.success {
                        StatusCode::OK
                    } else {
                        StatusCode::INTERNAL_SERVER_ERROR
                    };

                    (status_code, Json(result)).into_response()
                }
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": format!("Failed to parse rollback response: {}", e)
                    }))
                ).into_response()
            }
        }
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": format!("Django hardening engine unavailable: {}", e)
            }))
        ).into_response()
    }
}

/// List available backups
async fn list_backups(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let client = Client::new();
    let django_url = get_django_url();

    match client
        .get(format!("{}/api/hardening/backups", django_url))
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status();
            match resp.text().await {
                Ok(body) => (StatusCode::from_u16(status.as_u16()).unwrap(), body).into_response(),
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": format!("Failed to read response: {}", e)
                    }))
                ).into_response()
            }
        }
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": format!("Django hardening engine unavailable: {}", e)
            }))
        ).into_response()
    }
}

/// Test SSH connection to target
async fn test_ssh_connection(
    State(state): State<AppState>,
    Json(payload): Json<TestConnectionRequest>,
) -> impl IntoResponse {
    // Get target SSH info
    let (target_ip, ssh_port, username, ssh_key_path) = match get_target_ssh_info(&state.pg_pool, payload.target_id).await {
        Ok(info) => info,
        Err(err) => return err.into_response(),
    };

    // Call Django hardening engine
    let client = Client::new();
    let django_url = get_django_url();

    let django_payload = serde_json::json!({
        "target_ip": target_ip,
        "ssh_key_path": ssh_key_path,
        "ssh_port": ssh_port,
        "username": username
    });

    match client
        .post(format!("{}/api/hardening/test-connection", django_url))
        .json(&django_payload)
        .send()
        .await
    {
        Ok(resp) => {
            match resp.json::<TestConnectionResponse>().await {
                Ok(result) => (StatusCode::OK, Json(result)).into_response(),
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": format!("Failed to parse response: {}", e)
                    }))
                ).into_response()
            }
        }
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": format!("Django hardening engine unavailable: {}", e)
            }))
        ).into_response()
    }
}
