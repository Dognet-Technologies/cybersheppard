// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - Targets API
// ============================================================================

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::middleware::auth::AuthUser;
use crate::models::Target;
use crate::AppState;

// ============================================================================
// DTOs (Data Transfer Objects)
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct CreateTargetRequest {
    pub hostname: String,
    pub ip_address: String,
    pub ssh_port: Option<i32>,
    pub ssh_username: Option<String>,
    pub ssh_key_id: Option<i32>,
    pub role: Option<String>,
    pub environment: Option<String>,
    pub gruppo: Option<String>,
    pub tags: Option<Vec<String>>,
    pub compliance_standard: Option<String>,
    pub monitoring_enabled: Option<bool>,
    pub monitoring_interval_seconds: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateTargetRequest {
    pub hostname: Option<String>,
    pub ip_address: Option<String>,
    pub ssh_port: Option<i32>,
    pub ssh_username: Option<String>,
    pub ssh_key_id: Option<i32>,
    pub role: Option<String>,
    pub environment: Option<String>,
    pub gruppo: Option<String>,
    pub tags: Option<Vec<String>>,
    pub compliance_standard: Option<String>,
    pub status: Option<String>,
    pub status_message: Option<String>,
    pub monitoring_enabled: Option<bool>,
    pub monitoring_interval_seconds: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct ListTargetsQuery {
    pub status: Option<String>,
    pub environment: Option<String>,
    pub gruppo: Option<String>,
    pub compliance_standard: Option<String>,
    pub monitoring_enabled: Option<bool>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct TargetResponse {
    pub id: i32,
    pub hostname: String,
    pub ip_address: String,
    pub ssh_port: i32,
    pub ssh_username: String,
    pub ssh_key_id: Option<i32>,
    pub role: Option<String>,
    pub environment: String,
    pub gruppo: Option<String>,
    pub tags: Option<serde_json::Value>,
    pub compliance_standard: Option<String>,
    pub status: String,
    pub status_message: Option<String>,
    pub last_seen: Option<String>,
    pub hardening_applied: bool,
    pub hardening_score: Option<i32>,
    pub monitoring_enabled: bool,
    pub monitoring_interval_seconds: i32,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct TargetListResponse {
    pub targets: Vec<TargetResponse>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

#[derive(Debug, Serialize)]
pub struct TargetStatusResponse {
    pub id: i32,
    pub hostname: String,
    pub status: String,
    pub status_message: Option<String>,
    pub last_seen: Option<String>,
    pub last_check: Option<String>,
    pub monitoring_enabled: bool,
    pub monitoring_errors_count: i32,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub message: String,
}

// ============================================================================
// Routes
// ============================================================================

pub fn routes() -> Router<crate::AppState> {
    Router::new()
        .route("/", get(list_targets).post(create_target))
        .route("/:id", get(get_target).put(update_target).delete(delete_target))
        .route("/:id/status", get(get_target_status))
        .route("/:id/test-connection", post(test_target_connection))
}

// ============================================================================
// Handlers
// ============================================================================

/// List all targets with optional filtering
async fn list_targets(
    State(state): State<AppState>,
    Query(params): Query<ListTargetsQuery>,
    _auth_user: AuthUser,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let limit = params.limit.unwrap_or(100).min(1000);
    let offset = params.offset.unwrap_or(0);

    // Build dynamic query based on filters
    let mut query = String::from(
        r#"
        SELECT id, hostname, ip_address, ssh_port, ssh_username, ssh_key_id,
               role, environment, gruppo, tags, compliance_standard,
               status, status_message, last_seen, last_check,
               hardening_applied, hardening_model_id, hardening_applied_at, hardening_score,
               monitoring_enabled, monitoring_interval_seconds, last_monitoring_at,
               monitoring_errors_count, created_at, updated_at
        FROM targets
        WHERE 1=1
        "#,
    );

    // Add filters
    if params.status.is_some() {
        query.push_str(" AND status = $1");
    }
    if params.environment.is_some() {
        query.push_str(" AND environment = $2");
    }
    if params.gruppo.is_some() {
        query.push_str(" AND gruppo = $3");
    }
    if params.compliance_standard.is_some() {
        query.push_str(" AND compliance_standard = $4");
    }
    if params.monitoring_enabled.is_some() {
        query.push_str(" AND monitoring_enabled = $5");
    }

    query.push_str(" ORDER BY created_at DESC");
    query.push_str(&format!(" LIMIT {} OFFSET {}", limit, offset));

    // For now, use simple query without complex filtering
    // TODO: Use proper parameterized query with sqlx query_as!
    let targets = sqlx::query_as::<_, Target>(
        r#"
        SELECT id, hostname, ip_address, ssh_port, ssh_username, ssh_key_id,
               role, environment, gruppo, tags, compliance_standard,
               status, status_message, last_seen, last_check,
               hardening_applied, hardening_model_id, hardening_applied_at, hardening_score,
               monitoring_enabled, monitoring_interval_seconds, last_monitoring_at,
               monitoring_errors_count, created_at, updated_at
        FROM targets
        ORDER BY created_at DESC
        LIMIT $1 OFFSET $2
        "#,
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.pg_pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Database error: {}", e),
            }),
        )
    })?;

    let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM targets")
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

    let target_responses: Vec<TargetResponse> = targets
        .into_iter()
        .map(|t| TargetResponse {
            id: t.id,
            hostname: t.hostname,
            ip_address: t.ip_address,
            ssh_port: t.ssh_port,
            ssh_username: t.ssh_username,
            ssh_key_id: t.ssh_key_id,
            role: t.role,
            environment: t.environment,
            gruppo: t.gruppo,
            tags: t.tags,
            compliance_standard: t.compliance_standard,
            status: t.status,
            status_message: t.status_message,
            last_seen: t.last_seen.map(|dt| dt.to_rfc3339()),
            hardening_applied: t.hardening_applied,
            hardening_score: t.hardening_score,
            monitoring_enabled: t.monitoring_enabled,
            monitoring_interval_seconds: t.monitoring_interval_seconds,
            created_at: t.created_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(TargetListResponse {
        targets: target_responses,
        total: total.0,
        limit,
        offset,
    }))
}

/// Create a new target
async fn create_target(
    State(state): State<AppState>,
    _auth_user: AuthUser,
    Json(payload): Json<CreateTargetRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    // Validate input
    if payload.hostname.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Hostname cannot be empty".to_string(),
            }),
        ));
    }

    if payload.ip_address.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "IP address cannot be empty".to_string(),
            }),
        ));
    }

    // Convert tags to JSON
    let tags_json = payload.tags.map(|tags| json!(tags));

    let target = sqlx::query_as::<_, Target>(
        r#"
        INSERT INTO targets (
            hostname, ip_address, ssh_port, ssh_username, ssh_key_id,
            role, environment, gruppo, tags, compliance_standard,
            monitoring_enabled, monitoring_interval_seconds
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        RETURNING id, hostname, ip_address, ssh_port, ssh_username, ssh_key_id,
                  role, environment, gruppo, tags, compliance_standard,
                  status, status_message, last_seen, last_check,
                  hardening_applied, hardening_model_id, hardening_applied_at, hardening_score,
                  monitoring_enabled, monitoring_interval_seconds, last_monitoring_at,
                  monitoring_errors_count, created_at, updated_at
        "#,
    )
    .bind(&payload.hostname)
    .bind(&payload.ip_address)
    .bind(payload.ssh_port.unwrap_or(22))
    .bind(payload.ssh_username.unwrap_or_else(|| "microcyber".to_string()))
    .bind(payload.ssh_key_id)
    .bind(payload.role)
    .bind(payload.environment.unwrap_or_else(|| "production".to_string()))
    .bind(payload.gruppo)
    .bind(tags_json)
    .bind(payload.compliance_standard)
    .bind(payload.monitoring_enabled.unwrap_or(true))
    .bind(payload.monitoring_interval_seconds.unwrap_or(30))
    .fetch_one(&state.pg_pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to create target: {}", e),
            }),
        )
    })?;

    let response = TargetResponse {
        id: target.id,
        hostname: target.hostname,
        ip_address: target.ip_address,
        ssh_port: target.ssh_port,
        ssh_username: target.ssh_username,
        ssh_key_id: target.ssh_key_id,
        role: target.role,
        environment: target.environment,
        gruppo: target.gruppo,
        tags: target.tags,
        compliance_standard: target.compliance_standard,
        status: target.status,
        status_message: target.status_message,
        last_seen: target.last_seen.map(|dt| dt.to_rfc3339()),
        hardening_applied: target.hardening_applied,
        hardening_score: target.hardening_score,
        monitoring_enabled: target.monitoring_enabled,
        monitoring_interval_seconds: target.monitoring_interval_seconds,
        created_at: target.created_at.to_rfc3339(),
    };

    Ok((StatusCode::CREATED, Json(response)))
}

/// Get a specific target by ID
async fn get_target(
    State(state): State<AppState>,
    Path(id): Path<i32>,
    _auth_user: AuthUser,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let target = sqlx::query_as::<_, Target>(
        r#"
        SELECT id, hostname, ip_address, ssh_port, ssh_username, ssh_key_id,
               role, environment, gruppo, tags, compliance_standard,
               status, status_message, last_seen, last_check,
               hardening_applied, hardening_model_id, hardening_applied_at, hardening_score,
               monitoring_enabled, monitoring_interval_seconds, last_monitoring_at,
               monitoring_errors_count, created_at, updated_at
        FROM targets
        WHERE id = $1
        "#,
    )
    .bind(id)
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
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Target not found".to_string(),
            }),
        )
    })?;

    let response = TargetResponse {
        id: target.id,
        hostname: target.hostname,
        ip_address: target.ip_address,
        ssh_port: target.ssh_port,
        ssh_username: target.ssh_username,
        ssh_key_id: target.ssh_key_id,
        role: target.role,
        environment: target.environment,
        gruppo: target.gruppo,
        tags: target.tags,
        compliance_standard: target.compliance_standard,
        status: target.status,
        status_message: target.status_message,
        last_seen: target.last_seen.map(|dt| dt.to_rfc3339()),
        hardening_applied: target.hardening_applied,
        hardening_score: target.hardening_score,
        monitoring_enabled: target.monitoring_enabled,
        monitoring_interval_seconds: target.monitoring_interval_seconds,
        created_at: target.created_at.to_rfc3339(),
    };

    Ok(Json(response))
}

/// Update a target
async fn update_target(
    State(state): State<AppState>,
    Path(id): Path<i32>,
    _auth_user: AuthUser,
    Json(payload): Json<UpdateTargetRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    // Check if target exists
    let exists: (bool,) = sqlx::query_as("SELECT EXISTS(SELECT 1 FROM targets WHERE id = $1)")
        .bind(id)
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

    if !exists.0 {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Target not found".to_string(),
            }),
        ));
    }

    // Build dynamic update query
    // For simplicity, update all fields that are provided
    let tags_json = payload.tags.map(|tags| json!(tags));

    let target = sqlx::query_as::<_, Target>(
        r#"
        UPDATE targets
        SET
            hostname = COALESCE($2, hostname),
            ip_address = COALESCE($3, ip_address),
            ssh_port = COALESCE($4, ssh_port),
            ssh_username = COALESCE($5, ssh_username),
            ssh_key_id = COALESCE($6, ssh_key_id),
            role = COALESCE($7, role),
            environment = COALESCE($8, environment),
            gruppo = COALESCE($9, gruppo),
            tags = COALESCE($10, tags),
            compliance_standard = COALESCE($11, compliance_standard),
            status = COALESCE($12, status),
            status_message = COALESCE($13, status_message),
            monitoring_enabled = COALESCE($14, monitoring_enabled),
            monitoring_interval_seconds = COALESCE($15, monitoring_interval_seconds),
            updated_at = NOW()
        WHERE id = $1
        RETURNING id, hostname, ip_address, ssh_port, ssh_username, ssh_key_id,
                  role, environment, gruppo, tags, compliance_standard,
                  status, status_message, last_seen, last_check,
                  hardening_applied, hardening_model_id, hardening_applied_at, hardening_score,
                  monitoring_enabled, monitoring_interval_seconds, last_monitoring_at,
                  monitoring_errors_count, created_at, updated_at
        "#,
    )
    .bind(id)
    .bind(payload.hostname)
    .bind(payload.ip_address)
    .bind(payload.ssh_port)
    .bind(payload.ssh_username)
    .bind(payload.ssh_key_id)
    .bind(payload.role)
    .bind(payload.environment)
    .bind(payload.gruppo)
    .bind(tags_json)
    .bind(payload.compliance_standard)
    .bind(payload.status)
    .bind(payload.status_message)
    .bind(payload.monitoring_enabled)
    .bind(payload.monitoring_interval_seconds)
    .fetch_one(&state.pg_pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to update target: {}", e),
            }),
        )
    })?;

    let response = TargetResponse {
        id: target.id,
        hostname: target.hostname,
        ip_address: target.ip_address,
        ssh_port: target.ssh_port,
        ssh_username: target.ssh_username,
        ssh_key_id: target.ssh_key_id,
        role: target.role,
        environment: target.environment,
        gruppo: target.gruppo,
        tags: target.tags,
        compliance_standard: target.compliance_standard,
        status: target.status,
        status_message: target.status_message,
        last_seen: target.last_seen.map(|dt| dt.to_rfc3339()),
        hardening_applied: target.hardening_applied,
        hardening_score: target.hardening_score,
        monitoring_enabled: target.monitoring_enabled,
        monitoring_interval_seconds: target.monitoring_interval_seconds,
        created_at: target.created_at.to_rfc3339(),
    };

    Ok(Json(response))
}

/// Delete a target
async fn delete_target(
    State(state): State<AppState>,
    Path(id): Path<i32>,
    _auth_user: AuthUser,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let result = sqlx::query("DELETE FROM targets WHERE id = $1")
        .bind(id)
        .execute(&state.pg_pool)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to delete target: {}", e),
                }),
            )
        })?;

    if result.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Target not found".to_string(),
            }),
        ));
    }

    Ok(Json(MessageResponse {
        message: "Target deleted successfully".to_string(),
    }))
}

/// Get target status and health
async fn get_target_status(
    State(state): State<AppState>,
    Path(id): Path<i32>,
    _auth_user: AuthUser,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let target = sqlx::query_as::<_, (i32, String, String, Option<String>, Option<DateTime<_>>, Option<DateTime<_>>, bool, i32)>(
        r#"
        SELECT id, hostname, status, status_message, last_seen, last_check,
               monitoring_enabled, monitoring_errors_count
        FROM targets
        WHERE id = $1
        "#,
    )
    .bind(id)
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
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Target not found".to_string(),
            }),
        )
    })?;

    let response = TargetStatusResponse {
        id: target.0,
        hostname: target.1,
        status: target.2,
        status_message: target.3,
        last_seen: target.4.map(|dt| dt.to_rfc3339()),
        last_check: target.5.map(|dt| dt.to_rfc3339()),
        monitoring_enabled: target.6,
        monitoring_errors_count: target.7,
    };

    Ok(Json(response))
}

/// Test SSH connection to target
async fn test_target_connection(
    State(_state): State<AppState>,
    Path(_id): Path<i32>,
    _auth_user: AuthUser,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    // TODO: Implement actual SSH connection test
    // This will use the SSH manager from Django backend
    Ok(Json(json!({
        "status": "not_implemented",
        "message": "SSH connection testing will be implemented with Django integration"
    })))
}
