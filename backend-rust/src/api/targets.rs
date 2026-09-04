// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - Targets API
// ============================================================================

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::middleware::auth::AuthUser;
use crate::middleware::permissions::ManagerUser;
use crate::models::Target;
use crate::AppState;

// ============================================================================
// DTOs (Data Transfer Objects)
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct CreateTargetRequest {
    pub hostname: String,
    pub ip_address: String,
    pub mac_address: Option<String>,
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
        .route("/:id/pairing", post(start_pairing).get(get_pairing_status))
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
        SELECT id, hostname, ip_address::text AS ip_address, ssh_port, ssh_username, ssh_key_id,
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
        SELECT id, hostname, ip_address::text AS ip_address, ssh_port, ssh_username, ssh_key_id,
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
    _manager: ManagerUser,
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

    // Identità per il pairing agent (stile FireDog): SHA512(ip+hostname+mac),
    // calcolata solo se il MAC è fornito. La stessa stringa è ricomposta
    // dall'agent in fase 2 di pairing (ip+hostname+mac, mac in minuscolo).
    let mac_norm = payload
        .mac_address
        .as_ref()
        .map(|m| m.trim().to_lowercase())
        .filter(|m| !m.is_empty());
    let identity_hash: Option<String> = mac_norm.as_ref().map(|mac| {
        use sha2::{Digest, Sha512};
        let mut h = Sha512::new();
        h.update(format!("{}{}{}", payload.ip_address, payload.hostname, mac));
        h.finalize().iter().map(|b| format!("{:02x}", b)).collect::<String>()
    });

    let target = sqlx::query_as::<_, Target>(
        r#"
        INSERT INTO targets (
            hostname, ip_address, mac_address, identity_hash, ssh_port, ssh_username, ssh_key_id,
            role, environment, gruppo, tags, compliance_standard,
            monitoring_enabled, monitoring_interval_seconds
        )
        VALUES ($1, $2::inet, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
        RETURNING id, hostname, ip_address::text AS ip_address, ssh_port, ssh_username, ssh_key_id,
                  role, environment, gruppo, tags, compliance_standard,
                  status, status_message, last_seen, last_check,
                  hardening_applied, hardening_model_id, hardening_applied_at, hardening_score,
                  monitoring_enabled, monitoring_interval_seconds, last_monitoring_at,
                  monitoring_errors_count, created_at, updated_at
        "#,
    )
    .bind(&payload.hostname)
    .bind(&payload.ip_address)
    .bind(mac_norm)
    .bind(identity_hash)
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
        SELECT id, hostname, ip_address::text AS ip_address, ssh_port, ssh_username, ssh_key_id,
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
    _manager: ManagerUser,
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
        RETURNING id, hostname, ip_address::text AS ip_address, ssh_port, ssh_username, ssh_key_id,
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
    _manager: ManagerUser,
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
    let target = sqlx::query_as::<_, (i32, String, String, Option<String>, Option<DateTime<Utc>>, Option<DateTime<Utc>>, bool, i32)>(
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
    _manager: ManagerUser,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    // TODO: Implement actual SSH connection test
    // This will use the SSH manager from Django backend
    Ok(Json(json!({
        "status": "not_implemented",
        "message": "SSH connection testing will be implemented with Django integration"
    })))
}

// ============================================================================
// Agent pairing (stile FireDog — finestra 3 minuti)
// ============================================================================

/// Avvia una finestra di pairing di 3 minuti per il target.
/// L'agent, avviato sul target entro la finestra, presenta ip/hostname/mac:
/// il server calcola SHA512(ip+hostname+mac) e lo confronta con `identity_hash`.
async fn start_pairing(
    State(state): State<AppState>,
    Path(id): Path<i32>,
    _manager: ManagerUser,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    use sqlx::Row;

    // Il target deve esistere e avere un'identità registrata (mac/identity_hash).
    let target = sqlx::query("SELECT identity_hash, agent_auth_token FROM targets WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.pg_pool)
        .await
        .map_err(db_err)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse { error: "Target not found".to_string() }),
            )
        })?;

    let identity_hash: Option<String> = target.try_get("identity_hash").ok().flatten();
    if identity_hash.as_deref().unwrap_or("").is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Target senza identità (MAC mancante): impossibile avviare il pairing".to_string(),
            }),
        ));
    }

    // Scade eventuali sessioni ancora aperte per lo stesso target.
    let _ = sqlx::query(
        "UPDATE pairing_sessions SET status = 'expired' \
         WHERE target_id = $1 AND status IN ('pending','verifying_hash')",
    )
    .bind(id)
    .execute(&state.pg_pool)
    .await;

    let row = sqlx::query(
        "INSERT INTO pairing_sessions (target_id, status, expires_at) \
         VALUES ($1, 'pending', now() + interval '3 minutes') \
         RETURNING id, expires_at",
    )
    .bind(id)
    .fetch_one(&state.pg_pool)
    .await
    .map_err(db_err)?;

    let session_id: i32 = row.try_get("id").map_err(db_err)?;
    let expires_at: DateTime<Utc> = row.try_get("expires_at").map_err(db_err)?;

    Ok(Json(json!({
        "session_id": session_id,
        "target_id": id,
        "status": "pending",
        "expires_at": expires_at.to_rfc3339(),
        "window_seconds": 180,
    })))
}

/// Poll dello stato dell'ultima sessione di pairing del target.
async fn get_pairing_status(
    State(state): State<AppState>,
    Path(id): Path<i32>,
    _auth: AuthUser,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    use sqlx::Row;

    let row = sqlx::query(
        "SELECT id, status, phase_1_verified, phase_2_verified, error_message, \
                expires_at, completed_at, agent_ip, agent_hostname, agent_mac \
         FROM pairing_sessions WHERE target_id = $1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(id)
    .fetch_optional(&state.pg_pool)
    .await
    .map_err(db_err)?;

    let Some(row) = row else {
        return Ok(Json(json!({ "status": "none", "target_id": id })));
    };

    let status: String = row.try_get("status").unwrap_or_else(|_| "unknown".to_string());
    let expires_at: Option<DateTime<Utc>> = row.try_get("expires_at").ok();
    // Se scaduta ma ancora "pending", riporta 'expired' (la scadenza è lazy).
    let effective = match (&status[..], expires_at) {
        ("pending" | "verifying_hash", Some(exp)) if exp < Utc::now() => "expired".to_string(),
        _ => status,
    };

    Ok(Json(json!({
        "session_id": row.try_get::<i32, _>("id").ok(),
        "target_id": id,
        "status": effective,
        "phase_1_verified": row.try_get::<bool, _>("phase_1_verified").unwrap_or(false),
        "phase_2_verified": row.try_get::<bool, _>("phase_2_verified").unwrap_or(false),
        "error_message": row.try_get::<Option<String>, _>("error_message").ok().flatten(),
        "expires_at": expires_at.map(|d| d.to_rfc3339()),
        "completed_at": row.try_get::<Option<DateTime<Utc>>, _>("completed_at").ok().flatten().map(|d| d.to_rfc3339()),
        "agent_ip": row.try_get::<Option<String>, _>("agent_ip").ok().flatten(),
        "agent_hostname": row.try_get::<Option<String>, _>("agent_hostname").ok().flatten(),
        "agent_mac": row.try_get::<Option<String>, _>("agent_mac").ok().flatten(),
    })))
}

/// Helper: mappa un errore sqlx a una 500 con messaggio generico.
fn db_err(e: sqlx::Error) -> (StatusCode, Json<ErrorResponse>) {
    tracing::error!(error = %e, "pairing db error");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse { error: "Database error".to_string() }),
    )
}
