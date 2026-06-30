// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - Hardening API
// ============================================================================
// Rust backend integration with Django Hardening Engine

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use reqwest::Client;
use chrono::{DateTime, Utc};
use sqlx::Row;
use crate::AppState;
use crate::models::{HardeningTemplate, HardeningExecution};
use crate::middleware::auth::AuthUser;
use crate::middleware::permissions::ManagerUser;

pub fn routes() -> Router<crate::AppState> {
    Router::new()
        // Django-based hardening endpoints
        .route("/models", get(list_models))
        .route("/models/:model_path", get(get_model))
        .route("/apply", post(apply_hardening))
        .route("/validate", post(validate_model))
        .route("/history/:target_id", get(hardening_history))
        .route("/rollback", post(rollback_hardening))
        .route("/backups", get(list_backups))
        .route("/test-connection", post(test_ssh_connection))
        // New template-based hardening endpoints
        .route("/templates", get(list_templates))
        .route("/templates/:id", get(get_template))
        .route("/execute", post(execute_template))
        .route("/executions", get(list_executions))
        .route("/executions/:id", get(get_execution))
        .route("/executions/:id/rollback", post(rollback_execution))
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

/// Validate that a model path contains only safe characters and no traversal sequences.
/// Allowed: alphanumeric, `/`, `-`, `_`, `.` — no `..`, null bytes, or leading `/`.
/// Returns Err with a 400 response if the path is invalid (CWE-22, CWE-918).
fn validate_model_path(path: &str) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if path.is_empty() || path.len() > 256 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid model path"})),
        ));
    }
    if path.contains("..") || path.starts_with('/') {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid model path"})),
        ));
    }
    let valid = path
        .chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '/' | '-' | '_' | '.'));
    if !valid {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid model path"})),
        ));
    }
    Ok(())
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
    // Validate model_path before embedding it in the Django URL (CWE-918, CWE-22)
    if let Err(err) = validate_model_path(&model_path) {
        return err.into_response();
    }

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
    _manager: ManagerUser,
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
    _manager: ManagerUser,
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
    _manager: ManagerUser,
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

// ============================================================================
// Template-Based Hardening DTOs
// ============================================================================

#[derive(Debug, Deserialize)]
struct ListTemplatesQuery {
    framework: Option<String>,      // nis2, nist, iso27001, mitre
    os: Option<String>,              // debian_ubuntu, rhel_oracle, sles, windows, docker, lxc
    priority: Option<String>,        // critical, high, medium, low
    compliance_level: Option<String>, // essential, standard, high
}

#[derive(Debug, Deserialize)]
struct ExecuteTemplateRequest {
    template_id: i32,
    target_ids: Vec<i32>,
    execution_mode: String, // 'dry_run' or 'apply'
}

#[derive(Debug, Deserialize)]
struct ListExecutionsQuery {
    target_id: Option<i32>,
    template_id: Option<i32>,
    status: Option<String>, // pending, running, completed, failed, rolled_back
    limit: Option<i64>,
}

#[derive(Debug, Serialize)]
struct TemplateResponse {
    #[serde(flatten)]
    template: HardeningTemplate,
    controls_count: i64,
    framework_names: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ExecutionResponse {
    execution_ids: Vec<i64>,
    message: String,
}

// ============================================================================
// Template-Based Hardening Handlers
// ============================================================================

/// GET /api/hardening/templates
/// List hardening templates with optional filters
async fn list_templates(
    State(state): State<AppState>,
    Query(params): Query<ListTemplatesQuery>,
    _auth_user: AuthUser,
) -> impl IntoResponse {
    let mut query = String::from(
        r#"
        SELECT *
        FROM hardening_templates
        WHERE 1=1
        "#,
    );

    // Apply filters
    if let Some(ref framework) = params.framework {
        query.push_str(&format!(" AND framework_code ILIKE '%{}%'", framework));
    }

    if let Some(ref os) = params.os {
        query.push_str(&format!(" AND target_os ILIKE '%{}%'", os));
    }

    if let Some(ref priority) = params.priority {
        query.push_str(&format!(
            " AND template_config->>'priority' = '{}'",
            priority
        ));
    }

    if let Some(ref compliance_level) = params.compliance_level {
        query.push_str(&format!(" AND compliance_level = '{}'", compliance_level));
    }

    query.push_str(" ORDER BY execution_order, name");

    match sqlx::query_as::<_, HardeningTemplate>(&query)
        .fetch_all(&state.pg_pool)
        .await
    {
        Ok(templates) => {
            // Enrich templates with additional metadata
            let mut enriched_templates = Vec::new();
            for template in templates {
                let controls_count = if let Some(controls) = template.template_config.get("controls") {
                    controls.as_array().map(|arr| arr.len() as i64).unwrap_or(0)
                } else {
                    0
                };

                let framework_names = if let Some(fw_code) = &template.framework_code {
                    fw_code
                        .split(',')
                        .map(|code| match code.trim() {
                            "nis2" => "NIS2".to_string(),
                            "nist" => "NIST 800-53".to_string(),
                            "iso27001" => "ISO 27001".to_string(),
                            "mitre" => "MITRE D3FEND".to_string(),
                            _ => code.to_string(),
                        })
                        .collect()
                } else {
                    Vec::new()
                };

                enriched_templates.push(TemplateResponse {
                    template,
                    controls_count,
                    framework_names,
                });
            }

            (StatusCode::OK, Json(serde_json::json!({ "templates": enriched_templates }))).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() }))
        ).into_response()
    }
}

/// GET /api/hardening/templates/:id
/// Get a single hardening template by ID
async fn get_template(
    State(state): State<AppState>,
    Path(id): Path<i32>,
    _auth_user: AuthUser,
) -> impl IntoResponse {
    match sqlx::query_as::<_, HardeningTemplate>(
        "SELECT * FROM hardening_templates WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.pg_pool)
    .await
    {
        Ok(Some(template)) => (StatusCode::OK, Json(template)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Template not found" }))
        ).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() }))
        ).into_response()
    }
}

/// POST /api/hardening/execute
/// Execute a hardening template on one or more targets
async fn execute_template(
    State(state): State<AppState>,
    _manager: ManagerUser,
    Json(payload): Json<ExecuteTemplateRequest>,
) -> impl IntoResponse {
    // Validate execution mode
    if !["dry_run", "apply"].contains(&payload.execution_mode.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid execution_mode. Must be 'dry_run' or 'apply'"}))
        ).into_response();
    }

    // Validate template exists
    let template_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM hardening_templates WHERE id = $1)",
    )
    .bind(payload.template_id)
    .fetch_one(&state.pg_pool)
    .await
    .unwrap_or(false);

    if !template_exists {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Template not found"}))
        ).into_response();
    }

    // Validate all targets exist
    for target_id in &payload.target_ids {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM targets WHERE id = $1 AND status = 'active')",
        )
        .bind(target_id)
        .fetch_one(&state.pg_pool)
        .await
        .unwrap_or(false);

        if !exists {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("Target {} not found or inactive", target_id)}))
            ).into_response();
        }
    }

    // Create execution records for each target
    let mut execution_ids = Vec::new();
    for target_id in payload.target_ids {
        match sqlx::query_scalar::<_, i64>(
            r#"
            INSERT INTO hardening_executions (
                template_id, target_id, execution_mode, status, started_at
            )
            VALUES ($1, $2, $3, 'pending', NOW())
            RETURNING id
            "#,
        )
        .bind(payload.template_id)
        .bind(target_id)
        .bind(&payload.execution_mode)
        .fetch_one(&state.pg_pool)
        .await
        {
            Ok(id) => execution_ids.push(id),
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": e.to_string()}))
                ).into_response();
            }
        }
    }

    let execution_count = execution_ids.len();
    (StatusCode::OK, Json(ExecutionResponse {
        execution_ids,
        message: format!(
            "Created {} execution(s) in {} mode. Executions will begin shortly.",
            execution_count,
            payload.execution_mode
        ),
    })).into_response()
}

/// GET /api/hardening/executions
/// List hardening executions with optional filters
async fn list_executions(
    State(state): State<AppState>,
    Query(params): Query<ListExecutionsQuery>,
    _auth_user: AuthUser,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(50).min(100);

    let mut query = String::from(
        r#"
        SELECT
            he.*,
            ht.name as template_name,
            t.hostname as target_hostname
        FROM hardening_executions he
        JOIN hardening_templates ht ON he.template_id = ht.id
        JOIN targets t ON he.target_id = t.id
        WHERE 1=1
        "#,
    );

    if let Some(target_id) = params.target_id {
        query.push_str(&format!(" AND he.target_id = {}", target_id));
    }

    if let Some(template_id) = params.template_id {
        query.push_str(&format!(" AND he.template_id = {}", template_id));
    }

    if let Some(ref status) = params.status {
        query.push_str(&format!(" AND he.status = '{}'", status));
    }

    query.push_str(&format!(" ORDER BY he.created_at DESC LIMIT {}", limit));

    match sqlx::query(&query)
        .fetch_all(&state.pg_pool)
        .await
    {
        Ok(executions) => {
            let executions_json: Vec<serde_json::Value> = executions
                .iter()
                .map(|row| {
                    let total_controls = row.try_get::<Option<i32>, _>("total_controls").ok().flatten().unwrap_or(0);
                    let successful = row.try_get::<Option<i32>, _>("successful_controls").ok().flatten().unwrap_or(0);
                    let failed = row.try_get::<Option<i32>, _>("failed_controls").ok().flatten().unwrap_or(0);

                    let progress = if total_controls > 0 {
                        ((successful + failed) as f64 / total_controls as f64) * 100.0
                    } else {
                        0.0
                    };

                    serde_json::json!({
                        "id": row.try_get::<i64, _>("id").ok(),
                        "template_id": row.try_get::<i32, _>("template_id").ok(),
                        "template_name": row.try_get::<String, _>("template_name").ok(),
                        "target_id": row.try_get::<i32, _>("target_id").ok(),
                        "target_hostname": row.try_get::<String, _>("target_hostname").ok(),
                        "execution_mode": row.try_get::<String, _>("execution_mode").ok(),
                        "status": row.try_get::<String, _>("status").ok(),
                        "started_at": row.try_get::<Option<DateTime<Utc>>, _>("started_at").ok().flatten(),
                        "completed_at": row.try_get::<Option<DateTime<Utc>>, _>("completed_at").ok().flatten(),
                        "total_controls": total_controls,
                        "successful_controls": successful,
                        "failed_controls": failed,
                        "progress_percentage": progress,
                        "compliance_score_before": row.try_get::<Option<f64>, _>("compliance_score_before").ok().flatten(),
                        "compliance_score_after": row.try_get::<Option<f64>, _>("compliance_score_after").ok().flatten(),
                    })
                })
                .collect();

            (StatusCode::OK, Json(serde_json::json!({ "executions": executions_json }))).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() }))
        ).into_response()
    }
}

/// GET /api/hardening/executions/:id
/// Get a single execution by ID with full details
async fn get_execution(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    _auth_user: AuthUser,
) -> impl IntoResponse {
    match sqlx::query_as::<_, HardeningExecution>(
        "SELECT * FROM hardening_executions WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.pg_pool)
    .await
    {
        Ok(Some(execution)) => {
            // Get template and target info
            let template_name: String = sqlx::query_scalar(
                "SELECT name FROM hardening_templates WHERE id = $1",
            )
            .bind(execution.template_id)
            .fetch_one(&state.pg_pool)
            .await
            .unwrap_or_else(|_| "Unknown".to_string());

            let target_hostname: String = sqlx::query_scalar(
                "SELECT hostname FROM targets WHERE id = $1",
            )
            .bind(execution.target_id)
            .fetch_one(&state.pg_pool)
            .await
            .unwrap_or_else(|_| "Unknown".to_string());

            let total_controls = execution.total_controls.unwrap_or(0);
            let successful = execution.successful_controls.unwrap_or(0);
            let failed = execution.failed_controls.unwrap_or(0);

            let progress = if total_controls > 0 {
                ((successful + failed) as f64 / total_controls as f64) * 100.0
            } else {
                0.0
            };

            (StatusCode::OK, Json(serde_json::json!({
                "execution": execution,
                "template_name": template_name,
                "target_hostname": target_hostname,
                "progress_percentage": progress,
            }))).into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Execution not found" }))
        ).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() }))
        ).into_response()
    }
}

/// POST /api/hardening/executions/:id/rollback
/// Rollback a completed hardening execution
async fn rollback_execution(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    _manager: ManagerUser,
) -> impl IntoResponse {
    // Get the execution
    let execution = match sqlx::query_as::<_, HardeningExecution>(
        "SELECT * FROM hardening_executions WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.pg_pool)
    .await
    {
        Ok(Some(exec)) => exec,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Execution not found"}))
            ).into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()}))
            ).into_response();
        }
    };

    // Validate execution can be rolled back
    if execution.status != "completed" {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Only completed executions can be rolled back"}))
        ).into_response();
    }

    if execution.execution_mode == "dry_run" {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Dry-run executions cannot be rolled back"}))
        ).into_response();
    }

    if execution.rollback_data.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "No rollback data available for this execution"}))
        ).into_response();
    }

    // Get template to check if rollback is supported
    let template = match sqlx::query_as::<_, HardeningTemplate>(
        "SELECT * FROM hardening_templates WHERE id = $1",
    )
    .bind(execution.template_id)
    .fetch_one(&state.pg_pool)
    .await
    {
        Ok(tmpl) => tmpl,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()}))
            ).into_response();
        }
    };

    if !template.rollback_supported {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "This template does not support rollback"}))
        ).into_response();
    }

    // Create new execution record for rollback
    match sqlx::query_scalar::<_, i64>(
        r#"
        INSERT INTO hardening_executions (
            template_id, target_id, execution_mode, status, started_at
        )
        VALUES ($1, $2, 'rollback', 'pending', NOW())
        RETURNING id
        "#,
    )
    .bind(execution.template_id)
    .bind(execution.target_id)
    .fetch_one(&state.pg_pool)
    .await
    {
        Ok(rollback_id) => {
            (StatusCode::OK, Json(serde_json::json!({
                "status": "success",
                "message": "Rollback execution created",
                "rollback_execution_id": rollback_id,
            }))).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()}))
        ).into_response()
    }
}
