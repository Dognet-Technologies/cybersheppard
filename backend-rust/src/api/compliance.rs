// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - Compliance API
// ============================================================================

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, patch, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::middleware::auth::AuthUser;
use crate::models::{CompliancePolicy, ComplianceViolation};
use crate::AppState;

pub fn routes() -> Router<crate::AppState> {
    Router::new()
        .route("/violations", get(list_violations))
        .route("/violations/:id", get(get_violation))
        .route("/violations/:id/acknowledge", patch(acknowledge_violation))
        .route("/violations/:id/resolve", patch(resolve_violation))
        .route("/policies", get(list_policies))
        .route("/policies/:id", get(get_policy))
        .route("/targets/:target_id/status", get(get_target_compliance_status))
}

// ============================================================================
// DTOs
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct ListViolationsQuery {
    pub target_id: Option<i32>,
    pub status: Option<String>,
    pub severity: Option<String>,
    pub category: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct AcknowledgeViolationRequest {
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ResolveViolationRequest {
    pub resolution_notes: String,
    pub status: Option<String>, // 'resolved' or 'false_positive'
}

#[derive(Debug, Serialize)]
pub struct ViolationListResponse {
    pub violations: Vec<ComplianceViolation>,
    pub total: i64,
    pub summary: ViolationSummary,
}

#[derive(Debug, Serialize)]
pub struct ViolationSummary {
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
    pub total: i64,
}

#[derive(Debug, Serialize)]
pub struct ComplianceStatusResponse {
    pub target_id: i32,
    pub status: String,
    pub score: i32,
    pub violations: ViolationSummary,
    pub last_check: Option<chrono::DateTime<chrono::Utc>>,
}

// ============================================================================
// Handlers
// ============================================================================

/// List compliance violations with filters
async fn list_violations(
    State(state): State<AppState>,
    Query(params): Query<ListViolationsQuery>,
    _auth_user: AuthUser,
) -> Result<Json<ViolationListResponse>, (StatusCode, Json<serde_json::Value>)> {
    let limit = params.limit.unwrap_or(50).min(100);
    let offset = params.offset.unwrap_or(0);

    // Build query
    let mut query = String::from(
        r#"
        SELECT * FROM compliance_violations
        WHERE 1=1
        "#,
    );

    let mut count_query = String::from(
        r#"
        SELECT COUNT(*) FROM compliance_violations
        WHERE 1=1
        "#,
    );

    if let Some(target_id) = params.target_id {
        query.push_str(&format!(" AND target_id = {}", target_id));
        count_query.push_str(&format!(" AND target_id = {}", target_id));
    }

    if let Some(ref status) = params.status {
        query.push_str(&format!(" AND status = '{}'", status));
        count_query.push_str(&format!(" AND status = '{}'", status));
    }

    if let Some(ref severity) = params.severity {
        query.push_str(&format!(" AND severity = '{}'", severity));
        count_query.push_str(&format!(" AND severity = '{}'", severity));
    }

    if let Some(ref category) = params.category {
        query.push_str(&format!(" AND category = '{}'", category));
        count_query.push_str(&format!(" AND category = '{}'", category));
    }

    query.push_str(&format!(
        " ORDER BY first_detected_at DESC LIMIT {} OFFSET {}",
        limit, offset
    ));

    let violations = sqlx::query_as::<_, ComplianceViolation>(&query)
        .fetch_all(&state.pg_pool)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
        })?;

    let total: i64 = sqlx::query_scalar(&count_query)
        .fetch_one(&state.pg_pool)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
        })?;

    // Get summary
    let summary = get_violations_summary(&state, params.target_id).await?;

    Ok(Json(ViolationListResponse {
        violations,
        total,
        summary,
    }))
}

/// Get a single violation by ID
async fn get_violation(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    _auth_user: AuthUser,
) -> Result<Json<ComplianceViolation>, (StatusCode, Json<serde_json::Value>)> {
    let violation = sqlx::query_as::<_, ComplianceViolation>(
        "SELECT * FROM compliance_violations WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.pg_pool)
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
            Json(json!({"error": "Violation not found"})),
        )
    })?;

    Ok(Json(violation))
}

/// Acknowledge a violation
async fn acknowledge_violation(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    auth_user: AuthUser,
    Json(payload): Json<AcknowledgeViolationRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    sqlx::query(
        r#"
        UPDATE compliance_violations
        SET status = 'acknowledged',
            acknowledged_by = $1,
            acknowledged_at = NOW(),
            resolution_notes = COALESCE($2, resolution_notes)
        WHERE id = $3
        "#,
    )
    .bind(auth_user.user_id)
    .bind(payload.notes)
    .bind(id)
    .execute(&state.pg_pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
    })?;

    Ok(Json(json!({
        "status": "success",
        "message": "Violation acknowledged"
    })))
}

/// Resolve a violation
async fn resolve_violation(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    auth_user: AuthUser,
    Json(payload): Json<ResolveViolationRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let status = payload
        .status
        .unwrap_or_else(|| "resolved".to_string());

    if !["resolved", "false_positive"].contains(&status.as_str()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid status. Must be 'resolved' or 'false_positive'"})),
        ));
    }

    sqlx::query(
        r#"
        UPDATE compliance_violations
        SET status = $1,
            resolved_by = $2,
            resolved_at = NOW(),
            resolution_notes = $3
        WHERE id = $4
        "#,
    )
    .bind(&status)
    .bind(auth_user.user_id)
    .bind(&payload.resolution_notes)
    .bind(id)
    .execute(&state.pg_pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
    })?;

    Ok(Json(json!({
        "status": "success",
        "message": format!("Violation marked as {}", status)
    })))
}

/// List compliance policies
async fn list_policies(
    State(state): State<AppState>,
    _auth_user: AuthUser,
) -> Result<Json<Vec<CompliancePolicy>>, (StatusCode, Json<serde_json::Value>)> {
    let policies = sqlx::query_as::<_, CompliancePolicy>(
        r#"
        SELECT * FROM compliance_policies
        WHERE is_active = TRUE
        ORDER BY category, severity DESC
        "#,
    )
    .fetch_all(&state.pg_pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
    })?;

    Ok(Json(policies))
}

/// Get a single policy
async fn get_policy(
    State(state): State<AppState>,
    Path(id): Path<i32>,
    _auth_user: AuthUser,
) -> Result<Json<CompliancePolicy>, (StatusCode, Json<serde_json::Value>)> {
    let policy = sqlx::query_as::<_, CompliancePolicy>(
        "SELECT * FROM compliance_policies WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.pg_pool)
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
            Json(json!({"error": "Policy not found"})),
        )
    })?;

    Ok(Json(policy))
}

/// Get compliance status for a target
async fn get_target_compliance_status(
    State(state): State<AppState>,
    Path(target_id): Path<i32>,
    _auth_user: AuthUser,
) -> Result<Json<ComplianceStatusResponse>, (StatusCode, Json<serde_json::Value>)> {
    // Get summary
    let summary = get_violations_summary(&state, Some(target_id)).await?;

    // Calculate status
    let status = if summary.critical > 0 {
        "critical"
    } else if summary.high > 0 {
        "non_compliant"
    } else if summary.medium > 0 {
        "warning"
    } else {
        "compliant"
    };

    // Calculate score
    let score = 100
        - ((summary.critical * 25).min(100)
            + (summary.high * 10).min(50)
            + (summary.medium * 5).min(30)
            + (summary.low * 1).min(10)) as i32;
    let score = score.max(0).min(100);

    // Get last check time
    let last_check = sqlx::query_scalar::<_, Option<chrono::DateTime<chrono::Utc>>>(
        "SELECT last_monitoring_at FROM targets WHERE id = $1",
    )
    .bind(target_id)
    .fetch_one(&state.pg_pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
    })?;

    Ok(Json(ComplianceStatusResponse {
        target_id,
        status: status.to_string(),
        score,
        violations: summary,
        last_check,
    }))
}

// ============================================================================
// Helper Functions
// ============================================================================

async fn get_violations_summary(
    state: &AppState,
    target_id: Option<i32>,
) -> Result<ViolationSummary, (StatusCode, Json<serde_json::Value>)> {
    let query = if let Some(tid) = target_id {
        format!(
            r#"
            SELECT
                COUNT(*) FILTER (WHERE severity = 'critical') as critical,
                COUNT(*) FILTER (WHERE severity = 'high') as high,
                COUNT(*) FILTER (WHERE severity = 'medium') as medium,
                COUNT(*) FILTER (WHERE severity = 'low') as low,
                COUNT(*) as total
            FROM compliance_violations
            WHERE target_id = {}
              AND status IN ('new', 'acknowledged', 'investigating')
            "#,
            tid
        )
    } else {
        r#"
            SELECT
                COUNT(*) FILTER (WHERE severity = 'critical') as critical,
                COUNT(*) FILTER (WHERE severity = 'high') as high,
                COUNT(*) FILTER (WHERE severity = 'medium') as medium,
                COUNT(*) FILTER (WHERE severity = 'low') as low,
                COUNT(*) as total
            FROM compliance_violations
            WHERE status IN ('new', 'acknowledged', 'investigating')
            "#
        .to_string()
    };

    let summary = sqlx::query_as::<_, (i64, i64, i64, i64, i64)>(&query)
        .fetch_one(&state.pg_pool)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
        })?;

    Ok(ViolationSummary {
        critical: summary.0,
        high: summary.1,
        medium: summary.2,
        low: summary.3,
        total: summary.4,
    })
}
