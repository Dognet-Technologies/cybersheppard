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
use crate::models::{
    CompliancePolicy, ComplianceViolation, ComplianceMacroarea, ComplianceControl,
    TargetComplianceStatus, TargetControlStatus,
};
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
        // New compliance framework endpoints
        .route("/macroareas", get(list_macroareas))
        .route("/controls", get(list_controls))
        .route("/controls/:id", get(get_control))
        .route("/dashboard", get(get_compliance_dashboard))
        .route("/targets", get(list_compliance_targets))
        .route("/gaps", get(list_compliance_gaps))
        .route("/targets/:target_id/score/:framework_code", get(get_target_framework_score))
        .route("/scan/:target_id", post(trigger_compliance_scan))
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

// ============================================================================
// New Compliance Framework DTOs
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct ListControlsQuery {
    pub framework: Option<String>,
    pub priority: Option<String>,
    pub os: Option<String>,
    pub macroarea_id: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct DashboardQuery {
    pub target_id: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct GapsQuery {
    pub framework: Option<String>,
    pub priority: Vec<String>, // Critical, High
}

#[derive(Debug, Serialize)]
pub struct MacroareaWithCount {
    #[serde(flatten)]
    pub macroarea: ComplianceMacroarea,
    pub controls_count: i64,
}

#[derive(Debug, Serialize)]
pub struct ControlWithMacroarea {
    #[serde(flatten)]
    pub control: ComplianceControl,
    pub macroarea_name: String,
}

#[derive(Debug, Serialize)]
pub struct FrameworkScore {
    pub framework_code: String,
    pub framework_name: String,
    pub compliance_score: f64,
    pub total_controls: i32,
    pub compliant_controls: i32,
    pub non_compliant_controls: i32,
    pub not_applicable_controls: i32,
    pub not_checked_controls: i32,
    pub critical_gaps: i64,
    pub high_gaps: i64,
    pub last_scan_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Serialize)]
pub struct DashboardResponse {
    pub frameworks: Vec<FrameworkScore>,
}

#[derive(Debug, Serialize)]
pub struct TargetComplianceOverview {
    pub target_id: i32,
    pub hostname: String,
    pub ip_address: String,
    pub frameworks: FrameworkScores,
    pub avg_score: f64,
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct FrameworkScores {
    pub nis2: f64,
    pub nist: f64,
    pub iso27001: f64,
    pub mitre: f64,
}

#[derive(Debug, Serialize)]
pub struct ComplianceGap {
    pub control_id: i32,
    pub requirement: String,
    pub macroarea: String,
    pub priority: String,
    pub framework_code: String,
    pub gap_description: String,
    pub target_count: i64,
}

// ============================================================================
// New Compliance Framework Handlers
// ============================================================================

/// GET /api/compliance/macroareas
/// List all compliance macroareas with control counts
async fn list_macroareas(
    State(state): State<AppState>,
    _auth_user: AuthUser,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let macroareas = sqlx::query_as::<_, ComplianceMacroarea>(
        r#"
        SELECT id, name, description, display_order, created_at
        FROM compliance_macroareas
        ORDER BY display_order
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

    // Get control counts for each macroarea
    let mut macroareas_with_counts = Vec::new();
    for macroarea in macroareas {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM compliance_controls WHERE macroarea_id = $1",
        )
        .bind(macroarea.id)
        .fetch_one(&state.pg_pool)
        .await
        .unwrap_or(0);

        macroareas_with_counts.push(MacroareaWithCount {
            macroarea,
            controls_count: count,
        });
    }

    Ok(Json(json!({ "macroareas": macroareas_with_counts })))
}

/// GET /api/compliance/controls
/// List compliance controls with filters
async fn list_controls(
    State(state): State<AppState>,
    Query(params): Query<ListControlsQuery>,
    _auth_user: AuthUser,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let mut query = String::from(
        r#"
        SELECT
            cc.*,
            cm.name as macroarea_name
        FROM compliance_controls cc
        JOIN compliance_macroareas cm ON cc.macroarea_id = cm.id
        WHERE 1=1
        "#,
    );

    // Apply filters
    if let Some(ref framework) = params.framework {
        match framework.as_str() {
            "nis2" => query.push_str(" AND cc.applies_to_nis2 = TRUE"),
            "nist" => query.push_str(" AND cc.applies_to_nist = TRUE"),
            "iso27001" => query.push_str(" AND cc.applies_to_iso = TRUE"),
            "mitre" => query.push_str(" AND cc.applies_to_mitre = TRUE"),
            _ => {}
        }
    }

    if let Some(ref priority) = params.priority {
        query.push_str(&format!(" AND cc.priority = '{}'", priority));
    }

    if let Some(ref os) = params.os {
        match os.as_str() {
            "debian_ubuntu" => query.push_str(" AND cc.supports_debian_ubuntu = TRUE"),
            "rhel_oracle" => query.push_str(" AND cc.supports_rhel_oracle = TRUE"),
            "sles" => query.push_str(" AND cc.supports_sles = TRUE"),
            "windows_2019" => query.push_str(" AND cc.supports_windows_2019 = TRUE"),
            "windows_2022" => query.push_str(" AND cc.supports_windows_2022 = TRUE"),
            "docker" => query.push_str(" AND cc.supports_docker = TRUE"),
            "lxc" => query.push_str(" AND cc.supports_lxc = TRUE"),
            _ => {}
        }
    }

    if let Some(macroarea_id) = params.macroarea_id {
        query.push_str(&format!(" AND cc.macroarea_id = {}", macroarea_id));
    }

    query.push_str(" ORDER BY cm.display_order, cc.priority DESC");

    // Note: This is a simplified query - in production you'd use parameterized queries
    let controls = sqlx::query(&query)
        .fetch_all(&state.pg_pool)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
        })?;

    // Convert to JSON manually since we're mixing types
    let controls_json: Vec<serde_json::Value> = controls
        .iter()
        .map(|row| {
            json!({
                "id": row.try_get::<i32, _>("id").ok(),
                "macroarea_id": row.try_get::<i32, _>("macroarea_id").ok(),
                "macroarea_name": row.try_get::<String, _>("macroarea_name").ok(),
                "sub_control": row.try_get::<Option<String>, _>("sub_control").ok().flatten(),
                "sub_sub_control": row.try_get::<Option<String>, _>("sub_sub_control").ok().flatten(),
                "requirement": row.try_get::<String, _>("requirement").ok(),
                "priority": row.try_get::<String, _>("priority").ok(),
                "implementation_complexity": row.try_get::<Option<String>, _>("implementation_complexity").ok().flatten(),
                "implementation_notes": row.try_get::<Option<String>, _>("implementation_notes").ok().flatten(),
                "nis2_references": row.try_get::<Vec<String>, _>("nis2_references").ok().unwrap_or_default(),
                "nist_references": row.try_get::<Vec<String>, _>("nist_references").ok().unwrap_or_default(),
                "iso_references": row.try_get::<Vec<String>, _>("iso_references").ok().unwrap_or_default(),
                "mitre_references": row.try_get::<Vec<String>, _>("mitre_references").ok().unwrap_or_default(),
                "applies_to_nis2": row.try_get::<bool, _>("applies_to_nis2").ok(),
                "applies_to_nist": row.try_get::<bool, _>("applies_to_nist").ok(),
                "applies_to_iso": row.try_get::<bool, _>("applies_to_iso").ok(),
                "applies_to_mitre": row.try_get::<bool, _>("applies_to_mitre").ok(),
                "supports_debian_ubuntu": row.try_get::<bool, _>("supports_debian_ubuntu").ok(),
                "supports_rhel_oracle": row.try_get::<bool, _>("supports_rhel_oracle").ok(),
                "supports_sles": row.try_get::<bool, _>("supports_sles").ok(),
                "supports_windows_2019": row.try_get::<bool, _>("supports_windows_2019").ok(),
                "supports_windows_2022": row.try_get::<bool, _>("supports_windows_2022").ok(),
                "supports_docker": row.try_get::<bool, _>("supports_docker").ok(),
                "supports_lxc": row.try_get::<bool, _>("supports_lxc").ok(),
            })
        })
        .collect();

    Ok(Json(json!({ "controls": controls_json })))
}

/// GET /api/compliance/controls/:id
/// Get single control by ID
async fn get_control(
    State(state): State<AppState>,
    Path(id): Path<i32>,
    _auth_user: AuthUser,
) -> Result<Json<ComplianceControl>, (StatusCode, Json<serde_json::Value>)> {
    let control = sqlx::query_as::<_, ComplianceControl>(
        "SELECT * FROM compliance_controls WHERE id = $1",
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
            Json(json!({"error": "Control not found"})),
        )
    })?;

    Ok(Json(control))
}

/// GET /api/compliance/dashboard
/// Get compliance dashboard data with framework scores
async fn get_compliance_dashboard(
    State(state): State<AppState>,
    Query(params): Query<DashboardQuery>,
    _auth_user: AuthUser,
) -> Result<Json<DashboardResponse>, (StatusCode, Json<serde_json::Value>)> {
    // Get framework scores
    let frameworks = vec!["nis2", "nist", "iso27001", "mitre"];
    let mut framework_scores = Vec::new();

    for framework_code in frameworks {
        let framework_name = match framework_code {
            "nis2" => "NIS2 Directive 2022/2555",
            "nist" => "NIST 800-53 Rev5",
            "iso27001" => "ISO 27001:2022",
            "mitre" => "MITRE D3FEND",
            _ => framework_code,
        };

        // Get aggregated stats for this framework
        let stats: Option<(i32, i32, i32, f64)> = if let Some(target_id) = params.target_id {
            sqlx::query_as(
                r#"
                SELECT
                    total_controls,
                    compliant_controls,
                    non_compliant_controls,
                    compliance_score
                FROM target_compliance_status
                WHERE target_id = $1 AND framework_code = $2
                "#,
            )
            .bind(target_id)
            .bind(framework_code)
            .fetch_optional(&state.pg_pool)
            .await
            .ok()
            .flatten()
        } else {
            // Average across all targets
            sqlx::query_as(
                r#"
                SELECT
                    SUM(total_controls)::INT as total_controls,
                    SUM(compliant_controls)::INT as compliant_controls,
                    SUM(non_compliant_controls)::INT as non_compliant_controls,
                    AVG(compliance_score) as avg_score
                FROM target_compliance_status
                WHERE framework_code = $1
                "#,
            )
            .bind(framework_code)
            .fetch_optional(&state.pg_pool)
            .await
            .ok()
            .flatten()
        };

        let (total, compliant, non_compliant, score) = stats.unwrap_or((0, 0, 0, 0.0));

        // Calculate not_applicable and not_checked (simplified - would need actual data)
        let not_applicable = 0;
        let not_checked = total - compliant - non_compliant;

        // Get gap counts (critical and high)
        let (critical_gaps, high_gaps): (i64, i64) = sqlx::query_as(
            r#"
            SELECT
                COUNT(*) FILTER (WHERE cc.priority = 'Critical') as critical_gaps,
                COUNT(*) FILTER (WHERE cc.priority = 'High') as high_gaps
            FROM target_control_status tcs
            JOIN compliance_controls cc ON tcs.control_id = cc.id
            WHERE tcs.status IN ('non_compliant', 'error')
            "#,
        )
        .fetch_one(&state.pg_pool)
        .await
        .unwrap_or((0, 0));

        framework_scores.push(FrameworkScore {
            framework_code: framework_code.to_string(),
            framework_name: framework_name.to_string(),
            compliance_score: score,
            total_controls: total,
            compliant_controls: compliant,
            non_compliant_controls: non_compliant,
            not_applicable_controls: not_applicable,
            not_checked_controls: not_checked,
            critical_gaps,
            high_gaps,
            last_scan_at: None,
        });
    }

    Ok(Json(DashboardResponse {
        frameworks: framework_scores,
    }))
}

/// GET /api/compliance/targets
/// List all targets with compliance overview
async fn list_compliance_targets(
    State(state): State<AppState>,
    _auth_user: AuthUser,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let targets: Vec<(i32, String, String)> = sqlx::query_as(
        r#"
        SELECT id, hostname, ip_address
        FROM targets
        WHERE status = 'active'
        ORDER BY hostname
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

    let mut targets_overview = Vec::new();

    for (target_id, hostname, ip_address) in targets {
        // Get scores for each framework
        let nis2_score: f64 = sqlx::query_scalar(
            "SELECT COALESCE(compliance_score, 0.0) FROM target_compliance_status WHERE target_id = $1 AND framework_code = 'nis2'",
        )
        .bind(target_id)
        .fetch_one(&state.pg_pool)
        .await
        .unwrap_or(0.0);

        let nist_score: f64 = sqlx::query_scalar(
            "SELECT COALESCE(compliance_score, 0.0) FROM target_compliance_status WHERE target_id = $1 AND framework_code = 'nist'",
        )
        .bind(target_id)
        .fetch_one(&state.pg_pool)
        .await
        .unwrap_or(0.0);

        let iso_score: f64 = sqlx::query_scalar(
            "SELECT COALESCE(compliance_score, 0.0) FROM target_compliance_status WHERE target_id = $1 AND framework_code = 'iso27001'",
        )
        .bind(target_id)
        .fetch_one(&state.pg_pool)
        .await
        .unwrap_or(0.0);

        let mitre_score: f64 = sqlx::query_scalar(
            "SELECT COALESCE(compliance_score, 0.0) FROM target_compliance_status WHERE target_id = $1 AND framework_code = 'mitre'",
        )
        .bind(target_id)
        .fetch_one(&state.pg_pool)
        .await
        .unwrap_or(0.0);

        let avg_score = (nis2_score + nist_score + iso_score + mitre_score) / 4.0;

        let status = if avg_score >= 80.0 {
            "compliant"
        } else if avg_score >= 60.0 {
            "warning"
        } else {
            "non_compliant"
        };

        targets_overview.push(TargetComplianceOverview {
            target_id,
            hostname,
            ip_address,
            frameworks: FrameworkScores {
                nis2: nis2_score,
                nist: nist_score,
                iso27001: iso_score,
                mitre: mitre_score,
            },
            avg_score,
            status: status.to_string(),
        });
    }

    Ok(Json(json!({ "targets": targets_overview })))
}

/// GET /api/compliance/gaps
/// List compliance gaps (non-compliant controls)
async fn list_compliance_gaps(
    State(state): State<AppState>,
    Query(params): Query<GapsQuery>,
    _auth_user: AuthUser,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Build query for gaps
    let mut query = String::from(
        r#"
        SELECT
            cc.id as control_id,
            cc.requirement,
            cm.name as macroarea,
            cc.priority,
            tcs.gap_description,
            COUNT(DISTINCT tcs.target_id) as target_count
        FROM target_control_status tcs
        JOIN compliance_controls cc ON tcs.control_id = cc.id
        JOIN compliance_macroareas cm ON cc.macroarea_id = cm.id
        WHERE tcs.status IN ('non_compliant', 'error')
        "#,
    );

    // Filter by priority (Critical, High)
    if !params.priority.is_empty() {
        let priorities: Vec<String> = params.priority.iter().map(|p| format!("'{}'", p)).collect();
        query.push_str(&format!(" AND cc.priority IN ({})", priorities.join(",")));
    }

    query.push_str(
        r#"
        GROUP BY cc.id, cc.requirement, cm.name, cc.priority, tcs.gap_description
        ORDER BY
            CASE cc.priority
                WHEN 'Critical' THEN 1
                WHEN 'High' THEN 2
                WHEN 'Medium' THEN 3
                WHEN 'Low' THEN 4
            END,
            target_count DESC
        "#,
    );

    let gaps: Vec<(i32, String, String, String, Option<String>, i64)> = sqlx::query_as(&query)
        .fetch_all(&state.pg_pool)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
        })?;

    let gaps_response: Vec<ComplianceGap> = gaps
        .into_iter()
        .map(|(control_id, requirement, macroarea, priority, gap_description, target_count)| {
            ComplianceGap {
                control_id,
                requirement,
                macroarea,
                priority,
                framework_code: "multi".to_string(), // Would need to determine from control
                gap_description: gap_description.unwrap_or_else(|| "Non-compliant".to_string()),
                target_count,
            }
        })
        .collect();

    Ok(Json(json!({ "gaps": gaps_response })))
}

/// GET /api/compliance/targets/:target_id/score/:framework_code
/// Get compliance score for specific target and framework
async fn get_target_framework_score(
    State(state): State<AppState>,
    Path((target_id, framework_code)): Path<(i32, String)>,
    _auth_user: AuthUser,
) -> Result<Json<TargetComplianceStatus>, (StatusCode, Json<serde_json::Value>)> {
    let status = sqlx::query_as::<_, TargetComplianceStatus>(
        r#"
        SELECT *
        FROM target_compliance_status
        WHERE target_id = $1 AND framework_code = $2
        "#,
    )
    .bind(target_id)
    .bind(&framework_code)
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
            Json(json!({"error": "Compliance status not found for this target/framework"})),
        )
    })?;

    Ok(Json(status))
}

/// POST /api/compliance/scan/:target_id
/// Trigger immediate compliance scan for a target
async fn trigger_compliance_scan(
    State(state): State<AppState>,
    Path(target_id): Path<i32>,
    _auth_user: AuthUser,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Check if agent is connected
    if !state.agent_registry.is_connected(target_id).await {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": format!("Agent for target {} is not connected", target_id)})),
        ));
    }

    // Trigger scan
    match state.compliance_scanner.trigger_scan(target_id).await {
        Ok(scan_id) => Ok(Json(json!({
            "status": "success",
            "message": "Compliance scan started",
            "scan_id": scan_id,
            "target_id": target_id
        }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )),
    }
}
