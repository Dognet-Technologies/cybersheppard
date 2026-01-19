// ============================================================================
// Auditd Events API
// ============================================================================

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;

use crate::AppState;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/events", get(get_events))
        .route("/events/:id", get(get_event_details))
        .route("/events/:id/status", post(update_event_status))
        .route("/stats", get(get_stats))
        .route("/realtime", get(get_realtime_events))
}

#[derive(Debug, Deserialize)]
pub struct EventsQuery {
    #[serde(default)]
    pub target_id: Option<i32>,

    #[serde(default)]
    pub severity: Option<String>,

    #[serde(default)]
    pub category: Option<String>,

    #[serde(default)]
    pub status: Option<String>,

    #[serde(default)]
    pub since: Option<String>, // ISO 8601 timestamp

    #[serde(default = "default_limit")]
    pub limit: i64,

    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    100
}

#[derive(Debug, Serialize)]
pub struct EventsResponse {
    pub events: Vec<AuditdEvent>,
    pub total: i64,
    pub has_more: bool,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct AuditdEvent {
    pub id: i64,
    pub target_id: i32,
    pub hostname: String,
    pub ip_address: String,
    pub collected_at: chrono::NaiveDateTime,
    pub severity: Option<String>,
    pub category: Option<String>,
    pub description: Option<String>,
    pub syscall: Option<String>,
    pub comm: Option<String>,
    pub command_full: Option<String>,
    pub parent_comm: Option<String>,
    pub container_name: Option<String>,
    pub status: String,
    pub correlated_with_firedog: bool,
    pub correlated_with_sentinel: bool,
    pub related_events_count: Option<i64>,
}

async fn get_events(
    State(state): State<Arc<AppState>>,
    Query(query): Query<EventsQuery>,
) -> Result<Json<EventsResponse>, Response> {
    // Build dynamic query
    let mut sql = String::from(
        "SELECT * FROM auditd_events_dashboard WHERE 1=1"
    );

    // Add filters
    if query.target_id.is_some() {
        sql.push_str(" AND target_id = $1");
    }
    if query.severity.is_some() {
        sql.push_str(" AND severity = $2");
    }
    if query.category.is_some() {
        sql.push_str(" AND category = $3");
    }
    if query.status.is_some() {
        sql.push_str(" AND status = $4");
    }
    if query.since.is_some() {
        sql.push_str(" AND collected_at >= $5");
    }

    sql.push_str(" ORDER BY collected_at DESC LIMIT $6 OFFSET $7");

    // Execute query (simplified - in production, use sqlx query builder)
    let events = sqlx::query_as::<_, AuditdEvent>(&sql)
        .fetch_all(&state.pg_pool)
        .await
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)).into_response()
        })?;

    // Get total count
    let total_sql = "SELECT COUNT(*) as count FROM auditd_events WHERE 1=1";
    let total: i64 = sqlx::query_scalar(total_sql)
        .fetch_one(&state.pg_pool)
        .await
        .unwrap_or(0);

    let has_more = (query.offset + query.limit) < total;

    Ok(Json(EventsResponse {
        events,
        total,
        has_more,
    }))
}

#[derive(Debug, Serialize)]
pub struct EventDetailsResponse {
    pub event: serde_json::Value,
    pub target: serde_json::Value,
    pub firedog_threats: serde_json::Value,
    pub sentinel_vulnerabilities: serde_json::Value,
    pub compliance_status: serde_json::Value,
    pub hardening_status: serde_json::Value,
}

async fn get_event_details(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<Json<EventDetailsResponse>, Response> {
    // Use the database function to get all details
    let result = sqlx::query!(
        r#"
        SELECT
            event,
            target,
            firedog_threats,
            sentinel_vulnerabilities,
            compliance_status,
            hardening_status
        FROM get_event_details($1)
        "#,
        id
    )
    .fetch_one(&state.pg_pool)
    .await
    .map_err(|e| {
        (StatusCode::NOT_FOUND, format!("Event not found: {}", e)).into_response()
    })?;

    Ok(Json(EventDetailsResponse {
        event: result.event.unwrap_or(serde_json::json!({})),
        target: result.target.unwrap_or(serde_json::json!({})),
        firedog_threats: result.firedog_threats.unwrap_or(serde_json::json!([])),
        sentinel_vulnerabilities: result.sentinel_vulnerabilities.unwrap_or(serde_json::json!([])),
        compliance_status: result.compliance_status.unwrap_or(serde_json::json!({})),
        hardening_status: result.hardening_status.unwrap_or(serde_json::json!({})),
    }))
}

#[derive(Debug, Deserialize)]
pub struct UpdateStatusRequest {
    pub status: String,
    pub resolution_notes: Option<String>,
}

async fn update_event_status(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Json(payload): Json<UpdateStatusRequest>,
) -> Result<StatusCode, Response> {
    sqlx::query!(
        r#"
        UPDATE auditd_events
        SET status = $1,
            resolution_notes = COALESCE($2, resolution_notes),
            resolved_at = CASE WHEN $1 = 'resolved' THEN NOW() ELSE resolved_at END
        WHERE id = $3
        "#,
        payload.status,
        payload.resolution_notes,
        id
    )
    .execute(&state.pg_pool)
    .await
    .map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Update failed: {}", e)).into_response()
    })?;

    Ok(StatusCode::OK)
}

#[derive(Debug, Serialize)]
pub struct StatsResponse {
    pub total_events: i64,
    pub by_severity: serde_json::Value,
    pub by_category: serde_json::Value,
    pub by_status: serde_json::Value,
    pub recent_critical: Vec<AuditdEvent>,
}

async fn get_stats(
    State(state): State<Arc<AppState>>,
) -> Result<Json<StatsResponse>, Response> {
    // Total events (last 24h)
    let total_events: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM auditd_events WHERE collected_at >= NOW() - INTERVAL '24 hours'"
    )
    .fetch_one(&state.pg_pool)
    .await
    .unwrap_or(0);

    // By severity
    let by_severity = sqlx::query!(
        r#"
        SELECT severity, COUNT(*) as count
        FROM auditd_events
        WHERE collected_at >= NOW() - INTERVAL '24 hours'
          AND severity IS NOT NULL
        GROUP BY severity
        "#
    )
    .fetch_all(&state.pg_pool)
    .await
    .map(|rows| {
        serde_json::json!(
            rows.iter()
                .map(|r| (r.severity.as_ref().unwrap(), r.count.unwrap()))
                .collect::<Vec<_>>()
        )
    })
    .unwrap_or(serde_json::json!([]));

    // By category
    let by_category = sqlx::query!(
        r#"
        SELECT category, COUNT(*) as count
        FROM auditd_events
        WHERE collected_at >= NOW() - INTERVAL '24 hours'
          AND category IS NOT NULL
        GROUP BY category
        ORDER BY count DESC
        LIMIT 10
        "#
    )
    .fetch_all(&state.pg_pool)
    .await
    .map(|rows| {
        serde_json::json!(
            rows.iter()
                .map(|r| (r.category.as_ref().unwrap(), r.count.unwrap()))
                .collect::<Vec<_>>()
        )
    })
    .unwrap_or(serde_json::json!([]));

    // By status
    let by_status = sqlx::query!(
        r#"
        SELECT status, COUNT(*) as count
        FROM auditd_events
        WHERE collected_at >= NOW() - INTERVAL '24 hours'
        GROUP BY status
        "#
    )
    .fetch_all(&state.pg_pool)
    .await
    .map(|rows| {
        serde_json::json!(
            rows.iter()
                .map(|r| (r.status.as_str(), r.count.unwrap()))
                .collect::<Vec<_>>()
        )
    })
    .unwrap_or(serde_json::json!([]));

    // Recent critical events
    let recent_critical = sqlx::query_as::<_, AuditdEvent>(
        "SELECT * FROM auditd_events_dashboard
         WHERE severity = 'critical'
         ORDER BY collected_at DESC
         LIMIT 10"
    )
    .fetch_all(&state.pg_pool)
    .await
    .unwrap_or_default();

    Ok(Json(StatsResponse {
        total_events,
        by_severity,
        by_category,
        by_status,
        recent_critical,
    }))
}

async fn get_realtime_events(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<AuditdEvent>>, Response> {
    // Get events from last 30 seconds for real-time updates
    let events = sqlx::query_as::<_, AuditdEvent>(
        "SELECT * FROM auditd_events_dashboard
         WHERE collected_at >= NOW() - INTERVAL '30 seconds'
         ORDER BY collected_at DESC
         LIMIT 50"
    )
    .fetch_all(&state.pg_pool)
    .await
    .map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)).into_response()
    })?;

    Ok(Json(events))
}
