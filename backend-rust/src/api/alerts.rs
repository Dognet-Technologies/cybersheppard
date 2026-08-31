// ============================================================================
// CYBERSHEPPARD - Alerts API
// ============================================================================

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post, patch},
    Json, Router,
};
use serde::Deserialize;
use crate::AppState;
use crate::services::alerting::{AlertingService, CreateAlertRequest};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list_alerts))
        .route("/active", get(get_active_alerts))
        .route("/", post(create_alert))
        .route("/:id/acknowledge", patch(acknowledge_alert))
        .route("/:id/resolve", patch(resolve_alert))
        .route("/rules", get(list_alert_rules))
}

#[derive(Debug, Deserialize)]
struct ListAlertsQuery {
    status: Option<String>,
    severity: Option<String>,
    limit: Option<i32>,
}

async fn list_alerts(
    State(state): State<AppState>,
    Query(query): Query<ListAlertsQuery>,
) -> impl IntoResponse {
    let service = AlertingService::new(state.pg_pool.clone());

    match service.get_alerts(query.status, query.severity, query.limit).await {
        Ok(alerts) => (StatusCode::OK, Json(alerts)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("Failed to get alerts: {}", e)
            }))
        ).into_response(),
    }
}

async fn get_active_alerts(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let service = AlertingService::new(state.pg_pool.clone());

    match service.get_active_alerts().await {
        Ok(alerts) => (StatusCode::OK, Json(alerts)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("Failed to get active alerts: {}", e)
            }))
        ).into_response(),
    }
}

async fn create_alert(
    State(state): State<AppState>,
    Json(request): Json<CreateAlertRequest>,
) -> impl IntoResponse {
    let service = AlertingService::new(state.pg_pool.clone());

    match service.create_alert(request).await {
        Ok(alert_id) => (StatusCode::CREATED, Json(serde_json::json!({
            "id": alert_id,
            "success": true
        }))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("Failed to create alert: {}", e)
            }))
        ).into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct AcknowledgeRequest {
    acknowledged_by: String,
}

async fn acknowledge_alert(
    State(state): State<AppState>,
    Path(alert_id): Path<i32>,
    Json(payload): Json<AcknowledgeRequest>,
) -> impl IntoResponse {
    let service = AlertingService::new(state.pg_pool.clone());

    match service.acknowledge_alert(alert_id, &payload.acknowledged_by).await {
        Ok(_) => (StatusCode::OK, Json(serde_json::json!({
            "success": true,
            "message": "Alert acknowledged"
        }))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("Failed to acknowledge alert: {}", e)
            }))
        ).into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct ResolveRequest {
    resolved_by: String,
    resolution_notes: Option<String>,
}

async fn resolve_alert(
    State(state): State<AppState>,
    Path(alert_id): Path<i32>,
    Json(payload): Json<ResolveRequest>,
) -> impl IntoResponse {
    let service = AlertingService::new(state.pg_pool.clone());

    match service.resolve_alert(alert_id, &payload.resolved_by, payload.resolution_notes).await {
        Ok(_) => (StatusCode::OK, Json(serde_json::json!({
            "success": true,
            "message": "Alert resolved"
        }))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("Failed to resolve alert: {}", e)
            }))
        ).into_response(),
    }
}

async fn list_alert_rules(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let service = AlertingService::new(state.pg_pool.clone());

    match service.get_alert_rules().await {
        Ok(rules) => (StatusCode::OK, Json(rules)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("Failed to get alert rules: {}", e)
            }))
        ).into_response(),
    }
}
