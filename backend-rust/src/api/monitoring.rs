// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - Monitoring API
// ============================================================================

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use serde_json::json;

use crate::models::MonitoringDataPayload;
use crate::services::compliance::ComplianceEngine;
use crate::AppState;

pub fn routes() -> Router<crate::AppState> {
    Router::new()
        .route("/data", post(receive_monitoring_data))
        .route("/metrics", get(get_metrics))
        .route("/events", get(get_events))
        .route("/logs", get(get_logs))
}

/// Receive monitoring data from target collectors
#[axum::debug_handler]
async fn receive_monitoring_data(
    State(state): State<AppState>,
    Json(payload): Json<MonitoringDataPayload>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    tracing::info!("📊 Received monitoring data from target: {}", payload.target_id);

    // Verify target exists and get target_id as integer
    let target_id: i32 = payload.target_id.parse().map_err(|_| {
        (StatusCode::BAD_REQUEST, Json(json!({"error": "Invalid target_id format"})))
    })?;

    // Check if target exists
    let target_exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM targets WHERE id = $1)"
    )
    .bind(target_id)
    .fetch_one(&state.pg_pool)
    .await
    .map_err(|e| {
        tracing::error!("Database error checking target: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "Internal server error"})))
    })?;

    if !target_exists {
        return Err((StatusCode::NOT_FOUND, Json(json!({"error": format!("Target {} not found", target_id)}))));
    }

    // Store metrics in InfluxDB (best effort - continue if fails)
    if let Err(e) = store_metrics_in_influx(&state, &payload).await {
        tracing::warn!("Failed to store metrics in InfluxDB: {} (continuing)", e);
    }

    // Evaluate behavioral compliance
    let compliance_engine = ComplianceEngine::new(state.pg_pool.clone());
    let mut violations_count = 0;
    let mut compliance_status = String::from("compliant");

    match compliance_engine.evaluate_compliance(target_id, &payload).await {
        Ok(violations) => {
            violations_count = violations.len();
            if !violations.is_empty() {
                tracing::warn!("🚨 {} compliance violation(s) detected for target {}", violations_count, target_id);

                // Record violations in database
                if let Err(e) = compliance_engine.record_violations(target_id, violations).await {
                    tracing::error!("Failed to record violations: {}", e);
                }

                // Get updated compliance status
                if let Ok((status, _score)) = compliance_engine.get_compliance_status(target_id).await {
                    compliance_status = status;
                }
            }
        }
        Err(e) => {
            tracing::error!("Failed to evaluate compliance: {}", e);
        }
    }

    // Update target's last_monitoring_at timestamp
    let _ = sqlx::query("UPDATE targets SET last_monitoring_at = $1, last_seen = $1 WHERE id = $2")
        .bind(Utc::now())
        .bind(target_id)
        .execute(&state.pg_pool)
        .await;

    tracing::info!("✅ Monitoring data processed for target {} (violations: {}, status: {})",
                   target_id, violations_count, compliance_status);

    Ok(Json(json!({
        "status": "success",
        "message": "Monitoring data received and processed",
        "target_id": target_id,
        "compliance": {
            "violations_detected": violations_count,
            "status": compliance_status
        }
    })))
}

/// Store metrics in InfluxDB (STUB - To be implemented with actual InfluxDB client)
async fn store_metrics_in_influx(
    _state: &AppState,
    _payload: &MonitoringDataPayload,
) -> anyhow::Result<()> {
    // TODO: Implement actual InfluxDB write operations
    // For now, this is a stub to allow the system to function
    // Real implementation requires proper InfluxDB 2.x client setup
    Ok(())
}

async fn get_metrics() -> &'static str {
    "TODO: implement get_metrics"
}

async fn get_events() -> &'static str {
    "TODO: implement get_events"
}

async fn get_logs() -> &'static str {
    "TODO: implement get_logs"
}

// ============================================================================
// Error Handling
// ============================================================================

#[derive(Debug)]
enum AppError {
    BadRequest(String),
    NotFound(String),
    InternalServerError,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            AppError::InternalServerError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            ),
        };

        let body = Json(json!({
            "error": message,
        }));

        (status, body).into_response()
    }
}
