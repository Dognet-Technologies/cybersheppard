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
use crate::AppState;

pub fn routes() -> Router<crate::AppState> {
    Router::new()
        .route("/data", post(receive_monitoring_data))
        .route("/metrics", get(get_metrics))
        .route("/events", get(get_events))
        .route("/logs", get(get_logs))
}

/// Receive monitoring data from target collectors
async fn receive_monitoring_data(
    State(state): State<AppState>,
    Json(payload): Json<MonitoringDataPayload>,
) -> Result<Json<serde_json::Value>, AppError> {
    tracing::info!(
        "📊 Received monitoring data from target: {}",
        payload.target_id
    );

    // Verify target exists and get target_id as integer
    let target_id_str = &payload.target_id;
    let target_id: i32 = target_id_str.parse().map_err(|_| {
        AppError::BadRequest("Invalid target_id format".to_string())
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
        AppError::InternalServerError
    })?;

    if !target_exists {
        return Err(AppError::NotFound(format!(
            "Target with id {} not found",
            target_id
        )));
    }

    // Store metrics in InfluxDB
    if let Err(e) = store_metrics_in_influx(&state, &payload).await {
        tracing::error!("Failed to store metrics in InfluxDB: {}", e);
        // Continue even if InfluxDB write fails
    }

    // Update target's last_monitoring_at timestamp
    sqlx::query(
        "UPDATE targets SET last_monitoring_at = $1, last_seen = $1 WHERE id = $2"
    )
    .bind(Utc::now())
    .bind(target_id)
    .execute(&state.pg_pool)
    .await
    .map_err(|e| {
        tracing::error!("Failed to update target timestamp: {}", e);
        AppError::InternalServerError
    })?;

    tracing::info!("✅ Monitoring data processed for target {}", target_id);

    Ok(Json(json!({
        "status": "success",
        "message": "Monitoring data received and processed",
        "target_id": target_id
    })))
}

/// Store metrics in InfluxDB
async fn store_metrics_in_influx(
    _state: &AppState,
    payload: &MonitoringDataPayload,
) -> Result<(), Box<dyn std::error::Error>> {
    // TODO: Implement proper InfluxDB writes
    // For now, log metrics - full InfluxDB integration will be completed during testing

    tracing::debug!(
        "Would write monitoring data to InfluxDB for target {}: system_metrics={}, auditd={}, network={}, processes={}",
        payload.target_id,
        payload.data.system_metrics.is_some(),
        payload.data.auditd.is_some(),
        payload.data.network.is_some(),
        payload.data.processes.is_some()
    );

    // Future implementation will:
    // 1. Create InfluxDB WriteQuery points for each metric category
    // 2. Use state.influx_client to write points to the metrics bucket
    // 3. Handle errors and retries appropriately

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
