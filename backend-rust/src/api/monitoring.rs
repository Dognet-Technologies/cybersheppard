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
use sqlx::Row;

use crate::models::MonitoringDataPayload;
use crate::services::compliance::ComplianceEngine;
use crate::AppState;

pub fn routes() -> Router<crate::AppState> {
    Router::new()
        .route("/data", post(receive_monitoring_data))
        .route("/metrics", get(get_metrics))
        .route("/events", get(get_events))
        .route("/logs", get(get_logs))
        .route("/sensors", get(get_sensors))
}

/// GET /api/monitoring/sensors — stato del sensore (auditd/Laurel) per target.
/// Derivato dalla telemetria: agente vivo (last_seen) + eventi che arrivano
/// (ultimo security_event). Sola lettura: nessun controllo remoto del servizio.
async fn get_sensors(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let rows = sqlx::query(
        r#"
        SELECT t.id, t.hostname, t.ip_address::text AS ip,
               GREATEST(t.last_seen, t.last_monitoring_at) AS agent_last_seen,
               (SELECT MAX(se.timestamp) FROM security_events se WHERE se.target_id = t.id) AS last_event_at,
               (SELECT COUNT(*) FROM security_events se
                  WHERE se.target_id = t.id AND se.timestamp > NOW() - INTERVAL '5 minutes') AS events_5m
        FROM targets t
        ORDER BY t.id
        "#,
    )
    .fetch_all(&state.pg_pool)
    .await
    .map_err(|e| {
        tracing::error!("get_sensors query error: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "Internal server error"})))
    })?;

    // Soglie (minuti): oltre queste, l'entità è considerata non sana.
    const AGENT_STALE_MIN: i64 = 5;
    const SENSOR_STALE_MIN: i64 = 10;
    let now = Utc::now();

    let sensors: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            let id: i32 = r.try_get("id").unwrap_or(0);
            let hostname: String = r.try_get("hostname").unwrap_or_default();
            let ip: Option<String> = r.try_get::<Option<String>, _>("ip").ok().flatten();
            let agent_seen: Option<chrono::DateTime<Utc>> =
                r.try_get::<Option<chrono::DateTime<Utc>>, _>("agent_last_seen").ok().flatten();
            let last_event: Option<chrono::DateTime<Utc>> =
                r.try_get::<Option<chrono::DateTime<Utc>>, _>("last_event_at").ok().flatten();
            let events_5m: i64 = r.try_get("events_5m").unwrap_or(0);

            let agent_min = agent_seen.map(|t| (now - t).num_minutes());
            let event_min = last_event.map(|t| (now - t).num_minutes());

            // Stato derivato: agente offline > sensore fermo > sano.
            let status = if agent_min.map(|m| m > AGENT_STALE_MIN).unwrap_or(true) {
                "agent_offline"
            } else if event_min.map(|m| m > SENSOR_STALE_MIN).unwrap_or(true) {
                "sensor_stale"
            } else {
                "healthy"
            };

            json!({
                "target_id": id,
                "hostname": hostname,
                "ip": ip,
                "agent_last_seen": agent_seen,
                "agent_minutes_ago": agent_min,
                "last_event_at": last_event,
                "event_minutes_ago": event_min,
                "events_5m": events_5m,
                "status": status,
            })
        })
        .collect();

    Ok(Json(json!({ "success": true, "data": sensors })))
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
