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

    // ✨ COMPLIANCE CHECK: Evaluate behavioral compliance
    let compliance_engine = ComplianceEngine::new(state.pg_pool.clone());
    let mut violations_count = 0;
    let mut compliance_status = String::from("compliant");

    match compliance_engine.evaluate_compliance(target_id, &payload).await {
        Ok(violations) => {
            violations_count = violations.len();

            if !violations.is_empty() {
                tracing::warn!(
                    "🚨 {} compliance violation(s) detected for target {}",
                    violations_count,
                    target_id
                );

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
            // Continue processing even if compliance check fails
        }
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

    tracing::info!(
        "✅ Monitoring data processed for target {} (violations: {}, status: {})",
        target_id,
        violations_count,
        compliance_status
    );

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

/// Store metrics in InfluxDB
async fn store_metrics_in_influx(
    state: &AppState,
    payload: &MonitoringDataPayload,
) -> Result<(), Box<dyn std::error::Error>> {
    use influxdb::{InfluxDbWriteable, Timestamp, WriteQuery};
    use chrono::Utc;

    let timestamp = Timestamp::from(payload.timestamp);
    let bucket = &state.influx_client.bucket_metrics;
    let target_id = &payload.target_id;

    // Write system metrics
    if let Some(ref metrics) = payload.data.system_metrics {
        if let Some(cpu_usage) = metrics.cpu_usage {
            let query = WriteQuery::new(timestamp, "system_cpu")
                .add_tag("target_id", target_id.clone())
                .add_field("usage", cpu_usage);
            state.influx_client.client.query(&query.into_query(bucket)).await?;
        }

        if let Some(memory_usage) = metrics.memory_usage {
            let query = WriteQuery::new(timestamp, "system_memory")
                .add_tag("target_id", target_id.clone())
                .add_field("usage", memory_usage);
            state.influx_client.client.query(&query.into_query(bucket)).await?;
        }

        if let Some(disk_usage) = metrics.disk_usage {
            let query = WriteQuery::new(timestamp, "system_disk")
                .add_tag("target_id", target_id.clone())
                .add_field("usage", disk_usage);
            state.influx_client.client.query(&query.into_query(bucket)).await?;
        }
    }

    // Write auditd metrics
    if let Some(ref metrics) = payload.data.auditd {
        if let Some(events) = metrics.events_last_hour {
            let query = WriteQuery::new(timestamp, "auditd_events")
                .add_tag("target_id", target_id.clone())
                .add_field("count", events);
            state.influx_client.client.query(&query.into_query(bucket)).await?;
        }

        if let Some(failed_logins) = metrics.failed_logins {
            let query = WriteQuery::new(timestamp, "auditd_failed_logins")
                .add_tag("target_id", target_id.clone())
                .add_field("count", failed_logins);
            state.influx_client.client.query(&query.into_query(bucket)).await?;
        }

        if let Some(privilege_esc) = metrics.privilege_escalations {
            let query = WriteQuery::new(timestamp, "auditd_privilege_escalations")
                .add_tag("target_id", target_id.clone())
                .add_field("count", privilege_esc);
            state.influx_client.client.query(&query.into_query(bucket)).await?;
        }

        if let Some(config_changes) = metrics.config_changes {
            let query = WriteQuery::new(timestamp, "auditd_config_changes")
                .add_tag("target_id", target_id.clone())
                .add_field("count", config_changes);
            state.influx_client.client.query(&query.into_query(bucket)).await?;
        }
    }

    // Write network metrics
    if let Some(ref metrics) = payload.data.network {
        if let Some(active_conns) = metrics.active_connections {
            let query = WriteQuery::new(timestamp, "network_connections")
                .add_tag("target_id", target_id.clone())
                .add_field("active", active_conns);
            state.influx_client.client.query(&query.into_query(bucket)).await?;
        }

        if let Some(failed_ssh) = metrics.failed_ssh_attempts {
            let query = WriteQuery::new(timestamp, "network_failed_ssh")
                .add_tag("target_id", target_id.clone())
                .add_field("attempts", failed_ssh);
            state.influx_client.client.query(&query.into_query(bucket)).await?;
        }
    }

    // Write process metrics
    if let Some(ref metrics) = payload.data.processes {
        if let Some(total) = metrics.total_processes {
            let query = WriteQuery::new(timestamp, "processes_total")
                .add_tag("target_id", target_id.clone())
                .add_field("count", total);
            state.influx_client.client.query(&query.into_query(bucket)).await?;
        }

        if let Some(zombie) = metrics.zombie_processes {
            let query = WriteQuery::new(timestamp, "processes_zombie")
                .add_tag("target_id", target_id.clone())
                .add_field("count", zombie);
            state.influx_client.client.query(&query.into_query(bucket)).await?;
        }
    }

    tracing::debug!("Metrics written to InfluxDB for target {}", target_id);
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
