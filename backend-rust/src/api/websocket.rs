// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - WebSocket Streaming API
// ============================================================================
// Real-time streaming of logs, metrics, and monitoring data

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, State,
    },
    response::IntoResponse,
    routing::get,
    Router,
};
use futures::{SinkExt, StreamExt};
use serde_json::json;
use tokio::time::{interval, Duration};
use tracing::info;

use crate::AppState;

pub fn routes() -> Router<crate::AppState> {
    Router::new()
        .route("/logs", get(ws_logs_handler))
        .route("/monitoring/:target_id", get(ws_monitoring_handler))
        .route("/violations", get(ws_violations_handler))
        .route("/system", get(ws_system_handler))
}

/// WebSocket handler for real-time logs streaming
async fn ws_logs_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    info!("📡 New WebSocket connection: logs stream");
    ws.on_upgrade(move |socket| handle_logs_stream(socket, state))
}

/// WebSocket handler for target-specific monitoring data
async fn ws_monitoring_handler(
    ws: WebSocketUpgrade,
    Path(target_id): Path<i32>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    info!("📡 New WebSocket connection: monitoring stream for target {}", target_id);
    ws.on_upgrade(move |socket| handle_monitoring_stream(socket, state, target_id))
}

/// WebSocket handler for real-time violations
async fn ws_violations_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    info!("📡 New WebSocket connection: violations stream");
    ws.on_upgrade(move |socket| handle_violations_stream(socket, state))
}

/// WebSocket handler for system-wide events
async fn ws_system_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    info!("📡 New WebSocket connection: system stream");
    ws.on_upgrade(move |socket| handle_system_stream(socket, state))
}

// ============================================================================
// Stream Handlers
// ============================================================================

/// Handle logs streaming
async fn handle_logs_stream(socket: WebSocket, state: AppState) {
    let (mut sender, mut receiver) = socket.split();

    let welcome = json!({
        "type": "connected",
        "stream": "logs",
        "timestamp": chrono::Utc::now().to_rfc3339()
    });

    if sender.send(Message::Text(welcome.to_string())).await.is_err() {
        return;
    }

    let mut heartbeat = interval(Duration::from_secs(30));

    loop {
        tokio::select! {
            msg = receiver.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        if text == "ping" {
                            let _ = sender.send(Message::Text("pong".to_string())).await;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        info!("WebSocket connection closed: logs stream");
                        break;
                    }
                    _ => {}
                }
            }

            _ = heartbeat.tick() => {
                let heartbeat_msg = json!({
                    "type": "heartbeat",
                    "timestamp": chrono::Utc::now().to_rfc3339()
                });

                if sender.send(Message::Text(heartbeat_msg.to_string())).await.is_err() {
                    break;
                }
            }

            _ = tokio::time::sleep(Duration::from_secs(5)) => {
                if let Ok(logs) = fetch_recent_logs(&state).await {
                    for log in logs {
                        let msg = Message::Text(serde_json::to_string(&log).unwrap());
                        if sender.send(msg).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
    }
}

/// Handle monitoring data streaming for specific target
async fn handle_monitoring_stream(socket: WebSocket, state: AppState, target_id: i32) {
    let (mut sender, mut receiver) = socket.split();

    let target_exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM targets WHERE id = $1)"
    )
    .bind(target_id)
    .fetch_one(&state.pg_pool)
    .await
    .unwrap_or(false);

    if !target_exists {
        let error = json!({
            "type": "error",
            "message": format!("Target {} not found", target_id)
        });
        let _ = sender.send(Message::Text(error.to_string())).await;
        return;
    }

    let welcome = json!({
        "type": "connected",
        "stream": "monitoring",
        "target_id": target_id,
        "timestamp": chrono::Utc::now().to_rfc3339()
    });

    if sender.send(Message::Text(welcome.to_string())).await.is_err() {
        return;
    }

    let mut heartbeat = interval(Duration::from_secs(30));
    let mut data_interval = interval(Duration::from_secs(10));

    loop {
        tokio::select! {
            msg = receiver.next() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => {
                        info!("WebSocket closed: monitoring stream for target {}", target_id);
                        break;
                    }
                    _ => {}
                }
            }

            _ = heartbeat.tick() => {
                let heartbeat_msg = json!({
                    "type": "heartbeat",
                    "timestamp": chrono::Utc::now().to_rfc3339()
                });

                if sender.send(Message::Text(heartbeat_msg.to_string())).await.is_err() {
                    break;
                }
            }

            _ = data_interval.tick() => {
                if let Ok(metrics) = fetch_target_metrics(&state, target_id).await {
                    let msg = json!({
                        "type": "monitoring",
                        "target_id": target_id,
                        "timestamp": chrono::Utc::now().to_rfc3339(),
                        "data": metrics
                    });

                    if sender.send(Message::Text(msg.to_string())).await.is_err() {
                        break;
                    }
                }
            }
        }
    }
}

/// Handle violations streaming
async fn handle_violations_stream(socket: WebSocket, state: AppState) {
    let (mut sender, mut receiver) = socket.split();

    let welcome = json!({
        "type": "connected",
        "stream": "violations",
        "timestamp": chrono::Utc::now().to_rfc3339()
    });

    if sender.send(Message::Text(welcome.to_string())).await.is_err() {
        return;
    }

    let mut heartbeat = interval(Duration::from_secs(30));
    let mut check_interval = interval(Duration::from_secs(5));

    loop {
        tokio::select! {
            msg = receiver.next() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => {
                        info!("WebSocket closed: violations stream");
                        break;
                    }
                    _ => {}
                }
            }

            _ = heartbeat.tick() => {
                let heartbeat_msg = json!({
                    "type": "heartbeat",
                    "timestamp": chrono::Utc::now().to_rfc3339()
                });

                if sender.send(Message::Text(heartbeat_msg.to_string())).await.is_err() {
                    break;
                }
            }

            _ = check_interval.tick() => {
                if let Ok(violations) = fetch_new_violations(&state).await {
                    for violation in violations {
                        let msg = Message::Text(serde_json::to_string(&violation).unwrap());
                        if sender.send(msg).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
    }
}

/// Handle system-wide events streaming
async fn handle_system_stream(socket: WebSocket, state: AppState) {
    let (mut sender, mut receiver) = socket.split();

    let welcome = json!({
        "type": "connected",
        "stream": "system",
        "timestamp": chrono::Utc::now().to_rfc3339()
    });

    if sender.send(Message::Text(welcome.to_string())).await.is_err() {
        return;
    }

    let mut heartbeat = interval(Duration::from_secs(30));
    let mut stats_interval = interval(Duration::from_secs(15));

    loop {
        tokio::select! {
            msg = receiver.next() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => {
                        info!("WebSocket closed: system stream");
                        break;
                    }
                    _ => {}
                }
            }

            _ = heartbeat.tick() => {
                let heartbeat_msg = json!({
                    "type": "heartbeat",
                    "timestamp": chrono::Utc::now().to_rfc3339()
                });

                if sender.send(Message::Text(heartbeat_msg.to_string())).await.is_err() {
                    break;
                }
            }

            _ = stats_interval.tick() => {
                if let Ok(stats) = fetch_system_stats(&state).await {
                    let msg = json!({
                        "type": "system_stats",
                        "timestamp": chrono::Utc::now().to_rfc3339(),
                        "data": stats
                    });

                    if sender.send(Message::Text(msg.to_string())).await.is_err() {
                        break;
                    }
                }
            }
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

async fn fetch_recent_logs(state: &AppState) -> Result<Vec<serde_json::Value>, sqlx::Error> {
    let logs = sqlx::query!(
        r#"
        SELECT id, user_id, action, resource, ip_address, created_at
        FROM audit_logs
        WHERE created_at > NOW() - INTERVAL '5 seconds'
        ORDER BY created_at DESC
        LIMIT 10
        "#
    )
    .fetch_all(&state.pg_pool)
    .await?;

    Ok(logs.into_iter().map(|log| {
        json!({
            "type": "log",
            "level": "info",
            "action": log.action,
            "resource": log.resource,
            "user_id": log.user_id,
            "ip": log.ip_address,
            "timestamp": log.created_at.to_rfc3339()
        })
    }).collect())
}

async fn fetch_target_metrics(state: &AppState, _target_id: i32) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    // TODO: Query InfluxDB for latest metrics
    Ok(json!({
        "cpu_usage": 45.5,
        "memory_usage": 60.2,
        "disk_usage": 70.0,
        "network_rx": 1024000,
        "network_tx": 512000
    }))
}

async fn fetch_new_violations(state: &AppState) -> Result<Vec<serde_json::Value>, sqlx::Error> {
    let violations = sqlx::query!(
        r#"
        SELECT id, target_id, metric_name, severity, detected_value, first_detected_at
        FROM compliance_violations
        WHERE first_detected_at > NOW() - INTERVAL '5 seconds'
        AND status = 'new'
        ORDER BY first_detected_at DESC
        LIMIT 10
        "#
    )
    .fetch_all(&state.pg_pool)
    .await?;

    Ok(violations.into_iter().map(|v| {
        json!({
            "type": "violation",
            "violation_id": v.id,
            "target_id": v.target_id,
            "metric_name": v.metric_name,
            "severity": v.severity,
            "detected_value": v.detected_value,
            "timestamp": v.first_detected_at.to_rfc3339()
        })
    }).collect())
}

async fn fetch_system_stats(state: &AppState) -> Result<serde_json::Value, sqlx::Error> {
    let targets_count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM targets")
        .fetch_one(&state.pg_pool)
        .await?;

    let violations_count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM compliance_violations WHERE status = 'new'"
    )
    .fetch_one(&state.pg_pool)
    .await?;

    let online_targets = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM targets WHERE status = 'online'"
    )
    .fetch_one(&state.pg_pool)
    .await?;

    Ok(json!({
        "total_targets": targets_count,
        "online_targets": online_targets,
        "active_violations": violations_count,
        "compliance_score": 85
    }))
}
