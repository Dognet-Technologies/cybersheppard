// ============================================================================
// WebSocket Alert Broadcaster - Real-time Security Alerts
// ============================================================================

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::Response,
};
use futures::{sink::SinkExt, stream::StreamExt};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;

use crate::utils::BigDecimalExt;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Alert message sent via WebSocket
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AlertMessage {
    /// New correlation detected
    CorrelationDetected {
        correlation_id: Uuid,
        correlation_type: String,
        severity: String,
        risk_score: f64,
        pattern_name: String,
        description: String,
        involved_hosts: Vec<String>,
        involved_users: Vec<String>,
        timestamp: String,
    },
    /// High anomaly detected
    AnomalyDetected {
        host_name: String,
        user_name: Option<String>,
        anomaly_score: f64,
        description: String,
        z_score: f64,
        timestamp: String,
    },
    /// Lateral movement prediction
    LateralMovementPrediction {
        correlation_id: Uuid,
        current_host: String,
        predicted_targets: Vec<String>,
        highest_risk_target: String,
        risk_score: f64,
        timestamp: String,
    },
    /// Host risk level changed
    HostRiskChanged {
        host_name: String,
        old_risk_level: String,
        new_risk_level: String,
        risk_score: f64,
        timestamp: String,
    },
    /// System status update
    SystemStatus {
        active_correlations: usize,
        high_risk_hosts: usize,
        recent_events_per_minute: f64,
        timestamp: String,
    },
    /// Keep-alive ping
    Ping {
        timestamp: String,
    },
}

/// WebSocket alert broadcaster
pub struct AlertBroadcaster {
    /// Broadcast channel for alerts
    tx: broadcast::Sender<AlertMessage>,
}

impl AlertBroadcaster {
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self { tx }
    }

    /// Broadcast an alert to all connected clients
    pub fn broadcast(&self, alert: AlertMessage) {
        match self.tx.send(alert.clone()) {
            Ok(receivers) => {
                debug!("Broadcasted alert to {} receivers", receivers);
            }
            Err(_) => {
                debug!("No receivers connected for alert broadcast");
            }
        }
    }

    /// Get a receiver for this broadcaster
    pub fn subscribe(&self) -> broadcast::Receiver<AlertMessage> {
        self.tx.subscribe()
    }

    /// Get number of active subscribers
    pub fn subscriber_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

/// WebSocket handler
pub async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(broadcaster): State<Arc<AlertBroadcaster>>,
) -> Response {
    ws.on_upgrade(|socket| handle_socket(socket, broadcaster))
}

/// Handle individual WebSocket connection
async fn handle_socket(socket: WebSocket, broadcaster: Arc<AlertBroadcaster>) {
    let (mut sender, mut receiver) = socket.split();
    let mut rx = broadcaster.subscribe();

    info!("New WebSocket client connected");

    // Send initial welcome message
    let welcome = AlertMessage::SystemStatus {
        active_correlations: 0,
        high_risk_hosts: 0,
        recent_events_per_minute: 0.0,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    if let Ok(json) = serde_json::to_string(&welcome) {
        if sender.send(Message::Text(json)).await.is_err() {
            error!("Failed to send welcome message");
            return;
        }
    }

    // Spawn task to receive alerts and send to client
    let mut send_task = tokio::spawn(async move {
        while let Ok(alert) = rx.recv().await {
            match serde_json::to_string(&alert) {
                Ok(json) => {
                    if sender.send(Message::Text(json)).await.is_err() {
                        warn!("Failed to send alert to client, disconnecting");
                        break;
                    }
                }
                Err(e) => {
                    error!("Failed to serialize alert: {}", e);
                }
            }
        }
    });

    // Spawn task to handle incoming messages from client (keep-alive, etc.)
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            match msg {
                Message::Text(text) => {
                    debug!("Received message from client: {}", text);
                    // Handle client messages if needed
                }
                Message::Close(_) => {
                    info!("Client sent close message");
                    break;
                }
                Message::Ping(data) => {
                    debug!("Received ping from client");
                }
                Message::Pong(_) => {
                    debug!("Received pong from client");
                }
                _ => {}
            }
        }
    });

    // Wait for either task to finish
    tokio::select! {
        _ = (&mut send_task) => {
            recv_task.abort();
        }
        _ = (&mut recv_task) => {
            send_task.abort();
        }
    }

    info!("WebSocket client disconnected");
}

/// Alert monitor service - monitors database and broadcasts alerts
pub struct AlertMonitorService {
    db: PgPool,
    broadcaster: Arc<AlertBroadcaster>,
    poll_interval_seconds: u64,
}

impl AlertMonitorService {
    pub fn new(db: PgPool, broadcaster: Arc<AlertBroadcaster>) -> Self {
        Self {
            db,
            broadcaster,
            poll_interval_seconds: 5, // Poll every 5 seconds
        }
    }

    /// Start monitoring for alerts
    pub async fn start_monitoring(self: Arc<Self>) {
        info!("Starting alert monitoring service (polling every {}s)", self.poll_interval_seconds);

        let mut last_check = chrono::Utc::now();

        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(self.poll_interval_seconds)).await;

            let now = chrono::Utc::now();

            // Check for new correlations
            if let Err(e) = self.check_new_correlations(last_check).await {
                error!("Error checking new correlations: {}", e);
            }

            // Check for high anomalies
            if let Err(e) = self.check_high_anomalies(last_check).await {
                error!("Error checking anomalies: {}", e);
            }

            // Check for lateral movement predictions
            if let Err(e) = self.check_lateral_movement_predictions(last_check).await {
                error!("Error checking predictions: {}", e);
            }

            // Check for host risk changes
            if let Err(e) = self.check_host_risk_changes(last_check).await {
                error!("Error checking host risks: {}", e);
            }

            // Send periodic status update
            if let Err(e) = self.send_system_status().await {
                error!("Error sending system status: {}", e);
            }

            last_check = now;
        }
    }

    /// Check for new correlations
    async fn check_new_correlations(&self, since: chrono::DateTime<chrono::Utc>) -> Result<(), sqlx::Error> {
        let rows = sqlx::query!(
            r#"
            SELECT
                id,
                correlation_type,
                severity,
                risk_score,
                pattern_name,
                pattern_description,
                involved_hosts,
                involved_users,
                created_at
            FROM event_correlations
            WHERE created_at > $1
              AND status = 'active'
              AND (severity IN ('critical', 'high') OR risk_score > 60)
            ORDER BY created_at DESC
            "#,
            since
        )
        .fetch_all(&self.db)
        .await?;

        for row in rows {
            let alert = AlertMessage::CorrelationDetected {
                correlation_id: row.id,
                correlation_type: row.correlation_type,
                severity: row.severity,
                risk_score: row.risk_score.to_f64(),
                pattern_name: row.pattern_name.unwrap_or_else(|| "Unknown".to_string()),
                description: row.pattern_description.unwrap_or_else(|| "No description".to_string()),
                involved_hosts: row.involved_hosts.unwrap_or_default(),
                involved_users: row.involved_users.unwrap_or_default(),
                timestamp: row.created_at.to_rfc3339(),
            };

            info!(
                "Broadcasting new correlation: {} ({})",
                alert_type(&alert),
                risk_score(&alert)
            );
            self.broadcaster.broadcast(alert);
        }

        Ok(())
    }

    /// Check for high anomalies
    async fn check_high_anomalies(&self, since: chrono::DateTime<chrono::Utc>) -> Result<(), sqlx::Error> {
        let rows = sqlx::query!(
            r#"
            SELECT
                source_host,
                user_name,
                anomaly_score,
                event_type,
                timestamp
            FROM security_events
            WHERE timestamp > $1
              AND anomaly_score > 70
            ORDER BY anomaly_score DESC
            LIMIT 50
            "#,
            since
        )
        .fetch_all(&self.db)
        .await?;

        for row in rows {
            let alert = AlertMessage::AnomalyDetected {
                host_name: row.source_host,
                user_name: row.user_name,
                anomaly_score: row.anomaly_score.to_f64(),
                description: format!("High anomaly score for event type: {}", row.event_type),
                z_score: row.anomaly_score.to_f64() / 10.0, // Approximate
                timestamp: row.timestamp.to_rfc3339(),
            };

            self.broadcaster.broadcast(alert);
        }

        Ok(())
    }

    /// Check for lateral movement predictions
    async fn check_lateral_movement_predictions(&self, since: chrono::DateTime<chrono::Utc>) -> Result<(), sqlx::Error> {
        let rows = sqlx::query!(
            r#"
            SELECT
                correlation_id,
                current_compromised_host,
                predictions,
                model_confidence,
                created_at
            FROM lateral_movement_predictions
            WHERE created_at > $1
              AND status = 'active'
            ORDER BY model_confidence DESC
            LIMIT 20
            "#,
            since
        )
        .fetch_all(&self.db)
        .await?;

        for row in rows {
            // Parse predictions JSON
            if let Some(predictions) = row.predictions.as_array() {
                let mut predicted_targets = Vec::new();
                let mut highest_risk = 0.0;
                let mut highest_risk_target = String::new();

                for pred in predictions {
                    if let Some(target) = pred["target_host"].as_str() {
                        predicted_targets.push(target.to_string());

                        if let Some(risk) = pred["risk_score"].as_f64() {
                            if risk > highest_risk {
                                highest_risk = risk;
                                highest_risk_target = target.to_string();
                            }
                        }
                    }
                }

                if !predicted_targets.is_empty() {
                    let alert = AlertMessage::LateralMovementPrediction {
                        correlation_id: row.correlation_id.unwrap_or_else(Uuid::nil),
                        current_host: row.current_compromised_host,
                        predicted_targets,
                        highest_risk_target,
                        risk_score: highest_risk,
                        timestamp: row.created_at.to_rfc3339(),
                    };

                    info!("Broadcasting lateral movement prediction");
                    self.broadcaster.broadcast(alert);
                }
            }
        }

        Ok(())
    }

    /// Check for host risk changes
    async fn check_host_risk_changes(&self, since: chrono::DateTime<chrono::Utc>) -> Result<(), sqlx::Error> {
        let rows = sqlx::query!(
            r#"
            SELECT
                host_name,
                total_risk_score,
                risk_level,
                last_calculated
            FROM host_risk_scores
            WHERE last_calculated > $1
              AND total_risk_score > 60
            ORDER BY total_risk_score DESC
            LIMIT 20
            "#,
            since
        )
        .fetch_all(&self.db)
        .await?;

        for row in rows {
            let alert = AlertMessage::HostRiskChanged {
                host_name: row.host_name,
                old_risk_level: "unknown".to_string(), // Would need to track previous state
                new_risk_level: row.risk_level.unwrap_or_else(|| "unknown".to_string()),
                risk_score: row.total_risk_score.to_f64(),
                timestamp: row.last_calculated.to_rfc3339(),
            };

            self.broadcaster.broadcast(alert);
        }

        Ok(())
    }

    /// Send system status update
    async fn send_system_status(&self) -> Result<(), sqlx::Error> {
        let active_correlations = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*)::INT as count
            FROM event_correlations
            WHERE status = 'active'
            "#
        )
        .fetch_one(&self.db)
        .await?
        .unwrap_or(0);

        let high_risk_hosts = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*)::INT as count
            FROM host_risk_scores
            WHERE total_risk_score > 60
            "#
        )
        .fetch_one(&self.db)
        .await?
        .unwrap_or(0);

        let recent_events = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*)::BIGINT as count
            FROM security_events
            WHERE timestamp > NOW() - INTERVAL '1 minute'
            "#
        )
        .fetch_one(&self.db)
        .await?
        .unwrap_or(0);

        let alert = AlertMessage::SystemStatus {
            active_correlations: active_correlations as usize,
            high_risk_hosts: high_risk_hosts as usize,
            recent_events_per_minute: recent_events as f64,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        self.broadcaster.broadcast(alert);
        Ok(())
    }
}

// Helper functions
fn alert_type(alert: &AlertMessage) -> &str {
    match alert {
        AlertMessage::CorrelationDetected { .. } => "Correlation",
        AlertMessage::AnomalyDetected { .. } => "Anomaly",
        AlertMessage::LateralMovementPrediction { .. } => "Lateral Movement",
        AlertMessage::HostRiskChanged { .. } => "Host Risk",
        AlertMessage::SystemStatus { .. } => "System Status",
        AlertMessage::Ping { .. } => "Ping",
    }
}

fn risk_score(alert: &AlertMessage) -> f64 {
    match alert {
        AlertMessage::CorrelationDetected { risk_score, .. } => *risk_score,
        AlertMessage::AnomalyDetected { anomaly_score, .. } => *anomaly_score,
        AlertMessage::LateralMovementPrediction { risk_score, .. } => *risk_score,
        AlertMessage::HostRiskChanged { risk_score, .. } => *risk_score,
        _ => 0.0,
    }
}
