// ============================================================================
// Agent API - WebSocket endpoint for agent connections
// ============================================================================

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::Response,
    routing::get, Router,
};
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::services::compliance_scanner::ComplianceScanResponse;
use crate::services::hardening_executor::HardeningResponse;
use crate::AppState;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AgentMessage {
    msg_type: MessageType,
    target_id: i32,
    timestamp: i64,
    payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MessageType {
    Auth,
    Metrics,
    Heartbeat,
    Command,
    CommandResponse,
    /// Batch di eventi di sicurezza (auditd arricchiti da Laurel) inoltrati
    /// dall'agent, compressi come le metriche.
    SecurityEvents,
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/ws", get(agent_websocket_handler))
}

async fn agent_websocket_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> Response {
    ws.on_upgrade(|socket| handle_agent_socket(socket, state))
}

async fn handle_agent_socket(socket: WebSocket, state: AppState) {
    let (mut ws_sender, mut ws_receiver) = socket.split();

    info!("Agent WebSocket connected");

    // Wait for authentication
    let target_id = match authenticate_agent(&mut ws_receiver, &state.pg_pool).await {
        Ok(id) => {
            info!("Agent authenticated: target_id={}", id);
            // The agent waits for this AuthAck (30s timeout) before streaming
            // metrics. Without it the agent times out and reconnects forever.
            let ack = serde_json::json!({ "msg_type": "auth_ack", "success": true });
            if ws_sender.send(Message::Text(ack.to_string())).await.is_err() {
                error!("Failed to send AuthAck to agent (target_id={})", id);
                return;
            }
            id
        }
        Err(e) => {
            error!("Agent authentication failed: {}", e);
            let nack = serde_json::json!({
                "msg_type": "auth_ack",
                "success": false,
                "message": e.to_string(),
            });
            let _ = ws_sender.send(Message::Text(nack.to_string())).await;
            let _ = ws_sender.send(Message::Close(None)).await;
            return;
        }
    };

    // Update target status to online
    let _ = update_target_status(&state.pg_pool, target_id, "online", true).await;

    // Create channel for sending messages to agent
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

    // Register agent in registry
    state.agent_registry.register(target_id, tx).await;

    // Spawn task to forward messages from channel to WebSocket
    let mut send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if ws_sender.send(msg).await.is_err() {
                break;
            }
        }
    });

    // Handle incoming messages from agent
    let mut recv_task = tokio::spawn({
        let pg_pool = state.pg_pool.clone();
        let hardening_executor = state.hardening_executor.clone();
        let compliance_scanner = state.compliance_scanner.clone();
        let event_collector = state.event_collector.clone();
        async move {
            while let Some(msg) = ws_receiver.next().await {
                match msg {
                    Ok(Message::Text(text)) => {
                        if let Err(e) = handle_agent_message(&text, target_id, &pg_pool, &hardening_executor, &compliance_scanner, &event_collector).await {
                            error!("Error handling message: {}", e);
                        }
                    }
                    Ok(Message::Close(_)) => {
                        info!("Agent disconnected: target_id={}", target_id);
                        break;
                    }
                    Err(e) => {
                        error!("WebSocket error: {}", e);
                        break;
                    }
                    _ => {}
                }
            }
        }
    });

    // Wait for either task to finish
    tokio::select! {
        _ = (&mut send_task) => recv_task.abort(),
        _ = (&mut recv_task) => send_task.abort(),
    }

    // Unregister agent from registry
    state.agent_registry.unregister(target_id).await;

    // Update target status to offline
    let _ = update_target_status(&state.pg_pool, target_id, "offline", false).await;
}

async fn authenticate_agent(
    receiver: &mut futures_util::stream::SplitStream<WebSocket>,
    db: &PgPool,
) -> anyhow::Result<i32> {
    // Wait for auth message with timeout
    let timeout = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        receiver.next()
    ).await?;

    if let Some(Ok(Message::Text(text))) = timeout {
        let msg: AgentMessage = serde_json::from_str(&text)?;

        if !matches!(msg.msg_type, MessageType::Auth) {
            anyhow::bail!("Expected auth message");
        }

        let auth_token = msg.payload["auth_token"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing auth_token"))?;

        // Verify token and get target_id
        let target = sqlx::query!(
            r#"
            SELECT id, agent_auth_token
            FROM targets
            WHERE id = $1 AND agent_auth_token = $2
            "#,
            msg.target_id,
            auth_token
        )
        .fetch_one(db)
        .await?;

        Ok(target.id)
    } else {
        anyhow::bail!("No auth message received")
    }
}

async fn handle_agent_message(
    text: &str,
    target_id: i32,
    db: &PgPool,
    hardening_executor: &std::sync::Arc<crate::services::hardening_executor::HardeningExecutor>,
    compliance_scanner: &std::sync::Arc<crate::services::compliance_scanner::ComplianceScanner>,
    event_collector: &std::sync::Arc<crate::services::event_collector::EventCollectorService>,
) -> anyhow::Result<()> {
    let msg: AgentMessage = serde_json::from_str(text)?;

    match msg.msg_type {
        MessageType::Metrics => {
            process_metrics(msg.payload, target_id, db).await?;
        }
        MessageType::SecurityEvents => {
            process_security_events(msg.payload, target_id, event_collector).await?;
        }
        MessageType::Heartbeat => {
            // Update last_seen
            sqlx::query!(
                r#"
                UPDATE targets
                SET last_monitoring_at = NOW(), agent_last_seen = NOW()
                WHERE id = $1
                "#,
                target_id
            )
            .execute(db)
            .await?;
        }
        MessageType::CommandResponse => {
            // Try to parse as hardening response first
            if let Ok(response) = serde_json::from_value::<HardeningResponse>(msg.payload.clone()) {
                hardening_executor.handle_agent_response(response).await?;
            }
            // Try to parse as compliance scan response
            else if let Ok(response) = serde_json::from_value::<ComplianceScanResponse>(msg.payload) {
                compliance_scanner.handle_scan_response(response).await?;
            } else {
                error!("Failed to parse command response from agent {}", target_id);
            }
        }
        _ => {}
    }

    Ok(())
}

/// Ingest a batch of Laurel-enriched auditd events forwarded by the agent.
/// Il payload è compresso come le metriche (base64+zstd di un array JSON di
/// eventi). Ogni evento passa da `event_collector.ingest_event` → security_events
/// (con tagging MITRE).
async fn process_security_events(
    payload: serde_json::Value,
    target_id: i32,
    event_collector: &std::sync::Arc<crate::services::event_collector::EventCollectorService>,
) -> anyhow::Result<()> {
    #[derive(Deserialize)]
    struct CompressedPayload {
        data: String,
    }
    let compressed: CompressedPayload = serde_json::from_value(payload)?;
    let events = decode_metric_snapshots(&compressed.data)?;

    let mut ingested = 0usize;
    for ev in &events {
        match event_collector.ingest_event(ev).await {
            Ok(Some(_)) => ingested += 1,
            Ok(None) => {} // evento filtrato (rumore)
            Err(e) => error!("Failed to ingest security event (target {}): {}", target_id, e),
        }
    }

    info!(
        "Ingested {}/{} security events for target_id={}",
        ingested,
        events.len(),
        target_id
    );
    Ok(())
}

/// Decode a dog_agent metric payload — base64 → zstd → JSON — normalized to a
/// list of `AllMetrics` snapshots. The agent flushes a buffered batch, so the
/// decoded JSON is normally an array; a single object is accepted too.
fn decode_metric_snapshots(data: &str) -> anyhow::Result<Vec<serde_json::Value>> {
    let compressed_bytes = base64::engine::general_purpose::STANDARD
        .decode(data.as_bytes())
        .map_err(|e| anyhow::anyhow!("base64 decode of metrics payload failed: {}", e))?;
    let json_bytes = zstd::decode_all(compressed_bytes.as_slice())
        .map_err(|e| anyhow::anyhow!("zstd decode of metrics payload failed: {}", e))?;
    let decoded: serde_json::Value = serde_json::from_slice(&json_bytes)?;
    Ok(match decoded {
        serde_json::Value::Array(items) => items,
        other => vec![other],
    })
}

async fn process_metrics(
    payload: serde_json::Value,
    target_id: i32,
    db: &PgPool,
) -> anyhow::Result<()> {
    info!("Processing metrics for target_id={}", target_id);

    // Extract compressed payload
    #[derive(Deserialize)]
    struct CompressedPayload {
        original_size: usize,
        compressed_size: usize,
        compression_ratio: f64,
        data: String,
    }

    let compressed: CompressedPayload = serde_json::from_value(payload)?;

    info!(
        "Received compressed metrics: {} → {} bytes ({:.1}%)",
        compressed.original_size,
        compressed.compressed_size,
        compressed.compression_ratio
    );

    // Decompress base64(zstd(json)) → normalized list of AllMetrics snapshots
    // (the agent flushes a buffered batch = a JSON array).
    let snapshots = decode_metric_snapshots(&compressed.data)?;

    // Persist each snapshot losslessly (JSONB). Full field-by-field mapping to
    // typed InfluxDB measurements (system/network/users/files/services/auditd)
    // is a follow-up; the snapshot guarantees no agent data is lost meanwhile.
    for snap in &snapshots {
        let hostname = snap.get("hostname").and_then(|v| v.as_str());
        let collected_at = snap
            .get("collected_at")
            .and_then(|v| v.as_i64())
            .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0));

        sqlx::query!(
            r#"
            INSERT INTO agent_metric_snapshots (target_id, hostname, collected_at, metrics)
            VALUES ($1, $2, $3, $4)
            "#,
            target_id,
            hostname,
            collected_at,
            snap,
        )
        .execute(db)
        .await?;
    }

    info!(
        "Persisted {} agent metric snapshot(s) for target_id={}",
        snapshots.len(),
        target_id
    );

    // Update last monitoring time
    sqlx::query!(
        r#"
        UPDATE targets
        SET last_monitoring_at = NOW(), agent_last_seen = NOW()
        WHERE id = $1
        "#,
        target_id
    )
    .execute(db)
    .await?;

    Ok(())
}

async fn update_target_status(
    db: &PgPool,
    target_id: i32,
    status: &str,
    agent_connected: bool,
) -> anyhow::Result<()> {
    sqlx::query!(
        r#"
        UPDATE targets
        SET status = $1, agent_connected = $2, agent_last_seen = NOW()
        WHERE id = $3
        "#,
        status,
        agent_connected,
        target_id
    )
    .execute(db)
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirror of dog_agent's compression: json → zstd → base64.
    fn encode(value: &serde_json::Value) -> String {
        let json = serde_json::to_vec(value).unwrap();
        let compressed = zstd::encode_all(json.as_slice(), 3).unwrap();
        base64::engine::general_purpose::STANDARD.encode(compressed)
    }

    #[test]
    fn decodes_a_batch_array_of_snapshots() {
        let batch = serde_json::json!([
            {"hostname": "h1", "collected_at": 1000, "system": {"cpu": 10}},
            {"hostname": "h2", "collected_at": 1001, "network": {"conns": 3}}
        ]);
        let out = decode_metric_snapshots(&encode(&batch)).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0]["hostname"], "h1");
        assert_eq!(out[1]["network"]["conns"], 3);
    }

    #[test]
    fn normalizes_a_single_object_to_one_snapshot() {
        let one = serde_json::json!({"hostname": "solo", "collected_at": 42});
        let out = decode_metric_snapshots(&encode(&one)).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["hostname"], "solo");
    }

    #[test]
    fn rejects_invalid_base64() {
        assert!(decode_metric_snapshots("not-valid-base64-@@@").is_err());
    }
}
