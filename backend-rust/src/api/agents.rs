// ============================================================================
// Agent API - WebSocket endpoint for agent connections
// ============================================================================

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::Response,
    routing::get,
    Json, Router,
};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

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
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/ws", get(agent_websocket_handler))
}

async fn agent_websocket_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> Response {
    ws.on_upgrade(|socket| handle_agent_socket(socket, state))
}

async fn handle_agent_socket(socket: WebSocket, state: Arc<AppState>) {
    let (mut sender, mut receiver) = socket.split();

    info!("Agent WebSocket connected");

    // Wait for authentication
    let target_id = match authenticate_agent(&mut receiver, &state.db).await {
        Ok(id) => {
            info!("Agent authenticated: target_id={}", id);
            id
        }
        Err(e) => {
            error!("Agent authentication failed: {}", e);
            let _ = sender.send(Message::Close(None)).await;
            return;
        }
    };

    // Update target status to online
    let _ = update_target_status(&state.db, target_id, "online", true).await;

    // Handle messages
    while let Some(msg) = receiver.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                if let Err(e) = handle_agent_message(&text, target_id, &state.db).await {
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

    // Update target status to offline
    let _ = update_target_status(&state.db, target_id, "offline", false).await;
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
) -> anyhow::Result<()> {
    let msg: AgentMessage = serde_json::from_str(text)?;

    match msg.msg_type {
        MessageType::Metrics => {
            process_metrics(msg.payload, target_id, db).await?;
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
        _ => {}
    }

    Ok(())
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

    // Decompress (in real implementation, use proper zstd decompression)
    // For now, just acknowledge receipt

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

    // TODO: Parse metrics and write to InfluxDB
    // This would replace the SSH-based collection entirely

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
