// ============================================================================
// Connection Module - WebSocket connection to backend
// ============================================================================

use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message, MaybeTlsStream, WebSocketStream};
use tracing::{error, info, warn};

use crate::collectors::AllMetrics;
use crate::compression::compress_json;
use crate::config::AgentConfig;

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMessage {
    pub msg_type: MessageType,
    pub target_id: i32,
    pub timestamp: i64,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageType {
    Auth,
    Metrics,
    Heartbeat,
    Command,
}

pub struct AgentConnection {
    pub config: AgentConfig,
    ws: Option<WsStream>,
    buffer: Vec<AllMetrics>,
    backoff: Duration,
}

impl AgentConnection {
    pub fn new(config: AgentConfig) -> Self {
        Self {
            config,
            ws: None,
            buffer: Vec::new(),
            backoff: Duration::from_secs(config.reconnect.initial_backoff),
        }
    }

    pub async fn connect(&mut self) -> Result<()> {
        info!("Connecting to backend: {}", self.config.backend_url);

        // Convert http(s) URL to ws(s)
        let ws_url = self.config.backend_url.replace("http://", "ws://").replace("https://", "wss://");
        let ws_url = format!("{}/api/agents/ws", ws_url);

        match connect_async(&ws_url).await {
            Ok((ws_stream, _response)) => {
                info!("WebSocket connected");
                self.ws = Some(ws_stream);
                self.backoff = Duration::from_secs(self.config.reconnect.initial_backoff);

                // Send authentication message
                self.send_auth().await?;

                Ok(())
            }
            Err(e) => {
                error!("Connection failed: {}", e);
                Err(e.into())
            }
        }
    }

    async fn send_auth(&mut self) -> Result<()> {
        let auth_msg = AgentMessage {
            msg_type: MessageType::Auth,
            target_id: self.config.target_id,
            timestamp: chrono::Utc::now().timestamp(),
            payload: serde_json::json!({
                "auth_token": self.config.auth_token,
                "agent_version": env!("CARGO_PKG_VERSION"),
                "hostname": hostname::get()?.to_string_lossy().to_string(),
            }),
        };

        self.send_message(&auth_msg).await?;
        info!("Authentication sent");

        Ok(())
    }

    pub async fn reconnect(&mut self) -> Result<()> {
        warn!("Reconnecting with backoff: {:?}", self.backoff);

        tokio::time::sleep(self.backoff).await;

        self.connect().await?;

        // Reset backoff on successful connection
        self.backoff = Duration::from_secs(self.config.reconnect.initial_backoff);

        Ok(())
    }

    fn increase_backoff(&mut self) {
        self.backoff = Duration::from_secs(
            (self.backoff.as_secs() as f64 * self.config.reconnect.backoff_multiplier) as u64
        ).min(Duration::from_secs(self.config.reconnect.max_backoff));
    }

    pub fn buffer_metrics(&mut self, metrics: AllMetrics) {
        self.buffer.push(metrics);

        // Force flush if buffer is full
        if self.buffer.len() >= self.config.max_buffer_size {
            warn!("Buffer full ({}), will flush on next send", self.buffer.len());
        }
    }

    pub fn buffer_size(&self) -> usize {
        self.buffer.len()
    }

    pub async fn send_buffered(&mut self) -> Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }

        // Compress batch
        let compressed = compress_json(&self.buffer, self.config.compression_level)?;

        info!(
            "Compressed {} payloads: {} → {} bytes ({:.1}%)",
            self.buffer.len(),
            compressed.original_size,
            compressed.compressed_size,
            compressed.compression_ratio
        );

        // Send
        let msg = AgentMessage {
            msg_type: MessageType::Metrics,
            target_id: self.config.target_id,
            timestamp: chrono::Utc::now().timestamp(),
            payload: serde_json::to_value(&compressed)?,
        };

        self.send_message(&msg).await?;

        // Clear buffer after successful send
        self.buffer.clear();

        Ok(())
    }

    async fn send_message(&mut self, msg: &AgentMessage) -> Result<()> {
        if let Some(ws) = &mut self.ws {
            let json = serde_json::to_string(msg)?;
            ws.send(Message::Text(json)).await?;
            Ok(())
        } else {
            Err(anyhow::anyhow!("Not connected"))
        }
    }

    pub fn is_connected(&self) -> bool {
        self.ws.is_some()
    }

    pub async fn handle_commands(&mut self) -> Result<()> {
        if let Some(ws) = &mut self.ws {
            while let Some(msg) = ws.next().await {
                match msg {
                    Ok(Message::Text(text)) => {
                        match serde_json::from_str::<AgentMessage>(&text) {
                            Ok(cmd) => {
                                info!("Received command: {:?}", cmd.msg_type);
                                // Handle commands (update config, restart, etc.)
                                self.handle_command(cmd).await?;
                            }
                            Err(e) => {
                                error!("Failed to parse command: {}", e);
                            }
                        }
                    }
                    Ok(Message::Close(_)) => {
                        info!("Server closed connection");
                        self.ws = None;
                        break;
                    }
                    Err(e) => {
                        error!("WebSocket error: {}", e);
                        self.ws = None;
                        break;
                    }
                    _ => {}
                }
            }
        }

        Ok(())
    }

    async fn handle_command(&mut self, cmd: AgentMessage) -> Result<()> {
        match cmd.msg_type {
            MessageType::Command => {
                // Handle configuration updates, restart requests, etc.
                info!("Processing command: {:?}", cmd.payload);
            }
            _ => {}
        }

        Ok(())
    }
}
