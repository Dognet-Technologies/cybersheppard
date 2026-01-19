// ============================================================================
// Agent Registry - Manages active agent WebSocket connections
// ============================================================================

use axum::extract::ws::Message;
use futures_util::stream::SplitSink;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info};

pub type AgentSender = mpsc::UnboundedSender<Message>;

/// Registry of active agent connections
/// Maps target_id -> sender for WebSocket communication
#[derive(Clone)]
pub struct AgentRegistry {
    connections: Arc<RwLock<HashMap<i32, AgentSender>>>,
}

impl AgentRegistry {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a new agent connection
    pub async fn register(&self, target_id: i32, sender: AgentSender) {
        let mut connections = self.connections.write().await;
        connections.insert(target_id, sender);
        info!("Agent registered: target_id={}, total={}", target_id, connections.len());
    }

    /// Unregister an agent connection
    pub async fn unregister(&self, target_id: i32) {
        let mut connections = self.connections.write().await;
        connections.remove(&target_id);
        info!("Agent unregistered: target_id={}, remaining={}", target_id, connections.len());
    }

    /// Check if an agent is connected
    pub async fn is_connected(&self, target_id: i32) -> bool {
        let connections = self.connections.read().await;
        connections.contains_key(&target_id)
    }

    /// Send a message to a specific agent
    pub async fn send_to_agent(&self, target_id: i32, message: Message) -> Result<(), String> {
        let connections = self.connections.read().await;

        if let Some(sender) = connections.get(&target_id) {
            sender.send(message)
                .map_err(|e| format!("Failed to send message to agent {}: {}", target_id, e))?;
            Ok(())
        } else {
            Err(format!("Agent {} not connected", target_id))
        }
    }

    /// Send a JSON command to a specific agent
    pub async fn send_command(&self, target_id: i32, command: serde_json::Value) -> Result<(), String> {
        let message_text = serde_json::to_string(&command)
            .map_err(|e| format!("Failed to serialize command: {}", e))?;

        self.send_to_agent(target_id, Message::Text(message_text)).await
    }

    /// Get list of all connected agent target IDs
    pub async fn get_connected_agents(&self) -> Vec<i32> {
        let connections = self.connections.read().await;
        connections.keys().copied().collect()
    }

    /// Get count of connected agents
    pub async fn count(&self) -> usize {
        let connections = self.connections.read().await;
        connections.len()
    }
}

impl Default for AgentRegistry {
    fn default() -> Self {
        Self::new()
    }
}
