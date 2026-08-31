// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - MCP protocol types (JSON-RPC 2.0)
// ============================================================================
//
// Tipi del protocollo MCP (Model Context Protocol) sopra JSON-RPC 2.0.
// Implementazione hand-rolled minima (`initialize`, `ping`, `tools/list`,
// `tools/call`, più le notification). Portato da SentinelCore per coerenza di
// suite.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Versione MCP di default quando il client non ne negozia una.
pub const DEFAULT_PROTOCOL_VERSION: &str = "2025-06-18";

// ───── Codici errore JSON-RPC 2.0 (sezione 5.1) ─────
#[allow(dead_code)]
pub const PARSE_ERROR: i32 = -32700;
pub const INVALID_REQUEST: i32 = -32600;
pub const METHOD_NOT_FOUND: i32 = -32601;
pub const INVALID_PARAMS: i32 = -32602;
pub const INTERNAL_ERROR: i32 = -32603;

/// Richiesta JSON-RPC 2.0. `id` assente ⇒ notification (nessuna risposta).
#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    #[allow(dead_code)]
    pub jsonrpc: Option<String>,
    #[serde(default)]
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Option<Value>,
}

impl JsonRpcRequest {
    /// Una richiesta senza `id` è una notification: non va risposta.
    pub fn is_notification(&self) -> bool {
        self.id.is_none()
    }
}

#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: &'static str,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    pub fn success(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: Value, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }
}

/// Errore di un tool, mappato poi su un errore JSON-RPC. `Invalid` ⇒ il client
/// ha sbagliato i parametri; `Internal` ⇒ problema lato server (il dettaglio
/// NON va esposto al client, va solo loggato).
#[derive(Debug)]
pub enum ToolError {
    Invalid(String),
    Internal(String),
}
