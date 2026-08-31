// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - MCP server (Model Context Protocol)
// ============================================================================
//
// Server MCP embedded in CyberSheppard. Espone un singolo endpoint
// `POST /api/mcp` che parla JSON-RPC 2.0, così un agente/LLM può interrogare
// target, alert, metriche e compliance. Portato da SentinelCore per coerenza
// di suite, adattato al modello auth di CyberSheppard.
//
// • Transport: HTTP semplice (richiesta→risposta JSON).
// • Auth: montato sotto auth_middleware, che accetta sia il JWT sia
//   `Authorization: Bearer sk_...` (API-key, vedi utils::api_key). L'AuthUser
//   arriva nelle request extensions.
// • CSRF: le richieste autenticate via API-key sono esentate dal CSRF
//   (vedi middleware::csrf) — usano Bearer, non il cookie che il CSRF protegge.
// • Scrittura: i tool di scrittura richiedono una API-key con scope 'write'
//   (vedi tools::require_write_scope), in aggiunta al controllo di ruolo.

pub mod protocol;
pub mod tools;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};

use crate::middleware::auth::AuthUser;
use crate::AppState;

use protocol::{
    JsonRpcRequest, JsonRpcResponse, ToolError, DEFAULT_PROTOCOL_VERSION, INVALID_PARAMS,
    INVALID_REQUEST, METHOD_NOT_FOUND,
};

const SERVER_NAME: &str = "cybersheppard-mcp";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Handler dell'endpoint `POST /api/mcp`. Accetta una singola richiesta
/// JSON-RPC o un batch (array). Le notification (senza `id`) non producono
/// risposta.
pub async fn handle_mcp(
    State(state): State<AppState>,
    user: AuthUser,
    Json(body): Json<Value>,
) -> Response {
    match body {
        Value::Array(items) => {
            if items.is_empty() {
                return Json(JsonRpcResponse::error(
                    Value::Null,
                    INVALID_REQUEST,
                    "Empty batch",
                ))
                .into_response();
            }
            let mut responses: Vec<JsonRpcResponse> = Vec::new();
            for item in items {
                if let Some(resp) = handle_value(&state, &user, item).await {
                    responses.push(resp);
                }
            }
            if responses.is_empty() {
                StatusCode::ACCEPTED.into_response()
            } else {
                Json(responses).into_response()
            }
        }
        obj @ Value::Object(_) => match handle_value(&state, &user, obj).await {
            Some(resp) => Json(resp).into_response(),
            None => StatusCode::ACCEPTED.into_response(),
        },
        _ => Json(JsonRpcResponse::error(
            Value::Null,
            INVALID_REQUEST,
            "Expected JSON-RPC object or array",
        ))
        .into_response(),
    }
}

async fn handle_value(state: &AppState, user: &AuthUser, value: Value) -> Option<JsonRpcResponse> {
    let req: JsonRpcRequest = match serde_json::from_value(value) {
        Ok(r) => r,
        Err(e) => {
            return Some(JsonRpcResponse::error(
                Value::Null,
                INVALID_REQUEST,
                format!("Invalid JSON-RPC request: {e}"),
            ))
        }
    };
    dispatch(state, user, req).await
}

async fn dispatch(state: &AppState, user: &AuthUser, req: JsonRpcRequest) -> Option<JsonRpcResponse> {
    let id = req.id.clone().unwrap_or(Value::Null);
    if req.is_notification() {
        return None;
    }

    let response = match req.method.as_str() {
        "initialize" => JsonRpcResponse::success(id, initialize_result(req.params.as_ref())),
        "ping" => JsonRpcResponse::success(id, json!({})),
        "tools/list" => JsonRpcResponse::success(id, tools_list_result()),
        "tools/call" => tools_call(state, user, id, req.params).await,
        other => JsonRpcResponse::error(id, METHOD_NOT_FOUND, format!("Method not found: {other}")),
    };
    Some(response)
}

fn initialize_result(params: Option<&Value>) -> Value {
    let protocol_version = params
        .and_then(|p| p.get("protocolVersion"))
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_PROTOCOL_VERSION);

    json!({
        "protocolVersion": protocol_version,
        "capabilities": { "tools": {} },
        "serverInfo": { "name": SERVER_NAME, "version": SERVER_VERSION }
    })
}

fn tools_list_result() -> Value {
    let tools: Vec<Value> = tools::tool_definitions()
        .into_iter()
        .map(|t| {
            json!({
                "name": t.name,
                "description": t.description,
                "inputSchema": t.input_schema,
            })
        })
        .collect();
    json!({ "tools": tools })
}

async fn tools_call(
    state: &AppState,
    user: &AuthUser,
    id: Value,
    params: Option<Value>,
) -> JsonRpcResponse {
    let params = params.unwrap_or_else(|| json!({}));
    let name = match params.get("name").and_then(Value::as_str) {
        Some(n) => n.to_string(),
        None => return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing tool name"),
    };
    let arguments = params.get("arguments").cloned();

    match tools::dispatch_tool(state, user, &name, arguments).await {
        Ok(value) => {
            let text = serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string());
            JsonRpcResponse::success(
                id,
                json!({
                    "content": [{ "type": "text", "text": text }],
                    "isError": false
                }),
            )
        }
        Err(ToolError::Invalid(msg)) => JsonRpcResponse::error(id, INVALID_PARAMS, msg),
        Err(ToolError::Internal(detail)) => {
            tracing::error!(tool = %name, error = %detail, "MCP tool execution failed");
            JsonRpcResponse::success(
                id,
                json!({
                    "content": [{ "type": "text", "text": "Internal error executing tool." }],
                    "isError": true
                }),
            )
        }
    }
}
