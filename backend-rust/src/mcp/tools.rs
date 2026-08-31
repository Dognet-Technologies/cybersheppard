// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - MCP tools
// ============================================================================
//
// Registry e implementazione dei tool MCP per il dominio CyberSheppard.
// I tool ereditano la visibilità dell'utente proprietario della API-key
// (stesso user_id/role), quindi l'RBAC esistente si applica. I tool di
// SCRITTURA sono gated da un secondo livello indipendente dal ruolo:
// `AuthUser.mcp_key_scope` deve essere ESATTAMENTE `Some("write")` (mai `None`
// = sessione JWT, mai `Some("read")`). Solo un admin può creare una chiave
// 'write' (vedi api::api_keys::create_api_key).
//
// Le query sono RUNTIME (non il macro `query!`): niente cache sqlx offline,
// build verde senza `cargo sqlx prepare`. Ogni tool di lettura usa
// `json_agg(row_to_json(...))` per restituire direttamente un array JSON.

use serde_json::{json, Value};

use super::protocol::ToolError;
use crate::middleware::auth::AuthUser;
use crate::AppState;

/// Definizione di un tool esposta da `tools/list`.
pub struct ToolDef {
    pub name: &'static str,
    pub description: &'static str,
    pub input_schema: Value,
}

const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 200;

/// Catalogo dei tool disponibili (read + write).
pub fn tool_definitions() -> Vec<ToolDef> {
    vec![
        ToolDef {
            name: "list_targets",
            description: "Elenca i target monitorati (host). Ritorna id, hostname, ip, status, \
                role, environment, stato agent e ultimo monitoring. Filtri opzionali per status \
                e connessione agent.",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "status": { "type": "string", "description": "Filtro per status (es. online, offline)." },
                    "agent_connected": { "type": "boolean", "description": "Solo target con agent connesso/disconnesso." },
                    "limit": { "type": "integer", "description": "Max righe (default 50, max 200)." }
                }
            }),
        },
        ToolDef {
            name: "list_alerts",
            description: "Elenca gli alert di sicurezza ordinati dal più recente. Ritorna id, \
                severity, title, message, alert_type, status, acknowledged, created_at. Filtri \
                opzionali per severity e status.",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "severity": { "type": "string", "description": "Filtro per severity (es. critical, high)." },
                    "status": { "type": "string", "description": "Filtro per status." },
                    "limit": { "type": "integer", "description": "Max righe (default 50, max 200)." }
                }
            }),
        },
        ToolDef {
            name: "get_target_metrics",
            description: "Ritorna gli ultimi snapshot di metriche inviati dall'agent per un \
                target (JSON con system/network/users/files/services/auditd secondo i collector \
                abilitati).",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target_id": { "type": "integer", "description": "ID del target." },
                    "limit": { "type": "integer", "description": "Numero di snapshot (default 1, max 50)." }
                },
                "required": ["target_id"]
            }),
        },
        ToolDef {
            name: "list_compliance_scans",
            description: "Elenca le scansioni di compliance (id, target_id, status, tempi, \
                controlli totali/verificati). Filtro opzionale per target_id.",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target_id": { "type": "integer", "description": "Filtro per target." },
                    "limit": { "type": "integer", "description": "Max righe (default 50, max 200)." }
                }
            }),
        },
        ToolDef {
            name: "acknowledge_alert",
            description: "Segna un alert come 'acknowledged' (preso in carico). Richiede una \
                API-key con scope 'write'.",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "alert_id": { "type": "integer", "description": "ID dell'alert da riconoscere." }
                },
                "required": ["alert_id"]
            }),
        },
    ]
}

/// Dispatch di `tools/call` verso il tool richiesto.
pub async fn dispatch_tool(
    state: &AppState,
    user: &AuthUser,
    name: &str,
    args: Option<Value>,
) -> Result<Value, ToolError> {
    let args = args.unwrap_or_else(|| json!({}));
    match name {
        "list_targets" => list_targets(state, &args).await,
        "list_alerts" => list_alerts(state, &args).await,
        "get_target_metrics" => get_target_metrics(state, &args).await,
        "list_compliance_scans" => list_compliance_scans(state, &args).await,
        "acknowledge_alert" => acknowledge_alert(state, user, &args).await,
        other => Err(ToolError::Invalid(format!("Unknown tool: {other}"))),
    }
}

// ─── Guardrail e helper argomenti ────────────────────────────────────────────

/// I tool di scrittura richiedono una API-key con scope ESATTAMENTE 'write'.
fn require_write_scope(user: &AuthUser) -> Result<(), ToolError> {
    if user.mcp_key_scope.as_deref() == Some("write") {
        Ok(())
    } else {
        Err(ToolError::Invalid(
            "Questo tool richiede una API-key con scope 'write'.".into(),
        ))
    }
}

fn opt_string(args: &Value, field: &str) -> Option<String> {
    args.get(field)
        .and_then(Value::as_str)
        .map(|s| s.to_string())
}

fn opt_bool(args: &Value, field: &str) -> Option<bool> {
    args.get(field).and_then(Value::as_bool)
}

fn required_i64(args: &Value, field: &str) -> Result<i64, ToolError> {
    args.get(field)
        .and_then(Value::as_i64)
        .ok_or_else(|| ToolError::Invalid(format!("Campo '{field}' mancante o non intero")))
}

fn clamp_limit(args: &Value, default: i64, max: i64) -> i64 {
    args.get("limit")
        .and_then(Value::as_i64)
        .unwrap_or(default)
        .clamp(1, max)
}

fn internal(ctx: &str, e: impl std::fmt::Display) -> ToolError {
    ToolError::Internal(format!("{ctx}: {e}"))
}

// ─── Tool di lettura ─────────────────────────────────────────────────────────

async fn list_targets(state: &AppState, args: &Value) -> Result<Value, ToolError> {
    let status = opt_string(args, "status");
    let agent_connected = opt_bool(args, "agent_connected");
    let limit = clamp_limit(args, DEFAULT_LIMIT, MAX_LIMIT);

    let (rows,): (Option<Value>,) = sqlx::query_as(
        r#"
        SELECT json_agg(t) FROM (
            SELECT id, hostname, host(ip_address) AS ip_address, status, role, environment,
                   agent_connected, agent_last_seen, last_monitoring_at, hardening_score
            FROM targets
            WHERE ($1::text IS NULL OR status = $1)
              AND ($2::bool IS NULL OR agent_connected = $2)
            ORDER BY id
            LIMIT $3
        ) t
        "#,
    )
    .bind(status)
    .bind(agent_connected)
    .bind(limit)
    .fetch_one(&state.pg_pool)
    .await
    .map_err(|e| internal("list_targets", e))?;

    Ok(rows.unwrap_or_else(|| json!([])))
}

async fn list_alerts(state: &AppState, args: &Value) -> Result<Value, ToolError> {
    let severity = opt_string(args, "severity");
    let status = opt_string(args, "status");
    let limit = clamp_limit(args, DEFAULT_LIMIT, MAX_LIMIT);

    let (rows,): (Option<Value>,) = sqlx::query_as(
        r#"
        SELECT json_agg(t) FROM (
            SELECT id, severity, title, message, alert_type, status, acknowledged,
                   acknowledged_by, created_at
            FROM alerts
            WHERE ($1::text IS NULL OR severity = $1)
              AND ($2::text IS NULL OR status = $2)
            ORDER BY created_at DESC
            LIMIT $3
        ) t
        "#,
    )
    .bind(severity)
    .bind(status)
    .bind(limit)
    .fetch_one(&state.pg_pool)
    .await
    .map_err(|e| internal("list_alerts", e))?;

    Ok(rows.unwrap_or_else(|| json!([])))
}

async fn get_target_metrics(state: &AppState, args: &Value) -> Result<Value, ToolError> {
    let target_id = required_i64(args, "target_id")? as i32;
    let limit = clamp_limit(args, 1, 50);

    let (rows,): (Option<Value>,) = sqlx::query_as(
        r#"
        SELECT json_agg(t) FROM (
            SELECT id, hostname, collected_at, received_at, metrics
            FROM agent_metric_snapshots
            WHERE target_id = $1
            ORDER BY received_at DESC
            LIMIT $2
        ) t
        "#,
    )
    .bind(target_id)
    .bind(limit)
    .fetch_one(&state.pg_pool)
    .await
    .map_err(|e| internal("get_target_metrics", e))?;

    Ok(rows.unwrap_or_else(|| json!([])))
}

async fn list_compliance_scans(state: &AppState, args: &Value) -> Result<Value, ToolError> {
    let target_id = args.get("target_id").and_then(Value::as_i64).map(|v| v as i32);
    let limit = clamp_limit(args, DEFAULT_LIMIT, MAX_LIMIT);

    let (rows,): (Option<Value>,) = sqlx::query_as(
        r#"
        SELECT json_agg(t) FROM (
            SELECT id, target_id, status, started_at, completed_at,
                   total_controls, checked_controls
            FROM compliance_scans
            WHERE ($1::int IS NULL OR target_id = $1)
            ORDER BY created_at DESC
            LIMIT $2
        ) t
        "#,
    )
    .bind(target_id)
    .bind(limit)
    .fetch_one(&state.pg_pool)
    .await
    .map_err(|e| internal("list_compliance_scans", e))?;

    Ok(rows.unwrap_or_else(|| json!([])))
}

// ─── Tool di scrittura (richiede scope 'write') ──────────────────────────────

async fn acknowledge_alert(
    state: &AppState,
    user: &AuthUser,
    args: &Value,
) -> Result<Value, ToolError> {
    require_write_scope(user)?;
    let alert_id = required_i64(args, "alert_id")? as i32;

    let result = sqlx::query(
        r#"
        UPDATE alerts
        SET acknowledged = true,
            status = 'acknowledged',
            acknowledged_by = $2,
            acknowledged_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(alert_id)
    .bind(&user.username)
    .execute(&state.pg_pool)
    .await
    .map_err(|e| internal("acknowledge_alert", e))?;

    if result.rows_affected() == 0 {
        return Err(ToolError::Invalid(format!("Alert {alert_id} non trovato")));
    }

    Ok(json!({ "acknowledged": true, "alert_id": alert_id, "by": user.username }))
}
