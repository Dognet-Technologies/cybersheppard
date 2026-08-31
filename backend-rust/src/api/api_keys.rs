// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - API Key management endpoints
// ============================================================================
//
// Gestione delle API-key per-utente (vedi migr. 014 e utils::api_key). Usate
// dai client programmatici, in particolare il server MCP. Le rotte vivono sotto
// /api/api-keys (protette da auth_middleware). La chiave in chiaro è mostrata
// UNA sola volta, alla creazione; in seguito solo prefisso/metadati.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::middleware::auth::AuthUser;
use crate::utils::api_key::{generate_api_key, hash_api_key};
use crate::AppState;

type ApiError = (StatusCode, Json<serde_json::Value>);

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list_api_keys).post(create_api_key))
        .route("/:id", delete(revoke_api_key))
}

/// Vista pubblica di una API-key: mai il `key_hash`, mai la chiave in chiaro.
#[derive(Debug, Serialize, sqlx::FromRow)]
struct ApiKeyInfo {
    id: i64,
    name: String,
    key_prefix: String,
    scope: String,
    created_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
struct CreateApiKeyRequest {
    name: String,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    expires_at: Option<DateTime<Utc>>,
}

fn internal(e: impl std::fmt::Display) -> ApiError {
    tracing::error!("api_keys error: {}", e);
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": "Internal server error" })),
    )
}

fn bad_request(msg: &str) -> ApiError {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": msg })))
}

/// GET /api/api-keys — elenca le chiavi dell'utente corrente.
async fn list_api_keys(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<Vec<ApiKeyInfo>>, ApiError> {
    let keys = sqlx::query_as::<_, ApiKeyInfo>(
        r#"
        SELECT id, name, key_prefix, scope, created_at, last_used_at, expires_at
        FROM user_api_keys
        WHERE user_id = $1
        ORDER BY created_at DESC
        "#,
    )
    .bind(user.user_id)
    .fetch_all(&state.pg_pool)
    .await
    .map_err(internal)?;

    Ok(Json(keys))
}

/// POST /api/api-keys — crea una chiave. Scope 'write' riservato agli admin.
/// Ritorna la chiave in chiaro UNA sola volta.
async fn create_api_key(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<CreateApiKeyRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let name = req.name.trim();
    if name.is_empty() {
        return Err(bad_request("Il nome della chiave è obbligatorio"));
    }

    let scope = req.scope.unwrap_or_else(|| "read".to_string());
    if scope != "read" && scope != "write" {
        return Err(bad_request("scope deve essere 'read' o 'write'"));
    }
    if scope == "write" && user.role != "admin" {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Solo un admin può creare chiavi con scope 'write'" })),
        ));
    }

    let (raw, prefix) = generate_api_key();
    let key_hash = hash_api_key(&raw);

    let (id,): (i64,) = sqlx::query_as(
        r#"
        INSERT INTO user_api_keys (user_id, name, key_hash, key_prefix, scope, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id
        "#,
    )
    .bind(user.user_id)
    .bind(name)
    .bind(&key_hash)
    .bind(&prefix)
    .bind(&scope)
    .bind(req.expires_at)
    .fetch_one(&state.pg_pool)
    .await
    .map_err(internal)?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": id,
            "name": name,
            "scope": scope,
            "key_prefix": prefix,
            "api_key": raw,
            "warning": "Conserva questa chiave adesso: non verrà più mostrata."
        })),
    ))
}

/// DELETE /api/api-keys/:id — revoca una chiave dell'utente corrente.
async fn revoke_api_key(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    let result = sqlx::query("DELETE FROM user_api_keys WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(user.user_id)
        .execute(&state.pg_pool)
        .await
        .map_err(internal)?;

    if result.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Chiave non trovata" })),
        ));
    }

    Ok(StatusCode::NO_CONTENT)
}
