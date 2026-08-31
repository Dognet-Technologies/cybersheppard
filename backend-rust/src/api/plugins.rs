// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - Plugins API
// ============================================================================

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get, post, put},
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;

use crate::middleware::auth::AuthUser;
use crate::middleware::permissions::{AdminUser, ManagerUser};
use crate::services::plugin_manager::PluginManager;
use crate::AppState;

pub fn routes() -> Router<crate::AppState> {
    Router::new()
        // Repositories
        .route("/repositories", get(list_repositories).post(add_repository))
        .route("/repositories/:id", delete(remove_repository))
        .route("/repositories/:id/fetch", post(fetch_repository_plugins))
        // Registry (available plugins)
        .route("/registry", get(list_available_plugins))
        // Installed plugins
        .route("/installed", get(list_installed_plugins))
        .route("/install/:registry_id", post(install_plugin))
        .route("/installed/:id", delete(uninstall_plugin))
        .route("/installed/:id/enable", post(enable_plugin))
        .route("/installed/:id/disable", post(disable_plugin))
        .route("/installed/:id/configure", put(configure_plugin))
}

// ============================================================================
// DTOs
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct AddRepositoryRequest {
    pub name: String,
    pub url: String,
    pub branch: String,
    pub trust_level: String, // official, community, private
}

#[derive(Debug, Deserialize)]
pub struct ConfigurePluginRequest {
    pub configuration: serde_json::Value,
}

// ============================================================================
// HANDLERS - Repositories
// ============================================================================

async fn list_repositories(
    State(state): State<AppState>,
    _auth_user: AuthUser,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let manager = PluginManager::new(state.pg_pool.clone());

    let repositories = manager.get_repositories().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
    })?;

    Ok(Json(json!({ "repositories": repositories })))
}

async fn add_repository(
    State(state): State<AppState>,
    AdminUser(auth_user): AdminUser,
    Json(payload): Json<AddRepositoryRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Validate trust level
    if !["official", "community", "private"].contains(&payload.trust_level.as_str()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid trust level. Must be: official, community, or private"})),
        ));
    }

    // Only admins can add official repositories
    if payload.trust_level == "official" && auth_user.role != "admin" {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Only administrators can add official repositories"})),
        ));
    }

    let manager = PluginManager::new(state.pg_pool.clone());

    let repo_id = manager
        .add_repository(
            &payload.name,
            &payload.url,
            &payload.branch,
            &payload.trust_level,
            auth_user.user_id,
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
        })?;

    Ok(Json(json!({
        "status": "success",
        "message": "Repository added successfully",
        "repository_id": repo_id
    })))
}

async fn remove_repository(
    State(state): State<AppState>,
    Path(id): Path<i32>,
    _admin: AdminUser,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let manager = PluginManager::new(state.pg_pool.clone());

    manager.remove_repository(id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
    })?;

    Ok(Json(json!({
        "status": "success",
        "message": "Repository removed successfully"
    })))
}

async fn fetch_repository_plugins(
    State(state): State<AppState>,
    Path(id): Path<i32>,
    _admin: AdminUser,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let manager = PluginManager::new(state.pg_pool.clone());

    let count = manager.fetch_repository_plugins(id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
    })?;

    Ok(Json(json!({
        "status": "success",
        "message": format!("Fetched {} plugins", count),
        "count": count
    })))
}

// ============================================================================
// HANDLERS - Available Plugins
// ============================================================================

async fn list_available_plugins(
    State(state): State<AppState>,
    _auth_user: AuthUser,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let manager = PluginManager::new(state.pg_pool.clone());

    let plugins = manager.get_available_plugins().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
    })?;

    Ok(Json(json!({ "plugins": plugins })))
}

// ============================================================================
// HANDLERS - Installed Plugins
// ============================================================================

async fn list_installed_plugins(
    State(state): State<AppState>,
    _auth_user: AuthUser,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let manager = PluginManager::new(state.pg_pool.clone());

    let plugins = manager.get_installed_plugins().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
    })?;

    Ok(Json(json!({ "plugins": plugins })))
}

async fn install_plugin(
    State(state): State<AppState>,
    Path(registry_id): Path<i32>,
    AdminUser(auth_user): AdminUser,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let manager = PluginManager::new(state.pg_pool.clone());

    let plugin_id = manager
        .install_plugin(registry_id, auth_user.user_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
        })?;

    Ok(Json(json!({
        "status": "success",
        "message": "Plugin installed successfully",
        "plugin_id": plugin_id
    })))
}

async fn uninstall_plugin(
    State(state): State<AppState>,
    Path(id): Path<i32>,
    _admin: AdminUser,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let manager = PluginManager::new(state.pg_pool.clone());

    manager.uninstall_plugin(id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
    })?;

    Ok(Json(json!({
        "status": "success",
        "message": "Plugin uninstalled successfully"
    })))
}

async fn enable_plugin(
    State(state): State<AppState>,
    Path(id): Path<i32>,
    _admin: AdminUser,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let manager = PluginManager::new(state.pg_pool.clone());

    manager.enable_plugin(id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
    })?;

    Ok(Json(json!({
        "status": "success",
        "message": "Plugin enabled successfully"
    })))
}

async fn disable_plugin(
    State(state): State<AppState>,
    Path(id): Path<i32>,
    _admin: AdminUser,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let manager = PluginManager::new(state.pg_pool.clone());

    manager.disable_plugin(id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
    })?;

    Ok(Json(json!({
        "status": "success",
        "message": "Plugin disabled successfully"
    })))
}

async fn configure_plugin(
    State(state): State<AppState>,
    Path(id): Path<i32>,
    _manager: ManagerUser,
    Json(payload): Json<ConfigurePluginRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let manager = PluginManager::new(state.pg_pool.clone());

    manager
        .configure_plugin(id, payload.configuration)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
        })?;

    Ok(Json(json!({
        "status": "success",
        "message": "Plugin configured successfully"
    })))
}
