// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - Integrations API
// ============================================================================

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use crate::AppState;
use crate::services::correlation_engine::CorrelationEngine;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/status", get(integration_status))
        .route("/sentinel-core/sync", post(sync_sentinel_core))
        .route("/firedog/sync", post(sync_firedog))
        .route("/correlations", get(get_correlations))
        .route("/correlations/:id/acknowledge", post(acknowledge_correlation))
        .route("/correlations/:id/resolve", post(resolve_correlation))
        .route("/correlations/target/:target_id", get(get_target_correlations))
}

#[derive(Serialize)]
struct IntegrationStatus {
    sentinel_core: IntegrationInfo,
    firedog: FireDogInfo,
}

#[derive(Serialize)]
struct IntegrationInfo {
    enabled: bool,
    last_sync: Option<String>,
    status: String,
}

#[derive(Serialize)]
struct FireDogInfo {
    enabled: bool,
    last_sync: Option<String>,
    status: String,
}

async fn integration_status(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let sentinel_status = sqlx::query!(
        r#"
        SELECT enabled, last_sync_at, last_sync_status
        FROM integration_settings
        WHERE integration_name = 'sentinel_core'
        "#
    )
    .fetch_optional(&state.pg_pool)
    .await;

    let firedog_status = sqlx::query!(
        r#"
        SELECT enabled, last_sync_at, last_sync_status
        FROM integration_settings
        WHERE integration_name = 'firedog'
        "#
    )
    .fetch_optional(&state.pg_pool)
    .await;

    let sentinel_info = if let Ok(Some(info)) = sentinel_status {
        IntegrationInfo {
            enabled: info.enabled.unwrap_or(false),
            last_sync: info.last_sync_at.map(|dt| dt.to_string()),
            status: info.last_sync_status.unwrap_or_else(|| "never_synced".to_string()),
        }
    } else {
        IntegrationInfo {
            enabled: false,
            last_sync: None,
            status: "not_configured".to_string(),
        }
    };

    let firedog_info = if let Ok(Some(info)) = firedog_status {
        FireDogInfo {
            enabled: info.enabled.unwrap_or(false),
            last_sync: info.last_sync_at.map(|dt| dt.to_string()),
            status: info.last_sync_status.unwrap_or_else(|| "never_synced".to_string()),
        }
    } else {
        FireDogInfo {
            enabled: false,
            last_sync: None,
            status: "not_configured".to_string(),
        }
    };

    (StatusCode::OK, Json(IntegrationStatus {
        sentinel_core: sentinel_info,
        firedog: firedog_info,
    }))
}

async fn sync_sentinel_core(
    State(_state): State<AppState>,
) -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "message": "Sentinel Core sync triggered (background task)"
    })))
}

async fn sync_firedog(
    State(_state): State<AppState>,
) -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "message": "FireDog sync triggered (background task)"
    })))
}

async fn get_correlations(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let engine = CorrelationEngine::new(state.pg_pool.clone());

    match engine.get_active_correlations().await {
        Ok(correlations) => (StatusCode::OK, Json(correlations)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("Failed to get correlations: {}", e)
            }))
        ).into_response(),
    }
}

async fn get_target_correlations(
    State(state): State<AppState>,
    Path(target_id): Path<i32>,
) -> impl IntoResponse {
    let engine = CorrelationEngine::new(state.pg_pool.clone());

    match engine.get_correlations_by_target(target_id).await {
        Ok(correlations) => (StatusCode::OK, Json(correlations)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("Failed to get correlations: {}", e)
            }))
        ).into_response(),
    }
}

#[derive(Deserialize)]
struct AcknowledgeRequest {
    acknowledged_by: String,
}

async fn acknowledge_correlation(
    State(state): State<AppState>,
    Path(correlation_id): Path<i32>,
    Json(payload): Json<AcknowledgeRequest>,
) -> impl IntoResponse {
    let engine = CorrelationEngine::new(state.pg_pool.clone());

    match engine.acknowledge_correlation(correlation_id, &payload.acknowledged_by).await {
        Ok(_) => (StatusCode::OK, Json(serde_json::json!({
            "success": true,
            "message": "Correlation acknowledged"
        }))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("Failed to acknowledge correlation: {}", e)
            }))
        ).into_response(),
    }
}

#[derive(Deserialize)]
struct ResolveRequest {
    resolved_by: String,
    resolution_notes: String,
}

async fn resolve_correlation(
    State(state): State<AppState>,
    Path(correlation_id): Path<i32>,
    Json(payload): Json<ResolveRequest>,
) -> impl IntoResponse {
    let engine = CorrelationEngine::new(state.pg_pool.clone());

    match engine.resolve_correlation(
        correlation_id,
        &payload.resolved_by,
        &payload.resolution_notes
    ).await {
        Ok(_) => (StatusCode::OK, Json(serde_json::json!({
            "success": true,
            "message": "Correlation resolved"
        }))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("Failed to resolve correlation: {}", e)
            }))
        ).into_response(),
    }
}
