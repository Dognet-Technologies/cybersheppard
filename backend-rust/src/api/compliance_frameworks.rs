// ============================================================================
// CYBERSHEPPARD - Compliance Frameworks API
// ============================================================================

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use crate::AppState;
use crate::services::compliance_engine::ComplianceEngine;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/frameworks", get(list_frameworks))
        .route("/frameworks/:id", get(get_framework))
        .route("/frameworks/summary", get(framework_summary))
        .route("/assessments/target/:target_id", get(get_target_assessments))
        .route("/assessments", post(create_assessment))
        .route("/overview", get(compliance_overview))
}

async fn list_frameworks(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let engine = ComplianceEngine::new(state.pg_pool.clone());

    match engine.get_frameworks().await {
        Ok(frameworks) => (StatusCode::OK, Json(frameworks)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("Failed to get frameworks: {}", e)
            }))
        ).into_response(),
    }
}

async fn get_framework(
    State(state): State<AppState>,
    Path(framework_id): Path<i32>,
) -> impl IntoResponse {
    let engine = ComplianceEngine::new(state.pg_pool.clone());

    match engine.get_framework(framework_id).await {
        Ok(framework) => (StatusCode::OK, Json(framework)).into_response(),
        Err(e) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": format!("Framework not found: {}", e)
            }))
        ).into_response(),
    }
}

async fn framework_summary(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let engine = ComplianceEngine::new(state.pg_pool.clone());

    match engine.get_framework_summary().await {
        Ok(summary) => (StatusCode::OK, Json(summary)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("Failed to get framework summary: {}", e)
            }))
        ).into_response(),
    }
}

async fn get_target_assessments(
    State(state): State<AppState>,
    Path(target_id): Path<i32>,
) -> impl IntoResponse {
    let engine = ComplianceEngine::new(state.pg_pool.clone());

    match engine.get_target_assessments(target_id).await {
        Ok(assessments) => (StatusCode::OK, Json(assessments)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("Failed to get assessments: {}", e)
            }))
        ).into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct CreateAssessmentRequest {
    target_id: i32,
    framework_id: i32,
    total_controls: i32,
}

async fn create_assessment(
    State(state): State<AppState>,
    Json(request): Json<CreateAssessmentRequest>,
) -> impl IntoResponse {
    let engine = ComplianceEngine::new(state.pg_pool.clone());

    match engine.create_assessment(
        request.target_id,
        request.framework_id,
        request.total_controls
    ).await {
        Ok(assessment_id) => (StatusCode::CREATED, Json(serde_json::json!({
            "id": assessment_id,
            "success": true
        }))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("Failed to create assessment: {}", e)
            }))
        ).into_response(),
    }
}

async fn compliance_overview(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let engine = ComplianceEngine::new(state.pg_pool.clone());

    match engine.get_compliance_overview().await {
        Ok(overview) => (StatusCode::OK, Json(overview)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("Failed to get compliance overview: {}", e)
            }))
        ).into_response(),
    }
}
