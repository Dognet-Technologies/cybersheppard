// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - Hardening API
// ============================================================================

use axum::{routing::{get, post}, Router};

pub fn routes() -> Router<crate::AppState> {
    Router::new()
        .route("/models", get(list_models))
        .route("/apply", post(apply_hardening))
        .route("/history", get(hardening_history))
        .route("/rollback", post(rollback_hardening))
}

async fn list_models() -> &'static str {
    "TODO: implement list_models"
}

async fn apply_hardening() -> &'static str {
    "TODO: implement apply_hardening"
}

async fn hardening_history() -> &'static str {
    "TODO: implement hardening_history"
}

async fn rollback_hardening() -> &'static str {
    "TODO: implement rollback_hardening"
}
