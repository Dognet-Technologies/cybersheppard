// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - Compliance API
// ============================================================================

use axum::{routing::{get, post}, Router};

pub fn routes() -> Router<crate::AppState> {
    Router::new()
        .route("/checks", get(list_checks))
        .route("/report", post(generate_report))
        .route("/standards", get(list_standards))
}

async fn list_checks() -> &'static str {
    "TODO: implement list_checks"
}

async fn generate_report() -> &'static str {
    "TODO: implement generate_report"
}

async fn list_standards() -> &'static str {
    "TODO: implement list_standards"
}
