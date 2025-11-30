// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - Monitoring API
// ============================================================================

use axum::{routing::get, Router};

pub fn routes() -> Router<crate::AppState> {
    Router::new()
        .route("/metrics", get(get_metrics))
        .route("/events", get(get_events))
        .route("/logs", get(get_logs))
}

async fn get_metrics() -> &'static str {
    "TODO: implement get_metrics"
}

async fn get_events() -> &'static str {
    "TODO: implement get_events"
}

async fn get_logs() -> &'static str {
    "TODO: implement get_logs"
}
