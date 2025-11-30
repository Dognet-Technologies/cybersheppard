// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - Integrations API
// ============================================================================

use axum::{routing::{get, post}, Router};

pub fn routes() -> Router<crate::AppState> {
    Router::new()
        .route("/status", get(integration_status))
        .route("/sentinel-core/sync", post(sync_sentinel_core))
        .route("/firedog/sync", post(sync_firedog))
        .route("/correlations", get(get_correlations))
}

async fn integration_status() -> &'static str {
    "TODO: implement integration_status"
}

async fn sync_sentinel_core() -> &'static str {
    "TODO: implement sync_sentinel_core"
}

async fn sync_firedog() -> &'static str {
    "TODO: implement sync_firedog"
}

async fn get_correlations() -> &'static str {
    "TODO: implement get_correlations"
}
