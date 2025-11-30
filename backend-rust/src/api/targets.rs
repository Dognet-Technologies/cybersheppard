// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - Targets API
// ============================================================================

use axum::{routing::{get, post, put, delete}, Router};

pub fn routes() -> Router<crate::AppState> {
    Router::new()
        .route("/", get(list_targets).post(create_target))
        .route("/:id", get(get_target).put(update_target).delete(delete_target))
        .route("/:id/status", get(get_target_status))
}

async fn list_targets() -> &'static str {
    "TODO: implement list_targets"
}

async fn create_target() -> &'static str {
    "TODO: implement create_target"
}

async fn get_target() -> &'static str {
    "TODO: implement get_target"
}

async fn update_target() -> &'static str {
    "TODO: implement update_target"
}

async fn delete_target() -> &'static str {
    "TODO: implement delete_target"
}

async fn get_target_status() -> &'static str {
    "TODO: implement get_target_status"
}
