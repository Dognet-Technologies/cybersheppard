// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - Settings API
// ============================================================================

use axum::{routing::{get, put}, Router};

pub fn routes() -> Router<crate::AppState> {
    Router::new()
        .route("/", get(get_settings).put(update_settings))
        .route("/notifications", get(get_notification_config).put(update_notification_config))
}

async fn get_settings() -> &'static str {
    "TODO: implement get_settings"
}

async fn update_settings() -> &'static str {
    "TODO: implement update_settings"
}

async fn get_notification_config() -> &'static str {
    "TODO: implement get_notification_config"
}

async fn update_notification_config() -> &'static str {
    "TODO: implement update_notification_config"
}
