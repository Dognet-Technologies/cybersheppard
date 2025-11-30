// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - Authentication API
// ============================================================================

use axum::{routing::post, Router};

pub fn routes() -> Router<crate::AppState> {
    Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/refresh", post(refresh_token))
}

async fn register() -> &'static str {
    "TODO: implement register"
}

async fn login() -> &'static str {
    "TODO: implement login"
}

async fn logout() -> &'static str {
    "TODO: implement logout"
}

async fn refresh_token() -> &'static str {
    "TODO: implement refresh_token"
}
