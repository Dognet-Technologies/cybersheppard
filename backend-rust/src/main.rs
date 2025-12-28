// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - Main Entry Point
// ============================================================================

mod api;
mod db;
mod middleware;
mod models;
mod services;
mod utils;

use axum::{
    middleware as axum_middleware,
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use tower::ServiceBuilder;
use tower_http::{
    compression::CompressionLayer,
    cors::CorsLayer,
    trace::{DefaultMakeSpan, TraceLayer},
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::db::{influxdb::InfluxDbClient, postgresql::PostgresPool};
use crate::middleware::auth::auth_middleware;
use crate::middleware::csrf::csrf_middleware;

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    pub pg_pool: PostgresPool,
    pub influx_client: InfluxDbClient,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    init_logging();

    // Load environment variables
    dotenvy::dotenv().ok();

    tracing::info!("🚀 Starting CyberSheppard (MicroSIEM) backend...");

    // Initialize database connections
    let pg_pool = db::postgresql::init_pool().await?;
    let influx_client = db::influxdb::init_client().await?;

    tracing::info!("✅ Database connections established");

    // Create application state
    let state = AppState {
        pg_pool,
        influx_client,
    };

    // Build application router
    let app = build_router(state);

    // Get server address from env
    let host = std::env::var("RUST_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = std::env::var("RUST_PORT").unwrap_or_else(|_| "8080".to_string());
    let addr: SocketAddr = format!("{}:{}", host, port).parse()?;

    tracing::info!("🌐 Server listening on http://{}", addr);

    // Start server
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Build the main application router
fn build_router(state: AppState) -> Router {
    // Public routes (no authentication required)
    let public_routes = Router::new()
        .route("/health", get(health_check))
        .nest("/api/auth", api::auth::routes());

    // Protected routes (require authentication)
    let protected_routes = Router::new()
        .nest("/api/auth", api::auth::protected_routes())
        .nest("/api/targets", api::targets::routes())
        .nest("/api/hardening", api::hardening::routes())
        .nest("/api/monitoring", api::monitoring::routes())
        .nest("/api/compliance", api::compliance::routes())
        .nest("/api/settings", api::settings::routes())
        .nest("/api/integrations", api::integrations::routes())
        .nest("/ws", api::websocket::routes())
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            csrf_middleware,
        ))
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    // Combine routes
    Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .with_state(state)
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http().make_span_with(DefaultMakeSpan::default()))
                .layer(CompressionLayer::new())
                .layer(CorsLayer::permissive()) // TODO: Configure properly for production
        )
}

/// Health check endpoint
async fn health_check() -> &'static str {
    "OK"
}

/// Initialize tracing/logging
fn init_logging() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "cybersheppard_backend=info,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
}
