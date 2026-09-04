// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - Main Entry Point
// ============================================================================

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

// Modules and the shared `AppState` now live in the library crate (src/lib.rs)
// so integration tests in tests/ can import them via `cybersheppard_backend::`.
use cybersheppard_backend::middleware::auth::auth_middleware;
use cybersheppard_backend::middleware::csrf::csrf_middleware;
use cybersheppard_backend::services::agent_registry::AgentRegistry;
use cybersheppard_backend::{api, db, mcp, services, websocket, AppState};

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

    // Create agent registry
    let agent_registry = AgentRegistry::new();
    tracing::info!("✅ Agent registry initialized");

    // Create hardening executor
    let hardening_executor = std::sync::Arc::new(services::hardening_executor::HardeningExecutor::new(
        pg_pool.clone(),
        agent_registry.clone(),
    ));
    tracing::info!("✅ Hardening executor initialized");

    // Create compliance scanner
    let compliance_scanner = std::sync::Arc::new(services::compliance_scanner::ComplianceScanner::new(
        pg_pool.clone(),
        agent_registry.clone(),
    ));
    tracing::info!("✅ Compliance scanner initialized");

    // Create event correlation services
    let event_collector = std::sync::Arc::new(services::event_collector::EventCollectorService::new(
        pg_pool.clone(),
        "/var/log/audit/audit.log".to_string(), // Default auditd log path
    ));
    tracing::info!("✅ Event collector initialized");

    let correlation_engine = std::sync::Arc::new(services::correlation_engine::CorrelationEngine::new(
        pg_pool.clone(),
    ));
    tracing::info!("✅ Correlation engine initialized");

    let anomaly_detection = std::sync::Arc::new(services::anomaly_detection::AnomalyDetectionService::new(
        pg_pool.clone(),
    ));
    tracing::info!("✅ Anomaly detection service initialized");

    let baseline_calculator = std::sync::Arc::new(services::baseline_calculator::BaselineCalculatorService::new(
        pg_pool.clone(),
    ));
    tracing::info!("✅ Baseline calculator initialized");

    let alert_broadcaster = std::sync::Arc::new(websocket::alert_broadcaster::AlertBroadcaster::new(1024));
    tracing::info!("✅ Alert broadcaster initialized");

    // Create application state
    let state = AppState {
        pg_pool: pg_pool.clone(),
        influx_client: influx_client.clone(),
        agent_registry: agent_registry.clone(),
        hardening_executor: hardening_executor.clone(),
        compliance_scanner: compliance_scanner.clone(),
        event_collector: event_collector.clone(),
        correlation_engine: correlation_engine.clone(),
        anomaly_detection: anomaly_detection.clone(),
        baseline_calculator: baseline_calculator.clone(),
        alert_broadcaster: alert_broadcaster.clone(),
    };

    // Nota: la raccolta metriche/eventi è push-based via agent (WebSocket
    // /api/agents/ws). Il vecchio scheduler SSH-pull (collector + influxdb_writer)
    // è stato rimosso in quanto architettura legacy non più utilizzata.

    // Start hardening executor background loop
    let executor_clone = hardening_executor.clone();
    tokio::spawn(async move {
        executor_clone.start().await;
    });
    tracing::info!("✅ Hardening executor background loop started");

    // Start compliance scanner background loop
    let scanner_clone = compliance_scanner.clone();
    tokio::spawn(async move {
        scanner_clone.start().await;
    });
    tracing::info!("✅ Compliance scanner background loop started");

    // Start alert monitor service for WebSocket broadcasting
    let alert_monitor = std::sync::Arc::new(websocket::alert_broadcaster::AlertMonitorService::new(
        pg_pool.clone(),
        alert_broadcaster.clone(),
    ));
    tokio::spawn(async move {
        alert_monitor.start_monitoring().await;
    });
    tracing::info!("✅ Alert monitor service started (WebSocket broadcasting)");

    // Correlazione AUTOMATICA: ogni 60s analizza gli eventi dell'ultima ora e
    // salva le correlazioni. Il guard "firma-occorrenza" in save_correlation
    // evita di ri-registrare lo stesso burst ad ogni giro, ma le ri-occorrenze
    // reali (eventi nuovi) restano come history. Niente più analisi manuale.
    let corr_pool = pg_pool.clone();
    tokio::spawn(async move {
        let engine = services::correlation_engine::CorrelationEngine::new(corr_pool);
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(15));
        loop {
            ticker.tick().await;
            match engine.analyze_correlations(1).await {
                Ok(c) => tracing::debug!("🔗 Correlazione automatica: {} valutate", c.len()),
                Err(e) => tracing::warn!("Errore correlazione automatica: {}", e),
            }
        }
    });
    tracing::info!("✅ Correlation engine started (automatico, ogni 15s)");

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
        .nest("/api/auth", api::auth::routes())
        .nest("/api/agents", api::agents::routes());

    // Protected routes (require authentication)
    let protected_routes = Router::new()
        .nest("/api/auth", api::auth::protected_routes())
        .nest("/api/targets", api::targets::routes())
        .nest("/api/auditd", api::auditd::routes())
        .nest("/api/hardening", api::hardening::routes())
        .nest("/api/monitoring", api::monitoring::routes())
        .nest("/api/compliance", api::compliance::routes())
        .nest("/api/compliance-frameworks", api::compliance_frameworks::routes())
        .nest("/api/alerts", api::alerts::routes())
        .nest("/api/settings", api::settings::routes())
        .nest("/api/api-keys", api::api_keys::routes())
        .nest("/api/integrations", api::integrations::routes())
        .nest("/api/events", api::security_events::routes())
        .nest("/api/plugins", api::plugins::routes())
        .route("/api/mcp", post(mcp::handle_mcp))
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
