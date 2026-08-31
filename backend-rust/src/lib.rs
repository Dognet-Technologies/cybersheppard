// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - Library crate
// ============================================================================
// Exposes the application's modules and the shared `AppState` so that both the
// binary (`src/main.rs`) and the integration tests (`tests/`) can import them
// via `cybersheppard_backend::...`. Without this library target, `tests/` files
// that reference the crate internals fail to compile (a binary crate is not
// importable).

pub mod api;
pub mod db;
pub mod integrations;
pub mod middleware;
pub mod models;
pub mod security_event;
pub mod services;
pub mod utils;
pub mod websocket;

use std::sync::Arc;

use crate::db::{influxdb::InfluxDbClient, postgresql::PostgresPool};
use crate::services::agent_registry::AgentRegistry;
use crate::services::anomaly_detection::AnomalyDetectionService;
use crate::services::baseline_calculator::BaselineCalculatorService;
use crate::services::compliance_scanner::ComplianceScanner;
use crate::services::correlation_engine::CorrelationEngine;
use crate::services::event_collector::EventCollectorService;
use crate::services::hardening_executor::HardeningExecutor;
use crate::websocket::alert_broadcaster::AlertBroadcaster;

/// Application state shared across handlers.
#[derive(Clone)]
pub struct AppState {
    pub pg_pool: PostgresPool,
    pub influx_client: InfluxDbClient,
    pub agent_registry: AgentRegistry,
    pub hardening_executor: Arc<HardeningExecutor>,
    pub compliance_scanner: Arc<ComplianceScanner>,
    pub event_collector: Arc<EventCollectorService>,
    pub correlation_engine: Arc<CorrelationEngine>,
    pub anomaly_detection: Arc<AnomalyDetectionService>,
    pub baseline_calculator: Arc<BaselineCalculatorService>,
    pub alert_broadcaster: Arc<AlertBroadcaster>,
}

/// Consente agli handler che estraggono `State<Arc<PgPool>>` di funzionare
/// dentro un router con stato `AppState`. `PgPool` è già reference-counted
/// internamente: il clone condivide lo stesso pool, l'Arc è solo un wrapper.
impl axum::extract::FromRef<AppState> for Arc<sqlx::PgPool> {
    fn from_ref(state: &AppState) -> Self {
        Arc::new(state.pg_pool.clone())
    }
}
