// ============================================================================
// Security Events API - REST endpoints for event correlation system
// ============================================================================

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json,
    Router,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;

use crate::security_event::{EventCorrelation, SecurityEvent};
use crate::services::{
    anomaly_detection::AnomalyDetectionService,
    baseline_calculator::BaselineCalculatorService,
    correlation_engine::CorrelationEngine,
    event_collector::EventCollectorService,
};

/// Query parameters for event listing
#[derive(Debug, Deserialize)]
pub struct EventsQuery {
    #[serde(default = "default_hours")]
    hours: i32,
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    user: Option<String>,
}

fn default_hours() -> i32 {
    24
}

fn default_limit() -> i64 {
    100
}

/// API Response wrapper
#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

impl<T> ApiResponse<T> {
    fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    fn error(message: String) -> ApiResponse<()> {
        ApiResponse {
            success: false,
            data: None,
            error: Some(message),
        }
    }
}

/// GET /api/events - Get recent security events
pub async fn get_events(
    State(db): State<Arc<PgPool>>,
    Query(params): Query<EventsQuery>,
) -> Result<Json<ApiResponse<Vec<SecurityEvent>>>, StatusCode> {
    let collector = EventCollectorService::new((*db).clone(), String::new());

    match collector.get_recent_events(params.hours, params.limit).await {
        Ok(events) => Ok(Json(ApiResponse::success(events))),
        Err(e) => {
            tracing::error!("Failed to get events: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// GET /api/events/stats - Get event statistics
pub async fn get_event_stats(
    State(db): State<Arc<PgPool>>,
    Query(params): Query<EventsQuery>,
) -> Result<Json<ApiResponse<serde_json::Value>>, StatusCode> {
    let collector = EventCollectorService::new((*db).clone(), String::new());

    match collector.get_severity_stats(params.hours).await {
        Ok(stats) => {
            let response = serde_json::json!({
                "severity_breakdown": stats,
                "timeframe_hours": params.hours,
            });
            Ok(Json(ApiResponse::success(response)))
        }
        Err(e) => {
            tracing::error!("Failed to get event stats: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// GET /api/correlations - Get active correlations
pub async fn get_correlations(
    State(db): State<Arc<PgPool>>,
    Query(params): Query<EventsQuery>,
) -> Result<Json<ApiResponse<Vec<EventCorrelation>>>, StatusCode> {
    let engine = CorrelationEngine::new((*db).clone());

    match engine.get_active_correlations(params.limit).await {
        Ok(correlations) => Ok(Json(ApiResponse::success(correlations))),
        Err(e) => {
            tracing::error!("Failed to get correlations: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// GET /api/correlations/stats - Get correlation statistics
pub async fn get_correlation_stats(
    State(db): State<Arc<PgPool>>,
) -> Result<Json<ApiResponse<serde_json::Value>>, StatusCode> {
    let engine = CorrelationEngine::new((*db).clone());

    match engine.get_correlation_stats().await {
        Ok(stats) => {
            let response = serde_json::json!({
                "correlations_by_type": stats,
            });
            Ok(Json(ApiResponse::success(response)))
        }
        Err(e) => {
            tracing::error!("Failed to get correlation stats: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// POST /api/correlations/analyze - Run correlation analysis
#[derive(Debug, Deserialize)]
pub struct AnalyzeRequest {
    #[serde(default = "default_hours")]
    hours: i32,
}

pub async fn analyze_correlations(
    State(db): State<Arc<PgPool>>,
    Json(req): Json<AnalyzeRequest>,
) -> Result<Json<ApiResponse<serde_json::Value>>, StatusCode> {
    let engine = CorrelationEngine::new((*db).clone());

    match engine.analyze_correlations(req.hours).await {
        Ok(correlations) => {
            let response = serde_json::json!({
                "analyzed_hours": req.hours,
                "correlations_found": correlations.len(),
                "correlations": correlations,
            });
            Ok(Json(ApiResponse::success(response)))
        }
        Err(e) => {
            tracing::error!("Failed to analyze correlations: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// POST /api/baselines/calculate - Calculate baselines
#[derive(Debug, Deserialize)]
pub struct CalculateBaselinesRequest {
    #[serde(default = "default_baseline_days")]
    days: i32,
}

fn default_baseline_days() -> i32 {
    30
}

pub async fn calculate_baselines(
    State(db): State<Arc<PgPool>>,
    Json(req): Json<CalculateBaselinesRequest>,
) -> Result<Json<ApiResponse<serde_json::Value>>, StatusCode> {
    let calculator = BaselineCalculatorService::new((*db).clone());

    match calculator.calculate_all_baselines(req.days).await {
        Ok(_) => {
            let response = serde_json::json!({
                "status": "completed",
                "days_analyzed": req.days,
            });
            Ok(Json(ApiResponse::success(response)))
        }
        Err(e) => {
            tracing::error!("Failed to calculate baselines: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// POST /api/anomalies/detect - Detect anomalies
pub async fn detect_anomalies(
    State(db): State<Arc<PgPool>>,
    Query(params): Query<EventsQuery>,
) -> Result<Json<ApiResponse<serde_json::Value>>, StatusCode> {
    let detector = AnomalyDetectionService::new((*db).clone());

    match detector.analyze_recent_events(params.hours).await {
        Ok(anomalies) => {
            let response = serde_json::json!({
                "analyzed_hours": params.hours,
                "anomalies_found": anomalies.len(),
                "anomalies": anomalies,
            });
            Ok(Json(ApiResponse::success(response)))
        }
        Err(e) => {
            tracing::error!("Failed to detect anomalies: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// GET /api/hosts/:host_name/risk - Get host risk score
pub async fn get_host_risk(
    State(db): State<Arc<PgPool>>,
    Path(host_name): Path<String>,
) -> Result<Json<ApiResponse<serde_json::Value>>, StatusCode> {
    let row = sqlx::query!(
        r#"
        SELECT
            host_name,
            anomaly_risk,
            vulnerability_risk,
            compliance_risk,
            threat_risk,
            total_risk_score,
            risk_level,
            active_alerts,
            critical_alerts,
            failed_compliance_controls,
            known_vulnerabilities,
            compromise_probability,
            compromise_indicators,
            last_calculated,
            asset_criticality,
            is_critical_asset
        FROM host_risk_scores
        WHERE host_name = $1
        "#,
        host_name
    )
    .fetch_optional(&*db)
    .await;

    match row {
        Ok(Some(row)) => {
            let response = serde_json::json!({
                "host_name": row.host_name,
                "risk_components": {
                    "anomaly_risk": row.anomaly_risk,
                    "vulnerability_risk": row.vulnerability_risk,
                    "compliance_risk": row.compliance_risk,
                    "threat_risk": row.threat_risk,
                },
                "total_risk_score": row.total_risk_score,
                "risk_level": row.risk_level,
                "indicators": {
                    "active_alerts": row.active_alerts,
                    "critical_alerts": row.critical_alerts,
                    "failed_compliance": row.failed_compliance_controls,
                    "vulnerabilities": row.known_vulnerabilities,
                },
                "compromise": {
                    "probability": row.compromise_probability,
                    "indicators": row.compromise_indicators,
                },
                "asset": {
                    "criticality": row.asset_criticality,
                    "is_critical": row.is_critical_asset,
                },
                "last_calculated": row.last_calculated,
            });
            Ok(Json(ApiResponse::success(response)))
        }
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(e) => {
            tracing::error!("Failed to get host risk: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// GET /api/alerts/active - Get active high-risk alerts
pub async fn get_active_alerts(
    State(db): State<Arc<PgPool>>,
    Query(params): Query<EventsQuery>,
) -> Result<Json<ApiResponse<serde_json::Value>>, StatusCode> {
    let rows = sqlx::query!(
        r#"
        SELECT
            c.id,
            c.correlation_type,
            c.pattern_name,
            c.pattern_description,
            c.severity,
            c.confidence,
            c.risk_score,
            c.event_count,
            c.involved_users,
            c.involved_hosts,
            c.attack_stage,
            c.created_at,
            p.predictions
        FROM event_correlations c
        LEFT JOIN lateral_movement_predictions p ON c.id = p.correlation_id AND p.status = 'active'
        WHERE c.status = 'active'
          AND (c.severity IN ('critical', 'high') OR c.risk_score > 60)
        ORDER BY c.risk_score DESC NULLS LAST, c.created_at DESC
        LIMIT $1
        "#,
        params.limit
    )
    .fetch_all(&*db)
    .await;

    match rows {
        Ok(rows) => {
            let alerts: Vec<serde_json::Value> = rows
                .into_iter()
                .map(|row| {
                    serde_json::json!({
                        "id": row.id,
                        "type": row.correlation_type,
                        "pattern": row.pattern_name,
                        "description": row.pattern_description,
                        "severity": row.severity,
                        "confidence": row.confidence,
                        "risk_score": row.risk_score,
                        "event_count": row.event_count,
                        "involved_users": row.involved_users,
                        "involved_hosts": row.involved_hosts,
                        "attack_stage": row.attack_stage,
                        "created_at": row.created_at,
                        "predictions": row.predictions,
                    })
                })
                .collect();

            let response = serde_json::json!({
                "active_alerts": alerts.len(),
                "alerts": alerts,
            });

            Ok(Json(ApiResponse::success(response)))
        }
        Err(e) => {
            tracing::error!("Failed to get active alerts: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// GET /api/dashboard/metrics - Get dashboard metrics
pub async fn get_dashboard_metrics(
    State(db): State<Arc<PgPool>>,
    Query(params): Query<EventsQuery>,
) -> Result<Json<ApiResponse<serde_json::Value>>, StatusCode> {
    // Event count by severity
    let event_stats = sqlx::query!(
        r#"
        SELECT severity, COUNT(*) as count
        FROM security_events
        WHERE timestamp > NOW() - INTERVAL '1 hour' * $1
        GROUP BY severity
        "#,
        params.hours as f64
    )
    .fetch_all(&*db)
    .await;

    // Correlation stats
    let correlation_stats = sqlx::query!(
        r#"
        SELECT correlation_type, COUNT(*) as count
        FROM event_correlations
        WHERE status = 'active'
        GROUP BY correlation_type
        "#
    )
    .fetch_all(&*db)
    .await;

    // High-risk hosts
    let high_risk_hosts = sqlx::query!(
        r#"
        SELECT host_name, total_risk_score, risk_level
        FROM host_risk_scores
        WHERE total_risk_score > 60
        ORDER BY total_risk_score DESC
        LIMIT 10
        "#
    )
    .fetch_all(&*db)
    .await;

    match (event_stats, correlation_stats, high_risk_hosts) {
        (Ok(events), Ok(correlations), Ok(hosts)) => {
            let response = serde_json::json!({
                "timeframe_hours": params.hours,
                "events_by_severity": events.into_iter().map(|r| {
                    serde_json::json!({
                        "severity": r.severity,
                        "count": r.count.unwrap_or(0)
                    })
                }).collect::<Vec<_>>(),
                "correlations_by_type": correlations.into_iter().map(|r| {
                    serde_json::json!({
                        "type": r.correlation_type,
                        "count": r.count.unwrap_or(0)
                    })
                }).collect::<Vec<_>>(),
                "high_risk_hosts": hosts.into_iter().map(|r| {
                    serde_json::json!({
                        "host": r.host_name,
                        "risk_score": r.total_risk_score,
                        "risk_level": r.risk_level
                    })
                }).collect::<Vec<_>>(),
            });

            Ok(Json(ApiResponse::success(response)))
        }
        _ => {
            tracing::error!("Failed to get dashboard metrics");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
/// Build security events API routes
pub fn routes() -> Router<crate::AppState> {
    Router::new()
        // Event queries
        .route("/", get(get_events))
        .route("/stats", get(get_event_stats))
        
        // Correlation queries
        .route("/correlations", get(get_correlations))
        .route("/correlations/stats", get(get_correlation_stats))
        .route("/correlations/analyze", post(analyze_correlations))
        
        // Baseline and anomaly detection
        .route("/baselines/calculate", post(calculate_baselines))
        .route("/anomalies/detect", post(detect_anomalies))
        
        // Risk assessment
        .route("/hosts/:host_name/risk", get(get_host_risk))
        
        // Active alerts and dashboard
        .route("/alerts/active", get(get_active_alerts))
        .route("/dashboard/metrics", get(get_dashboard_metrics))
}
