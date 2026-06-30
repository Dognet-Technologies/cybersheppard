// ============================================================================
// CYBERSHEPPARD - Alerting Service
// ============================================================================

use sqlx::PgPool;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct Alert {
    pub id: i32,
    pub severity: String,
    pub title: String,
    pub message: String,
    pub alert_type: String,
    pub status: String,
    pub acknowledged: bool,
    pub resolved: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateAlertRequest {
    pub severity: String,
    pub title: String,
    pub message: String,
    pub alert_type: String,
    pub entity_type: Option<String>,
    pub entity_id: Option<i32>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct AlertRule {
    pub id: i32,
    pub name: String,
    pub description: Option<String>,
    pub enabled: Option<bool>,  // Changed from bool
    pub severity: String,
    pub trigger_type: String,
}

pub struct AlertingService {
    pg_pool: PgPool,
}

impl AlertingService {
    pub fn new(pg_pool: PgPool) -> Self {
        Self { pg_pool }
    }

    pub async fn create_alert(
        &self,
        request: CreateAlertRequest,
    ) -> Result<i32, Box<dyn std::error::Error + Send + Sync>> {
        let result = sqlx::query!(
            r#"
            INSERT INTO alerts (
                severity, title, message, alert_type,
                entity_type, entity_id, metadata, status
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, 'new')
            RETURNING id
            "#,
            request.severity,
            request.title,
            request.message,
            request.alert_type,
            request.entity_type,
            request.entity_id,
            request.metadata
        )
        .fetch_one(&self.pg_pool)
        .await?;

        tracing::info!(
            "Created alert: {} (ID: {}, severity: {})",
            request.title,
            result.id,
            request.severity
        );

        Ok(result.id)
    }

    pub async fn get_alerts(
        &self,
        status: Option<String>,
        severity: Option<String>,
        limit: Option<i32>,
    ) -> Result<Vec<Alert>, Box<dyn std::error::Error + Send + Sync>> {
        let mut query = String::from(
            r#"
            SELECT id, severity, title, message, alert_type,
                   status, acknowledged, resolved, created_at
            FROM alerts
            WHERE 1=1
            "#
        );

        if let Some(ref s) = status {
            query.push_str(&format!(" AND status = '{}'", s));
        }

        if let Some(ref s) = severity {
            query.push_str(&format!(" AND severity = '{}'", s));
        }

        query.push_str(" ORDER BY created_at DESC");

        if let Some(l) = limit {
            query.push_str(&format!(" LIMIT {}", l));
        }

        let alerts = sqlx::query_as::<_, Alert>(&query)
            .fetch_all(&self.pg_pool)
            .await?;

        Ok(alerts)
    }

    pub async fn get_active_alerts(&self) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error + Send + Sync>> {
        let alerts = sqlx::query!(
            r#"
            SELECT
                a.id, a.severity, a.title, a.message, a.alert_type,
                a.status, a.acknowledged, a.created_at,
                ar.name as rule_name,
                COUNT(ad.id) as "delivery_attempts!: i64",
                COUNT(CASE WHEN ad.status = 'delivered' THEN ad.id END) as "successful_deliveries!: i64"
            FROM alerts a
            LEFT JOIN alert_rules ar ON a.rule_id = ar.id
            LEFT JOIN alert_deliveries ad ON a.id = ad.alert_id
            WHERE NOT a.resolved
            GROUP BY a.id, ar.name
            ORDER BY a.created_at DESC
            LIMIT 100
            "#
        )
        .fetch_all(&self.pg_pool)
        .await?;

        let result: Vec<serde_json::Value> = alerts
            .into_iter()
            .map(|row| {
                serde_json::json!({
                    "id": row.id,
                    "severity": row.severity,
                    "title": row.title,
                    "message": row.message,
                    "alert_type": row.alert_type,
                    "status": row.status,
                    "acknowledged": row.acknowledged,
                    "created_at": row.created_at,
                    "rule_name": row.rule_name,
                    "delivery_attempts": row.delivery_attempts,
                    "successful_deliveries": row.successful_deliveries,
                })
            })
            .collect();

        Ok(result)
    }

    pub async fn acknowledge_alert(
        &self,
        alert_id: i32,
        acknowledged_by: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        sqlx::query!(
            r#"
            UPDATE alerts
            SET
                acknowledged = true,
                acknowledged_by = $1,
                acknowledged_at = NOW(),
                status = 'acknowledged'
            WHERE id = $2
            "#,
            acknowledged_by,
            alert_id
        )
        .execute(&self.pg_pool)
        .await?;

        tracing::info!("Alert {} acknowledged by {}", alert_id, acknowledged_by);

        Ok(())
    }

    pub async fn resolve_alert(
        &self,
        alert_id: i32,
        resolved_by: &str,
        resolution_notes: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        sqlx::query!(
            r#"
            UPDATE alerts
            SET
                resolved = true,
                resolved_by = $1,
                resolved_at = NOW(),
                resolution_notes = $2,
                status = 'resolved'
            WHERE id = $3
            "#,
            resolved_by,
            resolution_notes,
            alert_id
        )
        .execute(&self.pg_pool)
        .await?;

        tracing::info!("Alert {} resolved by {}", alert_id, resolved_by);

        Ok(())
    }

    pub async fn get_alert_rules(&self) -> Result<Vec<AlertRule>, Box<dyn std::error::Error + Send + Sync>> {
        let rules = sqlx::query_as!(
            AlertRule,
            r#"
            SELECT id, name, description, enabled, severity, trigger_type
            FROM alert_rules
            WHERE enabled = true
            ORDER BY severity DESC, name
            "#
        )
        .fetch_all(&self.pg_pool)
        .await?;

        Ok(rules)
    }

    pub async fn trigger_violation_alert(
        &self,
        violation_id: i32,
        target_hostname: &str,
        metric_name: &str,
        severity: &str,
    ) -> Result<i32, Box<dyn std::error::Error + Send + Sync>> {
        let alert_id = self.create_alert(CreateAlertRequest {
            severity: severity.to_string(),
            title: format!("Compliance Violation on {}", target_hostname),
            message: format!(
                "Compliance violation detected: {} (severity: {})",
                metric_name, severity
            ),
            alert_type: "security_violation".to_string(),
            entity_type: Some("violation".to_string()),
            entity_id: Some(violation_id),
            metadata: Some(serde_json::json!({
                "target": target_hostname,
                "metric": metric_name,
            })),
        }).await?;

        sqlx::query!(
            r#"
            UPDATE compliance_violations
            SET alert_generated = true, alert_id = $1
            WHERE id = $2
            "#,
            alert_id,
            violation_id as i64
        )
        .execute(&self.pg_pool)
        .await?;

        Ok(alert_id)
    }

    pub async fn trigger_correlation_alert(
        &self,
        correlation_id: i32,
        target_hostname: &str,
        risk_level: &str,
    ) -> Result<i32, Box<dyn std::error::Error + Send + Sync>> {
        let alert_id = self.create_alert(CreateAlertRequest {
            severity: risk_level.to_string(),
            title: format!("Security Correlation on {}", target_hostname),
            message: format!(
                "High-risk security correlation detected (risk level: {})",
                risk_level
            ),
            alert_type: "threat_detected".to_string(),
            entity_type: Some("correlation".to_string()),
            entity_id: Some(correlation_id),
            metadata: Some(serde_json::json!({
                "target": target_hostname,
                "risk_level": risk_level,
            })),
        }).await?;

        Ok(alert_id)
    }
}
