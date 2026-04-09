// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - Integration Clients
// ============================================================================

use crate::db::postgresql::PostgresPool;
use crate::utils::BigDecimalExt;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use bigdecimal::BigDecimal;
use ipnetwork::IpNetwork;

#[derive(Clone)]
pub struct IntegrationService {
    pg_pool: PostgresPool,
    http_client: Client,
}

#[derive(Debug, Deserialize)]
struct IntegrationConfig {
    service_name: String,
    base_url: String,
    api_key: Option<String>,
    is_enabled: Option<bool>,  // Changed from bool to Option<bool>
}

#[derive(Debug, Serialize, Deserialize)]
struct SentinelVulnerability {
    cve_id: String,
    severity: String,
    cvss_score: Option<BigDecimal>,  // Changed from f64
    epss_score: Option<BigDecimal>,  // Changed from f64
    description: Option<String>,
    published_date: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct FireDogThreat {
    threat_id: i32,
    source_ip: IpNetwork,  // Changed from String
    threat_type: String,
    classification: String,
    score: BigDecimal,  // Changed from i32
    details: Option<String>,
    detected_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl IntegrationService {
    pub fn new(pg_pool: PostgresPool) -> Self {
        Self {
            pg_pool,
            http_client: Client::new(),
        }
    }

    /// Load integration configuration
    async fn load_config(&self, service_name: &str) -> Result<IntegrationConfig, sqlx::Error> {
        sqlx::query_as!(
            IntegrationConfig,
            r#"
            SELECT service_name, base_url, api_key, is_enabled
            FROM integration_configs
            WHERE service_name = $1
            "#,
            service_name
        )
        .fetch_one(&self.pg_pool)
        .await
    }

    /// Sync vulnerabilities from Sentinel Core
    pub async fn sync_sentinel_vulnerabilities(
        &self,
        target_id: i32,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let config = self.load_config("sentinel_core").await?;

        if !config.is_enabled.unwrap_or(false) {
            return Ok(0);
        }

        let url = format!("{}/api/vulnerabilities?target_id={}", config.base_url, target_id);
        let mut request = self.http_client.get(&url);

        if let Some(api_key) = &config.api_key {
            request = request.header("Authorization", format!("Bearer {}", api_key));
        }

        let response = request.send().await?;
        let vulnerabilities: Vec<SentinelVulnerability> = response.json().await?;

        let mut synced_count = 0;

        for vuln in vulnerabilities {
            sqlx::query!(
                r#"
                INSERT INTO sentinel_vulnerabilities
                    (target_id, cve_id, severity, cvss_score, epss_score, description, published_date)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                ON CONFLICT (target_id, cve_id) DO UPDATE
                SET severity = EXCLUDED.severity,
                    cvss_score = EXCLUDED.cvss_score,
                    epss_score = EXCLUDED.epss_score,
                    description = EXCLUDED.description,
                    updated_at = NOW()
                "#,
                target_id,
                vuln.cve_id,
                vuln.severity,
                vuln.cvss_score,
                vuln.epss_score,
                vuln.description,
                vuln.published_date
            )
            .execute(&self.pg_pool)
            .await?;

            synced_count += 1;
        }

        // Log sync
        self.log_sync("sentinel_core", "vulnerability_sync", synced_count as i32, None).await?;

        tracing::info!("Synced {} vulnerabilities from Sentinel Core for target {}", synced_count, target_id);
        Ok(synced_count)
    }

    /// Sync threats from FireDog
    pub async fn sync_firedog_threats(
        &self,
        target_id: i32,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let config = self.load_config("firedog").await?;

        if !config.is_enabled.unwrap_or(false) {
            return Ok(0);
        }

        let url = format!("{}/api/threats?target_id={}", config.base_url, target_id);
        let mut request = self.http_client.get(&url);

        if let Some(api_key) = &config.api_key {
            request = request.header("Authorization", format!("Bearer {}", api_key));
        }

        let response = request.send().await?;
        let threats: Vec<FireDogThreat> = response.json().await?;

        let mut synced_count = 0;

        for threat in threats {
            sqlx::query!(
                r#"
                INSERT INTO firedog_threats
                    (target_id, firedog_threat_id, source_ip, threat_type, classification, score, details, detected_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                ON CONFLICT (firedog_threat_id) DO UPDATE
                SET threat_type = EXCLUDED.threat_type,
                    classification = EXCLUDED.classification,
                    score = EXCLUDED.score,
                    details = EXCLUDED.details
                "#,
                target_id,
                threat.threat_id,
                threat.source_ip,
                threat.threat_type,
                threat.classification,
                threat.score,
                threat.details,
                threat.detected_at
            )
            .execute(&self.pg_pool)
            .await?;

            synced_count += 1;
        }

        // Log sync
        self.log_sync("firedog", "threat_sync", synced_count as i32, None).await?;

        tracing::info!("Synced {} threats from FireDog for target {}", synced_count, target_id);
        Ok(synced_count)
    }

    /// Correlate vulnerabilities with threats
    pub async fn correlate_security_data(
        &self,
        target_id: i32,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        // Get recent vulnerabilities and threats
        let vulnerabilities = sqlx::query!(
            r#"
            SELECT cve_id, cvss_score
            FROM sentinel_vulnerabilities
            WHERE target_id = $1 AND cvss_score > 7.0
            "#,
            target_id
        )
        .fetch_all(&self.pg_pool)
        .await?;

        let threats = sqlx::query!(
            r#"
            SELECT source_ip, threat_type, score
            FROM firedog_threats
            WHERE target_id = $1 AND score > 70
            ORDER BY detected_at DESC
            LIMIT 100
            "#,
            target_id
        )
        .fetch_all(&self.pg_pool)
        .await?;

        let mut correlations_created = 0;

        // Simple correlation: high CVE + high threat score from same IP
        for vuln in &vulnerabilities {
            for threat in &threats {
                let confidence = calculate_correlation_confidence(
                    vuln.cvss_score.to_f64(),
                    threat.score.to_f64(),
                );

                if confidence > 0.5 {
                    let recommended_action = format!(
                        "High-priority: CVE {} (CVSS {:.1}) combined with threat from {} (score {}). Investigate immediately.",
                        vuln.cve_id,
                        vuln.cvss_score.to_f64(),
                        threat.source_ip,
                        threat.score.to_f64()
                    );

                    sqlx::query!(
                        r#"
                        INSERT INTO security_correlations
                            (target_id, vulnerability_cve, vulnerability_cvss, threat_source_ip,
                             threat_type, threat_score, correlation_confidence, recommended_action)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                        "#,
                        target_id,
                        vuln.cve_id,
                        vuln.cvss_score,
                        threat.source_ip,
                        threat.threat_type,
                        threat.score,
                        confidence as f32,
                        recommended_action
                    )
                    .execute(&self.pg_pool)
                    .await?;

                    correlations_created += 1;
                }
            }
        }

        tracing::info!("Created {} security correlations for target {}", correlations_created, target_id);
        Ok(correlations_created)
    }

    /// Log integration sync
    async fn log_sync(
        &self,
        integration_name: &str,
        sync_type: &str,
        records_fetched: i32,
        error_message: Option<String>,
    ) -> Result<(), sqlx::Error> {
        let status = if error_message.is_none() { "success" } else { "failed" };

        sqlx::query!(
            r#"
            INSERT INTO integration_sync_logs
                (integration_id, sync_type, status, records_fetched, error_message, completed_at)
            VALUES (
                (SELECT id FROM integration_configs WHERE service_name = $1),
                $2, $3, $4, $5, NOW()
            )
            "#,
            integration_name,
            sync_type,
            status,
            records_fetched,
            error_message
        )
        .execute(&self.pg_pool)
        .await?;

        Ok(())
    }
}

/// Calculate correlation confidence score
fn calculate_correlation_confidence(cvss_score: f64, threat_score: f64) -> f64 {
    let normalized_cvss = cvss_score / 10.0;
    let normalized_threat = threat_score / 100.0;

    (normalized_cvss * 0.6 + normalized_threat * 0.4).min(1.0)
}
