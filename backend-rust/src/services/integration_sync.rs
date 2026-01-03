// ============================================================================
// CYBERSHEPPARD - Integration Synchronization Service
// ============================================================================

use sqlx::PgPool;
use tokio::time::{interval, Duration};
use crate::integrations::{SentinelCoreClient, FireDogClient};
use crate::utils::{BigDecimalExt, ToBigDecimal, ToIpNetwork};
use chrono::Utc;

pub struct IntegrationSyncService {
    sentinel_client: Option<SentinelCoreClient>,
    firedog_client: Option<FireDogClient>,
    pg_pool: PgPool,
    sync_interval_secs: u64,
}

impl IntegrationSyncService {
    pub fn new(
        sentinel_client: Option<SentinelCoreClient>,
        firedog_client: Option<FireDogClient>,
        pg_pool: PgPool,
        sync_interval_secs: u64,
    ) -> Self {
        Self {
            sentinel_client,
            firedog_client,
            pg_pool,
            sync_interval_secs,
        }
    }

    pub async fn start(self) {
        let mut ticker = interval(Duration::from_secs(self.sync_interval_secs));

        loop {
            ticker.tick().await;

            tracing::info!("Starting integration synchronization");

            if self.sentinel_client.is_some() {
                if let Err(e) = self.sync_vulnerabilities().await {
                    tracing::error!("Failed to sync vulnerabilities: {}", e);
                }
            }

            if self.firedog_client.is_some() {
                if let Err(e) = self.sync_threats().await {
                    tracing::error!("Failed to sync threats: {}", e);
                }
            }

            if let Err(e) = self.correlate_security_data().await {
                tracing::error!("Failed to correlate security data: {}", e);
            }

            tracing::info!("Integration synchronization complete");
        }
    }

    async fn sync_vulnerabilities(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let sentinel_client = match &self.sentinel_client {
            Some(client) => client,
            None => return Ok(()),
        };

        let started_at = Utc::now();
        let mut records_synced = 0;
        let mut records_failed = 0;

        let targets = sqlx::query!(
            r#"
            SELECT id, hostname, ip_address, sentinel_asset_id
            FROM targets
            WHERE is_active = true
            "#
        )
        .fetch_all(&self.pg_pool)
        .await?;

        for target in targets {
            if let Some(asset_id) = target.sentinel_asset_id {
                tracing::debug!("Syncing vulnerabilities for target {}", target.hostname);

                match sentinel_client.get_asset_vulnerabilities(asset_id).await {
                    Ok(vulnerabilities) => {
                        for vuln in vulnerabilities {
                            match sqlx::query!(
                                r#"
                                INSERT INTO sentinel_vulnerabilities (
                                    target_id, cve_id, title, description, severity,
                                    cvss_score, cvss_vector, epss_score,
                                    affected_packages, published_date, last_modified_date
                                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                                ON CONFLICT (target_id, cve_id) DO UPDATE SET
                                    title = EXCLUDED.title,
                                    description = EXCLUDED.description,
                                    severity = EXCLUDED.severity,
                                    cvss_score = EXCLUDED.cvss_score,
                                    cvss_vector = EXCLUDED.cvss_vector,
                                    epss_score = EXCLUDED.epss_score,
                                    affected_packages = EXCLUDED.affected_packages,
                                    last_modified_date = EXCLUDED.last_modified_date,
                                    updated_at = NOW()
                                "#,
                                target.id,
                                vuln.cve_id,
                                vuln.title,
                                vuln.description,
                                vuln.severity,
                                vuln.cvss_score.to_bigdecimal(),
                                vuln.cvss_vector,
                                vuln.epss_score.map(|s| s.to_bigdecimal()),
                                &vuln.affected_packages,
                                vuln.published_date,
                                vuln.last_modified_date
                            )
                            .execute(&self.pg_pool)
                            .await
                            {
                                Ok(_) => records_synced += 1,
                                Err(e) => {
                                    tracing::error!("Failed to insert vulnerability {}: {}", vuln.cve_id, e);
                                    records_failed += 1;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to get vulnerabilities for asset {}: {}", asset_id, e);
                        records_failed += 1;
                    }
                }
            }
        }

        let completed_at = Utc::now();
        let duration = (completed_at - started_at).num_milliseconds() as f64 / 1000.0;

        sqlx::query!(
            r#"
            INSERT INTO integration_sync_log (
                integration_name, sync_type, status, records_synced,
                records_failed, started_at, completed_at, duration_seconds
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
            "sentinel_core",
            "vulnerabilities",
            if records_failed == 0 { "success" } else { "partial" },
            records_synced,
            records_failed,
            started_at,
            completed_at,
            duration.to_bigdecimal()
        )
        .execute(&self.pg_pool)
        .await?;

        tracing::info!(
            "Synced {} vulnerabilities from Sentinel Core ({} failed)",
            records_synced, records_failed
        );

        Ok(())
    }

    async fn sync_threats(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let firedog_client = match &self.firedog_client {
            Some(client) => client,
            None => return Ok(()),
        };

        let started_at = Utc::now();
        let mut records_synced = 0;
        let mut records_failed = 0;

        match firedog_client.get_threats(Some(100), Some(false)).await {
            Ok(threats) => {
                for threat in threats {
                    let target = sqlx::query!(
                        "SELECT id FROM targets WHERE ip_address::text = $1",
                        threat.destination_ip
                    )
                    .fetch_optional(&self.pg_pool)
                    .await?;

                    if let Some(target) = target {
                        match sqlx::query!(
                            r#"
                            INSERT INTO firedog_threats (
                                target_id, firedog_threat_id, source_ip, destination_ip,
                                destination_port, threat_type, classification, score,
                                details, detected_at, acknowledged, acknowledged_by,
                                acknowledged_at
                            ) VALUES ($1, $2, $3::inet, $4::inet, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                            ON CONFLICT (firedog_threat_id) DO NOTHING
                            "#,
                            target.id,
                            threat.id,
                            threat.source_ip.to_ipnetwork(),
                            threat.destination_ip.to_ipnetwork(),
                            threat.destination_port,
                            threat.threat_type,
                            threat.classification,
                            threat.score.to_bigdecimal(),
                            threat.details,
                            threat.detected_at,
                            threat.acknowledged,
                            threat.acknowledged_by,
                            threat.acknowledged_at
                        )
                        .execute(&self.pg_pool)
                        .await
                        {
                            Ok(_) => records_synced += 1,
                            Err(e) => {
                                tracing::error!("Failed to insert threat {}: {}", threat.id, e);
                                records_failed += 1;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                tracing::error!("Failed to get threats from FireDog: {}", e);
                records_failed += 1;
            }
        }

        let completed_at = Utc::now();
        let duration = (completed_at - started_at).num_milliseconds() as f64 / 1000.0;

        sqlx::query!(
            r#"
            INSERT INTO integration_sync_log (
                integration_name, sync_type, status, records_synced,
                records_failed, started_at, completed_at, duration_seconds
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
            "firedog",
            "threats",
            if records_failed == 0 { "success" } else { "partial" },
            records_synced,
            records_failed,
            started_at,
            completed_at,
            duration.to_bigdecimal()
        )
        .execute(&self.pg_pool)
        .await?;

        tracing::info!(
            "Synced {} threats from FireDog ({} failed)",
            records_synced, records_failed
        );

        Ok(())
    }

    async fn correlate_security_data(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let correlations = sqlx::query!(
            r#"
            SELECT
                t.id as target_id,
                t.hostname,
                t.ip_address,
                v.cve_id,
                v.cvss_score,
                v.severity as vulnerability_severity,
                th.source_ip,
                th.threat_type,
                th.score as threat_score
            FROM targets t
            INNER JOIN sentinel_vulnerabilities v ON t.id = v.target_id
            INNER JOIN firedog_threats th ON t.id = th.target_id
            WHERE
                v.severity IN ('critical', 'high')
                AND th.score >= 7.0
                AND th.detected_at > NOW() - INTERVAL '24 hours'
                AND NOT EXISTS (
                    SELECT 1 FROM security_correlations sc
                    WHERE sc.target_id = t.id
                    AND sc.vulnerability_cve = v.cve_id
                    AND sc.threat_source_ip = th.source_ip::text::inet
                    AND sc.created_at > NOW() - INTERVAL '1 hour'
                )
            "#
        )
        .fetch_all(&self.pg_pool)
        .await?;

        for correlation in &correlations {
            let cvss = correlation.cvss_score.to_f64();
            let threat_score = correlation.threat_score.to_f64();

            let risk_level = if cvss >= 9.0 && threat_score >= 8.0 {
                "critical"
            } else if cvss >= 7.0 && threat_score >= 7.0 {
                "high"
            } else {
                "medium"
            };

            tracing::warn!(
                "HIGH-RISK CORRELATION: Target {} has vulnerability {} (CVSS {}) and active threat from {} (score {})",
                correlation.hostname,
                correlation.cve_id,
                cvss,
                correlation.source_ip,
                threat_score
            );

            sqlx::query!(
                r#"
                INSERT INTO security_correlations (
                    target_id, correlation_type, risk_level,
                    vulnerability_cve, vulnerability_cvss, vulnerability_severity,
                    threat_source_ip, threat_type, threat_score,
                    correlation_confidence, correlation_rule, recommended_action
                ) VALUES ($1, $2, $3, $4, $5, $6, $7::inet, $8, $9, $10, $11, $12)
                "#,
                correlation.target_id,
                "vuln_threat_match",
                risk_level,
                correlation.cve_id,
                correlation.cvss_score,
                correlation.vulnerability_severity,
                correlation.source_ip,
                correlation.threat_type,
                correlation.threat_score,
                0.90_f64.to_bigdecimal(),
                "Vulnerability + Active Threat",
                "Consider applying security patches immediately and blocking attacker IP in firewall"
            )
            .execute(&self.pg_pool)
            .await?;
        }

        if !correlations.is_empty() {
            tracing::info!("Created {} security correlations", correlations.len());
        }

        Ok(())
    }
}
