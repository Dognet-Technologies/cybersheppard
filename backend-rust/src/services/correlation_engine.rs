// ============================================================================
// CYBERSHEPPARD - Security Correlation Engine
// ============================================================================

use sqlx::PgPool;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use bigdecimal::BigDecimal;

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct SecurityCorrelation {
    pub id: Option<i32>,
    pub target_id: i32,
    pub target_hostname: Option<String>,
    pub correlation_type: Option<String>,
    pub risk_level: Option<String>,
    pub vulnerability_cve: Option<String>,
    pub vulnerability_cvss: Option<BigDecimal>,
    pub threat_source_ip: Option<String>,
    pub threat_type: Option<String>,
    pub threat_score: Option<BigDecimal>,
    pub correlation_confidence: Option<BigDecimal>,
    pub recommended_action: Option<String>,
    pub status: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
}

pub struct CorrelationEngine {
    pg_pool: PgPool,
}

impl CorrelationEngine {
    pub fn new(pg_pool: PgPool) -> Self {
        Self { pg_pool }
    }

    pub async fn analyze_correlations(&self) -> Result<Vec<SecurityCorrelation>, Box<dyn std::error::Error + Send + Sync>> {
        let mut correlations = Vec::new();

        let vuln_threat_matches = self.find_vulnerability_threat_matches().await?;
        correlations.extend(vuln_threat_matches);

        Ok(correlations)
    }

    pub async fn get_active_correlations(&self) -> Result<Vec<SecurityCorrelation>, Box<dyn std::error::Error + Send + Sync>> {
        let correlations = sqlx::query_as!(
            SecurityCorrelation,
            r#"
            SELECT
                sc.id,
                sc.target_id,
                t.hostname as target_hostname,
                sc.correlation_type,
                sc.risk_level,
                sc.vulnerability_cve,
                sc.vulnerability_cvss,
                sc.threat_source_ip::text as threat_source_ip,
                sc.threat_type,
                sc.threat_score,
                sc.correlation_confidence,
                sc.recommended_action,
                sc.status,
                sc.created_at
            FROM security_correlations sc
            INNER JOIN targets t ON sc.target_id = t.id
            WHERE sc.status != 'resolved'
            ORDER BY
                sc.created_at DESC,
                CASE sc.risk_level
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                END
            "#
        )
        .fetch_all(&self.pg_pool)
        .await?;

        Ok(correlations)
    }

    pub async fn get_correlations_by_target(&self, target_id: i32) -> Result<Vec<SecurityCorrelation>, Box<dyn std::error::Error + Send + Sync>> {
        let correlations = sqlx::query_as!(
            SecurityCorrelation,
            r#"
            SELECT
                sc.id,
                sc.target_id,
                t.hostname as target_hostname,
                sc.correlation_type,
                sc.risk_level,
                sc.vulnerability_cve,
                sc.vulnerability_cvss,
                sc.threat_source_ip::text as threat_source_ip,
                sc.threat_type,
                sc.threat_score,
                sc.correlation_confidence,
                sc.recommended_action,
                sc.status,
                sc.created_at
            FROM security_correlations sc
            INNER JOIN targets t ON sc.target_id = t.id
            WHERE sc.target_id = $1
            ORDER BY sc.created_at DESC
            "#,
            target_id
        )
        .fetch_all(&self.pg_pool)
        .await?;

        Ok(correlations)
    }

    pub async fn acknowledge_correlation(&self, correlation_id: i32, acknowledged_by: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        sqlx::query!(
            r#"
            UPDATE security_correlations
            SET
                acknowledged = true,
                acknowledged_by = $1,
                acknowledged_at = NOW(),
                status = 'acknowledged',
                updated_at = NOW()
            WHERE id = $2
            "#,
            acknowledged_by,
            correlation_id
        )
        .execute(&self.pg_pool)
        .await?;

        Ok(())
    }

    pub async fn resolve_correlation(&self, correlation_id: i32, resolved_by: &str, resolution_notes: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        sqlx::query!(
            r#"
            UPDATE security_correlations
            SET
                resolved = true,
                resolved_by = $1,
                resolved_at = NOW(),
                resolution_notes = $2,
                status = 'resolved',
                updated_at = NOW()
            WHERE id = $3
            "#,
            resolved_by,
            resolution_notes,
            correlation_id
        )
        .execute(&self.pg_pool)
        .await?;

        Ok(())
    }

    async fn find_vulnerability_threat_matches(&self) -> Result<Vec<SecurityCorrelation>, Box<dyn std::error::Error + Send + Sync>> {
        let matches = sqlx::query_as!(
            SecurityCorrelation,
            r#"
            SELECT
                -1 as id,
                t.id as target_id,
                t.hostname as target_hostname,
                'vuln_threat_match' as correlation_type,
                CASE
                    WHEN v.cvss_score >= 9.0 AND th.score >= 8.0 THEN 'critical'
                    WHEN v.cvss_score >= 7.0 AND th.score >= 7.0 THEN 'high'
                    ELSE 'medium'
                END as risk_level,
                v.cve_id as vulnerability_cve,
                v.cvss_score as vulnerability_cvss,
                th.source_ip::text as threat_source_ip,
                th.threat_type,
                th.score as threat_score,
                0.90::real as correlation_confidence,
                'Apply security patches immediately and block attacker IP in firewall' as recommended_action,
                'new' as status,
                NOW() as created_at
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

        Ok(matches)
    }
}
