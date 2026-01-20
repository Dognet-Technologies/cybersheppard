// ============================================================================
// Correlation Engine - Advanced Event Correlation & Pattern Detection
// ============================================================================

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use serde_json::json;
use sqlx::PgPool;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::models::security_event::{
    AttackStage, CorrelationStatus, CorrelationType, EventCorrelation, SecurityEvent, Severity,
};

/// Correlation Engine - Detects attack patterns and sequences
pub struct CorrelationEngine {
    db: PgPool,
    // Configurable thresholds
    failed_login_threshold: i32,
    lateral_movement_window_minutes: i32,
    sequence_window_minutes: i32,
}

impl CorrelationEngine {
    pub fn new(db: PgPool) -> Self {
        Self {
            db,
            failed_login_threshold: 5,
            lateral_movement_window_minutes: 60,
            sequence_window_minutes: 30,
        }
    }

    /// Run correlation analysis on recent events
    pub async fn analyze_correlations(&self, hours: i32) -> Result<Vec<EventCorrelation>> {
        info!("Starting correlation analysis for last {} hours", hours);

        let mut correlations = Vec::new();

        // 1. Detect brute force attacks (failed logins)
        let brute_force = self.detect_brute_force_attacks(hours).await?;
        correlations.extend(brute_force);
        info!("Detected {} brute force patterns", correlations.len());

        // 2. Detect lateral movement patterns
        let lateral = self.detect_lateral_movement(hours).await?;
        correlations.extend(lateral);
        info!("Detected {} lateral movement patterns", correlations.len());

        // 3. Detect privilege escalation attempts
        let privesc = self.detect_privilege_escalation(hours).await?;
        correlations.extend(privesc);
        info!("Detected {} privilege escalation patterns", correlations.len());

        // 4. Detect data exfiltration patterns
        let exfil = self.detect_data_exfiltration(hours).await?;
        correlations.extend(exfil);
        info!("Detected {} data exfiltration patterns", correlations.len());

        // 5. Detect anomaly clusters (high anomaly scores)
        let anomaly_clusters = self.detect_anomaly_clusters(hours).await?;
        correlations.extend(anomaly_clusters);

        info!("Total correlations detected: {}", correlations.len());

        // Persist correlations to database
        for correlation in &correlations {
            self.save_correlation(correlation).await?;
        }

        Ok(correlations)
    }

    /// Detect brute force attack patterns
    /// Pattern: Multiple failed logins from same source to same user
    async fn detect_brute_force_attacks(&self, hours: i32) -> Result<Vec<EventCorrelation>> {
        let rows = sqlx::query!(
            r#"
            SELECT
                user_name,
                source_host,
                source_ip,
                COUNT(*) as failed_count,
                MIN(timestamp) as first_attempt,
                MAX(timestamp) as last_attempt,
                array_agg(DISTINCT event_type) as event_types
            FROM security_events
            WHERE event_category = 'authentication'
              AND severity IN ('high', 'medium')
              AND timestamp > NOW() - INTERVAL '1 hour' * $1
              AND (
                  event_data->>'result' LIKE '%fail%'
                  OR event_data->>'res' LIKE '%fail%'
              )
            GROUP BY user_name, source_host, source_ip
            HAVING COUNT(*) >= $2
            "#,
            hours,
            self.failed_login_threshold
        )
        .fetch_all(&self.db)
        .await?;

        let mut correlations = Vec::new();

        for row in rows {
            let failed_count = row.failed_count.unwrap_or(0);
            let confidence = Self::calculate_confidence(failed_count, 5, 20);
            let risk_score = Self::calculate_risk_score(failed_count as f64, 5.0, 20.0);

            let severity = if failed_count > 15 {
                Severity::Critical
            } else if failed_count > 10 {
                Severity::High
            } else {
                Severity::Medium
            };

            let user_name = row.user_name.unwrap_or_else(|| "unknown".to_string());
            let source_ip_str = row.source_ip.map(|ip: IpAddr| ip.to_string());

            let correlation = EventCorrelation {
                id: Uuid::new_v4(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
                correlation_type: CorrelationType::Frequency,
                pattern_name: Some("Brute Force Attack".to_string()),
                pattern_description: Some(format!(
                    "{} failed login attempts for user '{}' from {}",
                    failed_count,
                    user_name,
                    source_ip_str.as_ref().unwrap_or(&row.source_host)
                )),
                confidence,
                severity,
                risk_score: Some(risk_score),
                first_event_time: row.first_attempt.unwrap(),
                last_event_time: row.last_attempt.unwrap(),
                time_window_seconds: Some(
                    (row.last_attempt.unwrap() - row.first_attempt.unwrap())
                        .num_seconds() as i32,
                ),
                event_count: failed_count as i32,
                involved_users: vec![user_name.clone()],
                involved_hosts: vec![row.source_host.clone()],
                involved_ips: row.source_ip.into_iter().collect(),
                involved_processes: vec![],
                statistical_significance: None,
                anomaly_score: Some(risk_score),
                z_score: None,
                baseline_deviation_percent: None,
                correlation_data: Some(json!({
                    "failed_attempts": failed_count,
                    "event_types": row.event_types,
                    "target_user": user_name,
                    "source": source_ip_str.unwrap_or_else(|| row.source_host.clone()),
                })),
                attack_stage: Some(AttackStage::InitialAccess),
                status: CorrelationStatus::Active,
                resolved_at: None,
                resolution_notes: None,
                assigned_to: None,
                assigned_at: None,
            };

            correlations.push(correlation);
        }

        Ok(correlations)
    }

    /// Detect lateral movement patterns
    /// Pattern: Successful login on host A → Network connection to host B → Login on host B
    async fn detect_lateral_movement(&self, hours: i32) -> Result<Vec<EventCorrelation>> {
        // Query for authentication sequences across hosts
        let rows = sqlx::query!(
            r#"
            WITH auth_events AS (
                SELECT
                    user_name,
                    source_host,
                    destination_host,
                    timestamp,
                    event_type
                FROM security_events
                WHERE timestamp > NOW() - INTERVAL '1 hour' * $1
                  AND event_category IN ('authentication', 'network')
                  AND user_name IS NOT NULL
            ),
            host_sequences AS (
                SELECT
                    a1.user_name,
                    a1.source_host as host1,
                    a2.source_host as host2,
                    a1.timestamp as first_time,
                    a2.timestamp as second_time,
                    EXTRACT(EPOCH FROM (a2.timestamp - a1.timestamp)) / 60 as time_diff_minutes
                FROM auth_events a1
                JOIN auth_events a2 ON a1.user_name = a2.user_name
                WHERE a1.source_host != a2.source_host
                  AND a2.timestamp > a1.timestamp
                  AND a2.timestamp <= a1.timestamp + INTERVAL '1 hour'
            )
            SELECT
                user_name,
                host1,
                host2,
                first_time,
                second_time,
                time_diff_minutes,
                COUNT(*) as sequence_count
            FROM host_sequences
            GROUP BY user_name, host1, host2, first_time, second_time, time_diff_minutes
            HAVING COUNT(*) >= 2
            ORDER BY sequence_count DESC
            LIMIT 50
            "#,
            hours
        )
        .fetch_all(&self.db)
        .await?;

        let mut correlations = Vec::new();

        for row in rows {
            let user_name = row.user_name.unwrap_or_else(|| "unknown".to_string());
            let time_diff = row.time_diff_minutes.unwrap_or(0.0);

            // Suspicious if lateral movement is very quick (< 5 minutes)
            let is_suspicious = time_diff < 5.0;
            let confidence = if is_suspicious { 0.85 } else { 0.60 };

            let severity = if is_suspicious {
                Severity::High
            } else {
                Severity::Medium
            };

            let correlation = EventCorrelation {
                id: Uuid::new_v4(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
                correlation_type: CorrelationType::LateralMovement,
                pattern_name: Some("Lateral Movement Detected".to_string()),
                pattern_description: Some(format!(
                    "User '{}' moved from {} to {} in {:.1} minutes",
                    user_name,
                    row.host1.as_ref().unwrap_or(&"unknown".to_string()),
                    row.host2.as_ref().unwrap_or(&"unknown".to_string()),
                    time_diff
                )),
                confidence,
                severity,
                risk_score: Some(if is_suspicious { 85.0 } else { 60.0 }),
                first_event_time: row.first_time.unwrap(),
                last_event_time: row.second_time.unwrap(),
                time_window_seconds: Some((time_diff * 60.0) as i32),
                event_count: row.sequence_count.unwrap_or(0) as i32,
                involved_users: vec![user_name.clone()],
                involved_hosts: vec![
                    row.host1.unwrap_or_else(|| "unknown".to_string()),
                    row.host2.unwrap_or_else(|| "unknown".to_string()),
                ],
                involved_ips: vec![],
                involved_processes: vec![],
                statistical_significance: None,
                anomaly_score: None,
                z_score: None,
                baseline_deviation_percent: None,
                correlation_data: Some(json!({
                    "lateral_movement": {
                        "from_host": row.host1,
                        "to_host": row.host2,
                        "time_minutes": time_diff,
                        "is_suspicious": is_suspicious,
                        "sequence_count": row.sequence_count
                    }
                })),
                attack_stage: Some(AttackStage::LateralMovement),
                status: CorrelationStatus::Active,
                resolved_at: None,
                resolution_notes: None,
                assigned_to: None,
                assigned_at: None,
            };

            correlations.push(correlation);
        }

        Ok(correlations)
    }

    /// Detect privilege escalation attempts
    /// Pattern: Normal user → sudo/su commands → root access
    async fn detect_privilege_escalation(&self, hours: i32) -> Result<Vec<EventCorrelation>> {
        let rows = sqlx::query!(
            r#"
            SELECT
                user_name,
                source_host,
                COUNT(*) as escalation_count,
                MIN(timestamp) as first_attempt,
                MAX(timestamp) as last_attempt,
                array_agg(DISTINCT process_name) as processes,
                array_agg(DISTINCT process_cmdline) as commands
            FROM security_events
            WHERE timestamp > NOW() - INTERVAL '1 hour' * $1
              AND (
                  process_name LIKE '%sudo%'
                  OR process_name LIKE '%su%'
                  OR process_cmdline LIKE '%sudo%'
                  OR process_cmdline LIKE '%su %'
                  OR event_data->>'uid' = '0'
              )
              AND user_name IS NOT NULL
              AND user_name != 'root'
            GROUP BY user_name, source_host
            HAVING COUNT(*) >= 3
            "#,
            hours
        )
        .fetch_all(&self.db)
        .await?;

        let mut correlations = Vec::new();

        for row in rows {
            let user_name = row.user_name.unwrap_or_else(|| "unknown".to_string());
            let escalation_count = row.escalation_count.unwrap_or(0);

            let confidence = Self::calculate_confidence(escalation_count, 3, 10);
            let risk_score = Self::calculate_risk_score(escalation_count as f64, 3.0, 10.0);

            let severity = if escalation_count > 7 {
                Severity::Critical
            } else if escalation_count > 5 {
                Severity::High
            } else {
                Severity::Medium
            };

            let correlation = EventCorrelation {
                id: Uuid::new_v4(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
                correlation_type: CorrelationType::Sequence,
                pattern_name: Some("Privilege Escalation Attempt".to_string()),
                pattern_description: Some(format!(
                    "User '{}' attempted privilege escalation {} times on {}",
                    user_name, escalation_count, row.source_host
                )),
                confidence,
                severity,
                risk_score: Some(risk_score),
                first_event_time: row.first_attempt.unwrap(),
                last_event_time: row.last_attempt.unwrap(),
                time_window_seconds: Some(
                    (row.last_attempt.unwrap() - row.first_attempt.unwrap())
                        .num_seconds() as i32,
                ),
                event_count: escalation_count as i32,
                involved_users: vec![user_name.clone()],
                involved_hosts: vec![row.source_host.clone()],
                involved_ips: vec![],
                involved_processes: row.processes.unwrap_or_default(),
                statistical_significance: None,
                anomaly_score: Some(risk_score),
                z_score: None,
                baseline_deviation_percent: None,
                correlation_data: Some(json!({
                    "escalation_attempts": escalation_count,
                    "commands": row.commands,
                })),
                attack_stage: Some(AttackStage::PrivilegeEscalation),
                status: CorrelationStatus::Active,
                resolved_at: None,
                resolution_notes: None,
                assigned_to: None,
                assigned_at: None,
            };

            correlations.push(correlation);
        }

        Ok(correlations)
    }

    /// Detect data exfiltration patterns
    /// Pattern: Large data transfers to external IPs
    async fn detect_data_exfiltration(&self, hours: i32) -> Result<Vec<EventCorrelation>> {
        let rows = sqlx::query!(
            r#"
            SELECT
                user_name,
                source_host,
                destination_ip,
                COUNT(*) as transfer_count,
                SUM(bytes_sent) as total_bytes,
                MIN(timestamp) as first_transfer,
                MAX(timestamp) as last_transfer
            FROM security_events
            WHERE timestamp > NOW() - INTERVAL '1 hour' * $1
              AND event_category = 'network'
              AND bytes_sent IS NOT NULL
              AND bytes_sent > 1000000  -- > 1MB
              AND destination_ip IS NOT NULL
            GROUP BY user_name, source_host, destination_ip
            HAVING SUM(bytes_sent) > 10000000  -- > 10MB total
            "#,
            hours
        )
        .fetch_all(&self.db)
        .await?;

        let mut correlations = Vec::new();

        for row in rows {
            let total_mb = row.total_bytes.unwrap_or(0) as f64 / 1_000_000.0;
            let confidence = if total_mb > 100.0 { 0.80 } else { 0.60 };
            let risk_score = (total_mb / 10.0).min(100.0);

            let severity = if total_mb > 500.0 {
                Severity::Critical
            } else if total_mb > 100.0 {
                Severity::High
            } else {
                Severity::Medium
            };

            let dest_ip = row.destination_ip.map(|ip: IpAddr| ip.to_string());

            let correlation = EventCorrelation {
                id: Uuid::new_v4(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
                correlation_type: CorrelationType::DataExfiltration,
                pattern_name: Some("Potential Data Exfiltration".to_string()),
                pattern_description: Some(format!(
                    "Large data transfer: {:.2} MB sent to {}",
                    total_mb,
                    dest_ip.as_ref().unwrap_or(&"unknown".to_string())
                )),
                confidence,
                severity,
                risk_score: Some(risk_score),
                first_event_time: row.first_transfer.unwrap(),
                last_event_time: row.last_transfer.unwrap(),
                time_window_seconds: Some(
                    (row.last_transfer.unwrap() - row.first_transfer.unwrap())
                        .num_seconds() as i32,
                ),
                event_count: row.transfer_count.unwrap_or(0) as i32,
                involved_users: row
                    .user_name
                    .map(|u| vec![u])
                    .unwrap_or_default(),
                involved_hosts: vec![row.source_host.clone()],
                involved_ips: row.destination_ip.into_iter().collect(),
                involved_processes: vec![],
                statistical_significance: None,
                anomaly_score: Some(risk_score),
                z_score: None,
                baseline_deviation_percent: None,
                correlation_data: Some(json!({
                    "total_bytes": row.total_bytes,
                    "total_mb": total_mb,
                    "transfer_count": row.transfer_count,
                    "destination": dest_ip,
                })),
                attack_stage: Some(AttackStage::Exfiltration),
                status: CorrelationStatus::Active,
                resolved_at: None,
                resolution_notes: None,
                assigned_to: None,
                assigned_at: None,
            };

            correlations.push(correlation);
        }

        Ok(correlations)
    }

    /// Detect clusters of high anomaly scores
    async fn detect_anomaly_clusters(&self, hours: i32) -> Result<Vec<EventCorrelation>> {
        let rows = sqlx::query!(
            r#"
            SELECT
                source_host,
                user_name,
                COUNT(*) as anomaly_count,
                AVG(anomaly_score) as avg_anomaly,
                MAX(anomaly_score) as max_anomaly,
                MIN(timestamp) as first_anomaly,
                MAX(timestamp) as last_anomaly,
                array_agg(DISTINCT event_type) as event_types
            FROM security_events
            WHERE timestamp > NOW() - INTERVAL '1 hour' * $1
              AND anomaly_score > 50
            GROUP BY source_host, user_name
            HAVING COUNT(*) >= 5 AND AVG(anomaly_score) > 60
            "#,
            hours
        )
        .fetch_all(&self.db)
        .await?;

        let mut correlations = Vec::new();

        for row in rows {
            let avg_anomaly = row.avg_anomaly.unwrap_or(0.0);
            let confidence = (avg_anomaly / 100.0).min(1.0);

            let severity = if avg_anomaly > 80.0 {
                Severity::Critical
            } else if avg_anomaly > 70.0 {
                Severity::High
            } else {
                Severity::Medium
            };

            let correlation = EventCorrelation {
                id: Uuid::new_v4(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
                correlation_type: CorrelationType::Anomaly,
                pattern_name: Some("Anomaly Cluster".to_string()),
                pattern_description: Some(format!(
                    "Cluster of {} anomalies (avg score: {:.1}) on {}",
                    row.anomaly_count.unwrap_or(0),
                    avg_anomaly,
                    row.source_host
                )),
                confidence,
                severity,
                risk_score: Some(avg_anomaly),
                first_event_time: row.first_anomaly.unwrap(),
                last_event_time: row.last_anomaly.unwrap(),
                time_window_seconds: Some(
                    (row.last_anomaly.unwrap() - row.first_anomaly.unwrap())
                        .num_seconds() as i32,
                ),
                event_count: row.anomaly_count.unwrap_or(0) as i32,
                involved_users: row
                    .user_name
                    .map(|u| vec![u])
                    .unwrap_or_default(),
                involved_hosts: vec![row.source_host.clone()],
                involved_ips: vec![],
                involved_processes: vec![],
                statistical_significance: None,
                anomaly_score: Some(avg_anomaly),
                z_score: None,
                baseline_deviation_percent: None,
                correlation_data: Some(json!({
                    "anomaly_count": row.anomaly_count,
                    "avg_score": avg_anomaly,
                    "max_score": row.max_anomaly,
                    "event_types": row.event_types,
                })),
                attack_stage: None,
                status: CorrelationStatus::Active,
                resolved_at: None,
                resolution_notes: None,
                assigned_to: None,
                assigned_at: None,
            };

            correlations.push(correlation);
        }

        Ok(correlations)
    }

    /// Save correlation to database
    async fn save_correlation(&self, correlation: &EventCorrelation) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO event_correlations (
                id, created_at, updated_at,
                correlation_type, pattern_name, pattern_description,
                confidence, severity, risk_score,
                first_event_time, last_event_time, time_window_seconds, event_count,
                involved_users, involved_hosts, involved_ips, involved_processes,
                statistical_significance, anomaly_score, z_score, baseline_deviation_percent,
                correlation_data, attack_stage, status
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
                $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24
            )
            ON CONFLICT (id) DO UPDATE SET
                updated_at = EXCLUDED.updated_at,
                event_count = EXCLUDED.event_count,
                last_event_time = EXCLUDED.last_event_time
            "#,
            correlation.id,
            correlation.created_at,
            correlation.updated_at,
            correlation.correlation_type.to_string(),
            correlation.pattern_name,
            correlation.pattern_description,
            correlation.confidence,
            correlation.severity.to_string(),
            correlation.risk_score,
            correlation.first_event_time,
            correlation.last_event_time,
            correlation.time_window_seconds,
            correlation.event_count,
            &correlation.involved_users,
            &correlation.involved_hosts,
            &correlation.involved_ips.iter().map(|ip| ip.to_string()).collect::<Vec<_>>(),
            &correlation.involved_processes,
            correlation.statistical_significance,
            correlation.anomaly_score,
            correlation.z_score,
            correlation.baseline_deviation_percent,
            correlation.correlation_data,
            correlation.attack_stage.as_ref().map(|s| s.to_string()),
            correlation.status.to_string()
        )
        .execute(&self.db)
        .await?;

        Ok(())
    }

    /// Calculate confidence score (0.0 - 1.0)
    fn calculate_confidence(observed: i64, min_threshold: i64, max_threshold: i64) -> f64 {
        if observed < min_threshold {
            0.3
        } else if observed > max_threshold {
            0.95
        } else {
            0.5 + ((observed - min_threshold) as f64 / (max_threshold - min_threshold) as f64) * 0.45
        }
    }

    /// Calculate risk score (0 - 100)
    fn calculate_risk_score(observed: f64, min_threshold: f64, max_threshold: f64) -> f64 {
        let normalized = ((observed - min_threshold) / (max_threshold - min_threshold))
            .max(0.0)
            .min(1.0);
        normalized * 100.0
    }

    /// Get active correlations
    pub async fn get_active_correlations(&self, limit: i64) -> Result<Vec<EventCorrelation>> {
        let rows = sqlx::query!(
            r#"
            SELECT
                id, created_at, updated_at,
                correlation_type, pattern_name, pattern_description,
                confidence, severity, risk_score,
                first_event_time, last_event_time, time_window_seconds, event_count,
                involved_users, involved_hosts, involved_ips, involved_processes,
                statistical_significance, anomaly_score, z_score, baseline_deviation_percent,
                correlation_data, attack_stage, status,
                resolved_at, resolution_notes, assigned_to, assigned_at
            FROM event_correlations
            WHERE status = 'active'
            ORDER BY risk_score DESC NULLS LAST, created_at DESC
            LIMIT $1
            "#,
            limit
        )
        .fetch_all(&self.db)
        .await?;

        let correlations = rows
            .into_iter()
            .map(|row| {
                Ok(EventCorrelation {
                    id: row.id,
                    created_at: row.created_at,
                    updated_at: row.updated_at,
                    correlation_type: serde_json::from_str(&format!("\"{}\"", row.correlation_type))?,
                    pattern_name: row.pattern_name,
                    pattern_description: row.pattern_description,
                    confidence: row.confidence,
                    severity: serde_json::from_str(&format!("\"{}\"", row.severity))?,
                    risk_score: row.risk_score,
                    first_event_time: row.first_event_time,
                    last_event_time: row.last_event_time,
                    time_window_seconds: row.time_window_seconds,
                    event_count: row.event_count,
                    involved_users: row.involved_users,
                    involved_hosts: row.involved_hosts,
                    involved_ips: row
                        .involved_ips
                        .into_iter()
                        .filter_map(|s| s.parse::<IpAddr>().ok())
                        .collect(),
                    involved_processes: row.involved_processes,
                    statistical_significance: row.statistical_significance,
                    anomaly_score: row.anomaly_score,
                    z_score: row.z_score,
                    baseline_deviation_percent: row.baseline_deviation_percent,
                    correlation_data: row.correlation_data,
                    attack_stage: row
                        .attack_stage
                        .and_then(|s| serde_json::from_str(&format!("\"{}\"", s)).ok()),
                    status: serde_json::from_str(&format!("\"{}\"", row.status))?,
                    resolved_at: row.resolved_at,
                    resolution_notes: row.resolution_notes,
                    assigned_to: row.assigned_to,
                    assigned_at: row.assigned_at,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(correlations)
    }

    /// Get correlation statistics
    pub async fn get_correlation_stats(&self) -> Result<HashMap<String, i64>> {
        let rows = sqlx::query!(
            r#"
            SELECT
                correlation_type,
                COUNT(*) as count
            FROM event_correlations
            WHERE status = 'active'
            GROUP BY correlation_type
            "#
        )
        .fetch_all(&self.db)
        .await?;

        let mut stats = HashMap::new();
        for row in rows {
            stats.insert(row.correlation_type, row.count.unwrap_or(0));
        }

        Ok(stats)
    }
}
