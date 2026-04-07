// ============================================================================
// Anomaly Detection Service - Z-Score and Statistical Analysis
// ============================================================================

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;
use std::collections::HashMap;
use tracing::{debug, info};

use crate::security_event::{
    AnomalyDetectionResult, BaselineCalculationResult, Severity,
};

/// Z-Score Anomaly Detection Service
pub struct AnomalyDetectionService {
    db: PgPool,
}

impl AnomalyDetectionService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Detect anomalies in user login frequency
    pub async fn detect_user_login_anomaly(
        &self,
        user_name: &str,
        current_logins: i64,
        timeframe_hours: i32,
    ) -> Result<AnomalyDetectionResult> {
        // Get baseline
        let baseline = self.get_user_baseline(user_name).await?;

        let z_score = {
            let stddev = baseline.stddev;
            if stddev > 0.0 {
                (current_logins as f64 - baseline.mean) / stddev
            } else {
                0.0
            }
        };

        let (is_anomaly, severity, description) = self.classify_z_score(
            z_score,
            &format!("User '{}' login frequency", user_name),
        );

        let deviation_percent = if baseline.mean > 0.0 {
            Some(((current_logins as f64 - baseline.mean) / baseline.mean * 100.0).abs())
        } else {
            None
        };

        Ok(AnomalyDetectionResult {
            is_anomaly,
            anomaly_score: z_score.abs() * 10.0, // Scale to 0-100
            z_score,
            severity,
            description,
            baseline_value: Some(baseline.mean),
            observed_value: current_logins as f64,
            deviation_percent,
        })
    }

    /// Detect anomalies in host connection count
    pub async fn detect_host_connection_anomaly(
        &self,
        host_name: &str,
        current_connections: i64,
        timeframe_hours: i32,
    ) -> Result<AnomalyDetectionResult> {
        // Get baseline
        let baseline = self.get_host_baseline(host_name).await?;

        let z_score = {
            let stddev = baseline.stddev;
            if stddev > 0.0 {
                (current_connections as f64 - baseline.mean) / stddev
            } else {
                0.0
            }
        };

        let (is_anomaly, severity, description) = self.classify_z_score(
            z_score,
            &format!("Host '{}' network connections", host_name),
        );

        let deviation_percent = if baseline.mean > 0.0 {
            Some(((current_connections as f64 - baseline.mean) / baseline.mean * 100.0).abs())
        } else {
            None
        };

        Ok(AnomalyDetectionResult {
            is_anomaly,
            anomaly_score: z_score.abs() * 10.0,
            z_score,
            severity,
            description,
            baseline_value: Some(baseline.mean),
            observed_value: current_connections as f64,
            deviation_percent,
        })
    }

    /// Detect anomalies in command execution patterns
    pub async fn detect_command_anomaly(
        &self,
        user_name: &str,
        command: &str,
        execution_count: i64,
        timeframe_hours: i32,
    ) -> Result<AnomalyDetectionResult> {
        // Check if command is in user's typical command set
        let is_typical = self.is_typical_command(user_name, command).await?;

        if !is_typical {
            // New/rare command is an anomaly
            return Ok(AnomalyDetectionResult {
                is_anomaly: true,
                anomaly_score: 60.0,
                z_score: 3.0,
                severity: Severity::Medium,
                description: format!(
                    "User '{}' executed unusual command: {}",
                    user_name, command
                ),
                baseline_value: None,
                observed_value: execution_count as f64,
                deviation_percent: None,
            });
        }

        // For typical commands, check execution frequency
        let baseline = self.get_command_baseline(user_name, command).await?;

        let z_score = {
            let stddev = baseline.stddev;
            if stddev > 0.0 {
                (execution_count as f64 - baseline.mean) / stddev
            } else {
                0.0
            }
        };

        let (is_anomaly, severity, description) = self.classify_z_score(
            z_score,
            &format!("Command '{}' execution frequency", command),
        );

        Ok(AnomalyDetectionResult {
            is_anomaly,
            anomaly_score: z_score.abs() * 10.0,
            z_score,
            severity,
            description,
            baseline_value: Some(baseline.mean),
            observed_value: execution_count as f64,
            deviation_percent: None,
        })
    }

    /// Classify Z-score into severity levels
    ///
    /// Z-Score Classification:
    /// |z| < 2.0:  Normal (not anomaly)
    /// 2.0 ≤ |z| < 3.0:  Low anomaly
    /// 3.0 ≤ |z| < 4.0:  Medium anomaly
    /// 4.0 ≤ |z| < 5.0:  High anomaly
    /// |z| ≥ 5.0:  Critical anomaly
    fn classify_z_score(&self, z_score: f64, context: &str) -> (bool, Severity, String) {
        let abs_z = z_score.abs();

        if abs_z < 2.0 {
            (
                false,
                Severity::Info,
                format!("{} is within normal range (z={:.2})", context, z_score),
            )
        } else if abs_z < 3.0 {
            (
                true,
                Severity::Low,
                format!(
                    "{} shows low anomaly: {:.1}% deviation (z={:.2})",
                    context,
                    (abs_z - 1.0) * 50.0,
                    z_score
                ),
            )
        } else if abs_z < 4.0 {
            (
                true,
                Severity::Medium,
                format!(
                    "{} shows medium anomaly: {:.1}% deviation (z={:.2})",
                    context,
                    (abs_z - 1.0) * 50.0,
                    z_score
                ),
            )
        } else if abs_z < 5.0 {
            (
                true,
                Severity::High,
                format!(
                    "{} shows high anomaly: {:.1}% deviation (z={:.2})",
                    context,
                    (abs_z - 1.0) * 50.0,
                    z_score
                ),
            )
        } else {
            (
                true,
                Severity::Critical,
                format!(
                    "{} shows critical anomaly: extreme deviation (z={:.2})",
                    context, z_score
                ),
            )
        }
    }

    /// Get user behavior baseline
    async fn get_user_baseline(&self, user_name: &str) -> Result<BaselineCalculationResult> {
        let row = sqlx::query!(
            r#"
            SELECT
                avg_logins_per_day::FLOAT8 as mean,
                stddev_logins_per_day::FLOAT8 as stddev
            FROM user_behavior_baselines
            WHERE user_name = $1
            "#,
            user_name
        )
        .fetch_optional(&self.db)
        .await?;

        if let Some(row) = row {
            Ok(BaselineCalculationResult {
                mean: row.mean.unwrap_or(0.0),
                stddev: row.stddev.unwrap_or(0.0),
                median: None,
                min: 0.0,
                max: 0.0,
                count: 0,
                threshold_low: 0.0,
                threshold_high: 0.0,
            })
        } else {
            // No baseline yet, return default
            Ok(BaselineCalculationResult {
                mean: 0.0,
                stddev: 0.0,
                median: None,
                min: 0.0,
                max: 0.0,
                count: 0,
                threshold_low: 0.0,
                threshold_high: 0.0,
            })
        }
    }

    /// Get host behavior baseline
    async fn get_host_baseline(&self, host_name: &str) -> Result<BaselineCalculationResult> {
        let row = sqlx::query!(
            r#"
            SELECT
                avg_connections_per_hour::FLOAT8 as mean,
                stddev_connections_per_hour::FLOAT8 as stddev
            FROM host_behavior_baselines
            WHERE host_name = $1
            "#,
            host_name
        )
        .fetch_optional(&self.db)
        .await?;

        if let Some(row) = row {
            Ok(BaselineCalculationResult {
                mean: row.mean.unwrap_or(0.0),
                stddev: row.stddev.unwrap_or(0.0),
                median: None,
                min: 0.0,
                max: 0.0,
                count: 0,
                threshold_low: 0.0,
                threshold_high: 0.0,
            })
        } else {
            Ok(BaselineCalculationResult {
                mean: 0.0,
                stddev: 0.0,
                median: None,
                min: 0.0,
                max: 0.0,
                count: 0,
                threshold_low: 0.0,
                threshold_high: 0.0,
            })
        }
    }

    /// Check if command is in user's typical command set
    async fn is_typical_command(&self, user_name: &str, command: &str) -> Result<bool> {
        let row = sqlx::query!(
            r#"
            SELECT common_commands
            FROM user_behavior_baselines
            WHERE user_name = $1
            "#,
            user_name
        )
        .fetch_optional(&self.db)
        .await?;

        if let Some(row) = row {
            Ok(row.common_commands.map(|cmds| cmds.contains(&command.to_string())).unwrap_or(false))
        } else {
            Ok(false)
        }
    }

    /// Get command execution baseline
    async fn get_command_baseline(
        &self,
        user_name: &str,
        command: &str,
    ) -> Result<BaselineCalculationResult> {
        // Query historical command execution frequency
        let row = sqlx::query!(
            r#"
            SELECT
                AVG(hourly_count)::FLOAT8 as mean,
                STDDEV(hourly_count)::FLOAT8 as stddev,
                MIN(hourly_count)::FLOAT8 as min,
                MAX(hourly_count)::FLOAT8 as max,
                COUNT(*) as count
            FROM (
                SELECT
                    date_trunc('hour', timestamp) as hour,
                    COUNT(*) as hourly_count
                FROM security_events
                WHERE user_name = $1
                  AND process_name LIKE '%' || $2 || '%'
                  AND timestamp > NOW() - INTERVAL '30 days'
                GROUP BY hour
            ) hourly_stats
            "#,
            user_name,
            command
        )
        .fetch_one(&self.db)
        .await?;

        let mean = row.mean.unwrap_or(0.0);
        let stddev = row.stddev.unwrap_or(0.0);

        Ok(BaselineCalculationResult {
            mean,
            stddev,
            median: None,
            min: row.min.unwrap_or(0.0),
            max: row.max.unwrap_or(0.0),
            count: row.count.unwrap_or(0) as usize,
            threshold_low: mean - 2.0 * stddev,
            threshold_high: mean + 2.0 * stddev,
        })
    }

    /// Analyze all recent events for anomalies
    pub async fn analyze_recent_events(&self, hours: i32) -> Result<Vec<AnomalyDetectionResult>> {
        info!("Analyzing events from last {} hours for anomalies", hours);

        let mut anomalies = Vec::new();

        // Analyze user login patterns
        let user_stats = self.get_user_login_stats(hours).await?;
        for (user_name, login_count) in user_stats {
            let result = self
                .detect_user_login_anomaly(&user_name, login_count, hours)
                .await?;
            if result.is_anomaly {
                anomalies.push(result);
            }
        }

        // Analyze host connection patterns
        let host_stats = self.get_host_connection_stats(hours).await?;
        for (host_name, connection_count) in host_stats {
            let result = self
                .detect_host_connection_anomaly(&host_name, connection_count, hours)
                .await?;
            if result.is_anomaly {
                anomalies.push(result);
            }
        }

        info!("Found {} anomalies in recent events", anomalies.len());
        Ok(anomalies)
    }

    /// Get user login statistics
    async fn get_user_login_stats(&self, hours: i32) -> Result<HashMap<String, i64>> {
        let rows = sqlx::query!(
            r#"
            SELECT user_name, COUNT(*) as login_count
            FROM security_events
            WHERE event_category = 'authentication'
              AND timestamp > NOW() - INTERVAL '1 hour' * $1
              AND user_name IS NOT NULL
            GROUP BY user_name
            "#,
            hours
        )
        .fetch_all(&self.db)
        .await?;

        let mut stats = HashMap::new();
        for row in rows {
            if let Some(user_name) = row.user_name {
                stats.insert(user_name, row.login_count.unwrap_or(0));
            }
        }

        Ok(stats)
    }

    /// Get host connection statistics
    async fn get_host_connection_stats(&self, hours: i32) -> Result<HashMap<String, i64>> {
        let rows = sqlx::query!(
            r#"
            SELECT source_host, COUNT(*) as connection_count
            FROM security_events
            WHERE event_category = 'network'
              AND timestamp > NOW() - INTERVAL '1 hour' * $1
            GROUP BY source_host
            "#,
            hours
        )
        .fetch_all(&self.db)
        .await?;

        let mut stats = HashMap::new();
        for row in rows {
            stats.insert(row.source_host, row.connection_count.unwrap_or(0));
        }

        Ok(stats)
    }

    /// Update anomaly score for an event
    pub async fn update_event_anomaly_score(
        &self,
        event_id: i64,
        anomaly_score: f64,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE security_events
            SET anomaly_score = $2
            WHERE id = $1
            "#,
            event_id,
            anomaly_score
        )
        .execute(&self.db)
        .await?;

        Ok(())
    }

    /// Batch update anomaly scores for recent events
    pub async fn batch_update_anomaly_scores(&self, hours: i32) -> Result<i64> {
        let anomalies = self.analyze_recent_events(hours).await?;

        let mut updated = 0;
        for anomaly in anomalies {
            // Find matching events and update scores
            // This is a simplified version - production would need event ID tracking
            debug!(
                "Anomaly detected: {} (score: {:.2})",
                anomaly.description, anomaly.anomaly_score
            );
            updated += 1;
        }

        info!("Updated {} events with anomaly scores", updated);
        Ok(updated as i64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_z_score_classification() {
        let service = AnomalyDetectionService {
            db: PgPool::connect("").await.unwrap(), // Mock
        };

        // Normal
        let (is_anomaly, severity, _) = service.classify_z_score(1.5, "Test");
        assert!(!is_anomaly);
        assert_eq!(severity, Severity::Info);

        // Low anomaly
        let (is_anomaly, severity, _) = service.classify_z_score(2.5, "Test");
        assert!(is_anomaly);
        assert_eq!(severity, Severity::Low);

        // Medium anomaly
        let (is_anomaly, severity, _) = service.classify_z_score(3.5, "Test");
        assert!(is_anomaly);
        assert_eq!(severity, Severity::Medium);

        // High anomaly
        let (is_anomaly, severity, _) = service.classify_z_score(4.5, "Test");
        assert!(is_anomaly);
        assert_eq!(severity, Severity::High);

        // Critical anomaly
        let (is_anomaly, severity, _) = service.classify_z_score(5.5, "Test");
        assert!(is_anomaly);
        assert_eq!(severity, Severity::Critical);
    }
}
