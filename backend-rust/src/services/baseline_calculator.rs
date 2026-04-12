// ============================================================================
// Baseline Calculator Service - Statistical Baseline Computation
// ============================================================================

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;
use std::collections::{HashMap, HashSet};
use tracing::{info, warn};

use crate::security_event::BaselineCalculationResult;

/// Baseline Calculator Service - Computes statistical baselines for UEBA
pub struct BaselineCalculatorService {
    db: PgPool,
}

impl BaselineCalculatorService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Calculate all baselines (users and hosts)
    pub async fn calculate_all_baselines(&self, days: i32) -> Result<()> {
        info!("Starting baseline calculation for {} days of data", days);

        // Calculate user baselines
        let user_count = self.calculate_user_baselines(days).await?;
        info!("Calculated baselines for {} users", user_count);

        // Calculate host baselines
        let host_count = self.calculate_host_baselines(days).await?;
        info!("Calculated baselines for {} hosts", host_count);

        Ok(())
    }

    /// Calculate user behavior baselines
    pub async fn calculate_user_baselines(&self, days: i32) -> Result<i64> {
        info!("Calculating user baselines for {} days", days);

        // Get all users with activity
        let users = self.get_active_users(days).await?;
        info!("Found {} active users", users.len());

        let mut updated = 0;

        for user_name in users {
            match self.calculate_user_baseline(&user_name, days).await {
                Ok(_) => {
                    updated += 1;
                    if updated % 10 == 0 {
                        info!("Processed {} user baselines", updated);
                    }
                }
                Err(e) => {
                    warn!("Failed to calculate baseline for user '{}': {}", user_name, e);
                }
            }
        }

        info!("Completed user baseline calculation: {} updated", updated);
        Ok(updated)
    }

    /// Calculate baseline for a single user
    async fn calculate_user_baseline(&self, user_name: &str, days: i32) -> Result<()> {
        let baseline_start = Utc::now() - Duration::days(days as i64);
        let baseline_end = Utc::now();

        // Login statistics
        let login_stats = self.calculate_login_stats(user_name, days).await?;

        // Typical login hours (histogram)
        let typical_hours = self.get_typical_login_hours(user_name, days).await?;

        // Typical login hosts
        let typical_hosts = self.get_typical_login_hosts(user_name, days).await?;

        // Session statistics
        let session_stats = self.calculate_session_stats(user_name, days).await?;

        // Command statistics
        let command_stats = self.calculate_command_stats(user_name, days).await?;
        let common_commands = self.get_common_commands(user_name, days, 20).await?;

        // File access patterns
        let typical_paths = self.get_typical_file_paths(user_name, days, 50).await?;

        // Process patterns
        let typical_processes = self.get_typical_processes(user_name, days, 30).await?;

        // Network patterns
        let network_stats = self.calculate_network_stats(user_name, days).await?;

        // Calculate thresholds (mean + 3*stddev for anomaly detection)
        let login_threshold = login_stats.mean + 3.0 * login_stats.stddev;
        let session_threshold = session_stats.mean + 3.0 * session_stats.stddev;
        let command_threshold = command_stats.mean + 3.0 * command_stats.stddev;

        // Count events analyzed
        let events_analyzed = self.count_user_events(user_name, days).await?;

        // Upsert baseline
        sqlx::query!(
            r#"
            INSERT INTO user_behavior_baselines (
                user_name,
                avg_logins_per_day, stddev_logins_per_day,
                typical_login_hours, typical_login_hosts,
                avg_session_duration_minutes, stddev_session_duration_minutes,
                avg_commands_per_session, common_commands,
                typical_file_paths, typical_processes,
                avg_network_connections_per_day,
                login_count_threshold_high,
                session_duration_threshold_high,
                command_count_threshold_high,
                baseline_start_date, baseline_end_date,
                events_analyzed, last_updated
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19
            )
            ON CONFLICT (user_name) DO UPDATE SET
                avg_logins_per_day = EXCLUDED.avg_logins_per_day,
                stddev_logins_per_day = EXCLUDED.stddev_logins_per_day,
                typical_login_hours = EXCLUDED.typical_login_hours,
                typical_login_hosts = EXCLUDED.typical_login_hosts,
                avg_session_duration_minutes = EXCLUDED.avg_session_duration_minutes,
                stddev_session_duration_minutes = EXCLUDED.stddev_session_duration_minutes,
                avg_commands_per_session = EXCLUDED.avg_commands_per_session,
                common_commands = EXCLUDED.common_commands,
                typical_file_paths = EXCLUDED.typical_file_paths,
                typical_processes = EXCLUDED.typical_processes,
                avg_network_connections_per_day = EXCLUDED.avg_network_connections_per_day,
                login_count_threshold_high = EXCLUDED.login_count_threshold_high,
                session_duration_threshold_high = EXCLUDED.session_duration_threshold_high,
                command_count_threshold_high = EXCLUDED.command_count_threshold_high,
                baseline_start_date = EXCLUDED.baseline_start_date,
                baseline_end_date = EXCLUDED.baseline_end_date,
                events_analyzed = EXCLUDED.events_analyzed,
                last_updated = EXCLUDED.last_updated
            "#,
            user_name,
            login_stats.mean,
            login_stats.stddev,
            &typical_hours,
            &typical_hosts,
            session_stats.mean,
            session_stats.stddev,
            command_stats.mean,
            &common_commands,
            &typical_paths,
            &typical_processes,
            network_stats.mean,
            login_threshold,
            session_threshold,
            command_threshold,
            baseline_start.date_naive(),
            baseline_end.date_naive(),
            events_analyzed,
            Utc::now()
        )
        .execute(&self.db)
        .await?;

        Ok(())
    }

    /// Calculate host behavior baselines
    pub async fn calculate_host_baselines(&self, days: i32) -> Result<i64> {
        info!("Calculating host baselines for {} days", days);

        let hosts = self.get_active_hosts(days).await?;
        info!("Found {} active hosts", hosts.len());

        let mut updated = 0;

        for host_name in hosts {
            match self.calculate_host_baseline(&host_name, days).await {
                Ok(_) => {
                    updated += 1;
                    if updated % 10 == 0 {
                        info!("Processed {} host baselines", updated);
                    }
                }
                Err(e) => {
                    warn!("Failed to calculate baseline for host '{}': {}", host_name, e);
                }
            }
        }

        info!("Completed host baseline calculation: {} updated", updated);
        Ok(updated)
    }

    /// Calculate baseline for a single host
    async fn calculate_host_baseline(&self, host_name: &str, days: i32) -> Result<()> {
        let baseline_start = Utc::now() - Duration::days(days as i64);
        let baseline_end = Utc::now();

        // Process patterns
        let typical_processes = self.get_host_typical_processes(host_name, days, 50).await?;

        // Network statistics
        let connection_stats = self.calculate_host_connection_stats(host_name, days).await?;
        let typical_ports = self.get_typical_listening_ports(host_name, days).await?;

        // User patterns
        let typical_users = self.get_typical_users_for_host(host_name, days).await?;

        // Calculate thresholds
        let connection_threshold = connection_stats.mean + 3.0 * connection_stats.stddev;

        // Count events
        let events_analyzed = self.count_host_events(host_name, days).await?;

        // Get asset criticality
        let asset_criticality = self.get_asset_criticality(host_name).await?;

        // Upsert baseline
        sqlx::query!(
            r#"
            INSERT INTO host_behavior_baselines (
                host_name,
                typical_processes,
                avg_connections_per_hour, stddev_connections_per_hour,
                typical_listening_ports,
                typical_users,
                connection_count_threshold_high,
                baseline_start_date, baseline_end_date,
                events_analyzed, last_updated,
                asset_criticality
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
            )
            ON CONFLICT (host_name) DO UPDATE SET
                typical_processes = EXCLUDED.typical_processes,
                avg_connections_per_hour = EXCLUDED.avg_connections_per_hour,
                stddev_connections_per_hour = EXCLUDED.stddev_connections_per_hour,
                typical_listening_ports = EXCLUDED.typical_listening_ports,
                typical_users = EXCLUDED.typical_users,
                connection_count_threshold_high = EXCLUDED.connection_count_threshold_high,
                baseline_start_date = EXCLUDED.baseline_start_date,
                baseline_end_date = EXCLUDED.baseline_end_date,
                events_analyzed = EXCLUDED.events_analyzed,
                last_updated = EXCLUDED.last_updated,
                asset_criticality = EXCLUDED.asset_criticality
            "#,
            host_name,
            &typical_processes,
            connection_stats.mean,
            connection_stats.stddev,
            &typical_ports,
            &typical_users,
            connection_threshold,
            baseline_start.date_naive(),
            baseline_end.date_naive(),
            events_analyzed,
            Utc::now(),
            asset_criticality
        )
        .execute(&self.db)
        .await?;

        Ok(())
    }

    // ========================================================================
    // Helper methods for statistics calculation
    // ========================================================================

    async fn get_active_users(&self, days: i32) -> Result<Vec<String>> {
        let rows = sqlx::query!(
            r#"
            SELECT DISTINCT user_name
            FROM security_events
            WHERE timestamp > NOW() - INTERVAL '1 day' * $1
              AND user_name IS NOT NULL
            "#,
            days
        )
        .fetch_all(&self.db)
        .await?;

        Ok(rows.into_iter().filter_map(|r| r.user_name).collect())
    }

    async fn get_active_hosts(&self, days: i32) -> Result<Vec<String>> {
        let rows = sqlx::query!(
            r#"
            SELECT DISTINCT source_host
            FROM security_events
            WHERE timestamp > NOW() - INTERVAL '1 day' * $1
            "#,
            days
        )
        .fetch_all(&self.db)
        .await?;

        Ok(rows.into_iter().map(|r| r.source_host).collect())
    }

    async fn calculate_login_stats(
        &self,
        user_name: &str,
        days: i32,
    ) -> Result<BaselineCalculationResult> {
        let row = sqlx::query!(
            r#"
            SELECT
                AVG(daily_logins)::FLOAT8 as mean,
                STDDEV(daily_logins)::FLOAT8 as stddev,
                MIN(daily_logins)::FLOAT8 as min,
                MAX(daily_logins)::FLOAT8 as max,
                COUNT(*) as count
            FROM (
                SELECT
                    date_trunc('day', timestamp) as day,
                    COUNT(*) as daily_logins
                FROM security_events
                WHERE user_name = $1
                  AND event_category = 'authentication'
                  AND timestamp > NOW() - INTERVAL '1 day' * $2
                GROUP BY day
            ) daily_stats
            "#,
            user_name,
            days
        )
        .fetch_one(&self.db)
        .await?;

        Ok(BaselineCalculationResult {
            mean: row.mean.unwrap_or(0.0),
            stddev: row.stddev.unwrap_or(0.0),
            median: None,
            min: row.min.unwrap_or(0.0),
            max: row.max.unwrap_or(0.0),
            count: row.count.unwrap_or(0) as usize,
            threshold_low: 0.0,
            threshold_high: 0.0,
        })
    }

    async fn get_typical_login_hours(&self, user_name: &str, days: i32) -> Result<Vec<i32>> {
        let rows = sqlx::query!(
            r#"
            SELECT EXTRACT(HOUR FROM timestamp)::INT as hour
            FROM security_events
            WHERE user_name = $1
              AND event_category = 'authentication'
              AND timestamp > NOW() - INTERVAL '1 day' * $2
            GROUP BY hour
            HAVING COUNT(*) > 5
            ORDER BY hour
            "#,
            user_name,
            days
        )
        .fetch_all(&self.db)
        .await?;

        Ok(rows.into_iter().filter_map(|r| r.hour).collect())
    }

    async fn get_typical_login_hosts(&self, user_name: &str, days: i32) -> Result<Vec<String>> {
        let rows = sqlx::query!(
            r#"
            SELECT source_host
            FROM security_events
            WHERE user_name = $1
              AND event_category = 'authentication'
              AND timestamp > NOW() - INTERVAL '1 day' * $2
            GROUP BY source_host
            HAVING COUNT(*) > 3
            ORDER BY COUNT(*) DESC
            LIMIT 20
            "#,
            user_name,
            days
        )
        .fetch_all(&self.db)
        .await?;

        Ok(rows.into_iter().map(|r| r.source_host).collect())
    }

    async fn calculate_session_stats(
        &self,
        _user_name: &str,
        _days: i32,
    ) -> Result<BaselineCalculationResult> {
        // Simplified - would need session tracking logic
        Ok(BaselineCalculationResult {
            mean: 30.0,
            stddev: 10.0,
            median: None,
            min: 5.0,
            max: 120.0,
            count: 0,
            threshold_low: 0.0,
            threshold_high: 0.0,
        })
    }

    async fn calculate_command_stats(
        &self,
        user_name: &str,
        days: i32,
    ) -> Result<BaselineCalculationResult> {
        let row = sqlx::query!(
            r#"
            SELECT
                AVG(cmd_count)::FLOAT8 as mean,
                STDDEV(cmd_count)::FLOAT8 as stddev
            FROM (
                SELECT COUNT(*) as cmd_count
                FROM security_events
                WHERE user_name = $1
                  AND process_cmdline IS NOT NULL
                  AND timestamp > NOW() - INTERVAL '1 day' * $2
                GROUP BY date_trunc('hour', timestamp)
            ) hourly_stats
            "#,
            user_name,
            days
        )
        .fetch_one(&self.db)
        .await?;

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
    }

    async fn get_common_commands(
        &self,
        user_name: &str,
        days: i32,
        limit: i64,
    ) -> Result<Vec<String>> {
        let rows = sqlx::query!(
            r#"
            SELECT process_name
            FROM security_events
            WHERE user_name = $1
              AND process_name IS NOT NULL
              AND timestamp > NOW() - INTERVAL '1 day' * $2
            GROUP BY process_name
            ORDER BY COUNT(*) DESC
            LIMIT $3
            "#,
            user_name,
            days,
            limit
        )
        .fetch_all(&self.db)
        .await?;

        Ok(rows.into_iter().filter_map(|r| r.process_name).collect())
    }

    async fn get_typical_file_paths(
        &self,
        user_name: &str,
        days: i32,
        limit: i64,
    ) -> Result<Vec<String>> {
        let rows = sqlx::query!(
            r#"
            SELECT file_path
            FROM security_events
            WHERE user_name = $1
              AND file_path IS NOT NULL
              AND timestamp > NOW() - INTERVAL '1 day' * $2
            GROUP BY file_path
            ORDER BY COUNT(*) DESC
            LIMIT $3
            "#,
            user_name,
            days,
            limit
        )
        .fetch_all(&self.db)
        .await?;

        Ok(rows.into_iter().filter_map(|r| r.file_path).collect())
    }

    async fn get_typical_processes(
        &self,
        user_name: &str,
        days: i32,
        limit: i64,
    ) -> Result<Vec<String>> {
        self.get_common_commands(user_name, days, limit).await
    }

    async fn calculate_network_stats(
        &self,
        user_name: &str,
        days: i32,
    ) -> Result<BaselineCalculationResult> {
        let row = sqlx::query!(
            r#"
            SELECT
                AVG(daily_connections)::FLOAT8 as mean,
                STDDEV(daily_connections)::FLOAT8 as stddev
            FROM (
                SELECT
                    date_trunc('day', timestamp) as day,
                    COUNT(*) as daily_connections
                FROM security_events
                WHERE user_name = $1
                  AND event_category = 'network'
                  AND timestamp > NOW() - INTERVAL '1 day' * $2
                GROUP BY day
            ) daily_stats
            "#,
            user_name,
            days
        )
        .fetch_one(&self.db)
        .await?;

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
    }

    async fn get_host_typical_processes(
        &self,
        host_name: &str,
        days: i32,
        limit: i64,
    ) -> Result<Vec<String>> {
        let rows = sqlx::query!(
            r#"
            SELECT process_name
            FROM security_events
            WHERE source_host = $1
              AND process_name IS NOT NULL
              AND timestamp > NOW() - INTERVAL '1 day' * $2
            GROUP BY process_name
            ORDER BY COUNT(*) DESC
            LIMIT $3
            "#,
            host_name,
            days,
            limit
        )
        .fetch_all(&self.db)
        .await?;

        Ok(rows.into_iter().filter_map(|r| r.process_name).collect())
    }

    async fn calculate_host_connection_stats(
        &self,
        host_name: &str,
        days: i32,
    ) -> Result<BaselineCalculationResult> {
        let row = sqlx::query!(
            r#"
            SELECT
                AVG(hourly_connections)::FLOAT8 as mean,
                STDDEV(hourly_connections)::FLOAT8 as stddev
            FROM (
                SELECT
                    date_trunc('hour', timestamp) as hour,
                    COUNT(*) as hourly_connections
                FROM security_events
                WHERE source_host = $1
                  AND event_category = 'network'
                  AND timestamp > NOW() - INTERVAL '1 day' * $2
                GROUP BY hour
            ) hourly_stats
            "#,
            host_name,
            days
        )
        .fetch_one(&self.db)
        .await?;

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
    }

    async fn get_typical_listening_ports(&self, host_name: &str, days: i32) -> Result<Vec<i32>> {
        let rows = sqlx::query!(
            r#"
            SELECT DISTINCT source_port
            FROM security_events
            WHERE source_host = $1
              AND source_port IS NOT NULL
              AND timestamp > NOW() - INTERVAL '1 day' * $2
            ORDER BY source_port
            LIMIT 50
            "#,
            host_name,
            days
        )
        .fetch_all(&self.db)
        .await?;

        Ok(rows.into_iter().filter_map(|r| r.source_port).collect())
    }

    async fn get_typical_users_for_host(&self, host_name: &str, days: i32) -> Result<Vec<String>> {
        let rows = sqlx::query!(
            r#"
            SELECT user_name
            FROM security_events
            WHERE source_host = $1
              AND user_name IS NOT NULL
              AND timestamp > NOW() - INTERVAL '1 day' * $2
            GROUP BY user_name
            ORDER BY COUNT(*) DESC
            LIMIT 20
            "#,
            host_name,
            days
        )
        .fetch_all(&self.db)
        .await?;

        Ok(rows.into_iter().filter_map(|r| r.user_name).collect())
    }

    async fn count_user_events(&self, user_name: &str, days: i32) -> Result<i32> {
        let row = sqlx::query!(
            r#"
            SELECT COUNT(*)::INT as count
            FROM security_events
            WHERE user_name = $1
              AND timestamp > NOW() - INTERVAL '1 day' * $2
            "#,
            user_name,
            days
        )
        .fetch_one(&self.db)
        .await?;

        Ok(row.count.unwrap_or(0))
    }

    async fn count_host_events(&self, host_name: &str, days: i32) -> Result<i32> {
        let row = sqlx::query!(
            r#"
            SELECT COUNT(*)::INT as count
            FROM security_events
            WHERE source_host = $1
              AND timestamp > NOW() - INTERVAL '1 day' * $2
            "#,
            host_name,
            days
        )
        .fetch_one(&self.db)
        .await?;

        Ok(row.count.unwrap_or(0))
    }

    async fn get_asset_criticality(&self, host_name: &str) -> Result<i32> {
        let row = sqlx::query!(
            r#"
            SELECT 5 as criticality
            FROM targets
            WHERE hostname = $1 OR ip_address::TEXT = $1
            LIMIT 1
            "#,
            host_name
        )
        .fetch_optional(&self.db)
        .await?;

        Ok(row.map(|r| r.criticality.unwrap_or(5)).unwrap_or(5))
    }
}
