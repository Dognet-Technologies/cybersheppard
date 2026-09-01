// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - Monitoring Scheduler
// ============================================================================
// Periodically collects monitoring data from all enabled targets

use sqlx::PgPool;
use tokio::time::{interval, Duration};
use tracing::{info, warn, error};
use chrono::Utc;
use std::sync::Arc;
use anyhow::Context;

use crate::db::influxdb::InfluxDbClient;
use crate::services::collector::{CollectorClient, create_temp_key_file, cleanup_temp_key_file};
use crate::services::influxdb_writer::write_collected_data;

// ============================================================================
// Target Info for Collection
// ============================================================================

#[derive(Debug, Clone)]
struct MonitoringTarget {
    id: i32,
    hostname: String,
    ip_address: String,
    ssh_port: i32,
    ssh_username: String,
    ssh_key_private: String,  // Decrypted private key content
    monitoring_interval_seconds: i32,
}

// ============================================================================
// Scheduler
// ============================================================================

pub struct MonitoringScheduler {
    pg_pool: PgPool,
    influx_client: Arc<InfluxDbClient>,
}

impl MonitoringScheduler {
    pub fn new(pg_pool: PgPool, influx_client: Arc<InfluxDbClient>) -> Self {
        Self {
            pg_pool,
            influx_client,
        }
    }

    /// Start the monitoring scheduler
    pub async fn start(self: Arc<Self>) {
        info!("🚀 Starting monitoring scheduler...");

        // Run every 60 seconds to check which targets need monitoring
        let mut ticker = interval(Duration::from_secs(60));

        loop {
            ticker.tick().await;

            if let Err(e) = self.collect_all_targets().await {
                error!("Scheduler error: {}", e);
            }
        }
    }

    /// Collect data from all enabled targets
    async fn collect_all_targets(&self) -> anyhow::Result<()> {
        // Get all targets with monitoring enabled
        let targets = self.get_monitoring_targets().await?;

        if targets.is_empty() {
            return Ok(());
        }

        info!("📊 Checking {} monitoring target(s)...", targets.len());

        // Spawn collection tasks for each target
        let mut tasks = vec![];

        for target in targets {
            // Check if it's time to collect (based on last_monitoring_at and interval)
            if !self.should_collect_now(&target).await? {
                continue;
            }

            let pg_pool = self.pg_pool.clone();
            let influx_client = self.influx_client.clone();

            // Spawn async task for this target
            let task = tokio::spawn(async move {
                collect_target_data(target, pg_pool, influx_client).await
            });

            tasks.push(task);
        }

        // Wait for all tasks to complete
        let results = futures::future::join_all(tasks).await;

        let mut success_count = 0;
        let mut error_count = 0;

        for result in results {
            match result {
                Ok(Ok(_)) => success_count += 1,
                Ok(Err(e)) => {
                    error_count += 1;
                    warn!("Collection failed: {}", e);
                }
                Err(e) => {
                    error_count += 1;
                    error!("Task panic: {}", e);
                }
            }
        }

        if success_count > 0 || error_count > 0 {
            info!("✅ Collection round: {} succeeded, {} failed", success_count, error_count);
        }

        Ok(())
    }

    /// Get all targets with monitoring enabled
    async fn get_monitoring_targets(&self) -> anyhow::Result<Vec<MonitoringTarget>> {
        let rows = sqlx::query_as::<_, (i32, String, String, i32, String, Option<i32>, i32)>(
            "SELECT t.id, t.hostname, t.ip_address::text, t.ssh_port, t.ssh_username,
                    t.ssh_key_id, t.monitoring_interval_seconds
             FROM targets t
             WHERE t.monitoring_enabled = true AND t.status = 'online'"
        )
        .fetch_all(&self.pg_pool)
        .await?;

        let mut targets = vec![];

        for (id, hostname, ip_address, ssh_port, ssh_username, ssh_key_id, monitoring_interval_seconds) in rows {
            // Get SSH key if specified
            if let Some(key_id) = ssh_key_id {
                if let Ok(Some(private_key)) = self.get_ssh_private_key(key_id).await {
                    targets.push(MonitoringTarget {
                        id,
                        hostname,
                        ip_address,
                        ssh_port,
                        ssh_username,
                        ssh_key_private: private_key,
                        monitoring_interval_seconds,
                    });
                } else {
                    warn!("⚠️  Target {} has invalid SSH key {}, skipping", id, key_id);
                }
            } else {
                warn!("⚠️  Target {} has no SSH key configured, skipping", id);
            }
        }

        Ok(targets)
    }

    /// Get decrypted SSH private key from database
    async fn get_ssh_private_key(&self, key_id: i32) -> anyhow::Result<Option<String>> {
        let row = sqlx::query_as::<_, (String,)>(
            "SELECT private_key FROM ssh_keys WHERE id = $1"
        )
        .bind(key_id)
        .fetch_optional(&self.pg_pool)
        .await?;

        if let Some((encrypted_key,)) = row {
            // Decrypt key using Fernet
            let fernet_key = std::env::var("FERNET_KEY")
                .context("FERNET_KEY environment variable not set")?;

            let fernet = fernet::Fernet::new(&fernet_key)
                .context("Invalid FERNET_KEY format")?;

            let decrypted = fernet.decrypt(&encrypted_key)
                .context("Failed to decrypt SSH private key")?;

            let decrypted_str = String::from_utf8(decrypted)
                .context("Decrypted key is not valid UTF-8")?;

            Ok(Some(decrypted_str))
        } else {
            Ok(None)
        }
    }

    /// Check if target should be collected now
    async fn should_collect_now(&self, target: &MonitoringTarget) -> anyhow::Result<bool> {
        let row = sqlx::query_as::<_, (Option<chrono::DateTime<Utc>>,)>(
            "SELECT last_monitoring_at FROM targets WHERE id = $1"
        )
        .bind(target.id)
        .fetch_one(&self.pg_pool)
        .await?;

        let (last_monitoring_opt,) = row;

        if let Some(last_monitoring) = last_monitoring_opt {
            let elapsed = Utc::now().signed_duration_since(last_monitoring);
            let interval = chrono::Duration::seconds(target.monitoring_interval_seconds as i64);

            Ok(elapsed >= interval)
        } else {
            // Never monitored, collect now
            Ok(true)
        }
    }
}

// ============================================================================
// Collection Function
// ============================================================================

/// Collect data from a single target
async fn collect_target_data(
    target: MonitoringTarget,
    pg_pool: PgPool,
    influx_client: Arc<InfluxDbClient>,
) -> anyhow::Result<()> {
    info!("🎯 Collecting data from {} ({})", target.hostname, target.ip_address);

    let start_time = std::time::Instant::now();

    // Create temporary key file
    let key_path = create_temp_key_file(&target.ssh_key_private)?;

    let result = async {
        // Create collector client
        let collector = CollectorClient::new(
            target.ip_address.clone(),
            target.ssh_port as u16,
            target.ssh_username.clone(),
            key_path.clone(),
        );

        // Collect data
        let collected_data = collector.collect_all_data(target.id)
            .map_err(|e| {
                // Update error count in database
                let _ = sqlx::query(
                    "UPDATE targets SET monitoring_errors_count = monitoring_errors_count + 1 WHERE id = $1"
                )
                .bind(target.id)
                .execute(&pg_pool);
                e
            })?;

        // Write to InfluxDB
        write_collected_data(&influx_client, &collected_data).await?;

        // Update last_monitoring_at timestamp
        sqlx::query(
            "UPDATE targets SET last_monitoring_at = $1, last_seen = $1, monitoring_errors_count = 0 WHERE id = $2"
        )
        .bind(Utc::now())
        .bind(target.id)
        .execute(&pg_pool)
        .await?;

        Ok::<(), anyhow::Error>(())
    }.await;

    // Cleanup key file
    cleanup_temp_key_file(&key_path);

    let duration = start_time.elapsed();

    match result {
        Ok(_) => {
            info!("✅ Data collection completed for {} in {:?}", target.hostname, duration);
            Ok(())
        }
        Err(e) => {
            error!("❌ Data collection failed for {}: {}", target.hostname, e);
            Err(e)
        }
    }
}
