// ============================================================================
// Compliance Scanner - Scans targets for compliance control verification
// ============================================================================

use crate::models::ComplianceControl;
use crate::services::agent_registry::AgentRegistry;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tracing::{error, info, warn};

/// Compliance scan command sent to agents
#[derive(Debug, Serialize, Deserialize)]
pub struct ComplianceScanCommand {
    pub msg_type: String, // "command"
    pub target_id: i32,
    pub timestamp: i64,
    pub payload: ComplianceScanPayload,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ComplianceScanPayload {
    pub command_type: String, // "compliance_scan"
    pub scan_id: i64,
    pub controls: Vec<ControlToCheck>,
    pub frameworks: Vec<String>, // ["nis2", "nist", "iso27001", "mitre"]
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ControlToCheck {
    pub control_id: i32,
    pub requirement: String,
    pub check_method: Option<String>,
    pub expected_value: Option<String>,
}

/// Response from agent after compliance scan
#[derive(Debug, Serialize, Deserialize)]
pub struct ComplianceScanResponse {
    pub scan_id: i64,
    pub target_id: i32,
    pub status: String, // "running", "completed", "failed"
    pub results: Option<Vec<ControlCheckResult>>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ControlCheckResult {
    pub control_id: i32,
    pub status: String, // "compliant", "non_compliant", "partial", "not_applicable", "error"
    pub check_output: Option<String>,
    pub compliance_score: f64,
    pub gap_description: Option<String>,
    pub evidence_data: Option<serde_json::Value>,
}

/// Compliance Scanner - Background service that schedules and processes scans
pub struct ComplianceScanner {
    pg_pool: PgPool,
    agent_registry: AgentRegistry,
}

impl ComplianceScanner {
    pub fn new(pg_pool: PgPool, agent_registry: AgentRegistry) -> Self {
        Self {
            pg_pool,
            agent_registry,
        }
    }

    /// Start the scanner background loop
    pub async fn start(self: Arc<Self>) {
        info!("Compliance scanner started");

        loop {
            if let Err(e) = self.run_scheduled_scans().await {
                error!("Error running compliance scans: {}", e);
            }

            // Run compliance scans every 1 hour
            sleep(Duration::from_secs(3600)).await;
        }
    }

    /// Run scheduled compliance scans for all active targets
    async fn run_scheduled_scans(&self) -> anyhow::Result<()> {
        info!("Starting scheduled compliance scans");

        // Get all active targets with connected agents
        let connected_agents = self.agent_registry.get_connected_agents().await;

        if connected_agents.is_empty() {
            info!("No agents connected, skipping compliance scans");
            return Ok(());
        }

        info!("Found {} connected agents for scanning", connected_agents.len());

        for target_id in connected_agents {
            if let Err(e) = self.scan_target(target_id).await {
                error!("Failed to scan target {}: {}", target_id, e);
            }
        }

        Ok(())
    }

    /// Scan a specific target for compliance
    pub async fn scan_target(&self, target_id: i32) -> anyhow::Result<()> {
        info!("Starting compliance scan for target {}", target_id);

        // Check if agent is connected
        if !self.agent_registry.is_connected(target_id).await {
            return Err(anyhow::anyhow!(
                "Agent for target {} is not connected",
                target_id
            ));
        }

        // Get target OS to filter applicable controls
        let target_os: Option<String> = sqlx::query_scalar(
            "SELECT os_type FROM targets WHERE id = $1",
        )
        .bind(target_id)
        .fetch_optional(&self.pg_pool)
        .await?;

        // Fetch all applicable controls for this target
        let controls = self.get_applicable_controls(target_id, target_os.as_deref()).await?;

        if controls.is_empty() {
            info!("No applicable controls for target {}", target_id);
            return Ok(());
        }

        // Create scan record
        let scan_id: i64 = sqlx::query_scalar(
            r#"
            INSERT INTO compliance_scans (target_id, status, started_at, total_controls)
            VALUES ($1, 'running', NOW(), $2)
            RETURNING id
            "#,
        )
        .bind(target_id)
        .bind(controls.len() as i32)
        .fetch_one(&self.pg_pool)
        .await?;

        // Build scan command
        let controls_to_check: Vec<ControlToCheck> = controls
            .iter()
            .map(|c| ControlToCheck {
                control_id: c.id,
                requirement: c.requirement.clone(),
                check_method: None, // Would be defined in control metadata
                expected_value: None,
            })
            .collect();

        let command = ComplianceScanCommand {
            msg_type: "command".to_string(),
            target_id,
            timestamp: chrono::Utc::now().timestamp(),
            payload: ComplianceScanPayload {
                command_type: "compliance_scan".to_string(),
                scan_id,
                controls: controls_to_check,
                frameworks: vec![
                    "nis2".to_string(),
                    "nist".to_string(),
                    "iso27001".to_string(),
                    "mitre".to_string(),
                ],
            },
        };

        // Send scan command to agent
        let command_json = serde_json::to_value(&command)?;
        self.agent_registry
            .send_command(target_id, command_json)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send scan command: {}", e))?;

        info!(
            "Compliance scan command sent to target {} (scan_id: {}, {} controls)",
            target_id,
            scan_id,
            controls.len()
        );

        Ok(())
    }

    /// Get applicable controls for a target based on OS
    async fn get_applicable_controls(
        &self,
        target_id: i32,
        os_type: Option<&str>,
    ) -> anyhow::Result<Vec<ComplianceControl>> {
        let mut query = String::from(
            r#"
            SELECT * FROM compliance_controls
            WHERE 1=1
            "#,
        );

        // Filter by OS if available
        if let Some(os) = os_type {
            match os.to_lowercase().as_str() {
                "debian" | "ubuntu" => {
                    query.push_str(" AND supports_debian_ubuntu = TRUE");
                }
                "rhel" | "centos" | "oracle" => {
                    query.push_str(" AND supports_rhel_oracle = TRUE");
                }
                "sles" => {
                    query.push_str(" AND supports_sles = TRUE");
                }
                "windows" => {
                    query.push_str(" AND (supports_windows_2019 = TRUE OR supports_windows_2022 = TRUE)");
                }
                "docker" => {
                    query.push_str(" AND supports_docker = TRUE");
                }
                "lxc" => {
                    query.push_str(" AND supports_lxc = TRUE");
                }
                _ => {}
            }
        }

        query.push_str(" ORDER BY priority DESC, id");

        let controls = sqlx::query_as::<_, ComplianceControl>(&query)
            .fetch_all(&self.pg_pool)
            .await?;

        Ok(controls)
    }

    /// Handle scan response from agent
    pub async fn handle_scan_response(
        &self,
        response: ComplianceScanResponse,
    ) -> anyhow::Result<()> {
        let scan_id = response.scan_id;
        let target_id = response.target_id;

        info!(
            "Received compliance scan response for target {} (scan_id: {}): status={}",
            target_id, scan_id, response.status
        );

        match response.status.as_str() {
            "completed" => {
                if let Some(results) = response.results {
                    self.process_scan_results(scan_id, target_id, &results)
                        .await?;
                }
            }
            "failed" => {
                // Mark scan as failed
                sqlx::query(
                    r#"
                    UPDATE compliance_scans
                    SET status = 'failed',
                        completed_at = NOW(),
                        error_message = $1
                    WHERE id = $2
                    "#,
                )
                .bind(response.error.as_deref())
                .bind(scan_id)
                .execute(&self.pg_pool)
                .await?;

                error!(
                    "Compliance scan {} failed: {}",
                    scan_id,
                    response.error.unwrap_or_else(|| "Unknown error".to_string())
                );
            }
            _ => {
                warn!("Unknown scan status: {}", response.status);
            }
        }

        Ok(())
    }

    /// Process scan results and update database
    async fn process_scan_results(
        &self,
        scan_id: i64,
        target_id: i32,
        results: &[ControlCheckResult],
    ) -> anyhow::Result<()> {
        info!(
            "Processing {} scan results for target {}",
            results.len(),
            target_id
        );

        // Begin transaction
        let mut tx = self.pg_pool.begin().await?;

        // Update or insert control status for each result
        for result in results {
            sqlx::query(
                r#"
                INSERT INTO target_control_status (
                    target_id, control_id, status, last_check_at,
                    check_method, check_output, remediation_applied,
                    evidence_data, compliance_score, gap_description
                )
                VALUES ($1, $2, $3, NOW(), 'agent_scan', $4, FALSE, $5, $6, $7)
                ON CONFLICT (target_id, control_id)
                DO UPDATE SET
                    status = EXCLUDED.status,
                    last_check_at = NOW(),
                    check_method = 'agent_scan',
                    check_output = EXCLUDED.check_output,
                    evidence_data = EXCLUDED.evidence_data,
                    compliance_score = EXCLUDED.compliance_score,
                    gap_description = EXCLUDED.gap_description,
                    updated_at = NOW()
                "#,
            )
            .bind(target_id)
            .bind(result.control_id)
            .bind(&result.status)
            .bind(&result.check_output)
            .bind(&result.evidence_data)
            .bind(result.compliance_score)
            .bind(&result.gap_description)
            .execute(&mut *tx)
            .await?;
        }

        // Update target_compliance_status for each framework
        self.update_framework_scores(&mut tx, target_id).await?;

        // Mark scan as completed
        sqlx::query(
            r#"
            UPDATE compliance_scans
            SET status = 'completed',
                completed_at = NOW(),
                checked_controls = $1
            WHERE id = $2
            "#,
        )
        .bind(results.len() as i32)
        .bind(scan_id)
        .execute(&mut *tx)
        .await?;

        // Commit transaction
        tx.commit().await?;

        info!(
            "Compliance scan {} completed successfully for target {}",
            scan_id, target_id
        );

        Ok(())
    }

    /// Update target_compliance_status scores for all frameworks
    async fn update_framework_scores(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        target_id: i32,
    ) -> anyhow::Result<()> {
        let frameworks = vec!["nis2", "nist", "iso27001", "mitre"];

        for framework_code in frameworks {
            // Calculate compliance metrics for this framework
            let (total, compliant, non_compliant, avg_score): (i64, i64, i64, Option<f64>) = sqlx::query_as(
                r#"
                SELECT
                    COUNT(*) as total,
                    COUNT(*) FILTER (WHERE tcs.status = 'compliant') as compliant,
                    COUNT(*) FILTER (WHERE tcs.status IN ('non_compliant', 'partial', 'error')) as non_compliant,
                    AVG(tcs.compliance_score) FILTER (WHERE tcs.compliance_score IS NOT NULL) as avg_score
                FROM target_control_status tcs
                JOIN compliance_controls cc ON tcs.control_id = cc.id
                WHERE tcs.target_id = $1
                  AND (
                    (cc.applies_to_nis2 = TRUE AND $2 = 'nis2') OR
                    (cc.applies_to_nist = TRUE AND $2 = 'nist') OR
                    (cc.applies_to_iso = TRUE AND $2 = 'iso27001') OR
                    (cc.applies_to_mitre = TRUE AND $2 = 'mitre')
                  )
                "#,
            )
            .bind(target_id)
            .bind(framework_code)
            .fetch_one(&mut **tx)
            .await?;

            let compliance_score = avg_score.unwrap_or(0.0);

            // Upsert target_compliance_status
            sqlx::query(
                r#"
                INSERT INTO target_compliance_status (
                    target_id, framework_code, total_controls,
                    compliant_controls, non_compliant_controls,
                    compliance_score, last_scan_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, NOW())
                ON CONFLICT (target_id, framework_code)
                DO UPDATE SET
                    total_controls = EXCLUDED.total_controls,
                    compliant_controls = EXCLUDED.compliant_controls,
                    non_compliant_controls = EXCLUDED.non_compliant_controls,
                    compliance_score = EXCLUDED.compliance_score,
                    last_scan_at = NOW(),
                    updated_at = NOW()
                "#,
            )
            .bind(target_id)
            .bind(framework_code)
            .bind(total as i32)
            .bind(compliant as i32)
            .bind(non_compliant as i32)
            .bind(compliance_score)
            .execute(&mut **tx)
            .await?;
        }

        Ok(())
    }

    /// Trigger immediate scan for a specific target (called from API)
    pub async fn trigger_scan(&self, target_id: i32) -> anyhow::Result<i64> {
        info!("Triggering immediate compliance scan for target {}", target_id);

        self.scan_target(target_id).await?;

        // Return the latest scan_id
        let scan_id: i64 = sqlx::query_scalar(
            "SELECT id FROM compliance_scans WHERE target_id = $1 ORDER BY created_at DESC LIMIT 1",
        )
        .bind(target_id)
        .fetch_one(&self.pg_pool)
        .await?;

        Ok(scan_id)
    }
}
