// ============================================================================
// Hardening Executor - Executes hardening templates on agents via WebSocket
// ============================================================================

use crate::models::{HardeningTemplate, HardeningExecution};
use crate::services::agent_registry::AgentRegistry;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tracing::{error, info, warn};

/// Hardening command sent to agents
#[derive(Debug, Serialize, Deserialize)]
pub struct HardeningCommand {
    pub msg_type: String, // "command"
    pub target_id: i32,
    pub timestamp: i64,
    pub payload: HardeningCommandPayload,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HardeningCommandPayload {
    pub command_type: String, // "execute_hardening"
    pub execution_id: i64,
    pub template: serde_json::Value, // YAML template as JSON
    pub execution_mode: String, // "dry_run" or "apply"
}

/// Response from agent after executing hardening
#[derive(Debug, Serialize, Deserialize)]
pub struct HardeningResponse {
    pub execution_id: i64,
    pub status: String, // "running", "completed", "failed"
    pub progress: Option<HardeningProgress>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HardeningProgress {
    pub total_controls: i32,
    pub successful_controls: i32,
    pub failed_controls: i32,
    pub current_control: Option<String>,
    pub compliance_score_before: Option<f64>,
    pub compliance_score_after: Option<f64>,
    pub execution_log: Option<String>,
    pub rollback_data: Option<serde_json::Value>,
}

/// Hardening Executor - Background service that processes pending executions
pub struct HardeningExecutor {
    pg_pool: PgPool,
    agent_registry: AgentRegistry,
}

impl HardeningExecutor {
    pub fn new(pg_pool: PgPool, agent_registry: AgentRegistry) -> Self {
        Self {
            pg_pool,
            agent_registry,
        }
    }

    /// Start the executor background loop
    pub async fn start(self: Arc<Self>) {
        info!("Hardening executor started");

        loop {
            if let Err(e) = self.process_pending_executions().await {
                error!("Error processing executions: {}", e);
            }

            // Check for pending executions every 5 seconds
            sleep(Duration::from_secs(5)).await;
        }
    }

    /// Process all pending hardening executions
    async fn process_pending_executions(&self) -> anyhow::Result<()> {
        // Fetch pending executions
        let executions = sqlx::query_as::<_, HardeningExecution>(
            r#"
            SELECT *
            FROM hardening_executions
            WHERE status = 'pending'
            ORDER BY created_at ASC
            LIMIT 10
            "#,
        )
        .fetch_all(&self.pg_pool)
        .await?;

        if executions.is_empty() {
            return Ok(());
        }

        info!("Found {} pending executions to process", executions.len());

        for execution in executions {
            if let Err(e) = self.process_execution(&execution).await {
                error!(
                    "Failed to process execution {}: {}",
                    execution.id, e
                );

                // Mark execution as failed
                let _ = sqlx::query!(
                    r#"
                    UPDATE hardening_executions
                    SET status = 'failed',
                        completed_at = NOW(),
                        execution_log = $1
                    WHERE id = $2
                    "#,
                    format!("Failed to start execution: {}", e),
                    execution.id
                )
                .execute(&self.pg_pool)
                .await;
            }
        }

        Ok(())
    }

    /// Process a single hardening execution
    async fn process_execution(&self, execution: &HardeningExecution) -> anyhow::Result<()> {
        let target_id = execution.target_id;
        let execution_id = execution.id;

        // Check if agent is connected
        if !self.agent_registry.is_connected(target_id).await {
            return Err(anyhow::anyhow!(
                "Agent for target {} is not connected",
                target_id
            ));
        }

        // Fetch the template
        let template = sqlx::query_as::<_, HardeningTemplate>(
            "SELECT * FROM hardening_templates WHERE id = $1",
        )
        .bind(execution.template_id)
        .fetch_one(&self.pg_pool)
        .await?;

        info!(
            "Executing template '{}' on target {} (execution_id: {})",
            template.name, target_id, execution_id
        );

        // Mark execution as running
        sqlx::query!(
            r#"
            UPDATE hardening_executions
            SET status = 'running',
                started_at = NOW()
            WHERE id = $1
            "#,
            execution_id
        )
        .execute(&self.pg_pool)
        .await?;

        // Build hardening command
        let command = HardeningCommand {
            msg_type: "command".to_string(),
            target_id,
            timestamp: chrono::Utc::now().timestamp(),
            payload: HardeningCommandPayload {
                command_type: "execute_hardening".to_string(),
                execution_id,
                template: template.template_config.clone(),
                execution_mode: execution.execution_mode.clone(),
            },
        };

        // Send command to agent
        let command_json = serde_json::to_value(&command)?;
        self.agent_registry
            .send_command(target_id, command_json)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send command to agent: {}", e))?;

        info!(
            "Hardening command sent to agent {} for execution {}",
            target_id, execution_id
        );

        Ok(())
    }

    /// Handle response from agent (called by agents.rs when receiving CommandResponse)
    pub async fn handle_agent_response(
        &self,
        response: HardeningResponse,
    ) -> anyhow::Result<()> {
        let execution_id = response.execution_id;

        info!(
            "Received hardening response for execution {}: status={}",
            execution_id, response.status
        );

        match response.status.as_str() {
            "running" => {
                if let Some(progress) = response.progress {
                    self.update_execution_progress(execution_id, &progress)
                        .await?;
                }
            }
            "completed" => {
                if let Some(progress) = response.progress {
                    self.complete_execution(execution_id, &progress).await?;
                }
            }
            "failed" => {
                self.fail_execution(execution_id, response.error.as_deref())
                    .await?;
            }
            _ => {
                warn!("Unknown response status: {}", response.status);
            }
        }

        Ok(())
    }

    /// Update execution progress
    async fn update_execution_progress(
        &self,
        execution_id: i64,
        progress: &HardeningProgress,
    ) -> anyhow::Result<()> {
        sqlx::query!(
            r#"
            UPDATE hardening_executions
            SET total_controls = $1,
                successful_controls = $2,
                failed_controls = $3,
                execution_log = $4
            WHERE id = $5
            "#,
            progress.total_controls,
            progress.successful_controls,
            progress.failed_controls,
            progress.execution_log.as_ref(),
            execution_id
        )
        .execute(&self.pg_pool)
        .await?;

        Ok(())
    }

    /// Mark execution as completed
    async fn complete_execution(
        &self,
        execution_id: i64,
        progress: &HardeningProgress,
    ) -> anyhow::Result<()> {
        sqlx::query!(
            r#"
            UPDATE hardening_executions
            SET status = 'completed',
                completed_at = NOW(),
                total_controls = $1,
                successful_controls = $2,
                failed_controls = $3,
                compliance_score_before = $4::FLOAT8,
                compliance_score_after = $5::FLOAT8,
                execution_log = $6,
                rollback_data = $7
            WHERE id = $8
            "#,
            progress.total_controls,
            progress.successful_controls,
            progress.failed_controls,
            progress.compliance_score_before,
            progress.compliance_score_after,
            progress.execution_log.as_ref(),
            progress.rollback_data.as_ref(),
            execution_id
        )
        .execute(&self.pg_pool)
        .await?;

        info!("Execution {} completed successfully", execution_id);

        // TODO: Update target_compliance_status based on results
        // TODO: Update target_control_status for each control

        Ok(())
    }

    /// Mark execution as failed
    async fn fail_execution(
        &self,
        execution_id: i64,
        error: Option<&str>,
    ) -> anyhow::Result<()> {
        sqlx::query!(
            r#"
            UPDATE hardening_executions
            SET status = 'failed',
                completed_at = NOW(),
                execution_log = $1
            WHERE id = $2
            "#,
            error,
            execution_id
        )
        .execute(&self.pg_pool)
        .await?;

        error!(
            "Execution {} failed: {}",
            execution_id,
            error.unwrap_or("Unknown error")
        );

        Ok(())
    }
}
