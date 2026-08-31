// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - Compliance Engine Service
// ============================================================================

use crate::db::postgresql::PostgresPool;
use crate::models::{CompliancePolicy, MonitoringDataPayload};
use serde_json::json;
use anyhow::Result;

#[derive(Clone)]
pub struct ComplianceEngine {
    pg_pool: PostgresPool,
}

#[derive(Debug, Clone)]
pub struct DetectedViolation {
    pub policy_id: Option<i32>,
    pub metric_name: String,
    pub category: String,
    pub detected_value: serde_json::Value,
    pub threshold_value: Option<serde_json::Value>,
    pub severity: String,
    pub event_details: Option<serde_json::Value>,
}

impl ComplianceEngine {
    pub fn new(pg_pool: PostgresPool) -> Self {
        Self { pg_pool }
    }

    /// Load active compliance policies for a target
    pub async fn load_policies(
        &self,
        target_id: i32,
    ) -> Result<Vec<CompliancePolicy>, sqlx::Error> {
        // Load both global policies (target_id = NULL) and target-specific policies
        let policies = sqlx::query_as::<_, CompliancePolicy>(
            r#"
            SELECT *
            FROM compliance_policies
            WHERE (target_id IS NULL OR target_id = $1)
              AND is_active = TRUE
            ORDER BY severity DESC, category
            "#,
        )
        .bind(target_id)
        .fetch_all(&self.pg_pool)
        .await?;

        Ok(policies)
    }

    /// Evaluate compliance for incoming monitoring data
    pub async fn evaluate_compliance(
        &self,
        target_id: i32,
        payload: &MonitoringDataPayload,
    ) -> anyhow::Result<Vec<DetectedViolation>> {
        let policies = self.load_policies(target_id).await?;
        let mut violations = Vec::new();

        for policy in policies {
            if let Some(violation) = self.check_policy(&policy, payload).await {
                violations.push(violation);
            }
        }

        Ok(violations)
    }

    /// Check a single policy against monitoring data
    async fn check_policy(
        &self,
        policy: &CompliancePolicy,
        payload: &MonitoringDataPayload,
    ) -> Option<DetectedViolation> {
        let metric_name = &policy.metric_name;
        let category = &policy.category;

        match category.as_str() {
            "ssh" | "network" => self.check_network_policy(policy, payload),
            "auditd" => self.check_auditd_policy(policy, payload),
            "sudo" => self.check_sudo_policy(policy, payload),
            "system" => self.check_system_policy(policy, payload),
            _ => None,
        }
    }

    /// Check network-related policies
    fn check_network_policy(
        &self,
        policy: &CompliancePolicy,
        payload: &MonitoringDataPayload,
    ) -> Option<DetectedViolation> {
        let network = payload.data.network.as_ref()?;
        let metric_name = &policy.metric_name;

        match metric_name.as_str() {
            "failed_ssh_attempts" => {
                let value = network.failed_ssh_attempts?;
                if self.exceeds_threshold(value, policy.threshold_value_max?) {
                    return Some(DetectedViolation {
                        policy_id: Some(policy.id),
                        metric_name: metric_name.clone(),
                        category: policy.category.clone(),
                        detected_value: json!(value),
                        threshold_value: Some(json!(policy.threshold_value_max)),
                        severity: policy.severity.clone(),
                        event_details: Some(json!({
                            "failed_attempts": value,
                            "threshold": policy.threshold_value_max,
                            "time_window_minutes": policy.time_window_minutes
                        })),
                    });
                }
            }
            "active_connections" => {
                let value = network.active_connections?;
                if self.exceeds_threshold(value, policy.threshold_value_max?) {
                    return Some(DetectedViolation {
                        policy_id: Some(policy.id),
                        metric_name: metric_name.clone(),
                        category: policy.category.clone(),
                        detected_value: json!(value),
                        threshold_value: Some(json!(policy.threshold_value_max)),
                        severity: policy.severity.clone(),
                        event_details: Some(json!({
                            "active_connections": value,
                            "threshold": policy.threshold_value_max
                        })),
                    });
                }
            }
            _ => {}
        }

        None
    }

    /// Check auditd-related policies
    fn check_auditd_policy(
        &self,
        policy: &CompliancePolicy,
        payload: &MonitoringDataPayload,
    ) -> Option<DetectedViolation> {
        let auditd = payload.data.auditd.as_ref()?;
        let metric_name = &policy.metric_name;

        match metric_name.as_str() {
            "failed_logins" => {
                let value = auditd.failed_logins?;
                if self.exceeds_threshold(value, policy.threshold_value_max?) {
                    return Some(DetectedViolation {
                        policy_id: Some(policy.id),
                        metric_name: metric_name.clone(),
                        category: policy.category.clone(),
                        detected_value: json!(value),
                        threshold_value: Some(json!(policy.threshold_value_max)),
                        severity: policy.severity.clone(),
                        event_details: Some(json!({
                            "failed_logins": value,
                            "threshold": policy.threshold_value_max,
                            "time_window_minutes": policy.time_window_minutes
                        })),
                    });
                }
            }
            "privilege_escalations" => {
                let value = auditd.privilege_escalations?;
                if self.exceeds_threshold(value, policy.threshold_value_max?) {
                    return Some(DetectedViolation {
                        policy_id: Some(policy.id),
                        metric_name: metric_name.clone(),
                        category: policy.category.clone(),
                        detected_value: json!(value),
                        threshold_value: Some(json!(policy.threshold_value_max)),
                        severity: policy.severity.clone(),
                        event_details: Some(json!({
                            "privilege_escalations": value,
                            "threshold": policy.threshold_value_max,
                            "status": auditd.status.clone().unwrap_or_default()
                        })),
                    });
                }
            }
            "config_changes" => {
                let value = auditd.config_changes?;
                // Config changes are critical - any change triggers violation
                if value > policy.threshold_value_max.unwrap_or(0) as i64 {
                    return Some(DetectedViolation {
                        policy_id: Some(policy.id),
                        metric_name: metric_name.clone(),
                        category: policy.category.clone(),
                        detected_value: json!(value),
                        threshold_value: Some(json!(policy.threshold_value_max)),
                        severity: policy.severity.clone(),
                        event_details: Some(json!({
                            "config_changes": value,
                            "threshold": policy.threshold_value_max,
                            "alert": "Critical system configuration files have been modified"
                        })),
                    });
                }
            }
            _ => {}
        }

        None
    }

    /// Check sudo-related policies
    fn check_sudo_policy(
        &self,
        policy: &CompliancePolicy,
        payload: &MonitoringDataPayload,
    ) -> Option<DetectedViolation> {
        let sudo = payload.data.sudo.as_ref()?;
        let metric_name = &policy.metric_name;

        match metric_name.as_str() {
            "failed_attempts" => {
                let value = sudo.failed_attempts?;
                if self.exceeds_threshold(value, policy.threshold_value_max?) {
                    return Some(DetectedViolation {
                        policy_id: Some(policy.id),
                        metric_name: metric_name.clone(),
                        category: policy.category.clone(),
                        detected_value: json!(value),
                        threshold_value: Some(json!(policy.threshold_value_max)),
                        severity: policy.severity.clone(),
                        event_details: Some(json!({
                            "failed_sudo_attempts": value,
                            "threshold": policy.threshold_value_max,
                            "unique_users": sudo.unique_users.clone().unwrap_or_default()
                        })),
                    });
                }
            }
            "commands_last_hour" => {
                let value = sudo.commands_last_hour?;
                if self.exceeds_threshold(value, policy.threshold_value_max?) {
                    return Some(DetectedViolation {
                        policy_id: Some(policy.id),
                        metric_name: metric_name.clone(),
                        category: policy.category.clone(),
                        detected_value: json!(value),
                        threshold_value: Some(json!(policy.threshold_value_max)),
                        severity: policy.severity.clone(),
                        event_details: Some(json!({
                            "sudo_commands": value,
                            "threshold": policy.threshold_value_max
                        })),
                    });
                }
            }
            _ => {}
        }

        None
    }

    /// Check system-related policies
    fn check_system_policy(
        &self,
        policy: &CompliancePolicy,
        payload: &MonitoringDataPayload,
    ) -> Option<DetectedViolation> {
        let metric_name = &policy.metric_name;

        match metric_name.as_str() {
            "cpu_usage" => {
                let system = payload.data.system_metrics.as_ref()?;
                let value = system.cpu_usage?;
                let threshold = policy.threshold_value_max? as f64;

                if value > threshold {
                    return Some(DetectedViolation {
                        policy_id: Some(policy.id),
                        metric_name: metric_name.clone(),
                        category: policy.category.clone(),
                        detected_value: json!(value),
                        threshold_value: Some(json!(threshold)),
                        severity: policy.severity.clone(),
                        event_details: Some(json!({
                            "cpu_usage": value,
                            "threshold": threshold
                        })),
                    });
                }
            }
            "memory_usage" => {
                let system = payload.data.system_metrics.as_ref()?;
                let value = system.memory_usage?;
                let threshold = policy.threshold_value_max? as f64;

                if value > threshold {
                    return Some(DetectedViolation {
                        policy_id: Some(policy.id),
                        metric_name: metric_name.clone(),
                        category: policy.category.clone(),
                        detected_value: json!(value),
                        threshold_value: Some(json!(threshold)),
                        severity: policy.severity.clone(),
                        event_details: Some(json!({
                            "memory_usage": value,
                            "threshold": threshold
                        })),
                    });
                }
            }
            "disk_usage" => {
                let system = payload.data.system_metrics.as_ref()?;
                let value = system.disk_usage?;
                let threshold = policy.threshold_value_max? as f64;

                if value > threshold {
                    return Some(DetectedViolation {
                        policy_id: Some(policy.id),
                        metric_name: metric_name.clone(),
                        category: policy.category.clone(),
                        detected_value: json!(value),
                        threshold_value: Some(json!(threshold)),
                        severity: policy.severity.clone(),
                        event_details: Some(json!({
                            "disk_usage": value,
                            "threshold": threshold
                        })),
                    });
                }
            }
            "zombie_processes" => {
                let processes = payload.data.processes.as_ref()?;
                let value = processes.zombie_processes?;

                if self.exceeds_threshold(value, policy.threshold_value_max?) {
                    return Some(DetectedViolation {
                        policy_id: Some(policy.id),
                        metric_name: metric_name.clone(),
                        category: policy.category.clone(),
                        detected_value: json!(value),
                        threshold_value: Some(json!(policy.threshold_value_max)),
                        severity: policy.severity.clone(),
                        event_details: Some(json!({
                            "zombie_processes": value,
                            "threshold": policy.threshold_value_max
                        })),
                    });
                }
            }
            "failed_services_count" => {
                let system = payload.data.system_metrics.as_ref()?;
                let failed_services = system.failed_services.as_ref()?;
                let value = failed_services.len() as i64;

                if value > policy.threshold_value_max.unwrap_or(0) as i64 {
                    return Some(DetectedViolation {
                        policy_id: Some(policy.id),
                        metric_name: metric_name.clone(),
                        category: policy.category.clone(),
                        detected_value: json!(value),
                        threshold_value: Some(json!(policy.threshold_value_max)),
                        severity: policy.severity.clone(),
                        event_details: Some(json!({
                            "failed_services_count": value,
                            "failed_services": failed_services,
                            "threshold": policy.threshold_value_max
                        })),
                    });
                }
            }
            _ => {}
        }

        None
    }

    /// Helper: Check if value exceeds threshold
    fn exceeds_threshold(&self, value: i64, threshold: i32) -> bool {
        value > threshold as i64
    }

    /// Record violations in database
    pub async fn record_violations(
        &self,
        target_id: i32,
        violations: Vec<DetectedViolation>,
    ) -> Result<Vec<i64>, sqlx::Error> {
        let mut violation_ids = Vec::new();

        for violation in violations {
            // Check if similar violation already exists (deduplication)
            let existing = sqlx::query_scalar::<_, i64>(
                r#"
                SELECT id FROM compliance_violations
                WHERE target_id = $1
                  AND metric_name = $2
                  AND status IN ('new', 'acknowledged', 'investigating')
                ORDER BY first_detected_at DESC
                LIMIT 1
                "#,
            )
            .bind(target_id)
            .bind(&violation.metric_name)
            .fetch_optional(&self.pg_pool)
            .await?;

            if let Some(existing_id) = existing {
                // Update existing violation (increment occurrences, update timestamp)
                sqlx::query(
                    r#"
                    UPDATE compliance_violations
                    SET last_detected_at = NOW(),
                        occurrences = occurrences + 1,
                        detected_value = $1
                    WHERE id = $2
                    "#,
                )
                .bind(&violation.detected_value)
                .bind(existing_id)
                .execute(&self.pg_pool)
                .await?;

                violation_ids.push(existing_id);
            } else {
                // Insert new violation
                let id = sqlx::query_scalar::<_, i64>(
                    r#"
                    INSERT INTO compliance_violations
                        (target_id, policy_id, metric_name, category, detected_value,
                         threshold_value, severity, event_details, status)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'new')
                    RETURNING id
                    "#,
                )
                .bind(target_id)
                .bind(violation.policy_id)
                .bind(&violation.metric_name)
                .bind(&violation.category)
                .bind(&violation.detected_value)
                .bind(&violation.threshold_value)
                .bind(&violation.severity)
                .bind(&violation.event_details)
                .fetch_one(&self.pg_pool)
                .await?;

                violation_ids.push(id);
            }
        }

        Ok(violation_ids)
    }

    /// Get compliance status for a target
    pub async fn get_compliance_status(
        &self,
        target_id: i32,
    ) -> Result<(String, i32), sqlx::Error> {
        // Count active violations by severity
        let (critical, high, medium, low) = sqlx::query_as::<_, (i64, i64, i64, i64)>(
            r#"
            SELECT
                COUNT(*) FILTER (WHERE severity = 'critical'),
                COUNT(*) FILTER (WHERE severity = 'high'),
                COUNT(*) FILTER (WHERE severity = 'medium'),
                COUNT(*) FILTER (WHERE severity = 'low')
            FROM compliance_violations
            WHERE target_id = $1
              AND status IN ('new', 'acknowledged', 'investigating')
            "#,
        )
        .bind(target_id)
        .fetch_one(&self.pg_pool)
        .await?;

        // Determine overall status
        let status = if critical > 0 {
            "critical"
        } else if high > 0 {
            "non_compliant"
        } else if medium > 0 {
            "warning"
        } else {
            "compliant"
        };

        // Calculate score
        let score = 100
            - (critical * 25).min(100)
            - (high * 10).min(50)
            - (medium * 5).min(30)
            - (low * 1).min(10);
        let score = score.max(0).min(100) as i32;

        Ok((status.to_string(), score))
    }
}
