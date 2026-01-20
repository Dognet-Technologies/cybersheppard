// ============================================================================
// Hardening Module - Execute hardening templates
// ============================================================================

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::Value;
use std::process::Command;
use tracing::{info, warn, error};

use super::{CommandResponse, HardeningProgress};

#[derive(Debug, Deserialize)]
struct HardeningTemplate {
    metadata: TemplateMetadata,
    #[serde(default)]
    preflight_checks: Vec<PreflightCheck>,
    #[serde(default)]
    backup_files: Vec<String>,
    hardening_steps: Vec<HardeningStep>,
    #[serde(default)]
    verification_steps: Vec<VerificationStep>,
    #[serde(default)]
    health_checks: Vec<HealthCheck>,
}

#[derive(Debug, Deserialize)]
struct TemplateMetadata {
    name: String,
    version: String,
    requires_reboot: bool,
}

#[derive(Debug, Deserialize)]
struct PreflightCheck {
    name: String,
    command: String,
    expected_output: Option<String>,
    failure_action: String,
}

#[derive(Debug, Deserialize)]
struct HardeningStep {
    name: String,
    control_id: Option<String>,
    priority: String,
    tasks: Vec<HardeningTask>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "task_type")]
#[serde(rename_all = "snake_case")]
enum HardeningTask {
    FileContent {
        file: String,
        content: String,
        backup: Option<bool>,
    },
    Command {
        command: String,
        expected_exit_code: Option<i32>,
    },
    Service {
        name: String,
        state: String, // enabled, disabled, started, stopped
    },
    Package {
        name: String,
        action: String, // install, remove
    },
}

#[derive(Debug, Deserialize)]
struct VerificationStep {
    name: String,
    command: String,
    expected_output_contains: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct HealthCheck {
    name: String,
    critical: bool,
}

pub async fn execute_hardening(
    execution_id: i64,
    template_name: String,
    execution_mode: String,
    template_config: Value,
) -> Result<CommandResponse> {
    info!(
        "Starting hardening execution {} with template '{}' in mode '{}'",
        execution_id, template_name, execution_mode
    );

    // Parse template configuration
    let template: HardeningTemplate = serde_json::from_value(template_config)
        .context("Failed to parse hardening template")?;

    let total_steps = template.hardening_steps.len() as i32;
    let mut completed_steps = 0;
    let mut successful_steps = 0;
    let mut failed_steps = 0;
    let mut logs = Vec::new();
    let mut error_message = None;

    // Execute preflight checks
    logs.push("=== Preflight Checks ===".to_string());
    for check in &template.preflight_checks {
        info!("Running preflight check: {}", check.name);
        logs.push(format!("Preflight: {}", check.name));

        if let Err(e) = run_preflight_check(check).await {
            error!("Preflight check failed: {}", e);
            logs.push(format!("  ❌ FAILED: {}", e));

            if check.failure_action == "abort" {
                return Ok(CommandResponse::HardeningResponse {
                    execution_id,
                    status: "failed".to_string(),
                    progress: HardeningProgress {
                        total_steps,
                        completed_steps: 0,
                        successful_steps: 0,
                        failed_steps: 1,
                        current_step: Some(format!("Preflight: {}", check.name)),
                    },
                    logs,
                    error_message: Some(format!("Preflight check failed: {}", e)),
                });
            }
        } else {
            logs.push("  ✓ Passed".to_string());
        }
    }

    // Create backups if not in dry-run mode
    if execution_mode != "dry_run" {
        logs.push("=== Creating Backups ===".to_string());
        for file_path in &template.backup_files {
            info!("Backing up: {}", file_path);
            logs.push(format!("Backup: {}", file_path));

            if let Err(e) = backup_file(file_path).await {
                warn!("Backup failed for {}: {}", file_path, e);
                logs.push(format!("  ⚠ Warning: {}", e));
            } else {
                logs.push("  ✓ Backed up".to_string());
            }
        }
    }

    // Execute hardening steps
    logs.push("=== Hardening Steps ===".to_string());
    for (idx, step) in template.hardening_steps.iter().enumerate() {
        let current_step = format!("Step {}/{}: {}", idx + 1, total_steps, step.name);
        info!("{}", current_step);
        logs.push(current_step.clone());

        let mut step_success = true;

        for task in &step.tasks {
            let task_result = if execution_mode == "dry_run" {
                execute_task_dryrun(task).await
            } else {
                execute_task(task).await
            };

            match task_result {
                Ok(log) => {
                    logs.push(format!("  ✓ {}", log));
                }
                Err(e) => {
                    error!("Task failed: {}", e);
                    logs.push(format!("  ❌ {}", e));
                    step_success = false;
                    break;
                }
            }
        }

        completed_steps += 1;

        if step_success {
            successful_steps += 1;
            logs.push("  ✓ Step completed".to_string());
        } else {
            failed_steps += 1;
            error_message = Some(format!("Failed at step: {}", step.name));

            // Stop execution on critical failure
            if step.priority == "Critical" {
                logs.push("  ❌ Critical step failed, aborting".to_string());
                break;
            }
        }
    }

    // Run verification if in apply mode
    if execution_mode == "apply" && error_message.is_none() {
        logs.push("=== Verification ===".to_string());
        for verification in &template.verification_steps {
            info!("Verifying: {}", verification.name);
            logs.push(format!("Verify: {}", verification.name));

            if let Err(e) = run_verification(verification).await {
                warn!("Verification failed: {}", e);
                logs.push(format!("  ⚠ {}", e));
            } else {
                logs.push("  ✓ Verified".to_string());
            }
        }
    }

    let status = if error_message.is_some() {
        "failed"
    } else if execution_mode == "dry_run" {
        "completed_dry_run"
    } else {
        "completed"
    };

    info!(
        "Hardening execution {} finished: {} successful, {} failed",
        execution_id, successful_steps, failed_steps
    );

    Ok(CommandResponse::HardeningResponse {
        execution_id,
        status: status.to_string(),
        progress: HardeningProgress {
            total_steps,
            completed_steps,
            successful_steps,
            failed_steps,
            current_step: None,
        },
        logs,
        error_message,
    })
}

async fn run_preflight_check(check: &PreflightCheck) -> Result<()> {
    let output = Command::new("sh")
        .arg("-c")
        .arg(&check.command)
        .output()
        .context("Failed to execute preflight check")?;

    if !output.status.success() {
        return Err(anyhow::anyhow!("Command failed with exit code {}", output.status));
    }

    if let Some(expected) = &check.expected_output {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if !stdout.contains(expected) {
            return Err(anyhow::anyhow!(
                "Expected output '{}' not found in: {}",
                expected,
                stdout.trim()
            ));
        }
    }

    Ok(())
}

async fn backup_file(file_path: &str) -> Result<()> {
    let backup_path = format!("{}.backup.{}", file_path, chrono::Utc::now().timestamp());

    Command::new("cp")
        .args(&[file_path, &backup_path])
        .output()
        .context("Failed to create backup")?;

    Ok(())
}

async fn execute_task(task: &HardeningTask) -> Result<String> {
    match task {
        HardeningTask::FileContent { file, content, .. } => {
            std::fs::write(file, content)
                .context(format!("Failed to write file {}", file))?;
            Ok(format!("Wrote {} bytes to {}", content.len(), file))
        }

        HardeningTask::Command { command, expected_exit_code } => {
            let output = Command::new("sh")
                .arg("-c")
                .arg(command)
                .output()
                .context("Failed to execute command")?;

            let expected_code = expected_exit_code.unwrap_or(0);
            let actual_code = output.status.code().unwrap_or(-1);

            if actual_code != expected_code {
                return Err(anyhow::anyhow!(
                    "Command exited with code {} (expected {}): {}",
                    actual_code,
                    expected_code,
                    String::from_utf8_lossy(&output.stderr)
                ));
            }

            Ok(format!("Command executed: {}", command))
        }

        HardeningTask::Service { name, state } => {
            let action = match state.as_str() {
                "enabled" => "enable",
                "disabled" => "disable",
                "started" => "start",
                "stopped" => "stop",
                _ => return Err(anyhow::anyhow!("Invalid service state: {}", state)),
            };

            Command::new("systemctl")
                .args(&[action, name])
                .output()
                .context(format!("Failed to {} service {}", action, name))?;

            Ok(format!("Service {} {}", name, state))
        }

        HardeningTask::Package { name, action } => {
            let cmd = match action.as_str() {
                "install" => vec!["apt-get", "install", "-y", name],
                "remove" => vec!["apt-get", "remove", "-y", name],
                _ => return Err(anyhow::anyhow!("Invalid package action: {}", action)),
            };

            Command::new("sudo")
                .args(&cmd)
                .output()
                .context(format!("Failed to {} package {}", action, name))?;

            Ok(format!("Package {} {}", name, action))
        }
    }
}

async fn execute_task_dryrun(task: &HardeningTask) -> Result<String> {
    // In dry-run mode, just log what would be done
    match task {
        HardeningTask::FileContent { file, content, .. } => {
            Ok(format!("[DRY-RUN] Would write {} bytes to {}", content.len(), file))
        }
        HardeningTask::Command { command, .. } => {
            Ok(format!("[DRY-RUN] Would execute: {}", command))
        }
        HardeningTask::Service { name, state } => {
            Ok(format!("[DRY-RUN] Would set service {} to {}", name, state))
        }
        HardeningTask::Package { name, action } => {
            Ok(format!("[DRY-RUN] Would {} package {}", action, name))
        }
    }
}

async fn run_verification(verification: &VerificationStep) -> Result<()> {
    let output = Command::new("sh")
        .arg("-c")
        .arg(&verification.command)
        .output()
        .context("Failed to execute verification")?;

    if !output.status.success() {
        return Err(anyhow::anyhow!("Verification command failed"));
    }

    if let Some(expected_list) = &verification.expected_output_contains {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for expected in expected_list {
            if !stdout.contains(expected) {
                return Err(anyhow::anyhow!(
                    "Expected output '{}' not found",
                    expected
                ));
            }
        }
    }

    Ok(())
}
