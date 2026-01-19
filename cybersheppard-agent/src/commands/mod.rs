// ============================================================================
// Commands Module - Handle commands from backend
// ============================================================================

pub mod compliance;
pub mod hardening;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command_type")]
#[serde(rename_all = "snake_case")]
pub enum CommandPayload {
    ComplianceScan {
        scan_id: i64,
        controls: Vec<ControlToCheck>,
        frameworks: Vec<String>,
    },
    ExecuteHardening {
        execution_id: i64,
        template_name: String,
        execution_mode: String, // "dry_run" or "apply"
        template_config: Value,
    },
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlToCheck {
    pub control_id: i32,
    pub requirement: String,
    pub priority: String,
    pub check_method: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "response_type")]
#[serde(rename_all = "snake_case")]
pub enum CommandResponse {
    ComplianceScanResponse {
        scan_id: i64,
        results: Vec<ControlCheckResult>,
        summary: ScanSummary,
    },
    HardeningResponse {
        execution_id: i64,
        status: String,
        progress: HardeningProgress,
        logs: Vec<String>,
        error_message: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlCheckResult {
    pub control_id: i32,
    pub status: String, // compliant, non_compliant, not_applicable, error
    pub evidence: Option<String>,
    pub gap_description: Option<String>,
    pub check_timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total_controls: i32,
    pub compliant: i32,
    pub non_compliant: i32,
    pub not_applicable: i32,
    pub errors: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardeningProgress {
    pub total_steps: i32,
    pub completed_steps: i32,
    pub successful_steps: i32,
    pub failed_steps: i32,
    pub current_step: Option<String>,
}

pub async fn handle_command(payload: CommandPayload) -> Result<CommandResponse> {
    match payload {
        CommandPayload::ComplianceScan { scan_id, controls, frameworks } => {
            compliance::execute_compliance_scan(scan_id, controls, frameworks).await
        }
        CommandPayload::ExecuteHardening { execution_id, template_name, execution_mode, template_config } => {
            hardening::execute_hardening(execution_id, template_name, execution_mode, template_config).await
        }
        CommandPayload::Unknown => {
            Err(anyhow::anyhow!("Unknown command type"))
        }
    }
}
