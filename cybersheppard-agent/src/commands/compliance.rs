// ============================================================================
// Compliance Module - Execute compliance scans
// ============================================================================

use anyhow::Result;
use chrono::Utc;
use std::process::Command;
use tracing::{info, warn, error};

use super::{CommandResponse, ControlCheckResult, ControlToCheck, ScanSummary};

pub async fn execute_compliance_scan(
    scan_id: i64,
    controls: Vec<ControlToCheck>,
    _frameworks: Vec<String>,
) -> Result<CommandResponse> {
    let total_controls = controls.len() as i32;
    info!("Starting compliance scan {} with {} controls", scan_id, total_controls);

    let mut results = Vec::new();
    let mut compliant = 0;
    let mut non_compliant = 0;
    let mut not_applicable = 0;
    let mut errors = 0;

    for control in controls {
        info!("Checking control {}: {}", control.control_id, control.requirement);

        let result = check_control(&control).await;

        match result.status.as_str() {
            "compliant" => compliant += 1,
            "non_compliant" => non_compliant += 1,
            "not_applicable" => not_applicable += 1,
            "error" => errors += 1,
            _ => {}
        }

        results.push(result);
    }

    info!(
        "Compliance scan {} completed: {} compliant, {} non-compliant, {} N/A, {} errors",
        scan_id, compliant, non_compliant, not_applicable, errors
    );

    Ok(CommandResponse::ComplianceScanResponse {
        scan_id,
        results,
        summary: ScanSummary {
            total_controls,
            compliant,
            non_compliant,
            not_applicable,
            errors,
        },
    })
}

async fn check_control(control: &ControlToCheck) -> ControlCheckResult {
    // This is a simplified implementation. In production, you would:
    // 1. Parse the check_method from the control
    // 2. Execute the appropriate system check (file permissions, running processes, etc.)
    // 3. Collect evidence
    // 4. Determine compliance status

    let requirement_lower = control.requirement.to_lowercase();

    // Example checks based on requirement keywords
    if requirement_lower.contains("ssh") && requirement_lower.contains("mfa") {
        check_ssh_mfa().await
    } else if requirement_lower.contains("firewall") {
        check_firewall().await
    } else if requirement_lower.contains("password") && requirement_lower.contains("policy") {
        check_password_policy().await
    } else if requirement_lower.contains("audit") || requirement_lower.contains("logging") {
        check_audit_logging().await
    } else if requirement_lower.contains("encryption") {
        check_encryption().await
    } else {
        // Default: mark as not_applicable for unimplemented checks
        ControlCheckResult {
            control_id: control.control_id,
            status: "not_applicable".to_string(),
            evidence: Some("Check not yet implemented for this control".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}

async fn check_ssh_mfa() -> ControlCheckResult {
    // Check if SSH is configured with MFA/2FA
    let check = Command::new("grep")
        .args(&["-i", "AuthenticationMethods", "/etc/ssh/sshd_config"])
        .output();

    match check {
        Ok(output) if output.status.success() => {
            let config = String::from_utf8_lossy(&output.stdout);
            if config.contains("publickey,keyboard-interactive") || config.contains("publickey,password") {
                ControlCheckResult {
                    control_id: 0,
                    status: "compliant".to_string(),
                    evidence: Some(format!("SSH MFA configured: {}", config.trim())),
                    gap_description: None,
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            } else {
                ControlCheckResult {
                    control_id: 0,
                    status: "non_compliant".to_string(),
                    evidence: Some("SSH configuration found but MFA not properly configured".to_string()),
                    gap_description: Some("Configure AuthenticationMethods with MFA in sshd_config".to_string()),
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            }
        }
        _ => {
            ControlCheckResult {
                control_id: 0,
                status: "non_compliant".to_string(),
                evidence: Some("SSH MFA configuration not found".to_string()),
                gap_description: Some("Enable and configure MFA for SSH access".to_string()),
                check_timestamp: Utc::now().to_rfc3339(),
            }
        }
    }
}

async fn check_firewall() -> ControlCheckResult {
    // Check if firewall is active
    let ufw_check = Command::new("ufw").args(&["status"]).output();
    let iptables_check = Command::new("iptables").args(&["-L", "-n"]).output();

    if let Ok(output) = ufw_check {
        if output.status.success() {
            let status = String::from_utf8_lossy(&output.stdout);
            if status.contains("Status: active") {
                return ControlCheckResult {
                    control_id: 0,
                    status: "compliant".to_string(),
                    evidence: Some("UFW firewall is active".to_string()),
                    gap_description: None,
                    check_timestamp: Utc::now().to_rfc3339(),
                };
            }
        }
    }

    if let Ok(output) = iptables_check {
        if output.status.success() {
            let rules = String::from_utf8_lossy(&output.stdout);
            if !rules.contains("policy ACCEPT") || rules.lines().count() > 10 {
                return ControlCheckResult {
                    control_id: 0,
                    status: "compliant".to_string(),
                    evidence: Some("iptables firewall rules configured".to_string()),
                    gap_description: None,
                    check_timestamp: Utc::now().to_rfc3339(),
                };
            }
        }
    }

    ControlCheckResult {
        control_id: 0,
        status: "non_compliant".to_string(),
        evidence: Some("No active firewall detected".to_string()),
        gap_description: Some("Enable and configure firewall (UFW or iptables)".to_string()),
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

async fn check_password_policy() -> ControlCheckResult {
    // Check password policy configuration
    let check = Command::new("grep")
        .args(&["-E", "^password.*pam_pwquality.so", "/etc/pam.d/common-password"])
        .output();

    match check {
        Ok(output) if output.status.success() => {
            ControlCheckResult {
                control_id: 0,
                status: "compliant".to_string(),
                evidence: Some("Password quality module (pam_pwquality) is configured".to_string()),
                gap_description: None,
                check_timestamp: Utc::now().to_rfc3339(),
            }
        }
        _ => {
            ControlCheckResult {
                control_id: 0,
                status: "non_compliant".to_string(),
                evidence: Some("Password quality module not found in PAM configuration".to_string()),
                gap_description: Some("Configure pam_pwquality for password policy enforcement".to_string()),
                check_timestamp: Utc::now().to_rfc3339(),
            }
        }
    }
}

async fn check_audit_logging() -> ControlCheckResult {
    // Check if auditd is running
    let check = Command::new("systemctl")
        .args(&["is-active", "auditd"])
        .output();

    match check {
        Ok(output) if output.status.success() => {
            let status = String::from_utf8_lossy(&output.stdout);
            if status.trim() == "active" {
                ControlCheckResult {
                    control_id: 0,
                    status: "compliant".to_string(),
                    evidence: Some("auditd service is active and running".to_string()),
                    gap_description: None,
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            } else {
                ControlCheckResult {
                    control_id: 0,
                    status: "non_compliant".to_string(),
                    evidence: Some(format!("auditd service status: {}", status.trim())),
                    gap_description: Some("Start and enable auditd service".to_string()),
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            }
        }
        _ => {
            ControlCheckResult {
                control_id: 0,
                status: "non_compliant".to_string(),
                evidence: Some("auditd service not found or not installed".to_string()),
                gap_description: Some("Install and configure auditd for system auditing".to_string()),
                check_timestamp: Utc::now().to_rfc3339(),
            }
        }
    }
}

async fn check_encryption() -> ControlCheckResult {
    // Check if filesystem encryption is enabled
    let check = Command::new("lsblk")
        .args(&["-f"])
        .output();

    match check {
        Ok(output) if output.status.success() => {
            let fs_info = String::from_utf8_lossy(&output.stdout);
            if fs_info.contains("crypto_LUKS") {
                ControlCheckResult {
                    control_id: 0,
                    status: "compliant".to_string(),
                    evidence: Some("LUKS encryption detected on filesystem".to_string()),
                    gap_description: None,
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            } else {
                ControlCheckResult {
                    control_id: 0,
                    status: "non_compliant".to_string(),
                    evidence: Some("No filesystem encryption detected".to_string()),
                    gap_description: Some("Enable LUKS encryption for sensitive data".to_string()),
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            }
        }
        _ => {
            ControlCheckResult {
                control_id: 0,
                status: "error".to_string(),
                evidence: Some("Unable to check filesystem encryption status".to_string()),
                gap_description: None,
                check_timestamp: Utc::now().to_rfc3339(),
            }
        }
    }
}
