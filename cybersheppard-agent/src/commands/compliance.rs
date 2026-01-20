// ============================================================================
// Compliance Module - Execute compliance scans
// ============================================================================

use anyhow::Result;
use chrono::Utc;
use std::process::Command;
use tracing::info;

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
    let requirement_lower = control.requirement.to_lowercase();

    // Set control_id for all results
    let mut result = if requirement_lower.contains("ssh") && requirement_lower.contains("mfa") {
        check_ssh_mfa().await
    } else if requirement_lower.contains("ssh") && (requirement_lower.contains("root") || requirement_lower.contains("permesso")) {
        check_ssh_root_login().await
    } else if requirement_lower.contains("ssh") && requirement_lower.contains("timeout") {
        check_ssh_timeout().await
    } else if requirement_lower.contains("firewall") {
        check_firewall().await
    } else if requirement_lower.contains("password") && requirement_lower.contains("policy") {
        check_password_policy().await
    } else if requirement_lower.contains("password") && (requirement_lower.contains("età") || requirement_lower.contains("scadenza")) {
        check_password_expiry().await
    } else if requirement_lower.contains("audit") || requirement_lower.contains("logging") {
        check_audit_logging().await
    } else if requirement_lower.contains("encryption") || requirement_lower.contains("cifratura") {
        check_encryption().await
    } else if requirement_lower.contains("antivirus") || requirement_lower.contains("malware") {
        check_antivirus().await
    } else if requirement_lower.contains("backup") {
        check_backup().await
    } else if requirement_lower.contains("patch") || requirement_lower.contains("aggiornament") || requirement_lower.contains("update") {
        check_patch_management().await
    } else if requirement_lower.contains("sudo") {
        check_sudo_config().await
    } else if requirement_lower.contains("selinux") || requirement_lower.contains("apparmor") {
        check_mandatory_access_control().await
    } else if requirement_lower.contains("fail2ban") || requirement_lower.contains("brute") {
        check_fail2ban().await
    } else if requirement_lower.contains("ntp") || requirement_lower.contains("time sync") {
        check_time_sync().await
    } else if requirement_lower.contains("umask") {
        check_umask().await
    } else if requirement_lower.contains("core dump") {
        check_core_dumps().await
    } else if requirement_lower.contains("sysctl") || requirement_lower.contains("kernel") {
        check_kernel_hardening().await
    } else if requirement_lower.contains("servizi inutilizzati") || requirement_lower.contains("unnecessary services") {
        check_unnecessary_services().await
    } else if requirement_lower.contains("permessi file") || requirement_lower.contains("file permission") {
        check_file_permissions().await
    } else {
        // Default: mark as not_applicable for unimplemented checks
        ControlCheckResult {
            control_id: control.control_id,
            status: "not_applicable".to_string(),
            evidence: Some("Check not yet implemented for this control".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        }
    };

    // Set the correct control_id
    result.control_id = control.control_id;
    result
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

// ============================================================================
// Additional Compliance Checks
// ============================================================================

async fn check_ssh_root_login() -> ControlCheckResult {
    let check = Command::new("grep")
        .args(&["^PermitRootLogin", "/etc/ssh/sshd_config"])
        .output();

    match check {
        Ok(output) if output.status.success() => {
            let config = String::from_utf8_lossy(&output.stdout);
            if config.contains("PermitRootLogin no") {
                ControlCheckResult {
                    control_id: 0,
                    status: "compliant".to_string(),
                    evidence: Some("SSH root login is disabled".to_string()),
                    gap_description: None,
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            } else {
                ControlCheckResult {
                    control_id: 0,
                    status: "non_compliant".to_string(),
                    evidence: Some(format!("SSH root login configuration: {}", config.trim())),
                    gap_description: Some("Set 'PermitRootLogin no' in /etc/ssh/sshd_config".to_string()),
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            }
        }
        _ => {
            ControlCheckResult {
                control_id: 0,
                status: "non_compliant".to_string(),
                evidence: Some("PermitRootLogin directive not found".to_string()),
                gap_description: Some("Add 'PermitRootLogin no' to /etc/ssh/sshd_config".to_string()),
                check_timestamp: Utc::now().to_rfc3339(),
            }
        }
    }
}

async fn check_ssh_timeout() -> ControlCheckResult {
    let check = Command::new("grep")
        .args(&["ClientAliveInterval", "/etc/ssh/sshd_config"])
        .output();

    match check {
        Ok(output) if output.status.success() => {
            let config = String::from_utf8_lossy(&output.stdout);
            ControlCheckResult {
                control_id: 0,
                status: "compliant".to_string(),
                evidence: Some(format!("SSH timeout configured: {}", config.trim())),
                gap_description: None,
                check_timestamp: Utc::now().to_rfc3339(),
            }
        }
        _ => {
            ControlCheckResult {
                control_id: 0,
                status: "non_compliant".to_string(),
                evidence: Some("SSH idle timeout not configured".to_string()),
                gap_description: Some("Configure ClientAliveInterval in sshd_config".to_string()),
                check_timestamp: Utc::now().to_rfc3339(),
            }
        }
    }
}

async fn check_password_expiry() -> ControlCheckResult {
    let check = Command::new("grep")
        .args(&["^PASS_MAX_DAYS", "/etc/login.defs"])
        .output();

    match check {
        Ok(output) if output.status.success() => {
            let config = String::from_utf8_lossy(&output.stdout);
            if let Some(days_str) = config.split_whitespace().nth(1) {
                if let Ok(days) = days_str.parse::<i32>() {
                    if days <= 90 {
                        return ControlCheckResult {
                            control_id: 0,
                            status: "compliant".to_string(),
                            evidence: Some(format!("Password expiry set to {} days", days)),
                            gap_description: None,
                            check_timestamp: Utc::now().to_rfc3339(),
                        };
                    }
                }
            }
            ControlCheckResult {
                control_id: 0,
                status: "non_compliant".to_string(),
                evidence: Some(format!("Password expiry: {}", config.trim())),
                gap_description: Some("Set PASS_MAX_DAYS to 90 or less in /etc/login.defs".to_string()),
                check_timestamp: Utc::now().to_rfc3339(),
            }
        }
        _ => {
            ControlCheckResult {
                control_id: 0,
                status: "non_compliant".to_string(),
                evidence: Some("Password expiry not configured".to_string()),
                gap_description: Some("Configure PASS_MAX_DAYS in /etc/login.defs".to_string()),
                check_timestamp: Utc::now().to_rfc3339(),
            }
        }
    }
}

async fn check_antivirus() -> ControlCheckResult {
    // Check for ClamAV
    let clamav = Command::new("systemctl")
        .args(&["is-active", "clamav-daemon"])
        .output();

    if let Ok(output) = clamav {
        let status = String::from_utf8_lossy(&output.stdout);
        if status.trim() == "active" {
            return ControlCheckResult {
                control_id: 0,
                status: "compliant".to_string(),
                evidence: Some("ClamAV antivirus is active".to_string()),
                gap_description: None,
                check_timestamp: Utc::now().to_rfc3339(),
            };
        }
    }

    ControlCheckResult {
        control_id: 0,
        status: "non_compliant".to_string(),
        evidence: Some("No active antivirus detected".to_string()),
        gap_description: Some("Install and configure antivirus (e.g., ClamAV)".to_string()),
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

async fn check_backup() -> ControlCheckResult {
    // Check for common backup tools
    let tools = vec!["bacula-fd", "duplicity", "restic", "borgbackup"];

    for tool in tools {
        if let Ok(output) = Command::new("which").arg(tool).output() {
            if output.status.success() {
                return ControlCheckResult {
                    control_id: 0,
                    status: "compliant".to_string(),
                    evidence: Some(format!("Backup tool detected: {}", tool)),
                    gap_description: None,
                    check_timestamp: Utc::now().to_rfc3339(),
                };
            }
        }
    }

    ControlCheckResult {
        control_id: 0,
        status: "non_compliant".to_string(),
        evidence: Some("No backup solution detected".to_string()),
        gap_description: Some("Install and configure automated backup solution".to_string()),
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

async fn check_patch_management() -> ControlCheckResult {
    // Check if unattended-upgrades is configured
    let check = Command::new("systemctl")
        .args(&["is-enabled", "unattended-upgrades"])
        .output();

    if let Ok(output) = check {
        let status = String::from_utf8_lossy(&output.stdout);
        if status.trim() == "enabled" {
            return ControlCheckResult {
                control_id: 0,
                status: "compliant".to_string(),
                evidence: Some("Automatic updates configured (unattended-upgrades)".to_string()),
                gap_description: None,
                check_timestamp: Utc::now().to_rfc3339(),
            };
        }
    }

    // Check for pending updates
    if let Ok(output) = Command::new("apt-get").args(&["-s", "upgrade"]).output() {
        let upgrades = String::from_utf8_lossy(&output.stdout);
        if upgrades.contains("0 upgraded") {
            return ControlCheckResult {
                control_id: 0,
                status: "compliant".to_string(),
                evidence: Some("System is up to date".to_string()),
                gap_description: None,
                check_timestamp: Utc::now().to_rfc3339(),
            };
        }
    }

    ControlCheckResult {
        control_id: 0,
        status: "non_compliant".to_string(),
        evidence: Some("Automatic updates not configured or pending updates".to_string()),
        gap_description: Some("Enable unattended-upgrades and apply pending updates".to_string()),
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

async fn check_sudo_config() -> ControlCheckResult {
    let check = Command::new("grep")
        .args(&["-r", "NOPASSWD", "/etc/sudoers.d/"])
        .output();

    match check {
        Ok(output) if output.status.success() => {
            let config = String::from_utf8_lossy(&output.stdout);
            if !config.is_empty() {
                ControlCheckResult {
                    control_id: 0,
                    status: "non_compliant".to_string(),
                    evidence: Some("NOPASSWD entries found in sudoers".to_string()),
                    gap_description: Some("Remove NOPASSWD from sudoers configuration".to_string()),
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            } else {
                ControlCheckResult {
                    control_id: 0,
                    status: "compliant".to_string(),
                    evidence: Some("No NOPASSWD entries in sudoers".to_string()),
                    gap_description: None,
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            }
        }
        _ => {
            ControlCheckResult {
                control_id: 0,
                status: "compliant".to_string(),
                evidence: Some("Sudo configuration appears secure".to_string()),
                gap_description: None,
                check_timestamp: Utc::now().to_rfc3339(),
            }
        }
    }
}

async fn check_mandatory_access_control() -> ControlCheckResult {
    // Check SELinux
    if let Ok(output) = Command::new("getenforce").output() {
        let status = String::from_utf8_lossy(&output.stdout);
        if status.trim() == "Enforcing" {
            return ControlCheckResult {
                control_id: 0,
                status: "compliant".to_string(),
                evidence: Some("SELinux is enforcing".to_string()),
                gap_description: None,
                check_timestamp: Utc::now().to_rfc3339(),
            };
        }
    }

    // Check AppArmor
    if let Ok(output) = Command::new("aa-status").output() {
        if output.status.success() {
            let status = String::from_utf8_lossy(&output.stdout);
            if status.contains("profiles are loaded") && !status.contains("0 profiles are loaded") {
                return ControlCheckResult {
                    control_id: 0,
                    status: "compliant".to_string(),
                    evidence: Some("AppArmor is active with loaded profiles".to_string()),
                    gap_description: None,
                    check_timestamp: Utc::now().to_rfc3339(),
                };
            }
        }
    }

    ControlCheckResult {
        control_id: 0,
        status: "non_compliant".to_string(),
        evidence: Some("No mandatory access control (SELinux/AppArmor) active".to_string()),
        gap_description: Some("Enable and configure SELinux or AppArmor".to_string()),
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

async fn check_fail2ban() -> ControlCheckResult {
    let check = Command::new("systemctl")
        .args(&["is-active", "fail2ban"])
        .output();

    match check {
        Ok(output) if output.status.success() => {
            let status = String::from_utf8_lossy(&output.stdout);
            if status.trim() == "active" {
                ControlCheckResult {
                    control_id: 0,
                    status: "compliant".to_string(),
                    evidence: Some("Fail2ban is active".to_string()),
                    gap_description: None,
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            } else {
                ControlCheckResult {
                    control_id: 0,
                    status: "non_compliant".to_string(),
                    evidence: Some("Fail2ban is installed but not active".to_string()),
                    gap_description: Some("Start and enable fail2ban service".to_string()),
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            }
        }
        _ => {
            ControlCheckResult {
                control_id: 0,
                status: "non_compliant".to_string(),
                evidence: Some("Fail2ban not installed".to_string()),
                gap_description: Some("Install and configure fail2ban for brute-force protection".to_string()),
                check_timestamp: Utc::now().to_rfc3339(),
            }
        }
    }
}

async fn check_time_sync() -> ControlCheckResult {
    let check = Command::new("timedatectl")
        .args(&["status"])
        .output();

    match check {
        Ok(output) if output.status.success() => {
            let status = String::from_utf8_lossy(&output.stdout);
            if status.contains("NTP service: active") || status.contains("System clock synchronized: yes") {
                ControlCheckResult {
                    control_id: 0,
                    status: "compliant".to_string(),
                    evidence: Some("NTP time synchronization is active".to_string()),
                    gap_description: None,
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            } else {
                ControlCheckResult {
                    control_id: 0,
                    status: "non_compliant".to_string(),
                    evidence: Some("Time synchronization not active".to_string()),
                    gap_description: Some("Enable NTP time synchronization".to_string()),
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            }
        }
        _ => {
            ControlCheckResult {
                control_id: 0,
                status: "error".to_string(),
                evidence: Some("Unable to check time synchronization status".to_string()),
                gap_description: None,
                check_timestamp: Utc::now().to_rfc3339(),
            }
        }
    }
}

async fn check_umask() -> ControlCheckResult {
    let check = Command::new("grep")
        .args(&["^umask", "/etc/login.defs"])
        .output();

    match check {
        Ok(output) if output.status.success() => {
            let config = String::from_utf8_lossy(&output.stdout);
            if config.contains("umask 077") || config.contains("umask 027") {
                ControlCheckResult {
                    control_id: 0,
                    status: "compliant".to_string(),
                    evidence: Some(format!("Secure umask configured: {}", config.trim())),
                    gap_description: None,
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            } else {
                ControlCheckResult {
                    control_id: 0,
                    status: "non_compliant".to_string(),
                    evidence: Some(format!("Umask: {}", config.trim())),
                    gap_description: Some("Set umask to 077 or 027 in /etc/login.defs".to_string()),
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            }
        }
        _ => {
            ControlCheckResult {
                control_id: 0,
                status: "non_compliant".to_string(),
                evidence: Some("Umask not configured".to_string()),
                gap_description: Some("Configure umask in /etc/login.defs".to_string()),
                check_timestamp: Utc::now().to_rfc3339(),
            }
        }
    }
}

async fn check_core_dumps() -> ControlCheckResult {
    let check = Command::new("grep")
        .args(&["hard.*core", "/etc/security/limits.conf"])
        .output();

    match check {
        Ok(output) if output.status.success() => {
            let config = String::from_utf8_lossy(&output.stdout);
            if config.contains("hard core 0") {
                ControlCheckResult {
                    control_id: 0,
                    status: "compliant".to_string(),
                    evidence: Some("Core dumps are disabled".to_string()),
                    gap_description: None,
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            } else {
                ControlCheckResult {
                    control_id: 0,
                    status: "non_compliant".to_string(),
                    evidence: Some("Core dumps may be enabled".to_string()),
                    gap_description: Some("Disable core dumps in /etc/security/limits.conf".to_string()),
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            }
        }
        _ => {
            ControlCheckResult {
                control_id: 0,
                status: "non_compliant".to_string(),
                evidence: Some("Core dump configuration not found".to_string()),
                gap_description: Some("Add '* hard core 0' to /etc/security/limits.conf".to_string()),
                check_timestamp: Utc::now().to_rfc3339(),
            }
        }
    }
}

async fn check_kernel_hardening() -> ControlCheckResult {
    let params = vec![
        ("net.ipv4.conf.all.rp_filter", "1"),
        ("net.ipv4.conf.default.rp_filter", "1"),
        ("net.ipv4.icmp_echo_ignore_broadcasts", "1"),
        ("net.ipv4.conf.all.accept_source_route", "0"),
    ];

    let mut compliant_params = 0;
    let mut total_params = params.len();

    for (param, expected) in &params {
        if let Ok(output) = Command::new("sysctl").arg(param).output() {
            let value = String::from_utf8_lossy(&output.stdout);
            if value.contains(&format!(" = {}", expected)) {
                compliant_params += 1;
            }
        }
    }

    if compliant_params >= total_params * 3 / 4 {
        ControlCheckResult {
            control_id: 0,
            status: "compliant".to_string(),
            evidence: Some(format!("{}/{} kernel security parameters configured", compliant_params, total_params)),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        }
    } else {
        ControlCheckResult {
            control_id: 0,
            status: "non_compliant".to_string(),
            evidence: Some(format!("Only {}/{} kernel parameters hardened", compliant_params, total_params)),
            gap_description: Some("Configure kernel hardening parameters in /etc/sysctl.conf".to_string()),
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}

async fn check_unnecessary_services() -> ControlCheckResult {
    let unnecessary = vec!["telnet", "rsh", "rlogin", "vsftpd", "xinetd"];
    let mut found_services = Vec::new();

    for service in &unnecessary {
        if let Ok(output) = Command::new("systemctl").args(&["is-active", service]).output() {
            let status = String::from_utf8_lossy(&output.stdout);
            if status.trim() == "active" {
                found_services.push(service.to_string());
            }
        }
    }

    if found_services.is_empty() {
        ControlCheckResult {
            control_id: 0,
            status: "compliant".to_string(),
            evidence: Some("No unnecessary services detected".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        }
    } else {
        ControlCheckResult {
            control_id: 0,
            status: "non_compliant".to_string(),
            evidence: Some(format!("Unnecessary services running: {}", found_services.join(", "))),
            gap_description: Some("Disable unnecessary services".to_string()),
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}

async fn check_file_permissions() -> ControlCheckResult {
    let critical_files = vec![
        ("/etc/passwd", "644"),
        ("/etc/shadow", "000"),
        ("/etc/group", "644"),
        ("/etc/gshadow", "000"),
    ];

    let mut issues = Vec::new();

    for (file, _expected) in &critical_files {
        if let Ok(output) = Command::new("stat").args(&["-c", "%a", file]).output() {
            let perms = String::from_utf8_lossy(&output.stdout);
            let perms = perms.trim();

            // Check if permissions are too permissive
            if file.contains("shadow") && perms != "000" && perms != "400" {
                issues.push(format!("{}: {}", file, perms));
            } else if !file.contains("shadow") && perms.starts_with('7') {
                issues.push(format!("{}: {}", file, perms));
            }
        }
    }

    if issues.is_empty() {
        ControlCheckResult {
            control_id: 0,
            status: "compliant".to_string(),
            evidence: Some("Critical file permissions are secure".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        }
    } else {
        ControlCheckResult {
            control_id: 0,
            status: "non_compliant".to_string(),
            evidence: Some(format!("Insecure permissions: {}", issues.join(", "))),
            gap_description: Some("Fix file permissions on critical system files".to_string()),
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}
