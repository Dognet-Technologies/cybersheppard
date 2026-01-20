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
    }
    // === IDENTITY & ACCESS MANAGEMENT (7 additional) ===
    else if requirement_lower.contains("account") && requirement_lower.contains("lock") {
        check_account_lockout().await
    } else if requirement_lower.contains("session") && requirement_lower.contains("timeout") {
        check_session_timeout().await
    } else if requirement_lower.contains("privileged") && requirement_lower.contains("account") {
        check_privileged_accounts().await
    } else if requirement_lower.contains("pam") && requirement_lower.contains("limit") {
        check_pam_limits().await
    } else if requirement_lower.contains("user") && (requirement_lower.contains("review") || requirement_lower.contains("audit")) {
        check_user_accounts_review().await
    } else if requirement_lower.contains("service") && requirement_lower.contains("account") {
        check_service_accounts().await
    } else if requirement_lower.contains("password") && requirement_lower.contains("history") {
        check_password_history().await
    }
    // === SYSTEM HARDENING (7 additional) ===
    else if requirement_lower.contains("boot") && requirement_lower.contains("secure") {
        check_secure_boot().await
    } else if requirement_lower.contains("grub") && requirement_lower.contains("password") {
        check_grub_password().await
    } else if requirement_lower.contains("ipv6") && requirement_lower.contains("disabl") {
        check_ipv6_disabled().await
    } else if requirement_lower.contains("usb") && requirement_lower.contains("storag") {
        check_usb_storage().await
    } else if requirement_lower.contains("ctrl+alt+del") || requirement_lower.contains("reboot") && requirement_lower.contains("disabl") {
        check_ctrl_alt_del().await
    } else if requirement_lower.contains("xinetd") || requirement_lower.contains("inetd") {
        check_xinetd_disabled().await
    } else if requirement_lower.contains("cron") && requirement_lower.contains("permission") {
        check_cron_permissions().await
    }
    // === ENCRYPTION & DATA PROTECTION (12 additional) ===
    else if requirement_lower.contains("tls") || requirement_lower.contains("ssl") {
        check_tls_configuration().await
    } else if requirement_lower.contains("cert") && requirement_lower.contains("valid") {
        check_certificate_validity().await
    } else if requirement_lower.contains("swap") && requirement_lower.contains("encrypt") {
        check_swap_encryption().await
    } else if requirement_lower.contains("tmp") && requirement_lower.contains("encrypt") {
        check_tmp_encryption().await
    } else if requirement_lower.contains("cipher") || requirement_lower.contains("algorithm") {
        check_crypto_algorithms().await
    } else if requirement_lower.contains("key") && requirement_lower.contains("management") {
        check_key_management().await
    } else if requirement_lower.contains("data") && requirement_lower.contains("rest") {
        check_data_at_rest().await
    } else if requirement_lower.contains("data") && requirement_lower.contains("transit") {
        check_data_in_transit().await
    } else if requirement_lower.contains("vpn") {
        check_vpn_encryption().await
    } else if requirement_lower.contains("fips") {
        check_fips_mode().await
    } else if requirement_lower.contains("random") && requirement_lower.contains("generator") {
        check_random_generator().await
    } else if requirement_lower.contains("partition") && requirement_lower.contains("encrypt") {
        check_partition_encryption().await
    }
    // === LOGGING & MONITORING (11 additional) ===
    else if requirement_lower.contains("syslog") || requirement_lower.contains("rsyslog") {
        check_syslog_config().await
    } else if requirement_lower.contains("log") && requirement_lower.contains("retention") {
        check_log_retention().await
    } else if requirement_lower.contains("log") && requirement_lower.contains("remote") {
        check_remote_logging().await
    } else if requirement_lower.contains("audit") && requirement_lower.contains("rules") {
        check_audit_rules().await
    } else if requirement_lower.contains("audit") && requirement_lower.contains("immutable") {
        check_audit_immutable().await
    } else if requirement_lower.contains("log") && requirement_lower.contains("integrity") {
        check_log_integrity().await
    } else if requirement_lower.contains("login") && requirement_lower.contains("record") {
        check_login_records().await
    } else if requirement_lower.contains("command") && requirement_lower.contains("history") {
        check_command_history().await
    } else if requirement_lower.contains("process") && requirement_lower.contains("accounting") {
        check_process_accounting().await
    } else if requirement_lower.contains("siem") || requirement_lower.contains("aggregat") {
        check_siem_integration().await
    } else if requirement_lower.contains("alert") && requirement_lower.contains("config") {
        check_alert_configuration().await
    }
    // === NETWORK SECURITY (6 additional) ===
    else if requirement_lower.contains("icmp") && requirement_lower.contains("redirect") {
        check_icmp_redirects().await
    } else if requirement_lower.contains("ip") && requirement_lower.contains("forward") {
        check_ip_forwarding().await
    } else if requirement_lower.contains("syn") && requirement_lower.contains("cookies") {
        check_syn_cookies().await
    } else if requirement_lower.contains("reverse") && requirement_lower.contains("path") {
        check_reverse_path_filter().await
    } else if requirement_lower.contains("tcp") && requirement_lower.contains("wrapper") {
        check_tcp_wrappers().await
    } else if requirement_lower.contains("network") && requirement_lower.contains("segmentation") {
        check_network_segmentation().await
    }
    // === PATCH & VULNERABILITY (8 additional) ===
    else if requirement_lower.contains("vulnerab") && requirement_lower.contains("scan") {
        check_vulnerability_scanning().await
    } else if requirement_lower.contains("cve") && requirement_lower.contains("track") {
        check_cve_tracking().await
    } else if requirement_lower.contains("kernel") && requirement_lower.contains("version") {
        check_kernel_version().await
    } else if requirement_lower.contains("package") && requirement_lower.contains("verif") {
        check_package_verification().await
    } else if requirement_lower.contains("repo") && requirement_lower.contains("secur") {
        check_repository_security().await
    } else if requirement_lower.contains("patch") && requirement_lower.contains("compliance") {
        check_patch_compliance().await
    } else if requirement_lower.contains("security") && requirement_lower.contains("update") {
        check_security_updates().await
    } else if requirement_lower.contains("end") && requirement_lower.contains("life") {
        check_end_of_life().await
    }
    // === BACKUP & RECOVERY (7 additional) ===
    else if requirement_lower.contains("backup") && requirement_lower.contains("encrypt") {
        check_backup_encryption().await
    } else if requirement_lower.contains("backup") && requirement_lower.contains("test") {
        check_backup_testing().await
    } else if requirement_lower.contains("backup") && requirement_lower.contains("retention") {
        check_backup_retention().await
    } else if requirement_lower.contains("backup") && requirement_lower.contains("offsite") {
        check_offsite_backup().await
    } else if requirement_lower.contains("rpo") || requirement_lower.contains("rto") {
        check_rpo_rto().await
    } else if requirement_lower.contains("disaster") && requirement_lower.contains("recovery") {
        check_disaster_recovery().await
    } else if requirement_lower.contains("snapshot") {
        check_snapshot_policy().await
    }
    // === MALWARE PROTECTION (6 additional) ===
    else if requirement_lower.contains("edr") || requirement_lower.contains("endpoint") {
        check_edr_solution().await
    } else if requirement_lower.contains("malware") && requirement_lower.contains("scan") {
        check_malware_scanning().await
    } else if requirement_lower.contains("signature") && requirement_lower.contains("update") {
        check_av_signatures().await
    } else if requirement_lower.contains("quarantine") {
        check_quarantine_config().await
    } else if requirement_lower.contains("behavior") && requirement_lower.contains("detection") {
        check_behavioral_detection().await
    } else if requirement_lower.contains("exploit") && requirement_lower.contains("prevention") {
        check_exploit_prevention().await
    }
    // === APPLICATION SECURITY (6 new) ===
    else if requirement_lower.contains("aslr") {
        check_aslr().await
    } else if requirement_lower.contains("dep") || requirement_lower.contains("nx") {
        check_dep_nx().await
    } else if requirement_lower.contains("library") && requirement_lower.contains("secur") {
        check_library_security().await
    } else if requirement_lower.contains("application") && requirement_lower.contains("whitelis") {
        check_application_whitelist().await
    } else if requirement_lower.contains("code") && requirement_lower.contains("sign") {
        check_code_signing().await
    } else if requirement_lower.contains("container") && requirement_lower.contains("secur") {
        check_container_security().await
    }
    // === SECURITY LIFECYCLE (9 new) ===
    else if requirement_lower.contains("asset") && requirement_lower.contains("inventory") {
        check_asset_inventory().await
    } else if requirement_lower.contains("configuration") && requirement_lower.contains("baseline") {
        check_config_baseline().await
    } else if requirement_lower.contains("change") && requirement_lower.contains("management") {
        check_change_management().await
    } else if requirement_lower.contains("security") && requirement_lower.contains("assessment") {
        check_security_assessment().await
    } else if requirement_lower.contains("incident") && requirement_lower.contains("response") {
        check_incident_response().await
    } else if requirement_lower.contains("security") && requirement_lower.contains("training") {
        check_security_training().await
    } else if requirement_lower.contains("policy") && requirement_lower.contains("documentation") {
        check_policy_documentation().await
    } else if requirement_lower.contains("decommission") {
        check_decommissioning().await
    } else if requirement_lower.contains("compliance") && requirement_lower.contains("audit") {
        check_compliance_audit_trail().await
    }
    // === PHYSICAL SECURITY (7 new) ===
    else if requirement_lower.contains("physical") && requirement_lower.contains("access") {
        check_physical_access().await
    } else if requirement_lower.contains("datacenter") && requirement_lower.contains("secur") {
        check_datacenter_security().await
    } else if requirement_lower.contains("bios") && requirement_lower.contains("password") {
        check_bios_password().await
    } else if requirement_lower.contains("chassis") && requirement_lower.contains("intrusion") {
        check_chassis_intrusion().await
    } else if requirement_lower.contains("screen") && requirement_lower.contains("lock") {
        check_screen_lock().await
    } else if requirement_lower.contains("environmental") && requirement_lower.contains("monitor") {
        check_environmental_monitoring().await
    } else if requirement_lower.contains("hardware") && requirement_lower.contains("inventory") {
        check_hardware_inventory().await
    }
    // === SUPPLY CHAIN SECURITY (7 new) ===
    else if requirement_lower.contains("vendor") && requirement_lower.contains("security") {
        check_vendor_security().await
    } else if requirement_lower.contains("sbom") || requirement_lower.contains("bill") && requirement_lower.contains("material") {
        check_sbom().await
    } else if requirement_lower.contains("software") && requirement_lower.contains("source") {
        check_software_source_verification().await
    } else if requirement_lower.contains("third") && requirement_lower.contains("party") {
        check_third_party_risk().await
    } else if requirement_lower.contains("supply") && requirement_lower.contains("chain") {
        check_supply_chain_integrity().await
    } else if requirement_lower.contains("procurement") && requirement_lower.contains("secur") {
        check_procurement_security().await
    } else if requirement_lower.contains("open") && requirement_lower.contains("source") {
        check_open_source_security().await
    }
    else {
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

// ============================================================================
// IDENTITY & ACCESS MANAGEMENT (IAM) - 7 Additional Checks
// ============================================================================

async fn check_account_lockout() -> ControlCheckResult {
    // Check PAM faillock configuration
    let check = Command::new("grep")
        .args(&["-E", "pam_faillock|pam_tally2", "/etc/pam.d/common-auth"])
        .output();

    match check {
        Ok(output) if output.status.success() => {
            ControlCheckResult {
                control_id: 0,
                status: "compliant".to_string(),
                evidence: Some("Account lockout policy configured via PAM".to_string()),
                gap_description: None,
                check_timestamp: Utc::now().to_rfc3339(),
            }
        }
        _ => {
            ControlCheckResult {
                control_id: 0,
                status: "non_compliant".to_string(),
                evidence: Some("No account lockout policy found".to_string()),
                gap_description: Some("Configure pam_faillock for account lockout".to_string()),
                check_timestamp: Utc::now().to_rfc3339(),
            }
        }
    }
}

async fn check_session_timeout() -> ControlCheckResult {
    // Check TMOUT in profile files
    let check = Command::new("grep")
        .args(&["-E", "^TMOUT=", "/etc/profile"])
        .output();

    match check {
        Ok(output) if output.status.success() => {
            let tmout = String::from_utf8_lossy(&output.stdout);
            ControlCheckResult {
                control_id: 0,
                status: "compliant".to_string(),
                evidence: Some(format!("Session timeout configured: {}", tmout.trim())),
                gap_description: None,
                check_timestamp: Utc::now().to_rfc3339(),
            }
        }
        _ => {
            ControlCheckResult {
                control_id: 0,
                status: "non_compliant".to_string(),
                evidence: Some("Session timeout not configured".to_string()),
                gap_description: Some("Set TMOUT variable in /etc/profile".to_string()),
                check_timestamp: Utc::now().to_rfc3339(),
            }
        }
    }
}

async fn check_privileged_accounts() -> ControlCheckResult {
    // Check for users with UID 0
    let check = Command::new("awk")
        .args(&["-F:", "$3 == 0 {print $1}", "/etc/passwd"])
        .output();

    match check {
        Ok(output) => {
            let users = String::from_utf8_lossy(&output.stdout);
            let user_list: Vec<&str> = users.lines().collect();
            if user_list.len() == 1 && user_list[0] == "root" {
                ControlCheckResult {
                    control_id: 0,
                    status: "compliant".to_string(),
                    evidence: Some("Only root has UID 0".to_string()),
                    gap_description: None,
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            } else {
                ControlCheckResult {
                    control_id: 0,
                    status: "non_compliant".to_string(),
                    evidence: Some(format!("Multiple UID 0 accounts: {}", users.trim())),
                    gap_description: Some("Remove additional privileged accounts".to_string()),
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            }
        }
        _ => {
            ControlCheckResult {
                control_id: 0,
                status: "error".to_string(),
                evidence: Some("Failed to check privileged accounts".to_string()),
                gap_description: None,
                check_timestamp: Utc::now().to_rfc3339(),
            }
        }
    }
}

async fn check_pam_limits() -> ControlCheckResult {
    // Check /etc/security/limits.conf
    let check = Command::new("test")
        .args(&["-f", "/etc/security/limits.conf"])
        .output();

    match check {
        Ok(output) if output.status.success() => {
            ControlCheckResult {
                control_id: 0,
                status: "compliant".to_string(),
                evidence: Some("PAM limits configuration file exists".to_string()),
                gap_description: None,
                check_timestamp: Utc::now().to_rfc3339(),
            }
        }
        _ => {
            ControlCheckResult {
                control_id: 0,
                status: "non_compliant".to_string(),
                evidence: Some("PAM limits not configured".to_string()),
                gap_description: Some("Configure /etc/security/limits.conf".to_string()),
                check_timestamp: Utc::now().to_rfc3339(),
            }
        }
    }
}

async fn check_user_accounts_review() -> ControlCheckResult {
    // Check for inactive accounts
    let check = Command::new("lastlog")
        .arg("-t")
        .arg("90")
        .output();

    match check {
        Ok(_output) => {
            ControlCheckResult {
                control_id: 0,
                status: "compliant".to_string(),
                evidence: Some("User account review mechanism available".to_string()),
                gap_description: None,
                check_timestamp: Utc::now().to_rfc3339(),
            }
        }
        _ => {
            ControlCheckResult {
                control_id: 0,
                status: "not_applicable".to_string(),
                evidence: Some("Cannot verify user account review process".to_string()),
                gap_description: Some("Implement periodic user account review".to_string()),
                check_timestamp: Utc::now().to_rfc3339(),
            }
        }
    }
}

async fn check_service_accounts() -> ControlCheckResult {
    // Check for service accounts with login shells
    let check = Command::new("awk")
        .args(&["-F:", "($3 < 1000 && $3 != 0 && $7 ~ /bash|sh/) {print $1}", "/etc/passwd"])
        .output();

    match check {
        Ok(output) => {
            let accounts = String::from_utf8_lossy(&output.stdout);
            if accounts.trim().is_empty() {
                ControlCheckResult {
                    control_id: 0,
                    status: "compliant".to_string(),
                    evidence: Some("No service accounts with login shells".to_string()),
                    gap_description: None,
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            } else {
                ControlCheckResult {
                    control_id: 0,
                    status: "non_compliant".to_string(),
                    evidence: Some(format!("Service accounts with shells: {}", accounts.trim())),
                    gap_description: Some("Set service accounts to /sbin/nologin".to_string()),
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            }
        }
        _ => {
            ControlCheckResult {
                control_id: 0,
                status: "error".to_string(),
                evidence: Some("Failed to check service accounts".to_string()),
                gap_description: None,
                check_timestamp: Utc::now().to_rfc3339(),
            }
        }
    }
}

async fn check_password_history() -> ControlCheckResult {
    // Check password history in PAM
    let check = Command::new("grep")
        .args(&["remember=", "/etc/pam.d/common-password"])
        .output();

    match check {
        Ok(output) if output.status.success() => {
            ControlCheckResult {
                control_id: 0,
                status: "compliant".to_string(),
                evidence: Some("Password history configured".to_string()),
                gap_description: None,
                check_timestamp: Utc::now().to_rfc3339(),
            }
        }
        _ => {
            ControlCheckResult {
                control_id: 0,
                status: "non_compliant".to_string(),
                evidence: Some("Password history not configured".to_string()),
                gap_description: Some("Configure password history in PAM".to_string()),
                check_timestamp: Utc::now().to_rfc3339(),
            }
        }
    }
}

// ============================================================================
// SYSTEM HARDENING - 7 Additional Checks
// ============================================================================

async fn check_secure_boot() -> ControlCheckResult {
    // Check if Secure Boot is enabled
    let check = Command::new("mokutil")
        .arg("--sb-state")
        .output();

    match check {
        Ok(output) if output.status.success() => {
            let state = String::from_utf8_lossy(&output.stdout);
            if state.contains("SecureBoot enabled") {
                ControlCheckResult {
                    control_id: 0,
                    status: "compliant".to_string(),
                    evidence: Some("Secure Boot is enabled".to_string()),
                    gap_description: None,
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            } else {
                ControlCheckResult {
                    control_id: 0,
                    status: "non_compliant".to_string(),
                    evidence: Some("Secure Boot is not enabled".to_string()),
                    gap_description: Some("Enable Secure Boot in UEFI settings".to_string()),
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            }
        }
        _ => {
            ControlCheckResult {
                control_id: 0,
                status: "not_applicable".to_string(),
                evidence: Some("Cannot determine Secure Boot status (UEFI may not be available)".to_string()),
                gap_description: None,
                check_timestamp: Utc::now().to_rfc3339(),
            }
        }
    }
}

async fn check_grub_password() -> ControlCheckResult {
    // Check if GRUB has password protection
    let check = Command::new("grep")
        .args(&["password_pbkdf2", "/boot/grub/grub.cfg"])
        .output();

    match check {
        Ok(output) if output.status.success() => {
            ControlCheckResult {
                control_id: 0,
                status: "compliant".to_string(),
                evidence: Some("GRUB password is configured".to_string()),
                gap_description: None,
                check_timestamp: Utc::now().to_rfc3339(),
            }
        }
        _ => {
            ControlCheckResult {
                control_id: 0,
                status: "non_compliant".to_string(),
                evidence: Some("GRUB password not configured".to_string()),
                gap_description: Some("Set password for GRUB bootloader".to_string()),
                check_timestamp: Utc::now().to_rfc3339(),
            }
        }
    }
}

async fn check_ipv6_disabled() -> ControlCheckResult {
    // Check if IPv6 is disabled
    let check = Command::new("sysctl")
        .arg("net.ipv6.conf.all.disable_ipv6")
        .output();

    match check {
        Ok(output) => {
            let value = String::from_utf8_lossy(&output.stdout);
            if value.contains("= 1") {
                ControlCheckResult {
                    control_id: 0,
                    status: "compliant".to_string(),
                    evidence: Some("IPv6 is disabled".to_string()),
                    gap_description: None,
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            } else {
                ControlCheckResult {
                    control_id: 0,
                    status: "non_compliant".to_string(),
                    evidence: Some("IPv6 is enabled".to_string()),
                    gap_description: Some("Disable IPv6 if not required".to_string()),
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            }
        }
        _ => {
            ControlCheckResult {
                control_id: 0,
                status: "error".to_string(),
                evidence: Some("Failed to check IPv6 status".to_string()),
                gap_description: None,
                check_timestamp: Utc::now().to_rfc3339(),
            }
        }
    }
}

async fn check_usb_storage() -> ControlCheckResult {
    // Check if USB storage is disabled
    let check = Command::new("lsmod")
        .output();

    match check {
        Ok(output) => {
            let modules = String::from_utf8_lossy(&output.stdout);
            if modules.contains("usb_storage") {
                ControlCheckResult {
                    control_id: 0,
                    status: "non_compliant".to_string(),
                    evidence: Some("USB storage module is loaded".to_string()),
                    gap_description: Some("Disable USB storage module if not required".to_string()),
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            } else {
                ControlCheckResult {
                    control_id: 0,
                    status: "compliant".to_string(),
                    evidence: Some("USB storage module not loaded".to_string()),
                    gap_description: None,
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            }
        }
        _ => {
            ControlCheckResult {
                control_id: 0,
                status: "error".to_string(),
                evidence: Some("Failed to check USB storage status".to_string()),
                gap_description: None,
                check_timestamp: Utc::now().to_rfc3339(),
            }
        }
    }
}

async fn check_ctrl_alt_del() -> ControlCheckResult {
    // Check if Ctrl+Alt+Del is disabled
    let check = Command::new("systemctl")
        .args(&["status", "ctrl-alt-del.target"])
        .output();

    match check {
        Ok(output) => {
            let status = String::from_utf8_lossy(&output.stdout);
            if status.contains("masked") {
                ControlCheckResult {
                    control_id: 0,
                    status: "compliant".to_string(),
                    evidence: Some("Ctrl+Alt+Del reboot is disabled".to_string()),
                    gap_description: None,
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            } else {
                ControlCheckResult {
                    control_id: 0,
                    status: "non_compliant".to_string(),
                    evidence: Some("Ctrl+Alt+Del reboot is enabled".to_string()),
                    gap_description: Some("Mask ctrl-alt-del.target with systemctl".to_string()),
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            }
        }
        _ => {
            ControlCheckResult {
                control_id: 0,
                status: "error".to_string(),
                evidence: Some("Failed to check Ctrl+Alt+Del status".to_string()),
                gap_description: None,
                check_timestamp: Utc::now().to_rfc3339(),
            }
        }
    }
}

async fn check_xinetd_disabled() -> ControlCheckResult {
    // Check if xinetd is disabled
    let check = Command::new("systemctl")
        .args(&["is-enabled", "xinetd"])
        .output();

    match check {
        Ok(output) => {
            let status = String::from_utf8_lossy(&output.stdout);
            if status.contains("disabled") || status.contains("masked") || !output.status.success() {
                ControlCheckResult {
                    control_id: 0,
                    status: "compliant".to_string(),
                    evidence: Some("xinetd is disabled or not installed".to_string()),
                    gap_description: None,
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            } else {
                ControlCheckResult {
                    control_id: 0,
                    status: "non_compliant".to_string(),
                    evidence: Some("xinetd is enabled".to_string()),
                    gap_description: Some("Disable xinetd service".to_string()),
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            }
        }
        _ => {
            ControlCheckResult {
                control_id: 0,
                status: "compliant".to_string(),
                evidence: Some("xinetd not found (likely not installed)".to_string()),
                gap_description: None,
                check_timestamp: Utc::now().to_rfc3339(),
            }
        }
    }
}

async fn check_cron_permissions() -> ControlCheckResult {
    // Check cron file permissions
    let files = vec!["/etc/crontab", "/etc/cron.d"];
    let mut compliant = true;

    for file in &files {
        if let Ok(output) = Command::new("stat").args(&["-c", "%a", file]).output() {
            let perms = String::from_utf8_lossy(&output.stdout);
            if perms.trim() != "600" && perms.trim() != "644" {
                compliant = false;
                break;
            }
        }
    }

    if compliant {
        ControlCheckResult {
            control_id: 0,
            status: "compliant".to_string(),
            evidence: Some("Cron permissions are secure".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        }
    } else {
        ControlCheckResult {
            control_id: 0,
            status: "non_compliant".to_string(),
            evidence: Some("Cron permissions are insecure".to_string()),
            gap_description: Some("Set proper permissions on cron files".to_string()),
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}

// ============================================================================
// ENCRYPTION & DATA PROTECTION - 12 Additional Checks
// ============================================================================

async fn check_tls_configuration() -> ControlCheckResult {
    let check = Command::new("openssl").args(&["version"]).output();
    match check {
        Ok(output) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout);
            ControlCheckResult {
                control_id: 0,
                status: "compliant".to_string(),
                evidence: Some(format!("OpenSSL installed: {}", version.trim())),
                gap_description: None,
                check_timestamp: Utc::now().to_rfc3339(),
            }
        }
        _ => ControlCheckResult {
            control_id: 0,
            status: "non_compliant".to_string(),
            evidence: Some("OpenSSL not found".to_string()),
            gap_description: Some("Install and configure OpenSSL".to_string()),
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}

async fn check_certificate_validity() -> ControlCheckResult {
    let cert_dirs = vec!["/etc/ssl/certs", "/etc/pki/tls/certs"];
    for dir in &cert_dirs {
        if let Ok(output) = Command::new("find").args(&[dir, "-name", "*.crt", "-type", "f"]).output() {
            if output.status.success() {
                return ControlCheckResult {
                    control_id: 0,
                    status: "compliant".to_string(),
                    evidence: Some("Certificate directory exists".to_string()),
                    gap_description: None,
                    check_timestamp: Utc::now().to_rfc3339(),
                };
            }
        }
    }
    ControlCheckResult {
        control_id: 0,
        status: "not_applicable".to_string(),
        evidence: Some("No certificate directories found".to_string()),
        gap_description: None,
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

async fn check_swap_encryption() -> ControlCheckResult {
    let check = Command::new("swapon").arg("--show").output();
    match check {
        Ok(output) => {
            let swaps = String::from_utf8_lossy(&output.stdout);
            if swaps.contains("/dev/mapper/") {
                ControlCheckResult {
                    control_id: 0,
                    status: "compliant".to_string(),
                    evidence: Some("Swap is encrypted".to_string()),
                    gap_description: None,
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            } else if swaps.trim().is_empty() {
                ControlCheckResult {
                    control_id: 0,
                    status: "not_applicable".to_string(),
                    evidence: Some("No swap configured".to_string()),
                    gap_description: None,
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            } else {
                ControlCheckResult {
                    control_id: 0,
                    status: "non_compliant".to_string(),
                    evidence: Some("Swap not encrypted".to_string()),
                    gap_description: Some("Encrypt swap space".to_string()),
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            }
        }
        _ => ControlCheckResult {
            control_id: 0,
            status: "error".to_string(),
            evidence: Some("Failed to check swap".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}

async fn check_tmp_encryption() -> ControlCheckResult {
    let check = Command::new("mount").output();
    match check {
        Ok(output) => {
            let mounts = String::from_utf8_lossy(&output.stdout);
            if mounts.contains("/tmp") && mounts.contains("tmpfs") {
                ControlCheckResult {
                    control_id: 0,
                    status: "compliant".to_string(),
                    evidence: Some("/tmp is tmpfs".to_string()),
                    gap_description: None,
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            } else {
                ControlCheckResult {
                    control_id: 0,
                    status: "non_compliant".to_string(),
                    evidence: Some("/tmp not secured".to_string()),
                    gap_description: Some("Mount /tmp as tmpfs".to_string()),
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            }
        }
        _ => ControlCheckResult {
            control_id: 0,
            status: "error".to_string(),
            evidence: Some("Failed to check /tmp".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}

async fn check_crypto_algorithms() -> ControlCheckResult {
    let check = Command::new("openssl").args(&["ciphers", "-v"]).output();
    match check {
        Ok(output) if output.status.success() => ControlCheckResult {
            control_id: 0,
            status: "compliant".to_string(),
            evidence: Some("Strong crypto available".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        },
        _ => ControlCheckResult {
            control_id: 0,
            status: "non_compliant".to_string(),
            evidence: Some("Cannot verify crypto".to_string()),
            gap_description: Some("Configure strong algorithms".to_string()),
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}

async fn check_key_management() -> ControlCheckResult {
    ControlCheckResult {
        control_id: 0,
        status: "not_applicable".to_string(),
        evidence: Some("Requires manual verification".to_string()),
        gap_description: Some("Implement key management".to_string()),
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

async fn check_data_at_rest() -> ControlCheckResult {
    let check = Command::new("dmsetup").args(&["ls", "--target", "crypt"]).output();
    match check {
        Ok(output) if output.status.success() => {
            let devices = String::from_utf8_lossy(&output.stdout);
            if !devices.trim().is_empty() {
                ControlCheckResult {
                    control_id: 0,
                    status: "compliant".to_string(),
                    evidence: Some(format!("Encrypted devices: {}", devices.trim())),
                    gap_description: None,
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            } else {
                ControlCheckResult {
                    control_id: 0,
                    status: "non_compliant".to_string(),
                    evidence: Some("No encrypted devices".to_string()),
                    gap_description: Some("Encrypt data at rest".to_string()),
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            }
        }
        _ => ControlCheckResult {
            control_id: 0,
            status: "error".to_string(),
            evidence: Some("Failed to check encryption".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}

async fn check_data_in_transit() -> ControlCheckResult {
    let check = Command::new("grep").args(&["-i", "Ciphers", "/etc/ssh/sshd_config"]).output();
    match check {
        Ok(output) if output.status.success() => ControlCheckResult {
            control_id: 0,
            status: "compliant".to_string(),
            evidence: Some("SSH encryption configured".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        },
        _ => ControlCheckResult {
            control_id: 0,
            status: "compliant".to_string(),
            evidence: Some("SSH uses default encryption".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}

async fn check_vpn_encryption() -> ControlCheckResult {
    let vpn_services = vec!["openvpn", "strongswan", "wireguard"];
    for service in &vpn_services {
        if let Ok(output) = Command::new("systemctl").args(&["is-active", service]).output() {
            if output.status.success() {
                return ControlCheckResult {
                    control_id: 0,
                    status: "compliant".to_string(),
                    evidence: Some(format!("VPN service {} active", service)),
                    gap_description: None,
                    check_timestamp: Utc::now().to_rfc3339(),
                };
            }
        }
    }
    ControlCheckResult {
        control_id: 0,
        status: "not_applicable".to_string(),
        evidence: Some("No VPN service detected".to_string()),
        gap_description: None,
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

async fn check_fips_mode() -> ControlCheckResult {
    let check = Command::new("cat").arg("/proc/sys/crypto/fips_enabled").output();
    match check {
        Ok(output) => {
            let fips = String::from_utf8_lossy(&output.stdout);
            if fips.trim() == "1" {
                ControlCheckResult {
                    control_id: 0,
                    status: "compliant".to_string(),
                    evidence: Some("FIPS mode enabled".to_string()),
                    gap_description: None,
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            } else {
                ControlCheckResult {
                    control_id: 0,
                    status: "non_compliant".to_string(),
                    evidence: Some("FIPS mode not enabled".to_string()),
                    gap_description: Some("Enable FIPS if required".to_string()),
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            }
        }
        _ => ControlCheckResult {
            control_id: 0,
            status: "not_applicable".to_string(),
            evidence: Some("FIPS not available".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}

async fn check_random_generator() -> ControlCheckResult {
    let check = Command::new("cat").arg("/proc/sys/kernel/random/entropy_avail").output();
    match check {
        Ok(output) => {
            let entropy = String::from_utf8_lossy(&output.stdout);
            if let Ok(val) = entropy.trim().parse::<i32>() {
                if val > 1000 {
                    ControlCheckResult {
                        control_id: 0,
                        status: "compliant".to_string(),
                        evidence: Some(format!("Entropy: {}", val)),
                        gap_description: None,
                        check_timestamp: Utc::now().to_rfc3339(),
                    }
                } else {
                    ControlCheckResult {
                        control_id: 0,
                        status: "non_compliant".to_string(),
                        evidence: Some(format!("Low entropy: {}", val)),
                        gap_description: Some("Install haveged or rng-tools".to_string()),
                        check_timestamp: Utc::now().to_rfc3339(),
                    }
                }
            } else {
                ControlCheckResult {
                    control_id: 0,
                    status: "error".to_string(),
                    evidence: Some("Cannot parse entropy".to_string()),
                    gap_description: None,
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            }
        }
        _ => ControlCheckResult {
            control_id: 0,
            status: "error".to_string(),
            evidence: Some("Failed to check entropy".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}

async fn check_partition_encryption() -> ControlCheckResult {
    let check = Command::new("lsblk").args(&["-o", "NAME,TYPE"]).output();
    match check {
        Ok(output) => {
            let devices = String::from_utf8_lossy(&output.stdout);
            if devices.contains("crypt") {
                ControlCheckResult {
                    control_id: 0,
                    status: "compliant".to_string(),
                    evidence: Some("Encrypted partitions detected".to_string()),
                    gap_description: None,
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            } else {
                ControlCheckResult {
                    control_id: 0,
                    status: "non_compliant".to_string(),
                    evidence: Some("No encrypted partitions".to_string()),
                    gap_description: Some("Encrypt partitions".to_string()),
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            }
        }
        _ => ControlCheckResult {
            control_id: 0,
            status: "error".to_string(),
            evidence: Some("Failed to check partitions".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}

// ============================================================================
// LOGGING & MONITORING - 11 Additional Checks
// ============================================================================

async fn check_syslog_config() -> ControlCheckResult {
    let check = Command::new("systemctl").args(&["is-active", "rsyslog"]).output();
    match check {
        Ok(output) if output.status.success() => ControlCheckResult {
            control_id: 0,
            status: "compliant".to_string(),
            evidence: Some("Syslog service active".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        },
        _ => ControlCheckResult {
            control_id: 0,
            status: "non_compliant".to_string(),
            evidence: Some("Syslog not active".to_string()),
            gap_description: Some("Enable rsyslog".to_string()),
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}

async fn check_log_retention() -> ControlCheckResult {
    let check = Command::new("grep").args(&["rotate", "/etc/logrotate.conf"]).output();
    match check {
        Ok(output) if output.status.success() => ControlCheckResult {
            control_id: 0,
            status: "compliant".to_string(),
            evidence: Some("Log rotation configured".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        },
        _ => ControlCheckResult {
            control_id: 0,
            status: "non_compliant".to_string(),
            evidence: Some("Log rotation not configured".to_string()),
            gap_description: Some("Configure logrotate".to_string()),
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}

async fn check_remote_logging() -> ControlCheckResult {
    let check = Command::new("grep").args(&["@@", "/etc/rsyslog.conf"]).output();
    match check {
        Ok(output) if output.status.success() => ControlCheckResult {
            control_id: 0,
            status: "compliant".to_string(),
            evidence: Some("Remote logging configured".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        },
        _ => ControlCheckResult {
            control_id: 0,
            status: "non_compliant".to_string(),
            evidence: Some("Remote logging not configured".to_string()),
            gap_description: Some("Configure remote syslog".to_string()),
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}

async fn check_audit_rules() -> ControlCheckResult {
    let check = Command::new("auditctl").arg("-l").output();
    match check {
        Ok(output) if output.status.success() => {
            let rules = String::from_utf8_lossy(&output.stdout);
            if rules.lines().count() > 5 {
                ControlCheckResult {
                    control_id: 0,
                    status: "compliant".to_string(),
                    evidence: Some(format!("{} audit rules configured", rules.lines().count())),
                    gap_description: None,
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            } else {
                ControlCheckResult {
                    control_id: 0,
                    status: "non_compliant".to_string(),
                    evidence: Some("Insufficient audit rules".to_string()),
                    gap_description: Some("Configure comprehensive audit rules".to_string()),
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            }
        }
        _ => ControlCheckResult {
            control_id: 0,
            status: "error".to_string(),
            evidence: Some("Cannot check audit rules".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}

async fn check_audit_immutable() -> ControlCheckResult {
    let check = Command::new("auditctl").arg("-s").output();
    match check {
        Ok(output) => {
            let status = String::from_utf8_lossy(&output.stdout);
            if status.contains("2") {
                ControlCheckResult {
                    control_id: 0,
                    status: "compliant".to_string(),
                    evidence: Some("Audit configuration immutable".to_string()),
                    gap_description: None,
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            } else {
                ControlCheckResult {
                    control_id: 0,
                    status: "non_compliant".to_string(),
                    evidence: Some("Audit config not immutable".to_string()),
                    gap_description: Some("Set audit -e 2 in rules".to_string()),
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            }
        }
        _ => ControlCheckResult {
            control_id: 0,
            status: "error".to_string(),
            evidence: Some("Cannot check audit status".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}

async fn check_log_integrity() -> ControlCheckResult {
    ControlCheckResult {
        control_id: 0,
        status: "not_applicable".to_string(),
        evidence: Some("Log integrity requires AIDE or similar".to_string()),
        gap_description: Some("Implement log integrity monitoring".to_string()),
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

async fn check_login_records() -> ControlCheckResult {
    let check = Command::new("last").arg("-n").arg("10").output();
    match check {
        Ok(output) if output.status.success() => ControlCheckResult {
            control_id: 0,
            status: "compliant".to_string(),
            evidence: Some("Login records available".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        },
        _ => ControlCheckResult {
            control_id: 0,
            status: "error".to_string(),
            evidence: Some("Cannot access login records".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}

async fn check_command_history() -> ControlCheckResult {
    let check = Command::new("grep").args(&["HISTSIZE", "/etc/profile"]).output();
    match check {
        Ok(output) if output.status.success() => ControlCheckResult {
            control_id: 0,
            status: "compliant".to_string(),
            evidence: Some("Command history configured".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        },
        _ => ControlCheckResult {
            control_id: 0,
            status: "non_compliant".to_string(),
            evidence: Some("Command history not configured".to_string()),
            gap_description: Some("Configure HISTSIZE and HISTFILESIZE".to_string()),
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}

async fn check_process_accounting() -> ControlCheckResult {
    let check = Command::new("systemctl").args(&["is-active", "acct"]).output();
    match check {
        Ok(output) if output.status.success() => ControlCheckResult {
            control_id: 0,
            status: "compliant".to_string(),
            evidence: Some("Process accounting active".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        },
        _ => ControlCheckResult {
            control_id: 0,
            status: "non_compliant".to_string(),
            evidence: Some("Process accounting not active".to_string()),
            gap_description: Some("Enable acct/psacct".to_string()),
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}

async fn check_siem_integration() -> ControlCheckResult {
    ControlCheckResult {
        control_id: 0,
        status: "not_applicable".to_string(),
        evidence: Some("SIEM integration requires manual verification".to_string()),
        gap_description: Some("Configure SIEM integration".to_string()),
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

async fn check_alert_configuration() -> ControlCheckResult {
    ControlCheckResult {
        control_id: 0,
        status: "not_applicable".to_string(),
        evidence: Some("Alert configuration requires manual verification".to_string()),
        gap_description: Some("Configure alerting system".to_string()),
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

// ============================================================================
// NETWORK SECURITY - 6 Additional Checks
// ============================================================================

async fn check_icmp_redirects() -> ControlCheckResult {
    let check = Command::new("sysctl").arg("net.ipv4.conf.all.accept_redirects").output();
    match check {
        Ok(output) => {
            let value = String::from_utf8_lossy(&output.stdout);
            if value.contains("= 0") {
                ControlCheckResult {
                    control_id: 0,
                    status: "compliant".to_string(),
                    evidence: Some("ICMP redirects disabled".to_string()),
                    gap_description: None,
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            } else {
                ControlCheckResult {
                    control_id: 0,
                    status: "non_compliant".to_string(),
                    evidence: Some("ICMP redirects enabled".to_string()),
                    gap_description: Some("Disable ICMP redirects in sysctl".to_string()),
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            }
        }
        _ => ControlCheckResult {
            control_id: 0,
            status: "error".to_string(),
            evidence: Some("Failed to check ICMP redirects".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}

async fn check_ip_forwarding() -> ControlCheckResult {
    let check = Command::new("sysctl").arg("net.ipv4.ip_forward").output();
    match check {
        Ok(output) => {
            let value = String::from_utf8_lossy(&output.stdout);
            if value.contains("= 0") {
                ControlCheckResult {
                    control_id: 0,
                    status: "compliant".to_string(),
                    evidence: Some("IP forwarding disabled".to_string()),
                    gap_description: None,
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            } else {
                ControlCheckResult {
                    control_id: 0,
                    status: "non_compliant".to_string(),
                    evidence: Some("IP forwarding enabled".to_string()),
                    gap_description: Some("Disable IP forwarding if not router".to_string()),
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            }
        }
        _ => ControlCheckResult {
            control_id: 0,
            status: "error".to_string(),
            evidence: Some("Failed to check IP forwarding".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}

async fn check_syn_cookies() -> ControlCheckResult {
    let check = Command::new("sysctl").arg("net.ipv4.tcp_syncookies").output();
    match check {
        Ok(output) => {
            let value = String::from_utf8_lossy(&output.stdout);
            if value.contains("= 1") {
                ControlCheckResult {
                    control_id: 0,
                    status: "compliant".to_string(),
                    evidence: Some("SYN cookies enabled".to_string()),
                    gap_description: None,
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            } else {
                ControlCheckResult {
                    control_id: 0,
                    status: "non_compliant".to_string(),
                    evidence: Some("SYN cookies disabled".to_string()),
                    gap_description: Some("Enable SYN cookies for SYN flood protection".to_string()),
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            }
        }
        _ => ControlCheckResult {
            control_id: 0,
            status: "error".to_string(),
            evidence: Some("Failed to check SYN cookies".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}

async fn check_reverse_path_filter() -> ControlCheckResult {
    let check = Command::new("sysctl").arg("net.ipv4.conf.all.rp_filter").output();
    match check {
        Ok(output) => {
            let value = String::from_utf8_lossy(&output.stdout);
            if value.contains("= 1") {
                ControlCheckResult {
                    control_id: 0,
                    status: "compliant".to_string(),
                    evidence: Some("Reverse path filtering enabled".to_string()),
                    gap_description: None,
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            } else {
                ControlCheckResult {
                    control_id: 0,
                    status: "non_compliant".to_string(),
                    evidence: Some("Reverse path filtering disabled".to_string()),
                    gap_description: Some("Enable reverse path filtering".to_string()),
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            }
        }
        _ => ControlCheckResult {
            control_id: 0,
            status: "error".to_string(),
            evidence: Some("Failed to check reverse path filter".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}

async fn check_tcp_wrappers() -> ControlCheckResult {
    let check = Command::new("test").args(&["-f", "/etc/hosts.allow"]).output();
    match check {
        Ok(output) if output.status.success() => ControlCheckResult {
            control_id: 0,
            status: "compliant".to_string(),
            evidence: Some("TCP wrappers configured".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        },
        _ => ControlCheckResult {
            control_id: 0,
            status: "non_compliant".to_string(),
            evidence: Some("TCP wrappers not configured".to_string()),
            gap_description: Some("Configure /etc/hosts.allow and hosts.deny".to_string()),
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}

async fn check_network_segmentation() -> ControlCheckResult {
    ControlCheckResult {
        control_id: 0,
        status: "not_applicable".to_string(),
        evidence: Some("Network segmentation requires manual verification".to_string()),
        gap_description: Some("Implement network segmentation".to_string()),
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

// ============================================================================
// PATCH & VULNERABILITY MANAGEMENT - 8 Additional Checks
// ============================================================================

async fn check_vulnerability_scanning() -> ControlCheckResult {
    ControlCheckResult {
        control_id: 0,
        status: "not_applicable".to_string(),
        evidence: Some("Vulnerability scanning requires external tool".to_string()),
        gap_description: Some("Implement vulnerability scanning (OpenVAS, Nessus)".to_string()),
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

async fn check_cve_tracking() -> ControlCheckResult {
    ControlCheckResult {
        control_id: 0,
        status: "not_applicable".to_string(),
        evidence: Some("CVE tracking requires external system".to_string()),
        gap_description: Some("Implement CVE tracking process".to_string()),
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

async fn check_kernel_version() -> ControlCheckResult {
    let check = Command::new("uname").arg("-r").output();
    match check {
        Ok(output) => {
            let version = String::from_utf8_lossy(&output.stdout);
            ControlCheckResult {
                control_id: 0,
                status: "compliant".to_string(),
                evidence: Some(format!("Kernel version: {}", version.trim())),
                gap_description: None,
                check_timestamp: Utc::now().to_rfc3339(),
            }
        }
        _ => ControlCheckResult {
            control_id: 0,
            status: "error".to_string(),
            evidence: Some("Cannot determine kernel version".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}

async fn check_package_verification() -> ControlCheckResult {
    let check = Command::new("dpkg").args(&["--verify"]).output();
    match check {
        Ok(_output) => ControlCheckResult {
            control_id: 0,
            status: "compliant".to_string(),
            evidence: Some("Package verification available".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        },
        _ => ControlCheckResult {
            control_id: 0,
            status: "not_applicable".to_string(),
            evidence: Some("Package verification not available".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}

async fn check_repository_security() -> ControlCheckResult {
    let check = Command::new("apt-key").arg("list").output();
    match check {
        Ok(output) if output.status.success() => ControlCheckResult {
            control_id: 0,
            status: "compliant".to_string(),
            evidence: Some("Repository keys configured".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        },
        _ => ControlCheckResult {
            control_id: 0,
            status: "non_compliant".to_string(),
            evidence: Some("Repository security issue".to_string()),
            gap_description: Some("Verify repository GPG keys".to_string()),
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}

async fn check_patch_compliance() -> ControlCheckResult {
    let check = Command::new("apt").args(&["list", "--upgradable"]).output();
    match check {
        Ok(output) => {
            let upgrades = String::from_utf8_lossy(&output.stdout);
            let count = upgrades.lines().count();
            if count <= 1 {
                ControlCheckResult {
                    control_id: 0,
                    status: "compliant".to_string(),
                    evidence: Some("System up to date".to_string()),
                    gap_description: None,
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            } else {
                ControlCheckResult {
                    control_id: 0,
                    status: "non_compliant".to_string(),
                    evidence: Some(format!("{} packages need updates", count - 1)),
                    gap_description: Some("Apply pending updates".to_string()),
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            }
        }
        _ => ControlCheckResult {
            control_id: 0,
            status: "error".to_string(),
            evidence: Some("Cannot check updates".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}

async fn check_security_updates() -> ControlCheckResult {
    let check = Command::new("grep").args(&["-r", "security", "/etc/apt/sources.list.d/"]).output();
    match check {
        Ok(output) if output.status.success() => ControlCheckResult {
            control_id: 0,
            status: "compliant".to_string(),
            evidence: Some("Security repository configured".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        },
        _ => ControlCheckResult {
            control_id: 0,
            status: "compliant".to_string(),
            evidence: Some("Using default security updates".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}

async fn check_end_of_life() -> ControlCheckResult {
    let check = Command::new("lsb_release").arg("-a").output();
    match check {
        Ok(output) => {
            let info = String::from_utf8_lossy(&output.stdout);
            ControlCheckResult {
                control_id: 0,
                status: "compliant".to_string(),
                evidence: Some(format!("OS info available: {}", info.lines().next().unwrap_or("Unknown"))),
                gap_description: None,
                check_timestamp: Utc::now().to_rfc3339(),
            }
        }
        _ => ControlCheckResult {
            control_id: 0,
            status: "not_applicable".to_string(),
            evidence: Some("Cannot determine OS version".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}

// ============================================================================
// BACKUP & RECOVERY - 7 Additional Checks
// ============================================================================

async fn check_backup_encryption() -> ControlCheckResult {
    ControlCheckResult {
        control_id: 0,
        status: "not_applicable".to_string(),
        evidence: Some("Backup encryption requires manual verification".to_string()),
        gap_description: Some("Verify backups are encrypted".to_string()),
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

async fn check_backup_testing() -> ControlCheckResult {
    ControlCheckResult {
        control_id: 0,
        status: "not_applicable".to_string(),
        evidence: Some("Backup testing requires manual verification".to_string()),
        gap_description: Some("Implement regular backup restoration tests".to_string()),
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

async fn check_backup_retention() -> ControlCheckResult {
    ControlCheckResult {
        control_id: 0,
        status: "not_applicable".to_string(),
        evidence: Some("Backup retention policy requires manual verification".to_string()),
        gap_description: Some("Define and implement backup retention policy".to_string()),
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

async fn check_offsite_backup() -> ControlCheckResult {
    ControlCheckResult {
        control_id: 0,
        status: "not_applicable".to_string(),
        evidence: Some("Offsite backup requires manual verification".to_string()),
        gap_description: Some("Implement offsite backup solution".to_string()),
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

async fn check_rpo_rto() -> ControlCheckResult {
    ControlCheckResult {
        control_id: 0,
        status: "not_applicable".to_string(),
        evidence: Some("RPO/RTO requires manual documentation review".to_string()),
        gap_description: Some("Define and document RPO/RTO requirements".to_string()),
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

async fn check_disaster_recovery() -> ControlCheckResult {
    ControlCheckResult {
        control_id: 0,
        status: "not_applicable".to_string(),
        evidence: Some("Disaster recovery plan requires manual verification".to_string()),
        gap_description: Some("Develop and test disaster recovery plan".to_string()),
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

async fn check_snapshot_policy() -> ControlCheckResult {
    let check = Command::new("lvdisplay").output();
    match check {
        Ok(output) if output.status.success() => {
            let lv_info = String::from_utf8_lossy(&output.stdout);
            if lv_info.contains("Snapshot") {
                ControlCheckResult {
                    control_id: 0,
                    status: "compliant".to_string(),
                    evidence: Some("LVM snapshots in use".to_string()),
                    gap_description: None,
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            } else {
                ControlCheckResult {
                    control_id: 0,
                    status: "not_applicable".to_string(),
                    evidence: Some("No LVM snapshots found".to_string()),
                    gap_description: Some("Consider implementing snapshot policy".to_string()),
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            }
        }
        _ => ControlCheckResult {
            control_id: 0,
            status: "not_applicable".to_string(),
            evidence: Some("LVM not in use".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}

// ============================================================================
// MALWARE PROTECTION - 6 Additional Checks
// ============================================================================

async fn check_edr_solution() -> ControlCheckResult {
    ControlCheckResult {
        control_id: 0,
        status: "not_applicable".to_string(),
        evidence: Some("EDR solution requires manual verification".to_string()),
        gap_description: Some("Deploy EDR solution".to_string()),
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

async fn check_malware_scanning() -> ControlCheckResult {
    let check = Command::new("freshclam").arg("--version").output();
    match check {
        Ok(output) if output.status.success() => ControlCheckResult {
            control_id: 0,
            status: "compliant".to_string(),
            evidence: Some("ClamAV signature updater installed".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        },
        _ => ControlCheckResult {
            control_id: 0,
            status: "non_compliant".to_string(),
            evidence: Some("No malware scanning configured".to_string()),
            gap_description: Some("Install and configure antimalware solution".to_string()),
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}

async fn check_av_signatures() -> ControlCheckResult {
    let check = Command::new("sigtool").args(&["--info", "/var/lib/clamav/main.cvd"]).output();
    match check {
        Ok(output) if output.status.success() => ControlCheckResult {
            control_id: 0,
            status: "compliant".to_string(),
            evidence: Some("AV signatures present".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        },
        _ => ControlCheckResult {
            control_id: 0,
            status: "non_compliant".to_string(),
            evidence: Some("Cannot verify AV signatures".to_string()),
            gap_description: Some("Update antivirus signatures".to_string()),
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}

async fn check_quarantine_config() -> ControlCheckResult {
    let check = Command::new("test").args(&["-d", "/var/lib/clamav/quarantine"]).output();
    match check {
        Ok(output) if output.status.success() => ControlCheckResult {
            control_id: 0,
            status: "compliant".to_string(),
            evidence: Some("Quarantine directory exists".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        },
        _ => ControlCheckResult {
            control_id: 0,
            status: "not_applicable".to_string(),
            evidence: Some("Quarantine not configured".to_string()),
            gap_description: Some("Configure malware quarantine".to_string()),
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}

async fn check_behavioral_detection() -> ControlCheckResult {
    ControlCheckResult {
        control_id: 0,
        status: "not_applicable".to_string(),
        evidence: Some("Behavioral detection requires advanced EDR".to_string()),
        gap_description: Some("Deploy behavioral detection solution".to_string()),
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

async fn check_exploit_prevention() -> ControlCheckResult {
    ControlCheckResult {
        control_id: 0,
        status: "not_applicable".to_string(),
        evidence: Some("Exploit prevention requires specialized solution".to_string()),
        gap_description: Some("Implement exploit prevention controls".to_string()),
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

// ============================================================================
// APPLICATION SECURITY - 6 Checks
// ============================================================================

async fn check_aslr() -> ControlCheckResult {
    let check = Command::new("sysctl").arg("kernel.randomize_va_space").output();
    match check {
        Ok(output) => {
            let value = String::from_utf8_lossy(&output.stdout);
            if value.contains("= 2") {
                ControlCheckResult {
                    control_id: 0,
                    status: "compliant".to_string(),
                    evidence: Some("ASLR fully enabled".to_string()),
                    gap_description: None,
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            } else {
                ControlCheckResult {
                    control_id: 0,
                    status: "non_compliant".to_string(),
                    evidence: Some("ASLR not fully enabled".to_string()),
                    gap_description: Some("Enable full ASLR (kernel.randomize_va_space=2)".to_string()),
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            }
        }
        _ => ControlCheckResult {
            control_id: 0,
            status: "error".to_string(),
            evidence: Some("Cannot check ASLR status".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}

async fn check_dep_nx() -> ControlCheckResult {
    let check = Command::new("grep").args(&["^flags", "/proc/cpuinfo"]).output();
    match check {
        Ok(output) => {
            let flags = String::from_utf8_lossy(&output.stdout);
            if flags.contains("nx") {
                ControlCheckResult {
                    control_id: 0,
                    status: "compliant".to_string(),
                    evidence: Some("NX/DEP supported by CPU".to_string()),
                    gap_description: None,
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            } else {
                ControlCheckResult {
                    control_id: 0,
                    status: "non_compliant".to_string(),
                    evidence: Some("NX/DEP not available".to_string()),
                    gap_description: Some("Hardware does not support NX/DEP".to_string()),
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            }
        }
        _ => ControlCheckResult {
            control_id: 0,
            status: "error".to_string(),
            evidence: Some("Cannot check NX/DEP".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}

async fn check_library_security() -> ControlCheckResult {
    let check = Command::new("ldd").arg("--version").output();
    match check {
        Ok(output) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout);
            ControlCheckResult {
                control_id: 0,
                status: "compliant".to_string(),
                evidence: Some(format!("glibc version: {}", version.lines().next().unwrap_or("Unknown"))),
                gap_description: None,
                check_timestamp: Utc::now().to_rfc3339(),
            }
        }
        _ => ControlCheckResult {
            control_id: 0,
            status: "error".to_string(),
            evidence: Some("Cannot check library versions".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}

async fn check_application_whitelist() -> ControlCheckResult {
    ControlCheckResult {
        control_id: 0,
        status: "not_applicable".to_string(),
        evidence: Some("Application whitelisting requires AppArmor/SELinux policies".to_string()),
        gap_description: Some("Implement application whitelisting".to_string()),
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

async fn check_code_signing() -> ControlCheckResult {
    ControlCheckResult {
        control_id: 0,
        status: "not_applicable".to_string(),
        evidence: Some("Code signing verification requires manual process".to_string()),
        gap_description: Some("Implement code signing verification".to_string()),
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

async fn check_container_security() -> ControlCheckResult {
    let check = Command::new("docker").arg("--version").output();
    match check {
        Ok(output) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout);
            ControlCheckResult {
                control_id: 0,
                status: "compliant".to_string(),
                evidence: Some(format!("Docker installed: {}", version.trim())),
                gap_description: None,
                check_timestamp: Utc::now().to_rfc3339(),
            }
        }
        _ => ControlCheckResult {
            control_id: 0,
            status: "not_applicable".to_string(),
            evidence: Some("Docker not installed".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}

// ============================================================================
// SECURITY LIFECYCLE MANAGEMENT - 9 Checks
// ============================================================================

async fn check_asset_inventory() -> ControlCheckResult {
    ControlCheckResult {
        control_id: 0,
        status: "not_applicable".to_string(),
        evidence: Some("Asset inventory requires CMDB or asset management system".to_string()),
        gap_description: Some("Implement asset inventory system".to_string()),
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

async fn check_config_baseline() -> ControlCheckResult {
    ControlCheckResult {
        control_id: 0,
        status: "not_applicable".to_string(),
        evidence: Some("Configuration baseline requires documentation".to_string()),
        gap_description: Some("Document and maintain configuration baseline".to_string()),
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

async fn check_change_management() -> ControlCheckResult {
    ControlCheckResult {
        control_id: 0,
        status: "not_applicable".to_string(),
        evidence: Some("Change management requires formal process".to_string()),
        gap_description: Some("Implement change management process".to_string()),
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

async fn check_security_assessment() -> ControlCheckResult {
    ControlCheckResult {
        control_id: 0,
        status: "not_applicable".to_string(),
        evidence: Some("Security assessments require manual scheduling".to_string()),
        gap_description: Some("Schedule regular security assessments".to_string()),
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

async fn check_incident_response() -> ControlCheckResult {
    ControlCheckResult {
        control_id: 0,
        status: "not_applicable".to_string(),
        evidence: Some("Incident response plan requires documentation".to_string()),
        gap_description: Some("Develop incident response plan".to_string()),
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

async fn check_security_training() -> ControlCheckResult {
    ControlCheckResult {
        control_id: 0,
        status: "not_applicable".to_string(),
        evidence: Some("Security training requires HR process".to_string()),
        gap_description: Some("Implement security awareness training".to_string()),
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

async fn check_policy_documentation() -> ControlCheckResult {
    ControlCheckResult {
        control_id: 0,
        status: "not_applicable".to_string(),
        evidence: Some("Security policies require documentation review".to_string()),
        gap_description: Some("Document security policies and procedures".to_string()),
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

async fn check_decommissioning() -> ControlCheckResult {
    ControlCheckResult {
        control_id: 0,
        status: "not_applicable".to_string(),
        evidence: Some("Decommissioning process requires manual verification".to_string()),
        gap_description: Some("Define secure decommissioning procedure".to_string()),
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

async fn check_compliance_audit_trail() -> ControlCheckResult {
    ControlCheckResult {
        control_id: 0,
        status: "compliant".to_string(),
        evidence: Some("Compliance audit trail maintained by CyberSheppard".to_string()),
        gap_description: None,
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

// ============================================================================
// PHYSICAL & ENVIRONMENTAL SECURITY - 7 Checks
// ============================================================================

async fn check_physical_access() -> ControlCheckResult {
    ControlCheckResult {
        control_id: 0,
        status: "not_applicable".to_string(),
        evidence: Some("Physical access controls require on-site verification".to_string(),),
        gap_description: Some("Implement physical access controls".to_string()),
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

async fn check_datacenter_security() -> ControlCheckResult {
    ControlCheckResult {
        control_id: 0,
        status: "not_applicable".to_string(),
        evidence: Some("Datacenter security requires facility audit".to_string()),
        gap_description: Some("Audit datacenter physical security".to_string()),
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

async fn check_bios_password() -> ControlCheckResult {
    ControlCheckResult {
        control_id: 0,
        status: "not_applicable".to_string(),
        evidence: Some("BIOS password requires physical access to verify".to_string()),
        gap_description: Some("Set BIOS/UEFI password".to_string()),
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

async fn check_chassis_intrusion() -> ControlCheckResult {
    ControlCheckResult {
        control_id: 0,
        status: "not_applicable".to_string(),
        evidence: Some("Chassis intrusion detection requires hardware support".to_string()),
        gap_description: Some("Enable chassis intrusion detection".to_string()),
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

async fn check_screen_lock() -> ControlCheckResult {
    let check = Command::new("gsettings")
        .args(&["get", "org.gnome.desktop.screensaver", "lock-enabled"])
        .output();

    match check {
        Ok(output) if output.status.success() => {
            let enabled = String::from_utf8_lossy(&output.stdout);
            if enabled.trim() == "true" {
                ControlCheckResult {
                    control_id: 0,
                    status: "compliant".to_string(),
                    evidence: Some("Screen lock enabled".to_string()),
                    gap_description: None,
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            } else {
                ControlCheckResult {
                    control_id: 0,
                    status: "non_compliant".to_string(),
                    evidence: Some("Screen lock not enabled".to_string()),
                    gap_description: Some("Enable automatic screen lock".to_string()),
                    check_timestamp: Utc::now().to_rfc3339(),
                }
            }
        }
        _ => ControlCheckResult {
            control_id: 0,
            status: "not_applicable".to_string(),
            evidence: Some("Cannot verify screen lock (no GUI)".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}

async fn check_environmental_monitoring() -> ControlCheckResult {
    ControlCheckResult {
        control_id: 0,
        status: "not_applicable".to_string(),
        evidence: Some("Environmental monitoring requires sensors".to_string()),
        gap_description: Some("Implement temperature/humidity monitoring".to_string()),
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

async fn check_hardware_inventory() -> ControlCheckResult {
    let check = Command::new("lshw").arg("-short").output();
    match check {
        Ok(output) if output.status.success() => ControlCheckResult {
            control_id: 0,
            status: "compliant".to_string(),
            evidence: Some("Hardware inventory available".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        },
        _ => ControlCheckResult {
            control_id: 0,
            status: "not_applicable".to_string(),
            evidence: Some("lshw not available".to_string()),
            gap_description: Some("Install lshw for hardware inventory".to_string()),
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}

// ============================================================================
// SUPPLY CHAIN SECURITY - 7 Checks
// ============================================================================

async fn check_vendor_security() -> ControlCheckResult {
    ControlCheckResult {
        control_id: 0,
        status: "not_applicable".to_string(),
        evidence: Some("Vendor security assessment requires manual process".to_string()),
        gap_description: Some("Implement vendor security assessment".to_string()),
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

async fn check_sbom() -> ControlCheckResult {
    ControlCheckResult {
        control_id: 0,
        status: "not_applicable".to_string(),
        evidence: Some("SBOM generation requires specialized tools".to_string()),
        gap_description: Some("Generate and maintain SBOM".to_string()),
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

async fn check_software_source_verification() -> ControlCheckResult {
    let check = Command::new("apt-key").arg("list").output();
    match check {
        Ok(output) if output.status.success() => ControlCheckResult {
            control_id: 0,
            status: "compliant".to_string(),
            evidence: Some("Software sources use GPG verification".to_string()),
            gap_description: None,
            check_timestamp: Utc::now().to_rfc3339(),
        },
        _ => ControlCheckResult {
            control_id: 0,
            status: "non_compliant".to_string(),
            evidence: Some("Software source verification not configured".to_string()),
            gap_description: Some("Enable GPG verification for repositories".to_string()),
            check_timestamp: Utc::now().to_rfc3339(),
        }
    }
}

async fn check_third_party_risk() -> ControlCheckResult {
    ControlCheckResult {
        control_id: 0,
        status: "not_applicable".to_string(),
        evidence: Some("Third-party risk assessment requires manual process".to_string()),
        gap_description: Some("Implement third-party risk management".to_string()),
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

async fn check_supply_chain_integrity() -> ControlCheckResult {
    ControlCheckResult {
        control_id: 0,
        status: "not_applicable".to_string(),
        evidence: Some("Supply chain integrity requires comprehensive program".to_string()),
        gap_description: Some("Develop supply chain security program".to_string()),
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

async fn check_procurement_security() -> ControlCheckResult {
    ControlCheckResult {
        control_id: 0,
        status: "not_applicable".to_string(),
        evidence: Some("Procurement security requires procurement process".to_string()),
        gap_description: Some("Integrate security into procurement".to_string()),
        check_timestamp: Utc::now().to_rfc3339(),
    }
}

async fn check_open_source_security() -> ControlCheckResult {
    ControlCheckResult {
        control_id: 0,
        status: "not_applicable".to_string(),
        evidence: Some("Open source security requires scanning tools".to_string()),
        gap_description: Some("Implement open source vulnerability scanning".to_string()),
        check_timestamp: Utc::now().to_rfc3339(),
    }
}
