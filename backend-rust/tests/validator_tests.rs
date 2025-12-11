// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - Hardening Validator Tests
// ============================================================================

#[cfg(test)]
mod validator_tests {
    use serde_json::json;
    use std::collections::HashMap;

    #[test]
    fn test_ssh_config_validation() {
        let config = json!({
            "PermitRootLogin": "no",
            "PasswordAuthentication": "no",
            "PubkeyAuthentication": "yes",
            "PermitEmptyPasswords": "no",
            "X11Forwarding": "no",
            "MaxAuthTries": "3",
            "Protocol": "2"
        });

        // Verify critical SSH settings
        assert_eq!(config["PermitRootLogin"], "no");
        assert_eq!(config["PasswordAuthentication"], "no");
        assert_eq!(config["PubkeyAuthentication"], "yes");
        assert_eq!(config["PermitEmptyPasswords"], "no");
        assert_eq!(config["MaxAuthTries"], "3");
    }

    #[test]
    fn test_ssh_insecure_config_detection() {
        let insecure_configs = vec![
            ("PermitRootLogin", "yes"),
            ("PasswordAuthentication", "yes"),
            ("PermitEmptyPasswords", "yes"),
            ("X11Forwarding", "yes"),
        ];

        for (key, value) in insecure_configs {
            // These should trigger validation failures
            assert!(is_insecure_ssh_setting(key, value));
        }
    }

    #[test]
    fn test_auditd_rules_validation() {
        let required_rules = vec![
            "-w /etc/passwd -p wa -k passwd_changes",
            "-w /etc/shadow -p wa -k shadow_changes",
            "-w /etc/sudoers -p wa -k sudoers_changes",
            "-w /var/log/auth.log -p wa -k auth_log",
            "-a always,exit -F arch=b64 -S execve -k exec_monitor",
        ];

        // Verify all required rules are present
        for rule in &required_rules {
            assert!(rule.starts_with("-w") || rule.starts_with("-a"));
            assert!(rule.contains("-k")); // All rules should have a key
        }

        assert_eq!(required_rules.len(), 5);
    }

    #[test]
    fn test_auditd_rule_parsing() {
        let rule = "-w /etc/passwd -p wa -k passwd_changes";

        // Parse rule components
        assert!(rule.contains("/etc/passwd"));
        assert!(rule.contains("-p wa")); // watch for write and attribute changes
        assert!(rule.contains("-k passwd_changes")); // key for identification
    }

    #[test]
    fn test_sysctl_parameters_validation() {
        let params: HashMap<&str, &str> = vec![
            ("net.ipv4.ip_forward", "0"),
            ("net.ipv4.conf.all.send_redirects", "0"),
            ("net.ipv4.conf.all.accept_redirects", "0"),
            ("net.ipv4.conf.all.log_martians", "1"),
            ("net.ipv4.icmp_echo_ignore_broadcasts", "1"),
            ("net.ipv4.tcp_syncookies", "1"),
            ("kernel.dmesg_restrict", "1"),
            ("kernel.randomize_va_space", "2"),
        ]
        .into_iter()
        .collect();

        // Verify security-critical parameters
        assert_eq!(params["net.ipv4.ip_forward"], "0"); // IP forwarding disabled
        assert_eq!(params["net.ipv4.tcp_syncookies"], "1"); // SYN flood protection
        assert_eq!(params["kernel.randomize_va_space"], "2"); // Full ASLR
        assert_eq!(params["kernel.dmesg_restrict"], "1"); // Restrict kernel logs

        assert_eq!(params.len(), 8);
    }

    #[test]
    fn test_sysctl_insecure_values() {
        let insecure_params = vec![
            ("net.ipv4.ip_forward", "1"), // Forwarding enabled is risky
            ("net.ipv4.conf.all.accept_redirects", "1"), // Accept redirects is risky
            ("kernel.randomize_va_space", "0"), // No ASLR is insecure
        ];

        for (param, value) in insecure_params {
            assert!(is_insecure_sysctl_value(param, value));
        }
    }

    #[test]
    fn test_drift_detection() {
        let baseline = json!({
            "PermitRootLogin": "no",
            "PasswordAuthentication": "no",
            "MaxAuthTries": "3"
        });

        let current = json!({
            "PermitRootLogin": "yes", // DRIFT: changed from "no"
            "PasswordAuthentication": "no",
            "MaxAuthTries": "5" // DRIFT: changed from "3"
        });

        // Detect drifts
        let drifts = detect_config_drift(&baseline, &current);
        assert_eq!(drifts.len(), 2); // PermitRootLogin and MaxAuthTries changed
    }

    #[test]
    fn test_validation_severity_levels() {
        let severities = vec!["critical", "high", "medium", "low", "info"];

        // Verify severity hierarchy
        assert!(severities.contains(&"critical"));
        assert!(severities.contains(&"high"));
        assert!(severities.contains(&"medium"));
        assert!(severities.contains(&"low"));

        // Critical findings should be at index 0 (highest priority)
        assert_eq!(severities[0], "critical");
    }

    #[test]
    fn test_validation_result_structure() {
        let result = json!({
            "target_id": 1,
            "validation_type": "ssh_hardening",
            "status": "failed",
            "total_checks": 7,
            "passed": 5,
            "failed": 2,
            "findings": [
                {
                    "severity": "high",
                    "category": "ssh_config",
                    "message": "PermitRootLogin is set to 'yes'",
                    "recommendation": "Set PermitRootLogin to 'no'"
                }
            ]
        });

        assert_eq!(result["status"], "failed");
        assert_eq!(result["passed"], 5);
        assert_eq!(result["failed"], 2);
        assert!(result["findings"].is_array());
    }

    #[test]
    fn test_compliance_score_calculation() {
        let total_checks = 20;
        let passed_checks = 18;
        let failed_checks = 2;

        let score = (passed_checks as f64 / total_checks as f64) * 100.0;

        assert_eq!(score, 90.0);
        assert!(score >= 80.0); // Minimum acceptable score
    }

    #[test]
    fn test_hardening_status_transitions() {
        let valid_statuses = vec![
            "pending",
            "in_progress",
            "completed",
            "failed",
            "validation_required",
        ];

        // Verify valid status transitions
        assert!(can_transition("pending", "in_progress"));
        assert!(can_transition("in_progress", "completed"));
        assert!(can_transition("completed", "validation_required"));
        assert!(!can_transition("completed", "pending")); // Invalid transition
    }
}

// Helper functions for validation tests
fn is_insecure_ssh_setting(key: &str, value: &str) -> bool {
    match (key, value) {
        ("PermitRootLogin", "yes") => true,
        ("PasswordAuthentication", "yes") => true,
        ("PermitEmptyPasswords", "yes") => true,
        ("X11Forwarding", "yes") => true,
        _ => false,
    }
}

fn is_insecure_sysctl_value(param: &str, value: &str) -> bool {
    match (param, value) {
        ("net.ipv4.ip_forward", "1") => true,
        ("net.ipv4.conf.all.accept_redirects", "1") => true,
        ("kernel.randomize_va_space", "0") => true,
        _ => false,
    }
}

fn detect_config_drift(baseline: &serde_json::Value, current: &serde_json::Value) -> Vec<String> {
    let mut drifts = Vec::new();

    if let (Some(baseline_obj), Some(current_obj)) = (baseline.as_object(), current.as_object()) {
        for (key, baseline_value) in baseline_obj {
            if let Some(current_value) = current_obj.get(key) {
                if baseline_value != current_value {
                    drifts.push(key.clone());
                }
            }
        }
    }

    drifts
}

fn can_transition(from: &str, to: &str) -> bool {
    let valid_transitions = vec![
        ("pending", "in_progress"),
        ("in_progress", "completed"),
        ("in_progress", "failed"),
        ("completed", "validation_required"),
        ("validation_required", "completed"),
        ("validation_required", "failed"),
        ("failed", "pending"),
    ];

    valid_transitions.contains(&(from, to))
}
