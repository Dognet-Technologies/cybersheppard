// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - Hardening Validators
// ============================================================================
// Post-hardening validation, compliance checks, and drift detection

use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgPool;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub target_id: i32,
    pub validator_name: String,
    pub status: ValidationStatus,
    pub checks_passed: usize,
    pub checks_failed: usize,
    pub total_checks: usize,
    pub score: i32,
    pub findings: Vec<ValidationFinding>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ValidationStatus {
    Passed,
    Failed,
    Warning,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationFinding {
    pub check_name: String,
    pub status: FindingStatus,
    pub severity: String,
    pub expected: serde_json::Value,
    pub actual: serde_json::Value,
    pub message: String,
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum FindingStatus {
    Pass,
    Fail,
    Warning,
    NotApplicable,
}

pub struct HardeningValidator {
    pg_pool: PgPool,
}

impl HardeningValidator {
    pub fn new(pg_pool: PgPool) -> Self {
        Self { pg_pool }
    }

    /// Validate SSH hardening configuration
    pub async fn validate_ssh_hardening(
        &self,
        target_id: i32,
        config_data: &serde_json::Value,
    ) -> Result<ValidationResult, Box<dyn std::error::Error>> {
        let mut findings = Vec::new();
        let timestamp = chrono::Utc::now();

        // Check PermitRootLogin
        findings.push(self.check_config_value(
            "PermitRootLogin",
            "no",
            config_data.get("PermitRootLogin"),
            "high",
            "Root login should be disabled",
            "Set PermitRootLogin to 'no' in /etc/ssh/sshd_config",
        ));

        // Check PasswordAuthentication
        findings.push(self.check_config_value(
            "PasswordAuthentication",
            "no",
            config_data.get("PasswordAuthentication"),
            "high",
            "Password authentication should be disabled",
            "Set PasswordAuthentication to 'no' and use key-based auth",
        ));

        // Check PubkeyAuthentication
        findings.push(self.check_config_value(
            "PubkeyAuthentication",
            "yes",
            config_data.get("PubkeyAuthentication"),
            "medium",
            "Public key authentication should be enabled",
            "Set PubkeyAuthentication to 'yes'",
        ));

        // Check Protocol version
        findings.push(self.check_config_value(
            "Protocol",
            "2",
            config_data.get("Protocol"),
            "critical",
            "Only Protocol 2 should be used",
            "Set Protocol to '2'",
        ));

        // Check X11Forwarding
        findings.push(self.check_config_value(
            "X11Forwarding",
            "no",
            config_data.get("X11Forwarding"),
            "medium",
            "X11 forwarding should be disabled",
            "Set X11Forwarding to 'no'",
        ));

        // Check PermitEmptyPasswords
        findings.push(self.check_config_value(
            "PermitEmptyPasswords",
            "no",
            config_data.get("PermitEmptyPasswords"),
            "critical",
            "Empty passwords should not be permitted",
            "Set PermitEmptyPasswords to 'no'",
        ));

        // Check MaxAuthTries
        if let Some(max_tries) = config_data.get("MaxAuthTries").and_then(|v| v.as_i64()) {
            if max_tries > 4 {
                findings.push(ValidationFinding {
                    check_name: "MaxAuthTries".to_string(),
                    status: FindingStatus::Fail,
                    severity: "medium".to_string(),
                    expected: json!(4),
                    actual: json!(max_tries),
                    message: "MaxAuthTries should be 4 or less".to_string(),
                    remediation: Some("Set MaxAuthTries to 4".to_string()),
                });
            } else {
                findings.push(ValidationFinding {
                    check_name: "MaxAuthTries".to_string(),
                    status: FindingStatus::Pass,
                    severity: "medium".to_string(),
                    expected: json!(4),
                    actual: json!(max_tries),
                    message: "MaxAuthTries is properly configured".to_string(),
                    remediation: None,
                });
            }
        }

        self.compile_validation_result(target_id, "SSH Hardening", findings, timestamp)
    }

    /// Validate Auditd configuration
    pub async fn validate_auditd_rules(
        &self,
        target_id: i32,
        rules: &Vec<String>,
    ) -> Result<ValidationResult, Box<dyn std::error::Error>> {
        let mut findings = Vec::new();
        let timestamp = chrono::Utc::now();

        // Required rules
        let required_rules = vec![
            ("-w /etc/passwd -p wa", "Password file monitoring"),
            ("-w /etc/shadow -p wa", "Shadow file monitoring"),
            ("-w /etc/group -p wa", "Group file monitoring"),
            ("-w /etc/sudoers -p wa", "Sudoers file monitoring"),
            ("-w /var/log/auth.log -p wa", "Auth log monitoring"),
            ("-w /var/log/sudo.log -p wa", "Sudo log monitoring"),
            ("-a always,exit -F arch=b64 -S execve", "Command execution auditing"),
        ];

        for (rule_pattern, description) in required_rules {
            let found = rules.iter().any(|r| r.contains(rule_pattern));

            findings.push(ValidationFinding {
                check_name: description.to_string(),
                status: if found { FindingStatus::Pass } else { FindingStatus::Fail },
                severity: "high".to_string(),
                expected: json!(rule_pattern),
                actual: json!(found),
                message: if found {
                    format!("Rule '{}' is present", description)
                } else {
                    format!("Required rule '{}' is missing", description)
                },
                remediation: if found {
                    None
                } else {
                    Some(format!("Add rule: {}", rule_pattern))
                },
            });
        }

        self.compile_validation_result(target_id, "Auditd Rules", findings, timestamp)
    }

    /// Validate sysctl kernel parameters
    pub async fn validate_sysctl_params(
        &self,
        target_id: i32,
        params: &HashMap<String, String>,
    ) -> Result<ValidationResult, Box<dyn std::error::Error>> {
        let mut findings = Vec::new();
        let timestamp = chrono::Utc::now();

        // Expected secure sysctl parameters
        let expected_params = vec![
            ("net.ipv4.ip_forward", "0", "IP forwarding should be disabled"),
            ("net.ipv4.conf.all.accept_source_route", "0", "Source routing should be disabled"),
            ("net.ipv4.conf.all.send_redirects", "0", "ICMP redirects should be disabled"),
            ("net.ipv4.icmp_echo_ignore_broadcasts", "1", "Broadcast ICMP should be ignored"),
            ("net.ipv4.conf.all.accept_redirects", "0", "ICMP redirects should not be accepted"),
            ("kernel.randomize_va_space", "2", "ASLR should be fully enabled"),
            ("kernel.dmesg_restrict", "1", "dmesg should be restricted"),
            ("kernel.kptr_restrict", "2", "Kernel pointers should be hidden"),
        ];

        for (param, expected_value, description) in expected_params {
            let actual_value = params.get(param);

            findings.push(ValidationFinding {
                check_name: param.to_string(),
                status: if actual_value == Some(&expected_value.to_string()) {
                    FindingStatus::Pass
                } else {
                    FindingStatus::Fail
                },
                severity: "high".to_string(),
                expected: json!(expected_value),
                actual: json!(actual_value.unwrap_or(&"not_set".to_string())),
                message: if actual_value == Some(&expected_value.to_string()) {
                    format!("{}: Correct", description)
                } else {
                    format!("{}: Incorrect or not set", description)
                },
                remediation: if actual_value == Some(&expected_value.to_string()) {
                    None
                } else {
                    Some(format!("Set {} = {} in /etc/sysctl.conf", param, expected_value))
                },
            });
        }

        self.compile_validation_result(target_id, "Sysctl Parameters", findings, timestamp)
    }

    /// Detect configuration drift
    pub async fn detect_drift(
        &self,
        target_id: i32,
        baseline_config: &serde_json::Value,
        current_config: &serde_json::Value,
    ) -> Result<Vec<DriftFinding>, Box<dyn std::error::Error>> {
        let mut drift_findings = Vec::new();

        self.compare_configs("", baseline_config, current_config, &mut drift_findings);

        Ok(drift_findings)
    }

    /// Recursive configuration comparison for drift detection
    fn compare_configs(
        &self,
        path: &str,
        baseline: &serde_json::Value,
        current: &serde_json::Value,
        findings: &mut Vec<DriftFinding>,
    ) {
        match (baseline, current) {
            (serde_json::Value::Object(b_map), serde_json::Value::Object(c_map)) => {
                // Check for removed keys
                for (key, b_value) in b_map {
                    let full_path = if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{}.{}", path, key)
                    };

                    if let Some(c_value) = c_map.get(key) {
                        self.compare_configs(&full_path, b_value, c_value, findings);
                    } else {
                        findings.push(DriftFinding {
                            path: full_path,
                            drift_type: DriftType::Removed,
                            baseline_value: Some(b_value.clone()),
                            current_value: None,
                            severity: "high".to_string(),
                        });
                    }
                }

                // Check for added keys
                for (key, c_value) in c_map {
                    if !b_map.contains_key(key) {
                        let full_path = if path.is_empty() {
                            key.clone()
                        } else {
                            format!("{}.{}", path, key)
                        };

                        findings.push(DriftFinding {
                            path: full_path,
                            drift_type: DriftType::Added,
                            baseline_value: None,
                            current_value: Some(c_value.clone()),
                            severity: "medium".to_string(),
                        });
                    }
                }
            }
            _ => {
                // Value comparison
                if baseline != current {
                    findings.push(DriftFinding {
                        path: path.to_string(),
                        drift_type: DriftType::Modified,
                        baseline_value: Some(baseline.clone()),
                        current_value: Some(current.clone()),
                        severity: "high".to_string(),
                    });
                }
            }
        }
    }

    /// Helper: Check configuration value
    fn check_config_value(
        &self,
        check_name: &str,
        expected: &str,
        actual: Option<&serde_json::Value>,
        severity: &str,
        message: &str,
        remediation: &str,
    ) -> ValidationFinding {
        let actual_str = actual.and_then(|v| v.as_str()).unwrap_or("not_set");
        let status = if actual_str == expected {
            FindingStatus::Pass
        } else {
            FindingStatus::Fail
        };

        ValidationFinding {
            check_name: check_name.to_string(),
            status,
            severity: severity.to_string(),
            expected: json!(expected),
            actual: json!(actual_str),
            message: message.to_string(),
            remediation: if status == FindingStatus::Pass {
                None
            } else {
                Some(remediation.to_string())
            },
        }
    }

    /// Helper: Compile validation result
    fn compile_validation_result(
        &self,
        target_id: i32,
        validator_name: &str,
        findings: Vec<ValidationFinding>,
        timestamp: chrono::DateTime<chrono::Utc>,
    ) -> Result<ValidationResult, Box<dyn std::error::Error>> {
        let total_checks = findings.len();
        let checks_passed = findings.iter().filter(|f| f.status == FindingStatus::Pass).count();
        let checks_failed = findings.iter().filter(|f| f.status == FindingStatus::Fail).count();

        // Calculate score: (passed / total) * 100
        let score = if total_checks > 0 {
            ((checks_passed as f64 / total_checks as f64) * 100.0) as i32
        } else {
            100
        };

        let status = if checks_failed == 0 {
            ValidationStatus::Passed
        } else if score >= 70 {
            ValidationStatus::Warning
        } else {
            ValidationStatus::Failed
        };

        Ok(ValidationResult {
            target_id,
            validator_name: validator_name.to_string(),
            status,
            checks_passed,
            checks_failed,
            total_checks,
            score,
            findings,
            timestamp,
        })
    }

    /// Store validation results in database
    pub async fn store_validation_result(
        &self,
        result: &ValidationResult,
    ) -> Result<i64, sqlx::Error> {
        let result_id = sqlx::query_scalar::<_, i64>(
            r#"
            INSERT INTO validation_results
                (target_id, validator_name, status, checks_passed, checks_failed,
                 total_checks, score, findings, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id
            "#,
        )
        .bind(result.target_id)
        .bind(&result.validator_name)
        .bind(format!("{:?}", result.status).to_lowercase())
        .bind(result.checks_passed as i32)
        .bind(result.checks_failed as i32)
        .bind(result.total_checks as i32)
        .bind(result.score)
        .bind(serde_json::to_value(&result.findings)?)
        .bind(result.timestamp)
        .fetch_one(&self.pg_pool)
        .await?;

        Ok(result_id)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftFinding {
    pub path: String,
    pub drift_type: DriftType,
    pub baseline_value: Option<serde_json::Value>,
    pub current_value: Option<serde_json::Value>,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DriftType {
    Added,
    Removed,
    Modified,
}
