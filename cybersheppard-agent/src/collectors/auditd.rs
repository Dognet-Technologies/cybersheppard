// ============================================================================
// Auditd Metrics Collector - Laurel JSON-based parsing
// ============================================================================

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditdMetrics {
    pub events: Vec<LaurelEvent>,
    pub summary: EventSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSummary {
    pub total_events: usize,
    pub suspicious_executions: usize,
    pub privilege_escalations: usize,
    pub file_access_violations: usize,
    pub failed_authentications: usize,
    pub sudo_commands: usize,
    pub network_connections: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaurelEvent {
    #[serde(rename = "ID")]
    pub id: String,

    #[serde(rename = "SYSCALL")]
    pub syscall: Option<SyscallInfo>,

    #[serde(rename = "EXECVE")]
    pub execve: Option<ExecveInfo>,

    #[serde(rename = "PATH")]
    pub path: Option<Vec<PathInfo>>,

    #[serde(rename = "CWD")]
    pub cwd: Option<CwdInfo>,

    #[serde(rename = "PARENT_INFO")]
    pub parent: Option<ParentInfo>,

    #[serde(rename = "CONTAINER_INFO")]
    pub container: Option<ContainerInfo>,

    #[serde(rename = "PROCTITLE")]
    pub proctitle: Option<String>,

    // Enrichment
    pub severity: Option<String>,
    pub category: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallInfo {
    pub syscall: String,
    pub success: bool,
    pub pid: i32,
    pub ppid: i32,
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub egid: u32,
    pub comm: String,
    pub exe: String,
    pub key: Option<String>,
    pub arch: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecveInfo {
    pub argc: usize,
    #[serde(rename = "ARGV")]
    pub argv: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathInfo {
    pub name: String,
    pub nametype: String,
    pub mode: Option<String>,
    pub ouid: Option<u32>,
    pub ogid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CwdInfo {
    pub cwd: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParentInfo {
    pub pid: i32,
    pub comm: String,
    pub exe: String,
    pub cmdline: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerInfo {
    pub id: String,
    pub name: Option<String>,
    pub image: Option<String>,
}

pub async fn collect() -> Result<AuditdMetrics> {
    let mut events = Vec::new();

    // Read Laurel JSON log file
    let laurel_log = "/var/log/laurel/audit.log";

    // Read last N lines (e.g., last 1000 events or last 5 minutes)
    match read_recent_events(laurel_log, 1000).await {
        Ok(raw_events) => {
            for line in raw_events {
                if line.trim().is_empty() {
                    continue;
                }

                // Parse Laurel JSON
                match serde_json::from_str::<LaurelEvent>(&line) {
                    Ok(mut event) => {
                        // Enrich event with security metadata
                        enrich_event(&mut event);

                        // Only include security-relevant events
                        if is_security_relevant(&event) {
                            events.push(event);
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to parse Laurel event: {}", e);
                        continue;
                    }
                }
            }
        }
        Err(e) => {
            tracing::error!("Failed to read Laurel log: {}", e);
        }
    }

    // Calculate summary
    let summary = calculate_summary(&events);

    Ok(AuditdMetrics {
        events,
        summary,
    })
}

async fn read_recent_events(path: &str, max_lines: usize) -> Result<Vec<String>> {
    // Read file from end (tail-like behavior)
    let content = tokio::fs::read_to_string(path).await?;

    let lines: Vec<String> = content
        .lines()
        .rev()
        .take(max_lines)
        .map(|s| s.to_string())
        .collect();

    Ok(lines.into_iter().rev().collect())
}

fn enrich_event(event: &mut LaurelEvent) {
    // Determine severity and category based on event characteristics
    if let Some(detection) = detect_threat(event) {
        event.severity = Some(detection.severity);
        event.category = Some(detection.category);
        event.description = Some(detection.description);
    }
}

struct ThreatDetection {
    severity: String,
    category: String,
    description: String,
}

fn detect_threat(event: &LaurelEvent) -> Option<ThreatDetection> {
    // 1. Privilege Escalation Detection
    if let Some(syscall) = &event.syscall {
        // setuid/setgid to root
        if (syscall.syscall == "setuid" || syscall.syscall == "setgid") && syscall.success {
            if syscall.euid == 0 || syscall.egid == 0 {
                return Some(ThreatDetection {
                    severity: "critical".to_string(),
                    category: "privilege_escalation".to_string(),
                    description: format!("Process {} escalated to root privileges", syscall.comm),
                });
            }
        }
    }

    // 2. Suspicious Command Execution
    if let Some(execve) = &event.execve {
        let command = execve.argv.join(" ");

        // Reverse shell patterns
        let reverse_shell_patterns = [
            "nc -e", "ncat -e", "bash -i", "python -c", "perl -e",
            "/dev/tcp/", "bash -c", "sh -c", "> /dev/tcp",
        ];

        for pattern in &reverse_shell_patterns {
            if command.contains(pattern) {
                return Some(ThreatDetection {
                    severity: "critical".to_string(),
                    category: "reverse_shell".to_string(),
                    description: format!("Potential reverse shell detected: {}", command),
                });
            }
        }

        // Web shell execution (web server spawning shell)
        if let Some(parent) = &event.parent {
            let web_servers = ["apache2", "nginx", "httpd", "php-fpm"];
            if web_servers.iter().any(|s| parent.comm.contains(s)) {
                let suspicious_commands = ["bash", "sh", "nc", "wget", "curl", "python"];
                if suspicious_commands.iter().any(|c| command.contains(c)) {
                    return Some(ThreatDetection {
                        severity: "critical".to_string(),
                        category: "webshell".to_string(),
                        description: format!("Web server executing suspicious command: {}", command),
                    });
                }
            }
        }
    }

    // 3. Sensitive File Access
    if let Some(paths) = &event.path {
        let sensitive_files = [
            "/etc/shadow", "/etc/passwd", "/etc/sudoers",
            "/root/.ssh/", "/home/", "/.ssh/authorized_keys",
        ];

        for path_info in paths {
            for sensitive in &sensitive_files {
                if path_info.name.contains(sensitive) {
                    if let Some(syscall) = &event.syscall {
                        if syscall.syscall == "openat" || syscall.syscall == "open" {
                            return Some(ThreatDetection {
                                severity: "high".to_string(),
                                category: "sensitive_file_access".to_string(),
                                description: format!("Process {} accessed sensitive file: {}",
                                    syscall.comm, path_info.name),
                            });
                        }
                    }
                }
            }
        }
    }

    // 4. Container Escape Attempts
    if let Some(container) = &event.container {
        if let Some(syscall) = &event.syscall {
            let escape_syscalls = ["mount", "unshare", "setns", "pivot_root"];
            if escape_syscalls.contains(&syscall.syscall.as_str()) {
                return Some(ThreatDetection {
                    severity: "critical".to_string(),
                    category: "container_escape".to_string(),
                    description: format!("Container {} attempting escape via {}",
                        container.name.as_ref().unwrap_or(&container.id), syscall.syscall),
                });
            }
        }
    }

    // 5. Persistence Mechanisms
    if let Some(paths) = &event.path {
        let persistence_locations = [
            "/etc/cron", "/etc/init.d/", "/etc/systemd/",
            "/.bashrc", "/.bash_profile", "/etc/rc.local",
        ];

        for path_info in paths {
            for location in &persistence_locations {
                if path_info.name.contains(location) && path_info.nametype == "CREATE" {
                    return Some(ThreatDetection {
                        severity: "high".to_string(),
                        category: "persistence".to_string(),
                        description: format!("Persistence mechanism created: {}", path_info.name),
                    });
                }
            }
        }
    }

    None
}

fn is_security_relevant(event: &LaurelEvent) -> bool {
    // Include events that have been flagged with severity
    if event.severity.is_some() {
        return true;
    }

    // Include execve events (command execution)
    if event.execve.is_some() {
        return true;
    }

    // Include privileged operations
    if let Some(syscall) = &event.syscall {
        if syscall.euid == 0 || syscall.egid == 0 {
            return true;
        }
    }

    // Include container events
    if event.container.is_some() {
        return true;
    }

    false
}

fn calculate_summary(events: &[LaurelEvent]) -> EventSummary {
    let mut summary = EventSummary {
        total_events: events.len(),
        suspicious_executions: 0,
        privilege_escalations: 0,
        file_access_violations: 0,
        failed_authentications: 0,
        sudo_commands: 0,
        network_connections: 0,
    };

    for event in events {
        if let Some(category) = &event.category {
            match category.as_str() {
                "reverse_shell" | "webshell" => summary.suspicious_executions += 1,
                "privilege_escalation" => summary.privilege_escalations += 1,
                "sensitive_file_access" => summary.file_access_violations += 1,
                _ => {}
            }
        }

        // Count sudo commands
        if let Some(execve) = &event.execve {
            if execve.argv.get(0).map(|s| s.as_str()) == Some("sudo") {
                summary.sudo_commands += 1;
            }
        }
    }

    summary
}
