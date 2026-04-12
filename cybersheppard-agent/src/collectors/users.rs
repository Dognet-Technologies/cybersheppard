// ============================================================================
// Users Metrics Collector - Accounts, Sessions, Sudo
// ============================================================================

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsersMetrics {
    pub user_accounts: Vec<UserAccount>,
    pub active_sessions: Vec<ActiveSession>,
    pub failed_logins: usize,
    pub sudo_commands: usize,
    pub sudo_failed_attempts: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAccount {
    pub username: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveSession {
    pub username: String,
    pub terminal: String,
    pub from: String,
    pub login_at: String,
}

pub async fn collect() -> Result<UsersMetrics> {
    let user_accounts = collect_user_accounts().await?;
    let active_sessions = collect_active_sessions().await?;
    let failed_logins = collect_failed_logins().await?;
    let (sudo_commands, sudo_failed_attempts) = collect_sudo_activity().await?;

    Ok(UsersMetrics {
        user_accounts,
        active_sessions,
        failed_logins,
        sudo_commands,
        sudo_failed_attempts,
    })
}

async fn collect_user_accounts() -> Result<Vec<UserAccount>> {
    let mut accounts = Vec::new();

    if let Ok(content) = tokio::fs::read_to_string("/etc/passwd").await {
        for line in content.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 7 {
                accounts.push(UserAccount {
                    username: parts[0].to_string(),
                    uid: parts[2].parse().unwrap_or(0),
                    gid: parts[3].parse().unwrap_or(0),
                    home: parts[5].to_string(),
                    shell: parts[6].to_string(),
                });
            }
        }
    }

    Ok(accounts)
}

async fn collect_active_sessions() -> Result<Vec<ActiveSession>> {
    let mut sessions = Vec::new();

    // Parse output of `who`
    if let Ok(output) = tokio::process::Command::new("who").output().await {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                sessions.push(ActiveSession {
                    username: parts[0].to_string(),
                    terminal: parts[1].to_string(),
                    login_at: parts[2..4].join(" "),
                    from: parts.get(4).map(|s| s.to_string()).unwrap_or_default(),
                });
            }
        }
    }

    Ok(sessions)
}

async fn collect_failed_logins() -> Result<usize> {
    let mut count = 0;

    if let Ok(content) = tokio::fs::read_to_string("/var/log/auth.log").await {
        for line in content.lines() {
            if line.contains("Failed password") {
                count += 1;
            }
        }
    }

    Ok(count)
}

async fn collect_sudo_activity() -> Result<(usize, usize)> {
    let mut commands = 0;
    let mut failed = 0;

    if let Ok(content) = tokio::fs::read_to_string("/var/log/auth.log").await {
        for line in content.lines() {
            if line.contains("sudo:") && line.contains("COMMAND=") {
                commands += 1;
            }
            if line.contains("sudo:") && line.contains("authentication failure") {
                failed += 1;
            }
        }
    }

    Ok((commands, failed))
}
