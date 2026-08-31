// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - Data Collector Service
// ============================================================================
// Connects to targets via SSH, executes collectors, retrieves JSON data

use ssh2::Session;
use std::io::Read;
use std::net::TcpStream;
use std::path::Path;
use tracing::{info, warn};
use anyhow::{Result, Context, bail};
use serde::{Deserialize, Serialize};
use std::time::Duration;

// ============================================================================
// Collector Data Models (matching bash script outputs)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorMetadata {
    pub collector: String,
    pub timestamp: String,
    pub hostname: String,
}

// Files Collector Data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileIntegrityData {
    pub critical_files: Vec<FileEntry>,
    pub suid_binaries: Vec<FileEntry>,
    pub world_writable: Vec<FileEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: String,
    pub hash: Option<String>,
    pub permissions: String,
    pub owner: String,
    pub group: String,
    pub size: i64,
    pub modified: String,
    pub status: Option<String>,  // new/modified/unchanged
}

// Packages Collector Data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageData {
    pub name: String,
    pub version: String,
    pub architecture: String,
    pub source: String,
    pub manager: String,
    pub security_update_available: bool,
}

// Users Collector Data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserActivityData {
    pub user_accounts: Vec<UserAccount>,
    pub active_sessions: Vec<ActiveSession>,
    pub recent_logins: Vec<LoginEntry>,
    pub failed_logins: Vec<FailedLogin>,
    pub sudo_commands: Vec<SudoCommand>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAccount {
    pub username: String,
    pub uid: i32,
    pub gid: i32,
    pub home: String,
    pub shell: String,
    pub has_sudo: bool,
    pub is_locked: bool,
    pub password_expires: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveSession {
    pub user: String,
    pub tty: String,
    pub from: String,
    pub login_time: String,
    pub idle: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginEntry {
    pub user: String,
    pub tty: String,
    pub from: String,
    pub login_time: String,
    pub logout_time: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailedLogin {
    pub user: String,
    pub from: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SudoCommand {
    pub user: String,
    pub command: String,
    pub timestamp: String,
}

// Services Collector Data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServicesData {
    pub systemd_services: Vec<SystemdService>,
    pub listening_ports: Vec<ListeningPort>,
    pub docker_containers: Vec<serde_json::Value>,  // Docker JSON is passed through
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemdService {
    pub name: String,
    pub load: String,
    pub active: String,
    pub sub: String,
    pub description: String,
    pub enabled: String,
    pub pid: Option<i32>,
    pub start_time: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListeningPort {
    pub protocol: String,
    pub state: String,
    pub local_address: String,
    pub local_port: i32,
    pub process: String,
}

// ============================================================================
// Collected Data Container
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectedData {
    pub target_id: i32,
    pub target_hostname: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub files: Option<FileIntegrityData>,
    pub packages: Option<Vec<PackageData>>,
    pub users: Option<UserActivityData>,
    pub services: Option<ServicesData>,
}

// ============================================================================
// SSH Collector Client
// ============================================================================

pub struct CollectorClient {
    target_ip: String,
    ssh_port: u16,
    username: String,
    private_key_path: String,
}

impl CollectorClient {
    /// Create new collector client for a target
    pub fn new(
        target_ip: String,
        ssh_port: u16,
        username: String,
        private_key_path: String,
    ) -> Self {
        Self {
            target_ip,
            ssh_port,
            username,
            private_key_path,
        }
    }

    /// Connect to target via SSH
    fn connect(&self) -> Result<Session> {
        info!("🔌 Connecting to {}:{}...", self.target_ip, self.ssh_port);

        // Create TCP connection
        let tcp = TcpStream::connect_timeout(
            &format!("{}:{}", self.target_ip, self.ssh_port).parse()?,
            Duration::from_secs(10),
        )
        .context("Failed to connect via TCP")?;

        // Create SSH session
        let mut sess = Session::new()?;
        sess.set_tcp_stream(tcp);
        sess.handshake()
            .context("SSH handshake failed")?;

        // Authenticate with private key
        sess.userauth_pubkey_file(
            &self.username,
            None,
            Path::new(&self.private_key_path),
            None,
        )
        .context("SSH authentication failed")?;

        if !sess.authenticated() {
            bail!("SSH authentication failed - not authenticated after key auth");
        }

        info!("✅ SSH connection established to {}", self.target_ip);
        Ok(sess)
    }

    /// Execute command on remote target
    fn execute_command(&self, sess: &Session, command: &str) -> Result<(i32, String, String)> {
        let mut channel = sess.channel_session()?;
        channel.exec(command)?;

        // Read stdout
        let mut stdout = String::new();
        channel.read_to_string(&mut stdout)?;

        // Read stderr
        let mut stderr = String::new();
        channel.stderr().read_to_string(&mut stderr)?;

        // Wait for command to finish
        channel.wait_close()?;
        let exit_code = channel.exit_status()?;

        Ok((exit_code, stdout, stderr))
    }

    /// Download file from remote target via SCP
    fn download_file(&self, sess: &Session, remote_path: &str) -> Result<String> {
        let (mut remote_file, _stat) = sess.scp_recv(Path::new(remote_path))
            .context(format!("Failed to SCP download: {}", remote_path))?;

        let mut contents = String::new();
        remote_file.read_to_string(&mut contents)?;

        // Signal end of transfer
        remote_file.send_eof()?;
        remote_file.wait_eof()?;
        remote_file.close()?;
        remote_file.wait_close()?;

        Ok(contents)
    }

    /// Run a collector script and retrieve JSON output
    fn run_collector(&self, sess: &Session, collector_name: &str) -> Result<String> {
        let script_path = format!("/opt/cybersheppard/collectors/{}_collector.sh", collector_name);

        info!("📊 Running {} collector on {}...", collector_name, self.target_ip);

        // Execute collector
        let (exit_code, stdout, stderr) = self.execute_command(
            sess,
            &format!("bash {} 2>&1", script_path),
        )?;

        if exit_code != 0 {
            warn!("⚠️  Collector {} exited with code {}: {}", collector_name, exit_code, stderr);
            bail!("Collector failed: {} (exit code: {})", stderr, exit_code);
        }

        // The stdout from the collector contains the JSON file path (last line)
        let output_path = stdout.trim().lines().last()
            .context("No output from collector")?;

        if !output_path.starts_with("/opt/cybersheppard/data/") {
            bail!("Unexpected collector output: {}", output_path);
        }

        // Download the JSON file
        let json_content = self.download_file(sess, output_path)?;

        // Also download metadata file if exists
        let meta_path = format!("{}.meta", output_path);
        if let Ok(meta_content) = self.download_file(sess, &meta_path) {
            info!("📄 Metadata: {}", meta_content.lines().take(3).collect::<Vec<_>>().join(" "));
        }

        // Cleanup remote file
        let _ = self.execute_command(sess, &format!("rm -f {} {}.meta", output_path, output_path));

        Ok(json_content)
    }

    /// Collect all monitoring data from target
    pub fn collect_all_data(&self, target_id: i32) -> Result<CollectedData> {
        let sess = self.connect()?;

        // Get hostname
        let (_, hostname, _) = self.execute_command(&sess, "hostname")?;
        let hostname = hostname.trim().to_string();

        let mut collected = CollectedData {
            target_id,
            target_hostname: hostname.clone(),
            timestamp: chrono::Utc::now(),
            files: None,
            packages: None,
            users: None,
            services: None,
        };

        // Run files collector
        match self.run_collector(&sess, "files") {
            Ok(json) => {
                match serde_json::from_str::<FileIntegrityData>(&json) {
                    Ok(data) => {
                        info!("✅ Files collector: {} critical files, {} SUID binaries",
                              data.critical_files.len(), data.suid_binaries.len());
                        collected.files = Some(data);
                    }
                    Err(e) => warn!("⚠️  Failed to parse files collector JSON: {}", e),
                }
            }
            Err(e) => warn!("⚠️  Files collector failed: {}", e),
        }

        // Run packages collector
        match self.run_collector(&sess, "packages") {
            Ok(json) => {
                match serde_json::from_str::<Vec<PackageData>>(&json) {
                    Ok(data) => {
                        let security_updates = data.iter().filter(|p| p.security_update_available).count();
                        info!("✅ Packages collector: {} packages, {} security updates",
                              data.len(), security_updates);
                        collected.packages = Some(data);
                    }
                    Err(e) => warn!("⚠️  Failed to parse packages collector JSON: {}", e),
                }
            }
            Err(e) => warn!("⚠️  Packages collector failed: {}", e),
        }

        // Run users collector
        match self.run_collector(&sess, "users") {
            Ok(json) => {
                match serde_json::from_str::<UserActivityData>(&json) {
                    Ok(data) => {
                        info!("✅ Users collector: {} accounts, {} active sessions, {} failed logins",
                              data.user_accounts.len(), data.active_sessions.len(), data.failed_logins.len());
                        collected.users = Some(data);
                    }
                    Err(e) => warn!("⚠️  Failed to parse users collector JSON: {}", e),
                }
            }
            Err(e) => warn!("⚠️  Users collector failed: {}", e),
        }

        // Run services collector
        match self.run_collector(&sess, "services") {
            Ok(json) => {
                match serde_json::from_str::<ServicesData>(&json) {
                    Ok(data) => {
                        info!("✅ Services collector: {} services, {} listening ports",
                              data.systemd_services.len(), data.listening_ports.len());
                        collected.services = Some(data);
                    }
                    Err(e) => warn!("⚠️  Failed to parse services collector JSON: {}", e),
                }
            }
            Err(e) => warn!("⚠️  Services collector failed: {}", e),
        }

        info!("🎉 Data collection completed for {} ({})", hostname, self.target_ip);

        Ok(collected)
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Create temporary private key file from string content
pub fn create_temp_key_file(key_content: &str) -> Result<String> {
    use std::io::Write;

    let temp_dir = std::env::temp_dir();
    let key_path = temp_dir.join(format!("cybersheppard_key_{}.pem", uuid::Uuid::new_v4()));

    let mut file = std::fs::File::create(&key_path)?;
    file.write_all(key_content.as_bytes())?;

    // Set correct permissions (0600)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&key_path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&key_path, perms)?;
    }

    Ok(key_path.to_string_lossy().to_string())
}

/// Remove temporary key file
pub fn cleanup_temp_key_file(key_path: &str) {
    if let Err(e) = std::fs::remove_file(key_path) {
        warn!("Failed to cleanup temp key file {}: {}", key_path, e);
    }
}
