// ============================================================================
// Agent Configuration
// ============================================================================

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use anyhow::{Context, Result};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentConfig {
    /// Backend server URL (WebSocket)
    pub backend_url: String,

    /// Agent authentication token
    pub auth_token: String,

    /// Target ID (assigned by backend)
    pub target_id: i32,

    /// Collection interval in seconds
    #[serde(default = "default_collection_interval")]
    pub collection_interval: u64,

    /// Send interval in seconds (buffer batching)
    #[serde(default = "default_send_interval")]
    pub send_interval: u64,

    /// Compression level (1-22, higher = better compression but slower)
    #[serde(default = "default_compression_level")]
    pub compression_level: i32,

    /// Max buffer size before forced flush (number of payloads)
    #[serde(default = "default_max_buffer_size")]
    pub max_buffer_size: usize,

    /// Reconnection settings
    #[serde(default)]
    pub reconnect: ReconnectConfig,

    /// Enabled collectors
    #[serde(default)]
    pub collectors: CollectorsConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReconnectConfig {
    /// Initial backoff in seconds
    #[serde(default = "default_initial_backoff")]
    pub initial_backoff: u64,

    /// Max backoff in seconds
    #[serde(default = "default_max_backoff")]
    pub max_backoff: u64,

    /// Backoff multiplier
    #[serde(default = "default_backoff_multiplier")]
    pub backoff_multiplier: f64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CollectorsConfig {
    #[serde(default = "default_true")]
    pub system: bool,

    #[serde(default = "default_true")]
    pub network: bool,

    #[serde(default = "default_true")]
    pub users: bool,

    #[serde(default = "default_true")]
    pub files: bool,

    #[serde(default = "default_true")]
    pub services: bool,

    #[serde(default = "default_true")]
    pub auditd: bool,

    #[serde(default = "default_true")]
    pub docker: bool,
}

// Default functions
fn default_collection_interval() -> u64 { 30 }
fn default_send_interval() -> u64 { 10 }
fn default_compression_level() -> i32 { 3 }
fn default_max_buffer_size() -> usize { 10 }
fn default_initial_backoff() -> u64 { 1 }
fn default_max_backoff() -> u64 { 300 }
fn default_backoff_multiplier() -> f64 { 2.0 }
fn default_true() -> bool { true }

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            initial_backoff: default_initial_backoff(),
            max_backoff: default_max_backoff(),
            backoff_multiplier: default_backoff_multiplier(),
        }
    }
}

impl Default for CollectorsConfig {
    fn default() -> Self {
        Self {
            system: true,
            network: true,
            users: true,
            files: true,
            services: true,
            auditd: true,
            docker: true,
        }
    }
}

impl AgentConfig {
    /// Load configuration from file
    pub fn load(path: &PathBuf) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {:?}", path))?;

        let config: AgentConfig = toml::from_str(&content)
            .context("Failed to parse config file")?;

        config.validate()?;

        Ok(config)
    }

    /// Validate configuration
    fn validate(&self) -> Result<()> {
        if self.backend_url.is_empty() {
            anyhow::bail!("backend_url cannot be empty");
        }

        if self.auth_token.is_empty() {
            anyhow::bail!("auth_token cannot be empty");
        }

        if self.target_id <= 0 {
            anyhow::bail!("target_id must be positive");
        }

        if self.compression_level < 1 || self.compression_level > 22 {
            anyhow::bail!("compression_level must be between 1 and 22");
        }

        Ok(())
    }

    /// Save configuration to file
    pub fn save(&self, path: &PathBuf) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .context("Failed to serialize config")?;

        std::fs::write(path, content)
            .with_context(|| format!("Failed to write config file: {:?}", path))?;

        Ok(())
    }

    /// Get default config path
    pub fn default_path() -> PathBuf {
        PathBuf::from("/etc/cybersheppard-agent/config.toml")
    }
}
