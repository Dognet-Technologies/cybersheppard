// ============================================================================
// Collectors Module - System metrics collection
// ============================================================================

mod system;
mod network;
mod users;
mod files;
mod services;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::config::AgentConfig;

pub use system::SystemMetrics;
pub use network::NetworkMetrics;
pub use users::UsersMetrics;
pub use files::FilesMetrics;
pub use services::ServicesMetrics;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllMetrics {
    pub collected_at: i64,
    pub hostname: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<SystemMetrics>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkMetrics>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub users: Option<UsersMetrics>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub files: Option<FilesMetrics>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub services: Option<ServicesMetrics>,
}

/// Collect all enabled metrics
pub async fn collect_all(config: &AgentConfig) -> Result<AllMetrics> {
    let hostname = hostname::get()?.to_string_lossy().to_string();

    let system = if config.collectors.system {
        Some(system::collect().await?)
    } else {
        None
    };

    let network = if config.collectors.network {
        Some(network::collect().await?)
    } else {
        None
    };

    let users = if config.collectors.users {
        Some(users::collect().await?)
    } else {
        None
    };

    let files = if config.collectors.files {
        Some(files::collect().await?)
    } else {
        None
    };

    let services = if config.collectors.services {
        Some(services::collect().await?)
    } else {
        None
    };

    Ok(AllMetrics {
        collected_at: chrono::Utc::now().timestamp(),
        hostname,
        system,
        network,
        users,
        files,
        services,
    })
}
