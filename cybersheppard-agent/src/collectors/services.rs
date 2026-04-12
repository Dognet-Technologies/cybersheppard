// ============================================================================
// Services Metrics Collector - Systemd, Docker, Listening Ports
// ============================================================================

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServicesMetrics {
    pub systemd_services: Vec<SystemdService>,
    pub docker_containers: Vec<DockerContainer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemdService {
    pub name: String,
    pub status: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerContainer {
    pub id: String,
    pub name: String,
    pub image: String,
    pub status: String,
    pub ports: Vec<String>,
}

pub async fn collect() -> Result<ServicesMetrics> {
    let systemd_services = collect_systemd_services().await?;
    let docker_containers = collect_docker_containers().await?;

    Ok(ServicesMetrics {
        systemd_services,
        docker_containers,
    })
}

async fn collect_systemd_services() -> Result<Vec<SystemdService>> {
    let mut services = Vec::new();

    // Run systemctl list-units
    if let Ok(output) = tokio::process::Command::new("systemctl")
        .args(&["list-units", "--type=service", "--all", "--no-pager"])
        .output()
        .await
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                services.push(SystemdService {
                    name: parts[0].trim_end_matches(".service").to_string(),
                    status: parts[3].to_string(),
                    enabled: parts[1] == "loaded",
                });
            }
        }
    }

    Ok(services)
}

async fn collect_docker_containers() -> Result<Vec<DockerContainer>> {
    let mut containers = Vec::new();

    // Check if docker is available
    if let Ok(output) = tokio::process::Command::new("docker")
        .args(&["ps", "-a", "--format", "{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}"])
        .output()
        .await
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split('|').collect();
            if parts.len() >= 5 {
                containers.push(DockerContainer {
                    id: parts[0].to_string(),
                    name: parts[1].to_string(),
                    image: parts[2].to_string(),
                    status: parts[3].to_string(),
                    ports: parts[4].split(',').map(|s| s.trim().to_string()).collect(),
                });
            }
        }
    }

    Ok(containers)
}
