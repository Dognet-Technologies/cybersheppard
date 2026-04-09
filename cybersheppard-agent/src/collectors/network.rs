// ============================================================================
// Network Metrics Collector - Connections, Ports, Traffic
// ============================================================================

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMetrics {
    pub active_connections: usize,
    pub listening_ports: Vec<ListeningPort>,
    pub established_connections: Vec<Connection>,
    pub failed_ssh_attempts: usize,
    pub interface_stats: HashMap<String, InterfaceStats>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListeningPort {
    pub port: u16,
    pub protocol: String,
    pub process: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    pub local_addr: String,
    pub remote_addr: String,
    pub state: String,
    pub pid: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceStats {
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub packets_sent: u64,
    pub packets_recv: u64,
    pub errors_in: u64,
    pub errors_out: u64,
}

pub async fn collect() -> Result<NetworkMetrics> {
    let listening_ports = collect_listening_ports().await?;
    let established_connections = collect_established_connections().await?;
    let active_connections = established_connections.len();
    let failed_ssh_attempts = collect_failed_ssh_attempts().await?;
    let interface_stats = collect_interface_stats().await?;

    Ok(NetworkMetrics {
        active_connections,
        listening_ports,
        established_connections,
        failed_ssh_attempts,
        interface_stats,
    })
}

async fn collect_listening_ports() -> Result<Vec<ListeningPort>> {
    let mut ports = Vec::new();

    // Parse /proc/net/tcp and /proc/net/tcp6
    for (file, protocol) in [("/proc/net/tcp", "tcp"), ("/proc/net/tcp6", "tcp6")] {
        if let Ok(content) = tokio::fs::read_to_string(file).await {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    // State 0A = listening
                    if parts[3] == "0A" {
                        if let Ok(port) = u16::from_str_radix(&parts[1].split(':').nth(1).unwrap_or("0"), 16) {
                            ports.push(ListeningPort {
                                port,
                                protocol: protocol.to_string(),
                                process: None, // Could parse /proc/{pid}/fd to find process
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(ports)
}

async fn collect_established_connections() -> Result<Vec<Connection>> {
    let mut connections = Vec::new();

    if let Ok(content) = tokio::fs::read_to_string("/proc/net/tcp").await {
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 && parts[3] == "01" {
                // State 01 = established
                connections.push(Connection {
                    local_addr: parts[1].to_string(),
                    remote_addr: parts[2].to_string(),
                    state: "ESTABLISHED".to_string(),
                    pid: None,
                });
            }
        }
    }

    Ok(connections)
}

async fn collect_failed_ssh_attempts() -> Result<usize> {
    // Parse /var/log/auth.log for failed SSH attempts in last hour
    let mut count = 0;

    if let Ok(content) = tokio::fs::read_to_string("/var/log/auth.log").await {
        for line in content.lines() {
            if line.contains("Failed password") || line.contains("Invalid user") {
                count += 1;
            }
        }
    }

    Ok(count)
}

async fn collect_interface_stats() -> Result<HashMap<String, InterfaceStats>> {
    let mut stats = HashMap::new();

    if let Ok(content) = tokio::fs::read_to_string("/proc/net/dev").await {
        for line in content.lines().skip(2) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 17 {
                let interface = parts[0].trim_end_matches(':').to_string();
                stats.insert(interface, InterfaceStats {
                    bytes_recv: parts[1].parse().unwrap_or(0),
                    packets_recv: parts[2].parse().unwrap_or(0),
                    errors_in: parts[3].parse().unwrap_or(0),
                    bytes_sent: parts[9].parse().unwrap_or(0),
                    packets_sent: parts[10].parse().unwrap_or(0),
                    errors_out: parts[11].parse().unwrap_or(0),
                });
            }
        }
    }

    Ok(stats)
}
