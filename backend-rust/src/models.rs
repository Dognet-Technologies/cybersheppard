// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - Data Models
// ============================================================================

use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use chrono::{DateTime, Utc};

// ============================================================================
// User Models
// ============================================================================

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub role: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

// ============================================================================
// Target Models
// ============================================================================

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Target {
    pub id: i32,
    pub hostname: String,
    pub ip_address: String,
    pub ssh_port: i32,
    pub ssh_username: String,
    pub ssh_key_id: Option<i32>,
    pub role: Option<String>,
    pub environment: String,
    pub gruppo: Option<String>,
    pub tags: Option<serde_json::Value>,
    pub compliance_standard: Option<String>,
    pub status: String,
    pub status_message: Option<String>,
    pub last_seen: Option<DateTime<Utc>>,
    pub last_check: Option<DateTime<Utc>>,
    pub hardening_applied: bool,
    pub hardening_model_id: Option<i32>,
    pub hardening_applied_at: Option<DateTime<Utc>>,
    pub hardening_score: Option<i32>,
    pub monitoring_enabled: bool,
    pub monitoring_interval_seconds: i32,
    pub last_monitoring_at: Option<DateTime<Utc>>,
    pub monitoring_errors_count: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct TargetGroup {
    pub id: i32,
    pub target_id: i32,
    pub group_name: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct TargetNetworkInterface {
    pub id: i32,
    pub target_id: i32,
    pub interface_name: String,
    pub ip_address: Option<String>,
    pub mac_address: Option<String>,
    pub is_primary: bool,
    pub created_at: DateTime<Utc>,
}

// ============================================================================
// Monitoring Models
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct MonitoringDataPayload {
    pub target_id: String,
    pub timestamp: DateTime<Utc>,
    pub data: MonitoringData,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MonitoringData {
    pub system_metrics: Option<SystemMetrics>,
    pub auditd: Option<AuditdMetrics>,
    pub sudo: Option<SudoMetrics>,
    pub network: Option<NetworkMetrics>,
    pub processes: Option<ProcessesMetrics>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SystemMetrics {
    pub cpu_usage: Option<f64>,
    pub memory_usage: Option<f64>,
    pub disk_usage: Option<f64>,
    pub load_average: Option<String>,
    pub uptime: Option<String>,
    pub failed_services: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditdMetrics {
    pub status: Option<String>,
    pub events_last_hour: Option<i64>,
    pub failed_logins: Option<i64>,
    pub config_changes: Option<i64>,
    pub privilege_escalations: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SudoMetrics {
    pub commands_last_hour: Option<i64>,
    pub failed_attempts: Option<i64>,
    pub unique_users: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkMetrics {
    pub active_connections: Option<i64>,
    pub listening_ports: Option<Vec<i32>>,
    pub failed_ssh_attempts: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProcessesMetrics {
    pub total_processes: Option<i64>,
    pub zombie_processes: Option<i64>,
    pub high_cpu_processes: Option<Vec<ProcessInfo>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub user: String,
    pub pid: i32,
    pub cpu: f64,
    pub mem: f64,
    pub command: String,
}
