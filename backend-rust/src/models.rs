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
