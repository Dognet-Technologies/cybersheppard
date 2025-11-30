// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - Data Models
// ============================================================================

use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use chrono::{DateTime, Utc};

// TODO: Implement all data models according to DATABASE_SCHEMA.md

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

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Target {
    pub id: i32,
    pub hostname: String,
    pub ip_address: String,
    pub ssh_port: i32,
    pub status: String,
    pub created_at: DateTime<Utc>,
}
