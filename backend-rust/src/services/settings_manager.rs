// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - Settings Manager Service
// ============================================================================

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use sha2::{Sha256, Digest};
use rand::Rng;

#[derive(Clone)]
pub struct SettingsManager {
    pg_pool: PgPool,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct SystemSetting {
    pub id: i32,
    pub setting_key: String,
    pub setting_value: Option<String>,
    pub setting_type: String,
    pub category: Option<String>,
    pub description: Option<String>,
    pub is_editable: bool,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct UserSetting {
    pub id: i32,
    pub user_id: i32,
    pub setting_key: String,
    pub setting_value: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct ApiKey {
    pub id: i32,
    pub name: String,
    pub description: Option<String>,
    pub key_prefix: String,
    pub service: Option<String>,
    pub permissions: serde_json::Value,
    pub is_active: bool,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct ApiKeyWithToken {
    pub api_key: ApiKey,
    pub token: String, // Only returned once during creation
}

#[derive(Debug, Serialize)]
pub struct HealthStatus {
    pub database: DatabaseHealth,
    pub api: ApiHealth,
    pub integrations: IntegrationsHealth,
}

#[derive(Debug, Serialize)]
pub struct DatabaseHealth {
    pub status: String,
    pub response_time_ms: u64,
    pub connection_pool_size: u32,
    pub connection_pool_idle: u32,
}

#[derive(Debug, Serialize)]
pub struct ApiHealth {
    pub status: String,
    pub uptime_seconds: u64,
}

#[derive(Debug, Serialize)]
pub struct IntegrationsHealth {
    pub sentinel_core: String,
    pub firedog: String,
}

impl SettingsManager {
    pub fn new(pg_pool: PgPool) -> Self {
        Self { pg_pool }
    }

    // ========================================================================
    // SYSTEM SETTINGS
    // ========================================================================

    pub async fn get_system_settings(
        &self,
        category: Option<&str>,
    ) -> Result<Vec<SystemSetting>, Box<dyn std::error::Error + Send + Sync>> {
        let settings = if let Some(cat) = category {
            sqlx::query_as::<_, SystemSetting>(
                "SELECT * FROM system_settings WHERE category = $1 ORDER BY setting_key"
            )
            .bind(cat)
            .fetch_all(&self.pg_pool)
            .await?
        } else {
            sqlx::query_as::<_, SystemSetting>(
                "SELECT * FROM system_settings ORDER BY category, setting_key"
            )
            .fetch_all(&self.pg_pool)
            .await?
        };

        Ok(settings)
    }

    pub async fn get_system_setting(
        &self,
        key: &str,
    ) -> Result<Option<SystemSetting>, Box<dyn std::error::Error + Send + Sync>> {
        let setting = sqlx::query_as::<_, SystemSetting>(
            "SELECT * FROM system_settings WHERE setting_key = $1"
        )
        .bind(key)
        .fetch_optional(&self.pg_pool)
        .await?;

        Ok(setting)
    }

    pub async fn update_system_setting(
        &self,
        key: &str,
        value: &str,
        user_id: i32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Check if setting is editable
        let setting = self.get_system_setting(key).await?
            .ok_or("Setting not found")?;

        if !setting.is_editable {
            return Err("Setting is not editable".into());
        }

        // Update setting
        sqlx::query(
            "UPDATE system_settings SET setting_value = $1, updated_at = NOW() WHERE setting_key = $2"
        )
        .bind(value)
        .bind(key)
        .execute(&self.pg_pool)
        .await?;

        // Audit log
        self.log_audit(user_id, "update_setting", "setting", 0, Some(&setting.setting_value.unwrap_or_default()), Some(value)).await?;

        Ok(())
    }

    // ========================================================================
    // USER SETTINGS
    // ========================================================================

    pub async fn get_user_settings(
        &self,
        user_id: i32,
    ) -> Result<Vec<UserSetting>, Box<dyn std::error::Error + Send + Sync>> {
        let settings = sqlx::query_as::<_, UserSetting>(
            "SELECT * FROM user_settings WHERE user_id = $1 ORDER BY setting_key"
        )
        .bind(user_id)
        .fetch_all(&self.pg_pool)
        .await?;

        Ok(settings)
    }

    pub async fn set_user_setting(
        &self,
        user_id: i32,
        key: &str,
        value: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        sqlx::query(
            r#"
            INSERT INTO user_settings (user_id, setting_key, setting_value)
            VALUES ($1, $2, $3)
            ON CONFLICT (user_id, setting_key)
            DO UPDATE SET setting_value = $3, updated_at = NOW()
            "#
        )
        .bind(user_id)
        .bind(key)
        .bind(value)
        .execute(&self.pg_pool)
        .await?;

        Ok(())
    }

    // ========================================================================
    // API KEYS
    // ========================================================================

    pub async fn generate_api_key(
        &self,
        name: &str,
        description: Option<&str>,
        service: Option<&str>,
        permissions: serde_json::Value,
        user_id: i32,
        expires_days: Option<i32>,
    ) -> Result<ApiKeyWithToken, Box<dyn std::error::Error + Send + Sync>> {
        // Generate random API key
        let token = self.generate_random_token();
        let key_hash = self.hash_api_key(&token);
        let key_prefix = &token[..8];

        let expires_at = expires_days.map(|days| {
            chrono::Utc::now() + chrono::Duration::days(days as i64)
        });

        // Insert into database
        let api_key = sqlx::query_as::<_, ApiKey>(
            r#"
            INSERT INTO api_keys (name, description, key_hash, key_prefix, service, permissions, expires_at, created_by)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id, name, description, key_prefix, service, permissions, is_active, last_used_at, expires_at, created_at
            "#
        )
        .bind(name)
        .bind(description)
        .bind(&key_hash)
        .bind(key_prefix)
        .bind(service)
        .bind(&permissions)
        .bind(expires_at)
        .bind(user_id)
        .fetch_one(&self.pg_pool)
        .await?;

        // Audit log
        self.log_audit(user_id, "generate_api_key", "api_key", api_key.id, None, Some(name)).await?;

        Ok(ApiKeyWithToken {
            api_key,
            token,
        })
    }

    pub async fn get_api_keys(
        &self,
        service: Option<&str>,
    ) -> Result<Vec<ApiKey>, Box<dyn std::error::Error + Send + Sync>> {
        let keys = if let Some(svc) = service {
            sqlx::query_as::<_, ApiKey>(
                "SELECT * FROM active_api_keys WHERE service = $1"
            )
            .bind(svc)
            .fetch_all(&self.pg_pool)
            .await?
        } else {
            sqlx::query_as::<_, ApiKey>(
                "SELECT * FROM active_api_keys"
            )
            .fetch_all(&self.pg_pool)
            .await?
        };

        Ok(keys)
    }

    pub async fn revoke_api_key(
        &self,
        key_id: i32,
        user_id: i32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        sqlx::query(
            "UPDATE api_keys SET is_active = false, revoked_at = NOW(), revoked_by = $1 WHERE id = $2"
        )
        .bind(user_id)
        .bind(key_id)
        .execute(&self.pg_pool)
        .await?;

        // Audit log
        self.log_audit(user_id, "revoke_api_key", "api_key", key_id, None, None).await?;

        Ok(())
    }

    // ========================================================================
    // HEALTH CHECKS
    // ========================================================================

    pub async fn check_health(&self) -> Result<HealthStatus, Box<dyn std::error::Error + Send + Sync>> {
        // Database health
        let start = std::time::Instant::now();
        let _ = sqlx::query("SELECT 1").fetch_one(&self.pg_pool).await?;
        let db_response_time = start.elapsed().as_millis() as u64;

        let database = DatabaseHealth {
            status: if db_response_time < 100 { "healthy".to_string() } else { "degraded".to_string() },
            response_time_ms: db_response_time,
            connection_pool_size: self.pg_pool.size() as u32,
            connection_pool_idle: self.pg_pool.num_idle() as u32,
        };

        // API health (always healthy if we can respond)
        let api = ApiHealth {
            status: "healthy".to_string(),
            uptime_seconds: 0, // TODO: implement proper uptime tracking
        };

        // Integration health (check if URLs are configured)
        let sentinel_url = self.get_system_setting("sentinel_core_url").await?;
        let firedog_url = self.get_system_setting("firedog_url").await?;

        let integrations = IntegrationsHealth {
            sentinel_core: if sentinel_url.and_then(|s| s.setting_value).unwrap_or_default().is_empty() {
                "not_configured".to_string()
            } else {
                "configured".to_string()
            },
            firedog: if firedog_url.and_then(|s| s.setting_value).unwrap_or_default().is_empty() {
                "not_configured".to_string()
            } else {
                "configured".to_string()
            },
        };

        Ok(HealthStatus {
            database,
            api,
            integrations,
        })
    }

    // ========================================================================
    // DATABASE OPERATIONS
    // ========================================================================

    pub async fn reset_database(
        &self,
        user_id: i32,
        confirm_token: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Security check: require confirmation token
        if confirm_token != "HARD_RESET_CONFIRMED" {
            return Err("Invalid confirmation token".into());
        }

        // Audit log BEFORE deletion
        self.log_audit(user_id, "reset_database", "system", 0, None, Some("HARD RESET INITIATED")).await?;

        // Delete all monitoring data (keep structure)
        sqlx::query("TRUNCATE TABLE compliance_violations CASCADE").execute(&self.pg_pool).await?;
        sqlx::query("TRUNCATE TABLE hardening_applications CASCADE").execute(&self.pg_pool).await?;
        sqlx::query("TRUNCATE TABLE sentinel_vulnerabilities CASCADE").execute(&self.pg_pool).await?;
        sqlx::query("TRUNCATE TABLE firedog_threats CASCADE").execute(&self.pg_pool).await?;
        sqlx::query("TRUNCATE TABLE security_correlations CASCADE").execute(&self.pg_pool).await?;
        sqlx::query("TRUNCATE TABLE alerts CASCADE").execute(&self.pg_pool).await?;
        sqlx::query("TRUNCATE TABLE compliance_assessments CASCADE").execute(&self.pg_pool).await?;

        Ok(())
    }

    pub async fn cleanup_old_data(
        &self,
        retention_days: i32,
    ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        let cutoff_date = chrono::Utc::now() - chrono::Duration::days(retention_days as i64);

        // Delete old violations
        let result = sqlx::query(
            "DELETE FROM compliance_violations WHERE first_detected_at < $1 AND status IN ('resolved', 'false_positive')"
        )
        .bind(cutoff_date)
        .execute(&self.pg_pool)
        .await?;

        Ok(result.rows_affected())
    }

    // ========================================================================
    // HELPER METHODS
    // ========================================================================

    fn generate_random_token(&self) -> String {
        let mut rng = rand::thread_rng();
        let token: String = (0..32)
            .map(|_| {
                let idx = rng.gen_range(0..62);
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
                    .chars()
                    .nth(idx)
                    .unwrap()
            })
            .collect();
        format!("cs_{}", token)
    }

    fn hash_api_key(&self, key: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    async fn log_audit(
        &self,
        user_id: i32,
        action: &str,
        entity_type: &str,
        entity_id: i32,
        old_value: Option<&str>,
        new_value: Option<&str>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        sqlx::query(
            r#"
            INSERT INTO settings_audit_log (user_id, action, entity_type, entity_id, old_value, new_value)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#
        )
        .bind(user_id)
        .bind(action)
        .bind(entity_type)
        .bind(entity_id)
        .bind(old_value)
        .bind(new_value)
        .execute(&self.pg_pool)
        .await?;

        Ok(())
    }
}
