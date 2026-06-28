// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - Plugin Manager Service
// ============================================================================

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use sha2::{Sha256, Digest};
use std::path::PathBuf;
use base64::{Engine as _, engine::general_purpose};

#[derive(Clone)]
pub struct PluginManager {
    pg_pool: PgPool,
    plugins_dir: PathBuf,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct PluginRepository {
    pub id: i32,
    pub name: String,
    pub url: String,
    pub repository_type: String,
    pub branch: String,
    pub trust_level: String,
    pub is_official: bool,
    pub verified_owner: bool,
    pub auto_fetch: bool,
    pub fetch_interval_hours: i32,
    pub last_fetched_at: Option<chrono::DateTime<chrono::Utc>>,
    pub fetch_status: Option<String>,
    pub require_checksum: bool,
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct PluginRegistryEntry {
    pub id: i32,
    pub repository_id: i32,
    pub plugin_name: String,
    pub version: String,
    pub stato: Option<String>,
    pub stability_level: Option<String>,
    pub description: Option<String>,
    pub owner: Option<String>,
    pub language: Option<String>,
    pub runtime_version: Option<String>,
    pub quality: Option<String>,
    pub license: Option<String>,
    pub min_cybersheppard_version: Option<String>,
    pub max_cybersheppard_version: Option<String>,
    pub checksum_sha256: Option<String>,
    pub permissions: serde_json::Value,
    pub max_memory_mb: Option<i32>,
    pub max_cpu_percent: Option<i32>,
    pub max_execution_time_ms: Option<i32>,
    pub download_url: Option<String>,
    pub documentation_url: Option<String>,
    pub configuration_schema: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct InstalledPlugin {
    pub id: i32,
    pub plugin_name: String,
    pub version: String,
    pub installed_path: Option<String>,
    pub status: String,
    pub is_enabled: bool,
    pub configuration: serde_json::Value,
    pub execution_count: i64,
    pub error_count: i64,
    pub success_count: i64,
    pub avg_execution_time_ms: Option<f64>,
    pub total_events_processed: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    pub stato: String,
    pub stability_level: String,
    pub owner: String,
    pub description: String,
    pub language: String,
    pub runtime: Option<String>,
    pub quality: String,
    pub license: String,
    pub compatibility: PluginCompatibility,
    pub permissions: Vec<String>,
    pub resources: PluginResources,
    pub events: PluginEvents,
    pub dependencies: Option<serde_json::Value>,
    pub configuration_schema: Option<serde_json::Value>,
    pub files: PluginFiles,
    pub repository: Option<String>,
    pub documentation: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PluginCompatibility {
    pub min_version: String,
    pub max_version: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PluginResources {
    pub max_memory_mb: i32,
    pub max_cpu_percent: i32,
    pub max_execution_time_ms: Option<i32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PluginEvents {
    pub subscribes: Vec<String>,
    pub publishes: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PluginFiles {
    pub main: String,
    pub checksum: String,
}

impl PluginManager {
    pub fn new(pg_pool: PgPool) -> Self {
        let plugins_dir = PathBuf::from("/var/cybersheppard/plugins");
        Self {
            pg_pool,
            plugins_dir,
        }
    }

    // ========================================================================
    // REPOSITORY MANAGEMENT
    // ========================================================================

    pub async fn get_repositories(&self) -> Result<Vec<PluginRepository>, Box<dyn std::error::Error + Send + Sync>> {
        let repos = sqlx::query_as::<_, PluginRepository>(
            "SELECT * FROM plugin_repositories ORDER BY is_official DESC, name ASC"
        )
        .fetch_all(&self.pg_pool)
        .await?;

        Ok(repos)
    }

    pub async fn add_repository(
        &self,
        name: &str,
        url: &str,
        branch: &str,
        trust_level: &str,
        user_id: i32,
    ) -> Result<i32, Box<dyn std::error::Error + Send + Sync>> {
        let repo_id = sqlx::query_scalar::<_, i32>(
            r#"
            INSERT INTO plugin_repositories (name, url, branch, trust_level, added_by)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id
            "#
        )
        .bind(name)
        .bind(url)
        .bind(branch)
        .bind(trust_level)
        .bind(user_id)
        .fetch_one(&self.pg_pool)
        .await?;

        Ok(repo_id)
    }

    pub async fn remove_repository(
        &self,
        repo_id: i32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        sqlx::query("DELETE FROM plugin_repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&self.pg_pool)
            .await?;

        Ok(())
    }

    // ========================================================================
    // PLUGIN REGISTRY (Fetching from GitHub)
    // ========================================================================

    pub async fn fetch_repository_plugins(
        &self,
        repo_id: i32,
    ) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        let repo = sqlx::query_as::<_, PluginRepository>(
            "SELECT * FROM plugin_repositories WHERE id = $1"
        )
        .bind(repo_id)
        .fetch_one(&self.pg_pool)
        .await?;

        // Fetch plugins list from GitHub API
        let plugins = self.fetch_plugins_from_github(&repo).await?;

        // Insert/update in registry
        let mut count = 0;
        for manifest in plugins {
            self.upsert_plugin_registry(&repo, &manifest).await?;
            count += 1;
        }

        // Update last fetched
        sqlx::query(
            r#"
            UPDATE plugin_repositories
            SET last_fetched_at = NOW(), fetch_status = 'success'
            WHERE id = $1
            "#
        )
        .bind(repo_id)
        .execute(&self.pg_pool)
        .await?;

        Ok(count)
    }

    async fn fetch_plugins_from_github(
        &self,
        repo: &PluginRepository,
    ) -> Result<Vec<PluginManifest>, Box<dyn std::error::Error + Send + Sync>> {
        // Parse GitHub URL
        // Expected format: https://github.com/owner/repo
        let parts: Vec<&str> = repo.url.trim_end_matches('/').split('/').collect();
        if parts.len() < 2 {
            return Err("Invalid GitHub URL format".into());
        }

        let owner = parts[parts.len() - 2];
        let repo_name = parts[parts.len() - 1];

        // Fetch repository contents via GitHub API
        let url = format!(
            "https://api.github.com/repos/{}/{}/contents/plugins?ref={}",
            owner, repo_name, repo.branch
        );

        let client = reqwest::Client::new();
        let response = client
            .get(&url)
            .header("User-Agent", "CyberSheppard-Plugin-Manager")
            .header("Accept", "application/vnd.github+json")
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("GitHub API error: {}", response.status()).into());
        }

        #[derive(Deserialize)]
        struct GitHubContent {
            name: String,
            #[serde(rename = "type")]
            content_type: String,
            download_url: Option<String>,
        }

        let contents: Vec<GitHubContent> = response.json().await?;

        let mut manifests = Vec::new();

        // Look for manifest.json files in plugin directories
        for item in contents {
            if item.content_type == "dir" {
                // Fetch manifest.json from this directory
                let manifest_url = format!(
                    "https://api.github.com/repos/{}/{}/contents/plugins/{}/manifest.json?ref={}",
                    owner, repo_name, item.name, repo.branch
                );

                match self.fetch_manifest(&client, &manifest_url).await {
                    Ok(manifest) => manifests.push(manifest),
                    Err(e) => {
                        eprintln!("Error fetching manifest for {}: {}", item.name, e);
                        continue;
                    }
                }
            }
        }

        Ok(manifests)
    }

    async fn fetch_manifest(
        &self,
        client: &reqwest::Client,
        url: &str,
    ) -> Result<PluginManifest, Box<dyn std::error::Error + Send + Sync>> {
        #[derive(Deserialize)]
        struct GitHubFile {
            content: String,
            encoding: String,
        }

        let response = client
            .get(url)
            .header("User-Agent", "CyberSheppard-Plugin-Manager")
            .header("Accept", "application/vnd.github+json")
            .send()
            .await?;

        if !response.status().is_success() {
            return Err("Failed to fetch manifest".into());
        }

        let file: GitHubFile = response.json().await?;

        // Decode base64 content
        let decoded = if file.encoding == "base64" {
            general_purpose::STANDARD.decode(&file.content.replace("\n", ""))
                .map_err(|e| format!("Base64 decode error: {}", e))?
        } else {
            file.content.as_bytes().to_vec()
        };

        let manifest: PluginManifest = serde_json::from_slice(&decoded)?;
        Ok(manifest)
    }

    async fn upsert_plugin_registry(
        &self,
        repo: &PluginRepository,
        manifest: &PluginManifest,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let checksum = manifest.files.checksum.strip_prefix("sha256:").unwrap_or(&manifest.files.checksum);

        sqlx::query(
            r#"
            INSERT INTO plugin_registry (
                repository_id, plugin_name, version, stato, stability_level,
                description, owner, language, runtime_version, quality, license,
                min_cybersheppard_version, max_cybersheppard_version,
                checksum_sha256, permissions, max_memory_mb, max_cpu_percent,
                max_execution_time_ms, subscribes_to_events,
                download_url, documentation_url, repository_url,
                configuration_schema, fetched_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
                $16, $17, $18, $19, $20, $21, $22, $23, NOW()
            )
            ON CONFLICT (repository_id, plugin_name, version)
            DO UPDATE SET
                description = EXCLUDED.description,
                quality = EXCLUDED.quality,
                checksum_sha256 = EXCLUDED.checksum_sha256,
                permissions = EXCLUDED.permissions,
                configuration_schema = EXCLUDED.configuration_schema,
                fetched_at = NOW()
            "#
        )
        .bind(repo.id)
        .bind(&manifest.name)
        .bind(&manifest.version)
        .bind(&manifest.stato)
        .bind(&manifest.stability_level)
        .bind(&manifest.description)
        .bind(&manifest.owner)
        .bind(&manifest.language)
        .bind(&manifest.runtime)
        .bind(&manifest.quality)
        .bind(&manifest.license)
        .bind(&manifest.compatibility.min_version)
        .bind(&manifest.compatibility.max_version)
        .bind(checksum)
        .bind(serde_json::to_value(&manifest.permissions)?)
        .bind(manifest.resources.max_memory_mb)
        .bind(manifest.resources.max_cpu_percent)
        .bind(manifest.resources.max_execution_time_ms)
        .bind(&manifest.events.subscribes)
        .bind(format!("https://github.com/{}/raw/{}/plugins/{}/{}",
            repo.url.trim_end_matches('/').split('/').last().unwrap(),
            repo.branch, manifest.name, manifest.files.main))
        .bind(&manifest.documentation)
        .bind(&manifest.repository)
        .bind(&manifest.configuration_schema)
        .execute(&self.pg_pool)
        .await?;

        Ok(())
    }

    // ========================================================================
    // PLUGIN INSTALLATION
    // ========================================================================

    pub async fn get_available_plugins(&self) -> Result<Vec<PluginRegistryEntry>, Box<dyn std::error::Error + Send + Sync>> {
        let plugins = sqlx::query_as::<_, PluginRegistryEntry>(
            "SELECT * FROM available_plugins ORDER BY repository_name, plugin_name"
        )
        .fetch_all(&self.pg_pool)
        .await?;

        Ok(plugins)
    }

    pub async fn get_installed_plugins(&self) -> Result<Vec<InstalledPlugin>, Box<dyn std::error::Error + Send + Sync>> {
        let plugins = sqlx::query_as::<_, InstalledPlugin>(
            "SELECT * FROM installed_plugins ORDER BY plugin_name"
        )
        .fetch_all(&self.pg_pool)
        .await?;

        Ok(plugins)
    }

    pub async fn install_plugin(
        &self,
        registry_id: i32,
        user_id: i32,
    ) -> Result<i32, Box<dyn std::error::Error + Send + Sync>> {
        // Get plugin from registry
        let plugin = sqlx::query_as::<_, PluginRegistryEntry>(
            "SELECT * FROM plugin_registry WHERE id = $1"
        )
        .bind(registry_id)
        .fetch_one(&self.pg_pool)
        .await?;

        // Create plugin directory
        let plugin_path = self.plugins_dir.join(format!("{}-{}", plugin.plugin_name, plugin.version));
        std::fs::create_dir_all(&plugin_path)?;

        // Download plugin files would go here
        // For now, just record the installation

        // Insert into installed_plugins
        let installed_id = sqlx::query_scalar::<_, i32>(
            r#"
            INSERT INTO installed_plugins (
                registry_id, plugin_name, version, installed_path,
                status, is_enabled, installed_by
            ) VALUES ($1, $2, $3, $4, 'installed', false, $5)
            RETURNING id
            "#
        )
        .bind(registry_id)
        .bind(&plugin.plugin_name)
        .bind(&plugin.version)
        .bind(plugin_path.to_str())
        .bind(user_id)
        .fetch_one(&self.pg_pool)
        .await?;

        Ok(installed_id)
    }

    pub async fn uninstall_plugin(
        &self,
        plugin_id: i32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Get plugin path
        let plugin = sqlx::query_as::<_, InstalledPlugin>(
            "SELECT * FROM installed_plugins WHERE id = $1"
        )
        .bind(plugin_id)
        .fetch_one(&self.pg_pool)
        .await?;

        // Delete files if path exists
        if let Some(path) = plugin.installed_path {
            let _ = std::fs::remove_dir_all(&path);
        }

        // Delete from database
        sqlx::query("DELETE FROM installed_plugins WHERE id = $1")
            .bind(plugin_id)
            .execute(&self.pg_pool)
            .await?;

        Ok(())
    }

    pub async fn enable_plugin(
        &self,
        plugin_id: i32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        sqlx::query(
            "UPDATE installed_plugins SET is_enabled = true, status = 'enabled' WHERE id = $1"
        )
        .bind(plugin_id)
        .execute(&self.pg_pool)
        .await?;

        Ok(())
    }

    pub async fn disable_plugin(
        &self,
        plugin_id: i32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        sqlx::query(
            "UPDATE installed_plugins SET is_enabled = false, status = 'disabled' WHERE id = $1"
        )
        .bind(plugin_id)
        .execute(&self.pg_pool)
        .await?;

        Ok(())
    }

    pub async fn configure_plugin(
        &self,
        plugin_id: i32,
        configuration: serde_json::Value,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        sqlx::query(
            "UPDATE installed_plugins SET configuration = $1 WHERE id = $2"
        )
        .bind(&configuration)
        .bind(plugin_id)
        .execute(&self.pg_pool)
        .await?;

        Ok(())
    }

    // ========================================================================
    // HELPER METHODS
    // ========================================================================

    pub fn verify_checksum(&self, content: &[u8], expected: &str) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(content);
        let result = format!("{:x}", hasher.finalize());
        result == expected
    }
}
