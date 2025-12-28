// ============================================================================
// CYBERSHEPPARD - Sentinel Core Integration Client
// ============================================================================

use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Clone)]
pub struct SentinelCoreClient {
    base_url: String,
    api_key: String,
    client: Client,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Vulnerability {
    pub cve_id: String,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub cvss_score: f32,
    pub cvss_vector: Option<String>,
    pub epss_score: Option<f32>,
    pub published_date: DateTime<Utc>,
    pub last_modified_date: DateTime<Utc>,
    pub affected_packages: Vec<String>,
    pub references: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Asset {
    pub id: Option<i32>,
    pub hostname: String,
    pub ip_address: String,
    pub os: String,
    pub os_version: String,
    pub packages: Vec<InstalledPackage>,
    pub last_scan: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct InstalledPackage {
    pub name: String,
    pub version: String,
    pub architecture: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VulnerabilityScanRequest {
    pub asset_id: i32,
    pub scan_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VulnerabilityScanResult {
    pub scan_id: String,
    pub asset_id: i32,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub status: String,
    pub vulnerabilities_found: i32,
    pub critical_count: i32,
    pub high_count: i32,
    pub medium_count: i32,
    pub low_count: i32,
}

impl SentinelCoreClient {
    pub fn new(base_url: String, api_key: String) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            base_url,
            api_key,
            client,
        }
    }

    pub async fn get_vulnerabilities_for_package(
        &self,
        package_name: &str,
        package_version: &str,
    ) -> Result<Vec<Vulnerability>, Box<dyn std::error::Error>> {
        let url = format!(
            "{}/api/v1/vulnerabilities?package={}&version={}",
            self.base_url, package_name, package_version
        );

        let response = self.client
            .get(&url)
            .header("X-API-Key", &self.api_key)
            .send()
            .await?;

        if response.status() == StatusCode::OK {
            let vulnerabilities: Vec<Vulnerability> = response.json().await?;
            Ok(vulnerabilities)
        } else {
            Err(format!("API error: {}", response.status()).into())
        }
    }

    pub async fn get_cve_details(
        &self,
        cve_id: &str,
    ) -> Result<Vulnerability, Box<dyn std::error::Error>> {
        let url = format!("{}/api/v1/vulnerabilities/{}", self.base_url, cve_id);

        let response = self.client
            .get(&url)
            .header("X-API-Key", &self.api_key)
            .send()
            .await?;

        if response.status() == StatusCode::OK {
            let vulnerability: Vulnerability = response.json().await?;
            Ok(vulnerability)
        } else {
            Err(format!("CVE not found: {}", cve_id).into())
        }
    }

    pub async fn sync_asset(
        &self,
        asset: &Asset,
    ) -> Result<i32, Box<dyn std::error::Error>> {
        if let Some(asset_id) = asset.id {
            let url = format!("{}/api/v1/assets/{}", self.base_url, asset_id);

            let response = self.client
                .put(&url)
                .header("X-API-Key", &self.api_key)
                .json(asset)
                .send()
                .await?;

            if response.status().is_success() {
                Ok(asset_id)
            } else {
                Err(format!("Failed to update asset: {}", response.status()).into())
            }
        } else {
            let url = format!("{}/api/v1/assets", self.base_url);

            let response = self.client
                .post(&url)
                .header("X-API-Key", &self.api_key)
                .json(asset)
                .send()
                .await?;

            if response.status() == StatusCode::CREATED {
                let created_asset: Asset = response.json().await?;
                Ok(created_asset.id.unwrap())
            } else {
                Err(format!("Failed to create asset: {}", response.status()).into())
            }
        }
    }

    pub async fn get_asset_vulnerabilities(
        &self,
        asset_id: i32,
    ) -> Result<Vec<Vulnerability>, Box<dyn std::error::Error>> {
        let url = format!(
            "{}/api/v1/assets/{}/vulnerabilities",
            self.base_url, asset_id
        );

        let response = self.client
            .get(&url)
            .header("X-API-Key", &self.api_key)
            .send()
            .await?;

        if response.status() == StatusCode::OK {
            let vulnerabilities: Vec<Vulnerability> = response.json().await?;
            Ok(vulnerabilities)
        } else {
            Err(format!("Failed to get vulnerabilities: {}", response.status()).into())
        }
    }

    pub async fn trigger_scan(
        &self,
        asset_id: i32,
        scan_type: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let url = format!("{}/api/v1/scans", self.base_url);

        let request = VulnerabilityScanRequest {
            asset_id,
            scan_type: scan_type.to_string(),
        };

        let response = self.client
            .post(&url)
            .header("X-API-Key", &self.api_key)
            .json(&request)
            .send()
            .await?;

        if response.status() == StatusCode::CREATED {
            let result: serde_json::Value = response.json().await?;
            Ok(result["scan_id"].as_str().unwrap_or("").to_string())
        } else {
            Err(format!("Failed to trigger scan: {}", response.status()).into())
        }
    }

    pub async fn get_scan_results(
        &self,
        scan_id: &str,
    ) -> Result<VulnerabilityScanResult, Box<dyn std::error::Error>> {
        let url = format!("{}/api/v1/scans/{}", self.base_url, scan_id);

        let response = self.client
            .get(&url)
            .header("X-API-Key", &self.api_key)
            .send()
            .await?;

        if response.status() == StatusCode::OK {
            let result: VulnerabilityScanResult = response.json().await?;
            Ok(result)
        } else {
            Err(format!("Failed to get scan results: {}", response.status()).into())
        }
    }
}
