# MicroSIEM (CyberSheppard) - Integration Specification

## 📋 Indice

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Sentinel Core Integration](#sentinel-core-integration)
4. [FireDog Integration](#firedog-integration)
5. [Data Synchronization](#data-synchronization)
6. [Security Correlation](#security-correlation)
7. [API Client Implementation](#api-client-implementation)
8. [Configuration](#configuration)

---

## Overview

**Integration Module**: Connessione bidirezionale tra MicroSIEM, Sentinel Core (vulnerability management) e FireDog (firewall management).

### Integration Goals

✅ **Vulnerability enrichment** - Arricchire dati target con CVE da Sentinel Core  
✅ **Threat correlation** - Correlare minacce FireDog con vulnerabilità  
✅ **Unified dashboard** - Vista unificata sicurezza da 3 sistemi  
✅ **Automated response** - Azioni automatiche basate su correlazioni  
✅ **Asset synchronization** - Sincronizzazione inventario asset  
✅ **Bidirectional updates** - Aggiornamenti bidirezionali tra sistemi  

---

## Architecture

### Integration Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                      MICROSIEM (CyberSheppard)                   │
│                                                                   │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  Integration Service (Rust)                                │  │
│  │  - API clients (Sentinel Core, FireDog)                    │  │
│  │  - Data synchronization                                    │  │
│  │  - Correlation engine                                      │  │
│  │  - Webhook receivers                                       │  │
│  └────────────┬───────────────────────────────┬───────────────┘  │
│               │                               │                  │
└───────────────┼───────────────────────────────┼──────────────────┘
                │                               │
                │ HTTP REST API                 │ HTTP REST API
                │ (with API Keys)               │ (with API Keys)
                ▼                               ▼
┌───────────────────────────────┐   ┌──────────────────────────────┐
│  SENTINEL CORE                │   │  FIREDOG                     │
│  (Vulnerability Management)   │   │  (Firewall Management)       │
├───────────────────────────────┤   ├──────────────────────────────┤
│                               │   │                              │
│  • CVE Database               │   │  • Threat Detection          │
│  • Asset Inventory            │   │  • Network Statistics        │
│  • Vulnerability Scans        │   │  • Firewall Rules            │
│  • EPSS Scores                │   │  • Attack Patterns           │
│  • Exploit Predictions        │   │  • Blocked IPs               │
│                               │   │                              │
│  API: /api/v1/*              │   │  API: /api/*                 │
│                               │   │                              │
└───────────────────────────────┘   └──────────────────────────────┘
```

### Data Flow

```
┌─────────────────────────────────────────────────────────────────┐
│  1. ASSET SYNCHRONIZATION                                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  MicroSIEM Target Added → Sync to Sentinel Core                 │
│                        → Sync to FireDog                         │
│                                                                  │
│  Sentinel Core Asset Updated → Sync to MicroSIEM                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  2. VULNERABILITY ENRICHMENT                                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  MicroSIEM detects package → Query Sentinel Core for CVEs       │
│                           → Store vulnerabilities                │
│                           → Display in dashboard                 │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  3. THREAT CORRELATION                                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  FireDog detects threat → Push to MicroSIEM webhook             │
│                         → Correlate with vulnerabilities         │
│                         → Check if target is vulnerable          │
│                         → Trigger high-priority alert            │
│                         → Suggest hardening actions              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  4. AUTOMATED RESPONSE                                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  High-risk correlation detected → Auto-apply firewall rule      │
│                                 → Block attacker IP in FireDog   │
│                                 → Trigger hardening in MicroSIEM │
│                                 → Send alert to admin            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Sentinel Core Integration

### API Endpoints Used

```rust
// Sentinel Core API endpoints
const SENTINEL_CORE_ENDPOINTS: &[(&str, &str)] = &[
    ("GET", "/api/v1/vulnerabilities"),          // List vulnerabilities
    ("GET", "/api/v1/vulnerabilities/{cve_id}"), // Get CVE details
    ("GET", "/api/v1/assets"),                    // List assets
    ("POST", "/api/v1/assets"),                   // Create asset
    ("PUT", "/api/v1/assets/{id}"),              // Update asset
    ("GET", "/api/v1/assets/{id}/vulnerabilities"), // Get asset vulnerabilities
    ("POST", "/api/v1/scans"),                    // Trigger vulnerability scan
    ("GET", "/api/v1/scans/{id}"),               // Get scan results
];
```

### SentinelCoreClient Implementation

```rust
// microsiem/backend/src/integrations/sentinel_core.rs

use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Clone)]
pub struct SentinelCoreClient {
    base_url: String,
    api_key: String,
    client: Client,
}

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
pub struct InstalledPackage {
    pub name: String,
    pub version: String,
    pub architecture: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VulnerabilityScanRequest {
    pub asset_id: i32,
    pub scan_type: String, // "quick" or "full"
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VulnerabilityScanResult {
    pub scan_id: String,
    pub asset_id: i32,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub status: String, // "pending", "running", "completed", "failed"
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
    
    /// Get vulnerabilities for a specific package
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
    
    /// Get CVE details by ID
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
    
    /// Create or update asset in Sentinel Core
    pub async fn sync_asset(
        &self,
        asset: &Asset,
    ) -> Result<i32, Box<dyn std::error::Error>> {
        if let Some(asset_id) = asset.id {
            // Update existing asset
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
            // Create new asset
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
    
    /// Get all vulnerabilities for an asset
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
    
    /// Trigger vulnerability scan for asset
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
    
    /// Get scan results
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
```

---

## FireDog Integration

### API Endpoints Used

```rust
// FireDog API endpoints
const FIREDOG_ENDPOINTS: &[(&str, &str)] = &[
    ("GET", "/api/threats/"),                    // List threats
    ("GET", "/api/threats/{id}/"),              // Get threat details
    ("POST", "/api/threats/{id}/acknowledge/"), // Acknowledge threat
    ("GET", "/api/targets/"),                    // List protected targets
    ("GET", "/api/targets/{id}/statistics/"),   // Get target statistics
    ("POST", "/api/firewall/block/"),           // Block IP address
    ("DELETE", "/api/firewall/block/{id}/"),    // Unblock IP address
];
```

### FireDogClient Implementation

```rust
// microsiem/backend/src/integrations/firedog.rs

use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Clone)]
pub struct FireDogClient {
    base_url: String,
    api_key: String,
    client: Client,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Threat {
    pub id: i32,
    pub source_ip: String,
    pub destination_ip: String,
    pub destination_port: i32,
    pub threat_type: String,
    pub classification: String,
    pub score: f32,
    pub details: String,
    pub detected_at: DateTime<Utc>,
    pub acknowledged: bool,
    pub acknowledged_by: Option<String>,
    pub acknowledged_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ThreatSummary {
    pub total_threats: i32,
    pub critical_threats: i32,
    pub high_threats: i32,
    pub medium_threats: i32,
    pub low_threats: i32,
    pub acknowledged_threats: i32,
    pub top_attackers: Vec<TopAttacker>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TopAttacker {
    pub ip_address: String,
    pub threat_count: i32,
    pub avg_score: f32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TargetStatistics {
    pub target_id: i32,
    pub target_ip: String,
    pub input_packets: i64,
    pub output_packets: i64,
    pub input_dropped: i64,
    pub output_dropped: i64,
    pub input_drop_rate: f32,
    pub output_drop_rate: f32,
    pub threats_detected: i32,
    pub last_threat: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BlockIPRequest {
    pub ip_address: String,
    pub reason: String,
    pub duration_hours: Option<i32>, // None = permanent
}

impl FireDogClient {
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
    
    /// Get all threats
    pub async fn get_threats(
        &self,
        limit: Option<i32>,
        acknowledged: Option<bool>,
    ) -> Result<Vec<Threat>, Box<dyn std::error::Error>> {
        let mut url = format!("{}/api/threats/", self.base_url);
        
        let mut params = Vec::new();
        if let Some(limit) = limit {
            params.push(format!("limit={}", limit));
        }
        if let Some(ack) = acknowledged {
            params.push(format!("acknowledged={}", ack));
        }
        
        if !params.is_empty() {
            url.push('?');
            url.push_str(&params.join("&"));
        }
        
        let response = self.client
            .get(&url)
            .header("X-API-Key", &self.api_key)
            .send()
            .await?;
        
        if response.status() == StatusCode::OK {
            let threats: Vec<Threat> = response.json().await?;
            Ok(threats)
        } else {
            Err(format!("API error: {}", response.status()).into())
        }
    }
    
    /// Get threat summary statistics
    pub async fn get_threat_summary(&self) -> Result<ThreatSummary, Box<dyn std::error::Error>> {
        let url = format!("{}/api/threats/summary/", self.base_url);
        
        let response = self.client
            .get(&url)
            .header("X-API-Key", &self.api_key)
            .send()
            .await?;
        
        if response.status() == StatusCode::OK {
            let summary: ThreatSummary = response.json().await?;
            Ok(summary)
        } else {
            Err(format!("Failed to get threat summary: {}", response.status()).into())
        }
    }
    
    /// Get statistics for a specific target
    pub async fn get_target_statistics(
        &self,
        target_id: i32,
    ) -> Result<TargetStatistics, Box<dyn std::error::Error>> {
        let url = format!("{}/api/targets/{}/statistics/", self.base_url, target_id);
        
        let response = self.client
            .get(&url)
            .header("X-API-Key", &self.api_key)
            .send()
            .await?;
        
        if response.status() == StatusCode::OK {
            let stats: TargetStatistics = response.json().await?;
            Ok(stats)
        } else {
            Err(format!("Failed to get target statistics: {}", response.status()).into())
        }
    }
    
    /// Block an IP address
    pub async fn block_ip(
        &self,
        ip_address: &str,
        reason: &str,
        duration_hours: Option<i32>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let url = format!("{}/api/firewall/block/", self.base_url);
        
        let request = BlockIPRequest {
            ip_address: ip_address.to_string(),
            reason: reason.to_string(),
            duration_hours,
        };
        
        let response = self.client
            .post(&url)
            .header("X-API-Key", &self.api_key)
            .json(&request)
            .send()
            .await?;
        
        if response.status().is_success() {
            tracing::info!("Blocked IP {} in FireDog: {}", ip_address, reason);
            Ok(())
        } else {
            Err(format!("Failed to block IP: {}", response.status()).into())
        }
    }
    
    /// Acknowledge a threat
    pub async fn acknowledge_threat(
        &self,
        threat_id: i32,
        acknowledged_by: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let url = format!("{}/api/threats/{}/acknowledge/", self.base_url, threat_id);
        
        let request = serde_json::json!({
            "acknowledged_by": acknowledged_by
        });
        
        let response = self.client
            .post(&url)
            .header("X-API-Key", &self.api_key)
            .json(&request)
            .send()
            .await?;
        
        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!("Failed to acknowledge threat: {}", response.status()).into())
        }
    }
}
```

---

## Data Synchronization

### Synchronization Service

```rust
// microsiem/backend/src/services/integration_sync.rs

use sqlx::PgPool;
use tokio::time::{interval, Duration};
use crate::integrations::{SentinelCoreClient, FireDogClient};

pub struct IntegrationSyncService {
    sentinel_client: SentinelCoreClient,
    firedog_client: FireDogClient,
    pg_pool: PgPool,
}

impl IntegrationSyncService {
    pub fn new(
        sentinel_client: SentinelCoreClient,
        firedog_client: FireDogClient,
        pg_pool: PgPool,
    ) -> Self {
        Self {
            sentinel_client,
            firedog_client,
            pg_pool,
        }
    }
    
    /// Start synchronization loop
    pub async fn start(&self) {
        // Sync every 5 minutes
        let mut ticker = interval(Duration::from_secs(300));
        
        loop {
            ticker.tick().await;
            
            tracing::info!("Starting integration synchronization");
            
            // Sync vulnerabilities from Sentinel Core
            if let Err(e) = self.sync_vulnerabilities().await {
                tracing::error!("Failed to sync vulnerabilities: {}", e);
            }
            
            // Sync threats from FireDog
            if let Err(e) = self.sync_threats().await {
                tracing::error!("Failed to sync threats: {}", e);
            }
            
            // Perform security correlations
            if let Err(e) = self.correlate_security_data().await {
                tracing::error!("Failed to correlate security data: {}", e);
            }
            
            tracing::info!("Integration synchronization complete");
        }
    }
    
    async fn sync_vulnerabilities(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Get all targets from MicroSIEM
        let targets = sqlx::query!(
            "SELECT id, hostname, ip_address, sentinel_asset_id FROM targets WHERE status = 'active'"
        )
        .fetch_all(&self.pg_pool)
        .await?;
        
        for target in targets {
            tracing::debug!("Syncing vulnerabilities for target {}", target.hostname);
            
            // Get vulnerabilities from Sentinel Core
            if let Some(asset_id) = target.sentinel_asset_id {
                let vulnerabilities = self.sentinel_client
                    .get_asset_vulnerabilities(asset_id)
                    .await?;
                
                // Store vulnerabilities in InfluxDB (via correlation measurement)
                for vuln in vulnerabilities {
                    // Insert into database for correlation
                    sqlx::query!(
                        r#"
                        INSERT INTO sentinel_vulnerabilities (
                            target_id, cve_id, severity, cvss_score, epss_score, 
                            description, published_date
                        ) VALUES ($1, $2, $3, $4, $5, $6, $7)
                        ON CONFLICT (target_id, cve_id) DO UPDATE SET
                            severity = EXCLUDED.severity,
                            cvss_score = EXCLUDED.cvss_score,
                            epss_score = EXCLUDED.epss_score,
                            updated_at = NOW()
                        "#,
                        target.id,
                        vuln.cve_id,
                        vuln.severity,
                        vuln.cvss_score,
                        vuln.epss_score,
                        vuln.description,
                        vuln.published_date
                    )
                    .execute(&self.pg_pool)
                    .await?;
                }
            }
        }
        
        Ok(())
    }
    
    async fn sync_threats(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Get unacknowledged threats from FireDog
        let threats = self.firedog_client
            .get_threats(Some(100), Some(false))
            .await?;
        
        for threat in threats {
            // Find MicroSIEM target matching threat destination IP
            let target = sqlx::query!(
                "SELECT id FROM targets WHERE ip_address = $1",
                threat.destination_ip
            )
            .fetch_optional(&self.pg_pool)
            .await?;
            
            if let Some(target) = target {
                // Store threat in database
                sqlx::query!(
                    r#"
                    INSERT INTO firedog_threats (
                        target_id, firedog_threat_id, source_ip, threat_type,
                        classification, score, details, detected_at
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                    ON CONFLICT (firedog_threat_id) DO NOTHING
                    "#,
                    target.id,
                    threat.id,
                    threat.source_ip,
                    threat.threat_type,
                    threat.classification,
                    threat.score,
                    threat.details,
                    threat.detected_at
                )
                .execute(&self.pg_pool)
                .await?;
            }
        }
        
        Ok(())
    }
    
    async fn correlate_security_data(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Find targets with both vulnerabilities and active threats
        let correlations = sqlx::query!(
            r#"
            SELECT 
                t.id as target_id,
                t.hostname,
                t.ip_address,
                v.cve_id,
                v.cvss_score,
                th.source_ip,
                th.threat_type,
                th.score as threat_score
            FROM targets t
            INNER JOIN sentinel_vulnerabilities v ON t.id = v.target_id
            INNER JOIN firedog_threats th ON t.id = th.target_id
            WHERE 
                v.severity IN ('critical', 'high')
                AND th.score >= 7.0
                AND th.detected_at > NOW() - INTERVAL '24 hours'
            "#
        )
        .fetch_all(&self.pg_pool)
        .await?;
        
        for correlation in correlations {
            tracing::warn!(
                "HIGH-RISK CORRELATION: Target {} has vulnerability {} (CVSS {}) and active threat from {} (score {})",
                correlation.hostname,
                correlation.cve_id,
                correlation.cvss_score,
                correlation.source_ip,
                correlation.threat_score
            );
            
            // Store correlation
            sqlx::query!(
                r#"
                INSERT INTO security_correlations (
                    target_id, vulnerability_cve, vulnerability_cvss,
                    threat_source_ip, threat_type, threat_score,
                    correlation_confidence, recommended_action, created_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
                "#,
                correlation.target_id,
                correlation.cve_id,
                correlation.cvss_score,
                correlation.source_ip,
                correlation.threat_type,
                correlation.threat_score,
                0.85, // High confidence
                "Consider applying security patches and blocking attacker IP"
            )
            .execute(&self.pg_pool)
            .await?;
            
            // Trigger alert (to be implemented in alert service)
            // self.alert_service.trigger_correlation_alert(...).await?;
        }
        
        Ok(())
    }
}
```

---

## Security Correlation

### Correlation Engine

```rust
// microsiem/backend/src/services/correlation_engine.rs

use sqlx::PgPool;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityCorrelation {
    pub target_id: i32,
    pub target_hostname: String,
    pub vulnerability_cve: String,
    pub vulnerability_cvss: f32,
    pub threat_source_ip: String,
    pub threat_type: String,
    pub threat_score: f32,
    pub correlation_confidence: f32,
    pub risk_level: String,
    pub recommended_actions: Vec<String>,
}

pub struct CorrelationEngine {
    pg_pool: PgPool,
}

impl CorrelationEngine {
    pub fn new(pg_pool: PgPool) -> Self {
        Self { pg_pool }
    }
    
    /// Analyze and create security correlations
    pub async fn analyze_correlations(&self) -> Result<Vec<SecurityCorrelation>, Box<dyn std::error::Error>> {
        let mut correlations = Vec::new();
        
        // Rule 1: Vulnerability + Active Threat = High Risk
        let vuln_threat_matches = self.find_vulnerability_threat_matches().await?;
        correlations.extend(vuln_threat_matches);
        
        // Rule 2: Multiple Failed Auths + Known Vulnerability = Targeted Attack
        let targeted_attacks = self.find_targeted_attacks().await?;
        correlations.extend(targeted_attacks);
        
        // Rule 3: Privilege Escalation Attempts + Vulnerable Kernel = Critical
        let privesc_attempts = self.find_privilege_escalation_attempts().await?;
        correlations.extend(privesc_attempts);
        
        Ok(correlations)
    }
    
    async fn find_vulnerability_threat_matches(&self) -> Result<Vec<SecurityCorrelation>, Box<dyn std::error::Error>> {
        let matches = sqlx::query_as!(
            SecurityCorrelation,
            r#"
            SELECT 
                t.id as target_id,
                t.hostname as target_hostname,
                v.cve_id as vulnerability_cve,
                v.cvss_score as vulnerability_cvss,
                th.source_ip as threat_source_ip,
                th.threat_type,
                th.score as threat_score,
                0.90 as correlation_confidence,
                CASE 
                    WHEN v.cvss_score >= 9.0 AND th.score >= 8.0 THEN 'critical'
                    WHEN v.cvss_score >= 7.0 AND th.score >= 7.0 THEN 'high'
                    ELSE 'medium'
                END as risk_level,
                ARRAY[
                    'Apply security patches immediately',
                    'Block attacker IP in firewall',
                    'Increase monitoring on affected target',
                    'Consider isolating target from network'
                ] as recommended_actions
            FROM targets t
            INNER JOIN sentinel_vulnerabilities v ON t.id = v.target_id
            INNER JOIN firedog_threats th ON t.id = th.target_id
            WHERE 
                v.severity IN ('critical', 'high')
                AND th.score >= 7.0
                AND th.detected_at > NOW() - INTERVAL '24 hours'
                AND NOT EXISTS (
                    SELECT 1 FROM security_correlations sc
                    WHERE sc.target_id = t.id
                    AND sc.vulnerability_cve = v.cve_id
                    AND sc.threat_source_ip = th.source_ip
                    AND sc.created_at > NOW() - INTERVAL '1 hour'
                )
            "#
        )
        .fetch_all(&self.pg_pool)
        .await?;
        
        Ok(matches)
    }
    
    async fn find_targeted_attacks(&self) -> Result<Vec<SecurityCorrelation>, Box<dyn std::error::Error>> {
        // Find targets with multiple failed auth attempts AND known vulnerabilities
        // This indicates a targeted attack where attacker knows about vulnerability
        
        // TODO: Implement logic
        
        Ok(Vec::new())
    }
    
    async fn find_privilege_escalation_attempts(&self) -> Result<Vec<SecurityCorrelation>, Box<dyn std::error::Error>> {
        // Find privilege escalation attempts on systems with vulnerable kernels
        
        // TODO: Implement logic
        
        Ok(Vec::new())
    }
}
```

---

## Configuration

### Integration Configuration Schema

```rust
// microsiem/backend/src/config/integrations.rs

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationConfig {
    pub sentinel_core: Option<SentinelCoreConfig>,
    pub firedog: Option<FireDogConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelCoreConfig {
    pub enabled: bool,
    pub base_url: String,
    pub api_key: String,
    pub sync_interval_minutes: i32,
    pub auto_create_assets: bool,
    pub auto_trigger_scans: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FireDogConfig {
    pub enabled: bool,
    pub base_url: String,
    pub api_key: String,
    pub sync_interval_minutes: i32,
    pub auto_block_high_threats: bool,
    pub auto_acknowledge_handled_threats: bool,
}

impl Default for IntegrationConfig {
    fn default() -> Self {
        Self {
            sentinel_core: None,
            firedog: None,
        }
    }
}
```

### Environment Variables

```bash
# Sentinel Core Integration
SENTINEL_CORE_ENABLED=true
SENTINEL_CORE_BASE_URL=https://sentinel-core.example.com
SENTINEL_CORE_API_KEY=sc_key_xxxxxxxxxxxxx
SENTINEL_CORE_SYNC_INTERVAL=5  # minutes
SENTINEL_CORE_AUTO_CREATE_ASSETS=true
SENTINEL_CORE_AUTO_TRIGGER_SCANS=false

# FireDog Integration
FIREDOG_ENABLED=true
FIREDOG_BASE_URL=https://firedog.example.com
FIREDOG_API_KEY=fd_key_xxxxxxxxxxxxx
FIREDOG_SYNC_INTERVAL=5  # minutes
FIREDOG_AUTO_BLOCK_HIGH_THREATS=false
FIREDOG_AUTO_ACKNOWLEDGE_HANDLED_THREATS=true
```

---

## API Endpoints (MicroSIEM)

### Integration Management Endpoints

```rust
// GET /api/integrations/status
// Returns status of all integrations

// POST /api/integrations/sentinel-core/sync
// Trigger manual sync with Sentinel Core

// POST /api/integrations/firedog/sync
// Trigger manual sync with FireDog

// GET /api/integrations/correlations
// Get security correlations

// POST /api/integrations/firedog/block-ip
// Block IP in FireDog firewall
{
  "ip_address": "192.168.1.100",
  "reason": "High-risk threat detected",
  "duration_hours": 24
}
```

---

## Summary

### Integration Features

✅ **Sentinel Core**: Vulnerability enrichment, asset sync, CVE details  
✅ **FireDog**: Threat detection, firewall management, statistics  
✅ **Correlation**: Vulnerability + Threat matching, risk scoring  
✅ **Automation**: Auto-blocking, auto-patching suggestions  
✅ **Unified View**: Single dashboard for all security data  

### Data Flow Summary

```
Target → MicroSIEM → Sentinel Core (vulnerabilities)
                   → FireDog (threats)
                   → Correlation Engine
                   → Automated Actions
                   → Alerts
```

---

**Versione**: 1.0.0  
**Data**: 2025-11-28  
**Autore**: Development Team
