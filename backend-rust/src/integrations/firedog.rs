// ============================================================================
// CYBERSHEPPARD - FireDog Integration Client
// ============================================================================

use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Clone)]
pub struct FireDogClient {
    base_url: String,
    api_key: String,
    client: Client,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
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
    pub duration_hours: Option<i32>,
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
