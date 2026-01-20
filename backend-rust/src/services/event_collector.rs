// ============================================================================
// Event Collector Service - Multi-source security event ingestion
// ============================================================================

use anyhow::{Context, Result};
use chrono::Utc;
use serde_json::{json, Value as JsonValue};
use sqlx::PgPool;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::models::security_event::{
    EventCategory, SecurityEvent, Severity, SourceType,
};

/// Event Collector Service
pub struct EventCollectorService {
    db: PgPool,
    auditd_log_path: String,
    enrichment_cache: HashMap<String, AssetEnrichment>,
}

#[derive(Debug, Clone)]
struct AssetEnrichment {
    criticality: i32,
    hostname: String,
    ip: Option<IpAddr>,
}

impl EventCollectorService {
    pub fn new(db: PgPool, auditd_log_path: String) -> Self {
        Self {
            db,
            auditd_log_path,
            enrichment_cache: HashMap::new(),
        }
    }

    /// Start collecting events from auditd/laurel
    pub async fn start_auditd_collection(&mut self) -> Result<()> {
        info!("Starting auditd event collection from {}", self.auditd_log_path);

        // Refresh asset enrichment cache
        self.refresh_enrichment_cache().await?;

        // Read auditd log file (Laurel JSON format)
        let file = File::open(&self.auditd_log_path)
            .await
            .context("Failed to open auditd log file")?;

        let reader = BufReader::new(file);
        let mut lines = reader.lines();

        let mut event_count = 0;
        let mut error_count = 0;

        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }

            match self.process_auditd_line(&line).await {
                Ok(Some(_)) => {
                    event_count += 1;
                    if event_count % 100 == 0 {
                        info!("Processed {} auditd events", event_count);
                    }
                }
                Ok(None) => {
                    // Skipped event (filtered or invalid)
                    debug!("Skipped auditd event");
                }
                Err(e) => {
                    error_count += 1;
                    error!("Failed to process auditd event: {}", e);
                    if error_count > 10 {
                        warn!("Too many errors ({}), continuing...", error_count);
                    }
                }
            }
        }

        info!(
            "Auditd collection completed: {} events processed, {} errors",
            event_count, error_count
        );

        Ok(())
    }

    /// Process a single auditd/laurel log line
    async fn process_auditd_line(&self, line: &str) -> Result<Option<i64>> {
        // Parse Laurel JSON format
        let audit_event: JsonValue = serde_json::from_str(line)
            .context("Failed to parse auditd JSON")?;

        // Extract key fields
        let event_type = audit_event["type"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();

        // Filter out noise events
        if self.should_skip_event(&event_type) {
            return Ok(None);
        }

        // Build SecurityEvent
        let mut event = self.parse_auditd_event(&audit_event)?;

        // Enrich event
        self.enrich_event(&mut event).await?;

        // Normalize to CEF format
        event.normalized_data = Some(self.normalize_to_cef(&event, &audit_event));

        // Insert into database
        let event_id = self.insert_event(&event).await?;

        Ok(Some(event_id))
    }

    /// Parse auditd event into SecurityEvent
    fn parse_auditd_event(&self, audit_event: &JsonValue) -> Result<SecurityEvent> {
        let timestamp = audit_event["time"]
            .as_str()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        let event_type = audit_event["type"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();

        let event_category = self.categorize_audit_event(&event_type);
        let severity = self.determine_severity(&event_type, audit_event);

        let source_host = audit_event["node"]
            .as_str()
            .or_else(|| audit_event["hostname"].as_str())
            .unwrap_or("unknown")
            .to_string();

        // Extract user information
        let user_name = audit_event["uid"]
            .as_str()
            .or_else(|| audit_event["auid"].as_str())
            .map(|s| s.to_string());

        let user_id = audit_event["uid"]
            .as_str()
            .and_then(|s| s.parse::<i32>().ok());

        // Extract process information
        let process_name = audit_event["exe"]
            .as_str()
            .or_else(|| audit_event["comm"].as_str())
            .map(|s| s.to_string());

        let process_pid = audit_event["pid"]
            .as_i64()
            .map(|p| p as i32);

        let process_ppid = audit_event["ppid"]
            .as_i64()
            .map(|p| p as i32);

        let process_cmdline = audit_event["proctitle"]
            .as_str()
            .or_else(|| audit_event["cmdline"].as_str())
            .map(|s| s.to_string());

        // Extract file information
        let file_path = audit_event["name"]
            .as_str()
            .or_else(|| audit_event["path"].as_str())
            .map(|s| s.to_string());

        let file_operation = self.extract_file_operation(audit_event);

        // Extract network information
        let destination_ip = audit_event["addr"]
            .as_str()
            .or_else(|| audit_event["daddr"].as_str())
            .and_then(|s| s.parse::<IpAddr>().ok());

        let destination_port = audit_event["port"]
            .as_i64()
            .map(|p| p as i32);

        Ok(SecurityEvent {
            id: None,
            timestamp,
            source_type: SourceType::Auditd,
            source_host,
            source_ip: None, // Will be enriched
            source_port: None,
            event_type,
            event_category,
            event_action: audit_event["syscall"].as_str().map(|s| s.to_string()),
            severity,
            user_name,
            user_id,
            process_name,
            process_pid,
            process_ppid,
            process_cmdline,
            file_path,
            file_operation,
            destination_ip,
            destination_port,
            destination_host: None,
            protocol: None,
            bytes_sent: None,
            bytes_received: None,
            event_data: Some(audit_event.clone()),
            normalized_data: None,
            geo_country: None,
            geo_city: None,
            asset_criticality: None,
            threat_score: None,
            correlation_id: None,
            parent_event_id: None,
            sequence_number: None,
            ingestion_time: Utc::now(),
            processed: false,
            anomaly_score: None,
        })
    }

    /// Categorize audit event type
    fn categorize_audit_event(&self, event_type: &str) -> EventCategory {
        match event_type {
            "USER_LOGIN" | "USER_LOGOUT" | "USER_AUTH" | "USER_ACCT" => {
                EventCategory::Authentication
            }
            "USER_CMD" | "USER_START" | "USER_END" | "CRED_ACQ" | "CRED_DISP" => {
                EventCategory::Authorization
            }
            "SYSCALL" | "EXECVE" | "PATH" => {
                EventCategory::System
            }
            "SOCKADDR" | "CONNECT" | "BIND" => {
                EventCategory::Network
            }
            _ => EventCategory::System,
        }
    }

    /// Determine event severity
    fn determine_severity(&self, event_type: &str, audit_event: &JsonValue) -> Severity {
        // Check for failure/denied
        let result = audit_event["result"]
            .as_str()
            .or_else(|| audit_event["res"].as_str())
            .unwrap_or("success");

        let is_failure = result.contains("fail") || result.contains("denied");

        match event_type {
            "USER_AUTH" if is_failure => Severity::High,
            "USER_LOGIN" if is_failure => Severity::Medium,
            "SYSCALL" if is_failure => Severity::Low,
            "USER_CMD" => Severity::Info,
            "CRED_ACQ" => Severity::Medium,
            "EXECVE" => {
                // Suspicious commands are high severity
                if let Some(exe) = audit_event["exe"].as_str() {
                    if exe.contains("nc") || exe.contains("ncat") || exe.contains("bash") {
                        return Severity::High;
                    }
                }
                Severity::Info
            }
            _ => Severity::Info,
        }
    }

    /// Extract file operation from audit event
    fn extract_file_operation(&self, audit_event: &JsonValue) -> Option<String> {
        if let Some(syscall) = audit_event["syscall"].as_str() {
            return Some(match syscall {
                "open" | "openat" => "read",
                "write" | "writev" => "write",
                "execve" | "execveat" => "execute",
                "unlink" | "unlinkat" | "rmdir" => "delete",
                _ => "unknown",
            }.to_string());
        }
        None
    }

    /// Check if event should be skipped (noise reduction)
    fn should_skip_event(&self, event_type: &str) -> bool {
        matches!(
            event_type,
            "CONFIG_CHANGE"
                | "DAEMON_START"
                | "DAEMON_END"
                | "SERVICE_START"
                | "SERVICE_STOP"
        )
    }

    /// Enrich event with asset information
    async fn enrich_event(&self, event: &mut SecurityEvent) -> Result<()> {
        // Lookup asset in cache
        if let Some(asset) = self.enrichment_cache.get(&event.source_host) {
            event.asset_criticality = Some(asset.criticality);
            event.source_ip = asset.ip;
        }

        // Geo-IP enrichment (placeholder - would use MaxMind GeoIP2)
        if let Some(ip) = event.destination_ip {
            event.geo_country = self.lookup_geo_country(ip);
            event.geo_city = self.lookup_geo_city(ip);
        }

        Ok(())
    }

    /// Normalize event to CEF (Common Event Format)
    fn normalize_to_cef(&self, event: &SecurityEvent, raw: &JsonValue) -> JsonValue {
        // CEF Format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        json!({
            "cef_version": 0,
            "device_vendor": "CyberSheppard",
            "device_product": "Security Event Collector",
            "device_version": "1.0",
            "signature_id": event.event_type,
            "name": format!("{:?} event on {}", event.event_category, event.source_host),
            "severity": format!("{:?}", event.severity),
            "extensions": {
                "src": event.source_host,
                "suser": event.user_name,
                "dhost": event.destination_host,
                "daddr": event.destination_ip.map(|ip| ip.to_string()),
                "fname": event.file_path,
                "act": event.event_action,
                "outcome": raw["result"].as_str().unwrap_or("unknown"),
                "cs1": event.process_name,
                "cs1Label": "ProcessName",
                "cn1": event.process_pid,
                "cn1Label": "ProcessPID"
            }
        })
    }

    /// Refresh asset enrichment cache from database
    async fn refresh_enrichment_cache(&mut self) -> Result<()> {
        let assets = sqlx::query!(
            r#"
            SELECT
                COALESCE(hostname, ip_address::TEXT, name) as hostname,
                ip_address,
                5 as criticality
            FROM targets
            WHERE status = 'active'
            "#
        )
        .fetch_all(&self.db)
        .await?;

        self.enrichment_cache.clear();

        for asset in assets {
            let hostname = asset.hostname.unwrap_or_else(|| "unknown".to_string());
            let ip = asset.ip_address.and_then(|ip_str| ip_str.parse::<IpAddr>().ok());

            self.enrichment_cache.insert(
                hostname.clone(),
                AssetEnrichment {
                    criticality: asset.criticality.unwrap_or(5),
                    hostname,
                    ip,
                },
            );
        }

        info!("Refreshed enrichment cache: {} assets", self.enrichment_cache.len());
        Ok(())
    }

    /// Insert event into database
    async fn insert_event(&self, event: &SecurityEvent) -> Result<i64> {
        let event_id = sqlx::query_scalar!(
            r#"
            INSERT INTO security_events (
                timestamp, source_type, source_host, source_ip, source_port,
                event_type, event_category, event_action, severity,
                user_name, user_id, process_name, process_pid, process_ppid, process_cmdline,
                file_path, file_operation,
                destination_ip, destination_port, destination_host, protocol,
                bytes_sent, bytes_received,
                event_data, normalized_data,
                geo_country, geo_city, asset_criticality, threat_score,
                correlation_id, parent_event_id, sequence_number,
                ingestion_time, processed, anomaly_score
            ) VALUES (
                $1, $2, $3, $4, $5,
                $6, $7, $8, $9,
                $10, $11, $12, $13, $14, $15,
                $16, $17,
                $18, $19, $20, $21,
                $22, $23,
                $24, $25,
                $26, $27, $28, $29,
                $30, $31, $32,
                $33, $34, $35
            )
            RETURNING id
            "#,
            event.timestamp,
            event.source_type.to_string(),
            event.source_host,
            event.source_ip as Option<IpAddr>,
            event.source_port,
            event.event_type,
            event.event_category.to_string(),
            event.event_action,
            event.severity.to_string(),
            event.user_name,
            event.user_id,
            event.process_name,
            event.process_pid,
            event.process_ppid,
            event.process_cmdline,
            event.file_path,
            event.file_operation,
            event.destination_ip as Option<IpAddr>,
            event.destination_port,
            event.destination_host,
            event.protocol,
            event.bytes_sent,
            event.bytes_received,
            event.event_data,
            event.normalized_data,
            event.geo_country,
            event.geo_city,
            event.asset_criticality,
            event.threat_score,
            event.correlation_id,
            event.parent_event_id,
            event.sequence_number,
            event.ingestion_time,
            event.processed,
            event.anomaly_score
        )
        .fetch_one(&self.db)
        .await?;

        Ok(event_id)
    }

    /// Geo-IP lookup (placeholder)
    fn lookup_geo_country(&self, _ip: IpAddr) -> Option<String> {
        // TODO: Integrate MaxMind GeoIP2 database
        None
    }

    /// Geo-IP city lookup (placeholder)
    fn lookup_geo_city(&self, _ip: IpAddr) -> Option<String> {
        // TODO: Integrate MaxMind GeoIP2 database
        None
    }

    /// Get recent events for analysis
    pub async fn get_recent_events(
        &self,
        hours: i32,
        limit: i64,
    ) -> Result<Vec<SecurityEvent>> {
        let events = sqlx::query_as!(
            SecurityEvent,
            r#"
            SELECT
                id, timestamp, source_type as "source_type: _", source_host,
                source_ip as "source_ip: IpAddr", source_port,
                event_type, event_category as "event_category: _",
                event_action, severity as "severity: _",
                user_name, user_id, process_name, process_pid, process_ppid, process_cmdline,
                file_path, file_operation,
                destination_ip as "destination_ip: IpAddr", destination_port,
                destination_host, protocol, bytes_sent, bytes_received,
                event_data, normalized_data,
                geo_country, geo_city, asset_criticality, threat_score,
                correlation_id, parent_event_id, sequence_number,
                ingestion_time, processed, anomaly_score
            FROM security_events
            WHERE timestamp > NOW() - INTERVAL '1 hour' * $1
            ORDER BY timestamp DESC
            LIMIT $2
            "#,
            hours,
            limit
        )
        .fetch_all(&self.db)
        .await?;

        Ok(events)
    }

    /// Get event count by severity
    pub async fn get_severity_stats(&self, hours: i32) -> Result<HashMap<String, i64>> {
        let rows = sqlx::query!(
            r#"
            SELECT severity, COUNT(*) as count
            FROM security_events
            WHERE timestamp > NOW() - INTERVAL '1 hour' * $1
            GROUP BY severity
            "#,
            hours
        )
        .fetch_all(&self.db)
        .await?;

        let mut stats = HashMap::new();
        for row in rows {
            stats.insert(row.severity, row.count.unwrap_or(0));
        }

        Ok(stats)
    }
}
