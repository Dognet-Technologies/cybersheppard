// ============================================================================
// Event Collector Service - Multi-source security event ingestion
// ============================================================================

use anyhow::{Context, Result};
use chrono::Utc;
use serde_json::{json, Value as JsonValue};
use sqlx::PgPool;
use std::collections::HashMap;
use std::net::IpAddr;

use crate::utils::ToBigDecimal;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing::{debug, error, info, warn};

use crate::security_event::{
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

/// Mappa un evento auditd sulla tattica/tecnica MITRE ATT&CK **solo quando è
/// intrinsecamente rilevante per la sicurezza**. Principio: ciò che mappa su
/// MITRE è già un evento di sicurezza; ciò che non mappa nasce come evento
/// grezzo (`mitre_tactic = NULL`) e va **sorvegliato** dal motore di
/// correlazione, che può elevarlo (per frequenza o sequenza) a evento di
/// sicurezza. Perciò la mappa è **conservativa**: attività normale (login
/// valido, sudo/execve/connect ordinari) resta NON mappata.
///
/// Speculare al seed di `mitre_attack_map` (migr. 015).
/// TODO: caricare la mappa dalla tabella per estenderla senza ricompilare, e
/// spostare i pattern contestuali (es. execve → shell uid=0) nel correlatore.
fn map_mitre_attack(
    event_type: &str,
    _event_category: &EventCategory,
    is_failure: bool,
) -> (Option<String>, Option<String>) {
    // Solo eventi intrinsecamente sospetti. Il resto → (None, None) = grezzo.
    let mapped: Option<(&str, &str)> = match (event_type, is_failure) {
        // Autenticazione FALLITA: sospetta di per sé (candidata brute force).
        ("USER_AUTH", true) | ("USER_LOGIN", true) => Some(("credential_access", "T1110")),
        // Acquisizione credenziali: sempre notevole.
        ("CRED_ACQ", _) => Some(("credential_access", "T1003")),
        // Un login/auth RIUSCITO è attività normale: NON mappa (lo elevano i
        // pattern di correlazione, es. molti login in poco tempo).
        _ => None,
    };

    match mapped {
        Some((tactic, technique)) => (Some(tactic.to_string()), Some(technique.to_string())),
        None => (None, None),
    }
}

/// Laurel (0.8.x) produce JSON **annidato**: un oggetto con `ID` (`epoch.ms:serial`)
/// e i record auditd come chiavi maiuscole (`SYSCALL`, `EXECVE`, `PROCTITLE`,
/// `PATH`, `SOCKADDR`, `USER_AUTH`, `CRED_ACQ`…). Il parser `parse_auditd_event`
/// si aspetta invece un evento auditd **piatto** (`type`, `time`, `uid`, `exe`,
/// `pid`…). Senza normalizzazione ogni evento Laurel diventa `system/unknown`
/// con tutti i campi NULL, e i detector di correlazione non scattano mai.
///
/// Questa funzione riconosce il formato Laurel e lo appiattisce nei campi che il
/// parser **e** i detector leggono (`type`, `time`, `uid`/`auid`, `exe`/`comm`,
/// `pid`/`ppid`, `proctitle`, `key`, `res`, `name`, `addr`/`port`, `hostname`,
/// `ses`). Ritorna `None` se `ev` non è nel formato Laurel, così il flusso auditd
/// piatto pre-esistente resta invariato.
fn normalize_laurel(ev: &JsonValue) -> Option<JsonValue> {
    let obj = ev.as_object()?;
    // Firma del formato Laurel: presenza di `ID` e assenza del `type` piatto.
    let id = obj.get("ID")?.as_str()?;
    if obj.contains_key("type") {
        return None;
    }

    let mut flat = serde_json::Map::new();

    // timestamp da ID "1788220826.251:555" → RFC3339
    if let Some(epoch) = id.split(':').next().and_then(|s| s.parse::<f64>().ok()) {
        let secs = epoch.trunc() as i64;
        let nsecs = (epoch.fract() * 1_000_000_000.0) as u32;
        if let Some(dt) = chrono::DateTime::from_timestamp(secs, nsecs) {
            flat.insert("time".into(), json!(dt.to_rfc3339()));
        }
    }

    // Un record Laurel può essere oggetto o array (primo elemento).
    let rec = |v: &JsonValue| -> Option<JsonValue> {
        match v {
            JsonValue::Object(_) => Some(v.clone()),
            JsonValue::Array(a) => a.first().cloned(),
            _ => None,
        }
    };

    // 1) Eventi syscall / execve
    if let Some(sc) = obj.get("SYSCALL").and_then(rec) {
        if let Some(scm) = sc.as_object() {
            let mnem = scm.get("SYSCALL").and_then(|v| v.as_str()).unwrap_or("");
            let is_exec =
                mnem == "execve" || mnem == "execveat" || obj.contains_key("EXECVE");
            flat.insert(
                "type".into(),
                json!(if is_exec { "EXECVE" } else { "SYSCALL" }),
            );
            // Identità: nome tradotto (UID) per user_name; auid numerico per i detector.
            if let Some(u) = scm.get("UID").and_then(|v| v.as_str()) {
                flat.insert("uid".into(), json!(u));
            }
            if let Some(a) = scm.get("auid") {
                flat.insert("auid".into(), a.clone());
            }
            if let Some(a) = scm.get("AUID") {
                flat.insert("auid_name".into(), a.clone());
            }
            for k in ["pid", "ppid", "ses", "comm", "exe", "subj"] {
                if let Some(v) = scm.get(k) {
                    flat.insert(k.into(), v.clone());
                }
            }
            flat.insert("syscall".into(), json!(mnem));
            if let Some(k) = scm.get("key") {
                if !k.is_null() {
                    flat.insert("key".into(), k.clone());
                }
            }
            let ok = scm
                .get("success")
                .and_then(|v| v.as_str())
                .map(|s| s == "yes")
                .unwrap_or(true);
            flat.insert("res".into(), json!(if ok { "success" } else { "failed" }));
        }
    }

    // 2) cmdline: da EXECVE.ARGV (argv completo) o, in fallback, da PROCTITLE.
    if let Some(ex) = obj.get("EXECVE").and_then(rec) {
        if let Some(argv) = ex.get("ARGV").and_then(|v| v.as_array()) {
            let cmd = argv
                .iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            if !cmd.is_empty() {
                flat.insert("proctitle".into(), json!(cmd));
            }
        }
    }
    if !flat.contains_key("proctitle") {
        if let Some(pt) = obj.get("PROCTITLE").and_then(rec) {
            if let Some(s) = pt
                .get("ARGV_STR")
                .and_then(|v| v.as_str())
                .or_else(|| pt.get("proctitle").and_then(|v| v.as_str()))
            {
                flat.insert("proctitle".into(), json!(s));
            }
        }
    }

    // 3) file: primo PATH con `name`.
    if let Some(paths) = obj.get("PATH").and_then(|v| v.as_array()) {
        if let Some(name) = paths
            .iter()
            .find_map(|p| p.get("name").and_then(|v| v.as_str()))
        {
            flat.insert("name".into(), json!(name));
        }
    }

    // 4) rete: SOCKADDR.
    if let Some(sa) = obj.get("SOCKADDR").and_then(rec) {
        if let Some(addr) = sa.get("addr").and_then(|v| v.as_str()) {
            flat.insert("addr".into(), json!(addr));
        }
        if let Some(port) = sa.get("port") {
            flat.insert("port".into(), port.clone());
        }
    }

    // 5) record di autenticazione/autorizzazione PAM.
    for rt in [
        "USER_AUTH", "USER_LOGIN", "USER_ACCT", "CRED_ACQ", "CRED_DISP", "USER_START",
        "USER_END", "USER_CMD", "USER_ERR", "LOGIN",
    ] {
        if let Some(r) = obj.get(rt).and_then(rec) {
            if let Some(ro) = r.as_object() {
                flat.insert("type".into(), json!(rt));
                for k in ["pid", "auid", "ses", "uid"] {
                    if let Some(v) = ro.get(k) {
                        flat.entry(k.to_string()).or_insert_with(|| v.clone());
                    }
                }
                if let Some(u) = ro
                    .get("UID")
                    .and_then(|v| v.as_str())
                    .or_else(|| ro.get("AUID").and_then(|v| v.as_str()))
                {
                    flat.insert("uid".into(), json!(u));
                }
                if let Some(msg) = ro.get("msg").and_then(|v| v.as_object()) {
                    for k in ["op", "acct", "hostname", "addr", "terminal", "exe", "res"] {
                        if let Some(v) = msg.get(k) {
                            flat.insert(k.into(), v.clone());
                        }
                    }
                }
            }
            break; // un solo record auth per evento
        }
    }

    // hostname/node del target (se presente).
    if let Some(h) = obj.get("NODE").and_then(|v| v.as_str()) {
        flat.insert("node".into(), json!(h));
    }

    // Conserva l'evento Laurel originale per riferimento/debug.
    flat.insert("laurel_raw".into(), ev.clone());

    Some(JsonValue::Object(flat))
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

    /// Process a single auditd/laurel log line (parse JSON then delegate).
    async fn process_auditd_line(&self, line: &str) -> Result<Option<i64>> {
        let audit_event: JsonValue =
            serde_json::from_str(line).context("Failed to parse auditd JSON")?;
        self.ingest_event(&audit_event, None).await
    }

    /// Ingest one already-parsed Laurel/auditd event into `security_events`.
    /// Public entry point for the agent-forwarded events path (`api/agents.rs`):
    /// filtro rumore → parse (con tagging MITRE) → enrich → normalize → insert.
    pub async fn ingest_event(
        &self,
        audit_event: &JsonValue,
        target_id: Option<i32>,
    ) -> Result<Option<i64>> {
        // Gli eventi inoltrati dall'agent arrivano nel formato annidato di Laurel:
        // appiattiscili nel formato piatto che il parser e i detector si aspettano.
        // Se non è formato Laurel (es. auditd grezzo), `normalized` è None e si usa
        // l'evento originale invariato.
        let normalized = normalize_laurel(audit_event);
        let event = normalized.as_ref().unwrap_or(audit_event);

        let event_type = event["type"].as_str().unwrap_or("unknown").to_string();

        if self.should_skip_event(&event_type) {
            return Ok(None);
        }

        let mut event = self.parse_auditd_event(event)?;
        event.target_id = target_id;
        self.enrich_event(&mut event).await?;
        event.normalized_data = Some(self.normalize_to_cef(&event, audit_event));
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

        // MITRE ATT&CK tagging (tattica + tecnica). is_failure distingue, es.,
        // brute force (credential_access) da valid accounts (initial_access).
        let result = audit_event["result"]
            .as_str()
            .or_else(|| audit_event["res"].as_str())
            .unwrap_or("success");
        let is_failure = result.contains("fail") || result.contains("denied");
        let (mitre_tactic, mitre_technique) =
            map_mitre_attack(&event_type, &event_category, is_failure);

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
            target_id: None,
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
            mitre_tactic,
            mitre_technique,
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

        // L'enrichment geo/IOC (GeoIP, threat-intel) è competenza del modulo
        // premium **Intellidog**, non del core: qui `geo_*` resta NULL.

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
                COALESCE(hostname, ip_address::TEXT) as hostname,
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
            let ip = Some(asset.ip_address.ip());

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
                ingestion_time, processed, anomaly_score,
                mitre_tactic, mitre_technique, target_id
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
                $33, $34, $35,
                $36, $37, $38
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
            event.threat_score.map(|v| v.to_bigdecimal()),
            event.correlation_id,
            event.parent_event_id,
            event.sequence_number,
            event.ingestion_time,
            event.processed,
            event.anomaly_score.map(|v| v.to_bigdecimal()),
            event.mitre_tactic,
            event.mitre_technique,
            event.target_id
        )
        .fetch_one(&self.db)
        .await?;

        Ok(event_id)
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
                id, target_id, timestamp, source_type as "source_type: _", source_host,
                source_ip as "source_ip: IpAddr", source_port,
                event_type, event_category as "event_category: _",
                event_action, severity as "severity: _",
                user_name, user_id, process_name, process_pid, process_ppid, process_cmdline,
                file_path, file_operation,
                destination_ip as "destination_ip: IpAddr", destination_port,
                destination_host, protocol, bytes_sent, bytes_received,
                event_data, normalized_data,
                geo_country, geo_city, asset_criticality,
                threat_score::float8 as "threat_score?",
                mitre_tactic, mitre_technique,
                correlation_id, parent_event_id, sequence_number,
                COALESCE(ingestion_time, NOW()) as "ingestion_time!",
                COALESCE(processed, false) as "processed!",
                anomaly_score::float8 as "anomaly_score?"
            FROM security_events
            WHERE timestamp > NOW() - INTERVAL '1 hour' * $1
            ORDER BY timestamp DESC
            LIMIT $2
            "#,
            hours as f64,
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
            hours as f64
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_auth_is_intrinsic_security_event_credential_access() {
        let (tac, tech) = map_mitre_attack("USER_AUTH", &EventCategory::Authentication, true);
        assert_eq!(tac.as_deref(), Some("credential_access"));
        assert_eq!(tech.as_deref(), Some("T1110"));
    }

    #[test]
    fn credential_acquisition_maps_to_credential_access() {
        let (tac, tech) = map_mitre_attack("CRED_ACQ", &EventCategory::Authorization, false);
        assert_eq!(tac.as_deref(), Some("credential_access"));
        assert_eq!(tech.as_deref(), Some("T1003"));
    }

    // Attività NORMALE: non mappa (resta grezza, la eleva la correlazione).
    #[test]
    fn successful_login_is_raw_not_a_security_event() {
        let (tac, tech) = map_mitre_attack("USER_LOGIN", &EventCategory::Authentication, false);
        assert!(tac.is_none());
        assert!(tech.is_none());
    }

    #[test]
    fn ordinary_sudo_and_exec_are_raw() {
        assert!(map_mitre_attack("USER_CMD", &EventCategory::Authorization, false).0.is_none());
        assert!(map_mitre_attack("EXECVE", &EventCategory::System, false).0.is_none());
        assert!(map_mitre_attack("CONNECT", &EventCategory::Network, false).0.is_none());
    }

    #[test]
    fn unknown_type_is_raw() {
        let (tac, tech) = map_mitre_attack("WEIRD_TYPE", &EventCategory::System, false);
        assert!(tac.is_none());
        assert!(tech.is_none());
    }
}
