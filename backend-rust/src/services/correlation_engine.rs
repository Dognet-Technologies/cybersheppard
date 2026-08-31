// ============================================================================
// Correlation Engine - Advanced Event Correlation & Pattern Detection
// ============================================================================

use anyhow::Result;
use chrono::Utc;
use ipnetwork::IpNetwork;
use serde_json::json;
use sqlx::PgPool;
use std::collections::HashMap;

use crate::utils::{BigDecimalExt, ToBigDecimal};
use tracing::info;
use uuid::Uuid;

use crate::security_event::{
    AttackStage, CorrelationStatus, CorrelationType, EventCorrelation, Severity,
};

/// Correlation Engine - Detects attack patterns and sequences
pub struct CorrelationEngine {
    db: PgPool,
    // Configurable thresholds
    failed_login_threshold: i32,
    lateral_movement_window_minutes: i32,
    sequence_window_minutes: i32,
}

/// Tecnica difensiva MITRE **D3FEND** che mitiga una data tattica ATT&CK
/// (cross-link con la mappatura compliance della suite — vedi
/// `documentazione/Host_Compliance_Framework_Mapping`). Usata per indicare
/// "quale controllo avrebbe fermato questa minaccia".
/// TODO: derivare dal controllo compliance specifico invece che dalla tattica.
fn d3fend_for_tactic(tactic: &str) -> Option<&'static str> {
    match tactic {
        "credential_access" | "initial_access" => Some("D3-MFA"), // Multi-factor Authentication
        "privilege_escalation" => Some("D3-PA"),                  // Process Analysis
        "execution" => Some("D3-PSEP"),                           // Process Segment Exec. Prevention
        "persistence" => Some("D3-FIM"),                          // File Integrity Monitoring
        "lateral_movement" => Some("D3-NTF"),                     // Network Traffic Filtering
        "command_and_control" | "exfiltration" => Some("D3-OTF"), // Outbound Traffic Filtering
        "defense_evasion" => Some("D3-FIM"),                      // File Integrity Monitoring (log tamper)
        "discovery" => Some("D3-PA"),                             // Process Analysis
        "impact" => Some("D3-FIM"),                               // File Integrity Monitoring
        _ => None,
    }
}

/// Tecnica MITRE ATT&CK (T-code + nome) associata a ogni regola di correlazione.
/// Completa la mappatura a livello di **tecnica** (oltre alla tattica
/// `attack_stage`): ogni minaccia elevata porta la sua tecnica precisa.
fn technique_for_pattern(pattern: &str) -> Option<(&'static str, &'static str)> {
    match pattern {
        "Brute Force Attack" => Some(("T1110", "Brute Force")),
        "Lateral Movement Detected" => Some(("T1021", "Remote Services")),
        "Privilege Escalation Attempt" | "Privilege Escalation (auid)" => {
            Some(("T1548", "Abuse Elevation Control Mechanism"))
        }
        "Potential Data Exfiltration" => Some(("T1041", "Exfiltration Over C2 Channel")),
        "Suspicious Process Execution" => Some(("T1059", "Command and Scripting Interpreter")),
        "C2 Beaconing" => Some(("T1071", "Application Layer Protocol")),
        "Persistence Mechanism" => Some(("T1547", "Boot or Logon Autostart Execution")),
        "Credential File Access" => Some(("T1003", "OS Credential Dumping")),
        "Discovery Burst" => Some(("T1082", "System Information Discovery")),
        "Defense Evasion" => Some(("T1070", "Indicator Removal")),
        "Suspicious Session Lifecycle" => Some(("T1078", "Valid Accounts")),
        "Mass File Operations" => Some(("T1486", "Data Encrypted for Impact")),
        _ => None, // es. "Anomaly Cluster": nessuna tecnica ATT&CK fissa
    }
}

impl CorrelationEngine {
    pub fn new(db: PgPool) -> Self {
        Self {
            db,
            failed_login_threshold: 5,
            lateral_movement_window_minutes: 60,
            sequence_window_minutes: 30,
        }
    }

    /// Run correlation analysis on recent events
    pub async fn analyze_correlations(&self, hours: i32) -> Result<Vec<EventCorrelation>> {
        info!("Starting correlation analysis for last {} hours", hours);

        let mut correlations = Vec::new();

        // 1. Detect brute force attacks (failed logins)
        let brute_force = self.detect_brute_force_attacks(hours).await?;
        correlations.extend(brute_force);
        info!("Detected {} brute force patterns", correlations.len());

        // 2. Detect lateral movement patterns
        let lateral = self.detect_lateral_movement(hours).await?;
        correlations.extend(lateral);
        info!("Detected {} lateral movement patterns", correlations.len());

        // 3. Detect privilege escalation attempts
        let privesc = self.detect_privilege_escalation(hours).await?;
        correlations.extend(privesc);
        info!("Detected {} privilege escalation patterns", correlations.len());

        // 4. Detect data exfiltration patterns
        let exfil = self.detect_data_exfiltration(hours).await?;
        correlations.extend(exfil);
        info!("Detected {} data exfiltration patterns", correlations.len());

        // 5. Detect anomaly clusters (high anomaly scores)
        let anomaly_clusters = self.detect_anomaly_clusters(hours).await?;
        correlations.extend(anomaly_clusters);

        // 6..N. Scuderia estesa — vedi docs/CORRELATION_RULES.md
        correlations.extend(self.detect_suspicious_process(hours).await?); // R6
        correlations.extend(self.detect_auid_privesc(hours).await?); // R7
        correlations.extend(self.detect_beaconing(hours).await?); // R9
        correlations.extend(self.detect_persistence(hours).await?); // R11
        correlations.extend(self.detect_credential_file_access(hours).await?); // R12
        correlations.extend(self.detect_discovery_burst(hours).await?); // R13
        correlations.extend(self.detect_defense_evasion(hours).await?); // R14
        correlations.extend(self.detect_suspicious_session(hours).await?); // R8
        correlations.extend(self.detect_mass_file_ops(hours).await?); // R15

        info!("Total correlations detected: {}", correlations.len());

        // Persist correlations to database
        for correlation in &correlations {
            self.save_correlation(correlation).await?;
        }

        Ok(correlations)
    }

    /// Detect brute force attack patterns
    /// Pattern: Multiple failed logins from same source to same user
    async fn detect_brute_force_attacks(&self, hours: i32) -> Result<Vec<EventCorrelation>> {
        let rows = sqlx::query!(
            r#"
            SELECT
                user_name,
                source_host,
                source_ip,
                COUNT(*) as failed_count,
                MIN(timestamp) as first_attempt,
                MAX(timestamp) as last_attempt,
                array_agg(DISTINCT event_type) as event_types
            FROM security_events
            WHERE event_category = 'authentication'
              AND severity IN ('high', 'medium')
              AND timestamp > NOW() - INTERVAL '1 hour' * $1
              AND (
                  event_data->>'result' LIKE '%fail%'
                  OR event_data->>'res' LIKE '%fail%'
              )
            GROUP BY user_name, source_host, source_ip
            HAVING COUNT(*) >= $2
            "#,
            hours as f64,
            self.failed_login_threshold as i64
        )
        .fetch_all(&self.db)
        .await?;

        let mut correlations = Vec::new();

        for row in rows {
            let failed_count = row.failed_count.unwrap_or(0);
            let confidence = Self::calculate_confidence(failed_count, 5, 20);
            let risk_score = Self::calculate_risk_score(failed_count as f64, 5.0, 20.0);

            let severity = if failed_count > 15 {
                Severity::Critical
            } else if failed_count > 10 {
                Severity::High
            } else {
                Severity::Medium
            };

            let user_name = row.user_name.unwrap_or_else(|| "unknown".to_string());
            let source_ip_str = row.source_ip.map(|ip| ip.ip().to_string());

            let correlation = EventCorrelation {
                id: Uuid::new_v4(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
                correlation_type: CorrelationType::Frequency,
                pattern_name: Some("Brute Force Attack".to_string()),
                pattern_description: Some(format!(
                    "{} failed login attempts for user '{}' from {}",
                    failed_count,
                    user_name,
                    source_ip_str.as_ref().unwrap_or(&row.source_host)
                )),
                confidence,
                severity,
                risk_score: Some(risk_score),
                first_event_time: row.first_attempt.unwrap(),
                last_event_time: row.last_attempt.unwrap(),
                time_window_seconds: Some(
                    (row.last_attempt.unwrap() - row.first_attempt.unwrap())
                        .num_seconds() as i32,
                ),
                event_count: failed_count as i32,
                involved_users: vec![user_name.clone()],
                involved_hosts: vec![row.source_host.clone()],
                involved_ips: row.source_ip.map(|ip| ip.ip()).into_iter().collect(),
                involved_processes: vec![],
                statistical_significance: None,
                anomaly_score: Some(risk_score),
                z_score: None,
                baseline_deviation_percent: None,
                correlation_data: Some(json!({
                    "failed_attempts": failed_count,
                    "event_types": row.event_types,
                    "target_user": user_name,
                    "source": source_ip_str.unwrap_or_else(|| row.source_host.clone()),
                })),
                // Brute force = credential_access (TA0006), non initial_access.
                attack_stage: Some(AttackStage::CredentialAccess),
                status: CorrelationStatus::Active,
                resolved_at: None,
                resolution_notes: None,
                assigned_to: None,
                assigned_at: None,
            };

            correlations.push(correlation);
        }

        Ok(correlations)
    }

    /// Detect lateral movement patterns
    /// Pattern: Successful login on host A → Network connection to host B → Login on host B
    async fn detect_lateral_movement(&self, hours: i32) -> Result<Vec<EventCorrelation>> {
        // Query for authentication sequences across hosts
        let rows = sqlx::query!(
            r#"
            WITH auth_events AS (
                SELECT
                    user_name,
                    source_host,
                    destination_host,
                    timestamp,
                    event_type
                FROM security_events
                WHERE timestamp > NOW() - INTERVAL '1 hour' * $1
                  AND event_category IN ('authentication', 'network')
                  AND user_name IS NOT NULL
            ),
            host_sequences AS (
                SELECT
                    a1.user_name,
                    a1.source_host as host1,
                    a2.source_host as host2,
                    a1.timestamp as first_time,
                    a2.timestamp as second_time,
                    EXTRACT(EPOCH FROM (a2.timestamp - a1.timestamp)) / 60 as time_diff_minutes
                FROM auth_events a1
                JOIN auth_events a2 ON a1.user_name = a2.user_name
                WHERE a1.source_host != a2.source_host
                  AND a2.timestamp > a1.timestamp
                  AND a2.timestamp <= a1.timestamp + INTERVAL '1 hour'
            )
            SELECT
                user_name,
                host1,
                host2,
                first_time,
                second_time,
                time_diff_minutes,
                COUNT(*) as sequence_count
            FROM host_sequences
            GROUP BY user_name, host1, host2, first_time, second_time, time_diff_minutes
            HAVING COUNT(*) >= 2
            ORDER BY sequence_count DESC
            LIMIT 50
            "#,
            hours as f64
        )
        .fetch_all(&self.db)
        .await?;

        let mut correlations = Vec::new();

        for row in rows {
            let user_name = row.user_name.unwrap_or_else(|| "unknown".to_string());
            let time_diff = row.time_diff_minutes.to_f64();
            let host1 = row.host1.clone();
            let host2 = row.host2.clone();

            // Suspicious if lateral movement is very quick (< 5 minutes)
            let is_suspicious = time_diff < 5.0;
            let confidence = if is_suspicious { 0.85 } else { 0.60 };

            let severity = if is_suspicious {
                Severity::High
            } else {
                Severity::Medium
            };

            let correlation = EventCorrelation {
                id: Uuid::new_v4(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
                correlation_type: CorrelationType::LateralMovement,
                pattern_name: Some("Lateral Movement Detected".to_string()),
                pattern_description: Some(format!(
                    "User '{}' moved from {} to {} in {:.1} minutes",
                    user_name, host1, host2, time_diff
                )),
                confidence,
                severity,
                risk_score: Some(if is_suspicious { 85.0 } else { 60.0 }),
                first_event_time: row.first_time,
                last_event_time: row.second_time,
                time_window_seconds: Some((time_diff * 60.0) as i32),
                event_count: row.sequence_count.unwrap_or(0) as i32,
                involved_users: vec![user_name.clone()],
                involved_hosts: vec![host1, host2],
                involved_ips: vec![],
                involved_processes: vec![],
                statistical_significance: None,
                anomaly_score: None,
                z_score: None,
                baseline_deviation_percent: None,
                correlation_data: Some(json!({
                    "lateral_movement": {
                        "from_host": row.host1,
                        "to_host": row.host2,
                        "time_minutes": time_diff,
                        "is_suspicious": is_suspicious,
                        "sequence_count": row.sequence_count
                    }
                })),
                attack_stage: Some(AttackStage::LateralMovement),
                status: CorrelationStatus::Active,
                resolved_at: None,
                resolution_notes: None,
                assigned_to: None,
                assigned_at: None,
            };

            correlations.push(correlation);
        }

        Ok(correlations)
    }

    /// Detect privilege escalation attempts
    /// Pattern: Normal user → sudo/su commands → root access
    async fn detect_privilege_escalation(&self, hours: i32) -> Result<Vec<EventCorrelation>> {
        let rows = sqlx::query!(
            r#"
            SELECT
                user_name,
                source_host,
                COUNT(*) as escalation_count,
                MIN(timestamp) as first_attempt,
                MAX(timestamp) as last_attempt,
                array_agg(DISTINCT process_name) FILTER (WHERE process_name IS NOT NULL) as processes,
                array_agg(DISTINCT process_cmdline) FILTER (WHERE process_cmdline IS NOT NULL) as commands
            FROM security_events
            WHERE timestamp > NOW() - INTERVAL '1 hour' * $1
              AND (
                  process_name LIKE '%sudo%'
                  OR process_name LIKE '%su%'
                  OR process_cmdline LIKE '%sudo%'
                  OR process_cmdline LIKE '%su %'
                  OR event_data->>'uid' = '0'
              )
              AND user_name IS NOT NULL
              AND user_name != 'root'
            GROUP BY user_name, source_host
            HAVING COUNT(*) >= 3
            "#,
            hours as f64
        )
        .fetch_all(&self.db)
        .await?;

        let mut correlations = Vec::new();

        for row in rows {
            let user_name = row.user_name.unwrap_or_else(|| "unknown".to_string());
            let escalation_count = row.escalation_count.unwrap_or(0);

            let confidence = Self::calculate_confidence(escalation_count, 3, 10);
            let risk_score = Self::calculate_risk_score(escalation_count as f64, 3.0, 10.0);

            let severity = if escalation_count > 7 {
                Severity::Critical
            } else if escalation_count > 5 {
                Severity::High
            } else {
                Severity::Medium
            };

            let correlation = EventCorrelation {
                id: Uuid::new_v4(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
                correlation_type: CorrelationType::Sequence,
                pattern_name: Some("Privilege Escalation Attempt".to_string()),
                pattern_description: Some(format!(
                    "User '{}' attempted privilege escalation {} times on {}",
                    user_name, escalation_count, row.source_host
                )),
                confidence,
                severity,
                risk_score: Some(risk_score),
                first_event_time: row.first_attempt.unwrap(),
                last_event_time: row.last_attempt.unwrap(),
                time_window_seconds: Some(
                    (row.last_attempt.unwrap() - row.first_attempt.unwrap())
                        .num_seconds() as i32,
                ),
                event_count: escalation_count as i32,
                involved_users: vec![user_name.clone()],
                involved_hosts: vec![row.source_host.clone()],
                involved_ips: vec![],
                involved_processes: row.processes.unwrap_or_default(),
                statistical_significance: None,
                anomaly_score: Some(risk_score),
                z_score: None,
                baseline_deviation_percent: None,
                correlation_data: Some(json!({
                    "escalation_attempts": escalation_count,
                    "commands": row.commands,
                })),
                attack_stage: Some(AttackStage::PrivilegeEscalation),
                status: CorrelationStatus::Active,
                resolved_at: None,
                resolution_notes: None,
                assigned_to: None,
                assigned_at: None,
            };

            correlations.push(correlation);
        }

        Ok(correlations)
    }

    /// Detect data exfiltration patterns
    /// Pattern: Large data transfers to external IPs
    async fn detect_data_exfiltration(&self, hours: i32) -> Result<Vec<EventCorrelation>> {
        let rows = sqlx::query!(
            r#"
            SELECT
                user_name,
                source_host,
                destination_ip,
                COUNT(*) as transfer_count,
                SUM(bytes_sent) as total_bytes,
                MIN(timestamp) as first_transfer,
                MAX(timestamp) as last_transfer
            FROM security_events
            WHERE timestamp > NOW() - INTERVAL '1 hour' * $1
              AND event_category = 'network'
              AND bytes_sent IS NOT NULL
              AND bytes_sent > 1000000  -- > 1MB
              AND destination_ip IS NOT NULL
            GROUP BY user_name, source_host, destination_ip
            HAVING SUM(bytes_sent) > 10000000  -- > 10MB total
            "#,
            hours as f64
        )
        .fetch_all(&self.db)
        .await?;

        let mut correlations = Vec::new();

        for row in rows {
            let total_mb = row.total_bytes.to_f64() / 1_000_000.0;
            let confidence = if total_mb > 100.0 { 0.80 } else { 0.60 };
            let risk_score = (total_mb / 10.0).min(100.0);

            let severity = if total_mb > 500.0 {
                Severity::Critical
            } else if total_mb > 100.0 {
                Severity::High
            } else {
                Severity::Medium
            };

            let dest_ip = row.destination_ip.map(|ip| ip.ip().to_string());

            let correlation = EventCorrelation {
                id: Uuid::new_v4(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
                correlation_type: CorrelationType::DataExfiltration,
                pattern_name: Some("Potential Data Exfiltration".to_string()),
                pattern_description: Some(format!(
                    "Large data transfer: {:.2} MB sent to {}",
                    total_mb,
                    dest_ip.as_ref().unwrap_or(&"unknown".to_string())
                )),
                confidence,
                severity,
                risk_score: Some(risk_score),
                first_event_time: row.first_transfer.unwrap(),
                last_event_time: row.last_transfer.unwrap(),
                time_window_seconds: Some(
                    (row.last_transfer.unwrap() - row.first_transfer.unwrap())
                        .num_seconds() as i32,
                ),
                event_count: row.transfer_count.unwrap_or(0) as i32,
                involved_users: row
                    .user_name
                    .map(|u| vec![u])
                    .unwrap_or_default(),
                involved_hosts: vec![row.source_host.clone()],
                involved_ips: row.destination_ip.map(|ip| ip.ip()).into_iter().collect(),
                involved_processes: vec![],
                statistical_significance: None,
                anomaly_score: Some(risk_score),
                z_score: None,
                baseline_deviation_percent: None,
                correlation_data: Some(json!({
                    "total_bytes": row.total_bytes,
                    "total_mb": total_mb,
                    "transfer_count": row.transfer_count,
                    "destination": dest_ip,
                })),
                attack_stage: Some(AttackStage::Exfiltration),
                status: CorrelationStatus::Active,
                resolved_at: None,
                resolution_notes: None,
                assigned_to: None,
                assigned_at: None,
            };

            correlations.push(correlation);
        }

        Ok(correlations)
    }

    /// Detect clusters of high anomaly scores
    async fn detect_anomaly_clusters(&self, hours: i32) -> Result<Vec<EventCorrelation>> {
        let rows = sqlx::query!(
            r#"
            SELECT
                source_host,
                user_name,
                COUNT(*) as anomaly_count,
                AVG(anomaly_score) as avg_anomaly,
                MAX(anomaly_score) as max_anomaly,
                MIN(timestamp) as first_anomaly,
                MAX(timestamp) as last_anomaly,
                array_agg(DISTINCT event_type) as event_types
            FROM security_events
            WHERE timestamp > NOW() - INTERVAL '1 hour' * $1
              AND anomaly_score > 50
            GROUP BY source_host, user_name
            HAVING COUNT(*) >= 5 AND AVG(anomaly_score) > 60
            "#,
            hours as f64
        )
        .fetch_all(&self.db)
        .await?;

        let mut correlations = Vec::new();

        for row in rows {
            let avg_anomaly = row.avg_anomaly.to_f64();
            let confidence = (avg_anomaly / 100.0).min(1.0);

            let severity = if avg_anomaly > 80.0 {
                Severity::Critical
            } else if avg_anomaly > 70.0 {
                Severity::High
            } else {
                Severity::Medium
            };

            let correlation = EventCorrelation {
                id: Uuid::new_v4(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
                correlation_type: CorrelationType::Anomaly,
                pattern_name: Some("Anomaly Cluster".to_string()),
                pattern_description: Some(format!(
                    "Cluster of {} anomalies (avg score: {:.1}) on {}",
                    row.anomaly_count.unwrap_or(0),
                    avg_anomaly,
                    row.source_host
                )),
                confidence,
                severity,
                risk_score: Some(avg_anomaly),
                first_event_time: row.first_anomaly.unwrap(),
                last_event_time: row.last_anomaly.unwrap(),
                time_window_seconds: Some(
                    (row.last_anomaly.unwrap() - row.first_anomaly.unwrap())
                        .num_seconds() as i32,
                ),
                event_count: row.anomaly_count.unwrap_or(0) as i32,
                involved_users: row
                    .user_name
                    .map(|u| vec![u])
                    .unwrap_or_default(),
                involved_hosts: vec![row.source_host.clone()],
                involved_ips: vec![],
                involved_processes: vec![],
                statistical_significance: None,
                anomaly_score: Some(avg_anomaly),
                z_score: None,
                baseline_deviation_percent: None,
                correlation_data: Some(json!({
                    "anomaly_count": row.anomaly_count,
                    "avg_score": avg_anomaly,
                    "max_score": row.max_anomaly,
                    "event_types": row.event_types,
                })),
                attack_stage: None,
                status: CorrelationStatus::Active,
                resolved_at: None,
                resolution_notes: None,
                assigned_to: None,
                assigned_at: None,
            };

            correlations.push(correlation);
        }

        Ok(correlations)
    }

    /// Costruttore comune di una correlazione (riduce il boilerplate dei detector).
    #[allow(clippy::too_many_arguments)]
    fn build_correlation(
        ctype: CorrelationType,
        name: &str,
        description: String,
        severity: Severity,
        confidence: f64,
        risk_score: f64,
        first: chrono::DateTime<Utc>,
        last: chrono::DateTime<Utc>,
        event_count: i32,
        users: Vec<String>,
        hosts: Vec<String>,
        ips: Vec<std::net::IpAddr>,
        processes: Vec<String>,
        data: serde_json::Value,
        stage: AttackStage,
    ) -> EventCorrelation {
        EventCorrelation {
            id: Uuid::new_v4(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            correlation_type: ctype,
            pattern_name: Some(name.to_string()),
            pattern_description: Some(description),
            confidence,
            severity,
            risk_score: Some(risk_score),
            first_event_time: first,
            last_event_time: last,
            time_window_seconds: Some((last - first).num_seconds() as i32),
            event_count,
            involved_users: users,
            involved_hosts: hosts,
            involved_ips: ips,
            involved_processes: processes,
            statistical_significance: None,
            anomaly_score: Some(risk_score),
            z_score: None,
            baseline_deviation_percent: None,
            correlation_data: Some(data),
            attack_stage: Some(stage),
            status: CorrelationStatus::Active,
            resolved_at: None,
            resolution_notes: None,
            assigned_to: None,
            assigned_at: None,
        }
    }

    /// R6 — Esecuzione sospetta (reverse-shell/interprete). Euristica 1-hop sul
    /// lignaggio di processo (una catena antenati completa da Laurel è TODO).
    async fn detect_suspicious_process(&self, hours: i32) -> Result<Vec<EventCorrelation>> {
        let rows = sqlx::query!(
            r#"
            SELECT source_host, user_name,
                   COUNT(*) as cnt, MIN(timestamp) as first_t, MAX(timestamp) as last_t,
                   array_agg(DISTINCT process_cmdline) FILTER (WHERE process_cmdline IS NOT NULL) as cmds
            FROM security_events
            WHERE timestamp > NOW() - INTERVAL '1 hour' * $1
              AND (
                  process_name ~* '(^|/)(nc|ncat|socat)$'
                  OR process_cmdline ~* '(bash|sh)[[:space:]]+-i'
                  OR process_cmdline ~* 'python[0-9]?[[:space:]]+-c'
                  OR process_cmdline ~* 'perl[[:space:]]+-e'
                  OR process_cmdline ~* '/dev/tcp/'
              )
            GROUP BY source_host, user_name
            HAVING COUNT(*) >= 1
            "#,
            hours as f64
        )
        .fetch_all(&self.db)
        .await?;

        let mut out = Vec::new();
        for r in rows {
            let cnt = r.cnt.unwrap_or(0);
            let host = r.source_host;
            let user = r.user_name.unwrap_or_else(|| "unknown".into());
            let cmds = r.cmds.unwrap_or_default();
            out.push(Self::build_correlation(
                CorrelationType::Sequence,
                "Suspicious Process Execution",
                format!("Esecuzione sospetta (reverse-shell/interprete) su {host} da '{user}' ({cnt} eventi)"),
                if cnt > 2 { Severity::Critical } else { Severity::High },
                Self::calculate_confidence(cnt, 1, 5),
                Self::calculate_risk_score(cnt as f64, 1.0, 5.0),
                r.first_t.unwrap(),
                r.last_t.unwrap(),
                cnt as i32,
                vec![user],
                vec![host],
                vec![],
                cmds.clone(),
                json!({ "commands": cmds }),
                AttackStage::Execution,
            ));
        }
        Ok(out)
    }

    /// R7 — Privilege escalation attribuita all'utente di login reale (auid).
    /// Un processo con uid=0 il cui auid è un utente NON root indica che qualcuno
    /// loggato come utente normale ha ottenuto root.
    async fn detect_auid_privesc(&self, hours: i32) -> Result<Vec<EventCorrelation>> {
        let rows = sqlx::query!(
            r#"
            SELECT source_host, event_data->>'auid' as auid,
                   COUNT(*) as cnt, MIN(timestamp) as first_t, MAX(timestamp) as last_t,
                   array_agg(DISTINCT process_cmdline) FILTER (WHERE process_cmdline IS NOT NULL) as cmds
            FROM security_events
            WHERE timestamp > NOW() - INTERVAL '1 hour' * $1
              AND event_data->>'uid' = '0'
              AND event_data->>'auid' IS NOT NULL
              AND event_data->>'auid' NOT IN ('0', '4294967295', 'unset', '-1')
            GROUP BY source_host, event_data->>'auid'
            HAVING COUNT(*) >= 1
            "#,
            hours as f64
        )
        .fetch_all(&self.db)
        .await?;

        let mut out = Vec::new();
        for r in rows {
            let cnt = r.cnt.unwrap_or(0);
            let host = r.source_host;
            let auid = r.auid.unwrap_or_else(|| "unknown".into());
            let cmds = r.cmds.unwrap_or_default();
            out.push(Self::build_correlation(
                CorrelationType::Sequence,
                "Privilege Escalation (auid)",
                format!("Login utente auid={auid} ha ottenuto uid=0 su {host} ({cnt} eventi)"),
                Severity::High,
                Self::calculate_confidence(cnt, 1, 5),
                Self::calculate_risk_score(cnt as f64, 1.0, 5.0),
                r.first_t.unwrap(),
                r.last_t.unwrap(),
                cnt as i32,
                vec![auid],
                vec![host],
                vec![],
                cmds.clone(),
                json!({ "commands": cmds, "gained_uid": 0 }),
                AttackStage::PrivilegeEscalation,
            ));
        }
        Ok(out)
    }

    /// R9 — Beaconing C2 (euristica): molte connessioni verso lo stesso dest,
    /// distribuite nel tempo. La periodicità vera (stddev inter-arrivo) è un TODO.
    async fn detect_beaconing(&self, hours: i32) -> Result<Vec<EventCorrelation>> {
        let rows = sqlx::query!(
            r#"
            SELECT source_host, host(destination_ip) as dest_ip, destination_port,
                   COUNT(*) as cnt, MIN(timestamp) as first_t, MAX(timestamp) as last_t
            FROM security_events
            WHERE timestamp > NOW() - INTERVAL '1 hour' * $1
              AND destination_ip IS NOT NULL
              AND event_category = 'network'
            GROUP BY source_host, host(destination_ip), destination_port
            HAVING COUNT(*) >= 10
               AND (MAX(timestamp) - MIN(timestamp)) > INTERVAL '5 minutes'
            "#,
            hours as f64
        )
        .fetch_all(&self.db)
        .await?;

        let mut out = Vec::new();
        for r in rows {
            let cnt = r.cnt.unwrap_or(0);
            let host = r.source_host;
            let dest = r.dest_ip.unwrap_or_default();
            let port = r.destination_port.unwrap_or(0);
            let ips: Vec<std::net::IpAddr> = dest.parse().ok().into_iter().collect();
            out.push(Self::build_correlation(
                CorrelationType::Frequency,
                "C2 Beaconing",
                format!("Connessioni ripetute ({cnt}) da {host} verso {dest}:{port} — possibile beaconing C2"),
                Severity::High,
                Self::calculate_confidence(cnt, 10, 60),
                Self::calculate_risk_score(cnt as f64, 10.0, 60.0),
                r.first_t.unwrap(),
                r.last_t.unwrap(),
                cnt as i32,
                vec![],
                vec![host],
                ips,
                vec![],
                json!({ "destination": dest, "port": port, "connections": cnt }),
                AttackStage::CommandAndControl,
            ));
        }
        Ok(out)
    }

    /// R11 — Persistenza: scritture su path di autostart/persistenza.
    async fn detect_persistence(&self, hours: i32) -> Result<Vec<EventCorrelation>> {
        let rows = sqlx::query!(
            r#"
            SELECT source_host, user_name,
                   COUNT(*) as cnt, MIN(timestamp) as first_t, MAX(timestamp) as last_t,
                   array_agg(DISTINCT file_path) as files
            FROM security_events
            WHERE timestamp > NOW() - INTERVAL '1 hour' * $1
              AND file_path IS NOT NULL
              AND (file_operation IS NULL OR file_operation IN ('write', 'create'))
              AND (
                  file_path ~* '/etc/cron'
                  OR file_path ~* '/etc/systemd/system'
                  OR file_path ~* 'authorized_keys'
                  OR file_path ~* '/etc/rc\.local'
                  OR file_path ~* '/etc/init\.d'
                  OR file_path ~* '\.bashrc$'
                  OR file_path ~* '/etc/profile'
              )
            GROUP BY source_host, user_name
            HAVING COUNT(*) >= 1
            "#,
            hours as f64
        )
        .fetch_all(&self.db)
        .await?;

        let mut out = Vec::new();
        for r in rows {
            let cnt = r.cnt.unwrap_or(0);
            let host = r.source_host;
            let user = r.user_name.unwrap_or_else(|| "unknown".into());
            let files = r.files.unwrap_or_default();
            out.push(Self::build_correlation(
                CorrelationType::Sequence,
                "Persistence Mechanism",
                format!("Scrittura su path di persistenza su {host} da '{user}' ({cnt} file)"),
                Severity::High,
                Self::calculate_confidence(cnt, 1, 5),
                Self::calculate_risk_score(cnt as f64, 1.0, 5.0),
                r.first_t.unwrap(),
                r.last_t.unwrap(),
                cnt as i32,
                vec![user],
                vec![host],
                vec![],
                vec![],
                json!({ "files": files }),
                AttackStage::Persistence,
            ));
        }
        Ok(out)
    }

    /// R12 — Accesso a file di credenziali (shadow/sudoers).
    async fn detect_credential_file_access(&self, hours: i32) -> Result<Vec<EventCorrelation>> {
        let rows = sqlx::query!(
            r#"
            SELECT source_host, user_name,
                   COUNT(*) as cnt, MIN(timestamp) as first_t, MAX(timestamp) as last_t,
                   array_agg(DISTINCT file_path) as files
            FROM security_events
            WHERE timestamp > NOW() - INTERVAL '1 hour' * $1
              AND file_path IS NOT NULL
              AND (
                  file_path = '/etc/shadow'
                  OR file_path = '/etc/gshadow'
                  OR file_path = '/etc/sudoers'
                  OR file_path ~* '/etc/sudoers\.d'
              )
            GROUP BY source_host, user_name
            HAVING COUNT(*) >= 1
            "#,
            hours as f64
        )
        .fetch_all(&self.db)
        .await?;

        let mut out = Vec::new();
        for r in rows {
            let cnt = r.cnt.unwrap_or(0);
            let host = r.source_host;
            let user = r.user_name.unwrap_or_else(|| "unknown".into());
            let files = r.files.unwrap_or_default();
            out.push(Self::build_correlation(
                CorrelationType::Sequence,
                "Credential File Access",
                format!("Accesso a file di credenziali su {host} da '{user}' ({cnt})"),
                Severity::High,
                Self::calculate_confidence(cnt, 1, 5),
                Self::calculate_risk_score(cnt as f64, 1.0, 5.0),
                r.first_t.unwrap(),
                r.last_t.unwrap(),
                cnt as i32,
                vec![user],
                vec![host],
                vec![],
                vec![],
                json!({ "files": files }),
                AttackStage::CredentialAccess,
            ));
        }
        Ok(out)
    }

    /// R13 — Discovery burst: varietà di comandi di ricognizione in finestra.
    async fn detect_discovery_burst(&self, hours: i32) -> Result<Vec<EventCorrelation>> {
        let rows = sqlx::query!(
            r#"
            SELECT source_host, user_name,
                   COUNT(DISTINCT process_name) as variety, COUNT(*) as cnt,
                   MIN(timestamp) as first_t, MAX(timestamp) as last_t,
                   array_agg(DISTINCT process_name) FILTER (WHERE process_name IS NOT NULL) as procs
            FROM security_events
            WHERE timestamp > NOW() - INTERVAL '1 hour' * $1
              AND process_name ~* '(^|/)(whoami|id|uname|hostname|netstat|ss|ps|ifconfig|ip|w|last|arp|lsof)$'
            GROUP BY source_host, user_name
            HAVING COUNT(DISTINCT process_name) >= 4
            "#,
            hours as f64
        )
        .fetch_all(&self.db)
        .await?;

        let mut out = Vec::new();
        for r in rows {
            let cnt = r.cnt.unwrap_or(0);
            let variety = r.variety.unwrap_or(0);
            let host = r.source_host;
            let user = r.user_name.unwrap_or_else(|| "unknown".into());
            let procs = r.procs.unwrap_or_default();
            out.push(Self::build_correlation(
                CorrelationType::Frequency,
                "Discovery Burst",
                format!("Ricognizione ({variety} comandi distinti) su {host} da '{user}'"),
                Severity::Medium,
                Self::calculate_confidence(variety, 4, 10),
                Self::calculate_risk_score(variety as f64, 4.0, 10.0),
                r.first_t.unwrap(),
                r.last_t.unwrap(),
                cnt as i32,
                vec![user],
                vec![host],
                vec![],
                procs.clone(),
                json!({ "recon_commands": procs }),
                AttackStage::Discovery,
            ));
        }
        Ok(out)
    }

    /// R14 — Defense evasion: tamper dei log di audit / clear della history.
    async fn detect_defense_evasion(&self, hours: i32) -> Result<Vec<EventCorrelation>> {
        let rows = sqlx::query!(
            r#"
            SELECT source_host, user_name,
                   COUNT(*) as cnt, MIN(timestamp) as first_t, MAX(timestamp) as last_t,
                   array_agg(DISTINCT process_cmdline) FILTER (WHERE process_cmdline IS NOT NULL) as cmds
            FROM security_events
            WHERE timestamp > NOW() - INTERVAL '1 hour' * $1
              AND (
                  process_cmdline ~* 'auditctl[[:space:]]+-D'
                  OR process_cmdline ~* 'systemctl[[:space:]]+stop[[:space:]]+auditd'
                  OR process_cmdline ~* 'history[[:space:]]+-c'
                  OR (process_cmdline ~* '\brm\b' AND process_cmdline ~* 'bash_history')
                  OR (file_path ~* 'bash_history' AND file_operation = 'delete')
                  OR (file_path ~* '/var/log/audit' AND file_operation IN ('write', 'delete'))
              )
            GROUP BY source_host, user_name
            HAVING COUNT(*) >= 1
            "#,
            hours as f64
        )
        .fetch_all(&self.db)
        .await?;

        let mut out = Vec::new();
        for r in rows {
            let cnt = r.cnt.unwrap_or(0);
            let host = r.source_host;
            let user = r.user_name.unwrap_or_else(|| "unknown".into());
            let cmds = r.cmds.unwrap_or_default();
            out.push(Self::build_correlation(
                CorrelationType::Sequence,
                "Defense Evasion",
                format!("Tamper log/history su {host} da '{user}' ({cnt} eventi)"),
                Severity::High,
                Self::calculate_confidence(cnt, 1, 5),
                Self::calculate_risk_score(cnt as f64, 1.0, 5.0),
                r.first_t.unwrap(),
                r.last_t.unwrap(),
                cnt as i32,
                vec![user],
                vec![host],
                vec![],
                cmds.clone(),
                json!({ "commands": cmds }),
                AttackStage::DefenseEvasion,
            ));
        }
        Ok(out)
    }

    /// R8 — Sessione sospetta: un login (ses) con auth fallite E poi eventi uid=0
    /// (la sessione "è partita male" ed è escalata — la storia dell'intrusione).
    async fn detect_suspicious_session(&self, hours: i32) -> Result<Vec<EventCorrelation>> {
        let rows = sqlx::query!(
            r#"
            SELECT source_host, event_data->>'ses' as ses,
                   COUNT(*) FILTER (WHERE event_category = 'authentication'
                       AND (event_data->>'result' LIKE '%fail%' OR event_data->>'res' LIKE '%fail%')) as fails,
                   COUNT(*) FILTER (WHERE event_data->>'uid' = '0') as root_events,
                   COUNT(*) as cnt, MIN(timestamp) as first_t, MAX(timestamp) as last_t
            FROM security_events
            WHERE timestamp > NOW() - INTERVAL '1 hour' * $1
              AND event_data->>'ses' IS NOT NULL
              AND event_data->>'ses' NOT IN ('unset', '4294967295', '-1')
            GROUP BY source_host, event_data->>'ses'
            HAVING COUNT(*) FILTER (WHERE event_category = 'authentication'
                       AND (event_data->>'result' LIKE '%fail%' OR event_data->>'res' LIKE '%fail%')) >= 1
               AND COUNT(*) FILTER (WHERE event_data->>'uid' = '0') >= 1
            "#,
            hours as f64
        )
        .fetch_all(&self.db)
        .await?;

        let mut out = Vec::new();
        for r in rows {
            let cnt = r.cnt.unwrap_or(0);
            let fails = r.fails.unwrap_or(0);
            let root_events = r.root_events.unwrap_or(0);
            let host = r.source_host;
            let ses = r.ses.unwrap_or_default();
            out.push(Self::build_correlation(
                CorrelationType::Sequence,
                "Suspicious Session Lifecycle",
                format!("Sessione {ses} su {host}: {fails} auth fallite poi {root_events} eventi root"),
                Severity::High,
                Self::calculate_confidence(cnt, 2, 10),
                Self::calculate_risk_score(cnt as f64, 2.0, 10.0),
                r.first_t.unwrap(),
                r.last_t.unwrap(),
                cnt as i32,
                vec![],
                vec![host],
                vec![],
                vec![],
                json!({ "session": ses, "failed_auths": fails, "root_events": root_events }),
                AttackStage::PrivilegeEscalation,
            ));
        }
        Ok(out)
    }

    /// R15 — Impact/ransomware: scritture/cancellazioni di massa in finestra breve.
    async fn detect_mass_file_ops(&self, hours: i32) -> Result<Vec<EventCorrelation>> {
        let rows = sqlx::query!(
            r#"
            SELECT source_host, user_name, COUNT(*) as cnt,
                   MIN(timestamp) as first_t, MAX(timestamp) as last_t
            FROM security_events
            WHERE timestamp > NOW() - INTERVAL '1 hour' * $1
              AND file_path IS NOT NULL
              AND file_operation IN ('write', 'delete')
            GROUP BY source_host, user_name
            HAVING COUNT(*) >= 100
               AND (MAX(timestamp) - MIN(timestamp)) < INTERVAL '5 minutes'
            "#,
            hours as f64
        )
        .fetch_all(&self.db)
        .await?;

        let mut out = Vec::new();
        for r in rows {
            let cnt = r.cnt.unwrap_or(0);
            let host = r.source_host;
            let user = r.user_name.unwrap_or_else(|| "unknown".into());
            out.push(Self::build_correlation(
                CorrelationType::Frequency,
                "Mass File Operations",
                format!("Operazioni di massa su file ({cnt}) su {host} da '{user}' in <5 min — possibile ransomware"),
                Severity::Critical,
                Self::calculate_confidence(cnt, 100, 1000),
                Self::calculate_risk_score(cnt as f64, 100.0, 1000.0),
                r.first_t.unwrap(),
                r.last_t.unwrap(),
                cnt as i32,
                vec![user],
                vec![host],
                vec![],
                vec![],
                json!({ "file_ops": cnt }),
                AttackStage::Impact,
            ));
        }
        Ok(out)
    }

    /// Save correlation to database
    async fn save_correlation(&self, correlation: &EventCorrelation) -> Result<()> {
        // Arricchisce correlation_data con la tattica ATT&CK e la tecnica
        // difensiva D3FEND che avrebbe mitigato la minaccia (cross-link con la
        // mappatura compliance della suite). Nessuna migrazione: sta nel JSONB.
        let correlation_data = {
            let mut base = correlation
                .correlation_data
                .clone()
                .unwrap_or_else(|| json!({}));
            if let Some(obj) = base.as_object_mut() {
                if let Some(stage) = correlation.attack_stage.as_ref() {
                    let tactic = stage.to_string();
                    if let Some(d3) = d3fend_for_tactic(&tactic) {
                        obj.insert("mitigating_d3fend".to_string(), json!(d3));
                    }
                    obj.insert("mitre_tactic".to_string(), json!(tactic));
                }
                // Tecnica ATT&CK precisa della regola (mappatura completa).
                if let Some((tid, tname)) = correlation
                    .pattern_name
                    .as_deref()
                    .and_then(technique_for_pattern)
                {
                    obj.insert("mitre_technique".to_string(), json!(tid));
                    obj.insert("mitre_technique_name".to_string(), json!(tname));
                }
            }
            base
        };

        sqlx::query!(
            r#"
            INSERT INTO event_correlations (
                id, created_at, updated_at,
                correlation_type, pattern_name, pattern_description,
                confidence, severity, risk_score,
                first_event_time, last_event_time, time_window_seconds, event_count,
                involved_users, involved_hosts, involved_ips, involved_processes,
                statistical_significance, anomaly_score, z_score, baseline_deviation_percent,
                correlation_data, attack_stage, status
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
                $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24
            )
            ON CONFLICT (id) DO UPDATE SET
                updated_at = EXCLUDED.updated_at,
                event_count = EXCLUDED.event_count,
                last_event_time = EXCLUDED.last_event_time
            "#,
            correlation.id,
            correlation.created_at,
            correlation.updated_at,
            correlation.correlation_type.to_string(),
            correlation.pattern_name,
            correlation.pattern_description,
            correlation.confidence.to_bigdecimal(),
            correlation.severity.to_string(),
            correlation.risk_score.map(|v| v.to_bigdecimal()),
            correlation.first_event_time,
            correlation.last_event_time,
            correlation.time_window_seconds,
            correlation.event_count,
            &correlation.involved_users,
            &correlation.involved_hosts,
            &correlation.involved_ips.iter().map(|ip| IpNetwork::from(*ip)).collect::<Vec<IpNetwork>>(),
            &correlation.involved_processes,
            correlation.statistical_significance.map(|v| v.to_bigdecimal()),
            correlation.anomaly_score.map(|v| v.to_bigdecimal()),
            correlation.z_score.map(|v| v.to_bigdecimal()),
            correlation.baseline_deviation_percent.map(|v| v.to_bigdecimal()),
            correlation_data,
            correlation.attack_stage.as_ref().map(|s| s.to_string()),
            correlation.status.to_string()
        )
        .execute(&self.db)
        .await?;

        Ok(())
    }

    /// Calculate confidence score (0.0 - 1.0)
    fn calculate_confidence(observed: i64, min_threshold: i64, max_threshold: i64) -> f64 {
        if observed < min_threshold {
            0.3
        } else if observed > max_threshold {
            0.95
        } else {
            0.5 + ((observed - min_threshold) as f64 / (max_threshold - min_threshold) as f64) * 0.45
        }
    }

    /// Calculate risk score (0 - 100)
    fn calculate_risk_score(observed: f64, min_threshold: f64, max_threshold: f64) -> f64 {
        let normalized = ((observed - min_threshold) / (max_threshold - min_threshold))
            .max(0.0)
            .min(1.0);
        normalized * 100.0
    }

    /// Get active correlations
    pub async fn get_active_correlations(&self, limit: i64) -> Result<Vec<EventCorrelation>> {
        let rows = sqlx::query!(
            r#"
            SELECT
                id, created_at, updated_at,
                correlation_type, pattern_name, pattern_description,
                confidence, severity, risk_score,
                first_event_time, last_event_time, time_window_seconds, event_count,
                involved_users, involved_hosts, involved_ips, involved_processes,
                statistical_significance, anomaly_score, z_score, baseline_deviation_percent,
                correlation_data, attack_stage, status,
                resolved_at, resolution_notes, assigned_to, assigned_at
            FROM event_correlations
            WHERE status = 'active'
            ORDER BY risk_score DESC NULLS LAST, created_at DESC
            LIMIT $1
            "#,
            limit
        )
        .fetch_all(&self.db)
        .await?;

        let correlations = rows
            .into_iter()
            .map(|row| {
                Ok(EventCorrelation {
                    id: row.id,
                    created_at: row.created_at,
                    updated_at: row.updated_at,
                    correlation_type: serde_json::from_str(&format!("\"{}\"", row.correlation_type))?,
                    pattern_name: row.pattern_name,
                    pattern_description: row.pattern_description,
                    confidence: row.confidence.to_f64(),
                    severity: serde_json::from_str(&format!("\"{}\"", row.severity))?,
                    risk_score: row.risk_score.map(|d| d.to_f64()),
                    first_event_time: row.first_event_time,
                    last_event_time: row.last_event_time,
                    time_window_seconds: row.time_window_seconds,
                    event_count: row.event_count,
                    involved_users: row.involved_users.unwrap_or_default(),
                    involved_hosts: row.involved_hosts.unwrap_or_default(),
                    involved_ips: row
                        .involved_ips
                        .unwrap_or_default()
                        .into_iter()
                        .map(|n| n.ip())
                        .collect(),
                    involved_processes: row.involved_processes.unwrap_or_default(),
                    statistical_significance: row.statistical_significance.map(|d| d.to_f64()),
                    anomaly_score: row.anomaly_score.map(|d| d.to_f64()),
                    z_score: row.z_score.map(|d| d.to_f64()),
                    baseline_deviation_percent: row.baseline_deviation_percent.map(|d| d.to_f64()),
                    correlation_data: row.correlation_data,
                    attack_stage: row
                        .attack_stage
                        .and_then(|s| serde_json::from_str(&format!("\"{}\"", s)).ok()),
                    status: serde_json::from_str(&format!(
                        "\"{}\"",
                        row.status.as_deref().unwrap_or("active")
                    ))?,
                    resolved_at: row.resolved_at,
                    resolution_notes: row.resolution_notes,
                    assigned_to: row.assigned_to,
                    assigned_at: row.assigned_at,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(correlations)
    }

    /// Get correlation statistics
    pub async fn get_correlation_stats(&self) -> Result<HashMap<String, i64>> {
        let rows = sqlx::query!(
            r#"
            SELECT
                correlation_type,
                COUNT(*) as count
            FROM event_correlations
            WHERE status = 'active'
            GROUP BY correlation_type
            "#
        )
        .fetch_all(&self.db)
        .await?;

        let mut stats = HashMap::new();
        for row in rows {
            stats.insert(row.correlation_type, row.count.unwrap_or(0));
        }

        Ok(stats)
    }
}
