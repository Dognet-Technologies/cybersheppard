// ============================================================================
// Correlation Engine - Advanced Event Correlation & Pattern Detection
// ============================================================================

use anyhow::Result;
use chrono::Utc;
use ipnetwork::IpNetwork;
use serde_json::json;
use sqlx::PgPool;
use sqlx::Row;
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
        "Reverse Shell" => Some(("T1071", "Application Layer Protocol")),
        "C2 Beaconing" => Some(("T1071", "Application Layer Protocol")),
        "Persistence Mechanism" => Some(("T1547", "Boot or Logon Autostart Execution")),
        "Credential File Access" => Some(("T1003", "OS Credential Dumping")),
        "Discovery Burst" => Some(("T1082", "System Information Discovery")),
        "Root Asset Discovery" => Some(("T1083", "File and Directory Discovery")),
        "Defense Evasion" => Some(("T1070", "Indicator Removal")),
        "io_uring Audit Evasion" => Some(("T1562", "Impair Defenses")),
        "Sensor Silence" => Some(("T1562", "Impair Defenses")),
        "Fileless Execution" => Some(("T1620", "Reflective Code Loading")),
        "eBPF Credential Access" => Some(("T1003", "OS Credential Dumping")),
        "Process Injection (ptrace)" => Some(("T1055", "Process Injection")),
        "Network Sweep" => Some(("T1046", "Network Service Discovery")),
        "Dynamic Linker Hijack" => Some(("T1574.006", "Dynamic Linker Hijacking")),
        "Suspicious Session Lifecycle" => Some(("T1078", "Valid Accounts")),
        "Mass File Operations" => Some(("T1486", "Data Encrypted for Impact")),
        // R25–R34 (detection host-local aggiuntive)
        "Off-Hours Login" => Some(("T1078", "Valid Accounts")),
        "SSH Authorized Keys Tampering" => Some(("T1098.004", "SSH Authorized Keys")),
        "System Config Tampering" => Some(("T1098", "Account Manipulation")),
        "Account Management" => Some(("T1136", "Create Account")),
        "SUID/SGID Backdoor" => Some(("T1548.001", "Setuid and Setgid")),
        "Execution From World-Writable Path" => Some(("T1059.004", "Unix Shell")),
        "Anomalous Root Execution" => Some(("T1059", "Command and Scripting Interpreter")),
        "First-Seen User On Host" => Some(("T1078", "Valid Accounts")),
        "New Login Source" => Some(("T1078", "Valid Accounts")),
        "Service Account Shell" => Some(("T1059.004", "Unix Shell")),
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
        correlations.extend(self.detect_root_asset_discovery(hours).await?); // R16
        correlations.extend(self.detect_io_uring_evasion(hours).await?); // R17
        correlations.extend(self.detect_sensor_silence(hours).await?); // R18
        correlations.extend(self.detect_fileless_execution(hours).await?); // R20
        correlations.extend(self.detect_ebpf_credential_access(hours).await?); // R21
        correlations.extend(self.detect_ptrace_injection(hours).await?); // R22
        correlations.extend(self.detect_network_sweep(hours).await?); // R23
        correlations.extend(self.detect_ld_preload(hours).await?); // R24
        correlations.extend(self.detect_defense_evasion(hours).await?); // R14
        correlations.extend(self.detect_suspicious_session(hours).await?); // R8
        correlations.extend(self.detect_mass_file_ops(hours).await?); // R15
        correlations.extend(self.detect_reverse_shell(hours).await?); // R10

        // R25–R34 — detection host-local aggiuntive (nessuna integrazione)
        correlations.extend(self.detect_off_hours_login(hours).await?); // R25
        correlations.extend(self.detect_authorized_keys_tampering(hours).await?); // R26
        correlations.extend(self.detect_system_config_tampering(hours).await?); // R27
        correlations.extend(self.detect_account_management(hours).await?); // R28
        correlations.extend(self.detect_suid_backdoor(hours).await?); // R29
        correlations.extend(self.detect_world_writable_exec(hours).await?); // R30
        correlations.extend(self.detect_anomalous_root_exec(hours).await?); // R31
        correlations.extend(self.detect_first_seen_user_host(hours).await?); // R32
        correlations.extend(self.detect_new_login_source(hours).await?); // R33
        correlations.extend(self.detect_service_shell(hours).await?); // R34

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

    // ========================================================================
    // Detection host-local aggiuntive (R25–R34) — nessuna integrazione cross-tool.
    // Scritte con l'API sqlx runtime (niente macro) per non toccare la cache .sqlx.
    // ========================================================================

    /// Legge un intero da system_settings (fallback su default se assente/errore).
    async fn setting_int(&self, key: &str, default: i32) -> i32 {
        let v: Option<String> = sqlx::query_scalar(
            "SELECT setting_value FROM system_settings WHERE setting_key = $1",
        )
        .bind(key)
        .fetch_optional(&self.db)
        .await
        .ok()
        .flatten();
        v.and_then(|s| s.trim().parse::<i32>().ok()).unwrap_or(default)
    }

    /// R25 — Login/attività fuori orario lavorativo (finestra configurabile in
    /// system_settings: business_hours_start/end, default 08–20; weekend sempre).
    async fn detect_off_hours_login(&self, hours: i32) -> Result<Vec<EventCorrelation>> {
        let start = self.setting_int("business_hours_start", 8).await;
        let end = self.setting_int("business_hours_end", 20).await;
        let rows = sqlx::query(
            r#"
            SELECT source_host, user_name,
                   COUNT(*) AS cnt, MIN(timestamp) AS first_t, MAX(timestamp) AS last_t
            FROM security_events
            WHERE timestamp > NOW() - INTERVAL '1 hour' * $1
              AND event_type ILIKE '%login%'
              AND ( EXTRACT(DOW FROM timestamp) IN (0, 6)
                    OR EXTRACT(HOUR FROM timestamp) < $2
                    OR EXTRACT(HOUR FROM timestamp) >= $3 )
            GROUP BY source_host, user_name
            HAVING COUNT(*) >= 1
            "#,
        )
        .bind(hours as f64)
        .bind(start as f64)
        .bind(end as f64)
        .fetch_all(&self.db)
        .await?;

        let mut out = Vec::new();
        for r in rows {
            let cnt: i64 = r.try_get("cnt").unwrap_or(0);
            let host: String = r.try_get("source_host").unwrap_or_default();
            let user: String = r.try_get::<Option<String>, _>("user_name").ok().flatten().unwrap_or_else(|| "unknown".into());
            let first = r.try_get::<chrono::DateTime<Utc>, _>("first_t").unwrap_or_else(|_| Utc::now());
            let last = r.try_get::<chrono::DateTime<Utc>, _>("last_t").unwrap_or_else(|_| Utc::now());
            out.push(Self::build_correlation(
                CorrelationType::Sequence,
                "Off-Hours Login",
                format!("Login/attività fuori orario ({start:02}:00–{end:02}:00, o weekend) di '{user}' su {host} ({cnt} eventi)"),
                Severity::Medium,
                Self::calculate_confidence(cnt, 1, 5),
                Self::calculate_risk_score(cnt as f64, 1.0, 8.0),
                first, last, cnt as i32,
                vec![user], vec![host], vec![], vec![],
                json!({ "business_hours": format!("{start}-{end}"), "reason": "off_hours" }),
                AttackStage::InitialAccess,
            ));
        }
        Ok(out)
    }

    /// R26 — Backdoor SSH: scrittura su ~/.ssh/authorized_keys.
    async fn detect_authorized_keys_tampering(&self, hours: i32) -> Result<Vec<EventCorrelation>> {
        let rows = sqlx::query(
            r#"
            SELECT source_host, user_name,
                   COUNT(*) AS cnt, MIN(timestamp) AS first_t, MAX(timestamp) AS last_t,
                   array_agg(DISTINCT file_path) FILTER (WHERE file_path IS NOT NULL) AS files
            FROM security_events
            WHERE timestamp > NOW() - INTERVAL '1 hour' * $1
              AND file_path ILIKE '%/.ssh/authorized_keys%'
              AND (file_operation IS NULL OR file_operation NOT ILIKE '%read%')
            GROUP BY source_host, user_name
            HAVING COUNT(*) >= 1
            "#,
        )
        .bind(hours as f64)
        .fetch_all(&self.db)
        .await?;

        let mut out = Vec::new();
        for r in rows {
            let cnt: i64 = r.try_get("cnt").unwrap_or(0);
            let host: String = r.try_get("source_host").unwrap_or_default();
            let user: String = r.try_get::<Option<String>, _>("user_name").ok().flatten().unwrap_or_else(|| "unknown".into());
            let files: Vec<String> = r.try_get("files").unwrap_or_default();
            let first = r.try_get::<chrono::DateTime<Utc>, _>("first_t").unwrap_or_else(|_| Utc::now());
            let last = r.try_get::<chrono::DateTime<Utc>, _>("last_t").unwrap_or_else(|_| Utc::now());
            out.push(Self::build_correlation(
                CorrelationType::Sequence,
                "SSH Authorized Keys Tampering",
                format!("Modifica di authorized_keys su {host} da '{user}' — possibile backdoor SSH ({cnt} eventi)"),
                Severity::High,
                Self::calculate_confidence(cnt, 1, 3),
                Self::calculate_risk_score(cnt as f64, 1.0, 3.0),
                first, last, cnt as i32,
                vec![user], vec![host], vec![], files.clone(),
                json!({ "files": files }),
                AttackStage::Persistence,
            ));
        }
        Ok(out)
    }

    /// R27 — Modifica di file di configurazione di sistema (scrittura, ≠ lettura
    /// credenziali di R12): passwd, sudoers, sshd_config, PAM, hosts, resolv.conf.
    async fn detect_system_config_tampering(&self, hours: i32) -> Result<Vec<EventCorrelation>> {
        let rows = sqlx::query(
            r#"
            SELECT source_host, user_name,
                   COUNT(*) AS cnt, MIN(timestamp) AS first_t, MAX(timestamp) AS last_t,
                   array_agg(DISTINCT file_path) FILTER (WHERE file_path IS NOT NULL) AS files
            FROM security_events
            WHERE timestamp > NOW() - INTERVAL '1 hour' * $1
              AND (file_operation IS NULL OR file_operation NOT ILIKE '%read%')
              AND (
                    file_path IN ('/etc/passwd','/etc/sudoers','/etc/ssh/sshd_config','/etc/hosts','/etc/resolv.conf')
                    OR file_path ILIKE '/etc/sudoers.d/%'
                    OR file_path ILIKE '/etc/pam.d/%'
                  )
            GROUP BY source_host, user_name
            HAVING COUNT(*) >= 1
            "#,
        )
        .bind(hours as f64)
        .fetch_all(&self.db)
        .await?;

        let mut out = Vec::new();
        for r in rows {
            let cnt: i64 = r.try_get("cnt").unwrap_or(0);
            let host: String = r.try_get("source_host").unwrap_or_default();
            let user: String = r.try_get::<Option<String>, _>("user_name").ok().flatten().unwrap_or_else(|| "unknown".into());
            let files: Vec<String> = r.try_get("files").unwrap_or_default();
            let first = r.try_get::<chrono::DateTime<Utc>, _>("first_t").unwrap_or_else(|_| Utc::now());
            let last = r.try_get::<chrono::DateTime<Utc>, _>("last_t").unwrap_or_else(|_| Utc::now());
            out.push(Self::build_correlation(
                CorrelationType::Sequence,
                "System Config Tampering",
                format!("Modifica config di sistema su {host} da '{user}': {} ({cnt} eventi)", files.join(", ")),
                Severity::High,
                Self::calculate_confidence(cnt, 1, 3),
                Self::calculate_risk_score(cnt as f64, 1.0, 4.0),
                first, last, cnt as i32,
                vec![user], vec![host], vec![], files.clone(),
                json!({ "files": files }),
                AttackStage::Persistence,
            ));
        }
        Ok(out)
    }

    /// R28 — Gestione account/gruppi (useradd/usermod/passwd/gpasswd…).
    async fn detect_account_management(&self, hours: i32) -> Result<Vec<EventCorrelation>> {
        let rows = sqlx::query(
            r#"
            SELECT source_host, user_name,
                   COUNT(*) AS cnt, MIN(timestamp) AS first_t, MAX(timestamp) AS last_t,
                   array_agg(DISTINCT process_cmdline) FILTER (WHERE process_cmdline IS NOT NULL) AS cmds
            FROM security_events
            WHERE timestamp > NOW() - INTERVAL '1 hour' * $1
              AND process_name ~* '(^|/)(useradd|usermod|userdel|adduser|deluser|groupadd|groupdel|gpasswd|chpasswd|passwd|chage)$'
            GROUP BY source_host, user_name
            HAVING COUNT(*) >= 1
            "#,
        )
        .bind(hours as f64)
        .fetch_all(&self.db)
        .await?;

        let mut out = Vec::new();
        for r in rows {
            let cnt: i64 = r.try_get("cnt").unwrap_or(0);
            let host: String = r.try_get("source_host").unwrap_or_default();
            let user: String = r.try_get::<Option<String>, _>("user_name").ok().flatten().unwrap_or_else(|| "unknown".into());
            let cmds: Vec<String> = r.try_get("cmds").unwrap_or_default();
            let first = r.try_get::<chrono::DateTime<Utc>, _>("first_t").unwrap_or_else(|_| Utc::now());
            let last = r.try_get::<chrono::DateTime<Utc>, _>("last_t").unwrap_or_else(|_| Utc::now());
            out.push(Self::build_correlation(
                CorrelationType::Sequence,
                "Account Management",
                format!("Gestione account/gruppi su {host} da '{user}' ({cnt} eventi)"),
                Severity::Medium,
                Self::calculate_confidence(cnt, 1, 3),
                Self::calculate_risk_score(cnt as f64, 1.0, 4.0),
                first, last, cnt as i32,
                vec![user], vec![host], vec![], cmds.clone(),
                json!({ "commands": cmds }),
                AttackStage::Persistence,
            ));
        }
        Ok(out)
    }

    /// R29 — Nuovo binario SUID/SGID (chmod +s / mode 4xxx-2xxx): backdoor privesc.
    async fn detect_suid_backdoor(&self, hours: i32) -> Result<Vec<EventCorrelation>> {
        let rows = sqlx::query(
            r#"
            SELECT source_host, user_name,
                   COUNT(*) AS cnt, MIN(timestamp) AS first_t, MAX(timestamp) AS last_t,
                   array_agg(DISTINCT process_cmdline) FILTER (WHERE process_cmdline IS NOT NULL) AS cmds
            FROM security_events
            WHERE timestamp > NOW() - INTERVAL '1 hour' * $1
              AND process_cmdline ~* 'chmod'
              AND process_cmdline ~* '(\+s|u\+s|g\+s|[0-7]?[2467][0-7]{3})'
            GROUP BY source_host, user_name
            HAVING COUNT(*) >= 1
            "#,
        )
        .bind(hours as f64)
        .fetch_all(&self.db)
        .await?;

        let mut out = Vec::new();
        for r in rows {
            let cnt: i64 = r.try_get("cnt").unwrap_or(0);
            let host: String = r.try_get("source_host").unwrap_or_default();
            let user: String = r.try_get::<Option<String>, _>("user_name").ok().flatten().unwrap_or_else(|| "unknown".into());
            let cmds: Vec<String> = r.try_get("cmds").unwrap_or_default();
            let first = r.try_get::<chrono::DateTime<Utc>, _>("first_t").unwrap_or_else(|_| Utc::now());
            let last = r.try_get::<chrono::DateTime<Utc>, _>("last_t").unwrap_or_else(|_| Utc::now());
            out.push(Self::build_correlation(
                CorrelationType::Sequence,
                "SUID/SGID Backdoor",
                format!("Creazione binario SUID/SGID su {host} da '{user}' — possibile backdoor privesc ({cnt} eventi)"),
                Severity::Critical,
                Self::calculate_confidence(cnt, 1, 2),
                Self::calculate_risk_score(cnt as f64, 1.0, 2.0),
                first, last, cnt as i32,
                vec![user], vec![host], vec![], cmds.clone(),
                json!({ "commands": cmds }),
                AttackStage::PrivilegeEscalation,
            ));
        }
        Ok(out)
    }

    /// R30 — Esecuzione da path world-writable (/tmp, /dev/shm, /var/tmp).
    async fn detect_world_writable_exec(&self, hours: i32) -> Result<Vec<EventCorrelation>> {
        let rows = sqlx::query(
            r#"
            SELECT source_host, user_name,
                   COUNT(*) AS cnt, MIN(timestamp) AS first_t, MAX(timestamp) AS last_t,
                   array_agg(DISTINCT process_cmdline) FILTER (WHERE process_cmdline IS NOT NULL) AS cmds
            FROM security_events
            WHERE timestamp > NOW() - INTERVAL '1 hour' * $1
              AND ( process_name ~* '^/(tmp|var/tmp|dev/shm|run/user/[0-9]+)/'
                    OR process_cmdline ~* '^/(tmp|var/tmp|dev/shm)/' )
            GROUP BY source_host, user_name
            HAVING COUNT(*) >= 1
            "#,
        )
        .bind(hours as f64)
        .fetch_all(&self.db)
        .await?;

        let mut out = Vec::new();
        for r in rows {
            let cnt: i64 = r.try_get("cnt").unwrap_or(0);
            let host: String = r.try_get("source_host").unwrap_or_default();
            let user: String = r.try_get::<Option<String>, _>("user_name").ok().flatten().unwrap_or_else(|| "unknown".into());
            let cmds: Vec<String> = r.try_get("cmds").unwrap_or_default();
            let first = r.try_get::<chrono::DateTime<Utc>, _>("first_t").unwrap_or_else(|_| Utc::now());
            let last = r.try_get::<chrono::DateTime<Utc>, _>("last_t").unwrap_or_else(|_| Utc::now());
            out.push(Self::build_correlation(
                CorrelationType::Sequence,
                "Execution From World-Writable Path",
                format!("Esecuzione da path world-writable su {host} da '{user}' ({cnt} eventi)"),
                Severity::High,
                Self::calculate_confidence(cnt, 1, 4),
                Self::calculate_risk_score(cnt as f64, 1.0, 5.0),
                first, last, cnt as i32,
                vec![user], vec![host], vec![], cmds.clone(),
                json!({ "commands": cmds }),
                AttackStage::Execution,
            ));
        }
        Ok(out)
    }

    /// R31 — Root exec anomalo: shell/tool di rete eseguiti come root da un
    /// contesto di servizio (auid non di login).
    async fn detect_anomalous_root_exec(&self, hours: i32) -> Result<Vec<EventCorrelation>> {
        let rows = sqlx::query(
            r#"
            SELECT source_host,
                   COUNT(*) AS cnt, MIN(timestamp) AS first_t, MAX(timestamp) AS last_t,
                   array_agg(DISTINCT process_cmdline) FILTER (WHERE process_cmdline IS NOT NULL) AS cmds
            FROM security_events
            WHERE timestamp > NOW() - INTERVAL '1 hour' * $1
              AND event_data->>'uid' = '0'
              AND event_data->>'auid' IN ('unset', '-1', '4294967295')
              AND process_name ~* '(^|/)(bash|sh|dash|zsh|nc|ncat|socat|python[0-9]?|perl|curl|wget)$'
            GROUP BY source_host
            HAVING COUNT(*) >= 1
            "#,
        )
        .bind(hours as f64)
        .fetch_all(&self.db)
        .await?;

        let mut out = Vec::new();
        for r in rows {
            let cnt: i64 = r.try_get("cnt").unwrap_or(0);
            let host: String = r.try_get("source_host").unwrap_or_default();
            let cmds: Vec<String> = r.try_get("cmds").unwrap_or_default();
            let first = r.try_get::<chrono::DateTime<Utc>, _>("first_t").unwrap_or_else(|_| Utc::now());
            let last = r.try_get::<chrono::DateTime<Utc>, _>("last_t").unwrap_or_else(|_| Utc::now());
            out.push(Self::build_correlation(
                CorrelationType::Sequence,
                "Anomalous Root Execution",
                format!("Shell/tool di rete eseguiti come root da contesto di servizio su {host} ({cnt} eventi)"),
                Severity::High,
                Self::calculate_confidence(cnt, 1, 4),
                Self::calculate_risk_score(cnt as f64, 1.0, 5.0),
                first, last, cnt as i32,
                vec!["root".into()], vec![host], vec![], cmds.clone(),
                json!({ "commands": cmds }),
                AttackStage::PrivilegeEscalation,
            ));
        }
        Ok(out)
    }

    /// R32 — Primo accesso mai visto di un utente su un host (baseline).
    async fn detect_first_seen_user_host(&self, hours: i32) -> Result<Vec<EventCorrelation>> {
        let rows = sqlx::query(
            r#"
            SELECT source_host, user_name,
                   COUNT(*) AS cnt, MIN(timestamp) AS first_t, MAX(timestamp) AS last_t
            FROM security_events
            WHERE event_type ILIKE '%login%' AND user_name IS NOT NULL
            GROUP BY source_host, user_name
            HAVING MIN(timestamp) > NOW() - INTERVAL '1 hour' * $1
            "#,
        )
        .bind(hours as f64)
        .fetch_all(&self.db)
        .await?;

        let mut out = Vec::new();
        for r in rows {
            let cnt: i64 = r.try_get("cnt").unwrap_or(0);
            let host: String = r.try_get("source_host").unwrap_or_default();
            let user: String = r.try_get::<Option<String>, _>("user_name").ok().flatten().unwrap_or_else(|| "unknown".into());
            let first = r.try_get::<chrono::DateTime<Utc>, _>("first_t").unwrap_or_else(|_| Utc::now());
            let last = r.try_get::<chrono::DateTime<Utc>, _>("last_t").unwrap_or_else(|_| Utc::now());
            out.push(Self::build_correlation(
                CorrelationType::Sequence,
                "First-Seen User On Host",
                format!("Primo accesso mai osservato di '{user}' su {host}"),
                Severity::Medium,
                0.6,
                45.0,
                first, last, cnt as i32,
                vec![user], vec![host], vec![], vec![],
                json!({ "reason": "first_seen_user_host" }),
                AttackStage::InitialAccess,
            ));
        }
        Ok(out)
    }

    /// R33 — Sorgente SSH inedita per un utente (baseline).
    async fn detect_new_login_source(&self, hours: i32) -> Result<Vec<EventCorrelation>> {
        let rows = sqlx::query(
            r#"
            SELECT user_name, host(source_ip) AS ip,
                   COUNT(*) AS cnt, MIN(timestamp) AS first_t, MAX(timestamp) AS last_t,
                   array_agg(DISTINCT source_host) FILTER (WHERE source_host IS NOT NULL) AS hosts
            FROM security_events
            WHERE event_type ILIKE '%login%' AND source_ip IS NOT NULL AND user_name IS NOT NULL
            GROUP BY user_name, host(source_ip)
            HAVING MIN(timestamp) > NOW() - INTERVAL '1 hour' * $1
            "#,
        )
        .bind(hours as f64)
        .fetch_all(&self.db)
        .await?;

        let mut out = Vec::new();
        for r in rows {
            let cnt: i64 = r.try_get("cnt").unwrap_or(0);
            let user: String = r.try_get::<Option<String>, _>("user_name").ok().flatten().unwrap_or_else(|| "unknown".into());
            let ip: String = r.try_get::<Option<String>, _>("ip").ok().flatten().unwrap_or_default();
            let hosts: Vec<String> = r.try_get("hosts").unwrap_or_default();
            let first = r.try_get::<chrono::DateTime<Utc>, _>("first_t").unwrap_or_else(|_| Utc::now());
            let last = r.try_get::<chrono::DateTime<Utc>, _>("last_t").unwrap_or_else(|_| Utc::now());
            out.push(Self::build_correlation(
                CorrelationType::Sequence,
                "New Login Source",
                format!("Nuova sorgente di login {ip} per l'utente '{user}'"),
                Severity::Medium,
                0.6,
                45.0,
                first, last, cnt as i32,
                vec![user], hosts, vec![], vec![],
                json!({ "source_ip": ip, "reason": "new_login_source" }),
                AttackStage::InitialAccess,
            ));
        }
        Ok(out)
    }

    /// R34 — Shell avviata da account di servizio (webshell/RCE: es. www-data→bash).
    async fn detect_service_shell(&self, hours: i32) -> Result<Vec<EventCorrelation>> {
        let rows = sqlx::query(
            r#"
            SELECT source_host, user_name,
                   COUNT(*) AS cnt, MIN(timestamp) AS first_t, MAX(timestamp) AS last_t,
                   array_agg(DISTINCT process_cmdline) FILTER (WHERE process_cmdline IS NOT NULL) AS cmds
            FROM security_events
            WHERE timestamp > NOW() - INTERVAL '1 hour' * $1
              AND process_name ~* '(^|/)(bash|sh|dash|zsh)$'
              AND user_name IN ('www-data','nginx','apache','apache2','httpd','postgres','mysql','mariadb','redis','tomcat','node','mongodb')
            GROUP BY source_host, user_name
            HAVING COUNT(*) >= 1
            "#,
        )
        .bind(hours as f64)
        .fetch_all(&self.db)
        .await?;

        let mut out = Vec::new();
        for r in rows {
            let cnt: i64 = r.try_get("cnt").unwrap_or(0);
            let host: String = r.try_get("source_host").unwrap_or_default();
            let user: String = r.try_get::<Option<String>, _>("user_name").ok().flatten().unwrap_or_else(|| "unknown".into());
            let cmds: Vec<String> = r.try_get("cmds").unwrap_or_default();
            let first = r.try_get::<chrono::DateTime<Utc>, _>("first_t").unwrap_or_else(|_| Utc::now());
            let last = r.try_get::<chrono::DateTime<Utc>, _>("last_t").unwrap_or_else(|_| Utc::now());
            out.push(Self::build_correlation(
                CorrelationType::Sequence,
                "Service Account Shell",
                format!("Shell avviata dall'account di servizio '{user}' su {host} — possibile webshell/RCE ({cnt} eventi)"),
                Severity::Critical,
                Self::calculate_confidence(cnt, 1, 3),
                Self::calculate_risk_score(cnt as f64, 1.0, 3.0),
                first, last, cnt as i32,
                vec![user], vec![host], vec![], cmds.clone(),
                json!({ "commands": cmds }),
                AttackStage::Execution,
            ));
        }
        Ok(out)
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

    /// R16 — **Root Asset / Credential Discovery** (T1083/T1552).
    /// Colma un gap emerso dal purple-team: la ricognizione post-exploit usa
    /// `find`/`ls`/`grep`/`locate` per cercare SUID, file di root, chiavi SSH e
    /// credenziali. Presi singolarmente sono comandi innocui (R13 guarda solo
    /// whoami/id/uname…), ma una raffica di queste ricerche nella stessa sessione
    /// è un chiaro segnale di attaccante che mappa privesc/credenziali.
    async fn detect_root_asset_discovery(&self, hours: i32) -> Result<Vec<EventCorrelation>> {
        let rows = sqlx::query!(
            r#"
            SELECT source_host, user_name,
                   COUNT(*) as cnt, MIN(timestamp) as first_t, MAX(timestamp) as last_t,
                   array_agg(DISTINCT process_cmdline) FILTER (WHERE process_cmdline IS NOT NULL) as cmds
            FROM security_events
            WHERE timestamp > NOW() - INTERVAL '1 hour' * $1
              AND process_cmdline ~* '(-perm[[:space:]]+-?[0-7]*(4000|2000|6000)|-user[[:space:]]+root|-name[[:space:]]+.*(id_rsa|id_ed25519|id_dsa|authorized_keys|\.pem|\.key|\.pgpass|shadow|\.kube|\.aws)|(^|/)(ls|find|cat|grep)[[:space:]].*(/root/|/etc/ssh/|\.ssh/|history)|grep[[:space:]].*(password|passwd|secret|token|api[_-]?key))'
            GROUP BY source_host, user_name
            HAVING COUNT(*) >= 3
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
                CorrelationType::Frequency,
                "Root Asset Discovery",
                format!(
                    "Enumerazione di asset privilegiati/credenziali ({cnt} ricerche) su {host} da '{user}'"
                ),
                Severity::High,
                Self::calculate_confidence(cnt as i64, 3, 12),
                Self::calculate_risk_score(cnt as f64, 3.0, 12.0),
                r.first_t.unwrap(),
                r.last_t.unwrap(),
                cnt as i32,
                vec![user],
                vec![host],
                vec![],
                vec![],
                json!({ "discovery_commands": cmds }),
                AttackStage::Discovery,
            ));
        }
        Ok(out)
    }

    /// R17 — **io_uring Audit Evasion** (T1562, Impair Defenses).
    /// io_uring esegue open/read/connect in contesto worker del kernel, aggirando
    /// sia i watch auditd basati su inode sia l'auditing dei syscall: nel lab una
    /// lettura di `/etc/shadow` via io_uring ha prodotto **zero** record. La difesa
    /// è auditare la syscall `io_uring_setup` (regola `-k io_uring`): il suo uso da
    /// parte di un processo non atteso è un forte indicatore di tentata evasione.
    /// Richiede la regola audit `-S io_uring_setup` sul target (deploy/audit).
    async fn detect_io_uring_evasion(&self, hours: i32) -> Result<Vec<EventCorrelation>> {
        let rows = sqlx::query!(
            r#"
            SELECT source_host, user_name, process_name,
                   COUNT(*) as cnt, MIN(timestamp) as first_t, MAX(timestamp) as last_t
            FROM security_events
            WHERE timestamp > NOW() - INTERVAL '1 hour' * $1
              AND (event_action = 'io_uring_setup'
                   OR event_data->>'syscall' = 'io_uring_setup'
                   OR event_data->>'key' ILIKE '%io_uring%')
              -- allowlist processi legittimi che usano io_uring (estendibile)
              AND COALESCE(process_name,'') !~* '(/usr/lib/|/usr/sbin/(mariadbd|mysqld|nginx|redis-server))'
            GROUP BY source_host, user_name, process_name
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
            let proc = r.process_name.unwrap_or_else(|| "unknown".into());
            out.push(Self::build_correlation(
                CorrelationType::Anomaly,
                "io_uring Audit Evasion",
                format!(
                    "Uso di io_uring da '{proc}' su {host} (utente '{user}') — potenziale evasione del monitoraggio auditd"
                ),
                Severity::High,
                0.8,
                80.0,
                r.first_t.unwrap(),
                r.last_t.unwrap(),
                cnt as i32,
                vec![user],
                vec![host],
                vec![],
                vec![proc],
                json!({ "note": "io_uring bypassa i watch inode e l'auditing syscall; verificare l'attività del processo" }),
                AttackStage::DefenseEvasion,
            ));
        }
        Ok(out)
    }

    /// R18 — **Sensor Silence** (T1562, Impair Defenses).
    /// Purple-team: uccidere il processo Laurel è inefficace (auditd lo respawna),
    /// ma un attaccante root può fermare auditd o disabilitare il plugin: nessun
    /// record locale lo segnala ("dead men tell no tales"). Difesa **server-side**:
    /// se un target ha l'agent connesso e vivo (metriche recenti) ma i suoi
    /// `security_events` si sono zittiti da oltre la soglia, è un forte segnale di
    /// manomissione del sensore. Threshold intenzionalmente conservativo per non
    /// generare falsi positivi su host poco attivi.
    async fn detect_sensor_silence(&self, _hours: i32) -> Result<Vec<EventCorrelation>> {
        let rows = sqlx::query!(
            r#"
            SELECT t.hostname, MAX(se.timestamp) as last_event
            FROM targets t
            JOIN security_events se ON se.target_id = t.id
            WHERE t.agent_connected = true
              AND t.agent_last_seen > NOW() - INTERVAL '5 minutes'
            GROUP BY t.hostname
            HAVING MAX(se.timestamp) < NOW() - INTERVAL '10 minutes'
            "#
        )
        .fetch_all(&self.db)
        .await?;

        let mut out = Vec::new();
        for r in rows {
            let host = r.hostname;
            let last = r.last_event.unwrap_or_else(Utc::now);
            out.push(Self::build_correlation(
                CorrelationType::Anomaly,
                "Sensor Silence",
                format!(
                    "Il target {host} ha l'agent vivo ma nessun evento di sicurezza da >10min — possibile stop di auditd/Laurel"
                ),
                Severity::Critical,
                0.85,
                85.0,
                last,
                Utc::now(),
                1,
                vec![],
                vec![host],
                vec![],
                vec![],
                json!({ "note": "agent connesso e metriche attive, ma pipeline eventi ferma", "last_event": last.to_rfc3339() }),
                AttackStage::DefenseEvasion,
            ));
        }
        Ok(out)
    }

    /// R20 — **Fileless Execution** (T1620, Reflective Code Loading).
    /// Esecuzione da memoria (`memfd_create`+exec) o da binario cancellato: l'`exe`
    /// riportato da auditd/Laurel è `/memfd:...(deleted)` o `.../(deleted)`, indizio
    /// forte di loader in-memory / anti-forense. Richiede l'audit di `execveat`
    /// (aggiunto in deploy/audit), altrimenti la variante memfd+execveat sfugge.
    async fn detect_fileless_execution(&self, hours: i32) -> Result<Vec<EventCorrelation>> {
        let rows = sqlx::query!(
            r#"
            SELECT source_host, user_name, process_name,
                   COUNT(*) as cnt, MIN(timestamp) as first_t, MAX(timestamp) as last_t
            FROM security_events
            WHERE timestamp > NOW() - INTERVAL '1 hour' * $1
              AND (process_name ILIKE '%memfd:%' OR process_name ILIKE '%(deleted)%')
            GROUP BY source_host, user_name, process_name
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
            let proc = r.process_name.unwrap_or_else(|| "unknown".into());
            out.push(Self::build_correlation(
                CorrelationType::Anomaly,
                "Fileless Execution",
                format!("Esecuzione fileless/da binario cancellato ('{proc}') su {host} da '{user}'"),
                Severity::High,
                0.8,
                78.0,
                r.first_t.unwrap(),
                r.last_t.unwrap(),
                cnt as i32,
                vec![user],
                vec![host],
                vec![],
                vec![proc],
                json!({ "note": "exe in memoria (memfd) o binario cancellato — possibile loader in-memory" }),
                AttackStage::Execution,
            ));
        }
        Ok(out)
    }

    /// R21 — **eBPF Credential Access** (T1003).
    /// Alimentato dal sensore eBPF opt-in (hook LSM `security_file_open`): cattura
    /// l'apertura di file credenziali (`shadow`, chiavi SSH, `.pgpass`, `sudoers`)
    /// **a livello kernel**, quindi anche quando avviene via **io_uring** o da
    /// **root/daemon** — i due punti ciechi di auditd/Laurel (R12/R17). Esclude i
    /// lettori legittimi del PAM/stack di sistema per ridurre il rumore.
    async fn detect_ebpf_credential_access(&self, hours: i32) -> Result<Vec<EventCorrelation>> {
        let rows = sqlx::query!(
            r#"
            SELECT source_host, user_name, process_name, target_id,
                   COUNT(*) as cnt, MIN(timestamp) as first_t, MAX(timestamp) as last_t,
                   array_agg(DISTINCT file_path) FILTER (WHERE file_path IS NOT NULL) as files
            FROM security_events
            WHERE timestamp > NOW() - INTERVAL '1 hour' * $1
              AND event_type = 'EBPF_CRED_ACCESS'
              AND COALESCE(process_name,'') !~* '(unix_chkpwd|sshd|^login$|^su$|^sudo$|passwd|systemd|pam|useradd|usermod|chpasswd|newgrp|gpasswd|vipw|cron|agetty|nscd|sssd)'
            GROUP BY source_host, user_name, process_name, target_id
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
            let proc = r.process_name.unwrap_or_else(|| "unknown".into());
            let files = r.files.unwrap_or_default();
            out.push(Self::build_correlation(
                CorrelationType::Anomaly,
                "eBPF Credential Access",
                format!(
                    "Accesso a file credenziali da '{proc}' su {host} (utente '{user}') rilevato dal sensore eBPF — resistente a evasione io_uring/root"
                ),
                Severity::Critical,
                0.9,
                88.0,
                r.first_t.unwrap(),
                r.last_t.unwrap(),
                cnt as i32,
                vec![user],
                vec![host],
                vec![],
                vec![proc],
                json!({ "sensor": "ebpf", "files": files, "note": "hook LSM security_file_open: cattura anche io_uring e processi root che auditd non vede" }),
                AttackStage::CredentialAccess,
            ));
        }
        Ok(out)
    }

    /// R22 — **Process Injection via ptrace** (T1055).
    /// Sensore eBPF (`security_ptrace_access_check`): un processo che si aggancia a
    /// un altro via ptrace/`process_vm_writev` è un classico di injection/masquerading
    /// (l'attività malevola appare sotto l'identità della vittima). Esclude i debugger
    /// noti per ridurre il rumore.
    async fn detect_ptrace_injection(&self, hours: i32) -> Result<Vec<EventCorrelation>> {
        let rows = sqlx::query!(
            r#"
            SELECT source_host, user_name, process_name, target_id,
                   COUNT(*) as cnt, MIN(timestamp) as first_t, MAX(timestamp) as last_t
            FROM security_events
            WHERE timestamp > NOW() - INTERVAL '1 hour' * $1
              AND event_type = 'EBPF_PTRACE'
              AND COALESCE(process_name,'') !~* '(^gdb$|^strace$|^ltrace$|^lldb$|^perf$|^dpkg|^systemd)'
            GROUP BY source_host, user_name, process_name, target_id
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
            let proc = r.process_name.unwrap_or_else(|| "unknown".into());
            out.push(Self::build_correlation(
                CorrelationType::Anomaly,
                "Process Injection (ptrace)",
                format!("Aggancio ptrace da '{proc}' su {host} (utente '{user}') — possibile code injection"),
                Severity::High,
                0.75,
                75.0,
                r.first_t.unwrap(),
                r.last_t.unwrap(),
                cnt as i32,
                vec![user],
                vec![host],
                vec![],
                vec![proc],
                json!({ "sensor": "ebpf", "note": "security_ptrace_access_check" }),
                AttackStage::DefenseEvasion,
            ));
        }
        Ok(out)
    }

    /// R23 — **Network Sweep** (T1046 / T1018).
    /// Ricognizione di rete: raffica di `ping`/`fping` (host sweep) o presenza di uno
    /// scanner (`nmap`/`masscan`/`zmap`/`hping`). Colma il gap del purple-team dove il
    /// ping-sweep veniva registrato ma non elevato.
    async fn detect_network_sweep(&self, hours: i32) -> Result<Vec<EventCorrelation>> {
        let rows = sqlx::query!(
            r#"
            SELECT source_host, user_name, target_id,
                   COUNT(*) as cnt, MIN(timestamp) as first_t, MAX(timestamp) as last_t,
                   array_agg(DISTINCT process_name) FILTER (WHERE process_name IS NOT NULL) as procs
            FROM security_events
            WHERE timestamp > NOW() - INTERVAL '1 hour' * $1
              AND process_name ~* '(^|/)(ping|fping|nmap|masscan|zmap|hping3?|arp-scan|ncat)$'
            GROUP BY source_host, user_name, target_id
            HAVING COUNT(*) >= 5 OR bool_or(process_name ~* '(nmap|masscan|zmap|hping)')
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
            let procs = r.procs.unwrap_or_default();
            out.push(Self::build_correlation(
                CorrelationType::Frequency,
                "Network Sweep",
                format!("Ricognizione di rete ({cnt} sonde) su {host} da '{user}'"),
                Severity::Medium,
                Self::calculate_confidence(cnt, 5, 30),
                Self::calculate_risk_score(cnt as f64, 5.0, 30.0),
                r.first_t.unwrap(),
                r.last_t.unwrap(),
                cnt as i32,
                vec![user],
                vec![host],
                vec![],
                procs,
                json!({ "note": "ping/port sweep o scanner di rete" }),
                AttackStage::Discovery,
            ));
        }
        Ok(out)
    }

    /// R24 — **Dynamic Linker Hijack via LD_PRELOAD** (T1574.006).
    /// Un `LD_PRELOAD` verso un percorso assoluto in un execve è un classico di
    /// hijack del linker / persistenza / evasione. Laurel cattura la env (config
    /// `execve-env`); qui si eleva quando LD_PRELOAD punta a un file.
    async fn detect_ld_preload(&self, hours: i32) -> Result<Vec<EventCorrelation>> {
        let rows = sqlx::query!(
            r#"
            SELECT source_host, user_name, process_name, target_id,
                   COUNT(*) as cnt, MIN(timestamp) as first_t, MAX(timestamp) as last_t
            FROM security_events
            WHERE timestamp > NOW() - INTERVAL '1 hour' * $1
              AND event_data::text ~ 'LD_PRELOAD.{0,4}/'
            GROUP BY source_host, user_name, process_name, target_id
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
            let proc = r.process_name.unwrap_or_else(|| "unknown".into());
            out.push(Self::build_correlation(
                CorrelationType::Anomaly,
                "Dynamic Linker Hijack",
                format!("LD_PRELOAD verso file impostato per '{proc}' su {host} (utente '{user}') — possibile hijack del linker"),
                Severity::High,
                0.8,
                76.0,
                r.first_t.unwrap(),
                r.last_t.unwrap(),
                cnt as i32,
                vec![user],
                vec![host],
                vec![],
                vec![proc],
                json!({ "note": "LD_PRELOAD verso percorso file in execve (T1574.006)" }),
                AttackStage::DefenseEvasion,
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

    /// R10 — Reverse shell: un'esecuzione sospetta (nc/bash -i//dev/tcp/python -c)
    /// **accompagnata** da una connessione di rete in uscita dallo stesso host in
    /// ~2 minuti. Segnale forte di C2, più specifico di R6 (solo exec).
    async fn detect_reverse_shell(&self, hours: i32) -> Result<Vec<EventCorrelation>> {
        let rows = sqlx::query!(
            r#"
            SELECT e.source_host, e.user_name,
                   COUNT(*) as cnt, MIN(e.timestamp) as first_t, MAX(e.timestamp) as last_t,
                   array_agg(DISTINCT e.process_cmdline) FILTER (WHERE e.process_cmdline IS NOT NULL) as cmds,
                   array_agg(DISTINCT host(n.destination_ip)) FILTER (WHERE n.destination_ip IS NOT NULL) as dests
            FROM security_events e
            JOIN security_events n
              ON n.source_host = e.source_host
             AND n.event_category = 'network'
             AND n.destination_ip IS NOT NULL
             AND n.timestamp BETWEEN e.timestamp - INTERVAL '2 minutes'
                                 AND e.timestamp + INTERVAL '2 minutes'
            WHERE e.timestamp > NOW() - INTERVAL '1 hour' * $1
              AND (
                  e.process_name ~* '(^|/)(nc|ncat|socat)$'
                  OR e.process_cmdline ~* '(bash|sh)[[:space:]]+-i'
                  OR e.process_cmdline ~* '/dev/tcp/'
                  OR e.process_cmdline ~* 'python[0-9]?[[:space:]]+-c'
              )
            GROUP BY e.source_host, e.user_name
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
            let dests = r.dests.unwrap_or_default();
            out.push(Self::build_correlation(
                CorrelationType::Sequence,
                "Reverse Shell",
                format!("Reverse shell su {host} da '{user}': exec sospetta + connessione in uscita"),
                Severity::Critical,
                Self::calculate_confidence(cnt, 1, 5),
                Self::calculate_risk_score(cnt as f64, 1.0, 5.0),
                r.first_t.unwrap(),
                r.last_t.unwrap(),
                cnt as i32,
                vec![user],
                vec![host],
                vec![],
                cmds.clone(),
                json!({ "commands": cmds, "destinations": dests }),
                AttackStage::CommandAndControl,
            ));
        }
        Ok(out)
    }

    /// Save correlation to database
    async fn save_correlation(&self, correlation: &EventCorrelation) -> Result<()> {
        // Guard "firma-occorrenza": le correlazioni sono una HISTORY degli
        // accadimenti (non idempotenti), ma l'analisi automatica ri-scansiona
        // periodicamente la stessa finestra. Per non ri-registrare lo STESSO
        // burst ad ogni giro, saltiamo l'inserimento se esiste già una
        // correlazione identica con lo stesso last_event_time (stessa tattica,
        // pattern, host e utenti). Un'occorrenza NUOVA ha eventi più recenti →
        // last_event_time diverso → nuova riga. Nessuna cache sqlx: query runtime.
        let already: Option<i32> = sqlx::query_scalar(
            r#"
            SELECT 1 FROM event_correlations
            WHERE correlation_type = $1
              AND coalesce(attack_stage::text, '') = coalesce($2::text, '')
              AND coalesce(pattern_name::text, '') = coalesce($3::text, '')
              AND last_event_time = $4
              AND involved_hosts = $5
              AND involved_users = $6
            LIMIT 1
            "#,
        )
        .bind(correlation.correlation_type.to_string())
        .bind(correlation.attack_stage.as_ref().map(|s| s.to_string()))
        .bind(&correlation.pattern_name)
        .bind(correlation.last_event_time)
        .bind(&correlation.involved_hosts)
        .bind(&correlation.involved_users)
        .fetch_optional(&self.db)
        .await?;
        if already.is_some() {
            return Ok(()); // stessa occorrenza già registrata: non duplicare
        }

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
