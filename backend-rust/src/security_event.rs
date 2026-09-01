// ============================================================================
// Security Event Models - Event Correlation System
// ============================================================================

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::net::IpAddr;
use uuid::Uuid;

/// Security event from various sources (auditd, SNMP, IDS/IPS)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub id: Option<i64>,
    /// Target (asset) da cui proviene l'evento, noto in fase di ingest agent.
    pub target_id: Option<i32>,
    pub timestamp: DateTime<Utc>,

    // Source
    pub source_type: SourceType,
    pub source_host: String,
    pub source_ip: Option<IpAddr>,
    pub source_port: Option<i32>,

    // Classification
    pub event_type: String,
    pub event_category: EventCategory,
    pub event_action: Option<String>,
    pub severity: Severity,

    // User/Process
    pub user_name: Option<String>,
    pub user_id: Option<i32>,
    pub process_name: Option<String>,
    pub process_pid: Option<i32>,
    pub process_ppid: Option<i32>,
    pub process_cmdline: Option<String>,

    // File/Resource
    pub file_path: Option<String>,
    pub file_operation: Option<String>,

    // Network
    pub destination_ip: Option<IpAddr>,
    pub destination_port: Option<i32>,
    pub destination_host: Option<String>,
    pub protocol: Option<String>,
    pub bytes_sent: Option<i64>,
    pub bytes_received: Option<i64>,

    // Event data
    pub event_data: Option<JsonValue>,
    pub normalized_data: Option<JsonValue>,

    // Enrichment
    pub geo_country: Option<String>,
    pub geo_city: Option<String>,
    pub asset_criticality: Option<i32>,
    pub threat_score: Option<f64>,

    // MITRE ATT&CK (tattica = vocabolario attack_stage; tecnica = T1xxx)
    pub mitre_tactic: Option<String>,
    pub mitre_technique: Option<String>,

    // Correlation
    pub correlation_id: Option<Uuid>,
    pub parent_event_id: Option<i64>,
    pub sequence_number: Option<i32>,

    // Metadata
    pub ingestion_time: DateTime<Utc>,
    pub processed: bool,
    pub anomaly_score: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "varchar")]
pub enum SourceType {
    // NB: sqlx::Type ignora #[serde(rename)] → servono anche i #[sqlx(rename)],
    // altrimenti la decodifica si aspetta il nome variante ("Auditd") mentre in
    // DB è memorizzato il valore minuscolo (da Display all'insert).
    #[serde(rename = "auditd")]
    #[sqlx(rename = "auditd")]
    Auditd,
    #[serde(rename = "snmp")]
    #[sqlx(rename = "snmp")]
    Snmp,
    #[serde(rename = "syslog")]
    #[sqlx(rename = "syslog")]
    Syslog,
    #[serde(rename = "ids")]
    #[sqlx(rename = "ids")]
    Ids,
    #[serde(rename = "ips")]
    #[sqlx(rename = "ips")]
    Ips,
    #[serde(rename = "firewall")]
    #[sqlx(rename = "firewall")]
    Firewall,
}

impl std::fmt::Display for SourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            SourceType::Auditd => write!(f, "auditd"),
            SourceType::Snmp => write!(f, "snmp"),
            SourceType::Syslog => write!(f, "syslog"),
            SourceType::Ids => write!(f, "ids"),
            SourceType::Ips => write!(f, "ips"),
            SourceType::Firewall => write!(f, "firewall"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "varchar")]
pub enum EventCategory {
    #[serde(rename = "authentication")]
    #[sqlx(rename = "authentication")]
    Authentication,
    #[serde(rename = "authorization")]
    #[sqlx(rename = "authorization")]
    Authorization,
    #[serde(rename = "data_access")]
    #[sqlx(rename = "data_access")]
    DataAccess,
    #[serde(rename = "network")]
    #[sqlx(rename = "network")]
    Network,
    #[serde(rename = "system")]
    #[sqlx(rename = "system")]
    System,
}

impl std::fmt::Display for EventCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            EventCategory::Authentication => write!(f, "authentication"),
            EventCategory::Authorization => write!(f, "authorization"),
            EventCategory::DataAccess => write!(f, "data_access"),
            EventCategory::Network => write!(f, "network"),
            EventCategory::System => write!(f, "system"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type, PartialEq, Eq, PartialOrd, Ord)]
#[sqlx(type_name = "varchar")]
pub enum Severity {
    #[serde(rename = "critical")]
    #[sqlx(rename = "critical")]
    Critical,
    #[serde(rename = "high")]
    #[sqlx(rename = "high")]
    High,
    #[serde(rename = "medium")]
    #[sqlx(rename = "medium")]
    Medium,
    #[serde(rename = "low")]
    #[sqlx(rename = "low")]
    Low,
    #[serde(rename = "info")]
    #[sqlx(rename = "info")]
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "critical"),
            Severity::High => write!(f, "high"),
            Severity::Medium => write!(f, "medium"),
            Severity::Low => write!(f, "low"),
            Severity::Info => write!(f, "info"),
        }
    }
}

/// Event Correlation - detected patterns and anomalies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventCorrelation {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,

    // Type and pattern
    pub correlation_type: CorrelationType,
    pub pattern_name: Option<String>,
    pub pattern_description: Option<String>,

    // Confidence and severity
    pub confidence: f64, // 0.0 - 1.0
    pub severity: Severity,
    pub risk_score: Option<f64>, // 0-100

    // Time window
    pub first_event_time: DateTime<Utc>,
    pub last_event_time: DateTime<Utc>,
    pub time_window_seconds: Option<i32>,
    pub event_count: i32,

    // Involved entities
    pub involved_users: Vec<String>,
    pub involved_hosts: Vec<String>,
    pub involved_ips: Vec<IpAddr>,
    pub involved_processes: Vec<String>,

    // Statistical analysis
    pub statistical_significance: Option<f64>,
    pub anomaly_score: Option<f64>,
    pub z_score: Option<f64>,
    pub baseline_deviation_percent: Option<f64>,

    // Correlation data
    pub correlation_data: Option<JsonValue>,

    // Attack stage
    pub attack_stage: Option<AttackStage>,

    // Status
    pub status: CorrelationStatus,
    pub resolved_at: Option<DateTime<Utc>>,
    pub resolution_notes: Option<String>,

    // Assignment
    pub assigned_to: Option<String>,
    pub assigned_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "varchar")]
pub enum CorrelationType {
    #[serde(rename = "sequence")]
    Sequence,
    #[serde(rename = "frequency")]
    Frequency,
    #[serde(rename = "anomaly")]
    Anomaly,
    #[serde(rename = "lateral_movement")]
    LateralMovement,
    #[serde(rename = "data_exfiltration")]
    DataExfiltration,
}

impl std::fmt::Display for CorrelationType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CorrelationType::Sequence => write!(f, "sequence"),
            CorrelationType::Frequency => write!(f, "frequency"),
            CorrelationType::Anomaly => write!(f, "anomaly"),
            CorrelationType::LateralMovement => write!(f, "lateral_movement"),
            CorrelationType::DataExfiltration => write!(f, "data_exfiltration"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "varchar")]
pub enum AttackStage {
    #[serde(rename = "reconnaissance")]
    Reconnaissance,
    #[serde(rename = "initial_access")]
    InitialAccess,
    #[serde(rename = "execution")]
    Execution,
    #[serde(rename = "persistence")]
    Persistence,
    #[serde(rename = "privilege_escalation")]
    PrivilegeEscalation,
    #[serde(rename = "credential_access")]
    CredentialAccess,
    #[serde(rename = "lateral_movement")]
    LateralMovement,
    #[serde(rename = "collection")]
    Collection,
    #[serde(rename = "exfiltration")]
    Exfiltration,
    #[serde(rename = "defense_evasion")]
    DefenseEvasion,
    #[serde(rename = "discovery")]
    Discovery,
    #[serde(rename = "command_and_control")]
    CommandAndControl,
    #[serde(rename = "impact")]
    Impact,
}

impl std::fmt::Display for AttackStage {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            AttackStage::Reconnaissance => write!(f, "reconnaissance"),
            AttackStage::InitialAccess => write!(f, "initial_access"),
            AttackStage::Execution => write!(f, "execution"),
            AttackStage::Persistence => write!(f, "persistence"),
            AttackStage::PrivilegeEscalation => write!(f, "privilege_escalation"),
            AttackStage::CredentialAccess => write!(f, "credential_access"),
            AttackStage::LateralMovement => write!(f, "lateral_movement"),
            AttackStage::Collection => write!(f, "collection"),
            AttackStage::Exfiltration => write!(f, "exfiltration"),
            AttackStage::DefenseEvasion => write!(f, "defense_evasion"),
            AttackStage::Discovery => write!(f, "discovery"),
            AttackStage::CommandAndControl => write!(f, "command_and_control"),
            AttackStage::Impact => write!(f, "impact"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "varchar")]
pub enum CorrelationStatus {
    #[serde(rename = "active")]
    Active,
    #[serde(rename = "investigating")]
    Investigating,
    #[serde(rename = "resolved")]
    Resolved,
    #[serde(rename = "false_positive")]
    FalsePositive,
}

impl std::fmt::Display for CorrelationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CorrelationStatus::Active => write!(f, "active"),
            CorrelationStatus::Investigating => write!(f, "investigating"),
            CorrelationStatus::Resolved => write!(f, "resolved"),
            CorrelationStatus::FalsePositive => write!(f, "false_positive"),
        }
    }
}

/// Lateral Movement Prediction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LateralMovementPrediction {
    pub id: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub correlation_id: Option<Uuid>,

    // Current state
    pub current_compromised_host: String,
    pub current_compromised_user: Option<String>,
    pub current_attack_stage: Option<String>,

    // Predictions
    pub predictions: JsonValue, // Array of prediction objects

    // Model
    pub model_name: String,
    pub model_version: Option<String>,
    pub model_confidence: Option<f64>,

    // Validation
    pub actual_outcome: Option<String>,
    pub outcome_timestamp: Option<DateTime<Utc>>,
    pub prediction_accuracy: Option<f64>,

    // Status
    pub status: String,
    pub expires_at: Option<DateTime<Utc>>,

    // Actions
    pub actions_taken: Vec<String>,
    pub actions_timestamp: Option<DateTime<Utc>>,
}

/// User Behavior Baseline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserBehaviorBaseline {
    pub user_name: String,

    // Login patterns
    pub avg_logins_per_day: Option<f64>,
    pub stddev_logins_per_day: Option<f64>,
    pub typical_login_hours: Vec<i32>,
    pub typical_login_hosts: Vec<String>,

    // Session patterns
    pub avg_session_duration_minutes: Option<f64>,
    pub stddev_session_duration_minutes: Option<f64>,
    pub avg_commands_per_session: Option<f64>,
    pub common_commands: Vec<String>,

    // Activity patterns
    pub typical_file_paths: Vec<String>,
    pub typical_processes: Vec<String>,
    pub avg_network_connections_per_day: Option<f64>,

    // Thresholds
    pub login_count_threshold_high: Option<f64>,
    pub session_duration_threshold_high: Option<f64>,
    pub command_count_threshold_high: Option<f64>,

    // Metadata
    pub events_analyzed: i32,
    pub last_updated: DateTime<Utc>,

    // Anomaly tracking
    pub anomaly_count_7d: i32,
    pub anomaly_count_30d: i32,
    pub last_anomaly_at: Option<DateTime<Utc>>,
}

/// Host Behavior Baseline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostBehaviorBaseline {
    pub host_name: String,

    // Process patterns
    pub typical_processes: Vec<String>,
    pub avg_cpu_percent: Option<f64>,
    pub avg_memory_mb: Option<f64>,

    // Network patterns
    pub avg_connections_per_hour: Option<f64>,
    pub stddev_connections_per_hour: Option<f64>,
    pub typical_listening_ports: Vec<i32>,
    pub avg_bandwidth_mbps: Option<f64>,

    // File patterns
    pub typical_file_modifications_per_hour: Option<f64>,
    pub critical_file_paths: Vec<String>,

    // User patterns
    pub typical_users: Vec<String>,
    pub avg_user_sessions_per_day: Option<f64>,

    // Service patterns
    pub expected_services: Vec<String>,

    // Thresholds
    pub connection_count_threshold_high: Option<f64>,
    pub process_count_threshold_high: Option<i32>,
    pub bandwidth_threshold_high_mbps: Option<f64>,

    // Metadata
    pub events_analyzed: i32,
    pub last_updated: DateTime<Utc>,
    pub asset_criticality: i32,
    pub is_server: bool,

    // Anomaly tracking
    pub anomaly_count_7d: i32,
    pub anomaly_count_30d: i32,
    pub last_anomaly_at: Option<DateTime<Utc>>,
}

/// Host Risk Score
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostRiskScore {
    pub host_name: String,

    // Risk components
    pub anomaly_risk: f64,
    pub vulnerability_risk: f64,
    pub compliance_risk: f64,
    pub threat_risk: f64,

    // Overall
    pub total_risk_score: f64,
    pub risk_level: String,

    // Contributing factors
    pub active_alerts: i32,
    pub critical_alerts: i32,
    pub failed_compliance_controls: i32,
    pub known_vulnerabilities: i32,

    // Compromise indicators
    pub compromise_probability: f64,
    pub compromise_indicators: Vec<String>,

    // Timestamps
    pub last_calculated: DateTime<Utc>,
    pub last_incident: Option<DateTime<Utc>>,

    // Asset
    pub asset_criticality: i32,
    pub is_critical_asset: bool,
}

/// Anomaly Detection Result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyDetectionResult {
    pub is_anomaly: bool,
    pub anomaly_score: f64,
    pub z_score: f64,
    pub severity: Severity,
    pub description: String,
    pub baseline_value: Option<f64>,
    pub observed_value: f64,
    pub deviation_percent: Option<f64>,
}

/// Statistical Baseline Calculation Result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineCalculationResult {
    pub mean: f64,
    pub stddev: f64,
    pub median: Option<f64>,
    pub min: f64,
    pub max: f64,
    pub count: usize,
    pub threshold_low: f64,
    pub threshold_high: f64,
}
