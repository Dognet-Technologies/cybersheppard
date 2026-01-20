-- ============================================================================
-- CYBERSHEPPARD - Event Correlation System
-- Migration 007
--
-- Advanced event correlation engine with predictive analytics
-- TimescaleDB hypertables for time-series optimization
-- Mathematical/Statistical algorithms: Z-Score, Markov Chain, Graph Analytics
-- ============================================================================

-- Enable TimescaleDB extension
CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;

-- ============================================================================
-- Security Events (TimescaleDB Hypertable)
-- Main table for all security events from multiple sources
-- ============================================================================

CREATE TABLE IF NOT EXISTS security_events (
    id BIGSERIAL,
    timestamp TIMESTAMPTZ NOT NULL,

    -- Source information
    source_type VARCHAR(50) NOT NULL, -- 'auditd', 'snmp', 'syslog', 'ids', 'ips', 'firewall'
    source_host VARCHAR(255) NOT NULL,
    source_ip INET,
    source_port INTEGER,

    -- Event classification
    event_type VARCHAR(100) NOT NULL, -- 'login', 'file_access', 'process', 'network', 'alert'
    event_category VARCHAR(50) NOT NULL, -- 'authentication', 'authorization', 'data_access', 'network', 'system'
    event_action VARCHAR(100), -- 'allow', 'deny', 'alert', 'block'
    severity VARCHAR(20) NOT NULL, -- 'critical', 'high', 'medium', 'low', 'info'

    -- User/Process information
    user_name VARCHAR(255),
    user_id INTEGER,
    process_name VARCHAR(255),
    process_pid INTEGER,
    process_ppid INTEGER,
    process_cmdline TEXT,

    -- File/Resource information
    file_path TEXT,
    file_operation VARCHAR(50), -- 'read', 'write', 'execute', 'delete'

    -- Network information
    destination_ip INET,
    destination_port INTEGER,
    destination_host VARCHAR(255),
    protocol VARCHAR(20), -- 'tcp', 'udp', 'icmp', 'http', 'https'
    bytes_sent BIGINT,
    bytes_received BIGINT,

    -- Event data (flexible JSONB for source-specific fields)
    event_data JSONB,
    normalized_data JSONB, -- CEF/LEEF normalized format

    -- Enrichment data
    geo_country VARCHAR(2),
    geo_city VARCHAR(100),
    geo_location POINT,
    asset_criticality INTEGER, -- 1-10 scale
    threat_score DECIMAL(5,2), -- 0-100

    -- Correlation
    correlation_id UUID,
    parent_event_id BIGINT,
    sequence_number INTEGER,

    -- Metadata
    ingestion_time TIMESTAMPTZ DEFAULT NOW(),
    processed BOOLEAN DEFAULT false,
    anomaly_score DECIMAL(10,2),

    -- Constraints
    CONSTRAINT security_events_severity_check CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info'))
);

-- Convert to hypertable (partitioned by timestamp)
SELECT create_hypertable('security_events', 'timestamp',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => TRUE
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_security_events_source_type ON security_events(source_type, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_source_host ON security_events(source_host, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_event_type ON security_events(event_type, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_severity ON security_events(severity, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_user ON security_events(user_name, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_correlation ON security_events(correlation_id) WHERE correlation_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_security_events_anomaly ON security_events(anomaly_score DESC) WHERE anomaly_score > 0;

-- GIN indexes for JSONB
CREATE INDEX IF NOT EXISTS idx_security_events_event_data ON security_events USING GIN(event_data);
CREATE INDEX IF NOT EXISTS idx_security_events_normalized ON security_events USING GIN(normalized_data);

-- Composite indexes for common queries
CREATE INDEX IF NOT EXISTS idx_security_events_user_time ON security_events(user_name, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_host_time ON security_events(source_host, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_processed ON security_events(processed, timestamp DESC) WHERE NOT processed;

-- Retention policy: Drop chunks older than 90 days
SELECT add_retention_policy('security_events', INTERVAL '90 days', if_not_exists => TRUE);

-- Compression policy: Compress chunks older than 7 days
ALTER TABLE security_events SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'source_host, event_type',
    timescaledb.compress_orderby = 'timestamp DESC'
);

SELECT add_compression_policy('security_events', INTERVAL '7 days', if_not_exists => TRUE);

COMMENT ON TABLE security_events IS 'Time-series security events from multiple sources (auditd, SNMP, IDS/IPS)';

-- ============================================================================
-- Event Correlations
-- Detected patterns, sequences, and anomalies
-- ============================================================================

CREATE TABLE IF NOT EXISTS event_correlations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Correlation type
    correlation_type VARCHAR(50) NOT NULL, -- 'sequence', 'frequency', 'anomaly', 'lateral_movement', 'data_exfiltration'
    pattern_name VARCHAR(255),
    pattern_description TEXT,

    -- Confidence and severity
    confidence DECIMAL(3,2) NOT NULL CHECK (confidence >= 0 AND confidence <= 1), -- 0.00 - 1.00
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    risk_score DECIMAL(5,2), -- 0-100

    -- Time window
    first_event_time TIMESTAMPTZ NOT NULL,
    last_event_time TIMESTAMPTZ NOT NULL,
    time_window_seconds INTEGER,
    event_count INTEGER NOT NULL,

    -- Involved entities
    involved_users TEXT[],
    involved_hosts TEXT[],
    involved_ips INET[],
    involved_processes TEXT[],

    -- Statistical analysis
    statistical_significance DECIMAL(5,4), -- p-value or similar
    anomaly_score DECIMAL(10,2),
    z_score DECIMAL(10,2),
    baseline_deviation_percent DECIMAL(5,2),

    -- Correlation data (algorithm-specific output)
    correlation_data JSONB,

    -- Attack stage (MITRE ATT&CK inspired)
    attack_stage VARCHAR(50), -- 'reconnaissance', 'initial_access', 'execution', 'persistence', 'privilege_escalation', 'credential_access', 'lateral_movement', 'collection', 'exfiltration'

    -- Status
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'investigating', 'resolved', 'false_positive')),
    resolved_at TIMESTAMPTZ,
    resolution_notes TEXT,

    -- Assignment
    assigned_to VARCHAR(100),
    assigned_at TIMESTAMPTZ
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_correlations_type ON event_correlations(correlation_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_correlations_severity ON event_correlations(severity, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_correlations_status ON event_correlations(status) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_correlations_confidence ON event_correlations(confidence DESC, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_correlations_risk ON event_correlations(risk_score DESC) WHERE risk_score > 50;
CREATE INDEX IF NOT EXISTS idx_correlations_attack_stage ON event_correlations(attack_stage, created_at DESC);

-- GIN indexes for arrays
CREATE INDEX IF NOT EXISTS idx_correlations_users ON event_correlations USING GIN(involved_users);
CREATE INDEX IF NOT EXISTS idx_correlations_hosts ON event_correlations USING GIN(involved_hosts);
CREATE INDEX IF NOT EXISTS idx_correlations_ips ON event_correlations USING GIN(involved_ips);

COMMENT ON TABLE event_correlations IS 'Detected event correlations, patterns, and anomalies';

-- ============================================================================
-- Lateral Movement Predictions
-- AI/ML predictions for attacker next moves
-- ============================================================================

CREATE TABLE IF NOT EXISTS lateral_movement_predictions (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    correlation_id UUID REFERENCES event_correlations(id) ON DELETE CASCADE,

    -- Current attack state
    current_compromised_host VARCHAR(255) NOT NULL,
    current_compromised_user VARCHAR(255),
    current_attack_stage VARCHAR(50),

    -- Predictions (JSONB array of prediction objects)
    predictions JSONB NOT NULL,
    /* Example JSONB structure:
    [{
        "action": "rdp_connection",
        "target_host": "DC01",
        "target_ip": "10.0.1.10",
        "probability": 0.87,
        "timeframe_minutes": 10,
        "risk_score": 95,
        "reasoning": "Domain controller with high privileges, RDP port open",
        "recommended_actions": ["Block RDP to DC", "Enable MFA", "Monitor accounts"]
    }]
    */

    -- Model information
    model_name VARCHAR(100) NOT NULL, -- 'markov_chain', 'bayesian_network', 'random_forest'
    model_version VARCHAR(20),
    model_confidence DECIMAL(3,2),

    -- Validation (for model accuracy tracking)
    actual_outcome VARCHAR(100),
    outcome_timestamp TIMESTAMPTZ,
    prediction_accuracy DECIMAL(3,2),

    -- Status
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'monitoring', 'blocked', 'expired')),
    expires_at TIMESTAMPTZ,

    -- Actions taken
    actions_taken TEXT[],
    actions_timestamp TIMESTAMPTZ
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_predictions_host ON lateral_movement_predictions(current_compromised_host, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_predictions_correlation ON lateral_movement_predictions(correlation_id);
CREATE INDEX IF NOT EXISTS idx_predictions_status ON lateral_movement_predictions(status) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_predictions_stage ON lateral_movement_predictions(current_attack_stage);
CREATE INDEX IF NOT EXISTS idx_predictions_expires ON lateral_movement_predictions(expires_at) WHERE status = 'active';

COMMENT ON TABLE lateral_movement_predictions IS 'AI/ML predictions for lateral movement and next attack targets';

-- ============================================================================
-- User Behavior Baselines
-- Statistical baselines for user activity patterns
-- ============================================================================

CREATE TABLE IF NOT EXISTS user_behavior_baselines (
    user_name VARCHAR(255) PRIMARY KEY,

    -- Login patterns
    avg_logins_per_day DECIMAL(5,2),
    stddev_logins_per_day DECIMAL(5,2),
    typical_login_hours INTEGER[], -- Array of hours [0-23]
    typical_login_hosts TEXT[],
    typical_login_sources INET[],

    -- Session patterns
    avg_session_duration_minutes DECIMAL(7,2),
    stddev_session_duration_minutes DECIMAL(7,2),
    avg_commands_per_session DECIMAL(7,2),
    common_commands TEXT[],

    -- Activity patterns
    typical_file_paths TEXT[],
    typical_processes TEXT[],
    avg_network_connections_per_day DECIMAL(7,2),
    typical_destination_ips INET[],
    typical_destination_ports INTEGER[],

    -- Anomaly thresholds (calculated based on stddev)
    login_count_threshold_high DECIMAL(5,2),
    session_duration_threshold_high DECIMAL(7,2),
    command_count_threshold_high DECIMAL(7,2),

    -- Baseline metadata
    baseline_start_date DATE NOT NULL,
    baseline_end_date DATE NOT NULL,
    events_analyzed INTEGER NOT NULL,
    last_updated TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Anomaly counters (for tracking)
    anomaly_count_7d INTEGER DEFAULT 0,
    anomaly_count_30d INTEGER DEFAULT 0,
    last_anomaly_at TIMESTAMPTZ
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_user_baselines_updated ON user_behavior_baselines(last_updated DESC);
CREATE INDEX IF NOT EXISTS idx_user_baselines_anomalies ON user_behavior_baselines(anomaly_count_7d DESC) WHERE anomaly_count_7d > 0;

COMMENT ON TABLE user_behavior_baselines IS 'Statistical behavior baselines for users (UEBA)';

-- ============================================================================
-- Host Behavior Baselines
-- Statistical baselines for host activity patterns
-- ============================================================================

CREATE TABLE IF NOT EXISTS host_behavior_baselines (
    host_name VARCHAR(255) PRIMARY KEY,

    -- Process patterns
    typical_processes TEXT[],
    typical_process_count_range INT4RANGE, -- min-max
    avg_cpu_percent DECIMAL(5,2),
    avg_memory_mb DECIMAL(10,2),

    -- Network patterns
    avg_connections_per_hour DECIMAL(7,2),
    stddev_connections_per_hour DECIMAL(7,2),
    typical_listening_ports INTEGER[],
    typical_destination_ips INET[],
    avg_bandwidth_mbps DECIMAL(10,2),

    -- File system patterns
    typical_file_modifications_per_hour DECIMAL(7,2),
    critical_file_paths TEXT[],

    -- User patterns
    typical_users TEXT[],
    avg_user_sessions_per_day DECIMAL(5,2),

    -- Service patterns
    expected_services TEXT[],

    -- Anomaly thresholds
    connection_count_threshold_high DECIMAL(7,2),
    process_count_threshold_high INTEGER,
    bandwidth_threshold_high_mbps DECIMAL(10,2),

    -- Baseline metadata
    baseline_start_date DATE NOT NULL,
    baseline_end_date DATE NOT NULL,
    events_analyzed INTEGER NOT NULL,
    last_updated TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Asset information
    asset_criticality INTEGER DEFAULT 5, -- 1-10
    is_server BOOLEAN DEFAULT false,

    -- Anomaly counters
    anomaly_count_7d INTEGER DEFAULT 0,
    anomaly_count_30d INTEGER DEFAULT 0,
    last_anomaly_at TIMESTAMPTZ
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_host_baselines_criticality ON host_behavior_baselines(asset_criticality DESC);
CREATE INDEX IF NOT EXISTS idx_host_baselines_updated ON host_behavior_baselines(last_updated DESC);
CREATE INDEX IF NOT EXISTS idx_host_baselines_anomalies ON host_behavior_baselines(anomaly_count_7d DESC) WHERE anomaly_count_7d > 0;
CREATE INDEX IF NOT EXISTS idx_host_baselines_servers ON host_behavior_baselines(is_server) WHERE is_server = true;

COMMENT ON TABLE host_behavior_baselines IS 'Statistical behavior baselines for hosts';

-- ============================================================================
-- Network Topology
-- Graph data for lateral movement analysis
-- ============================================================================

CREATE TABLE IF NOT EXISTS network_topology (
    id BIGSERIAL PRIMARY KEY,
    source_host VARCHAR(255) NOT NULL,
    destination_host VARCHAR(255) NOT NULL,

    -- Connection statistics
    connection_count INTEGER DEFAULT 0,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Traffic patterns
    avg_bandwidth_mbps DECIMAL(10,2),
    total_bytes_transferred BIGINT DEFAULT 0,
    typical_protocols TEXT[],
    typical_ports INTEGER[],

    -- Criticality scores
    source_criticality INTEGER DEFAULT 5,
    destination_criticality INTEGER DEFAULT 5,
    path_risk_score DECIMAL(5,2), -- 0-100

    -- Graph analytics (calculated)
    betweenness_centrality DECIMAL(10,6), -- For identifying critical paths
    trust_score DECIMAL(3,2), -- 0-1, how normal is this connection

    -- Status
    is_expected BOOLEAN DEFAULT true,
    is_anomalous BOOLEAN DEFAULT false,
    last_anomaly_at TIMESTAMPTZ,

    UNIQUE(source_host, destination_host)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_network_topo_source ON network_topology(source_host, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_network_topo_destination ON network_topology(destination_host, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_network_topo_anomalous ON network_topology(is_anomalous) WHERE is_anomalous = true;
CREATE INDEX IF NOT EXISTS idx_network_topo_centrality ON network_topology(betweenness_centrality DESC);
CREATE INDEX IF NOT EXISTS idx_network_topo_risk ON network_topology(path_risk_score DESC) WHERE path_risk_score > 50;

COMMENT ON TABLE network_topology IS 'Network topology graph for lateral movement analysis';

-- ============================================================================
-- Host Risk Scores
-- Aggregated risk scores per host (updated in real-time)
-- ============================================================================

CREATE TABLE IF NOT EXISTS host_risk_scores (
    host_name VARCHAR(255) PRIMARY KEY,

    -- Risk components
    anomaly_risk DECIMAL(5,2) DEFAULT 0, -- 0-100
    vulnerability_risk DECIMAL(5,2) DEFAULT 0, -- 0-100
    compliance_risk DECIMAL(5,2) DEFAULT 0, -- 0-100
    threat_risk DECIMAL(5,2) DEFAULT 0, -- 0-100

    -- Overall risk
    total_risk_score DECIMAL(5,2) DEFAULT 0, -- 0-100, weighted average
    risk_level VARCHAR(20), -- 'critical', 'high', 'medium', 'low'

    -- Contributing factors
    active_alerts INTEGER DEFAULT 0,
    critical_alerts INTEGER DEFAULT 0,
    failed_compliance_controls INTEGER DEFAULT 0,
    known_vulnerabilities INTEGER DEFAULT 0,

    -- Compromise indicators
    compromise_probability DECIMAL(3,2) DEFAULT 0, -- 0-1
    compromise_indicators TEXT[],

    -- Timestamps
    last_calculated TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_incident TIMESTAMPTZ,

    -- Asset info
    asset_criticality INTEGER DEFAULT 5,
    is_critical_asset BOOLEAN DEFAULT false
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_host_risk_total ON host_risk_scores(total_risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_host_risk_level ON host_risk_scores(risk_level) WHERE risk_level IN ('critical', 'high');
CREATE INDEX IF NOT EXISTS idx_host_risk_critical ON host_risk_scores(is_critical_asset) WHERE is_critical_asset = true;
CREATE INDEX IF NOT EXISTS idx_host_risk_compromise ON host_risk_scores(compromise_probability DESC) WHERE compromise_probability > 0.5;

COMMENT ON TABLE host_risk_scores IS 'Real-time risk scores for hosts based on multiple factors';

-- ============================================================================
-- Aggregated Security Metrics (TimescaleDB Continuous Aggregate)
-- Pre-computed hourly statistics for dashboards
-- ============================================================================

CREATE MATERIALIZED VIEW IF NOT EXISTS security_metrics_hourly
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 hour', timestamp) AS hour,
    source_type,
    event_category,
    severity,
    COUNT(*) AS event_count,
    COUNT(DISTINCT user_name) AS unique_users,
    COUNT(DISTINCT source_host) AS unique_hosts,
    COUNT(DISTINCT source_ip) AS unique_ips,
    AVG(anomaly_score) AS avg_anomaly_score,
    MAX(anomaly_score) AS max_anomaly_score,
    COUNT(*) FILTER (WHERE anomaly_score > 50) AS high_anomaly_count
FROM security_events
GROUP BY hour, source_type, event_category, severity
WITH NO DATA;

-- Refresh policy
SELECT add_continuous_aggregate_policy('security_metrics_hourly',
    start_offset => INTERVAL '3 hours',
    end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour',
    if_not_exists => TRUE
);

COMMENT ON MATERIALIZED VIEW security_metrics_hourly IS 'Hourly aggregated security metrics for dashboards';

-- ============================================================================
-- Functions and Triggers
-- ============================================================================

-- Update updated_at timestamp
CREATE OR REPLACE FUNCTION update_correlation_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_correlations_updated
    BEFORE UPDATE ON event_correlations
    FOR EACH ROW
    EXECUTE FUNCTION update_correlation_timestamp();

-- Calculate risk level from risk score
CREATE OR REPLACE FUNCTION calculate_risk_level(score DECIMAL)
RETURNS VARCHAR AS $$
BEGIN
    RETURN CASE
        WHEN score >= 80 THEN 'critical'
        WHEN score >= 60 THEN 'high'
        WHEN score >= 40 THEN 'medium'
        ELSE 'low'
    END;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Update risk level when risk score changes
CREATE OR REPLACE FUNCTION update_host_risk_level()
RETURNS TRIGGER AS $$
BEGIN
    NEW.risk_level = calculate_risk_level(NEW.total_risk_score);
    NEW.last_calculated = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_host_risk_level
    BEFORE INSERT OR UPDATE OF total_risk_score ON host_risk_scores
    FOR EACH ROW
    EXECUTE FUNCTION update_host_risk_level();

-- ============================================================================
-- Views for Common Queries
-- ============================================================================

-- Active high-risk correlations
CREATE OR REPLACE VIEW active_high_risk_correlations AS
SELECT
    c.*,
    p.predictions AS lateral_movement_predictions
FROM event_correlations c
LEFT JOIN lateral_movement_predictions p ON c.id = p.correlation_id AND p.status = 'active'
WHERE c.status = 'active'
  AND (c.severity IN ('critical', 'high') OR c.risk_score > 60)
ORDER BY c.risk_score DESC, c.created_at DESC;

COMMENT ON VIEW active_high_risk_correlations IS 'Active correlations with high risk requiring investigation';

-- Recent anomalies by host
CREATE OR REPLACE VIEW recent_host_anomalies AS
SELECT
    source_host,
    COUNT(*) AS anomaly_count,
    MAX(timestamp) AS last_anomaly,
    AVG(anomaly_score) AS avg_anomaly_score,
    MAX(anomaly_score) AS max_anomaly_score,
    array_agg(DISTINCT event_type) AS event_types
FROM security_events
WHERE anomaly_score > 50
  AND timestamp > NOW() - INTERVAL '24 hours'
GROUP BY source_host
ORDER BY max_anomaly_score DESC;

COMMENT ON VIEW recent_host_anomalies IS 'Hosts with anomalies in last 24 hours';

-- ============================================================================
-- Initial Data / Configuration
-- ============================================================================

-- Insert default risk scores for existing targets
INSERT INTO host_risk_scores (host_name, asset_criticality)
SELECT
    COALESCE(hostname, ip_address::TEXT, name) AS host_name,
    5 AS asset_criticality
FROM targets
WHERE status = 'active'
ON CONFLICT (host_name) DO NOTHING;

-- ============================================================================
-- Performance Tuning
-- ============================================================================

-- Analyze tables for query planner
ANALYZE security_events;
ANALYZE event_correlations;
ANALYZE lateral_movement_predictions;
ANALYZE user_behavior_baselines;
ANALYZE host_behavior_baselines;
ANALYZE network_topology;
ANALYZE host_risk_scores;

-- ============================================================================
-- Comments
-- ============================================================================

COMMENT ON SCHEMA public IS 'CyberSheppard Event Correlation System with TimescaleDB';
