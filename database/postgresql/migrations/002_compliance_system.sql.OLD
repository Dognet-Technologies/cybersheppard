-- ============================================================================
-- CYBERSHEPPARD (MicroSIEM) - Compliance System
-- Migration: 002_compliance_system.sql
-- Description: Add tables for behavioral compliance monitoring
-- Date: 2025-12-05
-- ============================================================================

BEGIN;

-- ============================================================================
-- 1. COMPLIANCE POLICIES
-- ============================================================================

CREATE TABLE compliance_policies (
    id SERIAL PRIMARY KEY,

    -- Associazione
    target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,  -- NULL = global policy
    hardening_model_id INTEGER REFERENCES hardening_models(id) ON DELETE CASCADE,

    -- Policy definition
    name VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(50) NOT NULL,  -- 'ssh', 'auditd', 'sudo', 'network', 'system'
    metric_name VARCHAR(100) NOT NULL,  -- 'failed_ssh_attempts', 'privilege_escalations', etc.

    -- Threshold configuration
    threshold_type VARCHAR(20) NOT NULL CHECK (threshold_type IN ('max', 'min', 'range', 'pattern', 'baseline')),
    threshold_value_max INTEGER,
    threshold_value_min INTEGER,
    time_window_minutes INTEGER DEFAULT 60,  -- Finestra temporale per valutazione

    -- Severity & Actions
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    auto_notify BOOLEAN DEFAULT TRUE,
    auto_remediate BOOLEAN DEFAULT FALSE,
    remediation_action VARCHAR(50),  -- 'block_ip', 'restart_service', 'reapply_hardening'

    -- Status
    is_active BOOLEAN DEFAULT TRUE,

    -- Metadata
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),

    CONSTRAINT unique_metric_per_target UNIQUE (target_id, metric_name)
);

CREATE INDEX idx_compliance_policies_target ON compliance_policies(target_id);
CREATE INDEX idx_compliance_policies_model ON compliance_policies(hardening_model_id);
CREATE INDEX idx_compliance_policies_category ON compliance_policies(category);
CREATE INDEX idx_compliance_policies_active ON compliance_policies(is_active) WHERE is_active = TRUE;

-- ============================================================================
-- 2. COMPLIANCE VIOLATIONS
-- ============================================================================

CREATE TABLE compliance_violations (
    id BIGSERIAL PRIMARY KEY,

    -- Associazione
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    policy_id INTEGER REFERENCES compliance_policies(id) ON DELETE SET NULL,

    -- Violation details
    metric_name VARCHAR(100) NOT NULL,
    category VARCHAR(50) NOT NULL,

    -- Values
    detected_value JSONB NOT NULL,      -- Valore rilevato (può essere complesso)
    threshold_value JSONB,              -- Soglia configurata
    deviation DECIMAL(10,2),            -- Deviazione percentuale dalla soglia

    -- Classification
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    confidence DECIMAL(3,2) DEFAULT 1.0,  -- Confidence score (0.0 - 1.0)

    -- Event details
    event_details JSONB,                -- Eventi specifici che hanno causato la violation
    related_events_count INTEGER DEFAULT 1,

    -- Status tracking
    status VARCHAR(20) DEFAULT 'new' CHECK (status IN ('new', 'acknowledged', 'investigating', 'resolved', 'false_positive', 'suppressed')),

    -- Timeline
    first_detected_at TIMESTAMP DEFAULT NOW(),
    last_detected_at TIMESTAMP DEFAULT NOW(),
    occurrences INTEGER DEFAULT 1,

    -- Resolution
    acknowledged_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    acknowledged_at TIMESTAMP,
    resolved_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    resolved_at TIMESTAMP,
    resolution_notes TEXT,

    -- Actions taken
    actions_taken JSONB,                -- Auto-remediation actions eseguite
    notification_sent BOOLEAN DEFAULT FALSE,
    notification_sent_at TIMESTAMP
);

CREATE INDEX idx_violations_target ON compliance_violations(target_id, first_detected_at DESC);
CREATE INDEX idx_violations_policy ON compliance_violations(policy_id);
CREATE INDEX idx_violations_status ON compliance_violations(status, severity);
CREATE INDEX idx_violations_new ON compliance_violations(status, first_detected_at DESC) WHERE status = 'new';
CREATE INDEX idx_violations_severity ON compliance_violations(severity, status);
CREATE INDEX idx_violations_category ON compliance_violations(category, status);
CREATE INDEX idx_violations_timeline ON compliance_violations(first_detected_at DESC);

-- ============================================================================
-- 3. COMPLIANCE HISTORY (aggregated stats per target)
-- ============================================================================

CREATE TABLE compliance_history (
    id BIGSERIAL PRIMARY KEY,

    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,

    -- Timestamp
    checked_at TIMESTAMP DEFAULT NOW(),

    -- Overall compliance
    compliance_status VARCHAR(20) CHECK (compliance_status IN ('compliant', 'warning', 'non_compliant', 'critical')),
    compliance_score INTEGER CHECK (compliance_score >= 0 AND compliance_score <= 100),

    -- Violations count per severity
    violations_critical INTEGER DEFAULT 0,
    violations_high INTEGER DEFAULT 0,
    violations_medium INTEGER DEFAULT 0,
    violations_low INTEGER DEFAULT 0,
    violations_total INTEGER DEFAULT 0,

    -- Metrics snapshot
    metrics_snapshot JSONB,

    -- Policies evaluated
    policies_checked INTEGER DEFAULT 0,
    policies_passed INTEGER DEFAULT 0,
    policies_failed INTEGER DEFAULT 0
);

CREATE INDEX idx_compliance_history_target ON compliance_history(target_id, checked_at DESC);
CREATE INDEX idx_compliance_history_status ON compliance_history(compliance_status, checked_at DESC);
CREATE INDEX idx_compliance_history_date ON compliance_history(checked_at DESC);

-- ============================================================================
-- 4. DEFAULT COMPLIANCE POLICIES
-- ============================================================================

-- Global policies (target_id = NULL, applicabili a tutti i target)

INSERT INTO compliance_policies
    (target_id, hardening_model_id, name, description, category, metric_name,
     threshold_type, threshold_value_max, time_window_minutes, severity, auto_notify, is_active)
VALUES
    -- SSH Policies
    (NULL, NULL, 'SSH Brute Force Detection', 'Detect excessive failed SSH login attempts',
     'ssh', 'failed_ssh_attempts', 'max', 10, 60, 'high', TRUE, TRUE),

    (NULL, NULL, 'SSH Critical Brute Force', 'Critical level of failed SSH attempts',
     'ssh', 'failed_ssh_attempts', 'max', 50, 60, 'critical', TRUE, TRUE),

    -- Auditd Policies
    (NULL, NULL, 'Config File Modifications', 'Detect unauthorized modifications to critical system files',
     'auditd', 'config_changes', 'max', 2, 1440, 'critical', TRUE, TRUE),

    (NULL, NULL, 'Privilege Escalation Attempts', 'Detect suspicious privilege escalation attempts',
     'auditd', 'privilege_escalations', 'max', 5, 60, 'high', TRUE, TRUE),

    (NULL, NULL, 'Excessive Failed Login Attempts', 'Detect potential brute force attacks via login',
     'auditd', 'failed_logins', 'max', 10, 60, 'high', TRUE, TRUE),

    (NULL, NULL, 'Critical Failed Login Attempts', 'Critical level of failed login attempts',
     'auditd', 'failed_logins', 'max', 50, 60, 'critical', TRUE, TRUE),

    -- Sudo Policies
    (NULL, NULL, 'Excessive Sudo Failures', 'Detect repeated failed sudo attempts',
     'sudo', 'failed_attempts', 'max', 5, 60, 'medium', TRUE, TRUE),

    (NULL, NULL, 'High Sudo Activity', 'Detect unusually high sudo command usage',
     'sudo', 'commands_last_hour', 'max', 50, 60, 'low', FALSE, TRUE),

    -- Network Policies
    (NULL, NULL, 'High Active Connections', 'Detect excessive number of active connections',
     'network', 'active_connections', 'max', 500, 5, 'medium', FALSE, TRUE),

    (NULL, NULL, 'Critical Active Connections', 'Critical number of active connections (possible DoS)',
     'network', 'active_connections', 'max', 1000, 5, 'high', TRUE, TRUE),

    -- System Policies
    (NULL, NULL, 'High CPU Usage', 'Detect sustained high CPU usage',
     'system', 'cpu_usage', 'max', 90, 10, 'medium', FALSE, TRUE),

    (NULL, NULL, 'High Memory Usage', 'Detect high memory consumption',
     'system', 'memory_usage', 'max', 90, 10, 'medium', FALSE, TRUE),

    (NULL, NULL, 'Disk Space Critical', 'Detect critical disk space usage',
     'system', 'disk_usage', 'max', 95, 5, 'high', TRUE, TRUE),

    (NULL, NULL, 'Zombie Processes Detected', 'Detect presence of zombie processes',
     'system', 'zombie_processes', 'max', 5, 5, 'low', FALSE, TRUE),

    (NULL, NULL, 'Critical Zombie Processes', 'Critical number of zombie processes',
     'system', 'zombie_processes', 'max', 20, 5, 'medium', TRUE, TRUE),

    (NULL, NULL, 'Failed Services Detected', 'Detect failed systemd services',
     'system', 'failed_services_count', 'max', 0, 5, 'high', TRUE, TRUE);

-- ============================================================================
-- 5. FUNCTIONS & TRIGGERS
-- ============================================================================

-- Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_compliance_policies_updated_at
    BEFORE UPDATE ON compliance_policies
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Function to calculate compliance score for a target
CREATE OR REPLACE FUNCTION calculate_compliance_score(p_target_id INTEGER)
RETURNS INTEGER AS $$
DECLARE
    v_score INTEGER;
    v_critical INTEGER;
    v_high INTEGER;
    v_medium INTEGER;
    v_low INTEGER;
BEGIN
    -- Count active violations by severity
    SELECT
        COUNT(*) FILTER (WHERE severity = 'critical'),
        COUNT(*) FILTER (WHERE severity = 'high'),
        COUNT(*) FILTER (WHERE severity = 'medium'),
        COUNT(*) FILTER (WHERE severity = 'low')
    INTO v_critical, v_high, v_medium, v_low
    FROM compliance_violations
    WHERE target_id = p_target_id
      AND status IN ('new', 'acknowledged', 'investigating');

    -- Calculate score (100 - penalties)
    v_score := 100
        - (v_critical * 25)  -- -25 per critical
        - (v_high * 10)      -- -10 per high
        - (v_medium * 5)     -- -5 per medium
        - (v_low * 1);       -- -1 per low

    -- Ensure score is between 0 and 100
    v_score := GREATEST(0, LEAST(100, v_score));

    RETURN v_score;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 6. CLEANUP FUNCTION
-- ============================================================================

CREATE OR REPLACE FUNCTION cleanup_old_compliance_data() RETURNS void AS $$
BEGIN
    -- Delete resolved violations older than 90 days
    DELETE FROM compliance_violations
    WHERE status IN ('resolved', 'false_positive')
      AND resolved_at < NOW() - INTERVAL '90 days';

    -- Delete old compliance history (keep 1 year)
    DELETE FROM compliance_history
    WHERE checked_at < NOW() - INTERVAL '1 year';

    VACUUM ANALYZE compliance_violations;
    VACUUM ANALYZE compliance_history;

    RAISE NOTICE 'Compliance data cleanup completed';
END;
$$ LANGUAGE plpgsql;

COMMIT;

-- ============================================================================
-- END OF MIGRATION
-- ============================================================================
