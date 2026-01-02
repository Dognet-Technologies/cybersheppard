-- ============================================================================
-- CYBERSHEPPARD (MicroSIEM) - Complete Database Schema (Consolidated)
-- Migration: 001_complete_schema.sql
-- Description: Full database schema with all tables (consolidated from multiple migrations)
-- Date: 2025-12-29
-- ============================================================================

BEGIN;

-- ============================================================================
-- 1. USERS & AUTHENTICATION
-- ============================================================================

-- Users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL CHECK (role IN ('admin', 'user')),

    -- Account status
    is_active BOOLEAN DEFAULT TRUE,
    is_verified BOOLEAN DEFAULT FALSE,
    email_verified_at TIMESTAMP,

    -- Session management
    last_login_at TIMESTAMP,
    last_login_ip INET,
    failed_login_attempts INTEGER DEFAULT 0,
    account_locked_until TIMESTAMP,

    -- Timestamps
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),

    -- Constraints
    CONSTRAINT username_length CHECK (length(username) >= 3),
    CONSTRAINT email_format CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$')
);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_active ON users(is_active) WHERE is_active = TRUE;

-- Refresh tokens table
CREATE TABLE refresh_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL UNIQUE,

    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    last_used_at TIMESTAMP,

    created_ip INET NOT NULL,
    user_agent TEXT,

    is_revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMP,
    revoked_reason VARCHAR(100)
);

CREATE INDEX idx_refresh_tokens_user ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_hash ON refresh_tokens(token_hash);
CREATE INDEX idx_refresh_tokens_expires ON refresh_tokens(expires_at);
CREATE INDEX idx_refresh_tokens_active ON refresh_tokens(user_id, is_revoked) WHERE is_revoked = FALSE;

-- CSRF tokens table
CREATE TABLE csrf_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL UNIQUE,

    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),

    is_used BOOLEAN DEFAULT FALSE,
    used_at TIMESTAMP
);

CREATE INDEX idx_csrf_tokens_user ON csrf_tokens(user_id);
CREATE INDEX idx_csrf_tokens_hash ON csrf_tokens(token_hash);
CREATE INDEX idx_csrf_tokens_expires ON csrf_tokens(expires_at);

-- Password reset tokens table
CREATE TABLE password_reset_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL UNIQUE,

    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),

    is_used BOOLEAN DEFAULT FALSE,
    used_at TIMESTAMP,

    created_ip INET NOT NULL
);

CREATE INDEX idx_password_reset_user ON password_reset_tokens(user_id);
CREATE INDEX idx_password_reset_token ON password_reset_tokens(token_hash);

-- Audit logs table
CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    username VARCHAR(50),

    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id INTEGER,

    ip_address INET NOT NULL,
    user_agent TEXT,

    details JSONB,

    success BOOLEAN DEFAULT TRUE,
    error_message TEXT,

    timestamp TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_user ON audit_logs(user_id, timestamp DESC);
CREATE INDEX idx_audit_logs_action ON audit_logs(action, timestamp DESC);
CREATE INDEX idx_audit_logs_resource ON audit_logs(resource_type, resource_id);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX idx_audit_logs_ip ON audit_logs(ip_address, timestamp DESC);

-- ============================================================================
-- 2. SSH KEYS MANAGEMENT
-- ============================================================================

CREATE TABLE ssh_keys (
    id SERIAL PRIMARY KEY,

    name VARCHAR(255) NOT NULL,
    fingerprint VARCHAR(255) UNIQUE NOT NULL,

    key_type VARCHAR(20) NOT NULL CHECK (key_type IN ('ed25519', 'rsa', 'ecdsa')),
    key_size INTEGER,

    public_key TEXT NOT NULL,
    private_key TEXT NOT NULL,  -- ENCRYPTED (Fernet)

    scope VARCHAR(20) DEFAULT 'global' CHECK (scope IN ('global', 'group', 'target')),
    scope_value VARCHAR(255),

    is_active BOOLEAN DEFAULT TRUE,

    last_used_at TIMESTAMP,
    usage_count INTEGER DEFAULT 0,

    rotation_days INTEGER DEFAULT 90,
    next_rotation_date DATE,

    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_ssh_keys_scope ON ssh_keys(scope, scope_value);
CREATE INDEX idx_ssh_keys_fingerprint ON ssh_keys(fingerprint);
CREATE INDEX idx_ssh_keys_active ON ssh_keys(is_active) WHERE is_active = TRUE;
CREATE INDEX idx_ssh_keys_rotation ON ssh_keys(next_rotation_date) WHERE is_active = TRUE;

-- ============================================================================
-- 3. TARGETS MANAGEMENT
-- ============================================================================

CREATE TABLE target_groups (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,

    default_ssh_key_id INTEGER REFERENCES ssh_keys(id) ON DELETE SET NULL,
    default_monitoring_interval INTEGER DEFAULT 30,

    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_target_groups_name ON target_groups(name);

CREATE TABLE targets (
    id SERIAL PRIMARY KEY,

    hostname VARCHAR(255) NOT NULL,
    ip_address INET NOT NULL,

    ssh_port INTEGER DEFAULT 22 CHECK (ssh_port > 0 AND ssh_port <= 65535),
    ssh_username VARCHAR(50) DEFAULT 'microcyber',
    ssh_key_id INTEGER REFERENCES ssh_keys(id) ON DELETE SET NULL,

    role VARCHAR(50),
    environment VARCHAR(20) DEFAULT 'production',
    gruppo VARCHAR(100),
    tags JSONB DEFAULT '[]',

    compliance_standard VARCHAR(50),

    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'offline', 'error', 'maintenance')),
    status_message TEXT,
    last_seen TIMESTAMP,
    last_check TIMESTAMP,

    hardening_applied BOOLEAN DEFAULT FALSE,
    hardening_model_id INTEGER,
    hardening_applied_at TIMESTAMP,
    hardening_score INTEGER CHECK (hardening_score >= 0 AND hardening_score <= 100),

    monitoring_enabled BOOLEAN DEFAULT TRUE,
    monitoring_interval_seconds INTEGER DEFAULT 30,
    last_monitoring_at TIMESTAMP,
    monitoring_errors_count INTEGER DEFAULT 0,

    -- Integration IDs (added from migration 005)
    sentinel_asset_id INTEGER,
    firedog_target_id INTEGER,

    description TEXT,
    notes TEXT,

    added_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),

    CONSTRAINT unique_ip_port UNIQUE (ip_address, ssh_port)
);

CREATE INDEX idx_targets_hostname ON targets(hostname);
CREATE INDEX idx_targets_ip ON targets(ip_address);
CREATE INDEX idx_targets_status ON targets(status);
CREATE INDEX idx_targets_role ON targets(role);
CREATE INDEX idx_targets_gruppo ON targets(gruppo);
CREATE INDEX idx_targets_compliance ON targets(compliance_standard);
CREATE INDEX idx_targets_active ON targets(status) WHERE status = 'active';
CREATE INDEX idx_targets_last_seen ON targets(last_seen DESC);
CREATE INDEX idx_targets_tags ON targets USING GIN (tags);

COMMENT ON COLUMN targets.sentinel_asset_id IS 'Asset ID in Sentinel Core system';
COMMENT ON COLUMN targets.firedog_target_id IS 'Target ID in FireDog system';

CREATE TABLE target_network_interfaces (
    id SERIAL PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,

    interface_name VARCHAR(50) NOT NULL,
    ip_address INET NOT NULL,
    mac_address MACADDR,
    netmask INET,
    is_primary BOOLEAN DEFAULT FALSE,

    discovered_at TIMESTAMP DEFAULT NOW(),
    last_seen TIMESTAMP DEFAULT NOW(),

    CONSTRAINT unique_target_interface UNIQUE (target_id, interface_name)
);

CREATE INDEX idx_target_interfaces_target ON target_network_interfaces(target_id);
CREATE INDEX idx_target_interfaces_ip ON target_network_interfaces(ip_address);

-- ============================================================================
-- 4. HARDENING MODELS
-- ============================================================================

CREATE TABLE hardening_models (
    id SERIAL PRIMARY KEY,

    name VARCHAR(100) UNIQUE NOT NULL,
    version VARCHAR(20) DEFAULT '1.0.0',
    description TEXT,

    role VARCHAR(50),
    compliance_standard VARCHAR(50),
    level VARCHAR(20) CHECK (level IN ('base', 'severo')),

    model_path TEXT NOT NULL,
    files_count INTEGER DEFAULT 0,

    hash_sha512 VARCHAR(128) NOT NULL,

    author VARCHAR(100),
    supported_os JSONB DEFAULT '[]',

    services_to_enable JSONB DEFAULT '[]',
    services_to_disable JSONB DEFAULT '[]',
    packages_to_install JSONB DEFAULT '[]',
    packages_to_remove JSONB DEFAULT '[]',
    requires_reboot BOOLEAN DEFAULT FALSE,

    is_active BOOLEAN DEFAULT TRUE,
    is_validated BOOLEAN DEFAULT FALSE,
    validation_errors JSONB,

    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    last_integrity_check TIMESTAMP
);

CREATE INDEX idx_hardening_models_name ON hardening_models(name);
CREATE INDEX idx_hardening_models_role ON hardening_models(role);
CREATE INDEX idx_hardening_models_compliance ON hardening_models(compliance_standard);
CREATE INDEX idx_hardening_models_level ON hardening_models(level);
CREATE INDEX idx_hardening_models_active ON hardening_models(is_active) WHERE is_active = TRUE;
CREATE INDEX idx_hardening_models_hash ON hardening_models(hash_sha512);

-- Add foreign key to targets now that hardening_models exists
ALTER TABLE targets ADD CONSTRAINT fk_targets_hardening_model
    FOREIGN KEY (hardening_model_id) REFERENCES hardening_models(id) ON DELETE SET NULL;

CREATE TABLE hardening_files (
    id SERIAL PRIMARY KEY,
    model_id INTEGER NOT NULL REFERENCES hardening_models(id) ON DELETE CASCADE,

    file_name VARCHAR(255) NOT NULL,
    target_path TEXT NOT NULL,

    content TEXT NOT NULL,
    hash_sha256 VARCHAR(64) NOT NULL,

    file_size INTEGER,
    file_mode VARCHAR(4) DEFAULT '0644',
    file_owner VARCHAR(50) DEFAULT 'root',
    file_group VARCHAR(50) DEFAULT 'root',

    created_at TIMESTAMP DEFAULT NOW(),

    CONSTRAINT unique_model_file UNIQUE (model_id, file_name)
);

CREATE INDEX idx_hardening_files_model ON hardening_files(model_id);
CREATE INDEX idx_hardening_files_path ON hardening_files(target_path);
CREATE INDEX idx_hardening_files_hash ON hardening_files(hash_sha256);

-- Hardening applications table (CORRECTED VERSION from migration 004)
CREATE TABLE hardening_applications (
    id BIGSERIAL PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    model_path VARCHAR(255) NOT NULL,  -- e.g., "base/ssh.yml"
    success BOOLEAN NOT NULL DEFAULT FALSE,
    steps_completed INTEGER NOT NULL DEFAULT 0,
    steps_failed INTEGER NOT NULL DEFAULT 0,
    backup_path TEXT,  -- Path to backup tarball
    duration_seconds DOUBLE PRECISION,
    result_log JSONB NOT NULL DEFAULT '[]'::jsonb,  -- Array of log messages
    applied_at TIMESTAMP NOT NULL DEFAULT NOW(),

    -- Constraints
    CONSTRAINT valid_steps CHECK (steps_completed >= 0 AND steps_failed >= 0)
);

CREATE INDEX idx_hardening_applications_target_id ON hardening_applications(target_id, applied_at DESC);
CREATE INDEX idx_hardening_applications_model_path ON hardening_applications(model_path);
CREATE INDEX idx_hardening_applications_success ON hardening_applications(success);
CREATE INDEX idx_hardening_applications_applied_at ON hardening_applications(applied_at DESC);

COMMENT ON TABLE hardening_applications IS 'Tracks history of hardening model applications to targets';
COMMENT ON COLUMN hardening_applications.model_path IS 'Path to hardening model (e.g., base/ssh.yml)';
COMMENT ON COLUMN hardening_applications.success IS 'Whether hardening application succeeded';
COMMENT ON COLUMN hardening_applications.result_log IS 'JSON array of log messages from application';

-- Create view for latest hardening status per target
CREATE OR REPLACE VIEW latest_hardening_status AS
SELECT DISTINCT ON (target_id)
    target_id,
    model_path,
    success,
    steps_completed,
    steps_failed,
    backup_path,
    duration_seconds,
    applied_at
FROM hardening_applications
ORDER BY target_id, applied_at DESC;

-- ============================================================================
-- 5. NOTIFICATIONS
-- ============================================================================

CREATE TABLE notification_config (
    id INTEGER PRIMARY KEY DEFAULT 1,

    email_enabled BOOLEAN DEFAULT FALSE,
    email_recipients JSONB DEFAULT '[]',
    smtp_host VARCHAR(255) DEFAULT 'localhost',
    smtp_port INTEGER DEFAULT 587,
    smtp_user VARCHAR(255) DEFAULT 'microcyber',
    smtp_password VARCHAR(500),
    smtp_use_tls BOOLEAN DEFAULT TRUE,
    smtp_from_email VARCHAR(255) DEFAULT 'cybersheppard@localhost',

    slack_enabled BOOLEAN DEFAULT FALSE,
    slack_webhook_url VARCHAR(500),
    slack_channel VARCHAR(100),

    discord_enabled BOOLEAN DEFAULT FALSE,
    discord_webhook_url VARCHAR(500),

    alert_on_critical_threat BOOLEAN DEFAULT TRUE,
    alert_on_high_threat BOOLEAN DEFAULT TRUE,
    alert_on_target_offline BOOLEAN DEFAULT TRUE,
    alert_on_hardening_failed BOOLEAN DEFAULT TRUE,
    alert_on_compliance_failed BOOLEAN DEFAULT TRUE,

    target_offline_threshold_minutes INTEGER DEFAULT 5,
    cooldown_minutes INTEGER DEFAULT 60,

    updated_at TIMESTAMP DEFAULT NOW(),
    updated_by INTEGER REFERENCES users(id) ON DELETE SET NULL,

    CONSTRAINT ensure_singleton CHECK (id = 1)
);

-- Insert default config
INSERT INTO notification_config (id) VALUES (1);

CREATE TABLE notification_logs (
    id BIGSERIAL PRIMARY KEY,

    notification_type VARCHAR(20) CHECK (notification_type IN ('email', 'slack', 'discord')),

    alert_type VARCHAR(50),
    severity VARCHAR(20) CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),

    target_id INTEGER REFERENCES targets(id) ON DELETE SET NULL,
    target_hostname VARCHAR(255),

    recipient VARCHAR(500),

    subject VARCHAR(500),
    message TEXT,

    success BOOLEAN DEFAULT TRUE,
    error_message TEXT,

    sent_at TIMESTAMP DEFAULT NOW(),

    fingerprint VARCHAR(64)
);

CREATE INDEX idx_notification_logs_type ON notification_logs(notification_type, sent_at DESC);
CREATE INDEX idx_notification_logs_alert ON notification_logs(alert_type, sent_at DESC);
CREATE INDEX idx_notification_logs_target ON notification_logs(target_id, sent_at DESC);
CREATE INDEX idx_notification_logs_date ON notification_logs(sent_at DESC);
CREATE INDEX idx_notification_logs_fingerprint ON notification_logs(fingerprint, sent_at DESC);

-- ============================================================================
-- 6. COMPLIANCE SYSTEM (from migration 002)
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

-- Insert default compliance policies
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

-- Old compliance tables from 001 (kept for compatibility)
CREATE TABLE compliance_checks (
    id BIGSERIAL PRIMARY KEY,

    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,

    standard VARCHAR(50) NOT NULL,
    check_id VARCHAR(100) NOT NULL,
    check_name VARCHAR(255) NOT NULL,
    category VARCHAR(100),

    status VARCHAR(20) CHECK (status IN ('pass', 'fail', 'warning', 'not_applicable')),
    score INTEGER,

    details TEXT,
    recommendation TEXT,

    evidence JSONB,

    checked_at TIMESTAMP DEFAULT NOW(),

    check_version VARCHAR(20),
    automated BOOLEAN DEFAULT TRUE
);

CREATE INDEX idx_compliance_checks_target ON compliance_checks(target_id, checked_at DESC);
CREATE INDEX idx_compliance_checks_standard ON compliance_checks(standard, status);
CREATE INDEX idx_compliance_checks_status ON compliance_checks(status);
CREATE INDEX idx_compliance_checks_date ON compliance_checks(checked_at DESC);

CREATE TABLE compliance_reports (
    id SERIAL PRIMARY KEY,

    target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,
    standard VARCHAR(50) NOT NULL,

    report_type VARCHAR(20) CHECK (report_type IN ('full', 'executive', 'delta')),
    title VARCHAR(255),

    total_checks INTEGER,
    checks_passed INTEGER,
    checks_failed INTEGER,
    checks_warning INTEGER,
    overall_score INTEGER,
    compliance_status VARCHAR(20) CHECK (compliance_status IN ('compliant', 'non_compliant', 'partial')),

    report_data JSONB,
    report_pdf_path TEXT,

    generated_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    generated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_compliance_reports_target ON compliance_reports(target_id, generated_at DESC);
CREATE INDEX idx_compliance_reports_standard ON compliance_reports(standard, generated_at DESC);
CREATE INDEX idx_compliance_reports_date ON compliance_reports(generated_at DESC);

-- ============================================================================
-- 7. INTEGRATIONS (from migration 005)
-- ============================================================================

CREATE TABLE integration_configs (
    id SERIAL PRIMARY KEY,

    service_name VARCHAR(50) UNIQUE NOT NULL,

    base_url VARCHAR(500) NOT NULL,
    api_key VARCHAR(500),

    is_enabled BOOLEAN DEFAULT TRUE,
    last_sync TIMESTAMP,
    last_sync_status VARCHAR(20) CHECK (last_sync_status IN ('success', 'failed', 'partial')),
    last_error TEXT,

    rate_limit_per_hour INTEGER DEFAULT 1000,

    sync_interval_minutes INTEGER DEFAULT 60,
    auto_sync_enabled BOOLEAN DEFAULT TRUE,

    field_mappings JSONB,

    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_integration_configs_service ON integration_configs(service_name);
CREATE INDEX idx_integration_configs_enabled ON integration_configs(is_enabled) WHERE is_enabled = TRUE;

CREATE TABLE integration_sync_logs (
    id BIGSERIAL PRIMARY KEY,

    integration_id INTEGER NOT NULL REFERENCES integration_configs(id) ON DELETE CASCADE,

    sync_type VARCHAR(50),
    started_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP,
    duration_seconds INTEGER,

    status VARCHAR(20) CHECK (status IN ('success', 'failed', 'partial')),
    records_fetched INTEGER,
    records_created INTEGER,
    records_updated INTEGER,
    records_failed INTEGER,

    error_message TEXT,
    error_details JSONB,

    triggered_by INTEGER REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX idx_integration_sync_logs_integration ON integration_sync_logs(integration_id, started_at DESC);
CREATE INDEX idx_integration_sync_logs_status ON integration_sync_logs(status);
CREATE INDEX idx_integration_sync_logs_date ON integration_sync_logs(started_at DESC);

-- Sentinel Core vulnerabilities table (EXTENDED VERSION from 005)
CREATE TABLE sentinel_vulnerabilities (
    id SERIAL PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    cve_id VARCHAR(50) NOT NULL,
    title VARCHAR(500),
    description TEXT,
    severity VARCHAR(20) NOT NULL,
    cvss_score DECIMAL(3,1),
    cvss_vector VARCHAR(100),
    epss_score DECIMAL(5,4),
    affected_packages TEXT[],
    published_date TIMESTAMP WITH TIME ZONE,
    last_modified_date TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(target_id, cve_id)
);

CREATE INDEX idx_sentinel_vulnerabilities_target ON sentinel_vulnerabilities(target_id);
CREATE INDEX idx_sentinel_vulnerabilities_cve ON sentinel_vulnerabilities(cve_id);
CREATE INDEX idx_sentinel_vulnerabilities_severity ON sentinel_vulnerabilities(severity);
CREATE INDEX idx_sentinel_vulnerabilities_cvss ON sentinel_vulnerabilities(cvss_score DESC);

COMMENT ON TABLE sentinel_vulnerabilities IS 'Vulnerabilities synced from Sentinel Core';
COMMENT ON COLUMN sentinel_vulnerabilities.epss_score IS 'Exploit Prediction Scoring System score (0.0-1.0)';

-- Vulnerability scan history
CREATE TABLE sentinel_scan_history (
    id SERIAL PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    scan_id VARCHAR(100) NOT NULL,
    scan_type VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL,
    vulnerabilities_found INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_sentinel_scan_target ON sentinel_scan_history(target_id);
CREATE INDEX idx_sentinel_scan_id ON sentinel_scan_history(scan_id);
CREATE INDEX idx_sentinel_scan_status ON sentinel_scan_history(status);

COMMENT ON TABLE sentinel_scan_history IS 'History of vulnerability scans triggered via Sentinel Core';

-- FireDog threats table (EXTENDED VERSION from 005)
CREATE TABLE firedog_threats (
    id SERIAL PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    firedog_threat_id INTEGER NOT NULL,
    source_ip INET NOT NULL,
    destination_ip INET NOT NULL,
    destination_port INTEGER,
    threat_type VARCHAR(100) NOT NULL,
    classification VARCHAR(50),
    score DECIMAL(4,2) NOT NULL,
    details TEXT,
    detected_at TIMESTAMP WITH TIME ZONE NOT NULL,
    acknowledged BOOLEAN DEFAULT FALSE,
    acknowledged_by VARCHAR(100),
    acknowledged_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(firedog_threat_id)
);

CREATE INDEX idx_firedog_threats_target ON firedog_threats(target_id);
CREATE INDEX idx_firedog_threats_source_ip ON firedog_threats(source_ip);
CREATE INDEX idx_firedog_threats_score ON firedog_threats(score DESC);
CREATE INDEX idx_firedog_threats_detected ON firedog_threats(detected_at DESC);
CREATE INDEX idx_firedog_threats_acknowledged ON firedog_threats(acknowledged) WHERE NOT acknowledged;

COMMENT ON TABLE firedog_threats IS 'Threats synced from FireDog firewall system';
COMMENT ON COLUMN firedog_threats.score IS 'Threat severity score (0.0-10.0)';

-- FireDog target statistics
CREATE TABLE firedog_statistics (
    id SERIAL PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    input_packets BIGINT DEFAULT 0,
    output_packets BIGINT DEFAULT 0,
    input_dropped BIGINT DEFAULT 0,
    output_dropped BIGINT DEFAULT 0,
    input_drop_rate DECIMAL(5,2),
    output_drop_rate DECIMAL(5,2),
    threats_detected INTEGER DEFAULT 0,
    last_threat_at TIMESTAMP WITH TIME ZONE,
    collected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_firedog_stats_target ON firedog_statistics(target_id);
CREATE INDEX idx_firedog_stats_collected ON firedog_statistics(collected_at DESC);

COMMENT ON TABLE firedog_statistics IS 'Network statistics from FireDog for each target';

-- Security correlations table (EXTENDED VERSION from 005)
CREATE TABLE security_correlations (
    id SERIAL PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    correlation_type VARCHAR(50) NOT NULL,
    risk_level VARCHAR(20) NOT NULL,

    -- Vulnerability data
    vulnerability_cve VARCHAR(50),
    vulnerability_cvss DECIMAL(3,1),
    vulnerability_severity VARCHAR(20),

    -- Threat data
    threat_source_ip INET,
    threat_type VARCHAR(100),
    threat_score DECIMAL(4,2),

    -- Correlation metadata
    correlation_confidence DECIMAL(3,2) NOT NULL,
    correlation_rule VARCHAR(100),
    recommended_action TEXT NOT NULL,

    -- Status
    status VARCHAR(20) DEFAULT 'new',
    acknowledged BOOLEAN DEFAULT FALSE,
    acknowledged_by VARCHAR(100),
    acknowledged_at TIMESTAMP WITH TIME ZONE,
    resolved BOOLEAN DEFAULT FALSE,
    resolved_by VARCHAR(100),
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolution_notes TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_correlations_target ON security_correlations(target_id);
CREATE INDEX idx_correlations_risk ON security_correlations(risk_level);
CREATE INDEX idx_correlations_status ON security_correlations(status);
CREATE INDEX idx_correlations_created ON security_correlations(created_at DESC);
CREATE INDEX idx_correlations_cve ON security_correlations(vulnerability_cve) WHERE vulnerability_cve IS NOT NULL;
CREATE INDEX idx_correlations_threat_ip ON security_correlations(threat_source_ip) WHERE threat_source_ip IS NOT NULL;

COMMENT ON TABLE security_correlations IS 'Security event correlations between vulnerabilities and threats';
COMMENT ON COLUMN security_correlations.correlation_confidence IS 'Confidence score (0.0-1.0)';
COMMENT ON COLUMN security_correlations.correlation_type IS 'Type: vuln_threat_match, targeted_attack, privesc_attempt, etc.';

-- Integration settings table
CREATE TABLE integration_settings (
    id SERIAL PRIMARY KEY,
    integration_name VARCHAR(50) NOT NULL UNIQUE,
    enabled BOOLEAN DEFAULT FALSE,
    base_url VARCHAR(500),
    api_key_encrypted TEXT,
    sync_interval_minutes INTEGER DEFAULT 5,
    last_sync_at TIMESTAMP WITH TIME ZONE,
    last_sync_status VARCHAR(20),
    last_sync_error TEXT,
    auto_sync BOOLEAN DEFAULT TRUE,
    config_json JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_integration_name ON integration_settings(integration_name);

COMMENT ON TABLE integration_settings IS 'Configuration for external integrations (Sentinel Core, FireDog)';

-- Insert default integration settings
INSERT INTO integration_settings (integration_name, enabled, sync_interval_minutes, config_json)
VALUES
    ('sentinel_core', FALSE, 5, '{"auto_create_assets": true, "auto_trigger_scans": false}'::jsonb),
    ('firedog', FALSE, 5, '{"auto_block_high_threats": false, "auto_acknowledge_handled_threats": true}'::jsonb)
ON CONFLICT (integration_name) DO NOTHING;

-- Integration sync log
CREATE TABLE integration_sync_log (
    id SERIAL PRIMARY KEY,
    integration_name VARCHAR(50) NOT NULL,
    sync_type VARCHAR(50) NOT NULL,
    status VARCHAR(20) NOT NULL,
    records_synced INTEGER DEFAULT 0,
    records_failed INTEGER DEFAULT 0,
    error_message TEXT,
    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE,
    duration_seconds DECIMAL(10,2),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_sync_log_integration ON integration_sync_log(integration_name);
CREATE INDEX idx_sync_log_status ON integration_sync_log(status);
CREATE INDEX idx_sync_log_started ON integration_sync_log(started_at DESC);

COMMENT ON TABLE integration_sync_log IS 'Log of integration synchronization operations';

-- Automated actions table
CREATE TABLE automated_actions (
    id SERIAL PRIMARY KEY,
    correlation_id INTEGER REFERENCES security_correlations(id) ON DELETE CASCADE,
    action_type VARCHAR(50) NOT NULL,
    action_target VARCHAR(200) NOT NULL,
    action_details JSONB,
    status VARCHAR(20) DEFAULT 'pending',
    executed_at TIMESTAMP WITH TIME ZONE,
    execution_result TEXT,
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_automated_actions_correlation ON automated_actions(correlation_id);
CREATE INDEX idx_automated_actions_status ON automated_actions(status);
CREATE INDEX idx_automated_actions_type ON automated_actions(action_type);

COMMENT ON TABLE automated_actions IS 'Automated response actions triggered by correlations';
COMMENT ON COLUMN automated_actions.action_type IS 'Type: block_ip, apply_hardening, send_alert, etc.';

-- ============================================================================
-- 8. COMPLIANCE FRAMEWORKS & ALERTING (from migration 006)
-- ============================================================================

-- Compliance frameworks table (CIS, PCI-DSS, NIST, ISO27001, etc.)
CREATE TABLE compliance_frameworks (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    display_name VARCHAR(200) NOT NULL,
    description TEXT,
    version VARCHAR(50),
    category VARCHAR(50),
    enabled BOOLEAN DEFAULT true,
    severity_threshold VARCHAR(20) DEFAULT 'medium',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_compliance_frameworks_enabled ON compliance_frameworks(enabled);
CREATE INDEX idx_compliance_frameworks_category ON compliance_frameworks(category);

COMMENT ON TABLE compliance_frameworks IS 'Security compliance frameworks (CIS, PCI-DSS, NIST, etc.)';

-- Insert default frameworks
INSERT INTO compliance_frameworks (name, display_name, description, version, category)
VALUES
    ('cis_debian', 'CIS Debian Linux Benchmark', 'Center for Internet Security Debian Linux hardening guidelines', '2.0', 'os_hardening'),
    ('cis_ubuntu', 'CIS Ubuntu Linux Benchmark', 'Center for Internet Security Ubuntu Linux hardening guidelines', '2.0', 'os_hardening'),
    ('pci_dss', 'PCI-DSS', 'Payment Card Industry Data Security Standard', '4.0', 'data_protection'),
    ('nist_csf', 'NIST Cybersecurity Framework', 'NIST framework for improving critical infrastructure cybersecurity', '1.1', 'security_framework'),
    ('iso_27001', 'ISO/IEC 27001', 'Information security management system requirements', '2013', 'security_framework'),
    ('gdpr', 'GDPR Compliance', 'General Data Protection Regulation requirements', '2016', 'data_protection'),
    ('hipaa', 'HIPAA Security Rule', 'Health Insurance Portability and Accountability Act', '2013', 'data_protection')
ON CONFLICT (name) DO NOTHING;

-- Compliance controls/requirements table
CREATE TABLE compliance_controls (
    id SERIAL PRIMARY KEY,
    framework_id INTEGER NOT NULL REFERENCES compliance_frameworks(id) ON DELETE CASCADE,
    control_id VARCHAR(50) NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL,
    category VARCHAR(100),
    automated_check BOOLEAN DEFAULT false,
    check_query TEXT,
    remediation_guidance TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(framework_id, control_id)
);

CREATE INDEX idx_compliance_controls_framework ON compliance_controls(framework_id);
CREATE INDEX idx_compliance_controls_severity ON compliance_controls(severity);
CREATE INDEX idx_compliance_controls_automated ON compliance_controls(automated_check) WHERE automated_check = true;

COMMENT ON TABLE compliance_controls IS 'Individual controls/requirements within compliance frameworks';

-- Compliance assessment results
CREATE TABLE compliance_assessments (
    id SERIAL PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    framework_id INTEGER NOT NULL REFERENCES compliance_frameworks(id) ON DELETE CASCADE,
    assessment_date TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    total_controls INTEGER NOT NULL,
    passed_controls INTEGER DEFAULT 0,
    failed_controls INTEGER DEFAULT 0,
    not_applicable INTEGER DEFAULT 0,
    compliance_score DECIMAL(5,2),
    status VARCHAR(20) DEFAULT 'in_progress',
    assessed_by VARCHAR(100),
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_compliance_assessments_target ON compliance_assessments(target_id);
CREATE INDEX idx_compliance_assessments_framework ON compliance_assessments(framework_id);
CREATE INDEX idx_compliance_assessments_date ON compliance_assessments(assessment_date DESC);
CREATE INDEX idx_compliance_assessments_score ON compliance_assessments(compliance_score DESC);

COMMENT ON TABLE compliance_assessments IS 'Compliance assessment results per target and framework';

-- Compliance control results
CREATE TABLE compliance_control_results (
    id SERIAL PRIMARY KEY,
    assessment_id INTEGER NOT NULL REFERENCES compliance_assessments(id) ON DELETE CASCADE,
    control_id INTEGER NOT NULL REFERENCES compliance_controls(id) ON DELETE CASCADE,
    status VARCHAR(20) NOT NULL,
    evidence TEXT,
    findings TEXT,
    remediation_status VARCHAR(20),
    remediation_notes TEXT,
    assessed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_compliance_control_results_assessment ON compliance_control_results(assessment_id);
CREATE INDEX idx_compliance_control_results_control ON compliance_control_results(control_id);
CREATE INDEX idx_compliance_control_results_status ON compliance_control_results(status);

COMMENT ON TABLE compliance_control_results IS 'Individual control assessment results';

-- Alert channels (email, slack, webhook, etc.)
CREATE TABLE alert_channels (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    channel_type VARCHAR(50) NOT NULL,
    enabled BOOLEAN DEFAULT true,
    configuration JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_alert_channels_type ON alert_channels(channel_type);
CREATE INDEX idx_alert_channels_enabled ON alert_channels(enabled) WHERE enabled = true;

COMMENT ON TABLE alert_channels IS 'Alert delivery channels (email, Slack, webhooks, etc.)';

-- Insert default channels
INSERT INTO alert_channels (name, channel_type, enabled, configuration)
VALUES
    ('system_email', 'email', false, '{"smtp_host": "localhost", "smtp_port": 25, "from_address": "alerts@cybersheppard.local"}'::jsonb),
    ('slack_security', 'slack', false, '{"webhook_url": "", "channel": "#security-alerts"}'::jsonb),
    ('webhook_siem', 'webhook', false, '{"url": "", "method": "POST", "headers": {}}'::jsonb)
ON CONFLICT (name) DO NOTHING;

-- Alert rules
CREATE TABLE alert_rules (
    id SERIAL PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    enabled BOOLEAN DEFAULT true,
    severity VARCHAR(20) NOT NULL,
    trigger_type VARCHAR(50) NOT NULL,
    trigger_conditions JSONB NOT NULL,
    throttle_minutes INTEGER DEFAULT 60,
    channels INTEGER[] NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_alert_rules_enabled ON alert_rules(enabled) WHERE enabled = true;
CREATE INDEX idx_alert_rules_severity ON alert_rules(severity);
CREATE INDEX idx_alert_rules_type ON alert_rules(trigger_type);

COMMENT ON TABLE alert_rules IS 'Alert rules configuration';
COMMENT ON COLUMN alert_rules.trigger_type IS 'Type: violation_detected, correlation_created, threshold_exceeded, compliance_failed';

-- Alerts table
CREATE TABLE alerts (
    id SERIAL PRIMARY KEY,
    rule_id INTEGER REFERENCES alert_rules(id) ON DELETE SET NULL,
    severity VARCHAR(20) NOT NULL,
    title VARCHAR(500) NOT NULL,
    message TEXT NOT NULL,
    alert_type VARCHAR(50) NOT NULL,
    entity_type VARCHAR(50),
    entity_id INTEGER,
    metadata JSONB,
    status VARCHAR(20) DEFAULT 'new',
    acknowledged BOOLEAN DEFAULT false,
    acknowledged_by VARCHAR(100),
    acknowledged_at TIMESTAMP WITH TIME ZONE,
    resolved BOOLEAN DEFAULT false,
    resolved_by VARCHAR(100),
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolution_notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_alerts_rule ON alerts(rule_id);
CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_type ON alerts(alert_type);
CREATE INDEX idx_alerts_status ON alerts(status);
CREATE INDEX idx_alerts_created ON alerts(created_at DESC);
CREATE INDEX idx_alerts_unresolved ON alerts(status) WHERE NOT resolved;

COMMENT ON TABLE alerts IS 'System alerts and notifications';
COMMENT ON COLUMN alerts.alert_type IS 'Type: security_violation, compliance_failure, threat_detected, system_error';

-- Alert deliveries (tracking)
CREATE TABLE alert_deliveries (
    id SERIAL PRIMARY KEY,
    alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    channel_id INTEGER NOT NULL REFERENCES alert_channels(id) ON DELETE CASCADE,
    status VARCHAR(20) NOT NULL,
    attempts INTEGER DEFAULT 1,
    last_attempt_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    delivered_at TIMESTAMP WITH TIME ZONE,
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_alert_deliveries_alert ON alert_deliveries(alert_id);
CREATE INDEX idx_alert_deliveries_channel ON alert_deliveries(channel_id);
CREATE INDEX idx_alert_deliveries_status ON alert_deliveries(status);

COMMENT ON TABLE alert_deliveries IS 'Alert delivery tracking per channel';

-- Report templates
CREATE TABLE report_templates (
    id SERIAL PRIMARY KEY,
    name VARCHAR(200) NOT NULL UNIQUE,
    template_type VARCHAR(50) NOT NULL,
    format VARCHAR(20) NOT NULL,
    template_content TEXT NOT NULL,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_report_templates_type ON report_templates(template_type);
CREATE INDEX idx_report_templates_enabled ON report_templates(enabled) WHERE enabled = true;

COMMENT ON TABLE report_templates IS 'Report templates for compliance and security reports';

-- Generated reports
CREATE TABLE generated_reports (
    id SERIAL PRIMARY KEY,
    template_id INTEGER REFERENCES report_templates(id) ON DELETE SET NULL,
    report_name VARCHAR(300) NOT NULL,
    file_path TEXT NOT NULL,
    generated_by VARCHAR(100),
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_generated_reports_template ON generated_reports(template_id);
CREATE INDEX idx_generated_reports_date ON generated_reports(generated_at DESC);

COMMENT ON TABLE generated_reports IS 'History of generated compliance and security reports';

-- ============================================================================
-- 9. SYSTEM SETTINGS (from migration 001)
-- ============================================================================

CREATE TABLE system_settings (
    id SERIAL PRIMARY KEY,

    category VARCHAR(50) NOT NULL,
    key VARCHAR(100) NOT NULL,

    value_type VARCHAR(20) CHECK (value_type IN ('string', 'integer', 'boolean', 'json')),
    value_string TEXT,
    value_integer INTEGER,
    value_boolean BOOLEAN,
    value_json JSONB,

    description TEXT,
    default_value TEXT,
    is_sensitive BOOLEAN DEFAULT FALSE,

    updated_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    updated_at TIMESTAMP DEFAULT NOW(),

    CONSTRAINT unique_category_key UNIQUE (category, key)
);

CREATE INDEX idx_system_settings_category ON system_settings(category);
CREATE INDEX idx_system_settings_key ON system_settings(key);

-- Insert default settings
INSERT INTO system_settings (category, key, value_type, value_integer, description) VALUES
    ('monitoring', 'default_interval_seconds', 'integer', 30, 'Default monitoring interval'),
    ('monitoring', 'data_retention_days', 'integer', 90, 'Days to keep monitoring data'),
    ('security', 'session_timeout_minutes', 'integer', 30, 'JWT session timeout'),
    ('security', 'max_login_attempts', 'integer', 5, 'Max failed login attempts before lockout'),
    ('security', 'lockout_duration_minutes', 'integer', 15, 'Account lockout duration');

-- ============================================================================
-- 10. FUNCTIONS, TRIGGERS, AND VIEWS
-- ============================================================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Triggers for updated_at on various tables
CREATE TRIGGER update_compliance_policies_updated_at
    BEFORE UPDATE ON compliance_policies
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_sentinel_vulnerabilities_updated_at
    BEFORE UPDATE ON sentinel_vulnerabilities
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_security_correlations_updated_at
    BEFORE UPDATE ON security_correlations
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_integration_settings_updated_at
    BEFORE UPDATE ON integration_settings
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

-- High-risk targets view
CREATE OR REPLACE VIEW high_risk_targets AS
SELECT
    t.id,
    t.hostname,
    t.ip_address,
    t.environment,
    COUNT(DISTINCT sv.id) as vulnerability_count,
    COUNT(DISTINCT CASE WHEN sv.severity IN ('critical', 'high') THEN sv.id END) as critical_vuln_count,
    COUNT(DISTINCT ft.id) as threat_count,
    COUNT(DISTINCT CASE WHEN ft.score >= 7.0 THEN ft.id END) as high_threat_count,
    COUNT(DISTINCT sc.id) as correlation_count,
    MAX(sv.cvss_score) as max_cvss_score,
    MAX(ft.score) as max_threat_score,
    MAX(ft.detected_at) as last_threat_at
FROM targets t
LEFT JOIN sentinel_vulnerabilities sv ON t.id = sv.target_id
LEFT JOIN firedog_threats ft ON t.id = ft.target_id
LEFT JOIN security_correlations sc ON t.id = sc.target_id
GROUP BY t.id, t.hostname, t.ip_address, t.environment
HAVING
    COUNT(DISTINCT CASE WHEN sv.severity IN ('critical', 'high') THEN sv.id END) > 0
    OR COUNT(DISTINCT CASE WHEN ft.score >= 7.0 THEN ft.id END) > 0
    OR COUNT(DISTINCT sc.id) > 0
ORDER BY
    correlation_count DESC,
    max_cvss_score DESC NULLS LAST,
    max_threat_score DESC NULLS LAST;

COMMENT ON VIEW high_risk_targets IS 'Targets with critical vulnerabilities, high threats, or security correlations';

-- Active security correlations view
CREATE OR REPLACE VIEW active_security_correlations AS
SELECT
    sc.id,
    sc.target_id,
    t.hostname,
    t.ip_address,
    sc.correlation_type,
    sc.risk_level,
    sc.vulnerability_cve,
    sc.vulnerability_cvss,
    sc.threat_source_ip,
    sc.threat_type,
    sc.threat_score,
    sc.correlation_confidence,
    sc.recommended_action,
    sc.status,
    sc.created_at,
    COUNT(aa.id) as automated_actions_count,
    COUNT(CASE WHEN aa.status = 'completed' THEN aa.id END) as completed_actions_count
FROM security_correlations sc
INNER JOIN targets t ON sc.target_id = t.id
LEFT JOIN automated_actions aa ON sc.id = aa.correlation_id
WHERE sc.status != 'resolved'
GROUP BY
    sc.id, t.hostname, t.ip_address
ORDER BY
    sc.created_at DESC,
    CASE sc.risk_level
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
    END;

COMMENT ON VIEW active_security_correlations IS 'Active (unresolved) security correlations with action status';

-- Target compliance overview view
CREATE OR REPLACE VIEW target_compliance_overview AS
SELECT
    t.id as target_id,
    t.hostname,
    t.ip_address,
    COUNT(DISTINCT cv.id) FILTER (WHERE cv.status IN ('new', 'acknowledged')) as active_violations,
    COUNT(DISTINCT cv.id) FILTER (WHERE cv.severity = 'critical') as critical_violations,
    COUNT(DISTINCT cv.id) FILTER (WHERE cv.severity = 'high') as high_violations,
    calculate_compliance_score(t.id) as compliance_score,
    MAX(cv.first_detected_at) as last_violation_at
FROM targets t
LEFT JOIN compliance_violations cv ON t.id = cv.target_id
GROUP BY t.id, t.hostname, t.ip_address;

COMMENT ON VIEW target_compliance_overview IS 'Compliance status overview per target';

-- Active alerts view
CREATE OR REPLACE VIEW active_alerts AS
SELECT
    a.id,
    a.severity,
    a.title,
    a.alert_type,
    a.status,
    a.acknowledged,
    a.created_at,
    COUNT(ad.id) as delivery_attempts,
    COUNT(CASE WHEN ad.status = 'delivered' THEN ad.id END) as successful_deliveries
FROM alerts a
LEFT JOIN alert_deliveries ad ON a.id = ad.alert_id
WHERE NOT a.resolved
GROUP BY a.id
ORDER BY
    a.created_at DESC,
    CASE a.severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        WHEN 'info' THEN 5
    END;

COMMENT ON VIEW active_alerts IS 'All active (unresolved) alerts with delivery status';

-- Framework compliance summary view
CREATE OR REPLACE VIEW framework_compliance_summary AS
SELECT
    cf.id as framework_id,
    cf.name,
    cf.display_name,
    COUNT(DISTINCT ca.id) as assessments_count,
    AVG(ca.compliance_score) as avg_compliance_score,
    COUNT(DISTINCT ca.target_id) as targets_assessed,
    MAX(ca.assessment_date) as last_assessment_date
FROM compliance_frameworks cf
LEFT JOIN compliance_assessments ca ON cf.id = ca.framework_id
WHERE cf.enabled = true
GROUP BY cf.id, cf.name, cf.display_name
ORDER BY avg_compliance_score DESC NULLS LAST;

COMMENT ON VIEW framework_compliance_summary IS 'Compliance summary per framework across all targets';

-- ============================================================================
-- 11. CLEANUP FUNCTIONS
-- ============================================================================

CREATE OR REPLACE FUNCTION cleanup_old_data() RETURNS void AS $$
BEGIN
    DELETE FROM audit_logs WHERE timestamp < NOW() - INTERVAL '1 year';
    DELETE FROM notification_logs WHERE sent_at < NOW() - INTERVAL '90 days';
    DELETE FROM refresh_tokens WHERE expires_at < NOW();
    DELETE FROM csrf_tokens WHERE expires_at < NOW();
    DELETE FROM integration_sync_logs WHERE started_at < NOW() - INTERVAL '30 days';
    DELETE FROM integration_sync_log WHERE started_at < NOW() - INTERVAL '30 days';

    VACUUM ANALYZE audit_logs;
    VACUUM ANALYZE notification_logs;
    VACUUM ANALYZE refresh_tokens;
    VACUUM ANALYZE csrf_tokens;

    RAISE NOTICE 'General data cleanup completed';
END;
$$ LANGUAGE plpgsql;

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
-- END OF COMPLETE SCHEMA
-- ============================================================================

-- ============================================================================
-- SCHEMA FIXES FOR CODE COMPATIBILITY
-- ============================================================================

-- Add missing columns to existing tables
ALTER TABLE targets ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE;
ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS token VARCHAR(512); -- For compatibility
ALTER TABLE csrf_tokens ADD COLUMN IF NOT EXISTS token VARCHAR(512); -- For compatibility  
ALTER TABLE compliance_violations ADD COLUMN IF NOT EXISTS alert_generated BOOLEAN DEFAULT FALSE;
ALTER TABLE compliance_violations ADD COLUMN IF NOT EXISTS alert_id INTEGER REFERENCES alerts(id) ON DELETE SET NULL;

-- Add indexes for new columns
CREATE INDEX IF NOT EXISTS idx_targets_is_active ON targets(is_active);
CREATE INDEX IF NOT EXISTS idx_compliance_violations_alert ON compliance_violations(alert_id);
