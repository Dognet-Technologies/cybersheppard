-- ============================================================================
-- CYBERSHEPPARD (MicroSIEM) - Initial Database Schema
-- Migration: 001_initial_schema.sql
-- Description: Create all initial tables
-- Date: 2025-11-30
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
-- 2. SSH KEYS MANAGEMENT (RIUSATO DA FIREDOG)
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

CREATE TABLE hardening_applications (
    id SERIAL PRIMARY KEY,

    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    model_id INTEGER NOT NULL REFERENCES hardening_models(id) ON DELETE RESTRICT,

    applied_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    applied_at TIMESTAMP DEFAULT NOW(),

    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'in_progress', 'completed', 'failed', 'rolled_back')),
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    duration_seconds INTEGER,

    steps_total INTEGER,
    steps_completed INTEGER,
    steps_failed INTEGER,

    result_log TEXT,
    error_message TEXT,

    rollback_available BOOLEAN DEFAULT TRUE,
    backup_path TEXT,
    rolled_back_at TIMESTAMP,
    rolled_back_by INTEGER REFERENCES users(id) ON DELETE SET NULL,

    pre_apply_checks JSONB,
    post_apply_checks JSONB
);

CREATE INDEX idx_hardening_apps_target ON hardening_applications(target_id, applied_at DESC);
CREATE INDEX idx_hardening_apps_model ON hardening_applications(model_id, applied_at DESC);
CREATE INDEX idx_hardening_apps_status ON hardening_applications(status);
CREATE INDEX idx_hardening_apps_date ON hardening_applications(applied_at DESC);

-- ============================================================================
-- 5. NOTIFICATIONS (RIUSATO DA FIREDOG)
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
-- 6. COMPLIANCE
-- ============================================================================

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
-- 7. INTEGRATIONS
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

-- Tables for integration data (Sentinel Core & FireDog)
CREATE TABLE sentinel_vulnerabilities (
    id SERIAL PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,

    cve_id VARCHAR(50) NOT NULL,
    severity VARCHAR(20),
    cvss_score DECIMAL(3,1),
    epss_score DECIMAL(5,4),

    description TEXT,
    published_date TIMESTAMP,

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),

    CONSTRAINT unique_target_cve UNIQUE (target_id, cve_id)
);

CREATE INDEX idx_sentinel_vulns_target ON sentinel_vulnerabilities(target_id, severity);
CREATE INDEX idx_sentinel_vulns_cve ON sentinel_vulnerabilities(cve_id);
CREATE INDEX idx_sentinel_vulns_severity ON sentinel_vulnerabilities(severity, cvss_score DESC);

CREATE TABLE firedog_threats (
    id SERIAL PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,

    firedog_threat_id INTEGER NOT NULL,
    source_ip INET NOT NULL,
    threat_type VARCHAR(50),
    classification VARCHAR(20),
    score INTEGER,

    details TEXT,
    detected_at TIMESTAMP,

    created_at TIMESTAMP DEFAULT NOW(),

    CONSTRAINT unique_firedog_threat UNIQUE (firedog_threat_id)
);

CREATE INDEX idx_firedog_threats_target ON firedog_threats(target_id, detected_at DESC);
CREATE INDEX idx_firedog_threats_source ON firedog_threats(source_ip, detected_at DESC);
CREATE INDEX idx_firedog_threats_type ON firedog_threats(threat_type, classification);

CREATE TABLE security_correlations (
    id SERIAL PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,

    vulnerability_cve VARCHAR(50),
    vulnerability_cvss DECIMAL(3,1),

    threat_source_ip INET,
    threat_type VARCHAR(50),
    threat_score INTEGER,

    correlation_confidence DECIMAL(3,2),
    recommended_action TEXT,

    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_security_corr_target ON security_correlations(target_id, created_at DESC);
CREATE INDEX idx_security_corr_cve ON security_correlations(vulnerability_cve);
CREATE INDEX idx_security_corr_ip ON security_correlations(threat_source_ip);

-- ============================================================================
-- 8. SYSTEM SETTINGS
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
-- 9. CLEANUP FUNCTION
-- ============================================================================

CREATE OR REPLACE FUNCTION cleanup_old_data() RETURNS void AS $$
BEGIN
    DELETE FROM audit_logs WHERE timestamp < NOW() - INTERVAL '1 year';
    DELETE FROM notification_logs WHERE sent_at < NOW() - INTERVAL '90 days';
    DELETE FROM refresh_tokens WHERE expires_at < NOW();
    DELETE FROM csrf_tokens WHERE expires_at < NOW();
    DELETE FROM integration_sync_logs WHERE started_at < NOW() - INTERVAL '30 days';

    VACUUM ANALYZE audit_logs;
    VACUUM ANALYZE notification_logs;
    VACUUM ANALYZE refresh_tokens;
    VACUUM ANALYZE csrf_tokens;

    RAISE NOTICE 'Cleanup completed';
END;
$$ LANGUAGE plpgsql;

COMMIT;

-- ============================================================================
-- END OF MIGRATION
-- ============================================================================
