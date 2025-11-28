# MicroSIEM (CyberSheppard) - Database Schema

## 📋 Indice

1. [Overview](#overview)
2. [PostgreSQL Schema](#postgresql-schema)
3. [InfluxDB Schema](#influxdb-schema)
4. [Relazioni tra Entità](#relazioni-tra-entità)
5. [Migrations](#migrations)
6. [Indexes e Performance](#indexes-e-performance)
7. [Data Retention Policies](#data-retention-policies)

---

## Overview

**Database Strategy**: Hybrid approach con PostgreSQL e InfluxDB

### PostgreSQL (Relational Data)
- **Uso**: Metadata, configurazioni, utenti, target, modelli hardening
- **Port**: 5432
- **Database Name**: `microsiem`
- **User**: `microsiem`
- **Encoding**: UTF8
- **Timezone**: UTC

### InfluxDB (Time-Series Data)
- **Uso**: Metriche, log, eventi di sicurezza, correlazioni
- **Port**: 8086
- **Organization**: `microsiem`
- **Bucket**: `metrics` (30d retention), `logs` (90d retention)
- **Precision**: Nanosecond

---

## PostgreSQL Schema

### 1. Users & Authentication

```sql
-- ============================================================================
-- USERS TABLE
-- ============================================================================
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,  -- bcrypt/argon2
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

-- ============================================================================
-- REFRESH TOKENS TABLE
-- ============================================================================
CREATE TABLE refresh_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL UNIQUE,  -- SHA256 of actual token
    
    -- Token metadata
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    last_used_at TIMESTAMP,
    
    -- Security tracking
    created_ip INET NOT NULL,
    user_agent TEXT,
    
    -- Revocation
    is_revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMP,
    revoked_reason VARCHAR(100)
);

CREATE INDEX idx_refresh_tokens_user ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_hash ON refresh_tokens(token_hash);
CREATE INDEX idx_refresh_tokens_expires ON refresh_tokens(expires_at);
CREATE INDEX idx_refresh_tokens_active ON refresh_tokens(user_id, is_revoked) 
    WHERE is_revoked = FALSE;

-- ============================================================================
-- CSRF TOKENS TABLE
-- ============================================================================
CREATE TABLE csrf_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL UNIQUE,  -- SHA256 of actual token
    
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    
    -- Single-use enforcement
    is_used BOOLEAN DEFAULT FALSE,
    used_at TIMESTAMP
);

CREATE INDEX idx_csrf_tokens_user ON csrf_tokens(user_id);
CREATE INDEX idx_csrf_tokens_hash ON csrf_tokens(token_hash);
CREATE INDEX idx_csrf_tokens_expires ON csrf_tokens(expires_at);

-- ============================================================================
-- PASSWORD RESET TOKENS TABLE
-- ============================================================================
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

-- ============================================================================
-- AUDIT LOGS TABLE
-- ============================================================================
CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    username VARCHAR(50),  -- Denormalized for deleted users
    
    -- Action details
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id INTEGER,
    
    -- Request context
    ip_address INET NOT NULL,
    user_agent TEXT,
    
    -- Additional data
    details JSONB,
    
    -- Result
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT,
    
    timestamp TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_user ON audit_logs(user_id, timestamp DESC);
CREATE INDEX idx_audit_logs_action ON audit_logs(action, timestamp DESC);
CREATE INDEX idx_audit_logs_resource ON audit_logs(resource_type, resource_id);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX idx_audit_logs_ip ON audit_logs(ip_address, timestamp DESC);

-- Partitioning by month for performance (optional)
-- CREATE TABLE audit_logs_y2025m01 PARTITION OF audit_logs
--     FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');

```

---

### 2. Targets Management

```sql
-- ============================================================================
-- TARGETS TABLE
-- ============================================================================
CREATE TABLE targets (
    id SERIAL PRIMARY KEY,
    
    -- Identification
    hostname VARCHAR(255) NOT NULL,
    ip_address INET NOT NULL,
    
    -- SSH connection
    ssh_port INTEGER DEFAULT 22 CHECK (ssh_port > 0 AND ssh_port <= 65535),
    ssh_username VARCHAR(50) DEFAULT 'microcyber',
    ssh_key_id INTEGER REFERENCES ssh_keys(id) ON DELETE SET NULL,
    
    -- Classification
    role VARCHAR(50),  -- web, database, dns, gateway, storage, generic
    environment VARCHAR(20) DEFAULT 'production',  -- production, staging, development
    gruppo VARCHAR(100),  -- Logical grouping (e.g., "webservers", "databases")
    tags JSONB DEFAULT '[]',  -- Flexible tagging
    
    -- Compliance
    compliance_standard VARCHAR(50),  -- nis2, pci, iso27001, none
    
    -- Status
    status VARCHAR(20) DEFAULT 'pending' 
        CHECK (status IN ('pending', 'active', 'offline', 'error', 'maintenance')),
    status_message TEXT,
    last_seen TIMESTAMP,
    last_check TIMESTAMP,
    
    -- Hardening
    hardening_applied BOOLEAN DEFAULT FALSE,
    hardening_model_id INTEGER REFERENCES hardening_models(id) ON DELETE SET NULL,
    hardening_applied_at TIMESTAMP,
    hardening_score INTEGER CHECK (hardening_score >= 0 AND hardening_score <= 100),
    
    -- Monitoring
    monitoring_enabled BOOLEAN DEFAULT TRUE,
    monitoring_interval_seconds INTEGER DEFAULT 30,
    last_monitoring_at TIMESTAMP,
    monitoring_errors_count INTEGER DEFAULT 0,
    
    -- Metadata
    description TEXT,
    notes TEXT,
    
    -- Ownership
    added_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    
    -- Constraints
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

-- ============================================================================
-- TARGET GROUPS TABLE
-- ============================================================================
CREATE TABLE target_groups (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    
    -- Group settings
    default_ssh_key_id INTEGER REFERENCES ssh_keys(id) ON DELETE SET NULL,
    default_monitoring_interval INTEGER DEFAULT 30,
    
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_target_groups_name ON target_groups(name);

-- ============================================================================
-- TARGET NETWORK INTERFACES TABLE
-- ============================================================================
CREATE TABLE target_network_interfaces (
    id SERIAL PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    
    interface_name VARCHAR(50) NOT NULL,  -- eth0, ens33, etc.
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

```

---

### 3. Hardening Models

```sql
-- ============================================================================
-- HARDENING MODELS TABLE
-- ============================================================================
CREATE TABLE hardening_models (
    id SERIAL PRIMARY KEY,
    
    -- Model identification
    name VARCHAR(100) UNIQUE NOT NULL,
    version VARCHAR(20) DEFAULT '1.0.0',
    description TEXT,
    
    -- Classification
    role VARCHAR(50),  -- web, database, dns, gateway, storage, generic
    compliance_standard VARCHAR(50),  -- nis2, pci, iso27001, none
    level VARCHAR(20) CHECK (level IN ('base', 'severo')),
    
    -- Model content
    model_path TEXT NOT NULL,  -- Path to model directory
    files_count INTEGER DEFAULT 0,
    
    -- Integrity
    hash_sha512 VARCHAR(128) NOT NULL,
    
    -- Metadata
    author VARCHAR(100),
    supported_os JSONB DEFAULT '[]',  -- ["debian11", "debian12", "ubuntu22.04"]
    
    -- Post-apply actions
    services_to_enable JSONB DEFAULT '[]',
    services_to_disable JSONB DEFAULT '[]',
    packages_to_install JSONB DEFAULT '[]',
    packages_to_remove JSONB DEFAULT '[]',
    requires_reboot BOOLEAN DEFAULT FALSE,
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    is_validated BOOLEAN DEFAULT FALSE,
    validation_errors JSONB,
    
    -- Ownership
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

-- ============================================================================
-- HARDENING APPLICATIONS TABLE
-- ============================================================================
CREATE TABLE hardening_applications (
    id SERIAL PRIMARY KEY,
    
    -- References
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    model_id INTEGER NOT NULL REFERENCES hardening_models(id) ON DELETE RESTRICT,
    
    -- Application details
    applied_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    applied_at TIMESTAMP DEFAULT NOW(),
    
    -- Execution
    status VARCHAR(20) DEFAULT 'pending' 
        CHECK (status IN ('pending', 'in_progress', 'completed', 'failed', 'rolled_back')),
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    duration_seconds INTEGER,
    
    -- Results
    steps_total INTEGER,
    steps_completed INTEGER,
    steps_failed INTEGER,
    
    result_log TEXT,  -- Detailed execution log
    error_message TEXT,
    
    -- Rollback
    rollback_available BOOLEAN DEFAULT TRUE,
    backup_path TEXT,  -- Path to backup files
    rolled_back_at TIMESTAMP,
    rolled_back_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    
    -- Validation
    pre_apply_checks JSONB,
    post_apply_checks JSONB
);

CREATE INDEX idx_hardening_apps_target ON hardening_applications(target_id, applied_at DESC);
CREATE INDEX idx_hardening_apps_model ON hardening_applications(model_id, applied_at DESC);
CREATE INDEX idx_hardening_apps_status ON hardening_applications(status);
CREATE INDEX idx_hardening_apps_date ON hardening_applications(applied_at DESC);

-- ============================================================================
-- HARDENING FILES TABLE (Model Contents)
-- ============================================================================
CREATE TABLE hardening_files (
    id SERIAL PRIMARY KEY,
    model_id INTEGER NOT NULL REFERENCES hardening_models(id) ON DELETE CASCADE,
    
    -- File identification
    file_name VARCHAR(255) NOT NULL,  -- e.g., "etc.ssh.sshd_config"
    target_path TEXT NOT NULL,  -- e.g., "/etc/ssh/sshd_config"
    
    -- File content
    content TEXT NOT NULL,
    hash_sha256 VARCHAR(64) NOT NULL,
    
    -- Metadata
    file_size INTEGER,
    file_mode VARCHAR(4) DEFAULT '0644',  -- Octal permissions
    file_owner VARCHAR(50) DEFAULT 'root',
    file_group VARCHAR(50) DEFAULT 'root',
    
    created_at TIMESTAMP DEFAULT NOW(),
    
    CONSTRAINT unique_model_file UNIQUE (model_id, file_name)
);

CREATE INDEX idx_hardening_files_model ON hardening_files(model_id);
CREATE INDEX idx_hardening_files_path ON hardening_files(target_path);
CREATE INDEX idx_hardening_files_hash ON hardening_files(hash_sha256);

```

---

### 4. SSH Keys Management (RIUSATO DA FIREDOG)

```sql
-- ============================================================================
-- SSH KEYS TABLE
-- RIUSATO 100% DA FIREDOG
-- ============================================================================
CREATE TABLE ssh_keys (
    id SERIAL PRIMARY KEY,
    
    -- Key identification
    name VARCHAR(255) NOT NULL,
    fingerprint VARCHAR(255) UNIQUE NOT NULL,
    
    -- Key type
    key_type VARCHAR(20) NOT NULL CHECK (key_type IN ('ed25519', 'rsa', 'ecdsa')),
    key_size INTEGER,  -- For RSA/ECDSA
    
    -- Key material
    public_key TEXT NOT NULL,
    private_key TEXT NOT NULL,  -- ENCRYPTED (Fernet)
    
    -- Scope
    scope VARCHAR(20) DEFAULT 'global' 
        CHECK (scope IN ('global', 'group', 'target')),
    scope_value VARCHAR(255),  -- Group name or target ID if scoped
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Usage tracking
    last_used_at TIMESTAMP,
    usage_count INTEGER DEFAULT 0,
    
    -- Rotation
    rotation_days INTEGER DEFAULT 90,
    next_rotation_date DATE,
    
    -- Ownership
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_ssh_keys_scope ON ssh_keys(scope, scope_value);
CREATE INDEX idx_ssh_keys_fingerprint ON ssh_keys(fingerprint);
CREATE INDEX idx_ssh_keys_active ON ssh_keys(is_active) WHERE is_active = TRUE;
CREATE INDEX idx_ssh_keys_rotation ON ssh_keys(next_rotation_date) WHERE is_active = TRUE;

```

---

### 5. Notifications (RIUSATO DA FIREDOG)

```sql
-- ============================================================================
-- NOTIFICATION CONFIG TABLE (SINGLETON)
-- RIUSATO 100% DA FIREDOG
-- ============================================================================
CREATE TABLE notification_config (
    id INTEGER PRIMARY KEY DEFAULT 1,  -- Singleton pattern
    
    -- Email configuration
    email_enabled BOOLEAN DEFAULT FALSE,
    email_recipients JSONB DEFAULT '[]',  -- ["admin@example.com", "security@example.com"]
    smtp_host VARCHAR(255) DEFAULT 'localhost',
    smtp_port INTEGER DEFAULT 587,
    smtp_user VARCHAR(255) DEFAULT 'microcyber',
    smtp_password VARCHAR(500),  -- ENCRYPTED (Fernet)
    smtp_use_tls BOOLEAN DEFAULT TRUE,
    smtp_from_email VARCHAR(255) DEFAULT 'microsiem@localhost',
    
    -- Slack configuration
    slack_enabled BOOLEAN DEFAULT FALSE,
    slack_webhook_url VARCHAR(500),
    slack_channel VARCHAR(100),
    
    -- Discord configuration
    discord_enabled BOOLEAN DEFAULT FALSE,
    discord_webhook_url VARCHAR(500),
    
    -- Alert triggers
    alert_on_critical_threat BOOLEAN DEFAULT TRUE,
    alert_on_high_threat BOOLEAN DEFAULT TRUE,
    alert_on_target_offline BOOLEAN DEFAULT TRUE,
    alert_on_hardening_failed BOOLEAN DEFAULT TRUE,
    alert_on_compliance_failed BOOLEAN DEFAULT TRUE,
    
    -- Thresholds
    target_offline_threshold_minutes INTEGER DEFAULT 5,
    cooldown_minutes INTEGER DEFAULT 60,  -- Min time between duplicate alerts
    
    -- Metadata
    updated_at TIMESTAMP DEFAULT NOW(),
    updated_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    
    CONSTRAINT ensure_singleton CHECK (id = 1)
);

-- Insert default config
INSERT INTO notification_config (id) VALUES (1)
ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- NOTIFICATION LOGS TABLE
-- RIUSATO 100% DA FIREDOG
-- ============================================================================
CREATE TABLE notification_logs (
    id BIGSERIAL PRIMARY KEY,
    
    -- Notification type
    notification_type VARCHAR(20) 
        CHECK (notification_type IN ('email', 'slack', 'discord')),
    
    -- Alert details
    alert_type VARCHAR(50),  -- target_offline, hardening_failed, threat_detected, etc.
    severity VARCHAR(20) CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    
    -- Target context (optional)
    target_id INTEGER REFERENCES targets(id) ON DELETE SET NULL,
    target_hostname VARCHAR(255),
    
    -- Recipient
    recipient VARCHAR(500),  -- Email address or webhook URL
    
    -- Message
    subject VARCHAR(500),
    message TEXT,
    
    -- Result
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT,
    
    -- Timing
    sent_at TIMESTAMP DEFAULT NOW(),
    
    -- Deduplication
    fingerprint VARCHAR(64)  -- Hash of (alert_type + target_id) for deduplication
);

CREATE INDEX idx_notification_logs_type ON notification_logs(notification_type, sent_at DESC);
CREATE INDEX idx_notification_logs_alert ON notification_logs(alert_type, sent_at DESC);
CREATE INDEX idx_notification_logs_target ON notification_logs(target_id, sent_at DESC);
CREATE INDEX idx_notification_logs_date ON notification_logs(sent_at DESC);
CREATE INDEX idx_notification_logs_fingerprint ON notification_logs(fingerprint, sent_at DESC);

```

---

### 6. Compliance Checks

```sql
-- ============================================================================
-- COMPLIANCE CHECKS TABLE
-- ============================================================================
CREATE TABLE compliance_checks (
    id BIGSERIAL PRIMARY KEY,
    
    -- Target
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    
    -- Check details
    standard VARCHAR(50) NOT NULL,  -- nis2, pci, iso27001
    check_id VARCHAR(100) NOT NULL,  -- e.g., "nis2_001", "pci_2.2.4"
    check_name VARCHAR(255) NOT NULL,
    category VARCHAR(100),  -- access_control, network_security, etc.
    
    -- Result
    status VARCHAR(20) CHECK (status IN ('pass', 'fail', 'warning', 'not_applicable')),
    score INTEGER,  -- 0-100
    
    -- Details
    details TEXT,
    recommendation TEXT,
    
    -- Evidence
    evidence JSONB,  -- JSON with proof/data
    
    -- Timing
    checked_at TIMESTAMP DEFAULT NOW(),
    
    -- Metadata
    check_version VARCHAR(20),
    automated BOOLEAN DEFAULT TRUE
);

CREATE INDEX idx_compliance_checks_target ON compliance_checks(target_id, checked_at DESC);
CREATE INDEX idx_compliance_checks_standard ON compliance_checks(standard, status);
CREATE INDEX idx_compliance_checks_status ON compliance_checks(status);
CREATE INDEX idx_compliance_checks_date ON compliance_checks(checked_at DESC);

-- ============================================================================
-- COMPLIANCE REPORTS TABLE
-- ============================================================================
CREATE TABLE compliance_reports (
    id SERIAL PRIMARY KEY,
    
    -- Report scope
    target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,  -- NULL for global report
    standard VARCHAR(50) NOT NULL,
    
    -- Report details
    report_type VARCHAR(20) CHECK (report_type IN ('full', 'executive', 'delta')),
    title VARCHAR(255),
    
    -- Results summary
    total_checks INTEGER,
    checks_passed INTEGER,
    checks_failed INTEGER,
    checks_warning INTEGER,
    overall_score INTEGER,  -- 0-100
    compliance_status VARCHAR(20) CHECK (compliance_status IN ('compliant', 'non_compliant', 'partial')),
    
    -- Report data
    report_data JSONB,  -- Full report in JSON format
    report_pdf_path TEXT,  -- Path to generated PDF
    
    -- Generation
    generated_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    generated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_compliance_reports_target ON compliance_reports(target_id, generated_at DESC);
CREATE INDEX idx_compliance_reports_standard ON compliance_reports(standard, generated_at DESC);
CREATE INDEX idx_compliance_reports_date ON compliance_reports(generated_at DESC);

```

---

### 7. Integration Settings

```sql
-- ============================================================================
-- INTEGRATION CONFIGS TABLE
-- ============================================================================
CREATE TABLE integration_configs (
    id SERIAL PRIMARY KEY,
    
    -- Integration identification
    service_name VARCHAR(50) UNIQUE NOT NULL,  -- sentinel_core, firedog
    
    -- Connection
    base_url VARCHAR(500) NOT NULL,
    api_key VARCHAR(500),  -- ENCRYPTED (Fernet)
    
    -- Status
    is_enabled BOOLEAN DEFAULT TRUE,
    last_sync TIMESTAMP,
    last_sync_status VARCHAR(20) CHECK (last_sync_status IN ('success', 'failed', 'partial')),
    last_error TEXT,
    
    -- Rate limiting
    rate_limit_per_hour INTEGER DEFAULT 1000,
    
    -- Sync settings
    sync_interval_minutes INTEGER DEFAULT 60,
    auto_sync_enabled BOOLEAN DEFAULT TRUE,
    
    -- Data mapping
    field_mappings JSONB,  -- Custom field mappings
    
    -- Metadata
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_integration_configs_service ON integration_configs(service_name);
CREATE INDEX idx_integration_configs_enabled ON integration_configs(is_enabled) WHERE is_enabled = TRUE;

-- ============================================================================
-- INTEGRATION SYNC LOGS TABLE
-- ============================================================================
CREATE TABLE integration_sync_logs (
    id BIGSERIAL PRIMARY KEY,
    
    integration_id INTEGER NOT NULL REFERENCES integration_configs(id) ON DELETE CASCADE,
    
    -- Sync details
    sync_type VARCHAR(50),  -- full, incremental, manual
    started_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP,
    duration_seconds INTEGER,
    
    -- Results
    status VARCHAR(20) CHECK (status IN ('success', 'failed', 'partial')),
    records_fetched INTEGER,
    records_created INTEGER,
    records_updated INTEGER,
    records_failed INTEGER,
    
    -- Error details
    error_message TEXT,
    error_details JSONB,
    
    triggered_by INTEGER REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX idx_integration_sync_logs_integration ON integration_sync_logs(integration_id, started_at DESC);
CREATE INDEX idx_integration_sync_logs_status ON integration_sync_logs(status);
CREATE INDEX idx_integration_sync_logs_date ON integration_sync_logs(started_at DESC);

```

---

### 8. System Settings

```sql
-- ============================================================================
-- SYSTEM SETTINGS TABLE
-- ============================================================================
CREATE TABLE system_settings (
    id SERIAL PRIMARY KEY,
    
    -- Setting identification
    category VARCHAR(50) NOT NULL,  -- monitoring, security, notification, etc.
    key VARCHAR(100) NOT NULL,
    
    -- Value (flexible types)
    value_type VARCHAR(20) CHECK (value_type IN ('string', 'integer', 'boolean', 'json')),
    value_string TEXT,
    value_integer INTEGER,
    value_boolean BOOLEAN,
    value_json JSONB,
    
    -- Metadata
    description TEXT,
    default_value TEXT,
    is_sensitive BOOLEAN DEFAULT FALSE,  -- Hide in UI
    
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
    ('security', 'lockout_duration_minutes', 'integer', 15, 'Account lockout duration')
ON CONFLICT (category, key) DO NOTHING;

-- ============================================================================
-- TEMPLATES TABLE (Future: Marketplace)
-- ============================================================================
CREATE TABLE templates (
    id SERIAL PRIMARY KEY,
    
    -- Template identification
    name VARCHAR(100) UNIQUE NOT NULL,
    version VARCHAR(20) DEFAULT '1.0.0',
    description TEXT,
    
    -- Template type
    template_type VARCHAR(50) NOT NULL,  -- hardening_model, monitoring_script, dashboard
    
    -- Source
    source VARCHAR(20) CHECK (source IN ('builtin', 'marketplace', 'custom')),
    repository_url VARCHAR(500),  -- GitHub URL for marketplace templates
    
    -- Content
    content JSONB,  -- Template data/configuration
    
    -- Metadata
    author VARCHAR(100),
    tags JSONB DEFAULT '[]',
    downloads_count INTEGER DEFAULT 0,
    rating_average DECIMAL(2,1),
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    is_verified BOOLEAN DEFAULT FALSE,
    
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_templates_type ON templates(template_type);
CREATE INDEX idx_templates_source ON templates(source);
CREATE INDEX idx_templates_active ON templates(is_active) WHERE is_active = TRUE;

```

---

## InfluxDB Schema

### Buckets

```javascript
// Create buckets with retention policies
CREATE BUCKET metrics
  WITH DURATION 30d
  SHARD DURATION 1d;

CREATE BUCKET logs
  WITH DURATION 90d
  SHARD DURATION 7d;

CREATE BUCKET correlations
  WITH DURATION 365d
  SHARD DURATION 30d;
```

---

### Measurements

#### 1. Target Metrics (from monitoring scripts)

```javascript
// ============================================================================
// MEASUREMENT: target_system_metrics
// ============================================================================
{
  measurement: "target_system_metrics",
  
  tags: {
    target_id: "123",
    hostname: "webserver-01",
    ip_address: "192.168.1.10",
    role: "web",
    environment: "production"
  },
  
  fields: {
    // CPU
    cpu_usage_percent: 45.2,
    cpu_load_1min: 1.5,
    cpu_load_5min: 1.2,
    cpu_load_15min: 1.0,
    
    // Memory
    memory_total_mb: 8192,
    memory_used_mb: 4096,
    memory_free_mb: 4096,
    memory_usage_percent: 50.0,
    swap_total_mb: 2048,
    swap_used_mb: 0,
    
    // Disk
    disk_root_total_gb: 100,
    disk_root_used_gb: 45,
    disk_root_free_gb: 55,
    disk_root_usage_percent: 45.0,
    
    // Network
    network_rx_bytes: 1234567890,
    network_tx_bytes: 9876543210,
    network_rx_packets: 123456,
    network_tx_packets: 98765,
    
    // Uptime
    uptime_seconds: 86400
  },
  
  timestamp: "2025-11-28T10:30:00Z"
}

// ============================================================================
// MEASUREMENT: target_hardening_status
// ============================================================================
{
  measurement: "target_hardening_status",
  
  tags: {
    target_id: "123",
    hostname: "webserver-01",
    model_name: "web_severo_nis2",
    compliance: "nis2"
  },
  
  fields: {
    hardening_score: 95,
    is_compliant: true,
    checks_total: 50,
    checks_passed: 48,
    checks_failed: 2,
    last_check_duration_seconds: 12.5
  },
  
  timestamp: "2025-11-28T10:30:00Z"
}

// ============================================================================
// MEASUREMENT: target_connections
// ============================================================================
{
  measurement: "target_connections",
  
  tags: {
    target_id: "123",
    hostname: "webserver-01",
    protocol: "tcp",
    state: "ESTABLISHED",
    local_port: "443"
  },
  
  fields: {
    count: 25,
    suspicious_count: 0,
    remote_ips: ["192.168.1.100", "192.168.1.101"],  // Array in JSON field
    remote_ips_unique: 2
  },
  
  timestamp: "2025-11-28T10:30:00Z"
}

// ============================================================================
// MEASUREMENT: target_services
// ============================================================================
{
  measurement: "target_services",
  
  tags: {
    target_id: "123",
    hostname: "webserver-01",
    service_name: "nginx",
    state: "active"
  },
  
  fields: {
    is_running: true,
    is_expected: true,
    pid: 1234,
    memory_mb: 45.2,
    cpu_percent: 2.5,
    unexpected_alert_triggered: false
  },
  
  timestamp: "2025-11-28T10:30:00Z"
}

// ============================================================================
// MEASUREMENT: target_users
// ============================================================================
{
  measurement: "target_users",
  
  tags: {
    target_id: "123",
    hostname: "webserver-01",
    username: "admin",
    terminal: "pts/0"
  },
  
  fields: {
    is_logged_in: true,
    login_time: "2025-11-28T09:00:00Z",
    remote_ip: "192.168.1.100",
    commands_count: 15,
    suspicious_commands_count: 0
  },
  
  timestamp: "2025-11-28T10:30:00Z"
}

// ============================================================================
// MEASUREMENT: target_packages
// ============================================================================
{
  measurement: "target_packages",
  
  tags: {
    target_id: "123",
    hostname: "webserver-01"
  },
  
  fields: {
    total_packages: 456,
    upgradable_packages: 3,
    security_updates_available: 1,
    vulnerable_packages_count: 1
  },
  
  timestamp: "2025-11-28T10:30:00Z"
}

```

---

#### 2. Auditd Events

```javascript
// ============================================================================
// MEASUREMENT: auditd_events
// ============================================================================
{
  measurement: "auditd_events",
  
  tags: {
    target_id: "123",
    hostname: "webserver-01",
    event_type: "SYSCALL",
    username: "admin",
    key: "sudoers",  // Audit rule key
    result: "success"
  },
  
  fields: {
    command: "vi /etc/sudoers",
    executable: "/usr/bin/vi",
    pid: 12345,
    ppid: 1234,
    uid: 1000,
    gid: 1000,
    cwd: "/home/admin",
    is_suspicious: false,
    severity: "info",  // info, warning, critical
    raw_event: "{...}"  // Full auditd event JSON
  },
  
  timestamp: "2025-11-28T10:30:15.123456789Z"
}

// ============================================================================
// MEASUREMENT: sudolog_events
// ============================================================================
{
  measurement: "sudolog_events",
  
  tags: {
    target_id: "123",
    hostname: "webserver-01",
    username: "admin",
    runas_user: "root",
    result: "success"
  },
  
  fields: {
    command: "systemctl restart nginx",
    tty: "pts/0",
    pwd: "/home/admin",
    is_suspicious: false,
    severity: "info"
  },
  
  timestamp: "2025-11-28T10:30:20Z"
}

// ============================================================================
// MEASUREMENT: privilege_escalation_vectors
// ============================================================================
{
  measurement: "privilege_escalation_vectors",
  
  tags: {
    target_id: "123",
    hostname: "webserver-01",
    vector_type: "suid_binary",
    severity: "high"
  },
  
  fields: {
    file_path: "/usr/bin/vim",
    permissions: "rwsr-xr-x",
    owner: "root",
    is_expected: false,
    cvss_score: 7.8,
    description: "Text editor with SUID bit - potential privesc"
  },
  
  timestamp: "2025-11-28T10:30:00Z"
}

```

---

#### 3. File Integrity

```javascript
// ============================================================================
// MEASUREMENT: file_integrity
// ============================================================================
{
  measurement: "file_integrity",
  
  tags: {
    target_id: "123",
    hostname: "webserver-01",
    file_path: "/etc/passwd",
    changed: "false"
  },
  
  fields: {
    hash_sha256: "abc123def456...",
    hash_sha512: "fedcba987654...",
    file_size: 1234,
    file_mode: "0644",
    file_owner: "root",
    file_group: "root",
    last_modified: "2025-11-20T10:00:00Z"
  },
  
  timestamp: "2025-11-28T10:30:00Z"
}

```

---

#### 4. Integration Data (Sentinel Core & FireDog)

```javascript
// ============================================================================
// MEASUREMENT: sentinel_vulnerabilities
// ============================================================================
{
  measurement: "sentinel_vulnerabilities",
  
  tags: {
    target_id: "123",
    target_hostname: "webserver-01",
    cve_id: "CVE-2024-12345",
    severity: "CRITICAL",
    asset_name: "webserver-01"
  },
  
  fields: {
    cvss_score: 9.8,
    epss_score: 0.85,
    title: "Remote Code Execution in OpenSSL",
    description: "Critical RCE vulnerability...",
    remediation: "Upgrade OpenSSL to 3.0.12"
  },
  
  timestamp: "2025-11-28T10:00:00Z"
}

// ============================================================================
// MEASUREMENT: firedog_threats
// ============================================================================
{
  measurement: "firedog_threats",
  
  tags: {
    target_id: "123",
    target_hostname: "webserver-01",
    target_ip: "192.168.1.10",
    source_ip: "203.0.113.45",
    threat_type: "PORT_SCAN",
    classification: "HIGH"
  },
  
  fields: {
    score: 75,
    details: "Port scan detected from 203.0.113.45: 1024 ports scanned in 60 seconds",
    acknowledged: false
  },
  
  timestamp: "2025-11-28T10:25:30Z"
}

// ============================================================================
// MEASUREMENT: firedog_statistics
// ============================================================================
{
  measurement: "firedog_statistics",
  
  tags: {
    target_id: "123",
    target_hostname: "webserver-01",
    target_ip: "192.168.1.10"
  },
  
  fields: {
    input_packets: 1234567,
    output_packets: 987654,
    input_dropped: 123,
    output_dropped: 12,
    input_drop_rate: 0.01,
    output_drop_rate: 0.001,
    pcap_input_size: 10485760,
    pcap_output_size: 5242880
  },
  
  timestamp: "2025-11-28T10:30:00Z"
}

```

---

#### 5. Correlation Data

```javascript
// ============================================================================
// MEASUREMENT: security_correlations
// ============================================================================
{
  measurement: "security_correlations",
  
  tags: {
    target_id: "123",
    hostname: "webserver-01",
    correlation_type: "vuln_threat_match",
    severity: "CRITICAL"
  },
  
  fields: {
    vulnerability_cve: "CVE-2024-12345",
    vulnerability_cvss: 9.8,
    threat_source_ip: "203.0.113.45",
    threat_type: "EXPLOIT_ATTEMPT",
    threat_score: 95,
    correlation_confidence: 0.92,
    description: "Exploit attempt detected for known vulnerability",
    recommended_action: "IMMEDIATE: Block source IP and patch system"
  },
  
  timestamp: "2025-11-28T10:30:00Z"
}

```

---

## Relazioni tra Entità

### Entity Relationship Diagram

```
┌──────────────┐         ┌──────────────┐
│    users     │────┬───<│ audit_logs   │
└──────────────┘    │    └──────────────┘
       │            │
       │            │    ┌──────────────────┐
       │            ├───<│ refresh_tokens   │
       │            │    └──────────────────┘
       │            │
       │            │    ┌──────────────────┐
       │            └───<│ csrf_tokens      │
       │                 └──────────────────┘
       │
       ├──────────┬──────────────────────────────┐
       │          │                              │
       ▼          ▼                              ▼
┌──────────┐  ┌──────────────┐      ┌──────────────────┐
│ targets  │  │hardening_    │      │notification_     │
│          │  │models        │      │config            │
└────┬─────┘  └──────┬───────┘      └──────────────────┘
     │               │
     │               │         ┌─────────────────┐
     │               └────────<│hardening_files  │
     │                         └─────────────────┘
     │
     ├───────────────┬─────────────┬──────────────┬───────────────┐
     │               │             │              │               │
     ▼               ▼             ▼              ▼               ▼
┌─────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────────┐
│hardening│  │compliance│  │target_   │  │notif_    │  │integration_ │
│_apps    │  │_checks   │  │network_  │  │logs      │  │sync_logs    │
│         │  │          │  │interfaces│  │          │  │             │
└─────────┘  └──────────┘  └──────────┘  └──────────┘  └─────────────┘

┌──────────────┐
│  ssh_keys    │─────> Used by targets, target_groups
└──────────────┘

┌──────────────┐
│integration_  │─────> Sentinel Core, FireDog
│configs       │
└──────────────┘
```

---

## Migrations

### Initial Migration (001_initial_schema.sql)

```sql
-- ============================================================================
-- MIGRATION: 001_initial_schema.sql
-- Description: Create initial database schema
-- Date: 2025-11-28
-- ============================================================================

BEGIN;

-- Create users table
CREATE TABLE users (
    -- [Full schema from above]
);

-- Create refresh_tokens table
CREATE TABLE refresh_tokens (
    -- [Full schema from above]
);

-- ... [All other tables]

-- Create indexes
-- ... [All indexes from above]

-- Insert default data
INSERT INTO notification_config (id) VALUES (1)
ON CONFLICT (id) DO NOTHING;

INSERT INTO system_settings (category, key, value_type, value_integer, description) VALUES
    ('monitoring', 'default_interval_seconds', 'integer', 30, 'Default monitoring interval'),
    -- ... [Other default settings]
ON CONFLICT (category, key) DO NOTHING;

COMMIT;
```

### Migration 002: Add Templates Support

```sql
-- ============================================================================
-- MIGRATION: 002_add_templates.sql
-- Description: Add templates table for marketplace
-- Date: 2025-12-01
-- ============================================================================

BEGIN;

CREATE TABLE templates (
    -- [Full schema from above]
);

CREATE INDEX idx_templates_type ON templates(template_type);
CREATE INDEX idx_templates_source ON templates(source);
CREATE INDEX idx_templates_active ON templates(is_active) WHERE is_active = TRUE;

COMMIT;
```

---

## Indexes e Performance

### Query Optimization

#### 1. Most Frequent Queries

```sql
-- Query: Get active targets for monitoring
SELECT id, hostname, ip_address, ssh_port, ssh_username
FROM targets
WHERE status = 'active' AND monitoring_enabled = TRUE;

-- Index: idx_targets_active (already created)
-- Performance: O(log n) due to B-tree index

-- Query: Get hardening applications for target (recent first)
SELECT * FROM hardening_applications
WHERE target_id = $1
ORDER BY applied_at DESC
LIMIT 10;

-- Index: idx_hardening_apps_target (already created)
-- Performance: O(log n + k) where k = 10

-- Query: Get audit logs for user (last 7 days)
SELECT * FROM audit_logs
WHERE user_id = $1 AND timestamp > NOW() - INTERVAL '7 days'
ORDER BY timestamp DESC
LIMIT 100;

-- Index: idx_audit_logs_user (already created)
-- Performance: O(log n + k) where k = 100
```

---

#### 2. Composite Indexes

```sql
-- For filtered queries with sorting
CREATE INDEX idx_targets_status_last_seen 
    ON targets(status, last_seen DESC);

-- For compliance queries
CREATE INDEX idx_compliance_checks_target_standard 
    ON compliance_checks(target_id, standard, checked_at DESC);

-- For notification deduplication
CREATE INDEX idx_notification_logs_dedup 
    ON notification_logs(fingerprint, sent_at DESC)
    WHERE sent_at > NOW() - INTERVAL '1 hour';
```

---

#### 3. Partial Indexes

```sql
-- Index only active entities
CREATE INDEX idx_ssh_keys_active_only 
    ON ssh_keys(scope, scope_value) 
    WHERE is_active = TRUE;

CREATE INDEX idx_targets_monitoring_enabled 
    ON targets(id, last_monitoring_at) 
    WHERE monitoring_enabled = TRUE AND status = 'active';

-- Index only recent data (hot data)
CREATE INDEX idx_audit_logs_recent 
    ON audit_logs(user_id, timestamp DESC)
    WHERE timestamp > NOW() - INTERVAL '30 days';
```

---

#### 4. GIN Indexes (for JSONB)

```sql
-- For searching in JSONB fields
CREATE INDEX idx_targets_tags_gin ON targets USING GIN (tags);
CREATE INDEX idx_hardening_models_supported_os_gin 
    ON hardening_models USING GIN (supported_os);

-- Query example:
SELECT * FROM targets 
WHERE tags @> '["production", "critical"]'::jsonb;
```

---

### Table Partitioning

#### Partition Audit Logs by Month

```sql
-- Convert audit_logs to partitioned table
CREATE TABLE audit_logs_new (
    LIKE audit_logs INCLUDING ALL
) PARTITION BY RANGE (timestamp);

-- Create partitions for 2025
CREATE TABLE audit_logs_y2025m11 PARTITION OF audit_logs_new
    FOR VALUES FROM ('2025-11-01') TO ('2025-12-01');

CREATE TABLE audit_logs_y2025m12 PARTITION OF audit_logs_new
    FOR VALUES FROM ('2025-12-01') TO ('2026-01-01');

-- Create default partition for future data
CREATE TABLE audit_logs_default PARTITION OF audit_logs_new DEFAULT;

-- Copy data and swap tables
INSERT INTO audit_logs_new SELECT * FROM audit_logs;
DROP TABLE audit_logs;
ALTER TABLE audit_logs_new RENAME TO audit_logs;
```

---

## Data Retention Policies

### PostgreSQL Retention

```sql
-- ============================================================================
-- CLEANUP FUNCTION: cleanup_old_data()
-- ============================================================================
CREATE OR REPLACE FUNCTION cleanup_old_data() RETURNS void AS $$
BEGIN
    -- Delete old audit logs (older than 1 year)
    DELETE FROM audit_logs 
    WHERE timestamp < NOW() - INTERVAL '1 year';
    
    -- Delete old notification logs (older than 90 days)
    DELETE FROM notification_logs 
    WHERE sent_at < NOW() - INTERVAL '90 days';
    
    -- Delete expired refresh tokens
    DELETE FROM refresh_tokens 
    WHERE expires_at < NOW();
    
    -- Delete expired CSRF tokens
    DELETE FROM csrf_tokens 
    WHERE expires_at < NOW();
    
    -- Delete old integration sync logs (older than 30 days)
    DELETE FROM integration_sync_logs 
    WHERE started_at < NOW() - INTERVAL '30 days';
    
    -- Vacuum tables to reclaim space
    VACUUM ANALYZE audit_logs;
    VACUUM ANALYZE notification_logs;
    VACUUM ANALYZE refresh_tokens;
    VACUUM ANALYZE csrf_tokens;
    
    RAISE NOTICE 'Cleanup completed';
END;
$$ LANGUAGE plpgsql;

-- Schedule cleanup (run daily at 2 AM)
-- Use pg_cron or external scheduler
SELECT cron.schedule('cleanup-old-data', '0 2 * * *', 'SELECT cleanup_old_data()');
```

---

### InfluxDB Retention

```javascript
// Retention policies configured at bucket creation

// metrics bucket: 30 days retention
CREATE BUCKET metrics 
  WITH DURATION 30d 
  SHARD DURATION 1d;

// logs bucket: 90 days retention
CREATE BUCKET logs 
  WITH DURATION 90d 
  SHARD DURATION 7d;

// correlations bucket: 1 year retention
CREATE BUCKET correlations 
  WITH DURATION 365d 
  SHARD DURATION 30d;

// Downsampling for long-term storage (optional)
CREATE TASK downsample_metrics
  EVERY 1h
  AS
    option task = {name: "downsample_metrics", every: 1h}
    
    from(bucket: "metrics")
      |> range(start: -1h)
      |> aggregateWindow(every: 5m, fn: mean)
      |> to(bucket: "metrics_downsampled", org: "microsiem")
```

---

## Database Configuration

### PostgreSQL Configuration Recommendations

```ini
# postgresql.conf optimizations for MicroSIEM

# Memory
shared_buffers = 2GB               # 25% of system RAM
effective_cache_size = 6GB         # 75% of system RAM
work_mem = 32MB
maintenance_work_mem = 512MB

# Connections
max_connections = 100
superuser_reserved_connections = 3

# Write Ahead Log
wal_level = replica
max_wal_size = 2GB
min_wal_size = 1GB
checkpoint_completion_target = 0.9

# Query Performance
random_page_cost = 1.1             # For SSD
effective_io_concurrency = 200     # For SSD

# Logging
logging_collector = on
log_directory = '/var/log/postgresql'
log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'
log_min_duration_statement = 1000  # Log queries > 1 second

# Autovacuum
autovacuum = on
autovacuum_max_workers = 4
autovacuum_naptime = 10s
```

---

### InfluxDB Configuration

```toml
# influxdb.conf

[data]
  dir = "/var/lib/influxdb/data"
  wal-dir = "/var/lib/influxdb/wal"
  
  # Cache settings
  cache-max-memory-size = 1073741824  # 1GB
  cache-snapshot-memory-size = 26214400  # 25MB
  
  # Compaction settings
  compact-full-write-cold-duration = "4h"
  max-concurrent-compactions = 0  # Auto (CPU cores / 2)

[coordinator]
  write-timeout = "10s"
  max-concurrent-queries = 0  # Unlimited
  query-timeout = "0s"  # Unlimited
  
[retention]
  enabled = true
  check-interval = "30m"

[http]
  enabled = true
  bind-address = ":8086"
  auth-enabled = true
  
[logging]
  level = "info"
```

---

## Backup Strategy

### PostgreSQL Backup

```bash
#!/bin/bash
# backup_postgresql.sh

BACKUP_DIR="/backups/postgresql"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DATABASE="microsiem"

# Full backup
pg_dump -U microsiem -h localhost -Fc $DATABASE > \
    "$BACKUP_DIR/microsiem_$TIMESTAMP.dump"

# Keep last 7 days
find $BACKUP_DIR -name "microsiem_*.dump" -mtime +7 -delete

# Backup to remote location (optional)
rsync -avz $BACKUP_DIR backup-server:/backups/microsiem/postgresql/
```

### InfluxDB Backup

```bash
#!/bin/bash
# backup_influxdb.sh

BACKUP_DIR="/backups/influxdb"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Backup all buckets
influx backup $BACKUP_DIR/$TIMESTAMP \
    --host http://localhost:8086 \
    --token $INFLUX_TOKEN

# Keep last 7 days
find $BACKUP_DIR -type d -mtime +7 -exec rm -rf {} +

# Backup to remote location (optional)
rsync -avz $BACKUP_DIR backup-server:/backups/microsiem/influxdb/
```

---

## Summary

### PostgreSQL Tables

| Categoria | Tabelle | Descrizione |
|-----------|---------|-------------|
| **Authentication** | 5 | users, refresh_tokens, csrf_tokens, password_reset_tokens, audit_logs |
| **Targets** | 3 | targets, target_groups, target_network_interfaces |
| **Hardening** | 3 | hardening_models, hardening_applications, hardening_files |
| **SSH & Notifications** | 3 | ssh_keys, notification_config, notification_logs |
| **Compliance** | 2 | compliance_checks, compliance_reports |
| **Integrations** | 2 | integration_configs, integration_sync_logs |
| **System** | 2 | system_settings, templates |
| **TOTALE** | **20 tabelle** | |

### InfluxDB Measurements

| Categoria | Measurements | Descrizione |
|-----------|--------------|-------------|
| **Target Metrics** | 6 | system_metrics, hardening_status, connections, services, users, packages |
| **Security Events** | 3 | auditd_events, sudolog_events, privilege_escalation_vectors |
| **File Integrity** | 1 | file_integrity |
| **Integrations** | 3 | sentinel_vulnerabilities, firedog_threats, firedog_statistics |
| **Correlations** | 1 | security_correlations |
| **TOTALE** | **14 measurements** | |

---

**Versione**: 1.0.0  
**Data**: 2025-11-28  
**Autore**: Development Team
