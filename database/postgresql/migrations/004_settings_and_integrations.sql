-- ============================================================================
-- CYBERSHEPPARD - Settings, API Keys and Integrations Schema
-- Migration 004
-- ============================================================================

-- ============================================================================
-- Settings Table
-- Key-value store for system-wide settings
-- ============================================================================

CREATE TABLE IF NOT EXISTS settings (
    id SERIAL PRIMARY KEY,
    key VARCHAR(255) UNIQUE NOT NULL,
    value TEXT NOT NULL,
    category VARCHAR(100) NOT NULL, -- 'system', 'appearance', 'notifications', etc.
    description TEXT,
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_by VARCHAR(100)
);

CREATE INDEX idx_settings_category ON settings(category);
CREATE INDEX idx_settings_key ON settings(key);

-- Insert default settings
INSERT INTO settings (key, value, category, description) VALUES
    ('theme', 'light', 'appearance', 'UI theme (light/dark)'),
    ('language', 'en', 'appearance', 'Interface language'),
    ('session_timeout', '3600', 'security', 'Session timeout in seconds'),
    ('enable_email_notifications', 'true', 'notifications', 'Enable email notifications'),
    ('enable_slack_notifications', 'false', 'notifications', 'Enable Slack notifications'),
    ('data_retention_days', '90', 'system', 'Number of days to retain data'),
    ('auto_cleanup_enabled', 'false', 'system', 'Enable automatic data cleanup')
ON CONFLICT (key) DO NOTHING;

-- ============================================================================
-- API Keys Table
-- Store API keys for authentication between services
-- ============================================================================

CREATE TABLE IF NOT EXISTS api_keys (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(255) UNIQUE NOT NULL, -- SHA256 hash of the API key
    key_prefix VARCHAR(20) NOT NULL, -- First 8 chars for identification (e.g., "cs_1234...")
    description TEXT,
    scopes TEXT[], -- Array of scopes: ['read', 'write', 'admin']
    is_active BOOLEAN NOT NULL DEFAULT true,
    expires_at TIMESTAMP,
    last_used_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    created_by VARCHAR(100) NOT NULL,
    revoked_at TIMESTAMP,
    revoked_by VARCHAR(100),

    CONSTRAINT chk_scopes CHECK (scopes IS NOT NULL AND array_length(scopes, 1) > 0)
);

CREATE INDEX idx_api_keys_key_hash ON api_keys(key_hash);
CREATE INDEX idx_api_keys_key_prefix ON api_keys(key_prefix);
CREATE INDEX idx_api_keys_is_active ON api_keys(is_active);
CREATE INDEX idx_api_keys_created_at ON api_keys(created_at DESC);

-- ============================================================================
-- Integrations Table
-- Store integration configurations (FireDog, CyberSheppard slave, etc.)
-- ============================================================================

CREATE TABLE IF NOT EXISTS integrations (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(100) NOT NULL, -- 'firedog', 'cybersheppard_slave', 'sentinel_core', etc.
    enabled BOOLEAN NOT NULL DEFAULT false,

    -- Connection details
    api_key VARCHAR(500), -- Encrypted API key
    hostname VARCHAR(500),
    ip_address VARCHAR(100),
    port INTEGER,
    use_ssl BOOLEAN DEFAULT true,

    -- Sync configuration
    sync_mode VARCHAR(50) DEFAULT 'pull', -- 'pull', 'push', 'bidirectional'
    sync_interval INTEGER DEFAULT 300, -- Sync interval in seconds
    last_sync_at TIMESTAMP,
    last_sync_status VARCHAR(50), -- 'success', 'failed', 'in_progress'
    last_sync_error TEXT,

    -- Additional config (JSON)
    config JSONB DEFAULT '{}',

    -- Metadata
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    created_by VARCHAR(100),

    CONSTRAINT chk_integration_type CHECK (type IN ('firedog', 'cybersheppard_slave', 'sentinel_core', 'custom')),
    CONSTRAINT chk_sync_mode CHECK (sync_mode IN ('pull', 'push', 'bidirectional'))
);

CREATE INDEX idx_integrations_type ON integrations(type);
CREATE INDEX idx_integrations_enabled ON integrations(enabled);
CREATE INDEX idx_integrations_last_sync_at ON integrations(last_sync_at DESC);

-- ============================================================================
-- System Status Log Table
-- Track system health metrics over time
-- ============================================================================

CREATE TABLE IF NOT EXISTS system_status_log (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL DEFAULT NOW(),

    -- System metrics
    cpu_usage_percent NUMERIC(5,2),
    memory_usage_percent NUMERIC(5,2),
    memory_total_mb BIGINT,
    memory_used_mb BIGINT,
    disk_usage_percent NUMERIC(5,2),
    disk_total_gb BIGINT,
    disk_used_gb BIGINT,

    -- Database metrics
    db_connections_active INTEGER,
    db_connections_idle INTEGER,
    db_connections_max INTEGER,
    db_size_mb BIGINT,
    db_tables_count INTEGER,

    -- Service status
    backend_healthy BOOLEAN DEFAULT true,
    database_healthy BOOLEAN DEFAULT true,
    agents_connected INTEGER DEFAULT 0,

    -- Additional metrics (JSON)
    metrics JSONB DEFAULT '{}'
);

CREATE INDEX idx_system_status_log_timestamp ON system_status_log(timestamp DESC);

-- Function to get latest system status
CREATE OR REPLACE FUNCTION get_latest_system_status()
RETURNS TABLE (
    cpu_usage_percent NUMERIC,
    memory_usage_percent NUMERIC,
    memory_total_mb BIGINT,
    memory_used_mb BIGINT,
    disk_usage_percent NUMERIC,
    disk_total_gb BIGINT,
    disk_used_gb BIGINT,
    db_connections_active INTEGER,
    db_connections_idle INTEGER,
    db_connections_max INTEGER,
    db_size_mb BIGINT,
    agents_connected INTEGER,
    recorded_at TIMESTAMP
)
LANGUAGE SQL
AS $$
    SELECT
        cpu_usage_percent,
        memory_usage_percent,
        memory_total_mb,
        memory_used_mb,
        disk_usage_percent,
        disk_total_gb,
        disk_used_gb,
        db_connections_active,
        db_connections_idle,
        db_connections_max,
        db_size_mb,
        agents_connected,
        timestamp
    FROM system_status_log
    ORDER BY timestamp DESC
    LIMIT 1;
$$;

-- ============================================================================
-- Database Cleanup Functions
-- Hard delete old data based on retention policies
-- ============================================================================

-- Function to clean up old audit events
CREATE OR REPLACE FUNCTION cleanup_old_auditd_events(retention_days INTEGER DEFAULT 90)
RETURNS TABLE (
    deleted_count BIGINT,
    cleanup_timestamp TIMESTAMP
)
LANGUAGE plpgsql
AS $$
DECLARE
    deleted_rows BIGINT;
BEGIN
    DELETE FROM auditd_events
    WHERE collected_at < NOW() - (retention_days || ' days')::INTERVAL;

    GET DIAGNOSTICS deleted_rows = ROW_COUNT;

    RETURN QUERY SELECT deleted_rows, NOW();
END;
$$;

-- Function to clean up old alerts
CREATE OR REPLACE FUNCTION cleanup_old_alerts(retention_days INTEGER DEFAULT 90)
RETURNS TABLE (
    deleted_count BIGINT,
    cleanup_timestamp TIMESTAMP
)
LANGUAGE plpgsql
AS $$
DECLARE
    deleted_rows BIGINT;
BEGIN
    DELETE FROM alerts
    WHERE created_at < NOW() - (retention_days || ' days')::INTERVAL
      AND resolved = true;

    GET DIAGNOSTICS deleted_rows = ROW_COUNT;

    RETURN QUERY SELECT deleted_rows, NOW();
END;
$$;

-- Function to clean up old system status logs
CREATE OR REPLACE FUNCTION cleanup_old_system_logs(retention_days INTEGER DEFAULT 30)
RETURNS TABLE (
    deleted_count BIGINT,
    cleanup_timestamp TIMESTAMP
)
LANGUAGE plpgsql
AS $$
DECLARE
    deleted_rows BIGINT;
BEGIN
    DELETE FROM system_status_log
    WHERE timestamp < NOW() - (retention_days || ' days')::INTERVAL;

    GET DIAGNOSTICS deleted_rows = ROW_COUNT;

    RETURN QUERY SELECT deleted_rows, NOW();
END;
$$;

-- Function to get database size information
CREATE OR REPLACE FUNCTION get_database_stats()
RETURNS TABLE (
    total_size_mb BIGINT,
    auditd_events_count BIGINT,
    auditd_events_size_mb BIGINT,
    alerts_count BIGINT,
    alerts_size_mb BIGINT,
    targets_count BIGINT,
    oldest_auditd_event TIMESTAMP,
    oldest_alert TIMESTAMP
)
LANGUAGE SQL
AS $$
    SELECT
        (pg_database_size(current_database()) / 1024 / 1024)::BIGINT as total_size_mb,
        (SELECT COUNT(*) FROM auditd_events)::BIGINT as auditd_events_count,
        (pg_total_relation_size('auditd_events') / 1024 / 1024)::BIGINT as auditd_events_size_mb,
        (SELECT COUNT(*) FROM alerts)::BIGINT as alerts_count,
        (pg_total_relation_size('alerts') / 1024 / 1024)::BIGINT as alerts_size_mb,
        (SELECT COUNT(*) FROM targets)::BIGINT as targets_count,
        (SELECT MIN(collected_at) FROM auditd_events) as oldest_auditd_event,
        (SELECT MIN(created_at) FROM alerts) as oldest_alert;
$$;

-- ============================================================================
-- Update triggers
-- ============================================================================

-- Trigger to update updated_at on settings table
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_settings_updated_at
    BEFORE UPDATE ON settings
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_integrations_updated_at
    BEFORE UPDATE ON integrations
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Comments
-- ============================================================================

COMMENT ON TABLE settings IS 'System-wide settings stored as key-value pairs';
COMMENT ON TABLE api_keys IS 'API keys for authentication between services';
COMMENT ON TABLE integrations IS 'External service integrations configuration';
COMMENT ON TABLE system_status_log IS 'Historical system health metrics';

COMMENT ON FUNCTION cleanup_old_auditd_events IS 'Hard delete audit events older than specified retention period';
COMMENT ON FUNCTION cleanup_old_alerts IS 'Hard delete resolved alerts older than specified retention period';
COMMENT ON FUNCTION cleanup_old_system_logs IS 'Hard delete system logs older than specified retention period';
COMMENT ON FUNCTION get_database_stats IS 'Get database size and table statistics';
