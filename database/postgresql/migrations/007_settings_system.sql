-- ============================================================================
-- CYBERSHEPPARD - Settings & System Configuration
-- ============================================================================

-- System-wide settings
CREATE TABLE IF NOT EXISTS system_settings (
    id SERIAL PRIMARY KEY,
    setting_key VARCHAR(100) NOT NULL UNIQUE,
    setting_value TEXT,
    setting_type VARCHAR(50) DEFAULT 'string', -- string, number, boolean, json
    category VARCHAR(50), -- database, security, monitoring, general
    description TEXT,
    is_editable BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- User-specific settings
CREATE TABLE IF NOT EXISTS user_settings (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    setting_key VARCHAR(100) NOT NULL,
    setting_value TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(user_id, setting_key)
);

-- API Keys for integrations
CREATE TABLE IF NOT EXISTS api_keys (
    id SERIAL PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    key_hash VARCHAR(255) NOT NULL UNIQUE, -- hashed API key
    key_prefix VARCHAR(20) NOT NULL, -- first 8 chars for display
    service VARCHAR(100), -- firedog, sentinelcore, cybersheppard, external
    permissions JSONB DEFAULT '[]'::jsonb, -- array of permissions
    is_active BOOLEAN DEFAULT true,
    last_used_at TIMESTAMP,
    expires_at TIMESTAMP,
    created_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW(),
    revoked_at TIMESTAMP,
    revoked_by INTEGER REFERENCES users(id)
);

-- Activity log for sensitive operations
CREATE TABLE IF NOT EXISTS settings_audit_log (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    action VARCHAR(100) NOT NULL, -- change_password, generate_api_key, update_setting, reset_database
    entity_type VARCHAR(50), -- setting, api_key, user
    entity_id INTEGER,
    old_value TEXT,
    new_value TEXT,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_system_settings_category ON system_settings(category);
CREATE INDEX IF NOT EXISTS idx_system_settings_key ON system_settings(setting_key);
CREATE INDEX IF NOT EXISTS idx_user_settings_user_id ON user_settings(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_service ON api_keys(service);
CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys(is_active);
CREATE INDEX IF NOT EXISTS idx_audit_log_user ON settings_audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON settings_audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_log_created ON settings_audit_log(created_at DESC);

-- Insert default system settings
INSERT INTO system_settings (setting_key, setting_value, setting_type, category, description, is_editable) VALUES
    -- Database settings
    ('db_retention_days', '90', 'number', 'database', 'Number of days to retain monitoring data', true),
    ('db_auto_vacuum', 'true', 'boolean', 'database', 'Enable automatic vacuum for database optimization', true),
    ('db_compression_enabled', 'true', 'boolean', 'database', 'Enable data compression for old records', true),

    -- Security settings
    ('session_timeout_minutes', '60', 'number', 'security', 'Session timeout in minutes', true),
    ('max_login_attempts', '5', 'number', 'security', 'Maximum failed login attempts before lockout', true),
    ('password_min_length', '8', 'number', 'security', 'Minimum password length', true),
    ('require_2fa', 'false', 'boolean', 'security', 'Require two-factor authentication', true),

    -- Monitoring settings
    ('monitoring_interval_seconds', '300', 'number', 'monitoring', 'Monitoring collection interval in seconds', true),
    ('alert_aggregation_window', '300', 'number', 'monitoring', 'Alert aggregation window in seconds', true),
    ('max_targets', '1000', 'number', 'monitoring', 'Maximum number of targets', false),

    -- Integration settings
    ('sentinel_core_url', '', 'string', 'integration', 'Sentinel Core API URL', true),
    ('firedog_url', '', 'string', 'integration', 'FireDog API URL', true),
    ('sync_interval_seconds', '600', 'number', 'integration', 'Integration sync interval in seconds', true),

    -- General settings
    ('app_name', 'CyberSheppard', 'string', 'general', 'Application name', true),
    ('app_version', '1.0.0', 'string', 'general', 'Application version', false),
    ('support_email', 'support@cybersheppard.local', 'string', 'general', 'Support email address', true),
    ('maintenance_mode', 'false', 'boolean', 'general', 'Enable maintenance mode', true)
ON CONFLICT (setting_key) DO NOTHING;

-- Trigger to update updated_at
CREATE OR REPLACE FUNCTION update_settings_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER system_settings_updated
    BEFORE UPDATE ON system_settings
    FOR EACH ROW
    EXECUTE FUNCTION update_settings_timestamp();

CREATE TRIGGER user_settings_updated
    BEFORE UPDATE ON user_settings
    FOR EACH ROW
    EXECUTE FUNCTION update_settings_timestamp();

-- View for active API keys
CREATE OR REPLACE VIEW active_api_keys AS
SELECT
    id,
    name,
    description,
    key_prefix,
    service,
    permissions,
    last_used_at,
    expires_at,
    created_by,
    created_at
FROM api_keys
WHERE is_active = true
  AND (expires_at IS NULL OR expires_at > NOW())
  AND revoked_at IS NULL
ORDER BY created_at DESC;

-- Function to generate API key prefix
CREATE OR REPLACE FUNCTION generate_api_key_prefix()
RETURNS TEXT AS $$
DECLARE
    chars TEXT := 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
    result TEXT := 'cs_'; -- CyberSheppard prefix
    i INTEGER;
BEGIN
    FOR i IN 1..16 LOOP
        result := result || substr(chars, floor(random() * length(chars) + 1)::integer, 1);
    END LOOP;
    RETURN result;
END;
$$ LANGUAGE plpgsql;

-- Function to cleanup old audit logs (keep last 90 days)
CREATE OR REPLACE FUNCTION cleanup_old_audit_logs()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM settings_audit_log
    WHERE created_at < NOW() - INTERVAL '90 days';

    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

COMMENT ON TABLE system_settings IS 'System-wide configuration settings';
COMMENT ON TABLE user_settings IS 'User-specific preferences and settings';
COMMENT ON TABLE api_keys IS 'API keys for service integrations';
COMMENT ON TABLE settings_audit_log IS 'Audit trail for sensitive settings operations';
