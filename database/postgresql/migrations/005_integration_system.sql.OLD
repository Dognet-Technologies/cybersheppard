-- ============================================================================
-- CYBERSHEPPARD - Integration System Schema
-- Migration: 005_integration_system
-- Description: Tables for Sentinel Core and FireDog integrations, correlation engine
-- ============================================================================

-- Add sentinel_asset_id to targets table
ALTER TABLE targets
ADD COLUMN IF NOT EXISTS sentinel_asset_id INTEGER,
ADD COLUMN IF NOT EXISTS firedog_target_id INTEGER;

COMMENT ON COLUMN targets.sentinel_asset_id IS 'Asset ID in Sentinel Core system';
COMMENT ON COLUMN targets.firedog_target_id IS 'Target ID in FireDog system';

-- ============================================================================
-- SENTINEL CORE INTEGRATION
-- ============================================================================

-- Sentinel Core vulnerabilities table
CREATE TABLE IF NOT EXISTS sentinel_vulnerabilities (
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
CREATE TABLE IF NOT EXISTS sentinel_scan_history (
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

-- ============================================================================
-- FIREDOG INTEGRATION
-- ============================================================================

-- FireDog threats table
CREATE TABLE IF NOT EXISTS firedog_threats (
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
CREATE TABLE IF NOT EXISTS firedog_statistics (
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

-- ============================================================================
-- SECURITY CORRELATION ENGINE
-- ============================================================================

-- Security correlations table
CREATE TABLE IF NOT EXISTS security_correlations (
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

-- ============================================================================
-- INTEGRATION CONFIGURATION
-- ============================================================================

-- Integration settings table
CREATE TABLE IF NOT EXISTS integration_settings (
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

-- ============================================================================
-- INTEGRATION SYNC LOG
-- ============================================================================

-- Sync history table
CREATE TABLE IF NOT EXISTS integration_sync_log (
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

-- ============================================================================
-- AUTOMATED ACTIONS
-- ============================================================================

-- Automated actions table
CREATE TABLE IF NOT EXISTS automated_actions (
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
-- FUNCTIONS AND TRIGGERS
-- ============================================================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Triggers for updated_at
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

-- ============================================================================
-- VIEWS
-- ============================================================================

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

-- ============================================================================
-- GRANTS
-- ============================================================================

-- Grant permissions (assuming microsiem_app user exists)
-- GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO microsiem_app;
-- GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO microsiem_app;

-- ============================================================================
-- MIGRATION COMPLETE
-- ============================================================================
