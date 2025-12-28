-- ============================================================================
-- CYBERSHEPPARD - Compliance Frameworks & Alerting System
-- Migration: 006_compliance_alerts
-- Description: Enhanced compliance frameworks, policies, and alerting system
-- ============================================================================

-- ============================================================================
-- COMPLIANCE FRAMEWORKS
-- ============================================================================

-- Compliance frameworks table (CIS, PCI-DSS, NIST, ISO27001, etc.)
CREATE TABLE IF NOT EXISTS compliance_frameworks (
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
CREATE TABLE IF NOT EXISTS compliance_controls (
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
CREATE TABLE IF NOT EXISTS compliance_assessments (
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
CREATE TABLE IF NOT EXISTS compliance_control_results (
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

-- ============================================================================
-- ALERTING SYSTEM
-- ============================================================================

-- Alert channels (email, slack, webhook, etc.)
CREATE TABLE IF NOT EXISTS alert_channels (
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
CREATE TABLE IF NOT EXISTS alert_rules (
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
CREATE TABLE IF NOT EXISTS alerts (
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
CREATE TABLE IF NOT EXISTS alert_deliveries (
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

-- ============================================================================
-- COMPLIANCE REPORTS
-- ============================================================================

-- Report templates
CREATE TABLE IF NOT EXISTS report_templates (
    id SERIAL PRIMARY KEY,
    name VARCHAR(200) NOT NULL UNIQUE,
    report_type VARCHAR(50) NOT NULL,
    description TEXT,
    template_config JSONB NOT NULL,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_report_templates_type ON report_templates(report_type);
CREATE INDEX idx_report_templates_enabled ON report_templates(enabled) WHERE enabled = true;

COMMENT ON TABLE report_templates IS 'Report generation templates';

-- Generated reports
CREATE TABLE IF NOT EXISTS generated_reports (
    id SERIAL PRIMARY KEY,
    template_id INTEGER REFERENCES report_templates(id) ON DELETE SET NULL,
    report_name VARCHAR(200) NOT NULL,
    report_type VARCHAR(50) NOT NULL,
    parameters JSONB,
    file_path VARCHAR(500),
    file_size_bytes BIGINT,
    format VARCHAR(20),
    generated_by VARCHAR(100),
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_generated_reports_type ON generated_reports(report_type);
CREATE INDEX idx_generated_reports_generated ON generated_reports(generated_at DESC);

COMMENT ON TABLE generated_reports IS 'Generated compliance and security reports';

-- ============================================================================
-- ENHANCED VIOLATIONS TABLE
-- ============================================================================

-- Add compliance framework reference to existing violations
ALTER TABLE compliance_violations
ADD COLUMN IF NOT EXISTS framework_id INTEGER REFERENCES compliance_frameworks(id) ON DELETE SET NULL,
ADD COLUMN IF NOT EXISTS control_id INTEGER REFERENCES compliance_controls(id) ON DELETE SET NULL,
ADD COLUMN IF NOT EXISTS alert_generated BOOLEAN DEFAULT false,
ADD COLUMN IF NOT EXISTS alert_id INTEGER REFERENCES alerts(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_violations_framework ON compliance_violations(framework_id);
CREATE INDEX IF NOT EXISTS idx_violations_control ON compliance_violations(control_id);
CREATE INDEX IF NOT EXISTS idx_violations_alert_generated ON compliance_violations(alert_generated) WHERE NOT alert_generated;

-- ============================================================================
-- VIEWS
-- ============================================================================

-- Compliance overview per target
CREATE OR REPLACE VIEW target_compliance_overview AS
SELECT
    t.id as target_id,
    t.hostname,
    t.ip_address,
    COUNT(DISTINCT ca.framework_id) as frameworks_assessed,
    AVG(ca.compliance_score) as avg_compliance_score,
    COUNT(DISTINCT CASE WHEN cv.severity = 'critical' THEN cv.id END) as critical_violations,
    COUNT(DISTINCT CASE WHEN cv.severity = 'high' THEN cv.id END) as high_violations,
    MAX(ca.assessment_date) as last_assessment_date
FROM targets t
LEFT JOIN compliance_assessments ca ON t.id = ca.target_id
LEFT JOIN compliance_violations cv ON t.id = cv.target_id AND cv.status = 'new'
GROUP BY t.id, t.hostname, t.ip_address;

COMMENT ON VIEW target_compliance_overview IS 'Compliance overview summary per target';

-- Active alerts view
CREATE OR REPLACE VIEW active_alerts AS
SELECT
    a.id,
    a.severity,
    a.title,
    a.message,
    a.alert_type,
    a.status,
    a.acknowledged,
    a.created_at,
    ar.name as rule_name,
    COUNT(ad.id) as delivery_attempts,
    COUNT(CASE WHEN ad.status = 'delivered' THEN ad.id END) as successful_deliveries
FROM alerts a
LEFT JOIN alert_rules ar ON a.rule_id = ar.id
LEFT JOIN alert_deliveries ad ON a.id = ad.alert_id
WHERE NOT a.resolved
GROUP BY a.id, ar.name
ORDER BY
    CASE a.severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
    END,
    a.created_at DESC;

COMMENT ON VIEW active_alerts IS 'Active (unresolved) alerts with delivery status';

-- Framework compliance summary
CREATE OR REPLACE VIEW framework_compliance_summary AS
SELECT
    cf.id as framework_id,
    cf.display_name as framework_name,
    cf.category,
    COUNT(DISTINCT ca.target_id) as targets_assessed,
    AVG(ca.compliance_score) as avg_compliance_score,
    COUNT(DISTINCT cc.id) as total_controls,
    COUNT(DISTINCT CASE WHEN cc.automated_check THEN cc.id END) as automated_controls
FROM compliance_frameworks cf
LEFT JOIN compliance_assessments ca ON cf.id = ca.framework_id
LEFT JOIN compliance_controls cc ON cf.id = cc.framework_id
WHERE cf.enabled
GROUP BY cf.id, cf.display_name, cf.category;

COMMENT ON VIEW framework_compliance_summary IS 'Summary of compliance status per framework';

-- ============================================================================
-- FUNCTIONS AND TRIGGERS
-- ============================================================================

-- Function to calculate compliance score
CREATE OR REPLACE FUNCTION calculate_compliance_score(
    p_total_controls INTEGER,
    p_passed_controls INTEGER,
    p_failed_controls INTEGER,
    p_not_applicable INTEGER
) RETURNS DECIMAL AS $$
BEGIN
    IF p_total_controls = 0 THEN
        RETURN 0;
    END IF;

    -- Score = (passed / (total - not_applicable)) * 100
    RETURN ROUND(
        (p_passed_controls::DECIMAL / NULLIF(p_total_controls - p_not_applicable, 0)) * 100,
        2
    );
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Trigger to auto-update compliance score
CREATE OR REPLACE FUNCTION update_compliance_score()
RETURNS TRIGGER AS $$
BEGIN
    NEW.compliance_score := calculate_compliance_score(
        NEW.total_controls,
        NEW.passed_controls,
        NEW.failed_controls,
        NEW.not_applicable
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_compliance_score
    BEFORE INSERT OR UPDATE OF total_controls, passed_controls, failed_controls, not_applicable
    ON compliance_assessments
    FOR EACH ROW
    EXECUTE FUNCTION update_compliance_score();

-- Trigger for updated_at columns
CREATE TRIGGER update_compliance_frameworks_updated_at
    BEFORE UPDATE ON compliance_frameworks
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_alert_channels_updated_at
    BEFORE UPDATE ON alert_channels
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_alert_rules_updated_at
    BEFORE UPDATE ON alert_rules
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_report_templates_updated_at
    BEFORE UPDATE ON report_templates
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- GRANTS
-- ============================================================================

-- Grant permissions (assuming microsiem_app user exists)
-- GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO microsiem_app;
-- GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO microsiem_app;

-- ============================================================================
-- MIGRATION COMPLETE
-- ============================================================================
