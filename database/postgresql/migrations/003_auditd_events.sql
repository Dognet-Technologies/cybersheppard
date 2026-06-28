-- ============================================================================
-- Migration: Auditd Events (Laurel-based)
-- Description: Store security events from auditd with Laurel enrichment
-- Date: 2026-01-19
-- ============================================================================

-- Create auditd_events table
CREATE TABLE IF NOT EXISTS auditd_events (
    id BIGSERIAL PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,

    -- Event identification
    event_id VARCHAR(255) NOT NULL, -- Laurel ID
    collected_at TIMESTAMP NOT NULL DEFAULT NOW(),

    -- Severity and categorization (from detection rules)
    severity VARCHAR(50), -- critical, high, medium, low
    category VARCHAR(100), -- reverse_shell, webshell, privilege_escalation, etc.
    description TEXT,

    -- Syscall information
    syscall VARCHAR(50),
    syscall_success BOOLEAN,
    pid INTEGER,
    ppid INTEGER,
    uid INTEGER,
    gid INTEGER,
    euid INTEGER,
    egid INTEGER,
    comm VARCHAR(255),
    exe TEXT,
    key VARCHAR(100),

    -- Command execution (EXECVE)
    command_argc INTEGER,
    command_argv TEXT[], -- Array of command arguments
    command_full TEXT, -- Full command line

    -- File paths accessed
    file_paths JSONB, -- Array of path objects

    -- Parent process information
    parent_pid INTEGER,
    parent_comm VARCHAR(255),
    parent_exe TEXT,
    parent_cmdline TEXT,

    -- Container information (if applicable)
    container_id VARCHAR(255),
    container_name VARCHAR(255),
    container_image VARCHAR(255),

    -- Full Laurel JSON (for detailed analysis)
    raw_event JSONB NOT NULL,

    -- Correlation flags
    correlated_with_firedog BOOLEAN DEFAULT FALSE,
    correlated_with_sentinel BOOLEAN DEFAULT FALSE,

    -- Investigation status
    status VARCHAR(50) DEFAULT 'new', -- new, investigating, resolved, false_positive
    assigned_to INTEGER REFERENCES users(id),
    resolution_notes TEXT,
    resolved_at TIMESTAMP,

    -- Indexes for performance
    CONSTRAINT idx_auditd_events_target_collected UNIQUE(target_id, event_id, collected_at)
);

-- Indexes for fast queries
CREATE INDEX IF NOT EXISTS idx_auditd_events_target_id ON auditd_events(target_id);
CREATE INDEX IF NOT EXISTS idx_auditd_events_collected_at ON auditd_events(collected_at DESC);
CREATE INDEX IF NOT EXISTS idx_auditd_events_severity ON auditd_events(severity) WHERE severity IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_auditd_events_category ON auditd_events(category) WHERE category IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_auditd_events_status ON auditd_events(status);
CREATE INDEX IF NOT EXISTS idx_auditd_events_container_id ON auditd_events(container_id) WHERE container_id IS NOT NULL;

-- GIN index for JSONB searches
CREATE INDEX IF NOT EXISTS idx_auditd_events_raw_event_gin ON auditd_events USING GIN(raw_event);

-- Create view for real-time dashboard
CREATE OR REPLACE VIEW auditd_events_dashboard AS
SELECT
    ae.id,
    ae.target_id,
    t.hostname,
    t.ip_address,
    ae.collected_at,
    ae.severity,
    ae.category,
    ae.description,
    ae.syscall,
    ae.comm,
    ae.command_full,
    ae.parent_comm,
    ae.container_name,
    ae.status,
    ae.correlated_with_firedog,
    ae.correlated_with_sentinel,
    -- Count related events (same target, same category, last hour)
    (SELECT COUNT(*)
     FROM auditd_events ae2
     WHERE ae2.target_id = ae.target_id
       AND ae2.category = ae.category
       AND ae2.collected_at >= NOW() - INTERVAL '1 hour'
    ) as related_events_count
FROM auditd_events ae
JOIN targets t ON ae.target_id = t.id
ORDER BY ae.collected_at DESC;

-- Create function to correlate with FireDog
CREATE OR REPLACE FUNCTION correlate_auditd_with_firedog()
RETURNS TRIGGER AS $$
BEGIN
    -- Check if there are FireDog threats for this target around the same time (±5 minutes)
    IF EXISTS (
        SELECT 1 FROM firedog_threats ft
        WHERE ft.target_id = NEW.target_id
          AND ft.timestamp BETWEEN (NEW.collected_at - INTERVAL '5 minutes')
                                AND (NEW.collected_at + INTERVAL '5 minutes')
    ) THEN
        NEW.correlated_with_firedog := TRUE;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create function to correlate with Sentinel Core
CREATE OR REPLACE FUNCTION correlate_auditd_with_sentinel()
RETURNS TRIGGER AS $$
BEGIN
    -- Check if there are vulnerabilities for this target
    IF EXISTS (
        SELECT 1 FROM sentinel_vulnerabilities sv
        WHERE sv.target_id = NEW.target_id
          AND sv.severity IN ('Critical', 'High')
    ) THEN
        NEW.correlated_with_sentinel := TRUE;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create triggers for automatic correlation
CREATE OR REPLACE TRIGGER trigger_correlate_firedog
    BEFORE INSERT ON auditd_events
    FOR EACH ROW
    EXECUTE FUNCTION correlate_auditd_with_firedog();

CREATE OR REPLACE TRIGGER trigger_correlate_sentinel
    BEFORE INSERT ON auditd_events
    FOR EACH ROW
    EXECUTE FUNCTION correlate_auditd_with_sentinel();

-- Create function to get event details with correlations
CREATE OR REPLACE FUNCTION get_event_details(event_id_param BIGINT)
RETURNS TABLE (
    -- Event info
    event JSONB,

    -- Target info
    target JSONB,

    -- Correlations
    firedog_threats JSONB,
    sentinel_vulnerabilities JSONB,

    -- Compliance and hardening
    compliance_status JSONB,
    hardening_status JSONB
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        -- Event
        jsonb_build_object(
            'id', ae.id,
            'event_id', ae.event_id,
            'collected_at', ae.collected_at,
            'severity', ae.severity,
            'category', ae.category,
            'description', ae.description,
            'syscall', ae.syscall,
            'command', ae.command_full,
            'parent_comm', ae.parent_comm,
            'container', jsonb_build_object(
                'id', ae.container_id,
                'name', ae.container_name,
                'image', ae.container_image
            ),
            'raw_event', ae.raw_event
        ) as event,

        -- Target
        jsonb_build_object(
            'id', t.id,
            'hostname', t.hostname,
            'ip_address', t.ip_address,
            'os_type', t.os_type,
            'status', t.status,
            'agent_version', t.agent_version
        ) as target,

        -- FireDog threats (within ±5 minutes)
        COALESCE((
            SELECT jsonb_agg(jsonb_build_object(
                'id', ft.id,
                'source_ip', ft.source_ip,
                'threat_type', ft.threat_type,
                'threat_score', ft.threat_score,
                'timestamp', ft.timestamp
            ))
            FROM firedog_threats ft
            WHERE ft.target_id = ae.target_id
              AND ft.timestamp BETWEEN (ae.collected_at - INTERVAL '5 minutes')
                                    AND (ae.collected_at + INTERVAL '5 minutes')
        ), '[]'::jsonb) as firedog_threats,

        -- Sentinel vulnerabilities
        COALESCE((
            SELECT jsonb_agg(jsonb_build_object(
                'cve_id', sv.cve_id,
                'severity', sv.severity,
                'cvss_score', sv.cvss_score,
                'affected_service', sv.affected_service,
                'description', sv.description
            ))
            FROM sentinel_vulnerabilities sv
            WHERE sv.target_id = ae.target_id
              AND sv.severity IN ('Critical', 'High')
        ), '[]'::jsonb) as sentinel_vulnerabilities,

        -- Compliance status
        jsonb_build_object(
            'violations', (
                SELECT COUNT(*)
                FROM compliance_violations cv
                WHERE cv.target_id = ae.target_id
                  AND cv.status = 'active'
            ),
            'frameworks_assessed', (
                SELECT COUNT(DISTINCT framework_id)
                FROM compliance_assessments ca
                WHERE ca.target_id = ae.target_id
            )
        ) as compliance_status,

        -- Hardening status
        jsonb_build_object(
            'templates_applied', (
                SELECT COUNT(*)
                FROM hardening_history hh
                WHERE hh.target_id = ae.target_id
                  AND hh.status = 'success'
            ),
            'last_hardening', (
                SELECT MAX(applied_at)
                FROM hardening_history hh
                WHERE hh.target_id = ae.target_id
                  AND hh.status = 'success'
            )
        ) as hardening_status

    FROM auditd_events ae
    JOIN targets t ON ae.target_id = t.id
    WHERE ae.id = event_id_param;
END;
$$ LANGUAGE plpgsql;

-- Comments
COMMENT ON TABLE auditd_events IS 'Security events from auditd with Laurel JSON parsing and enrichment';
COMMENT ON COLUMN auditd_events.raw_event IS 'Full Laurel JSON for detailed forensic analysis';
COMMENT ON COLUMN auditd_events.severity IS 'Severity from detection rules: critical, high, medium, low';
COMMENT ON COLUMN auditd_events.category IS 'Threat category: reverse_shell, webshell, privilege_escalation, etc.';
COMMENT ON FUNCTION get_event_details IS 'Get complete event details with all correlations and context';
