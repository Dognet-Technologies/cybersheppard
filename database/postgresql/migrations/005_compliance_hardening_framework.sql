-- ============================================================================
-- CYBERSHEPPARD - Compliance & Hardening Framework
-- Migration 005
--
-- Complete implementation based on Host_Compliance_Framework_Mapping(4).xlsx
-- 113 controls across 12 macroareas, 4 frameworks (NIS2, NIST, ISO, MITRE)
-- ============================================================================

-- ============================================================================
-- Compliance Frameworks
-- ============================================================================

CREATE TABLE IF NOT EXISTS compliance_frameworks (
    id SERIAL PRIMARY KEY,
    code VARCHAR(50) UNIQUE NOT NULL, -- 'nis2', 'nist', 'iso27001', 'mitre'
    name VARCHAR(255) NOT NULL,
    version VARCHAR(100) NOT NULL,
    description TEXT,
    published_date DATE,
    active BOOLEAN DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Ensure compliance_frameworks has all columns needed by this migration
-- (table may already exist with a different schema from migration 001)
ALTER TABLE compliance_frameworks ADD COLUMN IF NOT EXISTS code VARCHAR(50);
ALTER TABLE compliance_frameworks ADD COLUMN IF NOT EXISTS active BOOLEAN DEFAULT true;
ALTER TABLE compliance_frameworks ADD COLUMN IF NOT EXISTS published_date DATE;
-- display_name exists in migration 001 schema as NOT NULL; provide a default for compatibility
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'compliance_frameworks' AND column_name = 'display_name'
    ) THEN
        ALTER TABLE compliance_frameworks ALTER COLUMN display_name SET DEFAULT '';
    END IF;
END $$;
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'compliance_frameworks_code_key' AND conrelid = 'compliance_frameworks'::regclass
    ) THEN
        ALTER TABLE compliance_frameworks ADD CONSTRAINT compliance_frameworks_code_key UNIQUE (code);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_frameworks_code ON compliance_frameworks(code);
CREATE INDEX IF NOT EXISTS idx_frameworks_active ON compliance_frameworks(active);

-- Insert the 4 main frameworks
INSERT INTO compliance_frameworks (code, name, version, description, published_date) VALUES
    ('nis2', 'NIS2 Directive', 'Directive 2022/2555', 'EU Cybersecurity Directive - Network and Information Security', '2022-12-27'),
    ('nist', 'NIST 800-53', 'Revision 5', 'Security and Privacy Controls for Information Systems and Organizations - 20 Control Families, 1000+ Controls', '2020-09-23'),
    ('iso27001', 'ISO/IEC 27001', '2022 Edition', 'Information Security Management Systems (ISMS) - Annex A: 93 Controls across 4 Categories', '2022-10-25'),
    ('mitre', 'MITRE D3FEND', 'v1.3.0', 'Defensive Countermeasures Knowledge Graph - 7 Tactics, 245+ Defensive Techniques', '2023-06-15')
ON CONFLICT (code) DO NOTHING;

-- ============================================================================
-- Compliance Macroareas
-- ============================================================================

CREATE TABLE IF NOT EXISTS compliance_macroareas (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    display_order INTEGER,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_macroareas_name ON compliance_macroareas(name);

-- Insert the 12 macroareas from Excel
INSERT INTO compliance_macroareas (name, description, display_order) VALUES
    ('Identity & Access Management (IAM)', 'Authentication, authorization, privileged access management, identity lifecycle', 1),
    ('System Hardening & Secure Configuration', 'OS hardening, kernel parameters, service configuration, secure defaults', 2),
    ('Encryption & Data Protection', 'Data at rest encryption, data in transit, key management, cryptographic controls', 3),
    ('Logging, Monitoring & Auditing', 'Audit logging, SIEM integration, log retention, monitoring infrastructure', 4),
    ('Network Security & Segmentation', 'Firewall rules, network isolation, DMZ, micro-segmentation, zero trust', 5),
    ('Patch & Vulnerability Management', 'Vulnerability scanning, patch management, CVE tracking, remediation workflows', 6),
    ('Backup & Recovery', 'Backup strategy, restore testing, RPO/RTO, disaster recovery, business continuity', 7),
    ('Malware & Threat Protection', 'Antivirus, EDR, threat detection, malware prevention, threat intelligence', 8),
    ('Application Security', 'Secure coding, application hardening, WAF, API security, OWASP compliance', 9),
    ('Security Lifecycle Management', 'Change management, asset management, configuration management, decommissioning', 10),
    ('Physical & Environmental Security', 'Physical access controls, environmental monitoring, hardware security', 11),
    ('Supply Chain Security', 'Vendor security, third-party risk, software supply chain, SBOM', 12)
ON CONFLICT (name) DO NOTHING;

-- ============================================================================
-- Patch: add columns missing from migration 001 to compliance_controls
-- ============================================================================
ALTER TABLE compliance_controls ADD COLUMN IF NOT EXISTS macroarea_id INTEGER REFERENCES compliance_macroareas(id);
ALTER TABLE compliance_controls ADD COLUMN IF NOT EXISTS sub_control VARCHAR(255);
ALTER TABLE compliance_controls ADD COLUMN IF NOT EXISTS sub_sub_control VARCHAR(255);
ALTER TABLE compliance_controls ADD COLUMN IF NOT EXISTS requirement TEXT;
ALTER TABLE compliance_controls ADD COLUMN IF NOT EXISTS priority VARCHAR(20);
ALTER TABLE compliance_controls ADD COLUMN IF NOT EXISTS implementation_complexity VARCHAR(20);
ALTER TABLE compliance_controls ADD COLUMN IF NOT EXISTS implementation_notes TEXT;
ALTER TABLE compliance_controls ADD COLUMN IF NOT EXISTS verification_method TEXT;
ALTER TABLE compliance_controls ADD COLUMN IF NOT EXISTS nis2_references TEXT[];
ALTER TABLE compliance_controls ADD COLUMN IF NOT EXISTS nist_references TEXT[];
ALTER TABLE compliance_controls ADD COLUMN IF NOT EXISTS iso_references TEXT[];
ALTER TABLE compliance_controls ADD COLUMN IF NOT EXISTS mitre_references TEXT[];
ALTER TABLE compliance_controls ADD COLUMN IF NOT EXISTS applies_to_nis2 BOOLEAN DEFAULT false;
ALTER TABLE compliance_controls ADD COLUMN IF NOT EXISTS applies_to_nist BOOLEAN DEFAULT false;
ALTER TABLE compliance_controls ADD COLUMN IF NOT EXISTS applies_to_iso BOOLEAN DEFAULT false;
ALTER TABLE compliance_controls ADD COLUMN IF NOT EXISTS applies_to_mitre BOOLEAN DEFAULT false;
ALTER TABLE compliance_controls ADD COLUMN IF NOT EXISTS applies_to_all_frameworks BOOLEAN DEFAULT false;
ALTER TABLE compliance_controls ADD COLUMN IF NOT EXISTS supports_debian_ubuntu BOOLEAN DEFAULT false;
ALTER TABLE compliance_controls ADD COLUMN IF NOT EXISTS supports_rhel_oracle BOOLEAN DEFAULT false;
ALTER TABLE compliance_controls ADD COLUMN IF NOT EXISTS supports_sles BOOLEAN DEFAULT false;
ALTER TABLE compliance_controls ADD COLUMN IF NOT EXISTS supports_windows_2019 BOOLEAN DEFAULT false;
ALTER TABLE compliance_controls ADD COLUMN IF NOT EXISTS supports_windows_2022 BOOLEAN DEFAULT false;
ALTER TABLE compliance_controls ADD COLUMN IF NOT EXISTS supports_docker BOOLEAN DEFAULT false;
ALTER TABLE compliance_controls ADD COLUMN IF NOT EXISTS supports_lxc BOOLEAN DEFAULT false;
ALTER TABLE compliance_controls ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT NOW();

-- ============================================================================
-- Patch: add columns missing from migration 001 to compliance_violations
-- ============================================================================
ALTER TABLE compliance_violations ADD COLUMN IF NOT EXISTS control_id INTEGER REFERENCES compliance_controls(id);
ALTER TABLE compliance_violations ADD COLUMN IF NOT EXISTS framework_code VARCHAR(50) REFERENCES compliance_frameworks(code);
ALTER TABLE compliance_violations ADD COLUMN IF NOT EXISTS title VARCHAR(500);
ALTER TABLE compliance_violations ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE compliance_violations ADD COLUMN IF NOT EXISTS current_value TEXT;
ALTER TABLE compliance_violations ADD COLUMN IF NOT EXISTS expected_value TEXT;
ALTER TABLE compliance_violations ADD COLUMN IF NOT EXISTS deviation_details TEXT;
ALTER TABLE compliance_violations ADD COLUMN IF NOT EXISTS risk_score NUMERIC(5,2);
ALTER TABLE compliance_violations ADD COLUMN IF NOT EXISTS business_impact TEXT;
ALTER TABLE compliance_violations ADD COLUMN IF NOT EXISTS technical_impact TEXT;
ALTER TABLE compliance_violations ADD COLUMN IF NOT EXISTS detected_at TIMESTAMP DEFAULT NOW();
ALTER TABLE compliance_violations ADD COLUMN IF NOT EXISTS detection_method VARCHAR(100);
ALTER TABLE compliance_violations ADD COLUMN IF NOT EXISTS remediation_plan TEXT;
ALTER TABLE compliance_violations ADD COLUMN IF NOT EXISTS remediation_deadline TIMESTAMP;
ALTER TABLE compliance_violations ADD COLUMN IF NOT EXISTS assigned_to VARCHAR(100);
ALTER TABLE compliance_violations ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMP;
ALTER TABLE compliance_violations ADD COLUMN IF NOT EXISTS resolved_by VARCHAR(100);
ALTER TABLE compliance_violations ADD COLUMN IF NOT EXISTS resolution_notes TEXT;
ALTER TABLE compliance_violations ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT NOW();

-- ============================================================================
-- Compliance Controls
-- Main table storing all 113 controls from Excel
-- ============================================================================

CREATE TABLE IF NOT EXISTS compliance_controls (
    id SERIAL PRIMARY KEY,
    macroarea_id INTEGER NOT NULL REFERENCES compliance_macroareas(id),

    -- Control identification
    sub_control VARCHAR(255), -- e.g., "Authentication"
    sub_sub_control VARCHAR(255), -- e.g., "SSH MFA"
    requirement TEXT NOT NULL, -- Full requirement description

    -- Priority and complexity
    priority VARCHAR(20) NOT NULL CHECK (priority IN ('Critical', 'High', 'Medium', 'Low')),
    implementation_complexity VARCHAR(20) CHECK (implementation_complexity IN ('High', 'Medium', 'Low')),

    -- Implementation guidance
    implementation_notes TEXT,
    verification_method TEXT,

    -- Framework references (stored as arrays for quick access)
    nis2_references TEXT[], -- e.g., ['Art.21(2)(e)']
    nist_references TEXT[], -- e.g., ['IA-2(1)', 'IA-2(2)', 'IA-2(12)']
    iso_references TEXT[], -- e.g., ['A.5.17', 'A.5.18']
    mitre_references TEXT[], -- e.g., ['D3-MFA']

    -- Framework applicability flags
    applies_to_nis2 BOOLEAN DEFAULT false,
    applies_to_nist BOOLEAN DEFAULT false,
    applies_to_iso BOOLEAN DEFAULT false,
    applies_to_mitre BOOLEAN DEFAULT false,
    applies_to_all_frameworks BOOLEAN DEFAULT false,

    -- OS/Platform support
    supports_debian_ubuntu BOOLEAN DEFAULT false,
    supports_rhel_oracle BOOLEAN DEFAULT false,
    supports_sles BOOLEAN DEFAULT false,
    supports_windows_2019 BOOLEAN DEFAULT false,
    supports_windows_2022 BOOLEAN DEFAULT false,
    supports_docker BOOLEAN DEFAULT false,
    supports_lxc BOOLEAN DEFAULT false,

    -- Metadata
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_controls_macroarea ON compliance_controls(macroarea_id);
CREATE INDEX IF NOT EXISTS idx_controls_priority ON compliance_controls(priority);
CREATE INDEX IF NOT EXISTS idx_controls_complexity ON compliance_controls(implementation_complexity);
CREATE INDEX IF NOT EXISTS idx_controls_nis2 ON compliance_controls(applies_to_nis2) WHERE applies_to_nis2 = true;
CREATE INDEX IF NOT EXISTS idx_controls_nist ON compliance_controls(applies_to_nist) WHERE applies_to_nist = true;
CREATE INDEX IF NOT EXISTS idx_controls_iso ON compliance_controls(applies_to_iso) WHERE applies_to_iso = true;
CREATE INDEX IF NOT EXISTS idx_controls_mitre ON compliance_controls(applies_to_mitre) WHERE applies_to_mitre = true;
CREATE INDEX IF NOT EXISTS idx_controls_all_frameworks ON compliance_controls(applies_to_all_frameworks) WHERE applies_to_all_frameworks = true;

-- GIN indexes for array searches
CREATE INDEX IF NOT EXISTS idx_controls_nis2_refs ON compliance_controls USING GIN(nis2_references);
CREATE INDEX IF NOT EXISTS idx_controls_nist_refs ON compliance_controls USING GIN(nist_references);
CREATE INDEX IF NOT EXISTS idx_controls_iso_refs ON compliance_controls USING GIN(iso_references);
CREATE INDEX IF NOT EXISTS idx_controls_mitre_refs ON compliance_controls USING GIN(mitre_references);

-- ============================================================================
-- Hardening Templates
-- Templates group multiple controls for specific scenarios
-- ============================================================================

CREATE TABLE IF NOT EXISTS hardening_templates (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,

    -- Framework alignment
    framework_code VARCHAR(50) REFERENCES compliance_frameworks(code), -- NULL = multi-framework
    compliance_level VARCHAR(50), -- e.g., "CIS Level 1", "PCI-DSS", "NIS2 Essential"

    -- Target environment
    target_os VARCHAR(50), -- 'debian', 'ubuntu', 'rhel', 'centos', 'windows', 'any'
    target_role VARCHAR(100), -- 'web_server', 'database', 'application', 'gateway', 'dns', 'generic'

    -- Template metadata
    version VARCHAR(50) DEFAULT '1.0',
    author VARCHAR(255),
    is_official BOOLEAN DEFAULT false, -- Official CyberSheppard template
    is_active BOOLEAN DEFAULT true,

    -- Configuration
    execution_order INTEGER DEFAULT 100, -- Order for staged deployments
    dry_run_recommended BOOLEAN DEFAULT true,
    requires_reboot BOOLEAN DEFAULT false,
    estimated_duration_minutes INTEGER, -- Estimated execution time

    -- Risk management
    risk_level VARCHAR(20) CHECK (risk_level IN ('Low', 'Medium', 'High')),
    rollback_supported BOOLEAN DEFAULT true,

    -- Template content (YAML configuration)
    template_config JSONB, -- Actual hardening commands/configuration

    -- Metadata
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    created_by VARCHAR(100),

    CONSTRAINT chk_target_os CHECK (target_os IN ('debian', 'ubuntu', 'rhel', 'centos', 'rocky', 'alma', 'sles', 'windows_2019', 'windows_2022', 'any')),
    CONSTRAINT chk_target_role CHECK (target_role IN ('web_server', 'database', 'application', 'gateway', 'dns', 'cache', 'storage', 'kubernetes', 'docker_host', 'generic'))
);

CREATE INDEX IF NOT EXISTS idx_templates_framework ON hardening_templates(framework_code);
CREATE INDEX IF NOT EXISTS idx_templates_os ON hardening_templates(target_os);
CREATE INDEX IF NOT EXISTS idx_templates_role ON hardening_templates(target_role);
CREATE INDEX IF NOT EXISTS idx_templates_active ON hardening_templates(is_active);
CREATE INDEX IF NOT EXISTS idx_templates_official ON hardening_templates(is_official);

-- ============================================================================
-- Hardening Template Controls
-- Many-to-many relationship: templates <-> controls
-- ============================================================================

CREATE TABLE IF NOT EXISTS hardening_template_controls (
    id SERIAL PRIMARY KEY,
    template_id INTEGER NOT NULL REFERENCES hardening_templates(id) ON DELETE CASCADE,
    control_id INTEGER NOT NULL REFERENCES compliance_controls(id) ON DELETE CASCADE,

    -- Control-specific configuration within this template
    is_mandatory BOOLEAN DEFAULT true, -- Can user skip this control?
    execution_order INTEGER, -- Order within template
    custom_parameters JSONB, -- Control-specific parameters

    created_at TIMESTAMP NOT NULL DEFAULT NOW(),

    UNIQUE(template_id, control_id)
);

CREATE INDEX IF NOT EXISTS idx_template_controls_template ON hardening_template_controls(template_id);
CREATE INDEX IF NOT EXISTS idx_template_controls_control ON hardening_template_controls(control_id);

-- ============================================================================
-- Target Compliance Status
-- Overall compliance status per target per framework
-- ============================================================================

CREATE TABLE IF NOT EXISTS target_compliance_status (
    id SERIAL PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    framework_code VARCHAR(50) NOT NULL REFERENCES compliance_frameworks(code),

    -- Compliance metrics
    total_controls INTEGER NOT NULL DEFAULT 0,
    compliant_controls INTEGER NOT NULL DEFAULT 0,
    non_compliant_controls INTEGER NOT NULL DEFAULT 0,
    not_applicable_controls INTEGER NOT NULL DEFAULT 0,
    not_checked_controls INTEGER NOT NULL DEFAULT 0,

    -- Calculated score (0-100)
    compliance_score NUMERIC(5,2), -- Percentage

    -- Priority breakdown
    critical_compliant INTEGER DEFAULT 0,
    critical_total INTEGER DEFAULT 0,
    high_compliant INTEGER DEFAULT 0,
    high_total INTEGER DEFAULT 0,
    medium_compliant INTEGER DEFAULT 0,
    medium_total INTEGER DEFAULT 0,
    low_compliant INTEGER DEFAULT 0,
    low_total INTEGER DEFAULT 0,

    -- Timestamps
    last_scan_at TIMESTAMP,
    next_scan_scheduled TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),

    UNIQUE(target_id, framework_code)
);

CREATE INDEX IF NOT EXISTS idx_target_compliance_target ON target_compliance_status(target_id);
CREATE INDEX IF NOT EXISTS idx_target_compliance_framework ON target_compliance_status(framework_code);
CREATE INDEX IF NOT EXISTS idx_target_compliance_score ON target_compliance_status(compliance_score DESC);
CREATE INDEX IF NOT EXISTS idx_target_compliance_last_scan ON target_compliance_status(last_scan_at DESC);

-- ============================================================================
-- Target Control Status
-- Detailed status of each control for each target
-- ============================================================================

CREATE TABLE IF NOT EXISTS target_control_status (
    id BIGSERIAL PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    control_id INTEGER NOT NULL REFERENCES compliance_controls(id) ON DELETE CASCADE,

    -- Status
    status VARCHAR(50) NOT NULL DEFAULT 'not_checked' CHECK (status IN ('compliant', 'non_compliant', 'partial', 'not_applicable', 'not_checked', 'error')),

    -- Check results
    last_check_at TIMESTAMP,
    check_method VARCHAR(100), -- 'automated', 'manual', 'agent', 'ssh'
    check_output TEXT, -- Detailed output from check
    error_message TEXT, -- If status = 'error'

    -- Remediation
    remediation_applied BOOLEAN DEFAULT false,
    remediation_at TIMESTAMP,
    remediation_method VARCHAR(100), -- 'template', 'manual', 'agent'
    remediation_output TEXT,

    -- Evidence
    evidence_data JSONB, -- Actual configuration values, file hashes, etc.

    -- Compliance context
    compliance_score NUMERIC(5,2), -- Individual control score (0-100)
    gap_description TEXT, -- What's missing for full compliance

    -- Metadata
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    checked_by VARCHAR(100),

    UNIQUE(target_id, control_id)
);

CREATE INDEX IF NOT EXISTS idx_target_control_target ON target_control_status(target_id);
CREATE INDEX IF NOT EXISTS idx_target_control_control ON target_control_status(control_id);
CREATE INDEX IF NOT EXISTS idx_target_control_status ON target_control_status(status);
CREATE INDEX IF NOT EXISTS idx_target_control_last_check ON target_control_status(last_check_at DESC);
CREATE INDEX IF NOT EXISTS idx_target_control_score ON target_control_status(compliance_score DESC);

-- ============================================================================
-- Hardening Executions
-- Track every hardening template execution
-- ============================================================================

CREATE TABLE IF NOT EXISTS hardening_executions (
    id BIGSERIAL PRIMARY KEY,
    template_id INTEGER NOT NULL REFERENCES hardening_templates(id),
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,

    -- Execution details
    execution_mode VARCHAR(20) NOT NULL CHECK (execution_mode IN ('dry_run', 'apply', 'rollback')),
    status VARCHAR(50) NOT NULL CHECK (status IN ('pending', 'running', 'completed', 'failed', 'rolled_back', 'partial')),

    -- Timing
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    duration_seconds INTEGER,

    -- Results
    total_controls INTEGER,
    successful_controls INTEGER,
    failed_controls INTEGER,
    skipped_controls INTEGER,

    -- Output
    execution_log TEXT, -- Complete execution log
    error_message TEXT,
    warnings TEXT[],

    -- Rollback info
    rollback_data JSONB, -- Snapshot of pre-execution state
    can_rollback BOOLEAN DEFAULT true,
    rolled_back_at TIMESTAMP,

    -- Metadata
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    executed_by VARCHAR(100),

    -- Before/after comparison
    compliance_score_before NUMERIC(5,2),
    compliance_score_after NUMERIC(5,2)
);

CREATE INDEX IF NOT EXISTS idx_hardening_exec_template ON hardening_executions(template_id);
CREATE INDEX IF NOT EXISTS idx_hardening_exec_target ON hardening_executions(target_id);
CREATE INDEX IF NOT EXISTS idx_hardening_exec_status ON hardening_executions(status);
CREATE INDEX IF NOT EXISTS idx_hardening_exec_started ON hardening_executions(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_hardening_exec_mode ON hardening_executions(execution_mode);

-- ============================================================================
-- Compliance Violations
-- Track detected violations and their remediation
-- ============================================================================

CREATE TABLE IF NOT EXISTS compliance_violations (
    id BIGSERIAL PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    control_id INTEGER NOT NULL REFERENCES compliance_controls(id),
    framework_code VARCHAR(50) REFERENCES compliance_frameworks(code),

    -- Violation details
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    title VARCHAR(500) NOT NULL,
    description TEXT NOT NULL,

    -- Current state vs expected state
    current_value TEXT,
    expected_value TEXT,
    deviation_details TEXT,

    -- Impact
    risk_score NUMERIC(5,2), -- 0-100
    business_impact TEXT,
    technical_impact TEXT,

    -- Detection
    detected_at TIMESTAMP NOT NULL DEFAULT NOW(),
    detection_method VARCHAR(100), -- 'scan', 'agent', 'audit', 'manual'

    -- Status
    status VARCHAR(50) NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'in_progress', 'resolved', 'accepted_risk', 'false_positive')),

    -- Remediation
    remediation_plan TEXT,
    remediation_deadline TIMESTAMP,
    resolved_at TIMESTAMP,
    resolution_notes TEXT,

    -- Recurrence
    first_seen_at TIMESTAMP,
    last_seen_at TIMESTAMP,
    occurrence_count INTEGER DEFAULT 1,

    -- Assignment
    assigned_to VARCHAR(100),
    assigned_at TIMESTAMP,

    -- Metadata
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_violations_target ON compliance_violations(target_id);
CREATE INDEX IF NOT EXISTS idx_violations_control ON compliance_violations(control_id);
CREATE INDEX IF NOT EXISTS idx_violations_framework ON compliance_violations(framework_code);
CREATE INDEX IF NOT EXISTS idx_violations_severity ON compliance_violations(severity);
CREATE INDEX IF NOT EXISTS idx_violations_status ON compliance_violations(status);
CREATE INDEX IF NOT EXISTS idx_violations_detected ON compliance_violations(detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_violations_deadline ON compliance_violations(remediation_deadline);

-- ============================================================================
-- Compliance Scan History
-- Track all compliance scans for audit trail
-- ============================================================================

CREATE TABLE IF NOT EXISTS compliance_scan_history (
    id BIGSERIAL PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    framework_code VARCHAR(50) REFERENCES compliance_frameworks(code),

    -- Scan details
    scan_type VARCHAR(50) CHECK (scan_type IN ('full', 'partial', 'quick', 'manual')),
    triggered_by VARCHAR(50) CHECK (triggered_by IN ('scheduled', 'manual', 'post_hardening', 'api', 'alert')),

    -- Timing
    started_at TIMESTAMP NOT NULL,
    completed_at TIMESTAMP,
    duration_seconds INTEGER,

    -- Results
    controls_checked INTEGER,
    compliant_count INTEGER,
    non_compliant_count INTEGER,
    error_count INTEGER,

    -- Score
    compliance_score NUMERIC(5,2),
    score_change NUMERIC(5,2), -- vs previous scan

    -- Output
    scan_report JSONB, -- Detailed scan results
    summary TEXT,

    -- Metadata
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    executed_by VARCHAR(100)
);

CREATE INDEX IF NOT EXISTS idx_scan_history_target ON compliance_scan_history(target_id);
CREATE INDEX IF NOT EXISTS idx_scan_history_framework ON compliance_scan_history(framework_code);
CREATE INDEX IF NOT EXISTS idx_scan_history_started ON compliance_scan_history(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_history_score ON compliance_scan_history(compliance_score DESC);

-- ============================================================================
-- Functions
-- ============================================================================

-- Calculate compliance score for a target/framework
CREATE OR REPLACE FUNCTION calculate_compliance_score(
    p_target_id INTEGER,
    p_framework_code VARCHAR
)
RETURNS NUMERIC AS $$
DECLARE
    v_total INTEGER;
    v_compliant INTEGER;
    v_score NUMERIC;
BEGIN
    -- Count total applicable controls
    SELECT COUNT(*) INTO v_total
    FROM target_control_status tcs
    JOIN compliance_controls cc ON tcs.control_id = cc.id
    WHERE tcs.target_id = p_target_id
      AND tcs.status != 'not_applicable'
      AND (
          (p_framework_code = 'nis2' AND cc.applies_to_nis2)
          OR (p_framework_code = 'nist' AND cc.applies_to_nist)
          OR (p_framework_code = 'iso27001' AND cc.applies_to_iso)
          OR (p_framework_code = 'mitre' AND cc.applies_to_mitre)
      );

    -- Count compliant controls
    SELECT COUNT(*) INTO v_compliant
    FROM target_control_status tcs
    JOIN compliance_controls cc ON tcs.control_id = cc.id
    WHERE tcs.target_id = p_target_id
      AND tcs.status = 'compliant'
      AND (
          (p_framework_code = 'nis2' AND cc.applies_to_nis2)
          OR (p_framework_code = 'nist' AND cc.applies_to_nist)
          OR (p_framework_code = 'iso27001' AND cc.applies_to_iso)
          OR (p_framework_code = 'mitre' AND cc.applies_to_mitre)
      );

    -- Calculate percentage
    IF v_total > 0 THEN
        v_score := (v_compliant::NUMERIC / v_total::NUMERIC) * 100;
    ELSE
        v_score := 0;
    END IF;

    RETURN ROUND(v_score, 2);
END;
$$ LANGUAGE plpgsql;

-- Update compliance status after control check
CREATE OR REPLACE FUNCTION update_target_compliance_status()
RETURNS TRIGGER AS $$
DECLARE
    v_framework_code VARCHAR;
BEGIN
    -- Update for all applicable frameworks
    FOR v_framework_code IN
        SELECT UNNEST(ARRAY['nis2', 'nist', 'iso27001', 'mitre'])
    LOOP
        INSERT INTO target_compliance_status (
            target_id,
            framework_code,
            total_controls,
            compliant_controls,
            non_compliant_controls,
            not_applicable_controls,
            not_checked_controls,
            compliance_score,
            last_scan_at
        )
        SELECT
            NEW.target_id,
            v_framework_code,
            COUNT(*) FILTER (WHERE tcs.status != 'not_applicable'),
            COUNT(*) FILTER (WHERE tcs.status = 'compliant'),
            COUNT(*) FILTER (WHERE tcs.status = 'non_compliant'),
            COUNT(*) FILTER (WHERE tcs.status = 'not_applicable'),
            COUNT(*) FILTER (WHERE tcs.status = 'not_checked'),
            calculate_compliance_score(NEW.target_id, v_framework_code),
            NOW()
        FROM target_control_status tcs
        JOIN compliance_controls cc ON tcs.control_id = cc.id
        WHERE tcs.target_id = NEW.target_id
          AND (
              (v_framework_code = 'nis2' AND cc.applies_to_nis2)
              OR (v_framework_code = 'nist' AND cc.applies_to_nist)
              OR (v_framework_code = 'iso27001' AND cc.applies_to_iso)
              OR (v_framework_code = 'mitre' AND cc.applies_to_mitre)
          )
        ON CONFLICT (target_id, framework_code)
        DO UPDATE SET
            total_controls = EXCLUDED.total_controls,
            compliant_controls = EXCLUDED.compliant_controls,
            non_compliant_controls = EXCLUDED.non_compliant_controls,
            not_applicable_controls = EXCLUDED.not_applicable_controls,
            not_checked_controls = EXCLUDED.not_checked_controls,
            compliance_score = EXCLUDED.compliance_score,
            last_scan_at = EXCLUDED.last_scan_at,
            updated_at = NOW();
    END LOOP;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to auto-update compliance status
CREATE OR REPLACE TRIGGER trigger_update_compliance_status
    AFTER INSERT OR UPDATE ON target_control_status
    FOR EACH ROW
    EXECUTE FUNCTION update_target_compliance_status();

-- Get compliance dashboard data for a target
CREATE OR REPLACE FUNCTION get_compliance_dashboard(p_target_id INTEGER)
RETURNS TABLE (
    framework_code VARCHAR,
    framework_name VARCHAR,
    compliance_score NUMERIC,
    total_controls INTEGER,
    compliant INTEGER,
    non_compliant INTEGER,
    critical_gaps INTEGER,
    high_gaps INTEGER,
    last_scan TIMESTAMP
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        tcs.framework_code,
        cf.name,
        tcs.compliance_score,
        tcs.total_controls,
        tcs.compliant_controls,
        tcs.non_compliant_controls,
        COUNT(*) FILTER (
            WHERE tcstat.status IN ('non_compliant', 'not_checked')
            AND cc.priority = 'Critical'
        )::INTEGER,
        COUNT(*) FILTER (
            WHERE tcstat.status IN ('non_compliant', 'not_checked')
            AND cc.priority = 'High'
        )::INTEGER,
        tcs.last_scan_at
    FROM target_compliance_status tcs
    JOIN compliance_frameworks cf ON tcs.framework_code = cf.code
    LEFT JOIN target_control_status tcstat ON tcstat.target_id = tcs.target_id
    LEFT JOIN compliance_controls cc ON tcstat.control_id = cc.id
        AND (
            (tcs.framework_code = 'nis2' AND cc.applies_to_nis2)
            OR (tcs.framework_code = 'nist' AND cc.applies_to_nist)
            OR (tcs.framework_code = 'iso27001' AND cc.applies_to_iso)
            OR (tcs.framework_code = 'mitre' AND cc.applies_to_mitre)
        )
    WHERE tcs.target_id = p_target_id
    GROUP BY
        tcs.framework_code,
        cf.name,
        tcs.compliance_score,
        tcs.total_controls,
        tcs.compliant_controls,
        tcs.non_compliant_controls,
        tcs.last_scan_at
    ORDER BY tcs.compliance_score DESC;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- Update triggers
-- ============================================================================

CREATE OR REPLACE TRIGGER update_controls_updated_at
    BEFORE UPDATE ON compliance_controls
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE OR REPLACE TRIGGER update_templates_updated_at
    BEFORE UPDATE ON hardening_templates
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE OR REPLACE TRIGGER update_target_compliance_updated_at
    BEFORE UPDATE ON target_compliance_status
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE OR REPLACE TRIGGER update_target_control_updated_at
    BEFORE UPDATE ON target_control_status
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE OR REPLACE TRIGGER update_violations_updated_at
    BEFORE UPDATE ON compliance_violations
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Comments
-- ============================================================================

COMMENT ON TABLE compliance_frameworks IS 'Compliance frameworks (NIS2, NIST 800-53, ISO 27001, MITRE D3FEND)';
COMMENT ON TABLE compliance_macroareas IS '12 macroareas organizing 113 controls';
COMMENT ON TABLE compliance_controls IS '113 host-level compliance controls mapped to 4 frameworks';
COMMENT ON TABLE hardening_templates IS 'Hardening templates grouping controls for specific scenarios';
COMMENT ON TABLE hardening_template_controls IS 'Many-to-many: templates to controls mapping';
COMMENT ON TABLE target_compliance_status IS 'Aggregated compliance status per target per framework';
COMMENT ON TABLE target_control_status IS 'Detailed status of each control for each target';
COMMENT ON TABLE hardening_executions IS 'Audit trail of all hardening template executions';
COMMENT ON TABLE compliance_violations IS 'Detected compliance violations requiring remediation';
COMMENT ON TABLE compliance_scan_history IS 'Historical record of all compliance scans';

COMMENT ON FUNCTION calculate_compliance_score(INTEGER, VARCHAR) IS 'Calculate compliance score (0-100) for target/framework pair';
COMMENT ON FUNCTION get_compliance_dashboard IS 'Get complete compliance dashboard data for a target';
