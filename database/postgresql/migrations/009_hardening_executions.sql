-- Migration 009: Create hardening_templates and hardening_executions tables

-- ============================================================================
-- Hardening Templates
-- ============================================================================

CREATE TABLE IF NOT EXISTS hardening_templates (
    id                          SERIAL PRIMARY KEY,
    name                        VARCHAR(255) UNIQUE NOT NULL,
    description                 TEXT,
    framework_code              VARCHAR(50),
    compliance_level            VARCHAR(50),
    target_os                   VARCHAR(50),
    target_role                 VARCHAR(100),
    version                     VARCHAR(50) DEFAULT '1.0',
    author                      VARCHAR(255),
    is_official                 BOOLEAN DEFAULT false,
    is_active                   BOOLEAN DEFAULT true,
    execution_order             INTEGER DEFAULT 100,
    dry_run_recommended         BOOLEAN DEFAULT true,
    requires_reboot             BOOLEAN DEFAULT false,
    estimated_duration_minutes  INTEGER,
    risk_level                  VARCHAR(20),
    rollback_supported          BOOLEAN DEFAULT true,
    template_config             JSONB,
    created_at                  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at                  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_by                  VARCHAR(100)
);

CREATE INDEX IF NOT EXISTS idx_templates_framework  ON hardening_templates(framework_code);
CREATE INDEX IF NOT EXISTS idx_templates_os         ON hardening_templates(target_os);
CREATE INDEX IF NOT EXISTS idx_templates_role       ON hardening_templates(target_role);
CREATE INDEX IF NOT EXISTS idx_templates_active     ON hardening_templates(is_active);
CREATE INDEX IF NOT EXISTS idx_templates_official   ON hardening_templates(is_official);

-- ============================================================================
-- Hardening Executions
-- ============================================================================

CREATE TABLE IF NOT EXISTS hardening_executions (
    id                      BIGSERIAL PRIMARY KEY,
    template_id             INTEGER NOT NULL REFERENCES hardening_templates(id) ON DELETE CASCADE,
    target_id               INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    execution_mode          VARCHAR(50) NOT NULL DEFAULT 'dry_run',
    status                  VARCHAR(50) NOT NULL DEFAULT 'pending',
    started_at              TIMESTAMP WITH TIME ZONE,
    completed_at            TIMESTAMP WITH TIME ZONE,
    duration_seconds        INTEGER,
    total_controls          INTEGER,
    successful_controls     INTEGER,
    failed_controls         INTEGER,
    skipped_controls        INTEGER,
    execution_log           TEXT,
    error_message           TEXT,
    warnings                TEXT[],
    rollback_data           JSONB,
    can_rollback            BOOLEAN DEFAULT true,
    rolled_back_at          TIMESTAMP WITH TIME ZONE,
    compliance_score_before DOUBLE PRECISION,
    compliance_score_after  DOUBLE PRECISION,
    executed_by             VARCHAR(100),
    created_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_hardening_executions_template_id ON hardening_executions(template_id);
CREATE INDEX IF NOT EXISTS idx_hardening_executions_target_id   ON hardening_executions(target_id);
CREATE INDEX IF NOT EXISTS idx_hardening_executions_status      ON hardening_executions(status);
CREATE INDEX IF NOT EXISTS idx_hardening_executions_started_at  ON hardening_executions(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_hardening_executions_created_at  ON hardening_executions(created_at DESC);
