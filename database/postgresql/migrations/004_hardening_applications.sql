-- ===========================================================================
-- CYBERSHEPPARD - Hardening Applications Table
-- ===========================================================================
-- Tracks hardening model applications to targets
-- Stores complete history with results and logs

-- Create hardening_applications table
CREATE TABLE IF NOT EXISTS hardening_applications (
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

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_hardening_applications_target_id
    ON hardening_applications(target_id, applied_at DESC);

CREATE INDEX IF NOT EXISTS idx_hardening_applications_model_path
    ON hardening_applications(model_path);

CREATE INDEX IF NOT EXISTS idx_hardening_applications_success
    ON hardening_applications(success);

CREATE INDEX IF NOT EXISTS idx_hardening_applications_applied_at
    ON hardening_applications(applied_at DESC);

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

-- Comments
COMMENT ON TABLE hardening_applications IS 'Tracks history of hardening model applications to targets';
COMMENT ON COLUMN hardening_applications.model_path IS 'Path to hardening model (e.g., base/ssh.yml)';
COMMENT ON COLUMN hardening_applications.success IS 'Whether hardening application succeeded';
COMMENT ON COLUMN hardening_applications.steps_completed IS 'Number of steps completed successfully';
COMMENT ON COLUMN hardening_applications.steps_failed IS 'Number of steps that failed';
COMMENT ON COLUMN hardening_applications.backup_path IS 'Path to backup tarball for rollback';
COMMENT ON COLUMN hardening_applications.result_log IS 'JSON array of log messages from application';
