-- ============================================================================
-- Migration 006: Compliance Scans Table
-- ============================================================================
-- Track compliance scan executions and their results

CREATE TABLE IF NOT EXISTS compliance_scans (
    id BIGSERIAL PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    status VARCHAR(50) NOT NULL DEFAULT 'pending', -- 'pending', 'running', 'completed', 'failed'
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    total_controls INTEGER,
    checked_controls INTEGER DEFAULT 0,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_compliance_scans_target_id ON compliance_scans(target_id);
CREATE INDEX IF NOT EXISTS idx_compliance_scans_status ON compliance_scans(status);
CREATE INDEX IF NOT EXISTS idx_compliance_scans_created_at ON compliance_scans(created_at DESC);

-- Comments
COMMENT ON TABLE compliance_scans IS 'Tracks compliance scan executions for targets';
COMMENT ON COLUMN compliance_scans.target_id IS 'Target being scanned';
COMMENT ON COLUMN compliance_scans.status IS 'Scan status: pending, running, completed, failed';
COMMENT ON COLUMN compliance_scans.total_controls IS 'Total number of controls to check';
COMMENT ON COLUMN compliance_scans.checked_controls IS 'Number of controls checked so far';
