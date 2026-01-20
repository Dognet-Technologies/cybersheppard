-- ============================================================================
-- Migration 008: Bayesian Network Support for Event Correlations
-- ============================================================================
-- Description: Add Bayesian inference fields to event_correlations table
-- Created: 2026-01-20
-- ============================================================================

-- Add Bayesian Network inference columns to event_correlations
ALTER TABLE event_correlations
ADD COLUMN IF NOT EXISTS bayesian_attack_stages JSONB,
ADD COLUMN IF NOT EXISTS bayesian_next_stages JSONB,
ADD COLUMN IF NOT EXISTS bayesian_confidence DECIMAL(10, 4),
ADD COLUMN IF NOT EXISTS bayesian_explanation TEXT,
ADD COLUMN IF NOT EXISTS bayesian_analyzed_at TIMESTAMPTZ;

-- Create index for efficient querying of Bayesian results
CREATE INDEX IF NOT EXISTS idx_event_correlations_bayesian_confidence
ON event_correlations(bayesian_confidence DESC)
WHERE bayesian_confidence IS NOT NULL;

-- Create index for Bayesian attack stages JSONB queries
CREATE INDEX IF NOT EXISTS idx_event_correlations_bayesian_stages
ON event_correlations USING GIN (bayesian_attack_stages)
WHERE bayesian_attack_stages IS NOT NULL;

-- Comment on columns
COMMENT ON COLUMN event_correlations.bayesian_attack_stages IS 'Bayesian Network inferred attack stages with probabilities: [(stage_id, probability), ...]';
COMMENT ON COLUMN event_correlations.bayesian_next_stages IS 'Predicted next attack stages based on Bayesian inference';
COMMENT ON COLUMN event_correlations.bayesian_confidence IS 'Overall confidence of Bayesian attack chain probability (0.0-1.0)';
COMMENT ON COLUMN event_correlations.bayesian_explanation IS 'Human-readable causal explanation of attack progression';
COMMENT ON COLUMN event_correlations.bayesian_analyzed_at IS 'Timestamp when Bayesian analysis was performed';

-- Create view for high-confidence Bayesian predictions
CREATE OR REPLACE VIEW bayesian_high_confidence_attacks AS
SELECT
    c.id,
    c.correlation_type,
    c.severity,
    c.risk_score,
    c.bayesian_attack_stages,
    c.bayesian_next_stages,
    c.bayesian_confidence,
    c.bayesian_explanation,
    c.involved_hosts,
    c.involved_users,
    c.created_at,
    c.bayesian_analyzed_at
FROM event_correlations c
WHERE c.bayesian_confidence > 0.7
  AND c.status = 'active'
ORDER BY c.bayesian_confidence DESC, c.risk_score DESC;

COMMENT ON VIEW bayesian_high_confidence_attacks IS 'Active correlations with high Bayesian confidence (>70%) for attack chain progression';
