-- ============================================================================
-- Migration: Agent Support
-- Description: Add columns to targets table for agent-based monitoring
-- Date: 2026-01-18
-- ============================================================================

-- Add agent-related columns to targets table
ALTER TABLE targets ADD COLUMN IF NOT EXISTS agent_enabled BOOLEAN DEFAULT FALSE;
ALTER TABLE targets ADD COLUMN IF NOT EXISTS agent_connected BOOLEAN DEFAULT FALSE;
ALTER TABLE targets ADD COLUMN IF NOT EXISTS agent_last_seen TIMESTAMP;
ALTER TABLE targets ADD COLUMN IF NOT EXISTS agent_auth_token VARCHAR(255);
ALTER TABLE targets ADD COLUMN IF NOT EXISTS agent_version VARCHAR(50);

-- CREATE INDEX IF NOT EXISTS for agent queries
CREATE INDEX IF NOT EXISTS idx_targets_agent_enabled ON targets(agent_enabled);
CREATE INDEX IF NOT EXISTS idx_targets_agent_connected ON targets(agent_connected);

-- Create agents_log table for tracking agent activity
CREATE TABLE IF NOT EXISTS agents_log (
    id SERIAL PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    event_type VARCHAR(50) NOT NULL, -- 'connected', 'disconnected', 'metrics_received', 'error'
    details JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agents_log_target_id ON agents_log(target_id);
CREATE INDEX IF NOT EXISTS idx_agents_log_created_at ON agents_log(created_at);
CREATE INDEX IF NOT EXISTS idx_agents_log_event_type ON agents_log(event_type);

-- Function to generate agent auth token
CREATE OR REPLACE FUNCTION generate_agent_token()
RETURNS TEXT AS $$
BEGIN
    RETURN encode(gen_random_bytes(32), 'hex');
END;
$$ LANGUAGE plpgsql;

-- Update existing targets with auth tokens
UPDATE targets
SET agent_auth_token = generate_agent_token()
WHERE agent_auth_token IS NULL;

-- Make agent_auth_token NOT NULL
ALTER TABLE targets ALTER COLUMN agent_auth_token SET NOT NULL;

COMMENT ON COLUMN targets.agent_enabled IS 'Whether agent-based monitoring is enabled for this target';
COMMENT ON COLUMN targets.agent_connected IS 'Current agent connection status';
COMMENT ON COLUMN targets.agent_last_seen IS 'Last time agent sent data';
COMMENT ON COLUMN targets.agent_auth_token IS 'Authentication token for agent WebSocket connection';
COMMENT ON COLUMN targets.agent_version IS 'Version of agent currently running';
COMMENT ON TABLE agents_log IS 'Log of agent connection events and activities';
