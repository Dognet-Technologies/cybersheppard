-- ============================================================================
-- 013_agent_metric_snapshots.sql
-- Snapshot lossless delle metriche inviate dal dog_agent via WebSocket.
-- L'agent invia batch di AllMetrics compressi (zstd+base64); il server li
-- decomprime e conserva il JSON originale qui. Il mapping fine verso le
-- measurement InfluxDB tipizzate è un follow-up: questa tabella garantisce
-- che nessun dato dell'agent vada perso nel frattempo.
-- ============================================================================

CREATE TABLE IF NOT EXISTS agent_metric_snapshots (
    id           BIGSERIAL PRIMARY KEY,
    target_id    INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    hostname     TEXT,
    collected_at TIMESTAMPTZ,               -- momento di raccolta lato agent
    received_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metrics      JSONB NOT NULL             -- AllMetrics decompresso (system/network/users/files/services/auditd)
);

CREATE INDEX IF NOT EXISTS idx_agent_metric_snapshots_target_time
    ON agent_metric_snapshots (target_id, received_at DESC);
