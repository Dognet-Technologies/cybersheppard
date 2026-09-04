-- ============================================================================
-- 020 — Identità target + sessioni di pairing agent (stile FireDog)
-- ============================================================================
-- Pairing per-identità come FireDog: identity_hash = SHA512(ip+hostname+mac).
-- L'agent, avviato sul target, presenta ip/hostname/mac; il server calcola lo
-- stesso hash e lo confronta con quello registrato, entro una finestra di 3 min.
-- Idempotente (IF NOT EXISTS), nessuna transazione esplicita.

ALTER TABLE targets ADD COLUMN IF NOT EXISTS mac_address VARCHAR(32);
ALTER TABLE targets ADD COLUMN IF NOT EXISTS identity_hash VARCHAR(128);

CREATE TABLE IF NOT EXISTS pairing_sessions (
    id               SERIAL PRIMARY KEY,
    target_id        INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    status           VARCHAR(32) NOT NULL DEFAULT 'pending',   -- pending|verifying_hash|success|failed|expired
    phase_1_verified BOOLEAN NOT NULL DEFAULT false,           -- api_key / token
    phase_2_verified BOOLEAN NOT NULL DEFAULT false,           -- identity hash
    agent_ip         VARCHAR(64),
    agent_hostname   VARCHAR(255),
    agent_mac        VARCHAR(32),
    error_message    TEXT,
    expires_at       TIMESTAMPTZ NOT NULL,                     -- created_at + 3 min
    completed_at     TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_pairing_sessions_target ON pairing_sessions (target_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_pairing_sessions_status ON pairing_sessions (status, expires_at);
