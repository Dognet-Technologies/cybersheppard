-- ============================================================================
-- 014_user_api_keys.sql
-- API-key per-utente, revocabili, con scope read/write (portato da SentinelCore
-- per coerenza di suite). Usate dai client programmatici — in particolare il
-- server MCP (POST /api/mcp): una chiave "impersona" il proprio utente, così
-- l'RBAC per ruolo si applica invariato. I tool di scrittura MCP richiedono una
-- chiave con scope 'write' (creabile solo da un admin).
-- Formato chiave: "sk_<48 alfanumerici>"; in storage se ne salva solo lo
-- SHA-256 (key_hash), mai la chiave in chiaro.
-- ============================================================================

CREATE TABLE IF NOT EXISTS user_api_keys (
    id           BIGSERIAL PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         VARCHAR(255) NOT NULL,
    key_hash     VARCHAR(64) NOT NULL,            -- SHA-256 hex della chiave "sk_..."
    key_prefix   VARCHAR(20) NOT NULL,            -- primi caratteri, per display (es. "sk_ab12")
    scope        VARCHAR(10) NOT NULL DEFAULT 'read',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    expires_at   TIMESTAMPTZ,
    UNIQUE (key_hash)
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'user_api_keys_scope_check'
    ) THEN
        ALTER TABLE user_api_keys
            ADD CONSTRAINT user_api_keys_scope_check CHECK (scope IN ('read', 'write'));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_user_api_keys_user_id ON user_api_keys (user_id);
CREATE INDEX IF NOT EXISTS idx_user_api_keys_key_prefix ON user_api_keys (key_prefix);
