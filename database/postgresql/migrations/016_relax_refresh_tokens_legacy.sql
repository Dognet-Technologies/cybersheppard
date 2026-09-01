-- ============================================================================
-- CYBERSHEPPARD (MicroSIEM) - Migration 016
-- Description: Relax legacy NOT NULL constraints on refresh_tokens.
--   The auth code (api/auth.rs) was migrated to the plaintext `token` column
--   (added in a later migration) for both storage and validation, but the
--   original `token_hash` and `created_ip` columns kept their NOT NULL
--   constraints. Inserting a refresh token therefore failed at runtime with
--   "null value in column token_hash ... violates not-null constraint".
--   This migration aligns the schema with the code by making the now-unused
--   legacy columns nullable. The UNIQUE index on token_hash is left in place
--   (SQL treats NULLs as distinct, so it does not block multiple rows).
-- ============================================================================

-- NB: nessun BEGIN/COMMIT esplicito: sqlx::migrate! esegue ogni migrazione in una
-- propria transazione. Un BEGIN/COMMIT interno confliggerebbe con quella gestione.

ALTER TABLE refresh_tokens ALTER COLUMN token_hash DROP NOT NULL;
ALTER TABLE refresh_tokens ALTER COLUMN created_ip DROP NOT NULL;

-- Same drift on csrf_tokens: the code (middleware/csrf.rs) stores the plaintext
-- `token` column and upserts with `ON CONFLICT (user_id)`, but the table kept the
-- legacy NOT NULL `token_hash` and had no UNIQUE constraint on user_id (only a
-- non-unique index), so token issuance failed with:
--   "there is no unique or exclusion constraint matching the ON CONFLICT specification".
ALTER TABLE csrf_tokens ALTER COLUMN token_hash DROP NOT NULL;
ALTER TABLE csrf_tokens DROP CONSTRAINT IF EXISTS csrf_tokens_user_id_key;
ALTER TABLE csrf_tokens ADD CONSTRAINT csrf_tokens_user_id_key UNIQUE (user_id);

-- targets.agent_auth_token is NOT NULL but the create handler (api/targets.rs)
-- does not populate it, so POST /api/targets failed with a not-null violation.
-- Give it a random default so the API can create agent-capable targets; the
-- token can still be overridden explicitly when provisioning an agent.
ALTER TABLE targets
    ALTER COLUMN agent_auth_token
    SET DEFAULT md5(random()::text || clock_timestamp()::text)
             || md5(random()::text || clock_timestamp()::text);

-- The agent WebSocket handler (api/agents.rs::update_target_status) sets a
-- connected target's status to 'online', but the original CHECK constraint only
-- allowed pending/active/offline/error/maintenance. The mismatch made the status
-- UPDATE fail silently (the caller ignores the error), so connected agents stayed
-- 'pending' in the UI. Add 'online' to the allowed set.
ALTER TABLE targets DROP CONSTRAINT IF EXISTS targets_status_check;
ALTER TABLE targets ADD CONSTRAINT targets_status_check
    CHECK (status IN ('pending', 'active', 'online', 'offline', 'error', 'maintenance'));
