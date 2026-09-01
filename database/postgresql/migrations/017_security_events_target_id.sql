-- ============================================================================
-- CYBERSHEPPARD (MicroSIEM) - Migration 017
-- Description: aggiunge `target_id` a security_events. Gli eventi inoltrati
--   dall'agent conoscono il target (id) in fase di ingest, ma finora non lo
--   memorizzavano: la tabella si legava ai target solo via `source_host` (spesso
--   "unknown" per gli eventi Laurel). La colonna abilita il legame diretto
--   evento→asset, usato dal detector R18 (Sensor Silence: agent vivo ma eventi
--   di sicurezza fermi) e in generale per query per-target affidabili.
-- ============================================================================

-- NB: nessun BEGIN/COMMIT: sqlx::migrate! gestisce la transazione per migrazione.
ALTER TABLE security_events
    ADD COLUMN IF NOT EXISTS target_id INTEGER REFERENCES targets(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_security_events_target ON security_events(target_id);
