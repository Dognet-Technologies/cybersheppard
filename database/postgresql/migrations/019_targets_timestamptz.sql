-- ============================================================================
-- CYBERSHEPPARD (MicroSIEM) - Migration 019
-- Description: allinea le colonne temporali di `targets` a TIMESTAMPTZ.
--   Le struct Rust (api/targets.rs) decodificano questi campi come
--   chrono::DateTime<Utc> (TIMESTAMPTZ), ma erano TIMESTAMP (senza time zone),
--   causando 500 su GET /api/targets ("mismatched types ... TIMESTAMPTZ ...
--   TIMESTAMP"), che a sua volta lasciava la pagina Targets e la Dashboard a 0.
--   Idempotente: ALTER allo stesso tipo non produce errori.
-- ============================================================================

ALTER TABLE targets ALTER COLUMN last_seen            TYPE TIMESTAMPTZ USING last_seen            AT TIME ZONE 'UTC';
ALTER TABLE targets ALTER COLUMN last_check           TYPE TIMESTAMPTZ USING last_check           AT TIME ZONE 'UTC';
ALTER TABLE targets ALTER COLUMN hardening_applied_at TYPE TIMESTAMPTZ USING hardening_applied_at AT TIME ZONE 'UTC';
ALTER TABLE targets ALTER COLUMN last_monitoring_at   TYPE TIMESTAMPTZ USING last_monitoring_at   AT TIME ZONE 'UTC';
ALTER TABLE targets ALTER COLUMN created_at           TYPE TIMESTAMPTZ USING created_at           AT TIME ZONE 'UTC';
ALTER TABLE targets ALTER COLUMN updated_at           TYPE TIMESTAMPTZ USING updated_at           AT TIME ZONE 'UTC';
ALTER TABLE targets ALTER COLUMN agent_last_seen      TYPE TIMESTAMPTZ USING agent_last_seen      AT TIME ZONE 'UTC';
