-- ============================================================================
-- CYBERSHEPPARD (MicroSIEM) - Migration 018
-- Description: allinea il tipo di compliance_macroareas.created_at a TIMESTAMPTZ.
--   Il codice (api/compliance.rs, struct ComplianceMacroarea) decodifica created_at
--   come chrono::DateTime<Utc> (TIMESTAMPTZ), ma la colonna era TIMESTAMP (senza
--   time zone), causando 500 su GET /api/compliance/macroareas
--   ("mismatched types ... TIMESTAMPTZ ... TIMESTAMP"). La conversione risolve il
--   decode. Idempotente: ri-eseguire l'ALTER allo stesso tipo non produce errori.
-- ============================================================================

ALTER TABLE compliance_macroareas
    ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
