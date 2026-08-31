-- ============================================================================
-- 015_mitre_event_mapping.sql
-- Correlazione MITRE degli eventi di sicurezza.
--   - security_events: colonne mitre_tactic (tattica ATT&CK, stesso vocabolario
--     di event_correlations.attack_stage) e mitre_technique (tecnica T1xxx).
--   - mitre_attack_map: mappa DATO-DRIVEN ed ESTENDIBILE evento → tattica/tecnica
--     ATT&CK (+ eventuale tecnica difensiva D3FEND del controllo mitigante).
--     Il backend usa oggi una mappa in codice speculare a questo seed; la tabella
--     è il punto di estensione verso una copertura completa a livello di tecnica
--     (TODO: caricare la mappa da qui invece che dal codice).
-- ============================================================================

ALTER TABLE security_events ADD COLUMN IF NOT EXISTS mitre_tactic    VARCHAR(50);
ALTER TABLE security_events ADD COLUMN IF NOT EXISTS mitre_technique VARCHAR(20);

CREATE INDEX IF NOT EXISTS idx_security_events_mitre_tactic
    ON security_events (mitre_tactic, timestamp DESC);

CREATE TABLE IF NOT EXISTS mitre_attack_map (
    id              BIGSERIAL PRIMARY KEY,
    match_type      VARCHAR(20) NOT NULL DEFAULT 'event_type', -- 'event_type' | 'category'
    match_value     VARCHAR(100) NOT NULL,
    on_failure      BOOLEAN,                 -- NULL = qualsiasi esito; true = solo fail; false = solo success
    mitre_tactic    VARCHAR(50) NOT NULL,    -- tattica ATT&CK (vocabolario attack_stage)
    mitre_technique VARCHAR(20),             -- tecnica ATT&CK (T1xxx) — estendibile
    technique_name  VARCHAR(255),
    d3fend          VARCHAR(50),             -- tecnica difensiva D3FEND del controllo mitigante
    description     TEXT,
    UNIQUE (match_type, match_value, on_failure)
);

-- Seed iniziale (mappa in codice in services/event_collector.rs la rispecchia).
-- Copertura di partenza: verrà estesa verso il set completo delle tecniche.
INSERT INTO mitre_attack_map (match_type, match_value, on_failure, mitre_tactic, mitre_technique, technique_name, d3fend, description) VALUES
    ('event_type', 'USER_AUTH',   true,  'credential_access',    'T1110', 'Brute Force',                         'D3-MFA', 'Autenticazione fallita ripetuta'),
    ('event_type', 'USER_LOGIN',  true,  'credential_access',    'T1110', 'Brute Force',                         'D3-MFA', 'Login fallito'),
    ('event_type', 'USER_LOGIN',  false, 'initial_access',       'T1078', 'Valid Accounts',                      'D3-MFA', 'Login riuscito'),
    ('event_type', 'USER_AUTH',   false, 'initial_access',       'T1078', 'Valid Accounts',                      'D3-MFA', 'Autenticazione riuscita'),
    ('event_type', 'CRED_ACQ',    NULL,  'credential_access',    'T1003', 'OS Credential Dumping',               NULL,     'Acquisizione credenziali'),
    ('event_type', 'USER_CMD',    NULL,  'privilege_escalation', 'T1548', 'Abuse Elevation Control Mechanism',   'D3-PA',  'Comando privilegiato (sudo/su)'),
    ('event_type', 'EXECVE',      NULL,  'execution',            'T1059', 'Command and Scripting Interpreter',   'D3-PSEP','Esecuzione di comando/shell'),
    ('event_type', 'SYSCALL',     true,  'execution',            'T1059', 'Command and Scripting Interpreter',   NULL,     'Syscall fallita'),
    ('event_type', 'PATH',        NULL,  'persistence',          'T1547', 'Boot or Logon Autostart Execution',   'D3-FIM', 'Modifica file/percorso sensibile'),
    ('event_type', 'CONNECT',     NULL,  'lateral_movement',     'T1021', 'Remote Services',                     'D3-NTF', 'Connessione di rete in uscita'),
    ('event_type', 'SOCKADDR',    NULL,  'lateral_movement',     'T1021', 'Remote Services',                     'D3-NTF', 'Attività socket'),
    ('category',   'network',     NULL,  'exfiltration',         'T1041', 'Exfiltration Over C2 Channel',        'D3-NTF', 'Trasferimento dati di rete'),
    ('category',   'authentication', NULL, 'credential_access',  'T1110', 'Brute Force',                         'D3-MFA', 'Evento di autenticazione'),
    ('category',   'authorization',  NULL, 'privilege_escalation','T1548','Abuse Elevation Control Mechanism',   'D3-PA',  'Evento di autorizzazione')
ON CONFLICT (match_type, match_value, on_failure) DO NOTHING;
