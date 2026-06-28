-- ============================================================================
-- CYBERSHEPPARD (MicroSIEM) - Simplify User Roles
-- ============================================================================
-- Descrizione: limita i ruoli utente a 3 -> admin, teamLeader, user.
-- Approccio: users.role resta VARCHAR garantito da un vincolo CHECK.
--   Un ENUM PostgreSQL imporrebbe un type-override in ogni query sqlx che tocca
--   users.role; il codice tratta role come stringa, quindi VARCHAR+CHECK mantiene
--   il codice invariato garantendo comunque i 3 valori ammessi.
-- Idempotente: riapplicabile senza errori.
-- ============================================================================

BEGIN;

-- La vista user_hierarchy dipende da users.role: va rimossa prima di alterare
-- la colonna, viene ricreata in fondo.
DROP VIEW IF EXISTS user_hierarchy CASCADE;

-- Se un run precedente aveva convertito role nell'enum custom, riportalo a VARCHAR.
DO $$
BEGIN
    IF (SELECT data_type FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'role') = 'USER-DEFINED' THEN
        ALTER TABLE users ALTER COLUMN role TYPE VARCHAR(20) USING role::text;
    END IF;
END $$;

-- Rimuovi eventuale CHECK preesistente su role (es. ('admin','user') da 001).
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;

-- Normalizza i valori esistenti ai 3 ruoli canonici.
UPDATE users SET role = CASE
    WHEN role IN ('admin', 'administrator', 'root') THEN 'admin'
    WHEN role IN ('manager', 'supervisor', 'lead', 'team_leader', 'teamLeader') THEN 'teamLeader'
    ELSE 'user'
END;

-- Applica il set ammesso.
ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('admin', 'teamLeader', 'user'));

-- Elimina i tipi enum non più usati, se presenti da iterazioni precedenti.
DROP TYPE IF EXISTS user_role_old;
DROP TYPE IF EXISTS user_role;

-- Colonne di gestione team (opzionali, per raggruppare gli utenti).
ALTER TABLE users ADD COLUMN IF NOT EXISTS team_id INTEGER;
ALTER TABLE users ADD COLUMN IF NOT EXISTS managed_by INTEGER REFERENCES users(id);

CREATE INDEX IF NOT EXISTS idx_users_team_id ON users(team_id);
CREATE INDEX IF NOT EXISTS idx_users_managed_by ON users(managed_by);

COMMENT ON COLUMN users.role IS 'User role: admin, teamLeader, or user';
COMMENT ON COLUMN users.team_id IS 'Team identifier for grouping users (optional)';
COMMENT ON COLUMN users.managed_by IS 'User ID of team leader managing this user (optional)';

-- Vista gerarchia team.
CREATE OR REPLACE VIEW user_hierarchy AS
SELECT
    u.id,
    u.username,
    u.email,
    u.role,
    u.team_id,
    u.managed_by,
    m.username AS manager_username,
    m.role AS manager_role,
    u.is_active,
    u.created_at
FROM users u
LEFT JOIN users m ON u.managed_by = m.id;

COMMENT ON VIEW user_hierarchy IS 'User hierarchy showing team leaders and their team members';

-- GRANT sulla vista solo se il ruolo applicativo esiste.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cybersheppard_app') THEN
        GRANT SELECT ON user_hierarchy TO cybersheppard_app;
    END IF;
END $$;

COMMIT;
