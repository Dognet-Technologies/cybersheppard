-- ============================================================================
-- CYBERSHEPPARD (MicroSIEM) - Simplify User Roles
-- ============================================================================
-- Migration: 009_simplify_roles.sql
-- Description: Simplify user roles to only 3: admin, teamLeader, user
-- Date: 2025-12-29
-- ============================================================================

BEGIN;

-- Drop old role type if exists (from previous complex system)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'user_role') THEN
        -- Rename old type
        ALTER TYPE user_role RENAME TO user_role_old;
    END IF;
END $$;

-- Create new simplified role type
CREATE TYPE user_role AS ENUM ('admin', 'teamLeader', 'user');

-- Update users table to use new role type
ALTER TABLE users
    ALTER COLUMN role TYPE user_role
    USING CASE
        WHEN role::text IN ('admin', 'administrator', 'root') THEN 'admin'::user_role
        WHEN role::text IN ('manager', 'supervisor', 'lead', 'team_leader', 'teamLeader') THEN 'teamLeader'::user_role
        ELSE 'user'::user_role
    END;

-- Drop old type if it exists
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'user_role_old') THEN
        DROP TYPE user_role_old;
    END IF;
END $$;

-- Add team_id for team management (optional, for future use)
ALTER TABLE users ADD COLUMN IF NOT EXISTS team_id INTEGER;
ALTER TABLE users ADD COLUMN IF NOT EXISTS managed_by INTEGER REFERENCES users(id);

-- Create index for team queries
CREATE INDEX IF NOT EXISTS idx_users_team_id ON users(team_id);
CREATE INDEX IF NOT EXISTS idx_users_managed_by ON users(managed_by);

-- Add comments
COMMENT ON TYPE user_role IS 'Simplified user roles: admin (full access), teamLeader (team management), user (basic access)';
COMMENT ON COLUMN users.role IS 'User role: admin, teamLeader, or user';
COMMENT ON COLUMN users.team_id IS 'Team identifier for grouping users (optional)';
COMMENT ON COLUMN users.managed_by IS 'User ID of team leader managing this user (optional)';

-- Create view for team hierarchy
CREATE OR REPLACE VIEW user_hierarchy AS
SELECT
    u.id,
    u.username,
    u.email,
    u.role,
    u.team_id,
    u.managed_by,
    m.username as manager_username,
    m.role as manager_role,
    u.is_active,
    u.created_at
FROM users u
LEFT JOIN users m ON u.managed_by = m.id;

COMMENT ON VIEW user_hierarchy IS 'User hierarchy showing team leaders and their team members';

-- Grant permissions on view
GRANT SELECT ON user_hierarchy TO cybersheppard_app;

COMMIT;
