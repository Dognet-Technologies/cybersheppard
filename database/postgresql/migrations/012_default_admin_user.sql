-- Migration 010: Add must_change_password flag and seed default admin user

ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT false;

-- Insert default admin user (admin / admin) only if no users exist yet
-- Password hash: argon2id hash of 'admin'
INSERT INTO users (username, email, password_hash, role, is_active, is_verified, must_change_password)
SELECT
    'admin',
    'admin@cybersheppard.local',
    '$argon2id$v=19$m=19456,t=2,p=1$eFHSaFuoZEGtJR6loJqHAg$BvKaU9AOVgBRY1NXqJlOPVzq1VBm5lFqkVQ9k1YxAvU',
    'admin',
    true,
    true,
    true
WHERE NOT EXISTS (SELECT 1 FROM users LIMIT 1);
