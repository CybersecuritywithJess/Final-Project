-- Adds "Continue with Google" support to an existing database.
--
-- A fresh install gets this from schema.sql already; run this only if your
-- audit_tracking database was created before Google sign-in existed:
--
--   mysql -u root audit_tracking < database/migrations/001_google_auth.sql

USE audit_tracking;

-- A Google user never sets a password here, so the hash must be allowed to be
-- absent. Password users are unaffected.
ALTER TABLE users MODIFY password_hash VARCHAR(255) NULL;

ALTER TABLE users
    ADD COLUMN google_id     VARCHAR(64)               NULL UNIQUE AFTER password_hash,
    ADD COLUMN avatar_url    VARCHAR(255)              NULL        AFTER google_id,
    ADD COLUMN auth_provider ENUM('password','google') NOT NULL DEFAULT 'password' AFTER avatar_url;
