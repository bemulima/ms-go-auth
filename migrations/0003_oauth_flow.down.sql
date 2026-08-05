DROP TABLE IF EXISTS auth_oauth_transaction;
DROP INDEX IF EXISTS idx_auth_identity_user_provider;
DROP INDEX IF EXISTS idx_auth_identity_provider_subject;

UPDATE auth_user
SET password_hash = ''
WHERE password_hash IS NULL;

UPDATE auth_user
SET password_updated_at = now()
WHERE password_updated_at IS NULL;

ALTER TABLE auth_user
    ALTER COLUMN password_hash SET NOT NULL,
    ALTER COLUMN password_updated_at SET NOT NULL;
