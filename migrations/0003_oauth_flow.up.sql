ALTER TABLE auth_user
    ALTER COLUMN password_hash DROP NOT NULL,
    ALTER COLUMN password_updated_at DROP NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_identity_user_provider
    ON auth_identity(user_id, provider);

CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_identity_provider_subject
    ON auth_identity(provider, provider_user_id);

CREATE TABLE IF NOT EXISTS auth_oauth_transaction (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    state_hash text UNIQUE NOT NULL,
    provider text NOT NULL,
    code_verifier text NOT NULL,
    return_to text NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_auth_oauth_transaction_provider
    ON auth_oauth_transaction(provider);

CREATE INDEX IF NOT EXISTS idx_auth_oauth_transaction_expires_at
    ON auth_oauth_transaction(expires_at);
