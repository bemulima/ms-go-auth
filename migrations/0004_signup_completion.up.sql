CREATE TABLE IF NOT EXISTS auth_signup_completion (
    operation_id uuid PRIMARY KEY,
    principal_id uuid UNIQUE NOT NULL,
    email text NOT NULL,
    proof_fingerprint text NOT NULL CHECK (proof_fingerprint ~ '^[0-9a-f]{64}$'),
    password_hash text NOT NULL DEFAULT '',
    state text NOT NULL CHECK (state IN ('pending', 'verified', 'completed')),
    principal_created boolean NOT NULL DEFAULT false,
    receipt_expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT idx_signup_email_proof UNIQUE (email, proof_fingerprint),
    CHECK ((state = 'pending' AND password_hash = '' AND receipt_expires_at IS NULL AND NOT principal_created)
        OR (state IN ('verified', 'completed') AND password_hash <> '' AND receipt_expires_at IS NOT NULL)),
    CHECK (state <> 'completed' OR principal_created)
);
