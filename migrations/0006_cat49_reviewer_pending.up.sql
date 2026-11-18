-- CAT-49: append-only disposable reviewer registration and activation.
-- No principal or role is created by this migration.
CREATE TABLE auth_cat49_reviewer_registration (
    request_id uuid PRIMARY KEY,
    principal_id uuid NOT NULL UNIQUE REFERENCES auth_user(id) ON DELETE RESTRICT,
    run_id text NOT NULL UNIQUE CHECK (run_id ~ '^[a-z0-9]{8,32}$'),
    intent_digest text NOT NULL CHECK (intent_digest ~ '^sha256:[0-9a-f]{64}$'),
    receipt_digest text NOT NULL CHECK (receipt_digest ~ '^sha256:[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE auth_cat49_reviewer_activation (
    principal_id uuid PRIMARY KEY REFERENCES auth_cat49_reviewer_registration(principal_id) ON DELETE RESTRICT,
    request_id uuid NOT NULL UNIQUE,
    rbac_receipt_digest text NOT NULL CHECK (rbac_receipt_digest ~ '^sha256:[0-9a-f]{64}$'),
    receipt_digest text NOT NULL CHECK (receipt_digest ~ '^sha256:[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE FUNCTION reject_cat49_reviewer_receipt_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'CAT-49 reviewer receipts are immutable';
END;
$$;
CREATE TRIGGER cat49_reviewer_registration_immutable BEFORE UPDATE OR DELETE ON auth_cat49_reviewer_registration
 FOR EACH ROW EXECUTE FUNCTION reject_cat49_reviewer_receipt_mutation();
CREATE TRIGGER cat49_reviewer_activation_immutable BEFORE UPDATE OR DELETE ON auth_cat49_reviewer_activation
 FOR EACH ROW EXECUTE FUNCTION reject_cat49_reviewer_receipt_mutation();
