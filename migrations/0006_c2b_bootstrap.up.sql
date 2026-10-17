BEGIN;
CREATE TABLE c2b_auth_bootstrap_intent(operation_id uuid PRIMARY KEY,principal_id uuid UNIQUE NOT NULL,intent_digest text NOT NULL CHECK(intent_digest ~ '^sha256:[0-9a-f]{64}$'),signed_json jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE c2b_auth_bootstrap_audit(operation_id uuid PRIMARY KEY,principal_id uuid UNIQUE NOT NULL,receipt_json jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT now());
CREATE FUNCTION c2b_auth_bootstrap_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'bootstrap audit immutable'; END $$;
CREATE TRIGGER c2b_auth_bootstrap_intent_guard BEFORE UPDATE OR DELETE ON c2b_auth_bootstrap_intent FOR EACH ROW EXECUTE FUNCTION c2b_auth_bootstrap_immutable();
CREATE TRIGGER c2b_auth_bootstrap_intent_truncate BEFORE TRUNCATE ON c2b_auth_bootstrap_intent FOR EACH STATEMENT EXECUTE FUNCTION c2b_auth_bootstrap_immutable();
CREATE TRIGGER c2b_auth_bootstrap_audit_guard BEFORE UPDATE OR DELETE ON c2b_auth_bootstrap_audit FOR EACH ROW EXECUTE FUNCTION c2b_auth_bootstrap_immutable();
CREATE TRIGGER c2b_auth_bootstrap_audit_truncate BEFORE TRUNCATE ON c2b_auth_bootstrap_audit FOR EACH STATEMENT EXECUTE FUNCTION c2b_auth_bootstrap_immutable();
COMMIT;
