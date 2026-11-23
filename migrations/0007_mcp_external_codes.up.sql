-- Auth-owned external MCP OAuth state. No endpoint or client is activated by
-- applying this schema; clients/consents must be explicitly registered later.
CREATE TABLE IF NOT EXISTS auth_mcp_client (
    client_id text PRIMARY KEY,
    resource_uri text NOT NULL,
    redirect_uris text[] NOT NULL,
    allowed_scopes text[] NOT NULL,
    disabled_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT auth_mcp_client_redirects_check CHECK (cardinality(redirect_uris) BETWEEN 1 AND 32 AND array_position(redirect_uris, NULL) IS NULL),
    CONSTRAINT auth_mcp_client_scopes_check CHECK (cardinality(allowed_scopes) BETWEEN 1 AND 32 AND array_position(allowed_scopes, NULL) IS NULL)
);

CREATE TABLE IF NOT EXISTS auth_mcp_consent (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    student_id uuid NOT NULL REFERENCES auth_user(id) ON DELETE CASCADE,
    client_id text NOT NULL REFERENCES auth_mcp_client(client_id) ON DELETE RESTRICT,
    resource_uri text NOT NULL,
    granted_scopes text[] NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT auth_mcp_consent_scopes_check CHECK (cardinality(granted_scopes) BETWEEN 1 AND 32 AND array_position(granted_scopes, NULL) IS NULL),
    CONSTRAINT auth_mcp_consent_identity UNIQUE (id, student_id, client_id, resource_uri)
);
CREATE INDEX IF NOT EXISTS idx_auth_mcp_consent_student_active
    ON auth_mcp_consent(student_id, client_id, resource_uri)
    WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS auth_mcp_authorization_code (
    code_hash text PRIMARY KEY,
    student_id uuid NOT NULL,
    client_id text NOT NULL REFERENCES auth_mcp_client(client_id) ON DELETE RESTRICT,
    consent_id uuid NOT NULL,
    redirect_uri text NOT NULL,
    resource_uri text NOT NULL,
    pkce_challenge text NOT NULL,
    scopes text[] NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT auth_mcp_code_hash_check CHECK (code_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT auth_mcp_code_challenge_check CHECK (pkce_challenge ~ '^[A-Za-z0-9_-]{43}$'),
    CONSTRAINT auth_mcp_code_scopes_check CHECK (cardinality(scopes) BETWEEN 1 AND 32 AND array_position(scopes, NULL) IS NULL),
    CONSTRAINT auth_mcp_code_consent_binding FOREIGN KEY (consent_id, student_id, client_id, resource_uri)
        REFERENCES auth_mcp_consent(id, student_id, client_id, resource_uri) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_auth_mcp_code_unconsumed_expiry
    ON auth_mcp_authorization_code(expires_at)
    WHERE consumed_at IS NULL;
