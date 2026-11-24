-- Isolated Mentor persona. No clients, consents, roles or permissions seeded.
CREATE TABLE public.auth_mcp_mentor_client (
  client_id text PRIMARY KEY CHECK (octet_length(client_id) BETWEEN 1 AND 256),
  display_name text NOT NULL CHECK (octet_length(display_name) BETWEEN 1 AND 160),
  resource_uri text NOT NULL,
  redirect_uris text[] NOT NULL CHECK (cardinality(redirect_uris) BETWEEN 1 AND 32),
  allowed_scopes text[] NOT NULL CHECK (allowed_scopes=ARRAY['mentor:profile:read']::text[]),
  disabled_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(client_id,resource_uri)
);
CREATE TABLE public.auth_mcp_mentor_consent (
  id uuid PRIMARY KEY,
  mentor_id uuid NOT NULL REFERENCES public.auth_user(id) ON DELETE CASCADE,
  client_id text NOT NULL,
  resource_uri text NOT NULL,
  granted_scopes text[] NOT NULL CHECK (granted_scopes=ARRAY['mentor:profile:read']::text[]),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(id,mentor_id,client_id,resource_uri),
  FOREIGN KEY(client_id,resource_uri) REFERENCES public.auth_mcp_mentor_client(client_id,resource_uri) ON DELETE RESTRICT,
  CHECK(id<>'00000000-0000-0000-0000-000000000000'),
  CHECK(mentor_id<>'00000000-0000-0000-0000-000000000000')
);
CREATE UNIQUE INDEX auth_mcp_mentor_one_active_consent ON public.auth_mcp_mentor_consent(mentor_id,client_id,resource_uri) WHERE revoked_at IS NULL;
CREATE TABLE public.auth_mcp_mentor_code (
  code_hash text PRIMARY KEY CHECK(code_hash ~ '^[0-9a-f]{64}$'),
  mentor_id uuid NOT NULL,
  client_id text NOT NULL,
  consent_id uuid NOT NULL,
  resource_uri text NOT NULL,
  redirect_uri text NOT NULL,
  pkce_challenge text NOT NULL CHECK(pkce_challenge ~ '^[A-Za-z0-9_-]{43}$'),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY(consent_id,mentor_id,client_id,resource_uri) REFERENCES public.auth_mcp_mentor_consent(id,mentor_id,client_id,resource_uri) ON DELETE CASCADE
);
CREATE INDEX auth_mcp_mentor_code_expiry ON public.auth_mcp_mentor_code(expires_at);
