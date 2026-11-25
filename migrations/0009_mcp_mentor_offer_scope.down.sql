-- Constraint validation refuses rollback while offers registrations or history remain.
ALTER TABLE public.auth_mcp_mentor_consent
  DROP CONSTRAINT auth_mcp_mentor_consent_granted_scopes_check,
  ADD CONSTRAINT auth_mcp_mentor_consent_granted_scopes_check
    CHECK (granted_scopes = ARRAY['mentor:profile:read']::text[]);
ALTER TABLE public.auth_mcp_mentor_client
  DROP CONSTRAINT auth_mcp_mentor_client_allowed_scopes_check,
  ADD CONSTRAINT auth_mcp_mentor_client_allowed_scopes_check
    CHECK (allowed_scopes = ARRAY['mentor:profile:read']::text[]);
