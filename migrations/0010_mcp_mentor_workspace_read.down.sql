-- Restore the prior ceiling. Refuse rollback while workspace-read rows remain.
ALTER TABLE public.auth_mcp_mentor_client
  DROP CONSTRAINT auth_mcp_mentor_client_allowed_scopes_check,
  ADD CONSTRAINT auth_mcp_mentor_client_allowed_scopes_check CHECK (
    array_ndims(allowed_scopes) = 1 AND array_lower(allowed_scopes, 1) = 1
    AND array_position(allowed_scopes, NULL) IS NULL
    AND (allowed_scopes = ARRAY['mentor:profile:read']::text[]
      OR allowed_scopes = ARRAY['mentor:offers:read']::text[]
      OR (cardinality(allowed_scopes) = 2
        AND allowed_scopes @> ARRAY['mentor:profile:read','mentor:offers:read']::text[]))
  );
ALTER TABLE public.auth_mcp_mentor_consent
  DROP CONSTRAINT auth_mcp_mentor_consent_granted_scopes_check,
  ADD CONSTRAINT auth_mcp_mentor_consent_granted_scopes_check CHECK (
    granted_scopes = ARRAY['mentor:profile:read']::text[]
    OR granted_scopes = ARRAY['mentor:offers:read']::text[]
  );
