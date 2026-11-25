-- Extend the singleton Mentor scope ceiling without adding grants.
ALTER TABLE public.auth_mcp_mentor_client
  DROP CONSTRAINT auth_mcp_mentor_client_allowed_scopes_check,
  ADD CONSTRAINT auth_mcp_mentor_client_allowed_scopes_check CHECK (
    array_ndims(allowed_scopes) = 1 AND array_lower(allowed_scopes, 1) = 1
    AND array_position(allowed_scopes, NULL) IS NULL
    AND cardinality(allowed_scopes) BETWEEN 1 AND 15
    AND allowed_scopes <@ ARRAY['mentor:profile:read','mentor:offers:read','mentor:students:read','mentor:cohorts:read','mentor:schedule:read','mentor:skills:read','mentor:reviews:read','mentor:skills:write','mentor:courses:write','mentor:tasks:write','mentor:courses:publish','mentor:tasks:publish','mentor:skills:publish','mentor:reviews:write','mentor:reviews:decide']::text[]
    AND cardinality(allowed_scopes) = ((('mentor:profile:read' = ANY(allowed_scopes))::integer)
        + (('mentor:offers:read' = ANY(allowed_scopes))::integer)
        + (('mentor:students:read' = ANY(allowed_scopes))::integer)
        + (('mentor:cohorts:read' = ANY(allowed_scopes))::integer)
        + (('mentor:schedule:read' = ANY(allowed_scopes))::integer)
        + (('mentor:skills:read' = ANY(allowed_scopes))::integer)
        + (('mentor:reviews:read' = ANY(allowed_scopes))::integer)
        + (('mentor:skills:write' = ANY(allowed_scopes))::integer)
        + (('mentor:courses:write' = ANY(allowed_scopes))::integer)
        + (('mentor:tasks:write' = ANY(allowed_scopes))::integer)
        + (('mentor:courses:publish' = ANY(allowed_scopes))::integer)
        + (('mentor:tasks:publish' = ANY(allowed_scopes))::integer)
        + (('mentor:skills:publish' = ANY(allowed_scopes))::integer)
        + (('mentor:reviews:write' = ANY(allowed_scopes))::integer)
        + (('mentor:reviews:decide' = ANY(allowed_scopes))::integer))
  );
ALTER TABLE public.auth_mcp_mentor_consent
  DROP CONSTRAINT auth_mcp_mentor_consent_granted_scopes_check,
  ADD CONSTRAINT auth_mcp_mentor_consent_granted_scopes_check CHECK (
    array_ndims(granted_scopes) = 1 AND array_lower(granted_scopes, 1) = 1
    AND array_position(granted_scopes, NULL) IS NULL
    AND cardinality(granted_scopes) = 1 AND granted_scopes <@ ARRAY['mentor:profile:read','mentor:offers:read','mentor:students:read','mentor:cohorts:read','mentor:schedule:read','mentor:skills:read','mentor:reviews:read','mentor:skills:write','mentor:courses:write','mentor:tasks:write','mentor:courses:publish','mentor:tasks:publish','mentor:skills:publish','mentor:reviews:write','mentor:reviews:decide']::text[]
  );
