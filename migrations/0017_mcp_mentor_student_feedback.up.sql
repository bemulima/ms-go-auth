-- Register exact Mentor student feedback scope without assigning grants.
ALTER TABLE public.auth_mcp_mentor_client
  DROP CONSTRAINT auth_mcp_mentor_client_allowed_scopes_check,
  ADD CONSTRAINT auth_mcp_mentor_client_allowed_scopes_check CHECK (
    array_ndims(allowed_scopes) = 1 AND array_lower(allowed_scopes, 1) = 1
    AND array_position(allowed_scopes, NULL) IS NULL
    AND cardinality(allowed_scopes) BETWEEN 1 AND 28
    AND allowed_scopes <@ ARRAY['mentor:profile:read','mentor:offers:read','mentor:students:read','mentor:cohorts:read','mentor:schedule:read','mentor:skills:read','mentor:reviews:read','mentor:skills:write','mentor:courses:write','mentor:tasks:write','mentor:courses:publish','mentor:tasks:publish','mentor:skills:publish','mentor:reviews:write','mentor:reviews:decide','mentor:profile:write','mentor:offers:write','mentor:students:write','mentor:cohorts:write','mentor:schedule:write','mentor:offers:publish','mentor:schedule:cancel','mentor:courses:read','mentor:tasks:read','mentor:notifications:read','mentor:dialogs:read','mentor:cohorts:respond','mentor:students:feedback']::text[]
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
        + (('mentor:reviews:decide' = ANY(allowed_scopes))::integer)
        + (('mentor:profile:write' = ANY(allowed_scopes))::integer)
        + (('mentor:offers:write' = ANY(allowed_scopes))::integer)
        + (('mentor:students:write' = ANY(allowed_scopes))::integer)
        + (('mentor:cohorts:write' = ANY(allowed_scopes))::integer)
        + (('mentor:schedule:write' = ANY(allowed_scopes))::integer)
        + (('mentor:offers:publish' = ANY(allowed_scopes))::integer)
        + (('mentor:schedule:cancel' = ANY(allowed_scopes))::integer)
        + (('mentor:courses:read' = ANY(allowed_scopes))::integer)
        + (('mentor:tasks:read' = ANY(allowed_scopes))::integer)
        + (('mentor:notifications:read' = ANY(allowed_scopes))::integer)
        + (('mentor:dialogs:read' = ANY(allowed_scopes))::integer)
        + (('mentor:cohorts:respond' = ANY(allowed_scopes))::integer)
        + (('mentor:students:feedback' = ANY(allowed_scopes))::integer))
  );
ALTER TABLE public.auth_mcp_mentor_consent
  DROP CONSTRAINT auth_mcp_mentor_consent_granted_scopes_check,
  ADD CONSTRAINT auth_mcp_mentor_consent_granted_scopes_check CHECK (
    array_ndims(granted_scopes) = 1 AND array_lower(granted_scopes, 1) = 1
    AND array_position(granted_scopes, NULL) IS NULL
    AND cardinality(granted_scopes) = 1 AND granted_scopes <@ ARRAY['mentor:profile:read','mentor:offers:read','mentor:students:read','mentor:cohorts:read','mentor:schedule:read','mentor:skills:read','mentor:reviews:read','mentor:skills:write','mentor:courses:write','mentor:tasks:write','mentor:courses:publish','mentor:tasks:publish','mentor:skills:publish','mentor:reviews:write','mentor:reviews:decide','mentor:profile:write','mentor:offers:write','mentor:students:write','mentor:cohorts:write','mentor:schedule:write','mentor:offers:publish','mentor:schedule:cancel','mentor:courses:read','mentor:tasks:read','mentor:notifications:read','mentor:dialogs:read','mentor:cohorts:respond','mentor:students:feedback']::text[]
  );
