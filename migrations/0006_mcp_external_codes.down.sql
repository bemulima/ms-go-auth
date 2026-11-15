-- Fail closed: never silently erase consent, client registrations or code
-- evidence, including consumed/expired rows. A deliberate, separately
-- approved retention/cleanup operation is required before rollback.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM auth_mcp_authorization_code)
       OR EXISTS (SELECT 1 FROM auth_mcp_consent)
       OR EXISTS (SELECT 1 FROM auth_mcp_client) THEN
        RAISE EXCEPTION 'refusing MCP schema rollback with retained authorization records';
    END IF;
END $$;

DROP TABLE IF EXISTS auth_mcp_authorization_code;
DROP TABLE IF EXISTS auth_mcp_consent;
DROP TABLE IF EXISTS auth_mcp_client;
