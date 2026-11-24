-- Retained registrations, revocations and consumed code receipts block rollback.
LOCK TABLE public.auth_mcp_mentor_client, public.auth_mcp_mentor_consent, public.auth_mcp_mentor_code IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
  IF EXISTS(SELECT 1 FROM public.auth_mcp_mentor_client)
    OR EXISTS(SELECT 1 FROM public.auth_mcp_mentor_consent)
    OR EXISTS(SELECT 1 FROM public.auth_mcp_mentor_code) THEN
    RAISE EXCEPTION 'refusing Mentor OAuth rollback with retained authorization records';
  END IF;
END $$;
DROP TABLE public.auth_mcp_mentor_code;
DROP TABLE public.auth_mcp_mentor_consent;
DROP TABLE public.auth_mcp_mentor_client;
