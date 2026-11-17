# MCP-53 — explicit private-learning OAuth scope ceiling (source only)

The existing Student MCP read scope platform ceiling is unchanged unless
`AUTH_MCP_PRIVATE_LEARNING_READ_SCOPES_ENABLED=true`, which defaults **false**.
This independent opt-in adds only `knowledge:read` and `lessons:read` to the
canonical requested/advertised scope grammar. It may be combined with the
separate default-off MCP write-scope ceiling.

The new scopes are **NOT automatically granted** by the Student role,
`courses:read`, a browser session or any external MCP client. A grant can
contain one only after ALL of these preconditions:

1. The operator enables the separate platform ceiling, with owner read
   services and privacy gates qualified.
2. The exact registered external client explicitly allows the scope.
3. The exact Student persists unrevoked consent for the same client/resource.
4. Auth signs a fresh canonical request and verifies RBAC's signed,
   per-scope default-Student permission result.
5. The Student owner and Course/Planner owner independently authorize the
   current selected graph or exact pinned lesson placement at request time.

RBAC maps these new scope strings only to `mcp.knowledge.read` and
`mcp.lessons.read`. Both permissions default to **absent**; this patch seeds
no rows, roles, grants or production policy. No new client, consent, UI,
endpoint, token or runtime service is enabled in this source checkpoint.

The canonical sorted Auth/RBAC scope grammar now supports up to ten scopes,
still denying unknown, duplicated or unordered values. The default ceiling
remains the previous four read scopes; no existing V0/Calendar consent gains
private access. Metadata, consent completion and access readback use the same
conditionally widened ceiling only after the separate flag is enabled.

Status: `SOURCE_PREPARED`; Go/real OAuth/Gherkin/Mac tests NOT_RUN here.
