# MCP-53: explicit Calendar OAuth read scope (source only)

The MCP Student read-scope ceiling now also admits `calendar:read`, in canonical
lexicographic position before `courses:read`. This is *only request grammar*.
It does not add a default client registration, grant, consent, RBAC permission
or Calendar data access.

To issue the scope, Auth must prove each of the following at authorization
**and** at subsequent MCP access verification: client registration permits
`calendar:read`, Student gave persisted current consent, Student session is
still valid, and RBAC signs a fresh per-scope decision containing
`calendar:read`. A default Student role by itself must not imply permission.

RBAC maps the exact scope to `mcp.calendar.read` with an empty resource kind;
it grants nothing unless the canonical role permissions store explicitly
contains that permission. A missing/revoked permission, unavailable RBAC,
wrong subject, invalid proof, stale consent or query for any write scope is
DENY. Existing three-scope V0 grants remain valid and unchanged.

Client BFF must show a separate Calendar consent description. The Calendar
owner uses a distinct service capability and exports only a bounded confirmed
event projection. Booking, cancellation, mentor management and reminders are
not implied. Real grant issuance/integration and Gherkin remain NOT_RUN until
the final local `VERTICAL_BATCH_V2` test gate.
