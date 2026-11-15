# MCP-00C3C: Auth-owned PostgreSQL grant readback (DORMANT)

Parent: [MCP Epic #53](https://github.com/bemulima/learning-platform-business/issues/53).
Stacked after [MCP-00C3B post-code token intent](mcp00-external-token-exchange-source.md).

Status: **source-only + opt-in isolated PostgreSQL test**. No OAuth HTTP
handler, JWT, Auth/RBAC adapter composition, external client registration,
permission, runtime schema migration, deployment or token grant is activated.

## Auth-owned half only

`NewMCPExternalAuthGrantRepository` implements
`domain.MCPExternalAuthGrantReader`, returning a narrowly typed
`MCPExternalAuthGrantSnapshot` from the existing **draft** Auth migration
`0006_mcp_external_codes`. The implementation is read-only; it deliberately
does **not** implement `domain.MCPExternalTokenGrantReadback` and cannot set
the `RBACStudentActive` status required by C3B token-intent preparation.

For the exact `(student UUID, client ID, consent UUID, resource URI)` tuple,
one SQL query verifies at read time:

- A currently existing `auth_user` with `email_verified=true` (0005).
- No unfinished `auth_signup_completion` state for the same principal (0004).
- A matching persisted Auth consent and approved client, with exact resource
  and client identity; no client disable or consent revocation.
- Consent expiry after both the caller clock **and PostgreSQL clock**.
- Current `client.allowed_scopes` and `consent.granted_scopes`, decoded as
  JSON arrays with exact elements (never by splitting a space-joined string);
  empty, duplicate, wildcard, malformed, non-ASCII or oversized scopes deny.

Canonical lowercase UUID input is validated before SQL and cast explicitly to
PostgreSQL `uuid`, avoiding the `text = uuid` ambiguity. GORM's query logger
is disabled for this operation; all unsuccessful lookups return only
`domain.ErrNotFound` and no partially trusted snapshot. This gate does not
claim that `auth_user` by itself proves the **Student** role; it does not.

## Missing composite RBAC authority

The future `MCPExternalTokenGrantReadback` adapter must combine this fresh
Auth snapshot with a separately verified **signed, current RBAC Student**
decision, including allowed Student scopes. Both halves must be joined by
the same exact subject and resource, with a uniform deny on any mismatch,
outage, unsigned decision or stale role. Nothing here mints a token or accepts
client-asserted roles.

After token issuance, every MCP resource request must still check signature,
issuer, MCP audience, scopes, grant revocation and the domain owner's object
ACL; a readback only at token issuance cannot prevent a later revocation race.

## Disposable PostgreSQL acceptance

The existing dedicated `MCP_AUTH_CODE_PG_ENABLE` test now applies draft Auth
migrations `0001`, `0003`, `0004`, `0005`, `0006` in its uniquely generated,
auto-cleaned schema on the exact guarded loopback
`codeci@127.0.0.1/mcp_external_codes_ci_test` database. The same fixture
retains all C2B single-use-code checks and adds C3C real GORM/PostgreSQL
readback tests:

- Positive confirmed identity and exact scopes; wrong Student/client/consent/
  resource and invalid UUID denied.
- Consent revoked/expired, client disabled/resource changed, account
  unverified, invalid stored scope, and unfinished signup denied; restoration
  recovers only the matching active binding.
- Client or consent scope reduction returns the **fresh reduced arrays**, not
  a stale grant; C3B's future RBAC composite must deny any removed scope.
- No shared database, running Auth server, key material or live RBAC is used.

`go test ./...` **skips** the live-Postgres case without the exact opt-in
environment. Only a recorded successful disposable CI run can establish the
actual SQL gate as GREEN. The new source files and the existing opt-in
workflow remain Draft pending owner review.
