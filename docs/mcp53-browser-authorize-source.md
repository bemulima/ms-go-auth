# MCP-53 — opt-in browser authorization and AS discovery

Status: **source-only candidate; Go targeted tests and runtime NOT_RUN in this environment**.
Do not enable in production, activate Gateway, claim external client compatibility,
or merge until the isolated vertical and exact Gherkin run pass.

This is an additive Auth-owned extension to the already implemented PKCE
completion, token exchange, consent readback and revocation APIs.

- `AUTH_MCP_STUDENT_ENABLED=false` remains the default; the browser entrypoint
  additionally requires `AUTH_MCP_BROWSER_ENABLED=true` and a strict HTTPS
  `AUTH_MCP_CONSENT_UI_URI` ending exactly in `/student/mcp/consent`.
- Auth now conditionally serves RFC 8414 metadata at
  `GET /.well-known/oauth-authorization-server`, advertising only
  `authorization_code`, PKCE `S256`, `none` token client auth and the registered
  `courses:read`, `profile:read`, `tasks:read` read scopes (MCP-01 pilot).
  It advertises neither write scope, refresh nor dynamic registration.
- The metadata points to the canonical public Gateway
  `GET /api/auth/v1/auth/mcp/authorize` and existing
  `POST /api/auth/v1/auth/mcp/token`. A non-canonical issuer path or non-default
  internal Auth API prefix makes browser startup fail closed.
- Public GET authorize accepts only the eight exact Student OAuth fields and
  exactly one of `courses:read`, `profile:read` or `tasks:read` (MCP-01
  read-only ceiling). It rejects combined scopes, unknown scopes, writes,
  Calendar and Teacher requests at the browser entrypoint. It redirects the
  allowed non-secret parameters to the fixed first-party consent UI, but does
  **not** admit a user, create consent, grant a permission or issue a code.
  Gateway strips all browser cookies and caller Authorization on this route.
- A signed-in Student explicitly confirms in Next.js. Its server-side BFF
  verifies the current HttpOnly cookie with Auth, then calls the existing
  bearer-only `POST /authorization/complete`. Auth rechecks the actual client,
  persisted Student consent and fresh RBAC role/scope before issuing a one-use
  PKCE authorization code. Frontend JS never receives a frontend JWT.

The first isolated vertical still needs an operator-provisioned, pre-registered
OAuth client and existing Student consent. Client ID Metadata Documents,
dynamic registration, creation of new consent, refresh-token rotation,
automated unauthenticated sign-in restoration, external client live proof,
runtime Gherkin and deployment are **outside this source checkpoint**.

MCP-01 source extension: the authorization-server platform ceiling now includes
the other two **already signed by RBAC** read scopes. These are never granted
by default. The client registry, the exact Student consent snapshot and the
fresh RBAC Student role + per-scope permission must independently allow a
scope before Auth can issue a token containing it. Existing V0 consent for
`courses:read` remains just that scope. Runtime and Practice Catalog may use
`tasks:read` for qualified, subject-scoped read projections only. All MCP-02
write scopes and MCP-03 Calendar/Teacher scopes stay **DENIED**, until their
separate owner, consent, permission and API contracts are implemented. This
extension's unit/real-service/Gherkin checks are **NOT_RUN** here.
