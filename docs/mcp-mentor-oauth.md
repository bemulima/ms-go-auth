# Mentor MCP authorization — MENT-07A

This is a complete source path for the initial `mentor.get_profile` capability.
`MCP_MENTOR_EXTERNAL_ENABLED` defaults to false. Source verification does not
activate routes, register a client, apply a migration, grant a permission or
establish live PostgreSQL/broker/edge acceptance.

## Persona and authority

Mentor uses separate `auth_mcp_mentor_client`, `auth_mcp_mentor_consent` and
`auth_mcp_mentor_code` tables, a dedicated RSA key pair, issuer ending in
`/mentor`, JOSE type `mentor-at+jwt`, and exact `persona=MENTOR`. The default Mentor scope is
`mentor:profile:read`. External access tokens contain exactly `iss`, `sub`,
`aud`, `client_id`, `grant_id`, `scope`, `persona`, `iat`, `exp`, `jti`; they
expire within five minutes and have a canonical nonzero UUID subject/grant/JTI.
The resource is the same exact configured HTTPS `/mcp` URL used by Student.

Student tables, consent, token type, scope policy and standalone verification
route remain unchanged. With both personas enabled, the private verifier uses
the untrusted JOSE type only to select a full verifier. A rejected branch is
terminal; there is no fallback, mixed identity DTO or scope union. Mentor's
public issuer must differ from both Student's issuer and the web JWT issuer.
Dedicated key isolation compares RSA moduli, including different exponents.

Every preview, consent approval, token exchange and access verification requires
a fresh signed RBAC decision and a fresh Mentor owner approval probe. RBAC must
confirm the current exact service-scoped Mentor role and its explicit permission
for the requested scope. Mentor independently applies its persisted approval and current
signed role fences. The token/grant path rereads Auth-owned account, client,
consent, expiry and scope state after remote authority calls. No role claim,
caller actor ID, generic Admin bypass or cached ALLOW establishes access.

## HTTP contract

Internal Auth prefix: `/api/v 1/auth/mcp/mentor`. Gateway public prefix:
`/api/auth/v 1/auth/mcp/mentor`.

| Method and suffix | Authentication and behavior |
| --- | --- |
| `GET /authorize` | Validate eight public OAuth parameters; redirect only to the configured first-party `/mentor/mcp/consent` page. No grant is created. |
| `GET /consent` | Live web-session bearer; preview registered client name, fixed scope and current consent status. |
| `POST /consent` | Live web-session bearer plus exact eight-field JSON; explicit consent and code committed together; returns `{redirect_uri}`. |
| `POST /token` | Public PKCE exchange; exact six-field form; no bearer or cookie. Returns `access_token`, `token_type`, `expires_in`, `scope`. |
| `POST /revoke` | Live web-session bearer and exact `{client_id,resource}` JSON; idempotent 204, including after role loss. |

The eight authorization fields are `response_type=code`, `client_id`,
`redirect_uri`, `resource`, `code_challenge`, `code_challenge_method=S256`,
one supported `scope`, and `state`. State is 22–256 characters from
`[A-Za-z 0-9._~-]`; the challenge and returned opaque code are canonical 43-byte
base64url strings. Codes contain 256 bits of entropy; the database stores only
their SHA-256 digest. Redirects match a registered complete URL exactly and
use HTTPS or literal loopback HTTP (`127.0.0.1`/`[::1]`). Credentials, fragments
and reserved callback token/code/state/error parameters are rejected.

Token form fields are `grant_type=authorization_code`, `code`, `code_verifier`,
`client_id`, `redirect_uri`, `resource`. A valid-shape wrong PKCE verifier burns
the code. Code replay, expiration, changed client/redirect/resource, lost
permission, suspension and revoked consent fail closed. There is no external
refresh-token flow in this version.

Consent responses are exact `{persona,client_id,client_name,resource,scopes,
consent_active,consent_expires_at?}`; the optional expiry is an RFC 3339 time.
Private introspection expiry is an integer Unix timestamp. Bearer endpoints
reject cookies and caller identity JSON; the first-party BFF owns browser
session/CSRF protection. The authenticated subject and session are rechecked
before the consent response is released. Errors expose only `invalid_request`,
`invalid_token`, `access_denied`, `invalid_grant` or `temporarily_unavailable`.
All responses are `Cache-Control: no-store`.

RFC 8414 discovery is `/.well-known/oauth-authorization-server/mentor`, with
issuer `https://<gateway-origin>/mentor`. Advertised endpoints use the canonical
Gateway public prefix above. No dynamic client registration is advertised.

## Private delegation

`POST /internal/mcp/verify` retains its separate `X-MCP-Service-Token` capability
and exact `{token,resource}` request. Mentor success has exactly `persona`,
`mentor_id`, `client_id`, `grant_id`, `audience`, `scopes`, numeric `expires_at`,
`owner_proof`. Student success keeps its previous shape. The private route is
also mounted on the optional existing dedicated Mentor HTTPS listener; the
ordinary Echo listener requires trusted TLS termination.

The owner probe calls only `POST /internal/mcp/v 1/mentor/approval` over verified
HTTPS with an independent capability and `{proof}`. It accepts only exact
`{schema:"mentor-mcp-approval.v 1",mentor_id,approved:true}` success. Its transport
has no proxy, redirects, transparent decompression, replayable body or retry;
body sizes and deadlines are bounded. An optional configured CA pool replaces
system roots. No client input controls the target origin.

Approval proofs use `iss`, `aud=ms-go-mentor-mcp`, `sub`, `persona=MENTOR`,
`purpose=MCP_MENTOR_APPROVAL_V 1`, integer `iat`/`exp`, UUID `jti`. Profile
delegation replaces purpose with `MCP_MENTOR_PROFILE_READ_V 1` and adds
`client_id`, `grant_id`, `resource`, `scope`. Both use exact RS256/JWT headers,
live lifetimes no longer than 15 seconds and no future issued time. Profile
expiry is also capped to the accepted OAuth grant. MCP alone receives this
proof and sends it to the dedicated Mentor read adapter; it is never a tool
output or an external access token. Owner approval/profile contracts remain
canonical in `ms-go-mentor`.

RBAC requests use subject `rbac.checkMCPMentorAccess`, the dedicated Mentor
signing key, audience `ms-go-rbac-mcp-mentor` and purpose
`AUTH_RBAC_MCP_MENTOR_ACCESS_V 1`. The exact claims are `iss`, `aud`, `sub`,
`persona`, `purpose`, `scope`, `jti`, `iat`, `exp`. The 15-second signed reply
must match the request subject, nonce, exact raw-proof SHA-256 and requested
scope, and cannot outlive the request. The reply's separate-key signature,
purpose, audience, expiry and response-JTI replay fence are mandatory. The
canonical response contract is owned by `ms-go-rbac`.

## Configuration and schema

| Configuration | Requirement when enabled |
| --- | --- |
| `MCP_MENTOR_EXTERNAL_ENABLED` | Default `false`. |
| `MCP_MENTOR_ISSUER` | Exact HTTPS issuer with path `/mentor`. |
| `MCP_MENTOR_RESOURCE_URI` | Exact HTTPS `/mcp`; equal to Student resource when both are enabled. |
| `MCP_MENTOR_CONSENT_UI_URI` | Fixed first-party HTTPS `/mentor/mcp/consent`. |
| `MCP_MENTOR_PRIVATE_KEY`, `MCP_MENTOR_PUBLIC_KEY` | Matching dedicated 2048–8192-bit RSA PEM pair; separate from configured web/role/lookup keys. |
| `MCP_MENTOR_RBAC_DECISION_PUBLIC_KEY` | Separate trusted RBAC decision key. |
| `MCP_MENTOR_APPROVAL_URL` | Fixed trusted HTTPS owner origin and exact approval path. |
| `MCP_MENTOR_APPROVAL_TOKEN` | Dedicated 32–256-byte printable capability, no comma. |
| `MCP_MENTOR_APPROVAL_CA_PEM` | Optional trusted CA certificate PEM; otherwise normal system trust. |
| `MCP_MENTOR_ACCESS_TTL` | Default `5m`, maximum `5m`. |
| `MCP_MENTOR_CONSENT_TTL` | Default `24h`, at least access TTL and at most `24h`. |
| `AUTH_MCP_ADAPTER_VERIFY_TOKEN` | Existing separate private verifier capability,32–4096 printable bytes, no comma. |
| `AUTH_DB_MIGRATE_ON_START` | Must be `false` when Mentor MCP is enabled. |

Enabled-only configuration is validated before database, broker or schema
startup effects. Missing keys/dependencies/schema never enable partial access.
Migration 0008 is additive and empty. Registered client metadata and the RBAC
permission assignment require separately approved owner administration; the
migration grants nothing. Consent approval serializes on the Auth account,
revokes the previous grant for that same client/resource, and commits the new
consent and hashed code in one transaction. Disconnect takes the same account
lock. Code redemption is one conditional `UPDATE ... RETURNING`; a lost response
does not permit replay. Rollback refuses retained registrations, consent and
code evidence, including expired/consumed/revoked rows.

Source tests cover PKCE/replay/concurrent redemption, explicit consent,
revocation during remote authority I/O, session loss, persona/scope/token
substitution, signed RBAC bindings, strict HTTP, pure metadata/configuration
and actual GORM transaction/column/logging protocol with an injected driver.
No injected driver result is PostgreSQL acceptance. Real schema lifecycle,
database concurrency, broker ACL and complete Gateway/browser acceptance remain
separate prerequisites before activation.

### MENT-07B offers consent

`MCP_MENTOR_OFFERS_ENABLED=false` by default. With Mentor OAuth and this
flag enabled, the Mentor issuer advertises `mentor:offers:read` as another
supported scope. Authorization requires an exact registered redirect and
explicit permission for that requested scope from both the client
registration and current signed RBAC decision. Each OAuth grant still has
one exact scope. Reapproval replaces the previous grant for that
mentor/client/resource. Changing scope requires another explicit approval.

The authorization code is bound to the exact consent it was created with.
Exchange and verification require the scope to match the current consent
and current client ceiling. The owner proof for `mentor:offers:read` uses
`MCP_MENTOR_OFFERS_READ_V1`, distinct from the profile purpose.
Migration 0009 widens scope checks without auto-granting new access. It
preserves existing profile rows and refuses rollback while offers entries
still need the new constraints. Runtime SQL and live authorization remain
unverified.

## MENT-07B workspace read scopes

`MCP_MENTOR_WORKSPACE_READ_ENABLED` defaults to false. When enabled, the
Mentor issuer supports explicit singleton approvals for
`mentor:students:read`, `mentor:cohorts:read`, `mentor:schedule:read`,
`mentor:skills:read` and `mentor:reviews:read`. A registered client may allow
several, while each authorization code, grant and token carries exactly one.
Authorization, metadata and per-request verification use the same flag.
Migration `0010_mcp_mentor_workspace_read` updates the closed database scope
constraints without adding any client or grant. Its rollback refuses retained
workspace scopes. After current Auth consent, scoped RBAC and Mentor approval
checks, Auth issues a proof with purpose `MCP_MENTOR_WORKSPACE_READ_V1` and
the exact verified scope. The proof expires within 15 seconds and by grant expiry.

## MENT-07D skill draft consent

`MCP_MENTOR_SKILL_DRAFT_ENABLED` defaults to false. When enabled,
`mentor:skills:write` requires its own current singleton consent and exact
RBAC permission. Auth issues a private `MCP_MENTOR_SKILL_DRAFT_V1` proof
after verifying the enabled flag, client, active grant and Mentor approval.
The operation ceiling covers skill draft create/edit, validation and preview.
Migration `0011_mcp_mentor_skill_draft` adds the exact scope to the existing
database checks. Its rollback refuses rows that retain it.

The workspace read flag also admits the explicit `mentor:courses:read` and
`mentor:tasks:read` singleton scopes for authored content inventory. Migration
`0015_mcp_mentor_authored_content_read` extends the client and consent checks.
