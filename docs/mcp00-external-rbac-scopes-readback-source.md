# MCP-00C3D4B: dormant Auth-signed RBAC Student scopes readback

Parent: [MCP Epic #53](https://github.com/bemulima/learning-platform-business/issues/53).
Auth-owned consumer of [RBAC Draft #18](https://github.com/bemulima/ms-go-rbac/pull/18),
stacked after Auth [Draft #23](https://github.com/bemulima/ms-go-auth/pull/23).

## Source-only signer

`MCPStudentScopeProofSigner.Sign` accepts only an Auth-owned **fresh grant
snapshot** (verified Student account, approved client and live consent) plus
an exact sorted, nonempty read-only scope request. It checks that **both**
stored client and consent scope arrays contain each requested scope. This
validation does not replace the required future fresh database read: callers
must obtain the snapshot from `MCPExternalAuthGrantReader`, not from an OAuth
request, bearer token, prompt, code receipt or stale cache.

The only accepted pilot values are `courses:read`, `profile:read` and
`tasks:read` (1–3 distinct values in ascending order). `lessons:read` and all
write/admin/unapproved scopes cannot be signed even when present in Auth's
stored scope arrays. The exact nine-claim proof has RS256 JWT header
`alg=RS256,typ=JWT` and claims
`iss,aud,sub,typ,purpose,scopes,jti,iat,exp`:

- `iss`: configured Auth issuer, normally `auth-service`.
- `aud`: `ms-go-rbac-mcp-student-scopes`.
- `typ`: `mcp_student_scope_check`.
- `purpose`: `AUTH_RBAC_MCP_STUDENT_SCOPES_V1`.
- `sub` / `jti`: canonical lowercase nonzero UUIDs; fresh request JTI.
- `scopes`: exact approved canonical array, without caller-controlled extras.
- `iat` / `exp`: integer Unix seconds, at most 30 seconds; expiry cannot
  exceed the provided Auth consent's expiration.

The signer uses the existing Auth RSA private/public key pair after validating
the two keys match. Missing keys disable signing, and malformed/partial/weak
keys fail closed. It does not sign a role assertion, resource JWT, OAuth access
token or consent artifact. No private key is stored in the repository.

## Strict signed readback (not connected)

The only outbound Core NATS request is `rbac.checkMCPStudentScopes`, with
exact JSON `{"proof":"<RS256 JWT>"}`. Proof is bounded at 8 KiB, request
envelope at 9 KiB and request/reply timeout at 3 seconds. No Student identity,
roles, client IDs or scopes are sent as untrusted unsigned JSON fields.

The only successful reply is `{"decision_jwt":"<RS256 JWT>"}`, verified with
a **dedicated RBAC scopes decision public key**. JWT header must be exactly
`alg=RS256,typ=JWT` and claims exactly
`iss,aud,sub,typ,purpose,requested_scopes,allowed_scopes,jti,request_jti,request_digest,iat,exp`.
The verifier enforces:

- `iss=ms-go-rbac`, `aud=ms-go-auth-mcp-student-scopes-decision`,
  `typ=mcp_student_scopes_decision`, and
  `purpose=RBAC_AUTH_MCP_STUDENT_SCOPES_DECISION_V1`.
- Exact subject, request JTI, and lowercase SHA-256 digest of **the raw Auth
  proof bytes**; the requested scope array matches the caller's exact bound
  request, without reordering or truncation.
- `allowed_scopes` is a non-null, sorted, explicit subset of requested scopes;
  `[]` is a valid **empty authorization**, never an implied grant.
- Fresh nonzero response JTI, RS256 signature, integer times, positive
  lifetime at most 30 seconds (RBAC emits 15 seconds), at most five seconds
  future clock skew and in-memory one-use response JTI replay protection.
- All signatures, fields and JSON are strict: duplicate, missing, extra,
  null, wrong type, unknown/write scope, role-only/reviewer JWT substitution,
  unsigned reply, transport error and missing keys fail closed.

The matching RBAC private signing key is RBAC-owned. Candidate Auth verifier
environment name: `AUTH_RBAC_MCP_STUDENT_SCOPES_DECISION_PUBLIC_KEY`. It is
**not loaded or wired** by the runtime. The client never accepts the role-only
`ALLOW` from Auth #23 as `allowed_scopes`.

## Not implemented / next stage

This PR contains isolated source and source tests only. There is no NATS
consumer registration, Auth composition-root wiring, runtime key provisioning,
JWT token issuance, OAuth route, DB mutation, migration, external deployment,
live broker round trip or main merge.

The `MCPExternalTokenGrantReadback` composition port remains intentionally
unimplemented. A follow-up must, **after single-use code redemption**, read
Auth-owned persisted account/client/consent again, check the separate signed
current RBAC Student role decision, request this scope decision with a fresh
proof, then intersect requested, client, consent, platform-policy and
RBAC-allowed scopes without ever elevating an empty subset. Resource owners
must still enforce object-level ACL and token/grant revocation at read time.

Source verification alone does not demonstrate a live Auth↔RBAC exchange.
