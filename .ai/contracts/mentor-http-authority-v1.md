# AUTH_MENTOR_HTTP_AUTHORITY_V1

Auth owns this additive direct HTTPS boundary; Mentor is its consumer. Parent:
bemulima/learning-platform-business#27, MENT-01A. Status: **default-off executable
wiring; runtime not run**. The wire operations below and existing
`/auth/verify`/`auth.verifyJWT` contracts are unchanged. Only explicit validated
`AUTH_MENTOR_ENABLED=true` mounts these operations on a dedicated HTTPS server,
never plaintext Echo. With the default false, no Mentor key/file read, new
connection or route is introduced. This source change does not activate a
runtime, install keys, apply SQL or grant a role. The machine companion is
`mentor-http-authority-v1.json`; runtime gates are in
[Mentor runtime](../../docs/mentor-runtime.md).

## Exact operations

All three operations are `POST` on the configured, trusted Auth HTTPS origin.
Paths are fixed and case-sensitive; alternate, escaped or normalized paths,
queries and fragments are rejected. A different route may return 404 and a
different method 405; neither invokes authority. Plain HTTP is not admitted.

| Path | Exact request body | Exact 200 response |
| --- | --- | --- |
| `/internal/v1/mentor/session/verify` | `{}` | `{"user_id":"<verified canonical UUID>"}` |
| `/internal/v1/mentor/admin-session/verify` | `{}` | `{"user_id":"<verified canonical UUID>"}` |
| `/internal/v1/mentor/role-decisions` | six fields below | `{"proof":"<exact Auth compact JWT>"}` |

The issuance body has exactly `target_user_id`, `application_id`,
`application_revision`, `decision`, `request_id`, and `decision_digest`.
Its field types, canonical UUID/digest formats and APPROVE=2 / SUSPEND=3 or 4
pairs are unchanged from `AUTH_RBAC_MENTOR_ROLE_DECISION_V1`. Revision is an
integer in canonical unsigned decimal form, never a fractional/exponent/string
encoding. No caller actor, role, service, bearer, reason or mutable scope is
accepted in the body.

One `Authorization` header carries `Bearer <current access token>`. The scheme
is case-insensitive, with exactly one separating ASCII space and a nonempty
RFC6750-style token of at most 8192 bytes; padding `=` may appear only at the
end. Duplicate headers, comma-separated credentials, whitespace/control bytes
and non-ASCII token bytes are rejected. Cookies, identity headers, middleware
user context and request/trace headers never supply authority or error text.

One `Content-Type` header is required: `application/json`, optionally with one
plain `charset=utf-8` parameter. Duplicate, extended/continued and empty
parameters are rejected rather than normalized. Bodies are bounded to 16384 bytes and parsed as one
exact JSON object. Unknown, missing, duplicate (including escaped-equivalent),
null, case-aliased, mistyped and trailing fields are invalid. Invalid UTF-8 and
unpaired surrogate escapes are rejected, not repaired. Empty-body and `null`
are not substitutes for `{}`.

Every response sets `Cache-Control: no-store` and contains only the documented
JSON envelope. Error responses are exactly `{"error":"<code>"}`:

| HTTP status | Code | Meaning |
| --- | --- | --- |
| 400 | `invalid_request` | Request framing or body is invalid |
| 401 | `unauthenticated` | Current access/session authority is absent or invalid |
| 403 | `forbidden` | Authenticated current actor lacks the required authority or exact committed intent |
| 503 | `unavailable` | Authority dependency, cancellation or configuration failure |
| 404 | `not_found` | Fixed route does not match |
| 405 | `method_not_allowed` | Fixed operation is not POST |

No proof is returned on any failure. Error diagnostics, credentials, session
IDs, other claims, foreign application data and key material are never echoed
or logged by this boundary. Operations have an overall three-second context
limit preserving an earlier caller deadline; cancellation is checked across
every dependency boundary and before a success response.

This is an operation-context limit, not a hard wall-clock deadline for a stalled
request-body read. Runtime mounting additionally requires bounded listener
header/body read and response-write deadlines; the handler does not configure a
listener or install those deadlines. The default-off executable wrapper now
sets bounded HTTPS header/read/write/idle/shutdown deadlines and uses the actual
Auth composition. Live TLS, key custody and deployment acceptance still remain
separate gates before exposing these routes.

## Current-session authority

The new narrow session verifier combines Auth's actual `tokenverify.Parser`
with a **mandatory** active session reader. It has no parser-only fallback.
It validates the verified canonical nonzero `sub` and `sid`, forbids any `typ`
claim, enforces token expiry, then reads the exact existing Auth-owned session
lookup key. Despite the legacy `RefreshTokenHash` field name, the current owner
encoding is `rt:<canonical sid>`, not SHA-256. This boundary preserves that
representation without changing stored sessions or pretending to migrate it.
The returned session must bind that exact lookup key and user, be unrevoked and unexpired;
the expiry/cancellation checks are repeated after the read. A known absent
session is unauthenticated; unavailable/corrupt/nil persistence is an
unavailable authority, not an ALLOW or fabricated semantic absence.

The PostgreSQL bridge wraps the existing Auth-owned refresh-session reader,
normalizes its known `gorm.ErrRecordNotFound` to the domain's known absence and
sanitizes other errors. Domain/usecase code does not import GORM or access any
foreign database. This bridge uses a private silent GORM session so its lookup
cannot log session keys or raw driver diagnostics; it does not replace the
supplied database's logger. Existing refresh/login/password-reset behavior is
unchanged.

User verification returns the derived subject only. Admin verification also
uses the existing authenticated signed `CanonicalAdminVerifier` and requires
the exact actor's unique current canonical-default Admin assignment. It then
reverifies the **same bearer, actor and sid** before returning. The token's
optional `role` claim, legacy role lookup with scope fallback and a previously
stored Admin ID cannot implement this authority.

## Issuance, consumers and limits

The production-style authority constructor requires the concrete strict live
session verifier and constructs the existing actual Mentor role-decision
issuer with it. Issuance requires both signed current Admin and exact committed
Mentor intent confirmations. The same live session is revalidated after those
owner reads before signing. Typed unavailable session outcomes stay unavailable
rather than being reported as a false credential denial. No session or proof is
retained, delegated or automatically renewed.

Mentor must use the configured trusted Auth HTTPS origin, verify certificate
and hostname, disable redirects/proxy credential forwarding and automatic
retries, and bound response size/deadlines. A TLS-authenticated identity reply
is the direct owner response to that request, not a reusable bearer proof.
The issued role proof must still pass independent pinned-key signature and
complete command-binding verification before forwarding to RBAC. ACK remains
distinct from fresh signed role readback and local Mentor finalization.

These bounded current-owner reads are point-in-time checks, not distributed
revocation locks. SQL isolation, live TLS/key custody, broker ACLs, deployment,
Gateway integration and executable Gherkin remain separate acceptance gates.
Tests may use actual parser/signature/usecase/HTTP code with controlled
persistence/owner fixtures and ephemeral test keys; this is not live runtime
or PostgreSQL acceptance.
