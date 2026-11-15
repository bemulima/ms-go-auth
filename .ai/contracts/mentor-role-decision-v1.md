# AUTH_RBAC_MENTOR_ROLE_DECISION_V1

Owner: Auth (assertion producer). Consumer: RBAC (signature admission and role
mutation owner). Business lifecycle owner: Mentor. Parent: bemulima/learning-platform-business#27.

Status: source-only additive contract. No HTTP route, NATS subscription,
runtime key, database migration or role mutation is activated by this cut.
Existing signup, reviewer, OAuth/MCP, JWT role claim and default Student flows
are unchanged. This document is canonical for the assertion; RBAC owns its
separate atomic application/receipt/fence contract.

## Authority before issuance

Auth must (1) verify the actual current session, (2) confirm a unique canonical-
default Admin assignment with an authenticated exact RBAC check, and (3) obtain
authenticated Mentor-owner confirmation of the exact **committed** decision.
The caller's actor/role headers, a legacy role lookup with scope fallback, a
Student-only default-role RPC, and a stored AdminID are not authority.

Mentor confirmation binds the derived Admin, target user, application, request,
decision digest and committed decision revision. APPROVE must correspond to
the current `APPROVAL_PENDING_GRANT` intent; SUSPEND to the current `SUSPENDED`
intent. Unknown,
foreign, stale, unavailable or mismatched confirmations produce no assertion.
The source issuer uses explicit mandatory owner ports. Dedicated signed
request/reply source adapters are specified by
[AUTH_MENTOR_OWNER_LOOKUPS_V1](mentor-owner-lookups-v1.md). They remain unmounted;
trusted key distribution, broker ACLs and runtime composition must be verified
before this issuer is wired into a production route.

No bearer or refresh token is persisted. The caller supplies a fresh live Admin
session when a new assertion is needed. Expired assertion/session does not grant
automatic renewal from a previous AdminID. Durable delegation is not introduced.

## Exact signed wire format

Compact RS256 JWT, RSA at least 2048 bits, separate Mentor matched key pair.
The header is exactly {"alg":"RS256","typ":"JWT"}. JWT parts use canonical
unpadded base64url. Total token size is at most 8192 bytes. No key URL, `kid`,
embedded key, alternative algorithm, unsigned or shared-secret fallback.

Claims are exactly these 16 required, non-null, case-sensitive fields:

| Claim | Required value or meaning |
| --- | --- |
| `iss` | `ms-go-auth` |
| `aud` | `ms-go-rbac-mentor-role` |
| `sub` | Admin actor derived from the verified live session |
| `typ` | `mentor_role_decision` |
| `purpose` | `AUTH_RBAC_MENTOR_ROLE_DECISION_V1` |
| `target_user_id` | Canonical target account; existing Student role stays unchanged |
| `application_id` | Mentor-owned application UUID |
| `application_revision` | Integer committed decision revision: APPROVE=2, SUSPEND=3 or4 in Mentor v1 |
| `decision` | Exactly `APPROVE` or `SUSPEND` |
| `request_id` | Immutable command UUID, not a new UUID on retry |
| `decision_digest` | Lowercase SHA-256 of the exact decision binding below |
| `role` | Fixed `mentor` |
| `service` | Fixed `ms-go-mentor`; never global/default scope |
| `jti` | Fresh canonical non-zero UUID for this assertion |
| `iat` | Positive integer Unix seconds |
| `exp` | Integer Unix seconds, strictly after iat and verification time |

All UUIDs are lowercase canonical hyphenated non-zero strings. Digest input is
UTF-8 `decision|admin_actor_id|application_id|request_id|expected_revision`, where
`expected_revision = application_revision - 1`, exactly matching Mentor's
existing DecisionIntent. Target identity is independently signed and must match
the Mentor owner confirmation and immutable RBAC application-target binding.
An APPROVED local finalization revision (3) is not the APPROVE fence revision (2).

Producer lifetime is 30 seconds. Consumer admits at most 30 seconds and at most
five seconds of future iat skew; exp equal to now is expired. Both timestamps
must be at most 9007199254740991 (2^53-1); use overflow-safe checks. Missing,
repeated (including escaped-equivalent), unknown, mistyped,
null, fractional/exponent-form integer or trailing fields fail closed. Signature,
exact purpose and bindings must pass before any role/receipt/store access.

## Replay and currentness

The assertion JTI is not the durable operation identity. A retry may obtain a
fresh assertion for the same immutable command. Replaying a still-valid assertion
can only replay that same idempotent operation; it cannot create another grant.
Every invocation authenticates the proof and canonical Admin again. RBAC stores
immutable command receipts and a monotonic per-application/target revision fence
in its future atomic adapter. A SUSPEND tombstone must prevent an older delayed
APPROVE even if no active grant existed when revocation arrived.

That adapter must enforce both immutable application-to-target binding and
target-plus-scope-to-application binding; substituting a new application ID must
not evade a revocation fence. The canonical Admin authorization decision and
fence/role/receipt commit require one atomic authority boundary, or an equivalent
recheck inside that transaction. A prior Admin lookup alone is not sufficient.

An old successful receipt is historical, not proof of a currently active role.
Mentor finalization additionally requires a fresh, authenticated scoped readback
with a new lookup nonce, exact proof-byte digest and current fence/state. The
signed readback transport is a following owner slice; this assertion alone does
not authorize Mentor private access or complete MENT-01A.

## Verification boundary

Tests must use real RSA signing/verification and exact producer/consumer byte
compatibility, plus denial cases for expired/wrong-purpose/tampered claims,
missing owner confirmation, non-Admin/session failure, key mismatch and revoke
before delayed grant. Test-only owner ports/state do not prove live sessions,
broker authentication, SQL atomicity, persistence or a mounted runtime feature.
