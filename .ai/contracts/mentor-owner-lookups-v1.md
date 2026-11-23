# AUTH_MENTOR_OWNER_LOOKUPS_V1

Status: default-off Auth requester wiring; runtime not run. Parent: bemulima/learning-platform-business#27,
MENT-01A. Auth owns the requests and its response acceptance below. RBAC and
Mentor own their respective signed response contracts and repository lookups.
No existing subject, proof purpose, key configuration or role mutation changes.

## Two fixed operations

| Field | Canonical Admin lookup | Committed intent lookup |
| --- | --- | --- |
| Actual Core NATS subject | `rbac.checkMentorCanonicalAdmin.v1` | `mentor.confirmCommittedRoleIntent.v1` |
| Request issuer | `ms-go-auth` | `ms-go-auth` |
| Request audience | `ms-go-rbac-mentor-canonical-admin` | `ms-go-mentor-committed-role-intent` |
| Request type | `mentor_canonical_admin_check` | `mentor_committed_role_intent_check` |
| Request purpose | `AUTH_RBAC_MENTOR_CANONICAL_ADMIN_LOOKUP_V1` | `AUTH_MENTOR_COMMITTED_ROLE_INTENT_V1` |

Requests are exactly `{"proof":"<compact JWT>"}`. The JWT header is exactly
`{"alg":"RS256","typ":"JWT"}`. Auth uses one dedicated **lookup** RSA key
pair (at least 2048 bits), distinct from access/refresh, reviewer, signup and
the final Mentor role-decision key. It authenticates Auth as the service caller,
not a user. The existing role-decision issuer still verifies the live Admin
session before using these ports. No bearer or refresh token is sent to owners.

The Admin request has exactly nine required non-null claims:
`iss, aud, sub, typ, purpose, subject, jti, iat, exp`.
`sub` is the Admin actor derived by the existing issuer, and `subject` is exactly
the concrete subject above. The operation has no caller-selected role or scope:
the owner checks only the unique canonical-default Admin assignment.

The Mentor request has exactly fifteen required non-null claims: the same nine,
plus `target_user_id, application_id, application_revision, decision, request_id,
decision_digest`. Those six fields are the existing Mentor command binding.
APPROVE revision 2 and SUSPEND revision 3 or 4 are the only pairs. The lowercase
SHA-256 digest is over UTF-8
`decision|sub|application_id|request_id|application_revision-1`, unchanged from
the committed Mentor DecisionIntent. The target is separately signed and
checked against the owner aggregate; it is not added to that digest format.

All actor/application/target/request/JTI UUIDs are lowercase canonical nonzero.
JWT segments use canonical unpadded base64url; token limit is 8192 bytes and
envelope limit is 16384 bytes. Exact JSON rejects unknown, duplicate (including
escaped-equivalent), missing, null, case-alias, mistyped and trailing fields.
Integer claims reject fractional and exponent forms. Times must be positive
integer Unix seconds no greater than 9007199254740991. Requests live for 30
seconds; verification permits no more than 30 seconds and 5 seconds of future
iat skew, using overflow-safe arithmetic. Expiry equal to now is invalid.

## Provider obligations

An unmounted `Handle(ctx, actualSubject, body)` checks the exact subject and
proof before any repository call. The same proof must still be valid after the
lookup and before signing. RBAC uses the actual narrow `GetDefaultRole` port,
never a lookup that can fall back to another scope. Mentor uses its actual
`ByID` application reader, validates the complete aggregate, and compares the
entire current committed binding including state and revision.

Only known missing/nonmatching state yields a signed DENY. Corrupt/ambiguous
state, cancellation, unavailable storage or signing configuration yield no
signed confirmation and a generic unavailable failure, never a false DENY.
No exception details, screening fields, foreign application state, tokens or
keys appear in responses/logs. No lookup writes or changes any role/application.

These are point-in-time owner reads, not a cross-service transaction. The later
RBAC mutation still requires transaction-level current Admin authorization,
revision fencing and fresh signed scoped readback before Mentor activation.

## Auth response acceptance

A successful/semantic-denial envelope is exactly
`{"decision_jwt":"<owner-signed JWT>"}`. Every owner has its own dedicated
RSA reply key, and Auth pins each corresponding public key independently.

| Field | RBAC reply | Mentor reply |
| --- | --- | --- |
| Issuer | `ms-go-rbac` | `ms-go-mentor` |
| Audience | `ms-go-auth-mentor-canonical-admin-decision` | `ms-go-auth-mentor-committed-role-intent-decision` |
| Type | `mentor_canonical_admin_decision` | `mentor_committed_role_intent_decision` |
| Purpose | `RBAC_AUTH_MENTOR_CANONICAL_ADMIN_DECISION_V1` | `MENTOR_AUTH_COMMITTED_ROLE_INTENT_DECISION_V1` |
| Owned response schema | `ms-go-rbac/.ai/contracts/mentor-canonical-admin-decision-v1.json` | `ms-go-mentor/.ai/contracts/mentor-committed-intent-decision-v1.json` |

Both responses must echo the exact requested `sub` and `subject`, have a fresh
canonical response `jti`, and bind `request_jti` plus lowercase SHA-256
`request_digest` of the **original exact compact request-proof bytes**. Reply
TTL is at most 15 seconds; expiry is capped at the original request expiry.
The client checks the original request is still valid too. Time bounds/skew,
strict JSON/header/encoding and token/envelope limits match the requests.

The Admin reply's twelve claims are the common nine plus `decision` (exactly
ALLOW or DENY), `request_jti` and `request_digest`. Only a valid bound ALLOW
becomes `UniqueCanonicalDefaultAdmin=true` for the exact actor.

The Mentor reply's nineteen claims are its original fifteen binding fields
plus `result` (ALLOW or DENY), `state`, `request_jti` and `request_digest`.
ALLOW requires exact `APPROVAL_PENDING_GRANT` or `SUSPENDED` state matching the
requested decision; DENY requires `UNCONFIRMED` and exposes no actual state.
Only a valid fully bound ALLOW becomes a committed/current confirmation.

## Retry, deadlines and deployment boundary

Each network attempt generates a fresh random JTI nonce; no response/ALLOW
cache, request-proof reuse or automatic retry is introduced. A response for a
prior lookup cannot authorize the next one. A durable replay table is not
required for these nonmutating nonce-correlated lookups. Auth bounds each
request/reply call to three seconds, preserving shorter caller deadlines and
checking cancellation before returning. Missing/unsigned/malformed replies,
wrong keys, purpose/scope swaps and owner errors all return unavailable.

These outbound adapters do not register provider subscriptions. Auth's explicit
Mentor opt-in now composes them with a separate authenticated, verified-TLS NATS
requester: one configured endpoint, frozen credential snapshot, broker
`AuthRequired`, verified TLS chain and no reconnect/fallback. The global legacy
requester is not reused. See [runtime gates](../../docs/mentor-runtime.md).
Actual key custody/distribution, broker ACLs and owner provider deployment still
require runtime acceptance. Tests may exercise real signing, handlers, clients and owner usecases
with controlled repository/transport fixtures. They must not be labelled live
owner, SQL, Gherkin or complete MENT-01A acceptance.
