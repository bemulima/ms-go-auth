# Mentor role decision assertion (source only)

The canonical Auth-owned wire contract is
[AUTH_RBAC_MENTOR_ROLE_DECISION_V1](../.ai/contracts/mentor-role-decision-v1.md),
with its [machine-readable companion](../.ai/contracts/mentor-role-decision-v1.json).
This additive issuer is **not mounted** in HTTP, NATS, the Auth composition root,
or a background recovery worker. It neither assigns a role nor activates Mentor
private access. Existing signup, OAuth/MCP, reviewer and JWT role-claim paths are
unchanged.

## Issuance boundary

`NewMentorRoleDecisionIssuer` requires dedicated matched RSA private/public key
material (at least 2048 bits), the existing narrow `VerifyToken` session port,
and two explicit owner-authority ports. Missing, malformed, weak or mismatched
keys, absent ports and typed-nil ports return an unavailable issuer. It does not
read general access-token keys or choose a shared-secret fallback.

`Issue` accepts the live access token and an immutable Mentor command, but no
caller-selected actor, role or service. Every invocation independently:

1. Validates canonical command identifiers, the decision/revision pair and digest.
2. Calls the actual Auth-owned current-session verifier and derives the actor
   from its result. A canonical persisted `sid` is required; legacy stateless
   tokens and refresh/other-proof `typ` claims are rejected. A token's `role`
   claim does not authorize this operation.
3. Recomputes the Mentor decision digest using that derived actor and
   `application_revision - 1`.
4. Requires an authenticated exact RBAC-owner confirmation of a **unique current
   canonical-default Admin** assignment for that same actor. The existing
   scope-fallback role RPC and Student-only default-role checks cannot implement
   this authority.
5. Requires authenticated Mentor-owner confirmation that the entire binding is
   exact, current and committed. `APPROVE` revision 2 requires state
   `APPROVAL_PENDING_GRANT`; `SUSPEND` revision 3 or 4 requires `SUSPENDED`.
6. Signs the contract's exact 16 claims with a fresh JTI and a 30-second lifetime.
   Timestamps are positive integer seconds; addition is checked before execution
   and both timestamps stay within the contract's safe-integer bound. Cancellation
   is checked between owner calls and before returning a signed assertion.

The source ports describe trust obligations; they do not manufacture trust.
Neither authenticated canonical-Admin nor committed-Mentor-intent transport is
implemented in this slice. A boolean from an unsigned response, a cached actor ID,
or an arbitrary implementation of the interfaces must never be wired as authority.
Real adapters must authenticate each owner and bind fresh responses to the exact
lookup. Key distribution and runtime wiring remain separate owner work.

## Retry and failure behavior

No access/refresh token, previous confirmation or signed assertion is persisted
or logged by this issuer. A same-command retry preserves its request ID, revision
and digest but must supply a fresh valid session and recheck both owners; it gets
a new assertion JTI. A historical AdminID or earlier successful assertion cannot
renew authority. Semantic denials, dependency outages, missing confirmations and
cancellation return no assertion; dependency error details are not copied into
public errors.

RBAC owns strict proof consumption, command receipts, immutable bindings and the
monotonic revision fence. A later signed fresh scoped readback remains necessary
before Mentor finalization; this producer alone does not complete MENT-01A.

## Verification

The test-first suite is `TestMentorRoleDecision*` in `internal/usecase`. It uses
ephemeral RSA keys generated only in memory and validates actual signatures,
exact claims, canonical encoding, revision/actor digest binding, fresh retry JTIs,
owner denials/mismatches/outages, missing/weak/mismatched configuration and
cancellation. An integration-shaped source test executes the existing Auth
access-token signer and `authService.VerifyToken`, replacing only the persistence
port with a test fixture; revoked and foreign sessions cannot issue assertions.
The constructor/issuer began as fail-closed stubs, and the same behavior tests
failed before the implementation was added.

The paired producer/consumer conformance command is
`node scripts/test-mentor-role-conformance.cjs --rbac /absolute/path/to/ms-go-rbac`.
Its source-only bridge executes the real Auth issuer and real RBAC consumer with
ephemeral test keys and test-only owner ports. It must not print or persist raw
assertions/private keys. It is not a substitute for mounted authenticated owner
transports, live-session/SQL integration, durable atomic role storage, broker
authentication, signed readback, or executable Gherkin acceptance.

No service startup, database migration, role grant, key installation or deployment
is performed by these source tests.
