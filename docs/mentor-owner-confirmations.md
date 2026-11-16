# Authenticated Mentor owner confirmations (source only)

The canonical Auth request/client contract is
[AUTH_MENTOR_OWNER_LOOKUPS_V1](../.ai/contracts/mentor-owner-lookups-v1.md), with
its [machine-readable companion](../.ai/contracts/mentor-owner-lookups-v1.json).
RBAC and Mentor own their respective signed response contracts and repositories.

`NewMentorOwnerConfirmationClient` is an additive outbound NATS adapter for the
existing `domain.CanonicalAdminVerifier` and
`domain.MentorCommittedIntentVerifier` ports. It is **not mounted** in Auth's
composition root or any HTTP/NATS subscription. Construction does not connect to
a broker, install keys, change a role or alter an application.

## Trust and keys

The constructor requires a `RequestWithContext` requester, a matched dedicated
Auth **lookup** RSA key pair, and independently pinned RBAC and Mentor reply
public keys. All RSA keys must be at least 2048 bits. Empty, malformed, weak or
mismatched configuration and nil/typed-nil requesters fail closed. The constructor
also rejects using the lookup key for replies or sharing the reply key between
the two owners. Access/refresh, reviewer, signup and final Mentor role-decision
keys are not read or used as fallbacks; deployment must separately ensure lookup
key separation from those credentials.

These proofs identify Auth as the service making an owner lookup. They do not
authenticate a user by themselves. The existing Mentor role-decision issuer must
still verify the live Admin session before invoking these ports. Only the derived
actor or exact Mentor command binding crosses this adapter: no access/refresh
token, caller-supplied role, mutable scope or bearer credential is forwarded.

## Fixed operations

| Port | Fixed Core NATS subject | Signed request / reply claims |
| --- | --- | --- |
| `ConfirmCanonicalAdmin` | `rbac.checkMentorCanonicalAdmin.v1` | 9 / 12 |
| `ConfirmCommittedMentorIntent` | `mentor.confirmCommittedRoleIntent.v1` | 15 / 19 |

Requests contain exactly a `proof` field holding an RS256 compact JWT. Each call
generates a fresh random JTI, sets a 30-second lifetime and signs the exact actor,
fixed subject/purpose and, for Mentor, the existing full decision binding. Local
validation rejects noncanonical IDs, unsupported decision/revision pairs and a
digest not matching the bound actor before any network request.

Replies must contain exactly `decision_jwt`. The adapter verifies the appropriate
pinned owner key, exact issuer/audience/type/purpose/subject, the original actor,
fresh canonical response JTI, request JTI and SHA-256 digest of the **original
compact request-proof bytes**. Mentor replies must echo every original command
field. A response for an earlier request cannot authorize a later lookup.

Exact JSON validation rejects missing, unknown, duplicate (including escaped
equivalents), case-aliased, null, mistyped and trailing fields. Headers permit only
`alg=RS256` and `typ=JWT`. JWT parts must be canonical unpadded base64url; no key URL,
embedded key or alternate algorithm is accepted. Limits are 8192 bytes per token
and 16384 bytes per envelope. Integer claims reject fraction/exponent encodings;
time checks use positive bounded integer seconds and safe subtraction.

Reply lifetime is at most 15 seconds and its expiry cannot exceed the original
request expiry. Both the original request and reply must still be valid after
network/signature processing. At most five seconds of future issued-at skew is
permitted; expiry equal to now is expired. Every call has a three-second deadline,
preserves a shorter parent deadline and checks cancellation after the network
reply and before returning authority. There is no automatic retry or ALLOW cache.

## Outcomes and limitations

A valid bound Admin `ALLOW` yields `UniqueCanonicalDefaultAdmin=true` for the
exact actor. A signed `DENY` yields a typed false confirmation with no error.
Mentor `ALLOW` requires the exact `APPROVAL_PENDING_GRANT` or `SUSPENDED` state for
the requested decision and yields committed/current confirmation. A signed
Mentor `DENY` requires `UNCONFIRMED`, returns committed/current false and exposes
no actual foreign application state.

Unsigned, invalid, mismatched or expired replies, cancellation and dependency
failures return only `ErrMentorOwnerConfirmationUnavailable`, never a fabricated
semantic DENY or dependency diagnostics. Raw proofs, tokens and keys are neither
logged nor persisted. Nonmutating nonce-correlated lookups need no durable replay
table in this adapter.

The owner reads are point-in-time confirmations, not a distributed transaction.
Final RBAC mutation still needs transaction-level current Admin authorization,
durable immutable receipts/revision fences and fresh authenticated scoped readback
before Mentor activation. Broker ACLs, key custody, runtime wiring, SQL integration
and executable Gherkin acceptance remain separately gated.

## Verification

`TestMentorOwnerClient*` is a genuine test-first suite: behavior failed against
fail-closed stubs before the client implementation was added. Tests generate
ephemeral keys in memory and use actual RSA signing/verification for exact request
claims, ALLOW/DENY, nonce correlation, owner/key/purpose swaps, all intent binding
fields, malformed JSON/encoding, lifetime boundaries, deadlines/cancellation and
configuration failures. Controlled requester fixtures are not a live NATS broker.

Cross-owner compatibility uses
`node scripts/test-mentor-owner-conformance.cjs --rbac /absolute/path/to/ms-go-rbac --mentor /absolute/path/to/ms-go-mentor`.
The bridge executes the real client and owner handlers with controlled transport
and repository fixtures, without printing/persisting raw proofs or private keys.
Source tests do not start services, migrate SQL, publish subscriptions, install
keys, activate roles or establish complete MENT-01A acceptance.
