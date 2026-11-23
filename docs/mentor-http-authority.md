# Mentor HTTP authority (default off)

The canonical wire contract is
[AUTH_MENTOR_HTTP_AUTHORITY_V1](../.ai/contracts/mentor-http-authority-v1.md), with
its [machine companion](../.ai/contracts/mentor-http-authority-v1.json). This
additive handler is **disabled by default**. Its wire behavior, JWT parser,
broker subjects and login/refresh behavior are unchanged. An explicit
[runtime opt-in](mentor-runtime.md) now composes this handler on a dedicated
HTTPS listener; it is never installed in plaintext Echo. Source construction
alone does not assign roles or activate Mentor private access.

## Concrete source construction

The intended composition uses these actual constructors in order:

1. `postgres.NewMentorSessionReader(db)` wraps the existing Auth-owned refresh
   session reader. It normalizes only a known record absence; nil, corrupt or
   unavailable results are sanitized unavailable authority. Its private GORM
   session disables SQL logging to keep session keys/driver diagnostics out of
   logs; it leaves the original database logger and legacy callers unchanged.
2. `usecase.NewMentorLiveSessionVerifier(parser, reader)` requires the real Auth
   `tokenverify.Parser` and a non-nil mandatory session reader. It accepts only
   verified canonical `sub`/`sid` access tokens without a `typ` claim and checks
   token time, exact active persisted binding and cancellation before/after reads.
3. `usecase.NewMentorHTTPAuthority(privatePEM, publicPEM, sessions, admins, intents)`
   requires that concrete verifier, dedicated matched Mentor proof keys and both
   existing authenticated owner ports. It creates the actual role-decision issuer
   with the same verifier. `VerifyAdmin` also rechecks the same live session after
   the signed canonical Admin confirmation.
4. `internalhttp.NewMentorHTTPAuthorityHandler(authority)` returns the standalone
   `http.Handler`; it rejects missing or zero-valued authority. It performs exact
   bounded request admission and emits only the canonical sanitized envelopes.

The infrastructure package name is `repo`; `postgres` above identifies its path
`internal/infrastructure/persistence/postgres`. The transport package name is
`internalhttp` at `internal/transport/http/private`.

Current Auth uses the legacy lookup encoding `rt:<canonical sid>` in the field
named `RefreshTokenHash`. The new boundary reuses that exact representation; it
does not introduce hashing or a silent migration. Existing session repository
queries and storage behavior are unchanged. Its active-row lookup cannot by
itself prove SQL cardinality or transaction isolation.

## Failure and authority boundaries

The user operation derives only the authenticated user ID. Admin verification
requires an authenticated unique canonical-default Admin assignment, not a role
claim or caller identity header. Role issuance additionally requires the exact
committed Mentor intent and revalidates the same bearer, actor and sid after
both owner confirmations before signing. No bearer, session result, Admin ID or
proof is cached, persisted, delegated or renewed by this boundary.

The strict session verifier preserves unauthenticated versus unavailable errors.
Known absence, expiry and revocation are unauthenticated; unknown/mixed store
errors, nil/corrupt results, cancellation and missing configuration are unavailable.
Unknown legacy issuer session-port errors retain their earlier denial semantics;
the production-style constructor cannot substitute that older boundary for the
concrete strict verifier. Error details and credentials are not logged or echoed.

These are fresh point-in-time owner checks, not a distributed revocation lock.
RBAC proof verification, atomic role/receipt/fence application and fresh signed
readback remain independent requirements before Mentor finalization.

## Verification and mounting gates

The command catalog includes `mentor-http-authority-targeted`,
`mentor-http-authority-race`, and `mentor-source-tests-without-sql`. Source tests
exercise the actual RSA access-token parser, strict session usecase, authenticated
authority composition, actual role-proof issuer and HTTP provider with controlled
owner/session fixtures. The PostgreSQL bridge tests execute the existing GORM
repository through a controlled `database/sql` driver; they are **not** real
PostgreSQL acceptance. An ephemeral `httptest` TLS server checks the source
provider, and the existing private router is checked to remain unmounted.

The cross-owner source conformance runner lives with the Mentor consumer:
`node scripts/test-owner-transport-conformance.cjs --auth /absolute/path/to/ms-go-auth --rbac /absolute/path/to/ms-go-rbac`.
Run it from that consumer repository. It composes the actual HTTPS provider and
consumer, role-proof issuance/verification, RBAC mutation/readback and Mentor
coordinator through test-only bridges, including
`test/mentortransportconformance/main.go`. Persistence and authority ports remain
controlled fixtures, so successful conformance does not prove SQL or mounted
runtime acceptance. No raw bearer, proof or private key should be output.

The three-second bound is an operation-context deadline, preserving an earlier
caller deadline. It cannot interrupt a stalled `io.Reader` by itself. Before
mounting, the real listener must enforce bounded header/body read and response
write deadlines as well as TLS identity and origin trust. The default-off
[executable wrapper](mentor-runtime.md) configures those deadlines and the
actual composition. Live listener acceptance, actual session/SQL integration, key custody, owner
transport authentication/ACLs, deployment and executable Gherkin remain separate
acceptance gates. No production service startup or migration is part of this cut.
