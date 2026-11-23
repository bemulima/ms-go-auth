# Mentor source composition

Parent: MENT-01A, `bemulima/learning-platform-business#27`.
Status: **pure source constructor**, used by the separate default-off
[runtime wrapper](mentor-runtime.md). It does not introduce a new HTTP/role
protocol or perform runtime activation itself.

`cmd/ms-go-auth.NewMentorComposition` accepts an explicit
`MentorCompositionConfig` and `MentorCompositionDependencies` and returns the
existing `MentorHTTPAuthorityHandler`. Its configuration is not read from the
environment or files. The explicit runtime wrapper validates its own configuration
before mapping it into this pure input.
`Enabled=false` (including the zero value) returns `(nil, nil)` immediately:
no keys or dependencies are inspected and no handler is produced.

When enabled, composition requires an existing Auth `*gorm.DB`, the actual
configured access-token `tokenverify.Parser`, and the existing owner requester.
It rejects missing/typed-nil dependencies, incomplete database handles and
invalid key configuration with only `ErrMentorCompositionUnavailable`.
It then assembles the actual PostgreSQL Mentor session reader, strict live
session verifier, signed owner-confirmation client, HTTP authority/role issuer
and fixed three-operation HTTP handler. The constructor does not accept an
alternative session verifier or unsigned owner-confirmation port.

The explicit key inputs are the matched dedicated Auth role-decision and
owner-lookup key pairs, plus independently pinned RBAC and Mentor reply public
keys. Their four RSA moduli must all differ; alternate PEM encodings or
different exponents do not make shared modulus key reuse acceptable. Actual
owner constructors additionally validate private/public matching and their
existing key requirements. There are no access/signup/reviewer key fallbacks.

The supplied parser is an opaque owner port. This constructor cannot attest
which access/legacy key that parser uses, or prove separation from keys not
supplied to it. Supplying Auth's real configured parser and establishing full
access/refresh/signup/reviewer key separation cannot be claimed from this pure
constructor alone. The executable wrapper now validates visible configured
key separation and uses the actual signer; deployed key custody still requires
runtime acceptance.

Construction performs no SQL query, connection, owner request, subscription,
route mounting or listener startup. It neither owns nor closes supplied DB or
requester lifecycles. Successful construction is not a health check, deployed
permission or evidence that the database is current. The executable `New`/`Run`
wrapper calls this constructor only after explicit opt-in; existing routes,
migration defaults and legacy flows remain unchanged when disabled.

The returned handler still requires actual TLS and the existing fixed paths;
the current plain Echo listener is not a compliant mounting location. A
dedicated default-off HTTPS listener now supplies bounded header/body read and
response write deadlines. Runtime key custody, endpoint trust, requester TLS/broker ACLs,
real session/SQL acceptance, deployment and executable Gherkin remain gates.
The three canonical contracts remain
[HTTP authority](../.ai/contracts/mentor-http-authority-v1.md),
[role decision](../.ai/contracts/mentor-role-decision-v1.md) and
[owner lookups](../.ai/contracts/mentor-owner-lookups-v1.md).

## Focused verification

`mentor-composition-targeted` exercises only this new glue. Tests use the actual
Auth RSA token parser, actual GORM repository over a controlled SQL driver,
actual signed owner client and issuer, and `httptest.NewRecorder`. They do not
open loopback sockets, start HTTP/NATS servers, contact a broker or run SQL on
PostgreSQL. Owner replies and stored sessions are controlled fixtures. An
in-process success cannot be reported as live owner/SQL/Gherkin acceptance.

The narrow checks cover disabled zero-I/O construction, incomplete/typed-nil
dependencies, purpose-key matching/separation, user/Admin/issuance wiring and
preserved unavailable-versus-unauthenticated outcomes. Existing crypto matrices
are not duplicated or rerun as part of this command.
