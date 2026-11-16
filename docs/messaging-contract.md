# Messaging contract

auth.verifyJWT is a queue-group Core NATS request/reply endpoint. Request is {"token":"..."}. Response contains ok, optional user_id and email, optional claims, and an error code. Role and expiry remain inside claims; there are no dedicated role or expires_at response fields.

The service calls user.create-user, rbac.assign-role, rbac.checkRole, and
rbac.checkPermission. These are RPC subjects, not durable events. The reviewer
permission lookup sends exactly `{ "proof": "<JWT>" }`; raw user IDs and
permission values are not accepted from the NATS payload. Auth signs the proof
with its existing matched RSA JWT key pair after its protected HTTP middleware
validates the user subject. RBAC verifies the proof using the existing
`AUTH_JWT_PUBLIC_KEY`, derives `sub`, and checks only the fixed
`knowledge_graph.review` permission. The proof uses RS256, issuer from
`AUTH_JWT_ISSUER`, audience `ms-go-rbac-knowledge-review`, type
`knowledge_graph_permission_check`, purpose
`AUTH_RBAC_KNOWLEDGE_GRAPH_REVIEW_PERMISSION_V1`, canonical UUID `jti`, and
integer `iat`/`exp` with a maximum 30-second lifetime and at most five seconds
of future `iat` skew. The JWT header is exactly `alg=RS256`, `typ=JWT`, and
the claims are limited to `iss`, `aud`, `sub`, `typ`, `purpose`, `permission`,
`jti`, `iat`, and `exp`. Missing, invalid, or mismatched RSA key configuration
disables issuance; no unsigned fallback is permitted. Payload changes require
producer/consumer tests in both owning repositories.

RBAC replies to a valid reviewer proof with exactly
{"decision_jwt":"<RS256 JWT>"}. The decision JWT uses issuer ms-go-rbac,
audience ms-go-auth-knowledge-review-permission-decision, type
knowledge_graph_permission_decision, purpose
RBAC_AUTH_KNOWLEDGE_GRAPH_REVIEW_DECISION_V1, and the fixed permission
knowledge_graph.review. Its exact claims are iss, aud, sub, typ, purpose,
permission, decision, jti, request_jti, request_digest, iat, and exp.
decision is exactly ALLOW or DENY; jti is a fresh canonical non-zero UUID;
request_jti is copied from the verified Auth proof; request_digest is the
lowercase SHA-256 digest of the exact proof bytes. RBAC signs the reply with
RBAC_REVIEWER_PERMISSION_DECISION_PRIVATE_KEY and Auth verifies with
AUTH_RBAC_PERMISSION_DECISION_PUBLIC_KEY. The signed decision lifetime is 15
seconds (hard maximum 30). Auth rejects unsigned {"ok":true} replies, bad
signatures/claims, a mismatched subject or request binding, expiry, and a
reused response JTI. Each new Auth lookup uses a fresh proof JTI, so a prior
signed reply cannot authorize a later request. Missing decision key
configuration leaves this reviewer issuance path fail-closed; other Auth and
RBAC RPC behavior is unchanged.

## MCP Student role decision request/readback — DORMANT (MCP-00C3D2)

Auth has an isolated, source-only client for the *future* Core NATS RPC
`rbac.checkMCPStudentRole`; it is not instantiated in bootstrap, and this
subject is not among Auth's active producers. Its only request envelope is
`{"proof":"<RS256 JWT>"}` (maximum 9 KiB). Auth must first confirm the
canonical Student subject from its own trusted account/grant storage. The
source-only signer never accepts a caller-provided OAuth scope or role, and
its fixed `role=student` claim merely requests a check; it does **not** grant
that role. Signer configuration reuses Auth's matched RSA JWT private/public
keys and `AUTH_JWT_ISSUER` (default `auth-service`). Missing keys disable the
signer, while malformed, weak, partial or mismatched configured keys fail
closed. Neither HTTP routing nor token signing is enabled here.

The Auth proof header is exactly `alg=RS256,typ=JWT`, with the exact claims
`iss,aud,sub,typ,purpose,role,jti,iat,exp`. The audience is
`ms-go-rbac-mcp-student-role`, type `mcp_student_role_check`, purpose
`AUTH_RBAC_MCP_STUDENT_ROLE_V1`; `sub` and fresh `jti` are canonical lowercase
nonzero UUIDs. The signed proof lives 30 seconds (RBAC permits up to five
seconds future clock skew). The reviewer permission audience/purpose and
ordinary access tokens are incompatible. RBAC must derive identity only from
this verified proof, then check the **current unique default Student role**,
never a caller header or legacy `rbac.checkRole` result. See the RBAC source
contract in [RBAC Draft #15](https://github.com/bemulima/ms-go-rbac/pull/15).

The only accepted reply shape is `{"decision_jwt":"<RS256 JWT>"}`. The
independently signed RBAC decision has the exact header `alg=RS256,typ=JWT` and
claims `iss,aud,sub,typ,purpose,role,decision,jti,request_jti,request_digest,iat,exp`.
It pins `iss=ms-go-rbac`, `aud=ms-go-auth-mcp-student-role-decision`,
`typ=mcp_student_role_decision`, `purpose=RBAC_AUTH_MCP_STUDENT_ROLE_DECISION_V1`,
`role=student`, `decision=ALLOW|DENY`. Its `request_jti` must match the Auth
request JTI and `request_digest` the lowercase SHA-256 of the *exact raw Auth
proof*. The response has its own fresh nonzero canonical UUID JTI, signed
15-second TTL (maximum 30 seconds), at most five seconds future clock skew,
and must not be replayed. Any unsigned boolean, invalid shape/key/signature,
extra/duplicated claim, mismatched subject/request/role, expiry or outage
fails closed. A valid signed DENY is a negative result, never authorization.

Only RBAC holds the dedicated future private decision key; the Auth verifier
will use only the matching public key supplied by
`AUTH_RBAC_MCP_STUDENT_DECISION_PUBLIC_KEY` (candidate configuration name;
**not yet** bound to a runtime environment variable). This key is separate
from the reviewer decision key. No new JWT credentials are shipped in source.

**Role is not scope.** This readback cannot fill
`MCPExternalTokenGrantStatus.RBACStudentScopes`, establish `courses:read` or
`tasks:write`, or activate Auth's dormant token exchange. A separately reviewed
RBAC/owner scope mapping, fresh Auth account/client/consent readback, binding
tests, and runtime composition are still required.

Signup completion treats User creation and RBAC assignment as required
synchronous acknowledgements. The frozen success, failure, and retry semantics
are defined in `.ai/contracts/auth-user-rbac-provisioning-v1.md`.

Signup role mutation uses a dedicated Auth-owned Ed25519 proof on the existing
assignment subject. The signed envelope binds the persisted signup operation,
canonical principal, exact `student` role and existing default scope; no outer
caller/header fields establish identity. See the authenticated transport addendum
in `.ai/contracts/auth-user-rbac-provisioning-v1.md`. Configure
`AUTH_RBAC_SIGNUP_PRIVATE_KEY` without a source/default secret; absent keys fail
closed for signup, and invalid nonempty keys fail composition. User access or
refresh tokens cannot replace this proof. Generic unsigned role assignment
remains a compatibility method without signup authority; OAuth and disposable
fixture policy require a human decision.

In the production composition, `auth.verifyJWT` also checks the persisted session
referenced by the access token's `sid`. Password recovery revokes those sessions
transactionally, so an otherwise valid access JWT is rejected before its TTL.
The existing request/response fields remain unchanged.
