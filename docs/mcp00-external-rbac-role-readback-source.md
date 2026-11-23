# MCP-00C3D2: dormant Auth → RBAC Student role request/readback

Parent: [MCP Epic #53](https://github.com/bemulima/learning-platform-business/issues/53).
Owner: Auth. Dependency: RBAC [Draft #15](https://github.com/bemulima/ms-go-rbac/pull/15)
(MCP-00C3D1 role producer). Stacked on Auth [Draft #22](https://github.com/bemulima/ms-go-auth/pull/22)
(MCP-00C3C actual PostgreSQL account/client/consent grant readback).

## What exists in this source-only slice

- `internal/usecase/mcp_student_role_proof.go`: creates a fresh, exact-purpose
  Auth RS256 JWT for the canonical Student identifier given by a future trusted
  Auth account/grant readback. Reuses the configured Auth JWT key pair, but
  cannot mint a normal access JWT or accept a reviewer proof instead.
- `internal/infrastructure/messaging/nats/mcp_student_role_client.go`:
  bounded request/reply **only** to `rbac.checkMCPStudentRole`. It sends one
  `proof` field, no raw identity, role, or scope. Absent keys, network errors,
  invalid context, or malformed requests fail closed.
- `internal/infrastructure/messaging/nats/mcp_student_role_decision.go`:
  separate RBAC public-key signature verifier and response-JTI replay guard.
  Pins exact JWT header/claims, Student role, issuer/audience/type/purpose,
  signature, subject, request JTI and exact proof digest, time and TTL.
  A valid signed DENY returns false. Reviewer and MCP decision envelopes
  cannot be substituted for each other.
- The domain exposes a role-only decision port. Nothing composes, configures,
  instantiates, subscribes, or calls it in running Auth. The signed RBAC
  Student decision private key stays exclusively in RBAC.

Wire contract: [Messaging contract](messaging-contract.md) and
`.ai/contracts/messaging.yaml`. The future Auth public key config name
`AUTH_RBAC_MCP_STUDENT_DECISION_PUBLIC_KEY` is informational, *not* loaded.

## Security and scope boundary

Auth's token exchange consumes each authorization code before it attempts a
fresh grant readback. This slice must eventually be invoked there only with
the freshly verified Student UUID. The signer does not independently look up
the Student account; it must never be exposed as an open identity-signing API.

An RBAC Student role decision **does not** imply permissions for any specific
MCP scope. Do not fill `RBACStudentScopes` from an `ALLOW`, copy consent scopes
into it, or treat default Student role as permission to read every Course or
modify every task. The existing deliberately unimplemented composite
`MCPExternalTokenGrantReadback` remains unimplemented. Nothing in this PR
issues OAuth tokens, mounts HTTP routes, changes service config or creates
database mutations.

## Acceptance / non-acceptance

- Targeted source tests: correct Auth signing; fresh JTI; malformed and
  mismatched RSA keys, missing keys, invalid identity, expired/future JWT,
  signed ALLOW/DENY, wrong key/role/purpose/audience/subject/request digest,
  stale/replayed reply, strict JSON and unavailable dependencies.
- Verify `./scripts/check-agent-policy.sh`, `gofmt`, targeted and whole-suite
  Go tests in CI; do not infer local Go tests from shell-only checks.
- No live NATS role consumer, Auth token signing, `RBACStudentScopes` policy,
  production key binding, runtime smoke or merge in this slice.

### Next required decisions

1. Approve an independent, explicit **scope-to-RBAC or owner policy mapping**;
   a role check alone cannot satisfy the exchange policy's four-way scope
   intersection.
2. Implement a composite fresh Auth+RBAC readback after code redemption;
   test role ALLOW/DENY, account/consent/client revocation and scope mismatch.
3. Only then review runtime key provisioning, NATS consumer registration,
   OAuth authorization-server HTTP paths, and resource-server JWT validation.
