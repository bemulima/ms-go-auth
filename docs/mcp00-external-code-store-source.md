# MCP-00C2 — external Student authorization-code persistence (DRAFT, NOT ACTIVE)

Parent: [MCP Epic #53](https://github.com/bemulima/learning-platform-business/issues/53). Dependent on MCP-00A Auth design and MCP-00C1 external PKCE/consent policy. This is **source-only**; no external OAuth endpoints, clients, tokens or permissions are activated.

## Auth ownership

- `internal/domain/mcp_external_code.go` owns a distinct external code and repository port, separate from provider-login `auth_oauth_transaction` and website/IDE `auth_refresh_token`.
- `internal/usecase/mcp_external_code.go` creates 32-byte CSPRNG codes, persists **only SHA-256 hashes**, caps TTL at five minutes and the persisted consent expiry, and returns the raw code only once to its future trusted caller. It invokes the MCP-00C1 exact-client/resource/redirect/scopes/S256 consent policy first.
- Redemption requires the exact registered client, redirect, resource, strong code shape and PKCE verifier. A wrong but well-formed verifier burns the code. Returned data is an **internal consumed-code receipt**, **not** an access token or a Student actor proof.
- `internal/infrastructure/persistence/postgres/mcp_external_code_repository.go` provides `INSERT … SELECT` against **persisted, active** client+consent and `UPDATE … RETURNING` with `consumed_at IS NULL`, expiry/revocation/scope/client predicates. The grant store and client registry must not be populated from untrusted MCP payloads.
- `migrations/0006_mcp_external_codes.{up,down}.sql` only defines three empty Auth-owned tables: approved client registry, Student consent, one-use codes. Foreign keys bind code to exact Student/client/resource consent; deletion of an Auth user cascades through their consent and codes, while client deletion requires explicit cleanup. No automatic client, scope, or consent is seeded. DOWN refuses retained rows of any kind, including expired or revoked evidence.
- Database methods disable GORM SQL logging for authorization inputs and hashed codes. Use-case returns one generic denial; production HTTP must also avoid logging query strings, code or verifier.

## Missing mandatory production gates

1. An Auth-authenticated Student session at `/authorize`, anti-CSRF, signed current RBAC Student role decision, immutable current consent, explicit per-client review and exact redirect registration. `verifiedStudentID` and `consent.ID` may never originate from a client-supplied user field or prompt.
2. RFC 8414 authorization-server discovery, authorization/consent UI, an Auth-owned code/token/refresh/revoke surface, one-time refresh rotation and replay-family invalidation, strong token audience/type/scope and `sid`/consent revocation checks. None is implemented here.
3. After code consumption, the token issuer must **recheck** current Student/RBAC/consent and sign only approved resource-bound access. A concurrent consent revocation may occur after code consumption; authorization at redemption alone is insufficient to establish token validity.
4. The MCP resource server must verify signature, issuer, type, audience, expiry, revocation, scopes and object-level ACL independently. The current `ms-go-mcp` production verifier still denies everything.
5. Rate limits for authorization/code exchange, abuse handling, audit (without secrets), client registration policy, operating domain/issuer, Gateway HTTPS route and end-client compatibility must be accepted before activation.

## Isolated acceptance checklist (NOT_RUN)

- Run Auth `gofmt`, policy, targeted `go test` and full `go vet ./...` + `go test ./...` with Go 1.24.4 before treating source as verified.
- Provision **disposable** PostgreSQL, migrate 0001–0006 with unchanged checksums, and check UP/DOWN on an empty store plus DOWN refusal after one record.
- Insert fixture-only registered client and explicit consent with no hidden data; verify one code can be redeemed once across concurrent PostgreSQL sessions, with 31 losers and no double-return.
- Verify denied issuance/redemption after consent revoke/expiry, client disable, scope reduction, wrong student/client/redirect/resource, malformed PKCE, code expiry and replay; no raw codes or verifiers in DB/logs.
- Simulate consent revoke racing code consumption and later token issuance once those stages exist; negative HTTP tests before any deployment.

An additional **opt-in disposable PostgreSQL gate** lives in `internal/infrastructure/persistence/postgres/mcp_external_code_repository_integration_test.go`, run through `.github/workflows/mcp00c2-postgres.yml`. It connects only to an exact loopback `mcp_external_codes_ci_test` database as `codeci`, creates a random isolated schema, applies `0001` and `0006`, and tests the *real GORM repository* for 32-way single-use consumption, binding errors, replay, revoked consent, disabled clients, reduced scopes, and retained-row rollback refusal. It skips without the guarded CI environment; passing ordinary `go test ./...` does not prove PostgreSQL behavior. The workflow reuses the migration provisioner's pinned PostgreSQL image in an ephemeral GitHub Actions runner; it does not connect to shared databases.

No shared migration was executed, no shared DB altered, and no active service was restarted. Do **not** merge as production OAuth functionality or start MCP-01 before these gates and the Auth HTTP issuer are accepted.
