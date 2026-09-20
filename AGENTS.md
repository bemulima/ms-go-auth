# Repository Guidelines

## Agent bootstrap

Read .ai/architecture.yaml, .ai/rules/common.md, .ai/service.yaml, .ai/commands.yaml, docs/README.md, the refactor workflow, and every affected owned contract before changing files. Capture `git status --short` and `git diff`, then run `./scripts/check-agent-policy.sh`; stop fail-closed if it fails.

## Architecture invariants

- internal/domain owns auth persistence models and outbound ports; internal/usecase owns signup, credentials, OAuth, refresh sessions, identity linking, and JWT behavior.
- internal/transport is inbound-only. HTTP routes are confined to `http/api/v1` and `http/private`; `internal/infrastructure` is outbound-only and contains PostgreSQL, Tarantool HTTP, NATS, and OAuth-provider implementations. `internal/adapters` is forbidden.
- `internal/domain` and `internal/usecase` must not import transport, infrastructure, or GORM. `cmd/ms-go-auth` is the composition root.
- ms-go-auth owns credentials, auth identities, OAuth transactions, refresh sessions, and token issuance/verification. ms-go-user owns user/profile data; ms-go-rbac owns roles.
- Core NATS subjects are request/reply. Signup user/role provisioning is currently best-effort; OAuth provisioning is stricter. Preserve or deliberately change this distinction with tests and docs.
- Secrets, token material, authorization codes, PKCE verifiers, and password hashes must never be logged or committed.

## Verification and delivery

- Use commands in .ai/commands.yaml and keep caches in .cache.
- Run agent policy, tracked-file gofmt, go vet ./..., and go test ./....
- Migrations, OAuth redirects, JWT claims/TTL, HTTP routes, and NATS payloads are compatibility-sensitive and must update code, tests, docs, and machine contracts together.
- Do not run migrations, start services, publish GitHub changes, or deploy without the required authorization.
