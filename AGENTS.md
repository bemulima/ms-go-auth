# Repository Guidelines

## Agent bootstrap

Read .ai/rules/common.md, .ai/service.yaml, docs/README.md, and every affected owned contract before changing files. Issues and linked pull requests are the durable task record; code, migrations, tests, and repository-owned docs are authoritative.

## Architecture invariants

- internal/domain owns auth persistence models; internal/usecase owns signup, credentials, OAuth, refresh sessions, identity linking, and JWT behavior.
- internal/adapters owns HTTP, PostgreSQL, Tarantool, NATS, and OAuth-provider details; internal/app is the composition root.
- ms-go-auth owns credentials, auth identities, OAuth transactions, refresh sessions, and token issuance/verification. ms-go-user owns user/profile data; ms-go-rbac owns roles.
- Core NATS subjects are request/reply. Signup user/role provisioning is currently best-effort; OAuth provisioning is stricter. Preserve or deliberately change this distinction with tests and docs.
- Secrets, token material, authorization codes, PKCE verifiers, and password hashes must never be logged or committed.

## Verification and delivery

- Use commands in .ai/commands.yaml and keep caches in .cache.
- Run agent policy, tracked-file gofmt, go vet ./..., and go test ./....
- Migrations, OAuth redirects, JWT claims/TTL, HTTP routes, and NATS payloads are compatibility-sensitive and must update code, tests, docs, and machine contracts together.
- Do not run migrations, start services, publish GitHub changes, or deploy without the required authorization.
