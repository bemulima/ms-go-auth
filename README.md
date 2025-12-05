# Auth Service

User authentication microservice extracted from ms-go-user. Handles credentials, OAuth identities, JWT issuance/verification, and coordination with ms-go-user (profiles) and ms-go-rbac (roles).

## Features
- Password-based signup/signin with Tarantool-backed code verification
- JWT access/refresh issuance and NATS RPC `auth.verifyJWT`
- Email change and password reset flows
- OAuth callback stub endpoint for future providers
- NATS RPC calls to `user.create-user` (ms-go-user) and `rbac.assign-role` for default role

## HTTP API (base path `/api/v1/auth`)
- `POST /signup/start` — start signup, send code via Tarantool
- `POST /signup/verify` — verify code, create auth user, call ms-go-user + RBAC, return tokens
- `POST /signin` — email/password login
- `POST /refresh` — refresh tokens
- `POST /password/reset/start` — start reset
- `POST /password/reset/finish` — finish reset
- `POST /email/change/start` (JWT) — start email change
- `POST /email/change/verify` — verify email change
- `POST /oauth/:provider/callback` — OAuth callback stub

## NATS
- RPC handler `auth.verifyJWT`
- Clients: `user.create-user`, `rbac.assign-role`

## Migrations
`migrations/0001_init.up.sql` creates `auth_user`, `auth_identity`, `auth_refresh_token`.

## Config (.env)
See `config/config.go` for variables: DB, JWT, NATS subjects, Tarantool URLs, default role, HTTP host/port/base path.

## Testing
- Unit/handler tests: `GOCACHE=../.gocache go test ./...`
- External deps are mocked (no DB/NATS required). Default role used in tests is `user` (configurable via `AUTH_DEFAULT_ROLE`).
