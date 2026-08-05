# Auth Service

User authentication microservice extracted from ms-go-user. Handles credentials, OAuth identities, JWT issuance/verification, and coordination with ms-go-user (profiles) and ms-go-rbac (roles).

## Features
- Password-based signup/signin with Tarantool-backed code verification over HTTP
- JWT access/refresh issuance and NATS RPC `auth.verifyJWT`
- Email change and password reset flows
- Server-owned OAuth2 Authorization Code flow with state, PKCE, Google, and GitHub
- Automatic identity linking by normalized verified email
- OAuth-only accounts with an optional password that can be set later
- NATS RPC calls to `user.create-user` (ms-go-user) and `rbac.assign-role` for default role
- Forwarding optional OAuth profile data to ms-go-user for first-name, last-name, birth-year, gender, and local avatar import

## Messaging Boundary

- Retained broker scope for this service is limited to Core NATS RPC: `auth.verifyJWT`, `user.create-user`, `rbac.assign-role`, `rbac.checkRole`.
- Tarantool signup and related verification flows are HTTP-owned in the target architecture and are not part of the retained broker catalog.
- Retained Core NATS RPC subjects are request/reply only and are expected to run queue-group-safe under multi-instance deployment. `auth.verifyJWT` is the read/check owner endpoint used by other services.

## HTTP API (base path `/api/v1/auth`)
- `POST /signup/start` — start signup, send code via Tarantool
- `POST /signup/verify` — verify code, create auth user, call ms-go-user + RBAC, return tokens
- `POST /signin` — email/password login
- `POST /refresh` — refresh tokens
- `POST /password/reset/start` — start reset
- `POST /password/reset/finish` — finish reset
- `POST /email/change/start` (JWT) — start email change
- `POST /email/change/verify` — verify email change
- `POST /oauth/:provider/start` — create one-time state + PKCE transaction and return the provider authorization URL
- `POST /oauth/:provider/callback` — consume state, exchange code, link/create identity, and return application tokens
- `GET /identities` (JWT) — list linked OAuth identities
- `DELETE /identities/:provider/:provider_user_id` (JWT) — remove an identity while preserving at least one login method
- `POST /password/set` (JWT) — set the first password for an OAuth-only account
- `POST /password/change` (JWT) — change an existing password

## NATS
- RPC handler `auth.verifyJWT`
- Clients: `user.create-user`, `rbac.assign-role`

For OAuth provisioning, `user.create-user` keeps the existing `id`, `email`, `source`, and `type` fields and optionally includes:

```json
{
  "oauth_profile": {
    "provider": "google",
    "first_name": "Ada",
    "last_name": "Lovelace",
    "birth_year": 1998,
    "gender": "female",
    "avatar_url": "https://provider.example/avatar"
  }
}
```

Providers leave unavailable fields empty. GitHub's combined `name` is not heuristically split into first and last name.

## Migrations
`migrations/0001_init.up.sql` creates `auth_user`, `auth_identity`, `auth_refresh_token`.
`migrations/0003_oauth_flow.up.sql` makes passwords optional, enforces one identity per provider per account, and creates the one-time OAuth transaction table.

## Config (.env)
See `.env.example` and `config/config.go`. Real client secrets belong in the ignored `.env` or a secret store, never in `.env.example`.

For local frontend development on port 3001, register these exact callbacks:

- Google: `http://localhost:3001/api/oauth/google/callback`
- GitHub: `http://localhost:3001/api/oauth/github/callback`

Direct provider setup pages:

- Google Cloud credentials: https://console.cloud.google.com/apis/credentials
- GitHub OAuth App: https://github.com/settings/applications/new

The Go provider contract is `internal/oauth.Provider`. Its normalized `Profile` supports optional `FirstName`, `LastName`, `BirthYear`, `Gender`, and `AvatarURL` values. `OAuth2Base` contains the shared OAuth2 config, PKCE exchange, HTTP client, and validation; `GoogleOAuth2` and `GitHubOAuth2` embed it and implement provider-specific profile loading. Adding another standards-compatible provider means implementing the interface and registering it in `internal/app/app.go`. Telegram login is not a regular OAuth2 provider and should use a separate adapter behind the same application-level identity contract.

## Testing
- Unit/handler tests: `XDG_CACHE_HOME=$PWD/.cache GOCACHE=$PWD/.cache/go-build GOMODCACHE=$PWD/.cache/gomod go test ./...`
- External deps are mocked (no DB/NATS required). Default role used in tests is `user` (configurable via `AUTH_DEFAULT_ROLE`).
