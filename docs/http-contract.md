# HTTP contract

The base path defaults to /api/v1. Auth routes are listed in .ai/contracts/http.yaml and internal/transport/http/api/v1/router.go. Protected routes use JWT middleware. /internal/health is GET.

OAuth start and callback are implemented for registered Google and GitHub providers.
Validation errors use the shared JSON error envelope.

## Verification-code flows

`POST /signup/start` accepts `{ "email", "password" }` and returns `202`
with `{ "message" }`. `POST /signup/verify` accepts `{ "email", "code" }`
and returns tokens.

`POST /email/change/start` requires a JWT, accepts `{ "new_email" }`, and
retains its `200` `{ "message" }` response. The public
`POST /email/change/verify` request is code-only: `{ "code" }`. It returns
the updated Auth user. The verification-code service resolves that code to the
bound `{ "user_id", "email" }`; callers never provide a user ID.

Password reset remains public. `POST /password/reset/start` accepts
`{ "email" }` and returns `202` with `{ "data": { "uuid" } }`.
`POST /password/reset/finish` accepts `{ "email", "code", "new_password" }`
and returns `200` with `{ "data": { "status": "ok" } }`.

Auth sends the following HTTP requests to the verification-code service:

| Flow | Request | Success response required by Auth |
| --- | --- | --- |
| Signup start | `POST TARANTOOL_SIGNUP_URL/api/v1/set-new-user` with `{ "value": { "email", "password" } }` | `200` |
| Signup verify | `POST TARANTOOL_SIGNUP_URL/api/v1/consume-signup-proof` with `{ "value": { "email", "code", "operation_id" } }` and `X-Internal-Token` | `{ "operation_id", "email", "password", "expires_at" }` |
| Email change start | `POST TARANTOOL_EMAIL_CHANGE_URL/api/v1/start-email-change` with `{ "value": { "user_id", "email" } }` | `{ "uuid" }` |
| Email change verify | `POST TARANTOOL_EMAIL_CHANGE_URL/api/v1/verify-email-change` with `{ "value": { "code" } }` | `{ "user_id", "email" }` |
| Password reset start | `POST TARANTOOL_SIGNUP_URL/api/v1/password-reset-start` with `{ "value": { "email" } }` | `{ "uuid" }` |
| Password reset verify | `POST TARANTOOL_SIGNUP_URL/api/v1/password-reset-verify` with `{ "value": { "email", "code" } }` | `200` |

The configured signup and email-change base URLs may point to the same
service. They remain separate configuration values so each flow follows its
owner endpoint.

Access TTL defaults to 15m and refresh TTL to 720h. These values are configuration defaults, not fixed protocol guarantees.

Signup verification generates its operation UUID internally; the public caller
continues to send only email and code. Auth trims code whitespace consistently
with the provider and normalizes email before selecting the durable operation.
`SIGNUP_CONSUME_INTERNAL_TOKEN` must be configured with the same internal secret
at Auth and Tarantool. Missing configuration and mismatched/expired receipts fail
closed; Auth never falls back to `check-new-user-code`. The legacy provider
endpoint remains a destructive one-shot compatibility endpoint.

The protected receipt contains the frozen signup password hash and UTC RFC3339
expiry computed from the provider's original signup creation time and existing
hard TTL. It is private server-to-server data and is never returned to public
Auth callers or logged. Verified pending operations may replay their exact
proof within this bound to repair required User/RBAC provisioning. Successful
terminal verification attempts token issuance once; later code replay fails.
After response loss use password signin. Password signin can also repair an
owned verified pending principal after receipt expiry, but returns no tokens
until all required acknowledgements and the terminal CAS succeed. Refresh and
OAuth cannot issue tokens for pending principals.
