# HTTP contract

The base path defaults to /api/v1. Auth routes are listed in .ai/contracts/http.yaml and internal/transport/http/api/v1/router.go. Protected routes use JWT middleware. /internal/health is GET.

OAuth start and callback are implemented for registered Google and GitHub providers.
Validation errors use the shared JSON error envelope.

## Verification-code flows

`POST /signup/start` accepts `{ "email", "password" }` and returns `202`
with `{ "message" }`. `POST /signup/verify` accepts `{ "email", "code" }`
and returns tokens in legacy mode.

`POST /email/change/start` requires a JWT, accepts `{ "new_email" }`, and
retains its `200` `{ "message" }` response. The public
`POST /email/change/verify` request is code-only: `{ "code" }`. It returns
the updated Auth user. The verification-code service resolves that code to the
bound `{ "user_id", "email" }`; callers never provide a user ID.

Password reset remains public. `POST /password/reset/start` accepts
`{ "email" }` and returns `202` with `{ "data": { "uuid" } }`.
`POST /password/reset/finish` accepts `{ "email", "code", "new_password" }`
and returns `200` with `{ "data": { "status": "ok" } }`.

Auth verification flows use its in-process `domain.VerificationClient` and `domain.SignupProofConsumer`, backed by the Auth-owned authenticated Tarantool functions. No verification HTTP provider is exposed. The legacy routes remain registered, but signup start/verify and password-reset start/finish return their existing error envelopes when the production email-code workflow is enabled. They are not fallback paths; the mounted UI uses the `/code/{registration,reset}/*` routes.

Access TTL defaults to 15m and refresh TTL to 720h. These values are configuration defaults, not fixed protocol guarantees.

Signup verification generates its operation UUID internally; the public caller
continues to send only email and code. Auth trims code whitespace consistently
with the provider and normalizes email before selecting the durable operation.
The configured identity-store runtime principal and credential are mandatory. Missing configuration and mismatched/expired receipts fail closed; recoverable signup never falls back to legacy verification. Legacy in-process verification is destructive and cannot recover a receipt.

The protected receipt contains the frozen signup password hash and UTC RFC3339
expiry computed from the provider's original signup creation time and existing
hard TTL. It is private persistence data and is never returned to public
Auth callers or logged. Verified pending operations may replay their exact
proof within this bound to repair required User/RBAC provisioning. Successful
terminal verification attempts token issuance once; later code replay fails.
After response loss use password signin. Password signin can also repair an
owned verified pending principal after receipt expiry, but returns no tokens
until all required acknowledgements and the terminal CAS succeed. Refresh and
OAuth cannot issue tokens for pending principals.

## Email-first registration

The mounted frontend uses `POST /auth/code/registration/start`, `/verify`, and
`/complete` below the configured HTTP base path. Start accepts only `{email}`
and returns 202 after the existing SMTP adapter sends a six-digit code. Verify
accepts `{email,code}` and returns `{grant,expires_in:600}`. Neither operation
creates an Auth account, User profile, RBAC assignment, or session.

Complete accepts `{email,grant,password}`. It atomically consumes the bound,
unexpired grant, then uses the existing durable signup completion, actual User
acknowledgement, signed RBAC provisioning/readback, and terminal CAS before
issuing access/refresh tokens. The account has `email_verified=true`. Concurrent
or later completion with the consumed grant is rejected. The Next.js session
BFF stores tokens in HttpOnly cookies and returns only user metadata.

Codes expire after 600 seconds, lock after five wrong attempts, and can be resent
after 60 seconds. Resend replaces the prior code. An allocation matching the
previous digest is retried up to ten times without sending or mutating limits;
exhaustion fails closed. Codes and grants are stored only as purpose-bound HMACs.
Grant expiry from Tarantool accepts the MessagePack uint32 timestamp encoding.
The older `/signup/*` routes are disabled by the email-code use-case gate in production mode.

## Email-code password recovery

The mounted recovery UI uses `POST /auth/code/reset/start`, `/verify`, and
`/complete` below the configured base path. All code generation, HMAC storage,
attempt limits, resend replacement/cooldown and grant expiry reuse the email-code
implementation above with purpose `reset`. A registration proof cannot authorize
password reset. OAuth-only identities without a local password receive no code.

Start accepts `{email}` and returns the same generic 202 response for eligible,
unknown, OAuth-only, throttled and delivery-failed requests. This avoids leaking
account eligibility or cooldown through public status/body. Verification accepts
`{email,code}` and returns a 600-second single-use grant. Completion accepts
`{email,grant,password}`, atomically consumes the grant and changes the password
in the same PostgreSQL transaction that revokes every active refresh session.
Existing access tokens carry a `sid`; authoritative verification reads its active
session and rejects revoked sessions even while the JWT signature/expiry remain
valid. No tokens are issued by reset completion. It returns `{status:"ok"}` after
the existing SMTP adapter sends a credential-free password-change notification.
The caller then signs in normally. Notification failure is reported after the
password transaction; the consumed grant cannot be retried. Legacy `/password/reset/*` routes are disabled by the email-code gate in production mode.

## Google external test boundary

Production startup normally uses Google's standard authorize/token/userinfo/JWKS
endpoints. `AUTH_OAUTH_GOOGLE_BOUNDARY_URL` optionally routes only those external
requests to the existing local provider fixture. Startup rejects this option
unless `AUTH_APP_ENV=test`, Auth HTTP and PostgreSQL bind to `127.0.0.1`, the
PostgreSQL database ends `_test`, and startup migrations are disabled. The URL
must be an HTTP loopback origin with an explicit port and no credentials, query,
fragment or path. The real Google adapter retains PKCE, nonce, RS256 signature,
expiry, issuer, audience, subject and trusted email validation. GitHub and email
flows are unaffected. OAuth against an existing unlinked email requires explicit
linking and never changes that account's password.

The extracted `test/integration/oauth_external_boundary_test.go` retains the
existing `TestAuthSmokeServe` entrypoint with `AUTH_SMOKE_SERVE_EXTERNAL_ONLY=true`.
It serves only external Google/GitHub endpoints and exposes no Auth,
SMTP, account seeding or session handling. It uses the existing private control
endpoint and readiness/stop contract. Never record callback query strings,
authorization codes, ID tokens, session tokens or PKCE verifiers in logs.

## GitHub external test boundary

`AUTH_OAUTH_GITHUB_BOUNDARY_URL` redirects only GitHub authorize/token/user/emails
requests to the same existing external provider fixture. The same
`ValidateLocalOAuthBoundary` startup gate applies when either Google or GitHub
boundary routing is configured: test environment, loopback HTTP/PostgreSQL,
owner-migrated database ending `_test`. The origin must have an explicit port
and no credentials, path, query or fragment. Default GitHub endpoints are
unchanged when the option is empty.

The real GitHub adapter still exchanges the code with its PKCE verifier, reads
provider user ID and verified email addresses, and rejects an absent usable email
through Auth's verified-profile gate. The OAuth callback creates one confirmed
Auth account without a local password, provisions actual User/RBAC, links the
GitHub subject and issues a persisted session. The existing external-only mode
also permits synthetic GitHub profiles ending `@example.test` with positive
numeric subjects; no Auth, SMTP or session simulation is introduced.

## Email-code runtime configuration

Production startup requires a dedicated `AUTH_EMAIL_CODE_HMAC_KEY` secret of at
least 32 bytes and the existing SMTP adapter settings `AUTH_SMTP_ADDRESS` and
`AUTH_SMTP_FROM`. Set `AUTH_EMAIL_ORIGIN_HOURLY_LIMIT` to a positive integer
(default 20). Keep all credentials outside version control; `.env.example`
contains empty secret placeholders. Mailpit is an isolated test receiver only.

## Auth/RBAC role claim contract — additive role key

The existing JWT wire format is unversioned: `role` remains an optional signed
string claim, and `/auth/verify` returns the verified subject in `user_id` and
other verified claims under `claims`. Previously issued tokens are neither
rewritten nor reinterpreted. The source-level role selection contract
`auth-rbac-role-claim.v1` admits the RBAC key `student_pro` in addition to the
existing candidate keys. Auth may sign that value only after its existing RBAC
role-check port returns true for that principal; it is never inferred from a
client cookie, configured default, or subscription hint. A configured default
is merely an additional role to check, not proof of an assignment.

This is an additive Auth candidate, not an RBAC role migration, grant, or
assignment. The RBAC seed currently defines `student` but not `student_pro`;
operators must not assume that the new candidate proves a deployed RBAC role
exists. RBAC unavailability produces no role claim; it does not justify an
unverified privileged role. Consumers requiring a role must fail closed when it
is absent. Existing role-candidate ordering continues to prefer admin,
moderator and teacher over student roles. Revalidation and new signed tokens are
required to observe a newly confirmed role; legacy access tokens retain their
existing claim until refresh or expiry.
