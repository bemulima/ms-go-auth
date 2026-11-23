# Notification verified recipient owner read

`POST /internal/v1/notification/recipient` is a service-only Auth capability for
Notification. It is absent unless `AUTH_NOTIFICATION_RECIPIENT_ENABLED=true` and
an independent `AUTH_NOTIFICATION_RECIPIENT_TOKEN` of 32–256 printable ASCII
bytes is supplied. The token is sent once in `X-Notification-Recipient-Token`.
Human Bearer tokens are rejected; user/role headers grant no authority.

Request (exact keys, at most 1024 UTF-8 bytes):

```json
{"schema":"auth.notification-recipient-request.v1","user_id":"11111111-1111-4111-8111-111111111111"}
```

Success `200`, JSON, `Cache-Control: no-store`, exact keys:

```json
{"schema":"auth.notification-recipient.v1","user_id":"11111111-1111-4111-8111-111111111111","email":"student@example.com","verified":true,"revision":"<64 lowercase hex>","checked_at":"2026-11-17T12:00:00Z"}
```

The response reads Auth's persisted `email_verified` flag. `checked_at` is the
current observation time, **not** a historical verification timestamp (Auth does
not persist one). Revision is SHA-256 of the exact documented domain, user ID,
email and `updated_at` snapshot. It is an equality pin, not a bearer credential.
The usecase reads the narrow projection twice and rejects changes, unverified
or invalid addresses, foreign identity, or incomplete signup. Each PostgreSQL
read selects only ID, email, verification, update time and the pending-signup
predicate in one statement. No profile, password, OAuth or session payload is
selected or returned. Missing recipient and denied verification both return
`404 {"error":"recipient_unavailable"}`. Invalid JSON/shape returns 400;
wrong/multiple capability tokens return 401; dependencies return generic 503.

Duplicate/case-altered/unknown/null fields, extra JSON values, query parameters,
content encoding, and unsupported content types fail closed. Operation timeout
is two seconds, with cancellation closing the request body.

Composition mounts the exact route in the existing Echo application and, when
enabled, its existing Mentor HTTPS handler. Notification must use a configured
HTTPS origin with certificate verification and no redirects. The Echo listener
requires trusted internal TLS termination and network isolation; the endpoint
must never be added to public Gateway routes. No listener, token, SMTP setting,
DB migration or deployment is activated by this source change.

Notification must resolve again immediately before sending and compare current
email and revision. This owner read cannot make remote SMTP acceptance atomic
with an Auth change; it bounds the observation window and does not claim recall
of an email already accepted by SMTP.
