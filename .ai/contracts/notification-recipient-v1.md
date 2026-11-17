# AUTH_NOTIFICATION_RECIPIENT_V1

Canonical contract: [Notification recipient](../../docs/notification-recipient-v1.md).

- Method/path: `POST /internal/v1/notification/recipient`.
- Caller: `ms-go-notification`; distinct `X-Notification-Recipient-Token` only.
- Request schema: `auth.notification-recipient-request.v1`; exact `schema,user_id`.
- Success schema: `auth.notification-recipient.v1`; exact
  `schema,user_id,email,verified,revision,checked_at`.
- `verified=true` comes from the current persisted Auth flag; pending signup denies.
- `revision=hex(SHA256("auth.notification-recipient.v1\n" + user_id + "\n" + email + "\n" + updated_at.UTC().Format(RFC3339Nano)))`.
- Response/request payload bounds: 2048/1024 bytes, no cache, no redirects.
- Errors: 400 invalid_request, 401 unauthenticated, 404 recipient_unavailable,
  405 method_not_allowed, 503 unavailable; envelope `{error:string}`.
- Default disabled; consumer must use HTTPS; no public Gateway exposure.
