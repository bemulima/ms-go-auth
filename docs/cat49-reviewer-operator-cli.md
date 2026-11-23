# CAT-49 dedicated Auth operator CLI — SOURCE_ONLY

The private CLI provides registration and activation, not a public route.
It is distinct from the rejected V1 STUDENT fixture and does not call it.

Registration creates one pending Auth principal and signed registration receipt.
It cannot issue a JWT. The protected Auth token path denies pending identities.
A separate RBAC owner CLI independently verifies the Auth receipt and grants
one MODERATOR; only after signed RBAC receipt validation and real RBAC role
readback can the Auth CLI append activation and enable verified sign-in.

The CLI is default-off, requires a private exact CAT-49 ownership marker,
task-owned Auth DB, non-superuser, loopback NATS and separate 0600 HMAC keys.
No existing canonical Auth/RBAC operation is modified or automatically invoked.
The new operator must pass independent automated approval before any execution.
Source tests and disposable PostgreSQL/authentication E2E remain NOT_RUN.
