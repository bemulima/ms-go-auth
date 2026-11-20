# CAT-49 reviewer pending gate

SOURCE_ONLY / NOT ACTIVATED. No moderator or Auth principal is created.

Migration 0006 introduces immutable registration and activation ledgers. An
Auth user registered for the CAT reviewer role is PENDING while registration
exists without a matching activation receipt. The existing central
SignupPrincipalPending port now checks this pending state. Both new access/
refresh issuance and verification of old JWTs must deny pending principals.

This is a prerequisite only. Registration, independent RBAC role receipt
verification, activation and trusted Gateway authorization require a separately
security-approved operator design before any real privileged action.
The old V1 STUDENT fixture must not be invoked or altered as a workaround.
Only task-owned disposable migrations may be applied after owner acceptance.
