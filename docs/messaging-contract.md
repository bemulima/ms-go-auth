# Messaging contract

auth.verifyJWT is a queue-group Core NATS request/reply endpoint. Request is {"token":"..."}. Response contains ok, optional user_id and email, optional claims, and an error code. Role and expiry remain inside claims; there are no dedicated role or expires_at response fields.

The service calls user.create-user, rbac.assign-role, and rbac.checkRole. These are RPC subjects, not durable events. Payload changes require producer/consumer tests in both owning repositories.

Signup completion treats User creation and RBAC assignment as required
synchronous acknowledgements. The frozen success, failure, and retry semantics
are defined in `.ai/contracts/auth-user-rbac-provisioning-v1.md`.
