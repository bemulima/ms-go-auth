# Architecture

ms-go-auth owns credentials, OAuth login identities, OAuth transactions, JWT issuance and verification, and refresh sessions. User profiles belong to ms-go-user and role assignments belong to ms-go-rbac. Echo adapters expose HTTP, Core NATS provides request/reply coordination, Tarantool HTTP owns verification-code flows, and PostgreSQL persists auth state.

Google and GitHub OAuth Authorization Code flows are implemented with one-time state and PKCE. This supersedes the former wiki statement that OAuth was only a stub. OAuth can link by normalized verified email and supports accounts without an initial password.

Known consistency boundary: classic signup ignores errors from user.create-user and rbac.assign-role after creating the auth record. OAuth provisioning checks those calls. Changes should either preserve this current behavior or introduce an explicit retry/outbox/compensation design.
