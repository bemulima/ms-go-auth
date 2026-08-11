# Database contract

auth_user owns normalized email and optional password hash. auth_identity owns provider/subject links with uniqueness per provider subject and per user/provider. auth_refresh_token stores hashed refresh session identifiers and revocation/expiry. auth_oauth_transaction stores hashed one-time state, PKCE verifier, return target, expiry, and consumption.

Migrations are ordered and reversible. Never expose password hashes, state hashes, PKCE verifiers, or refresh hashes.
