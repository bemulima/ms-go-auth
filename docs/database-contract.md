# Database contract

auth_user owns normalized email and optional password hash. auth_identity owns provider/subject links with uniqueness per provider subject and per user/provider. auth_refresh_token stores hashed refresh session identifiers and revocation/expiry. auth_oauth_transaction stores hashed one-time state, PKCE verifier, return target, expiry, and consumption.

Migrations are ordered and reversible. Never expose password hashes, state hashes, PKCE verifiers, or refresh hashes.

Startup schema changes are controlled by `AUTH_DB_MIGRATE_ON_START`, which
defaults to `true` for backwards compatibility. Set it to `false` during a
rollout where the owner migration runner applies the forward migrations before
the service starts; this skips the extension creation, compatibility `ALTER`,
and GORM `AutoMigrate` statements as one gate.
