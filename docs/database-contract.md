# Database contract

auth_user owns normalized email and optional password hash. auth_identity owns provider/subject links with uniqueness per provider subject and per user/provider. auth_refresh_token stores hashed refresh session identifiers and revocation/expiry. auth_oauth_transaction stores hashed one-time state, PKCE verifier, return target, expiry, and consumption.

## Migration lifecycle

`task migrate-up` is the canonical repository-owned migration command. It targets the `postgres` service in this repository's `docker-compose.yml` by default, applies `migrations/*.up.sql` in filename order, and records each applied filename, up/down checksum, kind, and timestamp in `auth_schema_migration`. Repeated execution is idempotent; a changed checksum for an applied migration fails closed. `task migrate-status` is read-only and reports applied, pending, environment-excluded, unknown, missing-rollback, and checksum-mismatched files without creating the evidence table.

Databases created by the former untracked migration path are adopted by running `task migrate-up`: idempotent schema SQL is re-evaluated and evidence is recorded. `task migrate-down` fails closed when it detects owned auth tables without migration evidence, unknown/removed evidence entries, or checksum drift. A database containing applied local-seed evidence can be rolled back only with an explicit `MIGRATION_ENV=local` or `MIGRATION_ENV=dev`, preventing production-mode fixture deletion.

The `0002_seed_auth_users` fixture is local-development data, not production data. It is applied only when callers explicitly set `MIGRATION_ENV=local` or `MIGRATION_ENV=dev`. The safe default is `production`, which applies schema migrations while reporting the seed as excluded; if local-seed evidence already exists, non-local migration commands fail closed instead of accepting fixture identities. Before any non-local schema evidence is adopted, migration-up transactionally locks `auth_user` against concurrent writes and rejects any canonical fixture UUID or normalized fixture email already present; a final check before commit prevents evidence/identity split state, and seed evidence is never synthesized.

Local/dev seed application locks `auth_user` against concurrent writes and preflights all seven canonical `(id,email)` pairs in the same transaction as the seed: each pair may be absent or already exact, but a fixture ID or normalized fixture email mapped to any other identity fails closed. After the seed SQL and again after evidence insertion, all seven exact pairs and the absence of conflicting normalized identities are verified before commit; any mismatch rolls back both seed changes and evidence. A legacy local database containing all seven exact pairs and no evidence is therefore adopted idempotently with the canonical checksum and without duplicate identities. Do not log or expose fixture credential material.

Downstream infrastructure for the local alpha stack must use this canonical invocation:

```sh
MIGRATION_ENV=local task migrate-up
```

An infrastructure orchestrator may override `COMPOSE_FILE`, `COMPOSE_PROJECT_NAME`, or `DB_SERVICE` while invoking the same task. The Postgres service must already be running; migration commands do not start or restart services.

Migrations are ordered and reversible. Never expose password hashes, state hashes, PKCE verifiers, or refresh hashes.
