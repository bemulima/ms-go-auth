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

Startup schema changes are controlled by `AUTH_DB_MIGRATE_ON_START`, which
defaults to `true` for backwards compatibility. Set it to `false` during a
rollout where the owner migration runner applies the forward migrations before
the service starts; this skips the extension creation, compatibility `ALTER`,
and GORM `AutoMigrate` statements as one gate.

## Native migration execution

`task migrate-status:native` and `task migrate:native` use the same
`scripts/migrate.sh` implementation and ordered `migrations/*.sql` files as
Docker mode. The native adapter derives a PostgreSQL DSN for the `lw_auth`
role and database from the approved infrastructure environment. On a machine
without a host `psql` client, the adapter uses the client already present in
the shared PostgreSQL container without changing the target endpoint or role.

Native application startup sets `AUTH_DB_MIGRATE_ON_START=false`; run the
owner migration task before starting the application process.

## Disposable migration verification

`task migration-integration-test` keeps the existing local, production-mode and
legacy migration scenarios in three unique disposable Compose projects with no
published ports. `.ai/testing/provisioners/auth-postgres-migration.v1.json` pins
the PostgreSQL image digest, Docker Engine 29.8.1 and Compose 5.5.1; the testing
manifest binds its exact SHA256. Both CI workflows install the matching tools
and verify the Compose release asset checksum before execution.

The existing lifecycle invokes `test/integration/migration_provisioner.py` for
each declared start, readiness and cleanup stage using its generated
`COMPOSE_FILE` and unique `COMPOSE_PROJECT_NAME`. Start and cleanup have 60-second
timeouts. Readiness requires an exact `SELECT 1` result within 60 seconds. The
exit trap attempts cleanup of all generated projects, including after startup
or scenario failure, removes their volumes and temporary files, and reports
cleanup failure through a nonzero exit status. Runtime version mismatch fails
before resources are created. This command uses no shared native database.

The harness clears ambient native migration endpoint overrides and fixes its
disposable database/user/service identity. It watches the original Task parent
and reaps owned provisioner children on cancellation. Canonical migration and
SQL commands also watch that parent, including inside shell substitutions;
they stop their own child process groups before fixture cleanup. The existing
migration SQL, scenarios and assertions are unchanged.
