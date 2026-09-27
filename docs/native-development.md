# Native macOS development

Auth runs as a macOS process while Docker supplies shared PostgreSQL and NATS.
The native adapter owns endpoint selection, so no host addresses are embedded
in application Go code. Auth's verification-code dependency is the native
`ms-go-tarantool` application API, which in turn uses Docker identity
Tarantool; it is distinct from the Tarantool protocol endpoint on port 3301.

## Start dependencies

From the infrastructure repository:

```sh
make native-infra-up
make native-infra-check
```

Start native `ms-go-tarantool` before Auth. Its Wave 1 endpoint is
`http://127.0.0.1:18081`.

## Migrate and run Auth

From this repository:

```sh
task migrate-status:native
task migrate:native
task run:native
```

The tasks read the approved infrastructure dotenv file at
`../../learning-platform-infrastructure/.env` by default. Set
`LW_INFRA_ENV_FILE` when it is elsewhere. The adapter derives the `lw_auth`
role credential without printing it and supplies these native values:

| Setting | Value |
| --- | --- |
| PostgreSQL | `127.0.0.1:5432`, database and role `lw_auth` |
| NATS | `nats://127.0.0.1:4222` |
| verification API | `http://127.0.0.1:18081` |
| HTTP | `127.0.0.1:8081` |
| startup schema changes | disabled after the explicit migration task |
| JWT issuer / audience | `lw-auth` / `frontend`, matching Compose and User |

Use `AUTH_NATIVE_DATABASE`, `AUTH_NATIVE_DB_USER`,
`AUTH_NATIVE_POSTGRES_HOST`, `AUTH_NATIVE_POSTGRES_PORT`,
`AUTH_NATIVE_NATS_URL`, `AUTH_NATIVE_TARANTOOL_URL`,
`AUTH_NATIVE_HTTP_HOST`, `AUTH_NATIVE_HTTP_PORT`, or a complete
`AUTH_NATIVE_DB_DSN` only to make an explicit native override. OAuth provider
credentials remain in the service's existing ignored `.env`; they are not
copied into the infrastructure environment.

`AUTH_NATIVE_TARANTOOL_URL` supplies both verification-code flows by default.
Set `AUTH_NATIVE_TARANTOOL_SIGNUP_URL` or
`AUTH_NATIVE_TARANTOOL_EMAIL_CHANGE_URL` when their application endpoints are
deployed separately.
Use `AUTH_NATIVE_JWT_ISSUER` or `AUTH_NATIVE_JWT_AUDIENCE` only when the
matching User verifier configuration is changed at the same time.

`scripts/migrate.sh` remains the only migration implementation. Its native
mode selects the DSN derived by the adapter. When macOS does not provide
`psql`, `scripts/native-psql.sh` invokes the PostgreSQL client already running
with the shared infrastructure; it neither starts an application container nor
prints credentials.

Use `Ctrl-C` to stop Auth. The service exposes its existing health endpoint at
`GET http://127.0.0.1:8081/internal/health`.

## Docker Compose path

The standalone Docker workflow remains available:

```sh
docker compose up -d
task migrate-up
```

Compose starts its own PostgreSQL and Core NATS services. The Auth container
uses `postgres:5432` and `nats:4222` via Docker DNS; the native task uses
loopback endpoints. Configure a reachable verification API in the service
environment before exercising signup or email-change flows. Stop only this
repository's containers with `docker compose down`; its named volumes are
preserved unless explicitly removed.
