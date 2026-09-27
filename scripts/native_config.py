#!/usr/bin/env python3
"""Run Auth commands with native-development endpoints and local secrets."""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INFRA_ENV_FILE = ROOT.parents[1] / "learning-platform-infrastructure" / ".env"
KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def load_dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, separator, value = line.partition("=")
        if separator != "=" or not KEY.fullmatch(key.strip()):
            raise ValueError(f"unsupported dotenv syntax at {path}:{number}")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key.strip()] = value
    return values


def required(values: dict[str, str], name: str) -> str:
    value = values.get(name, "")
    if not value:
        raise ValueError(f"{name} is required by the approved infrastructure environment")
    return value


def native_environment(require_tarantool: bool) -> dict[str, str]:
    configured_path = os.environ.get("LW_INFRA_ENV_FILE")
    infra_env_file = Path(configured_path).expanduser() if configured_path else DEFAULT_INFRA_ENV_FILE
    values = load_dotenv(infra_env_file)
    # Shared credentials remain owned by the infrastructure dotenv file. Only
    # explicit native overrides may replace its endpoint settings.
    values.update({name: value for name, value in os.environ.items() if name.startswith("AUTH_NATIVE_")})

    database = values.get("AUTH_NATIVE_DATABASE", "lw_auth")
    postgres_host = values.get("AUTH_NATIVE_POSTGRES_HOST", "127.0.0.1")
    postgres_port = values.get("AUTH_NATIVE_POSTGRES_PORT", "5432")
    db_user = values.get("AUTH_NATIVE_DB_USER", values.get("LW_AUTH_DB_USER", "lw_auth"))
    db_password = values.get("AUTH_NATIVE_DB_PASSWORD") or values.get("LW_AUTH_DB_PASSWORD") or required(values, "LW_POSTGRES_PASSWORD")
    native_port = values.get("AUTH_NATIVE_HTTP_PORT", "8081")
    db_dsn = values.get("AUTH_NATIVE_DB_DSN")
    if db_dsn:
        parsed = urlsplit(db_dsn)
        if parsed.scheme not in {"postgres", "postgresql"} or not parsed.hostname or not parsed.username or parsed.password is None or not parsed.path.strip("/"):
            raise ValueError("AUTH_NATIVE_DB_DSN must be a complete PostgreSQL DSN")
        database = unquote(parsed.path.strip("/"))
        postgres_host = parsed.hostname
        postgres_port = str(parsed.port or 5432)
        db_user = unquote(parsed.username)
        db_password = unquote(parsed.password)
        sslmode = parse_qs(parsed.query).get("sslmode", ["disable"])[0]
    else:
        db_dsn = "postgres://{}:{}@{}:{}/{}?sslmode=disable".format(
            quote(db_user, safe=""),
            quote(db_password, safe=""),
            postgres_host,
            postgres_port,
            database,
        )
        sslmode = values.get("AUTH_NATIVE_DB_SSLMODE", "disable")

    tarantool_url = values.get("AUTH_NATIVE_TARANTOOL_URL", "http://127.0.0.1:18081")
    tarantool_signup_url = values.get("AUTH_NATIVE_TARANTOOL_SIGNUP_URL", tarantool_url)
    tarantool_email_change_url = values.get("AUTH_NATIVE_TARANTOOL_EMAIL_CHANGE_URL", tarantool_url)
    if require_tarantool and (not tarantool_signup_url or not tarantool_email_change_url):
        raise ValueError("native Auth runtime requires signup and email-change Tarantool URLs")

    environment = dict(os.environ)
    environment.update(
        {
            "AUTH_APP_NAME": values.get("AUTH_NATIVE_APP_NAME", "lw-auth"),
            "AUTH_APP_ENV": values.get("AUTH_NATIVE_APP_ENV", "local"),
            "AUTH_HTTP_HOST": values.get("AUTH_NATIVE_HTTP_HOST", "127.0.0.1"),
            "AUTH_HTTP_PORT": native_port,
            "AUTH_DB_HOST": postgres_host,
            "AUTH_DB_PORT": postgres_port,
            "AUTH_DB_USER": db_user,
            "AUTH_DB_PASSWORD": db_password,
            "AUTH_DB_NAME": database,
            "AUTH_DB_SSLMODE": sslmode,
            "AUTH_DB_MIGRATE_ON_START": "false",
            "NATS_URL": values.get("AUTH_NATIVE_NATS_URL", "nats://127.0.0.1:4222"),
            # Keep native JWT validation aligned with the shared Compose
            # contract and the User service's native verifier settings.
            "AUTH_JWT_ISSUER": values.get("AUTH_NATIVE_JWT_ISSUER", "lw-auth"),
            "AUTH_JWT_AUDIENCE": values.get("AUTH_NATIVE_JWT_AUDIENCE", "frontend"),
            "AUTH_MIGRATION_DSN": db_dsn,
            "AUTH_MIGRATION_PSQL": str(ROOT / "scripts" / "native-psql.sh"),
        }
    )
    if tarantool_signup_url or tarantool_email_change_url:
        environment.update(
            {
                "TARANTOOL_SIGNUP_URL": tarantool_signup_url,
                "TARANTOOL_EMAIL_CHANGE_URL": tarantool_email_change_url,
            }
        )
    if require_tarantool:
        environment["AUTH_JWT_SECRET"] = required(values, "LW_AUTH_JWT_SECRET")

    print(
        "native Auth config: database={} postgres={}:{} nats={} tarantool_signup={} tarantool_email_change={} http={}:{}".format(
            database,
            postgres_host,
            postgres_port,
            environment["NATS_URL"],
            tarantool_signup_url,
            tarantool_email_change_url,
            environment["AUTH_HTTP_HOST"],
            environment["AUTH_HTTP_PORT"],
        ),
        flush=True,
    )
    return environment


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require-tarantool",
        action="store_true",
        help="require a native ms-go-tarantool HTTP endpoint for application runtime",
    )
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a command is required after --")
    try:
        environment = native_environment(args.require_tarantool)
    except (OSError, ValueError) as error:
        print(f"native Auth configuration failed: {error}", file=sys.stderr)
        return 2
    os.execvpe(command[0], command, environment)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
