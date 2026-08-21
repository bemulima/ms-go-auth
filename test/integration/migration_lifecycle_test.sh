#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
project="auth-migration-test-${RANDOM}-$$"
tmp_dir=$(mktemp -d)
local_compose="$tmp_dir/local-compose.yml"
prod_compose="$tmp_dir/prod-compose.yml"
legacy_compose="$tmp_dir/legacy-compose.yml"

cleanup() {
  docker compose -p "$project-local" -f "$local_compose" down -v --remove-orphans >/dev/null 2>&1 || true
  docker compose -p "$project-prod" -f "$prod_compose" down -v --remove-orphans >/dev/null 2>&1 || true
  docker compose -p "$project-legacy" -f "$legacy_compose" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

write_compose() {
  local path=$1
  printf '%s\n' \
    'services:' \
    '  postgres:' \
    '    image: postgres:16-alpine' \
    '    environment:' \
    '      POSTGRES_USER: app' \
    '      POSTGRES_DB: authdb' \
    '      POSTGRES_HOST_AUTH_METHOD: trust' \
    '    healthcheck:' \
    '      test: ["CMD-SHELL", "pg_isready -U app -d authdb"]' \
    '      interval: 1s' \
    '      timeout: 2s' \
    '      retries: 30' > "$path"
}

wait_for_db() {
  local compose_file=$1 compose_project=$2
  for _ in $(seq 1 60); do
    if docker compose -p "$compose_project" -f "$compose_file" exec -T postgres \
      psql -U app -d authdb -tAc 'SELECT 1' >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "disposable Postgres did not become ready" >&2
  return 1
}

run_task() {
  local compose_file=$1 compose_project=$2 environment=$3 task_name=$4
  (
    cd "$repo_root"
    COMPOSE_FILE="$compose_file" \
    COMPOSE_PROJECT_NAME="$compose_project" \
    MIGRATION_ENV="$environment" \
      task "$task_name"
  )
}

run_task_default_env() {
  local compose_file=$1 compose_project=$2 task_name=$3
  (
    cd "$repo_root"
    COMPOSE_FILE="$compose_file" \
    COMPOSE_PROJECT_NAME="$compose_project" \
      task "$task_name"
  )
}

query() {
  local compose_file=$1 compose_project=$2 sql=$3
  docker compose -p "$compose_project" -f "$compose_file" exec -T postgres \
    psql -U app -d authdb -v ON_ERROR_STOP=1 -tAc "$sql"
}

apply_sql() {
  local compose_file=$1 compose_project=$2 sql_file=$3
  docker compose -p "$compose_project" -f "$compose_file" exec -T postgres \
    psql -X -q -U app -d authdb -v ON_ERROR_STOP=1 < "$sql_file"
}

assert_contains() {
  local value=$1 expected=$2
  if [[ $value != *"$expected"* ]]; then
    echo "expected output to contain: $expected" >&2
    return 1
  fi
}

assert_eq() {
  local actual=$1 expected=$2
  if [[ $actual != "$expected" ]]; then
    echo "expected '$expected', got '$actual'" >&2
    return 1
  fi
}

file_checksum() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d ' ' -f 1
  else
    shasum -a 256 "$1" | cut -d ' ' -f 1
  fi
}

write_compose "$local_compose"
write_compose "$prod_compose"
write_compose "$legacy_compose"

default_summary=$(cd "$repo_root" && env -u COMPOSE_FILE -u COMPOSE_PROJECT_NAME -u MIGRATION_ENV task --summary migrate-up)
assert_contains "$default_summary" 'COMPOSE_FILE: "docker-compose.yml"'
if [[ $default_summary == *"ms-go-user"* ]]; then
  echo "canonical migration task must not target ms-go-user" >&2
  exit 1
fi

make_summary=$(cd "$repo_root" && make -n migrate-up)
assert_contains "$make_summary" "task migrate-up"
if [[ $make_summary == *"migrate -path"* || $make_summary == *"0002_seed_auth_users"* ]]; then
  echo "Makefile must delegate to the environment-gated canonical task" >&2
  exit 1
fi

docker compose -p "$project-local" -f "$local_compose" up -d postgres >/dev/null
wait_for_db "$local_compose" "$project-local"

local_first=$(run_task "$local_compose" "$project-local" local migrate-up)
assert_contains "$local_first" "applied 0001_init.up.sql"
assert_contains "$local_first" "applied 0002_seed_auth_users.up.sql"
assert_contains "$local_first" "applied 0003_oauth_flow.up.sql"
assert_eq "$(query "$local_compose" "$project-local" 'SELECT count(*) FROM auth_user')" "7"
assert_eq "$(query "$local_compose" "$project-local" "SELECT count(*) FROM auth_user WHERE email = 'student1@example.com'")" "1"
assert_eq "$(query "$local_compose" "$project-local" 'SELECT count(*) FROM auth_schema_migration')" "3"

local_second=$(run_task "$local_compose" "$project-local" local migrate-up)
assert_contains "$local_second" "already applied 0001_init.up.sql"
assert_eq "$(query "$local_compose" "$project-local" 'SELECT count(*) FROM auth_user')" "7"
assert_eq "$(query "$local_compose" "$project-local" 'SELECT count(*) FROM auth_schema_migration')" "3"

local_status=$(run_task "$local_compose" "$project-local" local migrate-status)
assert_contains "$local_status" "0002_seed_auth_users.up.sql"
assert_contains "$local_status" "applied"

set +e
prod_up_output=$(run_task_default_env "$local_compose" "$project-local" migrate-up 2>&1)
prod_up_status=$?
set -e
if [[ $prod_up_status == 0 ]]; then
  echo "production migration unexpectedly accepted local seed evidence" >&2
  exit 1
fi
assert_contains "$prod_up_output" "local seed migration evidence is not allowed outside MIGRATION_ENV=local or dev"

set +e
prod_down_output=$(run_task_default_env "$local_compose" "$project-local" migrate-down 2>&1)
prod_down_status=$?
set -e
if [[ $prod_down_status == 0 ]]; then
  echo "production rollback unexpectedly processed local seed evidence" >&2
  exit 1
fi
assert_contains "$prod_down_output" "local seed migration evidence requires MIGRATION_ENV=local or dev for rollback"
assert_eq "$(query "$local_compose" "$project-local" 'SELECT count(*) FROM auth_user')" "7"

query "$local_compose" "$project-local" \
  "UPDATE auth_schema_migration SET checksum = repeat('0', 64) WHERE name = '0001_init.up.sql'" >/dev/null
set +e
checksum_output=$(run_task "$local_compose" "$project-local" local migrate-up 2>&1)
checksum_status=$?
set -e
if [[ $checksum_status == 0 ]]; then
  echo "checksum sabotage unexpectedly succeeded" >&2
  exit 1
fi
assert_contains "$checksum_output" "checksum mismatch for applied migration 0001_init.up.sql"
set +e
checksum_down_output=$(run_task "$local_compose" "$project-local" local migrate-down 2>&1)
checksum_down_status=$?
set -e
if [[ $checksum_down_status == 0 ]]; then
  echo "rollback with checksum mismatch unexpectedly succeeded" >&2
  exit 1
fi
assert_contains "$checksum_down_output" "checksum mismatch for applied migration 0001_init.up.sql"
assert_eq "$(query "$local_compose" "$project-local" 'SELECT count(*) FROM auth_user')" "7"
assert_eq "$(query "$local_compose" "$project-local" "SELECT to_regclass('public.auth_oauth_transaction') IS NOT NULL")" "t"
assert_eq "$(query "$local_compose" "$project-local" 'SELECT count(*) FROM auth_schema_migration')" "3"

docker compose -p "$project-prod" -f "$prod_compose" up -d postgres >/dev/null
wait_for_db "$prod_compose" "$project-prod"

pre_status=$(run_task_default_env "$prod_compose" "$project-prod" migrate-status)
assert_contains "$pre_status" "0001_init.up.sql"
assert_contains "$pre_status" "pending"
assert_contains "$pre_status" "excluded (production)"
assert_eq "$(query "$prod_compose" "$project-prod" "SELECT to_regclass('public.auth_schema_migration') IS NULL")" "t"

prod_output=$(run_task_default_env "$prod_compose" "$project-prod" migrate-up)
assert_contains "$prod_output" "skipped local/dev seed 0002_seed_auth_users.up.sql"
assert_eq "$(query "$prod_compose" "$project-prod" 'SELECT count(*) FROM auth_user')" "0"
assert_eq "$(query "$prod_compose" "$project-prod" 'SELECT count(*) FROM auth_schema_migration')" "2"

prod_status=$(run_task_default_env "$prod_compose" "$project-prod" migrate-status)
assert_contains "$prod_status" "0002_seed_auth_users.up.sql"
assert_contains "$prod_status" "excluded (production)"

query "$prod_compose" "$project-prod" \
  "INSERT INTO auth_schema_migration (name, checksum, down_checksum, kind) VALUES ('9999_removed.up.sql', repeat('f', 64), repeat('e', 64), 'schema')" >/dev/null
unknown_status=$(run_task_default_env "$prod_compose" "$project-prod" migrate-status)
assert_contains "$unknown_status" "9999_removed.up.sql"
assert_contains "$unknown_status" "unknown applied migration"
set +e
unknown_down_output=$(run_task_default_env "$prod_compose" "$project-prod" migrate-down 2>&1)
unknown_down_status=$?
set -e
if [[ $unknown_down_status == 0 ]]; then
  echo "rollback with unknown evidence unexpectedly succeeded" >&2
  exit 1
fi
assert_contains "$unknown_down_output" "unknown applied migration 9999_removed.up.sql"

docker compose -p "$project-legacy" -f "$legacy_compose" up -d postgres >/dev/null
wait_for_db "$legacy_compose" "$project-legacy"
apply_sql "$legacy_compose" "$project-legacy" "$repo_root/migrations/0001_init.up.sql"
apply_sql "$legacy_compose" "$project-legacy" "$repo_root/migrations/0003_oauth_flow.up.sql"
apply_sql "$legacy_compose" "$project-legacy" "$repo_root/migrations/0002_seed_auth_users.up.sql"
assert_eq "$(query "$legacy_compose" "$project-legacy" 'SELECT count(*) FROM auth_user')" "7"
query "$legacy_compose" "$project-legacy" \
  "DELETE FROM auth_user WHERE id = '00000000-0000-0000-0000-0000000000b1';
   INSERT INTO auth_user (id, email, password_hash, password_updated_at)
   VALUES ('10000000-0000-0000-0000-0000000000b1', 'student1@example.com', 'replacement-account', now())" >/dev/null
apply_sql "$legacy_compose" "$project-legacy" "$repo_root/migrations/0002_seed_auth_users.down.sql"
assert_eq "$(query "$legacy_compose" "$project-legacy" 'SELECT count(*) FROM auth_user')" "1"
assert_eq "$(query "$legacy_compose" "$project-legacy" "SELECT count(*) FROM auth_user WHERE id = '10000000-0000-0000-0000-0000000000b1' AND email = 'student1@example.com'")" "1"
set +e
legacy_down_output=$(run_task_default_env "$legacy_compose" "$project-legacy" migrate-down 2>&1)
legacy_down_status=$?
set -e
if [[ $legacy_down_status == 0 ]]; then
  echo "untracked legacy rollback unexpectedly succeeded" >&2
  exit 1
fi
assert_contains "$legacy_down_output" "legacy migration state is untracked"

query "$legacy_compose" "$project-legacy" "
  CREATE TABLE auth_schema_migration (
    name text PRIMARY KEY,
    checksum text NOT NULL,
    down_checksum text,
    kind text NOT NULL CHECK (kind IN ('schema', 'local_seed')),
    applied_at timestamptz NOT NULL DEFAULT now()
  )
" >/dev/null
set +e
empty_down_output=$(run_task_default_env "$legacy_compose" "$project-legacy" migrate-down 2>&1)
empty_down_status=$?
set -e
if [[ $empty_down_status == 0 ]]; then
  echo "rollback with empty evidence unexpectedly succeeded" >&2
  exit 1
fi
assert_contains "$empty_down_output" "migration evidence is empty while owned auth tables exist"

legacy_adopt=$(run_task_default_env "$legacy_compose" "$project-legacy" migrate-up)
assert_contains "$legacy_adopt" "applied 0001_init.up.sql"
assert_eq "$(query "$legacy_compose" "$project-legacy" 'SELECT count(*) FROM auth_schema_migration')" "2"
query "$legacy_compose" "$project-legacy" \
  "UPDATE auth_schema_migration SET down_checksum = repeat('0', 64) WHERE name = '0001_init.up.sql'" >/dev/null
set +e
down_checksum_output=$(run_task_default_env "$legacy_compose" "$project-legacy" migrate-down 2>&1)
down_checksum_status=$?
set -e
if [[ $down_checksum_status == 0 ]]; then
  echo "rollback with down checksum mismatch unexpectedly succeeded" >&2
  exit 1
fi
assert_contains "$down_checksum_output" "rollback checksum mismatch for applied migration 0001_init.up.sql"
assert_eq "$(query "$legacy_compose" "$project-legacy" "SELECT to_regclass('public.auth_oauth_transaction') IS NOT NULL")" "t"
assert_eq "$(query "$legacy_compose" "$project-legacy" 'SELECT count(*) FROM auth_schema_migration')" "2"
down_hash=$(file_checksum "$repo_root/migrations/0001_init.down.sql")
query "$legacy_compose" "$project-legacy" \
  "UPDATE auth_schema_migration SET down_checksum = '$down_hash' WHERE name = '0001_init.up.sql'" >/dev/null
legacy_down=$(run_task_default_env "$legacy_compose" "$project-legacy" migrate-down)
assert_contains "$legacy_down" "rolled back 0001_init.up.sql"
assert_eq "$(query "$legacy_compose" "$project-legacy" "SELECT to_regclass('public.auth_user') IS NULL")" "t"
assert_eq "$(query "$legacy_compose" "$project-legacy" 'SELECT count(*) FROM auth_schema_migration')" "0"

echo "migration lifecycle integration test passed"
