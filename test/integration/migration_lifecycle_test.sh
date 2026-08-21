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

reset_schema() {
  local compose_file=$1 compose_project=$2
  query "$compose_file" "$compose_project" 'DROP SCHEMA public CASCADE; CREATE SCHEMA public' >/dev/null
}

prepare_auth_schema() {
  local compose_file=$1 compose_project=$2
  apply_sql "$compose_file" "$compose_project" "$repo_root/migrations/0001_init.up.sql"
  apply_sql "$compose_file" "$compose_project" "$repo_root/migrations/0003_oauth_flow.up.sql"
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

# Exact legacy fixtures are safe to adopt locally without duplication.
prepare_auth_schema "$legacy_compose" "$project-legacy"
apply_sql "$legacy_compose" "$project-legacy" "$repo_root/migrations/0002_seed_auth_users.up.sql"
legacy_exact_adopt=$(run_task "$legacy_compose" "$project-legacy" local migrate-up)
assert_contains "$legacy_exact_adopt" "applied 0002_seed_auth_users.up.sql"
assert_eq "$(query "$legacy_compose" "$project-legacy" 'SELECT count(*) FROM auth_user')" "7"
assert_eq "$(query "$legacy_compose" "$project-legacy" 'SELECT count(*) FROM auth_schema_migration')" "3"
seed_hash=$(file_checksum "$repo_root/migrations/0002_seed_auth_users.up.sql")
assert_eq "$(query "$legacy_compose" "$project-legacy" "SELECT checksum FROM auth_schema_migration WHERE name = '0002_seed_auth_users.up.sql'")" "$seed_hash"

# A fixture email attached to a different ID must fail before seed evidence.
reset_schema "$legacy_compose" "$project-legacy"
prepare_auth_schema "$legacy_compose" "$project-legacy"
query "$legacy_compose" "$project-legacy" \
  "INSERT INTO auth_user (id, email) VALUES ('10000000-0000-0000-0000-0000000000a1', E'\\tAdmin@Example.com\\t')" >/dev/null
set +e
conflicting_email_output=$(run_task "$legacy_compose" "$project-legacy" local migrate-up 2>&1)
conflicting_email_status=$?
set -e
if [[ $conflicting_email_status == 0 ]]; then
  echo "local migration unexpectedly accepted a fixture email with a different ID" >&2
  exit 1
fi
assert_contains "$conflicting_email_output" "fixture identity conflict"
assert_eq "$(query "$legacy_compose" "$project-legacy" "SELECT count(*) FROM auth_schema_migration WHERE name = '0002_seed_auth_users.up.sql'")" "0"
assert_eq "$(query "$legacy_compose" "$project-legacy" "SELECT count(*) FROM auth_user WHERE id = '10000000-0000-0000-0000-0000000000a1' AND email = E'\\tAdmin@Example.com\\t'")" "1"

# A fixture ID attached to a different email must also fail closed.
reset_schema "$legacy_compose" "$project-legacy"
prepare_auth_schema "$legacy_compose" "$project-legacy"
query "$legacy_compose" "$project-legacy" \
  "INSERT INTO auth_user (id, email) VALUES ('00000000-0000-0000-0000-0000000000a1', 'other-admin@example.com')" >/dev/null
set +e
conflicting_id_output=$(run_task "$legacy_compose" "$project-legacy" dev migrate-up 2>&1)
conflicting_id_status=$?
set -e
if [[ $conflicting_id_status == 0 ]]; then
  echo "local migration unexpectedly accepted a fixture ID with a different email" >&2
  exit 1
fi
assert_contains "$conflicting_id_output" "fixture identity conflict"
assert_eq "$(query "$legacy_compose" "$project-legacy" "SELECT count(*) FROM auth_schema_migration WHERE name = '0002_seed_auth_users.up.sql'")" "0"
assert_eq "$(query "$legacy_compose" "$project-legacy" "SELECT count(*) FROM auth_user WHERE id = '00000000-0000-0000-0000-0000000000a1' AND email = 'other-admin@example.com'")" "1"

# A partial exact set is completed without duplicate or mismatched identities.
reset_schema "$legacy_compose" "$project-legacy"
prepare_auth_schema "$legacy_compose" "$project-legacy"
query "$legacy_compose" "$project-legacy" "
  INSERT INTO auth_user (id, email) VALUES
    ('00000000-0000-0000-0000-0000000000a1', 'admin@example.com'),
    ('00000000-0000-0000-0000-0000000000b1', 'student1@example.com'),
    ('00000000-0000-0000-0000-0000000000c1', 'user@example.com')
" >/dev/null
partial_adopt=$(run_task "$legacy_compose" "$project-legacy" local migrate-up)
assert_contains "$partial_adopt" "applied 0002_seed_auth_users.up.sql"
assert_eq "$(query "$legacy_compose" "$project-legacy" 'SELECT count(*) FROM auth_user')" "7"
assert_eq "$(query "$legacy_compose" "$project-legacy" "SELECT count(*) FROM auth_schema_migration WHERE name = '0002_seed_auth_users.up.sql'")" "1"

# Sabotage one insert: post-apply verification must roll back rows and evidence.
reset_schema "$legacy_compose" "$project-legacy"
prepare_auth_schema "$legacy_compose" "$project-legacy"
query "$legacy_compose" "$project-legacy" "
  CREATE FUNCTION discard_one_fixture() RETURNS trigger LANGUAGE plpgsql AS \$\$
  BEGIN
    IF NEW.id = '00000000-0000-0000-0000-0000000000c1' THEN
      RETURN NULL;
    END IF;
    RETURN NEW;
  END
  \$\$;
  CREATE TRIGGER sabotage_fixture_insert BEFORE INSERT ON auth_user
  FOR EACH ROW EXECUTE FUNCTION discard_one_fixture()
" >/dev/null
set +e
sabotage_output=$(run_task "$legacy_compose" "$project-legacy" local migrate-up 2>&1)
sabotage_status=$?
set -e
if [[ $sabotage_status == 0 ]]; then
  echo "sabotaged seed migration unexpectedly recorded evidence" >&2
  exit 1
fi
assert_contains "$sabotage_output" "fixture seed verification failed"
assert_eq "$(query "$legacy_compose" "$project-legacy" 'SELECT count(*) FROM auth_user')" "0"
assert_eq "$(query "$legacy_compose" "$project-legacy" "SELECT count(*) FROM auth_schema_migration WHERE name = '0002_seed_auth_users.up.sql'")" "0"

# Evidence-time local sabotage must roll back normalized duplicates and seed evidence.
reset_schema "$legacy_compose" "$project-legacy"
prepare_auth_schema "$legacy_compose" "$project-legacy"
query "$legacy_compose" "$project-legacy" "
  CREATE TABLE auth_schema_migration (
    name text PRIMARY KEY,
    checksum text NOT NULL,
    down_checksum text,
    kind text NOT NULL CHECK (kind IN ('schema', 'local_seed')),
    applied_at timestamptz NOT NULL DEFAULT now()
  );
  CREATE FUNCTION inject_local_fixture_on_evidence() RETURNS trigger LANGUAGE plpgsql AS \$\$
  BEGIN
    IF NEW.name = '0002_seed_auth_users.up.sql' THEN
      INSERT INTO auth_user (id, email)
      VALUES ('10000000-0000-0000-0000-0000000000a1', ' Admin@Example.com ');
    END IF;
    RETURN NEW;
  END
  \$\$;
  CREATE TRIGGER sabotage_local_evidence_insert BEFORE INSERT ON auth_schema_migration
  FOR EACH ROW EXECUTE FUNCTION inject_local_fixture_on_evidence()
" >/dev/null
set +e
local_evidence_sabotage_output=$(run_task "$legacy_compose" "$project-legacy" local migrate-up 2>&1)
local_evidence_sabotage_status=$?
set -e
if [[ $local_evidence_sabotage_status == 0 ]]; then
  echo "local evidence-time fixture sabotage unexpectedly succeeded" >&2
  exit 1
fi
assert_contains "$local_evidence_sabotage_output" "fixture identity conflict"
assert_eq "$(query "$legacy_compose" "$project-legacy" "SELECT count(*) FROM auth_schema_migration WHERE name = '0002_seed_auth_users.up.sql'")" "0"
assert_eq "$(query "$legacy_compose" "$project-legacy" 'SELECT count(*) FROM auth_user')" "0"

# Production must reject exact legacy fixtures before adopting schema evidence.
reset_schema "$legacy_compose" "$project-legacy"
prepare_auth_schema "$legacy_compose" "$project-legacy"
apply_sql "$legacy_compose" "$project-legacy" "$repo_root/migrations/0002_seed_auth_users.up.sql"
set +e
prod_exact_fixture_output=$(run_task_default_env "$legacy_compose" "$project-legacy" migrate-up 2>&1)
prod_exact_fixture_status=$?
set -e
if [[ $prod_exact_fixture_status == 0 ]]; then
  echo "production migration unexpectedly adopted exact fixture identities" >&2
  exit 1
fi
assert_contains "$prod_exact_fixture_output" "fixture identities are not allowed outside MIGRATION_ENV=local or dev"
assert_eq "$(query "$legacy_compose" "$project-legacy" 'SELECT count(*) FROM auth_schema_migration')" "0"
assert_eq "$(query "$legacy_compose" "$project-legacy" 'SELECT count(*) FROM auth_user')" "7"

# Production must also reject a Unicode-space-normalized fixture email on a noncanonical ID.
reset_schema "$legacy_compose" "$project-legacy"
prepare_auth_schema "$legacy_compose" "$project-legacy"
query "$legacy_compose" "$project-legacy" \
  "INSERT INTO auth_user (id, email) VALUES ('10000000-0000-0000-0000-0000000000a1', U&'\\00A0Admin@Example.com\\00A0')" >/dev/null
set +e
prod_fixture_email_output=$(run_task_default_env "$legacy_compose" "$project-legacy" migrate-up 2>&1)
prod_fixture_email_status=$?
set -e
if [[ $prod_fixture_email_status == 0 ]]; then
  echo "production migration unexpectedly adopted a noncanonical fixture email" >&2
  exit 1
fi
assert_contains "$prod_fixture_email_output" "fixture identities are not allowed outside MIGRATION_ENV=local or dev"
assert_eq "$(query "$legacy_compose" "$project-legacy" 'SELECT count(*) FROM auth_schema_migration')" "0"
assert_eq "$(query "$legacy_compose" "$project-legacy" "SELECT count(*) FROM auth_user WHERE id = '10000000-0000-0000-0000-0000000000a1' AND email = U&'\\00A0Admin@Example.com\\00A0'")" "1"

# Evidence-time sabotage must not create a production fixture/evidence split state.
reset_schema "$legacy_compose" "$project-legacy"
prepare_auth_schema "$legacy_compose" "$project-legacy"
query "$legacy_compose" "$project-legacy" "
  CREATE TABLE auth_schema_migration (
    name text PRIMARY KEY,
    checksum text NOT NULL,
    down_checksum text,
    kind text NOT NULL CHECK (kind IN ('schema', 'local_seed')),
    applied_at timestamptz NOT NULL DEFAULT now()
  );
  CREATE FUNCTION inject_fixture_on_evidence() RETURNS trigger LANGUAGE plpgsql AS \$\$
  BEGIN
    IF NEW.name = '0001_init.up.sql' THEN
      INSERT INTO auth_user (id, email)
      VALUES ('10000000-0000-0000-0000-0000000000a1', 'admin@example.com');
    END IF;
    RETURN NEW;
  END
  \$\$;
  CREATE TRIGGER sabotage_evidence_insert BEFORE INSERT ON auth_schema_migration
  FOR EACH ROW EXECUTE FUNCTION inject_fixture_on_evidence()
" >/dev/null
set +e
prod_evidence_sabotage_output=$(run_task_default_env "$legacy_compose" "$project-legacy" migrate-up 2>&1)
prod_evidence_sabotage_status=$?
set -e
if [[ $prod_evidence_sabotage_status == 0 ]]; then
  echo "production evidence-time fixture sabotage unexpectedly succeeded" >&2
  exit 1
fi
assert_contains "$prod_evidence_sabotage_output" "fixture identities are not allowed outside MIGRATION_ENV=local or dev"
assert_eq "$(query "$legacy_compose" "$project-legacy" 'SELECT count(*) FROM auth_schema_migration')" "0"
assert_eq "$(query "$legacy_compose" "$project-legacy" 'SELECT count(*) FROM auth_user')" "0"

# Preserve untracked-down and rollback-checksum fail-closed protections.
reset_schema "$legacy_compose" "$project-legacy"
prepare_auth_schema "$legacy_compose" "$project-legacy"
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
