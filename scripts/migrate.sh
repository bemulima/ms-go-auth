#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
compose_file=${COMPOSE_FILE:-$repo_root/docker-compose.yml}
compose_project=${COMPOSE_PROJECT_NAME:-ms-go-auth}
db_service=${DB_SERVICE:-postgres}
db_user=${AUTH_DB_USER:-app}
db_name=${AUTH_DB_NAME:-authdb}
migration_env=${MIGRATION_ENV:-production}
action=${1:-}
evidence_available=false
fixture_values_sql="
  ('00000000-0000-0000-0000-0000000000a1'::uuid, 'admin@example.com'::text),
  ('00000000-0000-0000-0000-0000000000a2'::uuid, 'manager@example.com'::text),
  ('00000000-0000-0000-0000-0000000000a3'::uuid, 'teacher@example.com'::text),
  ('00000000-0000-0000-0000-0000000000b1'::uuid, 'student1@example.com'::text),
  ('00000000-0000-0000-0000-0000000000b2'::uuid, 'student2@example.com'::text),
  ('00000000-0000-0000-0000-0000000000b3'::uuid, 'student3@example.com'::text),
  ('00000000-0000-0000-0000-0000000000c1'::uuid, 'user@example.com'::text)
"
fixture_trim_chars_sql="
  ' ' || chr(9) || chr(10) || chr(11) || chr(12) || chr(13) ||
  chr(133) || chr(160) || chr(5760) || chr(8192) || chr(8193) ||
  chr(8194) || chr(8195) || chr(8196) || chr(8197) || chr(8198) ||
  chr(8199) || chr(8200) || chr(8201) || chr(8202) || chr(8232) ||
  chr(8233) || chr(8239) || chr(8287) || chr(12288)
"

compose=(docker compose -p "$compose_project" -f "$compose_file")
psql=("${compose[@]}" exec -T "$db_service" psql -X -U "$db_user" -d "$db_name" -v ON_ERROR_STOP=1)

usage() {
  echo "usage: MIGRATION_ENV=<local|dev|production> $0 <up|down|status>" >&2
  exit 2
}

checksum() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d ' ' -f 1
  else
    shasum -a 256 "$1" | cut -d ' ' -f 1
  fi
}

is_local_seed() {
  [[ $1 == *_seed_*.up.sql ]]
}

seed_enabled() {
  [[ $migration_env == local || $migration_env == dev ]]
}

write_fixture_preflight_sql() {
  printf '\nDO $fixture_preflight$\nBEGIN\n  LOCK TABLE auth_user IN SHARE ROW EXCLUSIVE MODE;\n  IF EXISTS (\n    WITH fixture(id, email) AS (VALUES %s)\n    SELECT 1\n    FROM auth_user AS auth\n    JOIN fixture ON auth.id = fixture.id OR lower(btrim(auth.email, %s)) = fixture.email\n    WHERE auth.id <> fixture.id OR auth.email <> fixture.email\n  ) THEN\n    RAISE EXCEPTION '\''fixture identity conflict: canonical seed IDs and emails must match exactly'\'';\n  END IF;\nEND\n$fixture_preflight$;\n' "$fixture_values_sql" "$fixture_trim_chars_sql"
}

write_fixture_verification_sql() {
  printf '\nDO $fixture_verify$\nBEGIN\n  IF (\n    WITH fixture(id, email) AS (VALUES %s)\n    SELECT count(*)\n    FROM fixture\n    JOIN auth_user AS auth ON auth.id = fixture.id AND auth.email = fixture.email\n  ) <> 7 THEN\n    RAISE EXCEPTION '\''fixture seed verification failed: all seven canonical identities must exist'\'';\n  END IF;\nEND\n$fixture_verify$;\n' "$fixture_values_sql"
}

write_production_fixture_guard_sql() {
  printf '\nDO $production_fixture_guard$\nBEGIN\n  IF to_regclass('\''public.auth_user'\'') IS NOT NULL THEN\n    EXECUTE '\''LOCK TABLE auth_user IN SHARE ROW EXCLUSIVE MODE'\'';\n    IF EXISTS (\n      WITH fixture(id, email) AS (VALUES %s)\n      SELECT 1\n      FROM auth_user AS auth\n      JOIN fixture ON auth.id = fixture.id OR lower(btrim(auth.email, %s)) = fixture.email\n    ) THEN\n      RAISE EXCEPTION '\''fixture identities are not allowed outside MIGRATION_ENV=local or dev'\'';\n    END IF;\n  END IF;\nEND\n$production_fixture_guard$;\n' "$fixture_values_sql" "$fixture_trim_chars_sql"
}

ensure_connection() {
  local attempt
  for attempt in $(seq 1 60); do
    if "${psql[@]}" -tAc 'SELECT 1' >/dev/null 2>&1; then
      return
    fi
    sleep 1
  done
  echo "auth database '$db_name' on service '$db_service' is not ready in compose project '$compose_project'" >&2
  exit 1
}

ensure_evidence_table() {
  "${psql[@]}" -q -c '
    CREATE TABLE IF NOT EXISTS auth_schema_migration (
      name text PRIMARY KEY,
      checksum text NOT NULL,
      down_checksum text,
      kind text NOT NULL CHECK (kind IN ('\''schema'\'', '\''local_seed'\'')),
      applied_at timestamptz NOT NULL DEFAULT now()
    );
    ALTER TABLE auth_schema_migration ADD COLUMN IF NOT EXISTS down_checksum text;
  '
  evidence_available=true
}

evidence_table_exists() {
  [[ $("${psql[@]}" -tAc "SELECT to_regclass('public.auth_schema_migration') IS NOT NULL") == t ]]
}

owned_schema_exists() {
  [[ $("${psql[@]}" -tAc "
    SELECT EXISTS (
      SELECT 1
      FROM unnest(ARRAY['auth_user', 'auth_identity', 'auth_refresh_token', 'auth_oauth_transaction']) AS relation_name
      WHERE to_regclass('public.' || relation_name) IS NOT NULL
    )
  ") == t ]]
}

applied_checksum() {
  if [[ $evidence_available != true ]]; then
    return 0
  fi
  printf "SELECT checksum FROM auth_schema_migration WHERE name = :'migration_name';\n" | \
    "${psql[@]}" -tA -v migration_name="$1"
}

applied_down_checksum() {
  if [[ $evidence_available != true ]]; then
    return 0
  fi
  printf "SELECT COALESCE(down_checksum, '') FROM auth_schema_migration WHERE name = :'migration_name';\n" | \
    "${psql[@]}" -tA -v migration_name="$1"
}

applied_names() {
  [[ $evidence_available == true ]] || return 0
  "${psql[@]}" -tAc 'SELECT name FROM auth_schema_migration ORDER BY name'
}

unknown_applied_names() {
  local name
  while IFS= read -r name; do
    [[ -n $name ]] || continue
    if [[ ! $name =~ ^[0-9]+_[A-Za-z0-9_]+\.up\.sql$ || ! -f $repo_root/migrations/$name ]]; then
      printf '%s\n' "$name"
    fi
  done < <(applied_names)
}

ensure_no_unknown_evidence() {
  local unknown
  unknown=$(unknown_applied_names)
  if [[ -n $unknown ]]; then
    echo "unknown applied migration ${unknown%%$'\n'*}" >&2
    exit 1
  fi
}

apply_file() {
  local file=$1 name down_file expected down_expected actual kind
  name=$(basename "$file")
  down_file=${file%.up.sql}.down.sql
  if [[ ! -f $down_file ]]; then
    echo "missing rollback for $name" >&2
    exit 1
  fi
  expected=$(checksum "$file")
  down_expected=$(checksum "$down_file")
  kind=schema
  if is_local_seed "$name"; then
    kind=local_seed
    if ! seed_enabled; then
      echo "skipped local/dev seed $name ($migration_env)"
      return
    fi
  fi

  actual=$(applied_checksum "$name")
  if [[ -n $actual ]]; then
    if [[ $actual != "$expected" ]]; then
      echo "checksum mismatch for applied migration $name" >&2
      exit 1
    fi
    actual=$(applied_down_checksum "$name")
    if [[ $actual != "$down_expected" ]]; then
      echo "rollback checksum mismatch for applied migration $name" >&2
      exit 1
    fi
    echo "already applied $name"
    return
  fi

  {
    printf 'BEGIN;\n'
    if [[ $kind == schema ]] && ! seed_enabled; then
      write_production_fixture_guard_sql
    fi
    if [[ $kind == local_seed ]]; then
      write_fixture_preflight_sql
    fi
    command cat "$file"
    if [[ $kind == local_seed ]]; then
      write_fixture_verification_sql
    fi
    if [[ $kind == schema ]] && ! seed_enabled; then
      write_production_fixture_guard_sql
    fi
    printf "\nINSERT INTO auth_schema_migration (name, checksum, down_checksum, kind) VALUES (:'migration_name', :'migration_checksum', :'down_checksum', :'migration_kind');\n"
    if [[ $kind == local_seed ]]; then
      write_fixture_preflight_sql
      write_fixture_verification_sql
    fi
    if [[ $kind == schema ]] && ! seed_enabled; then
      write_production_fixture_guard_sql
    fi
    printf 'COMMIT;\n'
  } | "${psql[@]}" -q \
      -v migration_name="$name" \
      -v migration_checksum="$expected" \
      -v down_checksum="$down_expected" \
      -v migration_kind="$kind"
  echo "applied $name"
}

migrate_up() {
  local file
  ensure_no_unknown_evidence
  if ! seed_enabled && [[ $("${psql[@]}" -tAc "SELECT EXISTS (SELECT 1 FROM auth_schema_migration WHERE kind = 'local_seed')") == t ]]; then
    echo "local seed migration evidence is not allowed outside MIGRATION_ENV=local or dev" >&2
    exit 1
  fi
  for file in "$repo_root"/migrations/*.up.sql; do
    apply_file "$file"
  done
}

migrate_down() {
  local up_file down_file name expected down_expected actual actual_down applied_count files=()
  if ! evidence_table_exists; then
    if owned_schema_exists; then
      echo "legacy migration state is untracked; run migrate-up first to adopt idempotent migrations before rollback" >&2
      exit 1
    fi
    echo "no applied auth migrations"
    return
  fi
  evidence_available=true
  applied_count=$("${psql[@]}" -tAc 'SELECT count(*) FROM auth_schema_migration')
  if [[ $applied_count == 0 ]]; then
    if owned_schema_exists; then
      echo "migration evidence is empty while owned auth tables exist; run migrate-up to adopt before rollback" >&2
      exit 1
    fi
    echo "no applied auth migrations"
    return
  fi
  ensure_no_unknown_evidence
  if ! seed_enabled && [[ $("${psql[@]}" -tAc "SELECT EXISTS (SELECT 1 FROM auth_schema_migration WHERE kind = 'local_seed')") == t ]]; then
    echo "local seed migration evidence requires MIGRATION_ENV=local or dev for rollback" >&2
    exit 1
  fi
  for up_file in "$repo_root"/migrations/*.up.sql; do
    files+=("$up_file")
  done

  # Validate the complete rollback chain before executing any destructive SQL.
  for ((i=${#files[@]}-1; i>=0; i--)); do
    up_file=${files[$i]}
    name=$(basename "$up_file")
    actual=$(applied_checksum "$name")
    [[ -n $actual ]] || continue
    expected=$(checksum "$up_file")
    if [[ $actual != "$expected" ]]; then
      echo "checksum mismatch for applied migration $name" >&2
      exit 1
    fi
    down_file=${up_file%.up.sql}.down.sql
    if [[ ! -f $down_file ]]; then
      echo "missing rollback for $name" >&2
      exit 1
    fi
    down_expected=$(checksum "$down_file")
    actual_down=$(applied_down_checksum "$name")
    if [[ $actual_down != "$down_expected" ]]; then
      echo "rollback checksum mismatch for applied migration $name" >&2
      exit 1
    fi
  done

  for ((i=${#files[@]}-1; i>=0; i--)); do
    up_file=${files[$i]}
    name=$(basename "$up_file")
    actual=$(applied_checksum "$name")
    [[ -n $actual ]] || continue
    down_file=${up_file%.up.sql}.down.sql
    {
      printf 'BEGIN;\n'
      command cat "$down_file"
      printf '\nDELETE FROM auth_schema_migration WHERE name = :'"'"'migration_name'"'"';\nCOMMIT;\n'
    } | "${psql[@]}" -q -v migration_name="$name"
    echo "rolled back $name"
  done
}

migration_status() {
  local file down_file name expected down_expected actual actual_down state
  if evidence_table_exists; then
    evidence_available=true
  fi
  printf '%-36s %-24s %s\n' MIGRATION STATUS CHECKSUM
  for file in "$repo_root"/migrations/*.up.sql; do
    name=$(basename "$file")
    expected=$(checksum "$file")
    actual=$(applied_checksum "$name")
    if [[ -n $actual ]]; then
      if [[ $actual != "$expected" ]]; then
        state='checksum mismatch'
      else
        down_file=${file%.up.sql}.down.sql
        if [[ ! -f $down_file ]]; then
          state='missing rollback'
        else
          down_expected=$(checksum "$down_file")
          actual_down=$(applied_down_checksum "$name")
          [[ $actual_down == "$down_expected" ]] && state=applied || state='rollback checksum mismatch'
        fi
      fi
    elif is_local_seed "$name" && ! seed_enabled; then
      state="excluded ($migration_env)"
    else
      state=pending
    fi
    printf '%-36s %-24s %.12s\n' "$name" "$state" "$expected"
  done
  if [[ $evidence_available == true ]]; then
    while IFS= read -r name; do
      [[ -n $name ]] || continue
      actual=$(applied_checksum "$name")
      printf '%-36s %-24s %.12s\n' "$name" 'unknown applied migration' "$actual"
    done < <(unknown_applied_names)
  fi
}

[[ -n $action ]] || usage
ensure_connection
case "$action" in
  up)
    ensure_evidence_table
    migrate_up
    ;;
  down) migrate_down ;;
  status) migration_status ;;
  *) usage ;;
esac
