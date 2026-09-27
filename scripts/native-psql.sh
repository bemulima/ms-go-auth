#!/usr/bin/env bash
# Run the existing auth migration script from macOS through the psql client
# already present in the shared PostgreSQL container. The client receives the
# DSN through its environment; no credential is printed or placed in argv.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
infra_root=${LW_INFRA_ROOT:-"$repo_root/../../learning-platform-infrastructure"}
compose_file=${LW_INFRA_COMPOSE_FILE:-"$infra_root/compose.yaml"}

if [[ -z ${AUTH_MIGRATION_DSN:-} ]]; then
  echo "AUTH_MIGRATION_DSN is required for native migrations" >&2
  exit 2
fi
if [[ ! -f $compose_file ]]; then
  echo "shared infrastructure Compose file is unavailable: $compose_file" >&2
  exit 2
fi

# Taskfile.yml exports selectors for this repository's standalone Compose
# project. They would make the shared-infrastructure client look for a
# non-existent `ms-go-auth` platform-postgres container.
unset COMPOSE_FILE COMPOSE_PROJECT_NAME

# Compose evaluates all declared services before selecting platform-postgres.
# This sentinel mirrors the native infrastructure lifecycle and applies only
# to this process when a non-started Planner path lacks its release token.
if [[ -z ${LW_PLANNER_ONBOARDING_HANDOFF_TOKEN+x} ]]; then
  export LW_PLANNER_ONBOARDING_HANDOFF_TOKEN=native-infra-not-started
fi

exec docker compose --project-directory "$infra_root" -f "$compose_file" \
  exec -T -e AUTH_MIGRATION_DSN platform-postgres \
  sh -ec 'exec psql --dbname "$AUTH_MIGRATION_DSN" "$@"' native-psql "$@"
