#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

GATEWAY_URL="${GATEWAY_URL:-http://localhost:8080}"
ADMIN_GATEWAY_URL="${ADMIN_GATEWAY_URL:-http://localhost:9090}"
HTTP_TIMEOUT="${HTTP_TIMEOUT:-30}"
DEBUG="${DEBUG:-0}"
MISMATCHES_OUT="${MISMATCHES_OUT:-}"
STATS_OUT="${STATS_OUT:-}"
CHECKLIST_OUT="${CHECKLIST_OUT:-}"

E2E_RUN_ID="${E2E_RUN_ID:-$(date +%s)}"
E2E_EMAIL="${E2E_EMAIL:-e2e-${E2E_RUN_ID}-$RANDOM@example.com}"
E2E_PASSWORD="${E2E_PASSWORD:-E2E-Password-123!}"

export GATEWAY_URL ADMIN_GATEWAY_URL HTTP_TIMEOUT DEBUG MISMATCHES_OUT
export STATS_OUT
export CHECKLIST_OUT
export E2E_RUN_ID E2E_EMAIL E2E_PASSWORD

RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
NC=$'\033[0m'

log_info() { echo "${GREEN}[INFO]${NC} $*"; }
log_warn() { echo "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo "${RED}[ERROR]${NC} $*"; }
log_debug() { [[ "${DEBUG}" == "1" ]] && echo "[DEBUG] $*"; }

append_check() {
  local line="$1"
  [[ -n "${CHECKLIST_OUT}" ]] || return 0
  echo "${line}" >>"${CHECKLIST_OUT}"
}

sanitize_evidence() {
  local evidence="$1"
  if [[ "${evidence}" == *"resp=<html"* || "${evidence}" == *"resp=<HTML"* ]]; then
    echo "${evidence%%resp=*}resp=[HTML omitted]"
    return 0
  fi
  echo "${evidence}" | sed -E 's/<[^>]+>//g' | tr '\n' ' ' | sed -E 's/[[:space:]]+/ /g'
}

suggest_fixes() {
  local component="$1"
  local wiki_ref="$2"
  local expected="$3"
  local observed="$4"

  if [[ "${observed}" == *"response обёрнут в data"* ]]; then
    cat <<'EOF'
  - Обновить wiki под фактический формат: `{"data": ...}`.
  - Либо изменить сервисные ответы, чтобы поля были на верхнем уровне.
  - Либо на клиенте принимать оба формата.
EOF
    return 0
  fi

  cat <<'EOF'
  - Уточнить, что является источником истины (wiki или реализация) и синхронизировать одно из двух.
EOF
}

check_deps() {
  command -v curl >/dev/null 2>&1 || { log_error "curl required"; exit 1; }
  command -v jq >/dev/null 2>&1 || { log_error "jq required"; exit 1; }
}

check_gateway() {
  log_info "Checking gateway ${GATEWAY_URL}..."
  if ! curl -fsS --max-time "${HTTP_TIMEOUT}" "${GATEWAY_URL}/healthz" >/dev/null; then
    log_error "Gateway not responding at ${GATEWAY_URL}"
    exit 1
  fi
}

record_mismatch() {
  local component="$1"
  local wiki_ref="$2"
  local expected="$3"
  local observed="$4"
  local evidence="$5"
  local severity="$6"
  local fix_repo="$7"

  E2E_MISMATCHES=$((E2E_MISMATCHES + 1))
  echo "${RED}✗${NC} (${severity}) ${component}: ${wiki_ref} | ${expected} → ${observed}"
  append_check "- ❌ [ms-go-auth/${E2E_SCENARIO:-unknown}] ${wiki_ref} — ${expected} → ${observed}"

  if [[ -n "${MISMATCHES_OUT}" ]]; then
    local fixes
    fixes="$(suggest_fixes "${component}" "${wiki_ref}" "${expected}" "${observed}")"
    evidence="$(sanitize_evidence "${evidence}")"
    {
      echo ""
      echo "## $(date +%Y%m%d-%H%M%S). ${component}: ${wiki_ref}"
      echo "- Компонент: ${component}"
      echo "- Wiki: \`${wiki_ref}\`"
      echo "- Ожидание (wiki): ${expected}"
      echo "- Наблюдение (факт): ${observed}"
      echo "- Доказательство: ${evidence}"
      echo "- Severity: ${severity}"
      echo "- Куда фиксить: ${fix_repo}"
      echo "- Варианты решения:"
      echo "${fixes}"
    } >>"${MISMATCHES_OUT}"
  fi
}

record_ok() {
  local what="$1"
  E2E_OK=$((E2E_OK + 1))
  echo "${GREEN}✓${NC} ${what}"
  append_check "- ✅ [ms-go-auth/${E2E_SCENARIO:-unknown}] ${what}"
}

http_json() {
  local method="$1"
  local path="$2"
  local body="${3:-}"
  local auth_header="${4:-}"

  local tmp
  tmp="$(mktemp)"
  local code

  local curl_args=(
    -sS
    --max-time "${HTTP_TIMEOUT}"
    -o "${tmp}"
    -w "%{http_code}"
    -X "${method}"
    -H "Content-Type: application/json"
  )
  [[ -n "${auth_header}" ]] && curl_args+=(-H "Authorization: Bearer ${auth_header}")
  [[ -n "${body}" ]] && curl_args+=(-d "${body}")
  curl_args+=("${GATEWAY_URL}${path}")

  log_debug "${method} ${path}"
  code="$(curl "${curl_args[@]}")" || { rm -f "${tmp}"; return 2; }
  cat "${tmp}"
  rm -f "${tmp}"
  echo ""
  echo "__HTTP_STATUS__=${code}"
}

extract_status() {
  awk -F= '/^__HTTP_STATUS__=/{print $2}'
}

extract_body() {
  sed '/^__HTTP_STATUS__=/d'
}

run_scenarios() {
  local scenarios_dir="${SCRIPT_DIR}/scenarios"
  local failed=0

  for scenario in "${scenarios_dir}"/*.sh; do
    [[ -f "${scenario}" ]] || continue
    export E2E_SCENARIO
    E2E_SCENARIO="$(basename "${scenario}")"
    log_info "Running $(basename "${scenario}")..."
    # shellcheck disable=SC1090
    if source "${scenario}"; then
      log_info "✓ $(basename "${scenario}") passed"
    else
      log_error "✗ $(basename "${scenario}") failed"
      ((failed++))
    fi
  done

  return "${failed}"
}

main() {
  log_info "Starting E2E Gateway tests for ms-go-auth"
  log_info "E2E_EMAIL=${E2E_EMAIL}"

  E2E_OK=0
  E2E_MISMATCHES=0

  check_deps
  check_gateway

  if run_scenarios; then
    log_info "All tests passed"
    log_info "Stats: ok=${E2E_OK} mismatches=${E2E_MISMATCHES}"
    if [[ -n "${STATS_OUT}" ]]; then
      printf "ms-go-auth ok=%s mismatches=%s\n" "${E2E_OK}" "${E2E_MISMATCHES}" >>"${STATS_OUT}"
    fi
    exit 0
  fi

  log_error "Some tests failed"
  log_info "Stats: ok=${E2E_OK} mismatches=${E2E_MISMATCHES}"
  if [[ -n "${STATS_OUT}" ]]; then
    printf "ms-go-auth ok=%s mismatches=%s\n" "${E2E_OK}" "${E2E_MISMATCHES}" >>"${STATS_OUT}"
  fi
  exit 1
}

export -f log_info log_warn log_error log_debug
export -f record_mismatch record_ok http_json extract_status extract_body

main "$@"
