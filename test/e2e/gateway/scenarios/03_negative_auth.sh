#!/usr/bin/env bash
set -euo pipefail

wiki_ref="wiki/AUTHENTICATION.md"

AUTH_API="/api/auth/v1/auth"
TARANTOOL_API="/api/tarantool/v1"

# 1) Invalid signup payload → 400
bad_body="$(jq -nc --arg email "not-an-email" --arg password "123" '{email:$email,password:$password}')"
bad_raw="$(http_json POST "${AUTH_API}/signup/start" "${bad_body}")"
bad_status="$(printf '%s\n' "${bad_raw}" | extract_status)"
bad_resp="$(printf '%s\n' "${bad_raw}" | extract_body)"
if [[ "${bad_status}" != "400" ]]; then
  record_mismatch "ms-go-auth" "${wiki_ref} (signup/start invalid)" "HTTP 400" "HTTP ${bad_status}" "POST ${AUTH_API}/signup/start resp=${bad_resp}" "major" "ms-go-auth"
  return 0
fi
record_ok "auth signup/start rejects invalid payload (400)"

# 2) Wrong password → 401
email="e2e-auth-neg-$(date +%s)-$RANDOM@example.com"
password="E2E-Password-123!"

start_body="$(jq -nc --arg email "${email}" --arg password "${password}" '{email:$email,password:$password}')"
start_raw="$(http_json POST "${AUTH_API}/signup/start" "${start_body}")"
start_status="$(printf '%s\n' "${start_raw}" | extract_status)"
start_resp="$(printf '%s\n' "${start_raw}" | extract_body)"
if [[ "${start_status}" != "202" ]]; then
  record_mismatch "ms-go-auth" "${wiki_ref} (signup/start)" "HTTP 202" "HTTP ${start_status}" "POST ${AUTH_API}/signup/start resp=${start_resp}" "blocker" "ms-go-auth"
  return 0
fi

tara_body="$(jq -nc --arg email "${email}" '{value:{email:$email,password:""}}')"
tara_raw="$(http_json POST "${TARANTOOL_API}/set-new-user" "${tara_body}")"
tara_status="$(printf '%s\n' "${tara_raw}" | extract_status)"
tara_resp="$(printf '%s\n' "${tara_raw}" | extract_body)"
if [[ "${tara_status}" != "200" ]]; then
  record_mismatch "ms-go-tarantool" "${wiki_ref} (signup/code)" "HTTP 200" "HTTP ${tara_status}" "POST ${TARANTOOL_API}/set-new-user resp=${tara_resp}" "blocker" "ms-go-tarantool"
  return 0
fi
code="$(echo "${tara_resp}" | jq -r '.code // empty')"
if [[ -z "${code}" ]]; then
  record_mismatch "ms-go-tarantool" "${wiki_ref} (signup/code)" "в E2E доступен code (APP_ENV=integration)" "code отсутствует" "POST ${TARANTOOL_API}/set-new-user resp=${tara_resp}" "blocker" "ms-go-tarantool"
  return 0
fi

verify_body="$(jq -nc --arg email "${email}" --arg code "${code}" '{email:$email,code:$code}')"
verify_raw="$(http_json POST "${AUTH_API}/signup/verify" "${verify_body}")"
verify_status="$(printf '%s\n' "${verify_raw}" | extract_status)"
verify_resp="$(printf '%s\n' "${verify_raw}" | extract_body)"
if [[ "${verify_status}" != "200" ]]; then
  record_mismatch "ms-go-auth" "${wiki_ref} (signup/verify)" "HTTP 200" "HTTP ${verify_status}" "POST ${AUTH_API}/signup/verify resp=${verify_resp}" "blocker" "ms-go-auth"
  return 0
fi

wrong_signin_body="$(jq -nc --arg email "${email}" --arg password "Wrong-Password-123!" '{email:$email,password:$password}')"
wrong_signin_raw="$(http_json POST "${AUTH_API}/signin" "${wrong_signin_body}")"
wrong_signin_status="$(printf '%s\n' "${wrong_signin_raw}" | extract_status)"
wrong_signin_resp="$(printf '%s\n' "${wrong_signin_raw}" | extract_body)"
if [[ "${wrong_signin_status}" != "401" ]]; then
  record_mismatch "ms-go-auth" "${wiki_ref} (signin invalid)" "HTTP 401" "HTTP ${wrong_signin_status}" "POST ${AUTH_API}/signin resp=${wrong_signin_resp}" "major" "ms-go-auth"
  return 0
fi
record_ok "auth signin rejects wrong password (401)"

return 0
