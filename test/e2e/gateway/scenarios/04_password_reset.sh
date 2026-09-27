#!/usr/bin/env bash
set -euo pipefail

AUTH_API="/api/auth/v1/auth"
TARANTOOL_API="/api/tarantool/v1"
wiki_ref="wiki/AUTHENTICATION.md"

email="${E2E_EMAIL}"
new_password="E2E-ResetPassword-123!"

# The public start endpoint must remain callable without an access token.
start_body="$(jq -nc --arg email "${email}" '{email:$email}')"
start_raw="$(http_json POST "${AUTH_API}/password/reset/start" "${start_body}")"
start_status="$(printf '%s\n' "${start_raw}" | extract_status)"
start_resp="$(printf '%s\n' "${start_raw}" | extract_body)"

if [[ "${start_status}" != "202" ]]; then
  record_mismatch "ms-go-auth" "${wiki_ref} (Password reset: start)" "HTTP 202 + data.uuid" "HTTP ${start_status}" "POST ${AUTH_API}/password/reset/start resp=${start_resp}" "blocker" "ms-go-auth/ms-go-tarantool"
  return 1
fi
if ! echo "${start_resp}" | jq -e '.data.uuid? | length > 0' >/dev/null 2>&1; then
  record_mismatch "ms-go-auth" "${wiki_ref} (Password reset: start)" "response contains data.uuid" "data.uuid absent" "POST ${AUTH_API}/password/reset/start resp=${start_resp}" "blocker" "ms-go-auth/ms-go-tarantool"
  return 1
fi
record_ok "auth password/reset/start returns 202 with uuid"

# In integration mode, obtain a deterministic reset code from the verification
# service. This mirrors the signup scenario's code hook.
tara_body="$(jq -nc --arg email "${email}" '{value:{email:$email}}')"
tara_raw="$(http_json POST "${TARANTOOL_API}/password-reset-start" "${tara_body}")"
tara_status="$(printf '%s\n' "${tara_raw}" | extract_status)"
tara_resp="$(printf '%s\n' "${tara_raw}" | extract_body)"

if [[ "${tara_status}" != "200" ]]; then
  record_mismatch "ms-go-tarantool" "${wiki_ref} (Password reset: code)" "HTTP 200 from Tarantool test hook" "HTTP ${tara_status}" "POST ${TARANTOOL_API}/password-reset-start resp=${tara_resp}" "blocker" "ms-go-tarantool/ms-gateway"
  return 1
fi
reset_code="$(echo "${tara_resp}" | jq -r '.code // empty')"
if [[ -z "${reset_code}" ]]; then
  record_mismatch "ms-go-tarantool" "${wiki_ref} (Password reset: code)" "integration response includes code" "code absent" "POST ${TARANTOOL_API}/password-reset-start resp=${tara_resp}" "blocker" "ms-go-tarantool"
  return 1
fi
record_ok "tarantool provides password reset code"

finish_body="$(jq -nc --arg email "${email}" --arg code "${reset_code}" --arg password "${new_password}" '{email:$email,code:$code,new_password:$password}')"
finish_raw="$(http_json POST "${AUTH_API}/password/reset/finish" "${finish_body}")"
finish_status="$(printf '%s\n' "${finish_raw}" | extract_status)"
finish_resp="$(printf '%s\n' "${finish_raw}" | extract_body)"

if [[ "${finish_status}" != "200" ]]; then
  record_mismatch "ms-go-auth" "${wiki_ref} (Password reset: finish)" "HTTP 200 + data.status=ok" "HTTP ${finish_status}" "POST ${AUTH_API}/password/reset/finish resp=${finish_resp}" "blocker" "ms-go-auth/ms-go-tarantool"
  return 1
fi
if ! echo "${finish_resp}" | jq -e '.data.status == "ok"' >/dev/null 2>&1; then
  record_mismatch "ms-go-auth" "${wiki_ref} (Password reset: finish)" "data.status=ok" "status missing or not ok" "POST ${AUTH_API}/password/reset/finish resp=${finish_resp}" "blocker" "ms-go-auth"
  return 1
fi
record_ok "auth password/reset/finish returns 200"

signin_body="$(jq -nc --arg email "${email}" --arg password "${new_password}" '{email:$email,password:$password}')"
signin_raw="$(http_json POST "${AUTH_API}/signin" "${signin_body}")"
signin_status="$(printf '%s\n' "${signin_raw}" | extract_status)"
signin_resp="$(printf '%s\n' "${signin_raw}" | extract_body)"

if [[ "${signin_status}" != "200" ]]; then
  record_mismatch "ms-go-auth" "${wiki_ref} (Password reset: signin)" "HTTP 200 with reset password" "HTTP ${signin_status}" "POST ${AUTH_API}/signin resp=${signin_resp}" "blocker" "ms-go-auth"
  return 1
fi
record_ok "auth signin works with reset password"

return 0
