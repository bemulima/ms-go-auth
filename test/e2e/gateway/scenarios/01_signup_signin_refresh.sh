#!/usr/bin/env bash
set -euo pipefail

AUTH_API="/api/auth/v1/auth"

wiki_ref="wiki/AUTHENTICATION.md"

email="${E2E_EMAIL}"
password="${E2E_PASSWORD}"

body="$(jq -nc --arg email "${email}" --arg password "${password}" '{email:$email,password:$password}')"
raw="$(http_json POST "${AUTH_API}/signup/start" "${body}")"
status="$(printf '%s\n' "${raw}" | extract_status)"
resp="$(printf '%s\n' "${raw}" | extract_body)"

if [[ "${status}" != "202" ]]; then
  record_mismatch "ms-go-auth" "${wiki_ref} (Регистрация: start)" "HTTP 202" "HTTP ${status}" "POST ${AUTH_API}/signup/start body=${body} resp=${resp}" "blocker" "ms-go-auth"
  return 1
fi
record_ok "auth signup/start returns 202"

if ! echo "${resp}" | jq -e '.message? | length > 0' >/dev/null 2>&1; then
  record_mismatch "ms-go-auth" "${wiki_ref} (Регистрация: start)" "response содержит message=\"verification code sent\"" "response не содержит поля message" "POST ${AUTH_API}/signup/start → 202 resp=${resp}" "major" "wiki/ms-go-auth"
fi

# Получение кода подтверждения (детерминизм для E2E): используем закрытый изолированный fixture.
code="$(verification_code "signup" "${email}")" || return 1
record_ok "owned isolated fixture provides verification code without a public provider API"

verify_body="$(jq -nc --arg email "${email}" --arg code "${code}" '{email:$email,code:$code}')"
verify_raw="$(http_json POST "${AUTH_API}/signup/verify" "${verify_body}")"
verify_status="$(printf '%s\n' "${verify_raw}" | extract_status)"
verify_resp="$(printf '%s\n' "${verify_raw}" | extract_body)"

if [[ "${verify_status}" != "200" ]]; then
  record_mismatch "ms-go-auth" "${wiki_ref} (Регистрация: verify)" "HTTP 200 + tokens" "HTTP ${verify_status}" "POST ${AUTH_API}/signup/verify resp=${verify_resp}" "blocker" "ms-go-auth"
  return 1
fi
record_ok "auth signup/verify returns 200"

access_token="$(echo "${verify_resp}" | jq -r '.access_token // empty')"
refresh_token="$(echo "${verify_resp}" | jq -r '.refresh_token // empty')"
if [[ -z "${access_token}" || -z "${refresh_token}" ]]; then
  record_mismatch "ms-go-auth" "${wiki_ref} (Регистрация: verify)" "tokens.access_token и tokens.refresh_token присутствуют" "токены отсутствуют/пустые" "POST ${AUTH_API}/signup/verify → 200 resp=${verify_resp}" "blocker" "ms-go-auth"
  return 1
fi
record_ok "auth returns access+refresh tokens"

# SignIn
signin_body="$(jq -nc --arg email "${email}" --arg password "${password}" '{email:$email,password:$password}')"
signin_raw="$(http_json POST "${AUTH_API}/signin" "${signin_body}")"
signin_status="$(printf '%s\n' "${signin_raw}" | extract_status)"
signin_resp="$(printf '%s\n' "${signin_raw}" | extract_body)"

if [[ "${signin_status}" != "200" ]]; then
  record_mismatch "ms-go-auth" "${wiki_ref} (Авторизация)" "HTTP 200 + tokens" "HTTP ${signin_status}" "POST ${AUTH_API}/signin resp=${signin_resp}" "blocker" "ms-go-auth"
  return 1
fi
record_ok "auth signin returns 200"

signin_refresh="$(echo "${signin_resp}" | jq -r '.refresh_token // empty')"
if [[ -n "${signin_refresh}" ]]; then
  refresh_token="${signin_refresh}"
fi

# Refresh
refresh_body="$(jq -nc --arg rt "${refresh_token}" '{refresh_token:$rt}')"
refresh_raw="$(http_json POST "${AUTH_API}/refresh" "${refresh_body}")"
refresh_status="$(printf '%s\n' "${refresh_raw}" | extract_status)"
refresh_resp="$(printf '%s\n' "${refresh_raw}" | extract_body)"

if [[ "${refresh_status}" != "200" ]]; then
  record_mismatch "ms-go-auth" "${wiki_ref} (Refresh)" "HTTP 200 + new tokens" "HTTP ${refresh_status}" "POST ${AUTH_API}/refresh resp=${refresh_resp}" "major" "ms-go-auth"
  return 1
fi
record_ok "auth refresh returns 200"

echo "${refresh_resp}" | jq -e '.access_token? and .refresh_token?' >/dev/null 2>&1 || {
  record_mismatch "ms-go-auth" "${wiki_ref} (Refresh)" "response содержит access_token и refresh_token" "response не содержит токены" "POST ${AUTH_API}/refresh → 200 resp=${refresh_resp}" "major" "ms-go-auth"
  return 1
}
record_ok "refresh response contains tokens"

export E2E_ACCESS_TOKEN="${access_token}"
export E2E_REFRESH_TOKEN="${refresh_token}"

return 0
