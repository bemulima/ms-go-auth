#!/usr/bin/env bash
set -euo pipefail

AUTH_API="/api/auth/v1/auth"
wiki_ref="wiki/AUTHENTICATION.md"

email="${E2E_EMAIL}"
old_password="${E2E_PASSWORD}"
access_token="${E2E_ACCESS_TOKEN:-}"

if [[ -z "${access_token}" ]]; then
  record_mismatch "ms-go-auth" "${wiki_ref} (Изменение пароля/email)" "токен доступен из signup/verify" "E2E_ACCESS_TOKEN пустой" "Запустить 01_signup_signin_refresh.sh перед этим сценарием" "blocker" "ms-go-auth/test/e2e/gateway"
  return 1
fi

new_password="E2E-NewPassword-123!"

# 6. Изменение пароля (authorized)
change_body="$(jq -nc --arg old "${old_password}" --arg new "${new_password}" '{old_password:$old,new_password:$new}')"
change_raw="$(http_json POST "${AUTH_API}/password/change" "${change_body}" "${access_token}")"
change_status="$(printf '%s\n' "${change_raw}" | extract_status)"
change_resp="$(printf '%s\n' "${change_raw}" | extract_body)"

if [[ "${change_status}" != "200" ]]; then
  record_mismatch "ms-go-auth" "${wiki_ref} (Изменение пароля)" "HTTP 200 + message" "HTTP ${change_status}" "POST ${AUTH_API}/password/change resp=${change_resp}" "major" "ms-go-auth/ms-go-tarantool"
else
  record_ok "auth password/change returns 200"
fi

# Re-login with new password should succeed
signin_body="$(jq -nc --arg email "${email}" --arg password "${new_password}" '{email:$email,password:$password}')"
signin_raw="$(http_json POST "${AUTH_API}/signin" "${signin_body}")"
signin_status="$(printf '%s\n' "${signin_raw}" | extract_status)"
signin_resp="$(printf '%s\n' "${signin_raw}" | extract_body)"

if [[ "${signin_status}" != "200" ]]; then
  record_mismatch "ms-go-auth" "${wiki_ref} (Изменение пароля)" "signin с новым паролем: HTTP 200" "HTTP ${signin_status}" "POST ${AUTH_API}/signin resp=${signin_resp}" "major" "ms-go-auth"
else
  record_ok "auth signin works with new password"
fi

# 7. Изменение email
new_email="e2e-new-email-${E2E_RUN_ID}-$RANDOM@example.com"
email_start_body="$(jq -nc --arg email "${new_email}" '{new_email:$email}')"
email_start_raw="$(http_json POST "${AUTH_API}/email/change/start" "${email_start_body}" "${access_token}")"
email_start_status="$(printf '%s\n' "${email_start_raw}" | extract_status)"
email_start_resp="$(printf '%s\n' "${email_start_raw}" | extract_body)"

if [[ "${email_start_status}" != "200" ]]; then
  record_mismatch "ms-go-auth" "${wiki_ref} (Изменение email: start)" "HTTP 200 + message" "HTTP ${email_start_status}" "POST ${AUTH_API}/email/change/start resp=${email_start_resp}" "major" "ms-go-auth/ms-go-tarantool"
else
  record_ok "auth email/change/start returns 200"
fi

return 0
