-- Disposable coordinator fixture only. Load locally AFTER Auth init.lua.
-- It adds no function or cleanup hook and never runs from production bootstrap.
assert(os.getenv('AUTH_VERIFICATION_CLEANUP_FIXTURE_ENABLED') == 'true',
    'explicit disposable cleanup fixture enablement required')
local prefix = os.getenv('AUTH_VERIFICATION_CLEANUP_PREFIX')
assert(prefix and #prefix >= 12 and #prefix <= 96
    and prefix:match('^t16[%w%-]+%-$'), 'synthetic cleanup prefix required')
local json = require('json')
local digest = require('digest')
local marker_name = 'auth_verification_cleanup_fixture'
if not box.space[marker_name] then
    box.schema.space.create(marker_name)
    box.space[marker_name]:format({
        {name = 'prefix', type = 'string'},
        {name = 'metadata', type = 'string'},
    })
    box.space[marker_name]:create_index('primary', {parts = {'prefix'}})
end
local marker = box.space[marker_name]
-- Repeated restart bootstraps observe the original committed fixture. They do
-- not revive expired proofs or overwrite an earlier fixture's retained data.
if marker:get({prefix}) then return 'already_seeded' end

local now = os.time()
local function ttl(name)
    local value = tonumber(os.getenv(name) or '86400')
    assert(value and value >= 1 and value == math.floor(value), 'invalid cleanup hard TTL')
    return value
end
local signup_old = now - ttl('SIGNUP_HARD_TTL_SECONDS') - 60
local email_old = now - ttl('EMAIL_CHANGE_HARD_TTL_SECONDS') - 60
local reset_old = now - ttl('PASSWORD_RESET_HARD_TTL_SECONDS') - 60
local old = math.min(signup_old, email_old, reset_old)
local count = 1205
local entries = {}
local used_codes = {}
local next_code = 0
local lookup = box.space.user_email_change_code_lookup
local function code()
    while next_code <= 9999 do
        local candidate = string.format('%04d', next_code)
        next_code = next_code + 1
        if not used_codes[candidate] and not lookup:get({candidate}) then
            used_codes[candidate] = true
            return candidate
        end
    end
    error('fixture code capacity unavailable')
end
local function uuid(kind, i)
    local value = digest.sha256_hex(prefix .. kind .. tostring(i)):sub(1, 32)
    return value:sub(1, 8) .. '-' .. value:sub(9, 12) .. '-' .. value:sub(13, 16)
        .. '-' .. value:sub(17, 20) .. '-' .. value:sub(21, 32)
end
local function add(space, key, tuple)
    table.insert(entries, {space = space, key = key, tuple = tuple})
end
local live_email = prefix .. 'live-signup@example.test'
local live_receipt_email = prefix .. 'live-receipt@example.test'
local live_operation = uuid('live-receipt', 1)
local live_reset_email = prefix .. 'live-reset@example.test'
local live_email_uuid = uuid('live-email', 1)
local live_code = code()
local legacy_user = prefix .. 'legacy-user'
local legacy_sandbox = prefix .. 'legacy-sandbox'
local live_deadline = now + 3600
local fixture_credential = 'disposable-cleanup-fixture-only'
add('user_signup_space', live_email, {live_email, fixture_credential, '9732', live_deadline, now, now, 0})
add('user_signup_consumption_receipts', live_operation,
    {live_operation, live_receipt_email, digest.sha256_hex(prefix .. 'live'), fixture_credential, live_deadline})
add('user_password_reset', live_reset_email,
    {live_reset_email, uuid('live-reset', 1), '9733', live_deadline, now, 0})
add('user_email_change', live_email_uuid,
    {live_email_uuid, legacy_user, prefix .. 'live-email@example.test', live_code, live_deadline, now, 0})
add('user_email_change_code_lookup', live_code, {live_code, live_email_uuid, live_deadline})
add('user', legacy_user, {legacy_user, 1, old, box.NULL, box.NULL, old, old})
-- An old missing-heartbeat session would be deleted by the retired cleanup.
-- Auth must retain it, because this is historical data owned by Sandbox.
add('sandbox', legacy_sandbox, {legacy_sandbox, legacy_user, 'fixture-lesson', old, box.NULL, 0})

for i = 1, count do
    local signup_email = prefix .. 'expired-signup-' .. i .. '@example.test'
    local receipt_email = prefix .. 'expired-receipt-' .. i .. '@example.test'
    local receipt_operation = uuid('expired-receipt', i)
    local reset_email = prefix .. 'expired-reset-' .. i .. '@example.test'
    local email_uuid = uuid('expired-email', i)
    local expired_code = code()
    add('user_signup_space', signup_email,
        {signup_email, fixture_credential, '9734', now - 1, signup_old, signup_old, 0})
    add('user_signup_consumption_receipts', receipt_operation,
        {receipt_operation, receipt_email, digest.sha256_hex(prefix .. i), fixture_credential, now - 1})
    add('user_password_reset', reset_email,
        {reset_email, uuid('expired-reset', i), '9735', now - 1, reset_old, 0})
    add('user_email_change', email_uuid,
        {email_uuid, legacy_user, prefix .. 'expired-email-' .. i .. '@example.test', expired_code, now - 1, email_old, 0})
    add('user_email_change_code_lookup', expired_code, {expired_code, email_uuid, now - 1})
end
-- This old UUID record shares a code now owned by a still-valid request. GC
-- must delete the old record while preserving the current reverse mapping.
local shadow_uuid = uuid('expired-shadow', 1)
add('user_email_change', shadow_uuid,
    {shadow_uuid, legacy_user, prefix .. 'expired-shadow@example.test', live_code, now - 1, email_old, 0})

local metadata = {
    prefix = prefix, seeded_at = now, expired_per_kind = count,
    seeded_expired_email_count = count + 1,
    live_email = live_email, live_receipt_email = live_receipt_email,
    live_operation = live_operation, live_reset_email = live_reset_email,
    live_email_uuid = live_email_uuid, live_code = live_code,
    legacy_user = legacy_user, legacy_sandbox = legacy_sandbox,
    old_timestamp = old, live_deadline = live_deadline,
    expired_email_uuids = {}, expired_lookup_codes = {},
}
for _, entry in ipairs(entries) do
    assert(box.space[entry.space], 'fixture schema missing')
    assert(not box.space[entry.space]:get({entry.key}), 'fixture refuses existing key overwrite')
    if entry.space == 'user_email_change' and entry.key ~= live_email_uuid then
        table.insert(metadata.expired_email_uuids, entry.key)
    elseif entry.space == 'user_email_change_code_lookup' and entry.key ~= live_code then
        table.insert(metadata.expired_lookup_codes, entry.key)
    end
end
-- Seed atomically; the real GC fiber cannot observe an incomplete fixture.
box.atomic(function()
    for _, entry in ipairs(entries) do
        box.space[entry.space]:insert(entry.tuple)
    end
    marker:insert({prefix, json.encode(metadata)})
end)
return 'seeded'
