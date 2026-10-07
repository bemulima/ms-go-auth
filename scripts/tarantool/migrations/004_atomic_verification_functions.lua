-- Auth owns only verification state. This migration never rewrites legacy tuples.
-- Global Lua definitions are loaded on every restart; the schema ledger remains
-- append-only. Binary CALL runs under a non-login, verification-only owner.
local digest = require('digest')
local owner = 'auth_verification_owner'
local verification_spaces = {
    'user_signup_space', 'user_signup_consumption_receipts',
    'user_email_change', 'user_email_change_code_lookup', 'user_password_reset',
}

local function integer(value)
    return type(value) == 'number' and value >= 0 and value < 9007199254740991
        and value == math.floor(value)
end

local function text(value, limit)
    return type(value) == 'string' and #value > 0 and #value <= limit
end

local function normalized_email(email)
    return text(email, 320) and email == email:match('^%s*(.-)%s*$'):lower()
end

local function canonical_uuid(value)
    return type(value) == 'string' and value ~= '00000000-0000-0000-0000-000000000000' and #value == 36 and value:match(
        '^%x%x%x%x%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x$')
        and value == value:lower()
end

-- Match the provider's length-framed SHA256(email, code), independently of the
-- PostgreSQL signup fingerprint. Do not trust the client's supplied binding.
local function frame(value)
    local n = #value
    local bytes = {}
    for i = 8, 1, -1 do
        bytes[i] = string.char(n % 256)
        n = math.floor(n / 256)
    end
    return table.concat(bytes) .. value
end

local function binding(email, code)
    return digest.sha256_hex(frame(email) .. frame(code))
end

local function ready()
    for _, name in ipairs(verification_spaces) do
        if not box.space[name] or not box.space[name].index.primary then
            return false
        end
    end
    local receipts = box.space.user_signup_consumption_receipts
    local lookup = box.space.user_email_change_code_lookup
    return receipts.index.email ~= nil and receipts.index.expires_at ~= nil
        and lookup.index.uuid ~= nil
        and box.space.ms_go_tarantool_schema_migrations:get({'004_atomic_verification_functions'}) ~= nil
end

function auth_verification_ready()
    if ready() then return 'ok' end
    return 'unavailable'
end

local function active_receipt(email, now)
    local receipts = box.space.user_signup_consumption_receipts
    local receipt = receipts.index.email:get({email})
    if receipt and receipt[5] > now then return receipt end
    if receipt then receipts:delete({receipt[1]}) end
    return nil
end

local function signup_start(args, resend)
    local email, password, code, now, code_ttl, hard_ttl
    if resend then
        email, code, now, code_ttl, hard_ttl = unpack(args)
    else
        email, password, code, now, code_ttl, hard_ttl = unpack(args)
    end
    if not normalized_email(email) or not text(code, 128)
        or not integer(now) or not integer(code_ttl) or code_ttl < 1
        or not integer(hard_ttl) or hard_ttl < 1
        or (not resend and (type(password) ~= 'string' or #password > 256)) then
        return 'unavailable'
    end
    if active_receipt(email, now) then return 'mismatch' end
    local proofs = box.space.user_signup_space
    local proof = proofs:get({email})
    -- Replacement must invalidate the previous code even when randomness
    -- produces the same value. The usecase retries allocation on conflict.
    if proof and proof[3] == code then return 'code_conflict' end
    if resend then
        if not proof then return 'not_found' end
        if proof[5] + hard_ttl <= now then return 'expired' end
        proof = proofs:replace({email, proof[2], code, now + code_ttl, proof[5], now, 0})
    else
        if password == '' and proof then password = proof[2] end
        if password == '' then return 'unavailable' end
        proof = proofs:replace({email, password, code, now + code_ttl, now, now, 0})
    end
    return 'ok', proof:totable()
end

local function signup_verify(args, consume)
    local email, code, operation, fingerprint, now, hard_ttl
    if consume then
        email, code, operation, fingerprint, now, hard_ttl = unpack(args)
    else
        email, code, now, hard_ttl = unpack(args)
    end
    if not normalized_email(email) or not text(code, 128)
        or not integer(now) or not integer(hard_ttl) or hard_ttl < 1 then
        return 'unavailable'
    end
    local receipts = box.space.user_signup_consumption_receipts
    if consume then
        if not canonical_uuid(operation) or fingerprint ~= binding(email, code) then
            return 'mismatch'
        end
        local receipt = receipts:get({operation})
        if receipt then
            if receipt[5] <= now then return 'expired' end
            if receipt[2] ~= email or receipt[3] ~= fingerprint then return 'mismatch' end
            return 'ok', receipt:totable()
        end
        if active_receipt(email, now) then return 'mismatch' end
    elseif active_receipt(email, now) then
        return 'not_found'
    end
    local proofs = box.space.user_signup_space
    local proof = proofs:get({email})
    if not proof then return 'not_found' end
    local expires = proof[5] + hard_ttl
    if proof[4] <= now or expires <= now then return 'expired' end
    if proof[3] ~= code then
        proofs:update({email}, {{'+', 7, 1}})
        return 'invalid_code'
    end
    if consume then
        local receipt = receipts:insert({operation, email, fingerprint, proof[2], expires})
        proofs:delete({email})
        return 'ok', receipt:totable()
    end
    -- Legacy verification returns only a live proof, never a recovery receipt.
    proofs:delete({email})
    return 'ok', proof:totable()
end

local function email_start(args)
    local uuid, user_id, email, code, now, code_ttl, hard_ttl = unpack(args)
    if not canonical_uuid(uuid) or not text(user_id, 128) or not normalized_email(email)
        or not text(code, 128) or not integer(now) or not integer(code_ttl) or code_ttl < 1
        or not integer(hard_ttl) or hard_ttl < 1 then return 'unavailable' end
    local changes = box.space.user_email_change
    local lookup = box.space.user_email_change_code_lookup
    local current = lookup:get({code})
    if current and current[2] ~= uuid and current[3] > now then return 'code_conflict' end
    local previous = changes:get({uuid})
    if previous and previous[4] == code then return 'code_conflict' end
    if previous and previous[4] ~= code then
        local old = lookup:get({previous[4]})
        if old and old[2] == uuid then lookup:delete({old[1]}) end
    end
    local previous_mapping = lookup.index.uuid:get({uuid})
    if previous_mapping and previous_mapping[1] ~= code then
        lookup:delete({previous_mapping[1]})
    end
    local proof = changes:replace({uuid, user_id, email, code, now + code_ttl, now, 0})
    lookup:replace({code, uuid, now + code_ttl})
    return 'ok', proof:totable()
end

local function email_verify(args)
    local code, now, hard_ttl = unpack(args)
    if not text(code, 128) or not integer(now) or not integer(hard_ttl) or hard_ttl < 1 then
        return 'unavailable'
    end
    local changes = box.space.user_email_change
    local lookup = box.space.user_email_change_code_lookup
    local mapping = lookup:get({code})
    if not mapping then return 'not_found' end
    local proof = changes:get({mapping[2]})
    if not proof or proof[4] ~= code then return 'not_found' end
    if proof[5] <= now or proof[6] + hard_ttl <= now then return 'expired' end
    changes:delete({proof[1]})
    lookup:delete({code})
    return 'ok', proof:totable()
end

local function reset_start(args)
    local email, uuid, code, now, code_ttl, hard_ttl = unpack(args)
    if not normalized_email(email) or not canonical_uuid(uuid) or not text(code, 128)
        or not integer(now) or not integer(code_ttl) or code_ttl < 1
        or not integer(hard_ttl) or hard_ttl < 1 then return 'unavailable' end
    local previous = box.space.user_password_reset:get({email})
    if previous and previous[3] == code then return 'code_conflict' end
    local proof = box.space.user_password_reset:replace({email, uuid, code, now + code_ttl, now, 0})
    return 'ok', proof:totable()
end

local function reset_verify(args)
    local email, code, now, hard_ttl = unpack(args)
    if not normalized_email(email) or not text(code, 128)
        or not integer(now) or not integer(hard_ttl) or hard_ttl < 1 then return 'unavailable' end
    local resets = box.space.user_password_reset
    local proof = resets:get({email})
    if not proof then return 'not_found' end
    if proof[4] <= now or proof[5] + hard_ttl <= now then return 'expired' end
    if proof[3] ~= code then
        resets:update({email}, {{'+', 6, 1}})
        return 'invalid_code'
    end
    resets:delete({email})
    return 'ok', proof:totable()
end

local counts = {
    signup_start = 6, signup_resend = 5, signup_verify = 4, signup_consume = 6,
    email_start = 7, email_verify = 3, reset_start = 6, reset_verify = 4,
}

function auth_verification(action, args)
    if type(action) ~= 'string' or type(args) ~= 'table'
        or not counts[action] or #args ~= counts[action] or not ready() then
        return 'unavailable'
    end
    return box.atomic(function()
        if action == 'signup_start' then return signup_start(args, false) end
        if action == 'signup_resend' then return signup_start(args, true) end
        if action == 'signup_verify' then return signup_verify(args, false) end
        if action == 'signup_consume' then return signup_verify(args, true) end
        if action == 'email_start' then return email_start(args) end
        if action == 'email_verify' then return email_verify(args) end
        if action == 'reset_start' then return reset_start(args) end
        if action == 'reset_verify' then return reset_verify(args) end
        return 'unavailable'
    end)
end

box.schema.user.create(owner, {if_not_exists = true})
-- Keep usage for setuid, but session is granted only while local bootstrap
-- switches identity to register functions. No owner password is configured.
box.schema.user.enable(owner)
for _, name in ipairs(verification_spaces) do
    box.schema.user.grant(owner, 'read,write', 'space', name, {if_not_exists = true})
end
box.schema.user.grant(owner, 'read', 'space', 'ms_go_tarantool_schema_migrations', {if_not_exists = true})
-- Only bootstrap briefly grants schema rights, then revokes them. Functions are
-- registered under this owner rather than admin, limiting setuid authority.
box.schema.user.grant(owner, 'create', 'universe', nil, {if_not_exists = true})
box.schema.user.grant(owner, 'read,write', 'space', '_func', {if_not_exists = true})
box.session.su(owner, function()
    box.schema.func.create('auth_verification', {if_not_exists = true, setuid = true})
    box.schema.func.create('auth_verification_ready', {if_not_exists = true, setuid = true})
end)
local owner_id = box.space._user.index.name:get({owner})[1]
for _, name in ipairs({'auth_verification', 'auth_verification_ready'}) do
    local definition = box.space._func.index.name:get({name})
    assert(definition and definition[2] == owner_id and definition[4] == 1,
        'verification function ownership or setuid differs from the required capability')
end
box.schema.user.revoke(owner, 'create', 'universe', nil, {if_exists = true})
box.schema.user.revoke(owner, 'read,write', 'space', '_func', {if_exists = true})
box.schema.user.revoke(owner, 'session', 'universe', nil, {if_exists = true})

local ledger = box.space.ms_go_tarantool_schema_migrations
if not ledger:get({'004_atomic_verification_functions'}) then
    ledger:insert({'004_atomic_verification_functions', os.time()})
end
return '004_atomic_verification_functions'
