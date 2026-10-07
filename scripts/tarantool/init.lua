-- Server-start bootstrap runs locally as admin. Auth connects over the binary
-- protocol with only the configured runtime principal, never an admin secret.
local fiber = require('fiber')
local log = require('log')
local runtime_user = os.getenv('TARANTOOL_USER')
local runtime_password = os.getenv('TARANTOOL_PASSWORD')
assert(runtime_user and runtime_user ~= '', 'TARANTOOL_USER is required')
assert(runtime_password and runtime_password ~= '', 'TARANTOOL_PASSWORD is required')
assert(runtime_user ~= 'admin' and runtime_user ~= 'guest'
    and runtime_user ~= 'auth_verification_owner', 'a dedicated runtime principal is required')

local source = debug.getinfo(1, 'S').source:sub(2)
local directory = source:match('^(.*)/[^/]+$') or '.'
local migration_dir = os.getenv('TARANTOOL_MIGRATIONS_DIR') or (directory .. '/migrations')
local cfg = {listen = os.getenv('TARANTOOL_LISTEN') or 3301, log_level = 5}
if os.getenv('TARANTOOL_WORK_DIR') then cfg.work_dir = os.getenv('TARANTOOL_WORK_DIR') end
box.cfg(cfg)

for _, migration in ipairs({
    '001_initial_schema', '002_make_secondary_indexes_nonunique',
    '003_signup_consumption_receipts', '004_atomic_verification_functions',
}) do
    dofile(migration_dir .. '/' .. migration .. '.lua')
end

box.schema.user.create(runtime_user, {if_not_exists = true})
box.schema.user.passwd(runtime_user, runtime_password)
-- An existing volume may retain grants from the old provider bootstrap. Remove
-- those grants explicitly before narrowing access; restart must not keep EVAL,
-- arbitrary CALL, schema mutation, direct reads, or legacy-space writes enabled.
box.schema.user.revoke(runtime_user, 'read,write,create,alter,drop,execute',
    'universe', nil, {if_exists = true})
box.schema.user.enable(runtime_user)
box.schema.user.grant(runtime_user, 'execute', 'function', 'auth_verification', {if_not_exists = true})
box.schema.user.grant(runtime_user, 'execute', 'function', 'auth_verification_ready', {if_not_exists = true})

local function hard_ttl(name)
    local value = tonumber(os.getenv(name) or '86400')
    assert(value and value >= 1 and value == math.floor(value), name .. ' must be positive seconds')
    return value
end
local signup_ttl = hard_ttl('SIGNUP_HARD_TTL_SECONDS')
local email_ttl = hard_ttl('EMAIL_CHANGE_HARD_TTL_SECONDS')
local reset_ttl = hard_ttl('PASSWORD_RESET_HARD_TTL_SECONDS')

-- The single verification GC fiber is the only cleanup owner. Each full scan
-- runs in one transaction so it cannot delete a concurrently replaced request.
-- Code expiry invalidates verification; hard TTL controls retained proof data.
-- Frozen receipt expiry is independent of subsequent configuration changes.
local function cleanup()
    local now = os.time()
    box.atomic(function()
        for _, proof in box.space.user_signup_space:pairs() do
            if proof[5] + signup_ttl <= now then
                box.space.user_signup_space:delete({proof[1]})
            end
        end
        for _, receipt in box.space.user_signup_consumption_receipts:pairs() do
            if receipt[5] <= now then
                box.space.user_signup_consumption_receipts:delete({receipt[1]})
            end
        end
        local lookup = box.space.user_email_change_code_lookup
        local changes = box.space.user_email_change
        for _, proof in changes:pairs() do
            if proof[6] + email_ttl <= now then
                local mapping = lookup:get({proof[4]})
                if mapping and mapping[2] == proof[1] then lookup:delete({proof[4]}) end
                changes:delete({proof[1]})
            end
        end
        for _, mapping in lookup:pairs() do
            local proof = changes:get({mapping[2]})
            if mapping[3] <= now or not proof or proof[4] ~= mapping[1] then
                lookup:delete({mapping[1]})
            end
        end
        for _, proof in box.space.user_password_reset:pairs() do
            if proof[5] + reset_ttl <= now then
                box.space.user_password_reset:delete({proof[1]})
            end
        end
    end)
end

fiber.create(function()
    fiber.name('auth_verification_gc')
    while true do
        local ok = pcall(cleanup)
        if not ok then log.error('verification cleanup unavailable') end
        fiber.sleep(60)
    end
end)

-- Legacy user and sandbox spaces remain on this identity volume as retained
-- historical data. Their business owner is not Auth; no cleanup runs here.
