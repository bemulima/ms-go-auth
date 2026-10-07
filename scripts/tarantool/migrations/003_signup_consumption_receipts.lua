-- Forward-only receipt space; existing proof tuple formats remain untouched.
local name = 'user_signup_consumption_receipts'
if not box.space[name] then
    box.schema.space.create(name, {if_not_exists = true})
    box.space[name]:format({
        {name = 'operation_id', type = 'string'},
        {name = 'email', type = 'string'},
        {name = 'proof_fingerprint', type = 'string'},
        {name = 'password_hash', type = 'string'},
        {name = 'expires_at', type = 'unsigned'},
    })
end
box.space[name]:create_index('primary', {parts = {'operation_id'}, if_not_exists = true})
box.space[name]:create_index('email', {parts = {'email'}, if_not_exists = true})
box.space[name]:create_index('expires_at', {parts = {'expires_at'}, unique = false, if_not_exists = true})

local ledger = box.space.ms_go_tarantool_schema_migrations
if not ledger:get({'003_signup_consumption_receipts'}) then
    ledger:replace({'003_signup_consumption_receipts', os.time()})
end
return '003_signup_consumption_receipts'
