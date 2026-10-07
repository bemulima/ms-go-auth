-- 001_initial_schema is forward-safe for the existing identity volume.
-- It creates missing spaces and indexes only; it never reformats, truncates,
-- or drops existing state.

local ledger_name = 'ms_go_tarantool_schema_migrations'

if not box.space[ledger_name] then
    box.schema.space.create(ledger_name, {if_not_exists = true})
    box.space[ledger_name]:format({
        {name = 'version', type = 'string'},
        {name = 'applied_at', type = 'unsigned'},
    })
    box.space[ledger_name]:create_index('primary', {parts = {'version'}, if_not_exists = true})
end

if not box.space.user then
    box.schema.space.create('user', {if_not_exists = true})
    box.space.user:format({
        {name = 'user_id', type = 'string'},
        {name = 'online', type = 'unsigned'},
        {name = 'last_seen_at', type = 'unsigned'},
        {name = 'last_login_at', type = 'unsigned', is_nullable = true},
        {name = 'last_logout_at', type = 'unsigned', is_nullable = true},
        {name = 'created_at', type = 'unsigned'},
        {name = 'updated_at', type = 'unsigned'},
    })
end
box.space.user:create_index('primary', {parts = {'user_id'}, if_not_exists = true})
box.space.user:create_index('online', {parts = {'online'}, unique = false, if_not_exists = true})

if not box.space.user_signup_space then
    box.schema.space.create('user_signup_space', {if_not_exists = true})
    box.space.user_signup_space:format({
        {name = 'email', type = 'string'},
        {name = 'password_hash', type = 'string'},
        {name = 'code', type = 'string'},
        {name = 'expires_at', type = 'unsigned'},
        {name = 'created_at', type = 'unsigned'},
        {name = 'last_sent_at', type = 'unsigned'},
        {name = 'attempts', type = 'unsigned'},
    })
end
box.space.user_signup_space:create_index('primary', {parts = {'email'}, if_not_exists = true})
box.space.user_signup_space:create_index('created_at', {parts = {'created_at'}, unique = false, if_not_exists = true})

if not box.space.user_email_change then
    box.schema.space.create('user_email_change', {if_not_exists = true})
    box.space.user_email_change:format({
        {name = 'uuid', type = 'string'},
        {name = 'user_id', type = 'string'},
        {name = 'email', type = 'string'},
        {name = 'code', type = 'string'},
        {name = 'expires_at', type = 'unsigned'},
        {name = 'created_at', type = 'unsigned'},
        {name = 'attempts', type = 'unsigned'},
    })
end
box.space.user_email_change:create_index('primary', {parts = {'uuid'}, if_not_exists = true})
box.space.user_email_change:create_index('created_at', {parts = {'created_at'}, unique = false, if_not_exists = true})

-- New requests reserve a unique active code in this separate lookup space.
-- Existing records remain available through their UUID without a rewrite.
if not box.space.user_email_change_code_lookup then
    box.schema.space.create('user_email_change_code_lookup', {if_not_exists = true})
    box.space.user_email_change_code_lookup:format({
        {name = 'code', type = 'string'},
        {name = 'uuid', type = 'string'},
        {name = 'expires_at', type = 'unsigned'},
    })
end
box.space.user_email_change_code_lookup:create_index('primary', {parts = {'code'}, if_not_exists = true})
box.space.user_email_change_code_lookup:create_index('uuid', {parts = {'uuid'}, if_not_exists = true})

if not box.space.user_password_reset then
    box.schema.space.create('user_password_reset', {if_not_exists = true})
    box.space.user_password_reset:format({
        {name = 'email', type = 'string'},
        {name = 'uuid', type = 'string'},
        {name = 'code', type = 'string'},
        {name = 'expires_at', type = 'unsigned'},
        {name = 'created_at', type = 'unsigned'},
        {name = 'attempts', type = 'unsigned'},
    })
end
box.space.user_password_reset:create_index('primary', {parts = {'email'}, if_not_exists = true})
box.space.user_password_reset:create_index('created_at', {parts = {'created_at'}, unique = false, if_not_exists = true})

if not box.space.sandbox then
    box.schema.space.create('sandbox', {if_not_exists = true})
    box.space.sandbox:format({
        {name = 'sandbox_id', type = 'string'},
        {name = 'user_id', type = 'string'},
        {name = 'lesson_id', type = 'string'},
        {name = 'started_at', type = 'unsigned'},
        {name = 'last_ping_at', type = 'unsigned', is_nullable = true},
        {name = 'status', type = 'unsigned'},
    })
end
box.space.sandbox:create_index('primary', {parts = {'sandbox_id'}, if_not_exists = true})
box.space.sandbox:create_index('user_lesson', {parts = {'user_id', 'lesson_id'}, unique = false, if_not_exists = true})
box.space.sandbox:create_index('status', {parts = {'status'}, unique = false, if_not_exists = true})

if not box.space[ledger_name]:get({'001_initial_schema'}) then
    box.space[ledger_name]:replace({'001_initial_schema', os.time()})
end
return '001_initial_schema'
