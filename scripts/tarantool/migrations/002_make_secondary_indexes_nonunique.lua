-- 002_make_secondary_indexes_nonunique repairs indexes created by the legacy
-- initializer, which omitted unique = false. Altering an index preserves every
-- tuple; this migration does not drop, truncate, reformat, or rewrite spaces.

local function make_nonunique(space_name, index_name)
    local space = box.space[space_name]
    if not space then
        return
    end
    local index = space.index[index_name]
    if index and index.unique then
        index:alter({unique = false})
    end
end

make_nonunique('user', 'online')
make_nonunique('user_signup_space', 'created_at')
make_nonunique('user_email_change', 'created_at')
make_nonunique('user_password_reset', 'created_at')
make_nonunique('sandbox', 'user_lesson')
make_nonunique('sandbox', 'status')

local ledger = box.space.ms_go_tarantool_schema_migrations
if not ledger:get({'002_make_secondary_indexes_nonunique'}) then
    ledger:replace({'002_make_secondary_indexes_nonunique', os.time()})
end
return '002_make_secondary_indexes_nonunique'
