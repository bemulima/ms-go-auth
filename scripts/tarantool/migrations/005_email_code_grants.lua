-- Additive Auth-owned code/grant state. Raw codes/grants are never persisted.
local owner='auth_verification_owner'
local function space(name,format,parts)
 local s=box.schema.space.create(name,{if_not_exists=true});s:format(format);s:create_index('primary',{parts=parts,if_not_exists=true});box.schema.user.grant(owner,'read,write','space',name,{if_not_exists=true});return s
end
local codes=space('auth_email_code',{{name='purpose',type='string'},{name='email',type='string'},{name='digest',type='string'},{name='expires',type='unsigned'},{name='attempts',type='unsigned'},{name='sent',type='unsigned'}},{{field=1,type='string'},{field=2,type='string'}})
local limits=space('auth_email_limit',{{name='key',type='string'},{name='timestamps',type='array'}},{{field=1,type='string'}})
local grants=space('auth_email_grant',{{name='digest',type='string'},{name='purpose',type='string'},{name='email',type='string'},{name='expires',type='unsigned'}},{{field=1,type='string'}})
local legacy=auth_verification
local function usage(key,now)
 local t=limits:get{key};local values={};if t then for _,v in ipairs(t[2])do if v>now-3600 then table.insert(values,v)end end end;return values
end
function auth_verification(action,a)
 if action~='code_start' and action~='code_verify' and action~='grant_consume' then return legacy(action,a) end
 return box.atomic(function()
  local purpose,email,digest,now=a[1],a[2],a[3],a[4]
  if (purpose~='registration' and purpose~='reset') or type(email)~='string' or #email>320 or type(digest)~='string' or #digest~=64 or type(now)~='number' then return 'invalid_request'end
  if action=='code_start'then
   local prior=codes:get{purpose,email};if prior and now-prior[6]<60 then return 'throttled'end
   if prior and prior[3]==digest then return 'code_conflict'end
   local ek='email:'..email;local ik='origin:'..a[5];local e=usage(ek,now);local i=usage(ik,now)
   if #e>=5 or #i>=a[6]then return 'throttled'end
   table.insert(e,now);table.insert(i,now);limits:replace{ek,e};limits:replace{ik,i}
   codes:replace{purpose,email,digest,now+600,0,now};return 'ok', {}
  elseif action=='code_verify'then
   local c=codes:get{purpose,email};if not c or c[4]<=now or c[5]>=5 then return 'expired_or_locked'end
   if c[3]~=digest then codes:update({purpose,email},{{'+',5,1}});return 'invalid_code'end
   codes:delete{purpose,email};grants:insert{a[5],purpose,email,now+600};return 'ok', {}
  else
   local g=grants:get{digest};if not g or g[2]~=purpose or g[3]~=email or g[4]<=now then return 'invalid_grant'end
   grants:delete{digest};return 'ok', {g[4]}
  end
 end)
end
-- Keep the same named function and non-login owner; no broader runtime privileges.
box.space.ms_go_tarantool_schema_migrations:replace{'005_email_code_grants',os.time()}
function auth_email_code_cleanup(now)
 for _,s in ipairs({codes,grants})do for _,t in s:pairs()do if t[4]<=now then s:delete(s==codes and {t[1],t[2]} or {t[1]})end end end
 for _,t in limits:pairs()do local v=usage(t[1],now);if #v==0 then limits:delete{t[1]}else limits:replace{t[1],v}end end
end
