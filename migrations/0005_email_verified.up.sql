ALTER TABLE auth_user ADD COLUMN IF NOT EXISTS email_verified boolean NOT NULL DEFAULT false;
UPDATE auth_user u SET email_verified=true WHERE EXISTS(SELECT 1 FROM auth_signup_completion s WHERE s.principal_id=u.id AND s.state='completed') OR EXISTS(SELECT 1 FROM auth_identity i WHERE i.user_id=u.id);
