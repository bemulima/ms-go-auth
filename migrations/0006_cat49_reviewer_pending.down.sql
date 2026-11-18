DO $$
BEGIN
 IF EXISTS (SELECT 1 FROM auth_cat49_reviewer_registration) OR
    EXISTS (SELECT 1 FROM auth_cat49_reviewer_activation) THEN
   RAISE EXCEPTION 'CAT-49 reviewer receipt rollback denied';
 END IF;
END;
$$;
DROP TABLE auth_cat49_reviewer_activation;
DROP TABLE auth_cat49_reviewer_registration;
DROP FUNCTION reject_cat49_reviewer_receipt_mutation();
