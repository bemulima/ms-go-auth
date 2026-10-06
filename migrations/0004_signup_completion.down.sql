-- Completion records retain both pending ownership and terminal replay denial.
-- Removing any of them would re-enable unsafe token/proof paths on rollback.
DO $$
BEGIN
    IF to_regclass('auth_signup_completion') IS NOT NULL THEN
        LOCK TABLE auth_signup_completion IN ACCESS EXCLUSIVE MODE;
        IF EXISTS (SELECT 1 FROM auth_signup_completion) THEN
            RAISE EXCEPTION 'cannot roll back signup completion with retained operations';
        END IF;
        DROP TABLE auth_signup_completion;
    END IF;
END $$;
