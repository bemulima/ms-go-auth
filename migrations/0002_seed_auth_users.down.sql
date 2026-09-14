-- Remove only fixture rows inserted with the deterministic local seed IDs.
DELETE FROM auth_user
WHERE (id, email) IN (
    ('00000000-0000-0000-0000-0000000000a1', 'admin@example.com'),
    ('00000000-0000-0000-0000-0000000000a2', 'manager@example.com'),
    ('00000000-0000-0000-0000-0000000000a3', 'teacher@example.com'),
    ('00000000-0000-0000-0000-0000000000b1', 'student1@example.com'),
    ('00000000-0000-0000-0000-0000000000b2', 'student2@example.com'),
    ('00000000-0000-0000-0000-0000000000b3', 'student3@example.com'),
    ('00000000-0000-0000-0000-0000000000c1', 'user@example.com')
);
