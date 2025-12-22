-- Remove seeded auth users
DELETE FROM auth_user WHERE email IN (
    'admin@example.com',
    'manager@example.com',
    'teacher@example.com',
    'student1@example.com',
    'student2@example.com',
    'student3@example.com',
    'user@example.com'
);
