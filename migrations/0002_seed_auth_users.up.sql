-- Seed auth users for testing
-- Password for all users: Password123!
-- Hash: $2a$10$7xzTCUMmJ9GY1XkWWPgr7OWX7U0rM4SgWJPfdYq0MKzpv64C.fwd2

INSERT INTO auth_user (id, email, password_hash, password_updated_at)
VALUES
    ('00000000-0000-0000-0000-0000000000a1', 'admin@example.com', '$2a$10$7xzTCUMmJ9GY1XkWWPgr7OWX7U0rM4SgWJPfdYq0MKzpv64C.fwd2', now()),
    ('00000000-0000-0000-0000-0000000000a2', 'manager@example.com', '$2a$10$7xzTCUMmJ9GY1XkWWPgr7OWX7U0rM4SgWJPfdYq0MKzpv64C.fwd2', now()),
    ('00000000-0000-0000-0000-0000000000a3', 'teacher@example.com', '$2a$10$7xzTCUMmJ9GY1XkWWPgr7OWX7U0rM4SgWJPfdYq0MKzpv64C.fwd2', now()),
    ('00000000-0000-0000-0000-0000000000b1', 'student1@example.com', '$2a$10$7xzTCUMmJ9GY1XkWWPgr7OWX7U0rM4SgWJPfdYq0MKzpv64C.fwd2', now()),
    ('00000000-0000-0000-0000-0000000000b2', 'student2@example.com', '$2a$10$7xzTCUMmJ9GY1XkWWPgr7OWX7U0rM4SgWJPfdYq0MKzpv64C.fwd2', now()),
    ('00000000-0000-0000-0000-0000000000b3', 'student3@example.com', '$2a$10$7xzTCUMmJ9GY1XkWWPgr7OWX7U0rM4SgWJPfdYq0MKzpv64C.fwd2', now()),
    ('00000000-0000-0000-0000-0000000000c1', 'user@example.com', '$2a$10$7xzTCUMmJ9GY1XkWWPgr7OWX7U0rM4SgWJPfdYq0MKzpv64C.fwd2', now())
ON CONFLICT (email) DO NOTHING;
