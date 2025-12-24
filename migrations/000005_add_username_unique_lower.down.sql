-- Remove case-insensitive unique index
DROP INDEX IF EXISTS idx_users_username_lower;
