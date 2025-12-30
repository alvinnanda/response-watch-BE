-- Remove plan-related columns from users table
DROP INDEX IF EXISTS idx_users_plan;
ALTER TABLE users DROP COLUMN IF EXISTS request_count_reset_at;
ALTER TABLE users DROP COLUMN IF EXISTS monthly_request_count;
ALTER TABLE users DROP COLUMN IF EXISTS plan;
