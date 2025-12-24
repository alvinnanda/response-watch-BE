-- Rollback initial database schema

-- Drop triggers
DROP TRIGGER IF EXISTS trigger_vendor_groups_updated_at ON vendor_groups;
DROP TRIGGER IF EXISTS trigger_requests_updated_at ON requests;
DROP TRIGGER IF EXISTS trigger_users_updated_at ON users;

-- Drop function
DROP FUNCTION IF EXISTS update_updated_at();

-- Drop tables
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS vendor_groups;
DROP TABLE IF EXISTS requests;
DROP TABLE IF EXISTS users;

-- Drop extension
-- Note: Not dropping pgcrypto as other things may depend on it
