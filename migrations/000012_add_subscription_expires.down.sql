-- Remove subscription expiration field
DROP INDEX IF EXISTS idx_users_subscription_expires;
ALTER TABLE users DROP COLUMN IF EXISTS subscription_expires_at;
