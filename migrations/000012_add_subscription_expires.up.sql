-- Add subscription expiration for paid plans
ALTER TABLE users ADD COLUMN subscription_expires_at TIMESTAMP WITH TIME ZONE;

-- Add index for expiration queries
CREATE INDEX idx_users_subscription_expires ON users(subscription_expires_at) 
  WHERE subscription_expires_at IS NOT NULL AND deleted_at IS NULL;
