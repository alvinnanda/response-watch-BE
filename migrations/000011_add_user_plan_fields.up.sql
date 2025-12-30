-- Add subscription fields to users table
ALTER TABLE users ADD COLUMN plan VARCHAR(20) NOT NULL DEFAULT 'free' 
  CHECK (plan IN ('free', 'basic', 'pro', 'enterprise'));

-- Add request count tracking (monthly reset)
ALTER TABLE users ADD COLUMN monthly_request_count INT DEFAULT 0;
ALTER TABLE users ADD COLUMN request_count_reset_at TIMESTAMP WITH TIME ZONE DEFAULT NOW();

-- Index for plan queries
CREATE INDEX idx_users_plan ON users(plan) WHERE deleted_at IS NULL;
