-- Add is_public column to users table
-- This column controls whether a user's account can be accessed publicly

ALTER TABLE users 
ADD COLUMN IF NOT EXISTS is_public BOOLEAN DEFAULT false NOT NULL;

-- Add comment for documentation
COMMENT ON COLUMN users.is_public IS 'Controls whether the user account can be accessed publicly';
