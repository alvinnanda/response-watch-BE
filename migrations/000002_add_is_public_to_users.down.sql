-- Rollback: Remove is_public column from users table

ALTER TABLE users 
DROP COLUMN IF EXISTS is_public;
