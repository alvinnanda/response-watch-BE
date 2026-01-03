-- Add email notification preference to users (default false/non-active)
ALTER TABLE users ADD COLUMN notify_email BOOLEAN DEFAULT false;
