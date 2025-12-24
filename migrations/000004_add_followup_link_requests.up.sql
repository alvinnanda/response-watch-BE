-- Add followup_link column to requests table
-- This column will store the ENCRYPTED followup link
ALTER TABLE requests ADD COLUMN followup_link TEXT;
