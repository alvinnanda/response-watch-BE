-- Remove plain text title column
DROP INDEX IF EXISTS idx_requests_title;
ALTER TABLE requests DROP COLUMN IF EXISTS title;
