-- Remove vendor_group_id from requests table
DROP INDEX IF EXISTS idx_requests_vendor_group_id;
ALTER TABLE requests DROP COLUMN IF EXISTS vendor_group_id;
