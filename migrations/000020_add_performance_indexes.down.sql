-- Rollback performance indexes

DROP INDEX IF EXISTS idx_requests_user_created_at;
DROP INDEX IF EXISTS idx_requests_user_status;
DROP INDEX IF EXISTS idx_requests_user_date_range;
DROP INDEX IF EXISTS idx_notes_user_reminder;
DROP INDEX IF EXISTS idx_requests_user_vendor_group;
