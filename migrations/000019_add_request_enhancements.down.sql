-- Rollback request enhancements
ALTER TABLE requests DROP COLUMN IF EXISTS resolution_notes;
ALTER TABLE requests DROP COLUMN IF EXISTS checkbox_issue_mismatch;
ALTER TABLE requests DROP COLUMN IF EXISTS reopen_count;
ALTER TABLE requests DROP COLUMN IF EXISTS reopened_at;
ALTER TABLE requests DROP COLUMN IF EXISTS scheduled_time;
