-- Add new fields for request enhancements
ALTER TABLE requests ADD COLUMN IF NOT EXISTS scheduled_time TIMESTAMP;
ALTER TABLE requests ADD COLUMN IF NOT EXISTS reopened_at TIMESTAMP;
ALTER TABLE requests ADD COLUMN IF NOT EXISTS reopen_count INTEGER DEFAULT 0;
ALTER TABLE requests ADD COLUMN IF NOT EXISTS checkbox_issue_mismatch BOOLEAN DEFAULT false;
ALTER TABLE requests ADD COLUMN IF NOT EXISTS resolution_notes TEXT;
