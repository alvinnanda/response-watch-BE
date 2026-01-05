-- Composite indexes for optimizing dashboard queries
-- These indexes target the slow /requests and /stats endpoints

-- 1. Index for /requests List endpoint (user_id + created_at DESC)
-- Optimizes: ORDER BY created_at DESC with user_id filter
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_requests_user_created_at 
ON requests(user_id, created_at DESC) 
WHERE deleted_at IS NULL;

-- 2. Index for /stats endpoint (user_id + status for GROUP BY)
-- Optimizes: COUNT(*) GROUP BY status with user_id filter
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_requests_user_status 
ON requests(user_id, status) 
WHERE deleted_at IS NULL;

-- 3. Covering index for date range queries 
-- Optimizes: start_date/end_date filters with user_id
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_requests_user_date_range 
ON requests(user_id, created_at) 
WHERE deleted_at IS NULL;

-- 4. Index for notes reminder queries
-- Optimizes: GET /notes/reminders endpoint
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_notes_user_reminder 
ON notes(user_id, remind_at) 
WHERE is_reminder = true AND remind_at IS NOT NULL;

-- 5. Index for vendor group queries with user
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_requests_user_vendor_group 
ON requests(user_id, vendor_group_id) 
WHERE deleted_at IS NULL AND vendor_group_id IS NOT NULL;
