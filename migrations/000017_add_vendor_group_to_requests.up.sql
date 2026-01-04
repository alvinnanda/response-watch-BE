-- Add vendor_group_id to requests table
ALTER TABLE requests 
ADD COLUMN vendor_group_id BIGINT REFERENCES vendor_groups(id) ON DELETE SET NULL;

-- Index for filtering
CREATE INDEX IF NOT EXISTS idx_requests_vendor_group_id ON requests(vendor_group_id) WHERE deleted_at IS NULL;
