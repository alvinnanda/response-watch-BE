-- Add vendor_phone and pics columns to vendor_groups table
ALTER TABLE vendor_groups 
ADD COLUMN IF NOT EXISTS vendor_phone VARCHAR(50),
ADD COLUMN IF NOT EXISTS pics JSONB DEFAULT '[]';
