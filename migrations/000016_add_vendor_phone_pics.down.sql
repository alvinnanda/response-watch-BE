-- Remove vendor_phone and pics columns from vendor_groups table
ALTER TABLE vendor_groups 
DROP COLUMN IF EXISTS vendor_phone,
DROP COLUMN IF EXISTS pics;
