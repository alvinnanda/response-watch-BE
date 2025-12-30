-- Remove security fields for protected descriptions
ALTER TABLE requests DROP COLUMN IF EXISTS is_description_secure;
ALTER TABLE requests DROP COLUMN IF EXISTS description_pin_hash;
