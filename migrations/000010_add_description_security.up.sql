-- Add security fields for protected descriptions
ALTER TABLE requests ADD COLUMN is_description_secure BOOLEAN DEFAULT FALSE;
ALTER TABLE requests ADD COLUMN description_pin_hash VARCHAR(64);
