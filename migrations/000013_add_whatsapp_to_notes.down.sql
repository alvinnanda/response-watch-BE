-- Remove whatsapp_phone column from notes table
ALTER TABLE notes DROP COLUMN IF EXISTS whatsapp_phone;

-- Note: Cannot easily remove enum value 'whatsapp' from reminder_channel_enum in PostgreSQL
-- The enum value will remain but be unused
