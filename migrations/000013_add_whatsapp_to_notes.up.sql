-- Add 'whatsapp' to reminder_channel_enum type
ALTER TYPE reminder_channel_enum ADD VALUE IF NOT EXISTS 'whatsapp';

-- Add whatsapp_phone column to notes table
ALTER TABLE notes ADD COLUMN IF NOT EXISTS whatsapp_phone VARCHAR(20);
