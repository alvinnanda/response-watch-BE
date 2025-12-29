ALTER TABLE notes DROP COLUMN IF EXISTS request_id;
ALTER TABLE notes ADD COLUMN request_uuid UUID;
ALTER TABLE notes ADD CONSTRAINT fk_request_uuid FOREIGN KEY (request_uuid) REFERENCES requests(uuid) ON DELETE SET NULL;
CREATE INDEX idx_notes_request_uuid ON notes(request_uuid);
