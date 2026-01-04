-- Add plain text title column for search
ALTER TABLE requests 
ADD COLUMN title TEXT;

-- Index for search
CREATE INDEX IF NOT EXISTS idx_requests_title ON requests USING gin(to_tsvector('simple', COALESCE(title, '')));
