-- Create device_usage table for tracking anonymous user activity
CREATE TABLE IF NOT EXISTS device_usage (
    id BIGSERIAL PRIMARY KEY,
    fingerprint_hash VARCHAR(64) NOT NULL,
    action VARCHAR(32) NOT NULL DEFAULT 'create_request',
    ip_address VARCHAR(45),
    real_ip VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Indexes for efficient lookups
CREATE INDEX idx_device_usage_fingerprint ON device_usage(fingerprint_hash);
CREATE INDEX idx_device_usage_created_at ON device_usage(created_at);
CREATE INDEX idx_device_usage_real_ip ON device_usage(real_ip);
