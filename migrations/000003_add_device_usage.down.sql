-- Rollback device_usage table
DROP INDEX IF EXISTS idx_device_usage_real_ip;
DROP INDEX IF EXISTS idx_device_usage_created_at;
DROP INDEX IF EXISTS idx_device_usage_fingerprint;
DROP TABLE IF EXISTS device_usage;
