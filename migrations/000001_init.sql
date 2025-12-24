-- ResponseWatch Initial Database Schema
-- Version: 1.0
-- Description: Creates users, requests, and vendor_groups tables with indexes

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================
-- Table: users
-- Requester/Admin accounts
-- ============================================
CREATE TABLE IF NOT EXISTS users (
    -- INTERNAL ID
    id SERIAL PRIMARY KEY,
    
    -- PUBLIC IDENTIFIER
    username VARCHAR(10) UNIQUE NOT NULL CHECK (LENGTH(username) >= 3 AND LENGTH(username) <= 10),
    
    -- AUTHENTICATION
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    
    -- PROFILE
    full_name VARCHAR(100),
    organization VARCHAR(100),
    
    -- ACCOUNT STATUS
    is_active BOOLEAN DEFAULT true,
    email_verified BOOLEAN DEFAULT false,
    email_verified_at TIMESTAMP WITH TIME ZONE,
    
    -- TIMESTAMPS
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login_at TIMESTAMP WITH TIME ZONE,
    
    -- SOFT DELETE
    deleted_at TIMESTAMP WITH TIME ZONE
);

-- Indexes for users
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username) WHERE deleted_at IS NULL;

-- ============================================
-- Table: requests
-- Request tickets with encrypted content
-- ============================================
CREATE TABLE IF NOT EXISTS requests (
    -- INTERNAL ID
    id SERIAL PRIMARY KEY,
    
    -- PUBLIC IDENTIFIER
    uuid UUID UNIQUE NOT NULL DEFAULT gen_random_uuid(),
    
    -- OWNERSHIP
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    
    -- PUBLIC ACCESS TOKEN
    url_token VARCHAR(64) UNIQUE NOT NULL,
    
    -- ENCRYPTED CONTENT (AES-256)
    title_encrypted TEXT NOT NULL,
    description_encrypted TEXT,
    
    -- STATE
    status VARCHAR(20) DEFAULT 'waiting' CHECK (status IN ('waiting', 'in_progress', 'done')),
    
    -- PIC LOGIC (snapshot of PIC options when link created)
    embedded_pic_list JSONB DEFAULT '[]',
    
    -- EXECUTION DATA
    start_pic VARCHAR(100),
    end_pic VARCHAR(100),
    
    -- AUDIT TRAIL (IP & Device)
    start_ip VARCHAR(45),
    end_ip VARCHAR(45),
    user_agent TEXT,
    
    -- TIMING METRICS
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    started_at TIMESTAMP WITH TIME ZONE,
    finished_at TIMESTAMP WITH TIME ZONE,
    
    -- CALCULATED FIELDS
    duration_seconds INTEGER,
    response_time_seconds INTEGER,
    
    -- SOFT DELETE
    deleted_at TIMESTAMP WITH TIME ZONE
);

-- Indexes for requests
CREATE INDEX IF NOT EXISTS idx_requests_user_id ON requests(user_id);
CREATE INDEX IF NOT EXISTS idx_requests_url_token ON requests(url_token);
CREATE INDEX IF NOT EXISTS idx_requests_uuid ON requests(uuid);
CREATE INDEX IF NOT EXISTS idx_requests_status ON requests(status) WHERE deleted_at IS NULL;

-- ============================================
-- Table: vendor_groups
-- Master data for PIC groups
-- ============================================
CREATE TABLE IF NOT EXISTS vendor_groups (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    group_name VARCHAR(100) NOT NULL,
    pic_names JSONB DEFAULT '[]',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    deleted_at TIMESTAMP WITH TIME ZONE
);

-- Indexes for vendor_groups
CREATE INDEX IF NOT EXISTS idx_vendor_groups_user_id ON vendor_groups(user_id) WHERE deleted_at IS NULL;

-- ============================================
-- Table: sessions
-- For session storage (cookie sessions)
-- ============================================
CREATE TABLE IF NOT EXISTS sessions (
    id VARCHAR(255) PRIMARY KEY,
    data BYTEA NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

-- ============================================
-- Function: update_updated_at
-- Automatically update updated_at on row change
-- ============================================
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Triggers for auto-updating updated_at
DROP TRIGGER IF EXISTS trigger_users_updated_at ON users;
CREATE TRIGGER trigger_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at();

DROP TRIGGER IF EXISTS trigger_requests_updated_at ON requests;
CREATE TRIGGER trigger_requests_updated_at
    BEFORE UPDATE ON requests
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at();

DROP TRIGGER IF EXISTS trigger_vendor_groups_updated_at ON vendor_groups;
CREATE TRIGGER trigger_vendor_groups_updated_at
    BEFORE UPDATE ON vendor_groups
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at();
