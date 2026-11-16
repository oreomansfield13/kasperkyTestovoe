CREATE TABLE IF NOT EXISTS threats (
    md5 VARCHAR(32) PRIMARY KEY,
    sha256 VARCHAR(64),
    name VARCHAR(255) NOT NULL,
    threat_type VARCHAR(50) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    description TEXT,
    file_size BIGINT NOT NULL DEFAULT 0,
    file_type VARCHAR(100),
    tags TEXT[] NOT NULL DEFAULT '{}',
    ref TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);