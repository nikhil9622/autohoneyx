-- AutoHoneyX Database Initialization Script

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Honeytokens table
CREATE TABLE IF NOT EXISTS honeytokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    token_id VARCHAR(255) UNIQUE NOT NULL,
    token_type VARCHAR(50) NOT NULL,
    token_value TEXT NOT NULL,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    triggered_at TIMESTAMP,
    triggered_by_ip INET,
    triggered_by_user_agent TEXT,
    is_triggered BOOLEAN DEFAULT FALSE,
    location_file VARCHAR(500),
    location_line INTEGER,
    created_by VARCHAR(100)
);

-- Attack logs table
CREATE TABLE IF NOT EXISTS attack_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    honeypot_type VARCHAR(50) NOT NULL,
    source_ip INET NOT NULL,
    user_agent TEXT,
    request_path TEXT,
    request_method VARCHAR(10),
    request_body TEXT,
    response_code INTEGER,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    metadata JSONB,
    honeytoken_id UUID REFERENCES honeytokens(id),
    severity VARCHAR(20) DEFAULT 'MEDIUM',
    classification VARCHAR(50)
);

-- Alerts table
CREATE TABLE IF NOT EXISTS alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    source_ip INET,
    honeytoken_id UUID REFERENCES honeytokens(id),
    attack_log_id UUID REFERENCES attack_logs(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sent_at TIMESTAMP,
    sent_via VARCHAR(50),
    is_sent BOOLEAN DEFAULT FALSE,
    metadata JSONB
);

-- Behavioral analysis results
CREATE TABLE IF NOT EXISTS behavior_analysis (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    attack_log_id UUID REFERENCES attack_logs(id),
    category VARCHAR(50) NOT NULL,
    confidence DECIMAL(5,4),
    features JSONB,
    predictions JSONB,
    analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_honeytokens_token_id ON honeytokens(token_id);
CREATE INDEX IF NOT EXISTS idx_honeytokens_type ON honeytokens(token_type);
CREATE INDEX IF NOT EXISTS idx_honeytokens_triggered ON honeytokens(is_triggered);
CREATE INDEX IF NOT EXISTS idx_attack_logs_source_ip ON attack_logs(source_ip);
CREATE INDEX IF NOT EXISTS idx_attack_logs_timestamp ON attack_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_attack_logs_honeypot_type ON attack_logs(honeypot_type);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);

