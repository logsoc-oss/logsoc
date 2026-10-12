-- Migration: login_audit table
-- Audit trail for login attempts (success, failure, MFA usage, source IP)
-- Date: 2026-07-04

CREATE TABLE IF NOT EXISTS login_audit (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id INT DEFAULT NULL,
    username VARCHAR(64) NOT NULL,
    source_ip VARCHAR(64) NOT NULL,
    user_agent TEXT DEFAULT NULL,
    status VARCHAR(32) NOT NULL,
    mfa_used TINYINT(1) DEFAULT 0,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    KEY idx_user (user_id),
    KEY idx_ip (source_ip),
    KEY idx_timestamp (timestamp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;