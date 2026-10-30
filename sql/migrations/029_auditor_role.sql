-- Ticket #29: Auditor role — role_expires_at + audit_trail table
-- Migration: 029_auditor_role.sql

-- Add role_expires_at column to users table
ALTER TABLE users ADD COLUMN role_expires_at DATETIME NULL;

-- Create audit_trail table for auditor consultation logging
CREATE TABLE IF NOT EXISTS audit_trail (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    action VARCHAR(64) NOT NULL,
    framework VARCHAR(50) NULL,
    period VARCHAR(64) NULL,
    ip_address VARCHAR(45) NULL,
    user_agent VARCHAR(255) NULL,
    details JSON NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_audit_trail_user_id (user_id),
    INDEX idx_audit_trail_action (action),
    INDEX idx_audit_trail_framework (framework),
    INDEX idx_audit_trail_created_at (created_at),
    CONSTRAINT fk_audit_trail_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;