-- Migration: policy_document_audit table
-- Audit trail for policy document actions
-- Date: 2026-06-12

CREATE TABLE IF NOT EXISTS policy_document_audit (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    document_id INT NOT NULL,
    action_type VARCHAR(32) NOT NULL,
    user_id INT DEFAULT NULL,
    username VARCHAR(64) DEFAULT NULL,
    details TEXT DEFAULT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    KEY idx_doc (document_id),
    KEY idx_timestamp (timestamp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;