-- Migration: policy_documents table (full CREATE)
-- Document library with BLOB storage, AI analysis, review workflow
-- Date: 2026-06-19 (updated 2026-07-07)

CREATE TABLE IF NOT EXISTS policy_documents (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    category VARCHAR(64) NOT NULL DEFAULT 'other',
    version VARCHAR(32) DEFAULT '1.0',
    status VARCHAR(16) DEFAULT 'draft',
    description TEXT DEFAULT NULL,
    file_data LONGBLOB NOT NULL,
    file_name VARCHAR(255) NOT NULL,
    file_type VARCHAR(128) NOT NULL,
    file_size INT NOT NULL,
    approved_by INT DEFAULT NULL,
    approved_at DATETIME DEFAULT NULL,
    ai_analysis TEXT DEFAULT NULL,
    ai_analyzed_at DATETIME DEFAULT NULL,
    created_by INT DEFAULT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    revision INT DEFAULT 1,
    review_status VARCHAR(32) DEFAULT NULL,
    reviewed_by_dsi INT DEFAULT NULL,
    reviewed_by_direction INT DEFAULT NULL,
    reviewed_dsi_at DATETIME DEFAULT NULL,
    reviewed_direction_at DATETIME DEFAULT NULL,
    generated_by_ia TINYINT(1) DEFAULT 0,
    skip_analysis TINYINT(1) NOT NULL DEFAULT 0,
    KEY idx_category (category),
    KEY idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;