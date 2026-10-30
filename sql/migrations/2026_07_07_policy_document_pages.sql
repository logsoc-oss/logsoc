-- Migration: policy_document_pages table
-- Page-by-page AI analysis results for reference documents
-- Date: 2026-07-07

CREATE TABLE IF NOT EXISTS policy_document_pages (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    document_id INT NOT NULL,
    page_number INT NOT NULL,
    total_pages INT NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'pending',  -- pending, analyzing, done, error, skipped
    result_text TEXT NULL,
    error_message TEXT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_policy_doc_pages_doc (document_id),
    INDEX idx_policy_doc_pages_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;