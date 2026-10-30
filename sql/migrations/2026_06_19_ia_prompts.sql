-- Migration: ia_prompts table
-- Configurable AI prompts for reference analysis, document analysis,
-- crisis chat, wizard generation, etc.
-- Date: 2026-06-19

CREATE TABLE IF NOT EXISTS ia_prompts (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    prompt_key VARCHAR(64) NOT NULL,
    label VARCHAR(128) NOT NULL,
    description TEXT DEFAULT NULL,
    prompt_text TEXT NOT NULL,
    variables TEXT DEFAULT NULL,
    is_system TINYINT(1) DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY prompt_key (prompt_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;