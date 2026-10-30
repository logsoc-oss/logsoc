-- Migration: asset_tags table
-- Tags for CMDB assets
-- Date: 2026-06-19

CREATE TABLE IF NOT EXISTS asset_tags (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(64) NOT NULL,
    created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;