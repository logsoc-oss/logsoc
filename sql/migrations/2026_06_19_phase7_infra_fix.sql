-- Phase 7 — Infrastructure: backup_history table + retention_policies additions
-- retention_policies already exists (data_domain, hot_days, warm_days, cold_days, anonymize_after_days, erase_after_days, notes, updated_at, updated_by)
-- We add: is_active, purge_after_days, name columns + backup_history table

ALTER TABLE retention_policies 
  ADD COLUMN IF NOT EXISTS name VARCHAR(255) AFTER id,
  ADD COLUMN IF NOT EXISTS auto_purge BOOLEAN DEFAULT TRUE AFTER cold_days,
  ADD COLUMN IF NOT EXISTS purge_after_days INT DEFAULT 1095 AFTER auto_purge,
  ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE AFTER purge_after_days,
  ADD COLUMN IF NOT EXISTS created_at DATETIME DEFAULT NOW() AFTER is_active;

-- Update existing rows with names
UPDATE retention_policies SET name = CONCAT('Retention - ', data_domain) WHERE name IS NULL;

CREATE TABLE IF NOT EXISTS backup_history (
  id INT AUTO_INCREMENT PRIMARY KEY,
  backup_type ENUM('mariadb','clickhouse','config','full') NOT NULL,
  status ENUM('success','failed','partial') NOT NULL,
  file_path VARCHAR(512),
  file_size BIGINT,
  s3_uploaded BOOLEAN DEFAULT FALSE,
  started_at DATETIME,
  completed_at DATETIME,
  error_message TEXT,
  INDEX idx_status (status),
  INDEX idx_started (started_at)
);