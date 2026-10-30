-- Phase 7 — Infrastructure: Retention policy + backup config
-- Retention policies for logs + RGPD auto-purge + backup tracking

CREATE TABLE IF NOT EXISTS retention_policies (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  data_type ENUM('siem_logs','siem_alerts','siem_events','audit_trail','user_sessions','incident_data') NOT NULL,
  hot_days INT DEFAULT 90,
  warm_days INT DEFAULT 365,
  cold_days INT DEFAULT 1095,       -- 3 years
  auto_purge BOOLEAN DEFAULT TRUE,
  purge_after_days INT DEFAULT 1095, -- RGPD max retention
  is_active BOOLEAN DEFAULT TRUE,
  created_at DATETIME,
  updated_at DATETIME,
  UNIQUE KEY uq_retention_name (name)
);

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

-- Seed default retention policies
INSERT INTO retention_policies (name, data_type, hot_days, warm_days, cold_days, auto_purge, purge_after_days, is_active, created_at, updated_at) VALUES
  ('SIEM Logs - Default', 'siem_logs', 90, 365, 1095, TRUE, 1095, TRUE, NOW(), NOW()),
  ('SIEM Alerts - Default', 'siem_alerts', 90, 365, 1095, TRUE, 1095, TRUE, NOW(), NOW()),
  ('Audit Trail - Legal', 'audit_trail', 90, 365, 2555, FALSE, 2555, TRUE, NOW(), NOW()),
  ('User Sessions - RGPD', 'user_sessions', 30, 90, 365, TRUE, 365, TRUE, NOW(), NOW()),
  ('Incident Data - Legal', 'incident_data', 90, 365, 2555, FALSE, 2555, TRUE, NOW(), NOW())
ON DUPLICATE KEY UPDATE updated_at = NOW();