-- Ticket #9 Option B: Generic retention module
-- 2026-06-24
--
-- Adds:
--   1. retention_jobs — tracking table for purge/archive job executions
--   2. personal_data_registry — GDPR article mapping for DB columns
--   3. Extra columns on retention_policies (archive_enabled, archive_path, purge_cron)
--
-- Idempotent: uses IF NOT EXISTS / ON DUPLICATE KEY UPDATE so re-running
-- on a populated DB is safe.

-- ─── 1. retention_jobs ──────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS retention_jobs (
    id INT NOT NULL AUTO_INCREMENT,
    policy_id INT NOT NULL,
    started_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    completed_at DATETIME NULL,
    records_archived INT NOT NULL DEFAULT 0,
    records_purged INT NOT NULL DEFAULT 0,
    status ENUM('running','completed','failed') NOT NULL DEFAULT 'running',
    error_message TEXT NULL,
    PRIMARY KEY (id),
    INDEX idx_rj_policy_id (policy_id),
    INDEX idx_rj_status (status),
    INDEX idx_rj_started_at (started_at),
    CONSTRAINT fk_rj_policy_id FOREIGN KEY (policy_id) REFERENCES retention_policies(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- ─── 2. personal_data_registry ──────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS personal_data_registry (
    id INT NOT NULL AUTO_INCREMENT,
    table_name VARCHAR(64) NOT NULL,
    column_name VARCHAR(64) NOT NULL,
    data_type ENUM('username','ip','email','hostname','mac','other') NOT NULL DEFAULT 'other',
    gdpr_article VARCHAR(32) NOT NULL DEFAULT '5(1)(e)',
    notes TEXT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_table_col (table_name, column_name),
    INDEX idx_pdr_table (table_name),
    INDEX idx_pdr_data_type (data_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- ─── 3. Extra columns on retention_policies ─────────────────────────────────
-- These are new for the generic retention module (ticket #9).

-- archive_enabled: whether to export data to archive_path before purging
SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='retention_policies' AND COLUMN_NAME='archive_enabled');
SET @sql = IF(@col_exists = 0,
    'ALTER TABLE retention_policies ADD COLUMN archive_enabled TINYINT(1) NOT NULL DEFAULT 1 AFTER is_active',
    'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- archive_path: local directory or S3 prefix for archived data
SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='retention_policies' AND COLUMN_NAME='archive_path');
SET @sql = IF(@col_exists = 0,
    'ALTER TABLE retention_policies ADD COLUMN archive_path VARCHAR(256) NOT NULL DEFAULT ''/var/logsoc/archive'' AFTER archive_enabled',
    'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- purge_cron: cron expression for automated purge schedule
SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='retention_policies' AND COLUMN_NAME='purge_cron');
SET @sql = IF(@col_exists = 0,
    'ALTER TABLE retention_policies ADD COLUMN purge_cron VARCHAR(32) NOT NULL DEFAULT ''0 2 * * *'' AFTER archive_path',
    'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- table_name: explicit MariaDB table name for the data_domain (for the generic purge)
SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='retention_policies' AND COLUMN_NAME='table_name');
SET @sql = IF(@col_exists = 0,
    'ALTER TABLE retention_policies ADD COLUMN table_name VARCHAR(64) NULL AFTER data_domain',
    'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- ─── 4. Seed: update retention_policies with table_name for 4 MVP tables ───

UPDATE retention_policies SET table_name = 'alerts' WHERE data_domain = 'siem_logs' AND table_name IS NULL;
-- siem_logs lives in ClickHouse; the MariaDB proxy table is logs_raw
UPDATE retention_policies SET table_name = 'logs_raw' WHERE data_domain = 'siem_logs' AND table_name IS NULL;
UPDATE retention_policies SET table_name = 'logs_raw' WHERE data_domain = 'siem_logs';
-- For the retention module, we treat siem_logs as operating on the MariaDB logs_raw table

-- Add a policy for yara_scan_results (7 years = 2555 days) if not present
INSERT INTO retention_policies (data_domain, table_name, hot_days, warm_days, cold_days, auto_purge, purge_after_days, is_active, archive_enabled, archive_path, purge_cron, anonymize_after_days, erase_after_days, notes)
VALUES ('yara_scan_results', 'yara_scan_results', 2555, 0, 0, 1, 2555, 1, 1, '/var/logsoc/archive', '0 2 * * *', NULL, 2555, 'YARA scan results: 7 years retention (RGPD art. 5(1)(e) security logging)')
ON DUPLICATE KEY UPDATE table_name = VALUES(table_name), notes = VALUES(notes);

-- Add a policy for alerts (180 days) if not present
INSERT INTO retention_policies (data_domain, table_name, hot_days, warm_days, cold_days, auto_purge, purge_after_days, is_active, archive_enabled, archive_path, purge_cron, anonymize_after_days, erase_after_days, notes)
VALUES ('alerts', 'alerts', 180, 0, 0, 1, 180, 1, 1, '/var/logsoc/archive', '0 2 * * *', 90, 180, 'Alerts: 180d retention, anonymize PII after 90d')
ON DUPLICATE KEY UPDATE table_name = VALUES(table_name), notes = VALUES(notes);

-- ─── 5. Seed: personal_data_registry for 4 MVP tables ───────────────────────

-- alerts
INSERT INTO personal_data_registry (table_name, column_name, data_type, gdpr_article, notes)
VALUES
    ('alerts', 'source_host',  'hostname', '5(1)(e)', 'Source hostname — identifies the machine that generated the alert'),
    ('alerts', 'assigned_to',  'username', '5(1)(e)', 'Analyst assigned to the alert — internal personal data'),
    ('alerts', 'closed_by',    'username', '5(1)(e)', 'User who closed the alert — internal personal data'),
    ('alerts', 'description',  'other',   '5(1)(e)', 'Free-text may contain PII (usernames, IPs, paths)'),
    ('alerts', 'related_log_ids', 'other', '5(1)(e)', 'May reference log entries containing PII')
ON DUPLICATE KEY UPDATE notes = VALUES(notes);

-- yara_scan_results
INSERT INTO personal_data_registry (table_name, column_name, data_type, gdpr_article, notes)
VALUES
    ('yara_scan_results', 'agent_id',    'other',   '5(1)(e)', 'Agent UUID — identifies the host machine'),
    ('yara_scan_results', 'target_path', 'other',   '5(1)(e)', 'File path may contain usernames (e.g. /home/user/...)'),
    ('yara_scan_results', 'raw_match',   'other',   '5(1)(e)', 'JSON match output may contain PII')
ON DUPLICATE KEY UPDATE notes = VALUES(notes);

-- logs_raw (siem_logs MariaDB proxy)
INSERT INTO personal_data_registry (table_name, column_name, data_type, gdpr_article, notes)
VALUES
    ('logs_raw', 'source_host', 'hostname', '5(1)(e)', 'Source hostname — identifies the machine'),
    ('logs_raw', 'source_ip',   'ip',       '5(1)(e)', 'Source IP address — personal data per GDPR'),
    ('logs_raw', 'message',     'other',   '5(1)(e)', 'Log message may contain usernames, IPs, paths'),
    ('logs_raw', 'raw_message', 'other',   '5(1)(e)', 'Raw log message may contain PII')
ON DUPLICATE KEY UPDATE notes = VALUES(notes);

-- access_logs (not yet a MariaDB table, but registered for future coverage)
INSERT INTO personal_data_registry (table_name, column_name, data_type, gdpr_article, notes)
VALUES
    ('access_logs', 'source_ip', 'ip',       '5(1)(e)', 'Client IP — personal data per GDPR'),
    ('access_logs', 'user_agent', 'other',  '5(1)(e)', 'User-Agent may contain OS fingerprinting data'),
    ('access_logs', 'username',   'username', '5(1)(e)', 'Authenticated username — direct identifier')
ON DUPLICATE KEY UPDATE notes = VALUES(notes);