-- T77.6 (2026-06-12) — YARA ruleset severity sidecar JSON.
--
-- After T77.5 BUGFIX, rule_count() returns the chunk count
-- (1 for a loaded blob) and rule_severity_ is cleared on swap.
-- The result: matches from pushed blobs show severity="unknown"
-- because the .yarac binary doesn't carry per-rule metadata.
--
-- Fix: store a JSON sidecar {rule_id: severity} alongside
-- the blob. Populated by the admin push tool. The agent reads
-- it from the metadata GET, then populates rule_severity_
-- before returning matches.
--
-- Schema:
--   - severity_json TEXT NOT NULL DEFAULT '{}'
--   - JSON content is a flat dict (1 level deep, no nesting)
--   - For 10K rules at ~6 bytes/entry (rule_id=8 + sev=4 + JSON
--     overhead), we get ~80KB max — well under TEXT's 64KB
--     limit if we trim. Actually MariaDB TEXT = 64KB, MEDIUMTEXT
--     = 16MB. We use TEXT — if 10K rules pushes over 64KB, we
--     switch to MEDIUMTEXT in a follow-up.
--
-- This migration is idempotent (uses IF NOT EXISTS pattern via
-- information_schema check, same as T64.6).

SET @col_exists := (
  SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'yara_ruleset'
    AND COLUMN_NAME = 'severity_json'
);
SET @sql := IF(@col_exists = 0,
  'ALTER TABLE yara_ruleset ADD COLUMN severity_json TEXT NOT NULL DEFAULT ''{}''',
  'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
